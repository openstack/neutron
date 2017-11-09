# Copyright 2016 Hewlett Packard Enterprise Development, LP
#
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from keystoneauth1 import loading as ks_loading
import netaddr
from neutron_lib.api.definitions import ip_allocation as ipalloc_apidef
from neutron_lib.api.definitions import l2_adjacency as l2adj_apidef
from neutron_lib.api.definitions import network as net_def
from neutron_lib.api.definitions import port as port_def
from neutron_lib.api.definitions import subnet as subnet_def
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants
from neutron_lib.plugins import directory
from novaclient import client as nova_client
from novaclient import exceptions as nova_exc
from oslo_config import cfg
from oslo_log import log

from neutron._i18n import _
from neutron.common import exceptions as n_exc
from neutron.db import _resource_extend as resource_extend
from neutron.db import api as db_api
from neutron.db.models import segment as segment_model
from neutron.db import models_v2
from neutron.extensions import segment
from neutron.notifiers import batch_notifier
from neutron.services.segments import db
from neutron.services.segments import exceptions
from neutron.services.segments import placement_client

LOG = log.getLogger(__name__)

NOVA_API_VERSION = '2.41'
IPV4_RESOURCE_CLASS = 'IPV4_ADDRESS'
SEGMENT_NAME_STUB = 'Neutron segment id %s'
MAX_INVENTORY_UPDATE_RETRIES = 10


@resource_extend.has_resource_extenders
@registry.has_registry_receivers
class Plugin(db.SegmentDbMixin, segment.SegmentPluginBase):

    _instance = None

    supported_extension_aliases = ["segment", "ip_allocation",
                                   l2adj_apidef.ALIAS]

    def __init__(self):
        self.nova_updater = NovaSegmentNotifier()

    @staticmethod
    @resource_extend.extends([net_def.COLLECTION_NAME])
    def _extend_network_dict_binding(network_res, network_db):
        if not directory.get_plugin('segments'):
            return

        # TODO(carl_baldwin) Make this work with service subnets when
        #                    it's a thing.
        is_adjacent = (not network_db.subnets
                       or not network_db.subnets[0].segment_id)
        network_res[l2adj_apidef.L2_ADJACENCY] = is_adjacent

    @staticmethod
    @resource_extend.extends([subnet_def.COLLECTION_NAME])
    def _extend_subnet_dict_binding(subnet_res, subnet_db):
        subnet_res['segment_id'] = subnet_db.get('segment_id')

    @staticmethod
    @resource_extend.extends([port_def.COLLECTION_NAME])
    def _extend_port_dict_binding(port_res, port_db):
        if not directory.get_plugin('segments'):
            return

        value = ipalloc_apidef.IP_ALLOCATION_IMMEDIATE
        if port_db.get('ip_allocation'):
            value = port_db.get('ip_allocation')
        port_res[ipalloc_apidef.IP_ALLOCATION] = value

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @registry.receives(resources.SEGMENT, [events.BEFORE_DELETE])
    def _prevent_segment_delete_with_subnet_associated(
            self, resource, event, trigger, context, segment,
            for_net_delete=False):
        """Raise exception if there are any subnets associated with segment."""
        if for_net_delete:
            # don't check if this is a part of a network delete operation
            return
        with db_api.context_manager.reader.using(context):
            segment_id = segment['id']
            query = context.session.query(models_v2.Subnet.id)
            query = query.filter(models_v2.Subnet.segment_id == segment_id)
            subnet_ids = [s[0] for s in query]

        if subnet_ids:
            reason = _("The segment is still associated with subnet(s) "
                       "%s") % ", ".join(subnet_ids)
            raise exceptions.SegmentInUse(segment_id=segment_id,
                                          reason=reason)


class Event(object):

    def __init__(self, method, segment_ids, total=None, reserved=None,
                 segment_host_mappings=None, host=None):
        self.method = method
        if isinstance(segment_ids, set):
            self.segment_ids = segment_ids
        else:
            self.segment_id = segment_ids
        self.total = total
        self.reserved = reserved
        self.segment_host_mappings = segment_host_mappings
        self.host = host


@registry.has_registry_receivers
class NovaSegmentNotifier(object):

    def __init__(self):
        self.p_client, self.n_client = self._get_clients()
        self.batch_notifier = batch_notifier.BatchNotifier(
            cfg.CONF.send_events_interval, self._send_notifications)

    def _get_clients(self):
        p_client = placement_client.PlacementAPIClient()

        n_auth = ks_loading.load_auth_from_conf_options(cfg.CONF, 'nova')
        n_session = ks_loading.load_session_from_conf_options(
            cfg.CONF,
            'nova',
            auth=n_auth)
        extensions = [
            ext for ext in nova_client.discover_extensions(NOVA_API_VERSION)
            if ext.name == "server_external_events"]
        n_client = nova_client.Client(
            NOVA_API_VERSION,
            session=n_session,
            region_name=cfg.CONF.nova.region_name,
            endpoint_type=cfg.CONF.nova.endpoint_type,
            extensions=extensions)

        return p_client, n_client

    def _send_notifications(self, batched_events):
        for event in batched_events:
            try:
                event.method(event)
            except n_exc.PlacementEndpointNotFound:
                LOG.debug('Placement API was not found when trying to '
                          'update routed networks IPv4 inventories')
                return

    @registry.receives(resources.SUBNET, [events.AFTER_CREATE])
    def _notify_subnet_created(self, resource, event, trigger, context,
                               subnet, **kwargs):
        segment_id = subnet.get('segment_id')
        if not segment_id or subnet['ip_version'] != constants.IP_VERSION_4:
            return
        total, reserved = self._calculate_inventory_total_and_reserved(subnet)
        if total:
            query = (
                context.session.query(segment_model.SegmentHostMapping).
                filter_by(segment_id=segment_id)
            )
            self.batch_notifier.queue_event(Event(
                self._create_or_update_nova_inventory, segment_id, total=total,
                reserved=reserved, segment_host_mappings=query.all()))

    def _create_or_update_nova_inventory(self, event):
        try:
            self._update_nova_inventory(event)
        except n_exc.PlacementResourceProviderNotFound:
            self._create_nova_inventory(event.segment_id, event.total,
                                        event.reserved,
                                        event.segment_host_mappings)

    def _update_nova_inventory(self, event):
        for count in range(MAX_INVENTORY_UPDATE_RETRIES):
            ipv4_inventory = self.p_client.get_inventory(event.segment_id,
                                                         IPV4_RESOURCE_CLASS)
            if event.total:
                ipv4_inventory['total'] += event.total
            if event.reserved:
                ipv4_inventory['reserved'] += event.reserved
            try:
                self.p_client.update_inventory(event.segment_id,
                                               ipv4_inventory,
                                               IPV4_RESOURCE_CLASS)
                return
            except n_exc.PlacementInventoryUpdateConflict:
                LOG.debug('Re-trying to update Nova IPv4 inventory for '
                          'routed network segment: %s', event.segment_id)
        LOG.error('Failed to update Nova IPv4 inventory for routed '
                  'network segment: %s', event.segment_id)

    def _create_nova_inventory(self, segment_id, total, reserved,
                               segment_host_mappings):
        name = SEGMENT_NAME_STUB % segment_id
        resource_provider = {'name': name, 'uuid': segment_id}
        self.p_client.create_resource_provider(resource_provider)
        aggregate = self.n_client.aggregates.create(name, None)
        self.p_client.associate_aggregates(segment_id, [aggregate.uuid])
        for mapping in segment_host_mappings:
            self.n_client.aggregates.add_host(aggregate.id, mapping['host'])
        ipv4_inventory = {'total': total, 'reserved': reserved,
                          'min_unit': 1, 'max_unit': 1, 'step_size': 1,
                          'allocation_ratio': 1.0,
                          'resource_class': IPV4_RESOURCE_CLASS}
        self.p_client.create_inventory(segment_id, ipv4_inventory)

    def _calculate_inventory_total_and_reserved(self, subnet):
        total = 0
        reserved = 0
        allocation_pools = subnet.get('allocation_pools') or []
        for pool in allocation_pools:
            total += int(netaddr.IPAddress(pool['end']) -
                         netaddr.IPAddress(pool['start'])) + 1
        if total:
            if subnet['gateway_ip']:
                total += 1
                reserved += 1
            if subnet['enable_dhcp']:
                reserved += 1
        return total, reserved

    @registry.receives(resources.SUBNET, [events.AFTER_UPDATE])
    def _notify_subnet_updated(self, resource, event, trigger, context,
                               subnet, original_subnet, **kwargs):
        segment_id = subnet.get('segment_id')
        if not segment_id or subnet['ip_version'] != constants.IP_VERSION_4:
            return
        filters = {'segment_id': [segment_id],
                   'ip_version': [constants.IP_VERSION_4]}
        if not subnet['allocation_pools']:
            plugin = directory.get_plugin()
            alloc_pools = [s['allocation_pools'] for s in
                           plugin.get_subnets(context, filters=filters)]
            if not any(alloc_pools):
                self.batch_notifier.queue_event(Event(
                    self._delete_nova_inventory, segment_id))
                return
        original_total, original_reserved = (
            self._calculate_inventory_total_and_reserved(original_subnet))
        updated_total, updated_reserved = (
            self._calculate_inventory_total_and_reserved(subnet))
        total = updated_total - original_total
        reserved = updated_reserved - original_reserved
        if total or reserved:
            segment_host_mappings = None
            if not original_subnet['allocation_pools']:
                segment_host_mappings = context.session.query(
                    segment_model.SegmentHostMapping).filter_by(
                        segment_id=segment_id).all()
            self.batch_notifier.queue_event(Event(
                self._create_or_update_nova_inventory, segment_id, total=total,
                reserved=reserved,
                segment_host_mappings=segment_host_mappings))

    @registry.receives(resources.SUBNET, [events.AFTER_DELETE])
    def _notify_subnet_deleted(self, resource, event, trigger, context,
                               subnet, **kwargs):
        segment_id = subnet.get('segment_id')
        if not segment_id or subnet['ip_version'] != constants.IP_VERSION_4:
            return
        total, reserved = self._calculate_inventory_total_and_reserved(subnet)
        if total:
            filters = {'segment_id': [segment_id], 'ip_version': [4]}
            plugin = directory.get_plugin()
            if plugin.get_subnets_count(context, filters=filters) > 0:
                self.batch_notifier.queue_event(Event(
                    self._update_nova_inventory, segment_id, total=-total,
                    reserved=-reserved))
            else:
                self.batch_notifier.queue_event(Event(
                    self._delete_nova_inventory, segment_id))

    def _get_aggregate_id(self, segment_id):
        aggregate_uuid = self.p_client.list_aggregates(
            segment_id)['aggregates'][0]
        aggregates = self.n_client.aggregates.list()
        for aggregate in aggregates:
            if aggregate.uuid == aggregate_uuid:
                return aggregate.id

    def _delete_nova_inventory(self, event):
        aggregate_id = self._get_aggregate_id(event.segment_id)
        aggregate = self.n_client.aggregates.get_details(
            aggregate_id)
        for host in aggregate.hosts:
            self.n_client.aggregates.remove_host(aggregate_id,
                                                 host)
        self.n_client.aggregates.delete(aggregate_id)
        self.p_client.delete_resource_provider(event.segment_id)

    @registry.receives(resources.SEGMENT_HOST_MAPPING, [events.AFTER_CREATE])
    def _notify_host_addition_to_aggregate(self, resource, event, trigger,
                                           context, host, current_segment_ids,
                                           **kwargs):
        query = context.session.query(models_v2.Subnet).filter(
            models_v2.Subnet.segment_id.in_(current_segment_ids))
        segment_ids = {subnet['segment_id'] for subnet in query}
        self.batch_notifier.queue_event(Event(self._add_host_to_aggregate,
            segment_ids, host=host))

    def _add_host_to_aggregate(self, event):
        for segment_id in event.segment_ids:
            try:
                aggregate_id = self._get_aggregate_id(segment_id)
            except n_exc.PlacementAggregateNotFound:
                LOG.info('When adding host %(host)s, aggregate not found '
                         'for routed network segment %(segment_id)s',
                         {'host': event.host, 'segment_id': segment_id})
                continue

            try:
                self.n_client.aggregates.add_host(aggregate_id, event.host)
            except nova_exc.Conflict:
                LOG.info('Host %(host)s already exists in aggregate for '
                         'routed network segment %(segment_id)s',
                         {'host': event.host, 'segment_id': segment_id})

    @registry.receives(resources.PORT,
                       [events.AFTER_CREATE, events.AFTER_DELETE])
    def _notify_port_created_or_deleted(self, resource, event, trigger,
                                        context, port, **kwargs):
        if not self._does_port_require_nova_inventory_update(port):
            return
        ipv4_subnets_number, segment_id = (
            self._get_ipv4_subnets_number_and_segment_id(port, context))
        if segment_id:
            if event == events.AFTER_DELETE:
                ipv4_subnets_number = -ipv4_subnets_number
            self.batch_notifier.queue_event(Event(self._update_nova_inventory,
                segment_id, reserved=ipv4_subnets_number))

    @registry.receives(resources.PORT, [events.AFTER_UPDATE])
    def _notify_port_updated(self, resource, event, trigger, context,
                             **kwargs):
        port = kwargs.get('port')
        original_port = kwargs.get('original_port')
        does_original_port_require_nova_inventory_update = (
            self._does_port_require_nova_inventory_update(original_port))
        does_port_require_nova_inventory_update = (
            self._does_port_require_nova_inventory_update(port))
        if not (does_original_port_require_nova_inventory_update or
                does_port_require_nova_inventory_update):
            return
        original_port_ipv4_subnets_number, segment_id = (
            self._get_ipv4_subnets_number_and_segment_id(original_port,
                                                         context))
        if not segment_id:
            return
        port_ipv4_subnets_number = len(self._get_ipv4_subnet_ids(port))
        if not does_original_port_require_nova_inventory_update:
            original_port_ipv4_subnets_number = 0
        if not does_port_require_nova_inventory_update:
            port_ipv4_subnets_number = 0
        update = port_ipv4_subnets_number - original_port_ipv4_subnets_number
        if update:
            self.batch_notifier.queue_event(Event(self._update_nova_inventory,
                segment_id, reserved=update))

    def _get_ipv4_subnets_number_and_segment_id(self, port, context):
        ipv4_subnet_ids = self._get_ipv4_subnet_ids(port)
        if not ipv4_subnet_ids:
            return 0, None
        segment_id = context.session.query(
            models_v2.Subnet).filter_by(id=ipv4_subnet_ids[0]).one()[
                    'segment_id']
        if not segment_id:
            return 0, None
        return len(ipv4_subnet_ids), segment_id

    def _does_port_require_nova_inventory_update(self, port):
        device_owner = port.get('device_owner')
        if (device_owner.startswith(constants.DEVICE_OWNER_COMPUTE_PREFIX) or
            device_owner == constants.DEVICE_OWNER_DHCP):
            return False
        return True

    def _get_ipv4_subnet_ids(self, port):
        ipv4_subnet_ids = []
        for ip in port.get('fixed_ips', []):
            if netaddr.IPAddress(
                    ip['ip_address']).version == constants.IP_VERSION_4:
                ipv4_subnet_ids.append(ip['subnet_id'])
        return ipv4_subnet_ids
