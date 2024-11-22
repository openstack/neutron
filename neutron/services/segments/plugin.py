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

import copy

from keystoneauth1 import loading as ks_loading
import netaddr
from neutron_lib.api.definitions import ip_allocation as ipalloc_apidef
from neutron_lib.api.definitions import l2_adjacency as l2adj_apidef
from neutron_lib.api.definitions import network as net_def
from neutron_lib.api.definitions import port as port_def
from neutron_lib.api.definitions import segment as seg_apidef
from neutron_lib.api.definitions import segments_peer_subnet_host_routes
from neutron_lib.api.definitions import standard_attr_segment
from neutron_lib.api.definitions import subnet as subnet_def
from neutron_lib.api.definitions import subnet_segmentid_writable
from neutron_lib.api import validators
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants
from neutron_lib.db import resource_extend
from neutron_lib import exceptions as n_exc
from neutron_lib.exceptions import placement as placement_exc
from neutron_lib.placement import client as placement_client
from neutron_lib.plugins import directory
from novaclient import client as nova_client
from novaclient import exceptions as nova_exc
from oslo_config import cfg
from oslo_log import log
from oslo_utils import excutils

from neutron._i18n import _
from neutron.common import ipv6_utils
from neutron.extensions import segment
from neutron.notifiers import batch_notifier
from neutron.objects import network as net_obj
from neutron.objects import ports as ports_obj
from neutron.objects import subnet as subnet_obj
from neutron.services.segments import db
from neutron.services.segments import exceptions


LOG = log.getLogger(__name__)

NOVA_API_VERSION = '2.41'
IPV4_RESOURCE_CLASS = 'IPV4_ADDRESS'
SEGMENT_NAME_STUB = 'Neutron segment id %s'
MAX_INVENTORY_UPDATE_RETRIES = 10


@resource_extend.has_resource_extenders
@registry.has_registry_receivers
class Plugin(db.SegmentDbMixin, segment.SegmentPluginBase):

    _instance = None

    supported_extension_aliases = [seg_apidef.ALIAS,
                                   ipalloc_apidef.ALIAS,
                                   l2adj_apidef.ALIAS,
                                   standard_attr_segment.ALIAS,
                                   subnet_segmentid_writable.ALIAS,
                                   segments_peer_subnet_host_routes.ALIAS]

    __native_pagination_support = True
    __native_sorting_support = True
    __filter_validation_support = True

    def __init__(self):
        self.nova_updater = NovaSegmentNotifier()
        self.segment_host_routes = SegmentHostRoutes()

    @staticmethod
    @resource_extend.extends([net_def.COLLECTION_NAME])
    def _extend_network_dict_binding(network_res, network_db):
        if not directory.get_plugin('segments'):
            return

        # TODO(carl_baldwin) Make this work with service subnets when
        #                    it's a thing.
        is_adjacent = (not network_db.subnets or
                       not network_db.subnets[0].segment_id)
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
            self, resource, event, trigger, payload=None):
        """Raise exception if there are any subnets associated with segment."""
        if payload.metadata.get(db.FOR_NET_DELETE):
            # don't check if this is a part of a network delete operation
            return
        segment_id = payload.resource_id
        subnets = subnet_obj.Subnet.get_objects(payload.context,
                                                segment_id=segment_id)
        subnet_ids = [s.id for s in subnets]

        if subnet_ids:
            reason = _("The segment is still associated with subnet(s) "
                       "%s") % ", ".join(subnet_ids)
            raise exceptions.SegmentInUse(segment_id=segment_id,
                                          reason=reason)

    @registry.receives(
        resources.SUBNET, [events.PRECOMMIT_DELETE_ASSOCIATIONS])
    def _validate_auto_address_subnet_delete(self, resource, event, trigger,
                                             payload):
        context = payload.context
        subnet = subnet_obj.Subnet.get_object(context, id=payload.resource_id)
        is_auto_addr_subnet = ipv6_utils.is_auto_address_subnet(subnet)
        if not is_auto_addr_subnet or subnet.segment_id is None:
            return

        ports = ports_obj.Port.get_ports_allocated_by_subnet_id(context,
                                                                subnet.id)
        for port in ports:
            fixed_ips = [f for f in port.fixed_ips if f.subnet_id != subnet.id]
            if len(fixed_ips) != 0:
                continue

            LOG.info("Found port %(port_id)s, with IP auto-allocation "
                     "only on subnet %(subnet)s which is associated with "
                     "segment %(segment_id)s, cannot delete",
                     {'port_id': port.id,
                      'subnet': subnet.id,
                      'segment_id': subnet.segment_id})
            raise n_exc.SubnetInUse(subnet_id=subnet.id)


class Event:

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
class NovaSegmentNotifier:

    def __init__(self):
        self.p_client, self.n_client = self._get_clients()
        self.batch_notifier = batch_notifier.BatchNotifier(
            cfg.CONF.send_events_interval, self._send_notifications)

    def _get_clients(self):
        p_client = placement_client.PlacementAPIClient(
            cfg.CONF, openstack_api_version='placement 1.1')

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
            except placement_exc.PlacementEndpointNotFound:
                LOG.debug('Placement API was not found when trying to '
                          'update routed networks IPv4 inventories')
                return

    def _notify_subnet(self, context, subnet, segment_id):
        total, reserved = self._calculate_inventory_total_and_reserved(subnet)
        if total:
            segment_host_mappings = net_obj.SegmentHostMapping.get_objects(
                context, segment_id=segment_id)
            self.batch_notifier.queue_event(Event(
                self._create_or_update_nova_inventory, segment_id, total=total,
                reserved=reserved,
                segment_host_mappings=segment_host_mappings))

    @registry.receives(resources.SUBNET, [events.AFTER_CREATE])
    def _notify_subnet_created(self, resource, event, trigger, payload):
        context = payload.context
        subnet = payload.latest_state
        segment_id = subnet.get('segment_id')
        if not segment_id or subnet['ip_version'] != constants.IP_VERSION_4:
            return
        self._notify_subnet(context, subnet, segment_id)

    def _create_or_update_nova_inventory(self, event):
        try:
            self._update_nova_inventory(event)
        except placement_exc.PlacementResourceProviderNotFound:
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
                self.p_client.update_resource_provider_inventory(
                    event.segment_id, ipv4_inventory, IPV4_RESOURCE_CLASS)
                return
            except placement_exc.PlacementResourceProviderGenerationConflict:
                LOG.debug('Re-trying to update Nova IPv4 inventory for '
                          'routed network segment: %s', event.segment_id)
        LOG.error('Failed to update Nova IPv4 inventory for routed '
                  'network segment: %s', event.segment_id)

    def _get_nova_aggregate_uuid(self, aggregate):
        try:
            return aggregate.uuid
        except AttributeError:
            with excutils.save_and_reraise_exception():
                LOG.exception("uuid was not returned as part of the aggregate "
                              "object which indicates that the Nova API "
                              "backend does not support microversions. Ensure "
                              "that the compute endpoint in the service "
                              "catalog points to the v2.1 API.")

    def _create_nova_inventory(self, segment_id, total, reserved,
                               segment_host_mappings):
        name = SEGMENT_NAME_STUB % segment_id
        resource_provider = {'name': name, 'uuid': segment_id}
        self.p_client.create_resource_provider(resource_provider)
        aggregate = self.n_client.aggregates.create(name, None)
        aggregate_uuid = self._get_nova_aggregate_uuid(aggregate)
        self.p_client.associate_aggregates(segment_id, [aggregate_uuid])
        for mapping in segment_host_mappings:
            self.n_client.aggregates.add_host(aggregate.id, mapping.host)
        ipv4_inventory = {
            IPV4_RESOURCE_CLASS: {
                'total': total, 'reserved': reserved, 'min_unit': 1,
                'max_unit': 1, 'step_size': 1, 'allocation_ratio': 1.0,
            }
        }
        self.p_client.update_resource_provider_inventories(
            segment_id, ipv4_inventory)

    def _calculate_inventory_total_and_reserved(self, subnet):
        total = 0
        reserved = 0
        allocation_pools = subnet.get('allocation_pools') or []
        for pool in allocation_pools:
            total += int(netaddr.IPAddress(pool['end']) -
                         netaddr.IPAddress(pool['start'])) + 1
        if total:
            if subnet.get('gateway_ip'):
                total += 1
                reserved += 1
            if subnet.get('enable_dhcp'):
                reserved += 1
        return total, reserved

    @registry.receives(resources.SUBNET, [events.AFTER_UPDATE])
    def _notify_subnet_updated(self, resource, event, trigger, payload):
        context = payload.context
        original_subnet = payload.states[0]
        subnet = payload.latest_state
        segment_id = subnet.get('segment_id')
        original_segment_id = original_subnet.get('segment_id')
        if not segment_id or subnet['ip_version'] != constants.IP_VERSION_4:
            return
        if original_segment_id != segment_id:
            # Migration to routed network, treat as create
            self._notify_subnet(context, subnet, segment_id)
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
                segment_host_mappings = net_obj.SegmentHostMapping.get_objects(
                    context, segment_id=segment_id)
            self.batch_notifier.queue_event(Event(
                self._create_or_update_nova_inventory, segment_id, total=total,
                reserved=reserved,
                segment_host_mappings=segment_host_mappings))

    @registry.receives(resources.SUBNET, [events.AFTER_DELETE])
    def _notify_subnet_deleted(self, resource, event, trigger, payload):
        context = payload.context
        subnet = payload.latest_state
        if payload.metadata.get(db.FOR_NET_DELETE):
            return  # skip segment RP update if it is going to be deleted

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
        try:
            aggregate_uuid = self.p_client.list_aggregates(
                segment_id)['aggregates'][0]
        except placement_exc.PlacementAggregateNotFound:
            LOG.info('Segment %s resource provider aggregate not found',
                     segment_id)
            return

        for aggregate in self.n_client.aggregates.list():
            nc_aggregate_uuid = self._get_nova_aggregate_uuid(aggregate)
            if nc_aggregate_uuid == aggregate_uuid:
                return aggregate.id

    def _delete_nova_inventory(self, event):
        aggregate_id = self._get_aggregate_id(event.segment_id)
        if aggregate_id:
            aggregate = self.n_client.aggregates.get_details(aggregate_id)
            for host in aggregate.hosts:
                self.n_client.aggregates.remove_host(aggregate_id, host)
            self.n_client.aggregates.delete(aggregate_id)

        try:
            self.p_client.delete_resource_provider(event.segment_id)
        except placement_exc.PlacementClientError as exc:
            LOG.info('Segment %s resource provider not found; error: %s',
                     event.segment_id, str(exc))

    @staticmethod
    def _payload_segment_ids(payload, key):
        # NOTE(twilson) My assumption is that this is to guarantee the subnets
        # passed exist in at least one subnet
        subnets = subnet_obj.Subnet.get_objects(
            payload.context, segment_id=payload.metadata.get(key))
        return {s.segment_id for s in subnets}

    @registry.receives(resources.SEGMENT_HOST_MAPPING, [events.AFTER_CREATE])
    def _notify_host_addition_to_aggregate(self, resource, event, trigger,
                                           payload=None):
        segment_ids = self._payload_segment_ids(payload, 'current_segment_ids')
        self.batch_notifier.queue_event(
            Event(self._add_host_to_aggregate,
                  segment_ids, host=payload.metadata.get('host')))

    def _add_host_to_aggregate(self, event):
        for segment_id in event.segment_ids:
            aggregate_id = self._get_aggregate_id(segment_id)
            if not aggregate_id:
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

    @registry.receives(resources.SEGMENT_HOST_MAPPING, [events.AFTER_DELETE])
    def _notify_host_removal_from_aggregate(self, resource, event, trigger,
                                            payload=None):
        segment_ids = self._payload_segment_ids(payload, 'deleted_segment_ids')
        self.batch_notifier.queue_event(
            Event(self._remove_host_from_aggregate,
                  segment_ids, host=payload.metadata.get('host')))

    def _remove_host_from_aggregate(self, event):
        for segment_id in event.segment_ids:
            aggregate_id = self._get_aggregate_id(segment_id)
            if not aggregate_id:
                LOG.info('When removing host %(host)s, aggregate not found '
                         'for routed network segment %(segment_id)s',
                         {'host': event.host, 'segment_id': segment_id})
                continue
            try:
                self.n_client.aggregates.remove_host(aggregate_id, event.host)
            except nova_exc.NotFound:
                LOG.info('Host %(host)s is not in aggregate for '
                         'routed network segment %(segment_ids)s',
                         {'host': event.host, 'segment_id': segment_id})

    @registry.receives(resources.PORT, [events.AFTER_CREATE,
                                        events.AFTER_DELETE])
    def _notify_port_created_or_deleted(self, resource, event, trigger,
                                        payload):
        context = payload.context
        port = payload.latest_state
        if not self._does_port_require_nova_inventory_update(port):
            return
        ipv4_subnets_number, segment_id = (
            self._get_ipv4_subnets_number_and_segment_id(port, context))
        if segment_id:
            if event == events.AFTER_DELETE:
                ipv4_subnets_number = -ipv4_subnets_number
            self.batch_notifier.queue_event(
                Event(self._update_nova_inventory,
                      segment_id, reserved=ipv4_subnets_number))

    @registry.receives(resources.PORT, [events.AFTER_UPDATE])
    def _notify_port_updated(self, resource, event, trigger, payload):
        context = payload.context
        port = payload.latest_state
        original_port = payload.states[0]
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
        subnet = subnet_obj.Subnet.get_object(context, id=ipv4_subnet_ids[0])
        if subnet and subnet.segment_id:
            return len(ipv4_subnet_ids), subnet.segment_id

        return 0, None

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

    @registry.receives(resources.SEGMENT, [events.AFTER_DELETE])
    def _notify_segment_deleted(
            self, resource, event, trigger, payload=None):
        if payload:
            self.batch_notifier.queue_event(Event(
                self._delete_nova_inventory, payload.resource_id))


@registry.has_registry_receivers
class SegmentHostRoutes:

    def _get_subnets(self, context, network_id):
        return subnet_obj.Subnet.get_objects(context, network_id=network_id)

    def _count_subnets(self, context, network_id):
        return subnet_obj.Subnet.count(context, network_id=network_id)

    def _calculate_routed_network_host_routes(self, context, ip_version,
                                              network_id=None, subnet_id=None,
                                              segment_id=None,
                                              host_routes=None,
                                              gateway_ip=None,
                                              old_gateway_ip=None,
                                              deleted_cidr=None):
        """Calculate host routes for routed network.

        This method is used to calculate the host routes for routed networks
        both when handling the user create or update request and when making
        updates to subnets on the network in response to events: AFTER_CREATE
        and AFTER_DELETE.

        :param ip_version: IP version (4/6).
        :param network_id: Network ID.
        :param subnet_id: UUID of the subnet.
        :param segment_id: Segement ID associated with the subnet.
        :param host_routes: Current host_routes of the subnet.
        :param gateway_ip: The subnets gateway IP address.
        :param old_gateway_ip: The old gateway IP address of the subnet when it
                               is changed on update.
        :param deleted_cidr: The cidr of a deleted subnet.
        :returns Host routes with routes for the other subnet's on the routed
                 network appended unless a route to the destination already
                 exists.
        """
        if host_routes is None:
            host_routes = []
        dest_ip_nets = [netaddr.IPNetwork(route['destination']) for
                        route in host_routes]

        # Drop routes to the deleted cidr, when the subnet was deleted.
        if deleted_cidr:
            delete_route = {'destination': deleted_cidr, 'nexthop': gateway_ip}
            if delete_route in host_routes:
                host_routes.remove(delete_route)

        for subnet in self._get_subnets(context, network_id):
            if (subnet.id == subnet_id or subnet.segment_id == segment_id or
                    subnet.ip_version != ip_version):
                continue
            subnet_ip_net = netaddr.IPNetwork(subnet.cidr)
            if old_gateway_ip:
                old_route = {'destination': str(subnet.cidr),
                             'nexthop': old_gateway_ip}
                if old_route in host_routes:
                    host_routes.remove(old_route)
                    dest_ip_nets.remove(subnet_ip_net)
            if gateway_ip:
                # Use netaddr here in case the user provided a summary route
                # (supernet route). I.e subnet.cidr = 10.0.1.0/24 and
                # the user provided a host route for 10.0.0.0/16. We don't
                # need to append a route in this case.
                if not any(subnet_ip_net in ip_net for ip_net in dest_ip_nets):
                    host_routes.append({'destination': subnet.cidr,
                                        'nexthop': gateway_ip})

        return host_routes

    def _host_routes_need_update(self, host_routes, calc_host_routes):
        """Compare host routes and calculated host routes

        :param host_routes: Current host routes
        :param calc_host_routes: Host routes + calculated host routes for
                                 routed network
        :returns True if host_routes and calc_host_routes are not equal
        """
        return ({(route['destination'],
                  route['nexthop']) for route in host_routes} !=
                {(route['destination'],
                  route['nexthop']) for route in calc_host_routes})

    def _update_routed_network_host_routes(self, context, network_id,
                                           deleted_cidr=None):
        """Update host routes on subnets on a routed network after event

        Host routes on the subnets on a routed network may need updates after
        any CREATE or DELETE event.

        :param network_id: Network ID
        :param deleted_cidr: The cidr of a deleted subnet.
        """
        for subnet in self._get_subnets(context, network_id):
            host_routes = [{'destination': str(route.destination),
                            'nexthop': route.nexthop}
                           for route in subnet.host_routes]
            calc_host_routes = self._calculate_routed_network_host_routes(
                context=context,
                ip_version=subnet.ip_version,
                network_id=subnet.network_id,
                subnet_id=subnet.id,
                segment_id=subnet.segment_id,
                host_routes=copy.deepcopy(host_routes),
                gateway_ip=subnet.gateway_ip,
                deleted_cidr=deleted_cidr)
            if self._host_routes_need_update(host_routes, calc_host_routes):
                LOG.debug(
                    "Updating host routes for subnet %s on routed network %s",
                    subnet.id, subnet.network_id)
                plugin = directory.get_plugin()
                plugin.update_subnet(context, subnet.id,
                                     {'subnet': {
                                         'host_routes': calc_host_routes}})

    @registry.receives(resources.SUBNET, [events.BEFORE_CREATE])
    def host_routes_before_create(self, resource, event, trigger,
                                  payload):
        context = payload.context
        subnet = payload.latest_state
        segment_id = subnet.get('segment_id')
        gateway_ip = subnet.get('gateway_ip')
        if validators.is_attr_set(subnet.get('host_routes')):
            host_routes = subnet.get('host_routes')
        else:
            host_routes = []
        if segment_id is not None and validators.is_attr_set(gateway_ip):
            calc_host_routes = self._calculate_routed_network_host_routes(
                context=context,
                ip_version=netaddr.IPNetwork(subnet['cidr']).version,
                network_id=subnet['network_id'],
                segment_id=segment_id,
                host_routes=copy.deepcopy(host_routes),
                gateway_ip=gateway_ip)
            if (not host_routes or
                    self._host_routes_need_update(host_routes,
                                                  calc_host_routes)):
                subnet['host_routes'] = calc_host_routes

    @registry.receives(resources.SUBNET, [events.BEFORE_UPDATE])
    def host_routes_before_update(self, resource, event, trigger,
                                  payload):
        context = payload.context
        original_subnet = payload.states[0]
        subnet = payload.latest_state
        orig_segment_id = original_subnet.get('segment_id')
        segment_id = subnet.get('segment_id', orig_segment_id)
        orig_gateway_ip = original_subnet.get('gateway_ip')
        gateway_ip = subnet.get('gateway_ip', orig_gateway_ip)
        orig_host_routes = original_subnet.get('host_routes')
        host_routes = subnet.get('host_routes', orig_host_routes)
        if (segment_id and (host_routes != orig_host_routes or
                            gateway_ip != orig_gateway_ip)):
            calc_host_routes = self._calculate_routed_network_host_routes(
                context=context,
                ip_version=netaddr.IPNetwork(original_subnet['cidr']).version,
                network_id=original_subnet['network_id'],
                segment_id=segment_id,
                host_routes=copy.deepcopy(host_routes),
                gateway_ip=gateway_ip,
                old_gateway_ip=orig_gateway_ip if (
                    gateway_ip != orig_gateway_ip) else None)
            if self._host_routes_need_update(host_routes, calc_host_routes):
                subnet['host_routes'] = calc_host_routes

    @registry.receives(resources.SUBNET, [events.AFTER_CREATE])
    def host_routes_after_create(self, resource, event, trigger,
                                 payload):
        context = payload.context
        subnet = payload.latest_state
        # If there are other subnets on the network and subnet has segment_id
        # ensure host routes for all subnets are updated.

        if (subnet.get('segment_id') and
                self._count_subnets(context, subnet['network_id']) > 1):
            self._update_routed_network_host_routes(context,
                                                    subnet['network_id'])

    @registry.receives(resources.SUBNET, [events.AFTER_DELETE])
    def host_routes_after_delete(self, resource, event, trigger,
                                 payload):
        # If this is a routed network, remove any routes to this subnet on
        # this networks remaining subnets.
        context = payload.context
        subnet = payload.latest_state
        if payload.metadata.get(db.FOR_NET_DELETE):
            return  # skip subnet update if the network is going to be deleted

        if subnet.get('segment_id'):
            self._update_routed_network_host_routes(
                context, subnet['network_id'], deleted_cidr=subnet['cidr'])
