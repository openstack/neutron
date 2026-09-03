# Copyright 2025 Red Hat, Inc.
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

import netaddr
from neutron_lib.api.definitions import ovn_bgp as ovn_bgp_apidef
from neutron_lib.api.definitions import provider_net as pnet
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants as n_const
from neutron_lib.db import resource_extend
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import directory
from neutron_lib.services import base as service_base
from oslo_config import cfg
from oslo_log import log

from neutron.common.ovn import utils as ovn_utils
from neutron.conf.services import bgp as bgp_config
from neutron.objects import bgp as bgp_objects
from neutron.objects import network as network_objects
from neutron.objects import router as router_objects
from neutron.services.bgp import commands as bgp_commands
from neutron.services.bgp import worker

LOG = log.getLogger(__name__)


@resource_extend.has_resource_extenders
@registry.has_registry_receivers
class BGPServicePlugin(service_base.ServicePluginBase):

    supported_extension_aliases = [ovn_bgp_apidef.ALIAS]

    def __init__(self):
        LOG.info("Starting BGP Service Plugin")
        super().__init__()
        bgp_config.register_opts(cfg.CONF)
        self._nb_ovn_inst = None

    @property
    def _nb_ovn(self):
        if self._nb_ovn_inst is None:
            plugin = directory.get_plugin()
            mech = plugin.mechanism_manager.mech_drivers['ovn'].obj
            self._nb_ovn_inst = mech.nb_ovn
        return self._nb_ovn_inst

    def get_workers(self):
        return [worker.BGPWorker()]

    def get_plugin_description(self):
        return "BGP service plugin for OVN"

    @classmethod
    def get_plugin_type(cls):
        return "bgp-service"

    @staticmethod
    def _validate_gateway_router_for_subnet(context, subnet_id):
        """Validate that the subnet is attached to a router with an ext GW.

        Raises BadRequest if no such router exists.
        """
        router = router_objects.Router.get_gateway_router_for_subnet(
            context, subnet_id)
        if not router:
            raise n_exc.BadRequest(
                resource='subnet',
                msg='The subnet %(subnet_id)s must be attached to a router '
                    'with an external gateway to enable leak_routes.'
                    % {'subnet_id': subnet_id})

    @staticmethod
    def _validate_no_cidr_overlap(context, cidr):
        leaked_cidrs = bgp_objects.SubnetBGPLeakRoutes.get_leaked_subnet_cidrs(
            context)
        new_subnet = netaddr.IPNetwork(cidr)
        for subnet_id, subnet_cidr in leaked_cidrs:
            existing = netaddr.IPNetwork(subnet_cidr)
            if new_subnet.version != existing.version:
                continue
            if new_subnet in existing or existing in new_subnet:
                raise n_exc.BadRequest(
                    resource='subnet',
                    msg='The subnet CIDR %s overlaps with already '
                        'leaked subnet %s (%s).'
                        % (cidr, subnet_id, subnet_cidr))

    @staticmethod
    @resource_extend.extends([ovn_bgp_apidef.COLLECTION_NAME])
    def _extend_subnet_dict_bgp(subnet_res, subnet_db):
        subnet_res[ovn_bgp_apidef.LEAK_ROUTES] = (
            subnet_db.get('bgp_leak_routes') is not None)
        return subnet_res

    @registry.receives(resources.NETWORK, [events.PRECOMMIT_CREATE])
    def _validate_provider_network(self, resource, event, trigger, payload):
        network = payload.latest_state
        network_type = network.get(pnet.NETWORK_TYPE)
        if network_type == n_const.TYPE_VLAN:
            raise n_exc.BadRequest(
                resource='network',
                msg='VLAN provider networks are not supported when the '
                    'BGP service plugin is enabled. '
                    'Only flat provider networks are supported.')
        if network_type == n_const.TYPE_FLAT:
            existing = network_objects.NetworkSegment.get_objects(
                payload.context, network_type=n_const.TYPE_FLAT)
            other_flat = [s for s in existing
                          if s.network_id != payload.resource_id]
            if other_flat:
                raise n_exc.BadRequest(
                    resource='network',
                    msg='Only a single flat provider network is supported '
                        'when the BGP service plugin is enabled.')

    @registry.receives(resources.SUBNET, [events.BEFORE_UPDATE])
    def _process_subnet_update_bgp(self, resource, event, trigger, payload):
        original = payload.states[0]
        updated = payload.states[1]
        try:
            leak_routes = updated[ovn_bgp_apidef.LEAK_ROUTES]
        except KeyError:
            return

        original_leak = original.get(ovn_bgp_apidef.LEAK_ROUTES, False)
        if original_leak == leak_routes:
            return

        context = payload.context
        subnet_id = payload.resource_id

        segments = network_objects.NetworkSegment.get_objects(
            context, network_id=updated['network_id'])
        network_type = segments[0].network_type if segments else None
        if leak_routes and network_type != n_const.TYPE_GENEVE:
            raise n_exc.BadRequest(
                resource='subnet',
                msg='The leak_routes attribute is only supported on '
                    'subnets belonging to geneve networks.')

        if leak_routes:
            self._validate_gateway_router_for_subnet(context, subnet_id)
            self._validate_no_cidr_overlap(context, updated['cidr'])
            ip_version = netaddr.IPNetwork(updated['cidr']).version
            nexthop_ip = router_objects.Router.get_gateway_ip_for_subnet(
                context, subnet_id, ip_version)
            if not nexthop_ip:
                raise n_exc.BadRequest(
                    resource='subnet',
                    msg='The router external gateway has no IPv%(ip_version)s'
                        ' address to use as nexthop for subnet '
                        '%(subnet_id)s.'
                        % {'ip_version': ip_version, 'subnet_id': subnet_id})
            bgp_objects.SubnetBGPLeakRoutes(
                context, subnet_id=subnet_id).create()
            LOG.info("Subnet %s updated: leak_routes enabled", subnet_id)
        else:
            bgp_objects.SubnetBGPLeakRoutes.delete_objects(
                context, subnet_id=subnet_id)
            LOG.info("Subnet %s updated: leak_routes disabled", subnet_id)

    @registry.receives(resources.SUBNET, [events.AFTER_UPDATE])
    def _process_subnet_after_update_bgp(self, resource, event, trigger,
                                         payload):
        original = payload.states[0]
        updated = payload.latest_state
        original_leak = original.get(ovn_bgp_apidef.LEAK_ROUTES, False)
        current_leak = updated.get(ovn_bgp_apidef.LEAK_ROUTES, False)
        if original_leak == current_leak:
            return

        context = payload.context
        network_id = updated['network_id']
        tenant_ls_name = ovn_utils.ovn_name(network_id)

        if current_leak:
            self._leak_subnet(context, updated, tenant_ls_name)
        else:
            self._unleak_subnet(context, updated, tenant_ls_name)

    @staticmethod
    def _is_last_leaked_subnet_on_network(context, network_id):
        return not bgp_objects.SubnetBGPLeakRoutes.network_has_leaked_subnets(
            context, network_id)

    def _leak_subnet(self, context, subnet, tenant_ls_name):
        subnet_id = subnet['id']
        cidr = subnet['cidr']
        ip_version = netaddr.IPNetwork(cidr).version
        nexthop_ip = router_objects.Router.get_gateway_ip_for_subnet(
            context, subnet_id, ip_version)
        if not nexthop_ip:
            LOG.error("No IPv%s nexthop found for subnet %s; "
                      "skipping OVN route creation, reconciler will retry.",
                      ip_version, subnet_id)
            return

        bgp_commands.LeakSubnetCommand(
            self._nb_ovn,
            tenant_ls_name,
            cidr,
            nexthop_ip,
        ).execute(check_error=True)

    def _unleak_subnet(self, context, subnet, tenant_ls_name):
        network_id = subnet['network_id']
        cidr = subnet['cidr']

        last_on_network = self._is_last_leaked_subnet_on_network(
            context, network_id)

        bgp_commands.UnleakSubnetCommand(
            self._nb_ovn,
            tenant_ls_name,
            cidr,
            last_on_network=last_on_network,
        ).execute(check_error=True)

    @registry.receives(resources.ROUTER_INTERFACE, [events.BEFORE_DELETE])
    def _process_router_interface_delete_bgp(self, resource, event, trigger,
                                             payload):
        context = payload.context
        subnet_id = payload.metadata['subnet_id']
        bgp_objects.SubnetBGPLeakRoutes.delete_objects(
            context, subnet_id=subnet_id)

    @registry.receives(resources.ROUTER_INTERFACE, [events.AFTER_DELETE])
    def _process_router_interface_after_delete_bgp(self, resource, event,
                                                   trigger, payload):
        context = payload.context
        port = payload.metadata['port']
        network_id = port['network_id']
        cidrs = payload.metadata['cidrs']
        try:
            cidr = cidrs[0]
        except IndexError:
            LOG.warning("No subnet on router interface %s", port['id'])
            return
        if len(cidrs) > 1:
            LOG.warning("Unexpected number of subnets on router interface %s: "
                        "%s", port['id'], cidrs)
        tenant_ls_name = ovn_utils.ovn_name(network_id)
        last_on_network = self._is_last_leaked_subnet_on_network(
            context, network_id)
        bgp_commands.UnleakSubnetCommand(
            self._nb_ovn,
            tenant_ls_name,
            cidr,
            last_on_network=last_on_network,
        ).execute(check_error=True)
