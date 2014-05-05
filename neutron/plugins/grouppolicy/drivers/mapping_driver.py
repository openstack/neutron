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

from neutron.api.v2 import attributes
from neutron.common import exceptions as nexc
from neutron.common import log
from neutron import manager
from neutron.openstack.common import log as logging
from neutron.plugins.grouppolicy import group_policy_driver_api as api


LOG = logging.getLogger(__name__)


class MappingDriver(api.PolicyDriver):

    @log.log
    def initialize(self):
        LOG.info("initialize")

    @log.log
    def create_endpoint_precommit(self, context):
        LOG.info("create_endpoint_precommit: %s", context.current)
        if context.current['neutron_port_id']:
            self._validate_ep_port(context)

    @log.log
    def create_endpoint_postcommit(self, context):
        LOG.info("create_endpoint_postcommit: %s", context.current)
        if not context.current['neutron_port_id']:
            self._create_ep_port(context)

    @log.log
    def update_endpoint_precommit(self, context):
        pass

    @log.log
    def update_endpoint_postcommit(self, context):
        pass

    @log.log
    def delete_endpoint_precommit(self, context):
        LOG.info("delete_endpoint_precommit: %s", context.current)

    @log.log
    def delete_endpoint_postcommit(self, context):
        LOG.info("delete_endpoint_postcommit: %s", context.current)

    @log.log
    def create_endpoint_group_precommit(self, context):
        LOG.info("create_endpoint_group_precommit: %s", context.current)
        if context.current['neutron_subnets']:
            self._validate_epg_subnets(context)

    @log.log
    def create_endpoint_group_postcommit(self, context):
        LOG.info("create_endpoint_group_postcommit: %s", context.current)
        # TODO(rkukura): Create/find BD if not specified
        if not context.current['neutron_subnets']:
            self._add_epg_subnet(context)

    @log.log
    def update_endpoint_group_precommit(self, context):
        pass

    @log.log
    def update_endpoint_group_postcommit(self, context):
        pass

    @log.log
    def delete_endpoint_group_precommit(self, context):
        LOG.info("delete_endpoint_group_precommit: %s", context.current)

    @log.log
    def delete_endpoint_group_postcommit(self, context):
        LOG.info("delete_endpoint_group_postcommit: %s", context.current)

    @log.log
    def create_bridge_domain_precommit(self, context):
        LOG.info("create_bridge_domain_precommit: %s", context.current)
        if context.current['neutron_network_id']:
            self._validate_bd_network(context)

    @log.log
    def create_bridge_domain_postcommit(self, context):
        LOG.info("create_bridge_domain_postcommit: %s", context.current)
        # TODO(rkukura): Create/find RD if not specified
        if not context.current['neutron_network_id']:
            self._create_bd_network(context)

    @log.log
    def update_bridge_domain_precommit(self, context):
        pass

    @log.log
    def update_bridge_domain_postcommit(self, context):
        pass

    @log.log
    def delete_bridge_domain_precommit(self, context):
        LOG.info("delete_bridge_domain_precommit: %s", context.current)

    @log.log
    def delete_bridge_domain_postcommit(self, context):
        LOG.info("delete_bridge_domain_postcommit: %s", context.current)

    @log.log
    def create_routing_domain_precommit(self, context):
        LOG.info("create_routing_domain_precommit: %s", context.current)
        if context.current['neutron_routers']:
            self._validate_rd_routers(context)

    @log.log
    def create_routing_domain_postcommit(self, context):
        LOG.info("create_routing_domain_postcommit: %s", context.current)
        if not context.current['neutron_routers']:
            self._add_rd_router(context)

    @log.log
    def update_routing_domain_precommit(self, context):
        pass

    @log.log
    def update_routing_domain_postcommit(self, context):
        pass

    @log.log
    def delete_routing_domain_precommit(self, context):
        LOG.info("delete_routing_domain_precommit: %s", context.current)

    @log.log
    def delete_routing_domain_postcommit(self, context):
        LOG.info("delete_routing_domain_postcommit: %s", context.current)

    def _validate_rd_routers(self, context):
        # TODO(rkukura): Implement
        pass

    def _add_rd_router(self, context):
        # TODO(rkukura): Implement
        pass

    def _validate_bd_network(self, context):
        # TODO(rkukura): Implement
        pass

    def _create_bd_network(self, context):
        attrs = {'network':
                 {'tenant_id': context.current['tenant_id'],
                  'name': 'bd_' + context.current['name'],
                  'admin_state_up': True,
                  'shared': False}}
        core_plugin = manager.NeutronManager.get_plugin()
        network = core_plugin.create_network(context._plugin_context, attrs)
        context.set_neutron_network_id(network['id'])

    def _validate_epg_subnets(self, context):
        # TODO(rkukura): Implement
        pass

    def _add_epg_subnet(self, context):
        bd_id = context.current['bridge_domain_id']
        bd = context._plugin.get_bridge_domain(context._plugin_context,
                                               bd_id)
        rd_id = bd['routing_domain_id']
        rd = context._plugin.get_routing_domain(context._plugin_context,
                                                rd_id)
        supernet = netaddr.IPNetwork(rd['ip_supernet'])
        LOG.info("allocating subnet from supernet: %s", supernet)
        attrs = {'subnet':
                 {'tenant_id': context.current['tenant_id'],
                  'name': 'epg_' + context.current['name'],
                  'network_id': bd['neutron_network_id'],
                  'ip_version': rd['ip_version'],
                  'enable_dhcp': True,
                  'gateway_ip': attributes.ATTR_NOT_SPECIFIED,
                  'allocation_pools': attributes.ATTR_NOT_SPECIFIED,
                  'dns_nameservers': attributes.ATTR_NOT_SPECIFIED,
                  'host_routes': attributes.ATTR_NOT_SPECIFIED}}
        core_plugin = manager.NeutronManager.get_plugin()
        subnet = None
        for cidr in supernet.subnet(rd['subnet_prefix_length']):
            LOG.info("trying: %s", cidr)
            # TODO(rkukura): Need to ensure subnet not already
            # allocated within entire RD, not just within BD's
            # network. We may need some sort of allocation pool for
            # this, or a set of locked for update queries.
            try:
                attrs['subnet']['cidr'] = cidr.__str__()
                subnet = core_plugin.create_subnet(context._plugin_context,
                                                   attrs)
                LOG.info("created subnet: %s", subnet)
                context.add_neutron_subnet(subnet['id'])
                return
            except Exception:
                LOG.exception("got exception")
        # TODO(rkukura): Need real exception
        raise nexc.ResourceExhausted("no more subnets in supernet")

    def _validate_ep_port(self, context):
        # TODO(rkukura): Implement
        pass

    def _create_ep_port(self, context):
        # TODO(rkukura): Implement
        pass
