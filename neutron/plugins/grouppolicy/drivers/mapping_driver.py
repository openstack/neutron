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

from oslo.config import cfg

from neutron.api.v2 import attributes
from neutron.common import exceptions as nexc
from neutron.common import log
from neutron import manager
from neutron.openstack.common import log as logging
from neutron.plugins.common import constants as pconst
from neutron.plugins.grouppolicy import group_policy_driver_api as api


LOG = logging.getLogger(__name__)

mapping_opts = [
    cfg.StrOpt('default_routing_domain_name',
               default='default',
               help=_("Name of each tenant's default routing_domain.")),
    cfg.IntOpt('default_ip_version',
               default=4,
               help=_("IP version (4 or 6) for implicitly created default "
                      "routing_domains.")),
    cfg.StrOpt('default_ip_supernet',
               default='172.16.0.0/12',
               help=_("IP supernet for implicitly created default "
                      "routing_domains, from which subnets are allocated for "
                      "endpoint_groups.")),
    cfg.IntOpt('default_subnet_prefix_length',
               default=26,
               help=_("Subnet prefix length for implicitly created "
                      "default routing_domains, controlling size of subnets "
                      "allocated for endpoint_groups.")),
]

cfg.CONF.register_opts(mapping_opts, "group_policy_mapping")


class MappingDriver(api.PolicyDriver):

    @log.log
    def initialize(self):
        LOG.info("initialize")
        gpm = cfg.CONF.group_policy_mapping
        self._default_rd_name = gpm.default_routing_domain_name
        self._default_ip_version = gpm.default_ip_version
        self._default_ip_supernet = gpm.default_ip_supernet
        self._default_subnet_prefix_length = gpm.default_subnet_prefix_length

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
        if not context.current['bridge_domain_id']:
            self._default_epg_bd(context)
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
        if not context.current['routing_domain_id']:
            self._default_bd_rd(context)
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
        attrs = {'router':
                 {'tenant_id': context.current['tenant_id'],
                  'name': 'rd_' + context.current['name'],
                  'external_gateway_info': None,
                  'admin_state_up': True}}
        plugins = manager.NeutronManager.get_service_plugins()
        l3_plugin = plugins.get(pconst.L3_ROUTER_NAT)
        if not l3_plugin:
            raise Exception(_("No L3 router service plugin found."))
        router = l3_plugin.create_router(context._plugin_context, attrs)
        LOG.info("created router: %s" % router)
        context.add_neutron_router(router['id'])

    def _default_bd_rd(self, context):
        filter = {'tenant_id': context.current['tenant_id'],
                  'name': self._default_rd_name}
        rds = context._plugin.get_routing_domains(context._plugin_context,
                                                  filter)
        rd = rds and rds[0]
        if not rd:
            # REVISIT(rkukura): Race condition could result in
            # multiple default RDs.
            attrs = {'routing_domain':
                     {'tenant_id': context.current['tenant_id'],
                      'name': self._default_rd_name,
                      'description': _("Implicitly created routing domain"),
                      'ip_version': self._default_ip_version,
                      'ip_supernet': self._default_ip_supernet,
                      'subnet_prefix_length':
                      self._default_subnet_prefix_length}}
            rd = context._plugin.create_routing_domain(context._plugin_context,
                                                       attrs)
        context.set_routing_domain_id(rd['id'])

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

    def _default_epg_bd(self, context):
        attrs = {'bridge_domain':
                 {'tenant_id': context.current['tenant_id'],
                  'name': context.current['name'],
                  'description': _("Implicitly created bridge domain"),
                  'routing_domain_id': None,
                  'neutron_network_id': None}}
        bd = context._plugin.create_bridge_domain(context._plugin_context,
                                                  attrs)
        context.set_bridge_domain_id(bd['id'])

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
            if context.is_cidr_available(cidr):
                try:
                    attrs['subnet']['cidr'] = cidr.__str__()
                    subnet = core_plugin.create_subnet(context._plugin_context,
                                                       attrs)
                    try:
                        context.add_neutron_subnet(subnet['id'])
                        return
                    except Exception:
                        LOG.exception("add_neutron_subnet failed")
                        core_plugin.delete_subnet(context._plugin_context,
                                                  subnet['id'])
                except Exception:
                    LOG.exception("create_subnet failed")
        # TODO(rkukura): Need real exception
        raise nexc.ResourceExhausted("no more subnets in supernet")

    def _validate_ep_port(self, context):
        # TODO(rkukura): Implement
        pass

    def _create_ep_port(self, context):
        epg_id = context.current['endpoint_group_id']
        epg = context._plugin.get_endpoint_group(context._plugin_context,
                                                 epg_id)
        bd_id = epg['bridge_domain_id']
        bd = context._plugin.get_bridge_domain(context._plugin_context,
                                               bd_id)
        attrs = {'port':
                 {'tenant_id': context.current['tenant_id'],
                  'name': 'ep_' + context.current['name'],
                  'network_id': bd['neutron_network_id'],
                  'mac_address': attributes.ATTR_NOT_SPECIFIED,
                  'fixed_ips': attributes.ATTR_NOT_SPECIFIED,
                  'device_id': '',
                  'device_owner': '',
                  'admin_state_up': True}}
        core_plugin = manager.NeutronManager.get_plugin()
        port = core_plugin.create_port(context._plugin_context, attrs)
        context.set_neutron_port_id(port['id'])
