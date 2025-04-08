# Copyright 2023 Red Hat, Inc.
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

from neutron_lib.api.definitions import provider_net
from neutron_lib import constants
from oslo_config import cfg
from oslo_utils import strutils
from sqlalchemy.dialects.mysql import dialect as mysql_dialect

from neutron.common.ovn import constants as ovn_const
from neutron.common.ovn import utils as ovn_utils
from neutron.conf.plugins.ml2.drivers.ovn import ovn_conf as ovn_config
from neutron.tests.functional import base
from neutron.tests.unit.api import test_extensions
from neutron.tests.unit.extensions import test_l3
from neutron.tests.unit import testlib_api


class TestOVNClient(testlib_api.MySQLTestCaseMixin,
                    base.TestOVNFunctionalBase,
                    test_l3.L3NatTestCaseMixin):

    def setUp(self, **kwargs):
        super().setUp(**kwargs)
        self.assertEqual(mysql_dialect.name, self.db.engine.dialect.name)
        ext_mgr = test_l3.L3TestExtensionManager()
        self.ext_api = test_extensions.setup_extensions_middleware(ext_mgr)

    def test_create_metadata_port(self):
        def check_metadata_port(enable_dhcp):
            ports = self.plugin.get_ports(
                self.context, filters={'network_id': [network['id']]})
            self.assertEqual(1, len(ports))
            if enable_dhcp:
                self.assertEqual(1, len(ports[0]['fixed_ips']))
            else:
                self.assertEqual(0, len(ports[0]['fixed_ips']))
            return ports

        ovn_config.cfg.CONF.set_override('ovn_metadata_enabled', True,
                                         group='ovn')
        ovn_client = self.mech_driver._ovn_client
        for enable_dhcp in (True, False):
            network_args = {'tenant_id': 'project_1',
                            'name': 'test_net_1',
                            'admin_state_up': True,
                            'shared': False,
                            'status': constants.NET_STATUS_ACTIVE}
            network = self.plugin.create_network(self.context,
                                                 {'network': network_args})
            subnet_args = {'tenant_id': 'project_1',
                           'name': 'test_snet_1',
                           'network_id': network['id'],
                           'ip_version': constants.IP_VERSION_4,
                           'cidr': '10.210.10.0/28',
                           'enable_dhcp': enable_dhcp,
                           'gateway_ip': constants.ATTR_NOT_SPECIFIED,
                           'allocation_pools': constants.ATTR_NOT_SPECIFIED,
                           'dns_nameservers': constants.ATTR_NOT_SPECIFIED,
                           'host_routes': constants.ATTR_NOT_SPECIFIED}
            self.plugin.create_subnet(self.context, {'subnet': subnet_args})

            # The metadata port has been created during the network creation.
            ports = check_metadata_port(enable_dhcp)

            # Force the deletion and creation the metadata port.
            self.plugin.delete_port(self.context, ports[0]['id'])
            ovn_client.create_metadata_port(self.context, network)
            check_metadata_port(enable_dhcp)

            # Call again the "create_metadata_port" method as is idempotent
            # because it checks first if the metadata port exists.
            ovn_client.create_metadata_port(self.context, network)
            check_metadata_port(enable_dhcp)

    def test_create_port(self):
        with self.network('test-ovn-client') as net:
            with self.subnet(net) as subnet:
                with self.port(subnet) as port:
                    port_data = port['port']
                    nb_ovn = self.mech_driver.nb_ovn
                    lsp = nb_ovn.lsp_get(port_data['id']).execute()
                    # The logical switch port has been created during the
                    # port creation.
                    self.assertIsNotNone(lsp)
                    ovn_client = self.mech_driver._ovn_client
                    port_data = self.plugin.get_port(self.context,
                                                     port_data['id'])
                    # Call the create_port again to ensure that the create
                    # command automatically checks for existing logical
                    # switch ports
                    ovn_client.create_port(self.context, port_data)

    def _test_router_reside_chassis_redirect(
            self, is_distributed_fip, net_type, expected_value=None):
        cfg.CONF.set_override(
            'enable_distributed_floating_ip', is_distributed_fip, group='ovn')
        net_arg = {
            provider_net.NETWORK_TYPE: net_type}
        if net_type == constants.TYPE_FLAT:
            net_arg[provider_net.PHYSICAL_NETWORK] = 'datacentre'
        with self.network('test-ovn-client', as_admin=True,
                          arg_list=tuple(net_arg.keys()), **net_arg) as net:
            with self.subnet(net) as subnet:
                subnet_id = subnet['subnet']['id']
                with self.router() as router:
                    router_id = router['router']['id']
                    self._router_interface_action(
                        'add', router_id, subnet_id, None)
                    lr = self.nb_api.lookup('Logical_Router',
                                            ovn_utils.ovn_name(router_id))
                    lrp = lr.ports[0]
                    if net_type in [constants.TYPE_VLAN, constants.TYPE_FLAT]:
                        self.assertEqual(
                            expected_value,
                            strutils.bool_from_string(
                                lrp.options[
                                    ovn_const.LRP_OPTIONS_RESIDE_REDIR_CH]))
                    else:
                        self.assertNotIn(
                            ovn_const.LRP_OPTIONS_RESIDE_REDIR_CH,
                            lrp.options)

    def test_router_reside_chassis_redirect_dvr_vlan_net(self):
        self._test_router_reside_chassis_redirect(True, 'vlan', False)

    def test_router_reside_chassis_redirect_non_dvr_vlan_net(self):
        self._test_router_reside_chassis_redirect(False, 'vlan', True)

    def test_router_reside_chassis_redirect_dvr_flat_net(self):
        self._test_router_reside_chassis_redirect(True, 'flat', False)

    def test_router_reside_chassis_redirect_non_dvr_flat_net(self):
        self._test_router_reside_chassis_redirect(False, 'flat', True)

    def test_router_reside_chassis_redirect_dvr_geneve_net(self):
        self._test_router_reside_chassis_redirect(True, 'geneve', False)

    def test_router_reside_chassis_redirect_non_dvr_geneve_net(self):
        self._test_router_reside_chassis_redirect(False, 'geneve')
