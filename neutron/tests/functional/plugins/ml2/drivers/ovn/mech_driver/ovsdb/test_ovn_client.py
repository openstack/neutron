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

from neutron_lib.api.definitions import external_net
from neutron_lib.api.definitions import network_mtu as mtu_def
from neutron_lib.api.definitions import provider_net
from neutron_lib import constants
from oslo_config import cfg
from oslo_utils import strutils

from neutron.common.ovn import constants as ovn_const
from neutron.common.ovn import utils as ovn_utils
from neutron.conf.plugins.ml2.drivers.ovn import ovn_conf as ovn_config
from neutron.tests.functional import base
from neutron.tests.unit.api import test_extensions
from neutron.tests.unit.extensions import test_l3


class TestOVNClient(base.TestOVNFunctionalBase,
                    test_l3.L3NatTestCaseMixin):

    def setUp(self, **kwargs):
        super().setUp(**kwargs)
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

    def test_create_router(self):
        ch = self.add_fake_chassis('host1', enable_chassis_as_gw=True,
                                   azs=[])
        net_arg = {provider_net.NETWORK_TYPE: 'geneve',
                   external_net.EXTERNAL: True}
        with self.network('test-ovn-client', as_admin=True,
                          arg_list=tuple(net_arg.keys()), **net_arg) as net:
            with self.subnet(net):
                ext_gw = {'network_id': net['network']['id']}
                with self.router(external_gateway_info=ext_gw) as router:
                    router_id = router['router']['id']
                    lr = self.nb_api.lookup('Logical_Router',
                                            ovn_utils.ovn_name(router_id))
                    self.assertEqual(ch, lr.options['chassis'])
                    lrp = lr.ports[0]
                    self.assertTrue(strutils.bool_from_string(
                        lrp.external_ids[ovn_const.OVN_ROUTER_IS_EXT_GW]))
                    hcg = self.nb_api.lookup('HA_Chassis_Group',
                                             ovn_utils.ovn_name(router_id))
                    self.assertIsNotNone(hcg)

                    # Remove the external GW port.
                    self._update('routers', router_id,
                                 {'router': {'external_gateway_info': {}}},
                                 as_admin=True)
                    lr = self.nb_api.lookup('Logical_Router',
                                            ovn_utils.ovn_name(router_id))
                    self.assertEqual([], lr.ports)
                    self.assertNotIn('chassis', lr.options)
                    hcg = self.nb_api.lookup('HA_Chassis_Group',
                                             ovn_utils.ovn_name(router_id),
                                             default=None)
                    self.assertIsNone(hcg)

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

    def test_process_address_group(self):
        def _find_address_set_for_ag():
            as_v4 = self.nb_api.lookup(
                'Address_Set',
                ovn_utils.ovn_ag_addrset_name(
                    ag['id'], 'ip' + str(constants.IP_VERSION_4)),
                default=None)
            as_v6 = self.nb_api.lookup(
                'Address_Set',
                ovn_utils.ovn_ag_addrset_name(
                    ag['id'], 'ip' + str(constants.IP_VERSION_6)),
                default=None)
            return as_v4, as_v6

        ovn_client = self.mech_driver._ovn_client
        ag_args = {'project_id': 'project_1',
                   'name': 'test_address_group',
                   'description': 'test address group',
                   'addresses': ['192.168.2.2/32',
                                 '2001:db8::/32']}
        ag = self.plugin.create_address_group(self.context,
                                              {'address_group': ag_args})
        self.assertIsNotNone(_find_address_set_for_ag()[0])
        self.assertIsNotNone(_find_address_set_for_ag()[1])

        # Call the create_address_group again to ensure that the create
        # command automatically checks for existing Address_Set
        ovn_client.create_address_group(self.context, ag)

        # Update the address group
        ag['addresses'] = ['20.0.0.1/32', '2002:db8::/32']
        ovn_client.update_address_group(self.context, ag)
        as_v4_new = _find_address_set_for_ag()[0]
        as_v6_new = _find_address_set_for_ag()[1]
        self.assertEqual(['20.0.0.1/32'], as_v4_new.addresses)
        self.assertEqual(['2002:db8::/32'], as_v6_new.addresses)

        # Delete the address group
        ovn_client.delete_address_group(self.context, ag['id'])
        self.assertEqual((None, None), _find_address_set_for_ag())

    def _check_gw_lrp_mtu(self, router_id, mtu):
        # Find gateway LRP and check the MTU value.
        lr = self.nb_api.lookup('Logical_Router',
                                ovn_utils.ovn_name(router_id))
        for lrp in lr.ports:
            if strutils.bool_from_string(
                    lrp.external_ids[
                        ovn_const.OVN_ROUTER_IS_EXT_GW]):
                self.assertEqual(mtu, int(lrp.options['gateway_mtu']))
                return

        self.fail('Gateway Logical_Router_Port not found for '
                  'router %s' % router_id)

    def test_update_network_lrp_mtu_updated(self):
        self.add_fake_chassis('host1', enable_chassis_as_gw=True, azs=[])
        net_ext_args = {provider_net.NETWORK_TYPE: 'geneve',
                        external_net.EXTERNAL: True,
                        mtu_def.MTU: 1300}
        net_int_args = {provider_net.NETWORK_TYPE: 'geneve',
                        mtu_def.MTU: 1400}
        with self.network(
                'test-ext-net', as_admin=True,
                arg_list=tuple(net_ext_args.keys()), **net_ext_args) as \
                net_ext, self.network(
                'test-int-net', as_admin=True,
                arg_list=tuple(net_int_args.keys()), **net_int_args) as \
                net_int:
            with self.subnet(net_ext, cidr='10.1.0.0/24'), \
                    self.subnet(net_int, cidr='10.2.0.0/24') as snet_int:
                ext_gw = {'network_id': net_ext['network']['id']}
                with self.router(external_gateway_info=ext_gw) as router:
                    router_id = router['router']['id']
                    self._router_interface_action(
                        'add', router_id, snet_int['subnet']['id'],
                        None)

                    self._check_gw_lrp_mtu(router_id, 1300)

                    # Update external network MTU.
                    net_ext_args = {'network': {mtu_def.MTU: 1350}}
                    req = self.new_update_request('networks', net_ext_args,
                                                  net_ext['network']['id'])
                    req.get_response(self.api)
                    self._check_gw_lrp_mtu(router_id, 1350)

    def test_add_new_router_interfaces_lrp_mtu_updated(self):
        mtu_ext = 1350
        internal_interfaces = [{'cidr': '10.2.0.0/24', 'mtu': mtu_ext - 10},
                               {'cidr': '10.3.0.0/24', 'mtu': mtu_ext + 10},
                               {'cidr': '10.4.0.0/24', 'mtu': mtu_ext - 20}]
        self.add_fake_chassis('host1', enable_chassis_as_gw=True, azs=[])
        net_ext_args = {provider_net.NETWORK_TYPE: 'geneve',
                        external_net.EXTERNAL: True,
                        mtu_def.MTU: mtu_ext}
        # Store the network's MTUs connected to the router.
        router_attached_net_mtus = {mtu_ext}
        with self.network(
                'test-ext-net', as_admin=True,
                arg_list=tuple(net_ext_args.keys()), **net_ext_args) as \
                net_ext:
            ext_gw = {'network_id': net_ext['network']['id']}
            with self.subnet(net_ext, cidr='10.1.0.0/24'), \
                    self.router(external_gateway_info=ext_gw) as router:
                router_id = router['router']['id']
                for _int in internal_interfaces:
                    # Attach a new internal interface to the router. If the new
                    # network MTU is lower than the minimum MTU connected, the
                    # GW LRP.options.gateway_mtu will be updated.
                    net_int_args = {provider_net.NETWORK_TYPE: 'geneve',
                                    mtu_def.MTU: _int['mtu']}
                    router_attached_net_mtus.add(_int['mtu'])
                    net_int = self._make_network(
                        self.fmt, name='nettest', admin_state_up=True,
                        **net_int_args)
                    snet_int = self._make_subnet(
                        self.fmt, net_int, constants.ATTR_NOT_SPECIFIED,
                        _int['cidr'])
                    self._router_interface_action(
                        'add', router_id, snet_int['subnet']['id'],
                        None)

                    # The GW LRP "gateway_mtu" value should be the minimum
                    # MTU connected to the router.
                    self._check_gw_lrp_mtu(router_id,
                                           min(router_attached_net_mtus))
