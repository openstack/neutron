# Copyright 2020 Red Hat, Inc.
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

from unittest import mock

from neutron.common.ovn import constants as ovn_const
from neutron.common.ovn import utils as ovn_utils
from neutron.common import utils as n_utils
from neutron.scheduler import l3_ovn_scheduler as l3_sched
from neutron.tests.functional import base
from neutron.tests.functional.resources.ovsdb import events
from neutron_lib.api.definitions import external_net
from neutron_lib.api.definitions import l3 as l3_apidef
from neutron_lib.api.definitions import portbindings
from neutron_lib.api.definitions import provider_net as pnet
from neutron_lib import constants as n_consts
from neutron_lib.plugins import directory
from ovsdbapp.backend.ovs_idl import idlutils


class TestRouter(base.TestOVNFunctionalBase):
    def setUp(self):
        super(TestRouter, self).setUp()
        self.chassis1 = self.add_fake_chassis(
            'ovs-host1', physical_nets=['physnet1', 'physnet3'])
        self.chassis2 = self.add_fake_chassis(
            'ovs-host2', physical_nets=['physnet2', 'physnet3'])
        self.cr_lrp_pb_event = events.WaitForCrLrpPortBindingEvent()
        self.sb_api.idl.notify_handler.watch_event(self.cr_lrp_pb_event)

    def _create_router(self, name, gw_info=None):
        router = {'router':
                  {'name': name,
                   'admin_state_up': True,
                   'tenant_id': self._tenant_id}}
        if gw_info:
            router['router']['external_gateway_info'] = gw_info
        return self.l3_plugin.create_router(self.context, router)

    def _create_ext_network(self, name, net_type, physnet, seg,
                            gateway, cidr):
        arg_list = (pnet.NETWORK_TYPE, external_net.EXTERNAL,)
        net_arg = {pnet.NETWORK_TYPE: net_type,
                   external_net.EXTERNAL: True}
        if seg:
            arg_list = arg_list + (pnet.SEGMENTATION_ID,)
            net_arg[pnet.SEGMENTATION_ID] = seg
        if physnet:
            arg_list = arg_list + (pnet.PHYSICAL_NETWORK,)
            net_arg[pnet.PHYSICAL_NETWORK] = physnet
        network = self._make_network(self.fmt, name, True,
                                     arg_list=arg_list, **net_arg)
        if cidr:
            self._make_subnet(self.fmt, network, gateway, cidr,
                              ip_version=n_consts.IP_VERSION_4)
        return network

    def _set_redirect_chassis_to_invalid_chassis(self, ovn_client):
        with ovn_client._nb_idl.transaction(check_error=True) as txn:
            for lrp in self.nb_api.tables[
                    'Logical_Router_Port'].rows.values():
                txn.add(ovn_client._nb_idl.update_lrouter_port(
                    lrp.name,
                    gateway_chassis=[ovn_const.OVN_GATEWAY_INVALID_CHASSIS]))

    def test_gateway_chassis_on_router_gateway_port(self):
        ext2 = self._create_ext_network(
            'ext2', 'flat', 'physnet3', None, "20.0.0.1", "20.0.0.0/24")
        gw_info = {'network_id': ext2['network']['id']}
        self._create_router('router1', gw_info=gw_info)
        expected = [row.name for row in
                    self.sb_api.tables['Chassis'].rows.values()]
        for row in self.nb_api.tables[
                'Logical_Router_Port'].rows.values():
            if self._l3_ha_supported():
                chassis = [gwc.chassis_name for gwc in row.gateway_chassis]
                self.assertItemsEqual(expected, chassis)
            else:
                rc = row.options.get(ovn_const.OVN_GATEWAY_CHASSIS_KEY)
                self.assertIn(rc, expected)

    def _check_gateway_chassis_candidates(self, candidates):
        # In this test, fake_select() is called once from _create_router()
        # and later from schedule_unhosted_gateways()
        ovn_client = self.l3_plugin._ovn_client
        ext1 = self._create_ext_network(
            'ext1', 'vlan', 'physnet1', 1, "10.0.0.1", "10.0.0.0/24")
        # mock select function and check if it is called with expected
        # candidates.

        def fake_select(*args, **kwargs):
            self.assertItemsEqual(candidates, kwargs['candidates'])
            # We are not interested in further processing, let us return
            # INVALID_CHASSIS to avoid erros
            return [ovn_const.OVN_GATEWAY_INVALID_CHASSIS]

        with mock.patch.object(ovn_client._ovn_scheduler, 'select',
                               side_effect=fake_select) as client_select,\
            mock.patch.object(self.l3_plugin.scheduler, 'select',
                              side_effect=fake_select) as plugin_select:
            gw_info = {'network_id': ext1['network']['id']}
            self._create_router('router1', gw_info=gw_info)
            self.assertFalse(plugin_select.called)
            self.assertTrue(client_select.called)
            client_select.reset_mock()
            plugin_select.reset_mock()

            # set redirect-chassis to neutron-ovn-invalid-chassis, so
            # that schedule_unhosted_gateways will try to schedule it
            self._set_redirect_chassis_to_invalid_chassis(ovn_client)
            self.l3_plugin.schedule_unhosted_gateways()
            self.assertFalse(client_select.called)
            self.assertTrue(plugin_select.called)

    def test_gateway_chassis_with_cms_and_bridge_mappings(self):
        # Both chassis1 and chassis3 are having proper bridge mappings,
        # but only chassis3 is having enable-chassis-as-gw.
        # Test if chassis3 is selected as candidate or not.
        self.chassis3 = self.add_fake_chassis(
            'ovs-host3', physical_nets=['physnet1'],
            external_ids={'ovn-cms-options': 'enable-chassis-as-gw'})
        self._check_gateway_chassis_candidates([self.chassis3])

    def test_gateway_chassis_with_cms_and_no_bridge_mappings(self):
        # chassis1 is having proper bridge mappings.
        # chassis3 is having enable-chassis-as-gw, but no bridge mappings.
        self.chassis3 = self.add_fake_chassis(
            'ovs-host3',
            external_ids={'ovn-cms-options': 'enable-chassis-as-gw'})
        ovn_client = self.l3_plugin._ovn_client
        ext1 = self._create_ext_network(
            'ext1', 'vlan', 'physnet1', 1, "10.0.0.1", "10.0.0.0/24")
        # As we have 'gateways' in the system, but without required
        # chassis we should not schedule gw in that case at all.
        self._set_redirect_chassis_to_invalid_chassis(ovn_client)
        with mock.patch.object(ovn_client._ovn_scheduler, 'select',
                              return_value=[self.chassis1]), \
            mock.patch.object(self.l3_plugin.scheduler, 'select',
                              side_effect=[self.chassis1]):
            gw_info = {'network_id': ext1['network']['id']}
            self._create_router('router1', gw_info=gw_info)

        with mock.patch.object(
                ovn_client._nb_idl, 'update_lrouter_port') as ulrp:
            self.l3_plugin.schedule_unhosted_gateways()
            # Make sure that we don't schedule on chassis3
            # and do not updated the lrp port.
            ulrp.assert_not_called()

    def test_gateway_chassis_with_bridge_mappings_and_no_cms(self):
        # chassis1 is configured with proper bridge mappings,
        # but none of the chassis having enable-chassis-as-gw.
        # Test if chassis1 is selected as candidate or not.
        self._check_gateway_chassis_candidates([self.chassis1])

    def _l3_ha_supported(self):
        # If the Gateway_Chassis table exists in SB database, then it
        # means that L3 HA is supported.
        return self.nb_api.tables.get('Gateway_Chassis')

    def test_gateway_chassis_least_loaded_scheduler(self):
        # This test will create 4 routers each with its own gateway.
        # Using the least loaded policy for scheduling gateway ports, we
        # expect that they are equally distributed across the two available
        # chassis.
        ovn_client = self.l3_plugin._ovn_client
        ovn_client._ovn_scheduler = l3_sched.OVNGatewayLeastLoadedScheduler()
        ext1 = self._create_ext_network(
            'ext1', 'flat', 'physnet3', None, "20.0.0.1", "20.0.0.0/24")
        gw_info = {'network_id': ext1['network']['id']}

        # Create 4 routers with a gateway. Since we're using physnet3, the
        # chassis candidates will be chassis1 and chassis2.
        for i in range(1, 5):
            self._create_router('router%d' % i, gw_info=gw_info)

        # At this point we expect two gateways to be present in chassis1
        # and two in chassis2. If schema supports L3 HA, we expect each
        # chassis to host 2 priority 2 gateways and 2 priority 1 ones.
        if self._l3_ha_supported():
            # Each chassis contains a dict of (priority, # of ports hosted).
            # {1: 2, 2: 2} means that this chassis hosts 2 ports of prio 1
            # and two ports of prio 2.
            expected = {self.chassis1: {1: 2, 2: 2},
                        self.chassis2: {1: 2, 2: 2}}
        else:
            # For non L3 HA, each chassis should contain two gateway ports.
            expected = {self.chassis1: 2,
                        self.chassis2: 2}
        sched_info = {}
        for row in self.nb_api.tables[
                'Logical_Router_Port'].rows.values():
            if self._l3_ha_supported():
                for gwc in row.gateway_chassis:
                    chassis = sched_info.setdefault(gwc.chassis_name, {})
                    chassis[gwc.priority] = chassis.get(gwc.priority, 0) + 1
            else:
                rc = row.options.get(ovn_const.OVN_GATEWAY_CHASSIS_KEY)
                sched_info[rc] = sched_info.get(rc, 0) + 1
        self.assertEqual(expected, sched_info)

    def _get_gw_port(self, router_id):
        router = self.l3_plugin._get_router(self.context, router_id)
        gw_port_id = router.get('gw_port_id', '')
        for row in self.nb_api.tables['Logical_Router_Port'].rows.values():
            if row.name == 'lrp-%s' % gw_port_id:
                return row

    def test_gateway_chassis_with_subnet_changes(self):
        """Launchpad bug #1843485: logical router port is getting lost

        Test cases when subnets are added to an external network after router
        has been configured to use that network via "set --external-gateway"
        """

        ovn_client = self.l3_plugin._ovn_client

        with mock.patch.object(
                ovn_client._ovn_scheduler, 'select',
                return_value=[ovn_const.OVN_GATEWAY_INVALID_CHASSIS]) as \
                client_select:
            router1 = self._create_router('router1', gw_info=None)
            router_id = router1['id']
            self.assertIsNone(self._get_gw_port(router_id),
                              "router logical port unexpected before ext net")

            # Create external network with no subnets and assign it to router
            ext1 = self._create_ext_network(
                'ext1', 'flat', 'physnet3', None, gateway=None, cidr=None)
            net_id = ext1['network']['id']

            gw_info = {'network_id': ext1['network']['id']}
            self.l3_plugin.update_router(
                self.context, router_id,
                {'router': {l3_apidef.EXTERNAL_GW_INFO: gw_info}})
            self.assertIsNotNone(self._get_gw_port(router_id),
                                 "router logical port must exist after gw add")

            # Add subnets to external network. This should percolate
            # into l3_plugin.update_router()
            kwargs = {'ip_version': n_consts.IP_VERSION_4,
                      'gateway_ip': '10.0.0.1', 'cidr': '10.0.0.0/24'}
            subnet4_res = self._create_subnet(
                self.fmt, net_id, **kwargs)
            subnet4 = self.deserialize(self.fmt, subnet4_res).get('subnet')
            self.assertIsNotNone(self._get_gw_port(router_id),
                                 "router logical port must exist after v4 add")

            kwargs = {'ip_version': n_consts.IP_VERSION_6,
                      'gateway_ip': 'fe81::1', 'cidr': 'fe81::/64',
                      'ipv6_ra_mode': n_consts.IPV6_SLAAC,
                      'ipv6_address_mode': n_consts.IPV6_SLAAC}
            subnet6_res = self._create_subnet(
                self.fmt, net_id, **kwargs)
            subnet6 = self.deserialize(self.fmt, subnet6_res).get('subnet')
            self.assertIsNotNone(self._get_gw_port(router_id),
                                 "router logical port must exist after v6 add")

            self.assertGreaterEqual(client_select.call_count, 3)

            # Verify that ports have had the subnets created
            kwargs = {'device_owner': n_consts.DEVICE_OWNER_ROUTER_GW}
            ports_res = self._list_ports(self.fmt, net_id=net_id, **kwargs)
            ports = self.deserialize(self.fmt, ports_res).get('ports')
            subnet4_ip = None
            subnet6_ip = None
            for port in ports:
                for fixed_ip in port.get('fixed_ips', []):
                    if fixed_ip.get('subnet_id') == subnet4['id']:
                        subnet4_ip = fixed_ip.get('ip_address')
                    if fixed_ip.get('subnet_id') == subnet6['id']:
                        subnet6_ip = fixed_ip.get('ip_address')
            self.assertIsNotNone(subnet4_ip)
            self.assertIsNotNone(subnet6_ip)

            # Verify that logical router port is properly configured
            gw_port = self._get_gw_port(router_id)
            self.assertIsNotNone(gw_port)

            expected_networks = ['%s/24' % subnet4_ip, '%s/64' % subnet6_ip]
            self.assertItemsEqual(
                expected_networks, gw_port.networks,
                'networks in ovn port must match fixed_ips in neutron')

    def test_logical_router_port_creation(self):
        """Launchpad bug #1844652: Verify creation and removal of lrp

        This test verifies that logical router port is created and removed
        based on attaching and detaching the external network to a router.
        """
        router = self._create_router('router1', gw_info=None)
        router_id = router['id']
        self.assertIsNone(self._get_gw_port(router_id),
                          "router logical port unexpected before ext net")

        # Create external network and assign it to router
        ext1 = self._create_ext_network(
            'ext1', 'flat', 'physnet3', None, gateway=None, cidr=None)
        gw_info = {'network_id': ext1['network']['id']}
        self.l3_plugin.update_router(
            self.context, router_id,
            {'router': {l3_apidef.EXTERNAL_GW_INFO: gw_info}})
        self.assertIsNotNone(self._get_gw_port(router_id),
                             "router logical port missing after ext net add")

        # Un-assign external network from router
        self.l3_plugin.update_router(
            self.context, router_id,
            {'router': {l3_apidef.EXTERNAL_GW_INFO: None}})
        self.assertIsNone(self._get_gw_port(router_id),
                          "router logical port exists after ext net removal")

    def test_gateway_chassis_with_bridge_mappings(self):
        """Check selected ovn chassis based on external network

        This test sets different gateway values to ensure that the proper
        chassis are candidates, based on the physical network mappings.
        """

        ovn_client = self.l3_plugin._ovn_client
        # Create external networks with vlan, flat and geneve network types
        ext1 = self._create_ext_network(
            'ext1', 'vlan', 'physnet1', 1, "10.0.0.1", "10.0.0.0/24")
        ext2 = self._create_ext_network(
            'ext2', 'flat', 'physnet3', None, "20.0.0.1", "20.0.0.0/24")
        ext3 = self._create_ext_network(
            'ext3', 'geneve', None, 10, "30.0.0.1", "30.0.0.0/24")
        # mock select function and check if it is called with expected
        # candidates.
        self.candidates = []

        def fake_select(*args, **kwargs):
            self.assertItemsEqual(self.candidates, kwargs['candidates'])
            # We are not interested in further processing, let us return
            # INVALID_CHASSIS to avoid erros
            return [ovn_const.OVN_GATEWAY_INVALID_CHASSIS]

        with mock.patch.object(ovn_client._ovn_scheduler, 'select',
                               side_effect=fake_select) as client_select,\
            mock.patch.object(self.l3_plugin.scheduler, 'select',
                              side_effect=fake_select) as plugin_select:
            self.candidates = [self.chassis1]
            gw_info = {'network_id': ext1['network']['id']}
            router1 = self._create_router('router1', gw_info=gw_info)

            # set redirect-chassis to neutron-ovn-invalid-chassis, so
            # that schedule_unhosted_gateways will try to schedule it
            self._set_redirect_chassis_to_invalid_chassis(ovn_client)
            self.l3_plugin.schedule_unhosted_gateways()

            self.candidates = [self.chassis1, self.chassis2]
            gw_info = {'network_id': ext2['network']['id']}
            self.l3_plugin.update_router(
                self.context, router1['id'],
                {'router': {l3_apidef.EXTERNAL_GW_INFO: gw_info}})
            self._set_redirect_chassis_to_invalid_chassis(ovn_client)
            self.l3_plugin.schedule_unhosted_gateways()

            self.candidates = []
            gw_info = {'network_id': ext3['network']['id']}
            self.l3_plugin.update_router(
                self.context, router1['id'],
                {'router': {l3_apidef.EXTERNAL_GW_INFO: gw_info}})
            self._set_redirect_chassis_to_invalid_chassis(ovn_client)
            self.l3_plugin.schedule_unhosted_gateways()

            # We can't test call_count for these mocks, as we have disabled
            # maintenance_worker which will trigger chassis events
            # and eventually calling schedule_unhosted_gateways.
            # However, we know for sure that these mocks must have been
            # called at least 3 times because that is the number of times
            # this test invokes them: 1x create_router + 2x update_router
            # for client_select mock; and 3x schedule_unhosted_gateways for
            # plugin_select mock.
            self.assertGreaterEqual(client_select.call_count, 3)
            self.assertGreaterEqual(plugin_select.call_count, 3)

    def test_router_gateway_port_binding_host_id(self):
        # Test setting chassis on chassisredirect port in Port_Binding table,
        # will update host_id of corresponding router gateway port
        # with this chassis.
        chassis = idlutils.row_by_value(self.sb_api.idl, 'Chassis',
                                        'name', self.chassis1)
        host_id = chassis.hostname
        ext = self._create_ext_network(
            'ext1', 'vlan', 'physnet1', 1, "10.0.0.1", "10.0.0.0/24")
        gw_info = {'network_id': ext['network']['id']}
        router = self._create_router('router1', gw_info=gw_info)
        core_plugin = directory.get_plugin()
        gw_port_id = router.get('gw_port_id')

        # Set chassis on chassisredirect port in Port_Binding table
        logical_port = 'cr-lrp-%s' % gw_port_id
        self.assertTrue(self.cr_lrp_pb_event.wait(logical_port),
                        msg='lrp %s failed to bind' % logical_port)
        self.sb_api.lsp_bind(logical_port, self.chassis1,
                             may_exist=True).execute(check_error=True)

        def check_port_binding_host_id(port_id):
            port = core_plugin.get_ports(
                self.context, filters={'id': [port_id]})[0]
            return port[portbindings.HOST_ID] == host_id

        # Test if router gateway port updated with this chassis
        n_utils.wait_until_true(lambda: check_port_binding_host_id(
            gw_port_id))

    def _validate_router_ipv6_ra_configs(self, lrp_name, expected_ra_confs):
        lrp = idlutils.row_by_value(self.nb_api.idl,
                                    'Logical_Router_Port', 'name', lrp_name)
        self.assertEqual(expected_ra_confs, lrp.ipv6_ra_configs)

    def _test_router_port_ipv6_ra_configs_helper(
            self, cidr='aef0::/64', ip_version=6,
            address_mode=n_consts.IPV6_SLAAC,):
        router1 = self._create_router('router1')
        n1 = self._make_network(self.fmt, 'n1', True)
        if ip_version == 6:
            kwargs = {'ip_version': 6, 'cidr': 'aef0::/64',
                      'ipv6_address_mode': address_mode,
                      'ipv6_ra_mode': address_mode}
        else:
            kwargs = {'ip_version': 4, 'cidr': '10.0.0.0/24'}

        res = self._create_subnet(self.fmt, n1['network']['id'],
                                  **kwargs)

        n1_s1 = self.deserialize(self.fmt, res)
        n1_s1_id = n1_s1['subnet']['id']
        router_iface_info = self.l3_plugin.add_router_interface(
            self.context, router1['id'], {'subnet_id': n1_s1_id})

        lrp_name = ovn_utils.ovn_lrouter_port_name(
            router_iface_info['port_id'])
        if ip_version == 6:
            expected_ra_configs = {
                'address_mode': ovn_utils.get_ovn_ipv6_address_mode(
                    address_mode),
                'send_periodic': 'true',
                'mtu': '1450'}
        else:
            expected_ra_configs = {}
        self._validate_router_ipv6_ra_configs(lrp_name, expected_ra_configs)

    def test_router_port_ipv6_ra_configs_addr_mode_slaac(self):
        self._test_router_port_ipv6_ra_configs_helper()

    def test_router_port_ipv6_ra_configs_addr_mode_dhcpv6_stateful(self):
        self._test_router_port_ipv6_ra_configs_helper(
            address_mode=n_consts.DHCPV6_STATEFUL)

    def test_router_port_ipv6_ra_configs_addr_mode_dhcpv6_stateless(self):
        self._test_router_port_ipv6_ra_configs_helper(
            address_mode=n_consts.DHCPV6_STATELESS)

    def test_router_port_ipv6_ra_configs_ipv4(self):
        self._test_router_port_ipv6_ra_configs_helper(
            ip_version=4)

    def test_gateway_chassis_rebalance(self):
        def _get_result_dict():
            sched_info = {}
            for row in self.nb_api.tables[
                    'Logical_Router_Port'].rows.values():
                for gwc in row.gateway_chassis:
                    chassis = sched_info.setdefault(gwc.chassis_name, {})
                    chassis[gwc.priority] = chassis.get(gwc.priority, 0) + 1
            return sched_info

        if not self._l3_ha_supported():
            self.skipTest('L3 HA not supported')
        ovn_client = self.l3_plugin._ovn_client
        chassis4 = self.add_fake_chassis(
            'ovs-host4', physical_nets=['physnet4'], external_ids={
                'ovn-cms-options': 'enable-chassis-as-gw'})
        ovn_client._ovn_scheduler = l3_sched.OVNGatewayLeastLoadedScheduler()
        ext1 = self._create_ext_network(
            'ext1', 'flat', 'physnet4', None, "30.0.0.1", "30.0.0.0/24")
        gw_info = {'network_id': ext1['network']['id']}
        # Create 20 routers with a gateway. Since we're using physnet4, the
        # chassis candidates will be chassis4 initially.
        for i in range(20):
            router = self._create_router('router%d' % i, gw_info=gw_info)
            gw_port_id = router.get('gw_port_id')
            logical_port = 'cr-lrp-%s' % gw_port_id
            self.assertTrue(self.cr_lrp_pb_event.wait(logical_port),
                            msg='lrp %s failed to bind' % logical_port)
            self.sb_api.lsp_bind(logical_port, chassis4,
                                 may_exist=True).execute(check_error=True)
        self.l3_plugin.schedule_unhosted_gateways()
        expected = {chassis4: {1: 20}}
        self.assertEqual(expected, _get_result_dict())

        # Add another chassis as a gateway chassis
        chassis5 = self.add_fake_chassis(
            'ovs-host5', physical_nets=['physnet4'], external_ids={
                'ovn-cms-options': 'enable-chassis-as-gw'})
        # Add a node as compute node. Compute node wont be
        # used to schedule the router gateway ports therefore
        # priority values wont be changed. Therefore chassis4 would
        # still have priority 2
        self.add_fake_chassis('ovs-host6', physical_nets=['physnet4'])

        # Chassis4 should have all ports at Priority 2
        self.l3_plugin.schedule_unhosted_gateways()
        self.assertEqual({2: 20}, _get_result_dict()[chassis4])
        # Chassis5 should have all ports at Priority 1
        self.assertEqual({1: 20}, _get_result_dict()[chassis5])

        # delete chassis that hosts all the gateways
        self.del_fake_chassis(chassis4)
        self.l3_plugin.schedule_unhosted_gateways()

        # As Chassis4 has been removed so all gateways that were
        # hosted there are now primaries on chassis5 and have
        # priority 1.
        self.assertEqual({1: 20}, _get_result_dict()[chassis5])

    def test_gateway_chassis_rebalance_max_chassis(self):
        chassis_list = []
        # spawn 6 chassis and check if port has MAX_CHASSIS candidates.
        for i in range(0, ovn_const.MAX_GW_CHASSIS + 1):
            chassis_list.append(
                self.add_fake_chassis(
                    'ovs-host%s' % i, physical_nets=['physnet1'],
                    external_ids={
                        'ovn-cms-options': 'enable-chassis-as-gw'}))

        ext1 = self._create_ext_network(
            'ext1', 'vlan', 'physnet1', 1, "10.0.0.1", "10.0.0.0/24")
        gw_info = {'network_id': ext1['network']['id']}
        router = self._create_router('router', gw_info=gw_info)
        gw_port_id = router.get('gw_port_id')
        logical_port = 'cr-lrp-%s' % gw_port_id
        self.assertTrue(self.cr_lrp_pb_event.wait(logical_port),
                        msg='lrp %s failed to bind' % logical_port)
        self.sb_api.lsp_bind(logical_port, chassis_list[0],
                             may_exist=True).execute(check_error=True)

        self.l3_plugin.schedule_unhosted_gateways()
        for row in self.nb_api.tables[
                'Logical_Router_Port'].rows.values():
            self.assertEqual(ovn_const.MAX_GW_CHASSIS,
                             len(row.gateway_chassis))
