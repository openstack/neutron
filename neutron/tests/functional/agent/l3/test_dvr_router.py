# Copyright (c) 2014 Red Hat, Inc.
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
import functools
from unittest import mock

import netaddr
from neutron_lib.api.definitions import portbindings
from neutron_lib import constants as lib_constants
from neutron_lib.exceptions import l3 as l3_exc
import testtools

from neutron.agent.l3 import agent as neutron_l3_agent
from neutron.agent.l3 import dvr_edge_ha_router as dvr_ha_router
from neutron.agent.l3 import dvr_edge_router
from neutron.agent.l3 import dvr_fip_ns
from neutron.agent.l3 import dvr_local_router
from neutron.agent.l3 import dvr_snat_ns
from neutron.agent.l3 import namespaces
from neutron.agent.linux import ip_lib
from neutron.agent.linux import iptables_manager
from neutron.common import utils
from neutron.tests.common import l3_test_common
from neutron.tests.common import machine_fixtures
from neutron.tests.common import net_helpers
from neutron.tests.functional.agent.l3 import framework


DEVICE_OWNER_COMPUTE = lib_constants.DEVICE_OWNER_COMPUTE_PREFIX + 'fake'


class DvrRouterTestFramework(framework.L3AgentTestFramework):

    def generate_dvr_router_info(self,
                                 enable_ha=False,
                                 enable_snat=False,
                                 enable_gw=True,
                                 snat_bound_fip=False,
                                 agent=None,
                                 extra_routes=False,
                                 enable_floating_ip=True,
                                 enable_centralized_fip=False,
                                 vrrp_id=None,
                                 **kwargs):
        if not agent:
            agent = self.agent
        router = l3_test_common.prepare_router_data(
            enable_snat=enable_snat,
            enable_floating_ip=enable_floating_ip,
            enable_ha=enable_ha,
            extra_routes=extra_routes,
            num_internal_ports=2,
            enable_gw=enable_gw,
            snat_bound_fip=snat_bound_fip,
            vrrp_id=vrrp_id,
            **kwargs)
        internal_ports = router.get(lib_constants.INTERFACE_KEY, [])
        router['distributed'] = True
        router['gw_port_host'] = agent.conf.host
        if enable_floating_ip:
            for floating_ip in router[lib_constants.FLOATINGIP_KEY]:
                floating_ip['host'] = agent.conf.host

        if enable_floating_ip and enable_centralized_fip:
            # For centralizing the fip, we are emulating the legacy
            # router behavior were the fip dict does not contain any
            # host information.
            router[lib_constants.FLOATINGIP_KEY][0]['host'] = None

        # In order to test the mixed dvr_snat and compute scenario, we create
        # two floating IPs, one is distributed, another is centralized.
        # The distributed floating IP should have the host, which was
        # just set to None above, then we set it back. The centralized
        # floating IP has host None, and this IP will be used to test
        # migration from centralized to distributed.
        if snat_bound_fip:
            router[lib_constants.FLOATINGIP_KEY][0]['host'] = agent.conf.host
            router[lib_constants.FLOATINGIP_KEY][1][
                lib_constants.DVR_SNAT_BOUND] = True
            router[lib_constants.FLOATINGIP_KEY][1]['host'] = None

        if enable_gw:
            external_gw_port = router['gw_port']
            router['gw_port'][portbindings.HOST_ID] = agent.conf.host
            self._add_snat_port_info_to_router(router, internal_ports)
            # FIP has a dependency on external gateway. So we need to create
            # the snat_port info and fip_agent_gw_port_info irrespective of
            # the agent type the dvr supports. The namespace creation is
            # dependent on the agent_type.
            if enable_floating_ip:
                for index, floating_ip in enumerate(router['_floatingips']):
                    floating_ip['floating_network_id'] = (
                        external_gw_port['network_id'])
                    floating_ip['port_id'] = internal_ports[index]['id']
                    floating_ip['status'] = 'ACTIVE'

            self._add_fip_agent_gw_port_info_to_router(router,
                                                       external_gw_port)
        # Router creation is delegated to router_factory. We have to
        # re-register here so that factory can find override agent mode
        # normally.
        self.agent._register_router_cls(self.agent.router_factory)
        return router

    def _add_fip_agent_gw_port_info_to_router(self, router, external_gw_port):
        # Add fip agent gateway port information to the router_info
        fip_gw_port_list = router.get(
            lib_constants.FLOATINGIP_AGENT_INTF_KEY, [])
        if not fip_gw_port_list and external_gw_port:
            # Get values from external gateway port
            fixed_ip = external_gw_port['fixed_ips'][0]
            float_subnet = external_gw_port['subnets'][0]
            port_ip = fixed_ip['ip_address']
            # Pick an ip address which is not the same as port_ip
            fip_gw_port_ip = str(netaddr.IPAddress(port_ip) + 5)
            # Add floatingip agent gateway port info to router
            prefixlen = netaddr.IPNetwork(float_subnet['cidr']).prefixlen
            router[lib_constants.FLOATINGIP_AGENT_INTF_KEY] = [
                {'subnets': [
                    {'cidr': float_subnet['cidr'],
                     'gateway_ip': float_subnet['gateway_ip'],
                     'id': fixed_ip['subnet_id']}],
                 'extra_subnets': external_gw_port['extra_subnets'],
                 'network_id': external_gw_port['network_id'],
                 'device_owner': lib_constants.DEVICE_OWNER_AGENT_GW,
                 'mac_address': 'fa:16:3e:80:8d:89',
                 portbindings.HOST_ID: self.agent.conf.host,
                 'fixed_ips': [{'subnet_id': fixed_ip['subnet_id'],
                                'ip_address': fip_gw_port_ip,
                                'prefixlen': prefixlen}],
                 'id': framework._uuid(),
                 'device_id': framework._uuid()}
            ]

    def _add_snat_port_info_to_router(self, router, internal_ports):
        # Add snat port information to the router
        snat_port_list = router.get(lib_constants.SNAT_ROUTER_INTF_KEY, [])
        if not snat_port_list and internal_ports:
            router[lib_constants.SNAT_ROUTER_INTF_KEY] = []
            for port in internal_ports:
                # Get values from internal port
                fixed_ip = port['fixed_ips'][0]
                snat_subnet = port['subnets'][0]
                port_ip = fixed_ip['ip_address']
                # Pick an ip address which is not the same as port_ip
                snat_ip = str(netaddr.IPAddress(port_ip) + 5)
                # Add the info to router as the first snat port
                # in the list of snat ports
                prefixlen = netaddr.IPNetwork(snat_subnet['cidr']).prefixlen
                snat_router_port = {
                    'subnets': [
                        {'cidr': snat_subnet['cidr'],
                         'gateway_ip': snat_subnet['gateway_ip'],
                         'id': fixed_ip['subnet_id']}],
                    'network_id': port['network_id'],
                    'device_owner': lib_constants.DEVICE_OWNER_ROUTER_SNAT,
                    'mac_address': 'fa:16:3e:80:8d:89',
                    'fixed_ips': [{'subnet_id': fixed_ip['subnet_id'],
                                   'ip_address': snat_ip,
                                   'prefixlen': prefixlen}],
                    'id': framework._uuid(),
                    'device_id': framework._uuid()}
                # Get the address scope if there is any
                if 'address_scopes' in port:
                    snat_router_port['address_scopes'] = port['address_scopes']
                router[lib_constants.SNAT_ROUTER_INTF_KEY].append(
                    snat_router_port)


class TestDvrRouter(DvrRouterTestFramework, framework.L3AgentTestFramework):
    def manage_router(self, agent, router):
        def _safe_fipnamespace_delete_on_ext_net(ext_net_id):
            try:
                agent.fipnamespace_delete_on_ext_net(None, ext_net_id)
            except RuntimeError:
                pass
        if router['gw_port']:
            self.addCleanup(
                _safe_fipnamespace_delete_on_ext_net,
                router['gw_port']['network_id'])

        return super(TestDvrRouter, self).manage_router(agent, router)

    def test_dvr_update_floatingip_statuses(self):
        self.agent.conf.agent_mode = 'dvr'
        self._test_update_floatingip_statuses(self.generate_dvr_router_info())

    def test_dvr_router_lifecycle_without_ha_without_snat_with_fips(self):
        self._dvr_router_lifecycle(enable_ha=False, enable_snat=False)

    def test_dvr_router_lifecycle_without_ha_with_snat_with_fips(self):
        self._dvr_router_lifecycle(enable_ha=False, enable_snat=True)

    def test_dvr_router_lifecycle_ha_with_snat_with_fips(self):
        self._dvr_router_lifecycle(enable_ha=True, enable_snat=True)

    def test_dvr_lifecycle_no_ha_with_snat_with_fips_with_cent_fips(self):
        self._dvr_router_lifecycle(enable_ha=False, enable_snat=True,
                                   snat_bound_fip=True)

    def test_dvr_lifecycle_ha_with_snat_with_fips_with_cent_fips(self):
        self._dvr_router_lifecycle(enable_ha=True, enable_snat=True,
                                   snat_bound_fip=True)

    def test_dvr_lifecycle_no_ha_with_snat_with_fips_with_cent_fips_no_gw(
            self):
        self._dvr_router_lifecycle(enable_ha=False, enable_snat=True,
                                   snat_bound_fip=True, enable_gw=False)

    def test_dvr_lifecycle_ha_with_snat_with_fips_with_cent_fips_no_gw(self):
        self._dvr_router_lifecycle(enable_ha=True, enable_snat=True,
                                   snat_bound_fip=True, enable_gw=False)

    def _check_routes(self, expected_routes, actual_routes):
        actual_routes = [{key: route[key] for key in expected_routes[0].keys()}
                         for route in actual_routes]
        self.assertEqual(expected_routes, actual_routes)

    def _helper_create_dvr_router_fips_for_ext_network(
            self, agent_mode, **dvr_router_kwargs):
        self.agent.conf.agent_mode = agent_mode
        router_info = self.generate_dvr_router_info(**dvr_router_kwargs)
        router = self.manage_router(self.agent, router_info)
        fip_ns = router.fip_ns.get_name()
        return router, fip_ns

    def _validate_fips_for_external_network(self, router, fip_ns):
        self.assertTrue(self._namespace_exists(router.ns_name))
        self.assertTrue(self._namespace_exists(fip_ns))
        self._assert_dvr_floating_ips(router)
        self._assert_snat_namespace_does_not_exist(router)

    def test_dvr_gateway_move_does_not_remove_redirect_rules(self):
        """Test to validate snat redirect rules not cleared with snat move."""
        self.agent.conf.agent_mode = 'dvr_snat'
        router_info = self.generate_dvr_router_info(enable_snat=True)
        router1 = self.manage_router(self.agent, router_info)
        router1.router['gw_port_host'] = ""
        self.agent._process_updated_router(router1.router)
        router_updated = self.agent.router_info[router1.router['id']]
        self.assertTrue(self._namespace_exists(router_updated.ns_name))
        ip4_rules_list = ip_lib.list_ip_rules(router1.ns_name,
                                              lib_constants.IP_VERSION_4)
        self.assertEqual(6, len(ip4_rules_list))
        # list_ip_rules list should have 6 entries.
        # Three entries from 'default', 'main' and 'local' table.
        # One rule for the floatingip.
        # The remaining 2 is for the two router interfaces(csnat ports).
        default_rules_list_count = 0
        interface_rules_list_count = 0
        for ip_rule in ip4_rules_list:
            tbl_index = ip_rule['table']
            if tbl_index in ['local', 'default', 'main',
                             str(dvr_fip_ns.FIP_RT_TBL)]:
                default_rules_list_count = default_rules_list_count + 1
            else:
                interface_rules_list_count = interface_rules_list_count + 1
        self.assertEqual(4, default_rules_list_count)
        self.assertEqual(2, interface_rules_list_count)

    def test_dvr_update_gateway_port_no_fip_fg_port_recovers_itself_with_fpr(
            self):
        self.agent.conf.agent_mode = 'dvr'
        # Create the router with external net
        router_info = self.generate_dvr_router_info()
        external_gw_port = router_info['gw_port']
        router = self.manage_router(self.agent, router_info)
        fg_port = router.fip_ns.agent_gateway_port
        fg_port_name = router.fip_ns.get_ext_device_name(fg_port['id'])
        fg_device = ip_lib.IPDevice(fg_port_name,
                                    namespace=router.fip_ns.name)
        fip_2_rtr_name = router.fip_ns.get_int_device_name(router.router_id)
        fpr_device = ip_lib.IPDevice(fip_2_rtr_name,
                                     namespace=router.fip_ns.name)
        # Now validate if the gateway is properly configured.
        rtr_2_fip, fip_2_rtr = router.rtr_fip_subnet.get_pair()
        tbl_index = router._get_snat_idx(fip_2_rtr)
        self.assertIn('via', fg_device.route.get_gateway(table=tbl_index))
        self._validate_fips_for_external_network(
            router, router.fip_ns.get_name())
        # Now delete the fg- port that was created
        router.fip_ns.driver.unplug(fg_port_name,
                                    namespace=router.fip_ns.name,
                                    prefix=dvr_fip_ns.FIP_EXT_DEV_PREFIX)
        # Now check if the fg- port is missing.
        self.assertFalse(fg_device.exists())
        fpr_device.link.set_down()
        # Now change the gateway ip for the router and do an update.
        router.ex_gw_port = copy.deepcopy(router.ex_gw_port)
        new_fg_port = copy.deepcopy(fg_port)
        for subnet in new_fg_port['subnets']:
            subnet['gateway_ip'] = '19.4.4.2'
        router.router[lib_constants.FLOATINGIP_AGENT_INTF_KEY] = [new_fg_port]
        self.assertRaises(l3_exc.FloatingIpSetupException,
                          self.agent._process_updated_router,
                          router.router)
        self.agent._process_updated_router(router.router)
        self.assertTrue(fg_device.exists())
        self.assertTrue(fpr_device.exists())
        updated_route = fg_device.route.list_routes(
                ip_version=lib_constants.IP_VERSION_4,
                table=tbl_index)
        expected_route = [{'cidr': '0.0.0.0/0',
                           'device': fg_port_name,
                           'table': tbl_index,
                           'via': '19.4.4.2'}]
        self._check_routes(expected_route, updated_route)
        self._validate_fips_for_external_network(
            router, router.fip_ns.get_name())
        self._delete_router(self.agent, router.router_id)
        self._assert_fip_namespace_deleted(external_gw_port)

    def test_dvr_update_gateway_port_with_no_gw_port_in_namespace(self):
        self.agent.conf.agent_mode = 'dvr'

        # Create the router with external net
        router_info = self.generate_dvr_router_info()
        external_gw_port = router_info['gw_port']
        router = self.manage_router(self.agent, router_info)
        fg_port = router.fip_ns.agent_gateway_port
        fg_port_name = router.fip_ns.get_ext_device_name(fg_port['id'])
        fg_device = ip_lib.IPDevice(fg_port_name,
                                    namespace=router.fip_ns.name)
        # Now validate if the gateway is properly configured.
        rtr_2_fip, fip_2_rtr = router.rtr_fip_subnet.get_pair()
        tbl_index = router._get_snat_idx(fip_2_rtr)
        self.assertIn('via', fg_device.route.get_gateway(table=tbl_index))
        self._validate_fips_for_external_network(
            router, router.fip_ns.get_name())
        # Now delete the fg- port that was created
        router.fip_ns.driver.unplug(fg_port_name,
                                    namespace=router.fip_ns.name,
                                    prefix=dvr_fip_ns.FIP_EXT_DEV_PREFIX)
        # Now check if the fg- port is missing.
        self.assertFalse(fg_device.exists())
        # Now change the gateway ip for the router and do an update.
        router.ex_gw_port = copy.deepcopy(router.ex_gw_port)
        new_fg_port = copy.deepcopy(fg_port)
        for subnet in new_fg_port['subnets']:
            subnet['gateway_ip'] = '19.4.4.2'
        router.router[lib_constants.FLOATINGIP_AGENT_INTF_KEY] = [new_fg_port]
        self.assertRaises(l3_exc.FloatingIpSetupException,
                          self.manage_router,
                          self.agent,
                          router.router)
        router = self.manage_router(self.agent, router.router)
        self.assertTrue(fg_device.exists())
        updated_route = fg_device.route.list_routes(
                ip_version=lib_constants.IP_VERSION_4,
                table=tbl_index)
        expected_route = [{'cidr': '0.0.0.0/0',
                           'device': fg_port_name,
                           'table': tbl_index,
                           'via': '19.4.4.2'}]
        self._check_routes(expected_route, updated_route)
        self._validate_fips_for_external_network(
            router, router.fip_ns.get_name())
        self._delete_router(self.agent, router.router_id)
        self._assert_fip_namespace_deleted(external_gw_port)

    @mock.patch.object(dvr_fip_ns.FipNamespace, 'subscribe')
    def test_dvr_process_fips_with_no_gw_port_in_namespace(self,
                                                           fip_subscribe):
        self.agent.conf.agent_mode = 'dvr'

        # Create the router with external net
        router_info = self.generate_dvr_router_info()
        external_gw_port = router_info['gw_port']
        ext_net_id = router_info['_floatingips'][0]['floating_network_id']

        # Create the fip namespace up front
        fip_ns = dvr_fip_ns.FipNamespace(ext_net_id,
                                         self.agent.conf,
                                         self.agent.driver,
                                         self.agent.use_ipv6)
        fip_ns.create()
        # Create the router with the fip, this shouldn't allow the
        # update_gateway_port to be called without the fg- port
        fip_subscribe.return_value = False
        fip_ns.agent_gateway_port = (
            router_info[lib_constants.FLOATINGIP_AGENT_INTF_KEY])
        # This will raise the exception and will also clear
        # subscription for the ext_net_id
        self.assertRaises(l3_exc.FloatingIpSetupException,
                          self.manage_router,
                          self.agent,
                          router_info)
        fip_subscribe.return_value = True
        self.manage_router(self.agent, router_info)
        # Now update the router again
        router = self.manage_router(self.agent, router_info)
        fg_port = router.fip_ns.agent_gateway_port
        fg_port_name = router.fip_ns.get_ext_device_name(fg_port['id'])
        fg_device = ip_lib.IPDevice(fg_port_name,
                                    namespace=router.fip_ns.name)
        rtr_2_fip, fip_2_rtr = router.rtr_fip_subnet.get_pair()
        tbl_index = router._get_snat_idx(fip_2_rtr)
        # Now validate if the gateway is properly configured.
        self.assertIn('via', fg_device.route.get_gateway(table=tbl_index))
        self._validate_fips_for_external_network(
            router, router.fip_ns.get_name())
        self._delete_router(self.agent, router.router_id)
        self._assert_fip_namespace_deleted(external_gw_port)

    def test_dvr_router_fips_stale_gw_port(self):
        self.agent.conf.agent_mode = 'dvr'

        # Create the router with external net
        dvr_router_kwargs = {'ip_address': '19.4.4.3',
                             'subnet_cidr': '19.4.4.0/24',
                             'gateway_ip': '19.4.4.1',
                             'gateway_mac': 'ca:fe:de:ab:cd:ef'}
        router_info = self.generate_dvr_router_info(**dvr_router_kwargs)
        external_gw_port = router_info['gw_port']
        ext_net_id = router_info['_floatingips'][0]['floating_network_id']

        # Create the fip namespace up front
        stale_fip_ns = dvr_fip_ns.FipNamespace(ext_net_id,
                                               self.agent.conf,
                                               self.agent.driver,
                                               self.agent.use_ipv6)
        stale_fip_ns.create()

        # Add a stale fg port to the namespace
        fixed_ip = external_gw_port['fixed_ips'][0]
        float_subnet = external_gw_port['subnets'][0]
        fip_gw_port_ip = str(netaddr.IPAddress(fixed_ip['ip_address']) + 10)
        prefixlen = netaddr.IPNetwork(float_subnet['cidr']).prefixlen
        stale_agent_gw_port = {
            'subnets': [{'cidr': float_subnet['cidr'],
                         'gateway_ip': float_subnet['gateway_ip'],
                         'id': fixed_ip['subnet_id']}],
            'network_id': external_gw_port['network_id'],
            'device_owner': lib_constants.DEVICE_OWNER_AGENT_GW,
            'mac_address': 'fa:16:3e:80:8f:89',
            portbindings.HOST_ID: self.agent.conf.host,
            'fixed_ips': [{'subnet_id': fixed_ip['subnet_id'],
                           'ip_address': fip_gw_port_ip,
                           'prefixlen': prefixlen}],
            'id': framework._uuid(),
            'device_id': framework._uuid()}
        stale_fip_ns.create_or_update_gateway_port(stale_agent_gw_port)

        stale_dev_exists = self.device_exists_with_ips_and_mac(
                stale_agent_gw_port,
                stale_fip_ns.get_ext_device_name,
                stale_fip_ns.get_name())
        self.assertTrue(stale_dev_exists)

        # Create the router, this shouldn't allow the duplicate port to stay
        router = self.manage_router(self.agent, router_info)

        # Assert the device no longer exists
        stale_dev_exists = self.device_exists_with_ips_and_mac(
                stale_agent_gw_port,
                stale_fip_ns.get_ext_device_name,
                stale_fip_ns.get_name())
        self.assertFalse(stale_dev_exists)

        # Validate things are looking good and clean up
        self._validate_fips_for_external_network(
            router, router.fip_ns.get_name())
        ext_gateway_port = router_info['gw_port']
        self._delete_router(self.agent, router.router_id)
        self._assert_fip_namespace_deleted(ext_gateway_port)

    def test_dvr_router_gateway_redirect_cleanup_on_agent_restart(self):
        """Test to validate the router namespace gateway redirect rule cleanup.

        This test checks for the non existence of the gateway redirect
        rules in the router namespace after the agent restarts while the
        gateway is removed for the router.
        """
        self.agent.conf.agent_mode = 'dvr_snat'
        router_info = self.generate_dvr_router_info()
        router1 = self.manage_router(self.agent, router_info)
        self._assert_snat_namespace_exists(router1)
        self.assertTrue(self._namespace_exists(router1.ns_name))
        restarted_agent = neutron_l3_agent.L3NATAgentWithStateReport(
            self.agent.host, self.agent.conf)
        router1.router['gw_port'] = ""
        router1.router['gw_port_host'] = ""
        router1.router['external_gateway_info'] = ""
        restarted_router = self.manage_router(restarted_agent, router1.router)
        self.assertTrue(self._namespace_exists(restarted_router.ns_name))
        ip4_rules_list = ip_lib.list_ip_rules(router1.ns_name,
                                              lib_constants.IP_VERSION_4)
        ip6_rules_list = ip_lib.list_ip_rules(router1.ns_name,
                                              lib_constants.IP_VERSION_6)
        # Just make sure the basic set of rules are there in the router
        # namespace
        self.assertEqual(3, len(ip4_rules_list))
        self.assertEqual(2, len(ip6_rules_list))

    def test_dvr_unused_snat_ns_deleted_when_agent_restarts_after_move(self):
        """Test to validate the stale snat namespace delete with snat move.

        This test validates the stale snat namespace cleanup when
        the agent restarts after the gateway port has been moved
        from the agent.
        """
        self.agent.conf.agent_mode = 'dvr_snat'
        router_info = self.generate_dvr_router_info()
        router1 = self.manage_router(self.agent, router_info)
        self._assert_snat_namespace_exists(router1)
        restarted_agent = neutron_l3_agent.L3NATAgentWithStateReport(
            self.agent.host, self.agent.conf)
        router1.router['gw_port_host'] = "my-new-host"
        restarted_router = self.manage_router(restarted_agent, router1.router)
        self._assert_snat_namespace_does_not_exist(restarted_router)

    def test_dvr_router_fips_for_multiple_ext_networks(self):
        agent_mode = 'dvr'
        # Create the first router fip with external net1
        dvr_router1_kwargs = {'ip_address': '19.4.4.3',
                              'subnet_cidr': '19.4.4.0/24',
                              'gateway_ip': '19.4.4.1',
                              'gateway_mac': 'ca:fe:de:ab:cd:ef'}
        router1, fip1_ns = (
            self._helper_create_dvr_router_fips_for_ext_network(
                agent_mode, **dvr_router1_kwargs))
        # Validate the fip with external net1
        self._validate_fips_for_external_network(router1, fip1_ns)

        # Create the second router fip with external net2
        dvr_router2_kwargs = {'ip_address': '19.4.5.3',
                              'subnet_cidr': '19.4.5.0/24',
                              'gateway_ip': '19.4.5.1',
                              'gateway_mac': 'ca:fe:de:ab:cd:fe'}
        router2, fip2_ns = (
            self._helper_create_dvr_router_fips_for_ext_network(
                agent_mode, **dvr_router2_kwargs))
        # Validate the fip with external net2
        self._validate_fips_for_external_network(router2, fip2_ns)

    def _dvr_router_lifecycle(self, enable_ha=False, enable_snat=False,
                              custom_mtu=2000,
                              ip_version=lib_constants.IP_VERSION_4,
                              dual_stack=False,
                              snat_bound_fip=False,
                              enable_gw=True):
        '''Test dvr router lifecycle

        :param enable_ha: sets the ha value for the router.
        :param enable_snat:  the value of enable_snat is used
        to  set the  agent_mode.
        '''

        # The value of agent_mode can be dvr, dvr_snat, or legacy.
        # Since by definition this is a dvr (distributed = true)
        # only dvr and dvr_snat are applicable
        self.agent.conf.agent_mode = 'dvr_snat' if enable_snat else 'dvr'

        # We get the router info particular to a dvr router
        router_info = self.generate_dvr_router_info(
            enable_ha, enable_snat, extra_routes=True,
            snat_bound_fip=snat_bound_fip, enable_gw=enable_gw)
        for key in ('_interfaces', '_snat_router_interfaces',
                    '_floatingip_agent_interfaces'):
            for port in router_info.get(key, []):
                port['mtu'] = custom_mtu
        if router_info['gw_port']:
            router_info['gw_port']['mtu'] = custom_mtu
        if enable_ha:
            router_info['_ha_interface']['mtu'] = custom_mtu

        # We need to mock the get_agent_gateway_port return value
        # because the whole L3PluginApi is mocked and we need the port
        # gateway_port information before the l3_agent will create it.
        # The port returned needs to have the same information as
        # router_info['gw_port']
        fip_agent_gw_port = self._get_fip_agent_gw_port_for_router(
            router_info['gw_port'])
        self.mock_plugin_api.get_agent_gateway_port.return_value = (
            fip_agent_gw_port)

        # With all that set we can now ask the l3_agent to
        # manage the router (create it, create namespaces,
        # attach interfaces, etc...)
        router = self.manage_router(self.agent, router_info)
        if enable_ha and not enable_gw:
            port = router.get_ex_gw_port()
            self.assertEqual({}, port)
        elif enable_ha and enable_gw:
            port = router.get_ex_gw_port()
            interface_name = router.get_external_device_name(port['id'])
            self._assert_no_ip_addresses_on_interface(router.ha_namespace,
                                                      interface_name)
            self.wait_until_ha_router_has_state(router, 'primary')

            # Keepalived notifies of a state transition when it starts,
            # not when it ends. Thus, we have to wait until keepalived finishes
            # configuring everything. We verify this by waiting until the last
            # device has an IP address.
            device = router.router[lib_constants.INTERFACE_KEY][-1]
            device_exists = functools.partial(
                self.device_exists_with_ips_and_mac,
                device,
                router.get_internal_device_name,
                router.ns_name)
            utils.wait_until_true(device_exists)
            name = router.get_internal_device_name(device['id'])
            self.assertEqual(custom_mtu,
                             ip_lib.IPDevice(name, router.ns_name).link.mtu)

        ext_gateway_port = router_info['gw_port']
        self.assertTrue(self._namespace_exists(router.ns_name))
        utils.wait_until_true(
            lambda: self._metadata_proxy_exists(self.agent.conf, router))
        self._assert_internal_devices(router)
        self._assert_dvr_external_device(router, enable_gw)
        self._assert_dvr_gateway(router, enable_gw)
        self._assert_dvr_floating_ips(router, snat_bound_fip=snat_bound_fip,
                                      enable_gw=enable_gw)
        self._assert_snat_chains(router, enable_gw=enable_gw)
        self._assert_floating_ip_chains(router, snat_bound_fip=snat_bound_fip,
                                        enable_gw=enable_gw)
        self._assert_metadata_chains(router)
        self._assert_rfp_fpr_mtu(router, custom_mtu, enable_gw=enable_gw)
        if enable_snat:
            if (ip_version == lib_constants.IP_VERSION_6 or dual_stack):
                ip_versions = [lib_constants.IP_VERSION_4,
                               lib_constants.IP_VERSION_6]
            else:
                ip_versions = [lib_constants.IP_VERSION_4]
            snat_ns_name = dvr_snat_ns.SnatNamespace.get_snat_ns_name(
                router.router_id)
            self._assert_onlink_subnet_routes(
                router, ip_versions, snat_ns_name, enable_gw=enable_gw)
            self._assert_extra_routes(router, namespace=snat_ns_name,
                                      enable_gw=enable_gw)

        # During normal operation, a router-gateway-clear followed by
        # a router delete results in two notifications to the agent.  This
        # code flow simulates the exceptional case where the notification of
        # the clearing of the gateway hast been missed, so we are checking
        # that the L3 agent is robust enough to handle that case and delete
        # the router correctly.
        self._delete_router(self.agent, router.router_id)
        self._assert_fip_namespace_deleted(ext_gateway_port,
                                           enable_gw=enable_gw)
        self._assert_router_does_not_exist(router)
        self._assert_snat_namespace_does_not_exist(router)

    def _get_fip_agent_gw_port_for_router(self, external_gw_port):
        # Add fip agent gateway port information to the router_info
        if external_gw_port:
            # Get values from external gateway port
            fixed_ip = external_gw_port['fixed_ips'][0]
            float_subnet = external_gw_port['subnets'][0]
            port_ip = fixed_ip['ip_address']
            # Pick an ip address which is not the same as port_ip
            fip_gw_port_ip = str(netaddr.IPAddress(port_ip) + 5)
            # Add floatingip agent gateway port info to router
            prefixlen = netaddr.IPNetwork(float_subnet['cidr']).prefixlen
            fip_agent_gw_port_info = {
                'subnets': [
                    {'cidr': float_subnet['cidr'],
                     'gateway_ip': float_subnet['gateway_ip'],
                     'id': fixed_ip['subnet_id']}],
                'extra_subnets': external_gw_port['extra_subnets'],
                'network_id': external_gw_port['network_id'],
                'device_owner': lib_constants.DEVICE_OWNER_AGENT_GW,
                'mac_address': 'fa:16:3e:80:8d:89',
                portbindings.HOST_ID: self.agent.conf.host,
                'fixed_ips': [{'subnet_id': fixed_ip['subnet_id'],
                               'ip_address': fip_gw_port_ip,
                               'prefixlen': prefixlen}],
                'id': framework._uuid(),
                'device_id': framework._uuid()
            }
            return fip_agent_gw_port_info

    def _assert_dvr_external_device(self, router, enable_gw):
        external_port = router.get_ex_gw_port()
        if not external_port:
            if not enable_gw:
                return
            self.fail('GW port is enabled but not present in the router')

        snat_ns_name = dvr_snat_ns.SnatNamespace.get_snat_ns_name(
            router.router_id)

        # if the agent is in dvr_snat mode, then we have to check
        # that the correct ports and ip addresses exist in the
        # snat_ns_name namespace
        if self.agent.conf.agent_mode == 'dvr_snat':
            device_exists = functools.partial(
                self.device_exists_with_ips_and_mac,
                external_port,
                router.get_external_device_name,
                snat_ns_name)
            utils.wait_until_true(device_exists)
        # if the agent is in dvr mode then the snat_ns_name namespace
        # should not be present at all:
        elif self.agent.conf.agent_mode == 'dvr':
            self.assertFalse(
                self._namespace_exists(snat_ns_name),
                "namespace %s was found but agent is in dvr mode not dvr_snat"
                % (str(snat_ns_name))
            )
        # if the agent is anything else the test is misconfigured
        # we force a test failure with message
        else:
            self.fail("Agent not configured for dvr or dvr_snat")

    def _assert_dvr_gateway(self, router, enable_gw):
        gateway_expected_in_snat_namespace = (
            self.agent.conf.agent_mode == 'dvr_snat'
        )
        if gateway_expected_in_snat_namespace:
            self._assert_dvr_snat_gateway(router, enable_gw=enable_gw)
            self._assert_removal_of_already_deleted_gateway_device(router)

        snat_namespace_should_not_exist = (
            self.agent.conf.agent_mode == 'dvr'
        )
        if snat_namespace_should_not_exist:
            self._assert_snat_namespace_does_not_exist(router)

    def _assert_dvr_snat_gateway(self, router, enable_gw=True):
        namespace = dvr_snat_ns.SnatNamespace.get_snat_ns_name(
            router.router_id)
        external_port = router.get_ex_gw_port()
        if not external_port:
            if not enable_gw:
                return
            self.fail('GW port is enabled but not present in the router')

        external_device_name = router.get_external_device_name(
            external_port['id'])
        external_device = ip_lib.IPDevice(external_device_name,
                                          namespace=namespace)
        existing_gateway = (
            external_device.route.get_gateway().get('via'))
        expected_gateway = external_port['subnets'][0]['gateway_ip']
        self.assertEqual(expected_gateway, existing_gateway)

    def _assert_removal_of_already_deleted_gateway_device(self, router):
        namespace = dvr_snat_ns.SnatNamespace.get_snat_ns_name(
            router.router_id)
        device = ip_lib.IPDevice("fakedevice",
                                 namespace=namespace)

        # Assert that no exception is thrown for this case
        self.assertIsNone(router._delete_gateway_device_if_exists(
                          device, "192.168.0.1", 0))

    def _assert_snat_namespace_does_not_exist(self, router):
        namespace = dvr_snat_ns.SnatNamespace.get_snat_ns_name(
            router.router_id)
        self.assertFalse(self._namespace_exists(namespace))

    def _assert_dvr_floating_ips(self, router, snat_bound_fip=False,
                                 enable_gw=True):
        def check_fg_port_created(device_name, ip_cidrs, mac, namespace):
            success = ip_lib.device_exists_with_ips_and_mac(
                device_name, ip_cidrs, mac, namespace=namespace)
            if success:
                return
            dev = ip_lib.IPDevice(device_name, namespace=namespace)
            dev_mac, dev_cidrs = dev.link.address, dev.addr.list()
            self.fail('Device name: %s, expected MAC: %s, expected CIDRs: %s, '
                      'device MAC: %s, device CIDRs: %s' %
                      (device_name, mac, ip_cidrs, dev_mac, dev_cidrs))

        # in the fip namespace:
        # Check that the fg-<port-id> (floatingip_agent_gateway)
        # is created with the ip address of the external gateway port
        floating_ips = router.router[lib_constants.FLOATINGIP_KEY]
        self.assertTrue(floating_ips)
        # We need to fetch the floatingip agent gateway port info
        # from the router_info
        if not enable_gw:
            return

        floating_agent_gw_port = (
            router.router[lib_constants.FLOATINGIP_AGENT_INTF_KEY])
        self.assertTrue(floating_agent_gw_port)

        external_gw_port = floating_agent_gw_port[0]
        fip_ns = self.agent.get_fip_ns(floating_ips[0]['floating_network_id'])
        fip_ns_name = fip_ns.get_name()
        check_fg_port_created(
            fip_ns.get_ext_device_name(external_gw_port['id']),
            [self._port_first_ip_cidr(external_gw_port)],
            external_gw_port['mac_address'], fip_ns_name)
        # Check fpr-router device has been created
        device_name = fip_ns.get_int_device_name(router.router_id)
        fpr_router_device_created_successfully = ip_lib.device_exists(
            device_name, namespace=fip_ns_name)
        self.assertTrue(fpr_router_device_created_successfully)

        # In the router namespace
        # Check rfp-<router-id> is created correctly
        for fip in floating_ips:
            device_name = fip_ns.get_rtr_ext_device_name(router.router_id)
            self.assertTrue(ip_lib.device_exists(
                device_name, namespace=router.ns_name))

        # In the router namespace, check the iptables rules are set
        # correctly
        for fip in floating_ips:
            expected_rules = router.floating_forward_rules(fip)
            if fip.get(lib_constants.DVR_SNAT_BOUND):
                iptables_mgr = router.snat_iptables_manager
            else:
                iptables_mgr = router.iptables_manager
            self._assert_iptables_rules_exist(
                iptables_mgr, 'nat', expected_rules)

    def test_dvr_router_fip_associations_exist_when_router_reenabled(self):
        """Test to validate the fip associations when router is re-enabled.

        This test validates the fip associations when the router is disabled
        and enabled back again. This test is specifically for the host where
        snat namespace is not created or gateway port is binded on other host.
        """
        self.agent.conf.agent_mode = 'dvr_snat'
        router_info = self.generate_dvr_router_info(enable_snat=True)
        # Ensure agent does not create snat namespace by changing gw_port_host
        router_info['gw_port_host'] = 'agent2'
        router_info_copy = copy.deepcopy(router_info)
        router1 = self.manage_router(self.agent, router_info)

        fip_ns_name = router1.fip_ns.name
        self.assertTrue(self._namespace_exists(router1.fip_ns.name))

        # Simulate disable router
        self.agent._safe_router_removed(router1.router['id'])
        self.assertFalse(self._namespace_exists(router1.ns_name))
        self.assertTrue(self._namespace_exists(fip_ns_name))

        # Simulated enable router
        router_updated = self.manage_router(self.agent, router_info_copy)
        self._assert_dvr_floating_ips(router_updated)

    def test_dvr_router_fip_associations_exist_when_snat_removed(self):
        """Test to validate the fip associations when snat is removed.

        This test validates the fip associations when the snat is removed from
        the agent. The fip associations should exist when the snat is moved to
        another l3 agent.
        """
        self.agent.conf.agent_mode = 'dvr_snat'
        router_info = self.generate_dvr_router_info(enable_snat=True)
        router_info_copy = copy.deepcopy(router_info)
        router1 = self.manage_router(self.agent, router_info)

        # Remove gateway port host and the binding host_id to simulate
        # removal of snat from l3 agent
        router_info_copy['gw_port_host'] = ''
        router_info_copy['gw_port']['binding:host_id'] = ''
        router_info_copy['gw_port']['binding:vif_type'] = 'unbound'
        router_info_copy['gw_port']['binding:vif_details'] = {}
        self.agent._process_updated_router(router_info_copy)
        router_updated = self.agent.router_info[router1.router['id']]
        self._assert_dvr_floating_ips(router_updated)

    def test_dvr_router_with_ha_for_fip_disassociation(self):
        """Test to validate the fip rules are deleted in dvr_snat_ha router.

        This test validates the fip rules are getting deleted in
        a router namespace when the router has ha and snat enabled after
        the floatingip is disassociated.
        """
        self.agent.conf.agent_mode = 'dvr_snat'
        router_info = self.generate_dvr_router_info(
            enable_snat=True, enable_ha=True, enable_gw=True)
        fip_agent_gw_port = router_info[
            lib_constants.FLOATINGIP_AGENT_INTF_KEY]
        self.mock_plugin_api.get_agent_gateway_port.return_value = (
            fip_agent_gw_port[0])
        router1 = self.manage_router(self.agent, router_info)
        fip_ns_name = router1.fip_ns.get_name()
        self.assertTrue(self._namespace_exists(router1.ns_name))
        self.assertTrue(self._namespace_exists(fip_ns_name))
        self._assert_snat_namespace_exists(router1)
        ip4_rules_list_with_fip = ip_lib.list_ip_rules(
            router1.ns_name, lib_constants.IP_VERSION_4)
        # The rules_list should have 6 entries:
        # 3 default rules (local, main and default)
        # 1 Fip forward rule
        # 2 interface rules to redirect to snat
        self.assertEqual(6, len(ip4_rules_list_with_fip))
        rfp_device_name = router1.fip_ns.get_rtr_ext_device_name(
            router1.router_id)
        rfp_device = ip_lib.IPDevice(rfp_device_name,
                                     namespace=router1.ns_name)
        rtr_2_fip, fip_2_rtr = router1.rtr_fip_subnet.get_pair()
        fpr_device_name = router1.fip_ns.get_int_device_name(router1.router_id)
        fpr_device = ip_lib.IPDevice(fpr_device_name,
                                     namespace=fip_ns_name)
        self._assert_default_gateway(
            fip_2_rtr, rfp_device, rfp_device_name, fpr_device)

        router1.router[lib_constants.FLOATINGIP_KEY] = []
        self.agent._process_updated_router(router1.router)
        router_updated = self.agent.router_info[router1.router['id']]
        self.assertTrue(self._namespace_exists(router_updated.ns_name))
        self._assert_snat_namespace_exists(router1)
        ip4_rules_list = ip_lib.list_ip_rules(router1.ns_name,
                                              lib_constants.IP_VERSION_4)
        self.assertEqual(5, len(ip4_rules_list))
        interface_rules_list_count = 0
        fip_rule_count = 0
        for ip_rule in ip4_rules_list:
            tbl_index = ip_rule['table']
            if tbl_index not in ['local', 'default', 'main']:
                interface_rules_list_count += 1
                if tbl_index == dvr_fip_ns.FIP_RT_TBL:
                    fip_rule_count += 1
        self.assertEqual(2, interface_rules_list_count)
        self.assertEqual(0, fip_rule_count)

    def _assert_default_gateway(self, fip_2_rtr, rfp_device,
                                device_name, fpr_device):
        v6_gateway = utils.cidr_to_ip(
                ip_lib.get_ipv6_lladdr(fpr_device.link.address))
        expected_gateway = [{'device': device_name,
                             'cidr': '0.0.0.0/0',
                             'via': str(fip_2_rtr.ip),
                             'table': dvr_fip_ns.FIP_RT_TBL},
                            {'device': device_name,
                             'cidr': '::/0',
                             'table': 'main',
                             'via': v6_gateway}]
        v4_routes = rfp_device.route.list_routes(
            ip_version=lib_constants.IP_VERSION_4,
            table=dvr_fip_ns.FIP_RT_TBL,
            via=str(fip_2_rtr.ip))
        v6_routers = rfp_device.route.list_routes(
            ip_version=lib_constants.IP_VERSION_6,
            via=v6_gateway)
        self._check_routes(expected_gateway, v4_routes + v6_routers)

    def test_dvr_router_rem_fips_on_restarted_agent(self):
        self.agent.conf.agent_mode = 'dvr_snat'
        router_info = self.generate_dvr_router_info()
        router1 = self.manage_router(self.agent, router_info)
        fip_ns = router1.fip_ns.get_name()
        self.assertTrue(self._namespace_exists(fip_ns))
        restarted_agent = neutron_l3_agent.L3NATAgentWithStateReport(
            self.agent.host, self.agent.conf)
        router1.router[lib_constants.FLOATINGIP_KEY] = []
        self.manage_router(restarted_agent, router1.router)
        self._assert_dvr_snat_gateway(router1)
        self.assertTrue(self._namespace_exists(fip_ns))

    def test_dvr_router_update_on_restarted_agent_sets_rtr_fip_connect(self):
        self.agent.conf.agent_mode = 'dvr_snat'
        router_info = self.generate_dvr_router_info()
        router1 = self.manage_router(self.agent, router_info)
        self.assertTrue(router1.rtr_fip_connect)
        fip_ns = router1.fip_ns.get_name()
        self.assertTrue(self._namespace_exists(fip_ns))
        restarted_agent = neutron_l3_agent.L3NATAgentWithStateReport(
            self.agent.host, self.agent.conf)
        router_updated = self.manage_router(restarted_agent, router1.router)
        self.assertTrue(router_updated.rtr_fip_connect)

    def test_dvr_router_add_fips_on_restarted_agent(self):
        self.agent.conf.agent_mode = 'dvr'
        router_info = self.generate_dvr_router_info()
        router = self.manage_router(self.agent, router_info)
        floating_ips = router.router[lib_constants.FLOATINGIP_KEY]
        router_ns = router.ns_name
        fip_rule_prio_1 = self._get_fixed_ip_rule_priority(
            router_ns, floating_ips[0]['fixed_ip_address'])
        restarted_agent = neutron_l3_agent.L3NATAgent(
            self.agent.host, self.agent.conf)
        floating_ips[0]['floating_ip_address'] = '21.4.4.2'
        floating_ips[0]['fixed_ip_address'] = '10.0.0.2'
        self.manage_router(restarted_agent, router_info)
        fip_rule_prio_2 = self._get_fixed_ip_rule_priority(
            router_ns, floating_ips[0]['fixed_ip_address'])
        self.assertNotEqual(fip_rule_prio_1, fip_rule_prio_2)

    def test_dvr_router_floating_ip_moved(self):
        self.agent.conf.agent_mode = 'dvr'
        router_info = self.generate_dvr_router_info()
        router = self.manage_router(self.agent, router_info)
        floating_ips = router.router[lib_constants.FLOATINGIP_KEY]
        router_ns = router.ns_name
        fixed_ip = floating_ips[0]['fixed_ip_address']
        self.assertTrue(self._fixed_ip_rule_exists(router_ns, fixed_ip))
        # Floating IP reassigned to another fixed IP
        new_fixed_ip = '10.0.0.2'
        self.assertNotEqual(new_fixed_ip, fixed_ip)
        floating_ips[0]['fixed_ip_address'] = new_fixed_ip
        self.agent._process_updated_router(router.router)
        self.assertFalse(self._fixed_ip_rule_exists(router_ns, fixed_ip))
        self.assertTrue(self._fixed_ip_rule_exists(router_ns, new_fixed_ip))

    def _assert_iptables_rules_exist(self, router_iptables_manager,
                                     table_name, expected_rules):
        rules = router_iptables_manager.get_rules_for_table(table_name)
        for rule in expected_rules:
            self.assertIn(
                str(iptables_manager.IptablesRule(rule[0], rule[1])), rules)
        return True

    def _assert_iptables_rules_not_exist(self, router_iptables_manager,
                                         table_name, expected_rules):
        rules = router_iptables_manager.get_rules_for_table(table_name)
        for rule in expected_rules:
            self.assertNotIn(
                str(iptables_manager.IptablesRule(rule[0], rule[1])), rules)
        return True

    def test_prevent_snat_rule_exist_on_restarted_agent(self):
        self.agent.conf.agent_mode = 'dvr_snat'
        router_info = self.generate_dvr_router_info()
        router = self.manage_router(self.agent, router_info)
        ext_port = router.get_ex_gw_port()
        rfp_devicename = router.get_external_device_interface_name(ext_port)
        prevent_snat_rule = router._prevent_snat_for_internal_traffic_rule(
            rfp_devicename)

        self._assert_iptables_rules_exist(
            router.iptables_manager, 'nat', [prevent_snat_rule])

        restarted_agent = neutron_l3_agent.L3NATAgentWithStateReport(
            self.agent.host, self.agent.conf)
        restarted_router = self.manage_router(restarted_agent, router_info)

        self._assert_iptables_rules_exist(
            restarted_router.iptables_manager, 'nat', [prevent_snat_rule])

    def _get_fixed_ip_rule_priority(self, namespace, fip):
        ipv4_rules = ip_lib.list_ip_rules(namespace, 4)
        for rule in (rule for rule in ipv4_rules
                     if utils.cidr_to_ip(rule['from']) == fip):
            return rule['priority']

    def _fixed_ip_rule_exists(self, namespace, ip):
        ipv4_rules = ip_lib.list_ip_rules(namespace, 4)
        for _ in (rule for rule in ipv4_rules
                  if utils.cidr_to_ip(rule['from']) == ip):
            return True
        return False

    def test_dvr_router_add_internal_network_set_arp_cache(self):
        # Check that, when the router is set up and there are
        # existing ports on the uplinked subnet, the ARP
        # cache is properly populated.
        self.agent.conf.agent_mode = 'dvr_snat'
        router_info = self.generate_dvr_router_info(enable_snat=True)
        expected_neighbors = ['35.4.1.10', '10.0.0.10', '10.200.0.3']
        allowed_address_net = netaddr.IPNetwork('10.100.0.0/30')
        subnet_id = router_info['_interfaces'][0]['fixed_ips'][0]['subnet_id']
        port_data = {
            'fixed_ips': [
                {'ip_address': expected_neighbors[0],
                 'subnet_id': subnet_id}],
            'mac_address': 'fa:3e:aa:bb:cc:dd',
            'device_owner': DEVICE_OWNER_COMPUTE,
            'allowed_address_pairs': [
                {'ip_address': expected_neighbors[1],
                 'mac_address': 'fa:3e:aa:bb:cc:dd'},
                {'ip_address': '10.200.0.3/32',
                 'mac_address': 'fa:3e:aa:bb:cc:dd'},
                {'ip_address': str(allowed_address_net),
                 'mac_address': 'fa:3e:aa:bb:cc:dd'}]
        }
        self.agent.plugin_rpc.get_ports_by_subnet.return_value = [port_data]
        router1 = self.manage_router(self.agent, router_info)
        internal_device = router1.get_internal_device_name(
            router_info['_interfaces'][0]['id'])
        for expected_neighbor in expected_neighbors:
            neighbor = ip_lib.dump_neigh_entries(
                lib_constants.IP_VERSION_4, internal_device,
                router1.ns_name,
                dst=expected_neighbor)
            self.assertNotEqual([], neighbor)
            self.assertEqual(expected_neighbor, neighbor[0]['dst'])
        for not_expected_neighbor in allowed_address_net:
            neighbor = ip_lib.dump_neigh_entries(
                lib_constants.IP_VERSION_4, internal_device,
                router1.ns_name,
                dst=str(not_expected_neighbor))
            self.assertEqual([], neighbor)

    def _assert_rfp_fpr_mtu(self, router, expected_mtu=1500, enable_gw=True):
        if not enable_gw:
            self.assertIsNone(router.fip_ns)
            return

        dev_mtu = self.get_device_mtu(
            router.router_id, router.fip_ns.get_rtr_ext_device_name,
            router.ns_name)
        self.assertEqual(expected_mtu, dev_mtu)
        dev_mtu = self.get_device_mtu(
            router.router_id, router.fip_ns.get_int_device_name,
            router.fip_ns.get_name())
        self.assertEqual(expected_mtu, dev_mtu)

    def test_dvr_router_fip_agent_mismatch(self):
        """Test to validate the floatingip agent mismatch.

        This test validates the condition where floatingip agent
        gateway port host mismatches with the agent and so the
        binding will not be there.

        """
        self.agent.conf.agent_mode = 'dvr'
        router_info = self.generate_dvr_router_info()
        floating_ip = router_info['_floatingips'][0]
        floating_ip['host'] = 'my_new_host'
        # In this case the floatingip binding is different and so it
        # should not create the floatingip namespace on the given agent.
        # This is also like there is no current binding.
        router1 = self.manage_router(self.agent, router_info)
        fip_ns = router1.fip_ns.get_name()
        self.assertTrue(self._namespace_exists(router1.ns_name))
        # FIP Namespace creation does not depend on the floatingip's
        # anymore and will be created on each agent when there is
        # a valid gateway.
        self.assertTrue(self._namespace_exists(fip_ns))
        self._assert_snat_namespace_does_not_exist(router1)

    def test_dvr_router_fip_create_for_migrating_port(self):
        """Test to validate the floatingip create on port migrate.

        This test validates the condition where floatingip host
        mismatches with the agent, but the 'dest_host' variable
        matches with the agent host, due to port pre-migrate
        phase.

        """
        self.agent.conf.agent_mode = 'dvr'
        router_info = self.generate_dvr_router_info()
        floating_ip = router_info['_floatingips'][0]
        floating_ip['host'] = 'my_new_host'
        floating_ip['dest_host'] = self.agent.host
        # Now we have the floatingip 'host' pointing to host that
        # does not match to the 'agent.host' and the floatingip
        # 'dest_host' matches with the agent.host in the case
        # of live migration due to the port_profile update from
        # nova.
        router1 = self.manage_router(self.agent, router_info)
        fip_ns = router1.fip_ns.get_name()
        self.assertTrue(self._namespace_exists(router1.ns_name))
        self.assertTrue(self._namespace_exists(fip_ns))

    def test_dvr_router_fip_late_binding(self):
        """Test to validate the floatingip migration or latebinding.

        This test validates the condition where floatingip private
        port changes while migration or when the private port host
        binding is done later after floatingip association.

        """
        self.agent.conf.agent_mode = 'dvr'
        router_info = self.generate_dvr_router_info()
        fip_agent_gw_port = router_info[
            lib_constants.FLOATINGIP_AGENT_INTF_KEY]
        # Now let us not pass the FLOATINGIP_AGENT_INTF_KEY, to emulate
        # that the server did not create the port, since there was no valid
        # host binding.
        router_info[lib_constants.FLOATINGIP_AGENT_INTF_KEY] = []
        self.mock_plugin_api.get_agent_gateway_port.return_value = (
            fip_agent_gw_port[0])
        router1 = self.manage_router(self.agent, router_info)
        fip_ns = router1.fip_ns.get_name()
        self.assertTrue(self._namespace_exists(router1.ns_name))
        self.assertTrue(self._namespace_exists(fip_ns))
        self._assert_snat_namespace_does_not_exist(router1)

    def test_dvr_router_fip_namespace_create_without_floatingip(self):
        """Test to validate the floatingip namespace creation without fip.

        This test validates the condition where floatingip namespace gets
        created on the agent when the gateway is added and without floatingip
        configured for the router.
        """
        self.agent.conf.agent_mode = 'dvr'
        router_info = self.generate_dvr_router_info(enable_floating_ip=False)
        fip_agent_gw_port = self._get_fip_agent_gw_port_for_router(
            router_info['gw_port'])
        self.mock_plugin_api.get_agent_gateway_port.return_value = (
            fip_agent_gw_port)
        router1 = self.manage_router(self.agent, router_info)
        fip_ns = router1.fip_ns.get_name()
        self.assertTrue(self._namespace_exists(router1.ns_name))
        self.assertTrue(self._namespace_exists(fip_ns))
        self.assertTrue(router1.rtr_fip_connect)
        self._assert_snat_namespace_does_not_exist(router1)

    def _assert_snat_namespace_exists(self, router):
        namespace = dvr_snat_ns.SnatNamespace.get_snat_ns_name(
            router.router_id)
        self.assertTrue(self._namespace_exists(namespace))

    def _get_dvr_snat_namespace_device_status(self, router,
                                              internal_dev_name=None):
        """Function returns the internal and external device status."""
        snat_ns = dvr_snat_ns.SnatNamespace.get_snat_ns_name(
            router.router_id)
        external_port = router.get_ex_gw_port()
        external_device_name = router.get_external_device_name(
            external_port['id'])
        qg_device_created_successfully = ip_lib.device_exists(
            external_device_name, namespace=snat_ns)
        sg_device_created_successfully = ip_lib.device_exists(
            internal_dev_name, namespace=snat_ns)
        return qg_device_created_successfully, sg_device_created_successfully

    def test_snat_bound_floating_ip(self):
        """Test to validate the snat bound floatingip lifecycle."""
        self.agent.conf.agent_mode = lib_constants.L3_AGENT_MODE_DVR_SNAT
        router_info = self.generate_dvr_router_info(snat_bound_fip=True)
        router1 = self.manage_router(self.agent, router_info)
        snat_bound_floatingips = router_info[lib_constants.FLOATINGIP_KEY]
        self._assert_snat_namespace_exists(router1)
        # In the snat namespace, check the iptables rules are set correctly
        for fip in snat_bound_floatingips:
            expected_rules = router1.floating_forward_rules(fip)
            if fip.get(lib_constants.DVR_SNAT_BOUND):
                self._assert_iptables_rules_exist(
                    router1.snat_iptables_manager, 'nat', expected_rules)

    def test_floating_ip_migrate_when_unbound_port_is_bound_to_a_host(self):
        """Test to check floating ips migrate from unbound to bound host."""
        self.agent.conf.agent_mode = lib_constants.L3_AGENT_MODE_DVR_SNAT
        router_info = self.generate_dvr_router_info(
            enable_floating_ip=True, enable_centralized_fip=True,
            enable_snat=True, snat_bound_fip=True)
        router1 = self.manage_router(self.agent, router_info)
        floatingips = router_info[lib_constants.FLOATINGIP_KEY]
        distributed_fip = floatingips[0]
        centralized_floatingip = floatingips[1]
        # For private ports hosted in dvr_no_fip agent, the floatingip
        # dict will contain the fip['host'] key, but the value will always
        # be None to emulate the legacy router.
        self.assertIsNone(centralized_floatingip['host'])
        self.assertTrue(self._namespace_exists(router1.ns_name))
        fip_ns = router1.fip_ns.get_name()
        self.assertTrue(self._namespace_exists(fip_ns))
        self._assert_snat_namespace_exists(router1)
        # If fips are centralized then, the DNAT rules are only
        # configured in the SNAT Namespace and not in the router-ns.
        expected_rules = router1.floating_forward_rules(distributed_fip)
        self.assertTrue(self._assert_iptables_rules_exist(
            router1.iptables_manager, 'nat', expected_rules))
        expected_rules = router1._centralized_floating_forward_rules(
            centralized_floatingip['floating_ip_address'],
            centralized_floatingip['fixed_ip_address'])
        self.assertTrue(self._assert_iptables_rules_exist(
            router1.snat_iptables_manager, 'nat', expected_rules))
        qrouter_ns = router1.ns_name
        fixed_ip_dist = distributed_fip['fixed_ip_address']
        snat_ns = router1.snat_namespace.name
        fixed_ip_cent = centralized_floatingip['fixed_ip_address']
        self.assertFalse(self._fixed_ip_rule_exists(qrouter_ns, fixed_ip_cent))
        self.assertTrue(self._fixed_ip_rule_exists(qrouter_ns, fixed_ip_dist))
        self.assertFalse(self._fixed_ip_rule_exists(snat_ns, fixed_ip_dist))
        self.assertFalse(self._fixed_ip_rule_exists(snat_ns, fixed_ip_cent))
        # Now let us edit the centralized floatingIP info with 'host'
        # and remove the 'dvr_snat_bound'
        router1.router[lib_constants.FLOATINGIP_KEY][1]['host'] = (
            self.agent.conf.host)
        del router1.router[lib_constants.FLOATINGIP_KEY][1]['dvr_snat_bound']
        self.agent._process_updated_router(router1.router)
        router_updated = self.agent.router_info[router_info['id']]

        qrouter_ns = router_updated.ns_name
        fixed_ip_dist = distributed_fip['fixed_ip_address']
        self._assert_snat_namespace_exists(router_updated)
        snat_ns = router_updated.snat_namespace.name
        fixed_ip_cent = centralized_floatingip['fixed_ip_address']
        router_updated.get_centralized_fip_cidr_set = mock.Mock(
            return_value=set(["19.4.4.3/32"]))
        self.assertTrue(self._assert_iptables_rules_not_exist(
            router_updated.snat_iptables_manager, 'nat', expected_rules))
        port = router_updated.get_ex_gw_port()
        interface_name = router_updated.get_external_device_name(port['id'])
        self._assert_ip_address_not_on_interface(
            snat_ns, interface_name,
            centralized_floatingip['floating_ip_address'])
        self.assertTrue(self._fixed_ip_rule_exists(qrouter_ns, fixed_ip_dist))
        self.assertFalse(self._fixed_ip_rule_exists(snat_ns, fixed_ip_dist))
        self.assertTrue(self._fixed_ip_rule_exists(qrouter_ns, fixed_ip_cent))
        self.assertFalse(self._fixed_ip_rule_exists(snat_ns, fixed_ip_cent))
        self.assertTrue(self._namespace_exists(fip_ns))

    def _test_get_centralized_fip_cidr_set(self, router_info,
                                           expected_result_empty):
        self.agent.conf.agent_mode = lib_constants.L3_AGENT_MODE_DVR_SNAT
        self.manage_router(self.agent, router_info)
        router = self.agent.router_info[router_info['id']]
        centralized_fips = router.get_centralized_fip_cidr_set()
        if expected_result_empty:
            self.assertEqual(set([]), centralized_fips)
        else:
            self.assertNotEqual(set([]), centralized_fips)

    def test_get_centralized_fip_cidr_set(self):
        router_info = self.generate_dvr_router_info(
            enable_floating_ip=True, enable_centralized_fip=True,
            enable_snat=True, snat_bound_fip=True)
        self._test_get_centralized_fip_cidr_set(router_info, False)

    def test_get_centralized_fip_cidr_set_not_snat_host(self):
        router_info = self.generate_dvr_router_info(
            enable_floating_ip=True, enable_centralized_fip=True,
            enable_snat=True, snat_bound_fip=True)
        router_info['gw_port_host'] = 'some-other-host'
        self._test_get_centralized_fip_cidr_set(router_info, True)

    def test_get_centralized_fip_cidr_set_no_ex_gw_port(self):
        self.agent.conf.agent_mode = lib_constants.L3_AGENT_MODE_DVR_SNAT
        router_info = self.generate_dvr_router_info(
            enable_floating_ip=True, enable_centralized_fip=True,
            enable_snat=True, snat_bound_fip=True)
        router_info['gw_port'] = {}
        self._test_get_centralized_fip_cidr_set(router_info, True)

    def test_floating_ip_not_deployed_on_dvr_no_external_agent(self):
        """Test to check floating ips not configured for dvr_no_external."""
        self.agent.conf.agent_mode = (
            lib_constants.L3_AGENT_MODE_DVR_NO_EXTERNAL)
        router_info = self.generate_dvr_router_info(
            enable_floating_ip=True, enable_centralized_fip=True)
        router1 = self.manage_router(self.agent, router_info)
        centralized_floatingips = router_info[lib_constants.FLOATINGIP_KEY]
        # For private ports hosted in dvr_no_fip agent, the floatingip
        # dict will contain the fip['host'] key, but the value will always
        # be None to emulate the legacy router.
        self.assertIsNone(centralized_floatingips[0]['host'])
        self.assertTrue(self._namespace_exists(router1.ns_name))
        fip_ns = router1.fip_ns.get_name()
        self.assertFalse(self._namespace_exists(fip_ns))
        # If fips are centralized then, the DNAT rules are only
        # configured in the SNAT Namespace and not in the router-ns.
        for fip in centralized_floatingips:
            expected_rules = router1.floating_forward_rules(fip)
            self.assertEqual(0, len(expected_rules))

    def test_floating_ip_create_does_not_raise_keyerror_on_missing_host(self):
        """Test to check floating ips configure does not raise Keyerror."""
        self.agent.conf.agent_mode = 'dvr'
        router_info = self.generate_dvr_router_info(
            enable_floating_ip=True)
        del router_info[lib_constants.FLOATINGIP_KEY][0]['host']
        centralized_floatingips = router_info[lib_constants.FLOATINGIP_KEY][0]
        self.assertIsNone(centralized_floatingips.get('host'))
        # No Keyerror should be raised when calling manage_router
        self.manage_router(self.agent, router_info)

    def test_dvr_router_snat_namespace_with_interface_remove(self):
        """Test to validate the snat namespace with interface remove.

        This test validates the snat namespace for all the external
        and internal devices. It also validates if the internal
        device corresponding to the router interface is removed
        when the router interface is deleted.
        """
        self.agent.conf.agent_mode = 'dvr_snat'
        router_info = self.generate_dvr_router_info()
        snat_internal_port = router_info[lib_constants.SNAT_ROUTER_INTF_KEY]
        router1 = self.manage_router(self.agent, router_info)
        csnat_internal_port = (
            router1.router[lib_constants.SNAT_ROUTER_INTF_KEY])
        # Now save the internal device name to verify later
        internal_device_name = router1._get_snat_int_device_name(
            csnat_internal_port[0]['id'])
        self._assert_snat_namespace_exists(router1)
        qg_device, sg_device = self._get_dvr_snat_namespace_device_status(
            router1, internal_dev_name=internal_device_name)
        self.assertTrue(qg_device)
        self.assertTrue(sg_device)
        self.assertEqual(router1.snat_ports, snat_internal_port)
        # Now let us not pass INTERFACE_KEY, to emulate
        # the interface has been removed.
        router1.router[lib_constants.INTERFACE_KEY] = []
        # Now let us not pass the SNAT_ROUTER_INTF_KEY, to emulate
        # that the server did not send it, since the interface has been
        # removed.
        router1.router[lib_constants.SNAT_ROUTER_INTF_KEY] = []
        self.agent._process_updated_router(router1.router)
        router_updated = self.agent.router_info[router_info['id']]
        self._assert_snat_namespace_exists(router_updated)
        qg_device, sg_device = self._get_dvr_snat_namespace_device_status(
            router_updated, internal_dev_name=internal_device_name)
        self.assertFalse(sg_device)
        self.assertTrue(qg_device)

    def _mocked_dvr_ha_router(self, agent, enable_ha=True, enable_gw=True,
                              enable_centralized_fip=False,
                              snat_bound_fip=False,
                              vrrp_id=None,
                              **kwargs):
        r_info = self.generate_dvr_router_info(
            enable_ha=enable_ha,
            enable_snat=True,
            agent=agent,
            enable_gw=enable_gw,
            enable_centralized_fip=enable_centralized_fip,
            snat_bound_fip=snat_bound_fip,
            vrrp_id=vrrp_id,
            **kwargs)

        r_snat_ns_name = namespaces.build_ns_name(dvr_snat_ns.SNAT_NS_PREFIX,
                                                  r_info['id'])

        mocked_r_snat_ns_name = r_snat_ns_name + '@' + agent.host
        r_ns_name = namespaces.build_ns_name(namespaces.NS_PREFIX,
                                             r_info['id'])

        mocked_r_ns_name = r_ns_name + '@' + agent.host

        return r_info, mocked_r_ns_name, mocked_r_snat_ns_name

    def _setup_dvr_ha_agents(self):
        self.agent.conf.agent_mode = 'dvr_snat'

        conf = self._configure_agent('agent2')
        self.failover_agent = neutron_l3_agent.L3NATAgentWithStateReport(
            'agent2', conf)
        self.failover_agent.conf.agent_mode = 'dvr_snat'

    def _setup_dvr_ha_bridges(self):
        br_int_1 = self._get_agent_ovs_integration_bridge(self.agent)
        br_int_2 = self._get_agent_ovs_integration_bridge(self.failover_agent)

        veth1, veth2 = self.useFixture(net_helpers.VethFixture()).ports
        veth1.link.set_up()
        veth2.link.set_up()
        br_int_1.add_port(veth1.name)
        br_int_2.add_port(veth2.name)

    def _create_dvr_ha_router(self, agent, enable_gw=True,
                              enable_centralized_fip=False,
                              snat_bound_fip=False, ha_interface=True,
                              vrrp_id=None, **kwargs):
        get_ns_name = mock.patch.object(namespaces.RouterNamespace,
                                        '_get_ns_name').start()
        get_snat_ns_name = mock.patch.object(dvr_snat_ns.SnatNamespace,
                                             'get_snat_ns_name').start()
        (r_info,
         mocked_r_ns_name,
         mocked_r_snat_ns_name) = self._mocked_dvr_ha_router(
             agent, ha_interface, enable_gw, enable_centralized_fip,
             snat_bound_fip,
             vrrp_id=vrrp_id,
             **kwargs)

        if not ha_interface:
            r_info['ha'] = True

        get_ns_name.return_value = mocked_r_ns_name
        get_snat_ns_name.return_value = mocked_r_snat_ns_name
        router = self.manage_router(agent, r_info)
        return router

    def _assert_ip_addresses_in_dvr_ha_snat_namespace_with_fip(self, router):
        namespace = router.ha_namespace
        ex_gw_port = router.get_ex_gw_port()
        snat_ports = router.get_snat_interfaces()
        if not snat_ports:
            return
        if router.is_router_primary():
            centralized_floatingips = (
                router.router[lib_constants.FLOATINGIP_KEY])
            for fip in centralized_floatingips:
                expected_rules = router.floating_forward_rules(fip)
                self.assertFalse(self._assert_iptables_rules_exist(
                    router.snat_iptables_manager, 'nat', expected_rules))

        snat_port = snat_ports[0]
        ex_gw_port_name = router.get_external_device_name(
            ex_gw_port['id'])
        snat_port_name = router._get_snat_int_device_name(
            snat_port['id'])

        ex_gw_port_cidrs = utils.fixed_ip_cidrs(ex_gw_port["fixed_ips"])
        snat_port_cidrs = utils.fixed_ip_cidrs(snat_port["fixed_ips"])

        self._assert_ip_addresses_on_interface(namespace,
                                               ex_gw_port_name,
                                               ex_gw_port_cidrs)
        self._assert_ip_addresses_on_interface(namespace,
                                               snat_port_name,
                                               snat_port_cidrs)

    def _assert_no_ip_addresses_in_dvr_ha_snat_namespace_with_fip(self,
                                                                  router):
        namespace = router.ha_namespace
        ex_gw_port = router.get_ex_gw_port()
        snat_ports = router.get_snat_interfaces()
        if not snat_ports:
            return
        snat_port = snat_ports[0]
        ex_gw_port_name = router.get_external_device_name(
            ex_gw_port['id'])
        snat_port_name = router._get_snat_int_device_name(
            snat_port['id'])

        self._assert_no_ip_addresses_on_interface(namespace,
                                                  snat_port_name)
        self._assert_no_ip_addresses_on_interface(namespace,
                                                  ex_gw_port_name)

    def _assert_ip_addresses_in_dvr_ha_snat_namespace(self, router):
        namespace = router.ha_namespace
        ex_gw_port = router.get_ex_gw_port()
        snat_ports = router.get_snat_interfaces()
        if not snat_ports:
            return

        snat_port = snat_ports[0]
        ex_gw_port_name = router.get_external_device_name(
            ex_gw_port['id'])
        snat_port_name = router._get_snat_int_device_name(
            snat_port['id'])

        ip = ex_gw_port["fixed_ips"][0]['ip_address']
        prefix_len = ex_gw_port["fixed_ips"][0]['prefixlen']
        ex_gw_port_cidr = ip + "/" + str(prefix_len)
        ip = snat_port["fixed_ips"][0]['ip_address']
        prefix_len = snat_port["fixed_ips"][0]['prefixlen']
        snat_port_cidr = ip + "/" + str(prefix_len)

        self._assert_ip_address_on_interface(namespace,
                                             ex_gw_port_name,
                                             ex_gw_port_cidr)
        self._assert_ip_address_on_interface(namespace,
                                             snat_port_name,
                                             snat_port_cidr)

    def _assert_no_ip_addresses_in_dvr_ha_snat_namespace(self, router):
        namespace = router.ha_namespace
        ex_gw_port = router.get_ex_gw_port()
        snat_ports = router.get_snat_interfaces()
        if not snat_ports:
            return

        snat_port = snat_ports[0]
        ex_gw_port_name = router.get_external_device_name(
            ex_gw_port['id'])
        snat_port_name = router._get_snat_int_device_name(
            snat_port['id'])

        self._assert_no_ip_addresses_on_interface(namespace,
                                                  snat_port_name)
        self._assert_no_ip_addresses_on_interface(namespace,
                                                  ex_gw_port_name)

    @mock.patch.object(dvr_local_router.DvrLocalRouter, 'connect_rtr_2_fip')
    @mock.patch.object(
        dvr_ha_router.DvrEdgeHaRouter, 'get_centralized_fip_cidr_set')
    def test_dvr_ha_router_with_centralized_fip_calls_keepalived_cidr(
            self, connect_rtr_2_fip_mock, fip_cidr_centralized_mock):

        self._setup_dvr_ha_agents()
        self._setup_dvr_ha_bridges()

        router1 = self._create_dvr_ha_router(
            self.agent, enable_gw=True,
            enable_centralized_fip=True,
            snat_bound_fip=True)
        self.assertTrue(fip_cidr_centralized_mock.called)
        restarted_agent = neutron_l3_agent.L3NATAgentWithStateReport(
            self.agent.host, self.agent.conf)
        self.manage_router(restarted_agent, router1.router)
        self.assertTrue(fip_cidr_centralized_mock.called)

    @mock.patch.object(dvr_local_router.DvrLocalRouter, 'connect_rtr_2_fip')
    @mock.patch.object(
        dvr_edge_router.DvrEdgeRouter, 'get_centralized_fip_cidr_set')
    def test_dvr_router_with_centralized_fip_calls_keepalived_cidr(
            self, connect_rtr_2_fip_mock, fip_cidr_centralized_mock):

        router_info = self.generate_dvr_router_info(
            enable_gw=True, enable_centralized_fip=True, snat_bound_fip=True)
        router1 = self.manage_router(self.agent, router_info)
        self.assertTrue(fip_cidr_centralized_mock.called)
        restarted_agent = neutron_l3_agent.L3NATAgentWithStateReport(
            self.agent.host, self.agent.conf)
        self.manage_router(restarted_agent, router1.router)
        self.assertTrue(fip_cidr_centralized_mock.called)

    def test_dvr_ha_router_unbound_from_agents(self):
        self._setup_dvr_ha_agents()
        self._setup_dvr_ha_bridges()

        router1 = self._create_dvr_ha_router(
            self.agent, enable_gw=True,
            vrrp_id=14,
            ha_port_ip="169.254.192.106",
            ha_port_mac="12:34:56:78:3a:aa")
        router2 = self._create_dvr_ha_router(
            self.failover_agent, enable_gw=True,
            vrrp_id=14,
            ha_port_ip="169.254.192.107",
            ha_port_mac="12:34:56:78:3a:bb")

        primary, backup = self._get_primary_and_backup_routers(
            router1, router2, check_external_device=False)

        self._assert_ip_addresses_in_dvr_ha_snat_namespace(primary)
        self._assert_no_ip_addresses_in_dvr_ha_snat_namespace(backup)
        primary_ha_device = primary.get_ha_device_name()
        backup_ha_device = backup.get_ha_device_name()
        self.assertTrue(
            ip_lib.device_exists(primary_ha_device, primary.ha_namespace))
        self.assertTrue(
            ip_lib.device_exists(backup_ha_device, backup.ha_namespace))

        new_primary_router = copy.deepcopy(primary.router)
        new_primary_router['_ha_interface'] = None
        self.agent._process_updated_router(new_primary_router)
        router_updated = self.agent.router_info[primary.router_id]

        self.assertTrue(self._namespace_exists(router_updated.ns_name))
        self._assert_snat_namespace_exists(router_updated)
        snat_namespace_name = dvr_snat_ns.SnatNamespace.get_snat_ns_name(
            router_updated.router_id)
        self.assertFalse(
            ip_lib.device_exists(primary_ha_device, snat_namespace_name))

        self.wait_until_ha_router_has_state(backup, 'primary')
        self._assert_ip_addresses_in_dvr_ha_snat_namespace(backup)
        self.assertTrue(
            ip_lib.device_exists(backup_ha_device, backup.ha_namespace))

    def _test_dvr_ha_router_failover_with_gw_and_fip(self, enable_gw,
                                                     enable_centralized_fip,
                                                     snat_bound_fip,
                                                     vrrp_id=None):
        self._setup_dvr_ha_agents()
        self._setup_dvr_ha_bridges()

        router1 = self._create_dvr_ha_router(
            self.agent, enable_gw=enable_gw,
            enable_centralized_fip=enable_centralized_fip,
            snat_bound_fip=snat_bound_fip,
            vrrp_id=vrrp_id,
            ha_port_ip="169.254.192.100",
            ha_port_mac="12:34:56:78:2b:aa")
        router2 = self._create_dvr_ha_router(
            self.failover_agent, enable_gw=enable_gw,
            enable_centralized_fip=enable_centralized_fip,
            snat_bound_fip=snat_bound_fip,
            vrrp_id=vrrp_id,
            ha_port_ip="169.254.192.101",
            ha_port_mac="12:34:56:78:2b:bb")

        primary, backup = self._get_primary_and_backup_routers(
            router1, router2, check_external_device=False)

        self.wait_until_ha_router_has_state(primary, 'primary')
        self.wait_until_ha_router_has_state(backup, 'backup')

        self._assert_ip_addresses_in_dvr_ha_snat_namespace_with_fip(primary)
        self._assert_no_ip_addresses_in_dvr_ha_snat_namespace_with_fip(backup)

        self.fail_ha_router(primary)

        self.wait_until_ha_router_has_state(backup, 'primary')
        self.wait_until_ha_router_has_state(primary, 'backup')

        self._assert_ip_addresses_in_dvr_ha_snat_namespace_with_fip(backup)
        self._assert_no_ip_addresses_in_dvr_ha_snat_namespace_with_fip(primary)

    def _test_dvr_ha_router_failover(self, enable_gw, vrrp_id=None):
        self._setup_dvr_ha_agents()
        self._setup_dvr_ha_bridges()

        router1 = self._create_dvr_ha_router(
            self.agent, enable_gw=enable_gw, vrrp_id=vrrp_id,
            ha_port_ip="169.254.192.102",
            ha_port_mac="12:34:56:78:2b:cc")
        router2 = self._create_dvr_ha_router(
            self.failover_agent, enable_gw, vrrp_id=vrrp_id,
            ha_port_ip="169.254.192.103",
            ha_port_mac="12:34:56:78:2b:dd")

        primary, backup = self._get_primary_and_backup_routers(
            router1, router2, check_external_device=False)

        self.wait_until_ha_router_has_state(primary, 'primary')
        self.wait_until_ha_router_has_state(backup, 'backup')

        self._assert_ip_addresses_in_dvr_ha_snat_namespace(primary)
        self._assert_no_ip_addresses_in_dvr_ha_snat_namespace(backup)

        self.fail_ha_router(primary)

        self.wait_until_ha_router_has_state(backup, 'primary')
        self.wait_until_ha_router_has_state(primary, 'backup')

        self._assert_ip_addresses_in_dvr_ha_snat_namespace(backup)
        self._assert_no_ip_addresses_in_dvr_ha_snat_namespace(primary)

    def test_dvr_ha_router_failover_with_gw(self):
        self._test_dvr_ha_router_failover(enable_gw=True, vrrp_id=10)

    def test_dvr_ha_router_failover_with_gw_and_floatingip(self):
        self._test_dvr_ha_router_failover_with_gw_and_fip(
            enable_gw=True, enable_centralized_fip=True, snat_bound_fip=True,
            vrrp_id=11)

    def test_dvr_ha_router_failover_without_gw(self):
        self._test_dvr_ha_router_failover(enable_gw=False, vrrp_id=12)

    def test_dvr_non_ha_router_update(self):
        self._setup_dvr_ha_agents()
        self._setup_dvr_ha_bridges()

        router1 = self._create_dvr_ha_router(
            self.agent,
            vrrp_id=13,
            ha_port_ip="169.254.192.104",
            ha_port_mac="12:34:56:78:2b:ee")
        router2 = self._create_dvr_ha_router(
            self.failover_agent,
            ha_interface=False,
            vrrp_id=13,
            ha_port_ip="169.254.192.105",
            ha_port_mac="12:34:56:78:2b:ff")

        r1_chsfr = mock.patch.object(self.agent,
                                     'check_ha_state_for_router').start()
        r2_chsfr = mock.patch.object(self.failover_agent,
                                     'check_ha_state_for_router').start()

        self.wait_until_ha_router_has_state(router1, 'primary')

        self.agent._process_updated_router(router1.router)
        self.assertTrue(r1_chsfr.called)
        self.failover_agent._process_updated_router(router2.router)
        self.assertFalse(r2_chsfr.called)

    def _setup_dvr_router_static_routes(self, router_namespace=True,
                                        check_fpr_int_rule_delete=False,
                                        enable_ha=False):
        """Test to validate the extra routes on dvr routers."""
        self.agent.conf.agent_mode = 'dvr_snat'
        router_info = self.generate_dvr_router_info(
            enable_snat=True, enable_ha=enable_ha)
        router1 = self.manage_router(self.agent, router_info)
        self.assertTrue(self._namespace_exists(router1.ns_name))
        self._assert_snat_namespace_exists(router1)
        fip_ns_name = router1.fip_ns.get_name()
        self.assertTrue(self._namespace_exists(fip_ns_name))
        snat_ns_name = dvr_snat_ns.SnatNamespace.get_snat_ns_name(
            router1.router_id)
        if router_namespace:
            router1.router['routes'] = [{'destination': '8.8.4.0/24',
                                         'nexthop': '35.4.0.20'}]
        else:
            router1.router['routes'] = [{'destination': '8.8.4.0/24',
                                         'nexthop': '19.4.4.10'}]

        self.agent._process_updated_router(router1.router)
        router_updated = self.agent.router_info[router_info['id']]
        if router_namespace:
            self._assert_extra_routes(router_updated)
            if not enable_ha:
                self._assert_extra_routes(router_updated,
                                          namespace=snat_ns_name)
        else:
            rtr_2_fip, fip_2_rtr = router_updated.rtr_fip_subnet.get_pair()
            # Now get the table index based on the fpr-interface ip.
            router_fip_table_idx = router_updated._get_snat_idx(fip_2_rtr)
            self._assert_extra_routes_for_fipns(
                router_updated, router_fip_table_idx)
            self._assert_extra_routes(router_updated, namespace=snat_ns_name)
        if check_fpr_int_rule_delete:
            router_updated.router[lib_constants.FLOATINGIP_KEY] = []
            router_updated.router['gw_port'] = ""
            router_updated.router['gw_port_host'] = ""
            router_updated.router['external_gateway_info'] = ""
            self.agent._process_updated_router(router_updated.router)
            new_router_info = self.agent.router_info[router_updated.router_id]
            self.assertTrue(self._namespace_exists(fip_ns_name))
            self._assert_extra_routes_for_fipns(
                new_router_info, router_fip_table_idx,
                check_fpr_int_rule_delete=check_fpr_int_rule_delete)

    def _assert_extra_routes_for_fipns(self, router, router_fip_table_idx,
                                       check_fpr_int_rule_delete=False):

        fip_ns_name = router.fip_ns.get_name()
        self.assertTrue(self._namespace_exists(fip_ns_name))
        fg_port = router.fip_ns.agent_gateway_port
        fg_port_name = router.fip_ns.get_ext_device_name(fg_port['id'])
        fip_ns_int_name = router.fip_ns.get_int_device_name(router.router_id)
        fg_device = ip_lib.IPDevice(fg_port_name,
                                    namespace=fip_ns_name)
        if not check_fpr_int_rule_delete:
            self.assertIn('via', fg_device.route.get_gateway(
                table=router_fip_table_idx))
        else:
            self.assertIsNone(fg_device.route.get_gateway(
                table=router_fip_table_idx))

        ext_net_fw_rules_list = ip_lib.list_ip_rules(
            fip_ns_name, lib_constants.IP_VERSION_4)
        if not check_fpr_int_rule_delete:
            # When floatingip are associated, make sure that the
            # corresponding rules and routes in route table are created
            # for the router.
            expected_rule = {u'from': '0.0.0.0/0',
                             u'iif': fip_ns_int_name,
                             'priority': str(router_fip_table_idx),
                             'table': str(router_fip_table_idx),
                             'type': 'unicast'}
            for rule in ext_net_fw_rules_list:
                rule_tbl = rule['table']
                if rule_tbl in ['default', 'local', 'main']:
                    continue
                if rule_tbl == str(router_fip_table_idx):
                    self.assertEqual(expected_rule, rule)
            # Now check the routes in the table.
            destination = router.router['routes'][0]['destination']
            next_hop = router.router['routes'][0]['nexthop']
            actual_routes = fg_device.route.list_routes(
                ip_version=lib_constants.IP_VERSION_4,
                table=router_fip_table_idx,
                via=str(next_hop))
            expected_extra_route = [{'cidr': str(destination),
                                     'device': fg_port_name,
                                     'table': router_fip_table_idx,
                                     'via': next_hop}]
            self._check_routes(expected_extra_route, actual_routes)
        else:
            # When floatingip are deleted or disassociated, make sure that the
            # corresponding rules and routes are cleared from the table
            # corresponding to the router.
            self.assertEqual(3, len(ext_net_fw_rules_list))
            rule_exist = False
            for rule in ext_net_fw_rules_list:
                rule_tbl = rule['table']
                if rule_tbl not in ['default', 'local', 'main']:
                    rule_exist = True
            self.assertFalse(rule_exist)
            tbl_routes = fg_device.route.list_routes(
                ip_version=lib_constants.IP_VERSION_4,
                table=router_fip_table_idx)
            self.assertEqual([], tbl_routes)

    def test_dvr_router_static_routes_in_fip_and_snat_namespace(self):
        self._setup_dvr_router_static_routes(router_namespace=False)

    def test_dvr_router_static_routes_in_snat_namespace_and_router_namespace(
            self):
        self._setup_dvr_router_static_routes()

    def test_dvr_ha_rtr_static_routes_in_rtr_namespace(self):
        self._setup_dvr_router_static_routes(enable_ha=True)

    def test_dvr_router_rule_and_route_table_cleared_when_fip_removed(self):
        self._setup_dvr_router_static_routes(
            router_namespace=False, check_fpr_int_rule_delete=True)

    def _assert_fip_namespace_interface_static_routes(self, address_scopes,
                                                      fpr_device, router_info,
                                                      rtr_2_fip,
                                                      fpr_device_name):
        fixed_ips_1 = router_info[lib_constants.INTERFACE_KEY][0]['fixed_ips']
        fixed_ips_2 = router_info[lib_constants.INTERFACE_KEY][1]['fixed_ips']
        actual_routes = fpr_device.route.list_routes(
                ip_version=lib_constants.IP_VERSION_4, table='main',
                via=str(rtr_2_fip.ip))
        if not address_scopes:
            self.assertEqual([], actual_routes)

        if address_scopes:
            cidr1 = (
                str(fixed_ips_1[0]['ip_address']) +
                '/' + str(fixed_ips_1[0]['prefixlen']))
            cidr2 = (
                str(fixed_ips_2[0]['ip_address']) +
                '/' + str(fixed_ips_2[0]['prefixlen']))
            net_addr_1 = netaddr.IPNetwork(cidr1).network
            net_addr_2 = netaddr.IPNetwork(cidr2).network
            route_cidr_1 = (
                str(net_addr_1) + '/' +
                str(fixed_ips_1[0]['prefixlen']))
            route_cidr_2 = (
                str(net_addr_2) + '/' +
                str(fixed_ips_2[0]['prefixlen']))
            expected_routes = [{'device': fpr_device_name,
                                'cidr': str(route_cidr_1),
                                'via': str(rtr_2_fip.ip),
                                'table': 'main'},
                               {'device': fpr_device_name,
                                'cidr': str(route_cidr_2),
                                'via': str(rtr_2_fip.ip),
                                'table': 'main'}]
            # Comparing the static routes for both internal interfaces on the
            # main table.
            self._check_routes(expected_routes, actual_routes)
        else:
            self.assertEqual([], actual_routes)

    def _assert_interface_rules_on_gateway_remove(self, router, agent,
                                                  address_scopes,
                                                  agent_gw_port, rfp_device,
                                                  fpr_device,
                                                  no_external=False):

        router.router[lib_constants.SNAT_ROUTER_INTF_KEY] = []
        router.router['gw_port'] = ""
        router.router['gw_port_host'] = ""
        self.agent._process_updated_router(router.router)
        router_updated = self.agent.router_info[router.router['id']]
        self.assertTrue(self._namespace_exists(router_updated.ns_name))
        if not no_external:
            self.assertFalse(rfp_device.exists())
            self.assertFalse(fpr_device.exists())
            self._assert_fip_namespace_deleted(
                agent_gw_port, assert_ovs_interface=False)
        if not address_scopes or no_external:
            ip4_rules_list = ip_lib.list_ip_rules(router_updated.ns_name,
                                                  lib_constants.IP_VERSION_4)
            ip6_rules_list = ip_lib.list_ip_rules(router_updated.ns_name,
                                                  lib_constants.IP_VERSION_6)
            self.assertEqual(3, len(ip4_rules_list))
            self.assertEqual(2, len(ip6_rules_list))

    def _setup_dvr_router_for_fast_path_exit(self, address_scopes=True):
        """Test to validate the fip and router namespace routes.

        This test validates the fip and router namespace routes
        that are based on the address scopes.
        If the address scopes of internal network and external network
        matches, the traffic will be forwarded to the fip namespace and
        the reverse traffic to the private network is forwarded to the
        router namespace.
        """
        self.agent.conf.agent_mode = 'dvr'
        router_info = self.generate_dvr_router_info(
            enable_snat=True, enable_gw=True, enable_floating_ip=True)
        router_info[lib_constants.FLOATINGIP_KEY] = []
        if address_scopes:
            address_scope1 = {
                str(lib_constants.IP_VERSION_4): 'scope1'}
            address_scope2 = {
                str(lib_constants.IP_VERSION_4): 'scope1'}
        else:
            address_scope1 = {
                str(lib_constants.IP_VERSION_4): 'scope2'}
            address_scope2 = {
                str(lib_constants.IP_VERSION_4): 'scope2'}
        router_info['gw_port']['address_scopes'] = {
            str(lib_constants.IP_VERSION_4): 'scope1'}
        router_info[lib_constants.INTERFACE_KEY][0]['address_scopes'] = (
            address_scope1)
        router_info[lib_constants.INTERFACE_KEY][1]['address_scopes'] = (
            address_scope2)
        # should have the same address_scopes as gw_port
        fip_agent_gw_ports = router_info[
            lib_constants.FLOATINGIP_AGENT_INTF_KEY]
        fip_agent_gw_ports[0]['address_scopes'] = (
            router_info['gw_port']['address_scopes'])
        self.mock_plugin_api.get_agent_gateway_port.return_value = (
            fip_agent_gw_ports[0])
        router1 = self.manage_router(self.agent, router_info)
        fip_ns_name = router1.fip_ns.get_name()
        self.assertTrue(self._namespace_exists(router1.ns_name))
        self.assertTrue(self._namespace_exists(fip_ns_name))

        # Check the router namespace for default route.
        rfp_device_name = router1.fip_ns.get_rtr_ext_device_name(
            router1.router_id)
        rfp_device = ip_lib.IPDevice(rfp_device_name,
                                     namespace=router1.ns_name)
        fpr_device_name = router1.fip_ns.get_int_device_name(router1.router_id)
        fpr_device = ip_lib.IPDevice(fpr_device_name,
                                     namespace=fip_ns_name)
        rtr_2_fip, fip_2_rtr = router1.rtr_fip_subnet.get_pair()
        self._assert_default_gateway(
            fip_2_rtr, rfp_device, rfp_device_name, fpr_device)

        # Check if any snat redirect rules in the router namespace exist.
        ip4_rules_list = ip_lib.list_ip_rules(router1.ns_name,
                                              lib_constants.IP_VERSION_4)
        ip6_rules_list = ip_lib.list_ip_rules(router1.ns_name,
                                              lib_constants.IP_VERSION_6)
        # Just make sure the basic set of rules are there in the router
        # namespace
        self.assertEqual(5, len(ip4_rules_list))
        self.assertEqual(2, len(ip6_rules_list))
        # Now check the fip namespace static routes for reaching the private
        # network.
        self._assert_fip_namespace_interface_static_routes(
            address_scopes, fpr_device,
            router_info, rtr_2_fip, fpr_device_name)

        # Now remove the gateway and validate if the respective interface
        # routes in router namespace is deleted respectively.
        self. _assert_interface_rules_on_gateway_remove(
            router1, self.agent, address_scopes, fip_agent_gw_ports[0],
            rfp_device, fpr_device)

    def test_dvr_fip_and_router_namespace_rules_with_address_scopes_match(
            self):
        self._setup_dvr_router_for_fast_path_exit(address_scopes=True)

    def test_dvr_fip_and_router_namespace_rules_with_address_scopes_mismatch(
            self):
        self._setup_dvr_router_for_fast_path_exit(address_scopes=False)

    @mock.patch.object(dvr_local_router.DvrLocalRouter,
                       '_add_interface_routing_rule_to_router_ns')
    @mock.patch.object(dvr_local_router.DvrLocalRouter,
                       '_add_interface_route_to_fip_ns')
    def test_dvr_no_external_router_namespace_rules_with_address_scopes_match(
            self, mock_add_interface_route_rule,
            mock_add_fip_interface_route_rule):
        """Test to validate the router namespace routes.

        This test validates the router namespace routes
        that are based on the address scopes.
        If the address scopes of internal network and external network
        matches, the traffic will be forwarded to SNAT namespace
        for agents that don't have external connectivity or configured
        as DVR_NO_EXTERNAL.
        """
        self.agent.conf.agent_mode = (
            lib_constants.L3_AGENT_MODE_DVR_NO_EXTERNAL)
        router_info = self.generate_dvr_router_info(
            enable_snat=True, enable_gw=True, enable_floating_ip=True)
        router_info[lib_constants.FLOATINGIP_KEY] = []
        address_scope1 = {
            str(lib_constants.IP_VERSION_4): 'scope1'}
        address_scope2 = {
            str(lib_constants.IP_VERSION_4): 'scope1'}
        router_info['gw_port']['address_scopes'] = {
            str(lib_constants.IP_VERSION_4): 'scope1'}
        router_info[lib_constants.INTERFACE_KEY][0]['address_scopes'] = (
            address_scope1)
        router_info[lib_constants.INTERFACE_KEY][1]['address_scopes'] = (
            address_scope2)
        router1 = self.manage_router(self.agent, router_info)
        self.assertTrue(self._namespace_exists(router1.ns_name))
        self.assertFalse(mock_add_interface_route_rule.called)
        self.assertFalse(mock_add_fip_interface_route_rule.called)
        # Check if any snat redirect rules in the router namespace exist.
        ip4_rules_list = ip_lib.list_ip_rules(router1.ns_name,
                                              lib_constants.IP_VERSION_4)
        ip6_rules_list = ip_lib.list_ip_rules(router1.ns_name,
                                              lib_constants.IP_VERSION_6)
        # Just make sure the basic set of rules are there in the router
        # namespace
        self.assertEqual(5, len(ip4_rules_list))
        self.assertEqual(2, len(ip6_rules_list))

        # Now remove the gateway and validate if the respective interface
        # routes in router namespace is deleted respectively.
        self. _assert_interface_rules_on_gateway_remove(
            router1, self.agent, True, mock.ANY,
            mock.ANY, mock.ANY, True)

    def test_dvr_router_gateway_update_to_none(self):
        self.agent.conf.agent_mode = 'dvr_snat'
        router_info = self.generate_dvr_router_info(enable_snat=True)
        router = self.manage_router(self.agent, router_info)
        gw_port = router.get_ex_gw_port()
        ex_gw_port_name = router.get_external_device_name(gw_port['id'])
        ex_gw_device = ip_lib.IPDevice(ex_gw_port_name,
                                       namespace=router.snat_namespace.name)
        fg_port = router.fip_ns.agent_gateway_port
        fg_port_name = router.fip_ns.get_ext_device_name(fg_port['id'])
        fg_device = ip_lib.IPDevice(fg_port_name,
                                    namespace=router.fip_ns.name)
        rtr_2_fip, fip_2_rtr = router.rtr_fip_subnet.get_pair()
        tbl_index = router._get_snat_idx(fip_2_rtr)

        self.assertIn('via', ex_gw_device.route.get_gateway())
        self.assertIn('via', fg_device.route.get_gateway(table=tbl_index))

        # Make this copy to make agent think gw_port changed.
        router.ex_gw_port = copy.deepcopy(router.ex_gw_port)
        for subnet in gw_port['subnets']:
            subnet['gateway_ip'] = None
        new_fg_port = copy.deepcopy(fg_port)
        for subnet in new_fg_port['subnets']:
            subnet['gateway_ip'] = None

        router.router[lib_constants.FLOATINGIP_AGENT_INTF_KEY] = [new_fg_port]
        router.process()
        self.assertIsNone(ex_gw_device.route.get_gateway())
        self.assertIsNone(fg_device.route.get_gateway())

    def _assert_fip_namespace_deleted(self, ext_gateway_port,
                                      assert_ovs_interface=True,
                                      enable_gw=True):
        if not enable_gw:
            self.assertEqual({}, ext_gateway_port)
            return

        ext_net_id = ext_gateway_port['network_id']
        fip_ns = self.agent.get_fip_ns(ext_net_id)
        fip_ns.unsubscribe = mock.Mock()
        self.agent.fipnamespace_delete_on_ext_net(
            self.agent.context, ext_net_id)
        if assert_ovs_interface:
            self._assert_interfaces_deleted_from_ovs()
        fip_ns_name = fip_ns.get_name()
        self.assertFalse(self._namespace_exists(fip_ns_name))
        self.assertTrue(fip_ns.destroyed)
        self.assertTrue(fip_ns.unsubscribe.called)

    def _setup_address_scope(self, internal_address_scope1,
                             internal_address_scope2, gw_address_scope=None):
        router_info = self.generate_dvr_router_info(enable_snat=True)
        address_scope1 = {
            str(lib_constants.IP_VERSION_4): internal_address_scope1}
        address_scope2 = {
            str(lib_constants.IP_VERSION_4): internal_address_scope2}
        if gw_address_scope:
            router_info['gw_port']['address_scopes'] = {
                str(lib_constants.IP_VERSION_4): gw_address_scope}
            fip_agent_gw_ports = router_info[
                lib_constants.FLOATINGIP_AGENT_INTF_KEY]
            fip_agent_gw_ports[0]['address_scopes'] = router_info['gw_port'][
                'address_scopes']
        router_info[lib_constants.INTERFACE_KEY][0]['address_scopes'] = (
            address_scope1)
        router_info[lib_constants.INTERFACE_KEY][1]['address_scopes'] = (
            address_scope2)
        # Renew the address scope
        router_info[lib_constants.SNAT_ROUTER_INTF_KEY] = []
        self._add_snat_port_info_to_router(
            router_info, router_info[lib_constants.INTERFACE_KEY])

        router = self.manage_router(self.agent, router_info)
        router_ip_cidr1 = self._port_first_ip_cidr(router.internal_ports[0])
        router_ip1 = router_ip_cidr1.partition('/')[0]
        router_ip_cidr2 = self._port_first_ip_cidr(router.internal_ports[1])
        router_ip2 = router_ip_cidr2.partition('/')[0]

        br_int = framework.get_ovs_bridge(
            self.agent.conf.OVS.integration_bridge)
        test_machine1 = self.useFixture(
            machine_fixtures.FakeMachine(
                br_int,
                net_helpers.increment_ip_cidr(router_ip_cidr1, 10),
                router_ip1))
        test_machine2 = self.useFixture(
            machine_fixtures.FakeMachine(
                br_int,
                net_helpers.increment_ip_cidr(router_ip_cidr2, 10),
                router_ip2))

        return test_machine1, test_machine2, router

    def test_connection_from_same_address_scope(self):
        self.agent.conf.agent_mode = 'dvr_snat'
        test_machine1, test_machine2, _ = self._setup_address_scope(
            'scope1', 'scope1')
        # Internal networks that are in the same address scope can connected
        # each other
        net_helpers.assert_ping(test_machine1.namespace, test_machine2.ip)
        net_helpers.assert_ping(test_machine2.namespace, test_machine1.ip)

    def test_connection_from_diff_address_scope(self):
        self.agent.conf.agent_mode = 'dvr_snat'
        test_machine1, test_machine2, _ = self._setup_address_scope(
            'scope1', 'scope2')
        # Internal networks that are not in the same address scope should
        # not reach each other
        test_machine1.assert_no_ping(test_machine2.ip)
        test_machine2.assert_no_ping(test_machine1.ip)

    @testtools.skip('bug/1543885')
    def test_fip_connection_for_address_scope(self):
        self.agent.conf.agent_mode = 'dvr_snat'
        (machine_same_scope, machine_diff_scope,
            router) = self._setup_address_scope('scope1', 'scope2', 'scope1')

        router.router[lib_constants.FLOATINGIP_KEY] = []
        fip_same_scope = '19.4.4.10'
        self._add_fip(router, fip_same_scope,
                      fixed_address=machine_same_scope.ip,
                      host=self.agent.conf.host,
                      fixed_ip_address_scope='scope1')
        fip_diff_scope = '19.4.4.11'
        self._add_fip(router, fip_diff_scope,
                      fixed_address=machine_diff_scope.ip,
                      host=self.agent.conf.host,
                      fixed_ip_address_scope='scope2')
        router.process()

        br_int = framework.get_ovs_bridge(
            self.agent.conf.OVS.integration_bridge)
        src_machine = self.useFixture(
            machine_fixtures.FakeMachine(br_int, '19.4.4.12/24'))
        # Floating ip should work no matter of address scope
        net_helpers.assert_ping(src_machine.namespace, fip_same_scope)
        net_helpers.assert_ping(src_machine.namespace, fip_diff_scope)

    def test_direct_route_for_address_scope(self):
        self.agent.conf.agent_mode = 'dvr_snat'
        (machine_same_scope, machine_diff_scope,
            router) = self._setup_address_scope('scope1', 'scope2', 'scope1')

        gw_port = router.get_ex_gw_port()
        gw_ip = self._port_first_ip_cidr(gw_port).partition('/')[0]
        br_int = framework.get_ovs_bridge(
            self.agent.conf.OVS.integration_bridge)

        src_machine = self.useFixture(
            machine_fixtures.FakeMachine(br_int, '19.4.4.12/24', gw_ip))
        # For the internal networks that are in the same address scope as
        # external network, they can directly route to external network
        net_helpers.assert_ping(src_machine.namespace, machine_same_scope.ip)
        # For the internal networks that are not in the same address scope as
        # external networks. SNAT will be used. Direct route will not work
        # here.
        src_machine.assert_no_ping(machine_diff_scope.ip)

    def test_dvr_snat_namespace_has_ip_nonlocal_bind_enabled(self):
        self.agent.conf.agent_mode = 'dvr_snat'
        router_info = self.generate_dvr_router_info(
            enable_ha=True, enable_snat=True)
        router = self.manage_router(self.agent, router_info)
        try:
            ip_nonlocal_bind_value = ip_lib.get_ip_nonlocal_bind(
                router.snat_namespace.name)
        except RuntimeError as rte:
            stat_message = 'cannot stat /proc/sys/net/ipv4/ip_nonlocal_bind'
            if stat_message in str(rte):
                raise self.skipException(
                    "This kernel doesn't support %s in network namespaces." % (
                        ip_lib.IP_NONLOCAL_BIND))
            raise
        self.assertEqual(1, ip_nonlocal_bind_value)

    def test_dvr_router_fip_namespace_routes(self):
        """Test to validate the floatingip namespace subnets routes."""
        self.agent.conf.agent_mode = 'dvr'
        router_info = self.generate_dvr_router_info(enable_floating_ip=False)
        fip_agent_gw_port = self._get_fip_agent_gw_port_for_router(
            router_info['gw_port'])
        self.mock_plugin_api.get_agent_gateway_port.return_value = (
            fip_agent_gw_port)
        router1 = self.manage_router(self.agent, router_info)

        fip_namespace = router1.fip_ns.get_name()
        ip_wrapper = ip_lib.IPWrapper(namespace=fip_namespace)
        interfaces = ip_wrapper.get_devices()
        fg_interface_name = next(
            interface.name for interface in interfaces
            if interface.name.startswith(dvr_fip_ns.FIP_EXT_DEV_PREFIX))

        ip_device = ip_lib.IPDevice(fg_interface_name, namespace=fip_namespace)
        routes = ip_device.route.list_onlink_routes(lib_constants.IP_VERSION_4)
        self.assertGreater(len(routes), 0)
        self.assertEqual(len(fip_agent_gw_port['extra_subnets']), len(routes))
        extra_subnet_cidr = set(extra_subnet['cidr'] for extra_subnet
                                in fip_agent_gw_port['extra_subnets'])
        routes_cidr = set(route['cidr'] for route in routes)
        self.assertEqual(extra_subnet_cidr, routes_cidr)

    def test_dvr_router_update_ecmp_routes(self):
        self.agent.conf.agent_mode = 'dvr'
        router_info = self.generate_dvr_router_info()
        router1 = self.manage_router(self.agent, router_info)
        router1.router['routes'] = [{'destination': '20.0.10.10/32',
                                     'nexthop': '35.4.0.11'},
                                    {'destination': '20.0.10.10/32',
                                     'nexthop': '35.4.0.22'},
                                    {'destination': '20.0.10.10/32',
                                     'nexthop': '35.4.0.33'}]
        self.agent._process_updated_router(router1.router)
        route_expected = {'cidr': '20.0.10.10/32',
                          'table': 'main',
                          'via': [{'via': '35.4.0.11'},
                                  {'via': '35.4.0.22'},
                                  {'via': '35.4.0.33'}]}

        self._assert_ecmp_route_in_routes(router=router1,
                                          expected_route=route_expected)

        # delete one route
        router1.router['routes'] = [{'destination': '20.0.10.10/32',
                                     'nexthop': '35.4.0.11'},
                                    {'destination': '20.0.10.10/32',
                                     'nexthop': '35.4.0.22'}]
        self.agent._process_updated_router(router1.router)
        route_expected = {'cidr': '20.0.10.10/32',
                          'table': 'main',
                          'via': [{'via': '35.4.0.11'},
                                  {'via': '35.4.0.22'}]}

        self._assert_ecmp_route_in_routes(router=router1,
                                          expected_route=route_expected)

        # delete one route again
        router1.router['routes'] = [{'destination': '20.0.10.10/32',
                                     'nexthop': '35.4.0.11'}]
        self.agent._process_updated_router(router1.router)
        route_expected = {'cidr': '20.0.10.10/32',
                          'table': 'main',
                          'via': '35.4.0.11'}
        self._assert_route_in_routes(router=router1,
                                     expected_route=route_expected)

    def _test_router_interface_mtu_update(self, ha):
        original_mtu = 1450
        router_info = self.generate_dvr_router_info(
            enable_ha=ha, enable_snat=True)
        router_info['_interfaces'][0]['mtu'] = original_mtu
        router_info['gw_port']['mtu'] = original_mtu
        router_info[lib_constants.SNAT_ROUTER_INTF_KEY][0]['mtu'] = (
            original_mtu)

        router = self.manage_router(self.agent, router_info)
        if ha:
            utils.wait_until_true(lambda: router.ha_state == 'primary')
            # Keepalived notifies of a state transition when it starts,
            # not when it ends. Thus, we have to wait until keepalived finishes
            # configuring everything. We verify this by waiting until the last
            # device has an IP address.
            device = router.router[lib_constants.INTERFACE_KEY][-1]
            device_exists = functools.partial(
                self.device_exists_with_ips_and_mac,
                device,
                router.get_internal_device_name,
                router.ns_name)
            utils.wait_until_true(device_exists)

        interface_name = router.get_internal_device_name(
            router_info['_interfaces'][0]['id'])
        gw_interface_name = router.get_external_device_name(
            router_info['gw_port']['id'])
        snat_internal_port = router_info[lib_constants.SNAT_ROUTER_INTF_KEY]
        snat_interface_name = router._get_snat_int_device_name(
            snat_internal_port[0]['id'])
        snat_namespace = dvr_snat_ns.SnatNamespace.get_snat_ns_name(
            router_info['id'])

        self.assertEqual(
            original_mtu,
            ip_lib.IPDevice(interface_name, router.ns_name).link.mtu)
        self.assertEqual(
            original_mtu,
            ip_lib.IPDevice(gw_interface_name, snat_namespace).link.mtu)
        self.assertEqual(
            original_mtu,
            ip_lib.IPDevice(snat_interface_name, snat_namespace).link.mtu)

        updated_mtu = original_mtu + 1
        router_info_copy = copy.deepcopy(router_info)
        router_info_copy['_interfaces'][0]['mtu'] = updated_mtu
        router_info_copy['gw_port']['mtu'] = updated_mtu
        router_info_copy[lib_constants.SNAT_ROUTER_INTF_KEY][0]['mtu'] = (
            updated_mtu)

        self.agent._process_updated_router(router_info_copy)

        self.assertEqual(
            updated_mtu,
            ip_lib.IPDevice(interface_name, router.ns_name).link.mtu)
        self.assertEqual(
            updated_mtu,
            ip_lib.IPDevice(gw_interface_name, snat_namespace).link.mtu)
        self.assertEqual(
            updated_mtu,
            ip_lib.IPDevice(snat_interface_name, snat_namespace).link.mtu)

    def test_dvr_router_interface_mtu_update(self):
        self._test_router_interface_mtu_update(ha=False)

    def test_dvr_ha_router_interface_mtu_update(self):
        self.skipTest(
            'Skip this test in 2023.2 until this patch and '
            'https://review.opendev.org/c/openstack/neutron/+/897439 are '
            'merged')
        self._test_router_interface_mtu_update(ha=True)
