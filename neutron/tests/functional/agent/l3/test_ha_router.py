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

import mock
from neutron_lib import constants
import six
import testtools

from neutron.agent.l3 import agent as neutron_l3_agent
from neutron.agent.l3 import namespaces
from neutron.agent.linux import ip_lib
from neutron.common import ipv6_utils
from neutron.common import utils as common_utils
from neutron.tests.common import l3_test_common
from neutron.tests.common import net_helpers
from neutron.tests.functional.agent.l3 import framework


class L3HATestCase(framework.L3AgentTestFramework):

    def test_ha_router_update_floatingip_statuses(self):
        self._test_update_floatingip_statuses(
            self.generate_router_info(enable_ha=True))

    def test_keepalived_state_change_notification(self):
        enqueue_mock = mock.patch.object(
            self.agent, 'enqueue_state_change').start()
        router_info = self.generate_router_info(enable_ha=True)
        router = self.manage_router(self.agent, router_info)
        common_utils.wait_until_true(lambda: router.ha_state == 'master')

        self.fail_ha_router(router)
        common_utils.wait_until_true(lambda: router.ha_state == 'backup')

        common_utils.wait_until_true(lambda: enqueue_mock.call_count == 3)
        calls = [args[0] for args in enqueue_mock.call_args_list]
        self.assertEqual((router.router_id, 'backup'), calls[0])
        self.assertEqual((router.router_id, 'master'), calls[1])
        self.assertEqual((router.router_id, 'backup'), calls[2])

    def _expected_rpc_report(self, expected):
        calls = (args[0][1] for args in
                 self.agent.plugin_rpc.update_ha_routers_states.call_args_list)

        # Get the last state reported for each router
        actual_router_states = {}
        for call in calls:
            for router_id, state in six.iteritems(call):
                actual_router_states[router_id] = state

        return actual_router_states == expected

    def test_keepalived_state_change_bulk_rpc(self):
        router_info = self.generate_router_info(enable_ha=True)
        router1 = self.manage_router(self.agent, router_info)
        self.fail_ha_router(router1)
        router_info = self.generate_router_info(enable_ha=True)
        router2 = self.manage_router(self.agent, router_info)

        common_utils.wait_until_true(lambda: router1.ha_state == 'backup')
        common_utils.wait_until_true(lambda: router2.ha_state == 'master')
        common_utils.wait_until_true(
            lambda: self._expected_rpc_report(
                {router1.router_id: 'standby', router2.router_id: 'active'}))

    def test_ha_router_lifecycle(self):
        self._router_lifecycle(enable_ha=True)

    def test_conntrack_disassociate_fip_ha_router(self):
        self._test_conntrack_disassociate_fip(ha=True)

    def test_ipv6_ha_router_lifecycle(self):
        self._router_lifecycle(enable_ha=True, ip_version=6)

    def test_ipv6_ha_router_lifecycle_with_no_gw_subnet(self):
        self.agent.conf.set_override('ipv6_gateway',
                                     'fe80::f816:3eff:fe2e:1')
        self._router_lifecycle(enable_ha=True, ip_version=6,
                               v6_ext_gw_with_sub=False)

    def test_ipv6_ha_router_lifecycle_with_no_gw_subnet_for_router_advts(self):
        # Verify that router gw interface is configured to receive Router
        # Advts from upstream router when no external gateway is configured.
        self._router_lifecycle(enable_ha=True, dual_stack=True,
                               v6_ext_gw_with_sub=False)

    @testtools.skipUnless(ipv6_utils.is_enabled(), "IPv6 is not enabled")
    def test_ipv6_router_advts_after_router_state_change(self):
        # Schedule router to l3 agent, and then add router gateway. Verify
        # that router gw interface is configured to receive Router Advts.
        router_info = l3_test_common.prepare_router_data(
            enable_snat=True, enable_ha=True, dual_stack=True, enable_gw=False)
        router = self.manage_router(self.agent, router_info)
        common_utils.wait_until_true(lambda: router.ha_state == 'master')
        _ext_dev_name, ex_port = l3_test_common.prepare_ext_gw_test(
            mock.Mock(), router)
        router_info['gw_port'] = ex_port
        router.process(self.agent)
        self._assert_ipv6_accept_ra(router)

    def test_keepalived_configuration(self):
        router_info = self.generate_router_info(enable_ha=True)
        router = self.manage_router(self.agent, router_info)
        expected = self.get_expected_keepalive_configuration(router)

        self.assertEqual(expected,
                         router.keepalived_manager.get_conf_on_disk())

        # Add a new FIP and change the GW IP address
        router.router = copy.deepcopy(router.router)
        existing_fip = '19.4.4.2'
        new_fip = '19.4.4.3'
        self._add_fip(router, new_fip)
        subnet_id = framework._uuid()
        fixed_ips = [{'ip_address': '19.4.4.10',
                      'prefixlen': 24,
                      'subnet_id': subnet_id}]
        subnets = [{'id': subnet_id,
                    'cidr': '19.4.4.0/24',
                    'gateway_ip': '19.4.4.5'}]
        router.router['gw_port']['subnets'] = subnets
        router.router['gw_port']['fixed_ips'] = fixed_ips

        router.process(self.agent)

        # Get the updated configuration and assert that both FIPs are in,
        # and that the GW IP address was updated.
        new_config = router.keepalived_manager.config.get_config_str()
        old_gw = '0.0.0.0/0 via 19.4.4.1'
        new_gw = '0.0.0.0/0 via 19.4.4.5'
        old_external_device_ip = '19.4.4.4'
        new_external_device_ip = '19.4.4.10'
        self.assertIn(existing_fip, new_config)
        self.assertIn(new_fip, new_config)
        self.assertNotIn(old_gw, new_config)
        self.assertIn(new_gw, new_config)
        external_port = router.get_ex_gw_port()
        external_device_name = router.get_external_device_name(
            external_port['id'])
        self.assertNotIn('%s/24 dev %s' %
                         (old_external_device_ip, external_device_name),
                         new_config)
        self.assertIn('%s/24 dev %s' %
                      (new_external_device_ip, external_device_name),
                      new_config)

    def test_ha_router_conf_on_restarted_agent(self):
        router_info = self.generate_router_info(enable_ha=True)
        router1 = self.manage_router(self.agent, router_info)
        self._add_fip(router1, '192.168.111.12')
        restarted_agent = neutron_l3_agent.L3NATAgentWithStateReport(
            self.agent.host, self.agent.conf)
        self.manage_router(restarted_agent, router1.router)
        common_utils.wait_until_true(
            lambda: self.floating_ips_configured(router1))
        self.assertIn(
            router1._get_primary_vip(),
            self._get_addresses_on_device(
                router1.ns_name,
                router1.get_ha_device_name()))

    def test_ha_router_ipv6_radvd_status(self):
        router_info = self.generate_router_info(ip_version=6, enable_ha=True)
        router1 = self.manage_router(self.agent, router_info)
        common_utils.wait_until_true(lambda: router1.ha_state == 'master')
        common_utils.wait_until_true(lambda: router1.radvd.enabled)

        def _check_lla_status(router, expected):
            internal_devices = router.router[constants.INTERFACE_KEY]
            for device in internal_devices:
                lladdr = ip_lib.get_ipv6_lladdr(device['mac_address'])
                exists = ip_lib.device_exists_with_ips_and_mac(
                    router.get_internal_device_name(device['id']), [lladdr],
                    device['mac_address'], router.ns_name)
                self.assertEqual(expected, exists)

        _check_lla_status(router1, True)

        device_name = router1.get_ha_device_name()
        ha_device = ip_lib.IPDevice(device_name, namespace=router1.ns_name)
        ha_device.link.set_down()

        common_utils.wait_until_true(lambda: router1.ha_state == 'backup')
        common_utils.wait_until_true(
            lambda: not router1.radvd.enabled, timeout=10)
        _check_lla_status(router1, False)

    def test_ha_router_process_ipv6_subnets_to_existing_port(self):
        router_info = self.generate_router_info(enable_ha=True, ip_version=6)
        router = self.manage_router(self.agent, router_info)

        def verify_ip_in_keepalived_config(router, iface):
            config = router.keepalived_manager.config.get_config_str()
            ip_cidrs = common_utils.fixed_ip_cidrs(iface['fixed_ips'])
            for ip_addr in ip_cidrs:
                self.assertIn(ip_addr, config)

        interface_id = router.router[constants.INTERFACE_KEY][0]['id']
        slaac = constants.IPV6_SLAAC
        slaac_mode = {'ra_mode': slaac, 'address_mode': slaac}

        # Add a second IPv6 subnet to the router internal interface.
        self._add_internal_interface_by_subnet(router.router, count=1,
                ip_version=6, ipv6_subnet_modes=[slaac_mode],
                interface_id=interface_id)
        router.process(self.agent)
        common_utils.wait_until_true(lambda: router.ha_state == 'master')

        # Verify that router internal interface is present and is configured
        # with IP address from both the subnets.
        internal_iface = router.router[constants.INTERFACE_KEY][0]
        self.assertEqual(2, len(internal_iface['fixed_ips']))
        self._assert_internal_devices(router)

        # Verify that keepalived config is properly updated.
        verify_ip_in_keepalived_config(router, internal_iface)

        # Remove one subnet from the router internal iface
        interfaces = copy.deepcopy(router.router.get(
            constants.INTERFACE_KEY, []))
        fixed_ips, subnets = [], []
        fixed_ips.append(interfaces[0]['fixed_ips'][0])
        subnets.append(interfaces[0]['subnets'][0])
        interfaces[0].update({'fixed_ips': fixed_ips, 'subnets': subnets})
        router.router[constants.INTERFACE_KEY] = interfaces
        router.process(self.agent)

        # Verify that router internal interface has a single ipaddress
        internal_iface = router.router[constants.INTERFACE_KEY][0]
        self.assertEqual(1, len(internal_iface['fixed_ips']))
        self._assert_internal_devices(router)

        # Verify that keepalived config is properly updated.
        verify_ip_in_keepalived_config(router, internal_iface)

    def test_delete_external_gateway_on_standby_router(self):
        router_info = self.generate_router_info(enable_ha=True)
        router = self.manage_router(self.agent, router_info)

        self.fail_ha_router(router)
        common_utils.wait_until_true(lambda: router.ha_state == 'backup')

        # The purpose of the test is to simply make sure no exception is raised
        port = router.get_ex_gw_port()
        interface_name = router.get_external_device_name(port['id'])
        router.external_gateway_removed(port, interface_name)

    def test_removing_floatingip_immediately(self):
        router_info = self.generate_router_info(enable_ha=True)
        router = self.manage_router(self.agent, router_info)
        ex_gw_port = router.get_ex_gw_port()
        interface_name = router.get_external_device_interface_name(ex_gw_port)
        common_utils.wait_until_true(lambda: router.ha_state == 'master')
        self._add_fip(router, '172.168.1.20', fixed_address='10.0.0.3')
        router.process(self.agent)
        router.router[constants.FLOATINGIP_KEY] = []
        # The purpose of the test is to simply make sure no exception is raised
        # Because router.process will consume the FloatingIpSetupException,
        # call the configure_fip_addresses directly here
        router.configure_fip_addresses(interface_name)

    def test_ha_port_status_update(self):
        router_info = self.generate_router_info(enable_ha=True)
        router_info[constants.HA_INTERFACE_KEY]['status'] = (
            constants.PORT_STATUS_DOWN)
        router1 = self.manage_router(self.agent, router_info)
        common_utils.wait_until_true(lambda: router1.ha_state == 'backup')

        router1.router[constants.HA_INTERFACE_KEY]['status'] = (
            constants.PORT_STATUS_ACTIVE)
        self.agent._process_updated_router(router1.router)
        common_utils.wait_until_true(lambda: router1.ha_state == 'master')


class L3HATestFailover(framework.L3AgentTestFramework):

    NESTED_NAMESPACE_SEPARATOR = '@'

    def setUp(self):
        super(L3HATestFailover, self).setUp()
        conf = self._configure_agent('agent2')
        self.failover_agent = neutron_l3_agent.L3NATAgentWithStateReport(
            'agent2', conf)

        br_int_1 = self._get_agent_ovs_integration_bridge(self.agent)
        br_int_2 = self._get_agent_ovs_integration_bridge(self.failover_agent)

        veth1, veth2 = self.useFixture(net_helpers.VethFixture()).ports
        br_int_1.add_port(veth1.name)
        br_int_2.add_port(veth2.name)

    def test_ha_router_failover(self):
        router_info = self.generate_router_info(enable_ha=True)
        get_ns_name = mock.patch.object(
            namespaces.RouterNamespace, '_get_ns_name').start()
        get_ns_name.return_value = "%s%s%s" % (
            'qrouter-' + router_info['id'],
            self.NESTED_NAMESPACE_SEPARATOR, self.agent.host)
        router1 = self.manage_router(self.agent, router_info)

        router_info_2 = copy.deepcopy(router_info)
        router_info_2[constants.HA_INTERFACE_KEY] = (
            l3_test_common.get_ha_interface(ip='169.254.192.2',
                                            mac='22:22:22:22:22:22'))

        get_ns_name.return_value = "%s%s%s" % (
            namespaces.RouterNamespace._get_ns_name(router_info_2['id']),
            self.NESTED_NAMESPACE_SEPARATOR, self.failover_agent.host)
        router2 = self.manage_router(self.failover_agent, router_info_2)

        common_utils.wait_until_true(lambda: router1.ha_state == 'master')
        common_utils.wait_until_true(lambda: router2.ha_state == 'backup')

        self.fail_ha_router(router1)

        common_utils.wait_until_true(lambda: router2.ha_state == 'master')
        common_utils.wait_until_true(lambda: router1.ha_state == 'backup')
