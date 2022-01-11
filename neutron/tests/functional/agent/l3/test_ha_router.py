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
from unittest import mock

from neutron_lib import constants
from oslo_log import log as logging
from oslo_utils import netutils
import testtools

from neutron.agent.common import ovs_lib
from neutron.agent.l3 import agent as neutron_l3_agent
from neutron.agent.linux import ip_lib
from neutron.common import utils as common_utils
from neutron.tests.common import l3_test_common
from neutron.tests.common import net_helpers
from neutron.tests.functional.agent.l3 import framework


LOG = logging.getLogger(__name__)


class L3HATestCase(framework.L3AgentTestFramework):

    def test_ha_router_update_floatingip_statuses(self):
        self._test_update_floatingip_statuses(
            self.generate_router_info(enable_ha=True))

    def test_keepalived_state_change_notification(self):
        enqueue_mock = mock.patch.object(
            self.agent, 'enqueue_state_change',
            side_effect=self.change_router_state).start()
        router_info = self.generate_router_info(enable_ha=True)
        router = self.manage_router(self.agent, router_info)
        self.wait_until_ha_router_has_state(router, 'primary')

        self.fail_ha_router(router)
        self.wait_until_ha_router_has_state(router, 'backup')

        def enqueue_call_count_match():
            LOG.debug("enqueue_mock called %s times.", enqueue_mock.call_count)
            return enqueue_mock.call_count in [2, 3]

        common_utils.wait_until_true(enqueue_call_count_match)
        calls = [args[0] for args in enqueue_mock.call_args_list]
        self.assertEqual((router.router_id, 'primary'), calls[-2])
        self.assertEqual((router.router_id, 'backup'), calls[-1])

    def _expected_rpc_report(self, expected):
        calls = (args[0][1] for args in
                 self.agent.plugin_rpc.update_ha_routers_states.call_args_list)

        # Get the last state reported for each router
        actual_router_states = {}
        for call in calls:
            for router_id, state in call.items():
                actual_router_states[router_id] = state

        return actual_router_states == expected

    def test_keepalived_state_change_bulk_rpc(self):
        router_info = self.generate_router_info(enable_ha=True)
        router1 = self.manage_router(self.agent, router_info)
        self.fail_ha_router(router1)
        router_info = self.generate_router_info(enable_ha=True)
        router2 = self.manage_router(self.agent, router_info)

        self.wait_until_ha_router_has_state(router1, 'backup')
        self.wait_until_ha_router_has_state(router2, 'primary')
        common_utils.wait_until_true(
            lambda: self._expected_rpc_report(
                {router1.router_id: 'standby', router2.router_id: 'active'}))

    def test_ha_router_lifecycle(self):
        router_info = self._router_lifecycle(enable_ha=True)
        # ensure everything was cleaned up
        self._router_lifecycle(enable_ha=True, router_info=router_info)

    def test_conntrack_disassociate_fip_ha_router(self):
        self._test_conntrack_disassociate_fip(ha=True)

    def test_ipv6_ha_router_lifecycle(self):
        self._router_lifecycle(enable_ha=True,
                               ip_version=constants.IP_VERSION_6)

    def test_ipv6_ha_router_lifecycle_with_no_gw_subnet(self):
        self.agent.conf.set_override('ipv6_gateway',
                                     'fe80::f816:3eff:fe2e:1')
        self._router_lifecycle(enable_ha=True,
                               ip_version=constants.IP_VERSION_6,
                               v6_ext_gw_with_sub=False)

    def test_ipv6_ha_router_lifecycle_with_no_gw_subnet_for_router_advts(self):
        # Verify that router gw interface is configured to receive Router
        # Advts from upstream router when no external gateway is configured.
        self._router_lifecycle(enable_ha=True, dual_stack=True,
                               v6_ext_gw_with_sub=False)

    def _test_ipv6_router_advts_and_fwd_helper(self, state, enable_v6_gw,
                                               expected_ra,
                                               expected_forwarding):
        # Schedule router to l3 agent, and then add router gateway. Verify
        # that router gw interface is configured to receive Router Advts and
        # IPv6 forwarding is enabled.
        router_info = l3_test_common.prepare_router_data(
            enable_snat=True, enable_ha=True, dual_stack=True, enable_gw=False)
        router = self.manage_router(self.agent, router_info)
        self.wait_until_ha_router_has_state(router, 'primary')
        if state == 'backup':
            self.fail_ha_router(router)
            self.wait_until_ha_router_has_state(router, 'backup')
        _ext_dev_name, ex_port = l3_test_common.prepare_ext_gw_test(
            mock.Mock(), router, dual_stack=enable_v6_gw)
        router_info['gw_port'] = ex_port
        router.process()
        self._assert_ipv6_accept_ra(router, expected_ra)
        # As router is going first to primary and than to backup mode,
        # ipv6_forwarding should be enabled on "all" interface always after
        # that transition
        self._assert_ipv6_forwarding(router, expected_forwarding,
                                     True)

    @testtools.skipUnless(netutils.is_ipv6_enabled(), "IPv6 is not enabled")
    def test_ipv6_router_advts_and_fwd_after_router_state_change_primary(self):
        # Check that RA and forwarding are enabled when there's no IPv6
        # gateway.
        self._test_ipv6_router_advts_and_fwd_helper('primary',
                                                    enable_v6_gw=False,
                                                    expected_ra=True,
                                                    expected_forwarding=True)
        # Check that RA is disabled and forwarding is enabled when an IPv6
        # gateway is configured.
        self._test_ipv6_router_advts_and_fwd_helper('primary',
                                                    enable_v6_gw=True,
                                                    expected_ra=False,
                                                    expected_forwarding=True)

    @testtools.skipUnless(netutils.is_ipv6_enabled(), "IPv6 is not enabled")
    def test_ipv6_router_advts_and_fwd_after_router_state_change_backup(self):
        # Check that both RA and forwarding are disabled on backup instances
        self._test_ipv6_router_advts_and_fwd_helper('backup',
                                                    enable_v6_gw=False,
                                                    expected_ra=False,
                                                    expected_forwarding=False)
        self._test_ipv6_router_advts_and_fwd_helper('backup',
                                                    enable_v6_gw=True,
                                                    expected_ra=False,
                                                    expected_forwarding=False)

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

        router.process()

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
        router_info = self.generate_router_info(
            ip_version=constants.IP_VERSION_6, enable_ha=True)
        router1 = self.manage_router(self.agent, router_info)
        self.wait_until_ha_router_has_state(router1, 'primary')
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

        self.wait_until_ha_router_has_state(router1, 'backup')
        common_utils.wait_until_true(
            lambda: not router1.radvd.enabled, timeout=10)
        _check_lla_status(router1, False)

    def test_ha_router_process_ipv6_subnets_to_existing_port(self):
        router_info = self.generate_router_info(enable_ha=True,
            ip_version=constants.IP_VERSION_6)
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
                ip_version=constants.IP_VERSION_6,
                ipv6_subnet_modes=[slaac_mode],
                interface_id=interface_id)
        router.process()
        self.wait_until_ha_router_has_state(router, 'primary')

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
        router.process()

        # Verify that router internal interface has a single ipaddress
        internal_iface = router.router[constants.INTERFACE_KEY][0]
        self.assertEqual(1, len(internal_iface['fixed_ips']))
        self._assert_internal_devices(router)

        # Verify that keepalived config is properly updated.
        verify_ip_in_keepalived_config(router, internal_iface)

    def test_delete_external_gateway_on_standby_router(self):
        router_info = self.generate_router_info(enable_ha=True)
        router = self.manage_router(self.agent, router_info)
        self.wait_until_ha_router_has_state(router, 'primary')

        self.fail_ha_router(router)
        self.wait_until_ha_router_has_state(router, 'backup')

        # The purpose of the test is to simply make sure no exception is raised
        port = router.get_ex_gw_port()
        interface_name = router.get_external_device_name(port['id'])
        router.external_gateway_removed(port, interface_name)

    def test_removing_floatingip_immediately(self):
        router_info = self.generate_router_info(enable_ha=True)
        router = self.manage_router(self.agent, router_info)
        ex_gw_port = router.get_ex_gw_port()
        interface_name = router.get_external_device_interface_name(ex_gw_port)
        self.wait_until_ha_router_has_state(router, 'primary')
        self._add_fip(router, '172.168.1.20', fixed_address='10.0.0.3')
        router.process()
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
        self.wait_until_ha_router_has_state(router1, 'backup')

        router1.router[constants.HA_INTERFACE_KEY]['status'] = (
            constants.PORT_STATUS_ACTIVE)
        self.agent._process_updated_router(router1.router)
        self.wait_until_ha_router_has_state(router1, 'primary')

    def test_ha_router_namespace_has_ip_nonlocal_bind_disabled(self):
        router_info = self.generate_router_info(enable_ha=True)
        router = self.manage_router(self.agent, router_info)
        try:
            ip_nonlocal_bind_value = ip_lib.get_ip_nonlocal_bind(
                router.router_namespace.name)
        except RuntimeError as rte:
            stat_message = 'cannot stat /proc/sys/net/ipv4/ip_nonlocal_bind'
            if stat_message in str(rte):
                raise self.skipException(
                    "This kernel doesn't support %s in network namespaces." % (
                        ip_lib.IP_NONLOCAL_BIND))
            raise
        self.assertEqual(0, ip_nonlocal_bind_value)

    @testtools.skipUnless(netutils.is_ipv6_enabled(), "IPv6 is not enabled")
    def test_ha_router_namespace_has_ipv6_forwarding_disabled(self):
        router_info = self.generate_router_info(enable_ha=True)
        router_info[constants.HA_INTERFACE_KEY]['status'] = (
            constants.PORT_STATUS_DOWN)
        router = self.manage_router(self.agent, router_info)
        external_port = router.get_ex_gw_port()
        external_device_name = router.get_external_device_name(
            external_port['id'])

        self.wait_until_ha_router_has_state(router, 'backup')
        self._wait_until_ipv6_forwarding_has_state(
            router.ns_name, external_device_name, 0)

        router.router[constants.HA_INTERFACE_KEY]['status'] = (
            constants.PORT_STATUS_ACTIVE)
        self.agent._process_updated_router(router.router)
        self.wait_until_ha_router_has_state(router, 'primary')
        self._wait_until_ipv6_forwarding_has_state(
            router.ns_name, external_device_name, 1)

    @testtools.skipUnless(netutils.is_ipv6_enabled(), "IPv6 is not enabled")
    def test_ha_router_without_gw_ipv6_forwarding_state(self):
        router_info = self.generate_router_info(
            enable_ha=True, enable_gw=False)
        router_info[constants.HA_INTERFACE_KEY]['status'] = (
            constants.PORT_STATUS_DOWN)
        router = self.manage_router(self.agent, router_info)

        self.wait_until_ha_router_has_state(router, 'backup')
        self._wait_until_ipv6_forwarding_has_state(router.ns_name, 'all', 0)

        router.router[constants.HA_INTERFACE_KEY]['status'] = (
            constants.PORT_STATUS_ACTIVE)
        self.agent._process_updated_router(router.router)
        self.wait_until_ha_router_has_state(router, 'primary')
        self._wait_until_ipv6_forwarding_has_state(router.ns_name, 'all', 1)

    def test_router_interface_mtu_update(self):
        original_mtu = 1450
        router_info = self.generate_router_info(False)
        router_info['_interfaces'][0]['mtu'] = original_mtu
        router_info['gw_port']['mtu'] = original_mtu

        router = self.manage_router(self.agent, router_info)

        interface_name = router.get_internal_device_name(
            router_info['_interfaces'][0]['id'])
        gw_interface_name = router.get_external_device_name(
            router_info['gw_port']['id'])

        self.assertEqual(
            original_mtu,
            ip_lib.IPDevice(interface_name, router.ns_name).link.mtu)
        self.assertEqual(
            original_mtu,
            ip_lib.IPDevice(gw_interface_name, router.ns_name).link.mtu)

        updated_mtu = original_mtu + 1
        router_info_copy = copy.deepcopy(router_info)
        router_info_copy['_interfaces'][0]['mtu'] = updated_mtu
        router_info_copy['gw_port']['mtu'] = updated_mtu

        self.agent._process_updated_router(router_info_copy)

        self.assertEqual(
            updated_mtu,
            ip_lib.IPDevice(interface_name, router.ns_name).link.mtu)
        self.assertEqual(
            updated_mtu,
            ip_lib.IPDevice(gw_interface_name, router.ns_name).link.mtu)

    def test_ha_router_update_ecmp_routes(self):
        dest_cidr = '8.8.8.0/24'
        nexthop1 = '19.4.4.4'
        nexthop2 = '19.4.4.5'
        router_info = self.generate_router_info(enable_ha=True)

        router = self.manage_router(self.agent, router_info)

        router.router['routes'] = [
            {'destination': dest_cidr, 'nexthop': nexthop1},
            {'destination': dest_cidr, 'nexthop': nexthop2}]
        self.agent._process_updated_router(router.router)

        config = router.keepalived_manager.config.get_config_str()
        self.assertIn(dest_cidr, config)
        self.assertIn(nexthop1, config)
        self.assertIn(nexthop2, config)

        # Delete one route
        router.router['routes'] = [
            {'destination': dest_cidr, 'nexthop': nexthop1}]
        self.agent._process_updated_router(router.router)

        config = router.keepalived_manager.config.get_config_str()
        self.assertIn(dest_cidr, config)
        self.assertIn(nexthop1, config)
        self.assertNotIn(nexthop2, config)


class L3HATestFailover(framework.L3AgentTestFramework):

    def setUp(self):
        super(L3HATestFailover, self).setUp()
        conf = self._configure_agent('agent2')
        self.failover_agent = neutron_l3_agent.L3NATAgentWithStateReport(
            'agent2', conf)

        br_int_1 = self._get_agent_ovs_integration_bridge(self.agent)
        br_int_2 = self._get_agent_ovs_integration_bridge(self.failover_agent)

        veth1, veth2 = self.useFixture(net_helpers.VethFixture()).ports
        veth1.link.set_up()
        veth2.link.set_up()
        br_int_1.add_port(veth1.name)
        br_int_2.add_port(veth2.name)

    @staticmethod
    def fail_gw_router_port(router):
        # NOTE(slaweq): in HA failover tests there are two integration bridges
        # connected with veth pair to each other. To stop traffic from router's
        # namespace to gw ip (19.4.4.1) it needs to be blocked by openflow rule
        # as simple setting ovs_integration_bridge device DOWN will not be
        # enough because same IP address is also configured on
        # ovs_integration_bridge device from second router and it will still
        # respond to ping
        r_br = ovs_lib.OVSBridge(router.driver.conf.OVS.integration_bridge)
        external_port = router.get_ex_gw_port()
        for subnet in external_port['subnets']:
            r_br.add_flow(
                proto='ip', nw_dst=subnet['gateway_ip'], actions='drop')

    @staticmethod
    def restore_gw_router_port(router):
        r_br = ovs_lib.OVSBridge(router.driver.conf.OVS.integration_bridge)
        external_port = router.get_ex_gw_port()
        for subnet in external_port['subnets']:
            r_br.delete_flows(proto='ip', nw_dst=subnet['gateway_ip'])

    def test_ha_router_failover(self):
        router1, router2 = self.create_ha_routers()

        primary_router, backup_router = self._get_primary_and_backup_routers(
            router1, router2)

        self._assert_ipv6_accept_ra(primary_router, True)
        self._assert_ipv6_forwarding(primary_router, True, True)
        self._assert_ipv6_accept_ra(backup_router, False)
        self._assert_ipv6_forwarding(backup_router, False, False)

        self.wait_until_ha_router_has_state(primary_router, 'primary')
        self.wait_until_ha_router_has_state(backup_router, 'backup')

        self.fail_ha_router(router1)

        # NOTE: passing backup_router as first argument, because we expect
        # that this router should be the primary
        new_primary, new_backup = self._get_primary_and_backup_routers(
            backup_router, primary_router)

        self.assertEqual(primary_router, new_backup)
        self.assertEqual(backup_router, new_primary)
        self._assert_ipv6_accept_ra(new_primary, True)
        self._assert_ipv6_forwarding(new_primary, True, True)
        self._assert_ipv6_accept_ra(new_backup, False)
        # after transition from primary -> backup, 'all' IPv6 forwarding should
        # be enabled
        self._assert_ipv6_forwarding(new_backup, False, True)

    def test_ha_router_lost_gw_connection(self):
        self.agent.conf.set_override(
            'ha_vrrp_health_check_interval', 5)
        self.failover_agent.conf.set_override(
            'ha_vrrp_health_check_interval', 5)

        router1, router2 = self.create_ha_routers()

        primary_router, backup_router = self._get_primary_and_backup_routers(
            router1, router2)

        self.fail_gw_router_port(primary_router)

        # NOTE: passing backup_router as first argument, because we expect
        # that this router should be the primary
        new_primary, new_backup = self._get_primary_and_backup_routers(
            backup_router, primary_router)

        self.assertEqual(primary_router, new_backup)
        self.assertEqual(backup_router, new_primary)

    def test_both_ha_router_lost_gw_connection(self):
        self.agent.conf.set_override(
            'ha_vrrp_health_check_interval', 5)
        self.failover_agent.conf.set_override(
            'ha_vrrp_health_check_interval', 5)

        router1, router2 = self.create_ha_routers()

        primary_router, backup_router = self._get_primary_and_backup_routers(
            router1, router2)

        self.fail_gw_router_port(primary_router)
        self.fail_gw_router_port(backup_router)

        self.wait_until_ha_router_has_state(primary_router, 'primary')
        self.wait_until_ha_router_has_state(backup_router, 'primary')

        self.restore_gw_router_port(primary_router)

        new_primary, new_backup = self._get_primary_and_backup_routers(
            primary_router, backup_router)

        self.assertEqual(primary_router, new_primary)
        self.assertEqual(backup_router, new_backup)


class LinuxBridgeL3HATestCase(L3HATestCase):
    INTERFACE_DRIVER = 'neutron.agent.linux.interface.BridgeInterfaceDriver'
