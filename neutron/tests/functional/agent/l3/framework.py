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
import os
from unittest import mock

import netaddr
from neutron_lib import constants
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import uuidutils
import testtools

from neutron.agent.common import ovs_lib
from neutron.agent.l3 import agent as neutron_l3_agent
from neutron.agent.l3 import dvr_local_router
from neutron.agent.l3 import namespaces
from neutron.agent.l3 import router_info as l3_router_info
from neutron.agent import l3_agent as l3_agent_main
from neutron.agent.linux import external_process
from neutron.agent.linux import ip_lib
from neutron.agent.linux import keepalived
from neutron.agent.metadata import driver_base
from neutron.common import utils as common_utils
from neutron.conf.agent import common as agent_config
from neutron.conf.agent.l3 import config as l3_config
from neutron.conf import common as common_config
from neutron.tests import base as test_base
from neutron.tests.common import l3_test_common
from neutron.tests.common import net_helpers
from neutron.tests.functional import base


LOG = logging.getLogger(__name__)

_uuid = uuidutils.generate_uuid

OVS_INTERFACE_DRIVER = 'neutron.agent.linux.interface.OVSInterfaceDriver'

KEEPALIVED_CONFIG = """\
global_defs {
    notification_email_from %(email_from)s
    router_id %(router_id)s
}
vrrp_instance VR_1 {
    state BACKUP
    interface %(ha_device_name)s
    virtual_router_id 1
    priority 50
    garp_master_delay 60
    nopreempt
    advert_int 2
    track_interface {
        %(ha_device_name)s
    }
    virtual_ipaddress {
        169.254.0.1/24 dev %(ha_device_name)s
    }
    virtual_ipaddress_excluded {
        %(floating_ip_cidr)s dev %(ex_device_name)s no_track
        %(external_device_cidr)s dev %(ex_device_name)s no_track
        %(internal_device_cidr)s dev %(internal_device_name)s no_track
        %(ex_port_ipv6)s dev %(ex_device_name)s scope link no_track
        %(int_port_ipv6)s dev %(internal_device_name)s scope link no_track
    }
    virtual_routes {
        0.0.0.0/0 via %(default_gateway_ip)s dev %(ex_device_name)s no_track protocol static
        8.8.8.0/24 via 19.4.4.4 no_track protocol static
        %(extra_subnet_cidr)s dev %(ex_device_name)s scope link no_track protocol static
    }
}"""  # noqa: E501 # pylint: disable=line-too-long


def get_ovs_bridge(br_name):
    return ovs_lib.OVSBridge(br_name)


class L3AgentTestFramework(base.BaseSudoTestCase):
    INTERFACE_DRIVER = OVS_INTERFACE_DRIVER
    NESTED_NAMESPACE_SEPARATOR = '@'

    def setUp(self):
        super(L3AgentTestFramework, self).setUp()
        self.mock_plugin_api = mock.patch(
            'neutron.agent.l3.agent.L3PluginApi').start().return_value
        mock.patch('neutron.agent.rpc.PluginReportStateAPI').start()
        mock.patch('neutron.agent.common.ovs_lib.'
                   'OVSBridge._set_port_dead').start()
        l3_config.register_l3_agent_config_opts(l3_config.OPTS, cfg.CONF)
        self.conf = self._configure_agent('agent1')
        self.agent = neutron_l3_agent.L3NATAgentWithStateReport('agent1',
                                                                self.conf)

    def _get_config_opts(self):
        config = cfg.ConfigOpts()
        config.register_opts(common_config.core_opts)
        config.register_opts(common_config.core_cli_opts)
        logging.register_options(config)
        agent_config.register_process_monitor_opts(config)
        agent_config.register_root_helper(config)
        return config

    def _configure_agent(self, host, agent_mode='dvr_snat'):
        conf = self._get_config_opts()
        l3_agent_main.register_opts(conf)
        conf.set_override('interface_driver', self.INTERFACE_DRIVER)

        br_int = self.useFixture(net_helpers.OVSBridgeFixture()).bridge
        conf.set_override('integration_bridge', br_int.br_name, 'OVS')

        temp_dir = self.get_new_temp_dir()
        get_temp_file_path = functools.partial(self.get_temp_file_path,
                                               root=temp_dir)
        conf.set_override('state_path', temp_dir.path)
        conf.set_override('log_file',
                          get_temp_file_path('log_file'))
        conf.set_override('metadata_proxy_socket',
                          get_temp_file_path('metadata_proxy'))
        conf.set_override('ha_confs_path',
                          get_temp_file_path('ha_confs'))
        conf.set_override('external_pids',
                          get_temp_file_path('external/pids'))
        conf.set_override('host', host)
        conf.set_override('agent_mode', agent_mode)

        return conf

    def _get_agent_ovs_integration_bridge(self, agent):
        return get_ovs_bridge(agent.conf.OVS.integration_bridge)

    def generate_router_info(self, enable_ha,
                             ip_version=constants.IP_VERSION_4,
                             extra_routes=True,
                             enable_fip=True, enable_snat=True,
                             num_internal_ports=1,
                             dual_stack=False, enable_gw=True,
                             v6_ext_gw_with_sub=True,
                             enable_pf_floating_ip=False,
                             qos_policy_id=None):
        if ip_version == constants.IP_VERSION_6 and not dual_stack:
            enable_snat = False
            enable_fip = False
            extra_routes = False

        return l3_test_common.prepare_router_data(ip_version=ip_version,
                                                  enable_snat=enable_snat,
                                                  num_internal_ports=(
                                                      num_internal_ports),
                                                  enable_floating_ip=(
                                                      enable_fip),
                                                  enable_ha=enable_ha,
                                                  extra_routes=extra_routes,
                                                  dual_stack=dual_stack,
                                                  enable_gw=enable_gw,
                                                  v6_ext_gw_with_sub=(
                                                      v6_ext_gw_with_sub),
                                                  enable_pf_floating_ip=(
                                                      enable_pf_floating_ip),
                                                  qos_policy_id=qos_policy_id)

    def change_router_state(self, router_id, state):
        LOG.debug("Router %s state changed to '%s'", router_id, state)
        ri = self.agent.router_info.get(router_id)
        if not ri:
            self.fail('Router %s is not present in the L3 agent' % router_id)
        ri.ha_state = state

    def _test_conntrack_disassociate_fip(self, ha):
        '''Test that conntrack immediately drops stateful connection
           that uses floating IP once it's disassociated.
        '''
        router_info = self.generate_router_info(enable_ha=ha)
        router = self.manage_router(self.agent, router_info)

        port = net_helpers.get_free_namespace_port(
            constants.PROTO_NAME_TCP, router.ns_name)
        client_address = '19.4.4.3'
        server_address = '35.4.0.4'

        def clean_fips(router):
            router.router[constants.FLOATINGIP_KEY] = []

        clean_fips(router)
        self._add_fip(router, client_address, fixed_address=server_address)
        router.process()

        router_ns = ip_lib.IPWrapper(namespace=router.ns_name)
        netcat = net_helpers.NetcatTester(
            router.ns_name, router.ns_name, client_address, port,
            protocol=net_helpers.NetcatTester.TCP)
        self.addCleanup(netcat.stop_processes)

        def assert_num_of_conntrack_rules(n):
            out = router_ns.netns.execute(
                ["conntrack", "-L", "--orig-src", client_address],
                privsep_exec=True)
            self.assertEqual(
                n, len([line for line in out.strip().split('\n') if line]))

        if ha:
            self.wait_until_ha_router_has_state(router, 'primary')

        with self.assert_max_execution_time(100):
            assert_num_of_conntrack_rules(0)

            self.assertTrue(netcat.test_connectivity())
            assert_num_of_conntrack_rules(1)

            clean_fips(router)
            router.process()
            assert_num_of_conntrack_rules(0)

            with testtools.ExpectedException(RuntimeError):
                netcat.test_connectivity()

    def _test_update_floatingip_statuses(self, router_info):
        router = self.manage_router(self.agent, router_info)
        rpc = self.agent.plugin_rpc.update_floatingip_statuses
        self.assertTrue(rpc.called)

        # Assert that every defined FIP is updated via RPC
        expected_fips = set([
            (fip['id'], constants.FLOATINGIP_STATUS_ACTIVE) for fip in
            router.router[constants.FLOATINGIP_KEY]])
        call = [args[0] for args in rpc.call_args_list][0]
        actual_fips = set(list(call[2].items()))
        self.assertEqual(expected_fips, actual_fips)

    def _gateway_check(self, gateway_ip, external_device):
        expected_gateway = gateway_ip
        ip_vers = netaddr.IPAddress(expected_gateway).version
        existing_gateway = external_device.route.get_gateway(
            ip_version=ip_vers).get('via')
        self.assertEqual(expected_gateway, existing_gateway)

    def _assert_ha_device(self, router):
        def ha_router_dev_name_getter(not_used):
            return router.get_ha_device_name()
        self.assertTrue(self.device_exists_with_ips_and_mac(
            router.router[constants.HA_INTERFACE_KEY],
            ha_router_dev_name_getter, router.ns_name))

    def _assert_gateway(self, router, v6_ext_gw_with_sub=True):
        external_port = router.get_ex_gw_port()
        external_device_name = router.get_external_device_name(
            external_port['id'])
        external_device = ip_lib.IPDevice(external_device_name,
                                          namespace=router.ns_name)
        for subnet in external_port['subnets']:
            self._gateway_check(subnet['gateway_ip'], external_device)
        if not v6_ext_gw_with_sub:
            self._gateway_check(self.agent.conf.ipv6_gateway,
                                external_device)

    def _check_external_device(self, router):
        external_port = router.get_ex_gw_port()
        return (self.device_exists_with_ips_and_mac(
            external_port, router.get_external_device_name,
            router.ns_name))

    def _assert_external_device(self, router):
        self.assertTrue(self._check_external_device(router))

    def _wait_until_addr_gen_mode_has_state(
            self, ns_name, state):
        ip_wrapper = ip_lib.IPWrapper(namespace=ns_name)

        def _addr_gen_mode_state():
            addr_gen_mode_state = ip_wrapper.netns.execute(
                ['sysctl', '-b', 'net.ipv6.conf.all.addr_gen_mode'],
                privsep_exec=True)
            return (
                state == int(addr_gen_mode_state))

        common_utils.wait_until_true(_addr_gen_mode_state)

    def _wait_until_ipv6_accept_ra_has_state(
            self, ns_name, device_name, enabled):
        ip_wrapper = ip_lib.IPWrapper(namespace=ns_name)

        def _ipv6_accept_ra_state():
            ra_state = ip_wrapper.netns.execute(
                ['sysctl', '-b', 'net.ipv6.conf.%s.accept_ra' % device_name],
                privsep_exec=True)
            return (
                enabled == (int(ra_state) != constants.ACCEPT_RA_DISABLED))

        common_utils.wait_until_true(_ipv6_accept_ra_state)

    def _assert_ipv6_accept_ra(self, router, enabled=True):
        external_port = router.get_ex_gw_port()
        external_device_name = router.get_external_device_name(
            external_port['id'])

        self._wait_until_ipv6_accept_ra_has_state(
            router.ns_name, external_device_name, enabled)

    def _wait_until_ipv6_forwarding_has_state(self, ns_name, dev_name, state):

        def _ipv6_forwarding_has_state():
            return ip_lib.get_ipv6_forwarding(
                device=dev_name, namespace=ns_name) == state

        common_utils.wait_until_true(_ipv6_forwarding_has_state)

    def _assert_ipv6_forwarding(self, router, enabled=True, all_enabled=True):
        external_port = router.get_ex_gw_port()
        external_device_name = router.get_external_device_name(
            external_port['id'])
        self._wait_until_ipv6_forwarding_has_state(
            router.ns_name, external_device_name, int(enabled))
        self._wait_until_ipv6_forwarding_has_state(
            router.ns_name, 'all', int(all_enabled))

    def _router_lifecycle(self, enable_ha, ip_version=constants.IP_VERSION_4,
                          dual_stack=False, v6_ext_gw_with_sub=True,
                          router_info=None):
        router_info = router_info or self.generate_router_info(
            enable_ha, ip_version, dual_stack=dual_stack,
            v6_ext_gw_with_sub=(v6_ext_gw_with_sub))
        return_copy = copy.deepcopy(router_info)
        router = self.manage_router(self.agent, router_info)

        # Add multiple-IPv6-prefix internal router port
        slaac = constants.IPV6_SLAAC
        slaac_mode = {'ra_mode': slaac, 'address_mode': slaac}
        subnet_modes = [slaac_mode] * 2
        self._add_internal_interface_by_subnet(router.router,
            count=2, ip_version=constants.IP_VERSION_6,
            ipv6_subnet_modes=subnet_modes)
        router.process()

        if enable_ha:
            self.wait_until_ha_router_has_state(router, 'primary')

            # Keepalived notifies of a state transition when it starts,
            # not when it ends. Thus, we have to wait until keepalived finishes
            # configuring everything. We verify this by waiting until the last
            # device has an IP address.
            device = router.router[constants.INTERFACE_KEY][-1]
            device_exists = functools.partial(
                self.device_exists_with_ips_and_mac,
                device,
                router.get_internal_device_name,
                router.ns_name)
            common_utils.wait_until_true(device_exists)

        self.assertTrue(self._namespace_exists(router.ns_name))
        common_utils.wait_until_true(
            lambda: self._metadata_proxy_exists(self.agent.conf, router))
        self._assert_internal_devices(router)
        self._assert_external_device(router)
        if not (enable_ha and
                (ip_version == constants.IP_VERSION_6 or dual_stack)):
            # Note(SridharG): enable the assert_gateway for IPv6 once
            # keepalived on Ubuntu14.04 (i.e., check-neutron-dsvm-functional
            # platform) is updated to 1.2.10 (or above).
            # For more details: https://review.opendev.org/#/c/151284/
            self._assert_gateway(router, v6_ext_gw_with_sub)
            self.assertTrue(self.floating_ips_configured(router))
            self._assert_snat_chains(router)
            self._assert_floating_ip_chains(router)
            self._assert_iptables_rules_converged(router)
            self._assert_extra_routes(router)
            if (ip_version == constants.IP_VERSION_6 or dual_stack):
                ip_versions = [constants.IP_VERSION_4, constants.IP_VERSION_6]
            else:
                ip_versions = [constants.IP_VERSION_4]
            self._assert_onlink_subnet_routes(router, ip_versions)
        self._assert_metadata_chains(router)

        # Verify router gateway interface is configured to receive Router Advts
        # when IPv6 is enabled and no IPv6 gateway is configured.
        if router.use_ipv6 and not v6_ext_gw_with_sub:
            if not self.agent.conf.ipv6_gateway:
                self._assert_ipv6_accept_ra(router)

        if enable_ha:
            self._assert_ha_device(router)
            common_utils.wait_until_true(
                lambda: router.keepalived_manager.get_process().active,
                timeout=15)

        self._delete_router(self.agent, router.router_id)

        self._assert_interfaces_deleted_from_ovs()
        self._assert_router_does_not_exist(router)
        if enable_ha:
            common_utils.wait_until_true(
                lambda: not router.keepalived_manager.get_process().active,
                timeout=15)
        return return_copy

    def manage_router(self, agent, router):
        self.addCleanup(agent._safe_router_removed, router['id'])
        with mock.patch.object(dvr_local_router.DvrLocalRouter,
                               '_load_used_fip_information'):
            agent._process_added_router(router)

        return agent.router_info[router['id']]

    def _delete_router(self, agent, router_id):
        agent._safe_router_removed(router_id)

    def _add_fip(self, router, fip_address, fixed_address='10.0.0.2',
                 host=None, fixed_ip_address_scope=None):
        fip = {'id': _uuid(),
               'port_id': _uuid(),
               'floating_ip_address': fip_address,
               'fixed_ip_address': fixed_address,
               'host': host,
               'fixed_ip_address_scope': fixed_ip_address_scope}
        router.router[constants.FLOATINGIP_KEY].append(fip)

    def _add_internal_interface_by_subnet(self, router, count=1,
                                          ip_version=constants.IP_VERSION_4,
                                          ipv6_subnet_modes=None,
                                          interface_id=None):
        return l3_test_common.router_append_subnet(router, count,
                                                   ip_version,
                                                   ipv6_subnet_modes,
                                                   interface_id)

    def _namespace_exists(self, namespace):
        return ip_lib.network_namespace_exists(namespace)

    def _metadata_proxy(self, conf, router):
        return external_process.ProcessManager(
            conf,
            router.router_id,
            router.ns_name,
            service=driver_base.HAPROXY_SERVICE)

    def _metadata_proxy_exists(self, conf, router):
        pm = self._metadata_proxy(conf, router)
        return pm.active

    def device_exists_with_ips_and_mac(self, expected_device, name_getter,
                                       namespace):
        ip_cidrs = common_utils.fixed_ip_cidrs(expected_device['fixed_ips'])
        return ip_lib.device_exists_with_ips_and_mac(
            name_getter(expected_device['id']), ip_cidrs,
            expected_device['mac_address'], namespace)

    @staticmethod
    def _port_first_ip_cidr(port):
        fixed_ip = port['fixed_ips'][0]
        return common_utils.ip_to_cidr(fixed_ip['ip_address'],
                                       fixed_ip['prefixlen'])

    def get_device_mtu(self, target_device, name_getter, namespace):
        device = ip_lib.IPDevice(name_getter(target_device), namespace)
        return device.link.mtu

    def get_expected_keepalive_configuration(self, router):
        ha_device_name = router.get_ha_device_name()
        external_port = router.get_ex_gw_port()
        ex_port_ipv6 = ip_lib.get_ipv6_lladdr(external_port['mac_address'])
        ex_device_name = router.get_external_device_name(
            external_port['id'])
        external_device_cidr = self._port_first_ip_cidr(external_port)
        internal_port = router.router[constants.INTERFACE_KEY][0]
        int_port_ipv6 = ip_lib.get_ipv6_lladdr(internal_port['mac_address'])
        internal_device_name = router.get_internal_device_name(
            internal_port['id'])
        internal_device_cidr = self._port_first_ip_cidr(internal_port)
        floating_ip_cidr = common_utils.ip_to_cidr(
            router.get_floating_ips()[0]['floating_ip_address'])
        default_gateway_ip = external_port['subnets'][0].get('gateway_ip')
        extra_subnet_cidr = external_port['extra_subnets'][0].get('cidr')
        return KEEPALIVED_CONFIG % {
            'email_from': keepalived.KEEPALIVED_EMAIL_FROM,
            'router_id': keepalived.KEEPALIVED_ROUTER_ID,
            'ha_device_name': ha_device_name,
            'ex_device_name': ex_device_name,
            'external_device_cidr': external_device_cidr,
            'internal_device_name': internal_device_name,
            'internal_device_cidr': internal_device_cidr,
            'floating_ip_cidr': floating_ip_cidr,
            'default_gateway_ip': default_gateway_ip,
            'int_port_ipv6': int_port_ipv6,
            'ex_port_ipv6': ex_port_ipv6,
            'extra_subnet_cidr': extra_subnet_cidr,
        }

    def _get_rule(self, iptables_manager, table, chain, predicate):
        rules = iptables_manager.get_chain(table, chain)
        result = next(rule for rule in rules if predicate(rule))
        return result

    def _assert_router_does_not_exist(self, router):
        # If the namespace assertion succeeds
        # then the devices and iptable rules have also been deleted,
        # so there's no need to check that explicitly.
        self.assertFalse(self._namespace_exists(router.ns_name))
        try:
            common_utils.wait_until_true(
                lambda: not self._metadata_proxy_exists(self.agent.conf,
                                                        router),
                timeout=10)
        except common_utils.WaitTimeout:
            pm = self._metadata_proxy(self.agent.conf, router)
            pid_file = pm.get_pid_file_name()
            if os.path.exists(pid_file):
                msg = 'PID file %s still exists and it should not.' % pid_file
            else:
                msg = 'PID file %s is not present.' % pid_file
            self.fail(msg)

    def _assert_snat_chains(self, router, enable_gw=True):
        check = self.assertFalse if enable_gw else self.assertTrue
        check(router.iptables_manager.is_chain_empty('nat', 'snat'))
        check(router.iptables_manager.is_chain_empty('nat', 'POSTROUTING'))

    def _assert_floating_ip_chains(self, router, snat_bound_fip=False,
                                   enable_gw=True):
        if snat_bound_fip:
            if enable_gw:
                self.assertFalse(router.snat_iptables_manager.is_chain_empty(
                    'nat', 'float-snat'))
            else:
                self.assertIsNone(router.snat_iptables_manager)

        check = self.assertFalse if enable_gw else self.assertTrue
        check(router.iptables_manager.is_chain_empty('nat', 'float-snat'))

    def _assert_iptables_rules_converged(self, router):
        # if your code is failing on this line, it means you are not generating
        # your iptables rules in the same format that iptables-save returns
        # them. run iptables-save to see the format they should be in
        self.assertFalse(router.iptables_manager.apply())

    def _assert_metadata_chains(self, router):
        metadata_port_filter = lambda rule: (
            str(self.agent.conf.metadata_port) in rule.rule)
        self.assertTrue(self._get_rule(router.iptables_manager,
                                       'nat',
                                       'PREROUTING',
                                       metadata_port_filter))
        self.assertTrue(self._get_rule(router.iptables_manager,
                                       'filter',
                                       'INPUT',
                                       metadata_port_filter))

    def _assert_internal_devices(self, router):
        internal_devices = router.router[constants.INTERFACE_KEY]
        self.assertGreater(len(internal_devices), 0)
        for device in internal_devices:
            self.assertTrue(self.device_exists_with_ips_and_mac(
                device, router.get_internal_device_name, router.ns_name))

    def _assert_extra_routes(self, router, namespace=None, enable_gw=True):
        if namespace is None:
            namespace = router.ns_name
        routes = ip_lib.list_ip_routes(namespace, constants.IP_VERSION_4)
        routes = [{'nexthop': route['via'],
                   'destination': route['cidr']} for route in routes]

        for extra_route in router.router['routes']:
            check = self.assertIn if enable_gw else self.assertNotIn
            check(extra_route, routes)

    def _assert_onlink_subnet_routes(
            self, router, ip_versions, namespace=None, enable_gw=True):
        ns_name = namespace or router.ns_name
        routes = []
        for ip_version in ip_versions:
            _routes = ip_lib.list_ip_routes(ns_name, ip_version)
            routes.extend(_routes)
        routes = set(route['cidr'] for route in routes)
        ex_gw_port = router.get_ex_gw_port()
        if not ex_gw_port:
            if not enable_gw:
                return
            self.fail('GW port is enabled but not present in the router')

        extra_subnets = ex_gw_port['extra_subnets']
        for extra_subnet in (route['cidr'] for route in extra_subnets):
            self.assertIn(extra_subnet, routes)

    def _assert_interfaces_deleted_from_ovs(self):
        bridge = ovs_lib.OVSBridge(self.agent.conf.OVS.integration_bridge)
        self.assertFalse(bridge.get_port_name_list())

    def floating_ips_configured(self, router):
        floating_ips = router.router[constants.FLOATINGIP_KEY]
        external_port = router.get_ex_gw_port()
        return len(floating_ips) and all(
            ip_lib.device_exists_with_ips_and_mac(
                router.get_external_device_name(external_port['id']),
                ['%s/32' % fip['floating_ip_address']],
                external_port['mac_address'],
                namespace=router.ns_name) for fip in floating_ips)

    def _create_router(self, router_info, agent):

        ns_name = "%s%s%s" % (
            'qrouter-' + router_info['id'],
            self.NESTED_NAMESPACE_SEPARATOR, agent.host)
        ext_name = "qg-%s-%s" % (agent.host, _uuid()[-4:])
        int_name = "qr-%s-%s" % (agent.host, _uuid()[-4:])

        get_ns_name = mock.patch.object(
            namespaces.RouterNamespace, '_get_ns_name').start()
        get_ns_name.return_value = ns_name
        get_ext_name = mock.patch.object(l3_router_info.RouterInfo,
            'get_external_device_name').start()
        get_ext_name.return_value = ext_name
        get_int_name = mock.patch.object(l3_router_info.RouterInfo,
            'get_internal_device_name').start()
        get_int_name.return_value = int_name

        router = self.manage_router(agent, router_info)

        router_ext_name = mock.patch.object(router,
            'get_external_device_name').start()
        router_ext_name.return_value = get_ext_name.return_value
        router_int_name = mock.patch.object(router,
            'get_internal_device_name').start()
        router_int_name.return_value = get_int_name.return_value

        return router

    def create_ha_routers(self):
        router_info = self.generate_router_info(enable_ha=True)
        router1 = self._create_router(router_info, self.agent)
        self._add_fip(router1, '192.168.111.12')

        r1_br = ip_lib.IPDevice(router1.driver.conf.OVS.integration_bridge)
        r1_br.addr.add('19.4.4.1/24')
        r1_br.link.set_up()

        router_info_2 = copy.deepcopy(router_info)
        router_info_2[constants.HA_INTERFACE_KEY] = (
            l3_test_common.get_ha_interface(ip='169.254.192.2',
                                            mac='22:22:22:22:22:22'))
        router2 = self._create_router(router_info_2, self.failover_agent)

        r2_br = ip_lib.IPDevice(router2.driver.conf.OVS.integration_bridge)
        r2_br.addr.add('19.4.4.1/24')
        r2_br.link.set_up()

        return (router1, router2)

    def _get_primary_and_backup_routers(self, router1, router2,
                                        check_external_device=True):

        try:
            self.wait_until_ha_router_has_state(router1, 'primary')
            if check_external_device:
                common_utils.wait_until_true(
                    lambda: self._check_external_device(router1))
            primary_router = router1
            backup_router = router2
        except common_utils.WaitTimeout:
            self.wait_until_ha_router_has_state(router2, 'primary')
            if check_external_device:
                common_utils.wait_until_true(
                    lambda: self._check_external_device(router2))
            primary_router = router2
            backup_router = router1

        self.wait_until_ha_router_has_state(primary_router, 'primary')
        if check_external_device:
            common_utils.wait_until_true(
                lambda: self._check_external_device(primary_router))
        self.wait_until_ha_router_has_state(backup_router, 'backup')

        LOG.debug("Found primary router %s and backup router %s",
                  primary_router.router_id, backup_router.router_id)
        return primary_router, backup_router

    def fail_ha_router(self, router):
        device_name = router.get_ha_device_name()
        LOG.debug("Failing HA router %s by setting device %s to DOWN",
                  router.router_id, device_name)
        ha_device = ip_lib.IPDevice(device_name, router.ha_namespace)
        ha_device.link.set_down()

    @test_base.unstable_test("bug 1956958")
    def wait_until_ha_router_has_state(self, router, expected_state):

        def router_has_expected_state():
            state = router.ha_state
            LOG.debug("Router %s; current state is '%s', "
                      "expected state is '%s'",
                      router.router_id, state, expected_state)
            return state == expected_state

        common_utils.wait_until_true(router_has_expected_state)

    @staticmethod
    def fail_gw_router_port(router):
        r_br = ip_lib.IPDevice(router.driver.conf.OVS.integration_bridge)
        r_br.link.set_down()

    @staticmethod
    def restore_gw_router_port(router):
        r_br = ip_lib.IPDevice(router.driver.conf.OVS.integration_bridge)
        r_br.link.set_up()

    @classmethod
    def _get_addresses_on_device(cls, namespace, interface):
        return [address['cidr'] for address in
                ip_lib.IPDevice(interface, namespace=namespace).addr.list()]

    def _assert_no_ip_addresses_on_interface(self, namespace, interface):
        self.assertEqual(
            [], self._get_addresses_on_device(namespace, interface))

    def _assert_ip_addresses_on_interface(self,
                                          namespace, interface, ip_addresses):
        for ip_address in ip_addresses:
            self._assert_ip_address_on_interface(namespace, interface,
                                                 ip_address)

    def _assert_ip_address_not_on_interface(self,
                                            namespace, interface, ip_address):
        self.assertNotIn(
            ip_address, self._get_addresses_on_device(namespace, interface))

    def _assert_ip_address_on_interface(self,
                                        namespace, interface, ip_address):
        self.assertIn(
            ip_address, self._get_addresses_on_device(namespace, interface))

    def _assert_ping_reply_from_expected_address(self, ping_result,
                                                 expected_address):
        ping_results = ping_result.split('\n')
        self.assertGreater(
            len(ping_results), 1,
            "The result from ping should be multiple lines")
        self.assertIn(
            expected_address, ping_results[1],
            ("Expect to see %s in the reply of ping, but failed" %
             expected_address))

    def _assert_route_in_routes(self, router, expected_route):
        updated_route = ip_lib.list_ip_routes(
            router.ns_name,
            ip_version=constants.IP_VERSION_4, )

        actual_routes = [{key: route[key] for key in expected_route.keys()}
                         for route in updated_route]
        self.assertIn(expected_route, actual_routes)

    def _assert_ecmp_route_in_routes(self, router, expected_route):
        updated_route = ip_lib.list_ip_routes(
            router.ns_name,
            ip_version=constants.IP_VERSION_4)
        routes_actual = [{key: route[key] for key in expected_route.keys()}
                         for route in updated_route]
        for entry in routes_actual:
            if entry['via']:
                if isinstance(entry['via'], (list, tuple)):
                    via_list = [{'via': hop['via']}
                                for hop in entry['via']]
                    entry['via'] = sorted(via_list, key=lambda i: i['via'])
        self.assertIn(expected_route, routes_actual)
