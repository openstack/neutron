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

import mock
import netaddr
from oslo_config import cfg
import testtools
import webob
import webob.dec
import webob.exc

from neutron.agent.common import config as agent_config
from neutron.agent.l3 import agent as neutron_l3_agent
from neutron.agent import l3_agent as l3_agent_main
from neutron.agent.linux import dhcp
from neutron.agent.linux import external_process
from neutron.agent.linux import ip_lib
from neutron.agent.linux import ovs_lib
from neutron.agent.metadata import agent as metadata_agent
from neutron.common import config as common_config
from neutron.common import constants as l3_constants
from neutron.common import utils as common_utils
from neutron.openstack.common import log as logging
from neutron.openstack.common import uuidutils
from neutron.services import advanced_service as adv_svc
from neutron.tests.common.agents import l3_agent as l3_test_agent
from neutron.tests.functional.agent.linux import base
from neutron.tests.functional.agent.linux import helpers
from neutron.tests.unit import test_l3_agent

LOG = logging.getLogger(__name__)
_uuid = uuidutils.generate_uuid

METADATA_REQUEST_TIMEOUT = 60


class L3AgentTestFramework(base.BaseOVSLinuxTestCase):
    def setUp(self):
        super(L3AgentTestFramework, self).setUp()
        self.check_sudo_enabled()
        mock.patch('neutron.agent.l3.agent.L3PluginApi').start()
        self.agent = self._configure_agent('agent1')

    def _get_config_opts(self):
        config = cfg.ConfigOpts()
        config.register_opts(common_config.core_opts)
        config.register_opts(common_config.core_cli_opts)
        config.register_cli_opts(logging.common_cli_opts)
        config.register_cli_opts(logging.logging_cli_opts)
        config.register_opts(logging.generic_log_opts)
        config.register_opts(logging.log_opts)
        agent_config.register_process_monitor_opts(config)
        return config

    def _configure_agent(self, host):
        conf = self._get_config_opts()
        l3_agent_main.register_opts(conf)
        cfg.CONF.set_override('debug', False)
        agent_config.setup_logging()
        conf.set_override(
            'interface_driver',
            'neutron.agent.linux.interface.OVSInterfaceDriver')
        conf.set_override('router_delete_namespaces', True)
        conf.set_override('root_helper', self.root_helper, group='AGENT')

        br_int = self.create_ovs_bridge()
        br_ex = self.create_ovs_bridge()
        conf.set_override('ovs_integration_bridge', br_int.br_name)
        conf.set_override('external_network_bridge', br_ex.br_name)

        temp_dir = self.get_new_temp_dir()
        get_temp_file_path = functools.partial(self.get_temp_file_path,
                                               root=temp_dir)
        conf.set_override('state_path', temp_dir.path)
        conf.set_override('metadata_proxy_socket',
                          get_temp_file_path('metadata_proxy'))
        conf.set_override('ha_confs_path',
                          get_temp_file_path('ha_confs'))
        conf.set_override('external_pids',
                          get_temp_file_path('external/pids'))
        conf.set_override('host', host)
        agent = l3_test_agent.TestL3NATAgent(host, conf)
        mock.patch.object(ip_lib, 'send_gratuitous_arp').start()

        return agent

    def generate_router_info(self, enable_ha):
        return test_l3_agent.prepare_router_data(enable_snat=True,
                                                 enable_floating_ip=True,
                                                 enable_ha=enable_ha,
                                                 extra_routes=True)

    def manage_router(self, agent, router):
        self.addCleanup(self._delete_router, agent, router['id'])
        ri = self._create_router(agent, router)
        return ri

    def _create_router(self, agent, router):
        agent._process_added_router(router)
        return agent.router_info[router['id']]

    def _delete_router(self, agent, router_id):
        agent._router_removed(router_id)

    def _add_fip(self, router, fip_address, fixed_address='10.0.0.2'):
        fip = {'id': _uuid(),
               'port_id': _uuid(),
               'floating_ip_address': fip_address,
               'fixed_ip_address': fixed_address}
        router.router[l3_constants.FLOATINGIP_KEY].append(fip)

    def _namespace_exists(self, namespace):
        ip = ip_lib.IPWrapper(self.root_helper, namespace)
        return ip.netns.exists(namespace)

    def _metadata_proxy_exists(self, conf, router):
        pm = external_process.ProcessManager(
            conf,
            router.router_id,
            router.ns_name)
        return pm.active

    def device_exists_with_ip_mac(self, expected_device, name_getter,
                                  namespace):
        return ip_lib.device_exists_with_ip_mac(
            name_getter(expected_device['id']),
            expected_device['ip_cidr'],
            expected_device['mac_address'],
            namespace, self.root_helper)

    def get_expected_keepalive_configuration(self, router):
        ha_confs_path = self.agent.conf.ha_confs_path
        router_id = router.router_id
        ha_device_name = router.get_ha_device_name(router.ha_port['id'])
        ha_device_cidr = router.ha_port['ip_cidr']
        external_port = self.agent._get_ex_gw_port(router)
        ex_port_ipv6 = router._get_ipv6_lladdr(
            external_port['mac_address'])
        external_device_name = self.agent.get_external_device_name(
            external_port['id'])
        external_device_cidr = external_port['ip_cidr']
        internal_port = router.router[l3_constants.INTERFACE_KEY][0]
        int_port_ipv6 = router._get_ipv6_lladdr(
            internal_port['mac_address'])
        internal_device_name = self.agent.get_internal_device_name(
            internal_port['id'])
        internal_device_cidr = internal_port['ip_cidr']
        floating_ip_cidr = common_utils.ip_to_cidr(
            self.agent.get_floating_ips(router)[0]['floating_ip_address'])
        default_gateway_ip = external_port['subnet'].get('gateway_ip')

        return """vrrp_instance VR_1 {
    state BACKUP
    interface %(ha_device_name)s
    virtual_router_id 1
    priority 50
    nopreempt
    advert_int 2
    track_interface {
        %(ha_device_name)s
    }
    virtual_ipaddress {
        169.254.0.1/24 dev %(ha_device_name)s
    }
    virtual_ipaddress_excluded {
        %(floating_ip_cidr)s dev %(external_device_name)s
        %(external_device_cidr)s dev %(external_device_name)s
        %(internal_device_cidr)s dev %(internal_device_name)s
        %(ex_port_ipv6)s dev %(external_device_name)s scope link
        %(int_port_ipv6)s dev %(internal_device_name)s scope link
    }
    virtual_routes {
        0.0.0.0/0 via %(default_gateway_ip)s dev %(external_device_name)s
        8.8.8.0/24 via 19.4.4.4
    }
    notify_master "%(ha_confs_path)s/%(router_id)s/notify_master.sh"
    notify_backup "%(ha_confs_path)s/%(router_id)s/notify_backup.sh"
    notify_fault "%(ha_confs_path)s/%(router_id)s/notify_fault.sh"
}""" % {
            'ha_confs_path': ha_confs_path,
            'router_id': router_id,
            'ha_device_name': ha_device_name,
            'ha_device_cidr': ha_device_cidr,
            'external_device_name': external_device_name,
            'external_device_cidr': external_device_cidr,
            'internal_device_name': internal_device_name,
            'internal_device_cidr': internal_device_cidr,
            'floating_ip_cidr': floating_ip_cidr,
            'default_gateway_ip': default_gateway_ip,
            'int_port_ipv6': int_port_ipv6,
            'ex_port_ipv6': ex_port_ipv6
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
        self.assertFalse(self._metadata_proxy_exists(self.agent.conf, router))

    def _assert_snat_chains(self, router):
        self.assertFalse(router.iptables_manager.is_chain_empty(
            'nat', 'snat'))
        self.assertFalse(router.iptables_manager.is_chain_empty(
            'nat', 'POSTROUTING'))

    def _assert_floating_ip_chains(self, router):
        self.assertFalse(router.iptables_manager.is_chain_empty(
            'nat', 'float-snat'))

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
        internal_devices = router.router[l3_constants.INTERFACE_KEY]
        self.assertTrue(len(internal_devices))
        for device in internal_devices:
            self.assertTrue(self.device_exists_with_ip_mac(
                device, self.agent.get_internal_device_name, router.ns_name))

    def _assert_extra_routes(self, router):
        routes = ip_lib.get_routing_table(self.root_helper, router.ns_name)
        routes = [{'nexthop': route['nexthop'],
                   'destination': route['destination']} for route in routes]

        for extra_route in router.router['routes']:
            self.assertIn(extra_route, routes)

    def _assert_interfaces_deleted_from_ovs(self):
        def assert_ovs_bridge_empty(bridge_name):
            bridge = ovs_lib.OVSBridge(bridge_name)
            self.assertFalse(bridge.get_port_name_list())

        assert_ovs_bridge_empty(self.agent.conf.ovs_integration_bridge)
        assert_ovs_bridge_empty(self.agent.conf.external_network_bridge)


class L3AgentTestCase(L3AgentTestFramework):
    def test_observer_notifications_legacy_router(self):
        self._test_observer_notifications(enable_ha=False)

    def test_observer_notifications_ha_router(self):
        self._test_observer_notifications(enable_ha=True)

    def _test_observer_notifications(self, enable_ha):
        """Test create, update, delete of router and notifications."""
        with mock.patch.object(
                self.agent.event_observers, 'notify') as notify:
            router_info = self.generate_router_info(enable_ha)
            router = self.manage_router(self.agent, router_info)
            self.agent._process_updated_router(router.router)
            self._delete_router(self.agent, router.router_id)

            calls = notify.call_args_list
            self.assertEqual(
                [((adv_svc.AdvancedService.before_router_added, router),),
                 ((adv_svc.AdvancedService.after_router_added, router),),
                 ((adv_svc.AdvancedService.before_router_updated, router),),
                 ((adv_svc.AdvancedService.after_router_updated, router),),
                 ((adv_svc.AdvancedService.before_router_removed, router),),
                 ((adv_svc.AdvancedService.after_router_removed, router),)],
                calls)

    def test_legacy_router_lifecycle(self):
        self._router_lifecycle(enable_ha=False)

    def test_ha_router_lifecycle(self):
        self._router_lifecycle(enable_ha=True)

    def test_conntrack_disassociate_fip(self):
        '''Test that conntrack immediately drops stateful connection
           that uses floating IP once it's disassociated.
        '''
        router_info = self.generate_router_info(enable_ha=False)
        router = self.manage_router(self.agent, router_info)

        port = helpers.get_free_namespace_port(router.ns_name)
        client_address = '19.4.4.3'
        server_address = '35.4.0.4'

        def clean_fips(router):
            router.router[l3_constants.FLOATINGIP_KEY] = []

        clean_fips(router)
        self._add_fip(router, client_address, fixed_address=server_address)
        self.agent.process_router(router)

        router_ns = ip_lib.IPWrapper(namespace=router.ns_name)
        netcat = helpers.NetcatTester(router_ns, router_ns,
                                      server_address, port,
                                      client_address=client_address,
                                      run_as_root=True,
                                      udp=False)
        self.addCleanup(netcat.stop_processes)

        def assert_num_of_conntrack_rules(n):
            out = router_ns.netns.execute(["conntrack", "-L",
                                           "--orig-src", client_address])
            self.assertEqual(
                n, len([line for line in out.strip().split('\n') if line]))

        with self.assert_max_execution_time(100):
            assert_num_of_conntrack_rules(0)

            self.assertTrue(netcat.test_connectivity())
            assert_num_of_conntrack_rules(1)

            clean_fips(router)
            self.agent.process_router(router)
            assert_num_of_conntrack_rules(0)

            with testtools.ExpectedException(RuntimeError):
                netcat.test_connectivity()

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
        router.router['gw_port']['subnet']['gateway_ip'] = '19.4.4.5'
        router.router['gw_port']['fixed_ips'][0]['ip_address'] = '19.4.4.10'

        self.agent.process_router(router)

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
        external_port = self.agent._get_ex_gw_port(router)
        external_device_name = self.agent.get_external_device_name(
            external_port['id'])
        self.assertNotIn('%s/24 dev %s' %
                         (old_external_device_ip, external_device_name),
                         new_config)
        self.assertIn('%s/24 dev %s' %
                      (new_external_device_ip, external_device_name),
                      new_config)

    def _router_lifecycle(self, enable_ha):
        router_info = self.generate_router_info(enable_ha)
        router = self.manage_router(self.agent, router_info)

        if enable_ha:
            port = self.agent._get_ex_gw_port(router)
            interface_name = self.agent.get_external_device_name(port['id'])
            self._assert_no_ip_addresses_on_interface(router, interface_name)
            helpers.wait_until_true(lambda: router.ha_state == 'master')

            # Keepalived notifies of a state transition when it starts,
            # not when it ends. Thus, we have to wait until keepalived finishes
            # configuring everything. We verify this by waiting until the last
            # device has an IP address.
            device = router.router[l3_constants.INTERFACE_KEY][-1]
            device_exists = functools.partial(
                self.device_exists_with_ip_mac,
                device,
                self.agent.get_internal_device_name,
                router.ns_name)
            helpers.wait_until_true(device_exists)

        self.assertTrue(self._namespace_exists(router.ns_name))
        self.assertTrue(self._metadata_proxy_exists(self.agent.conf, router))
        self._assert_internal_devices(router)
        self._assert_external_device(router)
        self._assert_gateway(router)
        self.assertTrue(self._floating_ips_configured(router))
        self._assert_snat_chains(router)
        self._assert_floating_ip_chains(router)
        self._assert_metadata_chains(router)
        self._assert_extra_routes(router)

        if enable_ha:
            self._assert_ha_device(router)
            self.assertTrue(router.keepalived_manager.process.active)

        self._delete_router(self.agent, router.router_id)

        self._assert_interfaces_deleted_from_ovs()
        self._assert_router_does_not_exist(router)
        if enable_ha:
            self.assertFalse(router.keepalived_manager.process.active)

    def _assert_external_device(self, router):
        external_port = self.agent._get_ex_gw_port(router)
        self.assertTrue(self.device_exists_with_ip_mac(
            external_port, self.agent.get_external_device_name,
            router.ns_name))

    def _assert_gateway(self, router):
        external_port = self.agent._get_ex_gw_port(router)
        external_device_name = self.agent.get_external_device_name(
            external_port['id'])
        external_device = ip_lib.IPDevice(external_device_name,
                                          self.root_helper,
                                          router.ns_name)
        existing_gateway = (
            external_device.route.get_gateway().get('gateway'))
        expected_gateway = external_port['subnet']['gateway_ip']
        self.assertEqual(expected_gateway, existing_gateway)

    def _floating_ips_configured(self, router):
        floating_ips = router.router[l3_constants.FLOATINGIP_KEY]
        external_port = self.agent._get_ex_gw_port(router)
        return len(floating_ips) and all(ip_lib.device_exists_with_ip_mac(
            self.agent.get_external_device_name(external_port['id']),
            '%s/32' % fip['floating_ip_address'],
            external_port['mac_address'],
            router.ns_name, self.root_helper) for fip in floating_ips)

    def _assert_ha_device(self, router):
        self.assertTrue(self.device_exists_with_ip_mac(
            router.router[l3_constants.HA_INTERFACE_KEY],
            router.get_ha_device_name, router.ns_name))

    def _assert_no_ip_addresses_on_interface(self, router, interface):
        device = ip_lib.IPDevice(interface, self.root_helper, router.ns_name)
        self.assertEqual([], device.addr.list())

    def test_ha_router_conf_on_restarted_agent(self):
        router_info = self.generate_router_info(enable_ha=True)
        router1 = self._create_router(self.agent, router_info)
        self._add_fip(router1, '192.168.111.12')
        restarted_agent = l3_test_agent.TestL3NATAgent(self.agent.host,
                                                       self.agent.conf)
        self._create_router(restarted_agent, router1.router)
        helpers.wait_until_true(lambda: self._floating_ips_configured(router1))


class L3HATestFramework(L3AgentTestFramework):
    def setUp(self):
        super(L3HATestFramework, self).setUp()
        self.failover_agent = self._configure_agent('agent2')

        br_int_1 = self.get_ovs_bridge(
            self.agent.conf.ovs_integration_bridge)
        br_int_2 = self.get_ovs_bridge(
            self.failover_agent.conf.ovs_integration_bridge)

        veth1, veth2 = self.create_veth()
        br_int_1.add_port(veth1.name)
        br_int_2.add_port(veth2.name)

    def test_ha_router_failover(self):
        router_info = self.generate_router_info(enable_ha=True)
        router1 = self.manage_router(self.agent, router_info)

        router_info_2 = copy.deepcopy(router_info)
        router_info_2[l3_constants.HA_INTERFACE_KEY] = (
            test_l3_agent.get_ha_interface(ip='169.254.192.2',
                                           mac='22:22:22:22:22:22'))

        router2 = self.manage_router(self.failover_agent, router_info_2)

        helpers.wait_until_true(lambda: router1.ha_state == 'master')
        helpers.wait_until_true(lambda: router2.ha_state == 'backup')

        device_name = router1.get_ha_device_name(
            router1.router[l3_constants.HA_INTERFACE_KEY]['id'])
        ha_device = ip_lib.IPDevice(device_name, self.root_helper,
                                    router1.ns_name)
        ha_device.link.set_down()

        helpers.wait_until_true(lambda: router2.ha_state == 'master')
        helpers.wait_until_true(lambda: router1.ha_state == 'fault')


class MetadataFakeProxyHandler(object):

    def __init__(self, status):
        self.status = status

    @webob.dec.wsgify()
    def __call__(self, req):
        return webob.Response(status=self.status)


class MetadataL3AgentTestCase(L3AgentTestFramework):

    def _create_metadata_fake_server(self, status):
        server = metadata_agent.UnixDomainWSGIServer('metadata-fake-server')
        self.addCleanup(server.stop)
        server.start(MetadataFakeProxyHandler(status),
                     self.agent.conf.metadata_proxy_socket,
                     workers=0, backlog=4096)

    def test_access_to_metadata_proxy(self):
        """Test access to the l3-agent metadata proxy.

        The test creates:
         * A l3-agent metadata service:
           * A router (which creates a metadata proxy in the router namespace),
           * A fake metadata server
         * A "client" namespace (simulating a vm) with a port on router
           internal subnet.

        The test queries from the "client" namespace the metadata proxy on
        http://169.254.169.254 and asserts that the metadata proxy added
        the X-Forwarded-For and X-Neutron-Router-Id headers to the request
        and forwarded the http request to the fake metadata server and the
        response to the "client" namespace.
        """
        router_info = self.generate_router_info(enable_ha=False)
        router = self.manage_router(self.agent, router_info)
        self._create_metadata_fake_server(webob.exc.HTTPOk.code)

        # Create and configure client namespace
        client_ns = self._create_namespace()
        router_ip_cidr = router.internal_ports[0]['ip_cidr']
        ip_cidr = self.shift_ip_cidr(router_ip_cidr)
        br_int = self.get_ovs_bridge(self.agent.conf.ovs_integration_bridge)
        port = self.bind_namespace_to_cidr(client_ns, br_int, ip_cidr)
        self.set_namespace_gateway(port, router_ip_cidr.partition('/')[0])

        # Query metadata proxy
        url = 'http://%(host)s:%(port)s' % {'host': dhcp.METADATA_DEFAULT_IP,
                                            'port': dhcp.METADATA_PORT}
        cmd = 'curl', '--max-time', METADATA_REQUEST_TIMEOUT, '-D-', url
        try:
            raw_headers = client_ns.netns.execute(cmd)
        except RuntimeError:
            self.fail('metadata proxy unreachable on %s before timeout' % url)

        # Check status code
        firstline = raw_headers.splitlines()[0]
        self.assertIn(str(webob.exc.HTTPOk.code), firstline.split())


class TestDvrRouter(L3AgentTestFramework):
    def test_dvr_router_lifecycle_without_ha_without_snat_with_fips(self):
        self._dvr_router_lifecycle(enable_ha=False, enable_snat=False)

    def test_dvr_router_lifecycle_without_ha_with_snat_with_fips(self):
        self._dvr_router_lifecycle(enable_ha=False, enable_snat=True)

    def _dvr_router_lifecycle(self, enable_ha=False, enable_snat=False):
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
            enable_ha, enable_snat)

        # We need to mock the get_agent_gateway_port return value
        # because the whole L3PluginApi is mocked and we need the port
        # gateway_port information before the l3_agent will create it.
        # The port returned needs to have the same information as
        # router_info['gw_port']
        mocked_gw_port = (
            neutron_l3_agent.L3PluginApi.return_value.get_agent_gateway_port)
        mocked_gw_port.return_value = router_info['gw_port']

        # We also need to mock the get_external_network_id method to
        # get the correct fip namespace.
        mocked_ext_net_id = (
            neutron_l3_agent.L3PluginApi.return_value.get_external_network_id)
        mocked_ext_net_id.return_value = (
            router_info['_floatingips'][0]['floating_network_id'])

        # With all that set we can now ask the l3_agent to
        # manage the router (create it, create namespaces,
        # attach interfaces, etc...)
        router = self.manage_router(self.agent, router_info)

        self.assertTrue(self._namespace_exists(router.ns_name))
        self.assertTrue(self._metadata_proxy_exists(self.agent.conf, router))
        self._assert_internal_devices(router)
        self._assert_dvr_external_device(router)
        self._assert_dvr_gateway(router)
        self._assert_dvr_floating_ips(router)
        self._assert_snat_chains(router)
        self._assert_floating_ip_chains(router)
        self._assert_metadata_chains(router)
        self._assert_extra_routes(router)

        self._delete_router(self.agent, router.router_id)
        self._assert_interfaces_deleted_from_ovs()
        self._assert_router_does_not_exist(router)

    def generate_dvr_router_info(self, enable_ha=False, enable_snat=False):
        router = test_l3_agent.prepare_router_data(
            enable_snat=enable_snat,
            enable_floating_ip=True,
            enable_ha=enable_ha)
        internal_ports = router.get(l3_constants.INTERFACE_KEY, [])
        router['distributed'] = True
        router['gw_port_host'] = self.agent.conf.host
        router['gw_port']['binding:host_id'] = self.agent.conf.host
        floating_ip = router['_floatingips'][0]
        floating_ip['floating_network_id'] = router['gw_port']['network_id']
        floating_ip['host'] = self.agent.conf.host
        floating_ip['port_id'] = internal_ports[0]['id']
        floating_ip['status'] = 'ACTIVE'

        self._add_snat_port_info_to_router(router, internal_ports)
        # FIP has a dependency on external gateway. So we need to create
        # the snat_port info and fip_agent_gw_port_info irrespective of
        # the agent type the dvr supports. The namespace creation is
        # dependent on the agent_type.
        external_gw_port = router['gw_port']
        self._add_fip_agent_gw_port_info_to_router(router, external_gw_port)
        return router

    def _add_fip_agent_gw_port_info_to_router(self, router, external_gw_port):
        # Add fip agent gateway port information to the router_info
        fip_gw_port_list = router.get(
            l3_constants.FLOATINGIP_AGENT_INTF_KEY, [])
        if not fip_gw_port_list and external_gw_port:
            # Get values from external gateway port
            fixed_ip = external_gw_port['fixed_ips'][0]
            float_subnet = external_gw_port['subnet']
            port_ip = fixed_ip['ip_address']
            # Pick an ip address which is not the same as port_ip
            fip_gw_port_ip = str(netaddr.IPAddress(port_ip) + 5)
            # Add floatingip agent gateway port info to router
            router[l3_constants.FLOATINGIP_AGENT_INTF_KEY] = [
                {'subnet':
                    {'cidr': float_subnet['cidr'],
                        'gateway_ip': float_subnet['gateway_ip'],
                        'id': fixed_ip['subnet_id']},
                    'network_id': external_gw_port['network_id'],
                    'device_owner': 'network:floatingip_agent_gateway',
                    'mac_address': 'fa:16:3e:80:8d:89',
                    'binding:host_id': self.agent.conf.host,
                    'fixed_ips': [{'subnet_id': fixed_ip['subnet_id'],
                                    'ip_address': fip_gw_port_ip}],
                    'id': _uuid(),
                    'device_id': _uuid()}
            ]

    def _add_snat_port_info_to_router(self, router, internal_ports):
        # Add snat port information to the router
        snat_port_list = router.get(l3_constants.SNAT_ROUTER_INTF_KEY, [])
        if not snat_port_list and internal_ports:
            # Get values from internal port
            port = internal_ports[0]
            fixed_ip = port['fixed_ips'][0]
            snat_subnet = port['subnet']
            port_ip = fixed_ip['ip_address']
            # Pick an ip address which is not the same as port_ip
            snat_ip = str(netaddr.IPAddress(port_ip) + 5)
            # Add the info to router as the first snat port
            # in the list of snat ports
            router[l3_constants.SNAT_ROUTER_INTF_KEY] = [
                {'subnet':
                    {'cidr': snat_subnet['cidr'],
                        'gateway_ip': snat_subnet['gateway_ip'],
                        'id': fixed_ip['subnet_id']},
                    'network_id': port['network_id'],
                    'device_owner': 'network:router_centralized_snat',
                    'mac_address': 'fa:16:3e:80:8d:89',
                    'fixed_ips': [{'subnet_id': fixed_ip['subnet_id'],
                                    'ip_address': snat_ip}],
                    'id': _uuid(),
                    'device_id': _uuid()}
            ]

    def _assert_dvr_external_device(self, router):
        external_port = self.agent._get_ex_gw_port(router)
        snat_ns_name = self.agent.get_snat_ns_name(router.router_id)

        # if the agent is in dvr_snat mode, then we have to check
        # that the correct ports and ip addresses exist in the
        # snat_ns_name namespace
        if self.agent.conf.agent_mode == 'dvr_snat':
            self.assertTrue(self.device_exists_with_ip_mac(
                external_port, self.agent.get_external_device_name,
                snat_ns_name))
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
            self.assertTrue(False, " agent not configured for dvr or dvr_snat")

    def _assert_dvr_gateway(self, router):
        gateway_expected_in_snat_namespace = (
            self.agent.conf.agent_mode == 'dvr_snat'
        )
        if gateway_expected_in_snat_namespace:
            self._assert_dvr_snat_gateway(router)

        snat_namespace_should_not_exist = (
            self.agent.conf.agent_mode == 'dvr'
        )
        if snat_namespace_should_not_exist:
            self._assert_snat_namespace_does_not_exist(router)

    def _assert_dvr_snat_gateway(self, router):
        namespace = self.agent.get_snat_ns_name(router.router_id)
        external_port = self.agent._get_ex_gw_port(router)
        external_device_name = self.agent.get_external_device_name(
            external_port['id'])
        external_device = ip_lib.IPDevice(external_device_name,
                                          self.root_helper,
                                          namespace)
        existing_gateway = (
            external_device.route.get_gateway().get('gateway'))
        expected_gateway = external_port['subnet']['gateway_ip']
        self.assertEqual(expected_gateway, existing_gateway)

    def _assert_snat_namespace_does_not_exist(self, router):
        namespace = self.agent.get_snat_ns_name(router.router_id)
        self.assertFalse(self._namespace_exists(namespace))

    def _assert_dvr_floating_ips(self, router):
        # in the fip namespace:
        # Check that the fg-<port-id> (floatingip_agent_gateway)
        # is created with the ip address of the external gateway port
        floating_ips = router.router[l3_constants.FLOATINGIP_KEY]
        self.assertTrue(floating_ips)
        # We need to fetch the floatingip agent gateway port info
        # from the router_info
        floating_agent_gw_port = (
            router.router[l3_constants.FLOATINGIP_AGENT_INTF_KEY])
        self.assertTrue(floating_agent_gw_port)

        external_gw_port = floating_agent_gw_port[0]
        fip_ns = self.agent.get_fip_ns(floating_ips[0]['floating_network_id'])
        fip_ns_name = fip_ns.get_name()
        fg_port_created_succesfully = ip_lib.device_exists_with_ip_mac(
            fip_ns.get_ext_device_name(external_gw_port['id']),
            external_gw_port['ip_cidr'],
            external_gw_port['mac_address'],
            fip_ns_name, self.root_helper)
        self.assertTrue(fg_port_created_succesfully)
        # Check fpr-router device has been created
        device_name = fip_ns.get_int_device_name(router.router_id)
        fpr_router_device_created_succesfully = ip_lib.device_exists(
            device_name, self.root_helper, fip_ns_name)
        self.assertTrue(fpr_router_device_created_succesfully)

        # In the router namespace
        # Check rfp-<router-id> is created correctly
        for fip in floating_ips:
            device_name = fip_ns.get_rtr_ext_device_name(router.router_id)
            self.assertTrue(ip_lib.device_exists(
                device_name, self.root_helper, router.ns_name))
