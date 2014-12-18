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

import fixtures
import mock
from oslo.config import cfg
import webob
import webob.dec
import webob.exc

from neutron.agent.common import config as agent_config
from neutron.agent.l3 import agent as l3_agent
from neutron.agent.linux import dhcp
from neutron.agent.linux import external_process
from neutron.agent.linux import ip_lib
from neutron.agent.metadata import agent as metadata_agent
from neutron.common import config as common_config
from neutron.common import constants as l3_constants
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
        return config

    def _configure_agent(self, host):
        conf = self._get_config_opts()
        l3_agent._register_opts(conf)
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

        temp_dir = self.useFixture(fixtures.TempDir()).path
        conf.set_override('state_path', temp_dir)
        conf.set_override('metadata_proxy_socket',
                          '%s/metadata_proxy' % temp_dir)
        conf.set_override('ha_confs_path',
                          '%s/ha_confs' % temp_dir)
        conf.set_override('external_pids',
                          '%s/external/pids' % temp_dir)
        conf.set_override('host', host)
        agent = l3_test_agent.TestL3NATAgent(host, conf)
        mock.patch.object(agent, '_arping').start()

        return agent

    def generate_router_info(self, enable_ha):
        return test_l3_agent.prepare_router_data(enable_snat=True,
                                                 enable_floating_ip=True,
                                                 enable_ha=enable_ha)

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

    def _namespace_exists(self, router):
        ip = ip_lib.IPWrapper(self.root_helper, router.ns_name)
        return ip.netns.exists(router.ns_name)

    def _metadata_proxy_exists(self, conf, router):
        pm = external_process.ProcessManager(
            conf,
            router.router_id,
            self.root_helper,
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
        ha_device_name = self.agent.get_ha_device_name(router.ha_port['id'])
        ha_device_cidr = router.ha_port['ip_cidr']
        external_port = self.agent._get_ex_gw_port(router)
        external_device_name = self.agent.get_external_device_name(
            external_port['id'])
        external_device_cidr = external_port['ip_cidr']
        internal_port = router.router[l3_constants.INTERFACE_KEY][0]
        internal_device_name = self.agent.get_internal_device_name(
            internal_port['id'])
        internal_device_cidr = internal_port['ip_cidr']
        floating_ip_cidr = (
            self.agent.get_floating_ips(router)[0]
            ['floating_ip_address'] + l3_agent.FLOATING_IP_CIDR_SUFFIX)
        default_gateway_ip = external_port['subnet'].get('gateway_ip')

        return """vrrp_sync_group VG_1 {
    group {
        VR_1
    }
    notify_master "%(ha_confs_path)s/%(router_id)s/notify_master.sh"
    notify_backup "%(ha_confs_path)s/%(router_id)s/notify_backup.sh"
    notify_fault "%(ha_confs_path)s/%(router_id)s/notify_fault.sh"
}
vrrp_instance VR_1 {
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
        %(floating_ip_cidr)s dev %(external_device_name)s
    }
    virtual_ipaddress_excluded {
        %(external_device_cidr)s dev %(external_device_name)s
        %(internal_device_cidr)s dev %(internal_device_name)s
    }
    virtual_routes {
        0.0.0.0/0 via %(default_gateway_ip)s dev %(external_device_name)s
    }
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
            'default_gateway_ip': default_gateway_ip
        }


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

    def test_keepalived_configuration(self):
        router_info = self.generate_router_info(enable_ha=True)
        router = self.manage_router(self.agent, router_info)
        expected = self.get_expected_keepalive_configuration(router)

        self.assertEqual(expected,
                         router.keepalived_manager.config.get_config_str())

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
        self.assertNotIn(old_external_device_ip, new_config)
        self.assertIn(new_external_device_ip, new_config)

    def _router_lifecycle(self, enable_ha):
        router_info = self.generate_router_info(enable_ha)
        router = self.manage_router(self.agent, router_info)

        if enable_ha:
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

        self.assertTrue(self._namespace_exists(router))
        self.assertTrue(self._metadata_proxy_exists(self.agent.conf, router))
        self._assert_internal_devices(router)
        self._assert_external_device(router)
        self._assert_gateway(router)
        self._assert_floating_ips(router)
        self._assert_snat_chains(router)
        self._assert_floating_ip_chains(router)

        if enable_ha:
            self._assert_ha_device(router)
            self.assertTrue(router.keepalived_manager.process.active)

        self._delete_router(self.agent, router.router_id)

        self._assert_router_does_not_exist(router)
        if enable_ha:
            self.assertFalse(router.keepalived_manager.process.active)

    def _assert_internal_devices(self, router):
        internal_devices = router.router[l3_constants.INTERFACE_KEY]
        self.assertTrue(len(internal_devices))
        for device in internal_devices:
            self.assertTrue(self.device_exists_with_ip_mac(
                device, self.agent.get_internal_device_name, router.ns_name))

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

    def _assert_floating_ips(self, router):
        floating_ips = router.router[l3_constants.FLOATINGIP_KEY]
        self.assertTrue(len(floating_ips))
        external_port = self.agent._get_ex_gw_port(router)
        for fip in floating_ips:
            self.assertTrue(ip_lib.device_exists_with_ip_mac(
                self.agent.get_external_device_name(external_port['id']),
                '%s/32' % fip['floating_ip_address'],
                external_port['mac_address'],
                router.ns_name, self.root_helper))

    def _assert_snat_chains(self, router):
        self.assertFalse(router.iptables_manager.is_chain_empty(
            'nat', 'snat'))
        self.assertFalse(router.iptables_manager.is_chain_empty(
            'nat', 'POSTROUTING'))

    def _assert_floating_ip_chains(self, router):
        self.assertFalse(router.iptables_manager.is_chain_empty(
            'nat', 'float-snat'))

    def _assert_router_does_not_exist(self, router):
        # If the namespace assertion succeeds
        # then the devices and iptable rules have also been deleted,
        # so there's no need to check that explicitly.
        self.assertFalse(self._namespace_exists(router))
        self.assertFalse(self._metadata_proxy_exists(self.agent.conf, router))

    def _assert_ha_device(self, router):
        self.assertTrue(self.device_exists_with_ip_mac(
            router.router[l3_constants.HA_INTERFACE_KEY],
            self.agent.get_ha_device_name, router.ns_name))


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
            test_l3_agent.get_ha_interface(ip='169.254.0.3',
                                           mac='22:22:22:22:22:22'))

        router2 = self.manage_router(self.failover_agent, router_info_2)

        helpers.wait_until_true(lambda: router1.ha_state == 'master')
        helpers.wait_until_true(lambda: router2.ha_state == 'backup')

        device_name = self.agent.get_ha_device_name(
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
