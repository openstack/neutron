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

import mock
from oslo.config import cfg

from neutron.agent.common import config
from neutron.agent import l3_agent
from neutron.agent.linux import external_process
from neutron.agent.linux import ip_lib
from neutron.common import constants as l3_constants
from neutron.openstack.common import log as logging
from neutron.openstack.common import uuidutils
from neutron.tests.functional.agent.linux import base
from neutron.tests.unit import test_l3_agent

LOG = logging.getLogger(__name__)
_uuid = uuidutils.generate_uuid


class L3AgentTestFramework(base.BaseOVSLinuxTestCase):
    def setUp(self):
        super(L3AgentTestFramework, self).setUp()
        self.check_sudo_enabled()
        self._configure()

    def _configure(self):
        l3_agent._register_opts(cfg.CONF)
        cfg.CONF.set_override('debug', True)
        config.setup_logging(cfg.CONF)
        cfg.CONF.set_override(
            'interface_driver',
            'neutron.agent.linux.interface.OVSInterfaceDriver')
        cfg.CONF.set_override('router_delete_namespaces', True)
        cfg.CONF.set_override('root_helper', self.root_helper, group='AGENT')
        cfg.CONF.set_override('use_namespaces', True)
        cfg.CONF.set_override('enable_metadata_proxy', True)

        br_int = self.create_ovs_bridge()
        cfg.CONF.set_override('ovs_integration_bridge', br_int.br_name)
        br_ex = self.create_ovs_bridge()
        cfg.CONF.set_override('external_network_bridge', br_ex.br_name)

        mock.patch('neutron.common.rpc.RpcProxy.cast').start()
        mock.patch('neutron.common.rpc.RpcProxy.call').start()
        mock.patch('neutron.common.rpc.RpcProxy.fanout_cast').start()
        self.agent = l3_agent.L3NATAgent('localhost', cfg.CONF)

        mock.patch.object(self.agent, '_send_gratuitous_arp_packet').start()

    def manage_router(self):
        router = test_l3_agent.prepare_router_data(enable_snat=True,
                                                   enable_floating_ip=True)
        self.addCleanup(self._delete_router, router['id'])
        ri = self._create_router(router)
        return ri

    def _create_router(self, router):
        self.agent._router_added(router['id'], router)
        ri = self.agent.router_info[router['id']]
        ri.router = router
        self.agent.process_router(ri)
        return ri

    def _delete_router(self, router_id):
        self.agent._router_removed(router_id)

    def _namespace_exists(self, router):
        ip = ip_lib.IPWrapper(self.root_helper, router.ns_name)
        return ip.netns.exists(router.ns_name)

    def _metadata_proxy_exists(self, router):
        pm = external_process.ProcessManager(
            cfg.CONF,
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


class L3AgentTestCase(L3AgentTestFramework):
    def test_router_lifecycle(self):
        router = self.manage_router()

        self.assertTrue(self._namespace_exists(router))
        self.assertTrue(self._metadata_proxy_exists(router))
        self._assert_internal_devices(router)
        self._assert_external_device(router)
        self._assert_gateway(router)
        self._assert_snat_chains(router)
        self._assert_floating_ip_chains(router)

        self._delete_router(router.router_id)
        self._assert_router_does_not_exist(router)

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
        self.assertFalse(self._metadata_proxy_exists(router))
