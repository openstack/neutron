# Copyright (c) 2015 Red Hat, Inc.
# Copyright (c) 2015 SUSE Linux Products GmbH
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

import eventlet
import mock
import random

from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import uuidutils

from neutron.agent.common import config as agent_config
from neutron.agent.common import ovs_lib
from neutron.agent.linux import interface
from neutron.agent.linux import polling
from neutron.agent.linux import utils as agent_utils
from neutron.common import config as common_config
from neutron.common import constants as n_const
from neutron.common import utils
from neutron.plugins.common import constants as p_const
from neutron.plugins.ml2.drivers.openvswitch.agent.common import config \
    as ovs_config
from neutron.plugins.ml2.drivers.openvswitch.agent.common import constants
from neutron.plugins.ml2.drivers.openvswitch.agent.openflow.ovs_ofctl \
    import br_int
from neutron.plugins.ml2.drivers.openvswitch.agent.openflow.ovs_ofctl \
    import br_phys
from neutron.plugins.ml2.drivers.openvswitch.agent.openflow.ovs_ofctl \
    import br_tun
from neutron.plugins.ml2.drivers.openvswitch.agent import ovs_neutron_agent \
    as ovs_agent
from neutron.tests.functional.agent.linux import base

LOG = logging.getLogger(__name__)


class OVSAgentTestFramework(base.BaseOVSLinuxTestCase):

    def setUp(self):
        super(OVSAgentTestFramework, self).setUp()
        agent_rpc = ('neutron.plugins.ml2.drivers.openvswitch.agent.'
                     'ovs_neutron_agent.OVSPluginApi')
        mock.patch(agent_rpc).start()
        mock.patch('neutron.agent.rpc.PluginReportStateAPI').start()
        self.br_int = base.get_rand_name(n_const.DEVICE_NAME_MAX_LEN,
                                         prefix='br-int')
        self.br_tun = base.get_rand_name(n_const.DEVICE_NAME_MAX_LEN,
                                         prefix='br-tun')
        patch_name_len = n_const.DEVICE_NAME_MAX_LEN - len("-patch-tun")
        self.patch_tun = "%s-patch-tun" % self.br_int[patch_name_len:]
        self.patch_int = "%s-patch-int" % self.br_tun[patch_name_len:]
        self.ovs = ovs_lib.BaseOVS()
        self.config = self._configure_agent()
        self.driver = interface.OVSInterfaceDriver(self.config)

    def _get_config_opts(self):
        config = cfg.ConfigOpts()
        config.register_opts(common_config.core_opts)
        config.register_opts(interface.OPTS)
        config.register_opts(ovs_config.ovs_opts, "OVS")
        config.register_opts(ovs_config.agent_opts, "AGENT")
        agent_config.register_interface_driver_opts_helper(config)
        agent_config.register_agent_state_opts_helper(config)
        return config

    def _configure_agent(self):
        config = self._get_config_opts()
        config.set_override(
            'interface_driver',
            'neutron.agent.linux.interface.OVSInterfaceDriver')
        config.set_override('integration_bridge', self.br_int, "OVS")
        config.set_override('ovs_integration_bridge', self.br_int)
        config.set_override('tunnel_bridge', self.br_tun, "OVS")
        config.set_override('int_peer_patch_port', self.patch_tun, "OVS")
        config.set_override('tun_peer_patch_port', self.patch_int, "OVS")
        config.set_override('host', 'ovs-agent')
        return config

    def _bridge_classes(self):
        return {
            'br_int': br_int.OVSIntegrationBridge,
            'br_phys': br_phys.OVSPhysicalBridge,
            'br_tun': br_tun.OVSTunnelBridge
        }

    def create_agent(self, create_tunnels=True):
        if create_tunnels:
            tunnel_types = [p_const.TYPE_VXLAN]
        else:
            tunnel_types = None
        local_ip = '192.168.10.1'
        bridge_mappings = {'physnet': self.br_int}
        agent = ovs_agent.OVSNeutronAgent(self._bridge_classes(),
                                          self.br_int, self.br_tun,
                                          local_ip, bridge_mappings,
                                          polling_interval=1,
                                          tunnel_types=tunnel_types,
                                          prevent_arp_spoofing=False,
                                          conf=self.config)
        self.addCleanup(self.ovs.delete_bridge, self.br_int)
        if tunnel_types:
            self.addCleanup(self.ovs.delete_bridge, self.br_tun)
        agent.sg_agent = mock.Mock()
        return agent

    def start_agent(self, agent):
        polling_manager = polling.InterfacePollingMinimizer()
        self.addCleanup(polling_manager.stop)
        polling_manager.start()
        agent_utils.wait_until_true(
            polling_manager._monitor.is_active)
        agent.check_ovs_status = mock.Mock(
            return_value=constants.OVS_NORMAL)
        t = eventlet.spawn(agent.rpc_loop, polling_manager)

        def stop_agent(agent, rpc_loop_thread):
            agent.run_daemon_loop = False
            rpc_loop_thread.wait()

        self.addCleanup(stop_agent, agent, t)

    def _bind_ports(self, ports, network, agent):
        devices = []
        for port in ports:
            dev = OVSAgentTestFramework._get_device_details(port, network)
            vif_name = port.get('vif_name')
            vif_id = uuidutils.generate_uuid(),
            vif_port = ovs_lib.VifPort(
                vif_name, "%s" % vif_id, 'id-%s' % vif_id,
                port.get('mac_address'), agent.int_br)
            dev['vif_port'] = vif_port
            devices.append(dev)
            agent._bind_devices(devices)

    def _create_test_port_dict(self):
        return {'id': uuidutils.generate_uuid(),
                'mac_address': utils.get_random_mac(
                    'fa:16:3e:00:00:00'.split(':')),
                'fixed_ips': [{
                    'ip_address': '10.%d.%d.%d' % (
                         random.randint(3, 254),
                         random.randint(3, 254),
                         random.randint(3, 254))}],
                'vif_name': base.get_rand_name(
                    self.driver.DEV_NAME_LEN, self.driver.DEV_NAME_PREFIX)}

    def _create_test_network_dict(self):
        return {'id': uuidutils.generate_uuid(),
                'tenant_id': uuidutils.generate_uuid()}

    def _plug_ports(self, network, ports, agent, ip_len=24):
        for port in ports:
            self.driver.plug(
                network.get('id'), port.get('id'), port.get('vif_name'),
                port.get('mac_address'),
                agent.int_br.br_name, namespace=None)
            ip_cidrs = ["%s/%s" % (port.get('fixed_ips')[0][
                'ip_address'], ip_len)]
            self.driver.init_l3(port.get('vif_name'), ip_cidrs, namespace=None)

    @staticmethod
    def _get_device_details(port, network):
        dev = {'device': port['id'],
               'port_id': port['id'],
               'network_id': network['id'],
               'network_type': 'vlan',
               'physical_network': 'physnet',
               'segmentation_id': 1,
               'fixed_ips': port['fixed_ips'],
               'device_owner': 'compute',
               'admin_state_up': True}
        return dev

    def assert_bridge(self, br, exists=True):
        self.assertEqual(exists, self.ovs.bridge_exists(br))

    def assert_patch_ports(self, agent):

        def get_peer(port):
            return agent.int_br.db_get_val(
                'Interface', port, 'options', check_error=True)

        agent_utils.wait_until_true(
            lambda: get_peer(self.patch_int) == {'peer': self.patch_tun})
        agent_utils.wait_until_true(
            lambda: get_peer(self.patch_tun) == {'peer': self.patch_int})

    def assert_bridge_ports(self):
        for port in [self.patch_tun, self.patch_int]:
            self.assertTrue(self.ovs.port_exists(port))

    def assert_vlan_tags(self, ports, agent):
        for port in ports:
            res = agent.int_br.db_get_val('Port', port.get('vif_name'), 'tag')
            self.assertTrue(res)


class TestOVSAgent(OVSAgentTestFramework):

    def _expected_plugin_rpc_call(self, call, expected_devices, is_up=True):
        """Helper to check expected rpc call are received
        :param call: The call to check
        :param expected_devices The device for which call is expected
        :param is_up True if expected_devices are devices that are set up,
               False if expected_devices are devices that are set down
        """
        if is_up:
            rpc_devices = [
                dev for args in call.call_args_list for dev in args[0][1]]
        else:
            rpc_devices = [
                dev for args in call.call_args_list for dev in args[0][2]]
        return not (set(expected_devices) - set(rpc_devices))

    def _create_ports(self, network, agent, trigger_resync=False):
        ports = []
        for x in range(3):
            ports.append(self._create_test_port_dict())

        def mock_device_raise_exception(context, devices_up, devices_down,
                                        agent_id, host=None):
            agent.plugin_rpc.update_device_list.side_effect = (
                mock_update_device)
            raise Exception('Exception to trigger resync')

        def mock_device_details(context, devices, agent_id, host=None):

            details = []
            for port in ports:
                if port['id'] in devices:
                    dev = OVSAgentTestFramework._get_device_details(
                        port, network)
                    details.append(dev)
            return {'devices': details, 'failed_devices': []}

        def mock_update_device(context, devices_up, devices_down, agent_id,
                               host=None):
            dev_up = []
            dev_down = []
            for port in ports:
                if devices_up and port['id'] in devices_up:
                    dev_up.append(port['id'])
                if devices_down and port['id'] in devices_down:
                    dev_down.append({'device': port['id'], 'exists': True})
            return {'devices_up': dev_up,
                    'failed_devices_up': [],
                    'devices_down': dev_down,
                    'failed_devices_down': []}

        (agent.plugin_rpc.get_devices_details_list_and_failed_devices.
            side_effect) = mock_device_details
        if trigger_resync:
            agent.plugin_rpc.update_device_list.side_effect = (
                 mock_device_raise_exception)
        else:
            agent.plugin_rpc.update_device_list.side_effect = (
                mock_update_device)
        return ports

    def test_port_creation_and_deletion(self):
        agent = self.create_agent()
        self.start_agent(agent)
        network = self._create_test_network_dict()
        ports = self._create_ports(network, agent)
        self._plug_ports(network, ports, agent)
        up_ports_ids = [p['id'] for p in ports]
        agent_utils.wait_until_true(
            lambda: self._expected_plugin_rpc_call(
                agent.plugin_rpc.update_device_list, up_ports_ids))
        down_ports_ids = [p['id'] for p in ports]
        for port in ports:
            agent.int_br.delete_port(port['vif_name'])
        agent_utils.wait_until_true(
            lambda: self._expected_plugin_rpc_call(
                agent.plugin_rpc.update_device_list, down_ports_ids, False))

    def test_resync_devices_set_up_after_exception(self):
        agent = self.create_agent()
        self.start_agent(agent)
        network = self._create_test_network_dict()
        ports = self._create_ports(network, agent, True)
        self._plug_ports(network, ports, agent)
        ports_ids = [p['id'] for p in ports]
        agent_utils.wait_until_true(
            lambda: self._expected_plugin_rpc_call(
                agent.plugin_rpc.update_device_list, ports_ids))

    def test_port_vlan_tags(self):
        agent = self.create_agent()
        self.start_agent(agent)
        network = self._create_test_network_dict()
        ports = self._create_ports(network, agent)
        ports_ids = [p['id'] for p in ports]
        self._plug_ports(network, ports, agent)
        agent_utils.wait_until_true(
            lambda: self._expected_plugin_rpc_call(
                agent.plugin_rpc.update_device_list, ports_ids))
        self.assert_vlan_tags(ports, agent)

    def test_assert_bridges_ports_vxlan(self):
        agent = self.create_agent()
        self.assertTrue(self.ovs.bridge_exists(self.br_int))
        self.assertTrue(self.ovs.bridge_exists(self.br_tun))
        self.assert_bridge_ports()
        self.assert_patch_ports(agent)

    def test_assert_bridges_ports_no_tunnel(self):
        self.create_agent(create_tunnels=False)
        self.assertTrue(self.ovs.bridge_exists(self.br_int))
        self.assertFalse(self.ovs.bridge_exists(self.br_tun))
