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

import random

import eventlet
import mock
from oslo_config import cfg
from oslo_utils import uuidutils

from neutron.agent.common import config as agent_config
from neutron.agent.common import ovs_lib
from neutron.agent.l2.extensions import manager as ext_manager
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
from neutron.tests.common import net_helpers
from neutron.tests.functional.agent.linux import base


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
        self.br_phys = base.get_rand_name(n_const.DEVICE_NAME_MAX_LEN,
                                          prefix='br-phys')
        patch_name_len = n_const.DEVICE_NAME_MAX_LEN - len("-patch-tun")
        self.patch_tun = "%s-patch-tun" % self.br_int[patch_name_len:]
        self.patch_int = "%s-patch-int" % self.br_tun[patch_name_len:]
        self.ovs = ovs_lib.BaseOVS()
        self.config = self._configure_agent()
        self.driver = interface.OVSInterfaceDriver(self.config)
        self.namespace = self.useFixture(net_helpers.NamespaceFixture()).name

    def _get_config_opts(self):
        config = cfg.ConfigOpts()
        config.register_opts(common_config.core_opts)
        config.register_opts(interface.OPTS)
        config.register_opts(ovs_config.ovs_opts, "OVS")
        config.register_opts(ovs_config.agent_opts, "AGENT")
        agent_config.register_interface_driver_opts_helper(config)
        agent_config.register_agent_state_opts_helper(config)
        ext_manager.register_opts(config)
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

    def create_agent(self, create_tunnels=True, ancillary_bridge=None):
        if create_tunnels:
            tunnel_types = [p_const.TYPE_VXLAN]
        else:
            tunnel_types = None
        bridge_mappings = ['physnet:%s' % self.br_phys]
        self.config.set_override('tunnel_types', tunnel_types, "AGENT")
        self.config.set_override('polling_interval', 1, "AGENT")
        self.config.set_override('prevent_arp_spoofing', False, "AGENT")
        self.config.set_override('local_ip', '192.168.10.1', "OVS")
        self.config.set_override('bridge_mappings', bridge_mappings, "OVS")
        # Physical bridges should be created prior to running
        self._bridge_classes()['br_phys'](self.br_phys).create()
        agent = ovs_agent.OVSNeutronAgent(self._bridge_classes(),
                                          self.config)
        self.addCleanup(self.ovs.delete_bridge, self.br_int)
        if tunnel_types:
            self.addCleanup(self.ovs.delete_bridge, self.br_tun)
        self.addCleanup(self.ovs.delete_bridge, self.br_phys)
        agent.sg_agent = mock.Mock()
        agent.ancillary_brs = []
        if ancillary_bridge:
            agent.ancillary_brs.append(ancillary_bridge)
        return agent

    def _mock_get_events(self, agent, polling_manager, ports):
        get_events = polling_manager.get_events
        p_ids = [p['id'] for p in ports]

        def filter_events():
            events = get_events()
            filtered_ports = []
            for dev in events['added']:
                iface_id = agent.int_br.portid_from_external_ids(
                    dev.get('external_ids', []))
                if iface_id in p_ids:
                    # if the event is not about a port that was created by
                    # this test, we filter the event out. Since these tests are
                    # not run in isolation processing all the events might make
                    # some test fail ( e.g. the agent might keep resycing
                    # because it keeps finding not ready ports that are created
                    # by other tests)
                    filtered_ports.append(dev)
            return {'added': filtered_ports, 'removed': events['removed']}
        polling_manager.get_events = mock.Mock(side_effect=filter_events)

    def start_agent(self, agent, ports=None, unplug_ports=None):
        if unplug_ports is None:
            unplug_ports = []
        if ports is None:
            ports = []
        self.setup_agent_rpc_mocks(agent, unplug_ports)
        polling_manager = polling.InterfacePollingMinimizer()
        self._mock_get_events(agent, polling_manager, ports)
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
        return polling_manager

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

    def _plug_ports(self, network, ports, agent,
                    bridge=None, namespace=None):
        if namespace is None:
            namespace = self.namespace
        for port in ports:
            bridge = bridge or agent.int_br
            self.driver.plug(
                network.get('id'), port.get('id'), port.get('vif_name'),
                port.get('mac_address'),
                bridge.br_name, namespace=namespace)
            ip_cidrs = ["%s/8" % (port.get('fixed_ips')[0][
                'ip_address'])]
            self.driver.init_l3(port.get('vif_name'), ip_cidrs,
                                namespace=namespace)

    def _unplug_ports(self, ports, agent):
        for port in ports:
            self.driver.unplug(
                port.get('vif_name'), agent.int_br.br_name, self.namespace)

    def _get_device_details(self, port, network):
        dev = {'device': port['id'],
               'port_id': port['id'],
               'network_id': network['id'],
               'network_type': network.get('network_type', 'vlan'),
               'physical_network': network.get('physical_network', 'physnet'),
               'segmentation_id': network.get('segmentation_id', 1),
               'fixed_ips': port['fixed_ips'],
               'device_owner': 'compute',
               'port_security_enabled': True,
               'security_groups': ['default'],
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

    def _expected_plugin_rpc_call(self, call, expected_devices, is_up=True):
        """Helper to check expected rpc call are received

        :param call: The call to check
        :param expected_devices: The device for which call is expected
        :param is_up: True if expected_devices are devices that are set up,
               False if expected_devices are devices that are set down
        """
        if is_up:
            rpc_devices = [
                dev for args in call.call_args_list for dev in args[0][1]]
        else:
            rpc_devices = [
                dev for args in call.call_args_list for dev in args[0][2]]
        for dev in rpc_devices:
            if dev in expected_devices:
                expected_devices.remove(dev)
        # reset mock otherwise if the mock is called again the same call param
        # will be processed again
        call.reset_mock()
        return not expected_devices

    def create_test_ports(self, amount=3, **kwargs):
        ports = []
        for x in range(amount):
            ports.append(self._create_test_port_dict(**kwargs))
        return ports

    def _mock_update_device(self, context, devices_up, devices_down, agent_id,
                            host=None):
        dev_up = []
        dev_down = []
        for port in self.ports:
            if devices_up and port['id'] in devices_up:
                dev_up.append(port['id'])
            if devices_down and port['id'] in devices_down:
                dev_down.append({'device': port['id'], 'exists': True})
        return {'devices_up': dev_up,
                'failed_devices_up': [],
                'devices_down': dev_down,
                'failed_devices_down': []}

    def setup_agent_rpc_mocks(self, agent, unplug_ports):
        def mock_device_details(context, devices, agent_id, host=None):
            details = []
            for port in self.ports:
                if port['id'] in devices:
                    dev = self._get_device_details(
                        port, self.network)
                    details.append(dev)
            ports_to_unplug = [x for x in unplug_ports if x['id'] in devices]
            if ports_to_unplug:
                self._unplug_ports(ports_to_unplug, self.agent)
            return {'devices': details, 'failed_devices': []}

        (agent.plugin_rpc.get_devices_details_list_and_failed_devices.
            side_effect) = mock_device_details
        agent.plugin_rpc.update_device_list.side_effect = (
            self._mock_update_device)

    def _prepare_resync_trigger(self, agent):
        def mock_device_raise_exception(context, devices_up, devices_down,
                                        agent_id, host=None):
            agent.plugin_rpc.update_device_list.side_effect = (
                self._mock_update_device)
            raise Exception('Exception to trigger resync')

        self.agent.plugin_rpc.update_device_list.side_effect = (
            mock_device_raise_exception)

    def _prepare_failed_dev_up_trigger(self, agent):

        def mock_failed_devices_up(context, devices_up, devices_down,
                                   agent_id, host=None):
            failed_devices = []
            devices = list(devices_up)
            # first port fails
            if self.ports[0]['id'] in devices_up:
                # reassign side_effect so that next RPC call will succeed
                agent.plugin_rpc.update_device_list.side_effect = (
                    self._mock_update_device)
                devices.remove(self.ports[0]['id'])
                failed_devices.append(self.ports[0]['id'])
            return {'devices_up': devices,
                    'failed_devices_up': failed_devices,
                    'devices_down': [],
                    'failed_devices_down': []}

        self.agent.plugin_rpc.update_device_list.side_effect = (
            mock_failed_devices_up)

    def _prepare_failed_dev_down_trigger(self, agent):

        def mock_failed_devices_down(context, devices_up, devices_down,
                                     agent_id, host=None):
            # first port fails
            failed_port_id = self.ports[0]['id']
            failed_devices_down = []
            dev_down = [
                {'device': p['id'], 'exists': True}
                for p in self.ports if p['id'] in devices_down and (
                    p['id'] != failed_port_id)]
            # check if it's the call to set devices down and if the device
            # that is supposed to fail is in the call then modify the
            # side_effect so that next RPC call will succeed.
            if devices_down and failed_port_id in devices_down:
                agent.plugin_rpc.update_device_list.side_effect = (
                     self._mock_update_device)
                failed_devices_down.append(failed_port_id)
            return {'devices_up': devices_up,
                    'failed_devices_up': [],
                    'devices_down': dev_down,
                    'failed_devices_down': failed_devices_down}

        self.agent.plugin_rpc.update_device_list.side_effect = (
            mock_failed_devices_down)

    def wait_until_ports_state(self, ports, up, timeout=60):
        port_ids = [p['id'] for p in ports]
        agent_utils.wait_until_true(
            lambda: self._expected_plugin_rpc_call(
                self.agent.plugin_rpc.update_device_list, port_ids, up),
            timeout=timeout)

    def setup_agent_and_ports(self, port_dicts, create_tunnels=True,
                              ancillary_bridge=None,
                              trigger_resync=False,
                              failed_dev_up=False,
                              failed_dev_down=False,
                              network=None):
        self.ports = port_dicts
        self.agent = self.create_agent(create_tunnels=create_tunnels,
                                       ancillary_bridge=ancillary_bridge)
        self.polling_manager = self.start_agent(self.agent, ports=self.ports)
        self.network = network or self._create_test_network_dict()
        if trigger_resync:
            self._prepare_resync_trigger(self.agent)
        elif failed_dev_up:
            self._prepare_failed_dev_up_trigger(self.agent)
        elif failed_dev_down:
            self._prepare_failed_dev_down_trigger(self.agent)

        self._plug_ports(self.network, self.ports, self.agent,
                         bridge=ancillary_bridge)

    def plug_ports_to_phys_br(self, network, ports, namespace=None):
        physical_network = network.get('physical_network', 'physnet')
        phys_segmentation_id = network.get('segmentation_id', None)
        network_type = network.get('network_type', 'flat')

        phys_br = self.agent.phys_brs[physical_network]

        self._plug_ports(network, ports, self.agent, bridge=phys_br,
                         namespace=namespace)

        if phys_segmentation_id and network_type == 'vlan':
            for port in ports:
                phys_br.set_db_attribute(
                    "Port", port['vif_name'], "tag", phys_segmentation_id)
