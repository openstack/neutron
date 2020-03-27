# Copyright (c) 2016 SUSE Linux Products GmbH
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

from neutron_lib import constants as n_consts
from neutron_lib.utils import helpers
from neutron_lib.utils import net
from oslo_utils import uuidutils

from neutron.agent.common import ovs_lib
from neutron.common import utils as common_utils
from neutron.objects import trunk as trunk_obj
from neutron.services.trunk.drivers.openvswitch.agent import ovsdb_handler
from neutron.services.trunk.drivers.openvswitch.agent import trunk_manager
from neutron.tests.functional.agent.l2 import base


def generate_tap_device_name():
    return n_consts.TAP_DEVICE_PREFIX + helpers.get_random_string(
        n_consts.DEVICE_NAME_MAX_LEN - len(n_consts.TAP_DEVICE_PREFIX))


class OVSDBHandlerTestCase(base.OVSAgentTestFramework):
    """Test functionality of OVSDBHandler.

    This suite aims for interaction between events coming from OVSDB monitor,
    agent and wiring ports via trunk bridge to integration bridge.
    """
    def setUp(self):
        """Prepare resources.

        Set up trunk_dict representing incoming data from Neutron-server when
        fetching for trunk details. Another resource trunk_br represents the
        trunk bridge which its creation is simulated when creating a port in l2
        agent framework.
        """
        super(OVSDBHandlerTestCase, self).setUp()
        trunk_id = uuidutils.generate_uuid()
        self.trunk_dict = {
            'id': trunk_id,
            'mac_address': net.get_random_mac('fa:16:3e:00:00:00'.split(':')),
            'sub_ports': []}
        self.trunk_port_name = generate_tap_device_name()
        self.trunk_br = trunk_manager.TrunkBridge(trunk_id)
        self.ovsdb_handler = self._prepare_mocked_ovsdb_handler()

    def _prepare_mocked_ovsdb_handler(self):
        handler = ovsdb_handler.OVSDBHandler(
            trunk_manager.TrunkManager(ovs_lib.OVSBridge(self.br_int)))
        mock.patch.object(handler, 'trunk_rpc').start()

        handler.trunk_rpc.get_trunk_details.side_effect = (
            self._mock_get_trunk_details)
        handler.trunk_rpc.update_subport_bindings.side_effect = (
            self._mock_update_subport_binding)

        return handler

    def _mock_get_trunk_details(self, context, parent_port_id):
        if parent_port_id == self.trunk_dict['port_id']:
            return trunk_obj.Trunk(**self.trunk_dict)

    def _mock_update_subport_binding(self, context, subports):
        return {self.trunk_dict['id']: [
            {'id': subport['port_id'], 'mac_address': subport['mac_address']}
            for subport in subports]
        }

    def _plug_ports(self, network, ports, agent, bridge=None, namespace=None):
        # creates only the trunk, the sub_port will be plugged by the
        # trunk manager
        if not self.trunk_br.exists():
            self.trunk_br.create()
            self.addCleanup(self.trunk_br.destroy)
        self.driver.plug(
            network['id'],
            self.trunk_dict['port_id'],
            self.trunk_port_name,
            self.trunk_dict['mac_address'],
            self.trunk_br.br_name)

    def _mock_get_events(self, agent, polling_manager, ports):
        get_events = polling_manager.get_events
        p_ids = [p['id'] for p in ports]

        def filter_events():
            events = get_events()
            filtered_events = {
                'added': [],
                'removed': [],
                'modified': []
            }
            for event_type in filtered_events:
                for dev in events[event_type]:
                    iface_id = agent.int_br.portid_from_external_ids(
                        dev.get('external_ids', []))
                    is_for_this_test = (
                        iface_id in p_ids or
                        iface_id == self.trunk_dict['port_id'] or
                        dev['name'] == self.trunk_br.br_name)
                    if is_for_this_test:
                        # if the event is not about a port that was created by
                        # this test, we filter the event out. Since these tests
                        # are not run in isolation processing all the events
                        # might make some test fail ( e.g. the agent might keep
                        # resycing because it keeps finding not ready ports
                        # that are created by other tests)
                        filtered_events[event_type].append(dev)
            return filtered_events
        mock.patch.object(polling_manager, 'get_events',
            side_effect=filter_events).start()

    def _fill_trunk_dict(self, num=3):
        ports = self.create_test_ports(amount=num)
        self.trunk_dict['port_id'] = ports[0]['id']
        self.trunk_dict['sub_ports'] = [trunk_obj.SubPort(
            id=uuidutils.generate_uuid(),
            port_id=ports[i]['id'],
            mac_address=ports[i]['mac_address'],
            segmentation_id=i,
            trunk_id=self.trunk_dict['id'])
            for i in range(1, num)]
        return ports

    def _test_trunk_creation_helper(self, ports):
        self.setup_agent_and_ports(port_dicts=ports)
        self.wait_until_ports_state(self.ports, up=True)
        self.trunk_br.delete_port(self.trunk_port_name)
        self.wait_until_ports_state(self.ports, up=False)
        common_utils.wait_until_true(lambda:
            not self.trunk_br.bridge_exists(self.trunk_br.br_name))

    def test_trunk_creation_with_subports(self):
        ports = self._fill_trunk_dict()
        self._test_trunk_creation_helper(ports[:1])

    def test_trunk_creation_with_no_subports(self):
        ports = self.create_test_ports(amount=1)
        self.trunk_dict['port_id'] = ports[0]['id']
        self._test_trunk_creation_helper(ports)

    def test_resync(self):
        ports = self._fill_trunk_dict()
        self.setup_agent_and_ports(port_dicts=ports)
        self.wait_until_ports_state(self.ports, up=True)
        self.agent.fullsync = True
        self.wait_until_ports_state(self.ports, up=True)

    def test_restart_subport_events(self):
        ports = self._fill_trunk_dict()
        self.setup_agent_and_ports(port_dicts=ports)
        self.wait_until_ports_state(self.ports, up=True)

        # restart and simulate a subport delete
        deleted_port = self.ports[2]
        deleted_sp = trunk_manager.SubPort(
            self.trunk_dict['id'], deleted_port['id'])
        self.stop_agent(self.agent, self.agent_thread)
        self.polling_manager.stop()
        self.trunk_dict['sub_ports'] = self.trunk_dict['sub_ports'][:1]
        self.setup_agent_and_ports(port_dicts=ports[:2])
        # NOTE: the port_dicts passed in setup_agent_and_ports is stored in
        # self.ports so we are waiting here only for ports[:2]
        self.wait_until_ports_state(self.ports, up=True)
        common_utils.wait_until_true(
            lambda: (deleted_sp.patch_port_trunk_name not in
                self.trunk_br.get_port_name_list()))

    def test_cleanup_on_vm_delete(self):
        with mock.patch.object(self.ovsdb_handler, 'handle_trunk_remove'):
            br_int = ovs_lib.OVSBridge(self.br_int)
            ports = self._fill_trunk_dict()
            self.setup_agent_and_ports(port_dicts=ports[:1])
            self.wait_until_ports_state(self.ports, up=True)
            self.trunk_br.delete_port(self.trunk_port_name)
            # We do not expect any instance port to show up on the trunk
            # bridge so we can set a much more aggressive timeout and
            # fail fast(er).
            self.ovsdb_handler.timeout = 1
            self.ovsdb_handler.handle_trunk_add(self.trunk_br.br_name)
            # Check no resources are left behind.
            self.assertFalse(self.trunk_br.exists())
            self.assertFalse(ovsdb_handler.bridge_has_service_port(br_int))

    def test_do_not_delete_trunk_bridge_with_instance_ports(self):
        ports = self._fill_trunk_dict()
        self.setup_agent_and_ports(port_dicts=ports)
        self.wait_until_ports_state(self.ports, up=True)
        self.ovsdb_handler.handle_trunk_remove(self.trunk_br.br_name,
                ports.pop())
        self.assertTrue(self.trunk_br.exists())
