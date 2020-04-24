#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from unittest import mock

from neutron_lib.callbacks import events as cb_events
from neutron_lib.services.trunk import constants as t_const
import oslo_messaging
from oslo_utils import uuidutils
import testtools

from neutron.api.rpc.callbacks import events
from neutron.api.rpc.handlers import resources_rpc
from neutron.objects import trunk
from neutron.services.trunk.drivers.linuxbridge.agent import driver
from neutron.services.trunk.drivers.linuxbridge.agent import trunk_plumber
from neutron.tests import base


class LinuxBridgeTrunkDriverTestCase(base.BaseTestCase):
    def setUp(self):
        super(LinuxBridgeTrunkDriverTestCase, self).setUp()
        self.plumber = mock.create_autospec(trunk_plumber.Plumber())
        self.stub = mock.create_autospec(driver.trunk_rpc.TrunkStub())
        self.tapi = mock.create_autospec(driver._TrunkAPI(self.stub))
        self.lbd = driver.LinuxBridgeTrunkDriver(self.plumber, self.tapi)
        self.trunk = trunk.Trunk(id=uuidutils.generate_uuid(),
                                 port_id=uuidutils.generate_uuid(),
                                 project_id=uuidutils.generate_uuid())
        self.subports = [trunk.SubPort(id=uuidutils.generate_uuid(),
                                       port_id=uuidutils.generate_uuid(),
                                       segmentation_type='vlan',
                                       trunk_id=self.trunk.id,
                                       segmentation_id=i)
                         for i in range(20)]
        self.trunk.sub_ports = self.subports

    def test_handle_trunks_created(self):
        self._test_handle_trunks_wire_event(events.CREATED)

    def test_handle_trunks_updated(self):
        self._test_handle_trunks_wire_event(events.UPDATED)

    def _test_handle_trunks_wire_event(self, event):
        self.plumber.trunk_on_host.return_value = True
        self.lbd.handle_trunks(mock.Mock(), 'TRUNKS',
                               [self.trunk], event)
        self.tapi.put_trunk.assert_called_once_with(
            self.trunk.port_id, self.trunk)
        self.tapi.bind_subports_to_host.assert_called_once_with(
            mock.ANY, self.trunk)
        self.assertFalse(self.plumber.delete_trunk_subports.called)

    def test_handle_trunks_deleted(self):
        self.lbd.handle_trunks(mock.Mock(), 'TRUNKS',
                               [self.trunk], events.DELETED)
        self.tapi.put_trunk.assert_called_once_with(
            self.trunk.port_id, None)
        self.plumber.delete_trunk_subports.assert_called_once_with(self.trunk)

    def test_handle_subports_deleted(self):
        self.tapi.get_trunk_by_id.return_value = self.trunk
        self.lbd.handle_subports(mock.Mock(), 'TRUNKS',
                                 self.trunk.sub_ports, events.DELETED)
        self.assertEqual(20, len(self.tapi.delete_trunk_subport.mock_calls))
        # should have tried to wire trunk at the end with state
        self.plumber.trunk_on_host.assert_called_once_with(self.trunk)

    def test_handle_subports_created(self):
        self.tapi.get_trunk_by_id.return_value = self.trunk
        self.lbd.handle_subports(mock.Mock(), 'TRUNKS',
                                 self.trunk.sub_ports, events.CREATED)
        self.assertEqual(20, len(self.tapi.put_trunk_subport.mock_calls))
        # should have tried to wire trunk at the end with state
        self.plumber.trunk_on_host.assert_called_once_with(self.trunk)

    def test_agent_port_change_is_trunk(self):
        self.tapi.get_trunk.return_value = self.trunk
        self.lbd.agent_port_change(
            'resource', 'event', 'trigger', payload=cb_events.DBEventPayload(
                'context', states=({'port_id': self.trunk.port_id},),
                resource_id=self.trunk.port_id))
        # should have tried to wire trunk
        self.plumber.trunk_on_host.assert_called_once_with(self.trunk)

    def test_agent_port_change_not_trunk(self):
        self.tapi.get_trunk.return_value = None
        self.tapi.get_trunk_for_subport.return_value = None
        other_port_id = uuidutils.generate_uuid()
        self.lbd.agent_port_change(
            'resource', 'event', 'trigger', payload=cb_events.DBEventPayload(
                'context', states=({'port_id': other_port_id},),
                resource_id=other_port_id))
        self.plumber.delete_subports_by_port_id.assert_called_once_with(
            other_port_id)

    def test_agent_port_change_is_subport(self):
        self.tapi.get_trunk.return_value = None
        self.tapi.get_trunk_for_subport.return_value = self.trunk
        port_dev = {'port_id': self.trunk.sub_ports[0].port_id,
                    'mac_address': 'mac_addr'}
        self.lbd.agent_port_change(
            'resource', 'event', 'trigger', payload=cb_events.DBEventPayload(
                'context', states=(port_dev,),
                resource_id=port_dev['port_id']))
        self.plumber.delete_subports_by_port_id.assert_called_once_with(
            self.trunk.sub_ports[0].port_id)

    def test_wire_trunk_happy_path(self):
        self.lbd.wire_trunk('ctx', self.trunk)
        self.tapi.bind_subports_to_host.assert_called_once_with(
            'ctx', self.trunk)
        self.plumber.ensure_trunk_subports.assert_called_once_with(self.trunk)
        self.tapi.set_trunk_status.assert_called_once_with(
            'ctx', self.trunk, t_const.TRUNK_ACTIVE_STATUS)

    def test_wire_trunk_not_on_host(self):
        # trunk device not on host
        self.plumber.trunk_on_host.return_value = False
        self.lbd.wire_trunk('ctx', self.trunk)
        # don't bind and don't set status
        self.assertFalse(self.tapi.bind_subports_to_host.called)
        self.assertFalse(self.tapi.set_trunk_status.called)

    def test_wire_trunk_concurrent_removal(self):
        self.plumber.trunk_on_host.side_effect = [True, False]
        self.plumber.ensure_trunk_subports.side_effect = ValueError()
        self.lbd.wire_trunk('ctx', self.trunk)
        # we don't change status if port was just removed
        self.assertFalse(self.tapi.set_trunk_status.called)

    def test_wire_trunk_other_exception(self):
        self.plumber.ensure_trunk_subports.side_effect = ValueError()
        self.lbd.wire_trunk('ctx', self.trunk)
        # degraded due to dataplane failure
        self.tapi.set_trunk_status.assert_called_once_with(
            'ctx', self.trunk, t_const.TRUNK_DEGRADED_STATUS)


class TrunkAPITestCase(base.BaseTestCase):
    def setUp(self):
        super(TrunkAPITestCase, self).setUp()
        self.stub = mock.create_autospec(driver.trunk_rpc.TrunkStub())
        self.tapi = driver._TrunkAPI(self.stub)
        self.trunk = trunk.Trunk(id=uuidutils.generate_uuid(),
                                 port_id=uuidutils.generate_uuid(),
                                 project_id=uuidutils.generate_uuid())
        self.subports = [trunk.SubPort(id=uuidutils.generate_uuid(),
                                       port_id=uuidutils.generate_uuid(),
                                       segmentation_type='vlan',
                                       trunk_id=self.trunk.id,
                                       segmentation_id=i)
                         for i in range(20)]
        self.trunk.sub_ports = self.subports
        self.stub.get_trunk_details.return_value = self.trunk

    def test_fetch_trunk(self):
        self.assertEqual(self.trunk, self.tapi._fetch_trunk('ctx', 'port'))
        self.stub.get_trunk_details.assert_called_once_with('ctx', 'port')

    def test_fetch_trunk_missing(self):
        self.stub.get_trunk_details.side_effect = (
            resources_rpc.ResourceNotFound(resource_id='1', resource_type='1'))
        self.assertIsNone(self.tapi._fetch_trunk('ctx', 'port'))

    def test_fetch_trunk_plugin_disabled(self):
        self.stub.get_trunk_details.side_effect = (
            oslo_messaging.RemoteError('CallbackNotFound'))
        self.assertIsNone(self.tapi._fetch_trunk('ctx', 'port'))

    def test_fetch_trunk_plugin_other_error(self):
        self.stub.get_trunk_details.side_effect = (
            oslo_messaging.RemoteError('vacuum full'))
        with testtools.ExpectedException(oslo_messaging.RemoteError):
            self.tapi._fetch_trunk('ctx', 'port')

    def test_set_trunk_status(self):
        self.tapi.set_trunk_status('ctx', self.trunk, 'STATUS')
        self.stub.update_trunk_status.assert_called_once_with(
            'ctx', self.trunk.id, 'STATUS')

    def test_bind_subports_to_host(self):
        self.tapi.bind_subports_to_host('ctx', self.trunk)
        self.stub.update_subport_bindings.assert_called_once_with(
            'ctx', self.trunk.sub_ports)

    def test_put_trunk_subport_non_existent_trunk(self):
        # trunks not registered are ignored
        self.tapi.put_trunk_subport(
            'non_trunk_id', self.trunk.sub_ports[0])

    def test_get_trunk_by_id(self):
        self.tapi.put_trunk(self.trunk.port_id, self.trunk)
        self.assertEqual(self.trunk,
                         self.tapi.get_trunk_by_id('ctx', self.trunk.id))
        self.assertIsNone(self.tapi.get_trunk_by_id('ctx', 'other_id'))

    def test_put_trunk_subport(self):
        self.tapi.put_trunk(self.trunk.port_id, self.trunk)
        new = trunk.SubPort(id=uuidutils.generate_uuid(),
                            port_id=uuidutils.generate_uuid(),
                            segmentation_type='vlan',
                            trunk_id=self.trunk.id,
                            segmentation_id=1010)
        self.tapi.put_trunk_subport(self.trunk.id, new)
        subs = self.tapi.get_trunk('ctx', self.trunk.port_id).sub_ports
        self.assertEqual(21, len(subs))
        self.assertEqual(new, subs[-1])

    def test_delete_trunk_subport(self):
        self.tapi.put_trunk(self.trunk.port_id, self.trunk)
        sub = self.trunk.sub_ports[10]
        self.tapi.delete_trunk_subport(self.trunk.id, sub)
        subs = self.tapi.get_trunk('ctx', self.trunk.port_id).sub_ports
        self.assertNotIn(sub, subs)
        self.assertEqual(19, len(subs))

    def test_get_trunk(self):
        self.tapi.put_trunk(self.trunk.port_id, self.trunk)
        self.assertEqual(self.trunk,
                         self.tapi.get_trunk('ctx', self.trunk.port_id))
        self.tapi.get_trunk('ctx', self.trunk.port_id)
        self.assertFalse(self.stub.get_trunk_details.called)

    def test_get_trunk_cache_miss(self):
        self.assertEqual(self.trunk,
                         self.tapi.get_trunk('ctx', self.trunk.port_id))
        self.tapi.get_trunk('ctx', self.trunk.port_id)
        self.assertEqual(1, len(self.stub.get_trunk_details.mock_calls))

    def test_get_trunk_not_found(self):
        self.stub.get_trunk_details.side_effect = (
            resources_rpc.ResourceNotFound(resource_id='1', resource_type='1'))
        self.assertIsNone(self.tapi.get_trunk('ctx', self.trunk.port_id))
        self.tapi.get_trunk('ctx', self.trunk.port_id)
        self.assertEqual(1, len(self.stub.get_trunk_details.mock_calls))

    def test_get_trunk_for_subport(self):
        self.tapi.put_trunk(self.trunk.port_id, self.trunk)
        t = self.tapi.get_trunk_for_subport(
            'ctx', self.trunk.sub_ports[0].port_id)
        self.assertEqual(self.trunk, t)
