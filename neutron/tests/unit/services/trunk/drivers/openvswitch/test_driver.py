# Copyright 2016 Hewlett Packard Enterprise Development LP
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from unittest import mock

from neutron_lib.api.definitions import portbindings
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib import constants
from neutron_lib import context
from neutron_lib.plugins.ml2 import ovs_constants as agent_consts
from neutron_lib.services.trunk import constants as trunk_consts
from oslo_config import cfg

from neutron.services.trunk.drivers.openvswitch import driver
from neutron.tests import base

GEN_TRUNK_BR_NAME_PATCH = (
    'neutron.services.trunk.drivers.openvswitch.utils.gen_trunk_br_name')


class OVSDriverTestCase(base.BaseTestCase):

    def test_driver_creation(self):
        ovs_driver = driver.OVSDriver.create()
        self.assertFalse(ovs_driver.is_loaded)
        self.assertEqual(driver.NAME, ovs_driver.name)
        self.assertEqual(driver.SUPPORTED_INTERFACES, ovs_driver.interfaces)
        self.assertEqual(driver.SUPPORTED_SEGMENTATION_TYPES,
                         ovs_driver.segmentation_types)
        self.assertEqual(constants.AGENT_TYPE_OVS, ovs_driver.agent_type)
        self.assertFalse(ovs_driver.can_trunk_bound_port)
        self.assertTrue(
            ovs_driver.is_agent_compatible(constants.AGENT_TYPE_OVS))
        self.assertTrue(
            ovs_driver.is_interface_compatible(driver.SUPPORTED_INTERFACES[0]))

    def test_driver_is_loaded(self):
        cfg.CONF.set_override('mechanism_drivers',
                              'openvswitch', group='ml2')
        ovs_driver = driver.OVSDriver.create()
        self.assertTrue(ovs_driver.is_loaded)

    def test_driver_is_not_loaded(self):
        cfg.CONF.set_override('core_plugin', 'my_foo_plugin')
        ovs_driver = driver.OVSDriver.create()
        self.assertFalse(ovs_driver.is_loaded)

    @mock.patch(GEN_TRUNK_BR_NAME_PATCH)
    def test_vif_details_bridge_name_handler_registration(self,
                                                          mock_gen_br_name):
        driver.register()
        mock_gen_br_name.return_value = 'fake-trunk-br-name'
        test_trigger = mock.Mock()
        registry.publish(agent_consts.OVS_BRIDGE_NAME, events.BEFORE_READ,
                         test_trigger,
                         payload=events.EventPayload(
                             None, metadata={
                                 'port': {
                                     'trunk_details': {
                                         'trunk_id': 'foo'
                                     }
                                 }
                             }))
        test_trigger.assert_called_once_with('fake-trunk-br-name')

    def test__update_subport_binding(self):
        ovs_driver = driver.OVSDriver.create()
        core_plugin = mock.Mock()
        core_plugin.get_port.return_value = {portbindings.HOST_ID: 'host_id'}
        ovs_driver._core_plugin = core_plugin
        ctx = context.get_admin_context()
        mock_subports = [mock.Mock(port_id='sport_id1'),
                         mock.Mock(port_id='sport_id2')]
        mock_trunk_obj = mock.Mock(sub_ports=mock_subports, port_id='port_id',
                                   id='trunk_id')
        with mock.patch.object(ovs_driver, '_get_trunk') as mock_get_trunk:
            mock_get_trunk.return_value = mock_trunk_obj
            updated_port = {
                'port': {portbindings.HOST_ID: 'host_id',
                         'device_owner': trunk_consts.TRUNK_SUBPORT_OWNER}}
            ovs_driver._update_subport_binding(ctx, 'trunk_id')
            core_plugin.update_port.assert_has_calls(
                [mock.call(ctx, 'sport_id1', updated_port),
                 mock.call(ctx, 'sport_id2', updated_port)], any_order=True)
