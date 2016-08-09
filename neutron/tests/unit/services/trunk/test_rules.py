# Copyright 2016 Hewlett Packard Enterprise Development Company, LP
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

import mock

import testtools

from neutron_lib import exceptions as n_exc
from oslo_utils import uuidutils

from neutron import manager
from neutron.plugins.common import utils
from neutron.services.trunk import constants
from neutron.services.trunk import drivers
from neutron.services.trunk import exceptions as trunk_exc
from neutron.services.trunk import plugin as trunk_plugin
from neutron.services.trunk import rules
from neutron.services.trunk import utils as trunk_utils
from neutron.tests import base
from neutron.tests.unit.plugins.ml2 import test_plugin
from neutron.tests.unit.services.trunk import fakes


class SubPortsValidatorTestCase(base.BaseTestCase):

    def setUp(self):
        super(SubPortsValidatorTestCase, self).setUp()
        self.segmentation_types = {constants.VLAN: utils.is_valid_vlan_tag}
        self.context = mock.ANY

    def test_validate_subport_subport_and_trunk_shared_port_id(self):
        shared_id = uuidutils.generate_uuid()
        validator = rules.SubPortsValidator(
            self.segmentation_types,
            [{'port_id': shared_id,
              'segmentation_type': 'vlan',
              'segmentation_id': 2}],
            shared_id)
        self.assertRaises(trunk_exc.ParentPortInUse,
                          validator.validate, self.context)

    def test_validate_subport_invalid_vlan_id(self):
        validator = rules.SubPortsValidator(
            self.segmentation_types,
            [{'port_id': uuidutils.generate_uuid(),
              'segmentation_type': 'vlan',
              'segmentation_id': 5000}])
        self.assertRaises(n_exc.InvalidInput,
                          validator.validate,
                          self.context)

    def test_validate_subport_vlan_id_not_an_int(self):
        validator = rules.SubPortsValidator(
            self.segmentation_types,
            [{'port_id': uuidutils.generate_uuid(),
              'segmentation_type': 'vlan',
              'segmentation_id': 'IamNotAnumber'}])
        self.assertRaises(n_exc.InvalidInput,
                          validator.validate,
                          self.context)

    def test_validate_subport_valid_vlan_id_as_string(self):
        validator = rules.SubPortsValidator(
            self.segmentation_types,
            [{'port_id': uuidutils.generate_uuid(),
              'segmentation_type': 'vlan',
              'segmentation_id': '2'}])
        with mock.patch.object(rules.TrunkPortValidator, 'validate') as f:
            validator.validate(self.context)
            f.assert_called_once_with(self.context)

    def test_validate_subport_subport_invalid_segmenation_type(self):
        validator = rules.SubPortsValidator(
            self.segmentation_types,
            [{'port_id': uuidutils.generate_uuid(),
              'segmentation_type': 'fake',
              'segmentation_id': 100}])
        self.assertRaises(n_exc.InvalidInput,
                          validator.validate,
                          self.context)

    def test_validate_subport_missing_segmenation_type(self):
        validator = rules.SubPortsValidator(
            self.segmentation_types,
            [{'port_id': uuidutils.generate_uuid(),
              'segmentation_id': 100}])
        self.assertRaises(n_exc.InvalidInput,
                          validator.validate,
                          self.context)

    def test_validate_subport_missing_segmenation_id(self):
        validator = rules.SubPortsValidator(
            self.segmentation_types,
            [{'port_id': uuidutils.generate_uuid(),
              'segmentation_type': 'fake'}])
        self.assertRaises(n_exc.InvalidInput,
                          validator.validate,
                          self.context)

    def test_validate_subport_missing_port_id(self):
        validator = rules.SubPortsValidator(
            self.segmentation_types,
            [{'segmentation_type': 'fake',
            'segmentation_id': 100}])
        self.assertRaises(n_exc.InvalidInput,
                          validator.validate,
                          self.context, basic_validation=True)


class TrunkPortValidatorTestCase(test_plugin.Ml2PluginV2TestCase):

    def setUp(self):
        super(TrunkPortValidatorTestCase, self).setUp()
        self.drivers_patch = mock.patch.object(drivers, 'register').start()
        self.compat_patch = mock.patch.object(
            trunk_plugin.TrunkPlugin, 'check_compatibility').start()
        self.trunk_plugin = trunk_plugin.TrunkPlugin()
        self.trunk_plugin.add_segmentation_type(constants.VLAN,
                                                utils.is_valid_vlan_tag)

    def test_validate_port_parent_in_use_by_trunk(self):
        with self.port() as trunk_parent:
            trunk = {'port_id': trunk_parent['port']['id'],
                     'tenant_id': 'test_tenant',
                     'sub_ports': []}
            self.trunk_plugin.create_trunk(self.context, {'trunk': trunk})
            validator = rules.TrunkPortValidator(trunk_parent['port']['id'])
            self.assertRaises(trunk_exc.ParentPortInUse,
                              validator.validate,
                              self.context)

    def test_validate_port_id_in_use_by_unrelated_trunk(self):
        with self.port() as trunk_parent,\
                 self.port() as subport:
            trunk = {'port_id': trunk_parent['port']['id'],
                     'tenant_id': 'test_tenant',
                     'sub_ports': [{'port_id': subport['port']['id'],
                                    'segmentation_type': 'vlan',
                                    'segmentation_id': 2}]}
            self.trunk_plugin.create_trunk(self.context, {'trunk': trunk})
            validator = rules.TrunkPortValidator(subport['port']['id'])
            self.assertRaises(trunk_exc.TrunkPortInUse,
                              validator.validate,
                              self.context)

    def test_validate_port_has_binding_host(self):
        with self.port() as port:
            core_plugin = manager.NeutronManager.get_plugin()
            port['port']['binding:host_id'] = 'host'
            core_plugin.update_port(self.context, port['port']['id'], port)
            validator = rules.TrunkPortValidator(port['port']['id'])
            self.assertTrue(validator.is_bound(self.context))

    def test_validate_port_cannot_be_trunked_raises(self):
        with self.port() as port, \
             mock.patch.object(rules.TrunkPortValidator,
                               "can_be_trunked", return_value=False), \
             testtools.ExpectedException(trunk_exc.ParentPortInUse):
            validator = rules.TrunkPortValidator(port['port']['id'])
            validator.validate(self.context)

    def test_can_be_trunked_returns_false(self):
        # need to trigger a driver registration
        fakes.FakeDriverCanTrunkBoundPort.create()
        self.trunk_plugin = trunk_plugin.TrunkPlugin()
        with self.port() as port, \
                mock.patch.object(manager.NeutronManager,
                                  "get_service_plugins") as f:
            f.return_value = {'trunk': self.trunk_plugin}
            core_plugin = manager.NeutronManager.get_plugin()
            port['port']['binding:host_id'] = 'host'
            core_plugin.update_port(self.context, port['port']['id'], port)
            validator = rules.TrunkPortValidator(port['port']['id'])
            # port cannot be trunked because of binding mismatch
            self.assertFalse(validator.can_be_trunked(self.context))

    def test_can_be_trunked_returns_true(self):
        # need to trigger a driver registration
        fakes.FakeDriverCanTrunkBoundPort.create()
        self.trunk_plugin = trunk_plugin.TrunkPlugin()
        with self.port() as port, \
                mock.patch.object(manager.NeutronManager,
                                  "get_service_plugins") as f, \
                mock.patch.object(trunk_utils, "is_driver_compatible",
                                  return_value=True) as g:
            f.return_value = {'trunk': self.trunk_plugin}
            core_plugin = manager.NeutronManager.get_plugin()
            port['port']['binding:host_id'] = 'host'
            core_plugin.update_port(self.context, port['port']['id'], port)
            validator = rules.TrunkPortValidator(port['port']['id'])
            self.assertTrue(validator.can_be_trunked(self.context))
            self.assertTrue(g.call_count)

    def test_can_be_trunked_unbound_port(self):
        with self.port() as port:
            validator = rules.TrunkPortValidator(port['port']['id'])
            self.assertTrue(validator.can_be_trunked(self.context))

    def test_can_be_trunked_raises_conflict(self):
        d1 = fakes.FakeDriver.create()
        d2 = fakes.FakeDriverWithAgent.create()
        self.trunk_plugin = trunk_plugin.TrunkPlugin()
        self.trunk_plugin._drivers = [d1, d2]
        with self.port() as port, \
                mock.patch.object(manager.NeutronManager,
                                  "get_service_plugins") as f, \
                mock.patch.object(trunk_utils, "is_driver_compatible",
                                  return_value=True):
            f.return_value = {'trunk': self.trunk_plugin}
            core_plugin = manager.NeutronManager.get_plugin()
            port['port']['binding:host_id'] = 'host'
            core_plugin.update_port(self.context, port['port']['id'], port)
            validator = rules.TrunkPortValidator(port['port']['id'])
            self.assertRaises(
                trunk_exc.TrunkPluginDriverConflict,
                validator.can_be_trunked, self.context)
