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

from neutron_lib import constants as n_const
from neutron_lib import exceptions as n_exc
from oslo_utils import uuidutils

from neutron import manager
from neutron.services.trunk import constants
from neutron.services.trunk import exceptions as trunk_exc
from neutron.services.trunk import plugin as trunk_plugin
from neutron.services.trunk import rules
from neutron.services.trunk.validators import vlan as vlan_driver
from neutron.tests import base
from neutron.tests.unit.plugins.ml2 import test_plugin


class SubPortsValidatorTestCase(base.BaseTestCase):

    def setUp(self):
        super(SubPortsValidatorTestCase, self).setUp()
        self.segmentation_types = {constants.VLAN: vlan_driver.vlan_range}
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
        self.trunk_plugin = trunk_plugin.TrunkPlugin()
        self.trunk_plugin.add_segmentation_type(constants.VLAN,
                                                vlan_driver.vlan_range)

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
            self.assertRaises(trunk_exc.ParentPortInUse,
                              validator.validate,
                              self.context)

    def test_validate_port_has_device_owner_compute(self):
        with self.port() as port:
            core_plugin = manager.NeutronManager.get_plugin()
            device_owner = n_const.DEVICE_OWNER_COMPUTE_PREFIX + 'test'
            port['port']['device_owner'] = device_owner
            core_plugin.update_port(self.context, port['port']['id'], port)
            validator = rules.TrunkPortValidator(port['port']['id'])
            self.assertRaises(trunk_exc.ParentPortInUse,
                              validator.validate,
                              self.context)
