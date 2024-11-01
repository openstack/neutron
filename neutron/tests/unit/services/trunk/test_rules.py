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

from unittest import mock

import testtools

from neutron_lib.api.definitions import trunk as trunk_api
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import directory
from neutron_lib.plugins.ml2 import api
from neutron_lib.plugins import utils as plugin_utils
from neutron_lib.services.trunk import constants
from oslo_utils import uuidutils

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
        super().setUp()
        self.segmentation_types = {
            constants.SEGMENTATION_TYPE_VLAN: plugin_utils.is_valid_vlan_tag}
        self.context = mock.ANY

        mock.patch.object(rules.SubPortsValidator, '_get_port_mtu',
                          return_value=None).start()
        mock.patch.object(rules.SubPortsValidator, '_prepare_subports',
                          return_value=None).start()

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
            f.assert_called_once_with(self.context, parent_port=False)

    def test_validate_subport_subport_invalid_segmentation_type(self):
        validator = rules.SubPortsValidator(
            self.segmentation_types,
            [{'port_id': uuidutils.generate_uuid(),
              'segmentation_type': 'fake',
              'segmentation_id': 100}])
        self.assertRaises(n_exc.InvalidInput,
                          validator.validate,
                          self.context)

    def test_validate_subport_missing_segmentation_type(self):
        validator = rules.SubPortsValidator(
            self.segmentation_types,
            [{'port_id': uuidutils.generate_uuid(),
              'segmentation_id': 100}])
        self.assertRaises(n_exc.InvalidInput,
                          validator.validate,
                          self.context)

    def test_validate_subport_missing_segmentation_id(self):
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


class SubPortsValidatorPrepareTestCase(base.BaseTestCase):

    def setUp(self):
        super().setUp()
        self.segmentation_types = {
            constants.SEGMENTATION_TYPE_VLAN: plugin_utils.is_valid_vlan_tag}
        self.context = mock.ANY

        mock.patch.object(rules.SubPortsValidator, '_get_port_mtu',
                          return_value=None).start()

    def test__prepare_subports_raise_no_provider_ext(self):
        validator = rules.SubPortsValidator(
            self.segmentation_types,
            [{'port_id': uuidutils.generate_uuid(),
              'segmentation_type': 'inherit'}])
        self.assertRaises(n_exc.InvalidInput,
                          validator._prepare_subports,
                          self.context)


class SubPortsValidatorMtuSanityTestCase(test_plugin.Ml2PluginV2TestCase):

    def setUp(self):
        super().setUp()
        self.segmentation_types = {
            constants.SEGMENTATION_TYPE_VLAN: plugin_utils.is_valid_vlan_tag}

    def test_validate_subport_mtu_same_as_trunk(self):
        self._test_validate_subport_trunk_mtu(1500, 1500)

    def test_validate_subport_mtu_smaller_than_trunks(self):
        self._test_validate_subport_trunk_mtu(500, 1500)

    def test_validate_subport_mtu_greater_than_trunks(self):
        self._test_validate_subport_trunk_mtu(1500, 500)

    def test_validate_subport_mtu_unset_trunks_set(self):
        self._test_validate_subport_trunk_mtu(None, 500)

    def test_validate_subport_mtu_set_trunks_unset(self):
        self._test_validate_subport_trunk_mtu(500, None)

    def test_validate_subport_mtu_set_trunks_net_exception(self):
        self._test_validate_subport_trunk_mtu(1500, 'exc')

    def _test_validate_subport_trunk_mtu(
            self, subport_net_mtu, trunk_net_mtu):
        plugin = directory.get_plugin()
        orig_get_network = plugin.get_network
        orig_get_networks = plugin.get_networks

        def get_networks_adjust_mtu(*args, **kwargs):
            res = orig_get_networks(*args, **kwargs)
            res[0][api.MTU] = subport_net_mtu
            return res

        def get_network_adjust_mtu(*args, **kwargs):
            res = orig_get_network(*args, **kwargs)
            if res['name'] == 'net_trunk':
                if trunk_net_mtu == 'exc':
                    raise n_exc.NetworkNotFound(net_id='net-id')
                res[api.MTU] = trunk_net_mtu
            elif res['name'] == 'net_subport':
                res[api.MTU] = subport_net_mtu
            return res

        with self.network('net_trunk') as trunk_net,\
            self.subnet(network=trunk_net) as trunk_subnet,\
            self.port(subnet=trunk_subnet) as trunk_port,\
            self.network('net_subport') as subport_net,\
            self.subnet(network=subport_net) as subport_subnet,\
            self.port(subnet=subport_subnet) as subport,\
            mock.patch.object(plugin, "get_network",
                              side_effect=get_network_adjust_mtu),\
            mock.patch.object(plugin, "get_networks",
                              side_effect=get_networks_adjust_mtu):
            trunk = {'port_id': trunk_port['port']['id'],
                     'tenant_id': 'test_tenant',
                     'sub_ports': [{'port_id': subport['port']['id'],
                                    'segmentation_type': 'vlan',
                                    'segmentation_id': 2}]}

            validator = rules.SubPortsValidator(
                self.segmentation_types, trunk['sub_ports'], trunk['port_id'])

            if subport_net_mtu is None or trunk_net_mtu is None:
                validator.validate(self.context)
            elif subport_net_mtu == 'exc' or trunk_net_mtu == 'exc':
                validator.validate(self.context)
            elif subport_net_mtu <= trunk_net_mtu:
                validator.validate(self.context)
            else:
                self.assertRaises(trunk_exc.SubPortMtuGreaterThanTrunkPortMtu,
                                  validator.validate, self.context)


class TrunkPortValidatorTestCase(test_plugin.Ml2PluginV2TestCase):

    def setUp(self):
        super().setUp()
        self.drivers_patch = mock.patch.object(drivers, 'register').start()
        self.compat_patch = mock.patch.object(
            trunk_plugin.TrunkPlugin, 'check_compatibility').start()
        self.trunk_plugin = trunk_plugin.TrunkPlugin()
        self.trunk_plugin.add_segmentation_type(
            constants.SEGMENTATION_TYPE_VLAN,
            plugin_utils.is_valid_vlan_tag)

    def test_validate_port_parent_in_use_by_trunk(self):
        with self.port() as trunk_parent:
            trunk = {'port_id': trunk_parent['port']['id'],
                     'project_id': 'test_tenant',
                     'sub_ports': []}
            self.trunk_plugin.create_trunk(
                self.context, {trunk_api.ALIAS: trunk})
            validator = rules.TrunkPortValidator(trunk_parent['port']['id'])
            self.assertRaises(trunk_exc.ParentPortInUse,
                              validator.validate,
                              self.context)

    def test_validate_port_id_in_use_by_unrelated_trunk(self):
        with self.port() as trunk_parent,\
                 self.port() as subport:
            trunk = {'port_id': trunk_parent['port']['id'],
                     'project_id': 'test_tenant',
                     'sub_ports': [{'port_id': subport['port']['id'],
                                    'segmentation_type': 'vlan',
                                    'segmentation_id': 2}]}
            self.trunk_plugin.create_trunk(
                self.context, {trunk_api.ALIAS: trunk})
            validator = rules.TrunkPortValidator(subport['port']['id'])
            self.assertRaises(trunk_exc.TrunkPortInUse,
                              validator.validate,
                              self.context)

    def test_validate_port_has_binding_host(self):
        with self.port() as port:
            core_plugin = directory.get_plugin()
            port['port']['binding:host_id'] = 'host'
            core_plugin.update_port(self.context, port['port']['id'], port)
            validator = rules.TrunkPortValidator(port['port']['id'])
            self.assertTrue(validator.is_bound(self.context))

    def test_validate_for_subport_calls_check(self):
        with self.port() as port:
            validator = rules.TrunkPortValidator(port['port']['id'])
            with mock.patch.object(validator, "check_not_in_use") as f:
                validator.validate(self.context, parent_port=False)
                f.assert_called_once_with(self.context)

    def test_validate_port_cannot_be_trunked_raises(self):
        with self.port() as port, \
             mock.patch.object(rules.TrunkPortValidator,
                               "can_be_trunked_or_untrunked",
                               return_value=False), \
             testtools.ExpectedException(trunk_exc.ParentPortInUse):
            validator = rules.TrunkPortValidator(port['port']['id'])
            validator.validate(self.context)

    def test_can_be_trunked_or_untrunked_returns_false(self):
        # need to trigger a driver registration
        fakes.FakeDriverCanTrunkBoundPort.create()
        self.trunk_plugin = trunk_plugin.TrunkPlugin()
        directory.add_plugin('trunk', self.trunk_plugin)
        with self.port() as port:
            core_plugin = directory.get_plugin()
            port['port']['binding:host_id'] = 'host'
            core_plugin.update_port(self.context, port['port']['id'], port)
            validator = rules.TrunkPortValidator(port['port']['id'])
            # port cannot be trunked because of binding mismatch
            self.assertFalse(
                validator.can_be_trunked_or_untrunked(self.context))

    def test_can_be_trunked_or_untrunked_returns_true(self):
        # need to trigger a driver registration
        fakes.FakeDriverCanTrunkBoundPort.create()
        self.trunk_plugin = trunk_plugin.TrunkPlugin()
        directory.add_plugin('trunk', self.trunk_plugin)
        with self.port() as port, \
                mock.patch.object(trunk_utils, "is_driver_compatible",
                                  return_value=True) as g:
            core_plugin = directory.get_plugin()
            port['port']['binding:host_id'] = 'host'
            core_plugin.update_port(self.context, port['port']['id'], port)
            validator = rules.TrunkPortValidator(port['port']['id'])
            self.assertTrue(
                validator.can_be_trunked_or_untrunked(self.context))
            self.assertTrue(g.call_count)

    def test_can_be_trunked_or_untrunked_unbound_port(self):
        with self.port() as port:
            validator = rules.TrunkPortValidator(port['port']['id'])
            self.assertTrue(
                validator.can_be_trunked_or_untrunked(self.context))

    def test_can_be_trunked_or_untrunked_raises_conflict(self):
        d1 = fakes.FakeDriver.create()
        d2 = fakes.FakeDriverWithAgent.create()
        self.trunk_plugin = trunk_plugin.TrunkPlugin()
        directory.add_plugin('trunk', self.trunk_plugin)
        self.trunk_plugin._drivers = [d1, d2]
        with self.port() as port, \
                mock.patch.object(trunk_utils, "is_driver_compatible",
                                  return_value=True):
            core_plugin = directory.get_plugin()
            port['port']['binding:host_id'] = 'host'
            core_plugin.update_port(self.context, port['port']['id'], port)
            validator = rules.TrunkPortValidator(port['port']['id'])
            self.assertRaises(
                trunk_exc.TrunkPluginDriverConflict,
                validator.can_be_trunked_or_untrunked, self.context)

    def test_check_not_in_use_pass(self):
        with self.port() as port:
            validator = rules.TrunkPortValidator(port['port']['id'])
            self.assertIsNone(validator.check_not_in_use(
                self.context))

    def test_check_not_in_use_raises(self):
        with self.port() as port:
            core_plugin = directory.get_plugin()
            port['port']['device_id'] = 'foo_device_id'
            core_plugin.update_port(self.context, port['port']['id'], port)
            validator = rules.TrunkPortValidator(port['port']['id'])
            self.assertRaises(n_exc.PortInUse,
                              validator.check_not_in_use, self.context)
