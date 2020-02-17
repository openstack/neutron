# Copyright (c) 2016 IBM Corp.
#
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

from neutron_lib.api.definitions import provider_net as provider
from neutron_lib import exceptions as exc
from neutron_lib.exceptions import placement as place_exc
from neutron_lib.plugins.ml2 import api
from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_utils import uuidutils

from neutron.db import segments_db
from neutron.plugins.ml2.common import exceptions as ml2_exc
from neutron.plugins.ml2 import managers
from neutron.tests import base
from neutron.tests.unit.plugins.ml2._test_mech_agent import FakePortContext
from neutron.tests.unit.plugins.ml2.drivers import mech_fake_agent
from neutron.tests.unit.plugins.ml2.drivers import mechanism_test


class TestManagers(base.BaseTestCase):
    def setUp(self):
        super(TestManagers, self).setUp()
        self.segment_id = "11111111-2222-3333-4444-555555555555"
        self.segments_to_bind = [{api.ID: self.segment_id,
                                  'network_type': 'vlan',
                                  'physical_network': 'public',
                                  api.SEGMENTATION_ID: 49}]
        original_port = {'fixed_ips': [{'subnet_id': mock.ANY,
                                        'ip_address': mock.ANY}]}
        self.context = FakePortContext(None, None, self.segments_to_bind,
                                       original=original_port)
        self.context._binding = mock.Mock()
        self.context._binding_levels = []
        self.context._new_bound_segment = self.segment_id
        self.context._next_segments_to_bind = None

    def test__check_driver_to_bind(self):
        cfg.CONF.set_override('mechanism_drivers', ['fake_agent'],
                              group='ml2')
        manager = managers.MechanismManager()

        with mock.patch.object(mech_fake_agent.FakeAgentMechanismDriver,
                               'bind_port') as bind_port:
            manager._bind_port_level(self.context, 0, self.segments_to_bind)
        self.assertEqual(1, bind_port.call_count)

    def test__check_driver_to_bind2(self):
        cfg.CONF.set_override('mechanism_drivers', ['fake_agent'],
                              group='ml2')
        manager = managers.MechanismManager()
        self.context._binding_levels = [mock.Mock(port_id="port_id",
                                             level=0,
                                             driver='fake_agent',
                                             segment_id=self.segment_id)]

        with mock.patch.object(mech_fake_agent.FakeAgentMechanismDriver,
                               'bind_port') as bind_port:
            manager._bind_port_level(self.context, 0, self.segments_to_bind)
        self.assertEqual(0, bind_port.call_count)

    def _check_drivers_connectivity(self, agents):
        cfg.CONF.set_override('mechanism_drivers', agents, group='ml2')
        manager = managers.MechanismManager()
        return (manager.ordered_mech_drivers,
                manager._check_drivers_connectivity(
                    manager.ordered_mech_drivers, self.context))

    def test__check_drivers_connectivity(self):
        self.assertEqual(*self._check_drivers_connectivity(['fake_agent']))

    def test__check_drivers_connectivity_ip_less_port(self):
        self.context._original['fixed_ips'] = []
        self.assertEqual(*self._check_drivers_connectivity(['fake_agent']))

    def test__check_drivers_connectivity_ip_less_port_l3_only_driver(self):
        self.context._original['fixed_ips'] = []
        self.assertEqual(
            [],
            self._check_drivers_connectivity(['fake_agent_l3'])[1])

    def test__infer_driver_from_allocation_positive(self):
        cfg.CONF.set_override(
            'mechanism_drivers', ['fake_agent'], group='ml2')
        manager = managers.MechanismManager()
        with mock.patch.object(mech_fake_agent.FakeAgentMechanismDriver,
                               'responsible_for_ports_allocation',
                               return_value=True):
            responsible_driver = manager._infer_driver_from_allocation(
                FakePortContext(
                    None,
                    None,
                    self.segments_to_bind,
                    profile={'allocation': 'fake_resource_provider'}))
            self.assertEqual(responsible_driver.name, 'fake_agent')

    def test__infer_driver_from_allocation_negative(self):
        cfg.CONF.set_override(
            'mechanism_drivers', ['fake_agent'], group='ml2')
        manager = managers.MechanismManager()
        with mock.patch.object(mech_fake_agent.FakeAgentMechanismDriver,
                               'responsible_for_ports_allocation',
                               return_value=False):
            self.assertRaises(
                place_exc.UnknownResourceProvider,
                manager._infer_driver_from_allocation,
                FakePortContext(
                    None,
                    None,
                    self.segments_to_bind,
                    profile={'allocation': 'fake_resource_provider'})
            )

    def test__infer_driver_from_allocation_ambiguous(self):
        cfg.CONF.set_override(
            'mechanism_drivers',
            ['fake_agent', 'another_fake_agent'],
            group='ml2')
        manager = managers.MechanismManager()
        with mock.patch.object(mech_fake_agent.FakeAgentMechanismDriver,
                               'responsible_for_ports_allocation',
                               return_value=True), \
            mock.patch.object(mech_fake_agent.AnotherFakeAgentMechanismDriver,
                              'responsible_for_ports_allocation',
                              return_value=True):
            self.assertRaises(
                place_exc.AmbiguousResponsibilityForResourceProvider,
                manager._infer_driver_from_allocation,
                FakePortContext(
                    None,
                    None,
                    self.segments_to_bind,
                    profile={'allocation': 'fake_resource_provider'})
            )

    @mock.patch.object(managers.LOG, 'critical')
    @mock.patch.object(managers.MechanismManager, '_driver_not_loaded')
    def test__driver_not_found(self, mock_not_loaded, mock_log):
        cfg.CONF.set_override('mechanism_drivers', ['invalidmech'],
                              group='ml2')
        self.assertRaises(SystemExit, managers.MechanismManager)
        mock_not_loaded.assert_not_called()
        mock_log.assert_called_once_with("The following mechanism drivers "
                                         "were not found: %s"
                                         % set(['invalidmech']))

    @mock.patch.object(managers.LOG, 'critical')
    @mock.patch.object(managers.MechanismManager, '_driver_not_found')
    def test__driver_not_loaded(self, mock_not_found, mock_log):
        cfg.CONF.set_override('mechanism_drivers', ['faulty_agent'],
                              group='ml2')
        self.assertRaises(SystemExit, managers.MechanismManager)
        mock_log.assert_called_once_with(u"The '%(entrypoint)s' entrypoint "
                                         "could not be loaded for the "
                                         "following reason: '%(reason)s'.",
                                         {'entrypoint': mock.ANY,
                                          'reason': mock.ANY})


class TestMechManager(base.BaseTestCase):
    def setUp(self):
        cfg.CONF.set_override('mechanism_drivers', ['test'], group='ml2')
        super(TestMechManager, self).setUp()
        self._manager = managers.MechanismManager()

    def _check_precommit(self, resource, operation):
        meth_name = "%s_%s_precommit" % (operation, resource)
        method = getattr(self._manager, meth_name)
        fake_ctxt = mock.Mock()
        fake_ctxt.current = {}

        with mock.patch.object(mechanism_test.TestMechanismDriver, meth_name,
                               side_effect=db_exc.DBDeadlock()):
            self.assertRaises(db_exc.DBDeadlock, method, fake_ctxt)

        with mock.patch.object(mechanism_test.TestMechanismDriver, meth_name,
                               side_effect=RuntimeError()):
            self.assertRaises(ml2_exc.MechanismDriverError, method, fake_ctxt)

    def _check_resource(self, resource):
        self._check_precommit(resource, 'create')
        self._check_precommit(resource, 'update')
        self._check_precommit(resource, 'delete')

    def test_network_precommit(self):
        self._check_resource('network')

    def test_subnet_precommit(self):
        self._check_resource('subnet')

    def test_port_precommit(self):
        self._check_resource('port')


class TypeManagerTestCase(base.BaseTestCase):

    def setUp(self):
        super(TypeManagerTestCase, self).setUp()
        self.type_manager = managers.TypeManager()
        self.ctx = mock.Mock()
        self.network = {'id': uuidutils.generate_uuid(),
                        'project_id': uuidutils.generate_uuid()}

    def test_update_network_segment_no_vlan_no_segmentation_id(self):
        net_data = {}
        segment = {api.NETWORK_TYPE: 'vlan'}
        self.assertRaises(
            exc.InvalidInput, self.type_manager.update_network_segment,
            self.ctx, self.network, net_data, segment)

        net_data = {provider.SEGMENTATION_ID: 1000}
        segment = {api.NETWORK_TYPE: 'no_vlan'}
        self.assertRaises(
            exc.InvalidInput, self.type_manager.update_network_segment,
            self.ctx, self.network, net_data, segment)

    def test_update_network_segment(self):
        segmentation_id = 1000
        net_data = {provider.SEGMENTATION_ID: segmentation_id}
        segment = {'id': uuidutils.generate_uuid(),
                   api.NETWORK_TYPE: 'vlan',
                   api.PHYSICAL_NETWORK: 'default_network'}
        new_segment = {api.NETWORK_TYPE: 'vlan',
                       api.PHYSICAL_NETWORK: 'default_network',
                       api.SEGMENTATION_ID: segmentation_id}
        with mock.patch.object(self.type_manager,
                               'validate_provider_segment') as mock_validate, \
                mock.patch.object(self.type_manager,
                                  'reserve_provider_segment') as mock_reserve,\
                mock.patch.object(self.type_manager,
                                  'release_network_segment') as mock_release, \
                mock.patch.object(segments_db, 'update_network_segment') as \
                mock_update_network_segment:
            self.type_manager.update_network_segment(self.ctx, self.network,
                                                     net_data, segment)
            mock_validate.assert_called_once_with(new_segment)
            mock_reserve.assert_called_once_with(
                self.ctx, new_segment,
                filters={'project_id': self.network['project_id']})
            mock_update_network_segment.assert_called_once_with(
                self.ctx, segment['id'], segmentation_id)
            mock_release.assert_called_once_with(self.ctx, segment)
