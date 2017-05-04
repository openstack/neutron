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

from neutron_lib.plugins.ml2 import api
from oslo_db import exception as db_exc

from neutron.plugins.ml2.common import exceptions as ml2_exc
from neutron.plugins.ml2 import config
from neutron.plugins.ml2 import managers
from neutron.tests import base
from neutron.tests.unit.plugins.ml2.drivers import mechanism_test


class TestManagers(base.BaseTestCase):

    def test__check_driver_to_bind(self):
        manager = managers.MechanismManager()
        bindinglevel = mock.Mock()
        bindinglevel.driver = 'fake_driver'
        bindinglevel.segment_id = 'fake_seg_id'
        binding_levels = [bindinglevel]
        segments_to_bind = [{api.SEGMENTATION_ID: 'fake_seg_id'}]
        self.assertFalse(manager._check_driver_to_bind(
            'fake_driver', segments_to_bind, binding_levels))

        bindinglevel.segment_id = 'fake_seg_id1'
        self.assertTrue(manager._check_driver_to_bind(
            'fake_driver', segments_to_bind, binding_levels))

    @mock.patch.object(managers.LOG, 'critical')
    @mock.patch.object(managers.MechanismManager, '_driver_not_loaded')
    def test__driver_not_found(self, mock_not_loaded, mock_log):
        config.cfg.CONF.set_override('mechanism_drivers', ['invalidmech'],
                                     group='ml2')
        self.assertRaises(SystemExit, managers.MechanismManager)
        mock_not_loaded.assert_not_called()
        mock_log.assert_called_once_with("The following mechanism drivers "
                                         "were not found: %s"
                                         % set(['invalidmech']))

    @mock.patch.object(managers.LOG, 'critical')
    @mock.patch.object(managers.MechanismManager, '_driver_not_found')
    def test__driver_not_loaded(self, mock_not_found, mock_log):
        config.cfg.CONF.set_override('mechanism_drivers', ['faulty_agent'],
                                     group='ml2')
        self.assertRaises(SystemExit, managers.MechanismManager)
        mock_log.assert_called_once_with(u"The '%(entrypoint)s' entrypoint "
                                         "could not be loaded for the "
                                         "following reason: '%(reason)s'.",
                                         {'entrypoint': mock.ANY,
                                          'reason': mock.ANY})


class TestMechManager(base.BaseTestCase):
    def setUp(self):
        config.cfg.CONF.set_override('mechanism_drivers', ['test'],
                                     group='ml2')
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
