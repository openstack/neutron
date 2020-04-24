# Copyright (c) 2016 Red Hat
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

import contextlib
from unittest import mock

import testtools

from neutron.services.trunk.drivers.openvswitch.agent import trunk_manager
from neutron.tests import base


class TrunkManagerTestCase(base.BaseTestCase):
    """Tests are aimed to cover negative cases to make sure there is no typo in
    the logging.
    """
    def setUp(self):
        super(TrunkManagerTestCase, self).setUp()
        self.trunk_manager = trunk_manager.TrunkManager(mock.sentinel.br_int)
        mock.patch.object(trunk_manager, 'TrunkBridge').start()

    @contextlib.contextmanager
    def _resource_fails(self, resource, method_name):
        with mock.patch.object(resource, method_name,
                side_effect=RuntimeError):
            with testtools.ExpectedException(trunk_manager.TrunkManagerError):
                yield

    def test_create_trunk_plug_fails(self):
        with self._resource_fails(trunk_manager.TrunkParentPort, 'plug'):
            self.trunk_manager.create_trunk(None, None, None)

    def test_remove_trunk_unplug_fails(self):
        with self._resource_fails(trunk_manager.TrunkParentPort, 'unplug'):
            self.trunk_manager.remove_trunk(None, None)

    def test_add_sub_port_plug_fails(self):
        with self._resource_fails(trunk_manager.SubPort, 'plug'):
            self.trunk_manager.add_sub_port(None, None, None, None)

    def test_remove_sub_port_unplug_fails(self):
        with self._resource_fails(trunk_manager.SubPort, 'unplug'):
            self.trunk_manager.remove_sub_port(None, None)
