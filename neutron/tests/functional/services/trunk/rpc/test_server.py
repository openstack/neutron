# (c) Copyright 2016 Hewlett Packard Enterprise Development LP
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import mock

from neutron_lib.services.trunk import constants

from neutron.services.trunk import plugin as trunk_plugin
from neutron.tests.common import helpers
from neutron.tests.unit.plugins.ml2 import base as ml2_test_base


class TrunkSkeletonTestCase(ml2_test_base.ML2TestFramework):

    def setUp(self):
        super(TrunkSkeletonTestCase, self).setUp()
        self.trunk_plugin = trunk_plugin.TrunkPlugin()

    def test__handle_port_binding_set_device_owner(self):
        helpers.register_ovs_agent(host=helpers.HOST)
        with self.port() as subport:
            port = (
                self.trunk_plugin.
                _rpc_backend._skeleton._handle_port_binding(
                    self.context, subport['port']['id'],
                    mock.ANY, helpers.HOST))
            self.assertEqual(
                constants.TRUNK_SUBPORT_OWNER, port['device_owner'])
