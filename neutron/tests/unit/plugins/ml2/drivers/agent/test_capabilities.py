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

import mock
from neutron_lib.callbacks import events
from neutron_lib import fixture

from neutron.plugins.ml2.drivers.agent import capabilities
from neutron.tests import base
from neutron.tests import tools


class CapabilitiesTest(base.BaseTestCase):

    def setUp(self):
        super(CapabilitiesTest, self).setUp()
        self._mgr = mock.Mock()
        self.useFixture(fixture.CallbackRegistryFixture(
            callback_manager=self._mgr))

    def test_notify_init_event(self):
        mock_agent_type = mock.Mock()
        mock_agent = mock.Mock()
        capabilities.notify_init_event(mock_agent_type, mock_agent)
        self._mgr.publish.assert_called_with(mock_agent_type,
                                            events.AFTER_INIT,
                                            mock_agent,
                                            payload=None)

    def test_register(self):
        mock_callback = mock.Mock()
        mock_agent_type = mock.Mock()
        capabilities.register(mock_callback, mock_agent_type)
        args = tools.get_subscribe_args(
            mock_callback, mock_agent_type, events.AFTER_INIT)
        self._mgr.subscribe.assert_called_with(*args)
