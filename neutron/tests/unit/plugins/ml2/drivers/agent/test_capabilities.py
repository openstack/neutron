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

from neutron.callbacks import events
from neutron.plugins.ml2.drivers.agent import capabilities
from neutron.tests import base


class CapabilitiesTest(base.BaseTestCase):

    @mock.patch("neutron.callbacks.manager.CallbacksManager.notify")
    def test_notify_init_event(self, mocked_manager):
        mock_agent_type = mock.Mock()
        mock_agent = mock.Mock()
        capabilities.notify_init_event(mock_agent_type, mock_agent)
        mocked_manager.assert_called_with(mock_agent_type,
                                          events.AFTER_INIT,
                                          mock_agent,
                                          agent=mock_agent)

    @mock.patch("neutron.callbacks.manager.CallbacksManager.subscribe")
    def test_register(self, mocked_subscribe):
        mock_callback = mock.Mock()
        mock_agent_type = mock.Mock()
        capabilities.register(mock_callback, mock_agent_type)
        mocked_subscribe.assert_called_with(mock_callback,
                                            mock_agent_type,
                                            events.AFTER_INIT)
