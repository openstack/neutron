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

import os
import signal
import threading
import time
import unittest
from unittest import mock

from oslo_utils import importutils


MODULE = ('neutron.plugins.ml2.drivers.openvswitch.agent.'
          'openflow.native.ovs_oskenapp')


class TestSignalHandling(unittest.TestCase):

    def setUp(self):
        super().setUp()

        os.environ['OSKEN_HUB_TYPE'] = 'native'
        self.ovs_oskenapp = importutils.import_module(MODULE)

    @mock.patch('neutron.plugins.ml2.drivers.openvswitch.agent.openflow.'
                'native.ovs_oskenapp.ovs_agent.main')
    def test_signal_execution_in_thread(self, mock_ovs_agent_main):
        # TODO(ralonsoh): refactor this test to make it compatible after the
        # eventlet removal.
        self.skipTest('This test is skipped after the eventlet removal and '
                      'needs to be refactored')
        # The event is used to validate the handler stop_running() has
        # been called and to synchronize the test
        stop_event = threading.Event()

        def mock_ovs_agent_main_impl(bridge_classes, register_signal):
            running = True

            def stop_running():
                nonlocal running

                running = False
                stop_event.set()

            register_signal(signal.SIGTERM, stop_running)

            while running:
                # Simulate processing by agent.
                time.sleep(0.1)

        mock_ovs_agent_main.side_effect = mock_ovs_agent_main_impl

        app = self.ovs_oskenapp.OVSNeutronAgentOSKenApp()

        self.addCleanup(app.stop)
        app.start()

        # Fire SIGTERM
        os.kill(os.getpid(), signal.SIGTERM)

        stop_event.wait(timeout=2)

        mock_ovs_agent_main.assert_called_once()
