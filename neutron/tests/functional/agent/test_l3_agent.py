# Copyright (c) 2014 Red Hat, Inc.
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

from neutron.common import topics
from neutron.tests.functional.agent.l3 import framework
from neutron.tests.functional import test_service


class TestL3AgentRestart(test_service.TestServiceRestart,
                         framework.L3AgentTestFramework):

    def _start_l3_agent(self, workers=1):
        with mock.patch("neutron.service.Service.start") as start_method:
            start_method.side_effect = self._fake_start
            self._start_service(
                host='agent1', binary='neutron-l3-agent',
                topic=topics.L3_AGENT,
                manager='neutron.agent.l3.agent.L3NATAgentWithStateReport',
                workers=workers, conf=self.conf)

    def test_restart_l3_agent_on_sighup(self):
        self._test_restart_service_on_sighup(service=self._start_l3_agent,
                                             workers=1)
