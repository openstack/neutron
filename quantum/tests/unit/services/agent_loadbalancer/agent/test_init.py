# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013 New Dream Network, LLC (DreamHost)
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
#
# @author: Mark McClain, DreamHost

import contextlib
import mock
from oslo.config import cfg

from quantum.plugins.services.agent_loadbalancer import agent
from quantum.tests import base


class TestLbaasService(base.BaseTestCase):
    def setUp(self):
        super(TestLbaasService, self).setUp()
        self.addCleanup(cfg.CONF.reset)

        cfg.CONF.register_opts(agent.OPTS)

    def test_start(self):
        with mock.patch.object(
            agent.rpc_service.Service, 'start'
        ) as mock_start:

            mgr = mock.Mock()
            agent_service = agent.LbaasAgentService('host', 'topic', mgr)
            agent_service.start()

            self.assertTrue(mock_start.called)

    def test_main(self):
        logging_str = 'quantum.agent.common.config.setup_logging'
        with contextlib.nested(
            mock.patch(logging_str),
            mock.patch.object(agent.service, 'launch'),
            mock.patch.object(agent, 'eventlet'),
            mock.patch('sys.argv'),
            mock.patch.object(agent.manager, 'LbaasAgentManager')
        ) as (mock_logging, mock_launch, mock_eventlet, sys_argv, mgr_cls):
            agent.main()

            self.assertTrue(mock_eventlet.monkey_patch.called)
            mock_launch.assert_called_once_with(mock.ANY)
