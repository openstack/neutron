# Copyright 2015 OpenStack Foundation.
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
from oslo_config import cfg
from oslo_messaging import conffixture as messaging_conffixture

from neutron.common import rpc
from neutron.tests import base


CONF = cfg.CONF
CONF.import_opt('state_path', 'neutron.common.config')


class ServiceTestCase(base.DietTestCase):
    # the class cannot be based on BaseTestCase since it mocks rpc.Connection

    def setUp(self):
        super(ServiceTestCase, self).setUp()
        self.host = 'foo'
        self.topic = 'neutron-agent'

        self.target_mock = mock.patch('oslo_messaging.Target')
        self.target_mock.start()

        self.messaging_conf = messaging_conffixture.ConfFixture(CONF)
        self.messaging_conf.transport_driver = 'fake'
        self.messaging_conf.response_timeout = 0
        self.useFixture(self.messaging_conf)

        self.addCleanup(rpc.cleanup)
        rpc.init(CONF)

    def test_operations(self):
        with mock.patch('oslo_messaging.get_rpc_server') as get_rpc_server:
            rpc_server = get_rpc_server.return_value

            service = rpc.Service(self.host, self.topic)
            service.start()
            rpc_server.start.assert_called_once_with()

            service.stop()
            rpc_server.stop.assert_called_once_with()
            rpc_server.wait.assert_called_once_with()
