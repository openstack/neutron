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

from neutron.cmd.eventlet import server
from neutron.tests import base


@mock.patch('neutron.server.wsgi_eventlet.eventlet_wsgi_server')
@mock.patch('neutron.server.wsgi_pecan.pecan_wsgi_server')
class TestNeutronServer(base.BaseTestCase):

    def test_legacy_server(self, pecan_mock, legacy_mock):
        cfg.CONF.set_override('web_framework', 'legacy')
        server._main_neutron_server()
        pecan_mock.assert_not_called()
        legacy_mock.assert_called_with()

    def test_pecan_server(self, pecan_mock, legacy_mock):
        cfg.CONF.set_override('web_framework', 'pecan')
        server._main_neutron_server()
        pecan_mock.assert_called_with()
        legacy_mock.assert_not_called()
