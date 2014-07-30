# Copyright (c) 2013 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# @author: Sukhdev Kapur, Arista Networks, Inc.
#


import pdb
import mock
from oslo.config import cfg

import neutron.db.api as ndb
from neutron.plugins.ml2.drivers.arista import arista_l3_driver as arista
from neutron.tests import base


def setup_arista_config(value=''):
    cfg.CONF.set_override('primary_l3_host', value, "arista-pri")
    cfg.CONF.set_override('primary_l3_username', value, "arista-pri")


def setup_valid_config():
    # Config is not valid if value is not set
    setup_arista_config('value')


class AristaL3DriverTestCases(base.BaseTestCase):
    """Test cases to test the RPC between Arista Driver and EOS.

    Tests all methods used to send commands between Arista Driver and EOS
    """

    pdb.set_trace()

    def setUp(self):
        super(AristaL3DriverTestCases, self).setUp()
        pdb.set_trace()
        setup_valid_config()
        self.drv = arista.AristaL3Driver()
        self.drv._servers = []
        self.drv._servers.append(mock.MagicMock())

    def test_no_exception_on_correct_configuration(self):
        self.assertIsNotNone(self.drv)

    def test_create_router_on_eos(self):
        router_name = 'test-router-1'
        route_domain = '123:123'

        self.drv.create_router_on_eos(router_name, router_domain,
                                        self.drv._servers[0])
        cmds = []

        self.drv._servers[0].runCmds.assert_called_once_with(version=1, cmds=cmds)

