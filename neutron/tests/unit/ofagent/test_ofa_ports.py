# Copyright (C) 2014 VA Linux Systems Japan K.K.
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
#
# @author: YAMAMOTO Takashi, VA Linux Systems Japan K.K.


import mock

from neutron.plugins.ofagent.agent import ports
from neutron.tests import base


class TestOFAgentPorts(base.BaseTestCase):
    def test_port(self):
        p1 = ports.Port(port_name='foo', ofport=999)
        ryu_ofp_port = mock.Mock(port_no=999)
        ryu_ofp_port.name = 'foo'
        p2 = ports.Port.from_ofp_port(ofp_port=ryu_ofp_port)
        self.assertEqual(p1.port_name, p2.port_name)
        self.assertEqual(p1.ofport, p2.ofport)
