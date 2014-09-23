# Copyright (C) 2014 VA Linux Systems Japan K.K.
# Copyright (C) 2014 YAMAMOTO Takashi <yamamoto at valinux co jp>
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

from neutron.common import constants as n_const
from neutron.plugins.ofagent.agent import ports
from neutron.tests import base


class TestOFAgentPorts(base.BaseTestCase):
    def test_port(self):
        name = 'foo03b9a237-0b'
        p1 = ports.Port(port_name=name, ofport=999)
        ryu_ofp_port = mock.Mock(port_no=999)
        ryu_ofp_port.name = name
        p2 = ports.Port.from_ofp_port(ofp_port=ryu_ofp_port)
        self.assertEqual(p1.port_name, p2.port_name)
        self.assertEqual(p1.ofport, p2.ofport)
        self.assertFalse(p1.is_neutron_port())
        self.assertFalse(p2.is_neutron_port())

    def test_neutron_port(self):
        for pref in ['qvo', 'qr-', 'qg-', n_const.TAP_DEVICE_PREFIX]:
            name = pref + '03b9a237-0b'
            p1 = ports.Port(port_name=name, ofport=999)
            ryu_ofp_port = mock.Mock(port_no=999)
            ryu_ofp_port.name = name
            p2 = ports.Port.from_ofp_port(ofp_port=ryu_ofp_port)
            self.assertEqual(p1.port_name, p2.port_name)
            self.assertEqual(p1.ofport, p2.ofport)
            self.assertTrue(p1.is_neutron_port())
            self.assertTrue(p2.is_neutron_port())
            self.assertTrue('tap03b9a237-0b', p1.normalized_port_name())
            self.assertTrue('tap03b9a237-0b', p2.normalized_port_name())

    def test_get_normalized_port_name(self):
        self.assertEqual('tap03b9a237-0b',
                         ports.get_normalized_port_name(
                             '03b9a237-0b1b-11e4-b537-08606e7f74e7'))
