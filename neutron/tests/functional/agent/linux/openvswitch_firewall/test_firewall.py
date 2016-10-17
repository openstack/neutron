# Copyright 2016, Red Hat, Inc.
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

import testtools

from neutron.agent.linux.openvswitch_firewall import exceptions
from neutron.agent.linux.openvswitch_firewall import firewall
from neutron.tests.common import net_helpers
from neutron.tests.functional import base


class TestGetTagFromOtherConfig(base.BaseSudoTestCase):
    def setUp(self):
        super(TestGetTagFromOtherConfig, self).setUp()
        self.bridge = self.useFixture(net_helpers.OVSBridgeFixture()).bridge

    def set_port_tag(self, port_name, tag):
        self.bridge.set_db_attribute(
            'Port', port_name, 'other_config', {'tag': str(tag)})

    def test_correct_tag_is_returned(self):
        port_number = 42
        port = self.useFixture(net_helpers.OVSPortFixture(self.bridge)).port
        self.set_port_tag(port.name, port_number)
        observed = firewall.get_tag_from_other_config(self.bridge, port.name)
        self.assertEqual(port_number, observed)

    def test_not_existing_name_raises_exception(self):
        with testtools.ExpectedException(exceptions.OVSFWTagNotFound):
            firewall.get_tag_from_other_config(self.bridge, 'foo')

    def test_bad_tag_value_raises_exception(self):
        port = self.useFixture(net_helpers.OVSPortFixture(self.bridge)).port
        self.set_port_tag(port.name, 'foo')
        with testtools.ExpectedException(exceptions.OVSFWTagNotFound):
            firewall.get_tag_from_other_config(self.bridge, port.name)

    def test_no_value_set_for_other_config_raises_exception(self):
        port = self.useFixture(net_helpers.OVSPortFixture(self.bridge)).port
        with testtools.ExpectedException(exceptions.OVSFWTagNotFound):
            firewall.get_tag_from_other_config(self.bridge, port.name)
