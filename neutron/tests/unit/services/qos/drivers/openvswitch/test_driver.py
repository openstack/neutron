# Copyright 2020 Ericsson Software Technology
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from unittest import mock

from neutron_lib.services.qos import constants as qos_consts

from neutron.objects import network as network_object
from neutron.services.qos.drivers.openvswitch import driver
from neutron.tests.unit.services.qos import base


class TestOVSDriver(base.BaseQosTestCase):

    def setUp(self):
        super(TestOVSDriver, self).setUp()
        self.driver = driver.OVSDriver.create()

    def test_validate_min_bw_rule_vs_physnet_non_physnet(self):
        scenarios = [
            ({'physical_network': 'fake physnet'}, self.assertTrue),
            ({}, self.assertFalse),
        ]
        for segment_kwargs, test_method in scenarios:
            segment = network_object.NetworkSegment(**segment_kwargs)
            net = network_object.Network(mock.Mock(), segments=[segment])
            rule = mock.Mock()
            rule.rule_type = qos_consts.RULE_TYPE_MINIMUM_BANDWIDTH
            port = mock.Mock()
            with mock.patch(
                    'neutron.objects.network.Network.get_object',
                    return_value=net):
                test_method(self.driver.validate_rule_for_port(
                    mock.Mock(), rule, port))
                test_method(self.driver.validate_rule_for_network(
                    mock.Mock(), rule, network_id=mock.Mock()))
