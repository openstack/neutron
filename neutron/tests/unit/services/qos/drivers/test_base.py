# Copyright 2017 OVH SAS
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

from neutron_lib.api.definitions import portbindings
from neutron_lib import context
from oslo_utils import uuidutils

from neutron.common import constants
from neutron.objects.qos import rule as rule_object
from neutron.services.qos.drivers import base as qos_base_driver
from neutron.services.qos import qos_consts
from neutron.tests import base


SUPPORTED_RULES = {
    qos_consts.RULE_TYPE_MINIMUM_BANDWIDTH: {
        "min_kbps": {'type:values': None},
        'direction': {'type:values': [constants.EGRESS_DIRECTION]}
    }
}


class FakeDriver(qos_base_driver.DriverBase):

    @staticmethod
    def create():
        return FakeDriver(
            name='fake_driver',
            vif_types=[portbindings.VIF_TYPE_OVS],
            vnic_types=[portbindings.VNIC_NORMAL],
            supported_rules=SUPPORTED_RULES,
            requires_rpc_notifications=False)


class TestDriverBase(base.BaseTestCase):

    def setUp(self):
        super(TestDriverBase, self).setUp()
        self.driver = FakeDriver.create()
        self.rule_data = {
            'minimum_bandwidth_rule': {
                'id': uuidutils.generate_uuid(),
                'min_kbps': 100,
                'direction': constants.EGRESS_DIRECTION
            },
            'dscp_marking_rule': {
                'id': uuidutils.generate_uuid(),
                'dscp_mark': 16
            }
        }
        ctxt = context.Context('fake_user', 'fake_tenant')
        self.minimum_bandwidth_rule = rule_object.QosMinimumBandwidthRule(
            ctxt, **self.rule_data['minimum_bandwidth_rule'])
        self.dscp_rule = rule_object.QosDscpMarkingRule(
            ctxt, **self.rule_data['dscp_marking_rule'])

    def test_is_vif_type_compatible(self):
        self.assertFalse(
            self.driver.is_vif_type_compatible(portbindings.VIF_TYPE_OTHER))
        self.assertTrue(
            self.driver.is_vif_type_compatible(portbindings.VIF_TYPE_OVS))

    def test_is_vnic_compatible(self):
        self.assertFalse(
            self.driver.is_vnic_compatible(portbindings.VNIC_BAREMETAL))
        self.assertTrue(
            self.driver.is_vnic_compatible(portbindings.VNIC_NORMAL))

    def test_is_rule_supported(self):
        # Rule which is in SUPPORTED_RULES should be supported
        self.assertTrue(
            self.driver.is_rule_supported(self.minimum_bandwidth_rule))
        # Rule which is not in SUPPORTED_RULES should not be supported
        self.assertFalse(self.driver.is_rule_supported(self.dscp_rule))
        # Rule which is in SUPPORTED_RULES but got not supported parameter
        # should not be supported
        self.minimum_bandwidth_rule.direction = constants.INGRESS_DIRECTION
        self.assertFalse(
            self.driver.is_rule_supported(self.minimum_bandwidth_rule))
