# Copyright 2015 Mellanox Technologies, Ltd
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

import mock
from oslo_utils import uuidutils

from neutron import context
from neutron.objects.qos import policy
from neutron.objects.qos import rule
from neutron.plugins.ml2.drivers.mech_sriov.agent.common import exceptions
from neutron.plugins.ml2.drivers.mech_sriov.agent.extension_drivers import (
    qos_driver)
from neutron.services.qos import qos_consts
from neutron.tests import base


class QosSRIOVAgentDriverTestCase(base.BaseTestCase):

    ASSIGNED_MAC = '00:00:00:00:00:66'
    PCI_SLOT = '0000:06:00.1'

    def setUp(self):
        super(QosSRIOVAgentDriverTestCase, self).setUp()
        self.context = context.get_admin_context()
        self.qos_driver = qos_driver.QosSRIOVAgentDriver()
        self.qos_driver.initialize()
        self.qos_driver.eswitch_mgr = mock.Mock()
        self.qos_driver.eswitch_mgr.set_device_max_rate = mock.Mock()
        self.qos_driver.eswitch_mgr.clear_max_rate = mock.Mock()
        self.max_rate_mock = self.qos_driver.eswitch_mgr.set_device_max_rate
        self.clear_max_rate_mock = self.qos_driver.eswitch_mgr.clear_max_rate
        self.rule = self._create_bw_limit_rule_obj()
        self.qos_policy = self._create_qos_policy_obj([self.rule])
        self.port = self._create_fake_port(self.qos_policy.id)

    def _create_bw_limit_rule_obj(self):
        rule_obj = rule.QosBandwidthLimitRule()
        rule_obj.id = uuidutils.generate_uuid()
        rule_obj.max_kbps = 2
        rule_obj.max_burst_kbps = 200
        rule_obj.obj_reset_changes()
        return rule_obj

    def _create_qos_policy_obj(self, rules):
        policy_dict = {'id': uuidutils.generate_uuid(),
                'tenant_id': uuidutils.generate_uuid(),
                'name': 'test',
                'description': 'test',
                'shared': False,
                'rules': rules}
        policy_obj = policy.QosPolicy(self.context, **policy_dict)
        policy_obj.obj_reset_changes()
        for policy_rule in policy_obj.rules:
            policy_rule.qos_policy_id = policy_obj.id
            policy_rule.obj_reset_changes()

        return policy_obj

    def _create_fake_port(self, qos_policy_id):
        return {'port_id': uuidutils.generate_uuid(),
                'profile': {'pci_slot': self.PCI_SLOT},
                'device': self.ASSIGNED_MAC,
                qos_consts.QOS_POLICY_ID: qos_policy_id,
                'device_owner': uuidutils.generate_uuid()}

    def test_create_rule(self):
        self.qos_driver.create(self.port, self.qos_policy)
        self.max_rate_mock.assert_called_once_with(
            self.ASSIGNED_MAC, self.PCI_SLOT, self.rule.max_kbps)

    def test_update_rule(self):
        self.qos_driver.update(self.port, self.qos_policy)
        self.max_rate_mock.assert_called_once_with(
            self.ASSIGNED_MAC, self.PCI_SLOT, self.rule.max_kbps)

    def test_delete_rules_on_assigned_vf(self):
        self.qos_driver.delete(self.port, self.qos_policy)
        self.max_rate_mock.assert_called_once_with(
            self.ASSIGNED_MAC, self.PCI_SLOT, 0)

    def test_delete_rules_on_released_vf(self):
        del self.port['device_owner']
        self.qos_driver.delete(self.port, self.qos_policy)
        self.clear_max_rate_mock.assert_called_once_with(self.PCI_SLOT)

    def test__set_vf_max_rate_captures_sriov_failure(self):
        self.max_rate_mock.side_effect = exceptions.SriovNicError()
        self.qos_driver._set_vf_max_rate(self.ASSIGNED_MAC, self.PCI_SLOT)

    def test__set_vf_max_rate_unknown_device(self):
        with mock.patch.object(self.qos_driver.eswitch_mgr, 'device_exists',
                               return_value=False):
            self.qos_driver._set_vf_max_rate(self.ASSIGNED_MAC, self.PCI_SLOT)
            self.assertFalse(self.max_rate_mock.called)
