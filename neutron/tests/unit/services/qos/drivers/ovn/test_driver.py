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

from neutron.objects.qos import policy as qos_policy
from neutron.objects.qos import rule as qos_rule
from neutron.tests import base
from neutron_lib import constants
from oslo_utils import uuidutils

from neutron.common.ovn import utils
from neutron.services.qos.drivers.ovn import driver

context = 'context'


class TestOVNQosNotificationDriver(base.BaseTestCase):

    def setUp(self):
        super(TestOVNQosNotificationDriver, self).setUp()
        self.mech_driver = mock.Mock()
        self.mech_driver._ovn_client = mock.Mock()
        self.mech_driver._ovn_client._qos_driver = mock.Mock()
        self.driver = driver.OVNQosNotificationDriver.create(
            self.mech_driver)
        self.policy = "policy"

    def test_create_policy(self):
        self.driver.create_policy(context, self.policy)
        self.driver._driver._ovn_client._qos_driver.create_policy.\
            assert_not_called()

    def test_update_policy(self):
        self.driver.update_policy(context, self.policy)
        self.driver._driver._ovn_client._qos_driver.update_policy.\
            assert_called_once_with(context, self.policy)

    def test_delete_policy(self):
        self.driver.delete_policy(context, self.policy)
        self.driver._driver._ovn_client._qos_driver.delete_policy.\
            assert_not_called()


class TestOVNQosDriver(base.BaseTestCase):

    def setUp(self):
        super(TestOVNQosDriver, self).setUp()
        self.plugin = mock.Mock()
        self.ovn_client = mock.Mock()
        self.driver = driver.OVNQosDriver(self.ovn_client)
        self.driver._plugin_property = self.plugin
        self.port_id = uuidutils.generate_uuid()
        self.policy_id = uuidutils.generate_uuid()
        self.network_id = uuidutils.generate_uuid()
        self.network_policy_id = uuidutils.generate_uuid()
        self.policy = self._create_fake_policy()
        self.port = self._create_fake_port()
        self.bw_rule = self._create_bw_limit_rule()
        self.bw_expected = {'qos_max_rate': 1000, 'qos_burst': 100000,
                            'direction': constants.EGRESS_DIRECTION}
        self.dscp_rule = self._create_dscp_rule()
        self.dscp_expected = {'dscp_mark': 16,
                              'direction': constants.EGRESS_DIRECTION}

    def _create_bw_limit_rule(self):
        rule_obj = qos_rule.QosBandwidthLimitRule()
        rule_obj.id = uuidutils.generate_uuid()
        rule_obj.max_kbps = 1000
        rule_obj.max_burst_kbps = 100000
        rule_obj.obj_reset_changes()
        return rule_obj

    def _create_dscp_rule(self):
        rule_obj = qos_rule.QosDscpMarkingRule()
        rule_obj.id = uuidutils.generate_uuid()
        rule_obj.dscp_mark = 16
        rule_obj.obj_reset_changes()
        return rule_obj

    def _create_fake_policy(self):
        policy_dict = {'id': self.network_policy_id}
        policy_obj = qos_policy.QosPolicy(context, **policy_dict)
        policy_obj.obj_reset_changes()
        return policy_obj

    def _create_fake_port(self):
        return {'id': self.port_id,
                'qos_policy_id': self.policy_id,
                'network_id': self.network_id,
                'device_owner': 'compute:fake'}

    def _create_fake_network(self):
        return {'id': self.network_id,
                'qos_policy_id': self.network_policy_id}

    def test__is_network_device_port(self):
        self.assertFalse(utils.is_network_device_port(self.port))
        port = self._create_fake_port()
        port['device_owner'] = constants.DEVICE_OWNER_DHCP
        self.assertTrue(utils.is_network_device_port(port))
        port['device_owner'] = 'neutron:LOADBALANCERV2'
        self.assertTrue(utils.is_network_device_port(port))

    def _generate_port_options(self, policy_id, return_val, expected_result):
        with mock.patch.object(qos_rule, 'get_rules',
                               return_value=return_val) as get_rules:
            options = self.driver._generate_port_options(context, policy_id)
            if policy_id:
                get_rules.assert_called_once_with(qos_policy.QosPolicy,
                                                  context, policy_id)
            else:
                get_rules.assert_not_called()
            self.assertEqual(expected_result, options)

    def test__generate_port_options_no_policy_id(self):
        self._generate_port_options(None, [], {})

    def test__generate_port_options_no_rules(self):
        self._generate_port_options(self.policy_id, [], {})

    def test__generate_port_options_with_bw_rule(self):
        self._generate_port_options(self.policy_id, [self.bw_rule],
                                    self.bw_expected)

    def test__generate_port_options_with_dscp_rule(self):
        self._generate_port_options(self.policy_id, [self.dscp_rule],
                                    self.dscp_expected)

    def _get_qos_options(self, port, port_policy, network_policy):
        with mock.patch.object(qos_policy.QosPolicy, 'get_network_policy',
                               return_value=self.policy) as get_network_policy:
            with mock.patch.object(self.driver, '_generate_port_options',
                                   return_value={}) as generate_port_options:
                options = self.driver.get_qos_options(port)
                if network_policy:
                    get_network_policy.\
                        assert_called_once_with(context, self.network_id)
                    generate_port_options. \
                        assert_called_once_with(context,
                                                self.network_policy_id)
                elif port_policy:
                    get_network_policy.assert_not_called()
                    generate_port_options.\
                        assert_called_once_with(context, self.policy_id)
                else:
                    get_network_policy.assert_not_called()
                    generate_port_options.assert_not_called()
                self.assertEqual({}, options)

    def test_get_qos_options_no_qos(self):
        port = self._create_fake_port()
        port.pop('qos_policy_id')
        self._get_qos_options(port, False, False)

    def test_get_qos_options_network_port(self):
        port = self._create_fake_port()
        port['device_owner'] = constants.DEVICE_OWNER_DHCP
        self._get_qos_options(port, False, False)

    @mock.patch('neutron_lib.context.get_admin_context', return_value=context)
    def test_get_qos_options_port_policy(self, *mocks):
        self._get_qos_options(self.port, True, False)

    @mock.patch('neutron_lib.context.get_admin_context', return_value=context)
    def test_get_qos_options_network_policy(self, *mocks):
        port = self._create_fake_port()
        port['qos_policy_id'] = None
        self._get_qos_options(port, False, True)

    def _update_network_ports(self, port, called):
        with mock.patch.object(self.plugin, 'get_ports',
                               return_value=[port]) as get_ports:
            with mock.patch.object(self.ovn_client,
                                   'update_port') as update_port:
                self.driver._update_network_ports(
                    context, self.network_id, {})
                get_ports.assert_called_once_with(
                    context, filters={'network_id': [self.network_id]})
                if called:
                    update_port.assert_called()
                else:
                    update_port.assert_not_called()

    def test__update_network_ports_port_policy(self):
        self._update_network_ports(self.port, False)

    def test__update_network_ports_network_device(self):
        port = self._create_fake_port()
        port['device_owner'] = constants.DEVICE_OWNER_DHCP
        self._update_network_ports(port, False)

    def test__update_network_ports(self):
        port = self._create_fake_port()
        port['qos_policy_id'] = None
        self._update_network_ports(port, True)

    def _update_network(self, network, called):
        with mock.patch.object(self.driver, '_generate_port_options',
                               return_value={}) as generate_port_options:
            with mock.patch.object(self.driver, '_update_network_ports'
                                   ) as update_network_ports:
                self.driver.update_network(network)
                if called:
                    generate_port_options.assert_called_once_with(
                        context, self.network_policy_id)
                    update_network_ports.assert_called_once_with(
                        context, self.network_id, {})
                else:
                    generate_port_options.assert_not_called()
                    update_network_ports.assert_not_called()

    @mock.patch('neutron_lib.context.get_admin_context', return_value=context)
    def test_update_network_no_qos(self, *mocks):
        network = self._create_fake_network()
        network.pop('qos_policy_id')
        self._update_network(network, False)

    @mock.patch('neutron_lib.context.get_admin_context', return_value=context)
    def test_update_network_policy_change(self, *mocks):
        network = self._create_fake_network()
        self._update_network(network, True)

    def test_update_policy(self):
        with mock.patch.object(self.driver, '_generate_port_options',
                               return_value={}) as generate_port_options, \
            mock.patch.object(self.policy, 'get_bound_networks',
                              return_value=[self.network_id]
                              ) as get_bound_networks, \
            mock.patch.object(self.driver, '_update_network_ports'
                              ) as update_network_ports, \
            mock.patch.object(self.policy, 'get_bound_ports',
                              return_value=[self.port_id]
                              ) as get_bound_ports, \
            mock.patch.object(self.plugin, 'get_port',
                              return_value=self.port) as get_port, \
            mock.patch.object(self.ovn_client, 'update_port',
                              ) as update_port:

            self.driver.update_policy(context, self.policy)

            generate_port_options.assert_called_once_with(
                context, self.network_policy_id)
            get_bound_networks.assert_called_once_with()
            update_network_ports.assert_called_once_with(
                context, self.network_id, {})
            get_bound_ports.assert_called_once_with()
            get_port.assert_called_once_with(context, self.port_id)
            update_port.assert_called_once_with(self.port, qos_options={})
