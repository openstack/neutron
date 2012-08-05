# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2012, Nachi Ueno, NTT MCL, Inc.
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
from mock import call

from quantum.api.v2 import attributes
from quantum.extensions import securitygroup as ext_sg
from quantum.plugins.linuxbridge.db import l2network_db_v2 as lb_db
from quantum.tests.unit import test_extension_security_group as test_sg

PLUGIN_NAME = ('quantum.plugins.linuxbridge.'
               'lb_quantum_plugin.LinuxBridgePluginV2')
AGENT_NAME = ('quantum.plugins.linuxbridge.'
              'agent.linuxbridg_quantum_agent.LinuxBridgeQuantumAgentRPC')
NOTIFIER = ('quantum.plugins.linuxbridge.'
            'lb_quantum_plugin.AgentNotifierApi')


class LinuxBridgeSecurityGroupsTestCase(test_sg.SecurityGroupDBTestCase):
    _plugin_name = PLUGIN_NAME

    def setUp(self, plugin=None):
        self.addCleanup(mock.patch.stopall)
        notifier_p = mock.patch(NOTIFIER)
        notifier_cls = notifier_p.start()
        self.notifier = mock.Mock()
        notifier_cls.return_value = self.notifier
        self._attribute_map_bk_ = {}
        for item in attributes.RESOURCE_ATTRIBUTE_MAP:
            self._attribute_map_bk_[item] = (attributes.
                                             RESOURCE_ATTRIBUTE_MAP[item].
                                             copy())
        super(LinuxBridgeSecurityGroupsTestCase, self).setUp(PLUGIN_NAME)

    def tearDown(self):
        super(LinuxBridgeSecurityGroupsTestCase, self).tearDown()
        attributes.RESOURCE_ATTRIBUTE_MAP = self._attribute_map_bk_


class TestLinuxBridgeSecurityGroups(LinuxBridgeSecurityGroupsTestCase,
                                    test_sg.TestSecurityGroups):

    def test_security_group_rule_updated(self):
        name = 'webservers'
        description = 'my webservers'
        with self.security_group(name, description) as sg:
            with self.security_group(name, description) as sg2:
                security_group_id = sg['security_group']['id']
                direction = "ingress"
                source_group_id = sg2['security_group']['id']
                protocol = 'tcp'
                port_range_min = 88
                port_range_max = 88
                with self.security_group_rule(security_group_id, direction,
                                              protocol, port_range_min,
                                              port_range_max,
                                              source_group_id=source_group_id
                                              ):
                    pass
            self.notifier.assert_has_calls(
                [call.security_groups_rule_updated(mock.ANY,
                                                   [security_group_id]),
                 call.security_groups_rule_updated(mock.ANY,
                                                   [security_group_id])])

    def test_security_group_member_updated(self):
        with self.network() as n:
            with self.subnet(n):
                with self.security_group() as sg:
                    security_group_id = sg['security_group']['id']
                    res = self._create_port(self.fmt, n['network']['id'])
                    port = self.deserialize(self.fmt, res)

                    data = {'port': {'fixed_ips': port['port']['fixed_ips'],
                                     'name': port['port']['name'],
                                     ext_sg.SECURITYGROUPS:
                                     [security_group_id]}}

                    req = self.new_update_request('ports', data,
                                                  port['port']['id'])
                    res = self.deserialize(self.fmt,
                                           req.get_response(self.api))
                    self.assertEquals(res['port'][ext_sg.SECURITYGROUPS][0],
                                      security_group_id)
                    self._delete('ports', port['port']['id'])
                    self.notifier.assert_has_calls(
                        [call.security_groups_member_updated(
                            mock.ANY, [mock.ANY]),
                         call.security_groups_member_updated(
                             mock.ANY, [security_group_id])])


class TestLinuxBridgeSecurityGroupsXML(TestLinuxBridgeSecurityGroups):
    fmt = 'xml'


class TestLinuxBridgeSecurityGroupsDB(LinuxBridgeSecurityGroupsTestCase):
    def test_security_group_get_port_from_device(self):
        with self.network() as n:
            with self.subnet(n):
                with self.security_group() as sg:
                    security_group_id = sg['security_group']['id']
                    res = self._create_port(self.fmt, n['network']['id'])
                    port = self.deserialize(self.fmt, res)
                    fixed_ips = port['port']['fixed_ips']
                    data = {'port': {'fixed_ips': fixed_ips,
                                     'name': port['port']['name'],
                                     ext_sg.SECURITYGROUPS:
                                     [security_group_id]}}

                    req = self.new_update_request('ports', data,
                                                  port['port']['id'])
                    res = self.deserialize(self.fmt,
                                           req.get_response(self.api))
                    port_id = res['port']['id']
                    device_id = port_id[:8]
                    port_dict = lb_db.get_port_from_device(device_id)
                    self.assertEqual(port_id, port_dict['id'])
                    self.assertEqual([security_group_id],
                                     port_dict[ext_sg.SECURITYGROUPS])
                    self.assertEqual([], port_dict['security_group_rules'])
                    self.assertEqual([fixed_ips[0]['ip_address']],
                                     port_dict['fixed_ips'])
                    self._delete('ports', port['port']['id'])

    def test_security_group_get_port_from_device_with_no_port(self):
        port_dict = lb_db.get_port_from_device('bad_device_id')
        self.assertEqual(None, port_dict)


class TestLinuxBridgeSecurityGroupsDBXML(TestLinuxBridgeSecurityGroupsDB):
    fmt = 'xml'
