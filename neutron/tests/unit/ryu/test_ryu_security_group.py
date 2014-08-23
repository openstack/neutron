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

import contextlib

import mock

from neutron.api.v2 import attributes
from neutron.extensions import securitygroup as ext_sg
from neutron import manager
from neutron.tests.unit.ryu import fake_ryu
from neutron.tests.unit import test_extension_security_group as test_sg
from neutron.tests.unit import test_security_groups_rpc as test_sg_rpc

PLUGIN_NAME = ('neutron.plugins.ryu.'
               'ryu_neutron_plugin.RyuNeutronPluginV2')
NOTIFIER = ('neutron.plugins.ryu.'
            'ryu_neutron_plugin.AgentNotifierApi')


class RyuSecurityGroupsTestCase(test_sg.SecurityGroupDBTestCase):
    _plugin_name = PLUGIN_NAME

    def setUp(self, plugin=None):
        test_sg_rpc.set_firewall_driver(test_sg_rpc.FIREWALL_HYBRID_DRIVER)
        self.fake_ryu = fake_ryu.patch_fake_ryu_client().start()
        self.notifier = mock.patch(NOTIFIER).start().return_value
        self._attribute_map_bk_ = {}
        for item in attributes.RESOURCE_ATTRIBUTE_MAP:
            self._attribute_map_bk_[item] = (attributes.
                                             RESOURCE_ATTRIBUTE_MAP[item].
                                             copy())
        super(RyuSecurityGroupsTestCase, self).setUp(PLUGIN_NAME)

    def tearDown(self):
        super(RyuSecurityGroupsTestCase, self).tearDown()
        attributes.RESOURCE_ATTRIBUTE_MAP = self._attribute_map_bk_


class TestRyuSecurityGroups(RyuSecurityGroupsTestCase,
                            test_sg.TestSecurityGroups,
                            test_sg_rpc.SGNotificationTestMixin):
    def test_security_group_get_port_from_device(self):
        with contextlib.nested(self.network(),
                               self.security_group()) as (n, sg):
            with self.subnet(n):
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
                plugin = manager.NeutronManager.get_plugin()
                port_dict = plugin.get_port_from_device(port_id)
                self.assertEqual(port_id, port_dict['id'])
                self.assertEqual([security_group_id],
                                 port_dict[ext_sg.SECURITYGROUPS])
                self.assertEqual([], port_dict['security_group_rules'])
                self.assertEqual([fixed_ips[0]['ip_address']],
                                 port_dict['fixed_ips'])
                self._delete('ports', port_id)

    def test_security_group_get_port_from_device_with_no_port(self):
        plugin = manager.NeutronManager.get_plugin()
        port_dict = plugin.get_port_from_device('bad_device_id')
        self.assertIsNone(port_dict)


class TestRyuSecurityGroupsXML(TestRyuSecurityGroups):
    fmt = 'xml'
