# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013, NEC Corporation
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

from quantum.api.v2 import attributes
from quantum.extensions import securitygroup as ext_sg
from quantum import manager
from quantum.plugins.nec.db import api as ndb  # noqa
from quantum.tests.unit import test_extension_security_group as test_sg
from quantum.tests.unit import test_security_groups_rpc as test_sg_rpc

PLUGIN_NAME = ('quantum.plugins.nec.nec_plugin.NECPluginV2')
AGENT_NAME = ('quantum.plugins.nec.agent.nec_quantum_agent.NECQuantumAgent')
NOTIFIER = ('quantum.plugins.nec.nec_plugin.NECPluginV2AgentNotifierApi')


class NecSecurityGroupsTestCase(test_sg.SecurityGroupDBTestCase):
    _plugin_name = PLUGIN_NAME

    def setUp(self, plugin=None):
        test_sg_rpc.set_firewall_driver(test_sg_rpc.FIREWALL_HYBRID_DRIVER)
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
        super(NecSecurityGroupsTestCase, self).setUp(PLUGIN_NAME)

    def tearDown(self):
        super(NecSecurityGroupsTestCase, self).tearDown()
        attributes.RESOURCE_ATTRIBUTE_MAP = self._attribute_map_bk_


class TestNecSecurityGroups(NecSecurityGroupsTestCase,
                            test_sg.TestSecurityGroups,
                            test_sg_rpc.SGNotificationTestMixin):

    def test_security_group_get_port_from_device(self):
        with contextlib.nested(self.network(),
                               self.security_group()) as (n, sg):
            with self.subnet(n):
                res = self._create_port(self.fmt, n['network']['id'])
                port = self.deserialize(self.fmt, res)
                port_id = port['port']['id']
                sg_id = sg['security_group']['id']
                fixed_ips = port['port']['fixed_ips']

                data = {'port': {'fixed_ips': fixed_ips,
                                 'name': port['port']['name'],
                                 ext_sg.SECURITYGROUPS: [sg_id]}}
                req = self.new_update_request('ports', data, port_id)
                res = self.deserialize(self.fmt,
                                       req.get_response(self.api))

                plugin = manager.QuantumManager.get_plugin()
                port_dict = plugin.callback_sg.get_port_from_device(port_id)
                self.assertEqual(port_id, port_dict['id'])
                self.assertEqual([sg_id],
                                 port_dict[ext_sg.SECURITYGROUPS])
                self.assertEqual([], port_dict['security_group_rules'])
                self.assertEqual([fixed_ips[0]['ip_address']],
                                 port_dict['fixed_ips'])
                self._delete('ports', port_id)


class TestNecSecurityGroupsXML(TestNecSecurityGroups):
    fmt = 'xml'
