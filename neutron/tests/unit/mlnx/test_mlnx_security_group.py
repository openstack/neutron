# Copyright (c) 2013 OpenStack Foundation
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
import webob.exc

from neutron.api.v2 import attributes
from neutron.extensions import securitygroup as ext_sg
from neutron.plugins.mlnx.db import mlnx_db_v2 as mlnx_db
from neutron.tests.unit import test_extension_security_group as test_sg
from neutron.tests.unit import test_security_groups_rpc as test_sg_rpc


PLUGIN_NAME = ('neutron.plugins.mlnx.'
               'mlnx_plugin.MellanoxEswitchPlugin')
NOTIFIER = ('neutron.plugins.mlnx.'
            'agent_notify_api.AgentNotifierApi')


class MlnxSecurityGroupsTestCase(test_sg.SecurityGroupDBTestCase):
    _plugin_name = PLUGIN_NAME

    def setUp(self, plugin=None):
        test_sg_rpc.set_firewall_driver(test_sg_rpc.FIREWALL_IPTABLES_DRIVER)
        notifier_p = mock.patch(NOTIFIER)
        notifier_cls = notifier_p.start()
        self.notifier = mock.Mock()
        notifier_cls.return_value = self.notifier
        self._attribute_map_bk_ = {}
        for item in attributes.RESOURCE_ATTRIBUTE_MAP:
            self._attribute_map_bk_[item] = (attributes.
                                             RESOURCE_ATTRIBUTE_MAP[item].
                                             copy())
        super(MlnxSecurityGroupsTestCase, self).setUp(PLUGIN_NAME)

    def tearDown(self):
        attributes.RESOURCE_ATTRIBUTE_MAP = self._attribute_map_bk_
        super(MlnxSecurityGroupsTestCase, self).tearDown()


class TestMlnxSecurityGroups(MlnxSecurityGroupsTestCase,
                             test_sg.TestSecurityGroups,
                             test_sg_rpc.SGNotificationTestMixin):
    pass


class TestMlnxSecurityGroupsXML(TestMlnxSecurityGroups):
    fmt = 'xml'


class TestMlnxSecurityGroupsDB(MlnxSecurityGroupsTestCase):
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
                    if res.status_int >= 400:
                        raise webob.exc.HTTPClientError(code=res.status_int)
                    res = self.deserialize(self.fmt,
                                           req.get_response(self.api))
                    port_id = res['port']['id']
                    device_id = port_id[:8]
                    port_dict = mlnx_db.get_port_from_device(device_id)
                    self.assertEqual(port_id, port_dict['id'])
                    self.assertEqual([security_group_id],
                                     port_dict[ext_sg.SECURITYGROUPS])
                    self.assertEqual([], port_dict['security_group_rules'])
                    self.assertEqual([fixed_ips[0]['ip_address']],
                                     port_dict['fixed_ips'])
                    self._delete('ports', port['port']['id'])

    def test_security_group_get_port_from_device_with_no_port(self):
        port_dict = mlnx_db.get_port_from_device('bad_device_id')
        self.assertIsNone(port_dict)


class TestMlnxSecurityGroupsDBXML(TestMlnxSecurityGroupsDB):
    fmt = 'xml'
