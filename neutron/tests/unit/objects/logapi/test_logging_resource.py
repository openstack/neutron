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

from oslo_utils import uuidutils

from neutron.objects.logapi import logging_resource as log_res
from neutron.objects import securitygroup
from neutron.tests.unit.objects import test_base
from neutron.tests.unit import testlib_api


class LogObjectTestCase(test_base.BaseObjectIfaceTestCase):

    _test_class = log_res.Log


class LogDBObjectTestCase(test_base.BaseDbObjectTestCase,
                          testlib_api.SqlTestCase):

    _test_class = log_res.Log

    def setUp(self):
        super(LogDBObjectTestCase, self).setUp()
        self._network_id = self._create_test_network_id()
        self._port_id = self._create_test_port_id(network_id=self._network_id)
        self._security_group = self._create_test_security_group()
        self.update_obj_fields({'resource_id': self._security_group['id'],
                                'target_id': self._port_id})

    def _create_test_security_group(self):
        sg_fields = self.get_random_object_fields(securitygroup.SecurityGroup)
        sg_obj = securitygroup.SecurityGroup(self.context, **sg_fields)
        return sg_obj

    def test_create_sg_log_with_secgroup(self):
        sg = self._create_test_security_group()
        sg_log = log_res.Log(context=self.context,
                             id=uuidutils.generate_uuid(),
                             name='test-create',
                             resource_type='security_group',
                             resource_id=sg.id,
                             enabled=False)
        sg_log.create()
        self.assertEqual(sg.id, sg_log.resource_id)

    def test_create_sg_log_with_port(self):
        port_id = self._create_test_port_id(network_id=self._network_id)
        sg_log = log_res.Log(context=self.context,
                             id=uuidutils.generate_uuid(),
                             name='test-create',
                             resource_type='security_group',
                             target_id=port_id,
                             enabled=False)
        sg_log.create()
        self.assertEqual(port_id, sg_log.target_id)

    def test_update_multiple_log_fields(self):
        sg_log = log_res.Log(context=self.context,
                             id=uuidutils.generate_uuid(),
                             name='test-create',
                             description='test-description',
                             resource_type='security_group',
                             enabled=False)
        sg_log.create()
        fields = {'name': 'test-update', 'description': 'test-update-descr',
                  'enabled': True}
        sg_log.update_fields(fields)
        sg_log.update()

        new_sg_log = log_res.Log.get_object(self.context, id=sg_log.id)
        self._assert_attrs(new_sg_log, **fields)

    def _assert_attrs(self, sg_log, **kwargs):
        """Check the values passed in kwargs match the values of the sg log"""
        for k in sg_log.fields:
            if k in kwargs:
                self.assertEqual(kwargs[k], sg_log[k])
