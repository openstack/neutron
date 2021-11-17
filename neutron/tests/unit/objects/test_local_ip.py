# Copyright 2021 Huawei, Inc.
# All rights reserved.
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

from unittest import mock

from neutron.objects import base as obj_base
from neutron.objects import local_ip
from neutron.tests.unit.objects import test_base as obj_test_base
from neutron.tests.unit import testlib_api


class LocalIPIfaceObjectTestCase(obj_test_base.BaseObjectIfaceTestCase):

    _test_class = local_ip.LocalIP


class LocalIPDbObjectTestCase(obj_test_base.BaseDbObjectTestCase,
                              testlib_api.SqlTestCase):

    _test_class = local_ip.LocalIP

    def setUp(self):
        super(LocalIPDbObjectTestCase, self).setUp()
        self.update_obj_fields(
            {'local_port_id': lambda: self._create_test_port_id(),
             'network_id': lambda: self._create_test_network_id()})


class LocalIPAssociationIfaceObjectTestCase(
        obj_test_base.BaseObjectIfaceTestCase):

    _test_class = local_ip.LocalIPAssociation

    def setUp(self):
        super(LocalIPAssociationIfaceObjectTestCase, self).setUp()
        mock.patch.object(obj_base.NeutronDbObject,
                          'load_synthetic_db_fields').start()


class LocalIPAssociationDbObjectTestCase(
        obj_test_base.BaseDbObjectTestCase, testlib_api.SqlTestCase):

    _test_class = local_ip.LocalIPAssociation

    def setUp(self):
        super(LocalIPAssociationDbObjectTestCase, self).setUp()
        self.update_obj_fields(
            {
                'local_ip_id':
                    lambda: self._create_test_local_ip_id(),
                'fixed_port_id':
                    lambda: self._create_test_port_id()
            })
