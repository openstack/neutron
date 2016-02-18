# Copyright (c) 2016 Mirantis, Inc.
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

from neutron_lib import exceptions as n_exc
from oslo_db import exception as obj_exc
from oslo_utils import uuidutils

from neutron.objects.db import api as obj_db_api
from neutron.objects import trunk as t_obj
from neutron.services.trunk import exceptions as t_exc
from neutron.tests.unit.objects import test_base
from neutron.tests.unit import testlib_api


class SubPortObjectTestCase(test_base.BaseObjectIfaceTestCase):

    _test_class = t_obj.SubPort

    def test_create_duplicates(self):
        with mock.patch.object(obj_db_api, 'create_object',
                               side_effect=obj_exc.DBDuplicateEntry):
            obj = self._test_class(self.context, **self.obj_fields[0])
            self.assertRaises(t_exc.DuplicateSubPort, obj.create)


class SubPortDbObjectTestCase(test_base.BaseDbObjectTestCase,
                              testlib_api.SqlTestCase):

    _test_class = t_obj.SubPort

    def setUp(self):
        super(SubPortDbObjectTestCase, self).setUp()
        self._create_test_network()
        for obj in self.obj_fields:
            self._create_port(id=obj['port_id'],
                              network_id=self._network['id'])
            self._create_trunk(trunk_id=obj['trunk_id'])

    def _create_trunk(self, trunk_id):
        port_id = uuidutils.generate_uuid()
        self._create_port(id=port_id, network_id=self._network['id'])
        trunk = t_obj.Trunk(self.context, id=trunk_id, port_id=port_id)
        trunk.create()

    def test_create_port_not_found(self):
        obj = self.obj_fields[0]
        obj['port_id'] = uuidutils.generate_uuid()

        sub_port = self._make_object(obj)
        self.assertRaises(n_exc.PortNotFound, sub_port.create)

    def test_create_trunk_not_found(self):
        obj = self.obj_fields[0]
        obj['trunk_id'] = uuidutils.generate_uuid()

        sub_port = self._make_object(obj)
        self.assertRaises(t_exc.TrunkNotFound, sub_port.create)


class TrunkObjectTestCase(test_base.BaseObjectIfaceTestCase):

    _test_class = t_obj.Trunk


class TrunkDbObjectTestCase(test_base.BaseDbObjectTestCase,
                            testlib_api.SqlTestCase):

    _test_class = t_obj.Trunk

    def setUp(self):
        super(TrunkDbObjectTestCase, self).setUp()

        self._create_test_network()

        for obj in self.obj_fields:
            self._create_port(id=obj['port_id'],
                              network_id=self._network['id'])

    def test_create_port_not_found(self):
        obj = self.obj_fields[0]
        obj['port_id'] = uuidutils.generate_uuid()

        trunk = self._make_object(obj)
        self.assertRaises(n_exc.PortNotFound, trunk.create)

    def test_create_with_sub_ports(self):
        tenant_id = uuidutils.generate_uuid()

        def _as_tuple(sub_port):
            return (sub_port['port_id'],
                    sub_port['segmentation_type'],
                    sub_port['segmentation_id'])

        sub_ports = []
        for vid in range(1, 3):
            port = self._create_port(network_id=self._network['id'])
            sub_ports.append(t_obj.SubPort(self.context, port_id=port['id'],
                                           segmentation_type='vlan',
                                           segmentation_id=vid))
        expected = set(map(_as_tuple, sub_ports))

        trunk = t_obj.Trunk(self.context, port_id=self.db_obj['port_id'],
                            sub_ports=sub_ports, tenant_id=tenant_id)
        trunk.create()

        sub_ports = t_obj.SubPort.get_objects(self.context, trunk_id=trunk.id)

        self.assertEqual(expected, set(map(_as_tuple, trunk.sub_ports)))
        self.assertEqual(expected, set(map(_as_tuple, sub_ports)))
