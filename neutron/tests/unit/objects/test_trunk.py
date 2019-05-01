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

import itertools

import mock
from neutron_lib import exceptions as n_exc
from neutron_lib.services.trunk import constants
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
        self._network_id = self._create_test_network_id()
        for obj in self.obj_fields:
            self._create_test_port(
                id=obj['port_id'], network_id=self._network_id)
            self._create_trunk(trunk_id=obj['trunk_id'])

    def _create_trunk(self, trunk_id):
        port_id = self._create_test_port_id(network_id=self._network_id)
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

        self._network_id = self._create_test_network_id()
        sub_ports = []
        for obj in self.db_objs:
            sub_ports.extend(obj['sub_ports'])

        for obj in itertools.chain(self.obj_fields, sub_ports):
            self._create_test_port(
                id=obj['port_id'], network_id=self._network_id)

    def test_create_port_not_found(self):
        obj = self.obj_fields[0]
        obj['port_id'] = uuidutils.generate_uuid()

        trunk = self._make_object(obj)
        self.assertRaises(n_exc.PortNotFound, trunk.create)

    def _test_create_trunk_with_subports(self, port_id, vids):
        project_id = uuidutils.generate_uuid()

        sub_ports = []
        for vid in vids:
            vid_port_id = self._create_test_port_id(
                network_id=self._network_id)
            sub_ports.append(t_obj.SubPort(
                self.context, port_id=vid_port_id, segmentation_type='vlan',
                segmentation_id=vid))
        trunk = t_obj.Trunk(
            self.context, port_id=port_id, sub_ports=sub_ports,
            project_id=project_id)
        trunk.create()
        self.assertEqual(sub_ports, trunk.sub_ports)
        return trunk

    def test_create_with_sub_ports(self):
        trunk = self._test_create_trunk_with_subports(
            self.db_objs[0]['port_id'], [1, 2])

        def _as_tuple(sub_port):
            return (sub_port['port_id'],
                    sub_port['segmentation_type'],
                    sub_port['segmentation_id'])

        expected = {_as_tuple(port) for port in trunk.sub_ports}

        sub_ports = t_obj.SubPort.get_objects(self.context, trunk_id=trunk.id)
        self.assertEqual(expected, {_as_tuple(port) for port in sub_ports})

    def test_get_object_includes_correct_subports(self):
        trunk1_vids = [1, 2, 3]
        trunk2_vids = [4, 5, 6]
        port_id1 = self.db_objs[0]['port_id']
        trunk1 = self._test_create_trunk_with_subports(port_id1, trunk1_vids)

        port_id2 = uuidutils.generate_uuid()
        self._create_test_port(
            id=port_id2, network_id=self._network_id)
        self._test_create_trunk_with_subports(port_id2, trunk2_vids)

        listed_trunk1 = t_obj.Trunk.get_object(
            self.context,
            id=trunk1.id,
            port_id=port_id1
        )
        self.assertEqual(
            set(trunk1_vids),
            {sp.segmentation_id for sp in listed_trunk1.sub_ports}
        )

    def test_update_multiple_fields(self):
        trunk = t_obj.Trunk(context=self.context,
                            admin_state_up=False,
                            port_id=self.db_objs[0]['port_id'],
                            status=constants.TRUNK_DOWN_STATUS)
        trunk.create()
        fields = {'admin_state_up': True,
                  'status': constants.TRUNK_ACTIVE_STATUS}
        trunk.update(**fields)

        trunk = t_obj.Trunk.get_object(self.context, id=trunk.id)
        self._assert_trunk_attrs(trunk, **fields)

    def _assert_trunk_attrs(self, trunk, **kwargs):
        """Check the values passed in kwargs match the values of the trunk"""
        for k in trunk.fields:
            if k in kwargs:
                self.assertEqual(kwargs[k], trunk[k])

    def test_v1_1_to_v1_0_drops_project_id(self):
        trunk_new = self._test_create_trunk_with_subports(
            self.db_objs[0]['port_id'], [1, 2])

        trunk_v1_0 = trunk_new.obj_to_primitive(target_version='1.0')
        self.assertNotIn('project_id', trunk_v1_0['versioned_object.data'])
        self.assertIn('tenant_id', trunk_v1_0['versioned_object.data'])

    def test_get_objects_tenant_id(self):
        trunk = t_obj.Trunk(context=self.context,
                            project_id='faketenant',
                            port_id=self.db_objs[0]['port_id'])
        trunk.create()
        self.assertIsNotNone(
            t_obj.Trunk.get_objects(self.context, tenant_id='faketenant'))

    def test_get_objects_both_tenant_and_project_ids(self):
        trunk = t_obj.Trunk(context=self.context,
                            project_id='faketenant',
                            port_id=self.db_objs[0]['port_id'])
        trunk.create()
        self.assertIsNotNone(
            t_obj.Trunk.get_objects(
                self.context, tenant_id='faketenant', project_id='faketenant'))
