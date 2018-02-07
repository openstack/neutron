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
from oslo_utils import uuidutils
import testscenarios

from neutron.objects import base as obj_base
from neutron.objects import network
from neutron.objects import ports
from neutron.objects.qos import binding
from neutron.objects.qos import policy
from neutron.tests import tools
from neutron.tests.unit.objects import test_base as obj_test_base
from neutron.tests.unit import testlib_api


class SecurityGroupPortBindingIfaceObjTestCase(
        obj_test_base.BaseObjectIfaceTestCase):
    _test_class = ports.SecurityGroupPortBinding


class SecurityGroupPortBindingDbObjectTestCase(
        obj_test_base.BaseDbObjectTestCase):
    _test_class = ports.SecurityGroupPortBinding


class BasePortBindingDbObjectTestCase(obj_test_base._BaseObjectTestCase,
                                      testlib_api.SqlTestCase):
    def setUp(self):
        super(BasePortBindingDbObjectTestCase, self).setUp()
        self.update_obj_fields(
            {'port_id': lambda: self._create_test_port_id()})


class PortBindingIfaceObjTestCase(obj_test_base.BaseObjectIfaceTestCase):
    _test_class = ports.PortBinding


class PortBindingDbObjectTestCase(obj_test_base.BaseDbObjectTestCase,
                                  BasePortBindingDbObjectTestCase):
    _test_class = ports.PortBinding


class DistributedPortBindingIfaceObjTestCase(
        obj_test_base.BaseObjectIfaceTestCase):
    _test_class = ports.DistributedPortBinding


class DistributedPortBindingDbObjectTestCase(
        obj_test_base.BaseDbObjectTestCase,
        BasePortBindingDbObjectTestCase):
    _test_class = ports.DistributedPortBinding


# TODO(ihrachys): this test case copies some functions from the base module.
# This is because we currently cannot inherit from the base class that contains
# those functions, because that same class provides test cases that we don't
# want to execute. Ideally, we would need to copy paste, but that would require
# some significant refactoring in the base test classes. Leaving it for a
# follow up.
class PortBindingVifDetailsTestCase(testscenarios.WithScenarios,
                                    obj_test_base._BaseObjectTestCase,
                                    testlib_api.SqlTestCase):

    scenarios = [
        (cls.__name__, {'_test_class': cls})
        for cls in (ports.PortBinding, ports.DistributedPortBinding)
    ]

    def setUp(self):
        super(PortBindingVifDetailsTestCase, self).setUp()
        self._create_test_network()
        getter = lambda: self._create_port(network_id=self._network['id']).id
        self.update_obj_fields({'port_id': getter})

    def _create_port(self, **port_attrs):
        attrs = {'project_id': uuidutils.generate_uuid(),
                 'admin_state_up': True,
                 'status': 'ACTIVE',
                 'device_id': 'fake_device',
                 'device_owner': 'fake_owner',
                 'mac_address': tools.get_random_EUI()}
        attrs.update(port_attrs)
        port = ports.Port(self.context, **attrs)
        port.create()
        return port

    def _create_test_network(self):
        self._network = network.Network(self.context,
                                        name='test-network1')
        self._network.create()

    def _make_object(self, fields):
        fields = obj_test_base.get_non_synthetic_fields(
            self._test_class, fields
        )
        return self._test_class(
            self.context,
            **obj_test_base.remove_timestamps_from_fields(
                fields, self._test_class.fields))

    def test_vif_details(self):
        vif_details = {'item1': 'val1', 'item2': 'val2'}
        obj = self._make_object(self.obj_fields[0])
        obj.vif_details = vif_details
        obj.create()

        obj = self._test_class.get_object(
            self.context, **obj._get_composite_keys())
        self.assertEqual(vif_details, obj.vif_details)

        vif_details['item1'] = 1.23
        del vif_details['item2']
        vif_details['item3'] = True

        obj.vif_details = vif_details
        obj.update()

        obj = self._test_class.get_object(
            self.context, **obj._get_composite_keys())
        self.assertEqual(vif_details, obj.vif_details)

        obj.vif_details = None
        obj.update()
        # here the obj is reloaded from DB,
        # so we test if vif_details is still none
        self.assertIsNone(obj.vif_details)

        obj = self._test_class.get_object(
            self.context, **obj._get_composite_keys())
        self.assertIsNone(obj.vif_details)

    def test_null_vif_details_in_db(self):
        # the null case for vif_details in our db model is an
        # empty string. add that here to simulate it correctly
        # in the tests
        kwargs = self.get_random_db_fields()
        kwargs['vif_details'] = ''
        db_obj = self._test_class.db_model(**kwargs)
        obj_fields = self._test_class.modify_fields_from_db(db_obj)
        obj = self._test_class(self.context, **obj_fields)
        self.assertIsNone(obj.vif_details)


class IPAllocationIfaceObjTestCase(obj_test_base.BaseObjectIfaceTestCase):

    _test_class = ports.IPAllocation


class IPAllocationDbObjectTestCase(obj_test_base.BaseDbObjectTestCase,
                                   testlib_api.SqlTestCase):

    _test_class = ports.IPAllocation

    def setUp(self):
        super(IPAllocationDbObjectTestCase, self).setUp()
        network_id = self._create_test_network_id()
        port_id = self._create_test_port_id(network_id=network_id)
        self.update_obj_fields(
            {'port_id': port_id, 'network_id': network_id,
             'subnet_id': lambda: self._create_test_subnet_id(network_id)})


class PortDNSIfaceObjTestCase(obj_test_base.BaseObjectIfaceTestCase):

    _test_class = ports.PortDNS


class PortDNSDbObjectTestCase(obj_test_base.BaseDbObjectTestCase,
                              testlib_api.SqlTestCase):

    _test_class = ports.PortDNS

    def setUp(self):
        super(PortDNSDbObjectTestCase, self).setUp()
        self.update_obj_fields(
            {'port_id': lambda: self._create_test_port_id()})


class PortBindingLevelIfaceObjTestCase(
        obj_test_base.BaseObjectIfaceTestCase):

    _test_class = ports.PortBindingLevel

    def setUp(self):
        super(PortBindingLevelIfaceObjTestCase, self).setUp()
        # for this object, the model contains segment_id but we expose it
        # through an ObjectField that is loaded without a relationship
        for obj in self.db_objs:
            obj['segment_id'] = None
        self.pager_map[self._test_class.obj_name()] = (
            obj_base.Pager(sorts=[('port_id', True), ('level', True)]))
        self.pager_map[network.NetworkSegment.obj_name()] = (
            obj_base.Pager(
                sorts=[('network_id', True), ('segment_index', True)]))


class PortBindingLevelDbObjectTestCase(
        obj_test_base.BaseDbObjectTestCase):

    _test_class = ports.PortBindingLevel


class PortIfaceObjTestCase(obj_test_base.BaseObjectIfaceTestCase):

    _test_class = ports.Port

    def setUp(self):
        super(PortIfaceObjTestCase, self).setUp()
        self.pager_map[ports.PortBindingLevel.obj_name()] = (
            obj_base.Pager(sorts=[('port_id', True), ('level', True)]))


class PortDbObjectTestCase(obj_test_base.BaseDbObjectTestCase,
                           testlib_api.SqlTestCase):

    _test_class = ports.Port

    def setUp(self):
        super(PortDbObjectTestCase, self).setUp()
        network_id = self._create_test_network_id()
        subnet_id = self._create_test_subnet_id(network_id)
        self.update_obj_fields(
            {'network_id': network_id,
             'fixed_ips': {'subnet_id': subnet_id, 'network_id': network_id}})

    def test_security_group_ids(self):
        groups = []
        objs = []
        for i in range(2):
            groups.append(self._create_test_security_group_id())
            objs.append(self._make_object(self.obj_fields[i]))
            objs[i].security_group_ids = {groups[i]}
            objs[i].create()

        self.assertEqual([objs[0]],
                         ports.Port.get_objects(
                             self.context, security_group_ids=(groups[0], )))
        self.assertEqual([objs[1]],
                         ports.Port.get_objects(
                             self.context, security_group_ids=(groups[1], )))

        sg3_id = self._create_test_security_group_id()
        objs[0].security_group_ids = {sg3_id}
        objs[0].update()

        objs[0] = ports.Port.get_object(self.context, id=objs[0].id)
        self.assertEqual({sg3_id}, objs[0].security_group_ids)

        objs[0].security_group_ids = set()
        objs[0].update()

        objs[0] = ports.Port.get_object(self.context, id=objs[0].id)
        self.assertFalse(objs[0].security_group_ids)

    def test_security_group_ids_and_port_id(self):
        objs = []
        group = self._create_test_security_group_id()
        for i in range(2):
            objs.append(self._make_object(self.obj_fields[i]))
            objs[i].security_group_ids = {group}
            objs[i].create()

        for i in range(2):
            self.assertEqual(
                [objs[i]],
                ports.Port.get_objects(
                    self.context, id=(objs[i].id, ),
                    security_group_ids=(group, )))

    def test__attach_security_group(self):
        obj = self._make_object(self.obj_fields[0])
        obj.create()

        sg_id = self._create_test_security_group_id()
        obj._attach_security_group(sg_id)

        obj = ports.Port.get_object(self.context, id=obj.id)
        self.assertIn(sg_id, obj.security_group_ids)

        sg2_id = self._create_test_security_group_id()
        obj._attach_security_group(sg2_id)

        obj = ports.Port.get_object(self.context, id=obj.id)
        self.assertIn(sg2_id, obj.security_group_ids)

    @mock.patch.object(policy.QosPolicy, 'unset_default')
    def test_qos_policy_id(self, *mocks):
        policy_obj = policy.QosPolicy(self.context)
        policy_obj.create()

        obj = self._make_object(self.obj_fields[0])
        obj.qos_policy_id = policy_obj.id
        obj.create()

        obj = ports.Port.get_object(self.context, id=obj.id)
        self.assertEqual(policy_obj.id, obj.qos_policy_id)

        policy_obj2 = policy.QosPolicy(self.context)
        policy_obj2.create()

        obj.qos_policy_id = policy_obj2.id
        obj.update()

        obj = ports.Port.get_object(self.context, id=obj.id)
        self.assertEqual(policy_obj2.id, obj.qos_policy_id)

        obj.qos_policy_id = None
        obj.update()

        obj = ports.Port.get_object(self.context, id=obj.id)
        self.assertIsNone(obj.qos_policy_id)

    @mock.patch.object(policy.QosPolicy, 'unset_default')
    def test__attach_qos_policy(self, *mocks):
        obj = self._make_object(self.obj_fields[0])
        obj.create()

        policy_obj = policy.QosPolicy(self.context)
        policy_obj.create()
        obj._attach_qos_policy(policy_obj.id)

        obj = ports.Port.get_object(self.context, id=obj.id)
        self.assertEqual(policy_obj.id, obj.qos_policy_id)
        qos_binding_obj = binding.QosPolicyPortBinding.get_object(
            self.context, port_id=obj.id)
        self.assertEqual(qos_binding_obj.policy_id, obj.qos_policy_id)
        old_policy_id = policy_obj.id

        policy_obj2 = policy.QosPolicy(self.context)
        policy_obj2.create()
        obj._attach_qos_policy(policy_obj2.id)

        obj = ports.Port.get_object(self.context, id=obj.id)
        self.assertEqual(policy_obj2.id, obj.qos_policy_id)
        qos_binding_obj2 = binding.QosPolicyPortBinding.get_object(
            self.context, port_id=obj.id)
        self.assertEqual(qos_binding_obj2.policy_id, obj.qos_policy_id)
        qos_binding_obj = binding.QosPolicyPortBinding.get_objects(
            self.context, policy_id=old_policy_id)
        self.assertEqual(0, len(qos_binding_obj))

    def test_get_objects_queries_constant(self):
        self.skipTest(
            'Port object loads segment info without relationships')

    def test_v1_1_to_v1_0_drops_data_plane_status(self):
        port_new = self._create_test_port()
        port_v1_0 = port_new.obj_to_primitive(target_version='1.0')
        self.assertNotIn('data_plane_status',
                         port_v1_0['versioned_object.data'])
