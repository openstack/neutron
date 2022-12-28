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

import netaddr
from neutron_lib.api.definitions import portbindings
from neutron_lib import constants
from neutron_lib.tests import tools
from oslo_utils import uuidutils
import testscenarios

from neutron.objects import base as obj_base
from neutron.objects import network
from neutron.objects import ports
from neutron.objects.qos import binding
from neutron.objects.qos import policy
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

    def test_get_duplicated_port_bindings(self):
        port_id = self._create_test_port_id()
        self.update_obj_fields(
            {'port_id': port_id, 'status': constants.ACTIVE},
            obj_fields=[self.obj_fields[0]])
        self.update_obj_fields(
            {'port_id': port_id, 'status': constants.INACTIVE},
            obj_fields=[self.obj_fields[1]])
        for i in range(3):
            _obj = self._make_object(self.obj_fields[i])
            _obj.create()
        dup_pb = ports.PortBinding.get_duplicated_port_bindings(self.context)
        self.assertEqual(1, len(dup_pb))
        self.assertEqual(port_id, dup_pb[0].port_id)
        # The PB register returned is the INACTIVE one.
        self.assertEqual(self.obj_fields[1]['host'], dup_pb[0].host)

    def test_get_port_binding_by_vnic_type(self):
        self.update_obj_fields({'vnic_type': portbindings.VNIC_NORMAL},
                               obj_fields=[self.obj_fields[0]])
        self.update_obj_fields({'vnic_type': portbindings.VNIC_DIRECT},
                               obj_fields=[self.obj_fields[1],
                                           self.obj_fields[2]])
        for i in range(3):
            _obj = self._make_object(self.obj_fields[i])
            _obj.create()

        for vnic_type, pb_num in [(portbindings.VNIC_NORMAL, 1),
                                  (portbindings.VNIC_DIRECT, 2),
                                  (portbindings.VNIC_MACVTAP, 0)]:
            pb = ports.PortBinding.get_port_binding_by_vnic_type(self.context,
                                                                 vnic_type)
            self.assertEqual(pb_num, len(pb))


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
        self.pager_map[self._test_class.obj_name()] = (
            obj_base.Pager(sorts=[('port_id', True), ('level', True)]))


class PortBindingLevelDbObjectTestCase(
        obj_test_base.BaseDbObjectTestCase, testlib_api.SqlTestCase):

    _test_class = ports.PortBindingLevel

    def setUp(self):
        super(PortBindingLevelDbObjectTestCase, self).setUp()
        self.update_obj_fields(
            {'port_id': lambda: self._create_test_port_id(),
             'segment_id': lambda: self._create_test_segment_id()})


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
        segment_id = self._create_test_segment_id(network_id)
        subnet_id = self._create_test_subnet_id(network_id)
        self.update_obj_fields(
            {'network_id': network_id,
             'fixed_ips': {'subnet_id': subnet_id,
                           'network_id': network_id},
             'device_owner': 'not_a_router',
             'binding_levels': {'segment_id': segment_id}})

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

    @mock.patch.object(policy.QosPolicy, 'unset_default')
    def test_qos_network_policy_id(self, *mocks):
        policy_obj = policy.QosPolicy(self.context)
        policy_obj.create()

        obj = self._make_object(self.obj_fields[0])
        obj.create()
        obj = ports.Port.get_object(self.context, id=obj.id)
        self.assertIsNone(obj.qos_network_policy_id)
        self.assertIsNone(obj.qos_policy_id)

        network = self._create_test_network(qos_policy_id=policy_obj.id)
        self.update_obj_fields({'network_id': network.id})
        obj = self._make_object(self.obj_fields[1])
        obj.create()
        obj = ports.Port.get_object(self.context, id=obj.id)
        self.assertEqual(policy_obj.id, obj.qos_network_policy_id)
        self.assertIsNone(obj.qos_policy_id)

    def test_get_objects_queries_constant(self):
        self.skipTest(
            'Port object loads segment info without relationships')

    def test_v1_2_to_v1_1_drops_segment_id_in_binding_levels(self):
        port_new = self._create_test_port()
        segment = network.NetworkSegment(
            self.context,
            # TODO(ihrachys) we should be able to create a segment object
            # without explicitly specifying id, but it's currently not working
            id=uuidutils.generate_uuid(),
            network_id=port_new.network_id,
            network_type='vxlan')
        segment.create()

        # TODO(ihrachys) we should be able to create / update level objects via
        # Port object, but it's currently not working
        binding = ports.PortBindingLevel(
            self.context, port_id=port_new.id,
            host='host1', level=0, segment_id=segment.id)
        binding.create()

        port_new = ports.Port.get_object(self.context, id=port_new.id)
        port_v1_1 = port_new.obj_to_primitive(target_version='1.1')

        lvl = port_v1_1['versioned_object.data']['binding_levels'][0]
        self.assertNotIn('segment_id', lvl['versioned_object.data'])

        # check that we also downgraded level object version
        self.assertEqual('1.0', lvl['versioned_object.version'])

        # finally, prove that binding primitive is now identical to direct
        # downgrade of the binding object
        binding_v1_0 = binding.obj_to_primitive(target_version='1.0')
        self.assertEqual(binding_v1_0, lvl)

    def test_v1_3_to_v1_2_unlists_distributed_bindings(self):
        port_new = self._create_test_port()

        # empty list transforms into None
        port_v1_2 = port_new.obj_to_primitive(target_version='1.2')
        port_data = port_v1_2['versioned_object.data']
        self.assertIsNone(port_data['distributed_binding'])

        # now insert a distributed binding
        binding = ports.DistributedPortBinding(
            self.context,
            host='host1', port_id=port_new.id, status='ACTIVE',
            vnic_type='vnic_type1', vif_type='vif_type1')
        binding.create()

        # refetch port object to include binding
        port_new = ports.Port.get_object(self.context, id=port_new.id)

        # new primitive should contain the binding data
        port_v1_2 = port_new.obj_to_primitive(target_version='1.2')
        port_data = port_v1_2['versioned_object.data']
        binding_data = (
            port_data['distributed_binding']['versioned_object.data'])
        self.assertEqual(binding.host, binding_data['host'])

    def test_v1_4_to_v1_3_converts_binding_to_portbinding_object(self):
        port_v1_4 = self._create_test_port()
        port_v1_3 = port_v1_4.obj_to_primitive(target_version='1.3')

        # Port has no bindings, so binding attribute should be None
        self.assertIsNone(port_v1_3['versioned_object.data']['binding'])
        active_binding = ports.PortBinding(self.context, port_id=port_v1_4.id,
                                           host='host1', vif_type='type')
        inactive_binding = ports.PortBinding(
            self.context, port_id=port_v1_4.id, host='host2', vif_type='type',
            status=constants.INACTIVE)
        active_binding.create()
        inactive_binding.create()
        port_v1_4 = ports.Port.get_object(self.context, id=port_v1_4.id)
        port_v1_3 = port_v1_4.obj_to_primitive(target_version='1.3')
        binding = port_v1_3['versioned_object.data']['binding']

        # Port has active binding, so the binding attribute should point to it
        self.assertEqual('host1', binding['versioned_object.data']['host'])
        active_binding.delete()
        port_v1_4 = ports.Port.get_object(self.context, id=port_v1_4.id)
        port_v1_3 = port_v1_4.obj_to_primitive(target_version='1.3')

        # Port has no active bindings, so binding attribute should be None
        self.assertIsNone(port_v1_3['versioned_object.data']['binding'])

        # bindings attribute in V1.4 port should have one inactive binding
        primitive = port_v1_4.obj_to_primitive()
        self.assertEqual(1,
                         len(primitive['versioned_object.data']['bindings']))
        binding = primitive['versioned_object.data']['bindings'][0]
        self.assertEqual(constants.INACTIVE,
                         binding['versioned_object.data']['status'])

        # Port with no binding attribute should be handled without raising
        # exception
        primitive['versioned_object.data'].pop('bindings')
        port_v1_4_no_binding = port_v1_4.obj_from_primitive(primitive)
        port_v1_4_no_binding.obj_to_primitive(target_version='1.3')

    def test_v1_5_to_v1_4_drops_qos_network_policy_id(self):
        port_new = self._create_test_port()
        port_v1_4 = port_new.obj_to_primitive(target_version='1.4')
        self.assertNotIn('qos_network_policy_id',
                         port_v1_4['versioned_object.data'])

    def test_v1_6_to_v1_5_drops_numa_affinity_policy(self):
        port_new = self._create_test_port()
        port_v1_5 = port_new.obj_to_primitive(target_version='1.5')
        self.assertNotIn('numa_affinity_policy',
                         port_v1_5['versioned_object.data'])

    def test_v1_7_to_v1_6_drops_device_profile(self):
        port_new = self._create_test_port()
        port_v1_6 = port_new.obj_to_primitive(target_version='1.6')
        self.assertNotIn('device_profile',
                         port_v1_6['versioned_object.data'])

    def test_v1_8_to_v1_7_drops_hints(self):
        port_new = self._create_test_port()
        port_v1_7 = port_new.obj_to_primitive(target_version='1.7')
        self.assertNotIn('hints',
                         port_v1_7['versioned_object.data'])

    def test_get_ports_ids_by_security_groups_except_router(self):
        sg_id = self._create_test_security_group_id()
        filter_owner = constants.ROUTER_INTERFACE_OWNERS_SNAT
        obj = self._make_object(self.obj_fields[0])
        obj.create()
        obj.security_group_ids = {sg_id}
        obj.update()
        self.assertEqual(1, len(
            ports.Port.get_ports_ids_by_security_groups(
                self.context, security_group_ids=(sg_id, ),
                excluded_device_owners=filter_owner)))
        obj.device_owner = constants.DEVICE_OWNER_ROUTER_SNAT
        obj.update()
        self.assertEqual(0, len(
            ports.Port.get_ports_ids_by_security_groups(
                self.context, security_group_ids=(sg_id, ),
                excluded_device_owners=filter_owner)))

    def test_get_ports_by_vnic_type_and_host(self):
        port1 = self._create_test_port()
        ports.PortBinding(
            self.context,
            host='host1', port_id=port1.id, status='ACTIVE',
            vnic_type='vnic_type1', vif_type='vif_type1').create()

        port2 = self._create_test_port()
        ports.PortBinding(
            self.context,
            host='host1', port_id=port2.id, status='ACTIVE',
            vnic_type='vnic_type2', vif_type='vif_type1').create()

        self.assertEqual(1, len(
            ports.Port.get_ports_by_vnic_type_and_host(
                self.context, 'vnic_type1', 'host1')))

    def test_check_network_ports_by_binding_types(self):
        port1 = self._create_test_port()
        network_id = port1.network_id
        ports.PortBinding(
            self.context,
            host='host1', port_id=port1.id, status='ACTIVE',
            vnic_type='vnic_type1', vif_type='vif_type1').create()

        port2 = self._create_test_port(network_id=network_id)
        ports.PortBinding(
            self.context,
            host='host2', port_id=port2.id, status='ACTIVE',
            vnic_type='vnic_type2', vif_type='vif_type2').create()

        self.assertTrue(
            ports.Port.check_network_ports_by_binding_types(
                self.context, network_id,
                binding_types=['vif_type1', 'vif_type2']))

        self.assertFalse(
            ports.Port.check_network_ports_by_binding_types(
                self.context, network_id,
                binding_types=['vif_type1', 'vif_type2'],
                negative_search=True))

    def test_get_ports_allocated_by_subnet_id(self):
        network_id = self._create_test_network_id()
        segment_id = self._create_test_segment_id(network_id)
        subnet_id = self._create_test_subnet_id(network_id)
        self.update_obj_fields(
            {'network_id': network_id,
             'fixed_ips': {'subnet_id': subnet_id,
                           'network_id': network_id},
             'device_owner': 'not_a_router',
             'binding_levels': {'segment_id': segment_id}},
            db_objs=[self.db_objs[0]])

        objs = []
        for idx in range(3):
            objs.append(self._make_object(self.obj_fields[idx]))
            objs[idx].create()

        ipa = ports.IPAllocation(self.context, port_id=objs[0].id,
                                 subnet_id=subnet_id, network_id=network_id,
                                 ip_address=netaddr.IPAddress('10.0.0.1'))
        ipa.create()

        ports_alloc = ports.Port.get_ports_allocated_by_subnet_id(self.context,
                                                                  subnet_id)
        self.assertEqual(1, len(ports_alloc))
        self.assertEqual(objs[0].id, ports_alloc[0].id)

    def _test_get_auto_deletable_ports(self, device_owner):
        network_id = self._create_test_network_id()
        segment_id = self._create_test_segment_id(network_id)
        port = self._create_test_port(device_owner=device_owner)
        binding = ports.PortBindingLevel(
            self.context, port_id=port.id,
            host='host1', level=0, segment_id=segment_id)
        binding.create()
        return (
            ports.Port.
            get_auto_deletable_port_ids_and_proper_port_count_by_segment(
                self.context, segment_id))

    def test_get_auto_deletable_ports_dhcp(self):
        dhcp_ports, count = self._test_get_auto_deletable_ports(
            'network:dhcp')
        self.assertEqual(
            (1, 0),
            (len(dhcp_ports), count),
        )

    def test_get_auto_deletable_ports_not_dhcp(self):
        dhcp_ports, count = self._test_get_auto_deletable_ports(
            'not_network_dhcp')
        self.assertEqual(
            (0, 1),
            (len(dhcp_ports), count),
        )

    def test_get_port_from_mac_and_pci_slot_no_ports(self):
        self.assertIsNone(
            ports.Port.get_port_from_mac_and_pci_slot(self.context,
                                                      'ca:fe:ca:fe:ca:fe'))

    def test_get_port_from_mac_and_pci_slot_no_pci_slot(self):
        obj = self._make_object(self.obj_fields[0])
        obj.create()
        mac_address = obj.mac_address
        port = ports.Port.get_port_from_mac_and_pci_slot(self.context,
                                                         mac_address)
        self.assertEqual(obj.id, port.id)

    def test_get_port_from_mac_and_pci_slot(self):
        obj = self._make_object(self.obj_fields[0])
        obj.create()
        mac_address = obj.mac_address
        pci_slot = '0000:04:00.1'
        port = ports.Port.get_port_from_mac_and_pci_slot(
            self.context, mac_address, pci_slot=pci_slot)
        self.assertIsNone(port)

        port_binding = ports.PortBinding(
            self.context, port_id=obj.id, host='any_host',
            vif_type=portbindings.VIF_TYPE_OTHER,
            vnic_type=portbindings.VNIC_DIRECT, profile={'pci_slot': pci_slot})
        port_binding.create()
        port = ports.Port.get_port_from_mac_and_pci_slot(
            self.context, mac_address, pci_slot=pci_slot)
        self.assertEqual(obj.id, port.id)
