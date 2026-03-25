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

from neutron_lib.api.definitions import availability_zone as az_def

from neutron.db import rbac_db_models
from neutron_lib import constants as lib_constants
from oslo_utils import uuidutils

from neutron.objects import base as obj_base
from neutron.objects import network
from neutron.objects.qos import binding
from neutron.objects.qos import policy
from neutron.tests.unit.objects import test_base as obj_test_base
from neutron.tests.unit.objects import test_rbac
from neutron.tests.unit import testlib_api


class NetworkRBACDbObjectTestCase(test_rbac.TestRBACObjectMixin,
                                  obj_test_base.BaseDbObjectTestCase,
                                  testlib_api.SqlTestCase):

    _test_class = network.NetworkRBAC
    _parent_class = network.Network

    def setUp(self):
        self._mock_get_valid_actions = mock.patch.object(
            rbac_db_models.NetworkRBAC, 'get_valid_actions',
            return_value=(rbac_db_models.ACCESS_EXTERNAL,
                          rbac_db_models.ACCESS_SHARED))
        self.mock_get_valid_actions = self._mock_get_valid_actions.start()
        super().setUp()
        for obj in self.db_objs:
            net_obj = network.Network(self.context, id=obj['object_id'])
            net_obj.create()

    def _create_test_network_rbac(self):
        self.objs[0].create()
        return self.objs[0]

    def _create_random_parent_object(self):
        objclass_fields = self.get_random_db_fields(self._parent_class)
        objclass_fields.pop(az_def.AZ_HINTS)
        _obj = self._parent_class(self.context, **objclass_fields)
        _obj.create()
        return _obj


class NetworkRBACIfaceOjectTestCase(test_rbac.TestRBACObjectMixin,
                                    obj_test_base.BaseObjectIfaceTestCase):

    _test_class = network.NetworkRBAC

    def setUp(self):
        self._mock_get_valid_actions = mock.patch.object(
            rbac_db_models.NetworkRBAC, 'get_valid_actions',
            return_value=(rbac_db_models.ACCESS_EXTERNAL,
                          rbac_db_models.ACCESS_SHARED))
        self.mock_get_valid_actions = self._mock_get_valid_actions.start()
        super().setUp()


class NetworkDhcpAgentBindingObjectIfaceTestCase(
        obj_test_base.BaseObjectIfaceTestCase):

    _test_class = network.NetworkDhcpAgentBinding


class NetworkDhcpAgentBindingDbObjectTestCase(
        obj_test_base.BaseDbObjectTestCase, testlib_api.SqlTestCase):

    _test_class = network.NetworkDhcpAgentBinding

    def setUp(self):
        super().setUp()
        self._network = self._create_test_network()

        index = iter(range(1, len(self.objs) + 2))
        self.update_obj_fields(
            {'network_id': self._network.id,
             'dhcp_agent_id': lambda: self._create_test_agent_id(),
             'binding_index': lambda: next(index)})


class NetworkPortSecurityIfaceObjTestCase(
        obj_test_base.BaseObjectIfaceTestCase):
    _test_class = network.NetworkPortSecurity


class NetworkPortSecurityDbObjTestCase(obj_test_base.BaseDbObjectTestCase,
                                       testlib_api.SqlTestCase):
    _test_class = network.NetworkPortSecurity

    def setUp(self):
        super().setUp()
        self.update_obj_fields({'id': lambda: self._create_test_network_id()})


class NetworkSegmentIfaceObjTestCase(obj_test_base.BaseObjectIfaceTestCase):
    _test_class = network.NetworkSegment

    def setUp(self):
        super().setUp()
        # TODO(ihrachys): we should not need to duplicate that in every single
        # place, instead we should move the default pager into the base class
        # attribute and pull it from there for testing matters. Leaving it for
        # a follow up.
        self.pager_map[self._test_class.obj_name()] = (
            obj_base.Pager(
                sorts=[('network_id', True), ('segment_index', True)]))


class NetworkSegmentDbObjTestCase(obj_test_base.BaseDbObjectTestCase,
                                  testlib_api.SqlTestCase):
    _test_class = network.NetworkSegment

    def setUp(self):
        super().setUp()
        self.update_obj_fields(
            {'network_id': lambda: self._create_test_network_id()})

    _seg_index = 0

    def _create_segment(self, network_type, physical_network, segmentation_id,
                        network_id=None):
        NetworkSegmentDbObjTestCase._seg_index += 1
        seg = network.NetworkSegment(
            self.context,
            id=uuidutils.generate_uuid(),
            network_id=network_id or self._create_test_network_id(),
            network_type=network_type,
            physical_network=physical_network,
            segmentation_id=segmentation_id,
            segment_index=self._seg_index)
        seg.create()
        return seg

    def test_count_segments(self):
        net_id = self._create_test_network_id()
        self._create_segment(lib_constants.TYPE_VLAN, 'physnet1', 100,
                             network_id=net_id)
        self._create_segment(lib_constants.TYPE_VLAN, 'physnet1', 200,
                             network_id=net_id)
        self._create_segment(lib_constants.TYPE_VLAN, 'physnet2', 50,
                             network_id=net_id)
        self._create_segment(lib_constants.TYPE_VLAN, 'physnet2', 150,
                             network_id=net_id)
        self._create_segment(lib_constants.TYPE_VLAN, 'physnet2', 300,
                             network_id=net_id)
        self._create_segment(lib_constants.TYPE_VXLAN, None, 5000,
                             network_id=net_id)

        _count = network.NetworkSegment.count_segments
        # Match network_type and physical_network
        self.assertEqual(
            2, _count(self.context, lib_constants.TYPE_VLAN, 'physnet1'))
        self.assertEqual(
            3, _count(self.context, lib_constants.TYPE_VLAN, 'physnet2'))
        # Wrong network_type
        self.assertEqual(
            0, _count(self.context, lib_constants.TYPE_GRE, 'physnet1'))
        # Wrong physical_network
        self.assertEqual(
            0, _count(self.context, lib_constants.TYPE_VLAN, 'no-such'))
        # Tunnel type with physical_network=None
        self.assertEqual(
            1, _count(self.context, lib_constants.TYPE_VXLAN, None))
        # Mismatch: VXLAN does not have physnet1
        self.assertEqual(
            0, _count(self.context, lib_constants.TYPE_VXLAN, 'physnet1'))

        # segment_range filtering on physnet2 (segments: 50, 150, 300)
        self.assertEqual(
            3, _count(self.context, lib_constants.TYPE_VLAN, 'physnet2',
                      segment_range={'minimum': 1, 'maximum': 400}))
        self.assertEqual(
            1, _count(self.context, lib_constants.TYPE_VLAN, 'physnet2',
                      segment_range={'minimum': 100, 'maximum': 200}))
        self.assertEqual(
            0, _count(self.context, lib_constants.TYPE_VLAN, 'physnet2',
                      segment_range={'minimum': 51, 'maximum': 149}))
        # Inclusive boundaries
        self.assertEqual(
            2, _count(self.context, lib_constants.TYPE_VLAN, 'physnet2',
                      segment_range={'minimum': 50, 'maximum': 150}))
        # No range returns all
        self.assertEqual(
            3, _count(self.context, lib_constants.TYPE_VLAN, 'physnet2',
                      segment_range=None))
        # Range that excludes physnet1 segments (100, 200)
        self.assertEqual(
            0, _count(self.context, lib_constants.TYPE_VLAN, 'physnet1',
                      segment_range={'minimum': 250, 'maximum': 400}))

    def test_hosts(self):
        hosts = ['host1', 'host2']
        obj = self._make_object(self.obj_fields[0])
        obj.hosts = hosts
        obj.create()

        obj = network.NetworkSegment.get_object(self.context, id=obj.id)
        self.assertEqual(hosts, obj.hosts)

        obj.hosts = ['host3']
        obj.update()

        obj = network.NetworkSegment.get_object(self.context, id=obj.id)
        self.assertEqual(['host3'], obj.hosts)

        obj.hosts = None
        obj.update()

        obj = network.NetworkSegment.get_object(self.context, id=obj.id)
        self.assertFalse(obj.hosts)


class NetworkObjectIfaceTestCase(test_rbac.RBACBaseObjectIfaceTestCase):
    _test_class = network.Network

    def setUp(self):
        super().setUp()
        self.pager_map[network.NetworkSegment.obj_name()] = (
            obj_base.Pager(
                sorts=[('network_id', True), ('segment_index', True)]))


class NetworkDbObjectTestCase(obj_test_base.BaseDbObjectTestCase,
                              testlib_api.SqlTestCase):
    _test_class = network.Network

    @mock.patch.object(policy.QosPolicy, 'unset_default')
    def test_qos_policy_id(self, *mocks):
        policy_obj = policy.QosPolicy(self.context)
        policy_obj.create()

        obj = self._make_object(self.obj_fields[0])
        obj.qos_policy_id = policy_obj.id
        obj.create()

        obj = network.Network.get_object(self.context, id=obj.id)
        self.assertEqual(policy_obj.id, obj.qos_policy_id)

        policy_obj2 = policy.QosPolicy(self.context)
        policy_obj2.create()

        obj.qos_policy_id = policy_obj2.id
        obj.update()

        obj = network.Network.get_object(self.context, id=obj.id)
        self.assertEqual(policy_obj2.id, obj.qos_policy_id)

        obj.qos_policy_id = None
        obj.update()

        obj = network.Network.get_object(self.context, id=obj.id)
        self.assertIsNone(obj.qos_policy_id)

    @mock.patch.object(policy.QosPolicy, 'unset_default')
    def test__attach_qos_policy(self, *mocks):
        obj = self._make_object(self.obj_fields[0])
        obj.create()

        policy_obj = policy.QosPolicy(self.context)
        policy_obj.create()
        obj._attach_qos_policy(policy_obj.id)

        obj = network.Network.get_object(self.context, id=obj.id)
        self.assertEqual(policy_obj.id, obj.qos_policy_id)
        qos_binding_obj = binding.QosPolicyNetworkBinding.get_object(
            self.context, network_id=obj.id)
        self.assertEqual(qos_binding_obj.policy_id, obj.qos_policy_id)
        old_policy_id = policy_obj.id

        policy_obj2 = policy.QosPolicy(self.context)
        policy_obj2.create()
        obj._attach_qos_policy(policy_obj2.id)

        obj = network.Network.get_object(self.context, id=obj.id)
        self.assertEqual(policy_obj2.id, obj.qos_policy_id)
        qos_binding_obj2 = binding.QosPolicyNetworkBinding.get_object(
            self.context, network_id=obj.id)
        self.assertEqual(qos_binding_obj2.policy_id, obj.qos_policy_id)
        qos_binding_obj = binding.QosPolicyNetworkBinding.get_objects(
            self.context, policy_id=old_policy_id)
        self.assertEqual(0, len(qos_binding_obj))

    def test_dns_domain(self):
        obj = self._make_object(self.obj_fields[0])
        obj.dns_domain = 'foo.com'
        obj.create()

        obj = network.Network.get_object(self.context, id=obj.id)
        self.assertEqual('foo.com', obj.dns_domain)

        obj.dns_domain = 'bar.com'
        obj.update()

        obj = network.Network.get_object(self.context, id=obj.id)
        self.assertEqual('bar.com', obj.dns_domain)

        obj.dns_domain = None
        obj.update()

        obj = network.Network.get_object(self.context, id=obj.id)
        self.assertIsNone(obj.dns_domain)

    def test__set_dns_domain(self):
        obj = self._make_object(self.obj_fields[0])
        obj.create()

        obj._set_dns_domain('foo.com')

        obj = network.Network.get_object(self.context, id=obj.id)
        self.assertEqual('foo.com', obj.dns_domain)

        obj._set_dns_domain('bar.com')

        obj = network.Network.get_object(self.context, id=obj.id)
        self.assertEqual('bar.com', obj.dns_domain)

    def test_v1_2_to_v1_1_drops_qinq_attribute(self):
        network_obj = self._make_object(self.obj_fields[0])
        network_v1_1 = network_obj.obj_to_primitive(target_version='1.1')
        self.assertNotIn('qinq', network_v1_1['versioned_object.data'])


class SegmentHostMappingIfaceObjectTestCase(
        obj_test_base.BaseObjectIfaceTestCase):

    _test_class = network.SegmentHostMapping


class SegmentHostMappingDbObjectTestCase(obj_test_base.BaseDbObjectTestCase,
                                         testlib_api.SqlTestCase):

    _test_class = network.SegmentHostMapping

    def setUp(self):
        super().setUp()
        self.update_obj_fields(
            {'segment_id': lambda: self._create_test_segment_id()})


class NetworkDNSDomainIfaceObjectTestcase(
        obj_test_base.BaseObjectIfaceTestCase):

    _test_class = network.NetworkDNSDomain


class NetworkDNSDomainDbObjectTestcase(obj_test_base.BaseDbObjectTestCase,
                                       testlib_api.SqlTestCase):

    _test_class = network.NetworkDNSDomain

    def setUp(self):
        super().setUp()
        self.update_obj_fields(
            {'network_id': lambda: self._create_test_network_id()})


class ExternalNetworkIfaceObjectTestCase(
        obj_test_base.BaseObjectIfaceTestCase):

    _test_class = network.ExternalNetwork


class ExternalNetworkDbObjectTestCase(obj_test_base.BaseDbObjectTestCase,
                                      testlib_api.SqlTestCase):

    _test_class = network.ExternalNetwork

    def setUp(self):
        super().setUp()
        self.update_obj_fields(
            {'network_id': lambda: self._create_test_network_id()})
