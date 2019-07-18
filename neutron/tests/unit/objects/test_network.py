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

import random

import mock

from neutron.db import rbac_db_models
from neutron.objects import base as obj_base
from neutron.objects import network
from neutron.objects.qos import binding
from neutron.objects.qos import policy
from neutron.tests.unit.objects import test_base as obj_test_base
from neutron.tests.unit.objects import test_rbac
from neutron.tests.unit import testlib_api


class _NetworkRBACBase(object):

    def get_random_object_fields(self, obj_cls=None):
        fields = (super(_NetworkRBACBase, self).
                  get_random_object_fields(obj_cls))
        rnd_actions = self._test_class.db_model.get_valid_actions()
        idx = random.randint(0, len(rnd_actions) - 1)
        fields['action'] = rnd_actions[idx]
        return fields


class NetworkRBACDbObjectTestCase(_NetworkRBACBase,
                                  obj_test_base.BaseDbObjectTestCase,
                                  testlib_api.SqlTestCase):

    _test_class = network.NetworkRBAC

    def setUp(self):
        self._mock_get_valid_actions = mock.patch.object(
            rbac_db_models.NetworkRBAC, 'get_valid_actions',
            return_value=(rbac_db_models.ACCESS_EXTERNAL,
                          rbac_db_models.ACCESS_SHARED))
        self.mock_get_valid_actions = self._mock_get_valid_actions.start()
        super(NetworkRBACDbObjectTestCase, self).setUp()
        for obj in self.db_objs:
            net_obj = network.Network(self.context, id=obj['object_id'])
            net_obj.create()

    def _create_test_network_rbac(self):
        self.objs[0].create()
        return self.objs[0]

    def test_object_version_degradation_1_1_to_1_0_no_id_no_project_id(self):
        network_rbac_obj = self._create_test_network_rbac()
        network_rbac_obj = network_rbac_obj.obj_to_primitive('1.0')
        self.assertNotIn('project_id',
                         network_rbac_obj['versioned_object.data'])
        self.assertNotIn('id', network_rbac_obj['versioned_object.data'])


class NetworkRBACIfaceOjectTestCase(_NetworkRBACBase,
                                    obj_test_base.BaseObjectIfaceTestCase):

    _test_class = network.NetworkRBAC

    def setUp(self):
        self._mock_get_valid_actions = mock.patch.object(
            rbac_db_models.NetworkRBAC, 'get_valid_actions',
            return_value=(rbac_db_models.ACCESS_EXTERNAL,
                          rbac_db_models.ACCESS_SHARED))
        self.mock_get_valid_actions = self._mock_get_valid_actions.start()
        super(NetworkRBACIfaceOjectTestCase, self).setUp()


class NetworkDhcpAgentBindingObjectIfaceTestCase(
        obj_test_base.BaseObjectIfaceTestCase):

    _test_class = network.NetworkDhcpAgentBinding


class NetworkDhcpAgentBindingDbObjectTestCase(
        obj_test_base.BaseDbObjectTestCase, testlib_api.SqlTestCase):

    _test_class = network.NetworkDhcpAgentBinding

    def setUp(self):
        super(NetworkDhcpAgentBindingDbObjectTestCase, self).setUp()
        self._network = self._create_test_network()

        self.update_obj_fields(
            {'network_id': self._network.id,
             'dhcp_agent_id': lambda: self._create_test_agent_id()})


class NetworkPortSecurityIfaceObjTestCase(
        obj_test_base.BaseObjectIfaceTestCase):
    _test_class = network.NetworkPortSecurity


class NetworkPortSecurityDbObjTestCase(obj_test_base.BaseDbObjectTestCase,
                                       testlib_api.SqlTestCase):
    _test_class = network.NetworkPortSecurity

    def setUp(self):
        super(NetworkPortSecurityDbObjTestCase, self).setUp()
        self.update_obj_fields({'id': lambda: self._create_test_network_id()})


class NetworkSegmentIfaceObjTestCase(obj_test_base.BaseObjectIfaceTestCase):
    _test_class = network.NetworkSegment

    def setUp(self):
        super(NetworkSegmentIfaceObjTestCase, self).setUp()
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
        super(NetworkSegmentDbObjTestCase, self).setUp()
        self.update_obj_fields(
            {'network_id': lambda: self._create_test_network_id()})

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
        super(NetworkObjectIfaceTestCase, self).setUp()
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


class SegmentHostMappingIfaceObjectTestCase(
        obj_test_base.BaseObjectIfaceTestCase):

    _test_class = network.SegmentHostMapping


class SegmentHostMappingDbObjectTestCase(obj_test_base.BaseDbObjectTestCase,
                                         testlib_api.SqlTestCase):

    _test_class = network.SegmentHostMapping

    def setUp(self):
        super(SegmentHostMappingDbObjectTestCase, self).setUp()
        self.update_obj_fields(
            {'segment_id': lambda: self._create_test_segment_id()})


class NetworkDNSDomainIfaceObjectTestcase(
        obj_test_base.BaseObjectIfaceTestCase):

    _test_class = network.NetworkDNSDomain


class NetworkDNSDomainDbObjectTestcase(obj_test_base.BaseDbObjectTestCase,
                                       testlib_api.SqlTestCase):

    _test_class = network.NetworkDNSDomain

    def setUp(self):
        super(NetworkDNSDomainDbObjectTestcase, self).setUp()
        self.update_obj_fields(
            {'network_id': lambda: self._create_test_network_id()})


class ExternalNetworkIfaceObjectTestCase(
        obj_test_base.BaseObjectIfaceTestCase):

    _test_class = network.ExternalNetwork


class ExternalNetworkDbObjectTestCase(obj_test_base.BaseDbObjectTestCase,
                                      testlib_api.SqlTestCase):

    _test_class = network.ExternalNetwork

    def setUp(self):
        super(ExternalNetworkDbObjectTestCase, self).setUp()
        self.update_obj_fields(
            {'network_id': lambda: self._create_test_network_id()})
