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
from operator import itemgetter

from oslo_utils import uuidutils

from neutron import context
from neutron.db import rbac_db_models
from neutron.objects import base as obj_base
from neutron.objects.db import api as obj_db_api
from neutron.objects import subnet
from neutron.tests.unit.objects import test_base as obj_test_base
from neutron.tests.unit import testlib_api


class IPAllocationPoolObjectIfaceTestCase(
    obj_test_base.BaseObjectIfaceTestCase):

    _test_class = subnet.IPAllocationPool


class IPAllocationPoolDbObjectTestCase(obj_test_base.BaseDbObjectTestCase,
                                       testlib_api.SqlTestCase):

    _test_class = subnet.IPAllocationPool

    def setUp(self):
        super(IPAllocationPoolDbObjectTestCase, self).setUp()
        self._create_test_network()
        self._create_test_subnet(self._network)
        for obj in itertools.chain(self.db_objs, self.obj_fields):
            obj['subnet_id'] = self._subnet['id']


class DNSNameServerObjectIfaceTestCase(obj_test_base.BaseObjectIfaceTestCase):

    _test_class = subnet.DNSNameServer

    def setUp(self):
        super(DNSNameServerObjectIfaceTestCase, self).setUp()
        self.pager_map[self._test_class.obj_name()] = (
            obj_base.Pager(sorts=[('order', True)]))


class DNSNameServerDbObjectTestCase(obj_test_base.BaseDbObjectTestCase,
                                    testlib_api.SqlTestCase):

    _test_class = subnet.DNSNameServer

    def setUp(self):
        super(DNSNameServerDbObjectTestCase, self).setUp()
        # (NOTE) If two object have the same value for a field and
        # they are sorted using that field, the order is not deterministic.
        # To avoid breaking the tests we ensure unique values for every field
        while not self._is_objects_unique():
            self.db_objs = list(self.get_random_fields() for _ in range(3))
        self.obj_fields = [self._test_class.modify_fields_from_db(db_obj)
                           for db_obj in self.db_objs]
        self._create_test_network()
        self._create_test_subnet(self._network)
        for obj in itertools.chain(self.db_objs, self.obj_fields):
            obj['subnet_id'] = self._subnet['id']

    def _is_objects_unique(self):
        order_set = set([x['order'] for x in self.db_objs])
        subnet_id_set = set([x['subnet_id'] for x in self.db_objs])
        address_set = set([x['address'] for x in self.db_objs])
        return 3 == len(order_set) == len(subnet_id_set) == len(address_set)

    def _create_dnsnameservers(self):
        for obj in self.obj_fields:
            dns = self._make_object(obj)
            dns.create()

    def test_get_objects_sort_by_order_asc(self):
        self._create_dnsnameservers()
        objs = self._test_class.get_objects(self.context)
        fields_sorted = sorted([dict(obj) for obj in self.obj_fields],
                               key=itemgetter('order'))
        self.assertEqual(
            fields_sorted,
            [obj_test_base.get_obj_db_fields(obj) for obj in objs])

    def test_get_objects_sort_by_order_desc(self):
        self._create_dnsnameservers()
        pager = obj_base.Pager(sorts=[('order', False)])
        objs = self._test_class.get_objects(self.context, _pager=pager,
                                            subnet_id=self._subnet.id)
        fields_sorted = sorted([dict(obj) for obj in self.obj_fields],
                               key=itemgetter('order'), reverse=True)
        self.assertEqual(
            fields_sorted,
            [obj_test_base.get_obj_db_fields(obj) for obj in objs])

    def test_get_objects_sort_by_address_asc_using_pager(self):
        self._create_dnsnameservers()
        pager = obj_base.Pager(sorts=[('address', True)])
        objs = self._test_class.get_objects(self.context, _pager=pager)
        fields_sorted = sorted([dict(obj) for obj in self.obj_fields],
                               key=itemgetter('address'))
        self.assertEqual(
            fields_sorted,
            [obj_test_base.get_obj_db_fields(obj) for obj in objs])


class RouteObjectIfaceTestCase(obj_test_base.BaseObjectIfaceTestCase):

    _test_class = subnet.Route


class RouteDbObjectTestCase(obj_test_base.BaseDbObjectTestCase,
                            testlib_api.SqlTestCase):

    _test_class = subnet.Route

    def setUp(self):
        super(RouteDbObjectTestCase, self).setUp()
        self._create_test_network()
        self._create_test_subnet(self._network)
        for obj in itertools.chain(self.db_objs, self.obj_fields):
            obj['subnet_id'] = self._subnet['id']


class SubnetObjectIfaceTestCase(obj_test_base.BaseObjectIfaceTestCase):

    _test_class = subnet.Subnet

    def setUp(self):
        super(SubnetObjectIfaceTestCase, self).setUp()
        self.pager_map[subnet.DNSNameServer.obj_name()] = (
            obj_base.Pager(sorts=[('order', True)]))


class SubnetDbObjectTestCase(obj_test_base.BaseDbObjectTestCase,
                             testlib_api.SqlTestCase):

    _test_class = subnet.Subnet

    def setUp(self):
        super(SubnetDbObjectTestCase, self).setUp()
        self._create_test_network()
        self._create_test_segment(self._network)
        for obj in itertools.chain(self.db_objs, self.obj_fields):
            obj['network_id'] = self._network['id']
            obj['segment_id'] = self._segment['id']

    def test_get_dns_nameservers_in_order(self):
        obj = self._make_object(self.obj_fields[0])
        obj.create()
        dns_nameservers = [(2, '1.2.3.4'), (1, '5.6.7.8'), (4, '7.7.7.7')]
        for order, address in dns_nameservers:
            dns = subnet.DNSNameServer(self.context, order=order,
                                       address=address,
                                       subnet_id=obj.id)
            dns.create()

        new = self._test_class.get_object(self.context, id=obj.id)
        self.assertEqual(1, new.dns_nameservers[0].order)
        self.assertEqual(2, new.dns_nameservers[1].order)
        self.assertEqual(4, new.dns_nameservers[-1].order)

    def _create_shared_network_rbac_entry(self, network):
        attrs = {
            'object_id': network['id'],
            'target_tenant': '*',
            'action': rbac_db_models.ACCESS_SHARED
        }
        obj_db_api.create_object(self.context, rbac_db_models.NetworkRBAC,
                                 attrs)

    def test_get_subnet_shared_true(self):
        network = self._create_network()
        self._create_shared_network_rbac_entry(network)
        subnet_data = dict(self.obj_fields[0])
        subnet_data['network_id'] = network['id']

        obj = self._make_object(subnet_data)
        # check if shared will be load by 'obj_load_attr' and using extra query
        # by RbacNeutronDbObjectMixin get_shared_with_tenant
        self.assertTrue(obj.shared)
        obj.create()
        # here the shared should be load by is_network_shared
        self.assertTrue(obj.shared)

        new = self._test_class.get_object(self.context,
                                          **obj._get_composite_keys())
        # again, the shared should be load by is_network_shared
        self.assertTrue(new.shared)

    def test_filter_by_shared(self):
        network = self._create_network()
        self._create_shared_network_rbac_entry(network)

        subnet_data = dict(self.obj_fields[0])
        subnet_data['network_id'] = network['id']
        obj = self._make_object(subnet_data)
        obj.create()

        result = self._test_class.get_objects(self.context, shared=True)

        self.assertEqual(obj, result[0])

    def test_get_shared_subnet_with_another_tenant(self):
        network_shared = self._create_network()
        self._create_shared_network_rbac_entry(network_shared)

        subnet_data = dict(self.obj_fields[0])
        subnet_data['network_id'] = network_shared['id']
        shared_subnet = self._make_object(subnet_data)
        shared_subnet.create()

        priv_subnet = self._make_object(self.obj_fields[1])
        priv_subnet.create()

        # Situation here:
        #   - we have one network with a subnet that are private
        #   - shared network with its subnet
        # creating new context, user should have access to one shared network

        all_subnets = self._test_class.get_objects(self.context)
        self.assertEqual(2, len(all_subnets))

        # access with new tenant_id, should be able to access to one subnet
        new_ctx = context.Context('', uuidutils.generate_uuid())
        public_subnets = self._test_class.get_objects(new_ctx)
        self.assertEqual([shared_subnet], public_subnets)

        # test get_object to fetch the private and then the shared subnet
        fetched_private_subnet = self._test_class.get_object(new_ctx,
                                                             id=priv_subnet.id)
        self.assertIsNone(fetched_private_subnet)

        fetched_public_subnet = (
            self._test_class.get_object(new_ctx, id=shared_subnet.id))
        self.assertEqual(shared_subnet, fetched_public_subnet)
