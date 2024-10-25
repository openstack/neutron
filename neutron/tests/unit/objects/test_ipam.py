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

from neutron.objects import ipam
from neutron.tests.unit.objects import test_base as obj_test_base
from neutron.tests.unit import testlib_api


class IpamSubnetObjectIfaceTestCase(obj_test_base.BaseObjectIfaceTestCase):

    _test_class = ipam.IpamSubnet


class IpamSubnetDbObjectTestCase(obj_test_base.BaseDbObjectTestCase,
                                 testlib_api.SqlTestCase):

    _test_class = ipam.IpamSubnet

    def setUp(self):
        super().setUp()
        self.update_obj_fields(
            {'neutron_subnet_id': lambda: self._create_test_subnet_id()})


class IpamAllocationPoolObjectIfaceTestCase(
        obj_test_base.BaseObjectIfaceTestCase):

    _test_class = ipam.IpamAllocationPool


class IpamAllocationPoolDbObjectTestCase(obj_test_base.BaseDbObjectTestCase,
                                         testlib_api.SqlTestCase):
    _test_class = ipam.IpamAllocationPool

    def setUp(self):
        super().setUp()
        self._create_test_ipam_subnet()
        self.update_obj_fields({'ipam_subnet_id': self._ipam_subnet['id']})

    def _create_test_ipam_subnet(self):
        attrs = self.get_random_object_fields(obj_cls=ipam.IpamSubnet)
        self._ipam_subnet = ipam.IpamSubnet(self.context, **attrs)
        self._ipam_subnet.create()


class IpamAllocationObjectIfaceTestCase(obj_test_base.BaseObjectIfaceTestCase):

    _test_class = ipam.IpamAllocation


class IpamAllocationDbObjectTestCase(obj_test_base.BaseDbObjectTestCase,
                                     testlib_api.SqlTestCase):

    _test_class = ipam.IpamAllocation

    def setUp(self):
        super().setUp()
        self._create_test_ipam_subnet()
        self.update_obj_fields({'ipam_subnet_id': self._ipam_subnet['id']})

    def _create_test_ipam_subnet(self):
        attrs = self.get_random_object_fields(obj_cls=ipam.IpamSubnet)
        self._ipam_subnet = ipam.IpamSubnet(self.context, **attrs)
        self._ipam_subnet.create()
