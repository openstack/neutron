# Copyright (c) 2015 OpenStack Foundation.
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

from oslo_utils import uuidutils

from neutron.objects import subnetpool
from neutron.tests.unit.objects import test_base as obj_test_base
from neutron.tests.unit import testlib_api


class SubnetPoolTestMixin(object):
    def _create_test_subnetpool(self):
        obj = subnetpool.SubnetPool(
            self.context,
            id=uuidutils.generate_uuid(),
            ip_version=4,
            default_prefixlen=24,
            min_prefixlen=0,
            max_prefixlen=32,
            shared=False)
        obj.create()
        return obj


class SubnetPoolIfaceObjectTestCase(obj_test_base.BaseObjectIfaceTestCase):

    _test_class = subnetpool.SubnetPool


class SubnetPoolDbObjectTestCase(obj_test_base.BaseDbObjectTestCase,
                                 testlib_api.SqlTestCase,
                                 SubnetPoolTestMixin):

    _test_class = subnetpool.SubnetPool

    def test_subnetpool_prefixes(self):
        pool = self._create_test_subnetpool()
        prefixes = obj_test_base.get_list_of_random_networks()
        pool.prefixes = prefixes
        pool.update()

        new_pool = self._test_class.get_object(self.context, id=pool.id)
        self.assertItemsEqual(prefixes, new_pool.prefixes)

        prefixes.pop()
        pool.prefixes = prefixes
        pool.update()

        new_pool = self._test_class.get_object(self.context, id=pool.id)
        self.assertItemsEqual(prefixes, new_pool.prefixes)

    def test_get_objects_queries_constant(self):
        # TODO(korzen) SubnetPool is using SubnetPoolPrefix object to reload
        # prefixes, which costs extra SQL query each time reload_prefixes
        # are called in get_object(s). SubnetPool has defined relationship
        # for SubnetPoolPrefixes, so it should be possible to reuse side loaded
        # values fo this. To be reworked in follow-up patch.
        pass


class SubnetPoolPrefixIfaceObjectTestCase(
        obj_test_base.BaseObjectIfaceTestCase):

    _test_class = subnetpool.SubnetPoolPrefix


class SubnetPoolPrefixDbObjectTestCase(
        obj_test_base.BaseDbObjectTestCase,
        testlib_api.SqlTestCase,
        SubnetPoolTestMixin):

    _test_class = subnetpool.SubnetPoolPrefix

    def setUp(self):
        super(SubnetPoolPrefixDbObjectTestCase, self).setUp()
        self.update_obj_fields(
            {'subnetpool_id': lambda: self._create_test_subnetpool().id})
