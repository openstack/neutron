# Copyright (c) 2016 Intel Corporation.
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

from neutron.objects.plugins.ml2 import vxlanallocation as vxlan_obj
from neutron.tests.unit.objects.plugins.ml2 import test_base as ml2_test_base
from neutron.tests.unit.objects import test_base
from neutron.tests.unit import testlib_api


class VxlanAllocationIfaceObjTestCase(test_base.BaseObjectIfaceTestCase):

    _test_class = vxlan_obj.VxlanAllocation


class VxlanAllocationDbObjTestCase(
        test_base.BaseDbObjectTestCase, testlib_api.SqlTestCase,
        ml2_test_base.SegmentAllocationDbObjTestCase):

    _test_class = vxlan_obj.VxlanAllocation


class VxlanEndpointIfaceObjTestCase(test_base.BaseObjectIfaceTestCase):

    _test_class = vxlan_obj.VxlanEndpoint


class VxlanEndpointDbObjTestCase(test_base.BaseDbObjectTestCase,
                                 testlib_api.SqlTestCase):

    _test_class = vxlan_obj.VxlanEndpoint
