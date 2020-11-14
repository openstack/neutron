# Copyright 2022 Troila
# All rights reserved.
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


from neutron.objects import ndp_proxy
from neutron.tests.unit.objects import test_base
from neutron.tests.unit import testlib_api


class NDPProxyIfaceObjectTestCase(test_base.BaseObjectIfaceTestCase):

    _test_class = ndp_proxy.NDPProxy


class NDPProxyDbObjectTestCase(test_base.BaseDbObjectTestCase,
                               testlib_api.SqlTestCase):

    _test_class = ndp_proxy.NDPProxy

    def setUp(self):
        super(NDPProxyDbObjectTestCase, self).setUp()
        self.update_obj_fields(
            {'router_id': lambda: self._create_test_router_id(),
             'port_id': lambda: self._create_test_port_id()})


class RouterNDPProxyStateIfaceObjectTestCase(
        test_base.BaseObjectIfaceTestCase):

    _test_class = ndp_proxy.RouterNDPProxyState


class RouterNDPProxyStateDbObjectTestCase(test_base.BaseDbObjectTestCase,
                                          testlib_api.SqlTestCase):

    _test_class = ndp_proxy.RouterNDPProxyState

    def setUp(self):
        super(RouterNDPProxyStateDbObjectTestCase, self).setUp()
        self.update_obj_fields(
            {'router_id': lambda: self._create_test_router_id()})
