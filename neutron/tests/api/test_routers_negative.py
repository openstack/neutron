# Copyright 2013 OpenStack Foundation
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

from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions as lib_exc
from tempest import test
import testtools

from neutron.tests.api import base_routers as base


class DvrRoutersNegativeTest(base.BaseRouterTest):

    @classmethod
    def skip_checks(cls):
        super(DvrRoutersNegativeTest, cls).skip_checks()
        if not test.is_extension_enabled('dvr', 'network'):
            msg = "DVR extension not enabled."
            raise cls.skipException(msg)

    @classmethod
    def resource_setup(cls):
        super(DvrRoutersNegativeTest, cls).resource_setup()
        cls.router = cls.create_router(data_utils.rand_name('router'))
        cls.network = cls.create_network()
        cls.subnet = cls.create_subnet(cls.network)

    @test.attr(type=['negative', 'smoke'])
    @test.idempotent_id('4990b055-8fc7-48ab-bba7-aa28beaad0b9')
    def test_router_create_tenant_distributed_returns_forbidden(self):
        with testtools.ExpectedException(lib_exc.Forbidden):
            self.create_router(
                data_utils.rand_name('router'), distributed=True)
