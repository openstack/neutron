# Copyright (c) 2014 Red Hat, Inc.
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

import copy
import os.path

from neutron import context
from neutron import policy

from neutron.api import extensions
from neutron.api.v2 import attributes

from neutron.tests import base

TEST_PATH = os.path.dirname(os.path.abspath(__file__))


class APIPolicyTestCase(base.BaseTestCase):
    """
    Tests for REST API policy checks. Ideally this would be done against an
    environment with an instantiated plugin, but there appears to be problems
    with instantiating a plugin against an sqlite environment and as yet, there
    is no precedent for running a functional test against an actual database
    backend.
    """

    api_version = "2.0"

    def setUp(self):
        super(APIPolicyTestCase, self).setUp()

        self.ATTRIBUTE_MAP_COPY = copy.copy(attributes.RESOURCE_ATTRIBUTE_MAP)
        self.extension_path = os.path.abspath(os.path.join(
            TEST_PATH, "../../../extensions"))
        policy.reset()

    def _network_definition(self):
        return {'name': 'test_network',
                'ports': [],
                'subnets': [],
                'status': 'up',
                'admin_state_up': True,
                'shared': False,
                'tenant_id': 'admin',
                'id': 'test_network',
                'router:external': True}

    def _check_external_router_policy(self, context):
        return policy.check(context, 'get_network', self._network_definition())

    def test_premature_loading(self):
        """
        Verifies that loading policies by way of admin context before
        populating extensions and extending the resource map results in
        networks with router:external is true being invisible to regular
        tenants.
        """
        extension_manager = extensions.ExtensionManager(self.extension_path)
        admin_context = context.get_admin_context()
        tenant_context = context.Context('test_user', 'test_tenant_id', False)
        extension_manager.extend_resources(self.api_version,
                                           attributes.RESOURCE_ATTRIBUTE_MAP)
        self.assertEqual(self._check_external_router_policy(admin_context),
                         True)
        self.assertEqual(self._check_external_router_policy(tenant_context),
                         False)

    def test_proper_load_order(self):
        """
        Verifies that loading policies by way of admin context after
        populating extensions and extending the resource map results in
        networks with router:external are visible to regular tenants.
        """
        extension_manager = extensions.ExtensionManager(self.extension_path)
        extension_manager.extend_resources(self.api_version,
                                           attributes.RESOURCE_ATTRIBUTE_MAP)
        admin_context = context.get_admin_context()
        tenant_context = context.Context('test_user', 'test_tenant_id', False)
        self.assertEqual(self._check_external_router_policy(admin_context),
                         True)
        self.assertEqual(self._check_external_router_policy(tenant_context),
                         True)

    def tearDown(self):
        if self.ATTRIBUTE_MAP_COPY:
            attributes.RESOURCE_ATTRIBUTE_MAP = self.ATTRIBUTE_MAP_COPY
        super(APIPolicyTestCase, self).tearDown()
