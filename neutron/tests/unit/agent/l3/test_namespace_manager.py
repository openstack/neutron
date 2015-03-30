# Copyright (c) 2015 Rackspace
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

import mock

from neutron.agent.l3 import dvr_snat_ns
from neutron.agent.l3 import namespace_manager
from neutron.agent.l3 import namespaces
from neutron.agent.linux import ip_lib
from neutron.openstack.common import uuidutils
from neutron.tests import base

_uuid = uuidutils.generate_uuid


class NamespaceManagerTestCaseFramework(base.BaseTestCase):

    def _create_namespace_manager(self):
        self.agent_conf = mock.Mock()
        self.driver = mock.Mock()
        return namespace_manager.NamespaceManager(self.agent_conf,
                                                  self.driver, True)


class TestNamespaceManager(NamespaceManagerTestCaseFramework):

    def test_get_prefix_and_id(self):
        ns_manager = self._create_namespace_manager()
        router_id = _uuid()

        ns_prefix, ns_id = ns_manager.get_prefix_and_id(
            namespaces.NS_PREFIX + router_id)
        self.assertEqual(ns_prefix, namespaces.NS_PREFIX)
        self.assertEqual(ns_id, router_id)

        ns_prefix, ns_id = ns_manager.get_prefix_and_id(
            dvr_snat_ns.SNAT_NS_PREFIX + router_id)
        self.assertEqual(ns_prefix, dvr_snat_ns.SNAT_NS_PREFIX)
        self.assertEqual(ns_id, router_id)

        ns_name = 'dhcp-' + router_id
        self.assertIsNone(ns_manager.get_prefix_and_id(ns_name))

    def test_is_managed(self):
        ns_manager = self._create_namespace_manager()
        router_id = _uuid()

        router_ns_name = namespaces.NS_PREFIX + router_id
        self.assertTrue(ns_manager.is_managed(router_ns_name))
        router_ns_name = dvr_snat_ns.SNAT_NS_PREFIX + router_id
        self.assertTrue(ns_manager.is_managed(router_ns_name))
        self.assertFalse(ns_manager.is_managed('dhcp-' + router_id))

    def test_list_all(self):
        ns_manager = self._create_namespace_manager()
        ns_names = [namespaces.NS_PREFIX + _uuid(),
                    dvr_snat_ns.SNAT_NS_PREFIX + _uuid(),
                    'dhcp-' + _uuid(), ]

        # Test the normal path
        with mock.patch.object(ip_lib.IPWrapper, 'get_namespaces',
                               return_value=ns_names):
            retrieved_ns_names = ns_manager.list_all()
        self.assertEqual(len(ns_names) - 1, len(retrieved_ns_names))
        for i in range(len(retrieved_ns_names)):
            self.assertIn(ns_names[i], retrieved_ns_names)
        self.assertNotIn(ns_names[-1], retrieved_ns_names)

        # Test path where IPWrapper raises exception
        with mock.patch.object(ip_lib.IPWrapper, 'get_namespaces',
                               side_effect=RuntimeError):
            retrieved_ns_names = ns_manager.list_all()
        self.assertFalse(retrieved_ns_names)
