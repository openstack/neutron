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
from oslo_utils import uuidutils

from neutron.agent.l3 import dvr_snat_ns
from neutron.agent.l3 import namespace_manager
from neutron.agent.l3 import namespaces
from neutron.agent.linux import ip_lib
from neutron.tests.functional import base

_uuid = uuidutils.generate_uuid


class NamespaceManagerTestFramework(base.BaseSudoTestCase):

    def setUp(self):
        super(NamespaceManagerTestFramework, self).setUp()
        self.agent_conf = mock.MagicMock()
        self.agent_conf.router_delete_namespaces = True
        self.metadata_driver_mock = mock.Mock()
        self.namespace_manager = namespace_manager.NamespaceManager(
            self.agent_conf, driver=None, clean_stale=True,
            metadata_driver=self.metadata_driver_mock)

    def _create_namespace(self, router_id, ns_class):
        namespace = ns_class(router_id, self.agent_conf, driver=None,
                             use_ipv6=False)
        namespace.create()
        self.addCleanup(self._delete_namespace, namespace)
        return namespace.name

    def _delete_namespace(self, namespace):
        try:
            namespace.delete()
        except RuntimeError as e:
            # If the namespace didn't exist when delete was attempted, mission
            # accomplished. Otherwise, re-raise the exception
            if 'No such file or directory' not in str(e):
                raise e

    def _namespace_exists(self, namespace):
        ip = ip_lib.IPWrapper(namespace=namespace)
        return ip.netns.exists(namespace)


class NamespaceManagerTestCase(NamespaceManagerTestFramework):

    def test_namespace_manager(self):
        router_id = _uuid()
        router_id_to_delete = _uuid()
        to_keep = set()
        to_delete = set()
        to_retrieve = set()
        to_keep.add(self._create_namespace(router_id,
                                           namespaces.RouterNamespace))
        to_keep.add(self._create_namespace(router_id,
                                           dvr_snat_ns.SnatNamespace))
        to_delete.add(self._create_namespace(router_id_to_delete,
                                             dvr_snat_ns.SnatNamespace))
        to_retrieve = to_keep | to_delete

        with mock.patch.object(namespace_manager.NamespaceManager, 'list_all',
                               return_value=to_retrieve):
            with self.namespace_manager as ns_manager:
                for ns_name in to_keep:
                    id_to_keep = ns_manager.get_prefix_and_id(ns_name)[1]
                    ns_manager.keep_router(id_to_keep)

        for ns_name in to_keep:
            self.assertTrue(self._namespace_exists(ns_name))
        for ns_name in to_delete:
            (self.metadata_driver_mock.destroy_monitored_metadata_proxy.
             assert_called_once_with(mock.ANY,
                                     router_id_to_delete,
                                     self.agent_conf))
            self.assertFalse(self._namespace_exists(ns_name))
