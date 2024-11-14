# Copyright (c) 2020 Red Hat, Inc.
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

import ddt
from neutron_lib.api.definitions import port_numa_affinity_policy_socket as \
    apidef
from neutron_lib import constants

from neutron.tests.common import test_db_base_plugin_v2
from neutron.tests.unit.extensions import test_port_numa_affinity_policy


TESTED_POLICIES = constants.PORT_NUMA_POLICIES


class PortNumaAffinityPolicySocketExtensionTestPlugin(
        test_port_numa_affinity_policy.
        PortNumaAffinityPolicyExtensionTestPlugin):
    """Test plugin to mixin the port NUMA affinity policy socket extension."""
    supported_extension_aliases = [apidef.ALIAS]


@ddt.ddt
class PortNumaAffinityPolicySocketExtensionTestCase(
         test_db_base_plugin_v2.NeutronDbPluginV2TestCase):
    """Test API extension numa_affinity_policy_socket attributes."""

    def setUp(self, *args):
        plugin = (
            'neutron.tests.unit.extensions.test_port_numa_affinity_policy_'
            'socket.PortNumaAffinityPolicySocketExtensionTestPlugin')
        super().setUp(plugin=plugin)

    def _create_and_check_port_nap(self, numa_affinity_policy):
        name = 'numa_affinity_policy'
        keys = [('name', name), ('admin_state_up', True),
                ('status', self.port_create_status),
                ('numa_affinity_policy', numa_affinity_policy)]
        with self.port(name=name,
                       numa_affinity_policy=numa_affinity_policy) as port:
            for k, v in keys:
                self.assertEqual(v, port['port'][k])
        return port

    def _update_and_check_port_nap(self, port, numa_affinity_policy):
        data = {'port': {'numa_affinity_policy': numa_affinity_policy}}
        req = self.new_update_request('ports', data,
                                      port['port']['id'])
        res = self.deserialize(self.fmt, req.get_response(self.api))
        self.assertEqual(numa_affinity_policy,
                         res['port']['numa_affinity_policy'])

    @ddt.data(*TESTED_POLICIES, None)
    def test_create_and_update_port_numa_affinity_policy(self,
                                                         numa_affinity_policy):
        port = self._create_and_check_port_nap(numa_affinity_policy)
        for new_nap in (*TESTED_POLICIES, None):
            self._update_and_check_port_nap(port, new_nap)
