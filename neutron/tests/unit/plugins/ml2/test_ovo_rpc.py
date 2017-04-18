#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import mock
from neutron_lib import context
from neutron_lib.plugins import directory

from neutron.objects import network
from neutron.objects import securitygroup
from neutron.objects import subnet
from neutron.plugins.ml2 import ovo_rpc
from neutron.tests.unit.plugins.ml2 import test_plugin


class OVOServerRpcInterfaceTestCase(test_plugin.Ml2PluginV2TestCase):

    def setUp(self):
        super(OVOServerRpcInterfaceTestCase, self).setUp()
        self.plugin = directory.get_plugin()
        self.ctx = context.get_admin_context()
        self.received = []
        receive = lambda s, ctx, obs, evt: self.received.append((obs[0], evt))
        mock.patch('neutron.api.rpc.handlers.resources_rpc.'
                   'ResourcesPushRpcApi.push', new=receive).start()
        # base case blocks the handler
        self.ovo_push_interface_p.stop()
        self.plugin.ovo_notifier = ovo_rpc.OVOServerRpcInterface()

    def _assert_object_received(self, ovotype, oid=None, event=None):
        self.plugin.ovo_notifier.wait()
        for obj, evt in self.received:
            if isinstance(obj, ovotype):
                if (obj.id == oid or not oid) and (not event or event == evt):
                    return obj
        self.fail("Could not find OVO %s with ID %s in %s" %
                  (ovotype, oid, self.received))

    def test_network_lifecycle(self):
        with self.network() as n:
            self._assert_object_received(network.Network,
                                         n['network']['id'],
                                         'updated')
            self.plugin.delete_network(self.ctx, n['network']['id'])
            self._assert_object_received(network.Network,
                                         n['network']['id'],
                                         'deleted')

    def test_subnet_lifecycle(self):
        with self.subnet() as s:
            self._assert_object_received(subnet.Subnet,
                                         s['subnet']['id'],
                                         'updated')
            self.plugin.delete_subnet(self.ctx, s['subnet']['id'])
            self._assert_object_received(subnet.Subnet,
                                         s['subnet']['id'],
                                         'deleted')

    def test_securitygroup_and_rule_lifecycle(self):
        # making a network makes a default security group
        with self.network() as n:
            sg = self._assert_object_received(securitygroup.SecurityGroup,
                                              event='updated')
            self.assertEqual(sg.tenant_id, n['network']['tenant_id'])
            sgr = self.plugin.create_security_group_rule(self.ctx,
                {'security_group_rule': {'security_group_id': sg.id,
                                         'tenant_id': sg.tenant_id,
                                         'port_range_min': None,
                                         'port_range_max': None,
                                         'remote_ip_prefix': None,
                                         'remote_group_id': None,
                                         'protocol': None,
                                         'direction': None,
                                         'ethertype': 'IPv4'}})
            self._assert_object_received(
                securitygroup.SecurityGroupRule, sgr['id'], 'updated')
            self.plugin.delete_security_group_rule(self.ctx, sgr['id'])
            self._assert_object_received(
                securitygroup.SecurityGroupRule, sgr['id'], 'deleted')
            self.plugin.delete_security_group(self.ctx, sg.id)
            self._assert_object_received(securitygroup.SecurityGroup, sg.id,
                                         'deleted')

    def test_transaction_state_error_doesnt_notify(self):
        # running in a transaction should cause it to skip notification since
        # fresh reads aren't possible.
        with self.ctx.session.begin():
            self.plugin.create_security_group(
                self.ctx, {'security_group': {'tenant_id': 'test',
                                              'description': 'desc',
                                              'name': 'test'}})
            self.assertEqual([], self.received)
