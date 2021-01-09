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

from unittest import mock

from neutron_lib import context
from neutron_lib.db import api as db_api
from neutron_lib.plugins import directory

from neutron.objects import address_group
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

    def _assert_object_received(self, ovotype, oid=None, event=None,
                                count=1):
        self.plugin.ovo_notifier.wait()
        match = 0
        for obj, evt in self.received:
            if isinstance(obj, ovotype):
                if (obj.id == oid or not oid) and (not event or event == evt):
                    match += 1
                    if count == 1:
                        return obj
        if count > 1:
            self.assertEqual(
                match, count,
                "Could not find match %s for OVO %s with ID %s in %s" %
                (match, ovotype, oid, self.received))
            return
        self.fail("Could not find OVO %s with ID %s or event %s in %s" %
                  (ovotype, oid, event, self.received))

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
                                         'remote_address_group_id': None,
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
        with db_api.CONTEXT_WRITER.using(self.ctx):
            self.plugin.create_security_group(
                self.ctx, {'security_group': {'tenant_id': 'test',
                                              'description': 'desc',
                                              'name': 'test'}})
            self.assertEqual([], self.received)

    def test_address_group_lifecycle(self):
        ag = self.plugin.create_address_group(self.ctx,
            {'address_group': {'project_id': self._tenant_id,
                               'name': 'an-address-group',
                               'description': 'An address group',
                               'addresses': ['10.0.0.1/32',
                                             '2001:db8::/32']}})
        self._assert_object_received(
            address_group.AddressGroup, ag['id'], 'updated', 2)
        self.plugin.update_address_group(self.ctx, ag['id'],
            {'address_group': {'name': 'an-address-group-other-name'}})
        self._assert_object_received(
            address_group.AddressGroup, ag['id'], 'updated', 3)
        self.plugin.add_addresses(self.ctx, ag['id'],
            {'addresses': ['10.0.0.2/32']})
        self._assert_object_received(
            address_group.AddressGroup, ag['id'], 'updated', 4)
        self.plugin.remove_addresses(self.ctx, ag['id'],
            {'addresses': ['10.0.0.1/32']})
        self._assert_object_received(
            address_group.AddressGroup, ag['id'], 'updated', 5)
        self.plugin.delete_address_group(self.ctx, ag['id'])
        self._assert_object_received(
            address_group.AddressGroup, ag['id'], 'deleted')
