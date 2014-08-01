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

from neutron.api.v2 import attributes
from neutron.common import constants
from neutron.common import exceptions as n_exc
from neutron import context
from neutron import manager
from neutron.tests import base
from neutron.tests.unit import test_db_plugin
from neutron.tests.unit import testlib_api


class TestNetworks(base.BaseTestCase):
    def setUp(self):
        super(TestNetworks, self).setUp()
        self._tenant_id = 'test-tenant'

        # Update the plugin
        self.setup_coreplugin(test_db_plugin.DB_PLUGIN_KLASS)

    def _create_network(self, plugin, ctx, shared=True):
        network = {'network': {'name': 'net',
                               'shared': shared,
                               'admin_state_up': True,
                               'tenant_id': self._tenant_id}}
        created_network = plugin.create_network(ctx, network)
        return (network, created_network['id'])

    def _create_port(self, plugin, ctx, net_id, device_owner, tenant_id):
        port = {'port': {'name': 'port',
                         'network_id': net_id,
                         'mac_address': attributes.ATTR_NOT_SPECIFIED,
                         'fixed_ips': attributes.ATTR_NOT_SPECIFIED,
                         'admin_state_up': True,
                         'device_id': 'device_id',
                         'device_owner': device_owner,
                         'tenant_id': tenant_id}}
        plugin.create_port(ctx, port)

    def _test_update_shared_net_used(self,
                                     device_owner,
                                     expected_exception=None):
        plugin = manager.NeutronManager.get_plugin()
        ctx = context.get_admin_context()
        network, net_id = self._create_network(plugin, ctx)

        self._create_port(plugin,
                          ctx,
                          net_id,
                          device_owner,
                          self._tenant_id + '1')

        network['network']['shared'] = False

        if (expected_exception):
            with testlib_api.ExpectedException(expected_exception):
                plugin.update_network(ctx, net_id, network)
        else:
            plugin.update_network(ctx, net_id, network)

    def test_update_shared_net_used_fails(self):
        self._test_update_shared_net_used('', n_exc.InvalidSharedSetting)

    def test_update_shared_net_used_as_router_gateway(self):
        self._test_update_shared_net_used(
            constants.DEVICE_OWNER_ROUTER_GW)

    def test_update_shared_net_used_by_floating_ip(self):
        self._test_update_shared_net_used(
            constants.DEVICE_OWNER_FLOATINGIP)
