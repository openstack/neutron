# Copyright (c) 2013 OpenStack Foundation.
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

import contextlib
import itertools

import mock
from oslo_log import log as logging
import testtools
from webob import exc

from neutron import context
from neutron.db import models_v2
from neutron.extensions import external_net as external_net
from neutron import manager
from neutron.openstack.common import uuidutils
from neutron.tests.unit.api.v2 import test_base
from neutron.tests.unit.db import test_db_base_plugin_v2


LOG = logging.getLogger(__name__)

_uuid = uuidutils.generate_uuid
_get_path = test_base._get_path


class ExtNetTestExtensionManager(object):

    def get_resources(self):
        return []

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


class ExtNetDBTestCase(test_db_base_plugin_v2.NeutronDbPluginV2TestCase):

    def _create_network(self, fmt, name, admin_state_up, **kwargs):
        """Override the routine for allowing the router:external attribute."""
        # attributes containing a colon should be passed with
        # a double underscore
        new_args = dict(itertools.izip(map(lambda x: x.replace('__', ':'),
                                           kwargs),
                                       kwargs.values()))
        arg_list = new_args.pop('arg_list', ()) + (external_net.EXTERNAL,)
        return super(ExtNetDBTestCase, self)._create_network(
            fmt, name, admin_state_up, arg_list=arg_list, **new_args)

    def setUp(self):
        plugin = 'neutron.tests.unit.extensions.test_l3.TestNoL3NatPlugin'
        ext_mgr = ExtNetTestExtensionManager()
        super(ExtNetDBTestCase, self).setUp(plugin=plugin, ext_mgr=ext_mgr)

    def _set_net_external(self, net_id):
        self._update('networks', net_id,
                     {'network': {external_net.EXTERNAL: True}})

    def test_list_nets_external(self):
        with self.network() as n1:
            self._set_net_external(n1['network']['id'])
            with self.network():
                body = self._list('networks')
                self.assertEqual(len(body['networks']), 2)

                body = self._list('networks',
                                  query_params="%s=True" %
                                               external_net.EXTERNAL)
                self.assertEqual(len(body['networks']), 1)

                body = self._list('networks',
                                  query_params="%s=False" %
                                               external_net.EXTERNAL)
                self.assertEqual(len(body['networks']), 1)

    def test_list_nets_external_pagination(self):
        if self._skip_native_pagination:
            self.skipTest("Skip test for not implemented pagination feature")
        with contextlib.nested(self.network(name='net1'),
                               self.network(name='net3')) as (n1, n3):
            self._set_net_external(n1['network']['id'])
            self._set_net_external(n3['network']['id'])
            with self.network(name='net2') as n2:
                self._test_list_with_pagination(
                    'network', (n1, n3), ('name', 'asc'), 1, 3,
                    query_params='router:external=True')
                self._test_list_with_pagination(
                    'network', (n2, ), ('name', 'asc'), 1, 2,
                    query_params='router:external=False')

    def test_get_network_succeeds_without_filter(self):
        plugin = manager.NeutronManager.get_plugin()
        ctx = context.Context(None, None, is_admin=True)
        result = plugin.get_networks(ctx, filters=None)
        self.assertEqual(result, [])

    def test_update_network_set_external_non_admin_fails(self):
        # Assert that a non-admin user cannot update the
        # router:external attribute
        with self.network(tenant_id='noadmin') as network:
            data = {'network': {'router:external': True}}
            req = self.new_update_request('networks',
                                          data,
                                          network['network']['id'])
            req.environ['neutron.context'] = context.Context('', 'noadmin')
            res = req.get_response(self.api)
            self.assertEqual(exc.HTTPForbidden.code, res.status_int)

    def test_network_filter_hook_admin_context(self):
        plugin = manager.NeutronManager.get_plugin()
        ctx = context.Context(None, None, is_admin=True)
        model = models_v2.Network
        conditions = plugin._network_filter_hook(ctx, model, [])
        self.assertEqual(conditions, [])

    def test_network_filter_hook_nonadmin_context(self):
        plugin = manager.NeutronManager.get_plugin()
        ctx = context.Context('edinson', 'cavani')
        model = models_v2.Network
        txt = "externalnetworks.network_id IS NOT NULL"
        conditions = plugin._network_filter_hook(ctx, model, [])
        self.assertEqual(conditions.__str__(), txt)
        # Try to concatenate conditions
        conditions = plugin._network_filter_hook(ctx, model, conditions)
        self.assertEqual(conditions.__str__(), "%s OR %s" % (txt, txt))

    def test_create_port_external_network_non_admin_fails(self):
        with self.network(router__external=True) as ext_net:
            with self.subnet(network=ext_net) as ext_subnet:
                with testtools.ExpectedException(
                        exc.HTTPClientError) as ctx_manager:
                    with self.port(subnet=ext_subnet,
                                   set_context='True',
                                   tenant_id='noadmin'):
                        pass
                    self.assertEqual(ctx_manager.exception.code, 403)

    def test_create_port_external_network_admin_succeeds(self):
        with self.network(router__external=True) as ext_net:
            with self.subnet(network=ext_net) as ext_subnet:
                with self.port(subnet=ext_subnet) as port:
                    self.assertEqual(port['port']['network_id'],
                                     ext_net['network']['id'])

    def test_create_external_network_non_admin_fails(self):
        with testtools.ExpectedException(exc.HTTPClientError) as ctx_manager:
            with self.network(router__external=True,
                              set_context='True',
                              tenant_id='noadmin'):
                pass
            self.assertEqual(ctx_manager.exception.code, 403)

    def test_create_external_network_admin_succeeds(self):
        with self.network(router__external=True) as ext_net:
            self.assertEqual(ext_net['network'][external_net.EXTERNAL],
                             True)

    def test_delete_network_check_disassociated_floatingips(self):
        with mock.patch.object(manager.NeutronManager,
                               'get_service_plugins') as srv_plugins:
            l3_mock = mock.Mock()
            srv_plugins.return_value = {'L3_ROUTER_NAT': l3_mock}
            with self.network() as net:
                req = self.new_delete_request('networks', net['network']['id'])
                res = req.get_response(self.api)
                self.assertEqual(res.status_int, exc.HTTPNoContent.code)
                (l3_mock.delete_disassociated_floatingips
                 .assert_called_once_with(mock.ANY, net['network']['id']))
