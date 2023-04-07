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

from unittest import mock

from neutron_lib.api.definitions import external_net as extnet_apidef
from neutron_lib import constants
from neutron_lib import context
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory
from oslo_utils import uuidutils
import testtools
from webob import exc

from neutron.db import external_net_db
from neutron.db import models_v2
from neutron.tests.unit.api.v2 import test_base
from neutron.tests.unit.db import test_db_base_plugin_v2


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
        new_args = dict(zip(map(lambda x: x.replace('__', ':'), kwargs),
                            kwargs.values()))
        arg_list = new_args.pop('arg_list', ()) + (extnet_apidef.EXTERNAL,)
        return super(ExtNetDBTestCase, self)._create_network(
            fmt, name, admin_state_up, arg_list=arg_list, **new_args)

    def setUp(self):
        plugin = 'neutron.tests.unit.extensions.test_l3.TestNoL3NatPlugin'
        ext_mgr = ExtNetTestExtensionManager()
        super(ExtNetDBTestCase, self).setUp(plugin=plugin, ext_mgr=ext_mgr)

    def _set_net_external(self, net_id):
        self._update('networks', net_id,
                     {'network': {extnet_apidef.EXTERNAL: True}},
                     as_admin=True)

    def test_list_nets_external(self):
        with self.network() as n1:
            self._set_net_external(n1['network']['id'])
            with self.network():
                body = self._list('networks')
                self.assertEqual(2, len(body['networks']))

                body = self._list('networks',
                                  query_params="%s=True" %
                                               extnet_apidef.EXTERNAL)
                self.assertEqual(1, len(body['networks']))

                body = self._list('networks',
                                  query_params="%s=False" %
                                               extnet_apidef.EXTERNAL)
                self.assertEqual(1, len(body['networks']))

    def test_list_nets_external_pagination(self):
        if self._skip_native_pagination:
            self.skipTest("Skip test for not implemented pagination feature")
        with self.network(name='net1') as n1, self.network(name='net3') as n3:
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
        plugin = directory.get_plugin()
        ctx = context.Context(None, None, is_admin=True)
        result = plugin.get_networks(ctx, filters=None)
        self.assertEqual([], result)

    def test_update_network_set_external_non_admin_fails(self):
        # Assert that a non-admin user cannot update the
        # router:external attribute
        with self.network(tenant_id='noadmin') as network:
            data = {'network': {'router:external': True}}
            req = self.new_update_request('networks',
                                          data,
                                          network['network']['id'],
                                          tenant_id='noadmin')
            res = req.get_response(self.api)
            self.assertEqual(exc.HTTPForbidden.code, res.status_int)

    def test_update_network_external_net_with_ports_set_not_shared(self):
        with self.network(router__external=True, shared=True,
                          as_admin=True) as ext_net,\
                self.subnet(network=ext_net) as ext_subnet, \
                self.port(subnet=ext_subnet,
                          tenant_id='',
                          device_owner=constants.DEVICE_OWNER_ROUTER_SNAT):
            data = {'network': {'shared': False}}
            req = self.new_update_request('networks',
                                          data,
                                          ext_net['network']['id'],
                                          as_admin=True)
            res = req.get_response(self.api)
            self.assertEqual(exc.HTTPOk.code, res.status_int)
            ctx = context.Context(None, None, is_admin=True)
            plugin = directory.get_plugin()
            result = plugin.get_networks(ctx)
            self.assertFalse(result[0]['shared'])

    def test_network_filter_hook_admin_context(self):
        ctx = context.Context(None, None, is_admin=True)
        model = models_v2.Network
        conditions = external_net_db._network_filter_hook(ctx, model, [])
        self.assertEqual([], conditions)

    def test_network_filter_hook_nonadmin_context(self):
        ctx = context.Context('edinson', 'cavani')
        model = models_v2.Network
        txt = ("networks.project_id = :project_id_1 OR "
               "networkrbacs.action = :action_1 AND "
               "networkrbacs.target_project = :target_project_1 OR "
               "networkrbacs.target_project = :target_project_2")
        conditions = external_net_db._network_filter_hook(ctx, model, [])
        self.assertEqual(conditions.__str__(), txt)
        # Try to concatenate conditions
        txt2 = (txt.replace('project_1', 'project_3').
                replace('project_2', 'project_4').
                replace('action_1', 'action_2').
                replace('project_id_1', 'project_id_2'))
        conditions = external_net_db._network_filter_hook(ctx, model,
                                                          conditions)
        self.assertEqual(conditions.__str__(), "%s OR %s" % (txt, txt2))

    def test_create_port_external_network_non_admin_fails(self):
        with self.network(as_admin=True, router__external=True) as ext_net:
            with self.subnet(network=ext_net) as ext_subnet:
                with testtools.ExpectedException(
                        exc.HTTPClientError) as ctx_manager:
                    with self.port(subnet=ext_subnet,
                                   is_admin=False,
                                   tenant_id='noadmin'):
                        pass
                    self.assertEqual(403, ctx_manager.exception.code)

    def test_create_port_external_network_admin_succeeds(self):
        with self.network(router__external=True, as_admin=True) as ext_net:
            with self.subnet(network=ext_net) as ext_subnet:
                with self.port(subnet=ext_subnet) as port:
                    self.assertEqual(port['port']['network_id'],
                                     ext_net['network']['id'])

    def test_create_external_network_non_admin_fails(self):
        with testtools.ExpectedException(exc.HTTPClientError) as ctx_manager:
            with self.network(router__external=True,
                              as_admin=False,
                              tenant_id='noadmin'):
                pass
            self.assertEqual(403, ctx_manager.exception.code)

    def test_create_external_network_admin_succeeds(self):
        with self.network(router__external=True, as_admin=True) as ext_net:
            self.assertTrue(ext_net['network'][extnet_apidef.EXTERNAL])

    def test_delete_network_check_disassociated_floatingips(self):
        l3_mock = mock.Mock()
        directory.add_plugin(plugin_constants.L3, l3_mock)
        with self.network() as net:
            req = self.new_delete_request('networks', net['network']['id'])
            res = req.get_response(self.api)
            self.assertEqual(exc.HTTPNoContent.code, res.status_int)
            (l3_mock.delete_disassociated_floatingips
             .assert_called_once_with(mock.ANY, net['network']['id']))
