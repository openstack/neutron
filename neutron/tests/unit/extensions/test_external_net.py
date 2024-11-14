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

from neutron_lib.api import attributes
from neutron_lib.api.definitions import external_net as extnet_apidef
from neutron_lib.api.definitions import subnet as subnet_apidef
from neutron_lib.api.definitions import subnet_external_network as \
    extsnet_apidef
from neutron_lib import constants
from neutron_lib import context
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory
from oslo_utils import uuidutils
import testtools
from webob import exc

from neutron.tests.unit.api.v2 import test_base


# Add subnet 'router:external' extension, without loading the extensions.
# This change must be done before the policies are parsed in order to load the
# 'convert_to' method before the ``FieldCheck`` instance for this field is
# created.
rname = subnet_apidef.COLLECTION_NAME
attributes.RESOURCES[rname].update(
    extsnet_apidef.RESOURCE_ATTRIBUTE_MAP[rname])
from neutron.tests.common import test_db_base_plugin_v2  # noqa: E402


_uuid = uuidutils.generate_uuid
_get_path = test_base._get_path


class ExtNetTestExtensionManager:

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
        return super()._create_network(
            fmt, name, admin_state_up, arg_list=arg_list, **new_args)

    def setUp(self):
        plugin = 'neutron.tests.unit.extensions.test_l3.TestNoL3NatPlugin'
        ext_mgr = ExtNetTestExtensionManager()
        super().setUp(plugin=plugin, ext_mgr=ext_mgr)

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

    def test_create_shared_networks_and_subnets(self):
        with (self.network(as_admin=True, router__external=True) as net_ext,
                self.network(as_admin=True, shared=True) as net_shared,
                self.network(as_admin=True) as net_admin):
            with (self.subnet(as_admin=True, network=net_ext)
                  as snet_ext, self.subnet(as_admin=True, network=net_shared)
                  as snet_shared, self.subnet(as_admin=True, network=net_admin)
                  as snet_admin):
                req = self.new_list_request('networks', as_admin=False,
                                            tenant_id='noadmin')
                res = self.deserialize(self.fmt, req.get_response(self.api))
                net_ids = {net['id'] for net in res['networks']}
                self.assertIn(net_ext['network']['id'], net_ids)
                self.assertIn(net_shared['network']['id'], net_ids)
                self.assertNotIn(net_admin['network']['id'], net_ids)

                req = self.new_list_request('subnets', as_admin=False,
                                            tenant_id='noadmin')
                res = self.deserialize(self.fmt, req.get_response(self.api))
                snet_ids = {snet['id'] for snet in res['subnets']}
                self.assertIn(snet_ext['subnet']['id'], snet_ids)
                self.assertIn(snet_shared['subnet']['id'], snet_ids)
                self.assertNotIn(snet_admin['subnet']['id'], snet_ids)
