# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 Nicira Networks, Inc.  All rights reserved.
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
#
# @author: Dan Wendlandt, Nicira, Inc
#

import contextlib
import copy
import itertools
import logging
import unittest

import mock
from webob import exc
import webtest

from quantum.api import extensions
from quantum.api.v2 import attributes
from quantum.common import config
from quantum.common import exceptions as q_exc
from quantum.common.test_lib import test_config
from quantum import context
from quantum.db import db_base_plugin_v2
from quantum.db import l3_db
from quantum.db import models_v2
from quantum.extensions import l3
from quantum import manager
from quantum.openstack.common import cfg
from quantum.openstack.common import uuidutils
from quantum.tests.unit import test_api_v2
from quantum.tests.unit import test_db_plugin
from quantum.tests.unit import test_extensions


LOG = logging.getLogger(__name__)

_uuid = uuidutils.generate_uuid
_get_path = test_api_v2._get_path


class L3TestExtensionManager(object):

    def get_resources(self):
        return l3.L3.get_resources()

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


class L3NatExtensionTestCase(unittest.TestCase):

    def setUp(self):

        plugin = 'quantum.extensions.l3.RouterPluginBase'

        # Ensure 'stale' patched copies of the plugin are never returned
        manager.QuantumManager._instance = None

        # Ensure existing ExtensionManager is not used
        extensions.PluginAwareExtensionManager._instance = None

        # Save the global RESOURCE_ATTRIBUTE_MAP
        self.saved_attr_map = {}
        for resource, attrs in attributes.RESOURCE_ATTRIBUTE_MAP.iteritems():
            self.saved_attr_map[resource] = attrs.copy()

        # Create the default configurations
        args = ['--config-file', test_api_v2.etcdir('quantum.conf.test')]
        config.parse(args=args)

        # Update the plugin and extensions path
        cfg.CONF.set_override('core_plugin', plugin)

        self._plugin_patcher = mock.patch(plugin, autospec=True)
        self.plugin = self._plugin_patcher.start()

        # Instantiate mock plugin and enable the 'router' extension
        manager.QuantumManager.get_plugin().supported_extension_aliases = (
            ["router"])

        ext_mgr = L3TestExtensionManager()
        self.ext_mdw = test_extensions.setup_extensions_middleware(ext_mgr)
        self.api = webtest.TestApp(self.ext_mdw)

    def tearDown(self):
        self._plugin_patcher.stop()
        self.api = None
        self.plugin = None
        cfg.CONF.reset()

        # Restore the global RESOURCE_ATTRIBUTE_MAP
        attributes.RESOURCE_ATTRIBUTE_MAP = self.saved_attr_map

    def test_router_create(self):
        router_id = _uuid()
        data = {'router': {'name': 'router1', 'admin_state_up': True,
                           'tenant_id': _uuid(),
                           'external_gateway_info': None}}
        return_value = copy.deepcopy(data['router'])
        return_value.update({'status': "ACTIVE", 'id': router_id})

        instance = self.plugin.return_value
        instance.create_router.return_value = return_value
        instance.get_routers_count.return_value = 0

        res = self.api.post_json(_get_path('routers'), data)

        instance.create_router.assert_called_with(mock.ANY,
                                                  router=data)
        self.assertEqual(res.status_int, exc.HTTPCreated.code)
        self.assertTrue('router' in res.json)
        router = res.json['router']
        self.assertEqual(router['id'], router_id)
        self.assertEqual(router['status'], "ACTIVE")
        self.assertEqual(router['admin_state_up'], True)

    def test_router_list(self):
        router_id = _uuid()
        return_value = [{'name': 'router1', 'admin_state_up': True,
                         'tenant_id': _uuid(), 'id': router_id}]

        instance = self.plugin.return_value
        instance.get_routers.return_value = return_value

        res = self.api.get(_get_path('routers'))

        instance.get_routers.assert_called_with(mock.ANY, fields=mock.ANY,
                                                filters=mock.ANY)
        self.assertEqual(res.status_int, exc.HTTPOk.code)

    def test_router_update(self):
        router_id = _uuid()
        update_data = {'router': {'admin_state_up': False}}
        return_value = {'name': 'router1', 'admin_state_up': False,
                        'tenant_id': _uuid(),
                        'status': "ACTIVE", 'id': router_id}

        instance = self.plugin.return_value
        instance.update_router.return_value = return_value

        res = self.api.put_json(_get_path('routers', id=router_id),
                                update_data)

        instance.update_router.assert_called_with(mock.ANY, router_id,
                                                  router=update_data)
        self.assertEqual(res.status_int, exc.HTTPOk.code)
        self.assertTrue('router' in res.json)
        router = res.json['router']
        self.assertEqual(router['id'], router_id)
        self.assertEqual(router['status'], "ACTIVE")
        self.assertEqual(router['admin_state_up'], False)

    def test_router_get(self):
        router_id = _uuid()
        return_value = {'name': 'router1', 'admin_state_up': False,
                        'tenant_id': _uuid(),
                        'status': "ACTIVE", 'id': router_id}

        instance = self.plugin.return_value
        instance.get_router.return_value = return_value

        res = self.api.get(_get_path('routers', id=router_id))

        instance.get_router.assert_called_with(mock.ANY, router_id,
                                               fields=mock.ANY)
        self.assertEqual(res.status_int, exc.HTTPOk.code)
        self.assertTrue('router' in res.json)
        router = res.json['router']
        self.assertEqual(router['id'], router_id)
        self.assertEqual(router['status'], "ACTIVE")
        self.assertEqual(router['admin_state_up'], False)

    def test_router_delete(self):
        router_id = _uuid()

        res = self.api.delete(_get_path('routers', id=router_id))

        instance = self.plugin.return_value
        instance.delete_router.assert_called_with(mock.ANY, router_id)
        self.assertEqual(res.status_int, exc.HTTPNoContent.code)

    def test_router_add_interface(self):
        router_id = _uuid()
        subnet_id = _uuid()
        port_id = _uuid()

        interface_data = {'subnet_id': subnet_id}
        return_value = copy.deepcopy(interface_data)
        return_value['port_id'] = port_id

        instance = self.plugin.return_value
        instance.add_router_interface.return_value = return_value

        path = _get_path('routers', id=router_id,
                         action="add_router_interface")
        res = self.api.put_json(path, interface_data)

        instance.add_router_interface.assert_called_with(mock.ANY, router_id,
                                                         interface_data)
        self.assertEqual(res.status_int, exc.HTTPOk.code)
        self.assertTrue('port_id' in res.json)
        self.assertEqual(res.json['port_id'], port_id)
        self.assertEqual(res.json['subnet_id'], subnet_id)


# This plugin class is just for testing
class TestL3NatPlugin(db_base_plugin_v2.QuantumDbPluginV2,
                      l3_db.L3_NAT_db_mixin):
    supported_extension_aliases = ["router"]

    def create_network(self, context, network):
        session = context.session
        with session.begin(subtransactions=True):
            net = super(TestL3NatPlugin, self).create_network(context,
                                                              network)
            self._process_l3_create(context, network['network'], net['id'])
            self._extend_network_dict_l3(context, net)
        return net

    def update_network(self, context, id, network):

        session = context.session
        with session.begin(subtransactions=True):
            net = super(TestL3NatPlugin, self).update_network(context, id,
                                                              network)
            self._process_l3_update(context, network['network'], id)
            self._extend_network_dict_l3(context, net)
        return net

    def delete_network(self, context, id):
        session = context.session
        with session.begin(subtransactions=True):
            net = super(TestL3NatPlugin, self).delete_network(context, id)

    def get_network(self, context, id, fields=None):
        net = super(TestL3NatPlugin, self).get_network(context, id, None)
        self._extend_network_dict_l3(context, net)
        return self._fields(net, fields)

    def get_networks(self, context, filters=None, fields=None):
        nets = super(TestL3NatPlugin, self).get_networks(context, filters,
                                                         None)
        for net in nets:
            self._extend_network_dict_l3(context, net)
        nets = self._filter_nets_l3(context, nets, filters)

        return [self._fields(net, fields) for net in nets]

    def delete_port(self, context, id, l3_port_check=True):
        if l3_port_check:
            self.prevent_l3_port_deletion(context, id)
        self.disassociate_floatingips(context, id)
        return super(TestL3NatPlugin, self).delete_port(context, id)


class L3NatDBTestCase(test_db_plugin.QuantumDbPluginV2TestCase):

    def _create_network(self, fmt, name, admin_status_up, **kwargs):
        """ Override the routine for allowing the router:external attribute """
        # attributes containing a colon should be passed with
        # a double underscore
        new_args = dict(itertools.izip(map(lambda x: x.replace('__', ':'),
                                           kwargs),
                                       kwargs.values()))
        arg_list = (l3.EXTERNAL,)
        return super(L3NatDBTestCase, self)._create_network(fmt,
                                                            name,
                                                            admin_status_up,
                                                            arg_list=arg_list,
                                                            **new_args)

    def setUp(self):
        test_config['plugin_name_v2'] = (
            'quantum.tests.unit.test_l3_plugin.TestL3NatPlugin')
        # for these tests we need to enable overlapping ips
        cfg.CONF.set_default('allow_overlapping_ips', True)
        ext_mgr = L3TestExtensionManager()
        test_config['extension_manager'] = ext_mgr
        super(L3NatDBTestCase, self).setUp()

    def _create_router(self, fmt, tenant_id, name=None, admin_state_up=None):
        data = {'router': {'tenant_id': tenant_id}}
        if name:
            data['router']['name'] = name
        if admin_state_up:
            data['router']['admin_state_up'] = admin_state_up
        router_req = self.new_create_request('routers', data, fmt)
        return router_req.get_response(self.ext_api)

    def _add_external_gateway_to_router(self, router_id, network_id,
                                        expected_code=exc.HTTPOk.code):
        return self._update('routers', router_id,
                            {'router': {'external_gateway_info':
                                        {'network_id': network_id}}},
                            expected_code=expected_code)

    def _remove_external_gateway_from_router(self, router_id, network_id,
                                             expected_code=exc.HTTPOk.code):
        return self._update('routers', router_id,
                            {'router': {'external_gateway_info':
                                       {}}},
                            expected_code=expected_code)

    def _router_interface_action(self, action, router_id, subnet_id, port_id,
                                 expected_code=exc.HTTPOk.code):
        interface_data = {}
        if subnet_id:
            interface_data.update({'subnet_id': subnet_id})
        if port_id and (action != 'add' or not subnet_id):
            interface_data.update({'port_id': port_id})

        req = self.new_action_request('routers', interface_data, router_id,
                                      "%s_router_interface" % action)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, expected_code)
        return self.deserialize('json', res)

    @contextlib.contextmanager
    def router(self, name='router1', admin_status_up=True,
               fmt='json', tenant_id=_uuid()):
        res = self._create_router(fmt, tenant_id, name=name,
                                  admin_state_up=admin_status_up)
        router = self.deserialize(fmt, res)
        yield router
        self._delete('routers', router['router']['id'])

    def test_router_crd_ops(self):
        with self.router() as r:
            body = self._list('routers')
            self.assertEquals(len(body['routers']), 1)
            self.assertEquals(body['routers'][0]['id'], r['router']['id'])

            body = self._show('routers', r['router']['id'])
            self.assertEquals(body['router']['id'], r['router']['id'])
            self.assertEquals(body['router']['external_gateway_info'], None)

        # post-delete, check that it is really gone
        body = self._list('routers')
        self.assertEquals(len(body['routers']), 0)

        body = self._show('routers', r['router']['id'],
                          expected_code=exc.HTTPNotFound.code)

    def test_router_update(self):
        rname1 = "yourrouter"
        rname2 = "nachorouter"
        with self.router(name=rname1) as r:
            body = self._show('routers', r['router']['id'])
            self.assertEquals(body['router']['name'], rname1)

            body = self._update('routers', r['router']['id'],
                                {'router': {'name': rname2}})

            body = self._show('routers', r['router']['id'])
            self.assertEquals(body['router']['name'], rname2)

    def test_router_add_interface_subnet(self):
        with self.router() as r:
            with self.subnet() as s:
                body = self._router_interface_action('add',
                                                     r['router']['id'],
                                                     s['subnet']['id'],
                                                     None)
                self.assertTrue('port_id' in body)

                # fetch port and confirm device_id
                r_port_id = body['port_id']
                body = self._show('ports', r_port_id)
                self.assertEquals(body['port']['device_id'], r['router']['id'])

                body = self._router_interface_action('remove',
                                                     r['router']['id'],
                                                     s['subnet']['id'],
                                                     None)
                body = self._show('ports', r_port_id,
                                  expected_code=exc.HTTPNotFound.code)

    def test_router_add_interface_subnet_with_bad_tenant(self):
        with mock.patch('quantum.context.Context.to_dict') as tdict:
            tenant_id = _uuid()
            admin_context = {'roles': ['admin']}
            tenant_context = {'tenant_id': 'bad_tenant',
                              'roles': []}
            tdict.return_value = admin_context
            with self.router(tenant_id=tenant_id) as r:
                with self.network(tenant_id=tenant_id) as n:
                    with self.subnet(network=n) as s:
                        tdict.return_value = tenant_context
                        err_code = exc.HTTPNotFound.code
                        self._router_interface_action('add',
                                                      r['router']['id'],
                                                      s['subnet']['id'],
                                                      None,
                                                      err_code)
                        tdict.return_value = admin_context
                        body = self._router_interface_action('add',
                                                             r['router']['id'],
                                                             s['subnet']['id'],
                                                             None)
                        self.assertTrue('port_id' in body)
                        tdict.return_value = tenant_context
                        self._router_interface_action('remove',
                                                      r['router']['id'],
                                                      s['subnet']['id'],
                                                      None,
                                                      err_code)
                        tdict.return_value = admin_context
                        body = self._router_interface_action('remove',
                                                             r['router']['id'],
                                                             s['subnet']['id'],
                                                             None)

    def test_router_add_interface_subnet_with_port_from_other_tenant(self):
        tenant_id = _uuid()
        other_tenant_id = _uuid()
        tenant_context = context.Context(user_id=None, tenant_id=tenant_id)
        admin_context = context.get_admin_context()
        with mock.patch('quantum.context.Context') as ctx:
            ctx.return_value = admin_context
            with contextlib.nested(
                self.router(tenant_id=tenant_id),
                self.network(tenant_id=tenant_id),
                self.network(tenant_id=other_tenant_id)) as (r, n1, n2):
                with contextlib.nested(
                    self.subnet(network=n1, cidr='10.0.0.0/24'),
                    self.subnet(network=n2, cidr='10.1.0.0/24')) as (s1, s2):
                        ctx.return_value = admin_context
                        body = self._router_interface_action(
                            'add',
                            r['router']['id'],
                            s2['subnet']['id'],
                            None)
                        self.assertTrue('port_id' in body)
                        ctx.return_value = tenant_context
                        self._router_interface_action(
                            'add',
                            r['router']['id'],
                            s1['subnet']['id'],
                            None)
                        self.assertTrue('port_id' in body)
                        self._router_interface_action(
                            'remove',
                            r['router']['id'],
                            s1['subnet']['id'],
                            None)
                        ctx.return_value = admin_context
                        body = self._router_interface_action(
                            'remove',
                            r['router']['id'],
                            s2['subnet']['id'],
                            None)

    def test_router_add_interface_port(self):
        with self.router() as r:
            with self.port(no_delete=True) as p:
                body = self._router_interface_action('add',
                                                     r['router']['id'],
                                                     None,
                                                     p['port']['id'])
                self.assertTrue('port_id' in body)
                self.assertEquals(body['port_id'], p['port']['id'])

                # fetch port and confirm device_id
                body = self._show('ports', p['port']['id'])
                self.assertEquals(body['port']['device_id'], r['router']['id'])

                # clean-up
                self._router_interface_action('remove',
                                              r['router']['id'],
                                              None,
                                              p['port']['id'])

    def test_router_add_interface_port_bad_tenant(self):
        with mock.patch('quantum.context.Context.to_dict') as tdict:
            tenant_id = _uuid()
            admin_context = {'roles': ['admin']}
            tenant_context = {'tenant_id': 'bad_tenant',
                              'roles': []}
            tdict.return_value = admin_context
            with self.router() as r:
                with self.port(no_delete=True) as p:
                    tdict.return_value = tenant_context
                    err_code = exc.HTTPNotFound.code
                    body = self._router_interface_action('add',
                                                         r['router']['id'],
                                                         None,
                                                         p['port']['id'],
                                                         err_code)
                    tdict.return_value = admin_context
                    body = self._router_interface_action('add',
                                                         r['router']['id'],
                                                         None,
                                                         p['port']['id'])

                    tdict.return_value = tenant_context
                    # clean-up
                    self._router_interface_action('remove',
                                                  r['router']['id'],
                                                  None,
                                                  p['port']['id'],
                                                  err_code)

                    tdict.return_value = admin_context
                    self._router_interface_action('remove',
                                                  r['router']['id'],
                                                  None,
                                                  p['port']['id'])

    def test_router_add_interface_dup_subnet1(self):
        with self.router() as r:
            with self.subnet() as s:
                body = self._router_interface_action('add',
                                                     r['router']['id'],
                                                     s['subnet']['id'],
                                                     None)
                body = self._router_interface_action('add',
                                                     r['router']['id'],
                                                     s['subnet']['id'],
                                                     None,
                                                     expected_code=exc.
                                                     HTTPBadRequest.code)
                body = self._router_interface_action('remove',
                                                     r['router']['id'],
                                                     s['subnet']['id'],
                                                     None)

    def test_router_add_interface_dup_subnet2(self):
        with self.router() as r:
            with self.subnet() as s:
                with self.port(subnet=s, no_delete=True) as p1:
                    with self.port(subnet=s) as p2:
                        self._router_interface_action('add',
                                                      r['router']['id'],
                                                      None,
                                                      p1['port']['id'])
                        self._router_interface_action('add',
                                                      r['router']['id'],
                                                      None,
                                                      p2['port']['id'],
                                                      expected_code=exc.
                                                      HTTPBadRequest.code)
                        # clean-up
                        self._router_interface_action('remove',
                                                      r['router']['id'],
                                                      None,
                                                      p1['port']['id'])

    def test_router_add_gateway_dup_subnet1(self):
        with self.router() as r:
            with self.subnet() as s:
                body = self._router_interface_action('add',
                                                     r['router']['id'],
                                                     s['subnet']['id'],
                                                     None)
                self._set_net_external(s['subnet']['network_id'])
                self._add_external_gateway_to_router(
                    r['router']['id'],
                    s['subnet']['network_id'],
                    expected_code=exc.HTTPBadRequest.code)
                body = self._router_interface_action('remove',
                                                     r['router']['id'],
                                                     s['subnet']['id'],
                                                     None)

    def test_router_add_gateway_dup_subnet2(self):
        with self.router() as r:
            with self.subnet() as s:
                self._set_net_external(s['subnet']['network_id'])
                self._add_external_gateway_to_router(
                    r['router']['id'],
                    s['subnet']['network_id'])
                self._router_interface_action('add',
                                              r['router']['id'],
                                              s['subnet']['id'],
                                              None,
                                              expected_code=exc.
                                              HTTPBadRequest.code)
                self._remove_external_gateway_from_router(
                    r['router']['id'],
                    s['subnet']['network_id'])

    def test_router_add_interface_overlapped_cidr(self):
        with self.router() as r:
            with self.subnet(cidr='10.0.1.0/24') as s1:
                self._router_interface_action('add',
                                              r['router']['id'],
                                              s1['subnet']['id'],
                                              None)

                def try_overlapped_cidr(cidr):
                    with self.subnet(cidr=cidr) as s2:
                        self._router_interface_action('add',
                                                      r['router']['id'],
                                                      s2['subnet']['id'],
                                                      None,
                                                      expected_code=exc.
                                                      HTTPBadRequest.code)
                # another subnet with same cidr
                try_overlapped_cidr('10.0.1.0/24')
                # another subnet with overlapped cidr including s1
                try_overlapped_cidr('10.0.0.0/16')
                # another subnet with overlapped cidr included by s1
                try_overlapped_cidr('10.0.1.1/32')
                # clean-up
                self._router_interface_action('remove',
                                              r['router']['id'],
                                              s1['subnet']['id'],
                                              None)

    def test_router_add_interface_no_data(self):
        with self.router() as r:
            body = self._router_interface_action('add',
                                                 r['router']['id'],
                                                 None,
                                                 None,
                                                 expected_code=exc.
                                                 HTTPBadRequest.code)

    def test_network_update_external_failure(self):
        with self.router() as r:
            with self.subnet() as s1:
                self._set_net_external(s1['subnet']['network_id'])
                self._add_external_gateway_to_router(
                    r['router']['id'],
                    s1['subnet']['network_id'])
                self._update('networks', s1['subnet']['network_id'],
                             {'network': {'router:external': False}},
                             expected_code=exc.HTTPConflict.code)
                self._remove_external_gateway_from_router(
                    r['router']['id'],
                    s1['subnet']['network_id'])

    def test_network_update_external(self):
        with self.router() as r:
            with self.network('test_net') as testnet:
                self._set_net_external(testnet['network']['id'])
                with self.subnet() as s1:
                    self._set_net_external(s1['subnet']['network_id'])
                    self._add_external_gateway_to_router(
                        r['router']['id'],
                        s1['subnet']['network_id'])
                    self._update('networks', testnet['network']['id'],
                                 {'network': {'router:external': False}})
                    self._remove_external_gateway_from_router(
                        r['router']['id'],
                        s1['subnet']['network_id'])

    def test_create_router_with_gwinfo(self):
        with self.subnet() as s:
            self._set_net_external(s['subnet']['network_id'])
            data = {'router': {'tenant_id': _uuid()}}
            data['router']['name'] = 'router1'
            data['router']['external_gateway_info'] = {
                'network_id': s['subnet']['network_id']}
            router_req = self.new_create_request('routers', data, 'json')
            res = router_req.get_response(self.ext_api)
            router = self.deserialize('json', res)
            self.assertEquals(
                s['subnet']['network_id'],
                router['router']['external_gateway_info']['network_id'])
            self._delete('routers', router['router']['id'])

    def test_router_add_gateway(self):
        with self.router() as r:
            with self.subnet() as s:
                self._set_net_external(s['subnet']['network_id'])
                self._add_external_gateway_to_router(
                    r['router']['id'],
                    s['subnet']['network_id'])
                body = self._show('routers', r['router']['id'])
                net_id = body['router']['external_gateway_info']['network_id']
                self.assertEquals(net_id, s['subnet']['network_id'])
                self._remove_external_gateway_from_router(
                    r['router']['id'],
                    s['subnet']['network_id'])
                body = self._show('routers', r['router']['id'])
                gw_info = body['router']['external_gateway_info']
                self.assertEquals(gw_info, None)

    def test_router_update_gateway(self):
        with self.router() as r:
            with self.subnet() as s1:
                with self.subnet() as s2:
                    self._set_net_external(s1['subnet']['network_id'])
                    self._add_external_gateway_to_router(
                        r['router']['id'],
                        s1['subnet']['network_id'])
                    body = self._show('routers', r['router']['id'])
                    net_id = (body['router']
                              ['external_gateway_info']['network_id'])
                    self.assertEquals(net_id, s1['subnet']['network_id'])
                    self._set_net_external(s2['subnet']['network_id'])
                    self._add_external_gateway_to_router(
                        r['router']['id'],
                        s2['subnet']['network_id'])
                    body = self._show('routers', r['router']['id'])
                    net_id = (body['router']
                              ['external_gateway_info']['network_id'])
                    self.assertEquals(net_id, s2['subnet']['network_id'])
                    self._remove_external_gateway_from_router(
                        r['router']['id'],
                        s2['subnet']['network_id'])

    def test_router_update_gateway_with_existed_floatingip(self):
        with self.subnet() as subnet:
            self._set_net_external(subnet['subnet']['network_id'])
            with self.floatingip_with_assoc() as fip:
                self._add_external_gateway_to_router(
                    fip['floatingip']['router_id'],
                    subnet['subnet']['network_id'],
                    expected_code=exc.HTTPConflict.code)

    def test_router_update_gateway_to_empty_with_existed_floatingip(self):
        with self.floatingip_with_assoc() as fip:
            self._remove_external_gateway_from_router(
                fip['floatingip']['router_id'], None,
                expected_code=exc.HTTPConflict.code)

    def test_router_add_gateway_invalid_network(self):
        with self.router() as r:
            self._add_external_gateway_to_router(
                r['router']['id'],
                "foobar", expected_code=exc.HTTPNotFound.code)

    def test_router_add_gateway_net_not_external(self):
        with self.router() as r:
            with self.subnet() as s:
                # intentionally do not set net as external
                self._add_external_gateway_to_router(
                    r['router']['id'],
                    s['subnet']['network_id'],
                    expected_code=exc.HTTPBadRequest.code)

    def test_router_add_gateway_no_subnet(self):
        with self.router() as r:
            with self.network() as n:
                self._set_net_external(n['network']['id'])
                self._add_external_gateway_to_router(
                    r['router']['id'],
                    n['network']['id'], expected_code=exc.HTTPBadRequest.code)

    def test_router_delete_inuse_interface(self):
        with self.router() as r:
            with self.subnet() as s:
                self._router_interface_action('add',
                                              r['router']['id'],
                                              s['subnet']['id'],
                                              None)
                self._delete('routers', r['router']['id'],
                             expected_code=exc.HTTPConflict.code)

                # remove interface so test can exit without errors
                self._router_interface_action('remove',
                                              r['router']['id'],
                                              s['subnet']['id'],
                                              None)

    def test_router_remove_router_interface_wrong_subnet_returns_409(self):
        with self.router() as r:
            with self.subnet() as s:
                with self.port(no_delete=True) as p:
                    self._router_interface_action('add',
                                                  r['router']['id'],
                                                  None,
                                                  p['port']['id'])
                    self._router_interface_action('remove',
                                                  r['router']['id'],
                                                  s['subnet']['id'],
                                                  p['port']['id'],
                                                  exc.HTTPConflict.code)
                    #remove properly to clean-up
                    self._router_interface_action('remove',
                                                  r['router']['id'],
                                                  None,
                                                  p['port']['id'])

    def test_router_remove_router_interface_wrong_port_returns_404(self):
        with self.router() as r:
            with self.subnet() as s:
                with self.port(no_delete=True) as p:
                    self._router_interface_action('add',
                                                  r['router']['id'],
                                                  None,
                                                  p['port']['id'])
                    # create another port for testing failure case
                    res = self._create_port('json', p['port']['network_id'])
                    p2 = self.deserialize('json', res)
                    self._router_interface_action('remove',
                                                  r['router']['id'],
                                                  None,
                                                  p2['port']['id'],
                                                  exc.HTTPNotFound.code)
                    # remove correct interface to cleanup
                    self._router_interface_action('remove',
                                                  r['router']['id'],
                                                  None,
                                                  p['port']['id'])
                    # remove extra port created
                    self._delete('ports', p2['port']['id'])

    def _set_net_external(self, net_id):
        self._update('networks', net_id,
                     {'network': {l3.EXTERNAL: True}})

    def _create_floatingip(self, fmt, network_id, port_id=None,
                           fixed_ip=None):
        data = {'floatingip': {'floating_network_id': network_id,
                               'tenant_id': self._tenant_id}}
        if port_id:
            data['floatingip']['port_id'] = port_id
            if fixed_ip:
                data['floatingip']['fixed_ip_address'] = fixed_ip
        floatingip_req = self.new_create_request('floatingips', data, fmt)
        return floatingip_req.get_response(self.ext_api)

    def _validate_floating_ip(self, fip):
        body = self._list('floatingips')
        self.assertEquals(len(body['floatingips']), 1)
        self.assertEquals(body['floatingips'][0]['id'],
                          fip['floatingip']['id'])

        body = self._show('floatingips', fip['floatingip']['id'])
        self.assertEquals(body['floatingip']['id'],
                          fip['floatingip']['id'])

    @contextlib.contextmanager
    def floatingip_with_assoc(self, port_id=None, fmt='json'):
        with self.subnet(cidr='11.0.0.0/24') as public_sub:
            self._set_net_external(public_sub['subnet']['network_id'])
            with self.port() as private_port:
                with self.router() as r:
                    sid = private_port['port']['fixed_ips'][0]['subnet_id']
                    private_sub = {'subnet': {'id': sid}}
                    self._add_external_gateway_to_router(
                        r['router']['id'],
                        public_sub['subnet']['network_id'])
                    self._router_interface_action('add', r['router']['id'],
                                                  private_sub['subnet']['id'],
                                                  None)

                    res = self._create_floatingip(
                        fmt,
                        public_sub['subnet']['network_id'],
                        port_id=private_port['port']['id'])
                    self.assertEqual(res.status_int, exc.HTTPCreated.code)
                    floatingip = self.deserialize(fmt, res)
                    yield floatingip
                    self._delete('floatingips', floatingip['floatingip']['id'])
                    self._remove_external_gateway_from_router(
                        r['router']['id'],
                        public_sub['subnet']['network_id'])
                    self._router_interface_action('remove',
                                                  r['router']['id'],
                                                  private_sub['subnet']['id'],
                                                  None)

    @contextlib.contextmanager
    def floatingip_no_assoc(self, private_sub, fmt='json'):
        with self.subnet(cidr='12.0.0.0/24') as public_sub:
            self._set_net_external(public_sub['subnet']['network_id'])
            with self.router() as r:
                self._add_external_gateway_to_router(
                    r['router']['id'],
                    public_sub['subnet']['network_id'])
                self._router_interface_action('add', r['router']['id'],
                                              private_sub['subnet']['id'],
                                              None)

                res = self._create_floatingip(
                    fmt,
                    public_sub['subnet']['network_id'])
                self.assertEqual(res.status_int, exc.HTTPCreated.code)
                floatingip = self.deserialize(fmt, res)
                yield floatingip
                self._delete('floatingips', floatingip['floatingip']['id'])
                self._remove_external_gateway_from_router(
                    r['router']['id'],
                    public_sub['subnet']['network_id'])
                self._router_interface_action('remove', r['router']['id'],
                                              private_sub['subnet']['id'],
                                              None)

    def test_floatingip_crd_ops(self):
        with self.floatingip_with_assoc() as fip:
            self._validate_floating_ip(fip)

        # post-delete, check that it is really gone
        body = self._list('floatingips')
        self.assertEquals(len(body['floatingips']), 0)

        self._show('floatingips', fip['floatingip']['id'],
                   expected_code=exc.HTTPNotFound.code)

    def test_floatingip_with_assoc_fails(self):
        fmt = 'json'
        with self.subnet(cidr='200.0.0.1/24') as public_sub:
            self._set_net_external(public_sub['subnet']['network_id'])
            with self.port() as private_port:
                with self.router() as r:
                    sid = private_port['port']['fixed_ips'][0]['subnet_id']
                    private_sub = {'subnet': {'id': sid}}
                    self._add_external_gateway_to_router(
                        r['router']['id'],
                        public_sub['subnet']['network_id'])
                    self._router_interface_action('add', r['router']['id'],
                                                  private_sub['subnet']['id'],
                                                  None)
                    PLUGIN_CLASS = 'quantum.db.l3_db.L3_NAT_db_mixin'
                    METHOD = PLUGIN_CLASS + '._update_fip_assoc'
                    with mock.patch(METHOD) as pl:
                        pl.side_effect = q_exc.BadRequest(
                            resource='floatingip',
                            msg='fake_error')
                        res = self._create_floatingip(
                            fmt,
                            public_sub['subnet']['network_id'],
                            port_id=private_port['port']['id'])
                        self.assertEqual(res.status_int, 400)

                    for p in self._list('ports')['ports']:
                        if p['device_owner'] == 'network:floatingip':
                            self.fail('garbage port is not deleted')

                    self._remove_external_gateway_from_router(
                        r['router']['id'],
                        public_sub['subnet']['network_id'])
                    self._router_interface_action('remove',
                                                  r['router']['id'],
                                                  private_sub['subnet']['id'],
                                                  None)

    def test_router_delete_with_floatingip(self):
        with self.port() as p:
            private_sub = {'subnet': {'id':
                                      p['port']['fixed_ips'][0]['subnet_id']}}
            with self.subnet(cidr='12.0.0.0/24') as public_sub:
                fmt = 'json'
                self._set_net_external(public_sub['subnet']['network_id'])
                res = self._create_router(fmt, _uuid())
                r = self.deserialize(fmt, res)
                self._add_external_gateway_to_router(
                    r['router']['id'],
                    public_sub['subnet']['network_id'])
                self._router_interface_action('add', r['router']['id'],
                                              private_sub['subnet']['id'],
                                              None)
                res = self._create_floatingip(
                    fmt, public_sub['subnet']['network_id'],
                    port_id=p['port']['id'])
                self.assertEqual(res.status_int, exc.HTTPCreated.code)
                floatingip = self.deserialize(fmt, res)
                self._delete('routers', r['router']['id'],
                             expected_code=exc.HTTPConflict.code)
                # Cleanup
                self._delete('floatingips', floatingip['floatingip']['id'])
                self._router_interface_action('remove', r['router']['id'],
                                              private_sub['subnet']['id'],
                                              None)
                self._delete('routers', r['router']['id'])

    def test_floatingip_update(self):
        with self.port() as p:
            private_sub = {'subnet': {'id':
                                      p['port']['fixed_ips'][0]['subnet_id']}}
            with self.floatingip_no_assoc(private_sub) as fip:
                body = self._show('floatingips', fip['floatingip']['id'])
                self.assertEquals(body['floatingip']['port_id'], None)
                self.assertEquals(body['floatingip']['fixed_ip_address'], None)

                port_id = p['port']['id']
                ip_address = p['port']['fixed_ips'][0]['ip_address']
                fixed_ip = p['port']['fixed_ips'][0]['ip_address']
                body = self._update('floatingips', fip['floatingip']['id'],
                                    {'floatingip': {'port_id': port_id}})
                self.assertEquals(body['floatingip']['port_id'], port_id)
                self.assertEquals(body['floatingip']['fixed_ip_address'],
                                  ip_address)

    def test_floatingip_with_assoc(self):
        with self.floatingip_with_assoc() as fip:
            body = self._show('floatingips', fip['floatingip']['id'])
            self.assertEquals(body['floatingip']['id'],
                              fip['floatingip']['id'])
            self.assertEquals(body['floatingip']['port_id'],
                              fip['floatingip']['port_id'])
            self.assertTrue(body['floatingip']['fixed_ip_address'] is not None)
            self.assertTrue(body['floatingip']['router_id'] is not None)

    def test_floatingip_port_delete(self):
        with self.subnet() as private_sub:
            with self.floatingip_no_assoc(private_sub) as fip:
                with self.port(subnet=private_sub) as p:
                    body = self._update('floatingips', fip['floatingip']['id'],
                                        {'floatingip':
                                         {'port_id': p['port']['id']}})
                # note: once this port goes out of scope, the port will be
                # deleted, which is what we want to test. We want to confirm
                # that the fields are set back to None
                body = self._show('floatingips', fip['floatingip']['id'])
                self.assertEquals(body['floatingip']['id'],
                                  fip['floatingip']['id'])
                self.assertEquals(body['floatingip']['port_id'], None)
                self.assertEquals(body['floatingip']['fixed_ip_address'], None)
                self.assertEquals(body['floatingip']['router_id'], None)

    def test_two_fips_one_port_invalid_return_409(self):
        with self.floatingip_with_assoc() as fip1:
            res = self._create_floatingip(
                'json',
                fip1['floatingip']['floating_network_id'],
                fip1['floatingip']['port_id'])
            self.assertEqual(res.status_int, exc.HTTPConflict.code)

    def test_floating_ip_direct_port_delete_returns_409(self):
        found = False
        with self.floatingip_with_assoc() as fip:
            for p in self._list('ports')['ports']:
                if p['device_owner'] == 'network:floatingip':
                    self._delete('ports', p['id'],
                                 expected_code=exc.HTTPConflict.code)
                    found = True
        self.assertTrue(found)

    def test_create_floatingip_no_ext_gateway_return_404(self):
        with self.subnet() as public_sub:
            self._set_net_external(public_sub['subnet']['network_id'])
            with self.port() as private_port:
                with self.router() as r:
                    res = self._create_floatingip(
                        'json',
                        public_sub['subnet']['network_id'],
                        port_id=private_port['port']['id'])
                    # this should be some kind of error
                    self.assertEqual(res.status_int, exc.HTTPNotFound.code)

    def test_create_floating_non_ext_network_returns_400(self):
        with self.subnet() as public_sub:
            # normally we would set the network of public_sub to be
            # external, but the point of this test is to handle when
            # that is not the case
            with self.router() as r:
                res = self._create_floatingip(
                    'json',
                    public_sub['subnet']['network_id'])
                self.assertEqual(res.status_int, exc.HTTPBadRequest.code)

    def test_create_floatingip_no_public_subnet_returns_400(self):
        with self.network() as public_network:
            with self.port() as private_port:
                with self.router() as r:
                    sid = private_port['port']['fixed_ips'][0]['subnet_id']
                    private_sub = {'subnet': {'id': sid}}
                    self._router_interface_action('add', r['router']['id'],
                                                  private_sub['subnet']['id'],
                                                  None)

                    res = self._create_floatingip(
                        'json',
                        public_network['network']['id'],
                        port_id=private_port['port']['id'])
                    self.assertEqual(res.status_int, exc.HTTPBadRequest.code)
                    # cleanup
                    self._router_interface_action('remove',
                                                  r['router']['id'],
                                                  private_sub['subnet']['id'],
                                                  None)

    def test_create_floatingip_invalid_floating_network_id_returns_400(self):
        # API-level test - no need to create all objects for l3 plugin
        res = self._create_floatingip('json', 'iamnotanuuid',
                                      uuidutils.generate_uuid(), '192.168.0.1')
        self.assertEqual(res.status_int, 400)

    def test_create_floatingip_invalid_floating_port_id_returns_400(self):
        # API-level test - no need to create all objects for l3 plugin
        res = self._create_floatingip('json', uuidutils.generate_uuid(),
                                      'iamnotanuuid', '192.168.0.1')
        self.assertEqual(res.status_int, 400)

    def test_create_floatingip_invalid_fixed_ip_address_returns_400(self):
        # API-level test - no need to create all objects for l3 plugin
        res = self._create_floatingip('json', uuidutils.generate_uuid(),
                                      uuidutils.generate_uuid(), 'iamnotnanip')
        self.assertEqual(res.status_int, 400)

    def test_floatingip_delete_router_intf_with_subnet_id_returns_409(self):
        found = False
        with self.floatingip_with_assoc() as fip:
            for p in self._list('ports')['ports']:
                if p['device_owner'] == 'network:router_interface':
                    subnet_id = p['fixed_ips'][0]['subnet_id']
                    router_id = p['device_id']
                    self._router_interface_action(
                        'remove', router_id, subnet_id, None,
                        expected_code=exc.HTTPConflict.code)
                    found = True
                    break
        self.assertTrue(found)

    def test_floatingip_delete_router_intf_with_port_id_returns_409(self):
        found = False
        with self.floatingip_with_assoc() as fip:
            for p in self._list('ports')['ports']:
                if p['device_owner'] == 'network:router_interface':
                    router_id = p['device_id']
                    self._router_interface_action(
                        'remove', router_id, None, p['id'],
                        expected_code=exc.HTTPConflict.code)
                    found = True
                    break
        self.assertTrue(found)

    def test_list_nets_external(self):
        with self.network() as n1:
            self._set_net_external(n1['network']['id'])
            with self.network() as n2:
                body = self._list('networks')
                self.assertEquals(len(body['networks']), 2)

                body = self._list('networks',
                                  query_params="%s=True" % l3.EXTERNAL)
                self.assertEquals(len(body['networks']), 1)

                body = self._list('networks',
                                  query_params="%s=False" % l3.EXTERNAL)
                self.assertEquals(len(body['networks']), 1)

    def test_get_network_succeeds_without_filter(self):
        plugin = manager.QuantumManager.get_plugin()
        ctx = context.Context(None, None, is_admin=True)
        result = plugin.get_networks(ctx, filters=None)
        self.assertEqual(result, [])

    def test_network_filter_hook_admin_context(self):
        plugin = manager.QuantumManager.get_plugin()
        ctx = context.Context(None, None, is_admin=True)
        model = models_v2.Network
        conditions = plugin._network_filter_hook(ctx, model, [])
        self.assertEqual(conditions, [])

    def test_network_filter_hook_nonadmin_context(self):
        plugin = manager.QuantumManager.get_plugin()
        ctx = context.Context('edinson', 'cavani')
        model = models_v2.Network
        txt = "externalnetworks.network_id IS NOT NULL"
        conditions = plugin._network_filter_hook(ctx, model, [])
        self.assertEqual(conditions.__str__(), txt)
        # Try to concatenate confitions
        conditions = plugin._network_filter_hook(ctx, model, conditions)
        self.assertEqual(conditions.__str__(), "%s OR %s" % (txt, txt))

    def test_create_port_external_network_non_admin_fails(self):
        with self.network(router__external=True) as ext_net:
            with self.subnet(network=ext_net) as ext_subnet:
                with self.assertRaises(exc.HTTPClientError) as ctx_manager:
                    with self.port(subnet=ext_subnet,
                                   set_context='True',
                                   tenant_id='noadmin'):
                        pass
                    self.assertEquals(ctx_manager.exception.code, 403)

    def test_create_port_external_network_admin_suceeds(self):
        with self.network(router__external=True) as ext_net:
            with self.subnet(network=ext_net) as ext_subnet:
                    with self.port(subnet=ext_subnet) as port:
                        self.assertEqual(port['port']['network_id'],
                                         ext_net['network']['id'])

    def test_create_external_network_non_admin_fails(self):
        with self.assertRaises(exc.HTTPClientError) as ctx_manager:
            with self.network(router__external=True,
                              set_context='True',
                              tenant_id='noadmin'):
                pass
            self.assertEquals(ctx_manager.exception.code, 403)

    def test_create_external_network_admin_suceeds(self):
        with self.network(router__external=True) as ext_net:
            self.assertEqual(ext_net['network'][l3.EXTERNAL],
                             True)
