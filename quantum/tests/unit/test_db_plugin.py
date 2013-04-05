# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (c) 2012 OpenStack Foundation.
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
import copy
import datetime
import os
import random

import mock
from oslo.config import cfg
import testtools
from testtools import matchers
import webob.exc

import quantum
from quantum.api import api_common
from quantum.api.extensions import PluginAwareExtensionManager
from quantum.api.v2 import attributes
from quantum.api.v2.attributes import ATTR_NOT_SPECIFIED
from quantum.api.v2.router import APIRouter
from quantum.common import config
from quantum.common import exceptions as q_exc
from quantum.common.test_lib import test_config
from quantum import context
from quantum.db import api as db
from quantum.db import db_base_plugin_v2
from quantum.db import models_v2
from quantum.manager import QuantumManager
from quantum.openstack.common import timeutils
from quantum.tests import base
from quantum.tests.unit import test_extensions
from quantum.tests.unit import testlib_api


DB_PLUGIN_KLASS = 'quantum.db.db_base_plugin_v2.QuantumDbPluginV2'
ROOTDIR = os.path.dirname(os.path.dirname(__file__))
ETCDIR = os.path.join(ROOTDIR, 'etc')


def optional_ctx(obj, fallback):
    if not obj:
        return fallback()

    @contextlib.contextmanager
    def context_wrapper():
        yield obj
    return context_wrapper()


def etcdir(*p):
    return os.path.join(ETCDIR, *p)


def _fake_get_pagination_helper(self, request):
    return api_common.PaginationEmulatedHelper(request, self._primary_key)


def _fake_get_sorting_helper(self, request):
    return api_common.SortingEmulatedHelper(request, self._attr_info)


class QuantumDbPluginV2TestCase(testlib_api.WebTestCase):
    fmt = 'json'
    resource_prefix_map = {}

    def setUp(self, plugin=None, service_plugins=None):
        super(QuantumDbPluginV2TestCase, self).setUp()

        # NOTE(jkoelker) for a 'pluggable' framework, Quantum sure
        #                doesn't like when the plugin changes ;)
        db._ENGINE = None
        db._MAKER = None
        # Make sure at each test a new instance of the plugin is returned
        QuantumManager._instance = None
        # Make sure at each test according extensions for the plugin is loaded
        PluginAwareExtensionManager._instance = None
        # Save the attributes map in case the plugin will alter it
        # loading extensions
        # Note(salvatore-orlando): shallow copy is not good enough in
        # this case, but copy.deepcopy does not seem to work, since it
        # causes test failures
        self._attribute_map_bk = {}
        for item in attributes.RESOURCE_ATTRIBUTE_MAP:
            self._attribute_map_bk[item] = (attributes.
                                            RESOURCE_ATTRIBUTE_MAP[item].
                                            copy())
        self._tenant_id = 'test-tenant'

        if not plugin:
            plugin = test_config.get('plugin_name_v2', DB_PLUGIN_KLASS)

        # Create the default configurations
        args = ['--config-file', etcdir('quantum.conf.test')]
        # If test_config specifies some config-file, use it, as well
        for config_file in test_config.get('config_files', []):
            args.extend(['--config-file', config_file])
        config.parse(args=args)
        # Update the plugin
        cfg.CONF.set_override('core_plugin', plugin)
        cfg.CONF.set_override(
            'service_plugins',
            [test_config.get(key, default)
             for key, default in (service_plugins or {}).iteritems()]
        )

        cfg.CONF.set_override('base_mac', "12:34:56:78:90:ab")
        cfg.CONF.set_override('max_dns_nameservers', 2)
        cfg.CONF.set_override('max_subnet_host_routes', 2)
        cfg.CONF.set_override('allow_pagination', True)
        cfg.CONF.set_override('allow_sorting', True)
        self.api = APIRouter()
        # Set the defualt port status
        self.port_create_status = 'ACTIVE'

        def _is_native_bulk_supported():
            plugin_obj = QuantumManager.get_plugin()
            native_bulk_attr_name = ("_%s__native_bulk_support"
                                     % plugin_obj.__class__.__name__)
            return getattr(plugin_obj, native_bulk_attr_name, False)

        self._skip_native_bulk = not _is_native_bulk_supported()

        def _is_native_pagination_support():
            native_pagination_attr_name = (
                "_%s__native_pagination_support" %
                QuantumManager.get_plugin().__class__.__name__)
            return (cfg.CONF.allow_pagination and
                    getattr(QuantumManager.get_plugin(),
                            native_pagination_attr_name, False))

        self._skip_native_pagination = not _is_native_pagination_support()

        def _is_native_sorting_support():
            native_sorting_attr_name = (
                "_%s__native_sorting_support" %
                QuantumManager.get_plugin().__class__.__name__)
            return (cfg.CONF.allow_sorting and
                    getattr(QuantumManager.get_plugin(),
                            native_sorting_attr_name, False))

        self._skip_native_sorting = not _is_native_sorting_support()

        ext_mgr = test_config.get('extension_manager', None)
        if ext_mgr:
            self.ext_api = test_extensions.setup_extensions_middleware(ext_mgr)

    def tearDown(self):
        self.api = None
        self._deserializers = None
        self._skip_native_bulk = None
        self._skip_native_pagination = None
        self._skip_native_sortin = None
        self.ext_api = None
        # NOTE(jkoelker) for a 'pluggable' framework, Quantum sure
        #                doesn't like when the plugin changes ;)
        db.clear_db()
        db._ENGINE = None
        db._MAKER = None
        cfg.CONF.reset()
        # Restore the original attribute map
        attributes.RESOURCE_ATTRIBUTE_MAP = self._attribute_map_bk
        super(QuantumDbPluginV2TestCase, self).tearDown()

    def _req(self, method, resource, data=None, fmt=None, id=None, params=None,
             action=None, subresource=None, sub_id=None):
        fmt = fmt or self.fmt

        path = '/%s.%s' % (
            '/'.join(p for p in
                     (resource, id, subresource, sub_id, action) if p),
            fmt
        )

        prefix = self.resource_prefix_map.get(resource)
        if prefix:
            path = prefix + path

        content_type = 'application/%s' % fmt
        body = None
        if data is not None:  # empty dict is valid
            body = self.serialize(data)
        return testlib_api.create_request(path, body, content_type, method,
                                          query_string=params)

    def new_create_request(self, resource, data, fmt=None, id=None,
                           subresource=None):
        return self._req('POST', resource, data, fmt, id=id,
                         subresource=subresource)

    def new_list_request(self, resource, fmt=None, params=None,
                         subresource=None):
        return self._req(
            'GET', resource, None, fmt, params=params, subresource=subresource
        )

    def new_show_request(self, resource, id, fmt=None, subresource=None):
        return self._req(
            'GET', resource, None, fmt, id=id, subresource=subresource
        )

    def new_delete_request(self, resource, id, fmt=None, subresource=None,
                           sub_id=None):
        return self._req(
            'DELETE',
            resource,
            None,
            fmt,
            id=id,
            subresource=subresource,
            sub_id=sub_id
        )

    def new_update_request(self, resource, data, id, fmt=None,
                           subresource=None):
        return self._req(
            'PUT', resource, data, fmt, id=id, subresource=subresource
        )

    def new_action_request(self, resource, data, id, action, fmt=None,
                           subresource=None):
        return self._req(
            'PUT',
            resource,
            data,
            fmt,
            id=id,
            action=action,
            subresource=subresource
        )

    def deserialize(self, content_type, response):
        ctype = 'application/%s' % content_type
        data = self._deserializers[ctype].deserialize(response.body)['body']
        return data

    def _create_bulk_from_list(self, fmt, resource, objects, **kwargs):
        """ Creates a bulk request from a list of objects """
        collection = "%ss" % resource
        req_data = {collection: objects}
        req = self.new_create_request(collection, req_data, fmt)
        if ('set_context' in kwargs and
                kwargs['set_context'] is True and
                'tenant_id' in kwargs):
            # create a specific auth context for this request
            req.environ['quantum.context'] = context.Context(
                '', kwargs['tenant_id'])
        elif 'context' in kwargs:
            req.environ['quantum.context'] = kwargs['context']
        return req.get_response(self.api)

    def _create_bulk(self, fmt, number, resource, data, name='test', **kwargs):
        """ Creates a bulk request for any kind of resource """
        objects = []
        collection = "%ss" % resource
        for i in range(0, number):
            obj = copy.deepcopy(data)
            obj[resource]['name'] = "%s_%s" % (name, i)
            if 'override' in kwargs and i in kwargs['override']:
                obj[resource].update(kwargs['override'][i])
            objects.append(obj)
        req_data = {collection: objects}
        req = self.new_create_request(collection, req_data, fmt)
        if ('set_context' in kwargs and
                kwargs['set_context'] is True and
                'tenant_id' in kwargs):
            # create a specific auth context for this request
            req.environ['quantum.context'] = context.Context(
                '', kwargs['tenant_id'])
        elif 'context' in kwargs:
            req.environ['quantum.context'] = kwargs['context']
        return req.get_response(self.api)

    def _create_network(self, fmt, name, admin_state_up,
                        arg_list=None, **kwargs):
        data = {'network': {'name': name,
                            'admin_state_up': admin_state_up,
                            'tenant_id': self._tenant_id}}
        for arg in (('admin_state_up', 'tenant_id', 'shared') +
                    (arg_list or ())):
            # Arg must be present
            if arg in kwargs:
                data['network'][arg] = kwargs[arg]
        network_req = self.new_create_request('networks', data, fmt)
        if (kwargs.get('set_context') and 'tenant_id' in kwargs):
            # create a specific auth context for this request
            network_req.environ['quantum.context'] = context.Context(
                '', kwargs['tenant_id'])

        return network_req.get_response(self.api)

    def _create_network_bulk(self, fmt, number, name,
                             admin_state_up, **kwargs):
        base_data = {'network': {'admin_state_up': admin_state_up,
                                 'tenant_id': self._tenant_id}}
        return self._create_bulk(fmt, number, 'network', base_data, **kwargs)

    def _create_subnet(self, fmt, net_id, cidr,
                       expected_res_status=None, **kwargs):
        data = {'subnet': {'network_id': net_id,
                           'cidr': cidr,
                           'ip_version': 4,
                           'tenant_id': self._tenant_id}}
        for arg in ('allocation_pools',
                    'ip_version', 'tenant_id',
                    'enable_dhcp', 'allocation_pools',
                    'dns_nameservers', 'host_routes',
                    'shared'):
            # Arg must be present and not null (but can be false)
            if arg in kwargs and kwargs[arg] is not None:
                data['subnet'][arg] = kwargs[arg]

        if ('gateway_ip' in kwargs and
            kwargs['gateway_ip'] is not ATTR_NOT_SPECIFIED):
            data['subnet']['gateway_ip'] = kwargs['gateway_ip']

        subnet_req = self.new_create_request('subnets', data, fmt)
        if (kwargs.get('set_context') and 'tenant_id' in kwargs):
            # create a specific auth context for this request
            subnet_req.environ['quantum.context'] = context.Context(
                '', kwargs['tenant_id'])

        subnet_res = subnet_req.get_response(self.api)
        if expected_res_status:
            self.assertEqual(subnet_res.status_int, expected_res_status)
        return subnet_res

    def _create_subnet_bulk(self, fmt, number, net_id, name,
                            ip_version=4, **kwargs):
        base_data = {'subnet': {'network_id': net_id,
                                'ip_version': ip_version,
                                'tenant_id': self._tenant_id}}
        # auto-generate cidrs as they should not overlap
        overrides = dict((k, v)
                         for (k, v) in zip(range(0, number),
                                           [{'cidr': "10.0.%s.0/24" % num}
                                            for num in range(0, number)]))
        kwargs.update({'override': overrides})
        return self._create_bulk(fmt, number, 'subnet', base_data, **kwargs)

    def _create_port(self, fmt, net_id, expected_res_status=None,
                     arg_list=None, **kwargs):
        data = {'port': {'network_id': net_id,
                         'tenant_id': self._tenant_id}}

        for arg in (('admin_state_up', 'device_id',
                    'mac_address', 'name', 'fixed_ips',
                    'tenant_id', 'device_owner', 'security_groups') +
                    (arg_list or ())):
            # Arg must be present
            if arg in kwargs:
                data['port'][arg] = kwargs[arg]
        port_req = self.new_create_request('ports', data, fmt)
        if (kwargs.get('set_context') and 'tenant_id' in kwargs):
            # create a specific auth context for this request
            port_req.environ['quantum.context'] = context.Context(
                '', kwargs['tenant_id'])

        port_res = port_req.get_response(self.api)
        if expected_res_status:
            self.assertEqual(port_res.status_int, expected_res_status)
        return port_res

    def _list_ports(self, fmt, expected_res_status=None,
                    net_id=None, **kwargs):
        query_params = None
        if net_id:
            query_params = "network_id=%s" % net_id
        port_req = self.new_list_request('ports', fmt, query_params)
        if ('set_context' in kwargs and
                kwargs['set_context'] is True and
                'tenant_id' in kwargs):
            # create a specific auth context for this request
            port_req.environ['quantum.context'] = context.Context(
                '', kwargs['tenant_id'])

        port_res = port_req.get_response(self.api)
        if expected_res_status:
            self.assertEqual(port_res.status_int, expected_res_status)
        return port_res

    def _create_port_bulk(self, fmt, number, net_id, name,
                          admin_state_up, **kwargs):
        base_data = {'port': {'network_id': net_id,
                              'admin_state_up': admin_state_up,
                              'tenant_id': self._tenant_id}}
        return self._create_bulk(fmt, number, 'port', base_data, **kwargs)

    def _make_network(self, fmt, name, admin_state_up, **kwargs):
        res = self._create_network(fmt, name, admin_state_up, **kwargs)
        # TODO(salvatore-orlando): do exception handling in this test module
        # in a uniform way (we do it differently for ports, subnets, and nets
        # Things can go wrong - raise HTTP exc with res code only
        # so it can be caught by unit tests
        if res.status_int >= 400:
            raise webob.exc.HTTPClientError(code=res.status_int)
        return self.deserialize(fmt, res)

    def _make_subnet(self, fmt, network, gateway, cidr,
                     allocation_pools=None, ip_version=4, enable_dhcp=True,
                     dns_nameservers=None, host_routes=None, shared=None):
        res = self._create_subnet(fmt,
                                  net_id=network['network']['id'],
                                  cidr=cidr,
                                  gateway_ip=gateway,
                                  tenant_id=network['network']['tenant_id'],
                                  allocation_pools=allocation_pools,
                                  ip_version=ip_version,
                                  enable_dhcp=enable_dhcp,
                                  dns_nameservers=dns_nameservers,
                                  host_routes=host_routes,
                                  shared=shared)
        # Things can go wrong - raise HTTP exc with res code only
        # so it can be caught by unit tests
        if res.status_int >= 400:
            raise webob.exc.HTTPClientError(code=res.status_int)
        return self.deserialize(fmt, res)

    def _make_port(self, fmt, net_id, expected_res_status=None, **kwargs):
        res = self._create_port(fmt, net_id, expected_res_status, **kwargs)
        # Things can go wrong - raise HTTP exc with res code only
        # so it can be caught by unit tests
        if res.status_int >= 400:
            raise webob.exc.HTTPClientError(code=res.status_int)
        return self.deserialize(fmt, res)

    def _api_for_resource(self, resource):
        if resource in ['networks', 'subnets', 'ports']:
            return self.api
        else:
            return self.ext_api

    def _delete(self, collection, id,
                expected_code=webob.exc.HTTPNoContent.code,
                quantum_context=None):
        req = self.new_delete_request(collection, id)
        if quantum_context:
            # create a specific auth context for this request
            req.environ['quantum.context'] = quantum_context
        res = req.get_response(self._api_for_resource(collection))
        self.assertEqual(res.status_int, expected_code)

    def _show(self, resource, id,
              expected_code=webob.exc.HTTPOk.code,
              quantum_context=None):
        req = self.new_show_request(resource, id)
        if quantum_context:
            # create a specific auth context for this request
            req.environ['quantum.context'] = quantum_context
        res = req.get_response(self._api_for_resource(resource))
        self.assertEqual(res.status_int, expected_code)
        return self.deserialize(self.fmt, res)

    def _update(self, resource, id, new_data,
                expected_code=webob.exc.HTTPOk.code,
                quantum_context=None):
        req = self.new_update_request(resource, new_data, id)
        if quantum_context:
            # create a specific auth context for this request
            req.environ['quantum.context'] = quantum_context
        res = req.get_response(self._api_for_resource(resource))
        self.assertEqual(res.status_int, expected_code)
        return self.deserialize(self.fmt, res)

    def _list(self, resource, fmt=None, quantum_context=None,
              query_params=None):
        fmt = fmt or self.fmt
        req = self.new_list_request(resource, fmt, query_params)
        if quantum_context:
            req.environ['quantum.context'] = quantum_context
        res = req.get_response(self._api_for_resource(resource))
        self.assertEqual(res.status_int, webob.exc.HTTPOk.code)
        return self.deserialize(fmt, res)

    def _do_side_effect(self, patched_plugin, orig, *args, **kwargs):
        """ Invoked by test cases for injecting failures in plugin """
        def second_call(*args, **kwargs):
            raise q_exc.QuantumException
        patched_plugin.side_effect = second_call
        return orig(*args, **kwargs)

    def _validate_behavior_on_bulk_failure(self, res, collection, errcode=400):
        self.assertEqual(res.status_int, errcode)
        req = self.new_list_request(collection)
        res = req.get_response(self.api)
        self.assertEqual(res.status_int, 200)
        items = self.deserialize(self.fmt, res)
        self.assertEqual(len(items[collection]), 0)

    def _validate_behavior_on_bulk_success(self, res, collection,
                                           names=['test_0', 'test_1']):
        self.assertEqual(res.status_int, 201)
        items = self.deserialize(self.fmt, res)[collection]
        self.assertEqual(len(items), 2)
        self.assertEqual(items[0]['name'], 'test_0')
        self.assertEqual(items[1]['name'], 'test_1')

    def _test_list_resources(self, resource, items, quantum_context=None,
                             query_params=None):
        res = self._list('%ss' % resource,
                         quantum_context=quantum_context,
                         query_params=query_params)
        resource = resource.replace('-', '_')
        self.assertEqual(sorted([i['id'] for i in res['%ss' % resource]]),
                         sorted([i[resource]['id'] for i in items]))

    @contextlib.contextmanager
    def network(self, name='net1',
                admin_state_up=True,
                fmt=None,
                do_delete=True,
                **kwargs):
        network = self._make_network(fmt or self.fmt, name,
                                     admin_state_up, **kwargs)
        try:
            yield network
        finally:
            if do_delete:
                # The do_delete parameter allows you to control whether the
                # created network is immediately deleted again. Therefore, this
                # function is also usable in tests, which require the creation
                # of many networks.
                self._delete('networks', network['network']['id'])

    @contextlib.contextmanager
    def subnet(self, network=None,
               gateway_ip=ATTR_NOT_SPECIFIED,
               cidr='10.0.0.0/24',
               fmt=None,
               ip_version=4,
               allocation_pools=None,
               enable_dhcp=True,
               dns_nameservers=None,
               host_routes=None,
               shared=None,
               do_delete=True):
        with optional_ctx(network, self.network) as network_to_use:
            subnet = self._make_subnet(fmt or self.fmt,
                                       network_to_use,
                                       gateway_ip,
                                       cidr,
                                       allocation_pools,
                                       ip_version,
                                       enable_dhcp,
                                       dns_nameservers,
                                       host_routes,
                                       shared=shared)
            try:
                yield subnet
            finally:
                if do_delete:
                    self._delete('subnets', subnet['subnet']['id'])

    @contextlib.contextmanager
    def port(self, subnet=None, fmt=None, no_delete=False,
             **kwargs):
        with optional_ctx(subnet, self.subnet) as subnet_to_use:
            net_id = subnet_to_use['subnet']['network_id']
            port = self._make_port(fmt or self.fmt, net_id, **kwargs)
            try:
                yield port
            finally:
                if not no_delete:
                    self._delete('ports', port['port']['id'])

    def _test_list_with_sort(self, collection, items, sorts, query_params=''):
        query_str = query_params
        for key, direction in sorts:
            query_str = query_str + "&sort_key=%s&sort_dir=%s" % (key,
                                                                  direction)
        req = self.new_list_request('%ss' % collection,
                                    params=query_str)
        api = self._api_for_resource('%ss' % collection)
        res = self.deserialize(self.fmt, req.get_response(api))
        collection = collection.replace('-', '_')
        expected_res = [item[collection]['id'] for item in items]
        self.assertEqual(sorted([n['id'] for n in res["%ss" % collection]]),
                         sorted(expected_res))

    def _test_list_with_pagination(self, collection, items, sort,
                                   limit, expected_page_num, query_params='',
                                   verify_key='id'):
        query_str = query_params + '&' if query_params else ''
        query_str = query_str + ("limit=%s&sort_key=%s&"
                                 "sort_dir=%s") % (limit, sort[0], sort[1])
        req = self.new_list_request("%ss" % collection, params=query_str)
        items_res = []
        page_num = 0
        api = self._api_for_resource('%ss' % collection)
        collection = collection.replace('-', '_')
        while req:
            page_num = page_num + 1
            res = self.deserialize(self.fmt, req.get_response(api))
            self.assertThat(len(res["%ss" % collection]),
                            matchers.LessThan(limit + 1))
            items_res = items_res + res["%ss" % collection]
            req = None
            if '%ss_links' % collection in res:
                for link in res['%ss_links' % collection]:
                    if link['rel'] == 'next':
                        content_type = 'application/%s' % self.fmt
                        req = testlib_api.create_request(link['href'],
                                                         '', content_type)
                        self.assertEqual(len(res["%ss" % collection]),
                                         limit)
        self.assertEqual(page_num, expected_page_num)
        self.assertEqual(sorted([n[verify_key] for n in items_res]),
                         sorted([item[collection][verify_key]
                                for item in items]))

    def _test_list_with_pagination_reverse(self, collection, items, sort,
                                           limit, expected_page_num,
                                           query_params=''):
        resources = '%ss' % collection
        collection = collection.replace('-', '_')
        api = self._api_for_resource(resources)
        marker = items[-1][collection]['id']
        query_str = query_params + '&' if query_params else ''
        query_str = query_str + ("limit=%s&page_reverse=True&"
                                 "sort_key=%s&sort_dir=%s&"
                                 "marker=%s") % (limit, sort[0], sort[1],
                                                 marker)
        req = self.new_list_request(resources, params=query_str)
        item_res = [items[-1][collection]]
        page_num = 0
        while req:
            page_num = page_num + 1
            res = self.deserialize(self.fmt, req.get_response(api))
            self.assertThat(len(res["%ss" % collection]),
                            matchers.LessThan(limit + 1))
            res["%ss" % collection].reverse()
            item_res = item_res + res["%ss" % collection]
            req = None
            if '%ss_links' % collection in res:
                for link in res['%ss_links' % collection]:
                    if link['rel'] == 'previous':
                        content_type = 'application/%s' % self.fmt
                        req = testlib_api.create_request(link['href'],
                                                         '', content_type)
                        self.assertEqual(len(res["%ss" % collection]),
                                         limit)
        self.assertEqual(page_num, expected_page_num)
        expected_res = [item[collection]['id'] for item in items]
        expected_res.reverse()
        self.assertEqual(sorted([n['id'] for n in item_res]),
                         sorted(expected_res))


class TestBasicGet(QuantumDbPluginV2TestCase):

    def test_single_get_admin(self):
        plugin = quantum.db.db_base_plugin_v2.QuantumDbPluginV2()
        with self.network() as network:
            net_id = network['network']['id']
            ctx = context.get_admin_context()
            n = plugin._get_network(ctx, net_id)
            self.assertEqual(net_id, n.id)

    def test_single_get_tenant(self):
        plugin = quantum.db.db_base_plugin_v2.QuantumDbPluginV2()
        with self.network() as network:
            net_id = network['network']['id']
            ctx = context.get_admin_context()
            n = plugin._get_network(ctx, net_id)
            self.assertEqual(net_id, n.id)


class TestV2HTTPResponse(QuantumDbPluginV2TestCase):
    def test_create_returns_201(self):
        res = self._create_network(self.fmt, 'net2', True)
        self.assertEqual(res.status_int, 201)

    def test_list_returns_200(self):
        req = self.new_list_request('networks')
        res = req.get_response(self.api)
        self.assertEqual(res.status_int, 200)

    def _check_list_with_fields(self, res, field_name):
        self.assertEqual(res.status_int, 200)
        body = self.deserialize(self.fmt, res)
        # further checks: 1 networks
        self.assertEqual(len(body['networks']), 1)
        # 1 field in the network record
        self.assertEqual(len(body['networks'][0]), 1)
        # field is 'name'
        self.assertIn(field_name, body['networks'][0])

    def test_list_with_fields(self):
        self._create_network(self.fmt, 'some_net', True)
        req = self.new_list_request('networks', params="fields=name")
        res = req.get_response(self.api)
        self._check_list_with_fields(res, 'name')

    def test_list_with_fields_noadmin(self):
        tenant_id = 'some_tenant'
        self._create_network(self.fmt,
                             'some_net',
                             True,
                             tenant_id=tenant_id,
                             set_context=True)
        req = self.new_list_request('networks', params="fields=name")
        req.environ['quantum.context'] = context.Context('', tenant_id)
        res = req.get_response(self.api)
        self._check_list_with_fields(res, 'name')

    def test_list_with_fields_noadmin_and_policy_field(self):
        """ If a field used by policy is selected, do not duplicate it.

        Verifies that if the field parameter explicitly specifies a field
        which is used by the policy engine, then it is not duplicated
        in the response.

        """
        tenant_id = 'some_tenant'
        self._create_network(self.fmt,
                             'some_net',
                             True,
                             tenant_id=tenant_id,
                             set_context=True)
        req = self.new_list_request('networks', params="fields=tenant_id")
        req.environ['quantum.context'] = context.Context('', tenant_id)
        res = req.get_response(self.api)
        self._check_list_with_fields(res, 'tenant_id')

    def test_show_returns_200(self):
        with self.network() as net:
            req = self.new_show_request('networks', net['network']['id'])
            res = req.get_response(self.api)
            self.assertEqual(res.status_int, 200)

    def test_delete_returns_204(self):
        res = self._create_network(self.fmt, 'net1', True)
        net = self.deserialize(self.fmt, res)
        req = self.new_delete_request('networks', net['network']['id'])
        res = req.get_response(self.api)
        self.assertEqual(res.status_int, 204)

    def test_update_returns_200(self):
        with self.network() as net:
            req = self.new_update_request('networks',
                                          {'network': {'name': 'steve'}},
                                          net['network']['id'])
            res = req.get_response(self.api)
            self.assertEqual(res.status_int, 200)

    def test_update_invalid_json_400(self):
        with self.network() as net:
            req = self.new_update_request('networks',
                                          '{{"name": "aaa"}}',
                                          net['network']['id'])
            res = req.get_response(self.api)
            self.assertEqual(res.status_int, 400)

    def test_bad_route_404(self):
        req = self.new_list_request('doohickeys')
        res = req.get_response(self.api)
        self.assertEqual(res.status_int, 404)


class TestPortsV2(QuantumDbPluginV2TestCase):
    def test_create_port_json(self):
        keys = [('admin_state_up', True), ('status', self.port_create_status)]
        with self.port(name='myname') as port:
            for k, v in keys:
                self.assertEqual(port['port'][k], v)
            self.assertTrue('mac_address' in port['port'])
            ips = port['port']['fixed_ips']
            self.assertEqual(len(ips), 1)
            self.assertEqual(ips[0]['ip_address'], '10.0.0.2')
            self.assertEqual('myname', port['port']['name'])

    def test_create_port_bad_tenant(self):
        with self.network() as network:
            data = {'port': {'network_id': network['network']['id'],
                             'tenant_id': 'bad_tenant_id',
                             'admin_state_up': True,
                             'device_id': 'fake_device',
                             'device_owner': 'fake_owner',
                             'fixed_ips': []}}

            port_req = self.new_create_request('ports', data)
            res = port_req.get_response(self.api)
            self.assertEqual(res.status_int, 403)

    def test_create_port_public_network(self):
        keys = [('admin_state_up', True), ('status', self.port_create_status)]
        with self.network(shared=True) as network:
            port_res = self._create_port(self.fmt,
                                         network['network']['id'],
                                         201,
                                         tenant_id='another_tenant',
                                         set_context=True)
            port = self.deserialize(self.fmt, port_res)
            for k, v in keys:
                self.assertEqual(port['port'][k], v)
            self.assertTrue('mac_address' in port['port'])
            self._delete('ports', port['port']['id'])

    def test_create_port_public_network_with_ip(self):
        with self.network(shared=True) as network:
            with self.subnet(network=network, cidr='10.0.0.0/24') as subnet:
                keys = [('admin_state_up', True),
                        ('status', self.port_create_status),
                        ('fixed_ips', [{'subnet_id': subnet['subnet']['id'],
                                        'ip_address': '10.0.0.2'}])]
                port_res = self._create_port(self.fmt,
                                             network['network']['id'],
                                             201,
                                             tenant_id='another_tenant',
                                             set_context=True)
                port = self.deserialize(self.fmt, port_res)
                for k, v in keys:
                    self.assertEqual(port['port'][k], v)
                self.assertTrue('mac_address' in port['port'])
                self._delete('ports', port['port']['id'])

    def test_create_ports_bulk_native(self):
        if self._skip_native_bulk:
            self.skipTest("Plugin does not support native bulk port create")
        with self.network() as net:
            res = self._create_port_bulk(self.fmt, 2, net['network']['id'],
                                         'test', True)
            self._validate_behavior_on_bulk_success(res, 'ports')
            for p in self.deserialize(self.fmt, res)['ports']:
                self._delete('ports', p['id'])

    def test_create_ports_bulk_emulated(self):
        real_has_attr = hasattr

        #ensures the API choose the emulation code path
        def fakehasattr(item, attr):
            if attr.endswith('__native_bulk_support'):
                return False
            return real_has_attr(item, attr)

        with mock.patch('__builtin__.hasattr',
                        new=fakehasattr):
            with self.network() as net:
                res = self._create_port_bulk(self.fmt, 2, net['network']['id'],
                                             'test', True)
                self._validate_behavior_on_bulk_success(res, 'ports')
                for p in self.deserialize(self.fmt, res)['ports']:
                    self._delete('ports', p['id'])

    def test_create_ports_bulk_wrong_input(self):
        with self.network() as net:
            overrides = {1: {'admin_state_up': 'doh'}}
            res = self._create_port_bulk(self.fmt, 2, net['network']['id'],
                                         'test', True,
                                         override=overrides)
            self.assertEqual(res.status_int, 400)
            req = self.new_list_request('ports')
            res = req.get_response(self.api)
            self.assertEqual(res.status_int, 200)
            ports = self.deserialize(self.fmt, res)
            self.assertEqual(len(ports['ports']), 0)

    def test_create_ports_bulk_emulated_plugin_failure(self):
        real_has_attr = hasattr

        #ensures the API choose the emulation code path
        def fakehasattr(item, attr):
            if attr.endswith('__native_bulk_support'):
                return False
            return real_has_attr(item, attr)

        with mock.patch('__builtin__.hasattr',
                        new=fakehasattr):
            orig = QuantumManager.get_plugin().create_port
            with mock.patch.object(QuantumManager.get_plugin(),
                                   'create_port') as patched_plugin:

                def side_effect(*args, **kwargs):
                    return self._do_side_effect(patched_plugin, orig,
                                                *args, **kwargs)

                patched_plugin.side_effect = side_effect
                with self.network() as net:
                    res = self._create_port_bulk(self.fmt, 2,
                                                 net['network']['id'],
                                                 'test',
                                                 True)
                    # We expect a 500 as we injected a fault in the plugin
                    self._validate_behavior_on_bulk_failure(res, 'ports', 500)

    def test_create_ports_bulk_native_plugin_failure(self):
        if self._skip_native_bulk:
            self.skipTest("Plugin does not support native bulk port create")
        ctx = context.get_admin_context()
        with self.network() as net:
            orig = QuantumManager._instance.plugin.create_port
            with mock.patch.object(QuantumManager._instance.plugin,
                                   'create_port') as patched_plugin:

                def side_effect(*args, **kwargs):
                    return self._do_side_effect(patched_plugin, orig,
                                                *args, **kwargs)

                patched_plugin.side_effect = side_effect
                res = self._create_port_bulk(self.fmt, 2, net['network']['id'],
                                             'test', True, context=ctx)
                # We expect a 500 as we injected a fault in the plugin
                self._validate_behavior_on_bulk_failure(res, 'ports', 500)

    def test_list_ports(self):
        # for this test we need to enable overlapping ips
        cfg.CONF.set_default('allow_overlapping_ips', True)
        with contextlib.nested(self.port(),
                               self.port(),
                               self.port()) as ports:
            self._test_list_resources('port', ports)

    def test_list_ports_filtered_by_fixed_ip(self):
        # for this test we need to enable overlapping ips
        cfg.CONF.set_default('allow_overlapping_ips', True)
        with contextlib.nested(self.port(), self.port()) as (port1, port2):
            fixed_ips = port1['port']['fixed_ips'][0]
            query_params = """
fixed_ips=ip_address%%3D%s&fixed_ips=ip_address%%3D%s&fixed_ips=subnet_id%%3D%s
""".strip() % (fixed_ips['ip_address'],
               '192.168.126.5',
               fixed_ips['subnet_id'])
            self._test_list_resources('port', [port1],
                                      query_params=query_params)

    def test_list_ports_public_network(self):
        with self.network(shared=True) as network:
            with self.subnet(network) as subnet:
                with contextlib.nested(self.port(subnet, tenant_id='tenant_1'),
                                       self.port(subnet, tenant_id='tenant_2')
                                       ) as (port1, port2):
                    # Admin request - must return both ports
                    self._test_list_resources('port', [port1, port2])
                    # Tenant_1 request - must return single port
                    q_context = context.Context('', 'tenant_1')
                    self._test_list_resources('port', [port1],
                                              quantum_context=q_context)
                    # Tenant_2 request - must return single port
                    q_context = context.Context('', 'tenant_2')
                    self._test_list_resources('port', [port2],
                                              quantum_context=q_context)

    def test_list_ports_with_sort_native(self):
        if self._skip_native_sorting:
            self.skipTest("Skip test for not implemented sorting feature")
        cfg.CONF.set_default('allow_overlapping_ips', True)
        with contextlib.nested(self.port(admin_state_up='True',
                                         mac_address='00:00:00:00:00:01'),
                               self.port(admin_state_up='False',
                                         mac_address='00:00:00:00:00:02'),
                               self.port(admin_state_up='False',
                                         mac_address='00:00:00:00:00:03')
                               ) as (port1, port2, port3):
            self._test_list_with_sort('port', (port3, port2, port1),
                                      [('admin_state_up', 'asc'),
                                       ('mac_address', 'desc')])

    def test_list_ports_with_sort_emulated(self):
        helper_patcher = mock.patch(
            'quantum.api.v2.base.Controller._get_sorting_helper',
            new=_fake_get_sorting_helper)
        helper_patcher.start()
        try:
            cfg.CONF.set_default('allow_overlapping_ips', True)
            with contextlib.nested(self.port(admin_state_up='True',
                                             mac_address='00:00:00:00:00:01'),
                                   self.port(admin_state_up='False',
                                             mac_address='00:00:00:00:00:02'),
                                   self.port(admin_state_up='False',
                                             mac_address='00:00:00:00:00:03')
                                   ) as (port1, port2, port3):
                self._test_list_with_sort('port', (port3, port2, port1),
                                          [('admin_state_up', 'asc'),
                                           ('mac_address', 'desc')])
        finally:
            helper_patcher.stop()

    def test_list_ports_with_pagination_native(self):
        if self._skip_native_pagination:
            self.skipTest("Skip test for not implemented pagination feature")
        cfg.CONF.set_default('allow_overlapping_ips', True)
        with contextlib.nested(self.port(mac_address='00:00:00:00:00:01'),
                               self.port(mac_address='00:00:00:00:00:02'),
                               self.port(mac_address='00:00:00:00:00:03')
                               ) as (port1, port2, port3):
            self._test_list_with_pagination('port',
                                            (port1, port2, port3),
                                            ('mac_address', 'asc'), 2, 2)

    def test_list_ports_with_pagination_emulated(self):
        helper_patcher = mock.patch(
            'quantum.api.v2.base.Controller._get_pagination_helper',
            new=_fake_get_pagination_helper)
        helper_patcher.start()
        try:
            cfg.CONF.set_default('allow_overlapping_ips', True)
            with contextlib.nested(self.port(mac_address='00:00:00:00:00:01'),
                                   self.port(mac_address='00:00:00:00:00:02'),
                                   self.port(mac_address='00:00:00:00:00:03')
                                   ) as (port1, port2, port3):
                self._test_list_with_pagination('port',
                                                (port1, port2, port3),
                                                ('mac_address', 'asc'), 2, 2)
        finally:
            helper_patcher.stop()

    def test_list_ports_with_pagination_reverse_native(self):
        if self._skip_native_pagination:
            self.skipTest("Skip test for not implemented pagination feature")
        cfg.CONF.set_default('allow_overlapping_ips', True)
        with contextlib.nested(self.port(mac_address='00:00:00:00:00:01'),
                               self.port(mac_address='00:00:00:00:00:02'),
                               self.port(mac_address='00:00:00:00:00:03')
                               ) as (port1, port2, port3):
            self._test_list_with_pagination_reverse('port',
                                                    (port1, port2, port3),
                                                    ('mac_address', 'asc'),
                                                    2, 2)

    def test_list_ports_with_pagination_reverse_emulated(self):
        helper_patcher = mock.patch(
            'quantum.api.v2.base.Controller._get_pagination_helper',
            new=_fake_get_pagination_helper)
        helper_patcher.start()
        try:
            cfg.CONF.set_default('allow_overlapping_ips', True)
            with contextlib.nested(self.port(mac_address='00:00:00:00:00:01'),
                                   self.port(mac_address='00:00:00:00:00:02'),
                                   self.port(mac_address='00:00:00:00:00:03')
                                   ) as (port1, port2, port3):
                self._test_list_with_pagination_reverse('port',
                                                        (port1, port2, port3),
                                                        ('mac_address', 'asc'),
                                                        2, 2)
        finally:
            helper_patcher.stop()

    def test_show_port(self):
        with self.port() as port:
            req = self.new_show_request('ports', port['port']['id'], self.fmt)
            sport = self.deserialize(self.fmt, req.get_response(self.api))
            self.assertEqual(port['port']['id'], sport['port']['id'])

    def test_delete_port(self):
        with self.port() as port:
            req = self.new_show_request('port', self.fmt, port['port']['id'])
            res = req.get_response(self.api)
            self.assertEqual(res.status_int, 404)

    def test_delete_port_public_network(self):
        with self.network(shared=True) as network:
            port_res = self._create_port(self.fmt,
                                         network['network']['id'],
                                         201,
                                         tenant_id='another_tenant',
                                         set_context=True)

            port = self.deserialize(self.fmt, port_res)
            # delete the port
            self._delete('ports', port['port']['id'])
            # Todo: verify!!!

    def test_update_port(self):
        with self.port() as port:
            data = {'port': {'admin_state_up': False}}
            req = self.new_update_request('ports', data, port['port']['id'])
            res = self.deserialize(self.fmt, req.get_response(self.api))
            self.assertEqual(res['port']['admin_state_up'],
                             data['port']['admin_state_up'])

    def test_update_port_not_admin(self):
        res = self._create_network(self.fmt, 'net1', True,
                                   tenant_id='not_admin',
                                   set_context=True)
        net1 = self.deserialize(self.fmt, res)
        res = self._create_port(self.fmt, net1['network']['id'],
                                tenant_id='not_admin', set_context=True)
        port = self.deserialize(self.fmt, res)
        data = {'port': {'admin_state_up': False}}
        quantum_context = context.Context('', 'not_admin')
        port = self._update('ports', port['port']['id'], data,
                            quantum_context=quantum_context)
        self.assertEqual(port['port']['admin_state_up'], False)

    def test_update_device_id_null(self):
        with self.port() as port:
            data = {'port': {'device_id': None}}
            req = self.new_update_request('ports', data, port['port']['id'])
            res = req.get_response(self.api)
            self.assertEqual(res.status_int, 400)

    def test_delete_network_if_port_exists(self):
        with self.port() as port:
            req = self.new_delete_request('networks',
                                          port['port']['network_id'])
            res = req.get_response(self.api)
            self.assertEqual(res.status_int, 409)

    def test_delete_network_port_exists_owned_by_network(self):
        res = self._create_network(fmt=self.fmt, name='net',
                                   admin_state_up=True)
        network = self.deserialize(self.fmt, res)
        network_id = network['network']['id']
        self._create_port(self.fmt, network_id, device_owner='network:dhcp')
        req = self.new_delete_request('networks', network_id)
        res = req.get_response(self.api)
        self.assertEqual(res.status_int, 204)

    def test_update_port_delete_ip(self):
        with self.subnet() as subnet:
            with self.port(subnet=subnet) as port:
                data = {'port': {'admin_state_up': False,
                                 'fixed_ips': []}}
                req = self.new_update_request('ports',
                                              data, port['port']['id'])
                res = self.deserialize(self.fmt, req.get_response(self.api))
                self.assertEqual(res['port']['admin_state_up'],
                                 data['port']['admin_state_up'])
                self.assertEqual(res['port']['fixed_ips'],
                                 data['port']['fixed_ips'])

    def test_no_more_port_exception(self):
        with self.subnet(cidr='10.0.0.0/32') as subnet:
            id = subnet['subnet']['network_id']
            res = self._create_port(self.fmt, id)
            data = self.deserialize(self.fmt, res)
            msg = str(q_exc.IpAddressGenerationFailure(net_id=id))
            self.assertEqual(data['QuantumError'], msg)
            self.assertEqual(res.status_int, 409)

    def test_update_port_update_ip(self):
        """Test update of port IP.

        Check that a configured IP 10.0.0.2 is replaced by 10.0.0.10.
        """
        with self.subnet() as subnet:
            with self.port(subnet=subnet) as port:
                ips = port['port']['fixed_ips']
                self.assertEqual(len(ips), 1)
                self.assertEqual(ips[0]['ip_address'], '10.0.0.2')
                self.assertEqual(ips[0]['subnet_id'], subnet['subnet']['id'])
                data = {'port': {'fixed_ips': [{'subnet_id':
                                                subnet['subnet']['id'],
                                                'ip_address': "10.0.0.10"}]}}
                req = self.new_update_request('ports', data,
                                              port['port']['id'])
                res = self.deserialize(self.fmt, req.get_response(self.api))
                ips = res['port']['fixed_ips']
                self.assertEqual(len(ips), 1)
                self.assertEqual(ips[0]['ip_address'], '10.0.0.10')
                self.assertEqual(ips[0]['subnet_id'], subnet['subnet']['id'])

    def test_update_port_update_ip_address_only(self):
        with self.subnet() as subnet:
            with self.port(subnet=subnet) as port:
                ips = port['port']['fixed_ips']
                self.assertEqual(len(ips), 1)
                self.assertEqual(ips[0]['ip_address'], '10.0.0.2')
                self.assertEqual(ips[0]['subnet_id'], subnet['subnet']['id'])
                data = {'port': {'fixed_ips': [{'subnet_id':
                                                subnet['subnet']['id'],
                                                'ip_address': "10.0.0.10"},
                                               {'ip_address': "10.0.0.2"}]}}
                req = self.new_update_request('ports', data,
                                              port['port']['id'])
                res = self.deserialize(self.fmt, req.get_response(self.api))
                ips = res['port']['fixed_ips']
                self.assertEqual(len(ips), 2)
                self.assertEqual(ips[0]['ip_address'], '10.0.0.2')
                self.assertEqual(ips[0]['subnet_id'], subnet['subnet']['id'])
                self.assertEqual(ips[1]['ip_address'], '10.0.0.10')
                self.assertEqual(ips[1]['subnet_id'], subnet['subnet']['id'])

    def test_update_port_update_ips(self):
        """Update IP and generate new IP on port.

        Check a port update with the specified subnet_id's. A IP address
        will be allocated for each subnet_id.
        """
        with self.subnet() as subnet:
            with self.port(subnet=subnet) as port:
                data = {'port': {'admin_state_up': False,
                                 'fixed_ips': [{'subnet_id':
                                                subnet['subnet']['id']}]}}
                req = self.new_update_request('ports', data,
                                              port['port']['id'])
                res = self.deserialize(self.fmt, req.get_response(self.api))
                self.assertEqual(res['port']['admin_state_up'],
                                 data['port']['admin_state_up'])
                ips = res['port']['fixed_ips']
                self.assertEqual(len(ips), 1)
                self.assertEqual(ips[0]['ip_address'], '10.0.0.3')
                self.assertEqual(ips[0]['subnet_id'], subnet['subnet']['id'])

    def test_update_port_add_additional_ip(self):
        """Test update of port with additional IP."""
        with self.subnet() as subnet:
            with self.port(subnet=subnet) as port:
                data = {'port': {'admin_state_up': False,
                                 'fixed_ips': [{'subnet_id':
                                                subnet['subnet']['id']},
                                               {'subnet_id':
                                                subnet['subnet']['id']}]}}
                req = self.new_update_request('ports', data,
                                              port['port']['id'])
                res = self.deserialize(self.fmt, req.get_response(self.api))
                self.assertEqual(res['port']['admin_state_up'],
                                 data['port']['admin_state_up'])
                ips = res['port']['fixed_ips']
                self.assertEqual(len(ips), 2)
                self.assertEqual(ips[0]['ip_address'], '10.0.0.3')
                self.assertEqual(ips[0]['subnet_id'], subnet['subnet']['id'])
                self.assertEqual(ips[1]['ip_address'], '10.0.0.4')
                self.assertEqual(ips[1]['subnet_id'], subnet['subnet']['id'])

    def test_requested_duplicate_mac(self):
        with self.port() as port:
            mac = port['port']['mac_address']
            # check that MAC address matches base MAC
            base_mac = cfg.CONF.base_mac[0:2]
            self.assertTrue(mac.startswith(base_mac))
            kwargs = {"mac_address": mac}
            net_id = port['port']['network_id']
            res = self._create_port(self.fmt, net_id=net_id, **kwargs)
            self.assertEqual(res.status_int, 409)

    def test_mac_generation(self):
        cfg.CONF.set_override('base_mac', "12:34:56:00:00:00")
        with self.port() as port:
            mac = port['port']['mac_address']
            self.assertTrue(mac.startswith("12:34:56"))

    def test_mac_generation_4octet(self):
        cfg.CONF.set_override('base_mac', "12:34:56:78:00:00")
        with self.port() as port:
            mac = port['port']['mac_address']
            self.assertTrue(mac.startswith("12:34:56:78"))

    def test_bad_mac_format(self):
        cfg.CONF.set_override('base_mac', "bad_mac")
        try:
            self.plugin._check_base_mac_format()
        except:
            return
        self.fail("No exception for illegal base_mac format")

    def test_mac_exhaustion(self):
        # rather than actually consuming all MAC (would take a LONG time)
        # we just raise the exception that would result.
        @staticmethod
        def fake_gen_mac(context, net_id):
            raise q_exc.MacAddressGenerationFailure(net_id=net_id)

        with mock.patch.object(quantum.db.db_base_plugin_v2.QuantumDbPluginV2,
                               '_generate_mac', new=fake_gen_mac):
            res = self._create_network(fmt=self.fmt, name='net1',
                                       admin_state_up=True)
            network = self.deserialize(self.fmt, res)
            net_id = network['network']['id']
            res = self._create_port(self.fmt, net_id=net_id)
            self.assertEqual(res.status_int, 503)

    def test_requested_duplicate_ip(self):
        with self.subnet() as subnet:
            with self.port(subnet=subnet) as port:
                ips = port['port']['fixed_ips']
                self.assertEqual(len(ips), 1)
                self.assertEqual(ips[0]['ip_address'], '10.0.0.2')
                self.assertEqual(ips[0]['subnet_id'], subnet['subnet']['id'])
                # Check configuring of duplicate IP
                kwargs = {"fixed_ips": [{'subnet_id': subnet['subnet']['id'],
                                         'ip_address': ips[0]['ip_address']}]}
                net_id = port['port']['network_id']
                res = self._create_port(self.fmt, net_id=net_id, **kwargs)
                self.assertEqual(res.status_int, 409)

    def test_requested_subnet_delete(self):
        with self.subnet() as subnet:
            with self.port(subnet=subnet) as port:
                ips = port['port']['fixed_ips']
                self.assertEqual(len(ips), 1)
                self.assertEqual(ips[0]['ip_address'], '10.0.0.2')
                self.assertEqual(ips[0]['subnet_id'], subnet['subnet']['id'])
                req = self.new_delete_request('subnet',
                                              subnet['subnet']['id'])
                res = req.get_response(self.api)
                self.assertEqual(res.status_int, 404)

    def test_requested_subnet_id(self):
        with self.subnet() as subnet:
            with self.port(subnet=subnet) as port:
                ips = port['port']['fixed_ips']
                self.assertEqual(len(ips), 1)
                self.assertEqual(ips[0]['ip_address'], '10.0.0.2')
                self.assertEqual(ips[0]['subnet_id'], subnet['subnet']['id'])
                # Request a IP from specific subnet
                kwargs = {"fixed_ips": [{'subnet_id': subnet['subnet']['id']}]}
                net_id = port['port']['network_id']
                res = self._create_port(self.fmt, net_id=net_id, **kwargs)
                port2 = self.deserialize(self.fmt, res)
                ips = port2['port']['fixed_ips']
                self.assertEqual(len(ips), 1)
                self.assertEqual(ips[0]['ip_address'], '10.0.0.3')
                self.assertEqual(ips[0]['subnet_id'], subnet['subnet']['id'])
                self._delete('ports', port2['port']['id'])

    def test_requested_subnet_id_not_on_network(self):
        with self.subnet() as subnet:
            with self.port(subnet=subnet) as port:
                # Create new network
                res = self._create_network(fmt=self.fmt, name='net2',
                                           admin_state_up=True)
                network2 = self.deserialize(self.fmt, res)
                subnet2 = self._make_subnet(self.fmt, network2, "1.1.1.1",
                                            "1.1.1.0/24", ip_version=4)
                net_id = port['port']['network_id']
                # Request a IP from specific subnet
                kwargs = {"fixed_ips": [{'subnet_id':
                                         subnet2['subnet']['id']}]}
                net_id = port['port']['network_id']
                res = self._create_port(self.fmt, net_id=net_id, **kwargs)
                self.assertEqual(res.status_int, 400)

    def test_overlapping_subnets(self):
        with self.subnet() as subnet:
            tenant_id = subnet['subnet']['tenant_id']
            net_id = subnet['subnet']['network_id']
            res = self._create_subnet(self.fmt,
                                      tenant_id=tenant_id,
                                      net_id=net_id,
                                      cidr='10.0.0.225/28',
                                      ip_version=4,
                                      gateway_ip=ATTR_NOT_SPECIFIED)
            self.assertEqual(res.status_int, 400)

    def test_requested_subnet_id_v4_and_v6(self):
        with self.subnet() as subnet:
                # Get a IPv4 and IPv6 address
                tenant_id = subnet['subnet']['tenant_id']
                net_id = subnet['subnet']['network_id']
                res = self._create_subnet(self.fmt,
                                          tenant_id=tenant_id,
                                          net_id=net_id,
                                          cidr='2607:f0d0:1002:51::0/124',
                                          ip_version=6,
                                          gateway_ip=ATTR_NOT_SPECIFIED)
                subnet2 = self.deserialize(self.fmt, res)
                kwargs = {"fixed_ips":
                          [{'subnet_id': subnet['subnet']['id']},
                           {'subnet_id': subnet2['subnet']['id']}]}
                res = self._create_port(self.fmt, net_id=net_id, **kwargs)
                port3 = self.deserialize(self.fmt, res)
                ips = port3['port']['fixed_ips']
                self.assertEqual(len(ips), 2)
                self.assertEqual(ips[0]['ip_address'], '10.0.0.2')
                self.assertEqual(ips[0]['subnet_id'], subnet['subnet']['id'])
                self.assertEqual(ips[1]['ip_address'], '2607:f0d0:1002:51::2')
                self.assertEqual(ips[1]['subnet_id'], subnet2['subnet']['id'])
                res = self._create_port(self.fmt, net_id=net_id)
                port4 = self.deserialize(self.fmt, res)
                # Check that a v4 and a v6 address are allocated
                ips = port4['port']['fixed_ips']
                self.assertEqual(len(ips), 2)
                self.assertEqual(ips[0]['ip_address'], '10.0.0.3')
                self.assertEqual(ips[0]['subnet_id'], subnet['subnet']['id'])
                self.assertEqual(ips[1]['ip_address'], '2607:f0d0:1002:51::3')
                self.assertEqual(ips[1]['subnet_id'], subnet2['subnet']['id'])
                self._delete('ports', port3['port']['id'])
                self._delete('ports', port4['port']['id'])

    def test_range_allocation(self):
        with self.subnet(gateway_ip='10.0.0.3',
                         cidr='10.0.0.0/29') as subnet:
                kwargs = {"fixed_ips":
                          [{'subnet_id': subnet['subnet']['id']},
                           {'subnet_id': subnet['subnet']['id']},
                           {'subnet_id': subnet['subnet']['id']},
                           {'subnet_id': subnet['subnet']['id']},
                           {'subnet_id': subnet['subnet']['id']}]}
                net_id = subnet['subnet']['network_id']
                res = self._create_port(self.fmt, net_id=net_id, **kwargs)
                port = self.deserialize(self.fmt, res)
                ips = port['port']['fixed_ips']
                self.assertEqual(len(ips), 5)
                alloc = ['10.0.0.1', '10.0.0.2', '10.0.0.4', '10.0.0.5',
                         '10.0.0.6']
                for i in range(len(alloc)):
                    self.assertEqual(ips[i]['ip_address'], alloc[i])
                    self.assertEqual(ips[i]['subnet_id'],
                                     subnet['subnet']['id'])
                self._delete('ports', port['port']['id'])

        with self.subnet(gateway_ip='11.0.0.6',
                         cidr='11.0.0.0/29') as subnet:
                kwargs = {"fixed_ips":
                          [{'subnet_id': subnet['subnet']['id']},
                           {'subnet_id': subnet['subnet']['id']},
                           {'subnet_id': subnet['subnet']['id']},
                           {'subnet_id': subnet['subnet']['id']},
                           {'subnet_id': subnet['subnet']['id']}]}
                net_id = subnet['subnet']['network_id']
                res = self._create_port(self.fmt, net_id=net_id, **kwargs)
                port = self.deserialize(self.fmt, res)
                ips = port['port']['fixed_ips']
                self.assertEqual(len(ips), 5)
                alloc = ['11.0.0.1', '11.0.0.2', '11.0.0.3', '11.0.0.4',
                         '11.0.0.5']
                for i in range(len(alloc)):
                    self.assertEqual(ips[i]['ip_address'], alloc[i])
                    self.assertEqual(ips[i]['subnet_id'],
                                     subnet['subnet']['id'])
                self._delete('ports', port['port']['id'])

    def test_requested_invalid_fixed_ips(self):
        with self.subnet() as subnet:
            with self.port(subnet=subnet) as port:
                ips = port['port']['fixed_ips']
                self.assertEqual(len(ips), 1)
                self.assertEqual(ips[0]['ip_address'], '10.0.0.2')
                self.assertEqual(ips[0]['subnet_id'], subnet['subnet']['id'])
                # Test invalid subnet_id
                kwargs = {"fixed_ips":
                          [{'subnet_id': subnet['subnet']['id']},
                           {'subnet_id':
                            '00000000-ffff-ffff-ffff-000000000000'}]}
                net_id = port['port']['network_id']
                res = self._create_port(self.fmt, net_id=net_id, **kwargs)
                port2 = self.deserialize(self.fmt, res)
                self.assertEqual(res.status_int, 404)

                # Test invalid IP address on specified subnet_id
                kwargs = {"fixed_ips":
                          [{'subnet_id': subnet['subnet']['id'],
                            'ip_address': '1.1.1.1'}]}
                net_id = port['port']['network_id']
                res = self._create_port(self.fmt, net_id=net_id, **kwargs)
                port2 = self.deserialize(self.fmt, res)
                self.assertEqual(res.status_int, 400)

                # Test invalid addresses - IP's not on subnet or network
                # address or broadcast address
                bad_ips = ['1.1.1.1', '10.0.0.0', '10.0.0.255']
                net_id = port['port']['network_id']
                for ip in bad_ips:
                    kwargs = {"fixed_ips": [{'ip_address': ip}]}
                    res = self._create_port(self.fmt, net_id=net_id, **kwargs)
                    port2 = self.deserialize(self.fmt, res)
                    self.assertEqual(res.status_int, 400)

                # Enable allocation of gateway address
                kwargs = {"fixed_ips":
                          [{'subnet_id': subnet['subnet']['id'],
                            'ip_address': '10.0.0.1'}]}
                net_id = port['port']['network_id']
                res = self._create_port(self.fmt, net_id=net_id, **kwargs)
                port2 = self.deserialize(self.fmt, res)
                ips = port2['port']['fixed_ips']
                self.assertEqual(len(ips), 1)
                self.assertEqual(ips[0]['ip_address'], '10.0.0.1')
                self.assertEqual(ips[0]['subnet_id'], subnet['subnet']['id'])
                self._delete('ports', port2['port']['id'])

    def test_invalid_ip(self):
        with self.subnet() as subnet:
            # Allocate specific IP
            kwargs = {"fixed_ips": [{'subnet_id': subnet['subnet']['id'],
                                     'ip_address': '1011.0.0.5'}]}
            net_id = subnet['subnet']['network_id']
            res = self._create_port(self.fmt, net_id=net_id, **kwargs)
            self.assertEqual(res.status_int, 400)

    def test_requested_split(self):
        with self.subnet() as subnet:
            with self.port(subnet=subnet) as port:
                ports_to_delete = []
                ips = port['port']['fixed_ips']
                self.assertEqual(len(ips), 1)
                self.assertEqual(ips[0]['ip_address'], '10.0.0.2')
                self.assertEqual(ips[0]['subnet_id'], subnet['subnet']['id'])
                # Allocate specific IP
                kwargs = {"fixed_ips": [{'subnet_id': subnet['subnet']['id'],
                                         'ip_address': '10.0.0.5'}]}
                net_id = port['port']['network_id']
                res = self._create_port(self.fmt, net_id=net_id, **kwargs)
                port2 = self.deserialize(self.fmt, res)
                ports_to_delete.append(port2)
                ips = port2['port']['fixed_ips']
                self.assertEqual(len(ips), 1)
                self.assertEqual(ips[0]['ip_address'], '10.0.0.5')
                self.assertEqual(ips[0]['subnet_id'], subnet['subnet']['id'])
                # Allocate specific IP's
                allocated = ['10.0.0.3', '10.0.0.4', '10.0.0.6']

                for a in allocated:
                    res = self._create_port(self.fmt, net_id=net_id)
                    port2 = self.deserialize(self.fmt, res)
                    ports_to_delete.append(port2)
                    ips = port2['port']['fixed_ips']
                    self.assertEqual(len(ips), 1)
                    self.assertEqual(ips[0]['ip_address'], a)
                    self.assertEqual(ips[0]['subnet_id'],
                                     subnet['subnet']['id'])

                for p in ports_to_delete:
                    self._delete('ports', p['port']['id'])

    def test_duplicate_ips(self):
        with self.subnet() as subnet:
            # Allocate specific IP
            kwargs = {"fixed_ips": [{'subnet_id': subnet['subnet']['id'],
                                     'ip_address': '10.0.0.5'},
                                    {'subnet_id': subnet['subnet']['id'],
                                     'ip_address': '10.0.0.5'}]}
            net_id = subnet['subnet']['network_id']
            res = self._create_port(self.fmt, net_id=net_id, **kwargs)
            self.assertEqual(res.status_int, 400)

    def test_fixed_ip_invalid_subnet_id(self):
        with self.subnet() as subnet:
            # Allocate specific IP
            kwargs = {"fixed_ips": [{'subnet_id': 'i am invalid',
                                     'ip_address': '10.0.0.5'}]}
            net_id = subnet['subnet']['network_id']
            res = self._create_port(self.fmt, net_id=net_id, **kwargs)
            self.assertEqual(res.status_int, 400)

    def test_fixed_ip_invalid_ip(self):
        with self.subnet() as subnet:
            # Allocate specific IP
            kwargs = {"fixed_ips": [{'subnet_id': subnet['subnet']['id'],
                                     'ip_address': '10.0.0.55555'}]}
            net_id = subnet['subnet']['network_id']
            res = self._create_port(self.fmt, net_id=net_id, **kwargs)
            self.assertEqual(res.status_int, 400)

    def test_requested_ips_only(self):
        with self.subnet() as subnet:
            with self.port(subnet=subnet) as port:
                ips = port['port']['fixed_ips']
                self.assertEqual(len(ips), 1)
                self.assertEqual(ips[0]['ip_address'], '10.0.0.2')
                self.assertEqual(ips[0]['subnet_id'], subnet['subnet']['id'])
                ips_only = ['10.0.0.18', '10.0.0.20', '10.0.0.22', '10.0.0.21',
                            '10.0.0.3', '10.0.0.17', '10.0.0.19']
                ports_to_delete = []
                for i in ips_only:
                    kwargs = {"fixed_ips": [{'ip_address': i}]}
                    net_id = port['port']['network_id']
                    res = self._create_port(self.fmt, net_id=net_id, **kwargs)
                    port = self.deserialize(self.fmt, res)
                    ports_to_delete.append(port)
                    ips = port['port']['fixed_ips']
                    self.assertEqual(len(ips), 1)
                    self.assertEqual(ips[0]['ip_address'], i)
                    self.assertEqual(ips[0]['subnet_id'],
                                     subnet['subnet']['id'])
                for p in ports_to_delete:
                    self._delete('ports', p['port']['id'])

    def test_recycling(self):
        # set expirations to past so that recycling is checked
        reference = datetime.datetime(2012, 8, 13, 23, 11, 0)
        cfg.CONF.set_override('dhcp_lease_duration', 0)

        with self.subnet(cidr='10.0.1.0/24') as subnet:
            with self.port(subnet=subnet) as port:
                with mock.patch.object(timeutils, 'utcnow') as mock_utcnow:
                    mock_utcnow.return_value = reference
                    ips = port['port']['fixed_ips']
                    self.assertEqual(len(ips), 1)
                    self.assertEqual(ips[0]['ip_address'], '10.0.1.2')
                    self.assertEqual(ips[0]['subnet_id'],
                                     subnet['subnet']['id'])
                    net_id = port['port']['network_id']
                    ports = []
                    for i in range(16 - 3):
                        res = self._create_port(self.fmt, net_id=net_id)
                        p = self.deserialize(self.fmt, res)
                        ports.append(p)
                    for i in range(16 - 3):
                        x = random.randrange(0, len(ports), 1)
                        p = ports.pop(x)
                        self._delete('ports', p['port']['id'])
                    res = self._create_port(self.fmt, net_id=net_id)
                    port = self.deserialize(self.fmt, res)
                    ips = port['port']['fixed_ips']
                    self.assertEqual(len(ips), 1)
                    self.assertEqual(ips[0]['ip_address'], '10.0.1.3')
                    self.assertEqual(ips[0]['subnet_id'],
                                     subnet['subnet']['id'])
                    self._delete('ports', port['port']['id'])

    def test_invalid_admin_state(self):
        with self.network() as network:
            data = {'port': {'network_id': network['network']['id'],
                             'tenant_id': network['network']['tenant_id'],
                             'admin_state_up': 7,
                             'fixed_ips': []}}
            port_req = self.new_create_request('ports', data)
            res = port_req.get_response(self.api)
            self.assertEqual(res.status_int, 400)

    def test_invalid_mac_address(self):
        with self.network() as network:
            data = {'port': {'network_id': network['network']['id'],
                             'tenant_id': network['network']['tenant_id'],
                             'admin_state_up': 1,
                             'mac_address': 'mac',
                             'fixed_ips': []}}
            port_req = self.new_create_request('ports', data)
            res = port_req.get_response(self.api)
            self.assertEqual(res.status_int, 400)

    def test_default_allocation_expiration(self):
        cfg.CONF.set_override('dhcp_lease_duration', 120)
        reference = datetime.datetime(2012, 8, 13, 23, 11, 0)

        with mock.patch.object(timeutils, 'utcnow') as mock_utcnow:
            mock_utcnow.return_value = reference

            plugin = QuantumManager.get_plugin()
            expires = plugin._default_allocation_expiration()
            self.assertEqual(expires,
                             reference + datetime.timedelta(seconds=120))

    def test_update_fixed_ip_lease_expiration(self):
        cfg.CONF.set_override('dhcp_lease_duration', 10)
        plugin = QuantumManager.get_plugin()
        with self.subnet() as subnet:
            with self.port(subnet=subnet) as port:
                update_context = context.Context('', port['port']['tenant_id'])
                plugin.update_fixed_ip_lease_expiration(
                    update_context,
                    subnet['subnet']['network_id'],
                    port['port']['fixed_ips'][0]['ip_address'],
                    500)

                q = update_context.session.query(models_v2.IPAllocation)
                q = q.filter_by(
                    port_id=port['port']['id'],
                    ip_address=port['port']['fixed_ips'][0]['ip_address'])

                ip_allocation = q.one()

                self.assertThat(
                    ip_allocation.expiration - timeutils.utcnow(),
                    matchers.GreaterThan(datetime.timedelta(seconds=10)))

    def test_port_delete_holds_ip(self):
        base_class = db_base_plugin_v2.QuantumDbPluginV2
        with mock.patch.object(base_class, '_hold_ip') as hold_ip:
            with self.subnet() as subnet:
                with self.port(subnet=subnet, no_delete=True) as port:
                    req = self.new_delete_request('ports', port['port']['id'])
                    res = req.get_response(self.api)
                    self.assertEqual(res.status_int, 204)

                    hold_ip.assert_called_once_with(
                        mock.ANY,
                        port['port']['network_id'],
                        port['port']['fixed_ips'][0]['subnet_id'],
                        port['port']['id'],
                        port['port']['fixed_ips'][0]['ip_address'])

    def test_update_fixed_ip_lease_expiration_invalid_address(self):
        cfg.CONF.set_override('dhcp_lease_duration', 10)
        plugin = QuantumManager.get_plugin()
        with self.subnet() as subnet:
            with self.port(subnet=subnet) as port:
                update_context = context.Context('', port['port']['tenant_id'])
                with mock.patch.object(db_base_plugin_v2, 'LOG') as log:
                    plugin.update_fixed_ip_lease_expiration(
                        update_context,
                        subnet['subnet']['network_id'],
                        '255.255.255.0',
                        120)
                    self.assertTrue(log.mock_calls)

    def test_hold_ip_address(self):
        plugin = QuantumManager.get_plugin()
        with self.subnet() as subnet:
            with self.port(subnet=subnet) as port:
                update_context = context.Context('', port['port']['tenant_id'])
                port_id = port['port']['id']
                with mock.patch.object(db_base_plugin_v2, 'LOG') as log:
                    ip_address = port['port']['fixed_ips'][0]['ip_address']
                    plugin._hold_ip(
                        update_context,
                        subnet['subnet']['network_id'],
                        subnet['subnet']['id'],
                        port_id,
                        ip_address)
                    self.assertTrue(log.mock_calls)

                    q = update_context.session.query(models_v2.IPAllocation)
                    q = q.filter_by(port_id=None, ip_address=ip_address)

                self.assertEqual(len(q.all()), 1)

    def test_recycle_held_ip_address(self):
        plugin = QuantumManager.get_plugin()
        with self.subnet() as subnet:
            with self.port(subnet=subnet) as port:
                update_context = context.Context('', port['port']['tenant_id'])
                port_id = port['port']['id']
                port_obj = plugin._get_port(update_context, port_id)

                for fixed_ip in port_obj.fixed_ips:
                    fixed_ip.active = False
                    fixed_ip.expiration = datetime.datetime.utcnow()

                with mock.patch.object(plugin, '_recycle_ip') as rc:
                    plugin._recycle_expired_ip_allocations(
                        update_context, subnet['subnet']['network_id'])
                    rc.assertEqual(len(rc.mock_calls), 1)
                    self.assertEqual(update_context._recycled_networks,
                                     set([subnet['subnet']['network_id']]))

    def test_recycle_expired_previously_run_within_context(self):
        plugin = QuantumManager.get_plugin()
        with self.subnet() as subnet:
            with self.port(subnet=subnet) as port:
                update_context = context.Context('', port['port']['tenant_id'])
                port_id = port['port']['id']
                port_obj = plugin._get_port(update_context, port_id)

                update_context._recycled_networks = set(
                    [subnet['subnet']['network_id']])

                for fixed_ip in port_obj.fixed_ips:
                    fixed_ip.active = False
                    fixed_ip.expiration = datetime.datetime.utcnow()

                with mock.patch.object(plugin, '_recycle_ip') as rc:
                    plugin._recycle_expired_ip_allocations(
                        update_context, subnet['subnet']['network_id'])
                    rc.assertFalse(rc.called)
                    self.assertEqual(update_context._recycled_networks,
                                     set([subnet['subnet']['network_id']]))

    def test_max_fixed_ips_exceeded(self):
        with self.subnet(gateway_ip='10.0.0.3',
                         cidr='10.0.0.0/24') as subnet:
                kwargs = {"fixed_ips":
                          [{'subnet_id': subnet['subnet']['id']},
                           {'subnet_id': subnet['subnet']['id']},
                           {'subnet_id': subnet['subnet']['id']},
                           {'subnet_id': subnet['subnet']['id']},
                           {'subnet_id': subnet['subnet']['id']},
                           {'subnet_id': subnet['subnet']['id']}]}
                net_id = subnet['subnet']['network_id']
                res = self._create_port(self.fmt, net_id=net_id, **kwargs)
                self.assertEqual(res.status_int, 400)

    def test_update_max_fixed_ips_exceeded(self):
        with self.subnet(gateway_ip='10.0.0.3',
                         cidr='10.0.0.0/24') as subnet:
            with self.port(subnet) as port:
                data = {'port': {'fixed_ips':
                                 [{'subnet_id': subnet['subnet']['id'],
                                   'ip_address': '10.0.0.2'},
                                  {'subnet_id': subnet['subnet']['id'],
                                   'ip_address': '10.0.0.4'},
                                  {'subnet_id': subnet['subnet']['id']},
                                  {'subnet_id': subnet['subnet']['id']},
                                  {'subnet_id': subnet['subnet']['id']},
                                  {'subnet_id': subnet['subnet']['id']}]}}
                req = self.new_update_request('ports', data,
                                              port['port']['id'])
                res = req.get_response(self.api)
                self.assertEqual(res.status_int, 400)


class TestNetworksV2(QuantumDbPluginV2TestCase):
    # NOTE(cerberus): successful network update and delete are
    #                 effectively tested above
    def test_create_network(self):
        name = 'net1'
        keys = [('subnets', []), ('name', name), ('admin_state_up', True),
                ('status', 'ACTIVE'), ('shared', False)]
        with self.network(name=name) as net:
            for k, v in keys:
                self.assertEqual(net['network'][k], v)

    def test_create_public_network(self):
        name = 'public_net'
        keys = [('subnets', []), ('name', name), ('admin_state_up', True),
                ('status', 'ACTIVE'), ('shared', True)]
        with self.network(name=name, shared=True) as net:
            for k, v in keys:
                self.assertEqual(net['network'][k], v)

    def test_create_public_network_no_admin_tenant(self):
        name = 'public_net'
        with testtools.ExpectedException(
                webob.exc.HTTPClientError) as ctx_manager:
            with self.network(name=name,
                              shared=True,
                              tenant_id="another_tenant",
                              set_context=True):
                pass
            self.assertEqual(ctx_manager.exception.code, 403)

    def test_update_network(self):
        with self.network() as network:
            data = {'network': {'name': 'a_brand_new_name'}}
            req = self.new_update_request('networks',
                                          data,
                                          network['network']['id'])
            res = self.deserialize(self.fmt, req.get_response(self.api))
            self.assertEqual(res['network']['name'],
                             data['network']['name'])

    def test_update_shared_network_noadmin_returns_403(self):
        with self.network(shared=True) as network:
            data = {'network': {'name': 'a_brand_new_name'}}
            req = self.new_update_request('networks',
                                          data,
                                          network['network']['id'])
            req.environ['quantum.context'] = context.Context('', 'somebody')
            res = req.get_response(self.api)
            # The API layer always returns 404 on updates in place of 403
            self.assertEqual(res.status_int, 404)

    def test_update_network_set_shared(self):
        with self.network(shared=False) as network:
            data = {'network': {'shared': True}}
            req = self.new_update_request('networks',
                                          data,
                                          network['network']['id'])
            res = self.deserialize(self.fmt, req.get_response(self.api))
            self.assertTrue(res['network']['shared'])

    def test_update_network_with_subnet_set_shared(self):
        with self.network(shared=False) as network:
            with self.subnet(network=network) as subnet:
                data = {'network': {'shared': True}}
                req = self.new_update_request('networks',
                                              data,
                                              network['network']['id'])
                res = self.deserialize(self.fmt, req.get_response(self.api))
                self.assertTrue(res['network']['shared'])
                # must query db to see whether subnet's shared attribute
                # has been updated or not
                ctx = context.Context('', '', is_admin=True)
                subnet_db = QuantumManager.get_plugin()._get_subnet(
                    ctx, subnet['subnet']['id'])
                self.assertEqual(subnet_db['shared'], True)

    def test_update_network_set_not_shared_single_tenant(self):
        with self.network(shared=True) as network:
            res1 = self._create_port(self.fmt,
                                     network['network']['id'],
                                     201,
                                     tenant_id=network['network']['tenant_id'],
                                     set_context=True)
            data = {'network': {'shared': False}}
            req = self.new_update_request('networks',
                                          data,
                                          network['network']['id'])
            res = self.deserialize(self.fmt, req.get_response(self.api))
            self.assertFalse(res['network']['shared'])
            port1 = self.deserialize(self.fmt, res1)
            self._delete('ports', port1['port']['id'])

    def test_update_network_set_not_shared_other_tenant_returns_409(self):
        with self.network(shared=True) as network:
            res1 = self._create_port(self.fmt,
                                     network['network']['id'],
                                     201,
                                     tenant_id='somebody_else',
                                     set_context=True)
            data = {'network': {'shared': False}}
            req = self.new_update_request('networks',
                                          data,
                                          network['network']['id'])
            self.assertEqual(req.get_response(self.api).status_int, 409)
            port1 = self.deserialize(self.fmt, res1)
            self._delete('ports', port1['port']['id'])

    def test_update_network_set_not_shared_multi_tenants_returns_409(self):
        with self.network(shared=True) as network:
            res1 = self._create_port(self.fmt,
                                     network['network']['id'],
                                     201,
                                     tenant_id='somebody_else',
                                     set_context=True)
            res2 = self._create_port(self.fmt,
                                     network['network']['id'],
                                     201,
                                     tenant_id=network['network']['tenant_id'],
                                     set_context=True)
            data = {'network': {'shared': False}}
            req = self.new_update_request('networks',
                                          data,
                                          network['network']['id'])
            self.assertEqual(req.get_response(self.api).status_int, 409)
            port1 = self.deserialize(self.fmt, res1)
            port2 = self.deserialize(self.fmt, res2)
            self._delete('ports', port1['port']['id'])
            self._delete('ports', port2['port']['id'])

    def test_update_network_set_not_shared_multi_tenants2_returns_409(self):
        with self.network(shared=True) as network:
            res1 = self._create_port(self.fmt,
                                     network['network']['id'],
                                     201,
                                     tenant_id='somebody_else',
                                     set_context=True)
            self._create_subnet(self.fmt,
                                network['network']['id'],
                                '10.0.0.0/24',
                                201,
                                tenant_id=network['network']['tenant_id'],
                                set_context=True)
            data = {'network': {'shared': False}}
            req = self.new_update_request('networks',
                                          data,
                                          network['network']['id'])
            self.assertEqual(req.get_response(self.api).status_int, 409)

            port1 = self.deserialize(self.fmt, res1)
            self._delete('ports', port1['port']['id'])

    def test_create_networks_bulk_native(self):
        if self._skip_native_bulk:
            self.skipTest("Plugin does not support native bulk network create")
        res = self._create_network_bulk(self.fmt, 2, 'test', True)
        self._validate_behavior_on_bulk_success(res, 'networks')

    def test_create_networks_bulk_native_quotas(self):
        if self._skip_native_bulk:
            self.skipTest("Plugin does not support native bulk network create")
        quota = 4
        cfg.CONF.set_override('quota_network', quota, group='QUOTAS')
        res = self._create_network_bulk(self.fmt, quota + 1, 'test', True)
        self._validate_behavior_on_bulk_failure(res, 'networks', errcode=409)

    def test_create_networks_bulk_tenants_and_quotas(self):
        if self._skip_native_bulk:
            self.skipTest("Plugin does not support native bulk network create")
        quota = 2
        cfg.CONF.set_override('quota_network', quota, group='QUOTAS')
        networks = [{'network': {'name': 'n1',
                                 'tenant_id': self._tenant_id}},
                    {'network': {'name': 'n2',
                                 'tenant_id': self._tenant_id}},
                    {'network': {'name': 'n1',
                                 'tenant_id': 't1'}},
                    {'network': {'name': 'n2',
                                 'tenant_id': 't1'}}]

        res = self._create_bulk_from_list(self.fmt, 'network', networks)
        self.assertEqual(res.status_int, 201)

    def test_create_networks_bulk_tenants_and_quotas_fail(self):
        if self._skip_native_bulk:
            self.skipTest("Plugin does not support native bulk network create")
        quota = 2
        cfg.CONF.set_override('quota_network', quota, group='QUOTAS')
        networks = [{'network': {'name': 'n1',
                                 'tenant_id': self._tenant_id}},
                    {'network': {'name': 'n2',
                                 'tenant_id': self._tenant_id}},
                    {'network': {'name': 'n1',
                                 'tenant_id': 't1'}},
                    {'network': {'name': 'n3',
                                 'tenant_id': self._tenant_id}},
                    {'network': {'name': 'n2',
                                 'tenant_id': 't1'}}]

        res = self._create_bulk_from_list(self.fmt, 'network', networks)
        self.assertEqual(res.status_int, 409)

    def test_create_networks_bulk_emulated(self):
        real_has_attr = hasattr

        #ensures the API choose the emulation code path
        def fakehasattr(item, attr):
            if attr.endswith('__native_bulk_support'):
                return False
            return real_has_attr(item, attr)

        with mock.patch('__builtin__.hasattr',
                        new=fakehasattr):
            res = self._create_network_bulk(self.fmt, 2, 'test', True)
            self._validate_behavior_on_bulk_success(res, 'networks')

    def test_create_networks_bulk_wrong_input(self):
        res = self._create_network_bulk(self.fmt, 2, 'test', True,
                                        override={1:
                                                  {'admin_state_up': 'doh'}})
        self.assertEqual(res.status_int, 400)
        req = self.new_list_request('networks')
        res = req.get_response(self.api)
        self.assertEqual(res.status_int, 200)
        nets = self.deserialize(self.fmt, res)
        self.assertEqual(len(nets['networks']), 0)

    def test_create_networks_bulk_emulated_plugin_failure(self):
        real_has_attr = hasattr

        def fakehasattr(item, attr):
            if attr.endswith('__native_bulk_support'):
                return False
            return real_has_attr(item, attr)

        orig = QuantumManager.get_plugin().create_network
        #ensures the API choose the emulation code path
        with mock.patch('__builtin__.hasattr',
                        new=fakehasattr):
            with mock.patch.object(QuantumManager.get_plugin(),
                                   'create_network') as patched_plugin:

                def side_effect(*args, **kwargs):
                    return self._do_side_effect(patched_plugin, orig,
                                                *args, **kwargs)

                patched_plugin.side_effect = side_effect
                res = self._create_network_bulk(self.fmt, 2, 'test', True)
                # We expect a 500 as we injected a fault in the plugin
                self._validate_behavior_on_bulk_failure(res, 'networks', 500)

    def test_create_networks_bulk_native_plugin_failure(self):
        if self._skip_native_bulk:
            self.skipTest("Plugin does not support native bulk network create")
        orig = QuantumManager.get_plugin().create_network
        with mock.patch.object(QuantumManager.get_plugin(),
                               'create_network') as patched_plugin:

            def side_effect(*args, **kwargs):
                return self._do_side_effect(patched_plugin, orig,
                                            *args, **kwargs)

            patched_plugin.side_effect = side_effect
            res = self._create_network_bulk(self.fmt, 2, 'test', True)
            # We expect a 500 as we injected a fault in the plugin
            self._validate_behavior_on_bulk_failure(res, 'networks', 500)

    def test_list_networks(self):
        with contextlib.nested(self.network(),
                               self.network(),
                               self.network()) as networks:
            self._test_list_resources('network', networks)

    def test_list_networks_with_sort_native(self):
        if self._skip_native_sorting:
            self.skipTest("Skip test for not implemented sorting feature")
        with contextlib.nested(self.network(admin_status_up=True,
                                            name='net1'),
                               self.network(admin_status_up=False,
                                            name='net2'),
                               self.network(admin_status_up=False,
                                            name='net3')
                               ) as (net1, net2, net3):
            self._test_list_with_sort('network', (net3, net2, net1),
                                      [('admin_state_up', 'asc'),
                                       ('name', 'desc')])

    def test_list_networks_with_sort_extended_attr_native_returns_400(self):
        if self._skip_native_sorting:
            self.skipTest("Skip test for not implemented sorting feature")
        with contextlib.nested(self.network(admin_status_up=True,
                                            name='net1'),
                               self.network(admin_status_up=False,
                                            name='net2'),
                               self.network(admin_status_up=False,
                                            name='net3')
                               ):
            req = self.new_list_request(
                'networks',
                params='sort_key=provider:segmentation_id&sort_dir=asc')
            res = req.get_response(self.api)
            self.assertEqual(400, res.status_int)

    def test_list_networks_with_sort_remote_key_native_returns_400(self):
        if self._skip_native_sorting:
            self.skipTest("Skip test for not implemented sorting feature")
        with contextlib.nested(self.network(admin_status_up=True,
                                            name='net1'),
                               self.network(admin_status_up=False,
                                            name='net2'),
                               self.network(admin_status_up=False,
                                            name='net3')
                               ):
            req = self.new_list_request(
                'networks', params='sort_key=subnets&sort_dir=asc')
            res = req.get_response(self.api)
            self.assertEqual(400, res.status_int)

    def test_list_networks_with_sort_emulated(self):
        helper_patcher = mock.patch(
            'quantum.api.v2.base.Controller._get_sorting_helper',
            new=_fake_get_sorting_helper)
        helper_patcher.start()
        try:
            with contextlib.nested(self.network(admin_status_up=True,
                                                name='net1'),
                                   self.network(admin_status_up=False,
                                                name='net2'),
                                   self.network(admin_status_up=False,
                                                name='net3')
                                   ) as (net1, net2, net3):
                self._test_list_with_sort('network', (net3, net2, net1),
                                          [('admin_state_up', 'asc'),
                                           ('name', 'desc')])
        finally:
            helper_patcher.stop()

    def test_list_networks_with_pagination_native(self):
        if self._skip_native_pagination:
            self.skipTest("Skip test for not implemented pagination feature")
        with contextlib.nested(self.network(name='net1'),
                               self.network(name='net2'),
                               self.network(name='net3')
                               ) as (net1, net2, net3):
            self._test_list_with_pagination('network',
                                            (net1, net2, net3),
                                            ('name', 'asc'), 2, 2)

    def test_list_networks_with_pagination_emulated(self):
        helper_patcher = mock.patch(
            'quantum.api.v2.base.Controller._get_pagination_helper',
            new=_fake_get_pagination_helper)
        helper_patcher.start()
        try:
            with contextlib.nested(self.network(name='net1'),
                                   self.network(name='net2'),
                                   self.network(name='net3')
                                   ) as (net1, net2, net3):
                self._test_list_with_pagination('network',
                                                (net1, net2, net3),
                                                ('name', 'asc'), 2, 2)
        finally:
            helper_patcher.stop()

    def test_list_networks_without_pk_in_fields_pagination_emulated(self):
        helper_patcher = mock.patch(
            'quantum.api.v2.base.Controller._get_pagination_helper',
            new=_fake_get_pagination_helper)
        helper_patcher.start()
        try:
            with contextlib.nested(self.network(name='net1',
                                                shared=True),
                                   self.network(name='net2',
                                                shared=False),
                                   self.network(name='net3',
                                                shared=True)
                                   ) as (net1, net2, net3):
                self._test_list_with_pagination('network',
                                                (net1, net2, net3),
                                                ('name', 'asc'), 2, 2,
                                                query_params="fields=name",
                                                verify_key='name')
        finally:
            helper_patcher.stop()

    def test_list_networks_without_pk_in_fields_pagination_native(self):
        if self._skip_native_pagination:
            self.skipTest("Skip test for not implemented pagination feature")
        with contextlib.nested(self.network(name='net1'),
                               self.network(name='net2'),
                               self.network(name='net3')
                               ) as (net1, net2, net3):
            self._test_list_with_pagination('network',
                                            (net1, net2, net3),
                                            ('name', 'asc'), 2, 2,
                                            query_params="fields=shared",
                                            verify_key='shared')

    def test_list_networks_with_pagination_reverse_native(self):
        if self._skip_native_pagination:
            self.skipTest("Skip test for not implemented pagination feature")
        with contextlib.nested(self.network(name='net1'),
                               self.network(name='net2'),
                               self.network(name='net3')
                               ) as (net1, net2, net3):
            self._test_list_with_pagination_reverse('network',
                                                    (net1, net2, net3),
                                                    ('name', 'asc'), 2, 2)

    def test_list_networks_with_pagination_reverse_emulated(self):
        helper_patcher = mock.patch(
            'quantum.api.v2.base.Controller._get_pagination_helper',
            new=_fake_get_pagination_helper)
        helper_patcher.start()
        try:
            with contextlib.nested(self.network(name='net1'),
                                   self.network(name='net2'),
                                   self.network(name='net3')
                                   ) as (net1, net2, net3):
                self._test_list_with_pagination_reverse('network',
                                                        (net1, net2, net3),
                                                        ('name', 'asc'), 2, 2)
        finally:
            helper_patcher.stop()

    def test_list_networks_with_parameters(self):
        with contextlib.nested(self.network(name='net1',
                                            admin_state_up=False),
                               self.network(name='net2')) as (net1, net2):
            query_params = 'admin_state_up=False'
            self._test_list_resources('network', [net1],
                                      query_params=query_params)
            query_params = 'admin_state_up=True'
            self._test_list_resources('network', [net2],
                                      query_params=query_params)

    def test_list_networks_with_fields(self):
        with self.network(name='net1') as net1:
            req = self.new_list_request('networks',
                                        params='fields=name')
            res = self.deserialize(self.fmt, req.get_response(self.api))
            self.assertEqual(1, len(res['networks']))
            self.assertEqual(res['networks'][0]['name'],
                             net1['network']['name'])
            self.assertEqual(None,
                             res['networks'][0].get('id'))

    def test_list_networks_with_parameters_invalid_values(self):
        with contextlib.nested(self.network(name='net1',
                                            admin_state_up=False),
                               self.network(name='net2')) as (net1, net2):
            req = self.new_list_request('networks',
                                        params='admin_state_up=fake')
            res = req.get_response(self.api)
            self.assertEqual(400, res.status_int)

    def test_show_network(self):
        with self.network(name='net1') as net:
            req = self.new_show_request('networks', net['network']['id'])
            res = self.deserialize(self.fmt, req.get_response(self.api))
            self.assertEqual(res['network']['name'],
                             net['network']['name'])

    def test_show_network_with_subnet(self):
        with self.network(name='net1') as net:
            with self.subnet(net) as subnet:
                req = self.new_show_request('networks', net['network']['id'])
                res = self.deserialize(self.fmt, req.get_response(self.api))
                self.assertEqual(res['network']['subnets'][0],
                                 subnet['subnet']['id'])

    def test_invalid_admin_status(self):
        value = [[7, False, 400], [True, True, 201], ["True", True, 201],
                 ["true", True, 201], [1, True, 201], ["False", False, 201],
                 [False, False, 201], ["false", False, 201],
                 ["7", False, 400]]
        for v in value:
            data = {'network': {'name': 'net',
                                'admin_state_up': v[0],
                                'tenant_id': self._tenant_id}}
            network_req = self.new_create_request('networks', data)
            req = network_req.get_response(self.api)
            self.assertEqual(req.status_int, v[2])
            if v[2] == 201:
                res = self.deserialize(self.fmt, req)
                self.assertEqual(res['network']['admin_state_up'], v[1])


class TestSubnetsV2(QuantumDbPluginV2TestCase):

    def _test_create_subnet(self, network=None, expected=None, **kwargs):
        keys = kwargs.copy()
        keys.setdefault('cidr', '10.0.0.0/24')
        keys.setdefault('ip_version', 4)
        keys.setdefault('enable_dhcp', True)
        with self.subnet(network=network, **keys) as subnet:
            # verify the response has each key with the correct value
            for k in keys:
                self.assertIn(k, subnet['subnet'])
                self.assertEqual(subnet['subnet'][k], keys[k])
            # verify the configured validations are correct
            if expected:
                for k in expected:
                    self.assertIn(k, subnet['subnet'])
                    self.assertEqual(subnet['subnet'][k], expected[k])
            return subnet

    def test_create_subnet(self):
        gateway_ip = '10.0.0.1'
        cidr = '10.0.0.0/24'
        subnet = self._test_create_subnet(gateway_ip=gateway_ip,
                                          cidr=cidr)
        self.assertEqual(4, subnet['subnet']['ip_version'])
        self.assertIn('name', subnet['subnet'])

    def test_create_two_subnets(self):
        gateway_ips = ['10.0.0.1', '10.0.1.1']
        cidrs = ['10.0.0.0/24', '10.0.1.0/24']
        with self.network() as network:
            with self.subnet(network=network,
                             gateway_ip=gateway_ips[0],
                             cidr=cidrs[0]):
                with self.subnet(network=network,
                                 gateway_ip=gateway_ips[1],
                                 cidr=cidrs[1]):
                    net_req = self.new_show_request('networks',
                                                    network['network']['id'])
                    raw_res = net_req.get_response(self.api)
                    net_res = self.deserialize(self.fmt, raw_res)
                    for subnet_id in net_res['network']['subnets']:
                        sub_req = self.new_show_request('subnets', subnet_id)
                        raw_res = sub_req.get_response(self.api)
                        sub_res = self.deserialize(self.fmt, raw_res)
                        self.assertIn(sub_res['subnet']['cidr'], cidrs)
                        self.assertIn(sub_res['subnet']['gateway_ip'],
                                      gateway_ips)

    def test_create_two_subnets_same_cidr_returns_400(self):
        gateway_ip_1 = '10.0.0.1'
        cidr_1 = '10.0.0.0/24'
        gateway_ip_2 = '10.0.0.10'
        cidr_2 = '10.0.0.0/24'
        with self.network() as network:
            with self.subnet(network=network,
                             gateway_ip=gateway_ip_1,
                             cidr=cidr_1):
                with testtools.ExpectedException(
                        webob.exc.HTTPClientError) as ctx_manager:
                    with self.subnet(network=network,
                                     gateway_ip=gateway_ip_2,
                                     cidr=cidr_2):
                        pass
                    self.assertEqual(ctx_manager.exception.code, 400)

    def test_create_subnet_bad_V4_cidr(self):
        with self.network() as network:
            data = {'subnet': {'network_id': network['network']['id'],
                    'cidr': '10.0.2.0',
                    'ip_version': '4',
                    'tenant_id': network['network']['tenant_id'],
                    'gateway_ip': '10.0.2.1'}}
            subnet_req = self.new_create_request('subnets', data)
            res = subnet_req.get_response(self.api)
            self.assertEqual(res.status_int, 400)

    def test_create_subnet_bad_V6_cidr(self):
        with self.network() as network:
            data = {'subnet': {'network_id': network['network']['id'],
                    'cidr': 'fe80::',
                    'ip_version': '6',
                    'tenant_id': network['network']['tenant_id'],
                    'gateway_ip': 'fe80::1'}}
            subnet_req = self.new_create_request('subnets', data)
            res = subnet_req.get_response(self.api)
            self.assertEqual(res.status_int, 400)

    def test_create_2_subnets_overlapping_cidr_allowed_returns_200(self):
        cidr_1 = '10.0.0.0/23'
        cidr_2 = '10.0.0.0/24'
        cfg.CONF.set_override('allow_overlapping_ips', True)

        with contextlib.nested(self.subnet(cidr=cidr_1),
                               self.subnet(cidr=cidr_2)):
            pass

    def test_create_2_subnets_overlapping_cidr_not_allowed_returns_400(self):
        cidr_1 = '10.0.0.0/23'
        cidr_2 = '10.0.0.0/24'
        cfg.CONF.set_override('allow_overlapping_ips', False)
        with testtools.ExpectedException(
                webob.exc.HTTPClientError) as ctx_manager:
            with contextlib.nested(self.subnet(cidr=cidr_1),
                                   self.subnet(cidr=cidr_2)):
                pass
            self.assertEqual(ctx_manager.exception.code, 400)

    def test_create_subnets_bulk_native(self):
        if self._skip_native_bulk:
            self.skipTest("Plugin does not support native bulk subnet create")
        with self.network() as net:
            res = self._create_subnet_bulk(self.fmt, 2, net['network']['id'],
                                           'test')
            self._validate_behavior_on_bulk_success(res, 'subnets')

    def test_create_subnets_bulk_emulated(self):
        real_has_attr = hasattr

        #ensures the API choose the emulation code path
        def fakehasattr(item, attr):
            if attr.endswith('__native_bulk_support'):
                return False
            return real_has_attr(item, attr)

        with mock.patch('__builtin__.hasattr',
                        new=fakehasattr):
            with self.network() as net:
                res = self._create_subnet_bulk(self.fmt, 2,
                                               net['network']['id'],
                                               'test')
                self._validate_behavior_on_bulk_success(res, 'subnets')

    def test_create_subnets_bulk_emulated_plugin_failure(self):
        real_has_attr = hasattr

        #ensures the API choose the emulation code path
        def fakehasattr(item, attr):
            if attr.endswith('__native_bulk_support'):
                return False
            return real_has_attr(item, attr)

        with mock.patch('__builtin__.hasattr',
                        new=fakehasattr):
            orig = QuantumManager.get_plugin().create_subnet
            with mock.patch.object(QuantumManager.get_plugin(),
                                   'create_subnet') as patched_plugin:

                def side_effect(*args, **kwargs):
                    self._do_side_effect(patched_plugin, orig,
                                         *args, **kwargs)

                patched_plugin.side_effect = side_effect
                with self.network() as net:
                    res = self._create_subnet_bulk(self.fmt, 2,
                                                   net['network']['id'],
                                                   'test')
                # We expect a 500 as we injected a fault in the plugin
                self._validate_behavior_on_bulk_failure(res, 'subnets', 500)

    def test_create_subnets_bulk_native_plugin_failure(self):
        if self._skip_native_bulk:
            self.skipTest("Plugin does not support native bulk subnet create")
        orig = QuantumManager._instance.plugin.create_subnet
        with mock.patch.object(QuantumManager._instance.plugin,
                               'create_subnet') as patched_plugin:
            def side_effect(*args, **kwargs):
                return self._do_side_effect(patched_plugin, orig,
                                            *args, **kwargs)

            patched_plugin.side_effect = side_effect
            with self.network() as net:
                res = self._create_subnet_bulk(self.fmt, 2,
                                               net['network']['id'],
                                               'test')

                # We expect a 500 as we injected a fault in the plugin
                self._validate_behavior_on_bulk_failure(res, 'subnets', 500)

    def test_delete_subnet(self):
        gateway_ip = '10.0.0.1'
        cidr = '10.0.0.0/24'
        # Create new network
        res = self._create_network(fmt=self.fmt, name='net',
                                   admin_state_up=True)
        network = self.deserialize(self.fmt, res)
        subnet = self._make_subnet(self.fmt, network, gateway_ip,
                                   cidr, ip_version=4)
        req = self.new_delete_request('subnets', subnet['subnet']['id'])
        res = req.get_response(self.api)
        self.assertEqual(res.status_int, 204)

    def test_delete_subnet_port_exists_owned_by_network(self):
        gateway_ip = '10.0.0.1'
        cidr = '10.0.0.0/24'
        # Create new network
        res = self._create_network(fmt=self.fmt, name='net',
                                   admin_state_up=True)
        network = self.deserialize(self.fmt, res)
        subnet = self._make_subnet(self.fmt, network, gateway_ip,
                                   cidr, ip_version=4)
        self._create_port(self.fmt,
                          network['network']['id'],
                          device_owner='network:dhcp')
        req = self.new_delete_request('subnets', subnet['subnet']['id'])
        res = req.get_response(self.api)
        self.assertEqual(res.status_int, 204)

    def test_delete_subnet_port_exists_owned_by_other(self):
        with self.subnet() as subnet:
            with self.port(subnet=subnet):
                id = subnet['subnet']['id']
                req = self.new_delete_request('subnets', id)
                res = req.get_response(self.api)
                data = self.deserialize(self.fmt, res)
                self.assertEqual(res.status_int, 409)
                msg = str(q_exc.SubnetInUse(subnet_id=id))
                self.assertEqual(data['QuantumError'], msg)

    def test_delete_network(self):
        gateway_ip = '10.0.0.1'
        cidr = '10.0.0.0/24'
        # Create new network
        res = self._create_network(fmt=self.fmt, name='net',
                                   admin_state_up=True)
        network = self.deserialize(self.fmt, res)
        self._make_subnet(self.fmt, network, gateway_ip, cidr, ip_version=4)
        req = self.new_delete_request('networks', network['network']['id'])
        res = req.get_response(self.api)
        self.assertEqual(res.status_int, 204)

    def test_create_subnet_bad_tenant(self):
        with self.network() as network:
            data = {'subnet': {'network_id': network['network']['id'],
                               'cidr': '10.0.2.0/24',
                               'ip_version': 4,
                               'tenant_id': 'bad_tenant_id',
                               'gateway_ip': '10.0.2.1'}}

            subnet_req = self.new_create_request('subnets', data)
            res = subnet_req.get_response(self.api)
            self.assertEqual(res.status_int, 403)

    def test_create_subnet_bad_ip_version(self):
        with self.network() as network:
            # Check bad IP version
            data = {'subnet': {'network_id': network['network']['id'],
                               'cidr': '10.0.2.0/24',
                               'ip_version': 'abc',
                               'tenant_id': network['network']['tenant_id'],
                               'gateway_ip': '10.0.2.1'}}
            subnet_req = self.new_create_request('subnets', data)
            res = subnet_req.get_response(self.api)
            self.assertEqual(res.status_int, 400)

    def test_create_subnet_bad_ip_version_null(self):
        with self.network() as network:
            # Check bad IP version
            data = {'subnet': {'network_id': network['network']['id'],
                               'cidr': '10.0.2.0/24',
                               'ip_version': None,
                               'tenant_id': network['network']['tenant_id'],
                               'gateway_ip': '10.0.2.1'}}
            subnet_req = self.new_create_request('subnets', data)
            res = subnet_req.get_response(self.api)
            self.assertEqual(res.status_int, 400)

    def test_create_subnet_bad_uuid(self):
        with self.network() as network:
            # Check invalid UUID
            data = {'subnet': {'network_id': None,
                               'cidr': '10.0.2.0/24',
                               'ip_version': 4,
                               'tenant_id': network['network']['tenant_id'],
                               'gateway_ip': '10.0.2.1'}}
            subnet_req = self.new_create_request('subnets', data)
            res = subnet_req.get_response(self.api)
            self.assertEqual(res.status_int, 400)

    def test_create_subnet_bad_boolean(self):
        with self.network() as network:
            # Check invalid boolean
            data = {'subnet': {'network_id': network['network']['id'],
                               'cidr': '10.0.2.0/24',
                               'ip_version': '4',
                               'enable_dhcp': None,
                               'tenant_id': network['network']['tenant_id'],
                               'gateway_ip': '10.0.2.1'}}
            subnet_req = self.new_create_request('subnets', data)
            res = subnet_req.get_response(self.api)
            self.assertEqual(res.status_int, 400)

    def test_create_subnet_bad_pools(self):
        with self.network() as network:
            # Check allocation pools
            allocation_pools = [[{'end': '10.0.0.254'}],
                                [{'start': '10.0.0.254'}],
                                [{'start': '1000.0.0.254'}],
                                [{'start': '10.0.0.2', 'end': '10.0.0.254'},
                                 {'end': '10.0.0.254'}],
                                None,
                                [{'start': '10.0.0.2', 'end': '10.0.0.3'},
                                 {'start': '10.0.0.2', 'end': '10.0.0.3'}]]
            tenant_id = network['network']['tenant_id']
            for pool in allocation_pools:
                data = {'subnet': {'network_id': network['network']['id'],
                                   'cidr': '10.0.2.0/24',
                                   'ip_version': '4',
                                   'tenant_id': tenant_id,
                                   'gateway_ip': '10.0.2.1',
                                   'allocation_pools': pool}}
                subnet_req = self.new_create_request('subnets', data)
                res = subnet_req.get_response(self.api)
                self.assertEqual(res.status_int, 400)

    def test_create_subnet_bad_nameserver(self):
        with self.network() as network:
            # Check nameservers
            nameserver_pools = [['1100.0.0.2'],
                                ['1.1.1.2', '1.1000.1.3'],
                                ['1.1.1.2', '1.1.1.2']]
            tenant_id = network['network']['tenant_id']
            for nameservers in nameserver_pools:
                data = {'subnet': {'network_id': network['network']['id'],
                                   'cidr': '10.0.2.0/24',
                                   'ip_version': '4',
                                   'tenant_id': tenant_id,
                                   'gateway_ip': '10.0.2.1',
                                   'dns_nameservers': nameservers}}
                subnet_req = self.new_create_request('subnets', data)
                res = subnet_req.get_response(self.api)
                self.assertEqual(res.status_int, 400)

    def test_create_subnet_bad_hostroutes(self):
        with self.network() as network:
            # Check hostroutes
            hostroute_pools = [[{'destination': '100.0.0.0/24'}],
                               [{'nexthop': '10.0.2.20'}],
                               [{'nexthop': '10.0.2.20',
                                 'destination': '100.0.0.0/8'},
                                {'nexthop': '10.0.2.20',
                                 'destination': '100.0.0.0/8'}]]
            tenant_id = network['network']['tenant_id']
            for hostroutes in hostroute_pools:
                data = {'subnet': {'network_id': network['network']['id'],
                                   'cidr': '10.0.2.0/24',
                                   'ip_version': '4',
                                   'tenant_id': tenant_id,
                                   'gateway_ip': '10.0.2.1',
                                   'host_routes': hostroutes}}
                subnet_req = self.new_create_request('subnets', data)
                res = subnet_req.get_response(self.api)
                self.assertEqual(res.status_int, 400)

    def test_create_subnet_defaults(self):
        gateway = '10.0.0.1'
        cidr = '10.0.0.0/24'
        allocation_pools = [{'start': '10.0.0.2',
                             'end': '10.0.0.254'}]
        enable_dhcp = True
        subnet = self._test_create_subnet()
        # verify cidr & gw have been correctly generated
        self.assertEqual(subnet['subnet']['cidr'], cidr)
        self.assertEqual(subnet['subnet']['gateway_ip'], gateway)
        self.assertEqual(subnet['subnet']['enable_dhcp'], enable_dhcp)
        self.assertEqual(subnet['subnet']['allocation_pools'],
                         allocation_pools)

    def test_create_subnet_gw_values(self):
        # Gateway not in subnet
        gateway = '100.0.0.1'
        cidr = '10.0.0.0/24'
        allocation_pools = [{'start': '10.0.0.1',
                             'end': '10.0.0.254'}]
        expected = {'gateway_ip': gateway,
                    'cidr': cidr,
                    'allocation_pools': allocation_pools}
        self._test_create_subnet(expected=expected, gateway_ip=gateway)
        # Gateway is last IP in range
        gateway = '10.0.0.254'
        allocation_pools = [{'start': '10.0.0.1',
                             'end': '10.0.0.253'}]
        expected = {'gateway_ip': gateway,
                    'cidr': cidr,
                    'allocation_pools': allocation_pools}
        self._test_create_subnet(expected=expected, gateway_ip=gateway)
        # Gateway is first in subnet
        gateway = '10.0.0.1'
        allocation_pools = [{'start': '10.0.0.2',
                             'end': '10.0.0.254'}]
        expected = {'gateway_ip': gateway,
                    'cidr': cidr,
                    'allocation_pools': allocation_pools}
        self._test_create_subnet(expected=expected,
                                 gateway_ip=gateway)

    def test_create_force_subnet_gw_values(self):
        cfg.CONF.set_override('force_gateway_on_subnet', True)
        with self.network() as network:
            self._create_subnet(self.fmt,
                                network['network']['id'],
                                '10.0.0.0/24',
                                400,
                                gateway_ip='100.0.0.1')

    def test_create_subnet_with_allocation_pool(self):
        gateway_ip = '10.0.0.1'
        cidr = '10.0.0.0/24'
        allocation_pools = [{'start': '10.0.0.2',
                             'end': '10.0.0.100'}]
        self._test_create_subnet(gateway_ip=gateway_ip,
                                 cidr=cidr,
                                 allocation_pools=allocation_pools)

    def test_create_subnet_with_none_gateway(self):
        cidr = '10.0.0.0/24'
        self._test_create_subnet(gateway_ip=None,
                                 cidr=cidr)

    def test_create_subnet_with_none_gateway_fully_allocated(self):
        cidr = '10.0.0.0/24'
        allocation_pools = [{'start': '10.0.0.1',
                             'end': '10.0.0.254'}]
        self._test_create_subnet(gateway_ip=None,
                                 cidr=cidr,
                                 allocation_pools=allocation_pools)

    def test_subnet_with_allocation_range(self):
        cfg.CONF.set_override('dhcp_lease_duration', 0)
        with self.network() as network:
            net_id = network['network']['id']
            data = {'subnet': {'network_id': net_id,
                               'cidr': '10.0.0.0/24',
                               'ip_version': 4,
                               'gateway_ip': '10.0.0.1',
                               'tenant_id': network['network']['tenant_id'],
                               'allocation_pools': [{'start': '10.0.0.100',
                                                    'end': '10.0.0.120'}]}}
            subnet_req = self.new_create_request('subnets', data)
            subnet = self.deserialize(self.fmt,
                                      subnet_req.get_response(self.api))
            # Check fixed IP not in allocation range
            kwargs = {"fixed_ips": [{'subnet_id': subnet['subnet']['id'],
                                     'ip_address': '10.0.0.10'}]}
            res = self._create_port(self.fmt, net_id=net_id, **kwargs)
            self.assertEqual(res.status_int, 201)
            port = self.deserialize(self.fmt, res)
            # delete the port
            self._delete('ports', port['port']['id'])

            # Check when fixed IP is gateway
            kwargs = {"fixed_ips": [{'subnet_id': subnet['subnet']['id'],
                                     'ip_address': '10.0.0.1'}]}
            res = self._create_port(self.fmt, net_id=net_id, **kwargs)
            self.assertEqual(res.status_int, 201)
            port = self.deserialize(self.fmt, res)
            # delete the port
            self._delete('ports', port['port']['id'])
        cfg.CONF.set_override('dhcp_lease_duration', 120)

    def test_create_subnet_with_none_gateway_allocation_pool(self):
        cidr = '10.0.0.0/24'
        allocation_pools = [{'start': '10.0.0.2',
                             'end': '10.0.0.100'}]
        self._test_create_subnet(gateway_ip=None,
                                 cidr=cidr,
                                 allocation_pools=allocation_pools)

    def test_create_subnet_with_v6_allocation_pool(self):
        gateway_ip = 'fe80::1'
        cidr = 'fe80::0/80'
        allocation_pools = [{'start': 'fe80::2',
                             'end': 'fe80::ffff:fffa:ffff'}]
        self._test_create_subnet(gateway_ip=gateway_ip,
                                 cidr=cidr, ip_version=6,
                                 allocation_pools=allocation_pools)

    def test_create_subnet_with_large_allocation_pool(self):
        gateway_ip = '10.0.0.1'
        cidr = '10.0.0.0/8'
        allocation_pools = [{'start': '10.0.0.2',
                             'end': '10.0.0.100'},
                            {'start': '10.1.0.0',
                             'end': '10.200.0.100'}]
        self._test_create_subnet(gateway_ip=gateway_ip,
                                 cidr=cidr,
                                 allocation_pools=allocation_pools)

    def test_create_subnet_multiple_allocation_pools(self):
        gateway_ip = '10.0.0.1'
        cidr = '10.0.0.0/24'
        allocation_pools = [{'start': '10.0.0.2',
                             'end': '10.0.0.100'},
                            {'start': '10.0.0.110',
                             'end': '10.0.0.150'}]
        self._test_create_subnet(gateway_ip=gateway_ip,
                                 cidr=cidr,
                                 allocation_pools=allocation_pools)

    def test_create_subnet_with_dhcp_disabled(self):
        enable_dhcp = False
        self._test_create_subnet(enable_dhcp=enable_dhcp)

    def test_create_subnet_default_gw_conflict_allocation_pool_returns_409(
        self):
        cidr = '10.0.0.0/24'
        allocation_pools = [{'start': '10.0.0.1',
                             'end': '10.0.0.5'}]
        with testtools.ExpectedException(
                webob.exc.HTTPClientError) as ctx_manager:
            self._test_create_subnet(cidr=cidr,
                                     allocation_pools=allocation_pools)
            self.assertEqual(ctx_manager.exception.code, 409)

    def test_create_subnet_gateway_in_allocation_pool_returns_409(self):
        gateway_ip = '10.0.0.50'
        cidr = '10.0.0.0/24'
        allocation_pools = [{'start': '10.0.0.1',
                             'end': '10.0.0.100'}]
        with testtools.ExpectedException(
                webob.exc.HTTPClientError) as ctx_manager:
            self._test_create_subnet(gateway_ip=gateway_ip,
                                     cidr=cidr,
                                     allocation_pools=allocation_pools)
            self.assertEqual(ctx_manager.exception.code, 409)

    def test_create_subnet_overlapping_allocation_pools_returns_409(self):
        gateway_ip = '10.0.0.1'
        cidr = '10.0.0.0/24'
        allocation_pools = [{'start': '10.0.0.2',
                             'end': '10.0.0.150'},
                            {'start': '10.0.0.140',
                             'end': '10.0.0.180'}]
        with testtools.ExpectedException(
                webob.exc.HTTPClientError) as ctx_manager:
            self._test_create_subnet(gateway_ip=gateway_ip,
                                     cidr=cidr,
                                     allocation_pools=allocation_pools)
            self.assertEqual(ctx_manager.exception.code, 409)

    def test_create_subnet_invalid_allocation_pool_returns_400(self):
        gateway_ip = '10.0.0.1'
        cidr = '10.0.0.0/24'
        allocation_pools = [{'start': '10.0.0.2',
                             'end': '10.0.0.256'}]
        with testtools.ExpectedException(
                webob.exc.HTTPClientError) as ctx_manager:
            self._test_create_subnet(gateway_ip=gateway_ip,
                                     cidr=cidr,
                                     allocation_pools=allocation_pools)
            self.assertEqual(ctx_manager.exception.code, 400)

    def test_create_subnet_out_of_range_allocation_pool_returns_400(self):
        gateway_ip = '10.0.0.1'
        cidr = '10.0.0.0/24'
        allocation_pools = [{'start': '10.0.0.2',
                             'end': '10.0.1.6'}]
        with testtools.ExpectedException(
                webob.exc.HTTPClientError) as ctx_manager:
            self._test_create_subnet(gateway_ip=gateway_ip,
                                     cidr=cidr,
                                     allocation_pools=allocation_pools)
            self.assertEqual(ctx_manager.exception.code, 400)

    def test_create_subnet_shared_returns_400(self):
        cidr = '10.0.0.0/24'
        with testtools.ExpectedException(
                webob.exc.HTTPClientError) as ctx_manager:
            self._test_create_subnet(cidr=cidr,
                                     shared=True)
            self.assertEqual(ctx_manager.exception.code, 400)

    def test_create_subnet_inconsistent_ipv6_cidrv4(self):
        with self.network() as network:
            data = {'subnet': {'network_id': network['network']['id'],
                               'cidr': '10.0.2.0/24',
                               'ip_version': 6,
                               'tenant_id': network['network']['tenant_id']}}
            subnet_req = self.new_create_request('subnets', data)
            res = subnet_req.get_response(self.api)
            self.assertEqual(res.status_int, 400)

    def test_create_subnet_inconsistent_ipv4_cidrv6(self):
        with self.network() as network:
            data = {'subnet': {'network_id': network['network']['id'],
                               'cidr': 'fe80::0/80',
                               'ip_version': 4,
                               'tenant_id': network['network']['tenant_id']}}
            subnet_req = self.new_create_request('subnets', data)
            res = subnet_req.get_response(self.api)
            self.assertEqual(res.status_int, 400)

    def test_create_subnet_inconsistent_ipv4_gatewayv6(self):
        with self.network() as network:
            data = {'subnet': {'network_id': network['network']['id'],
                               'cidr': '10.0.2.0/24',
                               'ip_version': 4,
                               'gateway_ip': 'fe80::1',
                               'tenant_id': network['network']['tenant_id']}}
            subnet_req = self.new_create_request('subnets', data)
            res = subnet_req.get_response(self.api)
            self.assertEqual(res.status_int, 400)

    def test_create_subnet_inconsistent_ipv6_gatewayv4(self):
        with self.network() as network:
            data = {'subnet': {'network_id': network['network']['id'],
                               'cidr': 'fe80::0/80',
                               'ip_version': 6,
                               'gateway_ip': '192.168.0.1',
                               'tenant_id': network['network']['tenant_id']}}
            subnet_req = self.new_create_request('subnets', data)
            res = subnet_req.get_response(self.api)
            self.assertEqual(res.status_int, 400)

    def test_create_subnet_inconsistent_ipv6_dns_v4(self):
        with self.network() as network:
            data = {'subnet': {'network_id': network['network']['id'],
                               'cidr': 'fe80::0/80',
                               'ip_version': 6,
                               'dns_nameservers': ['192.168.0.1'],
                               'tenant_id': network['network']['tenant_id']}}
            subnet_req = self.new_create_request('subnets', data)
            res = subnet_req.get_response(self.api)
            self.assertEqual(res.status_int, 400)

    def test_create_subnet_inconsistent_ipv4_hostroute_dst_v6(self):
        host_routes = [{'destination': 'fe80::0/48',
                        'nexthop': '10.0.2.20'}]
        with self.network() as network:
            data = {'subnet': {'network_id': network['network']['id'],
                               'cidr': '10.0.2.0/24',
                               'ip_version': 4,
                               'host_routes': host_routes,
                               'tenant_id': network['network']['tenant_id']}}
            subnet_req = self.new_create_request('subnets', data)
            res = subnet_req.get_response(self.api)
            self.assertEqual(res.status_int, 400)

    def test_create_subnet_inconsistent_ipv4_hostroute_np_v6(self):
        host_routes = [{'destination': '172.16.0.0/24',
                        'nexthop': 'fe80::1'}]
        with self.network() as network:
            data = {'subnet': {'network_id': network['network']['id'],
                               'cidr': '10.0.2.0/24',
                               'ip_version': 4,
                               'host_routes': host_routes,
                               'tenant_id': network['network']['tenant_id']}}
            subnet_req = self.new_create_request('subnets', data)
            res = subnet_req.get_response(self.api)
            self.assertEqual(res.status_int, 400)

    def test_update_subnet(self):
        with self.subnet() as subnet:
            data = {'subnet': {'gateway_ip': '11.0.0.1'}}
            req = self.new_update_request('subnets', data,
                                          subnet['subnet']['id'])
            res = self.deserialize(self.fmt, req.get_response(self.api))
            self.assertEqual(res['subnet']['gateway_ip'],
                             data['subnet']['gateway_ip'])

    def test_update_subnet_shared_returns_400(self):
        with self.network(shared=True) as network:
            with self.subnet(network=network) as subnet:
                data = {'subnet': {'shared': True}}
                req = self.new_update_request('subnets', data,
                                              subnet['subnet']['id'])
                res = req.get_response(self.api)
                self.assertEqual(res.status_int, 400)

    def test_update_subnet_inconsistent_ipv4_gatewayv6(self):
        with self.network() as network:
            with self.subnet(network=network) as subnet:
                data = {'subnet': {'gateway_ip': 'fe80::1'}}
                req = self.new_update_request('subnets', data,
                                              subnet['subnet']['id'])
                res = req.get_response(self.api)
                self.assertEqual(res.status_int, 400)

    def test_update_subnet_inconsistent_ipv6_gatewayv4(self):
        with self.network() as network:
            with self.subnet(network=network,
                             ip_version=6, cidr='fe80::/48') as subnet:
                data = {'subnet': {'gateway_ip': '10.1.1.1'}}
                req = self.new_update_request('subnets', data,
                                              subnet['subnet']['id'])
                res = req.get_response(self.api)
                self.assertEqual(res.status_int, 400)

    def test_update_subnet_inconsistent_ipv4_dns_v6(self):
        dns_nameservers = ['fe80::1']
        with self.network() as network:
            with self.subnet(network=network) as subnet:
                data = {'subnet': {'dns_nameservers': dns_nameservers}}
                req = self.new_update_request('subnets', data,
                                              subnet['subnet']['id'])
                res = req.get_response(self.api)
                self.assertEqual(res.status_int, 400)

    def test_update_subnet_inconsistent_ipv6_hostroute_dst_v4(self):
        host_routes = [{'destination': 'fe80::0/48',
                        'nexthop': '10.0.2.20'}]
        with self.network() as network:
            with self.subnet(network=network,
                             ip_version=6, cidr='fe80::/48') as subnet:
                data = {'subnet': {'host_routes': host_routes}}
                req = self.new_update_request('subnets', data,
                                              subnet['subnet']['id'])
                res = req.get_response(self.api)
                self.assertEqual(res.status_int, 400)

    def test_update_subnet_inconsistent_ipv6_hostroute_np_v4(self):
        host_routes = [{'destination': '172.16.0.0/24',
                        'nexthop': 'fe80::1'}]
        with self.network() as network:
            with self.subnet(network=network,
                             ip_version=6, cidr='fe80::/48') as subnet:
                data = {'subnet': {'host_routes': host_routes}}
                req = self.new_update_request('subnets', data,
                                              subnet['subnet']['id'])
                res = req.get_response(self.api)
                self.assertEqual(res.status_int, 400)

    def test_update_subnet_gateway_in_allocation_pool_returns_409(self):
        allocation_pools = [{'start': '10.0.0.2', 'end': '10.0.0.254'}]
        with self.network() as network:
            with self.subnet(network=network,
                             allocation_pools=allocation_pools,
                             cidr='10.0.0.0/24') as subnet:
                data = {'subnet': {'gateway_ip': '10.0.0.50'}}
                req = self.new_update_request('subnets', data,
                                              subnet['subnet']['id'])
                res = req.get_response(self.api)
                self.assertEqual(res.status_int, 409)

    def test_show_subnet(self):
        with self.network() as network:
            with self.subnet(network=network) as subnet:
                req = self.new_show_request('subnets',
                                            subnet['subnet']['id'])
                res = self.deserialize(self.fmt, req.get_response(self.api))
                self.assertEqual(res['subnet']['id'],
                                 subnet['subnet']['id'])
                self.assertEqual(res['subnet']['network_id'],
                                 network['network']['id'])

    def test_list_subnets(self):
        with self.network() as network:
            with contextlib.nested(self.subnet(network=network,
                                               gateway_ip='10.0.0.1',
                                               cidr='10.0.0.0/24'),
                                   self.subnet(network=network,
                                               gateway_ip='10.0.1.1',
                                               cidr='10.0.1.0/24'),
                                   self.subnet(network=network,
                                               gateway_ip='10.0.2.1',
                                               cidr='10.0.2.0/24')) as subnets:
                self._test_list_resources('subnet', subnets)

    def test_list_subnets_shared(self):
        with self.network(shared=True) as network:
            with self.subnet(network=network, cidr='10.0.0.0/24') as subnet:
                with self.subnet(cidr='10.0.1.0/24') as priv_subnet:
                    # normal user should see only 1 subnet
                    req = self.new_list_request('subnets')
                    req.environ['quantum.context'] = context.Context(
                        '', 'some_tenant')
                    res = self.deserialize(self.fmt,
                                           req.get_response(self.api))
                    self.assertEqual(len(res['subnets']), 1)
                    self.assertEqual(res['subnets'][0]['cidr'],
                                     subnet['subnet']['cidr'])
                    # admin will see both subnets
                    admin_req = self.new_list_request('subnets')
                    admin_res = self.deserialize(
                        self.fmt, admin_req.get_response(self.api))
                    self.assertEqual(len(admin_res['subnets']), 2)
                    cidrs = [sub['cidr'] for sub in admin_res['subnets']]
                    self.assertIn(subnet['subnet']['cidr'], cidrs)
                    self.assertIn(priv_subnet['subnet']['cidr'], cidrs)

    def test_list_subnets_with_parameter(self):
        with self.network() as network:
            with contextlib.nested(self.subnet(network=network,
                                               gateway_ip='10.0.0.1',
                                               cidr='10.0.0.0/24'),
                                   self.subnet(network=network,
                                               gateway_ip='10.0.1.1',
                                               cidr='10.0.1.0/24')
                                   ) as subnets:
                query_params = 'ip_version=4&ip_version=6'
                self._test_list_resources('subnet', subnets,
                                          query_params=query_params)
                query_params = 'ip_version=6'
                self._test_list_resources('subnet', [],
                                          query_params=query_params)

    def test_list_subnets_with_sort_native(self):
        if self._skip_native_sorting:
            self.skipTest("Skip test for not implemented sorting feature")
        with contextlib.nested(self.subnet(enable_dhcp=True,
                                           cidr='10.0.0.0/24'),
                               self.subnet(enable_dhcp=False,
                                           cidr='11.0.0.0/24'),
                               self.subnet(enable_dhcp=False,
                                           cidr='12.0.0.0/24')
                               ) as (subnet1, subnet2, subnet3):
            self._test_list_with_sort('subnet', (subnet3, subnet2, subnet1),
                                      [('enable_dhcp', 'asc'),
                                       ('cidr', 'desc')])

    def test_list_subnets_with_sort_emulated(self):
        helper_patcher = mock.patch(
            'quantum.api.v2.base.Controller._get_sorting_helper',
            new=_fake_get_sorting_helper)
        helper_patcher.start()
        try:
            with contextlib.nested(self.subnet(enable_dhcp=True,
                                               cidr='10.0.0.0/24'),
                                   self.subnet(enable_dhcp=False,
                                               cidr='11.0.0.0/24'),
                                   self.subnet(enable_dhcp=False,
                                               cidr='12.0.0.0/24')
                                   ) as (subnet1, subnet2, subnet3):
                self._test_list_with_sort('subnet', (subnet3,
                                                     subnet2,
                                                     subnet1),
                                          [('enable_dhcp', 'asc'),
                                           ('cidr', 'desc')])
        finally:
            helper_patcher.stop()

    def test_list_subnets_with_pagination_native(self):
        if self._skip_native_pagination:
            self.skipTest("Skip test for not implemented sorting feature")
        with contextlib.nested(self.subnet(cidr='10.0.0.0/24'),
                               self.subnet(cidr='11.0.0.0/24'),
                               self.subnet(cidr='12.0.0.0/24')
                               ) as (subnet1, subnet2, subnet3):
            self._test_list_with_pagination('subnet',
                                            (subnet1, subnet2, subnet3),
                                            ('cidr', 'asc'), 2, 2)

    def test_list_subnets_with_pagination_emulated(self):
        helper_patcher = mock.patch(
            'quantum.api.v2.base.Controller._get_pagination_helper',
            new=_fake_get_pagination_helper)
        helper_patcher.start()
        try:
            with contextlib.nested(self.subnet(cidr='10.0.0.0/24'),
                                   self.subnet(cidr='11.0.0.0/24'),
                                   self.subnet(cidr='12.0.0.0/24')
                                   ) as (subnet1, subnet2, subnet3):
                self._test_list_with_pagination('subnet',
                                                (subnet1, subnet2, subnet3),
                                                ('cidr', 'asc'), 2, 2)
        finally:
            helper_patcher.stop()

    def test_list_subnets_with_pagination_reverse_native(self):
        if self._skip_native_sorting:
            self.skipTest("Skip test for not implemented sorting feature")
        with contextlib.nested(self.subnet(cidr='10.0.0.0/24'),
                               self.subnet(cidr='11.0.0.0/24'),
                               self.subnet(cidr='12.0.0.0/24')
                               ) as (subnet1, subnet2, subnet3):
            self._test_list_with_pagination_reverse('subnet',
                                                    (subnet1, subnet2,
                                                     subnet3),
                                                    ('cidr', 'asc'), 2, 2)

    def test_list_subnets_with_pagination_reverse_emulated(self):
        helper_patcher = mock.patch(
            'quantum.api.v2.base.Controller._get_pagination_helper',
            new=_fake_get_pagination_helper)
        helper_patcher.start()
        try:
            with contextlib.nested(self.subnet(cidr='10.0.0.0/24'),
                                   self.subnet(cidr='11.0.0.0/24'),
                                   self.subnet(cidr='12.0.0.0/24')
                                   ) as (subnet1, subnet2, subnet3):
                self._test_list_with_pagination_reverse('subnet',
                                                        (subnet1, subnet2,
                                                         subnet3),
                                                        ('cidr', 'asc'), 2, 2)
        finally:
            helper_patcher.stop()

    def test_invalid_ip_version(self):
        with self.network() as network:
            data = {'subnet': {'network_id': network['network']['id'],
                               'cidr': '10.0.2.0/24',
                               'ip_version': 7,
                               'tenant_id': network['network']['tenant_id'],
                               'gateway_ip': '10.0.2.1'}}

            subnet_req = self.new_create_request('subnets', data)
            res = subnet_req.get_response(self.api)
            self.assertEqual(res.status_int, 400)

    def test_invalid_subnet(self):
        with self.network() as network:
            data = {'subnet': {'network_id': network['network']['id'],
                               'cidr': 'invalid',
                               'ip_version': 4,
                               'tenant_id': network['network']['tenant_id'],
                               'gateway_ip': '10.0.2.1'}}

            subnet_req = self.new_create_request('subnets', data)
            res = subnet_req.get_response(self.api)
            self.assertEqual(res.status_int, 400)

    def test_invalid_ip_address(self):
        with self.network() as network:
            data = {'subnet': {'network_id': network['network']['id'],
                               'cidr': '10.0.2.0/24',
                               'ip_version': 4,
                               'tenant_id': network['network']['tenant_id'],
                               'gateway_ip': 'ipaddress'}}

            subnet_req = self.new_create_request('subnets', data)
            res = subnet_req.get_response(self.api)
            self.assertEqual(res.status_int, 400)

    def test_invalid_uuid(self):
        with self.network() as network:
            data = {'subnet': {'network_id': 'invalid-uuid',
                               'cidr': '10.0.2.0/24',
                               'ip_version': 4,
                               'tenant_id': network['network']['tenant_id'],
                               'gateway_ip': '10.0.0.1'}}

            subnet_req = self.new_create_request('subnets', data)
            res = subnet_req.get_response(self.api)
            self.assertEqual(res.status_int, 400)

    def test_create_subnet_with_one_dns(self):
        gateway_ip = '10.0.0.1'
        cidr = '10.0.0.0/24'
        allocation_pools = [{'start': '10.0.0.2',
                             'end': '10.0.0.100'}]
        dns_nameservers = ['1.2.3.4']
        self._test_create_subnet(gateway_ip=gateway_ip,
                                 cidr=cidr,
                                 allocation_pools=allocation_pools,
                                 dns_nameservers=dns_nameservers)

    def test_create_subnet_with_two_dns(self):
        gateway_ip = '10.0.0.1'
        cidr = '10.0.0.0/24'
        allocation_pools = [{'start': '10.0.0.2',
                             'end': '10.0.0.100'}]
        dns_nameservers = ['1.2.3.4', '4.3.2.1']
        self._test_create_subnet(gateway_ip=gateway_ip,
                                 cidr=cidr,
                                 allocation_pools=allocation_pools,
                                 dns_nameservers=dns_nameservers)

    def test_create_subnet_with_too_many_dns(self):
        with self.network() as network:
            dns_list = ['1.1.1.1', '2.2.2.2', '3.3.3.3']
            data = {'subnet': {'network_id': network['network']['id'],
                               'cidr': '10.0.2.0/24',
                               'ip_version': 4,
                               'tenant_id': network['network']['tenant_id'],
                               'gateway_ip': '10.0.0.1',
                               'dns_nameservers': dns_list}}

            subnet_req = self.new_create_request('subnets', data)
            res = subnet_req.get_response(self.api)
            self.assertEqual(res.status_int, 400)

    def test_create_subnet_with_one_host_route(self):
        gateway_ip = '10.0.0.1'
        cidr = '10.0.0.0/24'
        allocation_pools = [{'start': '10.0.0.2',
                             'end': '10.0.0.100'}]
        host_routes = [{'destination': '135.207.0.0/16',
                       'nexthop': '1.2.3.4'}]
        self._test_create_subnet(gateway_ip=gateway_ip,
                                 cidr=cidr,
                                 allocation_pools=allocation_pools,
                                 host_routes=host_routes)

    def test_create_subnet_with_two_host_routes(self):
        gateway_ip = '10.0.0.1'
        cidr = '10.0.0.0/24'
        allocation_pools = [{'start': '10.0.0.2',
                             'end': '10.0.0.100'}]
        host_routes = [{'destination': '135.207.0.0/16',
                       'nexthop': '1.2.3.4'},
                       {'destination': '12.0.0.0/8',
                       'nexthop': '4.3.2.1'}]

        self._test_create_subnet(gateway_ip=gateway_ip,
                                 cidr=cidr,
                                 allocation_pools=allocation_pools,
                                 host_routes=host_routes)

    def test_create_subnet_with_too_many_routes(self):
        with self.network() as network:
            host_routes = [{'destination': '135.207.0.0/16',
                            'nexthop': '1.2.3.4'},
                           {'destination': '12.0.0.0/8',
                            'nexthop': '4.3.2.1'},
                           {'destination': '141.212.0.0/16',
                            'nexthop': '2.2.2.2'}]

            data = {'subnet': {'network_id': network['network']['id'],
                               'cidr': '10.0.2.0/24',
                               'ip_version': 4,
                               'tenant_id': network['network']['tenant_id'],
                               'gateway_ip': '10.0.0.1',
                               'host_routes': host_routes}}

            subnet_req = self.new_create_request('subnets', data)
            res = subnet_req.get_response(self.api)
            self.assertEqual(res.status_int, 400)

    def test_update_subnet_dns(self):
        with self.subnet() as subnet:
            data = {'subnet': {'dns_nameservers': ['11.0.0.1']}}
            req = self.new_update_request('subnets', data,
                                          subnet['subnet']['id'])
            res = self.deserialize(self.fmt, req.get_response(self.api))
            self.assertEqual(res['subnet']['dns_nameservers'],
                             data['subnet']['dns_nameservers'])

    def test_update_subnet_dns_to_None(self):
        with self.subnet(dns_nameservers=['11.0.0.1']) as subnet:
            data = {'subnet': {'dns_nameservers': None}}
            req = self.new_update_request('subnets', data,
                                          subnet['subnet']['id'])
            res = self.deserialize(self.fmt, req.get_response(self.api))
            self.assertEqual([], res['subnet']['dns_nameservers'])
            data = {'subnet': {'dns_nameservers': ['11.0.0.3']}}
            req = self.new_update_request('subnets', data,
                                          subnet['subnet']['id'])
            res = self.deserialize(self.fmt, req.get_response(self.api))
            self.assertEqual(data['subnet']['dns_nameservers'],
                             res['subnet']['dns_nameservers'])

    def test_update_subnet_dns_with_too_many_entries(self):
        with self.subnet() as subnet:
            dns_list = ['1.1.1.1', '2.2.2.2', '3.3.3.3']
            data = {'subnet': {'dns_nameservers': dns_list}}
            req = self.new_update_request('subnets', data,
                                          subnet['subnet']['id'])
            res = req.get_response(self.api)
            self.assertEqual(res.status_int, 400)

    def test_update_subnet_route(self):
        with self.subnet() as subnet:
            data = {'subnet': {'host_routes':
                    [{'destination': '12.0.0.0/8', 'nexthop': '1.2.3.4'}]}}
            req = self.new_update_request('subnets', data,
                                          subnet['subnet']['id'])
            res = self.deserialize(self.fmt, req.get_response(self.api))
            self.assertEqual(res['subnet']['host_routes'],
                             data['subnet']['host_routes'])

    def test_update_subnet_route_to_None(self):
        with self.subnet(host_routes=[{'destination': '12.0.0.0/8',
                                       'nexthop': '1.2.3.4'}]) as subnet:
            data = {'subnet': {'host_routes': None}}
            req = self.new_update_request('subnets', data,
                                          subnet['subnet']['id'])
            res = self.deserialize(self.fmt, req.get_response(self.api))
            self.assertEqual([], res['subnet']['host_routes'])
            data = {'subnet': {'host_routes': [{'destination': '12.0.0.0/8',
                                                'nexthop': '1.2.3.4'}]}}
            req = self.new_update_request('subnets', data,
                                          subnet['subnet']['id'])
            res = self.deserialize(self.fmt, req.get_response(self.api))
            self.assertEqual(data['subnet']['host_routes'],
                             res['subnet']['host_routes'])

    def test_update_subnet_route_with_too_many_entries(self):
        with self.subnet() as subnet:
            data = {'subnet': {'host_routes': [
                    {'destination': '12.0.0.0/8', 'nexthop': '1.2.3.4'},
                    {'destination': '13.0.0.0/8', 'nexthop': '1.2.3.5'},
                    {'destination': '14.0.0.0/8', 'nexthop': '1.2.3.6'}]}}
            req = self.new_update_request('subnets', data,
                                          subnet['subnet']['id'])
            res = req.get_response(self.api)
            self.assertEqual(res.status_int, 400)

    def test_delete_subnet_with_dns(self):
        gateway_ip = '10.0.0.1'
        cidr = '10.0.0.0/24'
        dns_nameservers = ['1.2.3.4']
        # Create new network
        res = self._create_network(fmt=self.fmt, name='net',
                                   admin_state_up=True)
        network = self.deserialize(self.fmt, res)
        subnet = self._make_subnet(self.fmt, network, gateway_ip,
                                   cidr, ip_version=4,
                                   dns_nameservers=dns_nameservers)
        req = self.new_delete_request('subnets', subnet['subnet']['id'])
        res = req.get_response(self.api)
        self.assertEqual(res.status_int, 204)

    def test_delete_subnet_with_route(self):
        gateway_ip = '10.0.0.1'
        cidr = '10.0.0.0/24'
        host_routes = [{'destination': '135.207.0.0/16',
                        'nexthop': '1.2.3.4'}]
        # Create new network
        res = self._create_network(fmt=self.fmt, name='net',
                                   admin_state_up=True)
        network = self.deserialize(self.fmt, res)
        subnet = self._make_subnet(self.fmt, network, gateway_ip,
                                   cidr, ip_version=4,
                                   host_routes=host_routes)
        req = self.new_delete_request('subnets', subnet['subnet']['id'])
        res = req.get_response(self.api)
        self.assertEqual(res.status_int, 204)

    def test_delete_subnet_with_dns_and_route(self):
        gateway_ip = '10.0.0.1'
        cidr = '10.0.0.0/24'
        dns_nameservers = ['1.2.3.4']
        host_routes = [{'destination': '135.207.0.0/16',
                        'nexthop': '1.2.3.4'}]
        # Create new network
        res = self._create_network(fmt=self.fmt, name='net',
                                   admin_state_up=True)
        network = self.deserialize(self.fmt, res)
        subnet = self._make_subnet(self.fmt, network, gateway_ip,
                                   cidr, ip_version=4,
                                   dns_nameservers=dns_nameservers,
                                   host_routes=host_routes)
        req = self.new_delete_request('subnets', subnet['subnet']['id'])
        res = req.get_response(self.api)
        self.assertEqual(res.status_int, 204)


class DbModelTestCase(base.BaseTestCase):
    """ DB model tests """
    def test_repr(self):
        """ testing the string representation of 'model' classes """
        network = models_v2.Network(name="net_net", status="OK",
                                    admin_state_up=True)
        actual_repr_output = repr(network)
        exp_start_with = "<quantum.db.models_v2.Network"
        exp_middle = "[object at %x]" % id(network)
        exp_end_with = (" {tenant_id=None, id=None, "
                        "name='net_net', status='OK', "
                        "admin_state_up=True, shared=None}>")
        final_exp = exp_start_with + exp_middle + exp_end_with
        self.assertEqual(actual_repr_output, final_exp)


class TestBasicGetXML(TestBasicGet):
    fmt = 'xml'


class TestNetworksV2XML(TestNetworksV2):
    fmt = 'xml'


class TestPortsV2XML(TestPortsV2):
    fmt = 'xml'


class TestSubnetsV2XML(TestSubnetsV2):
    fmt = 'xml'


class TestV2HTTPResponseXML(TestV2HTTPResponse):
    fmt = 'xml'
