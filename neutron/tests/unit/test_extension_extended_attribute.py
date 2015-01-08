# Copyright 2013 VMware, Inc
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

"""
Unit tests for extension extended attribute
"""

from oslo_config import cfg
import webob.exc as webexc

import neutron
from neutron.api import extensions
from neutron.api.v2 import attributes
from neutron.common import config
from neutron import manager
from neutron.plugins.common import constants
from neutron.plugins.ml2 import plugin as ml2_plugin
from neutron import quota
from neutron.tests import base
from neutron.tests.unit.extensions import extendedattribute as extattr
from neutron.tests.unit import test_api_v2
from neutron.tests.unit import testlib_api
from neutron.tests.unit import testlib_plugin
from neutron import wsgi

_uuid = test_api_v2._uuid
_get_path = test_api_v2._get_path
extensions_path = ':'.join(neutron.tests.unit.extensions.__path__)


class ExtensionExtendedAttributeTestPlugin(
    ml2_plugin.Ml2Plugin):

    supported_extension_aliases = [
        'ext-obj-test', "extended-ext-attr"
    ]

    def __init__(self, configfile=None):
        super(ExtensionExtendedAttributeTestPlugin, self)
        self.objs = []
        self.objh = {}

    def create_ext_test_resource(self, context, ext_test_resource):
        obj = ext_test_resource['ext_test_resource']
        id = _uuid()
        obj['id'] = id
        self.objs.append(obj)
        self.objh.update({id: obj})
        return obj

    def get_ext_test_resources(self, context, filters=None, fields=None):
        return self.objs

    def get_ext_test_resource(self, context, id, fields=None):
        return self.objh[id]


class ExtensionExtendedAttributeTestCase(base.BaseTestCase,
                                         testlib_plugin.PluginSetupHelper):
    def setUp(self):
        super(ExtensionExtendedAttributeTestCase, self).setUp()
        plugin = (
            "neutron.tests.unit.test_extension_extended_attribute."
            "ExtensionExtendedAttributeTestPlugin"
        )

        # point config file to: neutron/tests/etc/neutron.conf.test
        self.config_parse()

        self.setup_coreplugin(plugin)

        ext_mgr = extensions.PluginAwareExtensionManager(
            extensions_path,
            {constants.CORE: ExtensionExtendedAttributeTestPlugin}
        )
        ext_mgr.extend_resources("2.0", {})
        extensions.PluginAwareExtensionManager._instance = ext_mgr

        app = config.load_paste_app('extensions_test_app')
        self._api = extensions.ExtensionMiddleware(app, ext_mgr=ext_mgr)

        self._tenant_id = "8c70909f-b081-452d-872b-df48e6c355d1"
        # Save the global RESOURCE_ATTRIBUTE_MAP
        self.saved_attr_map = {}
        for resource, attrs in attributes.RESOURCE_ATTRIBUTE_MAP.iteritems():
            self.saved_attr_map[resource] = attrs.copy()
        # Add the resources to the global attribute map
        # This is done here as the setup process won't
        # initialize the main API router which extends
        # the global attribute map
        attributes.RESOURCE_ATTRIBUTE_MAP.update(
            extattr.EXTENDED_ATTRIBUTES_2_0)
        self.agentscheduler_dbMinxin = manager.NeutronManager.get_plugin()
        self.addCleanup(self.restore_attribute_map)

        quota.QUOTAS._driver = None
        cfg.CONF.set_override('quota_driver', 'neutron.quota.ConfDriver',
                              group='QUOTAS')

    def restore_attribute_map(self):
        # Restore the original RESOURCE_ATTRIBUTE_MAP
        attributes.RESOURCE_ATTRIBUTE_MAP = self.saved_attr_map

    def _do_request(self, method, path, data=None, params=None, action=None):
        content_type = 'application/json'
        body = None
        if data is not None:  # empty dict is valid
            body = wsgi.Serializer().serialize(data, content_type)

        req = testlib_api.create_request(
            path, body, content_type,
            method, query_string=params)
        res = req.get_response(self._api)
        if res.status_code >= 400:
            raise webexc.HTTPClientError(detail=res.body, code=res.status_code)
        if res.status_code != webexc.HTTPNoContent.code:
            return res.json

    def _ext_test_resource_create(self, attr=None):
        data = {
            "ext_test_resource": {
                "tenant_id": self._tenant_id,
                "name": "test",
                extattr.EXTENDED_ATTRIBUTE: attr
            }
        }

        res = self._do_request('POST', _get_path('ext_test_resources'), data)
        return res['ext_test_resource']

    def test_ext_test_resource_create(self):
        ext_test_resource = self._ext_test_resource_create()
        attr = _uuid()
        ext_test_resource = self._ext_test_resource_create(attr)
        self.assertEqual(ext_test_resource[extattr.EXTENDED_ATTRIBUTE], attr)

    def test_ext_test_resource_get(self):
        attr = _uuid()
        obj = self._ext_test_resource_create(attr)
        obj_id = obj['id']
        res = self._do_request('GET', _get_path(
            'ext_test_resources/{0}'.format(obj_id)))
        obj2 = res['ext_test_resource']
        self.assertEqual(obj2[extattr.EXTENDED_ATTRIBUTE], attr)
