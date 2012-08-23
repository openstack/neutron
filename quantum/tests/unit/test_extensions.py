# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright 2011 OpenStack LLC.
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

import logging
import os
import unittest

import routes
import webob
from webtest import AppError
from webtest import TestApp

from quantum.common import config
from quantum.common import exceptions
from quantum.extensions import extensions
from quantum.extensions.extensions import (
    ExtensionManager,
    ExtensionMiddleware,
    PluginAwareExtensionManager,
)
from quantum.openstack.common import jsonutils
from quantum.db.db_base_plugin_v2 import QuantumDbPluginV2
from quantum.tests.unit import BaseTest
from quantum.tests.unit.extension_stubs import (
    ExtensionExpectingPluginInterface,
    StubBaseAppController,
    StubExtension,
    StubPlugin,
)
import quantum.tests.unit.extensions
from quantum import wsgi

LOG = logging.getLogger('quantum.tests.test_extensions')

ROOTDIR = os.path.dirname(os.path.dirname(__file__))
ETCDIR = os.path.join(ROOTDIR, 'etc')


def etcdir(*p):
    return os.path.join(ETCDIR, *p)

extensions_path = ':'.join(quantum.tests.unit.extensions.__path__)


class ExtensionsTestApp(wsgi.Router):

    def __init__(self, options={}):
        mapper = routes.Mapper()
        controller = StubBaseAppController()
        mapper.resource("dummy_resource", "/dummy_resources",
                        controller=controller)
        super(ExtensionsTestApp, self).__init__(mapper)


class FakePluginWithExtension(QuantumDbPluginV2):
    """A fake plugin used only for extension testing in this file."""

    supported_extension_aliases = ["FOXNSOX"]

    def method_to_support_foxnsox_extension(self, context):
        self._log("method_to_support_foxnsox_extension", context)


class ResourceExtensionTest(unittest.TestCase):

    class ResourceExtensionController(wsgi.Controller):

        def index(self, request):
            return "resource index"

        def show(self, request, id):
            return {'data': {'id': id}}

        def notimplemented_function(self, request, id):
            return webob.exc.HTTPClientError(NotImplementedError())

        def custom_member_action(self, request, id):
            return {'member_action': 'value'}

        def custom_collection_action(self, request, **kwargs):
            return {'collection': 'value'}

    def test_exceptions_notimplemented(self):
        controller = self.ResourceExtensionController()
        member = {'notimplemented_function': "GET"}
        res_ext = extensions.ResourceExtension('tweedles', controller,
                                               member_actions=member)
        test_app = _setup_extensions_test_app(SimpleExtensionManager(res_ext))

        # Ideally we would check for a 501 code here but webtest doesn't take
        # anything that is below 200 or above 400 so we can't actually check
        # it.  It thows AppError instead.
        try:
            response = (
                test_app.get("/tweedles/some_id/notimplemented_function"))
            # Shouldn't be reached
            self.assertTrue(False)
        except AppError:
            pass

    def test_resource_can_be_added_as_extension(self):
        res_ext = extensions.ResourceExtension(
            'tweedles', self.ResourceExtensionController())
        test_app = _setup_extensions_test_app(SimpleExtensionManager(res_ext))
        index_response = test_app.get("/tweedles")
        self.assertEqual(200, index_response.status_int)
        self.assertEqual("resource index", index_response.body)

        show_response = test_app.get("/tweedles/25266")
        self.assertEqual({'data': {'id': "25266"}}, show_response.json)

    def test_resource_extension_with_custom_member_action(self):
        controller = self.ResourceExtensionController()
        member = {'custom_member_action': "GET"}
        res_ext = extensions.ResourceExtension('tweedles', controller,
                                               member_actions=member)
        test_app = _setup_extensions_test_app(SimpleExtensionManager(res_ext))

        response = test_app.get("/tweedles/some_id/custom_member_action")
        self.assertEqual(200, response.status_int)
        self.assertEqual(jsonutils.loads(response.body)['member_action'],
                         "value")

    def test_resource_extension_for_get_custom_collection_action(self):
        controller = self.ResourceExtensionController()
        collections = {'custom_collection_action': "GET"}
        res_ext = extensions.ResourceExtension('tweedles', controller,
                                               collection_actions=collections)
        test_app = _setup_extensions_test_app(SimpleExtensionManager(res_ext))

        response = test_app.get("/tweedles/custom_collection_action")
        self.assertEqual(200, response.status_int)
        self.assertEqual(jsonutils.loads(response.body)['collection'], "value")

    def test_resource_extension_for_put_custom_collection_action(self):
        controller = self.ResourceExtensionController()
        collections = {'custom_collection_action': "PUT"}
        res_ext = extensions.ResourceExtension('tweedles', controller,
                                               collection_actions=collections)
        test_app = _setup_extensions_test_app(SimpleExtensionManager(res_ext))

        response = test_app.put("/tweedles/custom_collection_action")

        self.assertEqual(200, response.status_int)
        self.assertEqual(jsonutils.loads(response.body)['collection'], 'value')

    def test_resource_extension_for_post_custom_collection_action(self):
        controller = self.ResourceExtensionController()
        collections = {'custom_collection_action': "POST"}
        res_ext = extensions.ResourceExtension('tweedles', controller,
                                               collection_actions=collections)
        test_app = _setup_extensions_test_app(SimpleExtensionManager(res_ext))

        response = test_app.post("/tweedles/custom_collection_action")

        self.assertEqual(200, response.status_int)
        self.assertEqual(jsonutils.loads(response.body)['collection'], 'value')

    def test_resource_extension_for_delete_custom_collection_action(self):
        controller = self.ResourceExtensionController()
        collections = {'custom_collection_action': "DELETE"}
        res_ext = extensions.ResourceExtension('tweedles', controller,
                                               collection_actions=collections)
        test_app = _setup_extensions_test_app(SimpleExtensionManager(res_ext))

        response = test_app.delete("/tweedles/custom_collection_action")

        self.assertEqual(200, response.status_int)
        self.assertEqual(jsonutils.loads(response.body)['collection'], 'value')

    def test_resource_ext_for_formatted_req_on_custom_collection_action(self):
        controller = self.ResourceExtensionController()
        collections = {'custom_collection_action': "GET"}
        res_ext = extensions.ResourceExtension('tweedles', controller,
                                               collection_actions=collections)
        test_app = _setup_extensions_test_app(SimpleExtensionManager(res_ext))

        response = test_app.get("/tweedles/custom_collection_action.json")

        self.assertEqual(200, response.status_int)
        self.assertEqual(jsonutils.loads(response.body)['collection'], "value")

    def test_resource_ext_for_nested_resource_custom_collection_action(self):
        controller = self.ResourceExtensionController()
        collections = {'custom_collection_action': "GET"}
        parent = dict(collection_name='beetles', member_name='beetle')
        res_ext = extensions.ResourceExtension('tweedles', controller,
                                               collection_actions=collections,
                                               parent=parent)
        test_app = _setup_extensions_test_app(SimpleExtensionManager(res_ext))

        response = test_app.get("/beetles/beetle_id"
                                "/tweedles/custom_collection_action")

        self.assertEqual(200, response.status_int)
        self.assertEqual(jsonutils.loads(response.body)['collection'], "value")

    def test_returns_404_for_non_existent_extension(self):
        test_app = _setup_extensions_test_app(SimpleExtensionManager(None))

        response = test_app.get("/non_extistant_extension", status='*')

        self.assertEqual(404, response.status_int)


class ActionExtensionTest(unittest.TestCase):

    def setUp(self):
        super(ActionExtensionTest, self).setUp()
        self.extension_app = _setup_extensions_test_app()

    def test_extended_action_for_adding_extra_data(self):
        action_name = 'FOXNSOX:add_tweedle'
        action_params = dict(name='Beetle')
        req_body = jsonutils.dumps({action_name: action_params})
        response = self.extension_app.post('/dummy_resources/1/action',
                                           req_body,
                                           content_type='application/json')
        self.assertEqual("Tweedle Beetle Added.", response.body)

    def test_extended_action_for_deleting_extra_data(self):
        action_name = 'FOXNSOX:delete_tweedle'
        action_params = dict(name='Bailey')
        req_body = jsonutils.dumps({action_name: action_params})
        response = self.extension_app.post("/dummy_resources/1/action",
                                           req_body,
                                           content_type='application/json')
        self.assertEqual("Tweedle Bailey Deleted.", response.body)

    def test_returns_404_for_non_existent_action(self):
        non_existent_action = 'blah_action'
        action_params = dict(name="test")
        req_body = jsonutils.dumps({non_existent_action: action_params})

        response = self.extension_app.post("/dummy_resources/1/action",
                                           req_body,
                                           content_type='application/json',
                                           status='*')

        self.assertEqual(404, response.status_int)

    def test_returns_404_for_non_existent_resource(self):
        action_name = 'add_tweedle'
        action_params = dict(name='Beetle')
        req_body = jsonutils.dumps({action_name: action_params})

        response = self.extension_app.post("/asdf/1/action", req_body,
                                           content_type='application/json',
                                           status='*')
        self.assertEqual(404, response.status_int)


class RequestExtensionTest(BaseTest):

    def test_headers_can_be_extended(self):
        def extend_headers(req, res):
            assert req.headers['X-NEW-REQUEST-HEADER'] == "sox"
            res.headers['X-NEW-RESPONSE-HEADER'] = "response_header_data"
            return res

        app = self._setup_app_with_request_handler(extend_headers, 'GET')
        response = app.get("/dummy_resources/1",
                           headers={'X-NEW-REQUEST-HEADER': "sox"})

        self.assertEqual(response.headers['X-NEW-RESPONSE-HEADER'],
                         "response_header_data")

    def test_extend_get_resource_response(self):
        def extend_response_data(req, res):
            data = jsonutils.loads(res.body)
            data['FOXNSOX:extended_key'] = req.GET.get('extended_key')
            res.body = jsonutils.dumps(data)
            return res

        app = self._setup_app_with_request_handler(extend_response_data, 'GET')
        response = app.get("/dummy_resources/1?extended_key=extended_data")

        self.assertEqual(200, response.status_int)
        response_data = jsonutils.loads(response.body)
        self.assertEqual('extended_data',
                         response_data['FOXNSOX:extended_key'])
        self.assertEqual('knox', response_data['fort'])

    def test_get_resources(self):
        app = _setup_extensions_test_app()

        response = app.get("/dummy_resources/1?chewing=newblue")

        response_data = jsonutils.loads(response.body)
        self.assertEqual('newblue', response_data['FOXNSOX:googoose'])
        self.assertEqual("Pig Bands!", response_data['FOXNSOX:big_bands'])

    def test_edit_previously_uneditable_field(self):

        def _update_handler(req, res):
            data = jsonutils.loads(res.body)
            data['uneditable'] = req.params['uneditable']
            res.body = jsonutils.dumps(data)
            return res

        base_app = TestApp(setup_base_app())
        response = base_app.put("/dummy_resources/1",
                                {'uneditable': "new_value"})
        self.assertEqual(response.json['uneditable'], "original_value")

        ext_app = self._setup_app_with_request_handler(_update_handler,
                                                       'PUT')
        ext_response = ext_app.put("/dummy_resources/1",
                                   {'uneditable': "new_value"})
        self.assertEqual(ext_response.json['uneditable'], "new_value")

    def _setup_app_with_request_handler(self, handler, verb):
        req_ext = extensions.RequestExtension(verb,
                                              '/dummy_resources/:(id)',
                                              handler)
        manager = SimpleExtensionManager(None, None, req_ext)
        return _setup_extensions_test_app(manager)


class ExtensionManagerTest(unittest.TestCase):

    def test_invalid_extensions_are_not_registered(self):

        class InvalidExtension(object):
            """
            This Extension doesn't implement extension methods :
            get_name, get_description, get_namespace and get_updated
            """
            def get_alias(self):
                return "invalid_extension"

        ext_mgr = ExtensionManager('')
        ext_mgr.add_extension(InvalidExtension())
        ext_mgr.add_extension(StubExtension("valid_extension"))

        self.assertTrue('valid_extension' in ext_mgr.extensions)
        self.assertFalse('invalid_extension' in ext_mgr.extensions)


class PluginAwareExtensionManagerTest(unittest.TestCase):

    def test_unsupported_extensions_are_not_loaded(self):
        stub_plugin = StubPlugin(supported_extensions=["e1", "e3"])
        ext_mgr = PluginAwareExtensionManager('', stub_plugin)

        ext_mgr.add_extension(StubExtension("e1"))
        ext_mgr.add_extension(StubExtension("e2"))
        ext_mgr.add_extension(StubExtension("e3"))

        self.assertTrue("e1" in ext_mgr.extensions)
        self.assertFalse("e2" in ext_mgr.extensions)
        self.assertTrue("e3" in ext_mgr.extensions)

    def test_extensions_are_not_loaded_for_plugins_unaware_of_extensions(self):
        class ExtensionUnawarePlugin(object):
            """
            This plugin does not implement supports_extension method.
            Extensions will not be loaded when this plugin is used.
            """
            pass

        ext_mgr = PluginAwareExtensionManager('', ExtensionUnawarePlugin())
        ext_mgr.add_extension(StubExtension("e1"))

        self.assertFalse("e1" in ext_mgr.extensions)

    def test_extensions_not_loaded_for_plugin_without_expected_interface(self):

        class PluginWithoutExpectedInterface(object):
            """
            Plugin does not implement get_foo method as expected by extension
            """
            supported_extension_aliases = ["supported_extension"]

        ext_mgr = PluginAwareExtensionManager('',
                                              PluginWithoutExpectedInterface())
        ext_mgr.add_extension(
            ExtensionExpectingPluginInterface("supported_extension"))

        self.assertFalse("e1" in ext_mgr.extensions)

    def test_extensions_are_loaded_for_plugin_with_expected_interface(self):

        class PluginWithExpectedInterface(object):
            """
            This Plugin implements get_foo method as expected by extension
            """
            supported_extension_aliases = ["supported_extension"]

            def get_foo(self, bar=None):
                pass
        ext_mgr = PluginAwareExtensionManager('',
                                              PluginWithExpectedInterface())
        ext_mgr.add_extension(
            ExtensionExpectingPluginInterface("supported_extension"))

        self.assertTrue("supported_extension" in ext_mgr.extensions)

    def test_extensions_expecting_quantum_plugin_interface_are_loaded(self):
        class ExtensionForQuamtumPluginInterface(StubExtension):
            """
            This Extension does not implement get_plugin_interface method.
            This will work with any plugin implementing QuantumPluginBase
            """
            pass
        stub_plugin = StubPlugin(supported_extensions=["e1"])
        ext_mgr = PluginAwareExtensionManager('', stub_plugin)
        ext_mgr.add_extension(ExtensionForQuamtumPluginInterface("e1"))

        self.assertTrue("e1" in ext_mgr.extensions)

    def test_extensions_without_need_for__plugin_interface_are_loaded(self):
        class ExtensionWithNoNeedForPluginInterface(StubExtension):
            """
            This Extension does not need any plugin interface.
            This will work with any plugin implementing QuantumPluginBase
            """
            def get_plugin_interface(self):
                return None

        stub_plugin = StubPlugin(supported_extensions=["e1"])
        ext_mgr = PluginAwareExtensionManager('', stub_plugin)
        ext_mgr.add_extension(ExtensionWithNoNeedForPluginInterface("e1"))

        self.assertTrue("e1" in ext_mgr.extensions)


class ExtensionControllerTest(unittest.TestCase):

    def setUp(self):
        super(ExtensionControllerTest, self).setUp()
        self.test_app = _setup_extensions_test_app()

    def test_index_gets_all_registerd_extensions(self):
        response = self.test_app.get("/extensions")
        foxnsox = response.json["extensions"][0]

        self.assertEqual(foxnsox["alias"], "FOXNSOX")
        self.assertEqual(foxnsox["namespace"],
                         "http://www.fox.in.socks/api/ext/pie/v1.0")

    def test_extension_can_be_accessed_by_alias(self):
        foxnsox_extension = self.test_app.get("/extensions/FOXNSOX").json
        foxnsox_extension = foxnsox_extension['extension']
        self.assertEqual(foxnsox_extension["alias"], "FOXNSOX")
        self.assertEqual(foxnsox_extension["namespace"],
                         "http://www.fox.in.socks/api/ext/pie/v1.0")

    def test_show_returns_not_found_for_non_existent_extension(self):
        response = self.test_app.get("/extensions/non_existent", status="*")

        self.assertEqual(response.status_int, 404)


def app_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    return ExtensionsTestApp(conf)


def setup_base_app():
    config_file = 'quantum.conf.test'
    args = ['--config-file', etcdir(config_file)]
    config.parse(args=args)
    app = config.load_paste_app('extensions_test_app')
    return app


def setup_extensions_middleware(extension_manager=None):
    extension_manager = (extension_manager or
                         PluginAwareExtensionManager(
                             extensions_path,
                             FakePluginWithExtension()))
    config_file = 'quantum.conf.test'
    args = ['--config-file', etcdir(config_file)]
    config.parse(args=args)
    app = config.load_paste_app('extensions_test_app')
    return ExtensionMiddleware(app, ext_mgr=extension_manager)


def _setup_extensions_test_app(extension_manager=None):
    return TestApp(setup_extensions_middleware(extension_manager))


class SimpleExtensionManager(object):

    def __init__(self, resource_ext=None, action_ext=None, request_ext=None):
        self.resource_ext = resource_ext
        self.action_ext = action_ext
        self.request_ext = request_ext

    def get_resources(self):
        resource_exts = []
        if self.resource_ext:
            resource_exts.append(self.resource_ext)
        return resource_exts

    def get_actions(self):
        action_exts = []
        if self.action_ext:
            action_exts.append(self.action_ext)
        return action_exts

    def get_request_extensions(self):
        request_extensions = []
        if self.request_ext:
            request_extensions.append(self.request_ext)
        return request_extensions
