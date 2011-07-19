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
import json
import unittest
import routes
import os.path
from tests.unit import BaseTest
from abc import  abstractmethod

from webtest import TestApp
from quantum.common import extensions
from quantum.common import wsgi
from quantum.common import config
from quantum.common.extensions import (ExtensionManager,
                                       PluginAwareExtensionManager)

extension_index_response = "Try to say this Mr. Knox, sir..."
test_conf_file = os.path.join(os.path.dirname(__file__), os.pardir,
                              os.pardir, 'etc', 'quantum.conf.test')


class ExtensionControllerTest(unittest.TestCase):

    def setUp(self):
        super(ExtensionControllerTest, self).setUp()
        self.test_app = setup_extensions_test_app()

    def test_index_gets_all_registerd_extensions(self):
        response = self.test_app.get("/extensions")
        foxnsox = response.json["extensions"][0]

        self.assertEqual(foxnsox["alias"], "FOXNSOX")
        self.assertEqual(foxnsox["namespace"],
                         "http://www.fox.in.socks/api/ext/pie/v1.0")

    def test_extension_can_be_accessed_by_alias(self):
        foxnsox_extension = self.test_app.get("/extensions/FOXNSOX").json

        self.assertEqual(foxnsox_extension["alias"], "FOXNSOX")
        self.assertEqual(foxnsox_extension["namespace"],
                         "http://www.fox.in.socks/api/ext/pie/v1.0")


class ResourceExtensionTest(unittest.TestCase):

    def test_resource_extension(self):
        res_ext = extensions.ResourceExtension('tweedles', StubController(
                                                  extension_index_response))
        test_app = setup_extensions_test_app(StubExtensionManager(res_ext))

        response = test_app.get("/tweedles")
        self.assertEqual(200, response.status_int)
        self.assertEqual(extension_index_response, response.body)

    def test_returns_404_for_non_existant_extension(self):
        test_app = setup_extensions_test_app(StubExtensionManager(None))

        response = test_app.get("/non_extistant_extension", status='*')

        self.assertEqual(404, response.status_int)


class StubExtension(object):

    def __init__(self, alias="stub_extension"):
        self.alias = alias

    def get_name(self):
        return "Stub Extension"

    def get_alias(self):
        return self.alias

    def get_description(self):
        return ""

    def get_namespace(self):
        return ""

    def get_updated(self):
        return ""


class StubPlugin(object):

    def __init__(self, supported_extensions=[]):
        self.supported_extensions = supported_extensions

    def supports_extension(self, extension):
        return extension.get_alias() in self.supported_extensions


class ExtensionExpectingPluginInterface(StubExtension):
    """
    This extension expects plugin to implement all the methods defined
    in StubPluginInterface
    """

    def get_plugin_interface(self):
        return StubPluginInterface


class StubPluginInterface(extensions.PluginInterface):

    @abstractmethod
    def get_foo(self, bar=None):
        pass


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

    def setUp(self):
        self.ext_mgr = PluginAwareExtensionManager('')

    def test_unsupported_extensions_are_not_loaded(self):
        self.ext_mgr.plugin = StubPlugin(supported_extensions=["e1", "e3"])

        self.ext_mgr.add_extension(StubExtension("e1"))
        self.ext_mgr.add_extension(StubExtension("e2"))
        self.ext_mgr.add_extension(StubExtension("e3"))

        self.assertTrue("e1" in self.ext_mgr.extensions)
        self.assertFalse("e2" in self.ext_mgr.extensions)
        self.assertTrue("e3" in self.ext_mgr.extensions)

    def test_extensions_are_not_loaded_for_plugins_unaware_of_extensions(self):
        class ExtensionUnawarePlugin(object):
            """
            This plugin does not implement supports_extension method.
            Extensions will not be loaded when this plugin is used.
            """
            pass

        self.ext_mgr.plugin = ExtensionUnawarePlugin()
        self.ext_mgr.add_extension(StubExtension("e1"))

        self.assertFalse("e1" in self.ext_mgr.extensions)

    def test_extensions_not_loaded_for_plugin_without_expected_interface(self):

        class PluginWithoutExpectedInterface(object):
            """
            Plugin does not implement get_foo method as expected by extension
            """
            def supports_extension(self, true):
                return true

        self.ext_mgr.plugin = PluginWithoutExpectedInterface()
        self.ext_mgr.add_extension(ExtensionExpectingPluginInterface("e1"))

        self.assertFalse("e1" in self.ext_mgr.extensions)

    def test_extensions_are_loaded_for_plugin_with_expected_interface(self):

        class PluginWithExpectedInterface(object):
            """
            This Plugin implements get_foo method as expected by extension
            """
            def supports_extension(self, true):
                return true

            def get_foo(self, bar=None):
                pass

        self.ext_mgr.plugin = PluginWithExpectedInterface()
        self.ext_mgr.add_extension(ExtensionExpectingPluginInterface("e1"))

        self.assertTrue("e1" in self.ext_mgr.extensions)

    def test_extensions_expecting_quantum_plugin_interface_are_loaded(self):
        class ExtensionForQuamtumPluginInterface(StubExtension):
            """
            This Extension does not implement get_plugin_interface method.
            This will work with any plugin implementing QuantumPluginBase
            """
            pass

        self.ext_mgr.plugin = StubPlugin(supported_extensions=["e1"])
        self.ext_mgr.add_extension(ExtensionForQuamtumPluginInterface("e1"))

        self.assertTrue("e1" in self.ext_mgr.extensions)

    def test_extensions_without_need_for__plugin_interface_are_loaded(self):
        class ExtensionWithNoNeedForPluginInterface(StubExtension):
            """
            This Extension does not need any plugin interface.
            This will work with any plugin implementing QuantumPluginBase
            """
            def get_plugin_interface(self):
                return None

        self.ext_mgr.plugin = StubPlugin(supported_extensions=["e1"])
        self.ext_mgr.add_extension(ExtensionWithNoNeedForPluginInterface("e1"))

        self.assertTrue("e1" in self.ext_mgr.extensions)


class ActionExtensionTest(unittest.TestCase):

    def setUp(self):
        super(ActionExtensionTest, self).setUp()
        self.extension_app = setup_extensions_test_app()

    def test_extended_action_for_adding_extra_data(self):
        action_name = 'add_tweedle'
        action_params = dict(name='Beetle')
        req_body = json.dumps({action_name: action_params})
        response = self.extension_app.post('/dummy_resources/1/action',
                                     req_body, content_type='application/json')
        self.assertEqual("Tweedle Beetle Added.", response.body)

    def test_extended_action_for_deleting_extra_data(self):
        action_name = 'delete_tweedle'
        action_params = dict(name='Bailey')
        req_body = json.dumps({action_name: action_params})
        response = self.extension_app.post("/dummy_resources/1/action",
                                     req_body, content_type='application/json')
        self.assertEqual("Tweedle Bailey Deleted.", response.body)

    def test_returns_404_for_non_existant_action(self):
        non_existant_action = 'blah_action'
        action_params = dict(name="test")
        req_body = json.dumps({non_existant_action: action_params})

        response = self.extension_app.post("/dummy_resources/1/action",
                                     req_body, content_type='application/json',
                                     status='*')

        self.assertEqual(404, response.status_int)

    def test_returns_404_for_non_existant_resource(self):
        action_name = 'add_tweedle'
        action_params = dict(name='Beetle')
        req_body = json.dumps({action_name: action_params})

        response = self.extension_app.post("/asdf/1/action", req_body,
                                   content_type='application/json', status='*')
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
            data = json.loads(res.body)
            data['extended_key'] = req.GET.get('extended_key')
            res.body = json.dumps(data)
            return res

        app = self._setup_app_with_request_handler(extend_response_data, 'GET')
        response = app.get("/dummy_resources/1?extended_key=extended_data")

        self.assertEqual(200, response.status_int)
        response_data = json.loads(response.body)
        self.assertEqual('extended_data', response_data['extended_key'])
        self.assertEqual('knox', response_data['fort'])

    def test_get_resources(self):
        app = setup_extensions_test_app()

        response = app.get("/dummy_resources/1?chewing=newblue")

        response_data = json.loads(response.body)
        self.assertEqual('newblue', response_data['googoose'])
        self.assertEqual("Pig Bands!", response_data['big_bands'])

    def test_edit_previously_uneditable_field(self):

        def _update_handler(req, res):
            data = json.loads(res.body)
            data['uneditable'] = req.params['uneditable']
            res.body = json.dumps(data)
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
                                   '/dummy_resources/:(id)', handler)
        manager = StubExtensionManager(None, None, req_ext)
        return setup_extensions_test_app(manager)


class TestExtensionMiddlewareFactory(unittest.TestCase):

    def test_app_configured_with_extensions_as_filter(self):
        conf, quantum_app = config.load_paste_app('extensions_app_with_filter',
                                        {"config_file": test_conf_file}, None)

        response = TestApp(quantum_app).get("/extensions")
        self.assertEqual(response.status_int, 200)


class ExtensionsTestApp(wsgi.Router):

    def __init__(self, options={}):
        mapper = routes.Mapper()
        controller = StubController(extension_index_response)
        mapper.resource("dummy_resource", "/dummy_resources",
                        controller=controller)
        super(ExtensionsTestApp, self).__init__(mapper)


class StubController(wsgi.Controller):

    def __init__(self, body):
        self.body = body

    def index(self, request):
        return self.body

    def show(self, request, id):
        return {'fort': 'knox'}

    def update(self, request, id):
        return {'uneditable': 'original_value'}


def app_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    return ExtensionsTestApp(conf)


def setup_base_app():
    options = {'config_file': test_conf_file}
    conf, app = config.load_paste_app('extensions_test_app', options, None)
    return app


def setup_extensions_middleware(extension_manager=None):
    options = {'config_file': test_conf_file}
    conf, app = config.load_paste_app('extensions_test_app', options, None)
    return extensions.ExtensionMiddleware(app, conf, extension_manager)


def setup_extensions_test_app(extension_manager=None):
    return TestApp(setup_extensions_middleware(extension_manager))


class StubExtensionManager(object):

    def __init__(self, resource_ext=None, action_ext=None, request_ext=None):
        self.resource_ext = resource_ext
        self.action_ext = action_ext
        self.request_ext = request_ext

    def get_name(self):
        return "Tweedle Beetle Extension"

    def get_alias(self):
        return "TWDLBETL"

    def get_description(self):
        return "Provides access to Tweedle Beetles"

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
