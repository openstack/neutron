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

from webtest import TestApp
from quantum.common import extensions
from quantum.common import wsgi
from quantum.common import config


response_body = "Try to say this Mr. Knox, sir..."
test_conf_file = os.path.join(os.path.dirname(__file__), os.pardir,
                              os.pardir, 'etc', 'quantum.conf.test')


class ExtensionControllerTest(unittest.TestCase):

    def setUp(self):
        super(ExtensionControllerTest, self).setUp()
        self.test_app = setup_extensions_test_app()

    def test_index(self):
        response = self.test_app.get("/extensions")
        self.assertEqual(200, response.status_int)

    def test_get_by_alias(self):
        response = self.test_app.get("/extensions/FOXNSOX")
        self.assertEqual(200, response.status_int)


class ResourceExtensionTest(unittest.TestCase):

    def test_no_extension_present(self):
        test_app = setup_extensions_test_app(StubExtensionManager(None))
        response = test_app.get("/blah", status='*')
        self.assertEqual(404, response.status_int)

    def test_get_resources(self):
        res_ext = extensions.ResourceExtension('tweedles',
                                               StubController(response_body))
        test_app = setup_extensions_test_app(StubExtensionManager(res_ext))

        response = test_app.get("/tweedles")
        self.assertEqual(200, response.status_int)
        self.assertEqual(response_body, response.body)


class ExtensionManagerTest(unittest.TestCase):

    def test_get_resources(self):
        test_app = setup_extensions_test_app()
        response = test_app.get('/foxnsocks')

        self.assertEqual(200, response.status_int)
        self.assertEqual(response_body, response.body)


class ActionExtensionTest(unittest.TestCase):

    def setUp(self):
        super(ActionExtensionTest, self).setUp()
        self.test_app = setup_extensions_test_app()

    def _send_server_action_request(self, url, body):
        return self.test_app.post(url, json.dumps(body),
                                  content_type='application/json', status='*')

    def test_extended_action(self):
        body = json.dumps(dict(add_tweedle=dict(name="test")))
        response = self.test_app.post('/dummy_resources/1/action', body,
                                      content_type='application/json')
        self.assertEqual("Tweedle Beetle Added.", response.body)

        body = json.dumps(dict(delete_tweedle=dict(name="test")))
        response = self.test_app.post("/dummy_resources/1/action", body,
                                      content_type='application/json')

        self.assertEqual(200, response.status_int)
        self.assertEqual("Tweedle Beetle Deleted.", response.body)

    def test_invalid_action_body(self):
        body = json.dumps(dict(blah=dict(name="test")))  # Doesn't exist
        response = self.test_app.post("/dummy_resources/1/action", body,
                                      content_type='application/json',
                                      status='*')
        self.assertEqual(404, response.status_int)

    def test_invalid_action(self):
        body = json.dumps(dict(blah=dict(name="test")))
        response = self.test_app.post("/asdf/1/action",
                                      body, content_type='application/json',
                                      status='*')
        self.assertEqual(404, response.status_int)


class RequestExtensionTest(BaseTest):

    def test_get_resources_with_stub_mgr(self):

        def _req_handler(req, res):
            # only handle JSON responses
            data = json.loads(res.body)
            data['googoose'] = req.GET.get('chewing')
            res.body = json.dumps(data)
            return res

        req_ext = extensions.RequestExtension('GET',
                                                '/dummy_resources/:(id)',
                                                _req_handler)

        manager = StubExtensionManager(None, None, req_ext)
        app = setup_extensions_test_app(manager)

        response = app.get("/dummy_resources/1?chewing=bluegoos",
                           extra_environ={'api.version': '1.1'})

        self.assertEqual(200, response.status_int)
        response_data = json.loads(response.body)
        self.assertEqual('bluegoos', response_data['googoose'])
        self.assertEqual('knox', response_data['fort'])

    def test_get_resources_with_mgr(self):
        app = setup_extensions_test_app()

        response = app.get("/dummy_resources/1?"
                                            "chewing=newblue", status='*')

        self.assertEqual(200, response.status_int)
        response_data = json.loads(response.body)
        self.assertEqual('newblue', response_data['googoose'])
        self.assertEqual("Pig Bands!", response_data['big_bands'])


class TestExtensionMiddlewareFactory(unittest.TestCase):

    def test_app_configured_with_extensions_as_filter(self):
        conf, quantum_app = config.load_paste_app('extensions_app_with_filter',
                                                  {"config_file": test_conf_file},
                                                  None)

        response = TestApp(quantum_app).get("/extensions")
        self.assertEqual(response.status_int, 200)


class ExtensionsTestApp(wsgi.Router):

    def __init__(self, options={}):
        mapper = routes.Mapper()
        controller = StubController(response_body)
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


def app_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    return ExtensionsTestApp(conf)


def setup_extensions_test_app(extension_manager=None):
    options = {'config_file': test_conf_file}
    conf, app = config.load_paste_app('extensions_test_app', options, None)
    extended_app = extensions.ExtensionMiddleware(app, conf, extension_manager)
    return TestApp(extended_app)


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
