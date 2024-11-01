# Copyright (c) 2011 OpenStack Foundation.
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

import copy
from unittest import mock

import fixtures
from neutron_lib import context
from neutron_lib import exceptions
from neutron_lib.plugins import constants as lib_const
from neutron_lib.plugins import directory
from neutron_lib.services import base as service_base
from oslo_config import cfg
from oslo_log import log as logging
from oslo_serialization import jsonutils
from oslo_service import wsgi as base_wsgi
import routes
import testtools
import webob
import webob.exc as webexc
import webtest

import neutron
from neutron.api import extensions
from neutron.api import wsgi
from neutron.common import config
from neutron.plugins.common import constants
from neutron import quota
from neutron.tests import base
from neutron.tests.unit.api.v2 import test_base
from neutron.tests.unit import dummy_plugin
from neutron.tests.unit import extension_stubs as ext_stubs
import neutron.tests.unit.extensions
from neutron.tests.unit.extensions import extendedattribute as extattr
from neutron.tests.unit import testlib_api

LOG = logging.getLogger(__name__)
_uuid = test_base._uuid
_get_path = test_base._get_path
extensions_path = ':'.join(neutron.tests.unit.extensions.__path__)


class CustomExtensionCheckMapMemento(fixtures.Fixture):
    """Create a copy of the custom extension support check map so it can be
    restored during test cleanup.
    """

    def _setUp(self):
        self._map_contents_backup = copy.deepcopy(
            extensions.EXTENSION_SUPPORTED_CHECK_MAP
        )
        self._plugin_agnostic_extensions_backup = set(
            extensions._PLUGIN_AGNOSTIC_EXTENSIONS
        )
        self.addCleanup(self._restore)

    def _restore(self):
        extensions.EXTENSION_SUPPORTED_CHECK_MAP = self._map_contents_backup
        extensions._PLUGIN_AGNOSTIC_EXTENSIONS = (
            self._plugin_agnostic_extensions_backup
        )


class ExtensionsTestApp(base_wsgi.Router):

    def __init__(self, options=None):
        options = options or {}
        mapper = routes.Mapper()
        controller = ext_stubs.StubBaseAppController()
        mapper.resource("dummy_resource", "/dummy_resources",
                        controller=controller)
        super().__init__(mapper)


class FakePluginWithExtension(service_base.ServicePluginBase):
    """A fake plugin used only for extension testing in this file."""

    supported_extension_aliases = ["FOXNSOX"]

    def method_to_support_foxnsox_extension(self, context):
        self._log("method_to_support_foxnsox_extension", context)

    def get_plugin_type(self):
        pass

    def get_plugin_description(self):
        pass


class ExtensionPathTest(base.BaseTestCase):

    def setUp(self):
        super().setUp()
        self.base_path = extensions.get_extensions_path()

    def test_get_extensions_path_with_plugins(self):
        cfg.CONF.set_override('api_extensions_path',
                              'neutron/tests/unit/extensions')
        path = extensions.get_extensions_path(
            {lib_const.CORE: FakePluginWithExtension()})
        self.assertEqual(path,
                         '%s:neutron/tests/unit/extensions' % self.base_path)

    def test_get_extensions_path_no_extensions(self):
        # Reset to default value, as it's overridden by base class
        cfg.CONF.set_override('api_extensions_path', '')
        path = extensions.get_extensions_path()
        self.assertEqual(path, self.base_path)

    def test_get_extensions_path_single_extension(self):
        cfg.CONF.set_override('api_extensions_path', 'path1')
        path = extensions.get_extensions_path()
        self.assertEqual(path, '%s:path1' % self.base_path)

    def test_get_extensions_path_multiple_extensions(self):
        cfg.CONF.set_override('api_extensions_path', 'path1:path2')
        path = extensions.get_extensions_path()
        self.assertEqual(path, '%s:path1:path2' % self.base_path)

    def test_get_extensions_path_duplicate_extensions(self):
        cfg.CONF.set_override('api_extensions_path', 'path1:path1')
        path = extensions.get_extensions_path()
        self.assertEqual(path, '%s:path1' % self.base_path)


class ResourceExtensionTest(base.BaseTestCase):

    class ResourceExtensionController(wsgi.Controller):

        def index(self, request):
            return "resource index"

        def show(self, request, id):
            return {'data': {'id': id}}

        def notimplemented_function(self, request, id):
            return webob.exc.HTTPNotImplemented()

        def custom_member_action(self, request, id):
            return {'member_action': 'value'}

        def custom_collection_method(self, request, **kwargs):
            return {'collection': 'value'}

        def custom_collection_action(self, request, **kwargs):
            return {'collection': 'value'}

    class DummySvcPlugin(wsgi.Controller):
        @classmethod
        def get_plugin_type(cls):
            return dummy_plugin.DUMMY_SERVICE_TYPE

        def index(self, request, **kwargs):
            return "resource index"

        def custom_member_action(self, request, **kwargs):
            return {'member_action': 'value'}

        def collection_action(self, request, **kwargs):
            return {'collection': 'value'}

        def show(self, request, id):
            return {'data': {'id': id}}

    def test_exceptions_notimplemented(self):
        controller = self.ResourceExtensionController()
        member = {'notimplemented_function': "GET"}
        res_ext = extensions.ResourceExtension('tweedles', controller,
                                               member_actions=member)
        test_app = _setup_extensions_test_app(SimpleExtensionManager(res_ext))

        # Ideally we would check for a 501 code here but webtest doesn't take
        # anything that is below 200 or above 400 so we can't actually check
        # it.  It throws webtest.AppError instead.
        try:
            test_app.get("/tweedles/some_id/notimplemented_function")
            # Shouldn't be reached
            self.fail()
        except webtest.AppError as e:
            self.assertIn('501', str(e))

    def test_resource_can_be_added_as_extension(self):
        res_ext = extensions.ResourceExtension(
            'tweedles', self.ResourceExtensionController())
        test_app = _setup_extensions_test_app(SimpleExtensionManager(res_ext))
        index_response = test_app.get("/tweedles")
        self.assertEqual(200, index_response.status_int)
        self.assertEqual(b"resource index", index_response.body)

        show_response = test_app.get("/tweedles/25266")
        self.assertEqual({'data': {'id': "25266"}}, show_response.json)

    def test_resource_gets_prefix_of_plugin(self):
        class DummySvcPlugin(wsgi.Controller):
            def index(self, request):
                return ""

            @classmethod
            def get_plugin_type(cls):
                return dummy_plugin.DUMMY_SERVICE_TYPE

        res_ext = extensions.ResourceExtension(
            'tweedles', DummySvcPlugin(), path_prefix="/dummy_svc")
        test_app = _setup_extensions_test_app(SimpleExtensionManager(res_ext))
        index_response = test_app.get("/dummy_svc/tweedles")
        self.assertEqual(200, index_response.status_int)

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

    def test_resource_ext_with_custom_member_action_gets_plugin_prefix(self):
        controller = self.DummySvcPlugin()
        member = {'custom_member_action': "GET"}
        collections = {'collection_action': "GET"}
        res_ext = extensions.ResourceExtension('tweedles', controller,
                                               path_prefix="/dummy_svc",
                                               member_actions=member,
                                               collection_actions=collections)
        test_app = _setup_extensions_test_app(SimpleExtensionManager(res_ext))

        response = test_app.get("/dummy_svc/tweedles/1/custom_member_action")
        self.assertEqual(200, response.status_int)
        self.assertEqual(jsonutils.loads(response.body)['member_action'],
                         "value")

        response = test_app.get("/dummy_svc/tweedles/collection_action")
        self.assertEqual(200, response.status_int)
        self.assertEqual(jsonutils.loads(response.body)['collection'],
                         "value")

    def test_plugin_prefix_with_parent_resource(self):
        controller = self.DummySvcPlugin()
        parent = dict(member_name="tenant",
                      collection_name="tenants")
        member = {'custom_member_action': "GET"}
        collections = {'collection_action': "GET"}
        res_ext = extensions.ResourceExtension('tweedles', controller, parent,
                                               path_prefix="/dummy_svc",
                                               member_actions=member,
                                               collection_actions=collections)
        test_app = _setup_extensions_test_app(SimpleExtensionManager(res_ext))

        index_response = test_app.get("/dummy_svc/tenants/1/tweedles")
        self.assertEqual(200, index_response.status_int)

        response = test_app.get("/dummy_svc/tenants/1/"
                                "tweedles/1/custom_member_action")
        self.assertEqual(200, response.status_int)
        self.assertEqual(jsonutils.loads(response.body)['member_action'],
                         "value")

        response = test_app.get("/dummy_svc/tenants/2/"
                                "tweedles/collection_action")
        self.assertEqual(200, response.status_int)
        self.assertEqual(jsonutils.loads(response.body)['collection'],
                         "value")

    def test_resource_extension_for_get_custom_collection_action(self):
        controller = self.ResourceExtensionController()
        collections = {'custom_collection_action': "GET"}
        res_ext = extensions.ResourceExtension('tweedles', controller,
                                               collection_actions=collections)
        test_app = _setup_extensions_test_app(SimpleExtensionManager(res_ext))

        response = test_app.get("/tweedles/custom_collection_action")
        self.assertEqual(200, response.status_int)
        LOG.debug(jsonutils.loads(response.body))
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

    def test_resource_extension_for_get_custom_collection_method(self):
        controller = self.ResourceExtensionController()
        collections = {'custom_collection_method': "GET"}
        res_ext = extensions.ResourceExtension('tweedles', controller,
                                               collection_methods=collections)
        test_app = _setup_extensions_test_app(SimpleExtensionManager(res_ext))

        response = test_app.get("/tweedles")

        self.assertEqual(200, response.status_int)
        self.assertEqual("value", jsonutils.loads(response.body)['collection'])

    def test_resource_extension_for_put_custom_collection_method(self):
        controller = self.ResourceExtensionController()
        collections = {'custom_collection_method': "PUT"}
        res_ext = extensions.ResourceExtension('tweedles', controller,
                                               collection_methods=collections)
        test_app = _setup_extensions_test_app(SimpleExtensionManager(res_ext))

        response = test_app.put("/tweedles")

        self.assertEqual(200, response.status_int)
        self.assertEqual('value', jsonutils.loads(response.body)['collection'])

    def test_resource_extension_for_post_custom_collection_method(self):
        controller = self.ResourceExtensionController()
        collections = {'custom_collection_method': "POST"}
        res_ext = extensions.ResourceExtension('tweedles', controller,
                                               collection_methods=collections)
        test_app = _setup_extensions_test_app(SimpleExtensionManager(res_ext))

        response = test_app.post("/tweedles")

        self.assertEqual(200, response.status_int)
        self.assertEqual('value', jsonutils.loads(response.body)['collection'])

    def test_resource_extension_for_delete_custom_collection_method(self):
        controller = self.ResourceExtensionController()
        collections = {'custom_collection_method': "DELETE"}
        res_ext = extensions.ResourceExtension('tweedles', controller,
                                               collection_methods=collections)
        test_app = _setup_extensions_test_app(SimpleExtensionManager(res_ext))

        response = test_app.delete("/tweedles")

        self.assertEqual(200, response.status_int)
        self.assertEqual('value', jsonutils.loads(response.body)['collection'])

    def test_resource_ext_for_formatted_req_on_custom_collection_method(self):
        controller = self.ResourceExtensionController()
        collections = {'custom_collection_method': "GET"}
        res_ext = extensions.ResourceExtension('tweedles', controller,
                                               collection_methods=collections)
        test_app = _setup_extensions_test_app(SimpleExtensionManager(res_ext))

        response = test_app.get("/tweedles.json")

        self.assertEqual(200, response.status_int)
        self.assertEqual("value", jsonutils.loads(response.body)['collection'])

    def test_resource_ext_for_nested_resource_custom_collection_method(self):
        controller = self.ResourceExtensionController()
        collections = {'custom_collection_method': "GET"}
        parent = {'collection_name': 'beetles', 'member_name': 'beetle'}
        res_ext = extensions.ResourceExtension('tweedles', controller,
                                               collection_methods=collections,
                                               parent=parent)
        test_app = _setup_extensions_test_app(SimpleExtensionManager(res_ext))

        response = test_app.get("/beetles/beetle_id/tweedles")

        self.assertEqual(200, response.status_int)
        self.assertEqual("value", jsonutils.loads(response.body)['collection'])

    def test_resource_extension_with_custom_member_action_and_attr_map(self):
        controller = self.ResourceExtensionController()
        member = {'custom_member_action': "GET"}
        params = {
            'tweedles': {
                'id': {'allow_post': False, 'allow_put': False,
                       'validate': {'type:uuid': None},
                       'is_visible': True},
                'name': {'allow_post': True, 'allow_put': True,
                         'validate': {'type:string': None},
                         'default': '', 'is_visible': True},
            }
        }
        res_ext = extensions.ResourceExtension('tweedles', controller,
                                               member_actions=member,
                                               attr_map=params)
        test_app = _setup_extensions_test_app(SimpleExtensionManager(res_ext))

        response = test_app.get("/tweedles/some_id/custom_member_action")
        self.assertEqual(200, response.status_int)
        self.assertEqual(jsonutils.loads(response.body)['member_action'],
                         "value")

    def test_returns_404_for_non_existent_extension(self):
        test_app = _setup_extensions_test_app(SimpleExtensionManager(None))

        response = test_app.get("/non_extistant_extension", status='*')

        self.assertEqual(404, response.status_int)


class ActionExtensionTest(base.BaseTestCase):

    def setUp(self):
        super().setUp()
        self.extension_app = _setup_extensions_test_app()

    def test_extended_action_for_adding_extra_data(self):
        action_name = 'FOXNSOX:add_tweedle'
        action_params = dict(name='Beetle')
        req_body = jsonutils.dumps({action_name: action_params})
        response = self.extension_app.post('/dummy_resources/1/action',
                                           req_body,
                                           content_type='application/json')
        self.assertEqual(b"Tweedle Beetle Added.", response.body)

    def test_extended_action_for_deleting_extra_data(self):
        action_name = 'FOXNSOX:delete_tweedle'
        action_params = dict(name='Bailey')
        req_body = jsonutils.dumps({action_name: action_params})
        response = self.extension_app.post("/dummy_resources/1/action",
                                           req_body,
                                           content_type='application/json')
        self.assertEqual(b"Tweedle Bailey Deleted.", response.body)

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


class RequestExtensionTest(base.BaseTestCase):

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
            res.body = jsonutils.dump_as_bytes(data)
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
            res.body = jsonutils.dump_as_bytes(data)
            return res

        base_app = webtest.TestApp(setup_base_app(self))
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


class ExtensionManagerTest(base.BaseTestCase):

    def test_optional_extensions_no_error(self):
        ext_mgr = extensions.ExtensionManager('')
        attr_map = {}
        ext_mgr.add_extension(ext_stubs.StubExtension('foo_alias',
                                                      optional=['cats']))
        ext_mgr.extend_resources("2.0", attr_map)
        self.assertIn('foo_alias', ext_mgr.extensions)

    def test_missing_required_extensions_raise_error(self):
        ext_mgr = extensions.ExtensionManager('')
        attr_map = {}
        ext_mgr.add_extension(ext_stubs.StubExtensionWithReqs('foo_alias'))
        self.assertRaises(exceptions.ExtensionsNotFound,
                          ext_mgr.extend_resources, "2.0", attr_map)

    def test_missing_required_extensions_gracefully_error(self):
        ext_mgr = extensions.ExtensionManager('')
        attr_map = {}
        default_ext = list(constants.DEFAULT_SERVICE_PLUGINS.values())[0]
        ext_mgr.add_extension(ext_stubs.StubExtensionWithReqs(default_ext))
        ext_mgr.extend_resources("2.0", attr_map)
        # none of the default extensions should be loaded as their
        # requirements are not satisfied, and yet we do not fail.
        self.assertFalse(ext_mgr.extensions)

    def test__check_faulty_extensions_raise_not_default_ext(self):
        ext_mgr = extensions.ExtensionManager('')
        with testtools.ExpectedException(exceptions.ExtensionsNotFound):
            ext_mgr._check_faulty_extensions({'foo'})

    def test_invalid_extensions_are_not_registered(self):

        class InvalidExtension:
            """Invalid extension.

            This Extension doesn't implement extension methods :
            get_name, get_description and get_updated
            """
            def get_alias(self):
                return "invalid_extension"

        ext_mgr = extensions.ExtensionManager('')
        ext_mgr.add_extension(InvalidExtension())
        ext_mgr.add_extension(ext_stubs.StubExtension("valid_extension"))

        self.assertIn('valid_extension', ext_mgr.extensions)
        self.assertNotIn('invalid_extension', ext_mgr.extensions)

    def test_assignment_of_attr_map(self):
        """Unit test for bug 1443342

        In this bug, an extension that extended multiple resources with the
        same dict would cause future extensions to inadvertently modify the
        resources of all of the resources since they were referencing the same
        dictionary.
        """

        class MultiResourceExtension(ext_stubs.StubExtension):
            """Generated Extended Resources.

            This extension's extended resource will assign
            to more than one resource.
            """

            def get_extended_resources(self, version):
                EXTENDED_TIMESTAMP = {
                    'created_at': {'allow_post': False, 'allow_put': False,
                                   'is_visible': True}}
                EXTENDED_RESOURCES = ["ext1", "ext2"]
                attrs = {}
                for resources in EXTENDED_RESOURCES:
                    attrs[resources] = EXTENDED_TIMESTAMP

                return attrs

        class AttrExtension(ext_stubs.StubExtension):
            def get_extended_resources(self, version):
                attrs = {
                    self.alias: {
                        '%s-attr' % self.alias: {'allow_post': False,
                                                 'allow_put': False,
                                                 'is_visible': True}}}
                return attrs

        ext_mgr = extensions.ExtensionManager('')
        attr_map = {}
        ext_mgr.add_extension(MultiResourceExtension('timestamp'))
        ext_mgr.extend_resources("2.0", attr_map)
        ext_mgr.add_extension(AttrExtension("ext1"))
        ext_mgr.add_extension(AttrExtension("ext2"))
        ext_mgr.extend_resources("2.0", attr_map)
        self.assertIn('created_at', attr_map['ext2'])
        self.assertIn('created_at', attr_map['ext1'])
        # now we need to make sure the attrextensions didn't leak across
        self.assertNotIn('ext1-attr', attr_map['ext2'])
        self.assertNotIn('ext2-attr', attr_map['ext1'])

    def test_extension_extends_sub_resource(self):
        """Unit test for bug 1722842

        Check that an extension can extend a sub-resource
        """
        RESOURCE = "test_resource"
        SUB_RESOURCE_NAME = "test_sub_resource"
        INITIAL_PARAM = "dummy_param1"
        ADDITIONAL_PARAM = "dummy_param2"

        SUB_RESOURCE = {
            'parent': {'member_name': RESOURCE},
            'parameters': {
                INITIAL_PARAM: {'allow_post': False,
                                'allow_put': False,
                                'validate': {'type:uuid': None},
                                'is_visible': True}
            }
        }

        class BaseExtension(ext_stubs.StubExtension):

            def get_extended_resources(self, version):
                return {
                     SUB_RESOURCE_NAME: SUB_RESOURCE
                }

        class ExtensionExtendingASubresource(ext_stubs.StubExtension):

            def get_extended_resources(self, version):
                return {
                    SUB_RESOURCE_NAME: {
                        'parameters': {
                            ADDITIONAL_PARAM: {'allow_post': False,
                                               'allow_put': False,
                                               'validate': {'type:uuid': None},
                                               'is_visible': True}
                        }
                    }
                }

            def get_required_extensions(self):
                return ['base_extension']

        ext_mgr = extensions.ExtensionManager('')
        attr_map = {}
        ext_mgr.add_extension(BaseExtension('base_extension'))
        ext_mgr.add_extension(
            ExtensionExtendingASubresource())
        ext_mgr.extend_resources("2.0", attr_map)

        # check that the parent descriptor is untouched
        self.assertEqual(SUB_RESOURCE['parent'],
                         attr_map[SUB_RESOURCE_NAME]['parent'])
        # check that the initial attribute is still here
        self.assertIn(INITIAL_PARAM,
                      attr_map[SUB_RESOURCE_NAME]['parameters'])
        # check that the new attribute is here as well
        self.assertIn(ADDITIONAL_PARAM,
                      attr_map[SUB_RESOURCE_NAME]['parameters'])


class PluginAwareExtensionManagerTest(base.BaseTestCase):

    def test_unsupported_extensions_are_not_loaded(self):
        stub_plugin = ext_stubs.StubPlugin(supported_extensions=["e1", "e3"])
        plugin_info = {lib_const.CORE: stub_plugin}
        with mock.patch("neutron.api.extensions.PluginAwareExtensionManager."
                        "check_if_plugin_extensions_loaded"):
            ext_mgr = extensions.PluginAwareExtensionManager('', plugin_info)

            ext_mgr.add_extension(ext_stubs.StubExtension("e1"))
            ext_mgr.add_extension(ext_stubs.StubExtension("e2"))
            ext_mgr.add_extension(ext_stubs.StubExtension("e3"))

            self.assertIn("e1", ext_mgr.extensions)
            self.assertNotIn("e2", ext_mgr.extensions)
            self.assertIn("e3", ext_mgr.extensions)

    def test_extensions_are_not_loaded_for_plugins_unaware_of_extensions(self):
        class ExtensionUnawarePlugin:
            """This plugin does not implement supports_extension method.

            Extensions will not be loaded when this plugin is used.
            """
            pass

        plugin_info = {lib_const.CORE: ExtensionUnawarePlugin()}
        ext_mgr = extensions.PluginAwareExtensionManager('', plugin_info)
        ext_mgr.add_extension(ext_stubs.StubExtension("e1"))

        self.assertNotIn("e1", ext_mgr.extensions)

    def test_extensions_not_loaded_for_plugin_without_expected_interface(self):

        class PluginWithoutExpectedIface:
            """Does not implement get_foo method as expected by extension."""
            supported_extension_aliases = ["supported_extension"]

        plugin_info = {lib_const.CORE: PluginWithoutExpectedIface()}
        with mock.patch("neutron.api.extensions.PluginAwareExtensionManager."
                        "check_if_plugin_extensions_loaded"):
            ext_mgr = extensions.PluginAwareExtensionManager('', plugin_info)
            ext_mgr.add_extension(ext_stubs.ExtensionExpectingPluginInterface(
                "supported_extension"))

            self.assertNotIn("e1", ext_mgr.extensions)

    def test_extensions_are_loaded_for_plugin_with_expected_interface(self):

        class PluginWithExpectedInterface(service_base.ServicePluginBase):
            """Implements get_foo method as expected by extension."""
            supported_extension_aliases = ["supported_extension"]

            def get_foo(self, ext=None):
                pass

            def get_plugin_type(self):
                pass

            def get_plugin_description(self):
                pass

        plugin_info = {lib_const.CORE: PluginWithExpectedInterface()}
        with mock.patch("neutron.api.extensions.PluginAwareExtensionManager."
                        "check_if_plugin_extensions_loaded"):
            ext_mgr = extensions.PluginAwareExtensionManager('', plugin_info)
            ext_mgr.add_extension(ext_stubs.ExtensionExpectingPluginInterface(
                "supported_extension"))

            self.assertIn("supported_extension", ext_mgr.extensions)

    def test_extensions_expecting_neutron_plugin_interface_are_loaded(self):
        class ExtensionForQuamtumPluginInterface(ext_stubs.StubExtension):
            """This Extension does not implement get_plugin_interface method.

            This will work with any plugin implementing NeutronPluginBase
            """
            pass
        stub_plugin = ext_stubs.StubPlugin(supported_extensions=["e1"])
        plugin_info = {lib_const.CORE: stub_plugin}

        with mock.patch("neutron.api.extensions.PluginAwareExtensionManager."
                        "check_if_plugin_extensions_loaded"):
            ext_mgr = extensions.PluginAwareExtensionManager('', plugin_info)
            ext_mgr.add_extension(ExtensionForQuamtumPluginInterface("e1"))

            self.assertIn("e1", ext_mgr.extensions)

    def test_extensions_without_need_for__plugin_interface_are_loaded(self):
        class ExtensionWithNoNeedForPluginInterface(ext_stubs.StubExtension):
            """This Extension does not need any plugin interface.

            This will work with any plugin implementing NeutronPluginBase
            """
            def get_plugin_interface(self):
                return None

        stub_plugin = ext_stubs.StubPlugin(supported_extensions=["e1"])
        plugin_info = {lib_const.CORE: stub_plugin}
        with mock.patch("neutron.api.extensions.PluginAwareExtensionManager."
                        "check_if_plugin_extensions_loaded"):
            ext_mgr = extensions.PluginAwareExtensionManager('', plugin_info)
            ext_mgr.add_extension(ExtensionWithNoNeedForPluginInterface("e1"))

            self.assertIn("e1", ext_mgr.extensions)

    def test_extension_loaded_for_non_core_plugin(self):
        class NonCorePluginExtenstion(ext_stubs.StubExtension):
            def get_plugin_interface(self):
                return None

        stub_plugin = ext_stubs.StubPlugin(supported_extensions=["e1"])
        plugin_info = {dummy_plugin.DUMMY_SERVICE_TYPE: stub_plugin}
        with mock.patch("neutron.api.extensions.PluginAwareExtensionManager."
                        "check_if_plugin_extensions_loaded"):
            ext_mgr = extensions.PluginAwareExtensionManager('', plugin_info)
            ext_mgr.add_extension(NonCorePluginExtenstion("e1"))

            self.assertIn("e1", ext_mgr.extensions)

    def test_unloaded_supported_extensions_raises_exception(self):
        stub_plugin = ext_stubs.StubPlugin(
            supported_extensions=["unloaded_extension"])
        plugin_info = {lib_const.CORE: stub_plugin}
        self.assertRaises(exceptions.ExtensionsNotFound,
                          extensions.PluginAwareExtensionManager,
                          '', plugin_info)

    def test_custom_supported_implementation(self):
        self.useFixture(CustomExtensionCheckMapMemento())

        class FakePlugin:
            pass

        class FakeExtension(ext_stubs.StubExtension):
            extensions.register_custom_supported_check(
                'stub_extension', lambda: True, plugin_agnostic=True
            )

        ext = FakeExtension()

        plugin_info = {lib_const.CORE: FakePlugin()}
        ext_mgr = extensions.PluginAwareExtensionManager('', plugin_info)
        ext_mgr.add_extension(ext)
        self.assertIn("stub_extension", ext_mgr.extensions)

        extensions.register_custom_supported_check(
            'stub_extension', lambda: False, plugin_agnostic=True
        )
        ext_mgr = extensions.PluginAwareExtensionManager('', plugin_info)
        ext_mgr.add_extension(ext)
        self.assertNotIn("stub_extension", ext_mgr.extensions)

    def test_custom_supported_implementation_plugin_specific(self):
        self.useFixture(CustomExtensionCheckMapMemento())

        class FakePlugin:
            pass

        class FakeExtension(ext_stubs.StubExtension):
            extensions.register_custom_supported_check(
                'stub_plugin_extension', lambda: True, plugin_agnostic=False
            )

        plugin_info = {lib_const.CORE: FakePlugin()}
        self.assertRaises(
            exceptions.ExtensionsNotFound,
            extensions.PluginAwareExtensionManager, '', plugin_info)


class ExtensionControllerTest(testlib_api.WebTestCase):

    def setUp(self):
        super().setUp()
        self.test_app = _setup_extensions_test_app()

    def test_index_gets_all_registerd_extensions(self):
        response = self.test_app.get("/extensions." + self.fmt)
        res_body = self.deserialize(response)
        foxnsox = res_body["extensions"][0]

        self.assertEqual(foxnsox["alias"], "FOXNSOX")

    def test_extension_can_be_accessed_by_alias(self):
        response = self.test_app.get("/extensions/FOXNSOX." + self.fmt)
        foxnsox_extension = self.deserialize(response)
        foxnsox_extension = foxnsox_extension['extension']
        self.assertEqual(foxnsox_extension["alias"], "FOXNSOX")

    def test_show_returns_not_found_for_non_existent_extension(self):
        response = self.test_app.get("/extensions/non_existent" + self.fmt,
                                     status="*")

        self.assertEqual(response.status_int, 404)


def app_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    return ExtensionsTestApp(conf)


def setup_base_app(test):
    base.BaseTestCase.config_parse()
    app = config.load_paste_app('extensions_test_app')
    return app


def setup_extensions_middleware(extension_manager=None):
    extension_manager = (extension_manager or
                         extensions.PluginAwareExtensionManager(
                             extensions_path,
                             {lib_const.CORE: FakePluginWithExtension()}))
    base.BaseTestCase.config_parse()
    app = config.load_paste_app('extensions_test_app')
    return extensions.ExtensionMiddleware(app, ext_mgr=extension_manager)


def _setup_extensions_test_app(extension_manager=None):
    return webtest.TestApp(setup_extensions_middleware(extension_manager))


class SimpleExtensionManager:

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


class ExtensionExtendedAttributeTestPlugin:

    supported_extension_aliases = [
        'ext-obj-test', "extended-ext-attr"
    ]

    def __init__(self, configfile=None):
        super()
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


class ExtensionExtendedAttributeTestCase(base.BaseTestCase):
    def setUp(self):
        super().setUp()
        plugin = (
            "neutron.tests.unit.api.test_extensions."
            "ExtensionExtendedAttributeTestPlugin"
        )

        # point config file to: neutron/tests/etc/neutron.conf
        self.config_parse()

        self.setup_coreplugin(plugin)

        ext_mgr = extensions.PluginAwareExtensionManager(
            extensions_path,
            {lib_const.CORE: ExtensionExtendedAttributeTestPlugin()}
        )
        ext_mgr.extend_resources("2.0", {})
        extensions.PluginAwareExtensionManager._instance = ext_mgr

        app = config.load_paste_app('extensions_test_app')
        self._api = extensions.ExtensionMiddleware(app, ext_mgr=ext_mgr)

        self._tenant_id = "8c70909f-b081-452d-872b-df48e6c355d1"

        self.agentscheduler_dbMinxin = directory.get_plugin()

        quota.QUOTAS._driver = None
        cfg.CONF.set_override('quota_driver',
                              'neutron.db.quota.driver_null.DbQuotaDriverNull',
                              group='QUOTAS')

    def _do_request(self, method, path, data=None, params=None, action=None):
        content_type = 'application/json'
        body = None
        if data is not None:  # empty dict is valid
            body = wsgi.Serializer().serialize(data, content_type)

        req = testlib_api.create_request(
            path, body, content_type,
            method, query_string=params)
        req.environ['neutron.context'] = context.Context(
            '', self._tenant_id, roles=['member', 'reader'])
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
            f'ext_test_resources/{obj_id}'))
        obj2 = res['ext_test_resource']
        self.assertEqual(obj2[extattr.EXTENDED_ATTRIBUTE], attr)
