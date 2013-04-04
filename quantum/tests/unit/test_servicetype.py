# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright 2012 OpenStack Foundation.
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
#
#    @author: Salvatore Orlando, VMware
#

import contextlib
import logging

import mock
from oslo.config import cfg
import webob.exc as webexc
import webtest

from quantum.api import extensions
from quantum import context
from quantum.db import api as db_api
from quantum.db import servicetype_db
from quantum.extensions import servicetype
from quantum import manager
from quantum.plugins.common import constants
from quantum.tests.unit import dummy_plugin as dp
from quantum.tests.unit import test_api_v2
from quantum.tests.unit import test_db_plugin
from quantum.tests.unit import test_extensions
from quantum.tests.unit import testlib_api


LOG = logging.getLogger(__name__)
DEFAULT_SERVICE_DEFS = [{'service_class': constants.DUMMY,
                         'plugin': dp.DUMMY_PLUGIN_NAME}]

_uuid = test_api_v2._uuid
_get_path = test_api_v2._get_path


class TestServiceTypeExtensionManager(object):
    """ Mock extensions manager """

    def get_resources(self):
        return (servicetype.Servicetype.get_resources() +
                dp.Dummy.get_resources())

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


class ServiceTypeTestCaseBase(testlib_api.WebTestCase):
    fmt = 'json'

    def setUp(self):
        # This is needed because otherwise a failure will occur due to
        # nonexisting core_plugin
        cfg.CONF.set_override('core_plugin', test_db_plugin.DB_PLUGIN_KLASS)
        cfg.CONF.set_override('service_plugins',
                              ["%s.%s" % (dp.__name__,
                                          dp.DummyServicePlugin.__name__)])
        self.addCleanup(cfg.CONF.reset)
        # Make sure at each test a new instance of the plugin is returned
        manager.QuantumManager._instance = None
        # Ensure existing ExtensionManager is not used
        extensions.PluginAwareExtensionManager._instance = None
        ext_mgr = TestServiceTypeExtensionManager()
        self.ext_mdw = test_extensions.setup_extensions_middleware(ext_mgr)
        self.api = webtest.TestApp(self.ext_mdw)
        self.resource_name = servicetype.RESOURCE_NAME.replace('-', '_')
        super(ServiceTypeTestCaseBase, self).setUp()


class ServiceTypeExtensionTestCase(ServiceTypeTestCaseBase):

    def setUp(self):
        self._patcher = mock.patch(
            "%s.%s" % (servicetype_db.__name__,
                       servicetype_db.ServiceTypeManager.__name__),
            autospec=True)
        self.addCleanup(self._patcher.stop)
        self.mock_mgr = self._patcher.start()
        self.mock_mgr.get_instance.return_value = self.mock_mgr.return_value
        super(ServiceTypeExtensionTestCase, self).setUp()

    def _test_service_type_create(self, env=None,
                                  expected_status=webexc.HTTPCreated.code):
        tenant_id = 'fake'
        if env and 'quantum.context' in env:
            tenant_id = env['quantum.context'].tenant_id

        data = {self.resource_name:
                {'name': 'test',
                 'tenant_id': tenant_id,
                 'service_definitions':
                 [{'service_class': constants.DUMMY,
                   'plugin': dp.DUMMY_PLUGIN_NAME}]}}
        return_value = data[self.resource_name].copy()
        svc_type_id = _uuid()
        return_value['id'] = svc_type_id

        instance = self.mock_mgr.return_value
        instance.create_service_type.return_value = return_value
        expect_errors = expected_status >= webexc.HTTPBadRequest.code
        res = self.api.post(_get_path('service-types', fmt=self.fmt),
                            self.serialize(data),
                            extra_environ=env,
                            expect_errors=expect_errors,
                            content_type='application/%s' % self.fmt)
        self.assertEqual(res.status_int, expected_status)
        if not expect_errors:
            instance.create_service_type.assert_called_with(mock.ANY,
                                                            service_type=data)
            res = self.deserialize(res)
            self.assertTrue(self.resource_name in res)
            svc_type = res[self.resource_name]
            self.assertEqual(svc_type['id'], svc_type_id)
            # NOTE(salvatore-orlando): The following two checks are
            # probably not essential
            self.assertEqual(svc_type['service_definitions'],
                             data[self.resource_name]['service_definitions'])

    def _test_service_type_update(self, env=None,
                                  expected_status=webexc.HTTPOk.code):
        svc_type_name = 'updated'
        data = {self.resource_name: {'name': svc_type_name}}

        svc_type_id = _uuid()
        return_value = {'id': svc_type_id,
                        'name': svc_type_name}

        instance = self.mock_mgr.return_value
        expect_errors = expected_status >= webexc.HTTPBadRequest.code
        instance.update_service_type.return_value = return_value
        res = self.api.put(_get_path('service-types/%s' % svc_type_id,
                                     fmt=self.fmt),
                           self.serialize(data))
        if not expect_errors:
            instance.update_service_type.assert_called_with(mock.ANY,
                                                            svc_type_id,
                                                            service_type=data)
            self.assertEqual(res.status_int, webexc.HTTPOk.code)
            res = self.deserialize(res)
            self.assertTrue(self.resource_name in res)
            svc_type = res[self.resource_name]
            self.assertEqual(svc_type['id'], svc_type_id)
            self.assertEqual(svc_type['name'],
                             data[self.resource_name]['name'])

    def test_service_type_create(self):
        self._test_service_type_create()

    def test_service_type_update(self):
        self._test_service_type_update()

    def test_service_type_delete(self):
        svctype_id = _uuid()
        instance = self.mock_mgr.return_value
        res = self.api.delete(_get_path('service-types/%s' % svctype_id,
                                        fmt=self.fmt))
        instance.delete_service_type.assert_called_with(mock.ANY,
                                                        svctype_id)
        self.assertEqual(res.status_int, webexc.HTTPNoContent.code)

    def test_service_type_get(self):
        svctype_id = _uuid()
        return_value = {self.resource_name: {'name': 'test',
                                             'service_definitions': [],
                                             'id': svctype_id}}

        instance = self.mock_mgr.return_value
        instance.get_service_type.return_value = return_value

        res = self.api.get(_get_path('service-types/%s' % svctype_id,
                                     fmt=self.fmt))

        instance.get_service_type.assert_called_with(mock.ANY,
                                                     svctype_id,
                                                     fields=mock.ANY)
        self.assertEqual(res.status_int, webexc.HTTPOk.code)

    def test_service_type_list(self):
        svctype_id = _uuid()
        return_value = [{self.resource_name: {'name': 'test',
                                              'service_definitions': [],
                                              'id': svctype_id}}]

        instance = self.mock_mgr.return_value
        instance.get_service_types.return_value = return_value

        res = self.api.get(_get_path('service-types',
                                     fmt=self.fmt))

        instance.get_service_types.assert_called_with(mock.ANY,
                                                      fields=mock.ANY,
                                                      filters=mock.ANY)
        self.assertEqual(res.status_int, webexc.HTTPOk.code)

    def test_create_service_type_nonadminctx_returns_403(self):
        tenant_id = _uuid()
        env = {'quantum.context': context.Context('', tenant_id,
                                                  is_admin=False)}
        self._test_service_type_create(
            env=env, expected_status=webexc.HTTPForbidden.code)

    def test_create_service_type_adminctx_returns_200(self):
        env = {'quantum.context': context.Context('', '', is_admin=True)}
        self._test_service_type_create(env=env)

    def test_update_service_type_nonadminctx_returns_403(self):
        tenant_id = _uuid()
        env = {'quantum.context': context.Context('', tenant_id,
                                                  is_admin=False)}
        self._test_service_type_update(
            env=env, expected_status=webexc.HTTPForbidden.code)

    def test_update_service_type_adminctx_returns_200(self):
        env = {'quantum.context': context.Context('', '', is_admin=True)}
        self._test_service_type_update(env=env)


class ServiceTypeExtensionTestCaseXML(ServiceTypeExtensionTestCase):
    fmt = 'xml'


class ServiceTypeManagerTestCase(ServiceTypeTestCaseBase):

    def setUp(self):
        db_api._ENGINE = None
        db_api._MAKER = None
        # Blank out service type manager instance
        servicetype_db.ServiceTypeManager._instance = None
        plugin_name = "%s.%s" % (dp.__name__, dp.DummyServicePlugin.__name__)
        cfg.CONF.set_override('service_definition', ['dummy:%s' % plugin_name],
                              group='DEFAULT_SERVICETYPE')
        self.addCleanup(db_api.clear_db)
        super(ServiceTypeManagerTestCase, self).setUp()

    @contextlib.contextmanager
    def service_type(self, name='svc_type',
                     default=True,
                     service_defs=None,
                     do_delete=True):
        if not service_defs:
            service_defs = [{'service_class': constants.DUMMY,
                             'plugin': dp.DUMMY_PLUGIN_NAME}]
        res = self._create_service_type(name, service_defs)
        svc_type = self.deserialize(res)
        if res.status_int >= 400:
            raise webexc.HTTPClientError(code=res.status_int)
        yield svc_type

        if do_delete:
            # The do_delete parameter allows you to control whether the
            # created network is immediately deleted again. Therefore, this
            # function is also usable in tests, which require the creation
            # of many networks.
            self._delete_service_type(svc_type[self.resource_name]['id'])

    def _list_service_types(self):
        return self.api.get(_get_path('service-types', fmt=self.fmt))

    def _show_service_type(self, svctype_id, expect_errors=False):
        return self.api.get(_get_path('service-types/%s' % str(svctype_id),
                                      fmt=self.fmt),
                            expect_errors=expect_errors)

    def _create_service_type(self, name, service_defs,
                             default=None, expect_errors=False):
        data = {self.resource_name:
                {'name': name,
                 'service_definitions': service_defs}
                }
        if default:
            data[self.resource_name]['default'] = default
        if 'tenant_id' not in data[self.resource_name]:
            data[self.resource_name]['tenant_id'] = 'fake'
        return self.api.post(_get_path('service-types', fmt=self.fmt),
                             self.serialize(data),
                             expect_errors=expect_errors,
                             content_type='application/%s' % self.fmt)

    def _create_dummy(self, dummyname='dummyobject'):
        data = {'dummy': {'name': dummyname,
                          'tenant_id': 'fake'}}
        dummy_res = self.api.post(_get_path('dummys', fmt=self.fmt),
                                  self.serialize(data),
                                  content_type='application/%s' % self.fmt)
        dummy_res = self.deserialize(dummy_res)
        return dummy_res['dummy']

    def _update_service_type(self, svc_type_id, name, service_defs,
                             default=None, expect_errors=False):
        data = {self.resource_name:
                {'name': name}}
        if service_defs is not None:
            data[self.resource_name]['service_definitions'] = service_defs
        # set this attribute only if True
        if default:
            data[self.resource_name]['default'] = default
        return self.api.put(
            _get_path('service-types/%s' % str(svc_type_id), fmt=self.fmt),
            self.serialize(data),
            expect_errors=expect_errors)

    def _delete_service_type(self, svctype_id, expect_errors=False):
        return self.api.delete(_get_path('service-types/%s' % str(svctype_id),
                                         fmt=self.fmt),
                               expect_errors=expect_errors)

    def _validate_service_type(self, res, name, service_defs,
                               svc_type_id=None):
        res = self.deserialize(res)
        self.assertTrue(self.resource_name in res)
        svc_type = res[self.resource_name]
        if svc_type_id:
            self.assertEqual(svc_type['id'], svc_type_id)
        if name:
            self.assertEqual(svc_type['name'], name)
        if service_defs:
            target_defs = []
            # unspecified drivers will value None in response
            for svc_def in service_defs:
                new_svc_def = svc_def.copy()
                new_svc_def['driver'] = svc_def.get('driver')
                target_defs.append(new_svc_def)
            self.assertEqual(svc_type['service_definitions'],
                             target_defs)
        self.assertEqual(svc_type['default'], False)

    def _test_service_type_create(self, name='test',
                                  service_defs=DEFAULT_SERVICE_DEFS,
                                  default=None,
                                  expected_status=webexc.HTTPCreated.code):
        expect_errors = expected_status >= webexc.HTTPBadRequest.code
        res = self._create_service_type(name, service_defs,
                                        default, expect_errors)
        self.assertEqual(res.status_int, expected_status)
        if not expect_errors:
            self.assertEqual(res.status_int, webexc.HTTPCreated.code)
            self._validate_service_type(res, name, service_defs)

    def _test_service_type_update(self, svc_type_id, name='test-updated',
                                  default=None, service_defs=None,
                                  expected_status=webexc.HTTPOk.code):
        expect_errors = expected_status >= webexc.HTTPBadRequest.code
        res = self._update_service_type(svc_type_id, name, service_defs,
                                        default, expect_errors)
        if not expect_errors:
            self.assertEqual(res.status_int, webexc.HTTPOk.code)
            self._validate_service_type(res, name, service_defs, svc_type_id)

    def test_service_type_create(self):
        self._test_service_type_create()

    def test_create_service_type_default_returns_400(self):
        self._test_service_type_create(
            default=True, expected_status=webexc.HTTPBadRequest.code)

    def test_create_service_type_no_svcdef_returns_400(self):
        self._test_service_type_create(
            service_defs=None,
            expected_status=webexc.HTTPBadRequest.code)

    def test_service_type_update_name(self):
        with self.service_type() as svc_type:
            self._test_service_type_update(svc_type[self.resource_name]['id'])

    def test_service_type_update_set_default_returns_400(self):
        with self.service_type() as svc_type:
            self._test_service_type_update(
                svc_type[self.resource_name]['id'], default=True,
                expected_status=webexc.HTTPBadRequest.code)

    def test_service_type_update_clear_svc_defs_returns_400(self):
        with self.service_type() as svc_type:
            self._test_service_type_update(
                svc_type[self.resource_name]['id'], service_defs=[],
                expected_status=webexc.HTTPBadRequest.code)

    def test_service_type_update_svc_defs(self):
        with self.service_type() as svc_type:
            svc_defs = [{'service': constants.DUMMY,
                         'plugin': 'foobar'}]
            self._test_service_type_update(
                svc_type[self.resource_name]['id'], service_defs=svc_defs,
                expected_status=webexc.HTTPBadRequest.code)

    def test_list_service_types(self):
        with contextlib.nested(self.service_type('st1'),
                               self.service_type('st2')):
            res = self._list_service_types()
            self.assertEqual(res.status_int, webexc.HTTPOk.code)
            data = self.deserialize(res)
            self.assertTrue('service_types' in data)
            # it must be 3 because we have the default service type too!
            self.assertEqual(len(data['service_types']), 3)

    def test_get_default_service_type(self):
        res = self._list_service_types()
        self.assertEqual(res.status_int, webexc.HTTPOk.code)
        data = self.deserialize(res)
        self.assertTrue('service_types' in data)
        self.assertEqual(len(data['service_types']), 1)
        def_svc_type = data['service_types'][0]
        self.assertEqual(def_svc_type['default'], True)

    def test_get_service_type(self):
        with self.service_type() as svc_type:
            svc_type_data = svc_type[self.resource_name]
            res = self._show_service_type(svc_type_data['id'])
            self.assertEqual(res.status_int, webexc.HTTPOk.code)
            self._validate_service_type(res, svc_type_data['name'],
                                        svc_type_data['service_definitions'],
                                        svc_type_data['id'])

    def test_delete_service_type_in_use_returns_409(self):
        with self.service_type() as svc_type:
            svc_type_data = svc_type[self.resource_name]
            mgr = servicetype_db.ServiceTypeManager.get_instance()
            ctx = context.Context('', '', is_admin=True)
            mgr.increase_service_type_refcount(ctx, svc_type_data['id'])
            res = self._delete_service_type(svc_type_data['id'], True)
            self.assertEqual(res.status_int, webexc.HTTPConflict.code)
            mgr.decrease_service_type_refcount(ctx, svc_type_data['id'])

    def test_create_dummy_increases_service_type_refcount(self):
        dummy = self._create_dummy()
        svc_type_res = self._show_service_type(dummy['service_type'])
        svc_type_res = self.deserialize(svc_type_res)
        svc_type = svc_type_res[self.resource_name]
        self.assertEqual(svc_type['num_instances'], 1)

    def test_delete_dummy_decreases_service_type_refcount(self):
        dummy = self._create_dummy()
        svc_type_res = self._show_service_type(dummy['service_type'])
        svc_type_res = self.deserialize(svc_type_res)
        svc_type = svc_type_res[self.resource_name]
        self.assertEqual(svc_type['num_instances'], 1)
        self.api.delete(_get_path('dummys/%s' % str(dummy['id']),
                                  fmt=self.fmt))
        svc_type_res = self._show_service_type(dummy['service_type'])
        svc_type_res = self.deserialize(svc_type_res)
        svc_type = svc_type_res[self.resource_name]
        self.assertEqual(svc_type['num_instances'], 0)


class ServiceTypeManagerTestCaseXML(ServiceTypeManagerTestCase):
    fmt = 'xml'
