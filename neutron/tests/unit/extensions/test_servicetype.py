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

import mock
from oslo_config import cfg
import webob.exc as webexc
import webtest

from neutron.api import extensions
from neutron.common import exceptions as n_exc
from neutron import context
from neutron.db import servicetype_db as st_db
from neutron.extensions import servicetype
from neutron.plugins.common import constants
from neutron.services import provider_configuration as provconf
from neutron.tests.unit.api import test_extensions
from neutron.tests.unit.api.v2 import test_base
from neutron.tests.unit.db import test_db_base_plugin_v2
from neutron.tests.unit import dummy_plugin as dp
from neutron.tests.unit import testlib_api


_uuid = test_base._uuid
_get_path = test_base._get_path


class ServiceTypeManagerTestCase(testlib_api.SqlTestCase):
    def setUp(self):
        self.service_providers = mock.patch.object(
            provconf.NeutronModule, 'service_providers').start()
        super(ServiceTypeManagerTestCase, self).setUp()
        self.ctx = context.get_admin_context()

    def _set_override(self, service_providers):
        self.service_providers.return_value = service_providers
        st_db.ServiceTypeManager._instance = None
        self.manager = st_db.ServiceTypeManager.get_instance()
        for provider in service_providers:
            self.manager.add_provider_configuration(
                provider.split(':')[0], provconf.ProviderConfiguration())

    def test_service_provider_driver_not_unique(self):
        self._set_override([constants.LOADBALANCER + ':lbaas:driver'])
        prov = {'service_type': constants.LOADBALANCER,
                'name': 'name2',
                'driver': 'driver',
                'default': False}
        self.assertRaises(
            n_exc.Invalid,
            self.manager.config['LOADBALANCER'].add_provider, prov)

    def test_get_service_providers(self):
        """Test that get_service_providers filters correctly."""
        self._set_override(
            [constants.LOADBALANCER +
             ':lbaas:driver_path1',
             constants.FIREWALL +
             ':fwaas:driver_path2'])
        ctx = context.get_admin_context()
        res = self.manager.get_service_providers(
            ctx,
            filters=dict(service_type=[constants.LOADBALANCER])
        )
        self.assertEqual(len(res), 1)

        res = self.manager.get_service_providers(
            ctx,
            filters=dict(service_type=[constants.FIREWALL])
        )
        self.assertEqual(len(res), 1)

    def test_multiple_default_providers_specified_for_service(self):
        self.assertRaises(
            n_exc.Invalid,
            self._set_override,
            [constants.LOADBALANCER +
            ':lbaas1:driver_path:default',
            constants.LOADBALANCER +
            ':lbaas2:driver_path:default'])

    def test_get_default_provider(self):
        self._set_override([constants.LOADBALANCER +
                            ':lbaas1:driver_path:default',
                            constants.DUMMY +
                            ':lbaas2:driver_path2'])
        # can pass None as a context
        p = self.manager.get_default_service_provider(None,
                                                      constants.LOADBALANCER)
        self.assertEqual(p, {'service_type': constants.LOADBALANCER,
                             'name': 'lbaas1',
                             'driver': 'driver_path',
                             'default': True})

        self.assertRaises(
            provconf.DefaultServiceProviderNotFound,
            self.manager.get_default_service_provider,
            None, constants.DUMMY
        )

    def test_add_resource_association(self):
        self._set_override([constants.LOADBALANCER +
                            ':lbaas1:driver_path:default',
                            constants.DUMMY +
                            ':lbaas2:driver_path2'])
        ctx = context.get_admin_context()
        self.manager.add_resource_association(ctx,
                                              constants.LOADBALANCER,
                                              'lbaas1', '123-123')
        self.assertEqual(ctx.session.
                         query(st_db.ProviderResourceAssociation).count(),
                         1)
        assoc = ctx.session.query(st_db.ProviderResourceAssociation).one()
        ctx.session.delete(assoc)

    def test_invalid_resource_association(self):
        self._set_override([constants.LOADBALANCER +
                            ':lbaas1:driver_path:default',
                            constants.DUMMY +
                            ':lbaas2:driver_path2'])
        ctx = context.get_admin_context()
        self.assertRaises(provconf.ServiceProviderNotFound,
                          self.manager.add_resource_association,
                          ctx, 'BLABLA_svc', 'name', '123-123')


class TestServiceTypeExtensionManager(object):
    """Mock extensions manager."""
    def get_resources(self):
        return (servicetype.Servicetype.get_resources() +
                dp.Dummy.get_resources())

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


class ServiceTypeExtensionTestCaseBase(testlib_api.WebTestCase):
    fmt = 'json'

    def setUp(self):
        # This is needed because otherwise a failure will occur due to
        # nonexisting core_plugin
        self.setup_coreplugin(test_db_base_plugin_v2.DB_PLUGIN_KLASS)

        cfg.CONF.set_override('service_plugins',
                              ["%s.%s" % (dp.__name__,
                                          dp.DummyServicePlugin.__name__)])
        # Ensure existing ExtensionManager is not used
        extensions.PluginAwareExtensionManager._instance = None
        ext_mgr = TestServiceTypeExtensionManager()
        self.ext_mdw = test_extensions.setup_extensions_middleware(ext_mgr)
        self.api = webtest.TestApp(self.ext_mdw)
        self.resource_name = servicetype.RESOURCE_NAME.replace('-', '_')
        super(ServiceTypeExtensionTestCaseBase, self).setUp()


class ServiceTypeExtensionTestCase(ServiceTypeExtensionTestCaseBase):

    def setUp(self):
        self._patcher = mock.patch(
            "neutron.db.servicetype_db.ServiceTypeManager",
            autospec=True)
        self.mock_mgr = self._patcher.start()
        self.mock_mgr.get_instance.return_value = self.mock_mgr.return_value
        super(ServiceTypeExtensionTestCase, self).setUp()

    def test_service_provider_list(self):
        instance = self.mock_mgr.return_value

        res = self.api.get(_get_path('service-providers', fmt=self.fmt))

        instance.get_service_providers.assert_called_with(mock.ANY,
                                                          filters={},
                                                          fields=[])
        self.assertEqual(res.status_int, webexc.HTTPOk.code)


class ServiceTypeManagerExtTestCase(ServiceTypeExtensionTestCaseBase):
    """Tests ServiceTypemanager as a public API."""
    def setUp(self):
        self.service_providers = mock.patch.object(
            provconf.NeutronModule, 'service_providers').start()
        service_providers = [
            constants.LOADBALANCER + ':lbaas:driver_path',
            constants.DUMMY + ':dummy:dummy_dr'
        ]
        self.service_providers.return_value = service_providers
        # Blank out service type manager instance
        st_db.ServiceTypeManager._instance = None
        self.manager = st_db.ServiceTypeManager.get_instance()
        for provider in service_providers:
            self.manager.add_provider_configuration(
                provider.split(':')[0], provconf.ProviderConfiguration())
        super(ServiceTypeManagerExtTestCase, self).setUp()

    def _list_service_providers(self):
        return self.api.get(_get_path('service-providers', fmt=self.fmt))

    def test_list_service_providers(self):
        res = self._list_service_providers()
        self.assertEqual(res.status_int, webexc.HTTPOk.code)
        data = self.deserialize(res)
        self.assertIn('service_providers', data)
        self.assertGreaterEqual(len(data['service_providers']), 2)
