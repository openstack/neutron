# Copyright 2013 VMware, Inc. All Rights Reserved.
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

import os
import shutil

import mock
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import constants
from oslo_config import cfg

from neutron import manager
from neutron.services import provider_configuration as provconf
from neutron.tests import base


class ParseServiceProviderConfigurationTestCase(base.BaseTestCase):

    def setUp(self):
        super(ParseServiceProviderConfigurationTestCase, self).setUp()
        self.service_providers = mock.patch.object(
            provconf.NeutronModule, 'service_providers').start()

    def _set_override(self, service_providers):
        self.service_providers.return_value = service_providers

    def test_default_service_provider_configuration(self):
        providers = cfg.CONF.service_providers.service_provider
        self.assertEqual([], providers)

    def test_parse_single_service_provider_opt(self):
        self._set_override([constants.LOADBALANCER +
                           ':lbaas:driver_path'])
        expected = {'service_type': constants.LOADBALANCER,
                    'name': 'lbaas',
                    'driver': 'driver_path',
                    'default': False}
        res = provconf.parse_service_provider_opt()
        self.assertEqual(1, len(res))
        self.assertEqual([expected], res)

    def test_parse_single_default_service_provider_opt(self):
        self._set_override([constants.LOADBALANCER +
                           ':lbaas:driver_path:default'])
        expected = {'service_type': constants.LOADBALANCER,
                    'name': 'lbaas',
                    'driver': 'driver_path',
                    'default': True}
        res = provconf.parse_service_provider_opt()
        self.assertEqual(1, len(res))
        self.assertEqual([expected], res)

    def test_parse_multi_service_provider_opt(self):
        self._set_override([constants.LOADBALANCER +
                            ':lbaas:driver_path',
                            constants.LOADBALANCER + ':name1:path1',
                            constants.LOADBALANCER +
                            ':name2:path2:default'])
        res = provconf.parse_service_provider_opt()
        # This parsing crosses repos if additional projects are installed,
        # so check that at least what we expect is there; there may be more.
        self.assertGreaterEqual(len(res), 3)

    def test_parse_service_provider_invalid_format(self):
        self._set_override([constants.LOADBALANCER +
                           ':lbaas:driver_path',
                           'svc_type:name1:path1:def'])
        self.assertRaises(n_exc.Invalid, provconf.parse_service_provider_opt)
        self._set_override([constants.LOADBALANCER +
                           ':',
                           'svc_type:name1:path1:def'])
        self.assertRaises(n_exc.Invalid, provconf.parse_service_provider_opt)

    def test_parse_service_provider_name_too_long(self):
        name = 'a' * 256
        self._set_override([constants.LOADBALANCER +
                           ':' + name + ':driver_path',
                           'svc_type:name1:path1:def'])
        self.assertRaises(n_exc.Invalid, provconf.parse_service_provider_opt)


class ProviderConfigurationTestCase(base.BaseTestCase):

    def setUp(self):
        super(ProviderConfigurationTestCase, self).setUp()
        self.service_providers = mock.patch.object(
            provconf.NeutronModule, 'service_providers').start()

    def _set_override(self, service_providers):
        self.service_providers.return_value = service_providers

    def test_ensure_driver_unique(self):
        pconf = provconf.ProviderConfiguration()
        pconf.providers[('svctype', 'name')] = {'driver': 'driver',
                                                'default': True}
        self.assertRaises(n_exc.Invalid,
                          pconf._ensure_driver_unique, 'driver')
        self.assertIsNone(pconf._ensure_driver_unique('another_driver1'))

    def test_ensure_default_unique(self):
        pconf = provconf.ProviderConfiguration()
        pconf.providers[('svctype', 'name')] = {'driver': 'driver',
                                                'default': True}
        self.assertRaises(n_exc.Invalid,
                          pconf._ensure_default_unique,
                          'svctype', True)
        self.assertIsNone(pconf._ensure_default_unique('svctype', False))
        self.assertIsNone(pconf._ensure_default_unique('svctype1', True))
        self.assertIsNone(pconf._ensure_default_unique('svctype1', False))

    def test_add_provider(self):
        pconf = provconf.ProviderConfiguration()
        prov = {'service_type': constants.LOADBALANCER,
                'name': 'name',
                'driver': 'path',
                'default': False}
        pconf.add_provider(prov)
        self.assertEqual(1, len(pconf.providers))
        self.assertEqual([(constants.LOADBALANCER, 'name')],
                         list(pconf.providers.keys()))
        self.assertEqual([{'driver': 'path', 'default': False}],
                         list(pconf.providers.values()))

    def test_add_duplicate_provider(self):
        pconf = provconf.ProviderConfiguration()
        prov = {'service_type': constants.LOADBALANCER,
                'name': 'name',
                'driver': 'path',
                'default': False}
        pconf.add_provider(prov)
        self.assertRaises(n_exc.Invalid, pconf.add_provider, prov)
        self.assertEqual(1, len(pconf.providers))

    def test_get_service_providers(self):
        self._set_override([constants.LOADBALANCER + ':name:path',
                            constants.LOADBALANCER + ':name2:path2',
                            'st2:name:driver:default',
                            'st3:name2:driver2:default'])
        provs = [{'service_type': constants.LOADBALANCER,
                  'name': 'name',
                  'driver': 'path',
                  'default': False},
                 {'service_type': constants.LOADBALANCER,
                  'name': 'name2',
                  'driver': 'path2',
                  'default': False},
                 {'service_type': 'st2',
                  'name': 'name',
                  'driver': 'driver',
                  'default': True
                  },
                 {'service_type': 'st3',
                  'name': 'name2',
                  'driver': 'driver2',
                  'default': True}]
        pconf = provconf.ProviderConfiguration()
        for prov in provs:
            p = pconf.get_service_providers(
                filters={'name': [prov['name']],
                         'service_type': prov['service_type']}
            )
            self.assertEqual([prov], p)

    def test_get_service_providers_with_fields(self):
        self._set_override([constants.LOADBALANCER + ":name:path",
                            constants.LOADBALANCER + ":name2:path2"])
        provs = [{'service_type': constants.LOADBALANCER,
                  'name': 'name',
                  'driver': 'path',
                  'default': False},
                 {'service_type': constants.LOADBALANCER,
                  'name': 'name2',
                  'driver': 'path2',
                  'default': False}]
        pconf = provconf.ProviderConfiguration()
        for prov in provs:
            p = pconf.get_service_providers(
                filters={'name': [prov['name']],
                         'service_type': prov['service_type']},
                fields=['name']
            )
            self.assertEqual([{'name': prov['name']}], p)


class GetProviderDriverClassTestCase(base.BaseTestCase):
    def test_get_provider_driver_class_hit(self):
        driver = 'ml2'
        expected = 'neutron.plugins.ml2.plugin.Ml2Plugin'
        actual = provconf.get_provider_driver_class(
            driver,
            namespace=manager.CORE_PLUGINS_NAMESPACE)
        self.assertEqual(expected, actual)

    def test_get_provider_driver_class_miss(self):
        retval = provconf.get_provider_driver_class('foo')
        self.assertEqual('foo', retval)


class NeutronModuleTestCase(base.BaseTestCase):

    def test_can_parse_multi_opt_service_provider_from_conf_file(self):
        mod = provconf.NeutronModule('neutron_test')
        mod.ini(base.ETCDIR)
        self.assertEqual(['foo', 'bar'], mod.service_providers(),
                         'Expected two providers, only one read')


class NeutronModuleConfigDirTestCase(base.BaseTestCase):

    def setup_config(self):
        self.config_parse(args=['--config-dir', base.ETCDIR])

    def test_can_parse_multi_opt_service_provider_from_conf_dir(self):
        mod = provconf.NeutronModule('neutron_test')
        mod.ini()
        self.assertEqual(['foo', 'bar'], mod.service_providers())


class NeutronModuleMultiConfigDirTestCase(base.BaseTestCase):

    def setUp(self):
        self.tmpdir = self.get_default_temp_dir().path
        shutil.copyfile(
            os.path.join(base.ETCDIR, 'neutron_test2.conf.example'),
            os.path.join(self.tmpdir, 'neutron_test.conf'))
        super(NeutronModuleMultiConfigDirTestCase, self).setUp()

    def setup_config(self):
        self.config_parse(args=[
            # NOTE(ihrachys): we expect the second directory to be checked
            '--config-dir', self.tmpdir, '--config-dir', base.ETCDIR
        ])

    def test_read_configuration_from_all_matching_files(self):
        mod = provconf.NeutronModule('neutron_test')
        mod.ini()
        self.assertEqual(['zzz', 'foo', 'bar'], mod.service_providers())


class NeutronModuleMultiConfigFileTestCase(base.BaseTestCase):

    def setUp(self):
        self.tmpdir = self.get_default_temp_dir().path
        self.filepath1 = os.path.join(self.tmpdir, 'neutron_test.conf')
        self.filepath2 = os.path.join(base.ETCDIR, 'neutron_test.conf')
        shutil.copyfile(
            os.path.join(base.ETCDIR, 'neutron_test2.conf.example'),
            self.filepath1)
        super(NeutronModuleMultiConfigFileTestCase, self).setUp()

    def setup_config(self):
        self.config_parse(args=[
            # NOTE(ihrachys): we expect both directories to be checked
            '--config-file', self.filepath1, '--config-file', self.filepath2
        ])

    def test_read_configuration_from_all_matching_files(self):
        mod = provconf.NeutronModule('neutron_test')
        mod.ini()
        self.assertEqual(['zzz', 'foo', 'bar'], mod.service_providers())


class NeutronModuleConfigNotParsedTestCase(base.DietTestCase):

    def setup_config(self):
        pass

    def test_ini_no_crash_if_config_files_not_parsed(self):
        mod = provconf.NeutronModule('neutron_test')
        mod.ini()
