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

from oslo_config import cfg

from neutron.common import exceptions as n_exc
from neutron import manager
from neutron.plugins.common import constants
from neutron.services import provider_configuration as provconf
from neutron.tests import base


class ParseServiceProviderConfigurationTestCase(base.BaseTestCase):
    def test_default_service_provider_configuration(self):
        providers = cfg.CONF.service_providers.service_provider
        self.assertEqual(providers, [])

    def test_parse_single_service_provider_opt(self):
        cfg.CONF.set_override('service_provider',
                              [constants.LOADBALANCER +
                               ':lbaas:driver_path'],
                              'service_providers')
        expected = {'service_type': constants.LOADBALANCER,
                    'name': 'lbaas',
                    'driver': 'driver_path',
                    'default': False}
        res = provconf.parse_service_provider_opt()
        self.assertEqual(len(res), 1)
        self.assertEqual(res, [expected])

    def test_parse_single_default_service_provider_opt(self):
        cfg.CONF.set_override('service_provider',
                              [constants.LOADBALANCER +
                               ':lbaas:driver_path:default'],
                              'service_providers')
        expected = {'service_type': constants.LOADBALANCER,
                    'name': 'lbaas',
                    'driver': 'driver_path',
                    'default': True}
        res = provconf.parse_service_provider_opt()
        self.assertEqual(len(res), 1)
        self.assertEqual(res, [expected])

    def test_parse_multi_service_provider_opt(self):
        cfg.CONF.set_override('service_provider',
                              [constants.LOADBALANCER +
                               ':lbaas:driver_path',
                               constants.LOADBALANCER + ':name1:path1',
                               constants.LOADBALANCER +
                               ':name2:path2:default'],
                              'service_providers')
        res = provconf.parse_service_provider_opt()
        # This parsing crosses repos if additional projects are installed,
        # so check that at least what we expect is there; there may be more.
        self.assertTrue(len(res) >= 3)

    def test_parse_service_provider_opt_not_allowed_raises(self):
        cfg.CONF.set_override('service_provider',
                              [constants.LOADBALANCER +
                               ':lbaas:driver_path',
                               'svc_type:name1:path1'],
                              'service_providers')
        self.assertRaises(n_exc.Invalid, provconf.parse_service_provider_opt)

    def test_parse_service_provider_invalid_format(self):
        cfg.CONF.set_override('service_provider',
                              [constants.LOADBALANCER +
                               ':lbaas:driver_path',
                               'svc_type:name1:path1:def'],
                              'service_providers')
        self.assertRaises(n_exc.Invalid, provconf.parse_service_provider_opt)
        cfg.CONF.set_override('service_provider',
                              [constants.LOADBALANCER +
                               ':',
                               'svc_type:name1:path1:def'],
                              'service_providers')
        self.assertRaises(n_exc.Invalid, provconf.parse_service_provider_opt)

    def test_parse_service_provider_name_too_long(self):
        name = 'a' * 256
        cfg.CONF.set_override('service_provider',
                              [constants.LOADBALANCER +
                               ':' + name + ':driver_path',
                               'svc_type:name1:path1:def'],
                              'service_providers')
        self.assertRaises(n_exc.Invalid, provconf.parse_service_provider_opt)


class ProviderConfigurationTestCase(base.BaseTestCase):
    def setUp(self):
        super(ProviderConfigurationTestCase, self).setUp()

    def test_ensure_driver_unique(self):
        pconf = provconf.ProviderConfiguration([])
        pconf.providers[('svctype', 'name')] = {'driver': 'driver',
                                                'default': True}
        self.assertRaises(n_exc.Invalid,
                          pconf._ensure_driver_unique, 'driver')
        self.assertIsNone(pconf._ensure_driver_unique('another_driver1'))

    def test_ensure_default_unique(self):
        pconf = provconf.ProviderConfiguration([])
        pconf.providers[('svctype', 'name')] = {'driver': 'driver',
                                                'default': True}
        self.assertRaises(n_exc.Invalid,
                          pconf._ensure_default_unique,
                          'svctype', True)
        self.assertIsNone(pconf._ensure_default_unique('svctype', False))
        self.assertIsNone(pconf._ensure_default_unique('svctype1', True))
        self.assertIsNone(pconf._ensure_default_unique('svctype1', False))

    def test_add_provider(self):
        pconf = provconf.ProviderConfiguration([])
        prov = {'service_type': constants.LOADBALANCER,
                'name': 'name',
                'driver': 'path',
                'default': False}
        pconf.add_provider(prov)
        self.assertEqual(len(pconf.providers), 1)
        self.assertEqual(pconf.providers.keys(),
                         [(constants.LOADBALANCER, 'name')])
        self.assertEqual(pconf.providers.values(),
                         [{'driver': 'path', 'default': False}])

    def test_add_duplicate_provider(self):
        pconf = provconf.ProviderConfiguration([])
        prov = {'service_type': constants.LOADBALANCER,
                'name': 'name',
                'driver': 'path',
                'default': False}
        pconf.add_provider(prov)
        self.assertRaises(n_exc.Invalid, pconf.add_provider, prov)
        self.assertEqual(len(pconf.providers), 1)

    def test_get_service_providers(self):
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
        pconf = provconf.ProviderConfiguration(provs)
        for prov in provs:
            p = pconf.get_service_providers(
                filters={'name': [prov['name']],
                         'service_type': prov['service_type']}
            )
            self.assertEqual(p, [prov])

    def test_get_service_providers_with_fields(self):
        provs = [{'service_type': constants.LOADBALANCER,
                  'name': 'name',
                  'driver': 'path',
                  'default': False},
                 {'service_type': constants.LOADBALANCER,
                  'name': 'name2',
                  'driver': 'path2',
                  'default': False}]
        pconf = provconf.ProviderConfiguration(provs)
        for prov in provs:
            p = pconf.get_service_providers(
                filters={'name': [prov['name']],
                         'service_type': prov['service_type']},
                fields=['name']
            )
            self.assertEqual(p, [{'name': prov['name']}])


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
