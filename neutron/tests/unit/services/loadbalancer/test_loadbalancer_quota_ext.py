# Copyright 2014 OpenStack Foundation.
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

from oslo.config import cfg

from neutron import context
from neutron import quota
from neutron.tests.unit import test_api_v2
from neutron.tests.unit import test_quota_ext

_get_path = test_api_v2._get_path


class LBaaSQuotaExtensionTestCase(
    test_quota_ext.QuotaExtensionTestCase):

    def setUp(self):
        super(LBaaSQuotaExtensionTestCase, self).setUp()
        cfg.CONF.set_override(
            'quota_items',
            ['vip', 'pool', 'member', 'health_monitor', 'extra1'],
            group='QUOTAS')
        quota.register_resources_from_config()


class LBaaSQuotaExtensionDbTestCase(LBaaSQuotaExtensionTestCase):
    fmt = 'json'

    def setUp(self):
        cfg.CONF.set_override(
            'quota_driver',
            'neutron.db.quota_db.DbQuotaDriver',
            group='QUOTAS')
        super(LBaaSQuotaExtensionDbTestCase, self).setUp()

    def test_quotas_loaded_right(self):
        res = self.api.get(_get_path('quotas', fmt=self.fmt))
        quota = self.deserialize(res)
        self.assertEqual([], quota['quotas'])
        self.assertEqual(200, res.status_int)

    def test_quotas_default_values(self):
        tenant_id = 'tenant_id1'
        env = {'neutron.context': context.Context('', tenant_id)}
        res = self.api.get(_get_path('quotas', id=tenant_id, fmt=self.fmt),
                           extra_environ=env)
        quota = self.deserialize(res)
        self.assertEqual(10, quota['quota']['vip'])
        self.assertEqual(10, quota['quota']['pool'])
        self.assertEqual(-1, quota['quota']['member'])
        self.assertEqual(-1, quota['quota']['health_monitor'])
        self.assertEqual(-1, quota['quota']['extra1'])

    def test_show_quotas_with_admin(self):
        tenant_id = 'tenant_id1'
        env = {'neutron.context': context.Context('', tenant_id + '2',
                                                  is_admin=True)}
        res = self.api.get(_get_path('quotas', id=tenant_id, fmt=self.fmt),
                           extra_environ=env)
        self.assertEqual(200, res.status_int)
        quota = self.deserialize(res)
        self.assertEqual(10, quota['quota']['vip'])
        self.assertEqual(10, quota['quota']['pool'])
        self.assertEqual(-1, quota['quota']['member'])
        self.assertEqual(-1, quota['quota']['health_monitor'])

    def test_show_quotas_with_owner_tenant(self):
        tenant_id = 'tenant_id1'
        env = {'neutron.context': context.Context('', tenant_id,
                                                  is_admin=False)}
        res = self.api.get(_get_path('quotas', id=tenant_id, fmt=self.fmt),
                           extra_environ=env)
        self.assertEqual(200, res.status_int)
        quota = self.deserialize(res)
        self.assertEqual(10, quota['quota']['vip'])
        self.assertEqual(10, quota['quota']['pool'])
        self.assertEqual(-1, quota['quota']['member'])
        self.assertEqual(-1, quota['quota']['health_monitor'])

    def test_update_quotas_to_unlimited(self):
        tenant_id = 'tenant_id1'
        env = {'neutron.context': context.Context('', tenant_id,
                                                  is_admin=True)}
        quotas = {'quota': {'pool': -1}}
        res = self.api.put(_get_path('quotas', id=tenant_id, fmt=self.fmt),
                           self.serialize(quotas), extra_environ=env,
                           expect_errors=False)
        self.assertEqual(200, res.status_int)

    def test_update_quotas_exceeding_current_limit(self):
        tenant_id = 'tenant_id1'
        env = {'neutron.context': context.Context('', tenant_id,
                                                  is_admin=True)}
        quotas = {'quota': {'pool': 120}}
        res = self.api.put(_get_path('quotas', id=tenant_id, fmt=self.fmt),
                           self.serialize(quotas), extra_environ=env,
                           expect_errors=False)
        self.assertEqual(200, res.status_int)

    def test_update_quotas_with_admin(self):
        tenant_id = 'tenant_id1'
        env = {'neutron.context': context.Context('', tenant_id + '2',
                                                  is_admin=True)}
        quotas = {'quota': {'pool': 100}}
        res = self.api.put(_get_path('quotas', id=tenant_id, fmt=self.fmt),
                           self.serialize(quotas), extra_environ=env)
        self.assertEqual(200, res.status_int)
        env2 = {'neutron.context': context.Context('', tenant_id)}
        res = self.api.get(_get_path('quotas', id=tenant_id, fmt=self.fmt),
                           extra_environ=env2)
        quota = self.deserialize(res)
        self.assertEqual(10, quota['quota']['vip'])
        self.assertEqual(100, quota['quota']['pool'])
        self.assertEqual(-1, quota['quota']['member'])
        self.assertEqual(-1, quota['quota']['health_monitor'])


class LBaaSQuotaExtensionDbTestCaseXML(LBaaSQuotaExtensionDbTestCase):
    fmt = 'xml'


class LBaaSQuotaExtensionCfgTestCase(
    LBaaSQuotaExtensionTestCase):

    def setUp(self):
        cfg.CONF.set_override(
            'quota_driver',
            'neutron.quota.ConfDriver',
            group='QUOTAS')
        super(LBaaSQuotaExtensionCfgTestCase, self).setUp()

    def test_quotas_default_values(self):
        tenant_id = 'tenant_id1'
        env = {'neutron.context': context.Context('', tenant_id)}
        res = self.api.get(_get_path('quotas', id=tenant_id, fmt=self.fmt),
                           extra_environ=env)
        quota = self.deserialize(res)
        self.assertEqual(10, quota['quota']['vip'])
        self.assertEqual(10, quota['quota']['pool'])
        self.assertEqual(-1, quota['quota']['member'])
        self.assertEqual(-1, quota['quota']['health_monitor'])
        self.assertEqual(-1, quota['quota']['extra1'])

    def test_update_quotas_forbidden(self):
        tenant_id = 'tenant_id1'
        quotas = {'quota': {'pool': 100}}
        res = self.api.put(_get_path('quotas', id=tenant_id, fmt=self.fmt),
                           self.serialize(quotas),
                           expect_errors=True)
        self.assertEqual(403, res.status_int)


class LBaaSQuotaExtensionCfgTestCaseXML(LBaaSQuotaExtensionCfgTestCase):
    fmt = 'xml'
