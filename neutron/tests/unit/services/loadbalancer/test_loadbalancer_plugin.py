# Copyright 2012 OpenStack Foundation.
# All Rights Reserved.
#
#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.

import copy

import mock
from webob import exc

from neutron.api.v2 import attributes as attr
from neutron.extensions import loadbalancer
from neutron.openstack.common import uuidutils
from neutron.plugins.common import constants
from neutron.tests.unit import test_api_v2
from neutron.tests.unit import test_api_v2_extension


_uuid = uuidutils.generate_uuid
_get_path = test_api_v2._get_path


class LoadBalancerExtensionTestCase(test_api_v2_extension.ExtensionTestCase):
    fmt = 'json'

    def setUp(self):
        super(LoadBalancerExtensionTestCase, self).setUp()
        self._setUpExtension(
            'neutron.extensions.loadbalancer.LoadBalancerPluginBase',
            constants.LOADBALANCER, loadbalancer.RESOURCE_ATTRIBUTE_MAP,
            loadbalancer.Loadbalancer, 'lb', use_quota=True)

    def test_vip_create(self):
        vip_id = _uuid()
        data = {'vip': {'name': 'vip1',
                        'description': 'descr_vip1',
                        'subnet_id': _uuid(),
                        'address': '127.0.0.1',
                        'protocol_port': 80,
                        'protocol': 'HTTP',
                        'pool_id': _uuid(),
                        'session_persistence': {'type': 'HTTP_COOKIE'},
                        'connection_limit': 100,
                        'admin_state_up': True,
                        'tenant_id': _uuid()}}
        return_value = copy.copy(data['vip'])
        return_value.update({'status': "ACTIVE", 'id': vip_id})

        instance = self.plugin.return_value
        instance.create_vip.return_value = return_value
        res = self.api.post(_get_path('lb/vips', fmt=self.fmt),
                            self.serialize(data),
                            content_type='application/%s' % self.fmt)
        instance.create_vip.assert_called_with(mock.ANY,
                                               vip=data)
        self.assertEqual(res.status_int, exc.HTTPCreated.code)
        res = self.deserialize(res)
        self.assertIn('vip', res)
        self.assertEqual(res['vip'], return_value)

    def test_vip_list(self):
        vip_id = _uuid()
        return_value = [{'name': 'vip1',
                         'admin_state_up': True,
                         'tenant_id': _uuid(),
                         'id': vip_id}]

        instance = self.plugin.return_value
        instance.get_vips.return_value = return_value

        res = self.api.get(_get_path('lb/vips', fmt=self.fmt))

        instance.get_vips.assert_called_with(mock.ANY, fields=mock.ANY,
                                             filters=mock.ANY)
        self.assertEqual(res.status_int, exc.HTTPOk.code)

    def test_vip_update(self):
        vip_id = _uuid()
        update_data = {'vip': {'admin_state_up': False}}
        return_value = {'name': 'vip1',
                        'admin_state_up': False,
                        'tenant_id': _uuid(),
                        'status': "ACTIVE",
                        'id': vip_id}

        instance = self.plugin.return_value
        instance.update_vip.return_value = return_value

        res = self.api.put(_get_path('lb/vips', id=vip_id, fmt=self.fmt),
                           self.serialize(update_data))

        instance.update_vip.assert_called_with(mock.ANY, vip_id,
                                               vip=update_data)
        self.assertEqual(res.status_int, exc.HTTPOk.code)
        res = self.deserialize(res)
        self.assertIn('vip', res)
        self.assertEqual(res['vip'], return_value)

    def test_vip_get(self):
        vip_id = _uuid()
        return_value = {'name': 'vip1',
                        'admin_state_up': False,
                        'tenant_id': _uuid(),
                        'status': "ACTIVE",
                        'id': vip_id}

        instance = self.plugin.return_value
        instance.get_vip.return_value = return_value

        res = self.api.get(_get_path('lb/vips', id=vip_id, fmt=self.fmt))

        instance.get_vip.assert_called_with(mock.ANY, vip_id,
                                            fields=mock.ANY)
        self.assertEqual(res.status_int, exc.HTTPOk.code)
        res = self.deserialize(res)
        self.assertIn('vip', res)
        self.assertEqual(res['vip'], return_value)

    def test_vip_delete(self):
        self._test_entity_delete('vip')

    def test_pool_create(self):
        pool_id = _uuid()
        hm_id = _uuid()
        data = {'pool': {'name': 'pool1',
                         'description': 'descr_pool1',
                         'subnet_id': _uuid(),
                         'protocol': 'HTTP',
                         'lb_method': 'ROUND_ROBIN',
                         'health_monitors': [hm_id],
                         'admin_state_up': True,
                         'tenant_id': _uuid()}}
        return_value = copy.copy(data['pool'])
        return_value['provider'] = 'lbaas'
        return_value.update({'status': "ACTIVE", 'id': pool_id})

        instance = self.plugin.return_value
        instance.create_pool.return_value = return_value
        res = self.api.post(_get_path('lb/pools', fmt=self.fmt),
                            self.serialize(data),
                            content_type='application/%s' % self.fmt)
        data['pool']['provider'] = attr.ATTR_NOT_SPECIFIED
        instance.create_pool.assert_called_with(mock.ANY,
                                                pool=data)
        self.assertEqual(res.status_int, exc.HTTPCreated.code)
        res = self.deserialize(res)
        self.assertIn('pool', res)
        self.assertEqual(res['pool'], return_value)

    def test_pool_list(self):
        pool_id = _uuid()
        return_value = [{'name': 'pool1',
                         'admin_state_up': True,
                         'tenant_id': _uuid(),
                         'id': pool_id}]

        instance = self.plugin.return_value
        instance.get_pools.return_value = return_value

        res = self.api.get(_get_path('lb/pools', fmt=self.fmt))

        instance.get_pools.assert_called_with(mock.ANY, fields=mock.ANY,
                                              filters=mock.ANY)
        self.assertEqual(res.status_int, exc.HTTPOk.code)

    def test_pool_update(self):
        pool_id = _uuid()
        update_data = {'pool': {'admin_state_up': False}}
        return_value = {'name': 'pool1',
                        'admin_state_up': False,
                        'tenant_id': _uuid(),
                        'status': "ACTIVE",
                        'id': pool_id}

        instance = self.plugin.return_value
        instance.update_pool.return_value = return_value

        res = self.api.put(_get_path('lb/pools', id=pool_id, fmt=self.fmt),
                           self.serialize(update_data))

        instance.update_pool.assert_called_with(mock.ANY, pool_id,
                                                pool=update_data)
        self.assertEqual(res.status_int, exc.HTTPOk.code)
        res = self.deserialize(res)
        self.assertIn('pool', res)
        self.assertEqual(res['pool'], return_value)

    def test_pool_get(self):
        pool_id = _uuid()
        return_value = {'name': 'pool1',
                        'admin_state_up': False,
                        'tenant_id': _uuid(),
                        'status': "ACTIVE",
                        'id': pool_id}

        instance = self.plugin.return_value
        instance.get_pool.return_value = return_value

        res = self.api.get(_get_path('lb/pools', id=pool_id, fmt=self.fmt))

        instance.get_pool.assert_called_with(mock.ANY, pool_id,
                                             fields=mock.ANY)
        self.assertEqual(res.status_int, exc.HTTPOk.code)
        res = self.deserialize(res)
        self.assertIn('pool', res)
        self.assertEqual(res['pool'], return_value)

    def test_pool_delete(self):
        self._test_entity_delete('pool')

    def test_pool_stats(self):
        pool_id = _uuid()

        stats = {'stats': 'dummy'}
        instance = self.plugin.return_value
        instance.stats.return_value = stats

        path = _get_path('lb/pools', id=pool_id,
                         action="stats", fmt=self.fmt)
        res = self.api.get(path)

        instance.stats.assert_called_with(mock.ANY, pool_id)
        self.assertEqual(res.status_int, exc.HTTPOk.code)
        res = self.deserialize(res)
        self.assertIn('stats', res)
        self.assertEqual(res['stats'], stats['stats'])

    def test_member_create(self):
        member_id = _uuid()
        data = {'member': {'pool_id': _uuid(),
                           'address': '127.0.0.1',
                           'protocol_port': 80,
                           'weight': 1,
                           'admin_state_up': True,
                           'tenant_id': _uuid()}}
        return_value = copy.copy(data['member'])
        return_value.update({'status': "ACTIVE", 'id': member_id})

        instance = self.plugin.return_value
        instance.create_member.return_value = return_value
        res = self.api.post(_get_path('lb/members', fmt=self.fmt),
                            self.serialize(data),
                            content_type='application/%s' % self.fmt)
        instance.create_member.assert_called_with(mock.ANY,
                                                  member=data)
        self.assertEqual(res.status_int, exc.HTTPCreated.code)
        res = self.deserialize(res)
        self.assertIn('member', res)
        self.assertEqual(res['member'], return_value)

    def test_member_list(self):
        member_id = _uuid()
        return_value = [{'name': 'member1',
                         'admin_state_up': True,
                         'tenant_id': _uuid(),
                         'id': member_id}]

        instance = self.plugin.return_value
        instance.get_members.return_value = return_value

        res = self.api.get(_get_path('lb/members', fmt=self.fmt))

        instance.get_members.assert_called_with(mock.ANY, fields=mock.ANY,
                                                filters=mock.ANY)
        self.assertEqual(res.status_int, exc.HTTPOk.code)

    def test_member_update(self):
        member_id = _uuid()
        update_data = {'member': {'admin_state_up': False}}
        return_value = {'admin_state_up': False,
                        'tenant_id': _uuid(),
                        'status': "ACTIVE",
                        'id': member_id}

        instance = self.plugin.return_value
        instance.update_member.return_value = return_value

        res = self.api.put(_get_path('lb/members', id=member_id,
                                     fmt=self.fmt),
                           self.serialize(update_data))

        instance.update_member.assert_called_with(mock.ANY, member_id,
                                                  member=update_data)
        self.assertEqual(res.status_int, exc.HTTPOk.code)
        res = self.deserialize(res)
        self.assertIn('member', res)
        self.assertEqual(res['member'], return_value)

    def test_member_get(self):
        member_id = _uuid()
        return_value = {'admin_state_up': False,
                        'tenant_id': _uuid(),
                        'status': "ACTIVE",
                        'id': member_id}

        instance = self.plugin.return_value
        instance.get_member.return_value = return_value

        res = self.api.get(_get_path('lb/members', id=member_id,
                                     fmt=self.fmt))

        instance.get_member.assert_called_with(mock.ANY, member_id,
                                               fields=mock.ANY)
        self.assertEqual(res.status_int, exc.HTTPOk.code)
        res = self.deserialize(res)
        self.assertIn('member', res)
        self.assertEqual(res['member'], return_value)

    def test_member_delete(self):
        self._test_entity_delete('member')

    def test_health_monitor_create(self):
        health_monitor_id = _uuid()
        data = {'health_monitor': {'type': 'HTTP',
                                   'delay': 2,
                                   'timeout': 1,
                                   'max_retries': 3,
                                   'http_method': 'GET',
                                   'url_path': '/path',
                                   'expected_codes': '200-300',
                                   'admin_state_up': True,
                                   'tenant_id': _uuid()}}
        return_value = copy.copy(data['health_monitor'])
        return_value.update({'status': "ACTIVE", 'id': health_monitor_id})

        instance = self.plugin.return_value
        instance.create_health_monitor.return_value = return_value
        res = self.api.post(_get_path('lb/health_monitors',
                                      fmt=self.fmt),
                            self.serialize(data),
                            content_type='application/%s' % self.fmt)
        instance.create_health_monitor.assert_called_with(mock.ANY,
                                                          health_monitor=data)
        self.assertEqual(res.status_int, exc.HTTPCreated.code)
        res = self.deserialize(res)
        self.assertIn('health_monitor', res)
        self.assertEqual(res['health_monitor'], return_value)

    def test_health_monitor_create_with_timeout_negative(self):
        data = {'health_monitor': {'type': 'HTTP',
                                   'delay': 2,
                                   'timeout': -1,
                                   'max_retries': 3,
                                   'http_method': 'GET',
                                   'url_path': '/path',
                                   'expected_codes': '200-300',
                                   'admin_state_up': True,
                                   'tenant_id': _uuid()}}
        res = self.api.post(_get_path('lb/health_monitors',
                                      fmt=self.fmt),
                            self.serialize(data),
                            content_type='application/%s' % self.fmt,
                            expect_errors=True)
        self.assertEqual(400, res.status_int)

    def test_health_monitor_list(self):
        health_monitor_id = _uuid()
        return_value = [{'type': 'HTTP',
                         'admin_state_up': True,
                         'tenant_id': _uuid(),
                         'id': health_monitor_id}]

        instance = self.plugin.return_value
        instance.get_health_monitors.return_value = return_value

        res = self.api.get(_get_path('lb/health_monitors', fmt=self.fmt))

        instance.get_health_monitors.assert_called_with(
            mock.ANY, fields=mock.ANY, filters=mock.ANY)
        self.assertEqual(res.status_int, exc.HTTPOk.code)

    def test_health_monitor_update(self):
        health_monitor_id = _uuid()
        update_data = {'health_monitor': {'admin_state_up': False}}
        return_value = {'type': 'HTTP',
                        'admin_state_up': False,
                        'tenant_id': _uuid(),
                        'status': "ACTIVE",
                        'id': health_monitor_id}

        instance = self.plugin.return_value
        instance.update_health_monitor.return_value = return_value

        res = self.api.put(_get_path('lb/health_monitors',
                                     id=health_monitor_id,
                                     fmt=self.fmt),
                           self.serialize(update_data))

        instance.update_health_monitor.assert_called_with(
            mock.ANY, health_monitor_id, health_monitor=update_data)
        self.assertEqual(res.status_int, exc.HTTPOk.code)
        res = self.deserialize(res)
        self.assertIn('health_monitor', res)
        self.assertEqual(res['health_monitor'], return_value)

    def test_health_monitor_get(self):
        health_monitor_id = _uuid()
        return_value = {'type': 'HTTP',
                        'admin_state_up': False,
                        'tenant_id': _uuid(),
                        'status': "ACTIVE",
                        'id': health_monitor_id}

        instance = self.plugin.return_value
        instance.get_health_monitor.return_value = return_value

        res = self.api.get(_get_path('lb/health_monitors',
                                     id=health_monitor_id,
                                     fmt=self.fmt))

        instance.get_health_monitor.assert_called_with(
            mock.ANY, health_monitor_id, fields=mock.ANY)
        self.assertEqual(res.status_int, exc.HTTPOk.code)
        res = self.deserialize(res)
        self.assertIn('health_monitor', res)
        self.assertEqual(res['health_monitor'], return_value)

    def test_health_monitor_delete(self):
        self._test_entity_delete('health_monitor')

    def test_create_pool_health_monitor(self):
        health_monitor_id = _uuid()
        data = {'health_monitor': {'id': health_monitor_id,
                                   'tenant_id': _uuid()}}

        return_value = copy.copy(data['health_monitor'])
        instance = self.plugin.return_value
        instance.create_pool_health_monitor.return_value = return_value
        res = self.api.post('/lb/pools/id1/health_monitors',
                            self.serialize(data),
                            content_type='application/%s' % self.fmt)
        instance.create_pool_health_monitor.assert_called_with(
            mock.ANY, pool_id='id1', health_monitor=data)
        self.assertEqual(res.status_int, exc.HTTPCreated.code)
        res = self.deserialize(res)
        self.assertIn('health_monitor', res)
        self.assertEqual(res['health_monitor'], return_value)

    def test_delete_pool_health_monitor(self):
        health_monitor_id = _uuid()

        res = self.api.delete('/lb/pools/id1/health_monitors/%s' %
                              health_monitor_id)

        instance = self.plugin.return_value
        instance.delete_pool_health_monitor.assert_called_with(
            mock.ANY, health_monitor_id, pool_id='id1')
        self.assertEqual(res.status_int, exc.HTTPNoContent.code)


class LoadBalancerExtensionTestCaseXML(LoadBalancerExtensionTestCase):
    fmt = 'xml'
