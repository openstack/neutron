# Copyright 2013 VMware, Inc
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

from neutron import context
from neutron.openstack.common import uuidutils
from neutron.plugins.vmware.dbexts import vcns_db
from neutron.plugins.vmware.vshield.common import exceptions as vcns_exc
from neutron.plugins.vmware.vshield import vcns_driver
from neutron.services.loadbalancer import constants as lb_constants
from neutron.tests.unit.db.loadbalancer import test_db_loadbalancer
from neutron.tests.unit import vmware
from neutron.tests.unit.vmware.vshield import fake_vcns

_uuid = uuidutils.generate_uuid

VSE_ID = 'edge-1'
POOL_MAP_INFO = {
    'pool_id': None,
    'edge_id': VSE_ID,
    'pool_vseid': 'pool-1'}

VCNS_CONFIG_FILE = vmware.get_fake_conf("vcns.ini.test")


class VcnsDriverTestCase(test_db_loadbalancer.LoadBalancerPluginDbTestCase):

    def vcns_loadbalancer_patch(self):
        instance = self.mock_vcns.start()
        instance.return_value.create_vip.side_effect = (
            self.fc2.create_vip)
        instance.return_value.get_vip.side_effect = (
            self.fc2.get_vip)
        instance.return_value.update_vip.side_effect = (
            self.fc2.update_vip)
        instance.return_value.delete_vip.side_effect = (
            self.fc2.delete_vip)
        instance.return_value.create_pool.side_effect = (
            self.fc2.create_pool)
        instance.return_value.get_pool.side_effect = (
            self.fc2.get_pool)
        instance.return_value.update_pool.side_effect = (
            self.fc2.update_pool)
        instance.return_value.delete_pool.side_effect = (
            self.fc2.delete_pool)
        instance.return_value.create_health_monitor.side_effect = (
            self.fc2.create_health_monitor)
        instance.return_value.get_health_monitor.side_effect = (
            self.fc2.get_health_monitor)
        instance.return_value.update_health_monitor.side_effect = (
            self.fc2.update_health_monitor)
        instance.return_value.delete_health_monitor.side_effect = (
            self.fc2.delete_health_monitor)
        instance.return_value.create_app_profile.side_effect = (
            self.fc2.create_app_profile)
        instance.return_value.update_app_profile.side_effect = (
            self.fc2.update_app_profile)
        instance.return_value.delete_app_profile.side_effect = (
            self.fc2.delete_app_profile)
        self.pool_id = None
        self.vip_id = None

    def setUp(self):

        self.config_parse(args=['--config-file', VCNS_CONFIG_FILE])
        # mock vcns
        self.fc2 = fake_vcns.FakeVcns(unique_router_name=False)
        self.mock_vcns = mock.patch(vmware.VCNS_NAME, autospec=True)
        self.vcns_loadbalancer_patch()

        self.driver = vcns_driver.VcnsDriver(mock.Mock())

        super(VcnsDriverTestCase, self).setUp()
        self.addCleanup(self.fc2.reset_all)
        self.addCleanup(self.mock_vcns.stop)

    def tearDown(self):
        super(VcnsDriverTestCase, self).tearDown()


class TestEdgeLbDriver(VcnsDriverTestCase):

    def test_create_and_get_vip(self):
        ctx = context.get_admin_context()
        with self.pool(do_delete=False) as pool:
            self.pool_id = pool['pool']['id']
            POOL_MAP_INFO['pool_id'] = pool['pool']['id']
            vcns_db.add_vcns_edge_pool_binding(ctx.session, POOL_MAP_INFO)
            with self.vip(pool=pool) as res:
                vip_create = res['vip']
                self.driver.create_vip(ctx, VSE_ID, vip_create)
                vip_get = self.driver.get_vip(ctx, vip_create['id'])
                for k, v in vip_get.iteritems():
                    self.assertEqual(vip_create[k], v)

    def test_create_two_vips_with_same_name(self):
        ctx = context.get_admin_context()
        with self.pool(do_delete=False) as pool:
            self.pool_id = pool['pool']['id']
            POOL_MAP_INFO['pool_id'] = pool['pool']['id']
            vcns_db.add_vcns_edge_pool_binding(ctx.session, POOL_MAP_INFO)
            with self.vip(pool=pool) as res:
                vip_create = res['vip']
                self.driver.create_vip(ctx, VSE_ID, vip_create)
                self.assertRaises(vcns_exc.Forbidden,
                                  self.driver.create_vip,
                                  ctx, VSE_ID, vip_create)

    def test_convert_app_profile(self):
        app_profile_name = 'app_profile_name'
        sess_persist1 = {'type': "SOURCE_IP"}
        sess_persist2 = {'type': "HTTP_COOKIE"}
        sess_persist3 = {'type': "APP_COOKIE",
                         'cookie_name': "app_cookie_name"}
        # protocol is HTTP and type is SOURCE_IP
        expect_vcns_app_profile1 = {
            'insertXForwardedFor': False,
            'name': app_profile_name,
            'serverSslEnabled': False,
            'sslPassthrough': False,
            'template': lb_constants.PROTOCOL_HTTP,
            'persistence': {'method': 'sourceip'}}
        vcns_app_profile = self.driver._convert_app_profile(
            app_profile_name, sess_persist1, lb_constants.PROTOCOL_HTTP)
        for k, v in expect_vcns_app_profile1.iteritems():
            self.assertEqual(vcns_app_profile[k], v)
        # protocol is HTTP and type is HTTP_COOKIE and APP_COOKIE
        expect_vcns_app_profile2 = {
            'insertXForwardedFor': False,
            'name': app_profile_name,
            'serverSslEnabled': False,
            'sslPassthrough': False,
            'template': lb_constants.PROTOCOL_HTTP,
            'persistence': {'method': 'cookie',
                            'cookieName': 'default_cookie_name',
                            'cookieMode': 'insert'}}
        vcns_app_profile = self.driver._convert_app_profile(
            app_profile_name, sess_persist2, lb_constants.PROTOCOL_HTTP)
        for k, v in expect_vcns_app_profile2.iteritems():
            self.assertEqual(vcns_app_profile[k], v)
        expect_vcns_app_profile3 = {
            'insertXForwardedFor': False,
            'name': app_profile_name,
            'serverSslEnabled': False,
            'sslPassthrough': False,
            'template': lb_constants.PROTOCOL_HTTP,
            'persistence': {'method': 'cookie',
                            'cookieName': sess_persist3['cookie_name'],
                            'cookieMode': 'app'}}
        vcns_app_profile = self.driver._convert_app_profile(
            app_profile_name, sess_persist3, lb_constants.PROTOCOL_HTTP)
        for k, v in expect_vcns_app_profile3.iteritems():
            self.assertEqual(vcns_app_profile[k], v)
        # protocol is HTTPS and type is SOURCE_IP
        expect_vcns_app_profile1 = {
            'insertXForwardedFor': False,
            'name': app_profile_name,
            'serverSslEnabled': False,
            'sslPassthrough': True,
            'template': lb_constants.PROTOCOL_HTTPS,
            'persistence': {'method': 'sourceip'}}
        vcns_app_profile = self.driver._convert_app_profile(
            app_profile_name, sess_persist1, lb_constants.PROTOCOL_HTTPS)
        for k, v in expect_vcns_app_profile1.iteritems():
            self.assertEqual(vcns_app_profile[k], v)
        # protocol is HTTPS, and type isn't SOURCE_IP
        self.assertRaises(vcns_exc.VcnsBadRequest,
                          self.driver._convert_app_profile,
                          app_profile_name,
                          sess_persist2, lb_constants.PROTOCOL_HTTPS)
        self.assertRaises(vcns_exc.VcnsBadRequest,
                          self.driver._convert_app_profile,
                          app_profile_name,
                          sess_persist3, lb_constants.PROTOCOL_HTTPS)
        # protocol is TCP and type is SOURCE_IP
        expect_vcns_app_profile1 = {
            'insertXForwardedFor': False,
            'name': app_profile_name,
            'serverSslEnabled': False,
            'sslPassthrough': False,
            'template': lb_constants.PROTOCOL_TCP,
            'persistence': {'method': 'sourceip'}}
        vcns_app_profile = self.driver._convert_app_profile(
            app_profile_name, sess_persist1, lb_constants.PROTOCOL_TCP)
        for k, v in expect_vcns_app_profile1.iteritems():
            self.assertEqual(vcns_app_profile[k], v)
        # protocol is TCP, and type isn't SOURCE_IP
        self.assertRaises(vcns_exc.VcnsBadRequest,
                          self.driver._convert_app_profile,
                          app_profile_name,
                          sess_persist2, lb_constants.PROTOCOL_TCP)
        self.assertRaises(vcns_exc.VcnsBadRequest,
                          self.driver._convert_app_profile,
                          app_profile_name,
                          sess_persist3, lb_constants.PROTOCOL_TCP)

    def test_update_vip(self):
        ctx = context.get_admin_context()
        with self.pool(do_delete=False) as pool:
            self.pool_id = pool['pool']['id']
            POOL_MAP_INFO['pool_id'] = pool['pool']['id']
            vcns_db.add_vcns_edge_pool_binding(ctx.session, POOL_MAP_INFO)
            with self.vip(pool=pool) as res:
                vip_create = res['vip']
                self.driver.create_vip(ctx, VSE_ID, vip_create)
                vip_update = {'id': vip_create['id'],
                              'pool_id': pool['pool']['id'],
                              'name': 'update_name',
                              'description': 'description',
                              'address': 'update_address',
                              'port_id': 'update_port_id',
                              'protocol_port': 'protocol_port',
                              'protocol': 'update_protocol'}
                self.driver.update_vip(ctx, vip_update)
                vip_get = self.driver.get_vip(ctx, vip_create['id'])
                for k, v in vip_get.iteritems():
                        if k in vip_update:
                            self.assertEqual(vip_update[k], v)

    def test_delete_vip(self):
        ctx = context.get_admin_context()
        with self.pool(do_delete=False) as pool:
            self.pool_id = pool['pool']['id']
            POOL_MAP_INFO['pool_id'] = pool['pool']['id']
            vcns_db.add_vcns_edge_pool_binding(ctx.session, POOL_MAP_INFO)
            with self.vip(pool=pool) as res:
                vip_create = res['vip']
                self.driver.create_vip(ctx, VSE_ID, vip_create)
                self.driver.delete_vip(ctx, vip_create['id'])
                self.assertRaises(vcns_exc.VcnsNotFound,
                                  self.driver.get_vip,
                                  ctx,
                                  vip_create['id'])

    #Test Pool Operation
    def test_create_and_get_pool(self):
        ctx = context.get_admin_context()
        with self.pool(do_delete=False) as p:
            self.pool_id = p['pool']['id']
            pool_create = p['pool']
            self.driver.create_pool(ctx, VSE_ID, pool_create, [])
            pool_get = self.driver.get_pool(ctx, pool_create['id'], VSE_ID)
            for k, v in pool_get.iteritems():
                self.assertEqual(pool_create[k], v)

    def test_create_two_pools_with_same_name(self):
        ctx = context.get_admin_context()
        with self.pool(do_delete=False) as p:
            self.pool_id = p['pool']['id']
            pool_create = p['pool']
            self.driver.create_pool(ctx, VSE_ID, pool_create, [])
            self.assertRaises(vcns_exc.Forbidden,
                              self.driver.create_pool,
                              ctx, VSE_ID, pool_create, [])

    def test_update_pool(self):
        ctx = context.get_admin_context()
        with self.pool(do_delete=False) as p:
            self.pool_id = p['pool']['id']
            pool_create = p['pool']
            self.driver.create_pool(ctx, VSE_ID, pool_create, [])
            pool_update = {'id': pool_create['id'],
                           'lb_method': 'lb_method',
                           'name': 'update_name',
                           'members': [],
                           'health_monitors': []}
            self.driver.update_pool(ctx, VSE_ID, pool_update, [])
            pool_get = self.driver.get_pool(ctx, pool_create['id'], VSE_ID)
            for k, v in pool_get.iteritems():
                    if k in pool_update:
                        self.assertEqual(pool_update[k], v)

    def test_delete_pool(self):
        ctx = context.get_admin_context()
        with self.pool(do_delete=False) as p:
            self.pool_id = p['pool']['id']
            pool_create = p['pool']
            self.driver.create_pool(ctx, VSE_ID, pool_create, [])
            self.driver.delete_pool(ctx, pool_create['id'], VSE_ID)
            self.assertRaises(vcns_exc.VcnsNotFound,
                              self.driver.get_pool,
                              ctx,
                              pool_create['id'],
                              VSE_ID)

    def test_create_and_get_monitor(self):
        ctx = context.get_admin_context()
        with self.health_monitor(do_delete=False) as m:
            monitor_create = m['health_monitor']
            self.driver.create_health_monitor(ctx, VSE_ID, monitor_create)
            monitor_get = self.driver.get_health_monitor(
                ctx, monitor_create['id'], VSE_ID)
            for k, v in monitor_get.iteritems():
                self.assertEqual(monitor_create[k], v)

    def test_update_health_monitor(self):
        ctx = context.get_admin_context()
        with self.health_monitor(do_delete=False) as m:
            monitor_create = m['health_monitor']
            self.driver.create_health_monitor(
                ctx, VSE_ID, monitor_create)
            monitor_update = {'id': monitor_create['id'],
                              'delay': 'new_delay',
                              'timeout': "new_timeout",
                              'type': 'type',
                              'max_retries': "max_retries"}
            self.driver.update_health_monitor(
                ctx, VSE_ID, monitor_create, monitor_update)
            monitor_get = self.driver.get_health_monitor(
                ctx, monitor_create['id'], VSE_ID)
            for k, v in monitor_get.iteritems():
                    if k in monitor_update:
                        self.assertEqual(monitor_update[k], v)

    def test_delete_health_monitor(self):
        ctx = context.get_admin_context()
        with self.health_monitor(do_delete=False) as m:
            monitor_create = m['health_monitor']
            self.driver.create_health_monitor(ctx, VSE_ID, monitor_create)
            self.driver.delete_health_monitor(
                ctx, monitor_create['id'], VSE_ID)
            self.assertRaises(vcns_exc.VcnsNotFound,
                              self.driver.get_health_monitor,
                              ctx,
                              monitor_create['id'],
                              VSE_ID)
