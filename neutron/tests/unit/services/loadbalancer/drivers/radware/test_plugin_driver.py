# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013 Radware LTD.
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
# @author: Avishay Balderman, Radware

import re

from eventlet import greenthread
import mock

from neutron import context
from neutron.extensions import loadbalancer
from neutron import manager
from neutron.openstack.common import jsonutils as json
from neutron.plugins.common import constants
from neutron.services.loadbalancer.drivers.radware import driver
from neutron.tests.unit.db.loadbalancer import test_db_loadbalancer

GET_200 = ('/api/workflow/', '/api/service/', '/api/workflowTemplate')


def rest_call_function_mock(action, resource, data, headers, binary=False):

    if rest_call_function_mock.RESPOND_WITH_ERROR:
        return 400, 'error_status', 'error_reason', None

    if action == 'GET':
        return _get_handler(resource)
    elif action == 'DELETE':
        return _delete_handler(resource)
    elif action == 'POST':
        return _post_handler(resource, binary)
    else:
        return 0, None, None, None


def _get_handler(resource):
    if resource == GET_200[2]:
        data = json.loads('[{"name":"a"},{"name":"b"}]')
        return 200, '', '', data

    if resource in GET_200:
        return 200, '', '', ''
    else:
        data = json.loads('{"complete":"True", "success": "True"}')
        return 202, '', '', data


def _delete_handler(resource):
    return 202, '', '', {'message': 'Not Found'}


def _post_handler(resource, binary):
    if re.search(r'/api/workflow/.+/action/.+', resource):
        data = json.loads('{"uri":"some_uri"}')
        return 202, '', '', data
    elif re.search(r'/api/service\?name=.+', resource):
        data = json.loads('{"links":{"actions":{"provision":"someuri"}}}')
        return 201, '', '', data
    elif binary:
        return 201, '', '', ''
    else:
        return 202, '', '', ''

RADWARE_PROVIDER = ('LOADBALANCER:radware:neutron.services.'
                    'loadbalancer.drivers.radware.driver.'
                    'LoadBalancerDriver:default')


class TestLoadBalancerPluginBase(
    test_db_loadbalancer.LoadBalancerPluginDbTestCase):

    def setUp(self):
        super(TestLoadBalancerPluginBase, self).setUp(
            lbaas_provider=RADWARE_PROVIDER)

        loaded_plugins = manager.NeutronManager().get_service_plugins()
        self.plugin_instance = loaded_plugins[constants.LOADBALANCER]


class TestLoadBalancerPlugin(TestLoadBalancerPluginBase):
    def setUp(self):
        super(TestLoadBalancerPlugin, self).setUp()

        rest_call_function_mock.__dict__.update(
            {'RESPOND_WITH_ERROR': False})

        self.rest_call_mock = mock.Mock(name='rest_call_mock',
                                        side_effect=rest_call_function_mock,
                                        spec=self.plugin_instance.
                                        drivers['radware'].
                                        rest_client.call)
        radware_driver = self.plugin_instance.drivers['radware']
        radware_driver.rest_client.call = self.rest_call_mock

        self.ctx = context.get_admin_context()

        self.addCleanup(radware_driver.completion_handler.join)
        self.addCleanup(mock.patch.stopall)

    def test_create_vip_failure(self):
        """Test the rest call failure handling by Exception raising."""
        self.rest_call_mock.reset_mock()
        with self.subnet() as subnet:
            with self.pool(provider='radware') as pool:
                vip_data = {
                    'name': 'vip1',
                    'subnet_id': subnet['subnet']['id'],
                    'pool_id': pool['pool']['id'],
                    'description': '',
                    'protocol_port': 80,
                    'protocol': 'HTTP',
                    'connection_limit': -1,
                    'admin_state_up': True,
                    'status': 'PENDING_CREATE',
                    'tenant_id': self._tenant_id,
                    'session_persistence': ''
                }

                rest_call_function_mock.__dict__.update(
                    {'RESPOND_WITH_ERROR': True})
                self.assertRaises(StandardError,
                                  self.plugin_instance.create_vip,
                                  (self.ctx, {'vip': vip_data}))

    def test_create_vip(self):
        self.rest_call_mock.reset_mock()
        with self.subnet() as subnet:
            with self.pool(provider='radware') as pool:
                vip_data = {
                    'name': 'vip1',
                    'subnet_id': subnet['subnet']['id'],
                    'pool_id': pool['pool']['id'],
                    'description': '',
                    'protocol_port': 80,
                    'protocol': 'HTTP',
                    'connection_limit': -1,
                    'admin_state_up': True,
                    'status': 'PENDING_CREATE',
                    'tenant_id': self._tenant_id,
                    'session_persistence': ''
                }

                vip = self.plugin_instance.create_vip(
                    self.ctx, {'vip': vip_data})

                # Test creation REST calls
                calls = [
                    mock.call('GET', u'/api/service/srv_' +
                              subnet['subnet']['network_id'], None, None),
                    mock.call('POST', u'/api/service?name=srv_' +
                              subnet['subnet']['network_id'], mock.ANY,
                              driver.CREATE_SERVICE_HEADER),
                    mock.call('GET', u'/api/workflow/l2_l3_' +
                              subnet['subnet']['network_id'], None, None),
                    mock.call('POST', '/api/workflow/l2_l3_' +
                              subnet['subnet']['network_id'] +
                              '/action/setup_l2_l3',
                              mock.ANY, driver.TEMPLATE_HEADER),
                    mock.call('POST', 'someuri',
                              None, driver.PROVISION_HEADER),


                    mock.call('POST', '/api/workflowTemplate/' +
                              driver.L4_WORKFLOW_TEMPLATE_NAME +
                              '?name=' + pool['pool']['id'],
                              mock.ANY,
                              driver.TEMPLATE_HEADER),
                    mock.call('POST', '/api/workflowTemplate/' +
                              driver.L2_L3_WORKFLOW_TEMPLATE_NAME +
                              '?name=l2_l3_' + subnet['subnet']['network_id'],
                              mock.ANY,
                              driver.TEMPLATE_HEADER),

                    mock.call('POST', '/api/workflow/' + pool['pool']['id'] +
                              '/action/' + driver.L4_ACTION_NAME,
                              mock.ANY, driver.TEMPLATE_HEADER),
                    mock.call('GET', '/api/workflow/' +
                              pool['pool']['id'], None, None)
                ]
                self.rest_call_mock.assert_has_calls(calls, any_order=True)

                # sleep to wait for the operation completion
                greenthread.sleep(1)

                #Test DB
                new_vip = self.plugin_instance.get_vip(self.ctx, vip['id'])
                self.assertEqual(new_vip['status'], 'ACTIVE')

                # Delete VIP
                self.plugin_instance.delete_vip(self.ctx, vip['id'])

                # Test deletion REST calls
                calls = [
                    mock.call('DELETE', u'/api/workflow/' + pool['pool']['id'],
                              None, None)
                ]
                self.rest_call_mock.assert_has_calls(calls, any_order=True)

    def test_update_vip(self):
        self.rest_call_mock.reset_mock()
        with self.subnet() as subnet:
            with self.pool(provider='radware', no_delete=True) as pool:
                vip_data = {
                    'name': 'vip1',
                    'subnet_id': subnet['subnet']['id'],
                    'pool_id': pool['pool']['id'],
                    'description': '',
                    'protocol_port': 80,
                    'protocol': 'HTTP',
                    'connection_limit': -1,
                    'admin_state_up': True,
                    'status': 'PENDING_CREATE',
                    'tenant_id': self._tenant_id,
                    'session_persistence': ''
                }

                vip = self.plugin_instance.create_vip(
                    self.ctx, {'vip': vip_data})

                vip_data['status'] = 'PENDING_UPDATE'
                self.plugin_instance.update_vip(self.ctx, vip['id'],
                                                {'vip': vip_data})

                # Test REST calls
                calls = [
                    mock.call('POST', '/api/workflow/' + pool['pool']['id'] +
                              '/action/' + driver.L4_ACTION_NAME,
                              mock.ANY, driver.TEMPLATE_HEADER),
                ]
                self.rest_call_mock.assert_has_calls(calls, any_order=True)

                updated_vip = self.plugin_instance.get_vip(self.ctx, vip['id'])
                self.assertEqual(updated_vip['status'], 'PENDING_UPDATE')

                # sleep to wait for the operation completion
                greenthread.sleep(1)
                updated_vip = self.plugin_instance.get_vip(self.ctx, vip['id'])
                self.assertEqual(updated_vip['status'], 'ACTIVE')

                # delete VIP
                self.plugin_instance.delete_vip(self.ctx, vip['id'])

    def test_delete_vip(self):
        self.rest_call_mock.reset_mock()
        with self.subnet() as subnet:
            with self.pool(provider='radware', no_delete=True) as pool:
                vip_data = {
                    'name': 'vip1',
                    'subnet_id': subnet['subnet']['id'],
                    'pool_id': pool['pool']['id'],
                    'description': '',
                    'protocol_port': 80,
                    'protocol': 'HTTP',
                    'connection_limit': -1,
                    'admin_state_up': True,
                    'status': 'PENDING_CREATE',
                    'tenant_id': self._tenant_id,
                    'session_persistence': ''
                }

                vip = self.plugin_instance.create_vip(
                    self.ctx, {'vip': vip_data})

                self.plugin_instance.delete_vip(self.ctx, vip['id'])

                calls = [
                    mock.call('DELETE', '/api/workflow/' + pool['pool']['id'],
                              None, None)
                ]
                self.rest_call_mock.assert_has_calls(calls, any_order=True)

                self.assertRaises(loadbalancer.VipNotFound,
                                  self.plugin_instance.get_vip,
                                  self.ctx, vip['id'])
                # add test checking all vip graph objects were removed from DB

    def test_delete_pool_with_vip(self):
        self.rest_call_mock.reset_mock()
        with self.subnet() as subnet:
            with self.pool(provider='radware', no_delete=True) as pool:
                with self.vip(pool=pool, subnet=subnet):
                    self.assertRaises(loadbalancer.PoolInUse,
                                      self.plugin_instance.delete_pool,
                                      self.ctx, pool['pool']['id'])

    def test_create_member_with_vip(self):
        self.rest_call_mock.reset_mock()
        with self.subnet() as subnet:
            with self.pool(provider='radware') as p:
                with self.vip(pool=p, subnet=subnet):
                    with self.member(pool_id=p['pool']['id']):
                        calls = [
                            mock.call(
                                'POST', '/api/workflow/' + p['pool']['id'] +
                                '/action/' + driver.L4_ACTION_NAME,
                                mock.ANY, driver.TEMPLATE_HEADER
                            ),
                            mock.call(
                                'POST', '/api/workflow/' + p['pool']['id'] +
                                '/action/' + driver.L4_ACTION_NAME,
                                mock.ANY, driver.TEMPLATE_HEADER
                            )
                        ]
                        self.rest_call_mock.assert_has_calls(calls,
                                                             any_order=True)

    def test_update_member_with_vip(self):
        self.rest_call_mock.reset_mock()
        with self.subnet() as subnet:
            with self.pool(provider='radware') as p:
                with self.member(pool_id=p['pool']['id']) as member:
                    with self.vip(pool=p, subnet=subnet):
                        self.plugin_instance.update_member(
                            self.ctx, member['member']['id'], member
                        )
                        calls = [
                            mock.call(
                                'POST', '/api/workflow/' + p['pool']['id'] +
                                '/action/' + driver.L4_ACTION_NAME,
                                mock.ANY, driver.TEMPLATE_HEADER
                            ),
                            mock.call(
                                'POST', '/api/workflow/' + p['pool']['id'] +
                                '/action/' + driver.L4_ACTION_NAME,
                                mock.ANY, driver.TEMPLATE_HEADER
                            )
                        ]
                        self.rest_call_mock.assert_has_calls(calls,
                                                             any_order=True)

                        updated_member = self.plugin_instance.get_member(
                            self.ctx, member['member']['id']
                        )

                        # sleep to wait for the operation completion
                        greenthread.sleep(1)
                        updated_member = self.plugin_instance.get_member(
                            self.ctx, member['member']['id']
                        )
                        self.assertEqual(updated_member['status'], 'ACTIVE')

    def test_update_member_without_vip(self):
        self.rest_call_mock.reset_mock()
        with self.subnet():
            with self.pool(provider='radware') as pool:
                with self.member(pool_id=pool['pool']['id']) as member:
                    member['member']['status'] = 'PENDING_UPDATE'
                    updated_member = self.plugin_instance.update_member(
                        self.ctx, member['member']['id'], member
                    )
                    self.assertEqual(updated_member['status'],
                                     'PENDING_UPDATE')

    def test_delete_member_with_vip(self):
        self.rest_call_mock.reset_mock()
        with self.subnet() as subnet:
            with self.pool(provider='radware') as p:
                with self.member(pool_id=p['pool']['id'],
                                 no_delete=True) as m:
                    with self.vip(pool=p, subnet=subnet):

                        self.plugin_instance.delete_member(self.ctx,
                                                           m['member']['id'])

                        calls = [
                            mock.call(
                                'POST', '/api/workflow/' + p['pool']['id'] +
                                '/action/' + driver.L4_ACTION_NAME,
                                mock.ANY, driver.TEMPLATE_HEADER
                            ),
                            mock.call(
                                'POST', '/api/workflow/' + p['pool']['id'] +
                                '/action/' + driver.L4_ACTION_NAME,
                                mock.ANY, driver.TEMPLATE_HEADER
                            )
                        ]
                        self.rest_call_mock.assert_has_calls(calls,
                                                             any_order=True)

                        greenthread.sleep(1)
                        self.assertRaises(loadbalancer.MemberNotFound,
                                          self.plugin_instance.get_member,
                                          self.ctx, m['member']['id'])

    def test_delete_member_without_vip(self):
        self.rest_call_mock.reset_mock()
        with self.subnet():
            with self.pool(provider='radware') as p:
                with self.member(pool_id=p['pool']['id'], no_delete=True) as m:
                    self.plugin_instance.delete_member(
                        self.ctx, m['member']['id']
                    )
                    self.assertRaises(loadbalancer.MemberNotFound,
                                      self.plugin_instance.get_member,
                                      self.ctx, m['member']['id'])
