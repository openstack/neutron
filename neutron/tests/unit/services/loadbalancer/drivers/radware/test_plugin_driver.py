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

import re

import contextlib
import mock
from oslo.config import cfg
from six.moves import queue as Queue

from neutron import context
from neutron.extensions import loadbalancer
from neutron import manager
from neutron.openstack.common import jsonutils
from neutron.plugins.common import constants
from neutron.services.loadbalancer.drivers.radware import driver
from neutron.services.loadbalancer.drivers.radware import exceptions as r_exc
from neutron.tests.unit.db.loadbalancer import test_db_loadbalancer

GET_200 = ('/api/workflow/', '/api/service/', '/api/workflowTemplate')
SERVER_DOWN_CODES = (-1, 301, 307)


class QueueMock(Queue.Queue):
    def __init__(self, completion_handler):
        self.completion_handler = completion_handler
        super(QueueMock, self).__init__()

    def put_nowait(self, oper):
        self.completion_handler(oper)


def _recover_function_mock(action, resource, data, headers, binary=False):
    pass


def rest_call_function_mock(action, resource, data, headers, binary=False):
    if rest_call_function_mock.RESPOND_WITH_ERROR:
        return 400, 'error_status', 'error_description', None
    if rest_call_function_mock.RESPOND_WITH_SERVER_DOWN in SERVER_DOWN_CODES:
        val = rest_call_function_mock.RESPOND_WITH_SERVER_DOWN
        return val, 'error_status', 'error_description', None
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
        if rest_call_function_mock.TEMPLATES_MISSING:
            data = jsonutils.loads('[]')
        else:
            data = jsonutils.loads(
                '[{"name":"openstack_l2_l3"},{"name":"openstack_l4"}]'
            )
        return 200, '', '', data

    if resource in GET_200:
        return 200, '', '', ''
    else:
        data = jsonutils.loads('{"complete":"True", "success": "True"}')
        return 202, '', '', data


def _delete_handler(resource):
    return 404, '', '', {'message': 'Not Found'}


def _post_handler(resource, binary):
    if re.search(r'/api/workflow/.+/action/.+', resource):
        data = jsonutils.loads('{"uri":"some_uri"}')
        return 202, '', '', data
    elif re.search(r'/api/service\?name=.+', resource):
        data = jsonutils.loads('{"links":{"actions":{"provision":"someuri"}}}')
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
        rest_call_function_mock.__dict__.update(
            {'TEMPLATES_MISSING': False})
        rest_call_function_mock.__dict__.update(
            {'RESPOND_WITH_SERVER_DOWN': 200})

        self.operation_completer_start_mock = mock.Mock(
            return_value=None)
        self.operation_completer_join_mock = mock.Mock(
            return_value=None)
        self.driver_rest_call_mock = mock.Mock(
            side_effect=rest_call_function_mock)
        self.flip_servers_mock = mock.Mock(
            return_value=None)
        self.recover_mock = mock.Mock(
            side_effect=_recover_function_mock)

        radware_driver = self.plugin_instance.drivers['radware']
        radware_driver.completion_handler.start = (
            self.operation_completer_start_mock)
        radware_driver.completion_handler.join = (
            self.operation_completer_join_mock)
        self.orig_call = radware_driver.rest_client.call
        self.orig__call = radware_driver.rest_client._call
        radware_driver.rest_client.call = self.driver_rest_call_mock
        radware_driver.rest_client._call = self.driver_rest_call_mock
        radware_driver.rest_client._flip_servers = self.flip_servers_mock
        radware_driver.rest_client._recover = self.recover_mock
        radware_driver.completion_handler.rest_client.call = (
            self.driver_rest_call_mock)

        radware_driver.queue = QueueMock(
            radware_driver.completion_handler.handle_operation_completion)

        self.addCleanup(radware_driver.completion_handler.join)

    def test_get_pip(self):
        """Call _get_pip twice and verify that a Port is created once."""
        port_dict = {'fixed_ips': [{'subnet_id': '10.10.10.10',
                                    'ip_address': '11.11.11.11'}]}
        self.plugin_instance._core_plugin.get_ports = mock.Mock(
            return_value=[])
        self.plugin_instance._core_plugin.create_port = mock.Mock(
            return_value=port_dict)
        radware_driver = self.plugin_instance.drivers['radware']
        radware_driver._get_pip(context.get_admin_context(),
                                'tenant_id', 'port_name',
                                'network_id', '10.10.10.10')
        self.plugin_instance._core_plugin.get_ports.assert_called_once()
        self.plugin_instance._core_plugin.create_port.assert_called_once()
        self.plugin_instance._core_plugin.create_port.reset_mock()
        self.plugin_instance._core_plugin.get_ports.reset_mock()
        self.plugin_instance._core_plugin.get_ports.return_value = [port_dict]
        radware_driver._get_pip(context.get_admin_context(),
                                'tenant_id', 'port_name',
                                'network_id', '10.10.10.10')
        self.plugin_instance._core_plugin.get_ports.assert_called_once()
        self.assertFalse(self.plugin_instance._core_plugin.create_port.called)

    def test_rest_client_recover_was_called(self):
        """Call the real REST client and verify _recover is called."""
        radware_driver = self.plugin_instance.drivers['radware']
        radware_driver.rest_client.call = self.orig_call
        radware_driver.rest_client._call = self.orig__call
        self.assertRaises(r_exc.RESTRequestFailure,
                          radware_driver._verify_workflow_templates)
        self.recover_mock.assert_called_once()

    def test_rest_client_flip_servers(self):
        radware_driver = self.plugin_instance.drivers['radware']
        server = radware_driver.rest_client.server
        sec_server = radware_driver.rest_client.secondary_server
        radware_driver.rest_client._flip_servers()
        self.assertEqual(server,
                         radware_driver.rest_client.secondary_server)
        self.assertEqual(sec_server,
                         radware_driver.rest_client.server)

    def test_verify_workflow_templates_server_down(self):
        """Test the rest call failure when backend is down."""
        for value in SERVER_DOWN_CODES:
            rest_call_function_mock.__dict__.update(
                {'RESPOND_WITH_SERVER_DOWN': value})
            self.assertRaises(r_exc.RESTRequestFailure,
                              self.plugin_instance.drivers['radware'].
                              _verify_workflow_templates)

    def test_verify_workflow_templates(self):
        """Test the rest call failure handling by Exception raising."""
        rest_call_function_mock.__dict__.update(
            {'TEMPLATES_MISSING': True})

        self.assertRaises(r_exc.WorkflowMissing,
                          self.plugin_instance.drivers['radware'].
                          _verify_workflow_templates)

    def test_create_vip_failure(self):
        """Test the rest call failure handling by Exception raising."""
        with self.network() as network:
            with self.subnet(network=network) as subnet:
                with self.pool(do_delete=False,
                               provider='radware',
                               subnet_id=subnet['subnet']['id']) as pool:
                    vip_data = {
                        'name': 'vip1',
                        'subnet_id': subnet['subnet']['id'],
                        'pool_id': pool['pool']['id'],
                        'description': '',
                        'protocol_port': 80,
                        'protocol': 'HTTP',
                        'connection_limit': -1,
                        'admin_state_up': True,
                        'status': constants.PENDING_CREATE,
                        'tenant_id': self._tenant_id,
                        'session_persistence': ''
                    }

                    rest_call_function_mock.__dict__.update(
                        {'RESPOND_WITH_ERROR': True})

                    self.assertRaises(r_exc.RESTRequestFailure,
                                      self.plugin_instance.create_vip,
                                      context.get_admin_context(),
                                      {'vip': vip_data})

    def test_create_vip(self):
        with self.subnet() as subnet:
            with self.pool(provider='radware',
                           subnet_id=subnet['subnet']['id']) as pool:
                vip_data = {
                    'name': 'vip1',
                    'subnet_id': subnet['subnet']['id'],
                    'pool_id': pool['pool']['id'],
                    'description': '',
                    'protocol_port': 80,
                    'protocol': 'HTTP',
                    'connection_limit': -1,
                    'admin_state_up': True,
                    'status': constants.PENDING_CREATE,
                    'tenant_id': self._tenant_id,
                    'session_persistence': ''
                }

                vip = self.plugin_instance.create_vip(
                    context.get_admin_context(), {'vip': vip_data})

                # Test creation REST calls
                calls = [
                    mock.call('GET', u'/api/service/srv_' +
                              subnet['subnet']['network_id'], None, None),
                    mock.call('POST', u'/api/service?name=srv_' +
                              subnet['subnet']['network_id'] + '&tenant=' +
                              vip['tenant_id'], mock.ANY,
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
                              'openstack_l4' +
                              '?name=' + pool['pool']['id'],
                              mock.ANY,
                              driver.TEMPLATE_HEADER),
                    mock.call('POST', '/api/workflowTemplate/' +
                              'openstack_l2_l3' +
                              '?name=l2_l3_' + subnet['subnet']['network_id'],
                              mock.ANY,
                              driver.TEMPLATE_HEADER),

                    mock.call('POST', '/api/workflow/' + pool['pool']['id'] +
                              '/action/BaseCreate',
                              mock.ANY, driver.TEMPLATE_HEADER),
                    mock.call('GET', '/api/workflow/' +
                              pool['pool']['id'], None, None)
                ]
                self.driver_rest_call_mock.assert_has_calls(calls,
                                                            any_order=True)

                #Test DB
                new_vip = self.plugin_instance.get_vip(
                    context.get_admin_context(),
                    vip['id']
                )
                self.assertEqual(new_vip['status'], constants.ACTIVE)

                # Delete VIP
                self.plugin_instance.delete_vip(
                    context.get_admin_context(), vip['id'])

                # Test deletion REST calls
                calls = [
                    mock.call('DELETE', u'/api/workflow/' + pool['pool']['id'],
                              None, None)
                ]
                self.driver_rest_call_mock.assert_has_calls(
                    calls, any_order=True)

    def test_create_vip_2_leg(self):
        """Test creation of a VIP where Alteon VIP and PIP are different."""

        with self.subnet(cidr='10.0.0.0/24') as subnet:
            with self.subnet(cidr='10.0.1.0/24') as pool_sub:
                with self.pool(provider='radware',
                               subnet_id=pool_sub['subnet']['id']) as pool:
                    vip_data = {
                        'name': 'vip1',
                        'subnet_id': subnet['subnet']['id'],
                        'pool_id': pool['pool']['id'],
                        'description': '',
                        'protocol_port': 80,
                        'protocol': 'HTTP',
                        'connection_limit': -1,
                        'admin_state_up': True,
                        'status': constants.PENDING_CREATE,
                        'tenant_id': self._tenant_id,
                        'session_persistence': ''
                    }

                    vip = self.plugin_instance.create_vip(
                        context.get_admin_context(), {'vip': vip_data})
                    name_suffix = '%s_%s' % (subnet['subnet']['network_id'],
                                             pool_sub['subnet']['network_id'])
                    # Test creation REST calls
                    calls = [
                        mock.call('GET', '/api/workflowTemplate', None, None),
                        mock.call('GET', '/api/service/srv_' + name_suffix,
                                  None, None),
                        mock.call('POST', '/api/service?name=srv_' +
                                  name_suffix + '&tenant=' + vip['tenant_id'],
                                  mock.ANY, driver.CREATE_SERVICE_HEADER),
                        mock.call('POST', 'someuri',
                                  None, driver.PROVISION_HEADER),
                        mock.call('GET', '/api/workflow/l2_l3_' + name_suffix,
                                  None, None),
                        mock.call('POST', '/api/workflowTemplate/' +
                                  'openstack_l2_l3' +
                                  '?name=l2_l3_' + name_suffix,
                                  mock.ANY,
                                  driver.TEMPLATE_HEADER),
                        mock.call('POST', '/api/workflow/l2_l3_' +
                                  name_suffix + '/action/setup_l2_l3',
                                  mock.ANY, driver.TEMPLATE_HEADER),
                        mock.call('GET', '/api/workflow/' +
                                  pool['pool']['id'], None, None),
                        mock.call('POST', '/api/workflowTemplate/' +
                                  'openstack_l4' +
                                  '?name=' + pool['pool']['id'],
                                  mock.ANY,
                                  driver.TEMPLATE_HEADER),
                        mock.call('POST', '/api/workflow/' +
                                  pool['pool']['id'] + '/action/BaseCreate',
                                  mock.ANY, driver.TEMPLATE_HEADER)
                    ]
                    self.driver_rest_call_mock.assert_has_calls(calls)
                    #Test DB
                    new_vip = self.plugin_instance.get_vip(
                        context.get_admin_context(),
                        vip['id']
                    )
                    self.assertEqual(new_vip['status'], constants.ACTIVE)

                    # Test that PIP neutron port was created
                    pip_port_filter = {
                        'name': ['pip_' + vip['id']],
                    }
                    plugin = manager.NeutronManager.get_plugin()
                    num_ports = plugin.get_ports_count(
                        context.get_admin_context(), filters=pip_port_filter)
                    self.assertTrue(num_ports > 0)

                    # Delete VIP
                    self.plugin_instance.delete_vip(
                        context.get_admin_context(), vip['id'])

                    # Test deletion REST calls
                    calls = [
                        mock.call('DELETE', u'/api/workflow/' +
                                  pool['pool']['id'], None, None)
                    ]
                    self.driver_rest_call_mock.assert_has_calls(calls)

    def test_update_vip(self):
        with self.subnet() as subnet:
            with self.pool(provider='radware',
                           do_delete=False,
                           subnet_id=subnet['subnet']['id']) as pool:
                vip_data = {
                    'name': 'vip1',
                    'subnet_id': subnet['subnet']['id'],
                    'pool_id': pool['pool']['id'],
                    'description': '',
                    'protocol_port': 80,
                    'protocol': 'HTTP',
                    'connection_limit': -1,
                    'admin_state_up': True,
                    'status': constants.PENDING_CREATE,
                    'tenant_id': self._tenant_id,
                    'session_persistence': ''
                }

                vip = self.plugin_instance.create_vip(
                    context.get_admin_context(), {'vip': vip_data})

                vip_data['status'] = constants.PENDING_UPDATE
                self.plugin_instance.update_vip(
                    context.get_admin_context(),
                    vip['id'], {'vip': vip_data})

                # Test REST calls
                calls = [
                    mock.call('POST', '/api/workflow/' + pool['pool']['id'] +
                              '/action/BaseCreate',
                              mock.ANY, driver.TEMPLATE_HEADER),
                ]
                self.driver_rest_call_mock.assert_has_calls(
                    calls, any_order=True)

                updated_vip = self.plugin_instance.get_vip(
                    context.get_admin_context(), vip['id'])
                self.assertEqual(updated_vip['status'], constants.ACTIVE)

                # delete VIP
                self.plugin_instance.delete_vip(
                    context.get_admin_context(), vip['id'])

    def test_update_vip_2_leg(self):
        """Test update of a VIP where Alteon VIP and PIP are different."""

        with self.subnet(cidr='10.0.0.0/24') as subnet:
            with self.subnet(cidr='10.0.1.0/24') as pool_subnet:
                with self.pool(provider='radware',
                               subnet_id=pool_subnet['subnet']['id']) as pool:
                    vip_data = {
                        'name': 'vip1',
                        'subnet_id': subnet['subnet']['id'],
                        'pool_id': pool['pool']['id'],
                        'description': '',
                        'protocol_port': 80,
                        'protocol': 'HTTP',
                        'connection_limit': -1,
                        'admin_state_up': True,
                        'status': constants.PENDING_CREATE,
                        'tenant_id': self._tenant_id,
                        'session_persistence': ''
                    }

                    vip = self.plugin_instance.create_vip(
                        context.get_admin_context(), {'vip': vip_data})

                    self.plugin_instance.update_vip(
                        context.get_admin_context(),
                        vip['id'], {'vip': vip_data})

                    # Test REST calls
                    calls = [
                        mock.call('POST', '/api/workflow/' +
                                  pool['pool']['id'] + '/action/BaseCreate',
                                  mock.ANY, driver.TEMPLATE_HEADER),
                    ]
                    self.driver_rest_call_mock.assert_has_calls(calls)

                    updated_vip = self.plugin_instance.get_vip(
                        context.get_admin_context(), vip['id'])
                    self.assertEqual(updated_vip['status'], constants.ACTIVE)

                    # delete VIP
                    self.plugin_instance.delete_vip(
                        context.get_admin_context(), vip['id'])

    def test_delete_vip_failure(self):
        plugin = self.plugin_instance

        with self.network() as network:
            with self.subnet(network=network) as subnet:
                with self.pool(do_delete=False,
                               provider='radware',
                               subnet_id=subnet['subnet']['id']) as pool:
                    with contextlib.nested(
                        self.member(pool_id=pool['pool']['id'],
                                    do_delete=False),
                        self.member(pool_id=pool['pool']['id'],
                                    address='192.168.1.101',
                                    do_delete=False),
                        self.health_monitor(do_delete=False),
                        self.vip(pool=pool, subnet=subnet, do_delete=False)
                    ) as (mem1, mem2, hm, vip):

                        plugin.create_pool_health_monitor(
                            context.get_admin_context(), hm, pool['pool']['id']
                        )

                        rest_call_function_mock.__dict__.update(
                            {'RESPOND_WITH_ERROR': True})

                        plugin.delete_vip(
                            context.get_admin_context(), vip['vip']['id'])

                        u_vip = plugin.get_vip(
                            context.get_admin_context(), vip['vip']['id'])
                        u_pool = plugin.get_pool(
                            context.get_admin_context(), pool['pool']['id'])
                        u_mem1 = plugin.get_member(
                            context.get_admin_context(), mem1['member']['id'])
                        u_mem2 = plugin.get_member(
                            context.get_admin_context(), mem2['member']['id'])
                        u_phm = plugin.get_pool_health_monitor(
                            context.get_admin_context(),
                            hm['health_monitor']['id'], pool['pool']['id'])

                        self.assertEqual(u_vip['status'], constants.ERROR)
                        self.assertEqual(u_pool['status'], constants.ACTIVE)
                        self.assertEqual(u_mem1['status'], constants.ACTIVE)
                        self.assertEqual(u_mem2['status'], constants.ACTIVE)
                        self.assertEqual(u_phm['status'], constants.ACTIVE)

    def test_delete_vip(self):
        with self.subnet() as subnet:
            with self.pool(provider='radware',
                           do_delete=False,
                           subnet_id=subnet['subnet']['id']) as pool:
                vip_data = {
                    'name': 'vip1',
                    'subnet_id': subnet['subnet']['id'],
                    'pool_id': pool['pool']['id'],
                    'description': '',
                    'protocol_port': 80,
                    'protocol': 'HTTP',
                    'connection_limit': -1,
                    'admin_state_up': True,
                    'status': constants.PENDING_CREATE,
                    'tenant_id': self._tenant_id,
                    'session_persistence': ''
                }

                vip = self.plugin_instance.create_vip(
                    context.get_admin_context(), {'vip': vip_data})

                self.plugin_instance.delete_vip(
                    context.get_admin_context(), vip['id'])

                calls = [
                    mock.call('DELETE', '/api/workflow/' + pool['pool']['id'],
                              None, None)
                ]
                self.driver_rest_call_mock.assert_has_calls(
                    calls, any_order=True)

                self.assertRaises(loadbalancer.VipNotFound,
                                  self.plugin_instance.get_vip,
                                  context.get_admin_context(), vip['id'])

    def test_delete_vip_2_leg(self):
        """Test deletion of a VIP where Alteon VIP and PIP are different."""

        self.driver_rest_call_mock.reset_mock()
        with self.subnet(cidr='10.0.0.0/24') as subnet:
            with self.subnet(cidr='10.0.1.0/24') as pool_subnet:
                with self.pool(provider='radware',
                               do_delete=False,
                               subnet_id=pool_subnet['subnet']['id']) as pool:
                    vip_data = {
                        'name': 'vip1',
                        'subnet_id': subnet['subnet']['id'],
                        'pool_id': pool['pool']['id'],
                        'description': '',
                        'protocol_port': 80,
                        'protocol': 'HTTP',
                        'connection_limit': -1,
                        'admin_state_up': True,
                        'status': constants.PENDING_CREATE,
                        'tenant_id': self._tenant_id,
                        'session_persistence': ''
                    }

                    vip = self.plugin_instance.create_vip(
                        context.get_admin_context(), {'vip': vip_data})

                    self.plugin_instance.delete_vip(
                        context.get_admin_context(), vip['id'])

                    calls = [
                        mock.call('DELETE', '/api/workflow/' +
                                  pool['pool']['id'], None, None)
                    ]
                    self.driver_rest_call_mock.assert_has_calls(calls)

                    # Test that PIP neutron port was deleted
                    pip_port_filter = {
                        'name': ['pip_' + vip['id']],
                    }
                    plugin = manager.NeutronManager.get_plugin()
                    num_ports = plugin.get_ports_count(
                        context.get_admin_context(), filters=pip_port_filter)
                    self.assertTrue(num_ports == 0)

                    self.assertRaises(loadbalancer.VipNotFound,
                                      self.plugin_instance.get_vip,
                                      context.get_admin_context(), vip['id'])

    def test_update_pool(self):
        with self.subnet():
            with self.pool() as pool:
                del pool['pool']['provider']
                del pool['pool']['status']
                self.plugin_instance.update_pool(
                    context.get_admin_context(),
                    pool['pool']['id'], pool)
                pool_db = self.plugin_instance.get_pool(
                    context.get_admin_context(), pool['pool']['id'])
                self.assertEqual(pool_db['status'], constants.PENDING_UPDATE)

    def test_delete_pool_with_vip(self):
        with self.subnet() as subnet:
            with self.pool(provider='radware',
                           do_delete=False,
                           subnet_id=subnet['subnet']['id']) as pool:
                with self.vip(pool=pool, subnet=subnet):
                    self.assertRaises(loadbalancer.PoolInUse,
                                      self.plugin_instance.delete_pool,
                                      context.get_admin_context(),
                                      pool['pool']['id'])

    def test_create_member_with_vip(self):
        with self.subnet() as subnet:
            with self.pool(provider='radware',
                           subnet_id=subnet['subnet']['id']) as p:
                with self.vip(pool=p, subnet=subnet):
                    with self.member(pool_id=p['pool']['id']):
                        calls = [
                            mock.call(
                                'POST', '/api/workflow/' + p['pool']['id'] +
                                '/action/BaseCreate',
                                mock.ANY, driver.TEMPLATE_HEADER
                            ),
                            mock.call(
                                'POST', '/api/workflow/' + p['pool']['id'] +
                                '/action/BaseCreate',
                                mock.ANY, driver.TEMPLATE_HEADER
                            )
                        ]
                        self.driver_rest_call_mock.assert_has_calls(
                            calls, any_order=True)

    def test_create_member_on_different_subnets(self):
        with contextlib.nested(
            self.subnet(),
            self.subnet(cidr='20.0.0.0/24'),
            self.subnet(cidr='30.0.0.0/24')
        ) as (vip_sub, pool_sub, member_sub):
            with self.pool(provider='radware',
                           subnet_id=pool_sub['subnet']['id']) as pool:
                with contextlib.nested(
                    self.port(subnet=vip_sub,
                              fixed_ips=[{'ip_address': '10.0.0.2'}]),
                    self.port(subnet=pool_sub,
                              fixed_ips=[{'ip_address': '20.0.0.2'}]),
                    self.port(subnet=member_sub,
                              fixed_ips=[{'ip_address': '30.0.0.2'}])
                ):
                    with contextlib.nested(
                        self.member(pool_id=pool['pool']['id'],
                                    address='10.0.0.2'),
                        self.member(pool_id=pool['pool']['id'],
                                    address='20.0.0.2'),
                        self.member(pool_id=pool['pool']['id'],
                                    address='30.0.0.2')
                    ) as (member_vip, member_pool, member_out):
                        with self.vip(pool=pool, subnet=vip_sub):
                            calls = [
                                mock.call(
                                    'POST', '/api/workflow/' +
                                    pool['pool']['id'] +
                                    '/action/BaseCreate',
                                    mock.ANY, driver.TEMPLATE_HEADER
                                )
                            ]
                            self.driver_rest_call_mock.assert_has_calls(
                                calls, any_order=True)

                            mock_calls = self.driver_rest_call_mock.mock_calls
                            params = mock_calls[-2][1][2]['parameters']
                            member_subnet_array = params['member_subnet_array']
                            member_mask_array = params['member_mask_array']
                            member_gw_array = params['member_gw_array']
                            self.assertEqual(member_subnet_array,
                                             ['10.0.0.0',
                                              '255.255.255.255',
                                              '30.0.0.0'])
                            self.assertEqual(member_mask_array,
                                             ['255.255.255.0',
                                              '255.255.255.255',
                                              '255.255.255.0'])
                            self.assertEqual(
                                member_gw_array,
                                [pool_sub['subnet']['gateway_ip'],
                                 '255.255.255.255',
                                 pool_sub['subnet']['gateway_ip']])

    def test_create_member_on_different_subnet_no_port(self):
        with contextlib.nested(
            self.subnet(),
            self.subnet(cidr='20.0.0.0/24'),
            self.subnet(cidr='30.0.0.0/24')
        ) as (vip_sub, pool_sub, member_sub):
            with self.pool(provider='radware',
                           subnet_id=pool_sub['subnet']['id']) as pool:
                with self.member(pool_id=pool['pool']['id'],
                                 address='30.0.0.2'):
                    with self.vip(pool=pool, subnet=vip_sub):
                        calls = [
                            mock.call(
                                'POST', '/api/workflow/' +
                                pool['pool']['id'] +
                                '/action/BaseCreate',
                                mock.ANY, driver.TEMPLATE_HEADER
                            )
                        ]
                        self.driver_rest_call_mock.assert_has_calls(
                            calls, any_order=True)

                        mock_calls = self.driver_rest_call_mock.mock_calls
                        params = mock_calls[-2][1][2]['parameters']
                        member_subnet_array = params['member_subnet_array']
                        member_mask_array = params['member_mask_array']
                        member_gw_array = params['member_gw_array']
                        self.assertEqual(member_subnet_array,
                                         ['30.0.0.2'])
                        self.assertEqual(member_mask_array,
                                         ['255.255.255.255'])
                        self.assertEqual(member_gw_array,
                                         [pool_sub['subnet']['gateway_ip']])

    def test_create_member_on_different_subnet_multiple_ports(self):
        cfg.CONF.set_override("allow_overlapping_ips", 'true')
        with self.network() as other_net:
            with contextlib.nested(
                self.subnet(),
                self.subnet(cidr='20.0.0.0/24'),
                self.subnet(cidr='30.0.0.0/24'),
                self.subnet(network=other_net, cidr='30.0.0.0/24')
            ) as (vip_sub, pool_sub, member_sub1, member_sub2):
                with self.pool(provider='radware',
                               subnet_id=pool_sub['subnet']['id']) as pool:
                    with contextlib.nested(
                        self.port(subnet=member_sub1,
                                  fixed_ips=[{'ip_address': '30.0.0.2'}]),
                        self.port(subnet=member_sub2,
                                  fixed_ips=[{'ip_address': '30.0.0.2'}])):
                        with self.member(pool_id=pool['pool']['id'],
                                         address='30.0.0.2'):
                            with self.vip(pool=pool, subnet=vip_sub):
                                calls = [
                                    mock.call(
                                        'POST', '/api/workflow/' +
                                        pool['pool']['id'] +
                                        '/action/BaseCreate',
                                        mock.ANY, driver.TEMPLATE_HEADER
                                    )
                                ]
                                self.driver_rest_call_mock.assert_has_calls(
                                    calls, any_order=True)

                                calls = self.driver_rest_call_mock.mock_calls
                                params = calls[-2][1][2]['parameters']
                                m_sub_array = params['member_subnet_array']
                                m_mask_array = params['member_mask_array']
                                m_gw_array = params['member_gw_array']
                                self.assertEqual(m_sub_array,
                                                 ['30.0.0.2'])
                                self.assertEqual(m_mask_array,
                                                 ['255.255.255.255'])
                                self.assertEqual(
                                    m_gw_array,
                                    [pool_sub['subnet']['gateway_ip']])

    def test_update_member_with_vip(self):
        with self.subnet() as subnet:
            with self.pool(provider='radware',
                           subnet_id=subnet['subnet']['id']) as p:
                with self.member(pool_id=p['pool']['id']) as member:
                    with self.vip(pool=p, subnet=subnet):
                        self.plugin_instance.update_member(
                            context.get_admin_context(),
                            member['member']['id'], member
                        )
                        calls = [
                            mock.call(
                                'POST', '/api/workflow/' + p['pool']['id'] +
                                '/action/BaseCreate',
                                mock.ANY, driver.TEMPLATE_HEADER
                            ),
                            mock.call(
                                'POST', '/api/workflow/' + p['pool']['id'] +
                                '/action/BaseCreate',
                                mock.ANY, driver.TEMPLATE_HEADER
                            )
                        ]
                        self.driver_rest_call_mock.assert_has_calls(
                            calls, any_order=True)

                        updated_member = self.plugin_instance.get_member(
                            context.get_admin_context(),
                            member['member']['id']
                        )

                        updated_member = self.plugin_instance.get_member(
                            context.get_admin_context(),
                            member['member']['id']
                        )
                        self.assertEqual(updated_member['status'],
                                         constants.ACTIVE)

    def test_update_member_without_vip(self):
        with self.subnet():
            with self.pool(provider='radware') as pool:
                with self.member(pool_id=pool['pool']['id']) as member:
                    member['member']['status'] = constants.PENDING_UPDATE
                    updated_member = self.plugin_instance.update_member(
                        context.get_admin_context(),
                        member['member']['id'], member
                    )
                    self.assertEqual(updated_member['status'],
                                     constants.PENDING_UPDATE)

    def test_delete_member_with_vip(self):
        with self.subnet() as subnet:
            with self.pool(provider='radware',
                           subnet_id=subnet['subnet']['id']) as p:
                with self.member(pool_id=p['pool']['id'],
                                 do_delete=False) as m:
                    with self.vip(pool=p, subnet=subnet):

                        # Reset mock and
                        # wait for being sure the member
                        # Changed status from PENDING-CREATE
                        # to ACTIVE

                        self.plugin_instance.delete_member(
                            context.get_admin_context(),
                            m['member']['id']
                        )

                        name, args, kwargs = (
                            self.driver_rest_call_mock.mock_calls[-2]
                        )
                        deletion_post_graph = str(args[2])

                        self.assertTrue(re.search(
                            r'.*\'member_address_array\': \[\].*',
                            deletion_post_graph
                        ))

                        calls = [
                            mock.call(
                                'POST', '/api/workflow/' + p['pool']['id'] +
                                '/action/BaseCreate',
                                mock.ANY, driver.TEMPLATE_HEADER
                            )
                        ]
                        self.driver_rest_call_mock.assert_has_calls(
                            calls, any_order=True)

                        self.assertRaises(loadbalancer.MemberNotFound,
                                          self.plugin_instance.get_member,
                                          context.get_admin_context(),
                                          m['member']['id'])

    def test_delete_member_without_vip(self):
        with self.subnet():
            with self.pool(provider='radware') as p:
                with self.member(pool_id=p['pool']['id'],
                                 do_delete=False) as m:
                    self.plugin_instance.delete_member(
                        context.get_admin_context(), m['member']['id']
                    )
                    self.assertRaises(loadbalancer.MemberNotFound,
                                      self.plugin_instance.get_member,
                                      context.get_admin_context(),
                                      m['member']['id'])

    def test_create_hm_with_vip(self):
        with self.subnet() as subnet:
            with self.health_monitor() as hm:
                with self.pool(provider='radware',
                               subnet_id=subnet['subnet']['id']) as pool:
                    with self.vip(pool=pool, subnet=subnet):

                        self.plugin_instance.create_pool_health_monitor(
                            context.get_admin_context(),
                            hm, pool['pool']['id']
                        )

                        # Test REST calls
                        calls = [
                            mock.call(
                                'POST', '/api/workflow/' + pool['pool']['id'] +
                                '/action/BaseCreate',
                                mock.ANY, driver.TEMPLATE_HEADER
                            ),
                            mock.call(
                                'POST', '/api/workflow/' + pool['pool']['id'] +
                                '/action/BaseCreate',
                                mock.ANY, driver.TEMPLATE_HEADER
                            )
                        ]
                        self.driver_rest_call_mock.assert_has_calls(
                            calls, any_order=True)

                        phm = self.plugin_instance.get_pool_health_monitor(
                            context.get_admin_context(),
                            hm['health_monitor']['id'], pool['pool']['id']
                        )
                        self.assertEqual(phm['status'], constants.ACTIVE)

    def test_delete_pool_hm_with_vip(self):
        with self.subnet() as subnet:
            with self.health_monitor(do_delete=False) as hm:
                with self.pool(provider='radware',
                               subnet_id=subnet['subnet']['id']) as pool:
                    with self.vip(pool=pool, subnet=subnet):
                        self.plugin_instance.create_pool_health_monitor(
                            context.get_admin_context(),
                            hm, pool['pool']['id']
                        )

                        self.plugin_instance.delete_pool_health_monitor(
                            context.get_admin_context(),
                            hm['health_monitor']['id'],
                            pool['pool']['id']
                        )

                        name, args, kwargs = (
                            self.driver_rest_call_mock.mock_calls[-2]
                        )
                        deletion_post_graph = str(args[2])

                        self.assertTrue(re.search(
                            r'.*\'hm_uuid_array\': \[\].*',
                            deletion_post_graph
                        ))

                        calls = [
                            mock.call(
                                'POST', '/api/workflow/' + pool['pool']['id'] +
                                '/action/BaseCreate',
                                mock.ANY, driver.TEMPLATE_HEADER
                            )
                        ]
                        self.driver_rest_call_mock.assert_has_calls(
                            calls, any_order=True)

                        self.assertRaises(
                            loadbalancer.PoolMonitorAssociationNotFound,
                            self.plugin_instance.get_pool_health_monitor,
                            context.get_admin_context(),
                            hm['health_monitor']['id'],
                            pool['pool']['id']
                        )
