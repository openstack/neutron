# Copyright (c) 2014 OpenStack Foundation.
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

import contextlib

import mock
from oslo.config import cfg
import webob.exc

from neutron import context
from neutron.plugins.vmware.dbexts import qos_db
from neutron.plugins.vmware.extensions import qos as ext_qos
from neutron.plugins.vmware import nsxlib
from neutron.tests.unit import test_extensions
from neutron.tests.unit.vmware import NSXEXT_PATH
from neutron.tests.unit.vmware.test_nsx_plugin import NsxPluginV2TestCase


class QoSTestExtensionManager(object):

    def get_resources(self):
        return ext_qos.Qos.get_resources()

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


class TestQoSQueue(NsxPluginV2TestCase):

    def setUp(self, plugin=None):
        cfg.CONF.set_override('api_extensions_path', NSXEXT_PATH)
        super(TestQoSQueue, self).setUp()
        ext_mgr = QoSTestExtensionManager()
        self.ext_api = test_extensions.setup_extensions_middleware(ext_mgr)

    def _create_qos_queue(self, fmt, body, **kwargs):
        qos_queue = self.new_create_request('qos-queues', body)
        if (kwargs.get('set_context') and 'tenant_id' in kwargs):
            # create a specific auth context for this request
            qos_queue.environ['neutron.context'] = context.Context(
                '', kwargs['tenant_id'])

        return qos_queue.get_response(self.ext_api)

    @contextlib.contextmanager
    def qos_queue(self, name='foo', min='0', max='10',
                  qos_marking=None, dscp='0', default=None, no_delete=False):

        body = {'qos_queue': {'tenant_id': 'tenant',
                              'name': name,
                              'min': min,
                              'max': max}}

        if qos_marking:
            body['qos_queue']['qos_marking'] = qos_marking
        if dscp:
            body['qos_queue']['dscp'] = dscp
        if default:
            body['qos_queue']['default'] = default
        res = self._create_qos_queue('json', body)
        qos_queue = self.deserialize('json', res)
        if res.status_int >= 400:
            raise webob.exc.HTTPClientError(code=res.status_int)

        yield qos_queue

        if not no_delete:
            self._delete('qos-queues',
                         qos_queue['qos_queue']['id'])

    def test_create_qos_queue(self):
        with self.qos_queue(name='fake_lqueue', min=34, max=44,
                            qos_marking='untrusted', default=False) as q:
            self.assertEqual(q['qos_queue']['name'], 'fake_lqueue')
            self.assertEqual(q['qos_queue']['min'], 34)
            self.assertEqual(q['qos_queue']['max'], 44)
            self.assertEqual(q['qos_queue']['qos_marking'], 'untrusted')
            self.assertFalse(q['qos_queue']['default'])

    def test_create_trusted_qos_queue(self):
        with mock.patch.object(qos_db.LOG, 'info') as log:
            with mock.patch.object(nsxlib.queue, 'do_request',
                                   return_value={"uuid": "fake_queue"}):
                with self.qos_queue(name='fake_lqueue', min=34, max=44,
                                    qos_marking='trusted', default=False) as q:
                    self.assertIsNone(q['qos_queue']['dscp'])
                    self.assertTrue(log.called)

    def test_create_qos_queue_name_exceeds_40_chars(self):
        name = 'this_is_a_queue_whose_name_is_longer_than_40_chars'
        with self.qos_queue(name=name) as queue:
            # Assert Neutron name is not truncated
            self.assertEqual(queue['qos_queue']['name'], name)

    def test_create_qos_queue_default(self):
        with self.qos_queue(default=True) as q:
            self.assertTrue(q['qos_queue']['default'])

    def test_create_qos_queue_two_default_queues_fail(self):
        with self.qos_queue(default=True):
            body = {'qos_queue': {'tenant_id': 'tenant',
                                  'name': 'second_default_queue',
                                  'default': True}}
            res = self._create_qos_queue('json', body)
            self.assertEqual(res.status_int, 409)

    def test_create_port_with_queue(self):
        with self.qos_queue(default=True) as q1:
            res = self._create_network('json', 'net1', True,
                                       arg_list=(ext_qos.QUEUE,),
                                       queue_id=q1['qos_queue']['id'])
            net1 = self.deserialize('json', res)
            self.assertEqual(net1['network'][ext_qos.QUEUE],
                             q1['qos_queue']['id'])
            device_id = "00fff4d0-e4a8-4a3a-8906-4c4cdafb59f1"
            with self.port(device_id=device_id, do_delete=False) as p:
                self.assertEqual(len(p['port'][ext_qos.QUEUE]), 36)

    def test_create_shared_queue_networks(self):
        with self.qos_queue(default=True, no_delete=True) as q1:
            res = self._create_network('json', 'net1', True,
                                       arg_list=(ext_qos.QUEUE,),
                                       queue_id=q1['qos_queue']['id'])
            net1 = self.deserialize('json', res)
            self.assertEqual(net1['network'][ext_qos.QUEUE],
                             q1['qos_queue']['id'])
            res = self._create_network('json', 'net2', True,
                                       arg_list=(ext_qos.QUEUE,),
                                       queue_id=q1['qos_queue']['id'])
            net2 = self.deserialize('json', res)
            self.assertEqual(net1['network'][ext_qos.QUEUE],
                             q1['qos_queue']['id'])
            device_id = "00fff4d0-e4a8-4a3a-8906-4c4cdafb59f1"
            res = self._create_port('json', net1['network']['id'],
                                    device_id=device_id)
            port1 = self.deserialize('json', res)
            res = self._create_port('json', net2['network']['id'],
                                    device_id=device_id)
            port2 = self.deserialize('json', res)
            self.assertEqual(port1['port'][ext_qos.QUEUE],
                             port2['port'][ext_qos.QUEUE])

            self._delete('ports', port1['port']['id'])
            self._delete('ports', port2['port']['id'])

    def test_remove_queue_in_use_fail(self):
        with self.qos_queue(no_delete=True) as q1:
            res = self._create_network('json', 'net1', True,
                                       arg_list=(ext_qos.QUEUE,),
                                       queue_id=q1['qos_queue']['id'])
            net1 = self.deserialize('json', res)
            device_id = "00fff4d0-e4a8-4a3a-8906-4c4cdafb59f1"
            res = self._create_port('json', net1['network']['id'],
                                    device_id=device_id)
            port = self.deserialize('json', res)
            self._delete('qos-queues', port['port'][ext_qos.QUEUE], 409)

    def test_update_network_new_queue(self):
        with self.qos_queue() as q1:
            res = self._create_network('json', 'net1', True,
                                       arg_list=(ext_qos.QUEUE,),
                                       queue_id=q1['qos_queue']['id'])
            net1 = self.deserialize('json', res)
            with self.qos_queue() as new_q:
                data = {'network': {ext_qos.QUEUE: new_q['qos_queue']['id']}}
                req = self.new_update_request('networks', data,
                                              net1['network']['id'])
                res = req.get_response(self.api)
                net1 = self.deserialize('json', res)
                self.assertEqual(net1['network'][ext_qos.QUEUE],
                                 new_q['qos_queue']['id'])

    def test_update_port_adding_device_id(self):
        with self.qos_queue(no_delete=True) as q1:
            res = self._create_network('json', 'net1', True,
                                       arg_list=(ext_qos.QUEUE,),
                                       queue_id=q1['qos_queue']['id'])
            net1 = self.deserialize('json', res)
            device_id = "00fff4d0-e4a8-4a3a-8906-4c4cdafb59f1"
            res = self._create_port('json', net1['network']['id'])
            port = self.deserialize('json', res)
            self.assertIsNone(port['port'][ext_qos.QUEUE])

            data = {'port': {'device_id': device_id}}
            req = self.new_update_request('ports', data,
                                          port['port']['id'])

            res = req.get_response(self.api)
            port = self.deserialize('json', res)
            self.assertEqual(len(port['port'][ext_qos.QUEUE]), 36)

    def test_get_port_with_qos_not_admin(self):
        body = {'qos_queue': {'tenant_id': 'not_admin',
                              'name': 'foo', 'min': 20, 'max': 20}}
        res = self._create_qos_queue('json', body, tenant_id='not_admin')
        q1 = self.deserialize('json', res)
        res = self._create_network('json', 'net1', True,
                                   arg_list=(ext_qos.QUEUE, 'tenant_id',),
                                   queue_id=q1['qos_queue']['id'],
                                   tenant_id="not_admin")
        net1 = self.deserialize('json', res)
        self.assertEqual(len(net1['network'][ext_qos.QUEUE]), 36)
        res = self._create_port('json', net1['network']['id'],
                                tenant_id='not_admin', set_context=True)

        port = self.deserialize('json', res)
        self.assertNotIn(ext_qos.QUEUE, port['port'])

    def test_dscp_value_out_of_range(self):
        body = {'qos_queue': {'tenant_id': 'admin', 'dscp': '64',
                              'name': 'foo', 'min': 20, 'max': 20}}
        res = self._create_qos_queue('json', body)
        self.assertEqual(res.status_int, 400)

    def test_dscp_value_with_qos_marking_trusted_returns_400(self):
        body = {'qos_queue': {'tenant_id': 'admin', 'dscp': '1',
                              'qos_marking': 'trusted',
                              'name': 'foo', 'min': 20, 'max': 20}}
        res = self._create_qos_queue('json', body)
        self.assertEqual(res.status_int, 400)

    def test_non_admin_cannot_create_queue(self):
        body = {'qos_queue': {'tenant_id': 'not_admin',
                              'name': 'foo', 'min': 20, 'max': 20}}
        res = self._create_qos_queue('json', body, tenant_id='not_admin',
                                     set_context=True)
        self.assertEqual(res.status_int, 403)

    def test_update_port_non_admin_does_not_show_queue_id(self):
        body = {'qos_queue': {'tenant_id': 'not_admin',
                              'name': 'foo', 'min': 20, 'max': 20}}
        res = self._create_qos_queue('json', body, tenant_id='not_admin')
        q1 = self.deserialize('json', res)
        res = self._create_network('json', 'net1', True,
                                   arg_list=(ext_qos.QUEUE,),
                                   tenant_id='not_admin',
                                   queue_id=q1['qos_queue']['id'])

        net1 = self.deserialize('json', res)
        res = self._create_port('json', net1['network']['id'],
                                tenant_id='not_admin', set_context=True)
        port = self.deserialize('json', res)
        device_id = "00fff4d0-e4a8-4a3a-8906-4c4cdafb59f1"
        data = {'port': {'device_id': device_id}}
        neutron_context = context.Context('', 'not_admin')
        port = self._update('ports', port['port']['id'], data,
                            neutron_context=neutron_context)
        self.assertNotIn(ext_qos.QUEUE, port['port'])

    def test_rxtx_factor(self):
        with self.qos_queue(max=10) as q1:

            res = self._create_network('json', 'net1', True,
                                       arg_list=(ext_qos.QUEUE,),
                                       queue_id=q1['qos_queue']['id'])
            net1 = self.deserialize('json', res)
            res = self._create_port('json', net1['network']['id'],
                                    arg_list=(ext_qos.RXTX_FACTOR,),
                                    rxtx_factor=2, device_id='1')
            port = self.deserialize('json', res)
            req = self.new_show_request('qos-queues',
                                        port['port'][ext_qos.QUEUE])
            res = req.get_response(self.ext_api)
            queue = self.deserialize('json', res)
            self.assertEqual(queue['qos_queue']['max'], 20)
