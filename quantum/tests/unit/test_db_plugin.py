# Copyright (c) 2012 OpenStack, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import contextlib
import logging
import mock
import os
import unittest

import quantum
from quantum.api.v2.router import APIRouter
from quantum.common import config
from quantum.common import exceptions as q_exc
from quantum.db import api as db
from quantum.openstack.common import cfg
from quantum.tests.unit.testlib_api import create_request
from quantum.wsgi import Serializer, JSONDeserializer


LOG = logging.getLogger(__name__)

ROOTDIR = os.path.dirname(os.path.dirname(__file__))
ETCDIR = os.path.join(ROOTDIR, 'etc')


def etcdir(*p):
    return os.path.join(ETCDIR, *p)


class QuantumDbPluginV2TestCase(unittest.TestCase):
    def setUp(self):
        super(QuantumDbPluginV2TestCase, self).setUp()

        # NOTE(jkoelker) for a 'pluggable' framework, Quantum sure
        #                doesn't like when the plugin changes ;)
        db._ENGINE = None
        db._MAKER = None

        self._tenant_id = 'test-tenant'

        json_deserializer = JSONDeserializer()
        self._deserializers = {
            'application/json': json_deserializer,
        }

        plugin = 'quantum.db.db_base_plugin_v2.QuantumDbPluginV2'
        # Create the default configurations
        args = ['--config-file', etcdir('quantum.conf.test')]
        config.parse(args=args)
        # Update the plugin
        cfg.CONF.set_override('core_plugin', plugin)
        self.api = APIRouter()

    def tearDown(self):
        super(QuantumDbPluginV2TestCase, self).tearDown()
        # NOTE(jkoelker) for a 'pluggable' framework, Quantum sure
        #                doesn't like when the plugin changes ;)
        db._ENGINE = None
        db._MAKER = None
        cfg.CONF.reset()

    def _req(self, method, resource, data=None, fmt='json', id=None):
        if id:
            path = '/%(resource)s/%(id)s.%(fmt)s' % locals()
        else:
            path = '/%(resource)s.%(fmt)s' % locals()
        content_type = 'application/%s' % fmt
        body = None
        if data:
            body = Serializer().serialize(data, content_type)
        return create_request(path, body, content_type, method)

    def new_create_request(self, resource, data, fmt='json'):
        return self._req('POST', resource, data, fmt)

    def new_list_request(self, resource, fmt='json'):
        return self._req('GET', resource, None, fmt)

    def new_show_request(self, resource, id, fmt='json'):
        return self._req('GET', resource, None, fmt, id=id)

    def new_delete_request(self, resource, id, fmt='json'):
        return self._req('DELETE', resource, None, fmt, id=id)

    def new_update_request(self, resource, data, id, fmt='json'):
        return self._req('PUT', resource, data, fmt, id=id)

    def deserialize(self, content_type, response):
        ctype = 'application/%s' % content_type
        data = self._deserializers[ctype].deserialize(response.body)['body']
        return data

    def _create_network(self, fmt, name, admin_status_up):
        data = {'network': {'name': name,
                            'admin_state_up': admin_status_up,
                            'tenant_id': self._tenant_id}}
        network_req = self.new_create_request('networks', data, fmt)
        return network_req.get_response(self.api)

    def _create_subnet(self, fmt, net_id, gateway_ip, cidr):
        data = {'subnet': {'network_id': net_id,
                           'cidr': cidr,
                           'ip_version': 4}}
        if gateway_ip:
            data['subnet']['gateway_ip'] = gateway_ip

        subnet_req = self.new_create_request('subnets', data, fmt)
        return subnet_req.get_response(self.api)

    def _create_port(self, fmt, net_id, custom_req_body=None,
                     expected_res_status=None, **kwargs):
        content_type = 'application/' + fmt
        data = {'port': {'network_id': net_id,
                         'tenant_id': self._tenant_id}}
        for arg in ('admin_state_up', 'device_id', 'mac_address',
                    'fixed_ips_v4', 'fixed_ips_v6'):
            if arg in kwargs:
                data['port'][arg] = kwargs[arg]

        port_req = self.new_create_request('ports', data, fmt)
        return port_req.get_response(self.api)

    def _make_subnet(self, fmt, network, gateway, cidr):
        res = self._create_subnet(fmt, network['network']['id'],
                                  gateway, cidr)
        return self.deserialize(fmt, res)

    def _make_port(self, fmt, net_id, **kwargs):
        res = self._create_port(fmt, net_id, **kwargs)
        return self.deserialize(fmt, res)

    def _delete(self, collection, id):
        req = self.new_delete_request(collection, id)
        req.get_response(self.api)

    @contextlib.contextmanager
    def network(self, name='net1', admin_status_up=True, fmt='json'):
        res = self._create_network(fmt, name, admin_status_up)
        network = self.deserialize(fmt, res)
        yield network
        self._delete('networks', network['network']['id'])

    @contextlib.contextmanager
    def subnet(self, network=None, gateway=None,
               cidr='10.0.0.0/24', fmt='json'):
        # TODO(anyone) DRY this
        if not network:
            with self.network() as network:
                subnet = self._make_subnet(fmt, network, gateway, cidr)
                yield subnet
                self._delete('subnets', subnet['subnet']['id'])
        else:
            subnet = self._make_subnet(fmt, network, gateway, cidr)
            yield subnet
            self._delete('subnets', subnet['subnet']['id'])

    @contextlib.contextmanager
    def port(self, subnet=None, fmt='json'):
        if not subnet:
            with self.subnet() as subnet:
                net_id = subnet['subnet']['network_id']
                port = self._make_port(fmt, net_id)
                yield port
                self._delete('ports', port['port']['id'])


class TestV2HTTPResponse(QuantumDbPluginV2TestCase):
    def test_create_returns_201(self):
        res = self._create_network('json', 'net2', True)
        self.assertEquals(res.status_int, 201)

    def test_list_returns_200(self):
        req = self.new_list_request('networks')
        res = req.get_response(self.api)
        self.assertEquals(res.status_int, 200)

    def test_show_returns_200(self):
        with self.network() as net:
            req = self.new_show_request('networks', net['network']['id'])
            res = req.get_response(self.api)
            self.assertEquals(res.status_int, 200)

    def test_delete_returns_204(self):
        res = self._create_network('json', 'net1', True)
        net = self.deserialize('json', res)
        req = self.new_delete_request('networks', net['network']['id'])
        res = req.get_response(self.api)
        self.assertEquals(res.status_int, 204)

    def test_update_returns_200(self):
        with self.network() as net:
            req = self.new_update_request('networks',
                                          {'network': {'name': 'steve'}},
                                          net['network']['id'])
            res = req.get_response(self.api)
            self.assertEquals(res.status_int, 200)

    def test_bad_route_404(self):
        req = self.new_list_request('doohickeys')
        res = req.get_response(self.api)
        self.assertEquals(res.status_int, 404)


class TestPortsV2(QuantumDbPluginV2TestCase):

    def test_create_port_json(self):
        keys = [('admin_state_up', True), ('status', 'ACTIVE')]
        with self.port() as port:
            for k, v in keys:
                self.assertEquals(port['port'][k], v)
            self.assertTrue('mac_address' in port['port'])

    def test_list_ports(self):
        with contextlib.nested(self.port(), self.port()) as (port1, port2):
            req = self.new_list_request('ports', 'json')
            port_list = self.deserialize('json', req.get_response(self.api))
            self.assertEqual(len(port_list['ports']), 2)
            ids = [p['id'] for p in port_list['ports']]
            self.assertTrue(port1['port']['id'] in ids)
            self.assertTrue(port2['port']['id'] in ids)

    def test_show_port(self):
        with self.port() as port:
            req = self.new_show_request('ports', port['port']['id'], 'json')
            sport = self.deserialize('json', req.get_response(self.api))
            self.assertEquals(port['port']['id'], sport['port']['id'])

    def test_delete_port(self):
        port_id = None
        with self.port() as port:
            port_id = port['port']['id']
        req = self.new_show_request('port', 'json', port['port']['id'])
        res = req.get_response(self.api)
        self.assertEquals(res.status_int, 404)

    def test_update_port(self):
        with self.port() as port:
            data = {'port': {'admin_state_up': False}}
            req = self.new_update_request('ports', data, port['port']['id'])
            res = self.deserialize('json', req.get_response(self.api))
            self.assertEqual(res['port']['admin_state_up'],
                             data['port']['admin_state_up'])

    def test_delete_network_if_port_exists(self):
        fmt = 'json'
        with self.port() as port:
            net_id = port['port']['network_id']
            req = self.new_delete_request('networks',
                                          port['port']['network_id'])
            res = req.get_response(self.api)
            self.assertEquals(res.status_int, 409)

    def test_requested_duplicate_mac(self):
        fmt = 'json'
        with self.port() as port:
            mac = port['port']['mac_address']
            # check that MAC address matches base MAC
            # TODO(garyk) read base mac from configuration file (CONF)
            base_mac = [0xfa, 0x16, 0x3e]
            base_mac_address = ':'.join(map(lambda x: "%02x" % x, base_mac))
            self.assertTrue(mac.startswith(base_mac_address))
            kwargs = {"mac_address": mac}
            net_id = port['port']['network_id']
            res = self._create_port(fmt, net_id=net_id, **kwargs)
            port2 = self.deserialize(fmt, res)
            self.assertEquals(res.status_int, 409)

    def test_mac_exhaustion(self):
        # rather than actually consuming all MAC (would take a LONG time)
        # we just raise the exception that would result.
        @staticmethod
        def fake_gen_mac(context, net_id):
            raise q_exc.MacAddressGenerationFailure(net_id=net_id)

        fmt = 'json'
        with mock.patch.object(quantum.db.db_base_plugin_v2.QuantumDbPluginV2,
                               '_generate_mac', new=fake_gen_mac):
            res = self._create_network(fmt=fmt, name='net1',
                                       admin_status_up=True)
            network = self.deserialize(fmt, res)
            net_id = network['network']['id']
            res = self._create_port(fmt, net_id=net_id)
            self.assertEquals(res.status_int, 503)


class TestNetworksV2(QuantumDbPluginV2TestCase):
    # NOTE(cerberus): successful network update and delete are
    #                 effectively tested above
    def test_create_network(self):
        name = 'net1'
        keys = [('subnets', []), ('name', name), ('admin_state_up', True),
                ('status', 'ACTIVE')]
        with self.network(name=name) as net:
            for k, v in keys:
                self.assertEquals(net['network'][k], v)

    def test_list_networks(self):
        with self.network(name='net1') as net1:
            with self.network(name='net2') as net2:
                req = self.new_list_request('networks')
                res = self.deserialize('json', req.get_response(self.api))

                self.assertEquals(res['networks'][0]['name'],
                                  net1['network']['name'])
                self.assertEquals(res['networks'][1]['name'],
                                  net2['network']['name'])

    def test_show_network(self):
        with self.network(name='net1') as net:
            req = self.new_show_request('networks', net['network']['id'])
            res = self.deserialize('json', req.get_response(self.api))
            self.assertEquals(res['network']['name'],
                              net['network']['name'])


class TestSubnetsV2(QuantumDbPluginV2TestCase):

    def test_create_subnet(self):
        gateway = '10.0.0.1'
        cidr = '10.0.0.0/24'
        keys = [('ip_version', 4), ('gateway_ip', gateway),
                ('cidr', cidr)]
        with self.subnet(gateway=gateway, cidr=cidr) as subnet:
            for k, v in keys:
                self.assertEquals(subnet['subnet'][k], v)

    def test_create_subnet_defaults(self):
        generated_gateway = '10.0.0.1'
        cidr = '10.0.0.0/24'
        keys = [('ip_version', 4), ('gateway_ip', generated_gateway),
                ('cidr', cidr)]
        # intentionally not passing gateway in
        with self.subnet(cidr=cidr) as subnet:
            for k, v in keys:
                self.assertEquals(subnet['subnet'][k], v)

    def test_update_subnet(self):
        with self.subnet() as subnet:
            data = {'subnet': {'gateway_ip': '11.0.0.1'}}
            req = self.new_update_request('subnets', data,
                                          subnet['subnet']['id'])
            res = self.deserialize('json', req.get_response(self.api))
            self.assertEqual(res['subnet']['gateway_ip'],
                             data['subnet']['gateway_ip'])

    def test_show_subnet(self):
        with self.network() as network:
            with self.subnet(network=network) as subnet:
                req = self.new_show_request('subnets',
                                            subnet['subnet']['id'])
                res = self.deserialize('json', req.get_response(self.api))
                self.assertEquals(res['subnet']['id'],
                                  subnet['subnet']['id'])
                self.assertEquals(res['subnet']['network_id'],
                                  network['network']['id'])

    def test_list_subnets(self):
        # NOTE(jkoelker) This would be a good place to use contextlib.nested
        #                or just drop 2.6 support ;)
        with self.network() as network:
            with self.subnet(network=network, gateway='10.0.0.1',
                             cidr='10.0.1.0/24') as subnet:
                with self.subnet(network=network, gateway='10.0.1.1',
                                 cidr='10.0.1.0/24') as subnet2:
                    req = self.new_list_request('subnets')
                    res = self.deserialize('json',
                                           req.get_response(self.api))
                    res1 = res['subnets'][0]
                    res2 = res['subnets'][1]
                    self.assertEquals(res1['cidr'],
                                      subnet['subnet']['cidr'])
                    self.assertEquals(res2['cidr'],
                                      subnet2['subnet']['cidr'])
