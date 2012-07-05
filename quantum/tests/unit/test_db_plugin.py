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
import random
import unittest2
import webob.exc

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


class QuantumDbPluginV2TestCase(unittest2.TestCase):
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
        cfg.CONF.set_override('base_mac', "12:34:56:78:90:ab")
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

    def _create_subnet(self, fmt, net_id, gateway_ip, cidr,
                       allocation_pools=None, ip_version=4):
        data = {'subnet': {'network_id': net_id,
                           'cidr': cidr,
                           'ip_version': ip_version}}
        if gateway_ip:
            data['subnet']['gateway_ip'] = gateway_ip
        if allocation_pools:
            data['subnet']['allocation_pools'] = allocation_pools
        subnet_req = self.new_create_request('subnets', data, fmt)
        return subnet_req.get_response(self.api)

    def _create_port(self, fmt, net_id, custom_req_body=None,
                     expected_res_status=None, **kwargs):
        content_type = 'application/' + fmt
        data = {'port': {'network_id': net_id,
                         'tenant_id': self._tenant_id}}
        for arg in ('admin_state_up', 'device_id', 'mac_address', 'fixed_ips'):
            # Arg must be present and not empty
            if arg in kwargs and kwargs[arg]:
                data['port'][arg] = kwargs[arg]

        port_req = self.new_create_request('ports', data, fmt)
        return port_req.get_response(self.api)

    def _make_subnet(self, fmt, network, gateway, cidr,
                     allocation_pools=None, ip_version=4):
        res = self._create_subnet(fmt,
                                  network['network']['id'],
                                  gateway,
                                  cidr,
                                  allocation_pools=allocation_pools,
                                  ip_version=ip_version)
        # Things can go wrong - raise HTTP exc with res code only
        # so it can be caught by unit tests
        if res.status_int >= 400:
            raise webob.exc.HTTPClientError(code=res.status_int)
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
    def subnet(self, network=None,
               gateway_ip=None,
               cidr='10.0.0.0/24',
               fmt='json',
               ip_version=4,
               allocation_pools=None):
        # TODO(anyone) DRY this
        # NOTE(salvatore-orlando): we can pass the network object
        # to gen function anyway, and then avoid the repetition
        if not network:
            with self.network() as network:
                subnet = self._make_subnet(fmt,
                                           network,
                                           gateway_ip,
                                           cidr,
                                           allocation_pools,
                                           ip_version)
                yield subnet
                self._delete('subnets', subnet['subnet']['id'])
        else:
            subnet = self._make_subnet(fmt,
                                       network,
                                       gateway_ip,
                                       cidr,
                                       allocation_pools,
                                       ip_version)
            yield subnet
            self._delete('subnets', subnet['subnet']['id'])

    @contextlib.contextmanager
    def port(self, subnet=None, fixed_ips=None, fmt='json'):
        if not subnet:
            with self.subnet() as subnet:
                net_id = subnet['subnet']['network_id']
                port = self._make_port(fmt, net_id, fixed_ips=fixed_ips)
                yield port
                self._delete('ports', port['port']['id'])
        else:
            net_id = subnet['subnet']['network_id']
            port = self._make_port(fmt, net_id, fixed_ips=fixed_ips)
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
            ips = port['port']['fixed_ips']
            self.assertEquals(len(ips), 1)
            self.assertEquals(ips[0]['ip_address'], '10.0.0.2')

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

    def test_update_port_delete_ip(self):
        with self.subnet() as subnet:
            with self.port(subnet=subnet) as port:
                data = {'port': {'admin_state_up': False,
                                 'fixed_ips': []}}
                req = self.new_update_request('ports',
                                              data, port['port']['id'])
                res = self.deserialize('json', req.get_response(self.api))
                self.assertEqual(res['port']['admin_state_up'],
                                 data['port']['admin_state_up'])
                self.assertEqual(res['port']['fixed_ips'],
                                 data['port']['fixed_ips'])

    def test_update_port_update_ip(self):
        """Test update of port IP.

        Check that a configured IP 10.0.0.2 is replaced by 10.0.0.10.
        """
        with self.subnet() as subnet:
            with self.port(subnet=subnet) as port:
                ips = port['port']['fixed_ips']
                self.assertEquals(len(ips), 1)
                self.assertEquals(ips[0]['ip_address'], '10.0.0.2')
                self.assertEquals(ips[0]['subnet_id'], subnet['subnet']['id'])
                data = {'port': {'fixed_ips': [{'subnet_id':
                                                subnet['subnet']['id'],
                                                'ip_address': "10.0.0.10"}]}}
                req = self.new_update_request('ports', data,
                                              port['port']['id'])
                res = self.deserialize('json', req.get_response(self.api))
                ips = res['port']['fixed_ips']
                self.assertEquals(len(ips), 1)
                self.assertEquals(ips[0]['ip_address'], '10.0.0.10')
                self.assertEquals(ips[0]['subnet_id'], subnet['subnet']['id'])

    def test_update_port_update_ips(self):
        """Update IP and generate new IP on port.

        Check a port update with the specified subnet_id's. A IP address
        will be allocated for each subnet_id.
        """
        with self.subnet() as subnet:
            with self.port(subnet=subnet) as port:
                data = {'port': {'admin_state_up': False,
                                 'fixed_ips': [{'subnet_id':
                                                subnet['subnet']['id']}]}}
                req = self.new_update_request('ports', data,
                                              port['port']['id'])
                res = self.deserialize('json', req.get_response(self.api))
                self.assertEqual(res['port']['admin_state_up'],
                                 data['port']['admin_state_up'])
                ips = res['port']['fixed_ips']
                self.assertEquals(len(ips), 1)
                self.assertEquals(ips[0]['ip_address'], '10.0.0.2')
                self.assertEquals(ips[0]['subnet_id'], subnet['subnet']['id'])

    def test_update_port_add_additional_ip(self):
        """Test update of port with additional IP."""
        with self.subnet() as subnet:
            with self.port(subnet=subnet) as port:
                data = {'port': {'admin_state_up': False,
                                 'fixed_ips': [{'subnet_id':
                                                subnet['subnet']['id']},
                                               {'subnet_id':
                                                subnet['subnet']['id']}]}}
                req = self.new_update_request('ports', data,
                                              port['port']['id'])
                res = self.deserialize('json', req.get_response(self.api))
                self.assertEqual(res['port']['admin_state_up'],
                                 data['port']['admin_state_up'])
                ips = res['port']['fixed_ips']
                self.assertEquals(len(ips), 2)
                self.assertEquals(ips[0]['ip_address'], '10.0.0.2')
                self.assertEquals(ips[0]['subnet_id'], subnet['subnet']['id'])
                self.assertEquals(ips[1]['ip_address'], '10.0.0.3')
                self.assertEquals(ips[1]['subnet_id'], subnet['subnet']['id'])

    def test_requested_duplicate_mac(self):
        fmt = 'json'
        with self.port() as port:
            mac = port['port']['mac_address']
            # check that MAC address matches base MAC
            base_mac = cfg.CONF.base_mac[0:2]
            self.assertTrue(mac.startswith(base_mac))
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

    def test_requested_duplicate_ip(self):
        fmt = 'json'
        with self.subnet() as subnet:
            with self.port(subnet=subnet) as port:
                ips = port['port']['fixed_ips']
                self.assertEquals(len(ips), 1)
                self.assertEquals(ips[0]['ip_address'], '10.0.0.2')
                self.assertEquals(ips[0]['subnet_id'], subnet['subnet']['id'])
                # Check configuring of duplicate IP
                kwargs = {"fixed_ips": [{'subnet_id': subnet['subnet']['id'],
                                         'ip_address': ips[0]['ip_address']}]}
                net_id = port['port']['network_id']
                res = self._create_port(fmt, net_id=net_id, **kwargs)
                port2 = self.deserialize(fmt, res)
                self.assertEquals(res.status_int, 409)

    def test_requested_subnet_delete(self):
        fmt = 'json'
        with self.subnet() as subnet:
            with self.port(subnet=subnet) as port:
                ips = port['port']['fixed_ips']
                self.assertEquals(len(ips), 1)
                self.assertEquals(ips[0]['ip_address'], '10.0.0.2')
                self.assertEquals(ips[0]['subnet_id'], subnet['subnet']['id'])
                req = self.new_delete_request('subnet',
                                              subnet['subnet']['id'])
                res = req.get_response(self.api)
                self.assertEquals(res.status_int, 404)

    def test_requested_subnet_id(self):
        fmt = 'json'
        with self.subnet() as subnet:
            with self.port(subnet=subnet) as port:
                ips = port['port']['fixed_ips']
                self.assertEquals(len(ips), 1)
                self.assertEquals(ips[0]['ip_address'], '10.0.0.2')
                self.assertEquals(ips[0]['subnet_id'], subnet['subnet']['id'])
                # Request a IP from specific subnet
                kwargs = {"fixed_ips": [{'subnet_id': subnet['subnet']['id']}]}
                net_id = port['port']['network_id']
                res = self._create_port(fmt, net_id=net_id, **kwargs)
                port2 = self.deserialize(fmt, res)
                ips = port2['port']['fixed_ips']
                self.assertEquals(len(ips), 1)
                self.assertEquals(ips[0]['ip_address'], '10.0.0.3')
                self.assertEquals(ips[0]['subnet_id'], subnet['subnet']['id'])

    def test_requested_subnet_id_not_on_network(self):
        fmt = 'json'
        with self.subnet() as subnet:
            with self.port(subnet=subnet) as port:
                # Create new network
                res = self._create_network(fmt=fmt, name='net2',
                                           admin_status_up=True)
                network2 = self.deserialize(fmt, res)
                subnet2 = self._make_subnet(fmt, network2, "1.1.1.1",
                                            "1.1.1.0/24", ip_version=4)
                net_id = port['port']['network_id']
                # Request a IP from specific subnet
                kwargs = {"fixed_ips": [{'subnet_id':
                                         subnet2['subnet']['id']}]}
                net_id = port['port']['network_id']
                res = self._create_port(fmt, net_id=net_id, **kwargs)
                self.assertEquals(res.status_int, 400)

    def test_requested_subnet_id_v4_and_v6(self):
        fmt = 'json'
        with self.subnet() as subnet:
                # Get a IPv4 and IPv6 address
                net_id = subnet['subnet']['network_id']
                res = self._create_subnet(fmt, net_id=net_id,
                                          cidr='2607:f0d0:1002:51::0/124',
                                          ip_version=6, gateway_ip=None)
                subnet2 = self.deserialize(fmt, res)
                kwargs = {"fixed_ips":
                          [{'subnet_id': subnet['subnet']['id']},
                           {'subnet_id': subnet2['subnet']['id']}]}
                res = self._create_port(fmt, net_id=net_id, **kwargs)
                port3 = self.deserialize(fmt, res)
                ips = port3['port']['fixed_ips']
                self.assertEquals(len(ips), 2)
                self.assertEquals(ips[0]['ip_address'], '10.0.0.2')
                self.assertEquals(ips[0]['subnet_id'], subnet['subnet']['id'])
                self.assertEquals(ips[1]['ip_address'], '2607:f0d0:1002:51::2')
                self.assertEquals(ips[1]['subnet_id'], subnet2['subnet']['id'])
                res = self._create_port(fmt, net_id=net_id)
                port3 = self.deserialize(fmt, res)
                # Check that a v4 and a v6 address are allocated
                ips = port3['port']['fixed_ips']
                self.assertEquals(len(ips), 2)
                self.assertEquals(ips[0]['ip_address'], '10.0.0.3')
                self.assertEquals(ips[0]['subnet_id'], subnet['subnet']['id'])
                self.assertEquals(ips[1]['ip_address'], '2607:f0d0:1002:51::3')
                self.assertEquals(ips[1]['subnet_id'], subnet2['subnet']['id'])

    def test_range_allocation(self):
        fmt = 'json'
        with self.subnet(gateway_ip='10.0.0.3',
                         cidr='10.0.0.0/29') as subnet:
                kwargs = {"fixed_ips":
                          [{'subnet_id': subnet['subnet']['id']},
                           {'subnet_id': subnet['subnet']['id']},
                           {'subnet_id': subnet['subnet']['id']},
                           {'subnet_id': subnet['subnet']['id']},
                           {'subnet_id': subnet['subnet']['id']}]}
                net_id = subnet['subnet']['network_id']
                res = self._create_port(fmt, net_id=net_id, **kwargs)
                port = self.deserialize(fmt, res)
                ips = port['port']['fixed_ips']
                self.assertEquals(len(ips), 5)
                alloc = ['10.0.0.1', '10.0.0.2', '10.0.0.4', '10.0.0.5',
                         '10.0.0.6']
                for i in range(len(alloc)):
                    self.assertEquals(ips[i]['ip_address'], alloc[i])
                    self.assertEquals(ips[i]['subnet_id'],
                                      subnet['subnet']['id'])
        with self.subnet(gateway_ip='11.0.0.6',
                         cidr='11.0.0.0/29') as subnet:
                kwargs = {"fixed_ips":
                          [{'subnet_id': subnet['subnet']['id']},
                           {'subnet_id': subnet['subnet']['id']},
                           {'subnet_id': subnet['subnet']['id']},
                           {'subnet_id': subnet['subnet']['id']},
                           {'subnet_id': subnet['subnet']['id']}]}
                net_id = subnet['subnet']['network_id']
                res = self._create_port(fmt, net_id=net_id, **kwargs)
                port = self.deserialize(fmt, res)
                ips = port['port']['fixed_ips']
                self.assertEquals(len(ips), 5)
                alloc = ['11.0.0.1', '11.0.0.2', '11.0.0.3', '11.0.0.4',
                         '11.0.0.5']
                for i in range(len(alloc)):
                    self.assertEquals(ips[i]['ip_address'], alloc[i])
                    self.assertEquals(ips[i]['subnet_id'],
                                      subnet['subnet']['id'])

    def test_requested_invalid_fixed_ips(self):
        fmt = 'json'
        with self.subnet() as subnet:
            with self.port(subnet=subnet) as port:
                ips = port['port']['fixed_ips']
                self.assertEquals(len(ips), 1)
                self.assertEquals(ips[0]['ip_address'], '10.0.0.2')
                self.assertEquals(ips[0]['subnet_id'], subnet['subnet']['id'])
                # Test invalid subnet_id
                kwargs = {"fixed_ips":
                          [{'subnet_id': subnet['subnet']['id']},
                           {'subnet_id':
                            '00000000-ffff-ffff-ffff-000000000000'}]}
                net_id = port['port']['network_id']
                res = self._create_port(fmt, net_id=net_id, **kwargs)
                port2 = self.deserialize(fmt, res)
                self.assertEquals(res.status_int, 404)

                # Test invalid IP address on specified subnet_id
                kwargs = {"fixed_ips":
                          [{'subnet_id': subnet['subnet']['id'],
                            'ip_address': '1.1.1.1'}]}
                net_id = port['port']['network_id']
                res = self._create_port(fmt, net_id=net_id, **kwargs)
                port2 = self.deserialize(fmt, res)
                self.assertEquals(res.status_int, 400)

                # Test invalid addresses - IP's not on subnet or network
                # address or broadcast address
                bad_ips = ['1.1.1.1', '10.0.0.0', '10.0.0.255']
                net_id = port['port']['network_id']
                for ip in bad_ips:
                    kwargs = {"fixed_ips": [{'ip_address': ip}]}
                    res = self._create_port(fmt, net_id=net_id, **kwargs)
                    port2 = self.deserialize(fmt, res)
                    self.assertEquals(res.status_int, 400)

                # Enable allocation of gateway address
                kwargs = {"fixed_ips":
                          [{'subnet_id': subnet['subnet']['id'],
                            'ip_address': '10.0.0.1'}]}
                net_id = port['port']['network_id']
                res = self._create_port(fmt, net_id=net_id, **kwargs)
                port2 = self.deserialize(fmt, res)
                ips = port2['port']['fixed_ips']
                self.assertEquals(len(ips), 1)
                self.assertEquals(ips[0]['ip_address'], '10.0.0.1')
                self.assertEquals(ips[0]['subnet_id'], subnet['subnet']['id'])
                self._delete('ports', port2['port']['id'])

    def test_requested_split(self):
        fmt = 'json'
        with self.subnet() as subnet:
            with self.port(subnet=subnet) as port:
                ips = port['port']['fixed_ips']
                self.assertEquals(len(ips), 1)
                self.assertEquals(ips[0]['ip_address'], '10.0.0.2')
                self.assertEquals(ips[0]['subnet_id'], subnet['subnet']['id'])
                # Allocate specific IP
                kwargs = {"fixed_ips": [{'subnet_id': subnet['subnet']['id'],
                                         'ip_address': '10.0.0.5'}]}
                net_id = port['port']['network_id']
                res = self._create_port(fmt, net_id=net_id, **kwargs)
                port2 = self.deserialize(fmt, res)
                ips = port2['port']['fixed_ips']
                self.assertEquals(len(ips), 1)
                self.assertEquals(ips[0]['ip_address'], '10.0.0.5')
                self.assertEquals(ips[0]['subnet_id'], subnet['subnet']['id'])
                # Allocate specific IP's
                allocated = ['10.0.0.3', '10.0.0.4', '10.0.0.6']
                for a in allocated:
                    res = self._create_port(fmt, net_id=net_id)
                    port2 = self.deserialize(fmt, res)
                    ips = port2['port']['fixed_ips']
                    self.assertEquals(len(ips), 1)
                    self.assertEquals(ips[0]['ip_address'], a)
                    self.assertEquals(ips[0]['subnet_id'],
                                      subnet['subnet']['id'])

    def test_requested_ips_only(self):
        fmt = 'json'
        with self.subnet() as subnet:
            with self.port(subnet=subnet) as port:
                ips = port['port']['fixed_ips']
                self.assertEquals(len(ips), 1)
                self.assertEquals(ips[0]['ip_address'], '10.0.0.2')
                self.assertEquals(ips[0]['subnet_id'], subnet['subnet']['id'])
                ips_only = ['10.0.0.18', '10.0.0.20', '10.0.0.22', '10.0.0.21',
                            '10.0.0.3', '10.0.0.17', '10.0.0.19']
                for i in ips_only:
                    kwargs = {"fixed_ips": [{'ip_address': i}]}
                    net_id = port['port']['network_id']
                    res = self._create_port(fmt, net_id=net_id, **kwargs)
                    port = self.deserialize(fmt, res)
                    ips = port['port']['fixed_ips']
                    self.assertEquals(len(ips), 1)
                    self.assertEquals(ips[0]['ip_address'], i)
                    self.assertEquals(ips[0]['subnet_id'],
                                      subnet['subnet']['id'])

    def test_recycling(self):
        fmt = 'json'
        with self.subnet(cidr='10.0.1.0/24') as subnet:
            with self.port(subnet=subnet) as port:
                ips = port['port']['fixed_ips']
                self.assertEquals(len(ips), 1)
                self.assertEquals(ips[0]['ip_address'], '10.0.1.2')
                self.assertEquals(ips[0]['subnet_id'], subnet['subnet']['id'])
                net_id = port['port']['network_id']
                ports = []
                for i in range(16 - 3):
                    res = self._create_port(fmt, net_id=net_id)
                    p = self.deserialize(fmt, res)
                    ports.append(p)
                for i in range(16 - 3):
                    x = random.randrange(0, len(ports), 1)
                    p = ports.pop(x)
                    self._delete('ports', p['port']['id'])
                res = self._create_port(fmt, net_id=net_id)
                port = self.deserialize(fmt, res)
                ips = port['port']['fixed_ips']
                self.assertEquals(len(ips), 1)
                self.assertEquals(ips[0]['ip_address'], '10.0.1.3')
                self.assertEquals(ips[0]['subnet_id'], subnet['subnet']['id'])


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

    def _test_create_subnet(self, network=None, **kwargs):
        keys = kwargs.copy()
        keys.setdefault('cidr', '10.0.0.0/24')
        keys.setdefault('ip_version', 4)
        with self.subnet(network=network, **keys) as subnet:
            # verify the response has each key with the correct value
            for k in keys:
                self.assertIn(k, subnet['subnet'])
                self.assertEquals(subnet['subnet'][k], keys[k])
            return subnet

    def test_create_subnet(self):
        gateway_ip = '10.0.0.1'
        cidr = '10.0.0.0/24'
        self._test_create_subnet(gateway_ip=gateway_ip,
                                 cidr=cidr)

    def test_create_two_subnets(self):
        gateway_ips = ['10.0.0.1', '10.0.1.1']
        cidrs = ['10.0.0.0/24', '10.0.1.0/24']
        with self.network() as network:
            with self.subnet(network=network,
                             gateway_ip=gateway_ips[0],
                             cidr=cidrs[0]):
                with self.subnet(network=network,
                                 gateway_ip=gateway_ips[1],
                                 cidr=cidrs[1]):
                    net_req = self.new_show_request('networks',
                                                    network['network']['id'])
                    raw_res = net_req.get_response(self.api)
                    net_res = self.deserialize('json', raw_res)
                    for subnet_id in net_res['network']['subnets']:
                        sub_req = self.new_show_request('subnets', subnet_id)
                        raw_res = sub_req.get_response(self.api)
                        sub_res = self.deserialize('json', raw_res)
                        self.assertIn(sub_res['subnet']['cidr'], cidrs)
                        self.assertIn(sub_res['subnet']['gateway_ip'],
                                      gateway_ips)

    def test_create_two_subnets_same_cidr_returns_400(self):
        gateway_ip_1 = '10.0.0.1'
        cidr_1 = '10.0.0.0/24'
        gateway_ip_2 = '10.0.0.10'
        cidr_2 = '10.0.0.0/24'
        with self.network() as network:
            with self.subnet(network=network,
                             gateway_ip=gateway_ip_1,
                             cidr=cidr_1):
                with self.assertRaises(
                        webob.exc.HTTPClientError) as ctx_manager:
                    with self.subnet(network=network,
                                     gateway_ip=gateway_ip_2,
                                     cidr=cidr_2):
                        pass
                self.assertEquals(ctx_manager.exception.code, 400)

    def test_delete_subnet(self):
        gateway_ip = '10.0.0.1'
        cidr = '10.0.0.0/24'
        fmt = 'json'
        # Create new network
        res = self._create_network(fmt=fmt, name='net',
                                   admin_status_up=True)
        network = self.deserialize(fmt, res)
        subnet = self._make_subnet(fmt, network, gateway_ip,
                                   cidr, ip_version=4)
        req = self.new_delete_request('subnets', subnet['subnet']['id'])
        res = req.get_response(self.api)
        self.assertEquals(res.status_int, 204)

    def test_delete_network(self):
        gateway_ip = '10.0.0.1'
        cidr = '10.0.0.0/24'
        fmt = 'json'
        # Create new network
        res = self._create_network(fmt=fmt, name='net',
                                   admin_status_up=True)
        network = self.deserialize(fmt, res)
        subnet = self._make_subnet(fmt, network, gateway_ip,
                                   cidr, ip_version=4)
        req = self.new_delete_request('networks', network['network']['id'])
        res = req.get_response(self.api)
        self.assertEquals(res.status_int, 204)

    def test_create_subnet_defaults(self):
        gateway = '10.0.0.1'
        cidr = '10.0.0.0/24'
        allocation_pools = [{'start': '10.0.0.2',
                             'end': '10.0.0.254'}]
        subnet = self._test_create_subnet()
        # verify cidr & gw have been correctly generated
        self.assertEquals(subnet['subnet']['cidr'], cidr)
        self.assertEquals(subnet['subnet']['gateway_ip'], gateway)
        self.assertEquals(subnet['subnet']['allocation_pools'],
                          allocation_pools)

    def test_create_subnet_with_allocation_pool(self):
        gateway_ip = '10.0.0.1'
        cidr = '10.0.0.0/24'
        allocation_pools = [{'start': '10.0.0.2',
                             'end': '10.0.0.100'}]
        self._test_create_subnet(gateway_ip=gateway_ip,
                                 cidr=cidr,
                                 allocation_pools=allocation_pools)

    def test_create_subnet_with_v6_allocation_pool(self):
        gateway_ip = 'fe80::1'
        cidr = 'fe80::0/80'
        allocation_pools = [{'start': 'fe80::2',
                             'end': 'fe80::ffff:fffa:ffff'}]
        self._test_create_subnet(gateway_ip=gateway_ip,
                                 cidr=cidr,
                                 allocation_pools=allocation_pools)

    def test_create_subnet_with_large_allocation_pool(self):
        gateway_ip = '10.0.0.1'
        cidr = '10.0.0.0/8'
        allocation_pools = [{'start': '10.0.0.2',
                             'end': '10.0.0.100'},
                            {'start': '10.1.0.0',
                             'end': '10.200.0.100'}]
        self._test_create_subnet(gateway_ip=gateway_ip,
                                 cidr=cidr,
                                 allocation_pools=allocation_pools)

    def test_create_subnet_multiple_allocation_pools(self):
        gateway_ip = '10.0.0.1'
        cidr = '10.0.0.0/24'
        allocation_pools = [{'start': '10.0.0.2',
                             'end': '10.0.0.100'},
                            {'start': '10.0.0.110',
                             'end': '10.0.0.150'}]
        self._test_create_subnet(gateway_ip=gateway_ip,
                                 cidr=cidr,
                                 allocation_pools=allocation_pools)

    def test_create_subnet_gateway_in_allocation_pool_returns_409(self):
        gateway_ip = '10.0.0.50'
        cidr = '10.0.0.0/24'
        allocation_pools = [{'start': '10.0.0.1',
                             'end': '10.0.0.100'}]
        with self.assertRaises(webob.exc.HTTPClientError) as ctx_manager:
            self._test_create_subnet(gateway_ip=gateway_ip,
                                     cidr=cidr,
                                     allocation_pools=allocation_pools)
        self.assertEquals(ctx_manager.exception.code, 409)

    def test_create_subnet_overlapping_allocation_pools_returns_409(self):
        gateway_ip = '10.0.0.1'
        cidr = '10.0.0.0/24'
        allocation_pools = [{'start': '10.0.0.2',
                             'end': '10.0.0.150'},
                            {'start': '10.0.0.140',
                             'end': '10.0.0.180'}]
        with self.assertRaises(webob.exc.HTTPClientError) as ctx_manager:
            self._test_create_subnet(gateway_ip=gateway_ip,
                                     cidr=cidr,
                                     allocation_pools=allocation_pools)
        self.assertEquals(ctx_manager.exception.code, 409)

    def test_create_subnet_invalid_allocation_pool_returns_400(self):
        gateway_ip = '10.0.0.1'
        cidr = '10.0.0.0/24'
        allocation_pools = [{'start': '10.0.0.2',
                             'end': '10.0.0.256'}]
        with self.assertRaises(webob.exc.HTTPClientError) as ctx_manager:
            self._test_create_subnet(gateway_ip=gateway_ip,
                                     cidr=cidr,
                                     allocation_pools=allocation_pools)
        self.assertEquals(ctx_manager.exception.code, 400)

    def test_create_subnet_out_of_range_allocation_pool_returns_400(self):
        gateway_ip = '10.0.0.1'
        cidr = '10.0.0.0/24'
        allocation_pools = [{'start': '10.0.0.2',
                             'end': '10.0.1.6'}]
        with self.assertRaises(webob.exc.HTTPClientError) as ctx_manager:
            self._test_create_subnet(gateway_ip=gateway_ip,
                                     cidr=cidr,
                                     allocation_pools=allocation_pools)
        self.assertEquals(ctx_manager.exception.code, 400)

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
            with self.subnet(network=network, gateway_ip='10.0.0.1',
                             cidr='10.0.0.0/24') as subnet:
                with self.subnet(network=network, gateway_ip='10.0.1.1',
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
