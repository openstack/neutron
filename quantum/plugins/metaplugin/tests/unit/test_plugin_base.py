# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2012, Nachi Ueno, NTT MCL, Inc.
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

import os

import mox
import mock
import uuid

from quantum.common import config
from quantum.common.exceptions import NotImplementedError
from quantum.db import api as db
from quantum.openstack.common import cfg
from quantum.plugins.metaplugin.meta_quantum_plugin import MetaPluginV2
from quantum.plugins.metaplugin.proxy_quantum_plugin import ProxyPluginV2
from quantum.plugins.metaplugin.tests.unit.basetest import BaseMetaTest
from quantum.plugins.metaplugin.tests.unit import fake_plugin
from quantum import context

CONF_FILE = ""
ROOTDIR = os.path.dirname(os.path.dirname(__file__))
ETCDIR = os.path.join(ROOTDIR, 'etc')
META_PATH = "quantum.plugins.metaplugin"
FAKE_PATH = "%s.tests.unit" % META_PATH
PROXY_PATH = "%s.proxy_quantum_plugin.ProxyPluginV2" % META_PATH
PLUGIN_LIST = \
    'fake1:%s.fake_plugin.Fake1,fake2:%s.fake_plugin.Fake2,proxy:%s' % \
    (FAKE_PATH, FAKE_PATH, PROXY_PATH)


def etcdir(*p):
    return os.path.join(ETCDIR, *p)


class PluginBaseTest(BaseMetaTest):
    """Class conisting of MetaQuantumPluginV2 unit tests"""

    def setUp(self):
        super(PluginBaseTest, self).setUp()
        db._ENGINE = None
        db._MAKER = None
        self.fake_tenant_id = str(uuid.uuid4())
        self.context = context.get_admin_context()

        args = ['--config-file', etcdir('quantum.conf.test')]
        #config.parse(args=args)
        # Update the plugin
        cfg.CONF.set_override('auth_url', 'http://localhost:35357/v2.0',
                                          'PROXY')
        cfg.CONF.set_override('auth_region', 'RegionOne', 'PROXY')
        cfg.CONF.set_override('admin_user', 'quantum', 'PROXY')
        cfg.CONF.set_override('admin_password', 'password', 'PROXY')
        cfg.CONF.set_override('admin_tenant_name', 'service', 'PROXY')
        cfg.CONF.set_override('plugin_list', PLUGIN_LIST, 'META')
        cfg.CONF.set_override('default_flavor', 'fake2', 'META')
        cfg.CONF.set_override('base_mac', "12:34:56:78:90:ab")

        self.client_cls_p = mock.patch('quantumclient.v2_0.client.Client')
        client_cls = self.client_cls_p.start()
        self.client_inst = mock.Mock()
        client_cls.return_value = self.client_inst
        self.client_inst.create_network.return_value = \
            {'id': 'fake_id'}
        self.client_inst.create_port.return_value = \
            {'id': 'fake_id'}
        self.client_inst.create_subnet.return_value = \
            {'id': 'fake_id'}
        self.client_inst.update_network.return_value = \
            {'id': 'fake_id'}
        self.client_inst.update_port.return_value = \
            {'id': 'fake_id'}
        self.client_inst.update_subnet.return_value = \
            {'id': 'fake_id'}
        self.client_inst.delete_network.return_value = True
        self.client_inst.delete_port.return_value = True
        self.client_inst.delete_subnet.return_value = True
        self.plugin = MetaPluginV2(configfile=None)

    def _fake_network(self, flavor):
        data = {'network': {'name': flavor,
                            'admin_state_up': True,
                            'tenant_id': self.fake_tenant_id,
                            'flavor:id': flavor}}
        return data

    def _fake_port(self, net_id):
        return {'port': {'name': net_id,
                         'network_id': net_id,
                         'admin_state_up': True,
                         'device_id': 'bad_device_id',
                         'admin_state_up': True,
                         'fixed_ips': [],
                         'mac_address':
                         self.plugin._generate_mac(self.context, net_id),
                         'tenant_id': self.fake_tenant_id}}

    def _fake_subnet(self, net_id):
        allocation_pools = [{'start': '10.0.0.2',
                             'end': '10.0.0.254'}]
        return {'subnet': {'name': net_id,
                           'network_id': net_id,
                           'gateway_ip': '10.0.0.1',
                           'cidr': '10.0.0.0/24',
                           'allocation_pools': allocation_pools,
                           'enable_dhcp': True,
                           'ip_version': 4}}

    def test_create_delete_network(self):
        network1 = self._fake_network('fake1')
        ret1 = self.plugin.create_network(self.context, network1)
        self.assertEqual('fake1', ret1['flavor:id'])

        network2 = self._fake_network('fake2')
        ret2 = self.plugin.create_network(self.context, network2)
        self.assertEqual('fake2', ret2['flavor:id'])

        network3 = self._fake_network('proxy')
        ret3 = self.plugin.create_network(self.context, network3)
        self.assertEqual('proxy', ret3['flavor:id'])

        db_ret1 = self.plugin.get_network(self.context, ret1['id'])
        self.assertEqual('fake1', db_ret1['name'])

        db_ret2 = self.plugin.get_network(self.context, ret2['id'])
        self.assertEqual('fake2', db_ret2['name'])

        db_ret3 = self.plugin.get_network(self.context, ret3['id'])
        self.assertEqual('proxy', db_ret3['name'])

        db_ret4 = self.plugin.get_networks(self.context)
        self.assertEqual(3, len(db_ret4))

        db_ret5 = self.plugin.get_networks(self.context,
                                           {'flavor:id': ['fake1']})
        self.assertEqual(1, len(db_ret5))
        self.assertEqual('fake1', db_ret5[0]['name'])
        self.plugin.delete_network(self.context, ret1['id'])
        self.plugin.delete_network(self.context, ret2['id'])
        self.plugin.delete_network(self.context, ret3['id'])

    def test_create_delete_port(self):
        network1 = self._fake_network('fake1')
        network_ret1 = self.plugin.create_network(self.context, network1)
        network2 = self._fake_network('fake2')
        network_ret2 = self.plugin.create_network(self.context, network2)
        network3 = self._fake_network('proxy')
        network_ret3 = self.plugin.create_network(self.context, network3)

        port1 = self._fake_port(network_ret1['id'])
        port2 = self._fake_port(network_ret2['id'])
        port3 = self._fake_port(network_ret3['id'])

        port1_ret = self.plugin.create_port(self.context, port1)
        port2_ret = self.plugin.create_port(self.context, port2)
        port3_ret = self.plugin.create_port(self.context, port3)

        self.assertEqual('fake1', port1_ret['device_id'])
        self.assertEqual('fake2', port2_ret['device_id'])
        self.assertEqual('bad_device_id', port3_ret['device_id'])

        port_in_db1 = self.plugin.get_port(self.context, port1_ret['id'])
        port_in_db2 = self.plugin.get_port(self.context, port2_ret['id'])
        port_in_db3 = self.plugin.get_port(self.context, port3_ret['id'])

        self.assertEqual('fake1', port_in_db1['device_id'])
        self.assertEqual('fake2', port_in_db2['device_id'])
        self.assertEqual('bad_device_id', port_in_db3['device_id'])

        port1['port']['admin_state_up'] = False
        port2['port']['admin_state_up'] = False
        port3['port']['admin_state_up'] = False
        self.plugin.update_port(self.context, port1_ret['id'], port1)
        self.plugin.update_port(self.context, port2_ret['id'], port2)
        self.plugin.update_port(self.context, port3_ret['id'], port3)
        port_in_db1 = self.plugin.get_port(self.context, port1_ret['id'])
        port_in_db2 = self.plugin.get_port(self.context, port2_ret['id'])
        port_in_db3 = self.plugin.get_port(self.context, port3_ret['id'])
        self.assertEqual(False, port_in_db1['admin_state_up'])
        self.assertEqual(False, port_in_db2['admin_state_up'])
        self.assertEqual(False, port_in_db3['admin_state_up'])

        self.plugin.delete_port(self.context, port1_ret['id'])
        self.plugin.delete_port(self.context, port2_ret['id'])
        self.plugin.delete_port(self.context, port3_ret['id'])

        self.plugin.delete_network(self.context, network_ret1['id'])
        self.plugin.delete_network(self.context, network_ret2['id'])
        self.plugin.delete_network(self.context, network_ret3['id'])

    def test_create_delete_subnet(self):
        network1 = self._fake_network('fake1')
        network_ret1 = self.plugin.create_network(self.context, network1)
        network2 = self._fake_network('fake2')
        network_ret2 = self.plugin.create_network(self.context, network2)
        network3 = self._fake_network('proxy')
        network_ret3 = self.plugin.create_network(self.context, network3)

        subnet1 = self._fake_subnet(network_ret1['id'])
        subnet2 = self._fake_subnet(network_ret2['id'])
        subnet3 = self._fake_subnet(network_ret3['id'])

        subnet1_ret = self.plugin.create_subnet(self.context, subnet1)
        subnet2_ret = self.plugin.create_subnet(self.context, subnet2)
        subnet3_ret = self.plugin.create_subnet(self.context, subnet3)
        self.assertEqual(network_ret1['id'], subnet1_ret['network_id'])
        self.assertEqual(network_ret2['id'], subnet2_ret['network_id'])
        self.assertEqual(network_ret3['id'], subnet3_ret['network_id'])

        subnet_in_db1 = self.plugin.get_subnet(self.context, subnet1_ret['id'])
        subnet_in_db2 = self.plugin.get_subnet(self.context, subnet2_ret['id'])
        subnet_in_db3 = self.plugin.get_subnet(self.context, subnet3_ret['id'])

        subnet1['subnet']['ip_version'] = 6
        subnet1['subnet']['allocation_pools'].pop()
        subnet2['subnet']['ip_version'] = 6
        subnet2['subnet']['allocation_pools'].pop()
        subnet3['subnet']['ip_version'] = 6
        subnet3['subnet']['allocation_pools'].pop()

        self.plugin.update_subnet(self.context,
                                  subnet1_ret['id'], subnet1)
        self.plugin.update_subnet(self.context,
                                  subnet2_ret['id'], subnet2)
        self.plugin.update_subnet(self.context,
                                  subnet3_ret['id'], subnet3)
        subnet_in_db1 = self.plugin.get_subnet(self.context, subnet1_ret['id'])
        subnet_in_db2 = self.plugin.get_subnet(self.context, subnet2_ret['id'])
        subnet_in_db3 = self.plugin.get_subnet(self.context, subnet3_ret['id'])

        self.assertEqual(6, subnet_in_db1['ip_version'])
        self.assertEqual(6, subnet_in_db2['ip_version'])
        self.assertEqual(6, subnet_in_db3['ip_version'])

        self.plugin.delete_subnet(self.context, subnet1_ret['id'])
        self.plugin.delete_subnet(self.context, subnet2_ret['id'])
        self.plugin.delete_subnet(self.context, subnet3_ret['id'])

        self.plugin.delete_network(self.context, network_ret1['id'])
        self.plugin.delete_network(self.context, network_ret2['id'])
        self.plugin.delete_network(self.context, network_ret3['id'])

    def test_extension_method(self):
        self.assertEqual('fake1', self.plugin.fake_func())
        self.assertEqual('fake2', self.plugin.fake_func2())

    def test_extension_not_implemented_method(self):
        try:
            self.plugin.not_implemented()
        except AttributeError:
            return
        except:
            self.fail("AttributeError Error is not raised")

        self.fail("No Error is not raised")
