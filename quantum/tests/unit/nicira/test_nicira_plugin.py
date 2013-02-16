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
import os

import mock
import webob.exc

import quantum.common.test_lib as test_lib
from quantum import context
from quantum.extensions import providernet as pnet
from quantum.extensions import securitygroup as secgrp
from quantum import manager
from quantum.openstack.common import cfg
from quantum.plugins.nicira.nicira_nvp_plugin import nvplib
from quantum.tests.unit.nicira import fake_nvpapiclient
import quantum.tests.unit.test_db_plugin as test_plugin
import quantum.tests.unit.test_extension_portsecurity as psec
import quantum.tests.unit.test_extension_security_group as ext_sg
import quantum.tests.unit.test_l3_plugin as test_l3_plugin

LOG = logging.getLogger(__name__)
NICIRA_PKG_PATH = 'quantum.plugins.nicira.nicira_nvp_plugin'


class NiciraPluginV2TestCase(test_plugin.QuantumDbPluginV2TestCase):

    _plugin_name = ('%s.QuantumPlugin.NvpPluginV2' % NICIRA_PKG_PATH)

    def _create_network(self, fmt, name, admin_state_up,
                        arg_list=None, providernet_args=None, **kwargs):
        data = {'network': {'name': name,
                            'admin_state_up': admin_state_up,
                            'tenant_id': self._tenant_id}}
        attributes = kwargs
        if providernet_args:
            attributes.update(providernet_args)
        for arg in (('admin_state_up', 'tenant_id', 'shared') +
                    (arg_list or ())):
            # Arg must be present and not empty
            if arg in kwargs and kwargs[arg]:
                data['network'][arg] = kwargs[arg]
        network_req = self.new_create_request('networks', data, fmt)
        if (kwargs.get('set_context') and 'tenant_id' in kwargs):
            # create a specific auth context for this request
            network_req.environ['quantum.context'] = context.Context(
                '', kwargs['tenant_id'])
        return network_req.get_response(self.api)

    def setUp(self):
        etc_path = os.path.join(os.path.dirname(__file__), 'etc')
        test_lib.test_config['config_files'] = [os.path.join(etc_path,
                                                             'nvp.ini.test')]
        # mock nvp api client
        self.fc = fake_nvpapiclient.FakeClient(etc_path)
        self.mock_nvpapi = mock.patch('%s.NvpApiClient.NVPApiHelper'
                                      % NICIRA_PKG_PATH, autospec=True)
        instance = self.mock_nvpapi.start()
        instance.return_value.login.return_value = "the_cookie"

        def _fake_request(*args, **kwargs):
            return self.fc.fake_request(*args, **kwargs)

        instance.return_value.request.side_effect = _fake_request
        super(NiciraPluginV2TestCase, self).setUp(self._plugin_name)

    def tearDown(self):
        self.fc.reset_all()
        super(NiciraPluginV2TestCase, self).tearDown()
        self.mock_nvpapi.stop()


class TestNiciraBasicGet(test_plugin.TestBasicGet, NiciraPluginV2TestCase):
    pass


class TestNiciraV2HTTPResponse(test_plugin.TestV2HTTPResponse,
                               NiciraPluginV2TestCase):
    pass


class TestNiciraPortsV2(test_plugin.TestPortsV2, NiciraPluginV2TestCase):

    def test_exhaust_ports_overlay_network(self):
        cfg.CONF.set_override('max_lp_per_overlay_ls', 1, group='NVP')
        with self.network(name='testnet',
                          arg_list=(pnet.NETWORK_TYPE,
                                    pnet.PHYSICAL_NETWORK,
                                    pnet.SEGMENTATION_ID)) as net:
            with self.subnet(network=net) as sub:
                with self.port(subnet=sub):
                    # creating another port should see an exception
                    self._create_port('json', net['network']['id'], 400)

    def test_exhaust_ports_bridged_network(self):
        cfg.CONF.set_override('max_lp_per_bridged_ls', 1, group="NVP")
        providernet_args = {pnet.NETWORK_TYPE: 'flat',
                            pnet.PHYSICAL_NETWORK: 'tzuuid'}
        with self.network(name='testnet',
                          providernet_args=providernet_args,
                          arg_list=(pnet.NETWORK_TYPE,
                                    pnet.PHYSICAL_NETWORK,
                                    pnet.SEGMENTATION_ID)) as net:
            with self.subnet(network=net) as sub:
                with self.port(subnet=sub):
                    with self.port(subnet=sub):
                        plugin = manager.QuantumManager.get_plugin()
                        ls = nvplib.get_lswitches(plugin.default_cluster,
                                                  net['network']['id'])
                        self.assertEqual(len(ls), 2)

    def test_update_port_delete_ip(self):
        # This test case overrides the default because the nvp plugin
        # implements port_security/security groups and it is not allowed
        # to remove an ip address from a port unless the security group
        # is first removed.
        with self.subnet() as subnet:
            with self.port(subnet=subnet) as port:
                data = {'port': {'admin_state_up': False,
                                 'fixed_ips': [],
                                 secgrp.SECURITYGROUPS: []}}
                req = self.new_update_request('ports',
                                              data, port['port']['id'])
                res = self.deserialize('json', req.get_response(self.api))
                self.assertEqual(res['port']['admin_state_up'],
                                 data['port']['admin_state_up'])
                self.assertEqual(res['port']['fixed_ips'],
                                 data['port']['fixed_ips'])


class TestNiciraNetworksV2(test_plugin.TestNetworksV2,
                           NiciraPluginV2TestCase):

    def _test_create_bridge_network(self, vlan_id=None):
        net_type = vlan_id and 'vlan' or 'flat'
        name = 'bridge_net'
        keys = [('subnets', []), ('name', name), ('admin_state_up', True),
                ('status', 'ACTIVE'), ('shared', False),
                (pnet.NETWORK_TYPE, net_type),
                (pnet.PHYSICAL_NETWORK, 'tzuuid'),
                (pnet.SEGMENTATION_ID, vlan_id)]
        providernet_args = {pnet.NETWORK_TYPE: net_type,
                            pnet.PHYSICAL_NETWORK: 'tzuuid'}
        if vlan_id:
            providernet_args[pnet.SEGMENTATION_ID] = vlan_id
        with self.network(name=name,
                          providernet_args=providernet_args,
                          arg_list=(pnet.NETWORK_TYPE,
                                    pnet.PHYSICAL_NETWORK,
                                    pnet.SEGMENTATION_ID)) as net:
            for k, v in keys:
                self.assertEquals(net['network'][k], v)

    def test_create_bridge_network(self):
        self._test_create_bridge_network()

    def test_create_bridge_vlan_network(self):
        self._test_create_bridge_network(vlan_id=123)

    def test_create_bridge_vlan_network_outofrange_returns_400(self):
        with self.assertRaises(webob.exc.HTTPClientError) as ctx_manager:
            self._test_create_bridge_network(vlan_id=5000)
        self.assertEquals(ctx_manager.exception.code, 400)

    def test_list_networks_filter_by_id(self):
        # We add this unit test to cover some logic specific to the
        # nvp plugin
        with contextlib.nested(self.network(name='net1'),
                               self.network(name='net2')) as (net1, net2):
            query_params = 'id=%s' % net1['network']['id']
            self._test_list_resources('network', [net1],
                                      query_params=query_params)
            query_params += '&id=%s' % net2['network']['id']
            self._test_list_resources('network', [net1, net2],
                                      query_params=query_params)


class NiciraPortSecurityTestCase(psec.PortSecurityDBTestCase):

    _plugin_name = ('%s.QuantumPlugin.NvpPluginV2' % NICIRA_PKG_PATH)

    def setUp(self):
        etc_path = os.path.join(os.path.dirname(__file__), 'etc')
        test_lib.test_config['config_files'] = [os.path.join(etc_path,
                                                             'nvp.ini.test')]
        # mock nvp api client
        fc = fake_nvpapiclient.FakeClient(etc_path)
        self.mock_nvpapi = mock.patch('%s.NvpApiClient.NVPApiHelper'
                                      % NICIRA_PKG_PATH, autospec=True)
        instance = self.mock_nvpapi.start()
        instance.return_value.login.return_value = "the_cookie"

        def _fake_request(*args, **kwargs):
            return fc.fake_request(*args, **kwargs)

        instance.return_value.request.side_effect = _fake_request
        super(NiciraPortSecurityTestCase, self).setUp(self._plugin_name)

    def tearDown(self):
        super(NiciraPortSecurityTestCase, self).tearDown()
        self.mock_nvpapi.stop()


class TestNiciraPortSecurity(psec.TestPortSecurity,
                             NiciraPortSecurityTestCase):
        pass


class NiciraSecurityGroupsTestCase(ext_sg.SecurityGroupDBTestCase):

    _plugin_name = ('%s.QuantumPlugin.NvpPluginV2' % NICIRA_PKG_PATH)

    def setUp(self):
        etc_path = os.path.join(os.path.dirname(__file__), 'etc')
        test_lib.test_config['config_files'] = [os.path.join(etc_path,
                                                             'nvp.ini.test')]
        # mock nvp api client
        fc = fake_nvpapiclient.FakeClient(etc_path)
        self.mock_nvpapi = mock.patch('%s.NvpApiClient.NVPApiHelper'
                                      % NICIRA_PKG_PATH, autospec=True)
        instance = self.mock_nvpapi.start()
        instance.return_value.login.return_value = "the_cookie"

        def _fake_request(*args, **kwargs):
            return fc.fake_request(*args, **kwargs)

        instance.return_value.request.side_effect = _fake_request
        super(NiciraSecurityGroupsTestCase, self).setUp(self._plugin_name)

    def tearDown(self):
        super(NiciraSecurityGroupsTestCase, self).tearDown()
        self.mock_nvpapi.stop()


class TestNiciraSecurityGroup(ext_sg.TestSecurityGroups,
                              NiciraSecurityGroupsTestCase):
    pass


class TestNiciraL3NatTestCase(test_l3_plugin.L3NatDBTestCase,
                              NiciraPluginV2TestCase):

        def test_floatingip_with_assoc_fails(self):
            self._test_floatingip_with_assoc_fails(
                'quantum.plugins.nicira.nicira_nvp_plugin.'
                'QuantumPlugin.NvpPluginV2')
