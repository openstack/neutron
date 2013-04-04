# Copyright (c) 2012 OpenStack Foundation.
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
import os

import mock
import netaddr
from oslo.config import cfg
import testtools
import webob.exc

from quantum.common import constants
import quantum.common.test_lib as test_lib
from quantum import context
from quantum.extensions import l3
from quantum.extensions import providernet as pnet
from quantum.extensions import securitygroup as secgrp
from quantum import manager
import quantum.plugins.nicira.nicira_nvp_plugin as nvp_plugin
from quantum.plugins.nicira.nicira_nvp_plugin.extensions import nvp_networkgw
from quantum.plugins.nicira.nicira_nvp_plugin.extensions import (nvp_qos
                                                                 as ext_qos)
from quantum.plugins.nicira.nicira_nvp_plugin import nvplib
from quantum.plugins.nicira.nicira_nvp_plugin import QuantumPlugin
from quantum.tests.unit.nicira import fake_nvpapiclient
import quantum.tests.unit.nicira.test_networkgw as test_l2_gw
import quantum.tests.unit.test_db_plugin as test_plugin
import quantum.tests.unit.test_extension_portsecurity as psec
import quantum.tests.unit.test_extension_security_group as ext_sg
from quantum.tests.unit import test_extensions
import quantum.tests.unit.test_l3_plugin as test_l3_plugin

NICIRA_PKG_PATH = nvp_plugin.__name__
NICIRA_EXT_PATH = "../../plugins/nicira/nicira_nvp_plugin/extensions"


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

        def _fake_request(*args, **kwargs):
            return self.fc.fake_request(*args, **kwargs)

        # Emulate tests against NVP 2.x
        instance.return_value.get_nvp_version.return_value = "2.999"
        instance.return_value.request.side_effect = _fake_request
        super(NiciraPluginV2TestCase, self).setUp(self._plugin_name)
        cfg.CONF.set_override('metadata_mode', None, 'NVP')
        self.addCleanup(self.fc.reset_all)
        self.addCleanup(self.mock_nvpapi.stop)


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

    def test_create_port_name_exceeds_40_chars(self):
        name = 'this_is_a_port_whose_name_is_longer_than_40_chars'
        with self.port(name=name) as port:
            # Assert the Quantum name is not truncated
            self.assertEqual(name, port['port']['name'])


class TestNiciraNetworksV2(test_plugin.TestNetworksV2,
                           NiciraPluginV2TestCase):

    def _test_create_bridge_network(self, vlan_id=None):
        net_type = vlan_id and 'vlan' or 'flat'
        name = 'bridge_net'
        expected = [('subnets', []), ('name', name), ('admin_state_up', True),
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
            for k, v in expected:
                self.assertEqual(net['network'][k], v)

    def test_create_bridge_network(self):
        self._test_create_bridge_network()

    def test_create_bridge_vlan_network(self):
        self._test_create_bridge_network(vlan_id=123)

    def test_create_bridge_vlan_network_outofrange_returns_400(self):
        with testtools.ExpectedException(
                webob.exc.HTTPClientError) as ctx_manager:
            self._test_create_bridge_network(vlan_id=5000)
            self.assertEqual(ctx_manager.exception.code, 400)

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

    def test_delete_network_after_removing_subet(self):
        gateway_ip = '10.0.0.1'
        cidr = '10.0.0.0/24'
        fmt = 'json'
        # Create new network
        res = self._create_network(fmt=fmt, name='net',
                                   admin_state_up=True)
        network = self.deserialize(fmt, res)
        subnet = self._make_subnet(fmt, network, gateway_ip,
                                   cidr, ip_version=4)
        req = self.new_delete_request('subnets', subnet['subnet']['id'])
        sub_del_res = req.get_response(self.api)
        self.assertEqual(sub_del_res.status_int, 204)
        req = self.new_delete_request('networks', network['network']['id'])
        net_del_res = req.get_response(self.api)
        self.assertEqual(net_del_res.status_int, 204)

    def test_list_networks_with_shared(self):
        with self.network(name='net1'):
            with self.network(name='net2', shared=True):
                req = self.new_list_request('networks')
                res = self.deserialize('json', req.get_response(self.api))
                self.assertEqual(len(res['networks']), 2)
                req_2 = self.new_list_request('networks')
                req_2.environ['quantum.context'] = context.Context('',
                                                                   'somebody')
                res = self.deserialize('json', req_2.get_response(self.api))
                # tenant must see a single network
                self.assertEqual(len(res['networks']), 1)

    def test_create_network_name_exceeds_40_chars(self):
        name = 'this_is_a_network_whose_name_is_longer_than_40_chars'
        with self.network(name=name) as net:
            # Assert Quantum name is not truncated
            self.assertEqual(net['network']['name'], name)


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
        self.addCleanup(self.mock_nvpapi.stop)


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

    def test_create_security_group_name_exceeds_40_chars(self):
        name = 'this_is_a_secgroup_whose_name_is_longer_than_40_chars'
        with self.security_group(name=name) as sg:
            # Assert Quantum name is not truncated
            self.assertEqual(sg['security_group']['name'], name)


class TestNiciraL3NatTestCase(test_l3_plugin.L3NatDBTestCase,
                              NiciraPluginV2TestCase):

    def _create_l3_ext_network(self, vlan_id=None):
        name = 'l3_ext_net'
        net_type = QuantumPlugin.NetworkTypes.L3_EXT
        providernet_args = {pnet.NETWORK_TYPE: net_type,
                            pnet.PHYSICAL_NETWORK: 'l3_gw_uuid'}
        if vlan_id:
            providernet_args[pnet.SEGMENTATION_ID] = vlan_id
        return self.network(name=name,
                            router__external=True,
                            providernet_args=providernet_args,
                            arg_list=(pnet.NETWORK_TYPE,
                                      pnet.PHYSICAL_NETWORK,
                                      pnet.SEGMENTATION_ID))

    def _test_create_l3_ext_network(self, vlan_id=None):
        name = 'l3_ext_net'
        net_type = QuantumPlugin.NetworkTypes.L3_EXT
        expected = [('subnets', []), ('name', name), ('admin_state_up', True),
                    ('status', 'ACTIVE'), ('shared', False),
                    (l3.EXTERNAL, True),
                    (pnet.NETWORK_TYPE, net_type),
                    (pnet.PHYSICAL_NETWORK, 'l3_gw_uuid'),
                    (pnet.SEGMENTATION_ID, vlan_id)]
        with self._create_l3_ext_network(vlan_id) as net:
            for k, v in expected:
                self.assertEqual(net['network'][k], v)

    def _nvp_validate_ext_gw(self, router_id, l3_gw_uuid, vlan_id):
        """ Verify data on fake NVP API client in order to validate
        plugin did set them properly"""
        ports = [port for port in self.fc._fake_lrouter_lport_dict.values()
                 if (port['lr_uuid'] == router_id and
                     port['att_type'] == "L3GatewayAttachment")]
        self.assertEqual(len(ports), 1)
        self.assertEqual(ports[0]['attachment_gwsvc_uuid'], l3_gw_uuid)
        self.assertEqual(ports[0].get('vlan_id'), vlan_id)

    def test_create_l3_ext_network_without_vlan(self):
        self._test_create_l3_ext_network()

    def _test_router_create_with_gwinfo_and_l3_ext_net(self, vlan_id=None):
        with self._create_l3_ext_network(vlan_id) as net:
            with self.subnet(network=net) as s:
                data = {'router': {'tenant_id': 'whatever'}}
                data['router']['name'] = 'router1'
                data['router']['external_gateway_info'] = {
                    'network_id': s['subnet']['network_id']}
                router_req = self.new_create_request('routers', data,
                                                     self.fmt)
                try:
                    res = router_req.get_response(self.ext_api)
                    router = self.deserialize(self.fmt, res)
                    self.assertEqual(
                        s['subnet']['network_id'],
                        (router['router']['external_gateway_info']
                         ['network_id']))
                    self._nvp_validate_ext_gw(router['router']['id'],
                                              'l3_gw_uuid', vlan_id)
                finally:
                    self._delete('routers', router['router']['id'])

    def test_router_create_with_gwinfo_and_l3_ext_net(self):
        self._test_router_create_with_gwinfo_and_l3_ext_net()

    def test_router_create_with_gwinfo_and_l3_ext_net_with_vlan(self):
        self._test_router_create_with_gwinfo_and_l3_ext_net(444)

    def _test_router_update_gateway_on_l3_ext_net(self, vlan_id=None):
        with self.router() as r:
            with self.subnet() as s1:
                with self._create_l3_ext_network(vlan_id) as net:
                    with self.subnet(network=net) as s2:
                        self._set_net_external(s1['subnet']['network_id'])
                        try:
                            self._add_external_gateway_to_router(
                                r['router']['id'],
                                s1['subnet']['network_id'])
                            body = self._show('routers', r['router']['id'])
                            net_id = (body['router']
                                      ['external_gateway_info']['network_id'])
                            self.assertEqual(net_id,
                                             s1['subnet']['network_id'])
                            # Plug network with external mapping
                            self._set_net_external(s2['subnet']['network_id'])
                            self._add_external_gateway_to_router(
                                r['router']['id'],
                                s2['subnet']['network_id'])
                            body = self._show('routers', r['router']['id'])
                            net_id = (body['router']
                                      ['external_gateway_info']['network_id'])
                            self.assertEqual(net_id,
                                             s2['subnet']['network_id'])
                            self._nvp_validate_ext_gw(body['router']['id'],
                                                      'l3_gw_uuid', vlan_id)
                        finally:
                            # Cleanup
                            self._remove_external_gateway_from_router(
                                r['router']['id'],
                                s2['subnet']['network_id'])

    def test_router_update_gateway_on_l3_ext_net(self):
        self._test_router_update_gateway_on_l3_ext_net()

    def test_router_update_gateway_on_l3_ext_net_with_vlan(self):
        self._test_router_update_gateway_on_l3_ext_net(444)

    def test_create_l3_ext_network_with_vlan(self):
        self._test_create_l3_ext_network(666)

    def test_floatingip_with_assoc_fails(self):
        self._test_floatingip_with_assoc_fails(
            'quantum.plugins.nicira.nicira_nvp_plugin.'
            'QuantumPlugin.NvpPluginV2')

    def _nvp_metadata_setup(self):
        cfg.CONF.set_override('metadata_mode', 'access_network', 'NVP')

    def _nvp_metadata_teardown(self):
        cfg.CONF.set_override('metadata_mode', None, 'NVP')

    def test_create_router_name_exceeds_40_chars(self):
        name = 'this_is_a_router_whose_name_is_longer_than_40_chars'
        with self.router(name=name) as rtr:
            # Assert Quantum name is not truncated
            self.assertEqual(rtr['router']['name'], name)

    def test_router_add_interface_subnet_with_metadata_access(self):
        self._nvp_metadata_setup()
        self.test_router_add_interface_subnet()
        self._nvp_metadata_teardown()

    def test_router_add_interface_port_with_metadata_access(self):
        self._nvp_metadata_setup()
        self.test_router_add_interface_port()
        self._nvp_metadata_teardown()

    def test_router_add_interface_dupsubnet_returns_400_with_metadata(self):
        self._nvp_metadata_setup()
        self.test_router_add_interface_dup_subnet1_returns_400()
        self._nvp_metadata_teardown()

    def test_router_add_interface_overlapped_cidr_returns_400_with(self):
        self._nvp_metadata_setup()
        self.test_router_add_interface_overlapped_cidr_returns_400()
        self._nvp_metadata_teardown()

    def test_router_remove_interface_inuse_returns_409_with_metadata(self):
        self._nvp_metadata_setup()
        self.test_router_remove_interface_inuse_returns_409()
        self._nvp_metadata_teardown()

    def test_router_remove_iface_wrong_sub_returns_409_with_metadata(self):
        self._nvp_metadata_setup()
        self.test_router_remove_interface_wrong_subnet_returns_409()
        self._nvp_metadata_teardown()

    def test_router_delete_with_metadata_access(self):
        self._nvp_metadata_setup()
        self.test_router_delete()
        self._nvp_metadata_teardown()

    def test_router_delete_with_port_existed_returns_409_with_metadata(self):
        self._nvp_metadata_setup()
        self.test_router_delete_with_port_existed_returns_409()
        self._nvp_metadata_teardown()

    def test_metadatata_network_created_with_router_interface_add(self):
        self._nvp_metadata_setup()
        with self.router() as r:
            with self.subnet() as s:
                self._router_interface_action('add',
                                              r['router']['id'],
                                              s['subnet']['id'],
                                              None)
                r_ports = self._list('ports')['ports']
                self.assertEqual(len(r_ports), 2)
                ips = []
                for port in r_ports:
                    ips.extend([netaddr.IPAddress(fixed_ip['ip_address'])
                                for fixed_ip in port['fixed_ips']])
                meta_cidr = netaddr.IPNetwork('169.254.0.0/16')
                self.assertTrue(any([ip in meta_cidr for ip in ips]))
                # Needed to avoid 409
                self._router_interface_action('remove',
                                              r['router']['id'],
                                              s['subnet']['id'],
                                              None)
        self._nvp_metadata_teardown()

    def test_metadatata_network_removed_with_router_interface_remove(self):
        self._nvp_metadata_setup()
        with self.router() as r:
            with self.subnet() as s:
                self._router_interface_action('add', r['router']['id'],
                                              s['subnet']['id'], None)
                subnets = self._list('subnets')['subnets']
                self.assertEqual(len(subnets), 2)
                meta_cidr = netaddr.IPNetwork('169.254.0.0/16')
                for subnet in subnets:
                    cidr = netaddr.IPNetwork(subnet['cidr'])
                    if meta_cidr == cidr or meta_cidr in cidr.supernet(16):
                        meta_sub_id = subnet['id']
                        meta_net_id = subnet['network_id']
                ports = self._list(
                    'ports',
                    query_params='network_id=%s' % meta_net_id)['ports']
                self.assertEqual(len(ports), 1)
                meta_port_id = ports[0]['id']
                self._router_interface_action('remove', r['router']['id'],
                                              s['subnet']['id'], None)
                self._show('networks', meta_net_id,
                           webob.exc.HTTPNotFound.code)
                self._show('ports', meta_port_id,
                           webob.exc.HTTPNotFound.code)
                self._show('subnets', meta_sub_id,
                           webob.exc.HTTPNotFound.code)
        self._nvp_metadata_teardown()

    def test_metadata_dhcp_host_route(self):
        cfg.CONF.set_override('metadata_mode', 'dhcp_host_route', 'NVP')
        subnets = self._list('subnets')['subnets']
        with self.subnet() as s:
            with self.port(subnet=s, device_id='1234',
                           device_owner='network:dhcp'):
                subnets = self._list('subnets')['subnets']
                self.assertEqual(len(subnets), 1)
                self.assertEquals(subnets[0]['host_routes'][0]['nexthop'],
                                  '10.0.0.2')
                self.assertEquals(subnets[0]['host_routes'][0]['destination'],
                                  '169.254.169.254/32')

            subnets = self._list('subnets')['subnets']
            # Test that route is deleted after dhcp port is removed
            self.assertEquals(len(subnets[0]['host_routes']), 0)


class NvpQoSTestExtensionManager(object):

    def get_resources(self):
        return ext_qos.Nvp_qos.get_resources()

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


class TestNiciraQoSQueue(NiciraPluginV2TestCase):

    def setUp(self, plugin=None):
        ext_path = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                                NICIRA_EXT_PATH)
        cfg.CONF.set_override('api_extensions_path', ext_path)
        super(TestNiciraQoSQueue, self).setUp()
        ext_mgr = NvpQoSTestExtensionManager()
        self.ext_api = test_extensions.setup_extensions_middleware(ext_mgr)

    def _create_qos_queue(self, fmt, body, **kwargs):
        qos_queue = self.new_create_request('qos-queues', body)
        if (kwargs.get('set_context') and 'tenant_id' in kwargs):
            # create a specific auth context for this request
            qos_queue.environ['quantum.context'] = context.Context(
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
        try:
            yield qos_queue
        finally:
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

    def test_create_qos_queue_name_exceeds_40_chars(self):
        name = 'this_is_a_queue_whose_name_is_longer_than_40_chars'
        with self.qos_queue(name=name) as queue:
            # Assert Quantum name is not truncated
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
            self.assertEqual(port['port'][ext_qos.QUEUE], None)

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
        self.assertEqual(ext_qos.QUEUE not in port['port'], True)

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
        quantum_context = context.Context('', 'not_admin')
        port = self._update('ports', port['port']['id'], data,
                            quantum_context=quantum_context)
        self.assertEqual(ext_qos.QUEUE not in port['port'], True)

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


class NiciraQuantumNVPOutOfSync(test_l3_plugin.L3NatTestCaseBase,
                                NiciraPluginV2TestCase):

    def test_delete_network_not_in_nvp(self):
        res = self._create_network('json', 'net1', True)
        net1 = self.deserialize('json', res)
        self.fc._fake_lswitch_dict.clear()
        req = self.new_delete_request('networks', net1['network']['id'])
        res = req.get_response(self.api)
        self.assertEqual(res.status_int, 204)

    def test_list_networks_not_in_nvp(self):
        res = self._create_network('json', 'net1', True)
        self.deserialize('json', res)
        self.fc._fake_lswitch_dict.clear()
        req = self.new_list_request('networks')
        nets = self.deserialize('json', req.get_response(self.api))
        self.assertEqual(nets['networks'][0]['status'],
                         constants.NET_STATUS_ERROR)

    def test_show_network_not_in_nvp(self):
        res = self._create_network('json', 'net1', True)
        net = self.deserialize('json', res)
        self.fc._fake_lswitch_dict.clear()
        req = self.new_show_request('networks', net['network']['id'])
        net = self.deserialize('json', req.get_response(self.api))
        self.assertEqual(net['network']['status'],
                         constants.NET_STATUS_ERROR)

    def test_delete_port_not_in_nvp(self):
        res = self._create_network('json', 'net1', True)
        net1 = self.deserialize('json', res)
        res = self._create_port('json', net1['network']['id'])
        port = self.deserialize('json', res)
        self.fc._fake_lswitch_lport_dict.clear()
        req = self.new_delete_request('ports', port['port']['id'])
        res = req.get_response(self.api)
        self.assertEqual(res.status_int, 204)

    def test_list_port_not_in_nvp(self):
        res = self._create_network('json', 'net1', True)
        net1 = self.deserialize('json', res)
        res = self._create_port('json', net1['network']['id'])
        self.deserialize('json', res)
        self.fc._fake_lswitch_lport_dict.clear()
        req = self.new_list_request('ports')
        nets = self.deserialize('json', req.get_response(self.api))
        self.assertEqual(nets['ports'][0]['status'],
                         constants.PORT_STATUS_ERROR)

    def test_show_port_not_in_nvp(self):
        res = self._create_network('json', 'net1', True)
        net1 = self.deserialize('json', res)
        res = self._create_port('json', net1['network']['id'])
        port = self.deserialize('json', res)
        self.fc._fake_lswitch_lport_dict.clear()
        req = self.new_show_request('ports', port['port']['id'])
        net = self.deserialize('json', req.get_response(self.api))
        self.assertEqual(net['port']['status'],
                         constants.PORT_STATUS_ERROR)

    def test_delete_port_and_network_not_in_nvp(self):
        res = self._create_network('json', 'net1', True)
        net1 = self.deserialize('json', res)
        res = self._create_port('json', net1['network']['id'])
        port = self.deserialize('json', res)
        self.fc._fake_lswitch_dict.clear()
        self.fc._fake_lswitch_lport_dict.clear()
        req = self.new_delete_request('ports', port['port']['id'])
        res = req.get_response(self.api)
        self.assertEqual(res.status_int, 204)
        req = self.new_delete_request('networks', net1['network']['id'])
        res = req.get_response(self.api)
        self.assertEqual(res.status_int, 204)

    def test_delete_router_not_in_nvp(self):
        res = self._create_router('json', 'tenant')
        router = self.deserialize('json', res)
        self.fc._fake_lrouter_dict.clear()
        req = self.new_delete_request('routers', router['router']['id'])
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, 204)

    def test_list_routers_not_in_nvp(self):
        res = self._create_router('json', 'tenant')
        self.deserialize('json', res)
        self.fc._fake_lrouter_dict.clear()
        req = self.new_list_request('routers')
        routers = self.deserialize('json', req.get_response(self.ext_api))
        self.assertEqual(routers['routers'][0]['status'],
                         constants.NET_STATUS_ERROR)

    def test_show_router_not_in_nvp(self):
        res = self._create_router('json', 'tenant')
        router = self.deserialize('json', res)
        self.fc._fake_lrouter_dict.clear()
        req = self.new_show_request('routers', router['router']['id'])
        router = self.deserialize('json', req.get_response(self.ext_api))
        self.assertEqual(router['router']['status'],
                         constants.NET_STATUS_ERROR)


class TestNiciraNetworkGateway(test_l2_gw.NetworkGatewayDbTestCase,
                               NiciraPluginV2TestCase):

    def setUp(self):
        ext_path = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                                NICIRA_EXT_PATH)
        cfg.CONF.set_override('api_extensions_path', ext_path)
        super(TestNiciraNetworkGateway, self).setUp()

    def test_create_network_gateway_name_exceeds_40_chars(self):
        name = 'this_is_a_gateway_whose_name_is_longer_than_40_chars'
        with self._network_gateway(name=name) as nw_gw:
            # Assert Quantum name is not truncated
            self.assertEqual(nw_gw[self.resource]['name'], name)

    def test_list_network_gateways(self):
        with self._network_gateway(name='test-gw-1') as gw1:
            with self._network_gateway(name='test_gw_2') as gw2:
                req = self.new_list_request(nvp_networkgw.COLLECTION_NAME)
                res = self.deserialize('json', req.get_response(self.ext_api))
                # We expect the default gateway too
                key = self.resource + 's'
                self.assertEqual(len(res[key]), 3)
                self.assertEqual(res[key][0]['default'],
                                 True)
                self.assertEqual(res[key][1]['name'],
                                 gw1[self.resource]['name'])
                self.assertEqual(res[key][2]['name'],
                                 gw2[self.resource]['name'])

    def test_delete_network_gateway(self):
        # The default gateway must still be there
        self._test_delete_network_gateway(1)
