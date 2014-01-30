# vim: tabstop=4 shiftwidth=4 softtabstop=4

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

import mock
import netaddr
from oslo.config import cfg
import webob.exc

from neutron.api.v2 import attributes
from neutron.common import constants
from neutron.common import exceptions as ntn_exc
import neutron.common.test_lib as test_lib
from neutron import context
from neutron.extensions import external_net
from neutron.extensions import l3
from neutron.extensions import l3_ext_gw_mode
from neutron.extensions import multiprovidernet as mpnet
from neutron.extensions import portbindings
from neutron.extensions import providernet as pnet
from neutron.extensions import securitygroup as secgrp
from neutron import manager
from neutron.manager import NeutronManager
from neutron.openstack.common import uuidutils
from neutron.plugins.nicira.common import exceptions as nvp_exc
from neutron.plugins.nicira.common import sync
from neutron.plugins.nicira.dbexts import nicira_db
from neutron.plugins.nicira.dbexts import nicira_qos_db as qos_db
from neutron.plugins.nicira.extensions import distributedrouter as dist_router
from neutron.plugins.nicira.extensions import nvp_networkgw
from neutron.plugins.nicira.extensions import nvp_qos as ext_qos
from neutron.plugins.nicira import NeutronPlugin
from neutron.plugins.nicira import NvpApiClient
from neutron.plugins.nicira.NvpApiClient import NVPVersion
from neutron.plugins.nicira import nvplib
from neutron.tests.unit import _test_extension_portbindings as test_bindings
from neutron.tests.unit.nicira import fake_nvpapiclient
from neutron.tests.unit.nicira import get_fake_conf
from neutron.tests.unit.nicira import NVPAPI_NAME
from neutron.tests.unit.nicira import NVPEXT_PATH
from neutron.tests.unit.nicira import PLUGIN_NAME
from neutron.tests.unit.nicira import STUBS_PATH
import neutron.tests.unit.nicira.test_networkgw as test_l2_gw
import neutron.tests.unit.test_db_plugin as test_plugin
import neutron.tests.unit.test_extension_allowedaddresspairs as test_addr_pair
import neutron.tests.unit.test_extension_ext_gw_mode as test_ext_gw_mode
import neutron.tests.unit.test_extension_portsecurity as psec
import neutron.tests.unit.test_extension_security_group as ext_sg
from neutron.tests.unit import test_extensions
import neutron.tests.unit.test_l3_plugin as test_l3_plugin
from neutron.tests.unit import testlib_api


from neutron.openstack.common import log
LOG = log.getLogger(__name__)


class NiciraPluginV2TestCase(test_plugin.NeutronDbPluginV2TestCase):

    def _create_network(self, fmt, name, admin_state_up,
                        arg_list=None, providernet_args=None, **kwargs):
        data = {'network': {'name': name,
                            'admin_state_up': admin_state_up,
                            'tenant_id': self._tenant_id}}
        # Fix to allow the router:external attribute and any other
        # attributes containing a colon to be passed with
        # a double underscore instead
        kwargs = dict((k.replace('__', ':'), v) for k, v in kwargs.items())
        if external_net.EXTERNAL in kwargs:
            arg_list = (external_net.EXTERNAL, ) + (arg_list or ())

        attrs = kwargs
        if providernet_args:
            attrs.update(providernet_args)
        for arg in (('admin_state_up', 'tenant_id', 'shared') +
                    (arg_list or ())):
            # Arg must be present and not empty
            if arg in kwargs and kwargs[arg]:
                data['network'][arg] = kwargs[arg]
        network_req = self.new_create_request('networks', data, fmt)
        if (kwargs.get('set_context') and 'tenant_id' in kwargs):
            # create a specific auth context for this request
            network_req.environ['neutron.context'] = context.Context(
                '', kwargs['tenant_id'])
        return network_req.get_response(self.api)

    def setUp(self,
              plugin=PLUGIN_NAME,
              ext_mgr=None,
              service_plugins=None):
        test_lib.test_config['config_files'] = [get_fake_conf('nvp.ini.test')]
        # mock nvp api client
        self.fc = fake_nvpapiclient.FakeClient(STUBS_PATH)
        self.mock_nvpapi = mock.patch(NVPAPI_NAME, autospec=True)
        self.mock_instance = self.mock_nvpapi.start()
        # Avoid runs of the synchronizer looping call
        patch_sync = mock.patch.object(sync, '_start_loopingcall')
        patch_sync.start()

        def _fake_request(*args, **kwargs):
            return self.fc.fake_request(*args, **kwargs)

        # Emulate tests against NVP 2.x
        self.mock_instance.return_value.get_nvp_version.return_value = (
            NVPVersion("2.9"))
        self.mock_instance.return_value.request.side_effect = _fake_request
        plugin = plugin or PLUGIN_NAME
        super(NiciraPluginV2TestCase, self).setUp(plugin=plugin,
                                                  ext_mgr=ext_mgr)
        cfg.CONF.set_override('metadata_mode', None, 'NVP')
        self.addCleanup(self.fc.reset_all)
        self.addCleanup(mock.patch.stopall)


class TestNiciraBasicGet(test_plugin.TestBasicGet, NiciraPluginV2TestCase):
    pass


class TestNiciraV2HTTPResponse(test_plugin.TestV2HTTPResponse,
                               NiciraPluginV2TestCase):
    pass


class TestNiciraProvidernet(NiciraPluginV2TestCase):

    def test_create_provider_network_default_physical_net(self):
        data = {'network': {'name': 'net1',
                            'admin_state_up': True,
                            'tenant_id': 'admin',
                            pnet.NETWORK_TYPE: 'vlan',
                            pnet.SEGMENTATION_ID: 411}}
        network_req = self.new_create_request('networks', data, self.fmt)
        net = self.deserialize(self.fmt, network_req.get_response(self.api))
        self.assertEqual(net['network'][pnet.NETWORK_TYPE], 'vlan')
        self.assertEqual(net['network'][pnet.SEGMENTATION_ID], 411)

    def test_create_provider_network(self):
        data = {'network': {'name': 'net1',
                            'admin_state_up': True,
                            'tenant_id': 'admin',
                            pnet.NETWORK_TYPE: 'vlan',
                            pnet.SEGMENTATION_ID: 411,
                            pnet.PHYSICAL_NETWORK: 'physnet1'}}
        network_req = self.new_create_request('networks', data, self.fmt)
        net = self.deserialize(self.fmt, network_req.get_response(self.api))
        self.assertEqual(net['network'][pnet.NETWORK_TYPE], 'vlan')
        self.assertEqual(net['network'][pnet.SEGMENTATION_ID], 411)
        self.assertEqual(net['network'][pnet.PHYSICAL_NETWORK], 'physnet1')


class TestNiciraPortsV2(NiciraPluginV2TestCase,
                        test_plugin.TestPortsV2,
                        test_bindings.PortBindingsTestCase,
                        test_bindings.PortBindingsHostTestCaseMixin):

    VIF_TYPE = portbindings.VIF_TYPE_OVS
    HAS_PORT_FILTER = True

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
                        plugin = manager.NeutronManager.get_plugin()
                        ls = nvplib.get_lswitches(plugin.cluster,
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
            # Assert the neutron name is not truncated
            self.assertEqual(name, port['port']['name'])

    def _verify_no_orphan_left(self, net_id):
        # Verify no port exists on net
        # ie: cleanup on db was successful
        query_params = "network_id=%s" % net_id
        self._test_list_resources('port', [],
                                  query_params=query_params)
        # Also verify no orphan port was left on nvp
        # no port should be there at all
        self.assertFalse(self.fc._fake_lswitch_lport_dict)

    def test_create_port_nvp_error_no_orphan_left(self):
        with mock.patch.object(nvplib, 'create_lport',
                               side_effect=NvpApiClient.NvpApiException):
            with self.network() as net:
                net_id = net['network']['id']
                self._create_port(self.fmt, net_id,
                                  webob.exc.HTTPInternalServerError.code)
                self._verify_no_orphan_left(net_id)

    def test_create_port_neutron_error_no_orphan_left(self):
        with mock.patch.object(nicira_db, 'add_neutron_nvp_port_mapping',
                               side_effect=ntn_exc.NeutronException):
            with self.network() as net:
                net_id = net['network']['id']
                self._create_port(self.fmt, net_id,
                                  webob.exc.HTTPInternalServerError.code)
                self._verify_no_orphan_left(net_id)

    def test_create_port_maintenance_returns_503(self):
        with self.network() as net:
            with mock.patch.object(nvplib, 'do_request',
                                   side_effect=nvp_exc.MaintenanceInProgress):
                data = {'port': {'network_id': net['network']['id'],
                                 'admin_state_up': False,
                                 'fixed_ips': [],
                                 'tenant_id': self._tenant_id}}
                plugin = manager.NeutronManager.get_plugin()
                with mock.patch.object(plugin, 'get_network',
                                       return_value=net['network']):
                    port_req = self.new_create_request('ports', data, self.fmt)
                    res = port_req.get_response(self.api)
                    self.assertEqual(webob.exc.HTTPServiceUnavailable.code,
                                     res.status_int)


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
        with testlib_api.ExpectedException(
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
                req_2.environ['neutron.context'] = context.Context('',
                                                                   'somebody')
                res = self.deserialize('json', req_2.get_response(self.api))
                # tenant must see a single network
                self.assertEqual(len(res['networks']), 1)

    def test_create_network_name_exceeds_40_chars(self):
        name = 'this_is_a_network_whose_name_is_longer_than_40_chars'
        with self.network(name=name) as net:
            # Assert neutron name is not truncated
            self.assertEqual(net['network']['name'], name)

    def test_create_network_maintenance_returns_503(self):
        data = {'network': {'name': 'foo',
                            'admin_state_up': True,
                            'tenant_id': self._tenant_id}}
        with mock.patch.object(nvplib, 'do_request',
                               side_effect=nvp_exc.MaintenanceInProgress):
            net_req = self.new_create_request('networks', data, self.fmt)
            res = net_req.get_response(self.api)
            self.assertEqual(webob.exc.HTTPServiceUnavailable.code,
                             res.status_int)

    def test_update_network_with_admin_false(self):
        data = {'network': {'admin_state_up': False}}
        with self.network() as net:
            plugin = manager.NeutronManager.get_plugin()
            self.assertRaises(NotImplementedError,
                              plugin.update_network,
                              context.get_admin_context(),
                              net['network']['id'], data)


class NiciraPortSecurityTestCase(psec.PortSecurityDBTestCase):

    def setUp(self):
        test_lib.test_config['config_files'] = [get_fake_conf('nvp.ini.test')]
        # mock nvp api client
        self.fc = fake_nvpapiclient.FakeClient(STUBS_PATH)
        self.mock_nvpapi = mock.patch(NVPAPI_NAME, autospec=True)
        instance = self.mock_nvpapi.start()
        instance.return_value.login.return_value = "the_cookie"
        # Avoid runs of the synchronizer looping call
        patch_sync = mock.patch.object(sync, '_start_loopingcall')
        patch_sync.start()

        def _fake_request(*args, **kwargs):
            return self.fc.fake_request(*args, **kwargs)

        instance.return_value.request.side_effect = _fake_request
        super(NiciraPortSecurityTestCase, self).setUp(PLUGIN_NAME)
        self.addCleanup(self.fc.reset_all)
        self.addCleanup(self.mock_nvpapi.stop)
        self.addCleanup(patch_sync.stop)


class TestNiciraPortSecurity(NiciraPortSecurityTestCase,
                             psec.TestPortSecurity):
        pass


class TestNiciraAllowedAddressPairs(test_addr_pair.TestAllowedAddressPairs,
                                    NiciraPluginV2TestCase):
    pass


class NiciraSecurityGroupsTestCase(ext_sg.SecurityGroupDBTestCase):

    def setUp(self):
        test_lib.test_config['config_files'] = [get_fake_conf('nvp.ini.test')]
        # mock nvp api client
        fc = fake_nvpapiclient.FakeClient(STUBS_PATH)
        self.mock_nvpapi = mock.patch(NVPAPI_NAME, autospec=True)
        instance = self.mock_nvpapi.start()
        instance.return_value.login.return_value = "the_cookie"
        # Avoid runs of the synchronizer looping call
        patch_sync = mock.patch.object(sync, '_start_loopingcall')
        patch_sync.start()

        def _fake_request(*args, **kwargs):
            return fc.fake_request(*args, **kwargs)

        instance.return_value.request.side_effect = _fake_request
        self.addCleanup(self.mock_nvpapi.stop)
        self.addCleanup(patch_sync.stop)
        super(NiciraSecurityGroupsTestCase, self).setUp(PLUGIN_NAME)


class TestNiciraSecurityGroup(ext_sg.TestSecurityGroups,
                              NiciraSecurityGroupsTestCase):

    def test_create_security_group_name_exceeds_40_chars(self):
        name = 'this_is_a_secgroup_whose_name_is_longer_than_40_chars'
        with self.security_group(name=name) as sg:
            # Assert Neutron name is not truncated
            self.assertEqual(sg['security_group']['name'], name)

    def test_create_security_group_rule_bad_input(self):
        name = 'foo security group'
        description = 'foo description'
        with self.security_group(name, description) as sg:
            security_group_id = sg['security_group']['id']
            protocol = 200
            min_range = 32
            max_range = 4343
            rule = self._build_security_group_rule(
                security_group_id, 'ingress', protocol,
                min_range, max_range)
            res = self._create_security_group_rule(self.fmt, rule)
            self.deserialize(self.fmt, res)
            self.assertEqual(res.status_int, 400)


class TestNiciraL3ExtensionManager(object):

    def get_resources(self):
        # Simulate extension of L3 attribute map
        # First apply attribute extensions
        for key in l3.RESOURCE_ATTRIBUTE_MAP.keys():
            l3.RESOURCE_ATTRIBUTE_MAP[key].update(
                l3_ext_gw_mode.EXTENDED_ATTRIBUTES_2_0.get(key, {}))
            l3.RESOURCE_ATTRIBUTE_MAP[key].update(
                dist_router.EXTENDED_ATTRIBUTES_2_0.get(key, {}))
        # Finally add l3 resources to the global attribute map
        attributes.RESOURCE_ATTRIBUTE_MAP.update(
            l3.RESOURCE_ATTRIBUTE_MAP)
        return l3.L3.get_resources()

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


class NiciraL3NatTest(test_l3_plugin.L3BaseForIntTests,
                      NiciraPluginV2TestCase):

    def _restore_l3_attribute_map(self):
        l3.RESOURCE_ATTRIBUTE_MAP = self._l3_attribute_map_bk

    def setUp(self, plugin=None, ext_mgr=None, service_plugins=None):
        self._l3_attribute_map_bk = {}
        for item in l3.RESOURCE_ATTRIBUTE_MAP:
            self._l3_attribute_map_bk[item] = (
                l3.RESOURCE_ATTRIBUTE_MAP[item].copy())
        cfg.CONF.set_override('api_extensions_path', NVPEXT_PATH)
        self.addCleanup(self._restore_l3_attribute_map)
        ext_mgr = ext_mgr or TestNiciraL3ExtensionManager()
        super(NiciraL3NatTest, self).setUp(
            plugin=plugin, ext_mgr=ext_mgr, service_plugins=service_plugins)
        plugin_instance = NeutronManager.get_plugin()
        self._plugin_name = "%s.%s" % (
            plugin_instance.__module__,
            plugin_instance.__class__.__name__)
        self._plugin_class = plugin_instance.__class__


class TestNiciraL3NatTestCase(NiciraL3NatTest,
                              test_l3_plugin.L3NatDBIntTestCase,
                              NiciraPluginV2TestCase):

    def _create_l3_ext_network(self, vlan_id=None):
        name = 'l3_ext_net'
        net_type = NeutronPlugin.NetworkTypes.L3_EXT
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
        net_type = NeutronPlugin.NetworkTypes.L3_EXT
        expected = [('subnets', []), ('name', name), ('admin_state_up', True),
                    ('status', 'ACTIVE'), ('shared', False),
                    (external_net.EXTERNAL, True),
                    (pnet.NETWORK_TYPE, net_type),
                    (pnet.PHYSICAL_NETWORK, 'l3_gw_uuid'),
                    (pnet.SEGMENTATION_ID, vlan_id)]
        with self._create_l3_ext_network(vlan_id) as net:
            for k, v in expected:
                self.assertEqual(net['network'][k], v)

    def _nvp_validate_ext_gw(self, router_id, l3_gw_uuid, vlan_id):
        """Verify data on fake NVP API client in order to validate
        plugin did set them properly
        """
        ports = [port for port in self.fc._fake_lrouter_lport_dict.values()
                 if (port['lr_uuid'] == router_id and
                     port['att_type'] == "L3GatewayAttachment")]
        self.assertEqual(len(ports), 1)
        self.assertEqual(ports[0]['attachment_gwsvc_uuid'], l3_gw_uuid)
        self.assertEqual(ports[0].get('vlan_id'), vlan_id)

    def test_create_l3_ext_network_without_vlan(self):
        self._test_create_l3_ext_network()

    def _test_router_create_with_gwinfo_and_l3_ext_net(self, vlan_id=None,
                                                       validate_ext_gw=True):
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
                    if validate_ext_gw:
                        self._nvp_validate_ext_gw(router['router']['id'],
                                                  'l3_gw_uuid', vlan_id)
                finally:
                    self._delete('routers', router['router']['id'])

    def test_router_create_with_gwinfo_and_l3_ext_net(self):
        self._test_router_create_with_gwinfo_and_l3_ext_net()

    def test_router_create_with_gwinfo_and_l3_ext_net_with_vlan(self):
        self._test_router_create_with_gwinfo_and_l3_ext_net(444)

    def _test_router_create_with_distributed(self, dist_input, dist_expected,
                                             version='3.1', return_code=201):
        self.mock_instance.return_value.get_nvp_version.return_value = (
            NvpApiClient.NVPVersion(version))

        data = {'tenant_id': 'whatever'}
        data['name'] = 'router1'
        data['distributed'] = dist_input
        router_req = self.new_create_request(
            'routers', {'router': data}, self.fmt)
        try:
            res = router_req.get_response(self.ext_api)
            self.assertEqual(return_code, res.status_int)
            if res.status_int == 201:
                router = self.deserialize(self.fmt, res)
                self.assertIn('distributed', router['router'])
                self.assertEqual(dist_expected,
                                 router['router']['distributed'])
        finally:
            if res.status_int == 201:
                self._delete('routers', router['router']['id'])

    def test_router_create_distributed_with_3_1(self):
        self._test_router_create_with_distributed(True, True)

    def test_router_create_distributed_with_new_nvp_versions(self):
        with mock.patch.object(nvplib, 'create_explicit_route_lrouter'):
            self._test_router_create_with_distributed(True, True, '3.2')
            self._test_router_create_with_distributed(True, True, '4.0')
            self._test_router_create_with_distributed(True, True, '4.1')

    def test_router_create_not_distributed(self):
        self._test_router_create_with_distributed(False, False)

    def test_router_create_distributed_unspecified(self):
        self._test_router_create_with_distributed(None, False)

    def test_router_create_distributed_returns_400(self):
        self._test_router_create_with_distributed(True, None, '3.0', 400)

    def test_router_create_on_obsolete_platform(self):

        def obsolete_response(*args, **kwargs):
            response = nvplib._create_implicit_routing_lrouter(*args, **kwargs)
            response.pop('distributed')
            return response

        with mock.patch.object(
            nvplib, 'create_lrouter', new=obsolete_response):
            self._test_router_create_with_distributed(None, False, '2.2')

    def test_router_create_nvp_error_returns_500(self, vlan_id=None):
        with mock.patch.object(nvplib,
                               'create_router_lport',
                               side_effect=NvpApiClient.NvpApiException):
            with self._create_l3_ext_network(vlan_id) as net:
                with self.subnet(network=net) as s:
                    data = {'router': {'tenant_id': 'whatever'}}
                    data['router']['name'] = 'router1'
                    data['router']['external_gateway_info'] = {
                        'network_id': s['subnet']['network_id']}
                    router_req = self.new_create_request(
                        'routers', data, self.fmt)
                    res = router_req.get_response(self.ext_api)
                    self.assertEqual(500, res.status_int)

    def test_router_add_gateway_invalid_network_returns_404(self):
        # NOTE(salv-orlando): This unit test has been overriden
        # as the nicira plugin support the ext_gw_mode extension
        # which mandates a uuid for the external network identifier
        with self.router() as r:
            self._add_external_gateway_to_router(
                r['router']['id'],
                uuidutils.generate_uuid(),
                expected_code=webob.exc.HTTPNotFound.code)

    def _test_router_update_gateway_on_l3_ext_net(self, vlan_id=None,
                                                  validate_ext_gw=True):
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
                            if validate_ext_gw:
                                self._nvp_validate_ext_gw(
                                    body['router']['id'],
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

    def test_router_list_by_tenant_id(self):
        with contextlib.nested(self.router(tenant_id='custom'),
                               self.router(),
                               self.router()
                               ) as routers:
            self._test_list_resources('router', [routers[0]],
                                      query_params="tenant_id=custom")

    def test_create_l3_ext_network_with_vlan(self):
        self._test_create_l3_ext_network(666)

    def test_floatingip_with_assoc_fails(self):
        self._test_floatingip_with_assoc_fails(self._plugin_name)

    def test_floatingip_with_invalid_create_port(self):
        self._test_floatingip_with_invalid_create_port(self._plugin_name)

    def _nvp_metadata_setup(self):
        cfg.CONF.set_override('metadata_mode', 'access_network', 'NVP')

    def _nvp_metadata_teardown(self):
        cfg.CONF.set_override('metadata_mode', None, 'NVP')

    def test_create_router_name_exceeds_40_chars(self):
        name = 'this_is_a_router_whose_name_is_longer_than_40_chars'
        with self.router(name=name) as rtr:
            # Assert Neutron name is not truncated
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

    def test_router_remove_iface_wrong_sub_returns_400_with_metadata(self):
        self._nvp_metadata_setup()
        self.test_router_remove_interface_wrong_subnet_returns_400()
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

    def test_metadata_network_create_rollback_on_create_subnet_failure(self):
        self._nvp_metadata_setup()
        with self.router() as r:
            with self.subnet() as s:
                # Raise a NeutronException (eg: NotFound)
                with mock.patch.object(self._plugin_class,
                                       'create_subnet',
                                       side_effect=ntn_exc.NotFound):
                    self._router_interface_action(
                        'add', r['router']['id'], s['subnet']['id'], None)
                # Ensure metadata network was removed
                nets = self._list('networks')['networks']
                self.assertEqual(len(nets), 1)
                # Needed to avoid 409
                self._router_interface_action('remove',
                                              r['router']['id'],
                                              s['subnet']['id'],
                                              None)
        self._nvp_metadata_teardown()

    def test_metadata_network_create_rollback_on_add_rtr_iface_failure(self):
        self._nvp_metadata_setup()
        with self.router() as r:
            with self.subnet() as s:
                # Raise a NeutronException when adding metadata subnet
                # to router
                # save function being mocked
                real_func = self._plugin_class.add_router_interface
                plugin_instance = manager.NeutronManager.get_plugin()

                def side_effect(*args):
                    if args[-1]['subnet_id'] == s['subnet']['id']:
                        # do the real thing
                        return real_func(plugin_instance, *args)
                    # otherwise raise
                    raise NvpApiClient.NvpApiException()

                with mock.patch.object(self._plugin_class,
                                       'add_router_interface',
                                       side_effect=side_effect):
                    self._router_interface_action(
                        'add', r['router']['id'], s['subnet']['id'], None)
                # Ensure metadata network was removed
                nets = self._list('networks')['networks']
                self.assertEqual(len(nets), 1)
                # Needed to avoid 409
                self._router_interface_action('remove',
                                              r['router']['id'],
                                              s['subnet']['id'],
                                              None)
        self._nvp_metadata_teardown()

    def test_metadata_network_removed_with_router_interface_remove(self):
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

    def test_metadata_network_remove_rollback_on_failure(self):
        self._nvp_metadata_setup()
        with self.router() as r:
            with self.subnet() as s:
                self._router_interface_action('add', r['router']['id'],
                                              s['subnet']['id'], None)
                networks = self._list('networks')['networks']
                for network in networks:
                    if network['id'] != s['subnet']['network_id']:
                        meta_net_id = network['id']
                ports = self._list(
                    'ports',
                    query_params='network_id=%s' % meta_net_id)['ports']
                meta_port_id = ports[0]['id']
                # Raise a NeutronException when removing
                # metadata subnet from router
                # save function being mocked
                real_func = self._plugin_class.remove_router_interface
                plugin_instance = manager.NeutronManager.get_plugin()

                def side_effect(*args):
                    if args[-1].get('subnet_id') == s['subnet']['id']:
                        # do the real thing
                        return real_func(plugin_instance, *args)
                    # otherwise raise
                    raise NvpApiClient.NvpApiException()

                with mock.patch.object(self._plugin_class,
                                       'remove_router_interface',
                                       side_effect=side_effect):
                    self._router_interface_action('remove', r['router']['id'],
                                                  s['subnet']['id'], None)
                # Metadata network and subnet should still be there
                self._show('networks', meta_net_id,
                           webob.exc.HTTPOk.code)
                self._show('ports', meta_port_id,
                           webob.exc.HTTPOk.code)
        self._nvp_metadata_teardown()

    def test_metadata_dhcp_host_route(self):
        cfg.CONF.set_override('metadata_mode', 'dhcp_host_route', 'NVP')
        subnets = self._list('subnets')['subnets']
        with self.subnet() as s:
            with self.port(subnet=s, device_id='1234',
                           device_owner='network:dhcp'):
                subnets = self._list('subnets')['subnets']
                self.assertEqual(len(subnets), 1)
                self.assertEqual(subnets[0]['host_routes'][0]['nexthop'],
                                 '10.0.0.2')
                self.assertEqual(subnets[0]['host_routes'][0]['destination'],
                                 '169.254.169.254/32')

            subnets = self._list('subnets')['subnets']
            # Test that route is deleted after dhcp port is removed
            self.assertEqual(len(subnets[0]['host_routes']), 0)

    def test_floatingip_disassociate(self):
        with self.port() as p:
            private_sub = {'subnet': {'id':
                                      p['port']['fixed_ips'][0]['subnet_id']}}
            with self.floatingip_no_assoc(private_sub) as fip:
                port_id = p['port']['id']
                body = self._update('floatingips', fip['floatingip']['id'],
                                    {'floatingip': {'port_id': port_id}})
                self.assertEqual(body['floatingip']['port_id'], port_id)
                # Disassociate
                body = self._update('floatingips', fip['floatingip']['id'],
                                    {'floatingip': {'port_id': None}})
                body = self._show('floatingips', fip['floatingip']['id'])
                self.assertIsNone(body['floatingip']['port_id'])
                self.assertIsNone(body['floatingip']['fixed_ip_address'])

    def test_create_router_maintenance_returns_503(self):
        with self._create_l3_ext_network() as net:
            with self.subnet(network=net) as s:
                with mock.patch.object(
                    nvplib,
                    'do_request',
                    side_effect=nvp_exc.MaintenanceInProgress):
                    data = {'router': {'tenant_id': 'whatever'}}
                    data['router']['name'] = 'router1'
                    data['router']['external_gateway_info'] = {
                        'network_id': s['subnet']['network_id']}
                    router_req = self.new_create_request(
                        'routers', data, self.fmt)
                    res = router_req.get_response(self.ext_api)
                    self.assertEqual(webob.exc.HTTPServiceUnavailable.code,
                                     res.status_int)


class NvpQoSTestExtensionManager(object):

    def get_resources(self):
        return ext_qos.Nvp_qos.get_resources()

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


class TestNiciraQoSQueue(NiciraPluginV2TestCase):

    def setUp(self, plugin=None):
        cfg.CONF.set_override('api_extensions_path', NVPEXT_PATH)
        super(TestNiciraQoSQueue, self).setUp()
        ext_mgr = NvpQoSTestExtensionManager()
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

    def test_create_trusted_qos_queue(self):
        with mock.patch.object(qos_db.LOG, 'info') as log:
            with mock.patch.object(nvplib, 'do_request',
                                   return_value={"uuid": "fake_queue"}):
                with self.qos_queue(name='fake_lqueue', min=34, max=44,
                                    qos_marking='trusted', default=False) as q:
                    self.assertEqual(q['qos_queue']['dscp'], None)
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

    def test_dscp_value_out_of_range(self):
        body = {'qos_queue': {'tenant_id': 'admin', 'dscp': '64',
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
        self.assertFalse(ext_qos.QUEUE in port['port'])

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


class NiciraExtGwModeTestCase(NiciraPluginV2TestCase,
                              test_ext_gw_mode.ExtGwModeIntTestCase):
    pass


class NiciraNeutronNVPOutOfSync(NiciraPluginV2TestCase,
                                test_l3_plugin.L3NatTestCaseMixin):

    def setUp(self):
        ext_mgr = test_l3_plugin.L3TestExtensionManager()
        test_lib.test_config['extension_manager'] = ext_mgr
        super(NiciraNeutronNVPOutOfSync, self).setUp()

    def test_delete_network_not_in_nvp(self):
        res = self._create_network('json', 'net1', True)
        net1 = self.deserialize('json', res)
        self.fc._fake_lswitch_dict.clear()
        req = self.new_delete_request('networks', net1['network']['id'])
        res = req.get_response(self.api)
        self.assertEqual(res.status_int, 204)

    def test_show_network_not_in_nvp(self):
        res = self._create_network('json', 'net1', True)
        net = self.deserialize('json', res)
        self.fc._fake_lswitch_dict.clear()
        req = self.new_show_request('networks', net['network']['id'],
                                    fields=['id', 'status'])
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

    def test_show_port_not_in_nvp(self):
        res = self._create_network('json', 'net1', True)
        net1 = self.deserialize('json', res)
        res = self._create_port('json', net1['network']['id'])
        port = self.deserialize('json', res)
        self.fc._fake_lswitch_lport_dict.clear()
        self.fc._fake_lswitch_lportstatus_dict.clear()
        req = self.new_show_request('ports', port['port']['id'],
                                    fields=['id', 'status'])
        net = self.deserialize('json', req.get_response(self.api))
        self.assertEqual(net['port']['status'],
                         constants.PORT_STATUS_ERROR)

    def test_create_port_on_network_not_in_nvp(self):
        res = self._create_network('json', 'net1', True)
        net1 = self.deserialize('json', res)
        self.fc._fake_lswitch_dict.clear()
        res = self._create_port('json', net1['network']['id'])
        port = self.deserialize('json', res)
        self.assertEqual(port['port']['status'], constants.PORT_STATUS_ERROR)

    def test_update_port_not_in_nvp(self):
        res = self._create_network('json', 'net1', True)
        net1 = self.deserialize('json', res)
        res = self._create_port('json', net1['network']['id'])
        port = self.deserialize('json', res)
        self.fc._fake_lswitch_lport_dict.clear()
        data = {'port': {'name': 'error_port'}}
        req = self.new_update_request('ports', data, port['port']['id'])
        port = self.deserialize('json', req.get_response(self.api))
        self.assertEqual(port['port']['status'], constants.PORT_STATUS_ERROR)
        self.assertEqual(port['port']['name'], 'error_port')

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

    def test_show_router_not_in_nvp(self):
        res = self._create_router('json', 'tenant')
        router = self.deserialize('json', res)
        self.fc._fake_lrouter_dict.clear()
        req = self.new_show_request('routers', router['router']['id'],
                                    fields=['id', 'status'])
        router = self.deserialize('json', req.get_response(self.ext_api))
        self.assertEqual(router['router']['status'],
                         constants.NET_STATUS_ERROR)

    def _create_network_and_subnet(self, cidr, external=False):
        net_res = self._create_network('json', 'ext_net', True)
        net = self.deserialize('json', net_res)
        net_id = net['network']['id']
        if external:
            self._update('networks', net_id,
                         {'network': {external_net.EXTERNAL: True}})
        sub_res = self._create_subnet('json', net_id, cidr)
        sub = self.deserialize('json', sub_res)
        return net_id, sub['subnet']['id']

    def test_clear_gateway_nat_rule_not_in_nvp(self):
        # Create external network and subnet
        ext_net_id = self._create_network_and_subnet('1.1.1.0/24', True)[0]
        # Create internal network and subnet
        int_sub_id = self._create_network_and_subnet('10.0.0.0/24')[1]
        res = self._create_router('json', 'tenant')
        router = self.deserialize('json', res)
        # Add interface to router (needed to generate NAT rule)
        req = self.new_action_request(
            'routers',
            {'subnet_id': int_sub_id},
            router['router']['id'],
            "add_router_interface")
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, 200)
        # Set gateway for router
        req = self.new_update_request(
            'routers',
            {'router': {'external_gateway_info':
                        {'network_id': ext_net_id}}},
            router['router']['id'])
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, 200)
        # Delete NAT rule from NVP, clear gateway
        # and verify operation still succeeds
        self.fc._fake_lrouter_nat_dict.clear()
        req = self.new_update_request(
            'routers',
            {'router': {'external_gateway_info': {}}},
            router['router']['id'])
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, 200)

    def test_update_router_not_in_nvp(self):
        res = self._create_router('json', 'tenant')
        router = self.deserialize('json', res)
        self.fc._fake_lrouter_dict.clear()
        req = self.new_update_request(
            'routers',
            {'router': {'name': 'goo'}},
            router['router']['id'])
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, 500)
        req = self.new_show_request('routers', router['router']['id'])
        router = self.deserialize('json', req.get_response(self.ext_api))
        self.assertEqual(router['router']['status'],
                         constants.NET_STATUS_ERROR)


class TestNiciraNetworkGateway(test_l2_gw.NetworkGatewayDbTestCase,
                               NiciraPluginV2TestCase):

    def setUp(self):
        cfg.CONF.set_override('api_extensions_path', NVPEXT_PATH)
        super(TestNiciraNetworkGateway, self).setUp()

    def test_create_network_gateway_name_exceeds_40_chars(self):
        name = 'this_is_a_gateway_whose_name_is_longer_than_40_chars'
        with self._network_gateway(name=name) as nw_gw:
            # Assert Neutron name is not truncated
            self.assertEqual(nw_gw[self.resource]['name'], name)

    def test_update_network_gateway_with_name_calls_backend(self):
        with mock.patch.object(
            nvplib, 'update_l2_gw_service') as mock_update_gw:
            with self._network_gateway(name='cavani') as nw_gw:
                nw_gw_id = nw_gw[self.resource]['id']
                self._update(nvp_networkgw.COLLECTION_NAME, nw_gw_id,
                             {self.resource: {'name': 'higuain'}})
                mock_update_gw.assert_called_once_with(
                    mock.ANY, nw_gw_id, 'higuain')

    def test_update_network_gateway_without_name_does_not_call_backend(self):
        with mock.patch.object(
            nvplib, 'update_l2_gw_service') as mock_update_gw:
            with self._network_gateway(name='something') as nw_gw:
                nw_gw_id = nw_gw[self.resource]['id']
                self._update(nvp_networkgw.COLLECTION_NAME, nw_gw_id,
                             {self.resource: {}})
                self.assertEqual(mock_update_gw.call_count, 0)

    def test_update_network_gateway_name_exceeds_40_chars(self):
        new_name = 'this_is_a_gateway_whose_name_is_longer_than_40_chars'
        with self._network_gateway(name='something') as nw_gw:
            nw_gw_id = nw_gw[self.resource]['id']
            self._update(nvp_networkgw.COLLECTION_NAME, nw_gw_id,
                         {self.resource: {'name': new_name}})
            req = self.new_show_request(nvp_networkgw.COLLECTION_NAME,
                                        nw_gw_id)
            res = self.deserialize('json', req.get_response(self.ext_api))
            # Assert Neutron name is not truncated
            self.assertEqual(new_name, res[self.resource]['name'])
            # Assert NVP name is truncated
            self.assertEqual(
                new_name[:40],
                self.fc._fake_gatewayservice_dict[nw_gw_id]['display_name'])

    def test_create_network_gateway_nvp_error_returns_500(self):
        def raise_nvp_api_exc(*args, **kwargs):
            raise NvpApiClient.NvpApiException

        with mock.patch.object(nvplib,
                               'create_l2_gw_service',
                               new=raise_nvp_api_exc):
            res = self._create_network_gateway(
                self.fmt, 'xxx', name='yyy',
                devices=[{'id': uuidutils.generate_uuid()}])
            self.assertEqual(500, res.status_int)

    def test_create_network_gateway_nvp_error_returns_409(self):
        with mock.patch.object(nvplib,
                               'create_l2_gw_service',
                               side_effect=NvpApiClient.Conflict):
            res = self._create_network_gateway(
                self.fmt, 'xxx', name='yyy',
                devices=[{'id': uuidutils.generate_uuid()}])
            self.assertEqual(409, res.status_int)

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

    def test_list_network_gateway_with_multiple_connections(self):
        self._test_list_network_gateway_with_multiple_connections(
            expected_gateways=2)

    def test_delete_network_gateway(self):
        # The default gateway must still be there
        self._test_delete_network_gateway(1)


class TestNiciraMultiProviderNetworks(NiciraPluginV2TestCase):

    def setUp(self, plugin=None):
        cfg.CONF.set_override('api_extensions_path', NVPEXT_PATH)
        super(TestNiciraMultiProviderNetworks, self).setUp()

    def test_create_network_provider(self):
        data = {'network': {'name': 'net1',
                            pnet.NETWORK_TYPE: 'vlan',
                            pnet.PHYSICAL_NETWORK: 'physnet1',
                            pnet.SEGMENTATION_ID: 1,
                            'tenant_id': 'tenant_one'}}
        network_req = self.new_create_request('networks', data)
        network = self.deserialize(self.fmt,
                                   network_req.get_response(self.api))
        self.assertEqual(network['network'][pnet.NETWORK_TYPE], 'vlan')
        self.assertEqual(network['network'][pnet.PHYSICAL_NETWORK], 'physnet1')
        self.assertEqual(network['network'][pnet.SEGMENTATION_ID], 1)
        self.assertNotIn(mpnet.SEGMENTS, network['network'])

    def test_create_network_single_multiple_provider(self):
        data = {'network': {'name': 'net1',
                            mpnet.SEGMENTS:
                            [{pnet.NETWORK_TYPE: 'vlan',
                              pnet.PHYSICAL_NETWORK: 'physnet1',
                              pnet.SEGMENTATION_ID: 1}],
                            'tenant_id': 'tenant_one'}}
        net_req = self.new_create_request('networks', data)
        network = self.deserialize(self.fmt, net_req.get_response(self.api))
        for provider_field in [pnet.NETWORK_TYPE, pnet.PHYSICAL_NETWORK,
                               pnet.SEGMENTATION_ID]:
            self.assertTrue(provider_field not in network['network'])
        tz = network['network'][mpnet.SEGMENTS][0]
        self.assertEqual(tz[pnet.NETWORK_TYPE], 'vlan')
        self.assertEqual(tz[pnet.PHYSICAL_NETWORK], 'physnet1')
        self.assertEqual(tz[pnet.SEGMENTATION_ID], 1)

        # Tests get_network()
        net_req = self.new_show_request('networks', network['network']['id'])
        network = self.deserialize(self.fmt, net_req.get_response(self.api))
        tz = network['network'][mpnet.SEGMENTS][0]
        self.assertEqual(tz[pnet.NETWORK_TYPE], 'vlan')
        self.assertEqual(tz[pnet.PHYSICAL_NETWORK], 'physnet1')
        self.assertEqual(tz[pnet.SEGMENTATION_ID], 1)

    def test_create_network_multprovider(self):
        data = {'network': {'name': 'net1',
                            mpnet.SEGMENTS:
                            [{pnet.NETWORK_TYPE: 'vlan',
                              pnet.PHYSICAL_NETWORK: 'physnet1',
                              pnet.SEGMENTATION_ID: 1},
                            {pnet.NETWORK_TYPE: 'stt',
                             pnet.PHYSICAL_NETWORK: 'physnet1'}],
                            'tenant_id': 'tenant_one'}}
        network_req = self.new_create_request('networks', data)
        network = self.deserialize(self.fmt,
                                   network_req.get_response(self.api))
        tz = network['network'][mpnet.SEGMENTS]
        for tz in data['network'][mpnet.SEGMENTS]:
            for field in [pnet.NETWORK_TYPE, pnet.PHYSICAL_NETWORK,
                          pnet.SEGMENTATION_ID]:
                self.assertEqual(tz.get(field), tz.get(field))

        # Tests get_network()
        net_req = self.new_show_request('networks', network['network']['id'])
        network = self.deserialize(self.fmt, net_req.get_response(self.api))
        tz = network['network'][mpnet.SEGMENTS]
        for tz in data['network'][mpnet.SEGMENTS]:
            for field in [pnet.NETWORK_TYPE, pnet.PHYSICAL_NETWORK,
                          pnet.SEGMENTATION_ID]:
                self.assertEqual(tz.get(field), tz.get(field))

    def test_create_network_with_provider_and_multiprovider_fail(self):
        data = {'network': {'name': 'net1',
                            mpnet.SEGMENTS:
                            [{pnet.NETWORK_TYPE: 'vlan',
                              pnet.PHYSICAL_NETWORK: 'physnet1',
                              pnet.SEGMENTATION_ID: 1}],
                            pnet.NETWORK_TYPE: 'vlan',
                            pnet.PHYSICAL_NETWORK: 'physnet1',
                            pnet.SEGMENTATION_ID: 1,
                            'tenant_id': 'tenant_one'}}

        network_req = self.new_create_request('networks', data)
        res = network_req.get_response(self.api)
        self.assertEqual(res.status_int, 400)

    def test_create_network_duplicate_segments(self):
        data = {'network': {'name': 'net1',
                            mpnet.SEGMENTS:
                            [{pnet.NETWORK_TYPE: 'vlan',
                              pnet.PHYSICAL_NETWORK: 'physnet1',
                              pnet.SEGMENTATION_ID: 1},
                            {pnet.NETWORK_TYPE: 'vlan',
                             pnet.PHYSICAL_NETWORK: 'physnet1',
                             pnet.SEGMENTATION_ID: 1}],
                            'tenant_id': 'tenant_one'}}
        network_req = self.new_create_request('networks', data)
        res = network_req.get_response(self.api)
        self.assertEqual(res.status_int, 400)
