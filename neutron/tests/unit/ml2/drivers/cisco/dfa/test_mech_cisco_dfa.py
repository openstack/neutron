# Copyright 2014 Cisco Systems, Inc.
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
#


import mock
from oslo.config import cfg
import testtools

from neutron.common import exceptions as n_exc
from neutron.plugins.ml2.drivers.cisco.dfa import cisco_dfa_rest
from neutron.plugins.ml2.drivers.cisco.dfa import config
from neutron.plugins.ml2.drivers.cisco.dfa import dfa_exceptions as dexc
from neutron.plugins.ml2.drivers.cisco.dfa import dfa_instance_api
from neutron.plugins.ml2.drivers.cisco.dfa import mech_cisco_dfa
from neutron.plugins.ml2.drivers.cisco.dfa import project_events
from neutron.plugins.ml2.drivers.cisco.dfa import projects_cache_db_v2
from neutron.tests import base


FAKE_NETWORK_NAME = 'test_dfa_network'
FAKE_NETWORK_ID = '949fdd05-a26a-4819-a829-9fc2285de6ff'
FAKE_CFG_PROF_ID = '8c30f360ffe948109c28ab56f69a82e1'
FAKE_SEG_ID = 12345
FAKE_PROJECT_NAME = 'test_dfa_project'
FAKE_PROJECT_ID = 'aee5da7e699444889c662cf7ec1c8de7'
FAKE_CFG_PROFILE_NAME = 'defaultNetworkL2Profile'
FAKE_INSTANCE_NAME = 'test_dfa_instance'
FAKE_SUBNET_ID = '1a3c5ee1-cb92-4fd8-bff1-8312ac295d64'
FAKE_PORT_ID = 'ea0d92cf-d0cb-4ed2-bbcf-ed7c6aaea4cb'
FAKE_DEVICE_ID = '20305657-78b7-48f4-a7cd-1edf3edbfcad'
FAKE_SECURITY_GRP_ID = '4b5b387d-cf21-4594-b926-f5a5c602295f'
FAKE_MAC_ADDR = 'fa:16:3e:70:15:c4'
FAKE_IP_ADDR = '23.24.25.4'
FAKE_GW_ADDR = '23.24.25.1'
FAKE_DHCP_IP_RANGE_START = '23.24.25.2'
FAKE_DHCP_IP_RANGE_END = '23.24.25.254'
FAKE_HOST_ID = 'test_dfa_host'
FAKE_FWD_MODE = 'proxy-gateway'
FAKE_DCNM_USER = 'cisco'
FAKE_DCNM_PASS = 'password'
FAKE_DCNM_IP = '1.1.2.2'


class FakeNetworkContext(object):
    """Network context for testing purposes only."""

    def __init__(self, network):
        self._network = network
        self._session = None

    @property
    def current(self):
        return self._network

    @property
    def original(self):
        return self._network


class FakePortContext(object):
    """Port context for testing purposes only."""

    def __init__(self, plugin_context, port):
        self._port = port
        self._plugin_context = plugin_context
        self._session = None

    @property
    def current(self):
        return self._port


class FakeSubnetContext(object):
    """Subnet context for testing purposes only."""

    def __init__(self, subnet):
        self._subnet = subnet

    @property
    def current(self):
        return self._subnet


class TestCiscoDFAMechDriver(base.BaseTestCase):
    """Test cases for cisco DFA mechanism driver."""

    def setUp(self):
        super(TestCiscoDFAMechDriver, self).setUp()

        dcnmpatcher = mock.patch(cisco_dfa_rest.__name__ + '.DFARESTClient')
        self.mdcnm = dcnmpatcher.start()

        # Define retrun values for keystone project.
        keys_patcher = mock.patch(project_events.__name__ + '.EventsHandler')
        self.mkeys = keys_patcher.start()

        inst_api_patcher = mock.patch(dfa_instance_api.__name__ +
                                      '.DFAInstanceAPI')
        self.m_inst_api = inst_api_patcher.start()

        proj_patcher = mock.patch(projects_cache_db_v2.__name__ +
                                  '.ProjectsInfoCache')
        self.mock_proj = proj_patcher.start()

        dfa_cfg_patcher = mock.patch(config.__name__ + '.CiscoDFAConfig')
        self.m_dfa_cfg = dfa_cfg_patcher.start()
        ml2_cisco_dfa_opts = {'dcnm_password': FAKE_DCNM_PASS,
                              'dcnm_user': FAKE_DCNM_USER,
                              'dcnm_ip': FAKE_DCNM_IP}
        for opt, val in ml2_cisco_dfa_opts.items():
            cfg.CONF.set_override(opt, val, 'ml2_cisco_dfa')

        self.dfa_mech_drvr = mech_cisco_dfa.CiscoDfaMechanismDriver()
        self.dfa_mech_drvr.initialize()
        self.dfa_mech_drvr._keys.is_valid_project.return_value = True
        self.net_context = self._create_network_context()
        self.proj_info = projects_cache_db_v2.ProjectsInfoCache()

    def _create_network_context(self):
        net_info = {'name': FAKE_NETWORK_NAME,
                    'tenant_id': FAKE_PROJECT_ID,
                    'dfa:cfg_profile_id': FAKE_CFG_PROF_ID,
                    'provider:segmentation_id': FAKE_SEG_ID,
                    'id': FAKE_NETWORK_ID}
        net_context = FakeNetworkContext(net_info)
        net_context._plugin_context = mock.MagicMock()
        net_context._session = net_context._plugin_context.session
        return net_context

    def _create_subnet_context(self):
        subnet_info = {
            'ipv6_ra_mode': None,
            'allocation_pools': [{'start': FAKE_DHCP_IP_RANGE_START,
                                  'end': FAKE_DHCP_IP_RANGE_END}],
            'host_routes': [],
            'ipv6_address_mode': None,
            'cidr': '23.24.25.0/24',
            'id': FAKE_SUBNET_ID,
            'name': u'',
            'enable_dhcp': True,
            'network_id': FAKE_NETWORK_ID,
            'tenant_id': FAKE_PROJECT_ID,
            'dns_nameservers': [],
            'gateway_ip': FAKE_GW_ADDR,
            'ip_version': 4,
            'shared': False}
        subnet_context = FakeSubnetContext(subnet_info)
        subnet_context._plugin_context = mock.MagicMock()
        return subnet_context

    def _create_port_context(self):
        port_info = {
            'status': 'ACTIVE',
            'binding:host_id': FAKE_HOST_ID,
            'allowed_address_pairs': [],
            'extra_dhcp_opts': [],
            'device_owner': u'compute:nova',
            'binding:profile': {},
            'fixed_ips': [{'subnet_id': FAKE_SUBNET_ID,
            'ip_address': FAKE_IP_ADDR}],
            'id': FAKE_PORT_ID,
            'security_groups': [FAKE_SECURITY_GRP_ID],
            'device_id': FAKE_DEVICE_ID,
            'name': u'',
            'admin_state_up': True,
            'network_id': FAKE_NETWORK_ID,
            'tenant_id': FAKE_PROJECT_ID,
            'binding:vif_details': {u'port_filter': True,
                                    u'ovs_hybrid_plug': True},
            'binding:vnic_type': u'normal',
            'binding:vif_type': u'ovs',
            'mac_address': FAKE_MAC_ADDR}
        port_context = FakePortContext(mock.MagicMock(), port_info)
        port_context._plugin_context = mock.MagicMock()
        port_context._session = port_context._plugin_context.session
        return port_context

    def test_create_network_postcommit_no_profile(self):
        query = self.net_context._session.query.return_value
        query.filter_by.return_value.one.return_value = None
        # Profile does not exist, catch the exception.
        with testtools.ExpectedException(n_exc.BadRequest):
            self.dfa_mech_drvr.create_network_postcommit(self.net_context)

    def test_create_network_postcommit_no_project(self):
        self.proj_info.get_project_name.side_effect = (
                        dexc.ProjectIdNotFound(project_id=FAKE_PROJECT_ID))
        # Project does not exist, catch the exception.
        with testtools.ExpectedException(dexc.ProjectIdNotFound):
            self.dfa_mech_drvr.create_network_postcommit(self.net_context)

    def test_delete_network_postcommit(self):
        self.dfa_mech_drvr.delete_network_postcommit(self.net_context)
        self.mdcnm.delete_network.return_value = None
        self.assertTrue(self.dfa_mech_drvr._dcnm_client.delete_network.called)

    def test_create_subnet_postcommit(self):
        subnet_ctxt = self._create_subnet_context()
        proj_obj = self.dfa_mech_drvr.projects_cache_db_v2
        cfgp_mock = mock.MagicMock(return_value=FAKE_CFG_PROFILE_NAME)
        self.dfa_mech_drvr.get_config_profile_name = cfgp_mock
        mechdrvr_mock = mock.MagicMock(return_value=self.net_context.current)
        self.dfa_mech_drvr.get_network_entry = mechdrvr_mock
        proj_obj.get_network_segid.return_value = FAKE_SEG_ID
        proj_obj.get_project_name.return_value = FAKE_PROJECT_NAME
        self.dfa_mech_drvr.create_subnet_postcommit(subnet_ctxt)
        self.assertTrue(self.dfa_mech_drvr._dcnm_client.create_network.called)

    def test_update_port_postcommit(self):
        port_ctxt = self._create_port_context()
        query = port_ctxt._session.query.return_value
        query.filter_by.return_value.one.return_value.forwarding_mode = (
                                                          FAKE_FWD_MODE)
        vm_info = {
            'status': 'up',
            'ip': port_ctxt.current.get('fixed_ips')[0]['ip_address'],
            'mac': port_ctxt.current.get('mac_address'),
            'segid': FAKE_SEG_ID,
            'inst_name': FAKE_INSTANCE_NAME,
            'inst_uuid': port_ctxt.current.get('device_id').replace('-', ''),
            'host': FAKE_HOST_ID,
            'port_id': port_ctxt.current.get('id'),
            'network_id': port_ctxt.current.get('network_id'),
            'oui_type': 'cisco',
        }
        self.proj_info.get_network_segid.return_value = FAKE_SEG_ID
        mechdrvr_mock = self.dfa_mech_drvr._inst_api.get_instance_for_uuid
        mechdrvr_mock.return_value = FAKE_INSTANCE_NAME
        self.dfa_mech_drvr.dfa_notifier = mock.MagicMock()
        self.dfa_mech_drvr.update_port_postcommit(port_ctxt)
        self.assertTrue(self.dfa_mech_drvr.dfa_notifier.send_vm_info.called)
        self.dfa_mech_drvr.dfa_notifier.send_vm_info.assert_called_with(
            port_ctxt._plugin_context, vm_info)

    def test_delete_port_postcommit(self):
        port_ctxt = self._create_port_context()
        query = port_ctxt._session.query.return_value
        query.filter_by.return_value.one.return_value.forwarding_mode = (
                                                                FAKE_FWD_MODE)
        vm_info = {
            'status': 'down',
            'ip': port_ctxt.current.get('fixed_ips')[0]['ip_address'],
            'mac': port_ctxt.current.get('mac_address'),
            'segid': FAKE_SEG_ID,
            'inst_name': FAKE_INSTANCE_NAME,
            'inst_uuid': port_ctxt.current.get('device_id').replace('-', ''),
            'host': FAKE_HOST_ID,
            'port_id': port_ctxt.current.get('id'),
            'network_id': port_ctxt.current.get('network_id'),
            'oui_type': 'cisco',
        }
        self.proj_info.get_network_segid.return_value = FAKE_SEG_ID
        instapi_mock = self.dfa_mech_drvr._inst_api.get_instance_for_uuid
        instapi_mock.return_value = FAKE_INSTANCE_NAME
        self.dfa_mech_drvr.dfa_notifier = mock.MagicMock()
        self.dfa_mech_drvr.delete_port_postcommit(port_ctxt)
        self.assertTrue(self.dfa_mech_drvr.dfa_notifier.send_vm_info.called)
        self.dfa_mech_drvr.dfa_notifier.send_vm_info.assert_called_with(
                 port_ctxt._plugin_context, vm_info)
