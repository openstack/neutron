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

from neutron.plugins.ml2.drivers.cisco.dfa import cisco_dfa_rest as dc
from neutron.plugins.ml2.drivers.cisco.dfa import config  # noqa
from neutron.tests import base


"""This file includes test cases for cisco_dfa_rest.py."""

FAKE_DCNM_IP = '1.1.1.1'
FAKE_DCNM_USERNAME = 'dcnmuser'
FAKE_DCNM_PASSWORD = 'dcnmpass'
org_url = 'http://%s/rest/auto-config/organizations'
part_url = 'http://%s/rest/auto-config/organizations/%s/partitions'
net_url = 'http://%s/rest/auto-config/organizations/%s/partitions/%s/networks'
del_net_url = ('http://%s/rest/auto-config/organizations/%s/partitions/%s/'
               'networks/segment/%s')


class TestNetwork(object):
    provider__segmentation_id = 123456
    name = 'cisco_test_network'
    config_profile = 'defaultL2ConfigProfile'


class TestCiscoDFAClient(base.BaseTestCase):
    """Test cases for DFARESTClient."""

    def setUp(self):
        # Declare the test resource.
        super(TestCiscoDFAClient, self).setUp()

        dcnm_cfg = {'dcnm_ip': FAKE_DCNM_IP,
                    'dcnm_user': FAKE_DCNM_USERNAME,
                    'dcnm_password': FAKE_DCNM_PASSWORD}
        for k, v in dcnm_cfg.items():
            cfg.CONF.set_override(k, v, 'ml2_cisco_dfa')

        self.dcnm_client = dc.DFARESTClient()
        mock.patch.object(self.dcnm_client, '_send_request').start()
        self.testnetwork = TestNetwork()

    def test_create_org(self):
        """Test create organization."""

        org_name = 'Test_Project'
        url = org_url % (cfg.CONF.ml2_cisco_dfa.dcnm_ip)
        payload = {'organizationName': org_name,
                   'description': org_name,
                   'orchestrationSource': 'Openstack Controller'}
        self.dcnm_client._create_org(org_name, org_name)
        self.dcnm_client._send_request.assert_called_with('POST', url,
                                                          payload,
                                                          'organization')

    def test_create_partition(self):
        """Test create partition."""

        org_name = 'Cisco'
        part_name = 'Lab'
        url = part_url % (cfg.CONF.ml2_cisco_dfa.dcnm_ip, org_name)
        payload = {'partitionName': part_name,
                   'description': org_name,
                   'organizationName': org_name}
        self.dcnm_client._create_partition(org_name, part_name, org_name)
        self.dcnm_client._send_request.assert_called_with('POST', url,
                                                          payload,
                                                          'partition')

    def test_create_project(self):
        """Test create project."""

        org_name = 'Cisco'
        self.dcnm_client.create_project(org_name)
        call_cnt = self.dcnm_client._send_request.call_count
        self.assertEqual(2, call_cnt)

    def test_create_network(self):
        """Test create network."""

        network_info = {}
        cfg_args = []
        seg_id = str(self.testnetwork.provider__segmentation_id)
        config_profile = self.testnetwork.config_profile
        network_name = self.testnetwork.name
        tenant_name = 'Cisco'
        url = net_url % (cfg.CONF.ml2_cisco_dfa.dcnm_ip, tenant_name,
                         tenant_name)

        cfg_args.append("$segmentId=" + seg_id)
        cfg_args.append("$netMaskLength=16")
        cfg_args.append("$gatewayIpAddress=30.31.32.1")
        cfg_args.append("$networkName=" + network_name)
        cfg_args.append("$vlanId=0")
        cfg_args.append("$vrfName=%s:%s" % (tenant_name, tenant_name))
        cfg_args = ';'.join(cfg_args)

        dhcp_scopes = {'ipRange': '10.11.12.14-10.11.12.254',
                       'subnet': '10.11.12.13',
                       'gateway': '10.11.12.1'}

        network_info = {"segmentId": seg_id,
                        "vlanId": "0",
                        "mobilityDomainId": "None",
                        "profileName": config_profile,
                        "networkName": network_name,
                        "configArg": cfg_args,
                        "organizationName": tenant_name,
                        "partitionName": tenant_name,
                        "description": network_name,
                        "dhcpScope": dhcp_scopes}

        self.dcnm_client._create_network(network_info)
        self.dcnm_client._send_request.assert_called_with('POST', url,
                                                          network_info,
                                                          'network')

    def test_delete_network(self):
        """Test delete network."""

        seg_id = self.testnetwork.provider__segmentation_id
        tenant_name = 'cisco'
        url = del_net_url % (cfg.CONF.ml2_cisco_dfa.dcnm_ip,
                             tenant_name, tenant_name, seg_id)
        self.dcnm_client.delete_network(tenant_name, self.testnetwork)
        self.dcnm_client._send_request.assert_called_with('DELETE', url,
                                                          '', 'network')

    def test_delete_tenant(self):
        """Test delete tenant."""

        tenant_name = 'cisco'
        self.dcnm_client.delete_tenant(tenant_name)
        call_cnt = self.dcnm_client._send_request.call_count
        self.assertEqual(2, call_cnt)
