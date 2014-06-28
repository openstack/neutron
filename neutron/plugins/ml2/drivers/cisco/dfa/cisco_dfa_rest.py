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


from oslo.config import cfg
import requests

from neutron.openstack.common import jsonutils
from neutron.openstack.common import log as logging
from neutron.plugins.ml2.drivers.cisco.dfa import dfa_exceptions as dexc

LOG = logging.getLogger(__name__)


class DFARESTClient(object):
    """DFA client class that provides APIs to interact with DCNM."""

    def __init__(self):
        self._ip = cfg.CONF.ml2_cisco_dfa.dcnm_ip
        self._user = cfg.CONF.ml2_cisco_dfa.dcnm_user
        self._pwd = cfg.CONF.ml2_cisco_dfa.dcnm_password
        if (not self._ip) or (not self._user) or (not self._pwd):
            msg = _("[DFARESTClient] Input DCNM IP, user name or password"
                    "parameter is not specified")
            raise ValueError(msg)

        # url timeout: 10 seconds
        self._TIMEOUT_RESPONSE = 10

        # urls
        net_url = 'http://%s/' % self._ip
        net_url += 'rest/auto-config/organizations/%s/partitions/%s/networks'
        self._create_network_url = net_url
        cfg_url = 'http://%s/rest/auto-config/profiles' % self._ip
        self._cfg_profile_list_url = cfg_url
        cfg_url += '/%s'
        self._cfg_profile_get_url = cfg_url
        self._org_url = 'http://%s/rest/auto-config/organizations' % self._ip
        tmp_url = 'http://%s/rest/auto-config/organizations/' % self._ip
        tmp_url += '%s/partitions'
        self._create_part_url = tmp_url
        self._del_org_url = self._org_url + '/%s'
        self._del_part = self._org_url + '/%s/partitions/%s'
        self._del_network_url = (self._org_url +
                                 '/%s/partitions/%s/networks/segment/%s')
        self._login_url = 'http://%s/rest/logon' % (self._ip)
        self._logout_url = 'http://%s/rest/logout' % (self._ip)
        self._exp_time = 100000
        self._resp_ok = 200

    def _create_network(self, network_info):
        """Send create network request to DCNM.

        :network_info: network parameters to be created on DCNM
        """
        url = self._create_network_url % (network_info['partitionName'],
                                          network_info['partitionName'])
        payload = network_info

        LOG.info(_('url %(url)s payload %(payload)s'),
                 {'url': url, 'payload': payload})
        return (self._send_request('POST', url, payload, 'network'))

    def _config_profile_get(self, thisprofile):
        """Get information of a config profile from DCNM.

        :thisprofile: network config profile in request
        """
        url = self._cfg_profile_get_url % (thisprofile)
        payload = {}

        res = self._send_request('GET', url, payload, 'config-profile')
        return res.json()

    def _config_profile_list(self):
        """Get list of supported config profile from DCNM."""
        url = self._cfg_profile_list_url
        payload = {}

        res = self._send_request('GET', url, payload, 'config-profile')
        return res.json()

    def _create_org(self, name, desc):
        """Create organization on the DCNM.

        :name: Name of organization
        :desc: Description of organization
        """
        url = self._org_url
        payload = {
            "organizationName": name,
            "description": name if len(desc) == 0 else desc,
            "orchestrationSource": "Openstack Controller"}

        return (self._send_request('POST', url, payload, 'organization'))

    def _create_partition(self, org_name, part_name, desc):
        """Send Create partition request to the DCNM.

        :org_name: name of organization
        :part_name: name of partition
        :desc: description of partition
        """
        url = self._create_part_url % (org_name)
        payload = {
            "partitionName": part_name,
            "description": part_name if len(desc) == 0 else desc,
            "organizationName": org_name}

        return (self._send_request('POST', url, payload, 'partition'))

    def _delete_org(self, org_name):
        """Send organization delete request to DCNM.

        :org_name: name of organization to be deleted
        """
        url = self._del_org_url % (org_name)
        self._send_request('DELETE', url, '', 'organization')

    def _delete_partition(self, org_name, partition_name):
        """Send partition delete request to DCNM.

        :partition_name: name of partition to be deleted
        """
        url = self._del_part % (org_name, partition_name)
        self._send_request('DELETE', url, '', 'partition')

    def _delete_network(self, network_info):
        """Send network delete request to DCNM.

        :partition_name: name of partition to be deleted
        """
        org_name = network_info.get('organizationName', '')
        part_name = network_info.get('partitionName', '')
        segment_id = network_info['segmentId']
        url = self._del_network_url % (org_name, part_name, segment_id)
        self._send_request('DELETE', url, '', 'network')

    def _login(self):
        """Login request to DCNM."""
        url_login = self._login_url
        expiration_time = self._exp_time

        payload = {'expirationTime': expiration_time}
        self._req_headers = {'Accept': 'application/json',
                             'Content-Type': 'application/json; charset=UTF-8'}
        res = requests.post(url_login,
                            data=jsonutils.dumps(payload),
                            headers=self._req_headers,
                            auth=(self._user, self._pwd),
                            timeout=self._TIMEOUT_RESPONSE)
        session_id = ''
        if res and res.status_code == self._resp_ok:
            session_id = res.json().get('Dcnm-Token')
        self._req_headers.update({'Dcnm-Token': session_id})

    def _logout(self):
        """Logout request to DCNM."""
        url_logout = self._logout_url
        requests.post(url_logout,
                      headers=self._req_headers,
                      timeout=self._TIMEOUT_RESPONSE)

    def _send_request(self, operation, url, payload, desc):
        """Send request to DCNM."""
        res = None
        try:
            payload_json = None
            if payload and payload != '':
                payload_json = jsonutils.dumps(payload)
            self._login()
            desc_lookup = {'POST': ' creation', 'PUT': ' update',
                           'DELETE': ' deletion', 'GET': ' get'}

            res = requests.request(operation, url, data=payload_json,
                                   headers=self._req_headers,
                                   timeout=self._TIMEOUT_RESPONSE)
            desc += desc_lookup.get(operation, operation.lower())
            LOG.info(_("DCNM-send_request: %(desc)s %(url)s %(pld)s"),
                     {'desc': desc, 'url': url, 'pld': payload})

            self._logout()
        except (requests.HTTPError, requests.Timeout,
                requests.ConnectionError) as e:
            LOG.exception(_('Error during request'))
            raise dexc.DFAClientRequestFailed(reason=e)

        return res

    def _check_for_supported_profile(self, thisprofile):
        """Filter those profiles that are not currently supported."""
        return (thisprofile.endswith('Ipv4TfProfile') or
                thisprofile.endswith('Ipv4EfProfile') or
                'defaultNetworkL2Profile' in thisprofile)

    def config_profile_list(self):
        """Return config profile list from DCNM."""
        profile_list = []
        these_profiles = []
        these_profiles = self._config_profile_list()
        profile_list = [q for p in these_profiles for q in
                        [p.get('profileName')]
                        if self._check_for_supported_profile(q)]
        return profile_list

    def config_profile_fwding_mode_get(self, profile_name):
        """Return forwarding mode of given config profile."""
        profile_params = self._config_profile_get(profile_name)
        fwd_cli = 'fabric forwarding mode proxy-gateway'
        if fwd_cli in profile_params['configCommands']:
            return 'proxy-gateway'
        else:
            return 'anycast-gateway'

    def create_network(self, tenant_name, network, subnet):
        """Create network on the DCNM.

        :tenant_name: name of tenant the network belongs to
        :network: network parameters
        :subnet: subnet parameters of the network
        """
        network_info = {}
        seg_id = str(network.provider__segmentation_id)
        subnet_ip_mask = subnet.cidr.split('/')
        gw_ip = subnet.gateway_ip
        cfg_args = [
            "$segmentId=" + seg_id,
            "$netMaskLength=" + subnet_ip_mask[1],
            "$gatewayIpAddress=" + gw_ip,
            "$networkName=" + network.name,
            "$vlanId=0",
            "$vrfName=" + tenant_name + ':' + tenant_name
        ]
        cfg_args = ';'.join(cfg_args)

        ip_range = ','.join(["%s-%s" % (p['start'], p['end']) for p in
                   subnet.allocation_pools])

        dhcp_scopes = {'ipRange': ip_range,
                       'subnet': subnet.cidr,
                       'gateway': gw_ip}

        network_info = {"segmentId": seg_id,
                        "vlanId": "0",
                        "mobilityDomainId": "None",
                        "profileName": network.config_profile,
                        "networkName": network.name,
                        "configArg": cfg_args,
                        "organizationName": tenant_name,
                        "partitionName": tenant_name,
                        "description": network.name,
                        "dhcpScope": dhcp_scopes}
        LOG.debug("Create %s network in DCNM." % network_info)

        self._create_network(network_info)

    def delete_network(self, tenant_name, network):
        """Delete network on the DCNM.

        :tenant_name: name of tenant the network belongs to
        :network: object that contains network parameters
        """
        network_info = {}
        seg_id = network.provider__segmentation_id
        network_info = {
            'organizationName': tenant_name,
            'partitionName': tenant_name,
            'segmentId': seg_id,
        }
        LOG.debug("Delete %s network in DCNM." % network_info)

        self._delete_network(network_info)

    def delete_tenant(self, tenant_name):
        """Delete tenant on the DCNM.

        :tenant_name: name of tenant to be deleted.
        """
        self._delete_partition(tenant_name, tenant_name)
        self._delete_org(tenant_name)

    def create_project(self, org_name, desc=None):
        """Create project on the DCNM.

        :org_name: name of organization to be created
        :desc: string that describes organization
        """
        desc = desc or org_name
        self._create_org(org_name, desc)
        self._create_partition(org_name, org_name, desc)
