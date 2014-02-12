# Copyright 2014 VMware, Inc
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

from neutron.openstack.common import excutils
from neutron.openstack.common import log as logging
from neutron.plugins.vmware.vshield.common import (
    exceptions as vcns_exc)

LOG = logging.getLogger(__name__)

ENCRYPTION_ALGORITHM_MAP = {
    '3des': '3des',
    'aes-128': 'aes',
    'aes-256': 'aes256'
}

PFS_MAP = {
    'group2': 'dh2',
    'group5': 'dh5'}

TRANSFORM_PROTOCOL_ALLOWED = ('esp',)

ENCAPSULATION_MODE_ALLOWED = ('tunnel',)


class EdgeIPsecVpnDriver():

    """Driver APIs for Edge IPsec VPN bulk configuration."""

    def _check_ikepolicy_ipsecpolicy_allowed(self, ikepolicy, ipsecpolicy):
        """Check whether ikepolicy and ipsecpolicy are allowed on vshield edge.

        Some IPsec VPN configurations and features are configured by default or
        not supported on vshield edge.

        """
        # Check validation of IKEPolicy.
        if ikepolicy['ike_version'] != 'v1':
            msg = _("Unsupported ike_version: %s! Only 'v1' ike version is "
                    "supported on vshield Edge!"
                    ) % ikepolicy['ike_version']
            LOG.warning(msg)
            raise vcns_exc.VcnsBadRequest(resource='ikepolicy',
                                          msg=msg)

        # In VSE, Phase 1 and Phase 2 share the same encryption_algorithm
        # and authentication algorithms setting. At present, just record the
        # discrepancy error in log and take ipsecpolicy to do configuration.
        if (ikepolicy['auth_algorithm'] != ipsecpolicy['auth_algorithm'] or
            ikepolicy['encryption_algorithm'] != ipsecpolicy[
                'encryption_algorithm'] or
            ikepolicy['pfs'] != ipsecpolicy['pfs']):
            msg = _("IKEPolicy and IPsecPolicy should have consistent "
                    "auth_algorithm, encryption_algorithm and pfs for VSE!")
            LOG.warning(msg)

        # Check whether encryption_algorithm is allowed.
        encryption_algorithm = ENCRYPTION_ALGORITHM_MAP.get(
            ipsecpolicy.get('encryption_algorithm'), None)
        if not encryption_algorithm:
            msg = _("Unsupported encryption_algorithm: %s! '3des', "
                    "'aes-128' and 'aes-256' are supported on VSE right now."
                    ) % ipsecpolicy['encryption_algorithm']
            LOG.warning(msg)
            raise vcns_exc.VcnsBadRequest(resource='ipsecpolicy',
                                          msg=msg)

        # Check whether pfs is allowed.
        if not PFS_MAP.get(ipsecpolicy['pfs']):
            msg = _("Unsupported pfs: %s! 'group2' and 'group5' "
                    "are supported on VSE right now.") % ipsecpolicy['pfs']
            LOG.warning(msg)
            raise vcns_exc.VcnsBadRequest(resource='ipsecpolicy',
                                          msg=msg)

        # Check whether transform protocol is allowed.
        if ipsecpolicy['transform_protocol'] not in TRANSFORM_PROTOCOL_ALLOWED:
            msg = _("Unsupported transform protocol: %s! 'esp' is supported "
                    "by default on VSE right now."
                    ) % ipsecpolicy['transform_protocol']
            LOG.warning(msg)
            raise vcns_exc.VcnsBadRequest(resource='ipsecpolicy',
                                          msg=msg)

        # Check whether encapsulation mode is allowed.
        if ipsecpolicy['encapsulation_mode'] not in ENCAPSULATION_MODE_ALLOWED:
            msg = _("Unsupported encapsulation mode: %s! 'tunnel' is "
                    "supported by default on VSE right now."
                    ) % ipsecpolicy['encapsulation_mode']
            LOG.warning(msg)
            raise vcns_exc.VcnsBadRequest(resource='ipsecpolicy',
                                          msg=msg)

    def _convert_ipsec_site(self, site, enablePfs=True):
        self._check_ikepolicy_ipsecpolicy_allowed(
            site['ikepolicy'], site['ipsecpolicy'])
        return {
            'enabled': site['site'].get('admin_state_up'),
            'enablePfs': enablePfs,
            'dhGroup': PFS_MAP.get(site['ipsecpolicy']['pfs']),
            'name': site['site'].get('name'),
            'description': site['site'].get('description'),
            'localId': site['external_ip'],
            'localIp': site['external_ip'],
            'peerId': site['site'].get('peer_id'),
            'peerIp': site['site'].get('peer_address'),
            'localSubnets': {
                'subnets': [site['subnet'].get('cidr')]},
            'peerSubnets': {
                'subnets': site['site'].get('peer_cidrs')},
            'authenticationMode': site['site'].get('auth_mode'),
            'psk': site['site'].get('psk'),
            'encryptionAlgorithm': ENCRYPTION_ALGORITHM_MAP.get(
                site['ipsecpolicy'].get('encryption_algorithm'))}

    def update_ipsec_config(self, edge_id, sites, enabled=True):
        ipsec_config = {'featureType': "ipsec_4.0",
                        'enabled': enabled}
        vse_sites = [self._convert_ipsec_site(site) for site in sites]
        ipsec_config['sites'] = {'sites': vse_sites}
        try:
            self.vcns.update_ipsec_config(edge_id, ipsec_config)
        except vcns_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("Failed to update ipsec vpn configuration "
                                "with edge_id: %s"), edge_id)

    def delete_ipsec_config(self, edge_id):
        try:
            self.vcns.delete_ipsec_config(edge_id)
        except vcns_exc.ResourceNotFound:
            LOG.warning(_("IPsec config not found on edge: %s"), edge_id)
        except vcns_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("Failed to delete ipsec vpn configuration "
                                "with edge_id: %s"), edge_id)

    def get_ipsec_config(self, edge_id):
        return self.vcns.get_ipsec_config(edge_id)
