# Copyright 2014 Cisco Systems, Inc.  All rights reserved.
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

import netaddr
from netaddr import core as net_exc

from neutron.common import exceptions
from neutron.db.vpn import vpn_validator
from neutron.openstack.common import log as logging


LIFETIME_LIMITS = {'IKE Policy': {'min': 60, 'max': 86400},
                   'IPSec Policy': {'min': 120, 'max': 2592000}}
MIN_CSR_MTU = 1500
MAX_CSR_MTU = 9192

LOG = logging.getLogger(__name__)


class CsrValidationFailure(exceptions.BadRequest):
    message = _("Cisco CSR does not support %(resource)s attribute %(key)s "
                "with value '%(value)s'")


class CiscoCsrVpnValidator(vpn_validator.VpnReferenceValidator):

    """Validator methods for the Cisco CSR."""

    def __init__(self, service_plugin):
        self.service_plugin = service_plugin
        super(CiscoCsrVpnValidator, self).__init__()

    def validate_lifetime(self, for_policy, policy_info):
        """Ensure lifetime in secs and value is supported, based on policy."""
        units = policy_info['lifetime']['units']
        if units != 'seconds':
            raise CsrValidationFailure(resource=for_policy,
                                       key='lifetime:units',
                                       value=units)
        value = policy_info['lifetime']['value']
        if (value < LIFETIME_LIMITS[for_policy]['min'] or
            value > LIFETIME_LIMITS[for_policy]['max']):
            raise CsrValidationFailure(resource=for_policy,
                                       key='lifetime:value',
                                       value=value)

    def validate_ike_version(self, policy_info):
        """Ensure IKE policy is v1 for current REST API."""
        version = policy_info['ike_version']
        if version != 'v1':
            raise CsrValidationFailure(resource='IKE Policy',
                                       key='ike_version',
                                       value=version)

    def validate_mtu(self, conn_info):
        """Ensure the MTU value is supported."""
        mtu = conn_info['mtu']
        if mtu < MIN_CSR_MTU or mtu > MAX_CSR_MTU:
            raise CsrValidationFailure(resource='IPSec Connection',
                                       key='mtu',
                                       value=mtu)

    def validate_public_ip_present(self, router):
        """Ensure there is one gateway IP specified for the router used."""
        gw_port = router.gw_port
        if not gw_port or len(gw_port.fixed_ips) != 1:
            raise CsrValidationFailure(resource='IPSec Connection',
                                       key='router:gw_port:ip_address',
                                       value='missing')

    def validate_peer_id(self, ipsec_conn):
        """Ensure that an IP address is specified for peer ID."""
        # TODO(pcm) Should we check peer_address too?
        peer_id = ipsec_conn['peer_id']
        try:
            netaddr.IPAddress(peer_id)
        except net_exc.AddrFormatError:
            raise CsrValidationFailure(resource='IPSec Connection',
                                       key='peer_id', value=peer_id)

    def validate_ipsec_site_connection(self, context, ipsec_sitecon,
                                       ip_version):
        """Validate IPSec site connection for Cisco CSR.

        After doing reference validation, do additional checks that relate
        to the Cisco CSR.
        """
        super(CiscoCsrVpnValidator, self)._check_dpd(ipsec_sitecon)

        ike_policy = self.service_plugin.get_ikepolicy(
            context, ipsec_sitecon['ikepolicy_id'])
        ipsec_policy = self.service_plugin.get_ipsecpolicy(
            context, ipsec_sitecon['ipsecpolicy_id'])
        vpn_service = self.service_plugin.get_vpnservice(
            context, ipsec_sitecon['vpnservice_id'])
        router = self.l3_plugin._get_router(context, vpn_service['router_id'])
        self.validate_lifetime('IKE Policy', ike_policy)
        self.validate_lifetime('IPSec Policy', ipsec_policy)
        self.validate_ike_version(ike_policy)
        self.validate_mtu(ipsec_sitecon)
        self.validate_public_ip_present(router)
        self.validate_peer_id(ipsec_sitecon)
        LOG.debug("IPSec connection validated for Cisco CSR")
