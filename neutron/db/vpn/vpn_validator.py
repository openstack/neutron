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

from neutron.db import l3_db
from neutron.extensions import vpnaas
from neutron import manager
from neutron.plugins.common import constants


class VpnReferenceValidator(object):

    """Baseline validation routines for VPN resources."""

    IP_MIN_MTU = {4: 68, 6: 1280}

    @property
    def l3_plugin(self):
        try:
            return self._l3_plugin
        except AttributeError:
            self._l3_plugin = manager.NeutronManager.get_service_plugins().get(
                constants.L3_ROUTER_NAT)
            return self._l3_plugin

    @property
    def core_plugin(self):
        try:
            return self._core_plugin
        except AttributeError:
            self._core_plugin = manager.NeutronManager.get_plugin()
            return self._core_plugin

    def _check_dpd(self, ipsec_sitecon):
        """Ensure that DPD timeout is greater than DPD interval."""
        if ipsec_sitecon['dpd_timeout'] <= ipsec_sitecon['dpd_interval']:
            raise vpnaas.IPsecSiteConnectionDpdIntervalValueError(
                attr='dpd_timeout')

    def _check_mtu(self, context, mtu, ip_version):
        if mtu < VpnReferenceValidator.IP_MIN_MTU[ip_version]:
            raise vpnaas.IPsecSiteConnectionMtuError(mtu=mtu,
                                                     version=ip_version)

    def assign_sensible_ipsec_sitecon_defaults(self, ipsec_sitecon,
                                               prev_conn=None):
        """Provide defaults for optional items, if missing.

        Flatten the nested DPD information, and set default values for
        any missing information. For connection updates, the previous
        values will be used as defaults for any missing items.
        """
        if not prev_conn:
            prev_conn = {'dpd_action': 'hold',
                         'dpd_interval': 30,
                         'dpd_timeout': 120}
        dpd = ipsec_sitecon.get('dpd', {})
        ipsec_sitecon['dpd_action'] = dpd.get('action',
                                              prev_conn['dpd_action'])
        ipsec_sitecon['dpd_interval'] = dpd.get('interval',
                                                prev_conn['dpd_interval'])
        ipsec_sitecon['dpd_timeout'] = dpd.get('timeout',
                                               prev_conn['dpd_timeout'])

    def validate_ipsec_site_connection(self, context, ipsec_sitecon,
                                       ip_version):
        """Reference implementation of validation for IPSec connection."""
        self._check_dpd(ipsec_sitecon)
        mtu = ipsec_sitecon.get('mtu')
        if mtu:
            self._check_mtu(context, mtu, ip_version)

    def _check_router(self, context, router_id):
        router = self.l3_plugin.get_router(context, router_id)
        if not router.get(l3_db.EXTERNAL_GW_INFO):
            raise vpnaas.RouterIsNotExternal(router_id=router_id)

    def _check_subnet_id(self, context, router_id, subnet_id):
        ports = self.core_plugin.get_ports(
            context,
            filters={
                'fixed_ips': {'subnet_id': [subnet_id]},
                'device_id': [router_id]})
        if not ports:
            raise vpnaas.SubnetIsNotConnectedToRouter(
                subnet_id=subnet_id,
                router_id=router_id)

    def validate_vpnservice(self, context, vpnservice):
        self._check_router(context, vpnservice['router_id'])
        self._check_subnet_id(context, vpnservice['router_id'],
                              vpnservice['subnet_id'])
