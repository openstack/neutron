
# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
#    (c) Copyright 2013 Hewlett-Packard Development Company, L.P.
#    All Rights Reserved.
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
# @author: Swaminathan Vasudevan, Hewlett-Packard

from neutron.db.vpn import vpn_db
from neutron.services.vpn.service_drivers import ipsec as ipsec_driver


class VPNPlugin(vpn_db.VPNPluginDb):

    """Implementation of the VPN Service Plugin.

    This class manages the workflow of VPNaaS request/response.
    Most DB related works are implemented in class
    vpn_db.VPNPluginDb.
    """
    supported_extension_aliases = ["vpnaas"]


class VPNDriverPlugin(VPNPlugin, vpn_db.VPNPluginRpcDbMixin):
    """VpnPlugin which supports VPN Service Drivers."""
    #TODO(nati) handle ikepolicy and ipsecpolicy update usecase
    def __init__(self):
        super(VPNDriverPlugin, self).__init__()
        self.ipsec_driver = ipsec_driver.IPsecVPNDriver(self)

    def _get_driver_for_vpnservice(self, vpnservice):
        return self.ipsec_driver

    def _get_driver_for_ipsec_site_connection(self, context,
                                              ipsec_site_connection):
        #TODO(nati) get vpnservice when we support service type framework
        vpnservice = None
        return self._get_driver_for_vpnservice(vpnservice)

    def create_ipsec_site_connection(self, context, ipsec_site_connection):
        ipsec_site_connection = super(
            VPNDriverPlugin, self).create_ipsec_site_connection(
                context, ipsec_site_connection)
        driver = self._get_driver_for_ipsec_site_connection(
            context, ipsec_site_connection)
        driver.create_ipsec_site_connection(context, ipsec_site_connection)
        return ipsec_site_connection

    def delete_ipsec_site_connection(self, context, ipsec_conn_id):
        ipsec_site_connection = self.get_ipsec_site_connection(
            context, ipsec_conn_id)
        super(VPNDriverPlugin, self).delete_ipsec_site_connection(
            context, ipsec_conn_id)
        driver = self._get_driver_for_ipsec_site_connection(
            context, ipsec_site_connection)
        driver.delete_ipsec_site_connection(context, ipsec_site_connection)

    def update_ipsec_site_connection(
            self, context,
            ipsec_conn_id, ipsec_site_connection):
        old_ipsec_site_connection = self.get_ipsec_site_connection(
            context, ipsec_conn_id)
        ipsec_site_connection = super(
            VPNDriverPlugin, self).update_ipsec_site_connection(
                context,
                ipsec_conn_id,
                ipsec_site_connection)
        driver = self._get_driver_for_ipsec_site_connection(
            context, ipsec_site_connection)
        driver.update_ipsec_site_connection(
            context, old_ipsec_site_connection, ipsec_site_connection)
        return ipsec_site_connection

    def delete_vpnservice(self, context, vpnservice_id):
        vpnservice = self._get_vpnservice(context, vpnservice_id)
        super(VPNDriverPlugin, self).delete_vpnservice(context, vpnservice_id)
        driver = self._get_driver_for_vpnservice(vpnservice)
        driver.delete_vpnservice(context, vpnservice)
