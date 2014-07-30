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


from neutron.common import rpc as n_rpc
from neutron.openstack.common import log as logging
from neutron.services.vpn.common import topics
from neutron.services.vpn import service_drivers
from neutron.services.vpn.service_drivers import cisco_csr_db as csr_id_map
from neutron.services.vpn.service_drivers import cisco_validator


LOG = logging.getLogger(__name__)

IPSEC = 'ipsec'
BASE_IPSEC_VERSION = '1.0'


class CiscoCsrIPsecVpnDriverCallBack(n_rpc.RpcCallback):

    """Handler for agent to plugin RPC messaging."""

    # history
    #   1.0 Initial version

    RPC_API_VERSION = BASE_IPSEC_VERSION

    def __init__(self, driver):
        super(CiscoCsrIPsecVpnDriverCallBack, self).__init__()
        self.driver = driver

    def get_vpn_services_on_host(self, context, host=None):
        """Retuns info on the vpnservices on the host."""
        plugin = self.driver.service_plugin
        vpnservices = plugin._get_agent_hosting_vpn_services(
            context, host)
        return [self.driver._make_vpnservice_dict(vpnservice, context)
                for vpnservice in vpnservices]

    def update_status(self, context, status):
        """Update status of all vpnservices."""
        plugin = self.driver.service_plugin
        plugin.update_status_by_agent(context, status)


class CiscoCsrIPsecVpnAgentApi(service_drivers.BaseIPsecVpnAgentApi,
                               n_rpc.RpcCallback):

    """API and handler for Cisco IPSec plugin to agent RPC messaging."""

    RPC_API_VERSION = BASE_IPSEC_VERSION

    def __init__(self, topic, default_version):
        super(CiscoCsrIPsecVpnAgentApi, self).__init__(
            topics.CISCO_IPSEC_AGENT_TOPIC, topic, default_version)


class CiscoCsrIPsecVPNDriver(service_drivers.VpnDriver):

    """Cisco CSR VPN Service Driver class for IPsec."""

    def __init__(self, service_plugin):
        super(CiscoCsrIPsecVPNDriver, self).__init__(
            service_plugin,
            cisco_validator.CiscoCsrVpnValidator(service_plugin))
        self.endpoints = [CiscoCsrIPsecVpnDriverCallBack(self)]
        self.conn = n_rpc.create_connection(new=True)
        self.conn.create_consumer(
            topics.CISCO_IPSEC_DRIVER_TOPIC, self.endpoints, fanout=False)
        self.conn.consume_in_threads()
        self.agent_rpc = CiscoCsrIPsecVpnAgentApi(
            topics.CISCO_IPSEC_AGENT_TOPIC, BASE_IPSEC_VERSION)

    @property
    def service_type(self):
        return IPSEC

    def create_ipsec_site_connection(self, context, ipsec_site_connection):
        vpnservice = self.service_plugin._get_vpnservice(
            context, ipsec_site_connection['vpnservice_id'])
        csr_id_map.create_tunnel_mapping(context, ipsec_site_connection)
        self.agent_rpc.vpnservice_updated(context, vpnservice['router_id'],
                                          reason='ipsec-conn-create')

    def update_ipsec_site_connection(
        self, context, old_ipsec_site_connection, ipsec_site_connection):
        vpnservice = self.service_plugin._get_vpnservice(
            context, ipsec_site_connection['vpnservice_id'])
        self.agent_rpc.vpnservice_updated(
            context, vpnservice['router_id'],
            reason='ipsec-conn-update')

    def delete_ipsec_site_connection(self, context, ipsec_site_connection):
        vpnservice = self.service_plugin._get_vpnservice(
            context, ipsec_site_connection['vpnservice_id'])
        self.agent_rpc.vpnservice_updated(context, vpnservice['router_id'],
                                          reason='ipsec-conn-delete')

    def create_ikepolicy(self, context, ikepolicy):
        pass

    def delete_ikepolicy(self, context, ikepolicy):
        pass

    def update_ikepolicy(self, context, old_ikepolicy, ikepolicy):
        pass

    def create_ipsecpolicy(self, context, ipsecpolicy):
        pass

    def delete_ipsecpolicy(self, context, ipsecpolicy):
        pass

    def update_ipsecpolicy(self, context, old_ipsec_policy, ipsecpolicy):
        pass

    def create_vpnservice(self, context, vpnservice):
        pass

    def update_vpnservice(self, context, old_vpnservice, vpnservice):
        self.agent_rpc.vpnservice_updated(context, vpnservice['router_id'],
                                          reason='vpn-service-update')

    def delete_vpnservice(self, context, vpnservice):
        self.agent_rpc.vpnservice_updated(context, vpnservice['router_id'],
                                          reason='vpn-service-delete')

    def get_cisco_connection_mappings(self, conn_id, context):
        """Obtain persisted mappings for IDs related to connection."""
        tunnel_id, ike_id, ipsec_id = csr_id_map.get_tunnel_mapping_for(
            conn_id, context.session)
        return {'site_conn_id': u'Tunnel%d' % tunnel_id,
                'ike_policy_id': u'%d' % ike_id,
                'ipsec_policy_id': u'%s' % ipsec_id}

    def _make_vpnservice_dict(self, vpnservice, context):
        """Collect all info on service, including Cisco info per IPSec conn."""
        vpnservice_dict = dict(vpnservice)
        vpnservice_dict['ipsec_conns'] = []
        vpnservice_dict['subnet'] = dict(
            vpnservice.subnet)
        vpnservice_dict['external_ip'] = vpnservice.router.gw_port[
            'fixed_ips'][0]['ip_address']
        for ipsec_conn in vpnservice.ipsec_site_connections:
            ipsec_conn_dict = dict(ipsec_conn)
            ipsec_conn_dict['ike_policy'] = dict(ipsec_conn.ikepolicy)
            ipsec_conn_dict['ipsec_policy'] = dict(ipsec_conn.ipsecpolicy)
            ipsec_conn_dict['peer_cidrs'] = [
                peer_cidr.cidr for peer_cidr in ipsec_conn.peer_cidrs]
            ipsec_conn_dict['cisco'] = self.get_cisco_connection_mappings(
                ipsec_conn['id'], context)
            vpnservice_dict['ipsec_conns'].append(ipsec_conn_dict)
        return vpnservice_dict
