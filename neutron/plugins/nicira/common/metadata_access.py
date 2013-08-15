# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 Nicira, Inc.
# All Rights Reserved
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
# @author: Salvatore Orlando, VMware

from eventlet import greenthread
import netaddr
from oslo.config import cfg

from neutron.api.rpc.agentnotifiers import dhcp_rpc_agent_api
from neutron.api.v2 import attributes
from neutron.common import constants
from neutron.common import exceptions as ntn_exc
from neutron.db import db_base_plugin_v2
from neutron.db import l3_db
from neutron.db import models_v2
from neutron.openstack.common import log as logging
from neutron.plugins.nicira.common import exceptions as nvp_exc
from neutron.plugins.nicira import NvpApiClient


LOG = logging.getLogger(__name__)

METADATA_DEFAULT_PREFIX = 30
METADATA_SUBNET_CIDR = '169.254.169.252/%d' % METADATA_DEFAULT_PREFIX
METADATA_GATEWAY_IP = '169.254.169.253'
METADATA_DHCP_ROUTE = '169.254.169.254/32'


class NvpMetadataAccess(object):

    def _find_metadata_port(self, context, ports):
        for port in ports:
            for fixed_ip in port['fixed_ips']:
                cidr = netaddr.IPNetwork(
                    self.get_subnet(context, fixed_ip['subnet_id'])['cidr'])
                if cidr in netaddr.IPNetwork(METADATA_SUBNET_CIDR):
                    return port

    def _create_metadata_access_network(self, context, router_id):
        # Add network
        # Network name is likely to be truncated on NVP
        net_data = {'name': 'meta-%s' % router_id,
                    'tenant_id': '',  # intentionally not set
                    'admin_state_up': True,
                    'port_security_enabled': False,
                    'shared': False,
                    'status': constants.NET_STATUS_ACTIVE}
        meta_net = self.create_network(context,
                                       {'network': net_data})
        greenthread.sleep(0)  # yield
        # From this point on there will be resources to garbage-collect
        # in case of failures
        meta_sub = None
        try:
            # Add subnet
            subnet_data = {'network_id': meta_net['id'],
                           'tenant_id': '',  # intentionally not set
                           'name': 'meta-%s' % router_id,
                           'ip_version': 4,
                           'shared': False,
                           'cidr': METADATA_SUBNET_CIDR,
                           'enable_dhcp': True,
                           # Ensure default allocation pool is generated
                           'allocation_pools': attributes.ATTR_NOT_SPECIFIED,
                           'gateway_ip': METADATA_GATEWAY_IP,
                           'dns_nameservers': [],
                           'host_routes': []}
            meta_sub = self.create_subnet(context,
                                          {'subnet': subnet_data})
            greenthread.sleep(0)  # yield
            self.add_router_interface(context, router_id,
                                      {'subnet_id': meta_sub['id']})
            greenthread.sleep(0)  # yield
        except (ntn_exc.NeutronException,
                nvp_exc.NvpPluginException,
                NvpApiClient.NvpApiException):
            # It is not necessary to explicitly delete the subnet
            # as it will be removed with the network
            self.delete_network(context, meta_net['id'])

        if cfg.CONF.dhcp_agent_notification:
            # We need to send a notification to the dhcp agent in
            # order to start the metadata agent proxy
            dhcp_notifier = dhcp_rpc_agent_api.DhcpAgentNotifyAPI()
            dhcp_notifier.notify(context, {'network': meta_net},
                                 'network.create.end')

    def _destroy_metadata_access_network(self, context, router_id, ports):
        if not ports:
            return
        meta_port = self._find_metadata_port(context, ports)
        if not meta_port:
            return
        meta_net_id = meta_port['network_id']
        meta_sub_id = meta_port['fixed_ips'][0]['subnet_id']
        self.remove_router_interface(
            context, router_id, {'port_id': meta_port['id']})
        greenthread.sleep(0)  # yield
        try:
            # Remove network (this will remove the subnet too)
            self.delete_network(context, meta_net_id)
            greenthread.sleep(0)  # yield
        except (ntn_exc.NeutronException, nvp_exc.NvpPluginException,
                NvpApiClient.NvpApiException):
            # must re-add the router interface
            self.add_router_interface(context, router_id,
                                      {'subnet_id': meta_sub_id})

        if cfg.CONF.dhcp_agent_notification:
            # We need to send a notification to the dhcp agent in
            # order to stop the metadata agent proxy
            dhcp_notifier = dhcp_rpc_agent_api.DhcpAgentNotifyAPI()
            dhcp_notifier.notify(context,
                                 {'network': {'id': meta_net_id}},
                                 'network.delete.end')

    def _handle_metadata_access_network(self, context, router_id,
                                        do_create=True):
        if cfg.CONF.NVP.metadata_mode != "access_network":
            LOG.debug(_("Metadata access network is disabled"))
            return
        if not cfg.CONF.allow_overlapping_ips:
            LOG.warn(_("Overlapping IPs must be enabled in order to setup "
                       "the metadata access network"))
            return
        # As we'll use a different device_owner for metadata interface
        # this query will return only 'real' router interfaces
        ctx_elevated = context.elevated()
        device_filter = {'device_id': [router_id],
                         'device_owner': [l3_db.DEVICE_OWNER_ROUTER_INTF]}
        # Retrieve ports calling database plugin
        ports = db_base_plugin_v2.NeutronDbPluginV2.get_ports(
            self, context, filters=device_filter)
        try:
            if ports:
                if (do_create and
                    not self._find_metadata_port(ctx_elevated, ports)):
                    self._create_metadata_access_network(ctx_elevated,
                                                         router_id)
                elif len(ports) == 1:
                    # The only port left might be the metadata port
                    self._destroy_metadata_access_network(ctx_elevated,
                                                          router_id,
                                                          ports)
            else:
                LOG.debug(_("No router interface found for router '%s'. "
                            "No metadata access network should be "
                            "created or destroyed"), router_id)
        # TODO(salvatore-orlando): A better exception handling in the
        # NVP plugin would allow us to improve error handling here
        except (ntn_exc.NeutronException, nvp_exc.NvpPluginException,
                NvpApiClient.NvpApiException):
            # Any exception here should be regarded as non-fatal
            LOG.exception(_("An error occurred while operating on the "
                            "metadata access network for router:'%s'"),
                          router_id)

    def _ensure_metadata_host_route(self, context, fixed_ip_data,
                                    is_delete=False):
        subnet = self._get_subnet(context, fixed_ip_data['subnet_id'])
        # If subnet does not have a gateway do not create metadata route. This
        # is done via the enable_isolated_metadata option if desired.
        if not subnet.get('gateway_ip'):
            return
        metadata_routes = [r for r in subnet.routes
                           if r['destination'] == METADATA_DHCP_ROUTE]

        if metadata_routes:
            # We should have only a single metadata route at any time
            # because the route logic forbids two routes with the same
            # destination. Update next hop with the provided IP address
            if not is_delete:
                metadata_routes[0].nexthop = fixed_ip_data['ip_address']
            else:
                context.session.delete(metadata_routes[0])
        else:
            # add the metadata route
            route = models_v2.SubnetRoute(subnet_id=subnet.id,
                                          destination=METADATA_DHCP_ROUTE,
                                          nexthop=fixed_ip_data['ip_address'])
            context.session.add(route)
        return cfg.CONF.dhcp_agent_notification

    def _send_subnet_update_end(self, context, subnet_id):
        updated_subnet = self.get_subnet(context, subnet_id)
        dhcp_notifier = dhcp_rpc_agent_api.DhcpAgentNotifyAPI()
        dhcp_notifier.notify(context,
                             {'subnet': updated_subnet},
                             'subnet.update.end')
