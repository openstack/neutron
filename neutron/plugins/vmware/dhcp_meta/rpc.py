# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 VMware, Inc.
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

from eventlet import greenthread
import netaddr
from oslo.config import cfg

from neutron.api.rpc.agentnotifiers import dhcp_rpc_agent_api
from neutron.api.v2 import attributes
from neutron.common import constants as const
from neutron.common import exceptions as ntn_exc
from neutron.common import rpc as n_rpc
from neutron.db import agents_db
from neutron.db import db_base_plugin_v2
from neutron.db import dhcp_rpc_base
from neutron.db import l3_db
from neutron.db import models_v2
from neutron.openstack.common import log as logging
from neutron.plugins.vmware.api_client import exception as api_exc
from neutron.plugins.vmware.common import config
from neutron.plugins.vmware.common import exceptions as nsx_exc

LOG = logging.getLogger(__name__)

METADATA_DEFAULT_PREFIX = 30
METADATA_SUBNET_CIDR = '169.254.169.252/%d' % METADATA_DEFAULT_PREFIX
METADATA_GATEWAY_IP = '169.254.169.253'
METADATA_DHCP_ROUTE = '169.254.169.254/32'


class NSXRpcCallbacks(dhcp_rpc_base.DhcpRpcCallbackMixin):

    RPC_API_VERSION = '1.1'

    def create_rpc_dispatcher(self):
        '''Get the rpc dispatcher for this manager.

        If a manager would like to set an rpc API version, or support more than
        one class as the target of rpc messages, override this method.
        '''
        return n_rpc.PluginRpcDispatcher([self,
                                          agents_db.AgentExtRpcCallback()])


def handle_network_dhcp_access(plugin, context, network, action):
    pass


def handle_port_dhcp_access(plugin, context, port_data, action):
    active_port = (cfg.CONF.NSX.metadata_mode == config.MetadataModes.INDIRECT
                   and port_data.get('device_owner') == const.DEVICE_OWNER_DHCP
                   and port_data.get('fixed_ips', []))
    if active_port:
        subnet_id = port_data['fixed_ips'][0]['subnet_id']
        subnet = plugin.get_subnet(context, subnet_id)
        _notify_rpc_agent(context, {'subnet': subnet}, 'subnet.update.end')


def handle_port_metadata_access(plugin, context, port, is_delete=False):
    if (cfg.CONF.NSX.metadata_mode == config.MetadataModes.INDIRECT and
        port.get('device_owner') == const.DEVICE_OWNER_DHCP):
        if port.get('fixed_ips', []) or is_delete:
            fixed_ip = port['fixed_ips'][0]
            query = context.session.query(models_v2.Subnet)
            subnet = query.filter(
                models_v2.Subnet.id == fixed_ip['subnet_id']).one()
            # If subnet does not have a gateway do not create metadata
            # route. This is done via the enable_isolated_metadata
            # option if desired.
            if not subnet.get('gateway_ip'):
                LOG.info(_('Subnet %s does not have a gateway, the metadata '
                           'route will not be created'), subnet['id'])
                return
            metadata_routes = [r for r in subnet.routes
                               if r['destination'] == METADATA_DHCP_ROUTE]
            if metadata_routes:
                # We should have only a single metadata route at any time
                # because the route logic forbids two routes with the same
                # destination. Update next hop with the provided IP address
                if not is_delete:
                    metadata_routes[0].nexthop = fixed_ip['ip_address']
                else:
                    context.session.delete(metadata_routes[0])
            else:
                # add the metadata route
                route = models_v2.SubnetRoute(
                    subnet_id=subnet.id,
                    destination=METADATA_DHCP_ROUTE,
                    nexthop=fixed_ip['ip_address'])
                context.session.add(route)


def handle_router_metadata_access(plugin, context, router_id, interface=None):
    if cfg.CONF.NSX.metadata_mode != config.MetadataModes.DIRECT:
        LOG.debug(_("Metadata access network is disabled"))
        return
    if not cfg.CONF.allow_overlapping_ips:
        LOG.warn(_("Overlapping IPs must be enabled in order to setup "
                   "the metadata access network"))
        return
    ctx_elevated = context.elevated()
    device_filter = {'device_id': [router_id],
                     'device_owner': [l3_db.DEVICE_OWNER_ROUTER_INTF]}
    # Retrieve ports calling database plugin
    ports = db_base_plugin_v2.NeutronDbPluginV2.get_ports(
        plugin, ctx_elevated, filters=device_filter)
    try:
        if ports:
            if (interface and
                not _find_metadata_port(plugin, ctx_elevated, ports)):
                _create_metadata_access_network(
                    plugin, ctx_elevated, router_id)
            elif len(ports) == 1:
                # The only port left might be the metadata port
                _destroy_metadata_access_network(
                    plugin, ctx_elevated, router_id, ports)
        else:
            LOG.debug(_("No router interface found for router '%s'. "
                        "No metadata access network should be "
                        "created or destroyed"), router_id)
    # TODO(salvatore-orlando): A better exception handling in the
    # NSX plugin would allow us to improve error handling here
    except (ntn_exc.NeutronException, nsx_exc.NsxPluginException,
            api_exc.NsxApiException):
        # Any exception here should be regarded as non-fatal
        LOG.exception(_("An error occurred while operating on the "
                        "metadata access network for router:'%s'"),
                      router_id)


def _find_metadata_port(plugin, context, ports):
    for port in ports:
        for fixed_ip in port['fixed_ips']:
            cidr = netaddr.IPNetwork(
                plugin.get_subnet(context, fixed_ip['subnet_id'])['cidr'])
            if cidr in netaddr.IPNetwork(METADATA_SUBNET_CIDR):
                return port


def _create_metadata_access_network(plugin, context, router_id):
    # Add network
    # Network name is likely to be truncated on NSX
    net_data = {'name': 'meta-%s' % router_id,
                'tenant_id': '',  # intentionally not set
                'admin_state_up': True,
                'port_security_enabled': False,
                'shared': False,
                'status': const.NET_STATUS_ACTIVE}
    meta_net = plugin.create_network(context,
                                     {'network': net_data})
    greenthread.sleep(0)  # yield
    plugin.schedule_network(context, meta_net)
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
        meta_sub = plugin.create_subnet(context,
                                        {'subnet': subnet_data})
        greenthread.sleep(0)  # yield
        plugin.add_router_interface(context, router_id,
                                    {'subnet_id': meta_sub['id']})
        greenthread.sleep(0)  # yield
        # Tell to start the metadata agent proxy, only if we had success
        _notify_rpc_agent(context, {'subnet': meta_sub}, 'subnet.create.end')
    except (ntn_exc.NeutronException,
            nsx_exc.NsxPluginException,
            api_exc.NsxApiException):
        # It is not necessary to explicitly delete the subnet
        # as it will be removed with the network
        plugin.delete_network(context, meta_net['id'])


def _destroy_metadata_access_network(plugin, context, router_id, ports):
    if not ports:
        return
    meta_port = _find_metadata_port(plugin, context, ports)
    if not meta_port:
        return
    meta_net_id = meta_port['network_id']
    meta_sub_id = meta_port['fixed_ips'][0]['subnet_id']
    plugin.remove_router_interface(
        context, router_id, {'port_id': meta_port['id']})
    greenthread.sleep(0)  # yield
    context.session.expunge_all()
    try:
        # Remove network (this will remove the subnet too)
        plugin.delete_network(context, meta_net_id)
        greenthread.sleep(0)  # yield
    except (ntn_exc.NeutronException, nsx_exc.NsxPluginException,
            api_exc.NsxApiException):
        # must re-add the router interface
        plugin.add_router_interface(context, router_id,
                                    {'subnet_id': meta_sub_id})
    # Tell to stop the metadata agent proxy
    _notify_rpc_agent(
        context, {'network': {'id': meta_net_id}}, 'network.delete.end')


def _notify_rpc_agent(context, payload, event):
    if cfg.CONF.dhcp_agent_notification:
        dhcp_notifier = dhcp_rpc_agent_api.DhcpAgentNotifyAPI()
        dhcp_notifier.notify(context, payload, event)
