# Copyright 2012 Big Switch Networks, Inc.
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

"""
Neutron REST Proxy Plug-in for Big Switch and FloodLight Controllers.

NeutronRestProxy provides a generic neutron plugin that translates all plugin
function calls to equivalent authenticated REST calls to a set of redundant
external network controllers. It also keeps persistent store for all neutron
state to allow for re-sync of the external controller(s), if required.

The local state on the plugin also allows for local response and fast-fail
semantics where it can be determined based on the local persistent store.

Network controller specific code is decoupled from this plugin and expected
to reside on the controller itself (via the REST interface).

This allows for:
 - independent authentication and redundancy schemes between neutron and the
   network controller
 - independent upgrade/development cycles between neutron and the controller
   as it limits the proxy code upgrade requirement to neutron release cycle
   and the controller specific code upgrade requirement to controller code
 - ability to sync the controller with neutron for independent recovery/reset

External REST API used by proxy is the same API as defined for neutron (JSON
subset) with some additional parameters (gateway on network-create and macaddr
on port-attach) on an additional PUT to do a bulk dump of all persistent data.
"""

import copy
import functools
import httplib
import re

import eventlet
from oslo_config import cfg
import oslo_messaging
from oslo_utils import importutils
from sqlalchemy.orm import exc as sqlexc

from neutron.agent import securitygroups_rpc as sg_rpc
from neutron.api import extensions as neutron_extensions
from neutron.api.rpc.agentnotifiers import dhcp_rpc_agent_api
from neutron.api.rpc.handlers import dhcp_rpc
from neutron.api.rpc.handlers import metadata_rpc
from neutron.api.rpc.handlers import securitygroups_rpc
from neutron.common import constants as const
from neutron.common import exceptions
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.common import utils
from neutron import context as qcontext
from neutron.db import agents_db
from neutron.db import agentschedulers_db
from neutron.db import allowedaddresspairs_db as addr_pair_db
from neutron.db import api as db
from neutron.db import db_base_plugin_v2
from neutron.db import external_net_db
from neutron.db import extradhcpopt_db
from neutron.db import l3_db
from neutron.db import models_v2
from neutron.db import securitygroups_db as sg_db
from neutron.db import securitygroups_rpc_base as sg_db_rpc
from neutron.extensions import allowedaddresspairs as addr_pair
from neutron.extensions import external_net
from neutron.extensions import extra_dhcp_opt as edo_ext
from neutron.extensions import portbindings
from neutron import manager
from neutron.i18n import _LE, _LI, _LW
from neutron.openstack.common import log as logging
from neutron.plugins.bigswitch import config as pl_config
from neutron.plugins.bigswitch.db import porttracker_db
from neutron.plugins.bigswitch import extensions
from neutron.plugins.bigswitch import servermanager
from neutron.plugins.bigswitch import version
from neutron.plugins.common import constants as pconst

LOG = logging.getLogger(__name__)

SYNTAX_ERROR_MESSAGE = _('Syntax error in server config file, aborting plugin')
METADATA_SERVER_IP = '169.254.169.254'


class AgentNotifierApi(sg_rpc.SecurityGroupAgentRpcApiMixin):

    def __init__(self, topic):
        self.topic = topic
        target = oslo_messaging.Target(topic=topic, version='1.0')
        self.client = n_rpc.get_client(target)

    def port_update(self, context, port):
        topic_port_update = topics.get_topic_name(self.client.target.topic,
                                                  topics.PORT, topics.UPDATE)
        cctxt = self.client.prepare(fanout=True, topic=topic_port_update)
        cctxt.cast(context, 'port_update', port=port)


class SecurityGroupServerRpcMixin(sg_db_rpc.SecurityGroupServerRpcMixin):

    def get_port_from_device(self, device):
        port_id = re.sub(r"^%s" % const.TAP_DEVICE_PREFIX, "", device)
        port = self.get_port_and_sgs(port_id)
        if port:
            port['device'] = device
        return port

    def get_port_and_sgs(self, port_id):
        """Get port from database with security group info."""

        LOG.debug("get_port_and_sgs() called for port_id %s", port_id)
        session = db.get_session()
        sg_binding_port = sg_db.SecurityGroupPortBinding.port_id

        with session.begin(subtransactions=True):
            query = session.query(
                models_v2.Port,
                sg_db.SecurityGroupPortBinding.security_group_id
            )
            query = query.outerjoin(sg_db.SecurityGroupPortBinding,
                                    models_v2.Port.id == sg_binding_port)
            query = query.filter(models_v2.Port.id.startswith(port_id))
            port_and_sgs = query.all()
            if not port_and_sgs:
                return
            port = port_and_sgs[0][0]
            plugin = manager.NeutronManager.get_plugin()
            port_dict = plugin._make_port_dict(port)
            port_dict['security_groups'] = [
                sg_id for port_, sg_id in port_and_sgs if sg_id]
            port_dict['security_group_rules'] = []
            port_dict['security_group_source_groups'] = []
            port_dict['fixed_ips'] = [ip['ip_address']
                                      for ip in port['fixed_ips']]
        return port_dict


class NeutronRestProxyV2Base(db_base_plugin_v2.NeutronDbPluginV2,
                             external_net_db.External_net_db_mixin):

    supported_extension_aliases = ["binding"]
    servers = None

    @property
    def l3_plugin(self):
        return manager.NeutronManager.get_service_plugins().get(
            pconst.L3_ROUTER_NAT)

    def _get_all_data(self, get_ports=True, get_floating_ips=True,
                      get_routers=True):
        admin_context = qcontext.get_admin_context()
        networks = []
        # this method is used by the ML2 driver so it can't directly invoke
        # the self.get_(ports|networks) methods
        plugin = manager.NeutronManager.get_plugin()
        all_networks = plugin.get_networks(admin_context) or []
        for net in all_networks:
            mapped_network = self._get_mapped_network_with_subnets(net)
            flips_n_ports = mapped_network
            if get_floating_ips:
                flips_n_ports = self._get_network_with_floatingips(
                    mapped_network)

            if get_ports:
                ports = []
                net_filter = {'network_id': [net.get('id')]}
                net_ports = plugin.get_ports(admin_context,
                                             filters=net_filter) or []
                for port in net_ports:
                    mapped_port = self._map_state_and_status(port)
                    mapped_port['attachment'] = {
                        'id': port.get('device_id'),
                        'mac': port.get('mac_address'),
                    }
                    mapped_port = self._extend_port_dict_binding(admin_context,
                                                                 mapped_port)
                    ports.append(mapped_port)
                flips_n_ports['ports'] = ports

            if flips_n_ports:
                networks.append(flips_n_ports)

        data = {'networks': networks}

        if get_routers and self.l3_plugin:
            routers = []
            all_routers = self.l3_plugin.get_routers(admin_context) or []
            for router in all_routers:
                interfaces = []
                mapped_router = self._map_state_and_status(router)
                router_filter = {
                    'device_owner': [const.DEVICE_OWNER_ROUTER_INTF],
                    'device_id': [router.get('id')]
                }
                router_ports = self.get_ports(admin_context,
                                              filters=router_filter) or []
                for port in router_ports:
                    net_id = port.get('network_id')
                    subnet_id = port['fixed_ips'][0]['subnet_id']
                    intf_details = self._get_router_intf_details(admin_context,
                                                                 net_id,
                                                                 subnet_id)
                    interfaces.append(intf_details)
                mapped_router['interfaces'] = interfaces

                routers.append(mapped_router)

            data.update({'routers': routers})
        return data

    def _send_all_data(self, send_ports=True, send_floating_ips=True,
                       send_routers=True, timeout=None,
                       triggered_by_tenant=None):
        """Pushes all data to network ctrl (networks/ports, ports/attachments).

        This gives the controller an option to re-sync it's persistent store
        with neutron's current view of that data.
        """
        data = self._get_all_data(send_ports, send_floating_ips, send_routers)
        data['triggered_by_tenant'] = triggered_by_tenant
        errstr = _("Unable to update remote topology: %s")
        return self.servers.rest_action('PUT', servermanager.TOPOLOGY_PATH,
                                        data, errstr, timeout=timeout)

    def _get_network_with_floatingips(self, network, context=None):
        if context is None:
            context = qcontext.get_admin_context()

        net_id = network['id']
        net_filter = {'floating_network_id': [net_id]}
        if self.l3_plugin:
            fl_ips = self.l3_plugin.get_floatingips(context,
                                                    filters=net_filter) or []
            network['floatingips'] = fl_ips

        return network

    def _get_all_subnets_json_for_network(self, net_id, context=None):
        if context is None:
            context = qcontext.get_admin_context()
        # start a sub-transaction to avoid breaking parent transactions
        with context.session.begin(subtransactions=True):
            subnets = self._get_subnets_by_network(context,
                                                   net_id)
        subnets_details = []
        if subnets:
            for subnet in subnets:
                subnet_dict = self._make_subnet_dict(subnet)
                mapped_subnet = self._map_state_and_status(subnet_dict)
                subnets_details.append(mapped_subnet)

        return subnets_details

    def _get_mapped_network_with_subnets(self, network, context=None):
        # if context is not provided, admin context is used
        if context is None:
            context = qcontext.get_admin_context()
        network = self._map_state_and_status(network)
        subnets = self._get_all_subnets_json_for_network(network['id'],
                                                         context)
        network['subnets'] = subnets
        for subnet in (subnets or []):
            if subnet['gateway_ip']:
                # FIX: For backward compatibility with wire protocol
                network['gateway'] = subnet['gateway_ip']
                break
        else:
            network['gateway'] = ''
        network[external_net.EXTERNAL] = self._network_is_external(
            context, network['id'])
        # include ML2 segmentation types
        network['segmentation_types'] = getattr(self, "segmentation_types", "")
        return network

    def _send_create_network(self, network, context=None):
        tenant_id = network['tenant_id']
        mapped_network = self._get_mapped_network_with_subnets(network,
                                                               context)
        self.servers.rest_create_network(tenant_id, mapped_network)

    def _send_update_network(self, network, context=None):
        net_id = network['id']
        tenant_id = network['tenant_id']
        mapped_network = self._get_mapped_network_with_subnets(network,
                                                               context)
        net_fl_ips = self._get_network_with_floatingips(mapped_network,
                                                        context)
        self.servers.rest_update_network(tenant_id, net_id, net_fl_ips)

    def _send_delete_network(self, network, context=None):
        net_id = network['id']
        tenant_id = network['tenant_id']
        self.servers.rest_delete_network(tenant_id, net_id)

    def _map_state_and_status(self, resource):
        resource = copy.copy(resource)

        resource['state'] = ('UP' if resource.pop('admin_state_up',
                                                  True) else 'DOWN')
        resource.pop('status', None)

        return resource

    def _warn_on_state_status(self, resource):
        if resource.get('admin_state_up', True) is False:
            LOG.warning(_LW("Setting admin_state_up=False is not supported "
                            "in this plugin version. Ignoring setting for "
                            "resource: %s"), resource)

        if 'status' in resource:
            if resource['status'] != const.NET_STATUS_ACTIVE:
                LOG.warning(_LW("Operational status is internally set by the "
                                "plugin. Ignoring setting status=%s."),
                            resource['status'])

    def _get_router_intf_details(self, context, intf_id, subnet_id):

        # we will use the network id as interface's id
        net_id = intf_id
        network = self.get_network(context, net_id)
        subnet = self.get_subnet(context, subnet_id)
        mapped_network = self._get_mapped_network_with_subnets(network)
        mapped_subnet = self._map_state_and_status(subnet)

        data = {
            'id': intf_id,
            "network": mapped_network,
            "subnet": mapped_subnet
        }

        return data

    def _extend_port_dict_binding(self, context, port):
        cfg_vif_type = cfg.CONF.NOVA.vif_type.lower()
        if cfg_vif_type not in (portbindings.VIF_TYPE_OVS,
                                portbindings.VIF_TYPE_IVS):
            LOG.warning(_LW("Unrecognized vif_type in configuration "
                            "[%s]. Defaulting to ovs."),
                        cfg_vif_type)
            cfg_vif_type = portbindings.VIF_TYPE_OVS
        # In ML2, the host_id is already populated
        if portbindings.HOST_ID in port:
            hostid = port[portbindings.HOST_ID]
        elif 'id' in port:
            hostid = porttracker_db.get_port_hostid(context, port['id'])
        else:
            hostid = None
        if hostid:
            port[portbindings.HOST_ID] = hostid
            override = self._check_hostvif_override(hostid)
            if override:
                cfg_vif_type = override
        port[portbindings.VIF_TYPE] = cfg_vif_type

        sg_enabled = sg_rpc.is_firewall_enabled()
        port[portbindings.VIF_DETAILS] = {
            # TODO(rkukura): Replace with new VIF security details
            portbindings.CAP_PORT_FILTER:
            'security-group' in self.supported_extension_aliases,
            portbindings.OVS_HYBRID_PLUG: sg_enabled
        }
        return port

    def _check_hostvif_override(self, hostid):
        for v in cfg.CONF.NOVA.vif_types:
            if hostid in getattr(cfg.CONF.NOVA, "node_override_vif_" + v, []):
                return v
        return False

    def _get_port_net_tenantid(self, context, port):
        net = super(NeutronRestProxyV2Base,
                    self).get_network(context, port["network_id"])
        return net['tenant_id']

    def async_port_create(self, tenant_id, net_id, port):
        try:
            self.servers.rest_create_port(tenant_id, net_id, port)
        except servermanager.RemoteRestError as e:
            # 404 should never be received on a port create unless
            # there are inconsistencies between the data in neutron
            # and the data in the backend.
            # Run a sync to get it consistent.
            if (cfg.CONF.RESTPROXY.auto_sync_on_failure and
                e.status == httplib.NOT_FOUND and
                servermanager.NXNETWORK in e.reason):
                LOG.error(_LE("Iconsistency with backend controller "
                              "triggering full synchronization."))
                # args depend on if we are operating in ML2 driver
                # or as the full plugin
                topoargs = self.servers.get_topo_function_args
                self._send_all_data(
                    send_ports=topoargs['get_ports'],
                    send_floating_ips=topoargs['get_floating_ips'],
                    send_routers=topoargs['get_routers'],
                    triggered_by_tenant=tenant_id
                )
                # If the full sync worked, the port will be created
                # on the controller so it can be safely marked as active
            else:
                # Any errors that don't result in a successful auto-sync
                # require that the port be placed into the error state.
                LOG.error(
                    _LE("NeutronRestProxyV2: Unable to create port: %s"), e)
                try:
                    self._set_port_status(port['id'], const.PORT_STATUS_ERROR)
                except exceptions.PortNotFound:
                    # If port is already gone from DB and there was an error
                    # creating on the backend, everything is already consistent
                    pass
                return
        new_status = (const.PORT_STATUS_ACTIVE if port['state'] == 'UP'
                      else const.PORT_STATUS_DOWN)
        try:
            self._set_port_status(port['id'], new_status)
        except exceptions.PortNotFound:
            # This port was deleted before the create made it to the controller
            # so it now needs to be deleted since the normal delete request
            # would have deleted an non-existent port.
            self.servers.rest_delete_port(tenant_id, net_id, port['id'])

    # NOTE(kevinbenton): workaround for eventlet/mysql deadlock
    @utils.synchronized('bsn-port-barrier')
    def _set_port_status(self, port_id, status):
        session = db.get_session()
        try:
            port = session.query(models_v2.Port).filter_by(id=port_id).one()
            port['status'] = status
            session.flush()
        except sqlexc.NoResultFound:
            raise exceptions.PortNotFound(port_id=port_id)


def put_context_in_serverpool(f):
    @functools.wraps(f)
    def wrapper(self, context, *args, **kwargs):
        # core plugin: context is top level object
        # ml2: keeps context in _plugin_context
        self.servers.set_context(getattr(context, '_plugin_context', context))
        return f(self, context, *args, **kwargs)
    return wrapper


class NeutronRestProxyV2(NeutronRestProxyV2Base,
                         addr_pair_db.AllowedAddressPairsMixin,
                         extradhcpopt_db.ExtraDhcpOptMixin,
                         agentschedulers_db.DhcpAgentSchedulerDbMixin,
                         SecurityGroupServerRpcMixin):

    _supported_extension_aliases = ["external-net", "binding",
                                    "extra_dhcp_opt", "quotas",
                                    "dhcp_agent_scheduler", "agent",
                                    "security-group", "allowed-address-pairs"]

    @property
    def supported_extension_aliases(self):
        if not hasattr(self, '_aliases'):
            aliases = self._supported_extension_aliases[:]
            sg_rpc.disable_security_group_extension_by_config(aliases)
            self._aliases = aliases
        return self._aliases

    def __init__(self):
        super(NeutronRestProxyV2, self).__init__()
        LOG.info(_LI('NeutronRestProxy: Starting plugin. Version=%s'),
                 version.version_string_with_vcs())
        pl_config.register_config()
        self.evpool = eventlet.GreenPool(cfg.CONF.RESTPROXY.thread_pool_size)

        # Include the Big Switch Extensions path in the api_extensions
        neutron_extensions.append_api_extensions_path(extensions.__path__)

        self.add_meta_server_route = cfg.CONF.RESTPROXY.add_meta_server_route

        # init network ctrl connections
        self.servers = servermanager.ServerPool()
        self.servers.get_topo_function = self._get_all_data
        self.servers.get_topo_function_args = {'get_ports': True,
                                               'get_floating_ips': True,
                                               'get_routers': True}

        self.network_scheduler = importutils.import_object(
            cfg.CONF.network_scheduler_driver
        )

        # setup rpc for security and DHCP agents
        self._setup_rpc()

        if cfg.CONF.RESTPROXY.sync_data:
            self._send_all_data()

        self.start_periodic_dhcp_agent_status_check()
        LOG.debug("NeutronRestProxyV2: initialization done")

    def _setup_rpc(self):
        self.conn = n_rpc.create_connection(new=True)
        self.topic = topics.PLUGIN
        self.notifier = AgentNotifierApi(topics.AGENT)
        # init dhcp agent support
        self._dhcp_agent_notifier = dhcp_rpc_agent_api.DhcpAgentNotifyAPI()
        self.agent_notifiers[const.AGENT_TYPE_DHCP] = (
            self._dhcp_agent_notifier
        )
        self.endpoints = [securitygroups_rpc.SecurityGroupServerRpcCallback(),
                          dhcp_rpc.DhcpRpcCallback(),
                          agents_db.AgentExtRpcCallback(),
                          metadata_rpc.MetadataRpcCallback()]
        self.conn.create_consumer(self.topic, self.endpoints,
                                  fanout=False)
        # Consume from all consumers in threads
        self.conn.consume_in_threads()

    @put_context_in_serverpool
    def create_network(self, context, network):
        """Create a network.

        Network represents an L2 network segment which can have a set of
        subnets and ports associated with it.

        :param context: neutron api request context
        :param network: dictionary describing the network

        :returns: a sequence of mappings with the following signature:
        {
            "id": UUID representing the network.
            "name": Human-readable name identifying the network.
            "tenant_id": Owner of network. NOTE: only admin user can specify
                         a tenant_id other than its own.
            "admin_state_up": Sets admin state of network.
                              if down, network does not forward packets.
            "status": Indicates whether network is currently operational
                      (values are "ACTIVE", "DOWN", "BUILD", and "ERROR")
            "subnets": Subnets associated with this network.
        }

        :raises: RemoteRestError
        """
        LOG.debug("NeutronRestProxyV2: create_network() called")

        self._warn_on_state_status(network['network'])

        with context.session.begin(subtransactions=True):
            self._ensure_default_security_group(
                context,
                network['network']["tenant_id"]
            )
            # create network in DB
            new_net = super(NeutronRestProxyV2, self).create_network(context,
                                                                     network)
            self._process_l3_create(context, new_net, network['network'])
            # create network on the network controller
            self._send_create_network(new_net, context)

        # return created network
        return new_net

    @put_context_in_serverpool
    def update_network(self, context, net_id, network):
        """Updates the properties of a particular Virtual Network.

        :param context: neutron api request context
        :param net_id: uuid of the network to update
        :param network: dictionary describing the updates

        :returns: a sequence of mappings with the following signature:
        {
            "id": UUID representing the network.
            "name": Human-readable name identifying the network.
            "tenant_id": Owner of network. NOTE: only admin user can
                         specify a tenant_id other than its own.
            "admin_state_up": Sets admin state of network.
                              if down, network does not forward packets.
            "status": Indicates whether network is currently operational
                      (values are "ACTIVE", "DOWN", "BUILD", and "ERROR")
            "subnets": Subnets associated with this network.
        }

        :raises: exceptions.NetworkNotFound
        :raises: RemoteRestError
        """
        LOG.debug("NeutronRestProxyV2.update_network() called")

        self._warn_on_state_status(network['network'])

        session = context.session
        with session.begin(subtransactions=True):
            new_net = super(NeutronRestProxyV2, self).update_network(
                context, net_id, network)
            self._process_l3_update(context, new_net, network['network'])

            # update network on network controller
            self._send_update_network(new_net, context)
        return new_net

    # NOTE(kevinbenton): workaround for eventlet/mysql deadlock
    @utils.synchronized('bsn-port-barrier')
    @put_context_in_serverpool
    def delete_network(self, context, net_id):
        """Delete a network.
        :param context: neutron api request context
        :param id: UUID representing the network to delete.

        :returns: None

        :raises: exceptions.NetworkInUse
        :raises: exceptions.NetworkNotFound
        :raises: RemoteRestError
        """
        LOG.debug("NeutronRestProxyV2: delete_network() called")

        # Validate args
        orig_net = super(NeutronRestProxyV2, self).get_network(context, net_id)
        with context.session.begin(subtransactions=True):
            self._process_l3_delete(context, net_id)
            ret_val = super(NeutronRestProxyV2, self).delete_network(context,
                                                                     net_id)
            self._send_delete_network(orig_net, context)
            return ret_val

    @put_context_in_serverpool
    def create_port(self, context, port):
        """Create a port, which is a connection point of a device
        (e.g., a VM NIC) to attach an L2 Neutron network.
        :param context: neutron api request context
        :param port: dictionary describing the port

        :returns:
        {
            "id": uuid representing the port.
            "network_id": uuid of network.
            "tenant_id": tenant_id
            "mac_address": mac address to use on this port.
            "admin_state_up": Sets admin state of port. if down, port
                              does not forward packets.
            "status": dicates whether port is currently operational
                      (limit values to "ACTIVE", "DOWN", "BUILD", and "ERROR")
            "fixed_ips": list of subnet IDs and IP addresses to be used on
                         this port
            "device_id": identifies the device (e.g., virtual server) using
                         this port.
        }

        :raises: exceptions.NetworkNotFound
        :raises: exceptions.StateInvalid
        :raises: RemoteRestError
        """
        LOG.debug("NeutronRestProxyV2: create_port() called")

        # Update DB in new session so exceptions rollback changes
        with context.session.begin(subtransactions=True):
            self._ensure_default_security_group_on_port(context, port)
            sgids = self._get_security_groups_on_port(context, port)
            # non-router port status is set to pending. it is then updated
            # after the async rest call completes. router ports are synchronous
            if port['port']['device_owner'] == l3_db.DEVICE_OWNER_ROUTER_INTF:
                port['port']['status'] = const.PORT_STATUS_ACTIVE
            else:
                port['port']['status'] = const.PORT_STATUS_BUILD
            dhcp_opts = port['port'].get(edo_ext.EXTRADHCPOPTS, [])
            new_port = super(NeutronRestProxyV2, self).create_port(context,
                                                                   port)
            self._process_port_create_security_group(context, new_port, sgids)
        if (portbindings.HOST_ID in port['port']
            and 'id' in new_port):
            host_id = port['port'][portbindings.HOST_ID]
            porttracker_db.put_port_hostid(context, new_port['id'],
                                           host_id)
        new_port[addr_pair.ADDRESS_PAIRS] = (
            self._process_create_allowed_address_pairs(
                context, new_port,
                port['port'].get(addr_pair.ADDRESS_PAIRS)))
        self._process_port_create_extra_dhcp_opts(context, new_port,
                                                  dhcp_opts)
        new_port = self._extend_port_dict_binding(context, new_port)
        net = super(NeutronRestProxyV2,
                    self).get_network(context, new_port["network_id"])
        if self.add_meta_server_route:
            if new_port['device_owner'] == const.DEVICE_OWNER_DHCP:
                destination = METADATA_SERVER_IP + '/32'
                self._add_host_route(context, destination, new_port)

        # create on network ctrl
        mapped_port = self._map_state_and_status(new_port)
        # ports have to be created synchronously when creating a router
        # port since adding router interfaces is a multi-call process
        if mapped_port['device_owner'] == l3_db.DEVICE_OWNER_ROUTER_INTF:
            self.servers.rest_create_port(net["tenant_id"],
                                          new_port["network_id"],
                                          mapped_port)
        else:
            self.evpool.spawn_n(self.async_port_create, net["tenant_id"],
                                new_port["network_id"], mapped_port)
        self.notify_security_groups_member_updated(context, new_port)
        return new_port

    def get_port(self, context, id, fields=None):
        with context.session.begin(subtransactions=True):
            port = super(NeutronRestProxyV2, self).get_port(context, id,
                                                            fields)
            self._extend_port_dict_binding(context, port)
        return self._fields(port, fields)

    def get_ports(self, context, filters=None, fields=None):
        with context.session.begin(subtransactions=True):
            ports = super(NeutronRestProxyV2, self).get_ports(context, filters,
                                                              fields)
            for port in ports:
                self._extend_port_dict_binding(context, port)
        return [self._fields(port, fields) for port in ports]

    @put_context_in_serverpool
    def update_port(self, context, port_id, port):
        """Update values of a port.

        :param context: neutron api request context
        :param id: UUID representing the port to update.
        :param port: dictionary with keys indicating fields to update.

        :returns: a mapping sequence with the following signature:
        {
            "id": uuid representing the port.
            "network_id": uuid of network.
            "tenant_id": tenant_id
            "mac_address": mac address to use on this port.
            "admin_state_up": sets admin state of port. if down, port
                               does not forward packets.
            "status": dicates whether port is currently operational
                       (limit values to "ACTIVE", "DOWN", "BUILD", and "ERROR")
            "fixed_ips": list of subnet IDs and IP addresses to be used on
                         this port
            "device_id": identifies the device (e.g., virtual server) using
                         this port.
        }

        :raises: exceptions.StateInvalid
        :raises: exceptions.PortNotFound
        :raises: RemoteRestError
        """
        LOG.debug("NeutronRestProxyV2: update_port() called")

        self._warn_on_state_status(port['port'])

        # Validate Args
        orig_port = super(NeutronRestProxyV2, self).get_port(context, port_id)
        with context.session.begin(subtransactions=True):
            # Update DB
            new_port = super(NeutronRestProxyV2,
                             self).update_port(context, port_id, port)
            ctrl_update_required = False
            if addr_pair.ADDRESS_PAIRS in port['port']:
                ctrl_update_required |= (
                    self.update_address_pairs_on_port(context, port_id, port,
                                                      orig_port, new_port))
            self._update_extra_dhcp_opts_on_port(context, port_id, port,
                                                 new_port)
            old_host_id = porttracker_db.get_port_hostid(context,
                                                         orig_port['id'])
            if (portbindings.HOST_ID in port['port']
                and 'id' in new_port):
                host_id = port['port'][portbindings.HOST_ID]
                porttracker_db.put_port_hostid(context, new_port['id'],
                                               host_id)
                if old_host_id != host_id:
                    ctrl_update_required = True

            if (new_port.get("device_id") != orig_port.get("device_id") and
                orig_port.get("device_id")):
                ctrl_update_required = True

            if ctrl_update_required:
                # tenant_id must come from network in case network is shared
                net_tenant_id = self._get_port_net_tenantid(context, new_port)
                new_port = self._extend_port_dict_binding(context, new_port)
                mapped_port = self._map_state_and_status(new_port)
                self.servers.rest_update_port(net_tenant_id,
                                              new_port["network_id"],
                                              mapped_port)
            need_port_update_notify = self.update_security_group_on_port(
                context, port_id, port, orig_port, new_port)
        need_port_update_notify |= self.is_security_group_member_updated(
            context, orig_port, new_port)

        if need_port_update_notify:
            self.notifier.port_update(context, new_port)

        # return new_port
        return new_port

    # NOTE(kevinbenton): workaround for eventlet/mysql deadlock
    @utils.synchronized('bsn-port-barrier')
    @put_context_in_serverpool
    def delete_port(self, context, port_id, l3_port_check=True):
        """Delete a port.
        :param context: neutron api request context
        :param id: UUID representing the port to delete.

        :raises: exceptions.PortInUse
        :raises: exceptions.PortNotFound
        :raises: exceptions.NetworkNotFound
        :raises: RemoteRestError
        """
        LOG.debug("NeutronRestProxyV2: delete_port() called")

        # if needed, check to see if this is a port owned by
        # and l3-router.  If so, we should prevent deletion.
        if l3_port_check and self.l3_plugin:
            self.l3_plugin.prevent_l3_port_deletion(context, port_id)
        with context.session.begin(subtransactions=True):
            if self.l3_plugin:
                router_ids = self.l3_plugin.disassociate_floatingips(
                    context, port_id, do_notify=False)
            port = super(NeutronRestProxyV2, self).get_port(context, port_id)
            # Tenant ID must come from network in case the network is shared
            tenid = self._get_port_net_tenantid(context, port)
            self._delete_port(context, port_id)
            self.servers.rest_delete_port(tenid, port['network_id'], port_id)

        if self.l3_plugin:
            # now that we've left db transaction, we are safe to notify
            self.l3_plugin.notify_routers_updated(context, router_ids)

    @put_context_in_serverpool
    def create_subnet(self, context, subnet):
        LOG.debug("NeutronRestProxyV2: create_subnet() called")

        self._warn_on_state_status(subnet['subnet'])

        with context.session.begin(subtransactions=True):
            # create subnet in DB
            new_subnet = super(NeutronRestProxyV2,
                               self).create_subnet(context, subnet)
            net_id = new_subnet['network_id']
            orig_net = super(NeutronRestProxyV2,
                             self).get_network(context, net_id)
            # update network on network controller
            self._send_update_network(orig_net, context)
        return new_subnet

    @put_context_in_serverpool
    def update_subnet(self, context, id, subnet):
        LOG.debug("NeutronRestProxyV2: update_subnet() called")

        self._warn_on_state_status(subnet['subnet'])

        with context.session.begin(subtransactions=True):
            # update subnet in DB
            new_subnet = super(NeutronRestProxyV2,
                               self).update_subnet(context, id, subnet)
            net_id = new_subnet['network_id']
            orig_net = super(NeutronRestProxyV2,
                             self).get_network(context, net_id)
            # update network on network controller
            self._send_update_network(orig_net, context)
            return new_subnet

    @put_context_in_serverpool
    def delete_subnet(self, context, id):
        LOG.debug("NeutronRestProxyV2: delete_subnet() called")
        orig_subnet = super(NeutronRestProxyV2, self).get_subnet(context, id)
        net_id = orig_subnet['network_id']
        with context.session.begin(subtransactions=True):
            # delete subnet in DB
            super(NeutronRestProxyV2, self).delete_subnet(context, id)
            orig_net = super(NeutronRestProxyV2, self).get_network(context,
                                                                   net_id)
            # update network on network controller - exception will rollback
            self._send_update_network(orig_net, context)

    def _add_host_route(self, context, destination, port):
        subnet = {}
        for fixed_ip in port['fixed_ips']:
            subnet_id = fixed_ip['subnet_id']
            nexthop = fixed_ip['ip_address']
            subnet['host_routes'] = [{'destination': destination,
                                      'nexthop': nexthop}]
            updated_subnet = self.update_subnet(context,
                                                subnet_id,
                                                {'subnet': subnet})
            payload = {'subnet': updated_subnet}
            self._dhcp_agent_notifier.notify(context, payload,
                                             'subnet.update.end')
            LOG.debug("Adding host route: ")
            LOG.debug("Destination:%(dst)s nexthop:%(next)s",
                      {'dst': destination, 'next': nexthop})
