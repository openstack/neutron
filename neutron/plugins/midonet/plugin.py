# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (C) 2012 Midokura Japan K.K.
# Copyright (C) 2013 Midokura PTE LTD
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
# @author: Takaaki Suzuki, Midokura Japan KK
# @author: Tomoe Sugihara, Midokura Japan KK
# @author: Ryu Ishimoto, Midokura Japan KK
# @author: Rossella Sblendido, Midokura Japan KK

from midonetclient import api
from oslo.config import cfg

from neutron.common import constants
from neutron.common import exceptions as n_exc
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.db import agents_db
from neutron.db import agentschedulers_db
from neutron.db import api as db
from neutron.db import db_base_plugin_v2
from neutron.db import dhcp_rpc_base
from neutron.db import external_net_db
from neutron.db import l3_db
from neutron.db import models_v2
from neutron.db import securitygroups_db
from neutron.extensions import securitygroup as ext_sg
from neutron.openstack.common import excutils
from neutron.openstack.common import log as logging
from neutron.openstack.common import rpc
from neutron.plugins.midonet.common import config  # noqa
from neutron.plugins.midonet.common import net_util
from neutron.plugins.midonet import midonet_lib

LOG = logging.getLogger(__name__)

METADATA_DEFAULT_IP = "169.254.169.254/32"
OS_FLOATING_IP_RULE_KEY = 'OS_FLOATING_IP'
OS_SG_RULE_KEY = 'OS_SG_RULE_ID'
OS_TENANT_ROUTER_RULE_KEY = 'OS_TENANT_ROUTER_RULE'
PRE_ROUTING_CHAIN_NAME = "OS_PRE_ROUTING_%s"
PORT_INBOUND_CHAIN_NAME = "OS_PORT_%s_INBOUND"
PORT_OUTBOUND_CHAIN_NAME = "OS_PORT_%s_OUTBOUND"
POST_ROUTING_CHAIN_NAME = "OS_POST_ROUTING_%s"
SG_INGRESS_CHAIN_NAME = "OS_SG_%s_INGRESS"
SG_EGRESS_CHAIN_NAME = "OS_SG_%s_EGRESS"
SG_PORT_GROUP_NAME = "OS_PG_%s"
SNAT_RULE = 'SNAT'


def _get_nat_ips(type, fip):
    """Get NAT IP address information.

    From the route type given, determine the source and target IP addresses
    from the provided floating IP DB object.
    """
    if type == 'pre-routing':
        return fip["floating_ip_address"], fip["fixed_ip_address"]
    elif type == 'post-routing':
        return fip["fixed_ip_address"], fip["floating_ip_address"]
    else:
        raise ValueError(_("Invalid nat_type %s") % type)


def _nat_chain_names(router_id):
    """Get the chain names for NAT.

    These names are used to associate MidoNet chains to the NAT rules
    applied to the router.  For each of these, there are two NAT types,
    'dnat' and 'snat' that are returned as keys, and the corresponding
    chain names as their values.
    """
    pre_routing_name = PRE_ROUTING_CHAIN_NAME % router_id
    post_routing_name = POST_ROUTING_CHAIN_NAME % router_id
    return {'pre-routing': pre_routing_name, 'post-routing': post_routing_name}


def _sg_chain_names(sg_id):
    """Get the chain names for security group.

    These names are used to associate a security group to MidoNet chains.
    There are two names for ingress and egress security group directions.
    """
    ingress = SG_INGRESS_CHAIN_NAME % sg_id
    egress = SG_EGRESS_CHAIN_NAME % sg_id
    return {'ingress': ingress, 'egress': egress}


def _port_chain_names(port_id):
    """Get the chain names for a port.

    These are chains to hold security group chains.
    """
    inbound = PORT_INBOUND_CHAIN_NAME % port_id
    outbound = PORT_OUTBOUND_CHAIN_NAME % port_id
    return {'inbound': inbound, 'outbound': outbound}


def _sg_port_group_name(sg_id):
    """Get the port group name for security group..

    This name is used to associate a security group to MidoNet  port groups.
    """
    return SG_PORT_GROUP_NAME % sg_id


def _rule_direction(sg_direction):
    """Convert the SG direction to MidoNet direction

    MidoNet terms them 'inbound' and 'outbound' instead of 'ingress' and
    'egress'.  Also, the direction is reversed since MidoNet sees it
    from the network port's point of view, not the VM's.
    """
    if sg_direction == 'ingress':
        return 'outbound'
    elif sg_direction == 'egress':
        return 'inbound'
    else:
        raise ValueError(_("Unrecognized direction %s") % sg_direction)


def _is_router_interface_port(port):
    """Check whether the given port is a router interface port."""
    device_owner = port['device_owner']
    return (device_owner in l3_db.DEVICE_OWNER_ROUTER_INTF)


def _is_router_gw_port(port):
    """Check whether the given port is a router gateway port."""
    device_owner = port['device_owner']
    return (device_owner in l3_db.DEVICE_OWNER_ROUTER_GW)


def _is_vif_port(port):
    """Check whether the given port is a standard VIF port."""
    device_owner = port['device_owner']
    return (not _is_dhcp_port(port) and
            device_owner not in (l3_db.DEVICE_OWNER_ROUTER_GW,
                                 l3_db.DEVICE_OWNER_ROUTER_INTF))


def _is_dhcp_port(port):
    """Check whether the given port is a DHCP port."""
    device_owner = port['device_owner']
    return device_owner.startswith('network:dhcp')


def _check_resource_exists(func, id, name, raise_exc=False):
    """Check whether the given resource exists in MidoNet data store."""
    try:
        func(id)
    except midonet_lib.MidonetResourceNotFound as exc:
        LOG.error(_("There is no %(name)s with ID %(id)s in MidoNet."),
                  {"name": name, "id": id})
        if raise_exc:
            raise MidonetPluginException(msg=exc)


class MidoRpcCallbacks(dhcp_rpc_base.DhcpRpcCallbackMixin):
    RPC_API_VERSION = '1.1'

    def create_rpc_dispatcher(self):
        """Get the rpc dispatcher for this manager.

        This a basic implementation that will call the plugin like get_ports
        and handle basic events
        If a manager would like to set an rpc API version, or support more than
        one class as the target of rpc messages, override this method.
        """
        return n_rpc.PluginRpcDispatcher([self,
                                          agents_db.AgentExtRpcCallback()])


class MidonetPluginException(n_exc.NeutronException):
    message = _("%(msg)s")


class MidonetPluginV2(db_base_plugin_v2.NeutronDbPluginV2,
                      external_net_db.External_net_db_mixin,
                      l3_db.L3_NAT_db_mixin,
                      agentschedulers_db.DhcpAgentSchedulerDbMixin,
                      securitygroups_db.SecurityGroupDbMixin):

    supported_extension_aliases = ['external-net', 'router', 'security-group',
                                   'agent' 'dhcp_agent_scheduler']
    __native_bulk_support = False

    def __init__(self):
        # Read config values
        midonet_conf = cfg.CONF.MIDONET
        midonet_uri = midonet_conf.midonet_uri
        admin_user = midonet_conf.username
        admin_pass = midonet_conf.password
        admin_project_id = midonet_conf.project_id
        self.provider_router_id = midonet_conf.provider_router_id
        self.provider_router = None

        self.mido_api = api.MidonetApi(midonet_uri, admin_user,
                                       admin_pass,
                                       project_id=admin_project_id)
        self.client = midonet_lib.MidoClient(self.mido_api)

        # self.provider_router_id should have been set.
        if self.provider_router_id is None:
            msg = _('provider_router_id should be configured in the plugin '
                    'config file')
            LOG.exception(msg)
            raise MidonetPluginException(msg=msg)

        self.setup_rpc()
        db.configure_db()

    def _get_provider_router(self):
        if self.provider_router is None:
            self.provider_router = self.client.get_router(
                self.provider_router_id)
        return self.provider_router

    def _dhcp_mappings(self, context, fixed_ips, mac):
        for fixed_ip in fixed_ips:
            subnet = self._get_subnet(context, fixed_ip["subnet_id"])
            if subnet["ip_version"] == 6:
                # TODO(ryu) handle IPv6
                continue
            yield subnet['cidr'], fixed_ip["ip_address"], mac

    def _metadata_subnets(self, context, fixed_ips):
        for fixed_ip in fixed_ips:
            subnet = self._get_subnet(context, fixed_ip["subnet_id"])
            if subnet["ip_version"] == 6:
                continue
            yield subnet['cidr'], fixed_ip["ip_address"]

    def _initialize_port_chains(self, port, in_chain, out_chain, sg_ids):

        tenant_id = port["tenant_id"]

        position = 1
        # mac spoofing protection
        self._add_chain_rule(in_chain, action='drop',
                             dl_src=port["mac_address"], inv_dl_src=True,
                             position=position)

        # ip spoofing protection
        for fixed_ip in port["fixed_ips"]:
            position += 1
            self._add_chain_rule(in_chain, action="drop",
                                 src_addr=fixed_ip["ip_address"] + "/32",
                                 inv_nw_src=True, dl_type=0x0800,  # IPv4
                                 position=position)

        # conntrack
        position += 1
        self._add_chain_rule(in_chain, action='accept',
                             match_forward_flow=True,
                             position=position)

        # Reset the position to process egress
        position = 1

        # Add rule for SGs
        if sg_ids:
            for sg_id in sg_ids:
                chain_name = _sg_chain_names(sg_id)["ingress"]
                chain = self.client.get_chain_by_name(tenant_id, chain_name)
                self._add_chain_rule(out_chain, action='jump',
                                     jump_chain_id=chain.get_id(),
                                     jump_chain_name=chain_name,
                                     position=position)
                position += 1

        # add reverse flow matching at the end
        self._add_chain_rule(out_chain, action='accept',
                             match_return_flow=True,
                             position=position)
        position += 1

        # fall back DROP rule at the end except for ARP
        self._add_chain_rule(out_chain, action='drop',
                             dl_type=0x0806,  # ARP
                             inv_dl_type=True, position=position)

    def _bind_port_to_sgs(self, context, port, sg_ids):
        self._process_port_create_security_group(context, port, sg_ids)
        if sg_ids is not None:
            for sg_id in sg_ids:
                pg_name = _sg_port_group_name(sg_id)
                self.client.add_port_to_port_group_by_name(
                    port["tenant_id"], pg_name, port["id"])

    def _unbind_port_from_sgs(self, context, port_id):
        self._delete_port_security_group_bindings(context, port_id)
        self.client.remove_port_from_port_groups(port_id)

    def _create_accept_chain_rule(self, context, sg_rule, chain=None):
        direction = sg_rule["direction"]
        tenant_id = sg_rule["tenant_id"]
        sg_id = sg_rule["security_group_id"]
        chain_name = _sg_chain_names(sg_id)[direction]

        if chain is None:
            chain = self.client.get_chain_by_name(tenant_id, chain_name)

        pg_id = None
        if sg_rule["remote_group_id"] is not None:
            pg_name = _sg_port_group_name(sg_id)
            pg = self.client.get_port_group_by_name(tenant_id, pg_name)
            pg_id = pg.get_id()

        props = {OS_SG_RULE_KEY: str(sg_rule["id"])}

        # Determine source or destination address by looking at direction
        src_pg_id = dst_pg_id = None
        src_addr = dst_addr = None
        src_port_to = dst_port_to = None
        src_port_from = dst_port_from = None
        if direction == "egress":
            dst_pg_id = pg_id
            dst_addr = sg_rule["remote_ip_prefix"]
            dst_port_from = sg_rule["port_range_min"]
            dst_port_to = sg_rule["port_range_max"]
        else:
            src_pg_id = pg_id
            src_addr = sg_rule["remote_ip_prefix"]
            src_port_from = sg_rule["port_range_min"]
            src_port_to = sg_rule["port_range_max"]

        return self._add_chain_rule(
            chain, action='accept', port_group_src=src_pg_id,
            port_group_dst=dst_pg_id,
            src_addr=src_addr, src_port_from=src_port_from,
            src_port_to=src_port_to,
            dst_addr=dst_addr, dst_port_from=dst_port_from,
            dst_port_to=dst_port_to,
            nw_proto=net_util.get_protocol_value(sg_rule["protocol"]),
            dl_type=net_util.get_ethertype_value(sg_rule["ethertype"]),
            properties=props)

    def setup_rpc(self):
        # RPC support
        self.topic = topics.PLUGIN
        self.conn = rpc.create_connection(new=True)
        self.callbacks = MidoRpcCallbacks()
        self.dispatcher = self.callbacks.create_rpc_dispatcher()
        self.conn.create_consumer(self.topic, self.dispatcher,
                                  fanout=False)
        # Consume from all consumers in a thread
        self.conn.consume_in_thread()

    def create_subnet(self, context, subnet):
        """Create Neutron subnet.

        Creates a Neutron subnet and a DHCP entry in MidoNet bridge.
        """
        LOG.debug(_("MidonetPluginV2.create_subnet called: subnet=%r"), subnet)

        subnet_data = subnet["subnet"]
        net = super(MidonetPluginV2, self).get_network(
            context, subnet['subnet']['network_id'], fields=None)

        session = context.session
        with session.begin(subtransactions=True):
            sn_entry = super(MidonetPluginV2, self).create_subnet(context,
                                                                  subnet)
            bridge = self.client.get_bridge(sn_entry['network_id'])

            gateway_ip = subnet_data['gateway_ip']
            cidr = subnet_data['cidr']
            self.client.create_dhcp(bridge, gateway_ip, cidr)

            # For external network, link the bridge to the provider router.
            if net['router:external']:
                self._link_bridge_to_gw_router(
                    bridge, self._get_provider_router(), gateway_ip, cidr)

        LOG.debug(_("MidonetPluginV2.create_subnet exiting: sn_entry=%r"),
                  sn_entry)
        return sn_entry

    def delete_subnet(self, context, id):
        """Delete Neutron subnet.

        Delete neutron network and its corresponding MidoNet bridge.
        """
        LOG.debug(_("MidonetPluginV2.delete_subnet called: id=%s"), id)
        subnet = super(MidonetPluginV2, self).get_subnet(context, id,
                                                         fields=None)
        net = super(MidonetPluginV2, self).get_network(context,
                                                       subnet['network_id'],
                                                       fields=None)
        bridge = self.client.get_bridge(subnet['network_id'])
        self.client.delete_dhcp(bridge)

        # If the network is external, clean up routes, links, ports.
        if net['router:external']:
            self._unlink_bridge_from_gw_router(bridge,
                                               self._get_provider_router())

        super(MidonetPluginV2, self).delete_subnet(context, id)
        LOG.debug(_("MidonetPluginV2.delete_subnet exiting"))

    def create_network(self, context, network):
        """Create Neutron network.

        Create a new Neutron network and its corresponding MidoNet bridge.
        """
        LOG.debug(_('MidonetPluginV2.create_network called: network=%r'),
                  network)
        tenant_id = self._get_tenant_id_for_create(context, network['network'])
        self._ensure_default_security_group(context, tenant_id)

        bridge = self.client.create_bridge(tenant_id,
                                           network['network']['name'])
        network['network']['id'] = bridge.get_id()

        session = context.session
        with session.begin(subtransactions=True):
            net = super(MidonetPluginV2, self).create_network(context, network)
            self._process_l3_create(context, net, network['network'])

        LOG.debug(_("MidonetPluginV2.create_network exiting: net=%r"), net)
        return net

    def update_network(self, context, id, network):
        """Update Neutron network.

        Update an existing Neutron network and its corresponding MidoNet
        bridge.
        """
        LOG.debug(_("MidonetPluginV2.update_network called: id=%(id)r, "
                    "network=%(network)r"), {'id': id, 'network': network})
        session = context.session
        with session.begin(subtransactions=True):
            net = super(MidonetPluginV2, self).update_network(
                context, id, network)
            self.client.update_bridge(id, net['name'])

        LOG.debug(_("MidonetPluginV2.update_network exiting: net=%r"), net)
        return net

    def get_network(self, context, id, fields=None):
        """Get Neutron network.

        Retrieves a Neutron network and its corresponding MidoNet bridge.
        """
        LOG.debug(_("MidonetPluginV2.get_network called: id=%(id)r, "
                    "fields=%(fields)r"), {'id': id, 'fields': fields})
        qnet = super(MidonetPluginV2, self).get_network(context, id, fields)
        self.client.get_bridge(id)

        LOG.debug(_("MidonetPluginV2.get_network exiting: qnet=%r"), qnet)
        return qnet

    def delete_network(self, context, id):
        """Delete a network and its corresponding MidoNet bridge."""
        LOG.debug(_("MidonetPluginV2.delete_network called: id=%r"), id)
        self.client.delete_bridge(id)
        try:
            super(MidonetPluginV2, self).delete_network(context, id)
        except Exception:
            LOG.error(_('Failed to delete neutron db, while Midonet bridge=%r'
                      'had been deleted'), id)
            raise

    def create_port(self, context, port):
        """Create a L2 port in Neutron/MidoNet."""
        LOG.debug(_("MidonetPluginV2.create_port called: port=%r"), port)
        port_data = port['port']
        # Create a bridge port in MidoNet and set the bridge port ID as the
        # port ID in Neutron.
        bridge = self.client.get_bridge(port_data["network_id"])
        tenant_id = bridge.get_tenant_id()
        bridge_port = self.client.add_bridge_port(bridge)
        port_data["id"] = bridge_port.get_id()
        try:
            session = context.session
            with session.begin(subtransactions=True):
                # Create a Neutron port
                new_port = super(MidonetPluginV2, self).create_port(context,
                                                                    port)
                port_data.update(new_port)
                self._ensure_default_security_group_on_port(context,
                                                            port)
                if _is_vif_port(port_data):
                    # Bind security groups to the port
                    sg_ids = self._get_security_groups_on_port(context, port)
                    self._bind_port_to_sgs(context, port_data, sg_ids)

                    # Create port chains
                    port_chains = {}
                    for d, name in _port_chain_names(
                        new_port["id"]).iteritems():
                        port_chains[d] = self.client.create_chain(tenant_id,
                                                                  name)

                    self._initialize_port_chains(port_data,
                                                 port_chains['inbound'],
                                                 port_chains['outbound'],
                                                 sg_ids)

                    # Update the port with the chain
                    self.client.update_port_chains(
                        bridge_port, port_chains["inbound"].get_id(),
                        port_chains["outbound"].get_id())

                    # DHCP mapping is only for VIF ports
                    for cidr, ip, mac in self._dhcp_mappings(
                            context, port_data["fixed_ips"],
                            port_data["mac_address"]):
                        self.client.add_dhcp_host(bridge, cidr, ip, mac)

                elif _is_dhcp_port(port_data):
                    # For DHCP port, add a metadata route
                    for cidr, ip in self._metadata_subnets(
                        context, port_data["fixed_ips"]):
                        self.client.add_dhcp_route_option(bridge, cidr, ip,
                                                          METADATA_DEFAULT_IP)

        except Exception as ex:
            # Try removing the MidoNet port before raising an exception.
            with excutils.save_and_reraise_exception():
                LOG.error(_("Failed to create a port on network %(net_id)s: "
                            "%(err)s"),
                          {"net_id": port_data["network_id"], "err": ex})
                self.client.delete_port(bridge_port.get_id())

        LOG.debug(_("MidonetPluginV2.create_port exiting: port=%r"), port_data)
        return port_data

    def get_port(self, context, id, fields=None):
        """Retrieve port."""
        LOG.debug(_("MidonetPluginV2.get_port called: id=%(id)s "
                    "fields=%(fields)r"), {'id': id, 'fields': fields})
        port = super(MidonetPluginV2, self).get_port(context, id, fields)
        "Check if the port exists in MidoNet DB"""
        try:
            self.client.get_port(id)
        except midonet_lib.MidonetResourceNotFound as exc:
            LOG.error(_("There is no port with ID %(id)s in MidoNet."),
                      {"id": id})
            port['status'] = constants.PORT_STATUS_ERROR
            raise exc
        LOG.debug(_("MidonetPluginV2.get_port exiting: port=%r"), port)
        return port

    def get_ports(self, context, filters=None, fields=None):
        """List neutron ports and verify that they exist in MidoNet."""
        LOG.debug(_("MidonetPluginV2.get_ports called: filters=%(filters)s "
                    "fields=%(fields)r"),
                  {'filters': filters, 'fields': fields})
        ports = super(MidonetPluginV2, self).get_ports(context, filters,
                                                       fields)
        return ports

    def delete_port(self, context, id, l3_port_check=True):
        """Delete a neutron port and corresponding MidoNet bridge port."""
        LOG.debug(_("MidonetPluginV2.delete_port called: id=%(id)s "
                    "l3_port_check=%(l3_port_check)r"),
                  {'id': id, 'l3_port_check': l3_port_check})
        # if needed, check to see if this is a port owned by
        # and l3-router.  If so, we should prevent deletion.
        if l3_port_check:
            self.prevent_l3_port_deletion(context, id)

        port = self.get_port(context, id)
        device_id = port['device_id']
        # If this port is for router interface/gw, unlink and delete.
        if _is_router_interface_port(port):
            self._unlink_bridge_from_router(device_id, id)
        elif _is_router_gw_port(port):
            # Gateway removed
            # Remove all the SNAT rules that are tagged.
            router = self._get_router(context, device_id)
            tenant_id = router["tenant_id"]
            chain_names = _nat_chain_names(device_id)
            for _type, name in chain_names.iteritems():
                self.client.remove_rules_by_property(
                    tenant_id, name, OS_TENANT_ROUTER_RULE_KEY,
                    SNAT_RULE)
            # Remove the default routes and unlink
            self._remove_router_gateway(port['device_id'])

        self.client.delete_port(id, delete_chains=True)
        try:
            for cidr, ip, mac in self._dhcp_mappings(
                    context, port["fixed_ips"], port["mac_address"]):
                self.client.delete_dhcp_host(port["network_id"], cidr, ip,
                                             mac)
        except Exception:
            LOG.error(_("Failed to delete DHCP mapping for port %(id)s"),
                      {"id": id})

        super(MidonetPluginV2, self).delete_port(context, id)

    def update_port(self, context, id, port):
        """Handle port update, including security groups and fixed IPs."""
        with context.session.begin(subtransactions=True):

            # Get the port and save the fixed IPs
            old_port = self._get_port(context, id)
            net_id = old_port["network_id"]
            mac = old_port["mac_address"]
            old_ips = old_port["fixed_ips"]
            import pdb
            LOG.debug("SUBNET 1 old ips %s", old_ips)
            # update the port DB
            p = super(MidonetPluginV2, self).update_port(context, id, port)
            # Calculate ip diff
            new_ips = p["fixed_ips"]
            LOG.debug("SUBNET 2 new ip %s", new_ips)
            for old_ip in old_ips[:]:
                for new_ip in new_ips[:]:
                    if ('ip_address' in new_ip and
                        old_ip['ip_address'] == new_ip['ip_address']):
                        old_ips.remove(old_ip)
                        new_ips.remove(new_ip)
            bridge = self.client.get_bridge(net_id)
            # For DHCP port, add or remove a metadata route
            LOG.debug("SUBNET 3 new ip n=%(n)s, old ip o=%(o)s", {"n":new_ips, "o":old_ips})
            if _is_dhcp_port(p):
                if old_ips:
                    for cidr, ip in self._metadata_subnets(
                        context, old_ips):
                        self.client.remove_dhcp_route_option(
                            bridge, cidr, ip, METADATA_DEFAULT_IP)
                if new_ips:
                    for cidr, ip in self._metadata_subnets(
                        context, new_ips):
                        self.client.add_dhcp_route_option(
                            bridge, cidr, ip, METADATA_DEFAULT_IP)
            # IPs have changed.  Re-map the DHCP entries
            if old_ips:
                for cidr, ip, mac in self._dhcp_mappings(
                        context, old_ips, mac):
                    self.client.remove_dhcp_host(bridge, cidr, ip, mac)
            if new_ips:
                for cidr, ip, mac in self._dhcp_mappings(context,
                                                         new_ips, mac):
                    self.client.add_dhcp_host(bridge, cidr, ip, mac)

            if (self._check_update_deletes_security_groups(port) or
                    self._check_update_has_security_groups(port)):
                self._unbind_port_from_sgs(context, p["id"])
                sg_ids = self._get_security_groups_on_port(context, port)
                self._bind_port_to_sgs(context, p, sg_ids)

        return p

    def create_router(self, context, router):
        """Handle router creation.

        When a new Neutron router is created, its corresponding MidoNet router
        is also created.  In MidoNet, this router is initialized with chains
        for inbuond and outbound traffic, which will be used to hold other
        chains that include various rules, such as NAT.

        :param router: Router information provided to create a new router.
        """
        LOG.debug(_("MidonetPluginV2.create_router called: router=%(router)s"),
                  {"router": router})
        tenant_id = self._get_tenant_id_for_create(context, router['router'])
        mido_router = self.client.create_router(tenant_id,
                                                router['router']['name'])
        mido_router_id = mido_router.get_id()

        try:
            with context.session.begin(subtransactions=True):

                router_data = super(MidonetPluginV2, self).create_router(
                    context, router)

                # get entry from the DB and update 'id' with MidoNet router id.
                router_db = self._get_router(context, router_data['id'])
                router_data['id'] = mido_router_id
                router_db.update(router_data)
        except Exception:
            # Try removing the midonet router
            with excutils.save_and_reraise_exception():
                self.client.delete_router(mido_router_id)

        # Create router chains
        chain_names = _nat_chain_names(mido_router_id)
        try:
            self.client.add_router_chains(mido_router,
                                          chain_names["pre-routing"],
                                          chain_names["post-routing"])
        except Exception:
            # Set the router status to Error
            with context.session.begin(subtransactions=True):
                r = self._get_router(context, router_data["id"])
                router_data['status'] = constants.NET_STATUS_ERROR
                r['status'] = router_data['status']
                context.session.add(r)

        LOG.debug(_("MidonetPluginV2.create_router exiting: "
                    "router_data=%(router_data)s."),
                  {"router_data": router_data})
        return router_data

    def _set_router_gateway(self, id, gw_router, gw_ip):
        """Set router uplink gateway

        :param ID: ID of the router
        :param gw_router: gateway router to link to
        :param gw_ip: gateway IP address
        """
        LOG.debug(_("MidonetPluginV2.set_router_gateway called: id=%(id)s, "
                    "gw_router=%(gw_router)s, gw_ip=%(gw_ip)s"),
                  {'id': id, 'gw_router': gw_router, 'gw_ip': gw_ip}),

        router = self.client.get_router(id)

        # Create a port in the gw router
        gw_port = self.client.add_router_port(gw_router,
                                              port_address='169.254.255.1',
                                              network_address='169.254.255.0',
                                              network_length=30)

        # Create a port in the router
        port = self.client.add_router_port(router,
                                           port_address='169.254.255.2',
                                           network_address='169.254.255.0',
                                           network_length=30)

        # Link them
        self.client.link(gw_port, port.get_id())

        # Add a route for gw_ip to bring it down to the router
        self.client.add_router_route(gw_router, type='Normal',
                                     src_network_addr='0.0.0.0',
                                     src_network_length=0,
                                     dst_network_addr=gw_ip,
                                     dst_network_length=32,
                                     next_hop_port=gw_port.get_id(),
                                     weight=100)

        # Add default route to uplink in the router
        self.client.add_router_route(router, type='Normal',
                                     src_network_addr='0.0.0.0',
                                     src_network_length=0,
                                     dst_network_addr='0.0.0.0',
                                     dst_network_length=0,
                                     next_hop_port=port.get_id(),
                                     weight=100)

    def _remove_router_gateway(self, id):
        """Clear router gateway

        :param ID: ID of the router
        """
        LOG.debug(_("MidonetPluginV2.remove_router_gateway called: "
                    "id=%(id)s"), {'id': id})
        router = self.client.get_router(id)

        # delete the port that is connected to the gateway router
        for p in router.get_ports():
            if p.get_port_address() == '169.254.255.2':
                peer_port_id = p.get_peer_id()
                if peer_port_id is not None:
                    self.client.unlink(p)
                    self.client.delete_port(peer_port_id)

        # delete default route
        for r in router.get_routes():
            if (r.get_dst_network_addr() == '0.0.0.0' and
                    r.get_dst_network_length() == 0):
                self.client.delete_route(r.get_id())

    def update_router(self, context, id, router):
        """Handle router updates."""
        LOG.debug(_("MidonetPluginV2.update_router called: id=%(id)s "
                    "router=%(router)r"), {"id": id, "router": router})

        router_data = router["router"]

        # Check if the update included changes to the gateway.
        gw_updated = l3_db.EXTERNAL_GW_INFO in router_data
        with context.session.begin(subtransactions=True):

            # Update the Neutron DB
            r = super(MidonetPluginV2, self).update_router(context, id,
                                                           router)
            tenant_id = r["tenant_id"]
            if gw_updated:
                if (l3_db.EXTERNAL_GW_INFO in r and
                    r[l3_db.EXTERNAL_GW_INFO] is not None):
                    # Gateway created
                    gw_port = self._get_port(context, r["gw_port_id"])
                    gw_ip = gw_port['fixed_ips'][0]['ip_address']

                    # First link routers and set up the routes
                    self._set_router_gateway(r["id"],
                                             self._get_provider_router(),
                                             gw_ip)

                    # Get the NAT chains and add dynamic SNAT rules.
                    chain_names = _nat_chain_names(r["id"])
                    props = {OS_TENANT_ROUTER_RULE_KEY: SNAT_RULE}
                    self.client.add_dynamic_snat(tenant_id,
                                                 chain_names['pre-routing'],
                                                 chain_names['post-routing'],
                                                 gw_ip, gw_port["id"], **props)

            # Update the name if changed
            changed_name = router_data.get('name')
            if changed_name:
                self.client.update_router(id, changed_name)

        LOG.debug(_("MidonetPluginV2.update_router exiting: router=%r"), r)
        return r

    def delete_router(self, context, id):
        """Handler for router deletion.

        Deleting a router on Neutron simply means deleting its corresponding
        router in MidoNet.

        :param id: router ID to remove
        """
        LOG.debug(_("MidonetPluginV2.delete_router called: id=%s"), id)

        self.client.delete_router_chains(id)
        self.client.delete_router(id)

        super(MidonetPluginV2, self).delete_router(context, id)

    def _link_bridge_to_gw_router(self, bridge, gw_router, gw_ip, cidr):
        """Link a bridge to the gateway router

        :param bridge:  bridge
        :param gw_router: gateway router to link to
        :param gw_ip: IP address of gateway
        :param cidr: network CIDR
        """
        net_addr, net_len = net_util.net_addr(cidr)

        # create a port on the gateway router
        gw_port = self.client.add_router_port(gw_router, port_address=gw_ip,
                                              network_address=net_addr,
                                              network_length=net_len)

        # create a bridge port, then link it to the router.
        port = self.client.add_bridge_port(bridge)
        self.client.link(gw_port, port.get_id())

        # add a route for the subnet in the gateway router
        self.client.add_router_route(gw_router, type='Normal',
                                     src_network_addr='0.0.0.0',
                                     src_network_length=0,
                                     dst_network_addr=net_addr,
                                     dst_network_length=net_len,
                                     next_hop_port=gw_port.get_id(),
                                     weight=100)

    def _unlink_bridge_from_gw_router(self, bridge, gw_router):
        """Unlink a bridge from the gateway router

        :param bridge: bridge to unlink
        :param gw_router: gateway router to unlink from
        """
        # Delete routes and unlink the router and the bridge.
        routes = self.client.get_router_routes(gw_router.get_id())

        bridge_ports_to_delete = [
            p for p in gw_router.get_peer_ports()
            if p.get_device_id() == bridge.get_id()]

        for p in bridge.get_peer_ports():
            if p.get_device_id() == gw_router.get_id():
                # delete the routes going to the bridge
                for r in routes:
                    if r.get_next_hop_port() == p.get_id():
                        self.client.delete_route(r.get_id())
                self.client.unlink(p)
                self.client.delete_port(p.get_id())

        # delete bridge port
        for port in bridge_ports_to_delete:
            self.client.delete_port(port.get_id())

    def _link_bridge_to_router(self, router, bridge_port_id, net_addr, net_len,
                               gw_ip, metadata_gw_ip):
        router_port = self.client.add_router_port(
            router, port_address=gw_ip, network_address=net_addr,
            network_length=net_len)
        self.client.link(router_port, bridge_port_id)
        self.client.add_router_route(router, type='Normal',
                                     src_network_addr='0.0.0.0',
                                     src_network_length=0,
                                     dst_network_addr=net_addr,
                                     dst_network_length=net_len,
                                     next_hop_port=router_port.get_id(),
                                     weight=100)

        if metadata_gw_ip:
            # Add a route for the metadata server.
            # Not all VM images supports DHCP option 121.  Add a route for the
            # Metadata server in the router to forward the packet to the bridge
            # that will send them to the Metadata Proxy.
            md_net_addr, md_net_len = net_util.net_addr(METADATA_DEFAULT_IP)
            self.client.add_router_route(
                router, type='Normal', src_network_addr=net_addr,
                src_network_length=net_len,
                dst_network_addr=md_net_addr,
                dst_network_length=md_net_len,
                next_hop_port=router_port.get_id(),
                next_hop_gateway=metadata_gw_ip)

    def _unlink_bridge_from_router(self, router_id, bridge_port_id):
        """Unlink a bridge from a router."""

        # Remove the routes to the port and unlink the port
        bridge_port = self.client.get_port(bridge_port_id)
        routes = self.client.get_router_routes(router_id)
        self.client.delete_port_routes(routes, bridge_port.get_peer_id())
        self.client.unlink(bridge_port)

    def add_router_interface(self, context, router_id, interface_info):
        """Handle router linking with network."""
        LOG.debug(_("MidonetPluginV2.add_router_interface called: "
                    "router_id=%(router_id)s "
                    "interface_info=%(interface_info)r"),
                  {'router_id': router_id, 'interface_info': interface_info})

        with context.session.begin(subtransactions=True):
            info = super(MidonetPluginV2, self).add_router_interface(
                context, router_id, interface_info)

        try:
            subnet = self._get_subnet(context, info["subnet_id"])
            cidr = subnet["cidr"]
            net_addr, net_len = net_util.net_addr(cidr)
            router = self.client.get_router(router_id)

            # Get the metadatat GW IP
            metadata_gw_ip = None
            rport_qry = context.session.query(models_v2.Port)
            dhcp_ports = rport_qry.filter_by(
                network_id=subnet["network_id"],
                device_owner='network:dhcp').all()
            if dhcp_ports and dhcp_ports[0].fixed_ips:
                metadata_gw_ip = dhcp_ports[0].fixed_ips[0].ip_address
            else:
                LOG.warn(_("DHCP agent is not working correctly. No port "
                           "to reach the Metadata server on this network"))
            # Link the router and the bridge
            self._link_bridge_to_router(router, info["port_id"], net_addr,
                                        net_len, subnet["gateway_ip"],
                                        metadata_gw_ip)
        except Exception:
            LOG.error(_("Failed to create MidoNet resources to add router "
                        "interface. info=%(info)s, router_id=%(router_id)s"),
                      {"info": info, "router_id": router_id})
            with excutils.save_and_reraise_exception():
                with context.session.begin(subtransactions=True):
                    self.remove_router_interface(context, router_id, info)

        LOG.debug(_("MidonetPluginV2.add_router_interface exiting: "
                    "info=%r"), info)
        return info

    def update_floatingip(self, context, id, floatingip):
        """Handle floating IP assocation and disassociation."""
        LOG.debug(_("MidonetPluginV2.update_floatingip called: id=%(id)s "
                    "floatingip=%(floatingip)s "),
                  {'id': id, 'floatingip': floatingip})

        session = context.session
        with session.begin(subtransactions=True):
            if floatingip['floatingip']['port_id']:
                fip = super(MidonetPluginV2, self).update_floatingip(
                    context, id, floatingip)

                # Add a route for the floating IP on the provider router.
                router = self.client.get_router(fip["router_id"])
                link_port = self.client.get_link_port(
                    self._get_provider_router(), router.get_id())
                self.client.add_router_route(
                    self._get_provider_router(),
                    src_network_addr='0.0.0.0',
                    src_network_length=0,
                    dst_network_addr=fip["floating_ip_address"],
                    dst_network_length=32,
                    next_hop_port=link_port.get_peer_id())

                # Add static SNAT and DNAT rules on the tenant router.
                props = {OS_FLOATING_IP_RULE_KEY: id}
                tenant_id = router.get_tenant_id()
                chain_names = _nat_chain_names(router.get_id())
                for chain_type, name in chain_names.iteritems():
                    src_ip, target_ip = _get_nat_ips(chain_type, fip)
                    if chain_type == 'pre-routing':
                        nat_type = 'dnat'
                    else:
                        nat_type = 'snat'
                    self.client.add_static_nat(tenant_id, name, src_ip,
                                               target_ip,
                                               link_port.get_id(),
                                               nat_type, **props)

            # disassociate floating IP
            elif floatingip['floatingip']['port_id'] is None:

                fip = super(MidonetPluginV2, self).get_floatingip(context, id)
                router = self.client.get_router(fip["router_id"])
                self.client.remove_static_route(self._get_provider_router(),
                                                fip["floating_ip_address"])

                chain_names = _nat_chain_names(router.get_id())
                for _type, name in chain_names.iteritems():
                    self.client.remove_rules_by_property(
                        router.get_tenant_id(), name, OS_FLOATING_IP_RULE_KEY,
                        id)

                super(MidonetPluginV2, self).update_floatingip(context, id,
                                                               floatingip)

        LOG.debug(_("MidonetPluginV2.update_floating_ip exiting: fip=%s"), fip)
        return fip

    def create_security_group(self, context, security_group, default_sg=False):
        """Create security group.

        Create a new security group, including the default security group.
        In MidoNet, this means creating a pair of chains, inbound and outbound,
        as well as a new port group.
        """
        LOG.debug(_("MidonetPluginV2.create_security_group called: "
                    "security_group=%(security_group)s "
                    "default_sg=%(default_sg)s "),
                  {'security_group': security_group, 'default_sg': default_sg})

        sg = security_group.get('security_group')
        tenant_id = self._get_tenant_id_for_create(context, sg)
        if not default_sg:
            self._ensure_default_security_group(context, tenant_id)

        # Create the Neutron sg first
        sg = super(MidonetPluginV2, self).create_security_group(
            context, security_group, default_sg)

        try:
            # Process the MidoNet side
            self.client.create_port_group(tenant_id,
                                          _sg_port_group_name(sg["id"]))
            chain_names = _sg_chain_names(sg["id"])
            chains = {}
            for direction, chain_name in chain_names.iteritems():
                c = self.client.create_chain(tenant_id, chain_name)
                chains[direction] = c

            # Create all the rules for this SG.  Only accept rules are created
            for r in sg['security_group_rules']:
                self._create_accept_chain_rule(context, r,
                                               chain=chains[r['direction']])
        except Exception:
            LOG.error(_("Failed to create MidoNet resources for sg %(sg)r"),
                      {"sg": sg})
            with excutils.save_and_reraise_exception():
                with context.session.begin(subtransactions=True):
                    sg = self._get_security_group(context, sg["id"])
                    context.session.delete(sg)

        LOG.debug(_("MidonetPluginV2.create_security_group exiting: sg=%r"),
                  sg)
        return sg

    def delete_security_group(self, context, id):
        """Delete chains for Neutron security group."""
        LOG.debug(_("MidonetPluginV2.delete_security_group called: id=%s"), id)

        with context.session.begin(subtransactions=True):
            sg = super(MidonetPluginV2, self).get_security_group(context, id)
            if not sg:
                raise ext_sg.SecurityGroupNotFound(id=id)

            if sg["name"] == 'default' and not context.is_admin:
                raise ext_sg.SecurityGroupCannotRemoveDefault()

            sg_id = sg['id']
            filters = {'security_group_id': [sg_id]}
            if super(MidonetPluginV2, self)._get_port_security_group_bindings(
                    context, filters):
                raise ext_sg.SecurityGroupInUse(id=sg_id)

            # Delete MidoNet Chains and portgroup for the SG
            tenant_id = sg['tenant_id']
            self.client.delete_chains_by_names(
                tenant_id, _sg_chain_names(sg["id"]).values())

            self.client.delete_port_group_by_name(
                tenant_id, _sg_port_group_name(sg["id"]))

            super(MidonetPluginV2, self).delete_security_group(context, id)

    def create_security_group_rule(self, context, security_group_rule):
        """Create a security group rule

        Create a security group rule in the Neutron DB and corresponding
        MidoNet resources in its data store.
        """
        LOG.debug(_("MidonetPluginV2.create_security_group_rule called: "
                    "security_group_rule=%(security_group_rule)r"),
                  {'security_group_rule': security_group_rule})

        with context.session.begin(subtransactions=True):
            rule = super(MidonetPluginV2, self).create_security_group_rule(
                context, security_group_rule)

            self._create_accept_chain_rule(context, rule)

            LOG.debug(_("MidonetPluginV2.create_security_group_rule exiting: "
                        "rule=%r"), rule)
            return rule

    def delete_security_group_rule(self, context, sg_rule_id):
        """Delete a security group rule

        Delete a security group rule from the Neutron DB and corresponding
        MidoNet resources from its data store.
        """
        LOG.debug(_("MidonetPluginV2.delete_security_group_rule called: "
                    "sg_rule_id=%s"), sg_rule_id)
        with context.session.begin(subtransactions=True):
            rule = super(MidonetPluginV2, self).get_security_group_rule(
                context, sg_rule_id)

            if not rule:
                raise ext_sg.SecurityGroupRuleNotFound(id=sg_rule_id)

            sg = self._get_security_group(context,
                                          rule["security_group_id"])
            chain_name = _sg_chain_names(sg["id"])[rule["direction"]]
            self.client.remove_rules_by_property(rule["tenant_id"], chain_name,
                                                 OS_SG_RULE_KEY,
                                                 str(rule["id"]))
            super(MidonetPluginV2, self).delete_security_group_rule(
                context, sg_rule_id)

    def _add_chain_rule(self, chain, action, **kwargs):

        nw_proto = kwargs.get("nw_proto")
        src_addr = kwargs.pop("src_addr", None)
        dst_addr = kwargs.pop("dst_addr", None)
        src_port_from = kwargs.pop("src_port_from", None)
        src_port_to = kwargs.pop("src_port_to", None)
        dst_port_from = kwargs.pop("dst_port_from", None)
        dst_port_to = kwargs.pop("dst_port_to", None)

        # Convert to the keys and values that midonet client understands
        if src_addr:
            kwargs["nw_src_addr"], kwargs["nw_src_length"] = net_util.net_addr(
                src_addr)

        if dst_addr:
            kwargs["nw_dst_addr"], kwargs["nw_dst_length"] = net_util.net_addr(
                dst_addr)

        kwargs["tp_src"] = {"start": src_port_from, "end": src_port_to}

        kwargs["tp_dst"] = {"start": dst_port_from, "end": dst_port_to}

        if nw_proto == 1:  # ICMP
            # Overwrite port fields regardless of the direction
            kwargs["tp_src"] = {"start": src_port_from, "end": src_port_from}
            kwargs["tp_dst"] = {"start": dst_port_to, "end": dst_port_to}

        return self.client.add_chain_rule(chain, action=action, **kwargs)
