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
# @author: Tomoe Sugihara, Midokura Japan KK
# @author: Ryu Ishimoto, Midokura Japan KK


from webob import exc as w_exc

from neutron.common import exceptions as q_exc
from neutron.openstack.common import log as logging


LOG = logging.getLogger(__name__)

PREFIX = 'OS_SG_'
NAME_IDENTIFIABLE_PREFIX_LEN = len(PREFIX) + 36  # 36 = length of uuid
OS_FLOATING_IP_RULE_KEY = 'OS_FLOATING_IP'
OS_ROUTER_IN_CHAIN_NAME_FORMAT = 'OS_ROUTER_IN_%s'
OS_ROUTER_OUT_CHAIN_NAME_FORMAT = 'OS_ROUTER_OUT_%s'
OS_SG_KEY = 'os_sg_rule_id'
OS_TENANT_ROUTER_RULE_KEY = 'OS_TENANT_ROUTER_RULE'
SNAT_RULE = 'SNAT'
SNAT_RULE_PROPERTY = {OS_TENANT_ROUTER_RULE_KEY: SNAT_RULE}
SUFFIX_IN = '_IN'
SUFFIX_OUT = '_OUT'


def sg_label(sg_id, sg_name):
    """Construct the security group ID used as chain identifier in MidoNet."""
    return PREFIX + str(sg_id) + '_' + sg_name


def sg_rule_properties(os_sg_rule_id):
    return {OS_SG_KEY: str(os_sg_rule_id)}

port_group_name = sg_label


def chain_names(sg_id, sg_name):
    """Get inbound and outbound chain names."""
    prefix = sg_label(sg_id, sg_name)
    in_chain_name = prefix + SUFFIX_IN
    out_chain_name = prefix + SUFFIX_OUT
    return {'in': in_chain_name, 'out': out_chain_name}


def router_chain_names(router_id):
    in_name = OS_ROUTER_IN_CHAIN_NAME_FORMAT % router_id
    out_name = OS_ROUTER_OUT_CHAIN_NAME_FORMAT % router_id
    return {'in': in_name, 'out': out_name}


def handle_api_error(fn):
    def wrapped(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except w_exc.HTTPException as ex:
            raise MidonetApiException(msg=ex)
    return wrapped


class MidonetResourceNotFound(q_exc.NotFound):
    message = _('MidoNet %(resource_type)s %(id)s could not be found')


class MidonetApiException(q_exc.NeutronException):
    message = _("MidoNet API error: %(msg)s")


class MidoClient:

    def __init__(self, mido_api):
        self.mido_api = mido_api

    @handle_api_error
    def create_bridge(self, tenant_id, name):
        """Create a new bridge

        :param tenant_id: id of tenant creating the bridge
        :param name: name of the bridge
        :returns: newly created bridge
        """
        LOG.debug(_("MidoClient.create_bridge called: "
                    "tenant_id=%(tenant_id)s, name=%(name)s"),
                  {'tenant_id': tenant_id, 'name': name})
        return self.mido_api.add_bridge().name(name).tenant_id(
            tenant_id).create()

    @handle_api_error
    def delete_bridge(self, id):
        """Delete a bridge

        :param id: id of the bridge
        """
        LOG.debug(_("MidoClient.delete_bridge called: id=%(id)s"), {'id': id})
        return self.mido_api.delete_bridge(id)

    @handle_api_error
    def get_bridge(self, id):
        """Get a bridge

        :param id: id of the bridge
        :returns: requested bridge. None if bridge does not exist.
        """
        LOG.debug(_("MidoClient.get_bridge called: id=%s"), id)
        try:
            return self.mido_api.get_bridge(id)
        except w_exc.HTTPNotFound:
            raise MidonetResourceNotFound(resource_type='Bridge', id=id)

    @handle_api_error
    def update_bridge(self, id, name):
        """Update a bridge of the given id with the new name

        :param id: id of the bridge
        :param name: name of the bridge to set to
        :returns: bridge object
        """
        LOG.debug(_("MidoClient.update_bridge called: "
                    "id=%(id)s, name=%(name)s"), {'id': id, 'name': name})
        try:
            return self.mido_api.get_bridge(id).name(name).update()
        except w_exc.HTTPNotFound:
            raise MidonetResourceNotFound(resource_type='Bridge', id=id)

    @handle_api_error
    def create_dhcp(self, bridge, gateway_ip, net_addr, net_len):
        """Create a new DHCP entry

        :param bridge: bridge object to add dhcp to
        :param gateway_ip: IP address of gateway
        :param net_addr: network IP address
        :param net_len: network IP address length
        :returns: newly created dhcp
        """
        LOG.debug(_("MidoClient.create_dhcp called: bridge=%s(bridge)s, "
                    "net_addr=%(net_addr)s, net_len=%(net_len)s, "
                    "gateway_ip=%(gateway_ip)s"),
                  {'bridge': bridge, 'net_addr': net_addr, 'net_len': net_len,
                   'gateway_ip': gateway_ip})
        return bridge.add_dhcp_subnet().default_gateway(
            gateway_ip).subnet_prefix(net_addr).subnet_length(
                net_len).create()

    @handle_api_error
    def create_dhcp_hosts(self, bridge, ip, mac):
        """Create DHCP host entries

        :param bridge: bridge of the DHCP
        :param ip: IP address
        :param mac: MAC address
        """
        LOG.debug(_("MidoClient.create_dhcp_hosts called: bridge=%s(bridge), "
                    "ip=%(ip)s, mac=%(mac)s"), {'bridge': bridge, 'ip': ip,
                                                'mac': mac})
        dhcp_subnets = bridge.get_dhcp_subnets()
        if dhcp_subnets:
            # Add the host to the first subnet as we currently support one
            # subnet per network.
            dhcp_subnets[0].add_dhcp_host().ip_addr(ip).mac_addr(mac).create()

    @handle_api_error
    def delete_dhcp_hosts(self, bridge_id, ip, mac):
        """Delete DHCP host entries

        :param bridge_id: id of the bridge of the DHCP
        :param ip: IP address
        :param mac: MAC address
        """
        LOG.debug(_("MidoClient.delete_dhcp_hosts called: "
                    "bridge_id=%s(bridge_id), ip=%(ip)s, mac=%(mac)s"),
                  {'bridge_id': bridge_id, 'ip': ip, 'mac': mac})
        bridge = self.get_bridge(bridge_id)
        dhcp_subnets = bridge.get_dhcp_subnets()
        if dhcp_subnets:
            for dh in dhcp_subnets[0].get_dhcp_hosts():
                if dh.get_mac_addr() == mac and dh.get_ip_addr() == ip:
                    dh.delete()

    @handle_api_error
    def delete_dhcp(self, bridge):
        """Delete a DHCP entry

        :param bridge: bridge to remove DHCP from
        """
        LOG.debug(_("MidoClient.delete_dhcp called: bridge=%s(bridge), "),
                  {'bridge': bridge})
        dhcp = bridge.get_dhcp_subnets()
        if not dhcp:
            raise MidonetApiException(msg="Tried to delete non-existent DHCP")
        dhcp[0].delete()

    @handle_api_error
    def delete_port(self, id):
        """Delete a port

        :param id: id of the port
        """
        LOG.debug(_("MidoClient.delete_port called: id=%(id)s"), {'id': id})
        self.mido_api.delete_port(id)

    @handle_api_error
    def get_port(self, id):
        """Get a port

        :param id: id of the port
        :returns: requested port. None if it does not exist
        """
        LOG.debug(_("MidoClient.get_port called: id=%(id)s"), {'id': id})
        try:
            return self.mido_api.get_port(id)
        except w_exc.HTTPNotFound:
            raise MidonetResourceNotFound(resource_type='Port', id=id)

    @handle_api_error
    def create_exterior_bridge_port(self, bridge):
        """Create a new exterior bridge port

        :param bridge: bridge object to add port to
        :returns: newly created port
        """
        LOG.debug(_("MidoClient.create_exterior_bridge_port called: "
                    "bridge=%(bridge)s"), {'bridge': bridge})
        return bridge.add_exterior_port().create()

    @handle_api_error
    def create_interior_bridge_port(self, bridge):
        """Create a new interior bridge port

        :param bridge: bridge object to add port to
        :returns: newly created port
        """
        LOG.debug(_("MidoClient.create_interior_bridge_port called: "
                    "bridge=%(bridge)s"), {'bridge': bridge})
        return bridge.add_interior_port().create()

    @handle_api_error
    def create_router(self, tenant_id, name):
        """Create a new router

        :param tenant_id: id of tenant creating the router
        :param name: name of the router
        :returns: newly created router
        """
        LOG.debug(_("MidoClient.create_router called: "
                    "tenant_id=%(tenant_id)s, name=%(name)s"),
                  {'tenant_id': tenant_id, 'name': name})
        return self.mido_api.add_router().name(name).tenant_id(
            tenant_id).create()

    @handle_api_error
    def create_tenant_router(self, tenant_id, name, metadata_router):
        """Create a new tenant router

        :param tenant_id: id of tenant creating the router
        :param name: name of the router
        :param metadata_router: metadata router
        :returns: newly created router
        """
        LOG.debug(_("MidoClient.create_tenant_router called: "
                    "tenant_id=%(tenant_id)s, name=%(name)s,"
                    " metadata_router=%(metadata_router)s"),
                  {'tenant_id': tenant_id, 'name': name,
                   'metadata_router': metadata_router})
        router = self.create_router(tenant_id, name)
        self.link_router_to_metadata_router(router, metadata_router)
        return router

    @handle_api_error
    def delete_tenant_router(self, id, metadata_router):
        """Delete a tenant router

        :param id: id of router
        :param metadata_router: metadata router
        """
        LOG.debug(_("MidoClient.delete_tenant_router called: "
                    "id=%(id)s, metadata_router=%(metadata_router)s"),
                  {'id': id, 'metadata_router': metadata_router})
        self.unlink_router_from_metadata_router(id, metadata_router)
        self.destroy_router_chains(id)

        # delete the router
        self.delete_router(id)

    @handle_api_error
    def delete_router(self, id):
        """Delete a router

        :param id: id of the router
        """
        LOG.debug(_("MidoClient.delete_router called: id=%(id)s"), {'id': id})
        return self.mido_api.delete_router(id)

    @handle_api_error
    def get_router(self, id):
        """Get a router with the given id

        :param id: id of the router
        :returns: requested router object.  None if it does not exist.
        """
        LOG.debug(_("MidoClient.get_router called: id=%(id)s"), {'id': id})
        try:
            return self.mido_api.get_router(id)
        except w_exc.HTTPNotFound:
            raise MidonetResourceNotFound(resource_type='Router', id=id)

    @handle_api_error
    def update_router(self, id, name):
        """Update a router of the given id with the new name

        :param id: id of the router
        :param name: name of the router to set to
        :returns: router object
        """
        LOG.debug(_("MidoClient.update_router called: "
                    "id=%(id)s, name=%(name)s"), {'id': id, 'name': name})
        try:
            return self.mido_api.get_router(id).name(name).update()
        except w_exc.HTTPNotFound:
            raise MidonetResourceNotFound(resource_type='Router', id=id)

    @handle_api_error
    def link_bridge_port_to_router(self, port_id, router_id, gateway_ip,
                                   net_addr, net_len, metadata_router):
        """Link a tenant bridge port to the router

        :param port_id: port ID
        :param router_id: router id to link to
        :param gateway_ip: IP address of gateway
        :param net_addr: network IP address
        :param net_len: network IP address length
        :param metadata_router: metadata router instance
        """
        LOG.debug(_("MidoClient.link_bridge_port_to_router called: "
                    "port_id=%(port_id)s, router_id=%(router_id)s, "
                    "gateway_ip=%(gateway_ip)s net_addr=%(net_addr)s, "
                    "net_len=%(net_len)s, "
                    "metadata_router=%(metadata_router)s"),
                  {'port_id': port_id, 'router_id': router_id,
                   'gateway_ip': gateway_ip, 'net_addr': net_addr,
                   'net_len': net_len, 'metadata_router': metadata_router})
        router = self.get_router(router_id)

        # create an interior port on the router
        in_port = router.add_interior_port()
        router_port = in_port.port_address(gateway_ip).network_address(
            net_addr).network_length(net_len).create()

        br_port = self.get_port(port_id)
        router_port.link(br_port.get_id())

        # add a route for the subnet in the provider router
        router.add_route().type('Normal').src_network_addr(
            '0.0.0.0').src_network_length(0).dst_network_addr(
                net_addr).dst_network_length(net_len).weight(
                    100).next_hop_port(router_port.get_id()).create()

        # add a route for the subnet in metadata router; forward
        # packets destined to the subnet to the tenant router
        for pp in metadata_router.get_peer_ports():
            if pp.get_device_id() == router.get_id():
                mdr_port_id = pp.get_peer_id()
                break
        else:
            raise Exception(
                _("Couldn't find a md router port for the router=%r"), router)

        metadata_router.add_route().type('Normal').src_network_addr(
            '0.0.0.0').src_network_length(0).dst_network_addr(
                net_addr).dst_network_length(net_len).weight(
                    100).next_hop_port(mdr_port_id).create()

    @handle_api_error
    def unlink_bridge_port_from_router(self, port_id, net_addr, net_len,
                                       metadata_router):
        """Unlink a tenant bridge port from the router

        :param bridge_id: bridge ID
        :param net_addr: network IP address
        :param net_len: network IP address length
        :param metadata_router: metadata router instance
        """
        LOG.debug(_("MidoClient.unlink_bridge_port_from_router called: "
                    "port_id=%(port_id)s, net_addr=%(net_addr)s, "
                    "net_len=%(net_len)s, "
                    "metadata_router=%(metadata_router)s"),
                  {'port_id': port_id, 'net_addr': net_addr,
                   'net_len': net_len, 'metadata_router': metadata_router})
        port = self.get_port(port_id)
        port.unlink()
        self.delete_port(port.get_peer_id())
        self.delete_port(port.get_id())

        # delete the route for the subnet in the metadata router
        for r in metadata_router.get_routes():
            if (r.get_dst_network_addr() == net_addr and
                r.get_dst_network_length() == net_len):
                LOG.debug(_('Deleting route=%r ...'), r)
                self.mido_api.delete_route(r.get_id())
                break

    @handle_api_error
    def link_bridge_to_provider_router(self, bridge, provider_router,
                                       gateway_ip, net_addr, net_len):
        """Link a tenant bridge to the provider router

        :param bridge: tenant bridge
        :param provider_router: provider router to link to
        :param gateway_ip: IP address of gateway
        :param net_addr: network IP address
        :param net_len: network IP address length
        """
        LOG.debug(_("MidoClient.link_bridge_to_provider_router called: "
                    "bridge=%(bridge)s, provider_router=%(provider_router)s, "
                    "gateway_ip=%(gateway_ip)s, net_addr=%(net_addr)s, "
                    "net_len=%(net_len)s"),
                  {'bridge': bridge, 'provider_router': provider_router,
                   'gateway_ip': gateway_ip, 'net_addr': net_addr,
                   'net_len': net_len})
        # create an interior port on the provider router
        in_port = provider_router.add_interior_port()
        pr_port = in_port.port_address(gateway_ip).network_address(
            net_addr).network_length(net_len).create()

        # create an interior bridge port, then link it to the router.
        br_port = bridge.add_interior_port().create()
        pr_port.link(br_port.get_id())

        # add a route for the subnet in the provider router
        provider_router.add_route().type('Normal').src_network_addr(
            '0.0.0.0').src_network_length(0).dst_network_addr(
                net_addr).dst_network_length(net_len).weight(
                    100).next_hop_port(pr_port.get_id()).create()

    @handle_api_error
    def unlink_bridge_from_provider_router(self, bridge, provider_router):
        """Unlink a tenant bridge from the provider router

        :param bridge: tenant bridge
        :param provider_router: provider router to link to
        """
        LOG.debug(_("MidoClient.unlink_bridge_from_provider_router called: "
                    "bridge=%(bridge)s, provider_router=%(provider_router)s"),
                  {'bridge': bridge, 'provider_router': provider_router})
        # Delete routes and unlink the router and the bridge.
        routes = provider_router.get_routes()

        bridge_ports_to_delete = [
            p for p in provider_router.get_peer_ports()
            if p.get_device_id() == bridge.get_id()]

        for p in bridge.get_peer_ports():
            if p.get_device_id() == provider_router.get_id():
                # delete the routes going to the bridge
                for r in routes:
                    if r.get_next_hop_port() == p.get_id():
                        self.mido_api.delete_route(r.get_id())
                p.unlink()
                self.mido_api.delete_port(p.get_id())

        # delete bridge port
        for port in bridge_ports_to_delete:
            self.mido_api.delete_port(port.get_id())

    @handle_api_error
    def set_router_external_gateway(self, id, provider_router, snat_ip):
        """Set router external gateway

        :param ID: ID of the tenant router
        :param provider_router: provider router
        :param snat_ip: SNAT IP address
        """
        LOG.debug(_("MidoClient.set_router_external_gateway called: "
                    "id=%(id)s, provider_router=%(provider_router)s, "
                    "snat_ip=%s(snat_ip)s)"),
                  {'id': id, 'provider_router': provider_router,
                   'snat_ip': snat_ip})
        tenant_router = self.get_router(id)

        # Create a interior port in the provider router
        in_port = provider_router.add_interior_port()
        pr_port = in_port.network_address(
            '169.254.255.0').network_length(30).port_address(
                '169.254.255.1').create()

        # Create a port in the tenant router
        tr_port = tenant_router.add_interior_port().network_address(
            '169.254.255.0').network_length(30).port_address(
                '169.254.255.2').create()

        # Link them
        pr_port.link(tr_port.get_id())

        # Add a route for snat_ip to bring it down to tenant
        provider_router.add_route().type(
            'Normal').src_network_addr('0.0.0.0').src_network_length(
                0).dst_network_addr(snat_ip).dst_network_length(
                    32).weight(100).next_hop_port(
                        pr_port.get_id()).create()

        # Add default route to uplink in the tenant router
        tenant_router.add_route().type('Normal').src_network_addr(
            '0.0.0.0').src_network_length(0).dst_network_addr(
                '0.0.0.0').dst_network_length(0).weight(
                    100).next_hop_port(tr_port.get_id()).create()

        # ADD SNAT(masquerade) rules
        chains = self.get_router_chains(
            tenant_router.get_tenant_id(), tenant_router.get_id())

        chains['in'].add_rule().nw_dst_address(snat_ip).nw_dst_length(
            32).type('rev_snat').flow_action('accept').in_ports(
                [tr_port.get_id()]).properties(
                    SNAT_RULE_PROPERTY).position(1).create()

        nat_targets = []
        nat_targets.append(
            {'addressFrom': snat_ip, 'addressTo': snat_ip,
             'portFrom': 1, 'portTo': 65535})

        chains['out'].add_rule().type('snat').flow_action(
            'accept').nat_targets(nat_targets).out_ports(
                [tr_port.get_id()]).properties(
                    SNAT_RULE_PROPERTY).position(1).create()

    @handle_api_error
    def clear_router_external_gateway(self, id):
        """Clear router external gateway

        :param ID: ID of the tenant router
        """
        LOG.debug(_("MidoClient.clear_router_external_gateway called: "
                    "id=%(id)s"), {'id': id})
        tenant_router = self.get_router(id)

        # delete the port that is connected to provider router
        for p in tenant_router.get_ports():
            if p.get_port_address() == '169.254.255.2':
                peer_port_id = p.get_peer_id()
                p.unlink()
                self.mido_api.delete_port(peer_port_id)
                self.mido_api.delete_port(p.get_id())

        # delete default route
        for r in tenant_router.get_routes():
            if (r.get_dst_network_addr() == '0.0.0.0' and
                    r.get_dst_network_length() == 0):
                self.mido_api.delete_route(r.get_id())

        # delete SNAT(masquerade) rules
        chains = self.get_router_chains(
            tenant_router.get_tenant_id(),
            tenant_router.get_id())

        for r in chains['in'].get_rules():
            if OS_TENANT_ROUTER_RULE_KEY in r.get_properties():
                if r.get_properties()[
                    OS_TENANT_ROUTER_RULE_KEY] == SNAT_RULE:
                    self.mido_api.delete_rule(r.get_id())

        for r in chains['out'].get_rules():
            if OS_TENANT_ROUTER_RULE_KEY in r.get_properties():
                if r.get_properties()[
                    OS_TENANT_ROUTER_RULE_KEY] == SNAT_RULE:
                    self.mido_api.delete_rule(r.get_id())

    @handle_api_error
    def get_router_chains(self, tenant_id, router_id):
        """Get router chains.

        Returns a dictionary that has in/out chain resources key'ed with 'in'
        and 'out' respectively, given the tenant_id and the router_id passed
        in in the arguments.
        """
        LOG.debug(_("MidoClient.get_router_chains called: "
                    "tenant_id=%(tenant_id)s router_id=%(router_id)s"),
                  {'tenant_id': tenant_id, 'router_id': router_id})

        chain_names = router_chain_names(router_id)
        chains = {}
        for c in self.mido_api.get_chains({'tenant_id': tenant_id}):
            if c.get_name() == chain_names['in']:
                chains['in'] = c
            elif c.get_name() == chain_names['out']:
                chains['out'] = c
        return chains

    @handle_api_error
    def create_router_chains(self, router):
        """Create chains for a new router.

        Creates chains for the router and returns the same dictionary as
        get_router_chains() returns.

        :param router: router to set chains for
        """
        LOG.debug(_("MidoClient.create_router_chains called: "
                    "router=%(router)s"), {'router': router})
        chains = {}
        router_id = router.get_id()
        tenant_id = router.get_tenant_id()
        chain_names = router_chain_names(router_id)
        chains['in'] = self.mido_api.add_chain().tenant_id(tenant_id).name(
            chain_names['in']).create()

        chains['out'] = self.mido_api.add_chain().tenant_id(tenant_id).name(
            chain_names['out']).create()

        # set chains to in/out filters
        router.inbound_filter_id(
            chains['in'].get_id()).outbound_filter_id(
                chains['out'].get_id()).update()
        return chains

    @handle_api_error
    def destroy_router_chains(self, id):
        """Deletes chains of a router.

        :param id: router ID to delete chains of
        """
        LOG.debug(_("MidoClient.destroy_router_chains called: "
                    "id=%(id)s"), {'id': id})
        # delete corresponding chains
        router = self.get_router(id)
        chains = self.get_router_chains(router.get_tenant_id(), id)
        self.mido_api.delete_chain(chains['in'].get_id())
        self.mido_api.delete_chain(chains['out'].get_id())

    @handle_api_error
    def link_router_to_metadata_router(self, router, metadata_router):
        """Link a router to the metadata router

        :param router: router to link
        :param metadata_router: metadata router
        """
        LOG.debug(_("MidoClient.link_router_to_metadata_router called: "
                    "router=%(router)s, metadata_router=%(metadata_router)s"),
                  {'router': router, 'metadata_router': metadata_router})
        # link to metadata router
        in_port = metadata_router.add_interior_port()
        mdr_port = in_port.network_address('169.254.255.0').network_length(
            30).port_address('169.254.255.1').create()

        tr_port = router.add_interior_port().network_address(
            '169.254.255.0').network_length(30).port_address(
                '169.254.255.2').create()
        mdr_port.link(tr_port.get_id())

        # forward metadata traffic to metadata router
        router.add_route().type('Normal').src_network_addr(
            '0.0.0.0').src_network_length(0).dst_network_addr(
                '169.254.169.254').dst_network_length(32).weight(
                    100).next_hop_port(tr_port.get_id()).create()

    @handle_api_error
    def unlink_router_from_metadata_router(self, id, metadata_router):
        """Unlink a router from the metadata router

        :param id: ID of router
        :param metadata_router: metadata router
        """
        LOG.debug(_("MidoClient.unlink_router_from_metadata_router called: "
                    "id=%(id)s, metadata_router=%(metadata_router)s"),
                  {'id': id, 'metadata_router': metadata_router})
        # unlink from metadata router and delete the interior ports
        # that connect metadata router and this router.
        for pp in metadata_router.get_peer_ports():
            if pp.get_device_id() == id:
                mdr_port = self.get_port(pp.get_peer_id())
                pp.unlink()
                self.mido_api.delete_port(pp.get_id())
                self.mido_api.delete_port(mdr_port.get_id())

    @handle_api_error
    def setup_floating_ip(self, router_id, provider_router, floating_ip,
                          fixed_ip, identifier):
        """Setup MidoNet for floating IP

        :param router_id: router_id
        :param provider_router: provider router
        :param floating_ip: floating IP address
        :param fixed_ip: fixed IP address
        :param identifier: identifier to use to map to MidoNet
        """
        LOG.debug(_("MidoClient.setup_floating_ip called: "
                    "router_id=%(router_id)s, "
                    "provider_router=%(provider_router)s"
                    "floating_ip=%(floating_ip)s, fixed_ip=%(fixed_ip)s"
                    "identifier=%(identifier)s"),
                  {'router_id': router_id, 'provider_router': provider_router,
                   'floating_ip': floating_ip, 'fixed_ip': fixed_ip,
                   'identifier': identifier})
        # unlink from metadata router and delete the interior ports
        router = self.mido_api.get_router(router_id)
        # find the provider router port that is connected to the tenant
        # of the floating ip
        for p in router.get_peer_ports():
            if p.get_device_id() == provider_router.get_id():
                pr_port = p

        # get the tenant router port id connected to provider router
        tr_port_id = pr_port.get_peer_id()

        # add a route for the floating ip to bring it to the tenant
        provider_router.add_route().type(
            'Normal').src_network_addr('0.0.0.0').src_network_length(
                0).dst_network_addr(
                    floating_ip).dst_network_length(
                        32).weight(100).next_hop_port(
                            pr_port.get_id()).create()

        chains = self.get_router_chains(router.get_tenant_id(), router_id)

        # add dnat/snat rule pair for the floating ip
        nat_targets = []
        nat_targets.append(
            {'addressFrom': fixed_ip, 'addressTo': fixed_ip,
             'portFrom': 0, 'portTo': 0})

        floating_property = {OS_FLOATING_IP_RULE_KEY: identifier}
        chains['in'].add_rule().nw_dst_address(
            floating_ip).nw_dst_length(32).type(
                'dnat').flow_action('accept').nat_targets(
                    nat_targets).in_ports([tr_port_id]).position(
                        1).properties(floating_property).create()

        nat_targets = []
        nat_targets.append(
            {'addressFrom': floating_ip, 'addressTo': floating_ip,
             'portFrom': 0, 'portTo': 0})

        chains['out'].add_rule().nw_src_address(
            fixed_ip).nw_src_length(32).type(
                'snat').flow_action('accept').nat_targets(
                    nat_targets).out_ports(
                        [tr_port_id]).position(1).properties(
                            floating_property).create()

    @handle_api_error
    def clear_floating_ip(self, router_id, provider_router, floating_ip,
                          identifier):
        """Remove floating IP

        :param router_id: router_id
        :param provider_router: provider router
        :param floating_ip: floating IP address
        :param identifier: identifier to use to map to MidoNet
        """
        LOG.debug(_("MidoClient.clear_floating_ip called: "
                    "router_id=%(router_id)s, "
                    "provider_router=%(provider_router)s"
                    "floating_ip=%(floating_ip)s, identifier=%(identifier)s"),
                  {'router_id': router_id, 'provider_router': provider_router,
                   'floating_ip': floating_ip, 'identifier': identifier})
        router = self.mido_api.get_router(router_id)

        # find the provider router port that is connected to the tenant
        # delete the route for this floating ip
        for r in provider_router.get_routes():
            if (r.get_dst_network_addr() == floating_ip and
                    r.get_dst_network_length() == 32):
                self.mido_api.delete_route(r.get_id())

        # delete snat/dnat rule pair for this floating ip
        chains = self.get_router_chains(router.get_tenant_id(), router_id)

        for r in chains['in'].get_rules():
            if OS_FLOATING_IP_RULE_KEY in r.get_properties():
                if r.get_properties()[OS_FLOATING_IP_RULE_KEY] == identifier:
                    LOG.debug(_('deleting rule=%r'), r)
                    self.mido_api.delete_rule(r.get_id())
                    break

        for r in chains['out'].get_rules():
            if OS_FLOATING_IP_RULE_KEY in r.get_properties():
                if r.get_properties()[OS_FLOATING_IP_RULE_KEY] == identifier:
                    LOG.debug(_('deleting rule=%r'), r)
                    self.mido_api.delete_rule(r.get_id())
                    break

    @handle_api_error
    def create_for_sg(self, tenant_id, sg_id, sg_name):
        """Create a new chain for security group.

        Creating a security group creates a pair of chains in MidoNet, one for
        inbound and the other for outbound.
        """
        LOG.debug(_("MidoClient.create_for_sg called: "
                    "tenant_id=%(tenant_id)s sg_id=%(sg_id)s "
                    "sg_name=%(sg_name)s "),
                  {'tenant_id': tenant_id, 'sg_id': sg_id, 'sg_name': sg_name})

        cnames = chain_names(sg_id, sg_name)
        self.mido_api.add_chain().tenant_id(tenant_id).name(
            cnames['in']).create()
        self.mido_api.add_chain().tenant_id(tenant_id).name(
            cnames['out']).create()

        pg_name = port_group_name(sg_id, sg_name)
        self.mido_api.add_port_group().tenant_id(tenant_id).name(
            pg_name).create()

    @handle_api_error
    def delete_for_sg(self, tenant_id, sg_id, sg_name):
        """Delete a chain mapped to a security group.

        Delete a SG means deleting all the chains (inbound and outbound)
        associated with the SG in MidoNet.
        """
        LOG.debug(_("MidoClient.delete_for_sg called: "
                    "tenant_id=%(tenant_id)s sg_id=%(sg_id)s "
                    "sg_name=%(sg_name)s "),
                  {'tenant_id': tenant_id, 'sg_id': sg_id, 'sg_name': sg_name})

        cnames = chain_names(sg_id, sg_name)
        chains = self.mido_api.get_chains({'tenant_id': tenant_id})
        for c in chains:
            if c.get_name() == cnames['in'] or c.get_name() == cnames['out']:
                LOG.debug(_('MidoClient.delete_for_sg: deleting chain=%r'),
                          c.get_id())
                self.mido_api.delete_chain(c.get_id())

        pg_name = port_group_name(sg_id, sg_name)
        pgs = self.mido_api.get_port_groups({'tenant_id': tenant_id})
        for pg in pgs:
            if pg.get_name() == pg_name:
                LOG.debug(_("MidoClient.delete_for_sg: deleting pg=%r"),
                          pg)
                self.mido_api.delete_port_group(pg.get_id())

    @handle_api_error
    def get_sg_chains(self, tenant_id, sg_id):
        """Get a list of chains mapped to a security group."""
        LOG.debug(_("MidoClient.get_sg_chains called: "
                    "tenant_id=%(tenant_id)s sg_id=%(sg_id)s"),
                  {'tenant_id': tenant_id, 'sg_id': sg_id})

        cnames = chain_names(sg_id, sg_name='')
        chain_name_prefix_for_id = cnames['in'][:NAME_IDENTIFIABLE_PREFIX_LEN]
        chains = {}

        for c in self.mido_api.get_chains({'tenant_id': tenant_id}):
            if c.get_name().startswith(chain_name_prefix_for_id):
                if c.get_name().endswith(SUFFIX_IN):
                    chains['in'] = c
                if c.get_name().endswith(SUFFIX_OUT):
                    chains['out'] = c
        assert 'in' in chains
        assert 'out' in chains
        return chains

    @handle_api_error
    def get_port_groups_for_sg(self, tenant_id, sg_id):
        LOG.debug(_("MidoClient.get_port_groups_for_sg called: "
                    "tenant_id=%(tenant_id)s sg_id=%(sg_id)s"),
                  {'tenant_id': tenant_id, 'sg_id': sg_id})

        pg_name_prefix = port_group_name(
            sg_id, sg_name='')[:NAME_IDENTIFIABLE_PREFIX_LEN]
        port_groups = self.mido_api.get_port_groups({'tenant_id': tenant_id})
        for pg in port_groups:
            if pg.get_name().startswith(pg_name_prefix):
                LOG.debug(_(
                    "MidoClient.get_port_groups_for_sg exiting: pg=%r"), pg)
                return pg
        return None

    @handle_api_error
    def create_for_sg_rule(self, rule):
        LOG.debug(_("MidoClient.create_for_sg_rule called: rule=%r"), rule)

        direction = rule['direction']
        protocol = rule['protocol']
        port_range_max = rule['port_range_max']
        rule_id = rule['id']
        security_group_id = rule['security_group_id']
        remote_group_id = rule['remote_group_id']
        remote_ip_prefix = rule['remote_ip_prefix']  # watch out. not validated
        tenant_id = rule['tenant_id']
        port_range_min = rule['port_range_min']

        # construct a corresponding rule
        tp_src_start = tp_src_end = None
        tp_dst_start = tp_dst_end = None
        nw_src_address = None
        nw_src_length = None
        port_group_id = None

        # handle source
        if remote_ip_prefix is not None:
            nw_src_address, nw_src_length = remote_ip_prefix.split('/')
        elif not remote_group_id is None:  # security group as a srouce
            source_pg = self.pg_manager.get_for_sg(tenant_id, remote_group_id)
            port_group_id = source_pg.get_id()
        else:
            raise Exception(_("Don't know what to do with rule=%r"), rule)

        # dst ports
        tp_dst_start, tp_dst_end = port_range_min, port_range_max

        # protocol
        if protocol == 'tcp':
            nw_proto = 6
        elif protocol == 'udp':
            nw_proto = 17
        elif protocol == 'icmp':
            nw_proto = 1
            # extract type and code from reporposed fields
            icmp_type = rule['from_port']
            icmp_code = rule['to_port']

            # translate -1(wildcard in OS) to midonet wildcard
            if icmp_type == -1:
                icmp_type = None
            if icmp_code == -1:
                icmp_code = None

            # set data for midonet rule
            tp_src_start = tp_src_end = icmp_type
            tp_dst_start = tp_dst_end = icmp_code

        chains = self.get_sg_chains(tenant_id, security_group_id)
        chain = None
        if direction == 'egress':
            chain = chains['in']
        elif direction == 'ingress':
            chain = chains['out']
        else:
            raise Exception(_("Don't know what to do with rule=%r"), rule)

        # create an accept rule
        properties = sg_rule_properties(rule_id)
        LOG.debug(_("MidoClient.create_for_sg_rule: adding accept rule "
                    "%(rule_id)s in portgroup %(port_group_id)s"),
                  {'rule_id': rule_id, 'port_group_id': port_group_id})
        chain.add_rule().port_group(port_group_id).type('accept').nw_proto(
            nw_proto).nw_src_address(nw_src_address).nw_src_length(
                nw_src_length).tp_src_start(tp_src_start).tp_src_end(
                    tp_src_end).tp_dst_start(tp_dst_start).tp_dst_end(
                        tp_dst_end).properties(properties).create()

    @handle_api_error
    def delete_for_sg_rule(self, rule):
        LOG.debug(_("MidoClient.delete_for_sg_rule called: rule=%r"), rule)

        tenant_id = rule['tenant_id']
        security_group_id = rule['security_group_id']
        rule_id = rule['id']

        properties = sg_rule_properties(rule_id)
        # search for the chains to find the rule to delete
        chains = self.get_sg_chains(tenant_id, security_group_id)
        for c in chains['in'], chains['out']:
            rules = c.get_rules()
            for r in rules:
                if r.get_properties() == properties:
                    LOG.debug(_("MidoClient.delete_for_sg_rule: deleting "
                                "rule %r"), r)
                    self.mido_api.delete_rule(r.get_id())
