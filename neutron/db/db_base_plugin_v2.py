# Copyright (c) 2012 OpenStack Foundation.
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

import netaddr
from oslo_config import cfg
from oslo_db import api as oslo_db_api
from oslo_db import exception as db_exc
from oslo_log import log as logging
from oslo_utils import excutils
from sqlalchemy import and_
from sqlalchemy import event
from sqlalchemy import orm
from sqlalchemy.orm import exc

from neutron.api.v2 import attributes
from neutron.common import constants
from neutron.common import exceptions as n_exc
from neutron.common import ipv6_utils
from neutron.common import utils
from neutron import context as ctx
from neutron.db import api as db_api
from neutron.db import common_db_mixin
from neutron.db import models_v2
from neutron.db import sqlalchemyutils
from neutron.extensions import l3
from neutron.i18n import _LE, _LI
from neutron import ipam
from neutron.ipam import subnet_alloc
from neutron import manager
from neutron import neutron_plugin_base_v2
from neutron.openstack.common import uuidutils
from neutron.plugins.common import constants as service_constants


LOG = logging.getLogger(__name__)

# Ports with the following 'device_owner' values will not prevent
# network deletion.  If delete_network() finds that all ports on a
# network have these owners, it will explicitly delete each port
# and allow network deletion to continue.  Similarly, if delete_subnet()
# finds out that all existing IP Allocations are associated with ports
# with these owners, it will allow subnet deletion to proceed with the
# IP allocations being cleaned up by cascade.
AUTO_DELETE_PORT_OWNERS = [constants.DEVICE_OWNER_DHCP]


class NeutronDbPluginV2(neutron_plugin_base_v2.NeutronPluginBaseV2,
                        common_db_mixin.CommonDbMixin):
    """V2 Neutron plugin interface implementation using SQLAlchemy models.

    Whenever a non-read call happens the plugin will call an event handler
    class method (e.g., network_created()).  The result is that this class
    can be sub-classed by other classes that add custom behaviors on certain
    events.
    """

    # This attribute specifies whether the plugin supports or not
    # bulk/pagination/sorting operations. Name mangling is used in
    # order to ensure it is qualified by class
    __native_bulk_support = True
    __native_pagination_support = True
    __native_sorting_support = True

    def __init__(self):
        if cfg.CONF.notify_nova_on_port_status_changes:
            from neutron.notifiers import nova
            # NOTE(arosen) These event listeners are here to hook into when
            # port status changes and notify nova about their change.
            self.nova_notifier = nova.Notifier()
            event.listen(models_v2.Port, 'after_insert',
                         self.nova_notifier.send_port_status)
            event.listen(models_v2.Port, 'after_update',
                         self.nova_notifier.send_port_status)
            event.listen(models_v2.Port.status, 'set',
                         self.nova_notifier.record_port_status_changed)

    def _get_network(self, context, id):
        try:
            network = self._get_by_id(context, models_v2.Network, id)
        except exc.NoResultFound:
            raise n_exc.NetworkNotFound(net_id=id)
        return network

    def _get_subnet(self, context, id):
        try:
            subnet = self._get_by_id(context, models_v2.Subnet, id)
        except exc.NoResultFound:
            raise n_exc.SubnetNotFound(subnet_id=id)
        return subnet

    def _get_subnetpool(self, context, id):
        try:
            return self._get_by_id(context, models_v2.SubnetPool, id)
        except exc.NoResultFound:
            raise n_exc.SubnetPoolNotFound(subnetpool_id=id)

    def _get_all_subnetpools(self, context):
        # NOTE(tidwellr): see note in _get_all_subnets()
        return context.session.query(models_v2.SubnetPool).all()

    def _get_port(self, context, id):
        try:
            port = self._get_by_id(context, models_v2.Port, id)
        except exc.NoResultFound:
            raise n_exc.PortNotFound(port_id=id)
        return port

    def _get_dns_by_subnet(self, context, subnet_id):
        dns_qry = context.session.query(models_v2.DNSNameServer)
        return dns_qry.filter_by(subnet_id=subnet_id).all()

    def _get_route_by_subnet(self, context, subnet_id):
        route_qry = context.session.query(models_v2.SubnetRoute)
        return route_qry.filter_by(subnet_id=subnet_id).all()

    def _get_router_gw_ports_by_network(self, context, network_id):
        port_qry = context.session.query(models_v2.Port)
        return port_qry.filter_by(network_id=network_id,
                device_owner=constants.DEVICE_OWNER_ROUTER_GW).all()

    def _get_subnets_by_network(self, context, network_id):
        subnet_qry = context.session.query(models_v2.Subnet)
        return subnet_qry.filter_by(network_id=network_id).all()

    def _get_subnets_by_subnetpool(self, context, subnetpool_id):
        subnet_qry = context.session.query(models_v2.Subnet)
        return subnet_qry.filter_by(subnetpool_id=subnetpool_id).all()

    def _get_all_subnets(self, context):
        # NOTE(salvatore-orlando): This query might end up putting
        # a lot of stress on the db. Consider adding a cache layer
        return context.session.query(models_v2.Subnet).all()

    @staticmethod
    def _generate_mac():
        return utils.get_random_mac(cfg.CONF.base_mac.split(':'))

    @staticmethod
    def _delete_ip_allocation(context, network_id, subnet_id, ip_address):

        # Delete the IP address from the IPAllocate table
        LOG.debug("Delete allocated IP %(ip_address)s "
                  "(%(network_id)s/%(subnet_id)s)",
                  {'ip_address': ip_address,
                   'network_id': network_id,
                   'subnet_id': subnet_id})
        context.session.query(models_v2.IPAllocation).filter_by(
            network_id=network_id,
            ip_address=ip_address,
            subnet_id=subnet_id).delete()

    @staticmethod
    def _store_ip_allocation(context, ip_address, network_id, subnet_id,
                             port_id):
        LOG.debug("Allocated IP %(ip_address)s "
                  "(%(network_id)s/%(subnet_id)s/%(port_id)s)",
                  {'ip_address': ip_address,
                   'network_id': network_id,
                   'subnet_id': subnet_id,
                   'port_id': port_id})
        allocated = models_v2.IPAllocation(
            network_id=network_id,
            port_id=port_id,
            ip_address=ip_address,
            subnet_id=subnet_id
        )
        context.session.add(allocated)

    @staticmethod
    def _generate_ip(context, subnets):
        try:
            return NeutronDbPluginV2._try_generate_ip(context, subnets)
        except n_exc.IpAddressGenerationFailure:
            NeutronDbPluginV2._rebuild_availability_ranges(context, subnets)

        return NeutronDbPluginV2._try_generate_ip(context, subnets)

    @staticmethod
    def _try_generate_ip(context, subnets):
        """Generate an IP address.

        The IP address will be generated from one of the subnets defined on
        the network.
        """
        range_qry = context.session.query(
            models_v2.IPAvailabilityRange).join(
                models_v2.IPAllocationPool).with_lockmode('update')
        for subnet in subnets:
            ip_range = range_qry.filter_by(subnet_id=subnet['id']).first()
            if not ip_range:
                LOG.debug("All IPs from subnet %(subnet_id)s (%(cidr)s) "
                          "allocated",
                          {'subnet_id': subnet['id'],
                           'cidr': subnet['cidr']})
                continue
            ip_address = ip_range['first_ip']
            if ip_range['first_ip'] == ip_range['last_ip']:
                # No more free indices on subnet => delete
                LOG.debug("No more free IP's in slice. Deleting "
                          "allocation pool.")
                context.session.delete(ip_range)
            else:
                # increment the first free
                new_first_ip = str(netaddr.IPAddress(ip_address) + 1)
                ip_range['first_ip'] = new_first_ip
            LOG.debug("Allocated IP - %(ip_address)s from %(first_ip)s "
                      "to %(last_ip)s",
                      {'ip_address': ip_address,
                       'first_ip': ip_address,
                       'last_ip': ip_range['last_ip']})
            return {'ip_address': ip_address,
                    'subnet_id': subnet['id']}
        raise n_exc.IpAddressGenerationFailure(net_id=subnets[0]['network_id'])

    @staticmethod
    def _rebuild_availability_ranges(context, subnets):
        """Rebuild availability ranges.

        This method is called only when there's no more IP available or by
        _update_subnet_allocation_pools. Calling
        _update_subnet_allocation_pools before calling this function deletes
        the IPAllocationPools associated with the subnet that is updating,
        which will result in deleting the IPAvailabilityRange too.
        """
        ip_qry = context.session.query(
            models_v2.IPAllocation).with_lockmode('update')
        # PostgreSQL does not support select...for update with an outer join.
        # No join is needed here.
        pool_qry = context.session.query(
            models_v2.IPAllocationPool).options(
                orm.noload('available_ranges')).with_lockmode('update')
        for subnet in sorted(subnets):
            LOG.debug("Rebuilding availability ranges for subnet %s",
                      subnet)

            # Create a set of all currently allocated addresses
            ip_qry_results = ip_qry.filter_by(subnet_id=subnet['id'])
            allocations = netaddr.IPSet([netaddr.IPAddress(i['ip_address'])
                                        for i in ip_qry_results])

            for pool in pool_qry.filter_by(subnet_id=subnet['id']):
                # Create a set of all addresses in the pool
                poolset = netaddr.IPSet(netaddr.IPRange(pool['first_ip'],
                                                        pool['last_ip']))

                # Use set difference to find free addresses in the pool
                available = poolset - allocations

                # Generator compacts an ip set into contiguous ranges
                def ipset_to_ranges(ipset):
                    first, last = None, None
                    for cidr in ipset.iter_cidrs():
                        if last and last + 1 != cidr.first:
                            yield netaddr.IPRange(first, last)
                            first = None
                        first, last = first if first else cidr.first, cidr.last
                    if first:
                        yield netaddr.IPRange(first, last)

                # Write the ranges to the db
                for ip_range in ipset_to_ranges(available):
                    available_range = models_v2.IPAvailabilityRange(
                        allocation_pool_id=pool['id'],
                        first_ip=str(netaddr.IPAddress(ip_range.first)),
                        last_ip=str(netaddr.IPAddress(ip_range.last)))
                    context.session.add(available_range)

    @staticmethod
    def _allocate_specific_ip(context, subnet_id, ip_address):
        """Allocate a specific IP address on the subnet."""
        ip = int(netaddr.IPAddress(ip_address))
        range_qry = context.session.query(
            models_v2.IPAvailabilityRange).join(
                models_v2.IPAllocationPool).with_lockmode('update')
        results = range_qry.filter_by(subnet_id=subnet_id)
        for ip_range in results:
            first = int(netaddr.IPAddress(ip_range['first_ip']))
            last = int(netaddr.IPAddress(ip_range['last_ip']))
            if first <= ip <= last:
                if first == last:
                    context.session.delete(ip_range)
                    return
                elif first == ip:
                    new_first_ip = str(netaddr.IPAddress(ip_address) + 1)
                    ip_range['first_ip'] = new_first_ip
                    return
                elif last == ip:
                    new_last_ip = str(netaddr.IPAddress(ip_address) - 1)
                    ip_range['last_ip'] = new_last_ip
                    return
                else:
                    # Adjust the original range to end before ip_address
                    old_last_ip = ip_range['last_ip']
                    new_last_ip = str(netaddr.IPAddress(ip_address) - 1)
                    ip_range['last_ip'] = new_last_ip

                    # Create a new second range for after ip_address
                    new_first_ip = str(netaddr.IPAddress(ip_address) + 1)
                    new_ip_range = models_v2.IPAvailabilityRange(
                        allocation_pool_id=ip_range['allocation_pool_id'],
                        first_ip=new_first_ip,
                        last_ip=old_last_ip)
                    context.session.add(new_ip_range)
                    return

    @staticmethod
    def _check_unique_ip(context, network_id, subnet_id, ip_address):
        """Validate that the IP address on the subnet is not in use."""
        ip_qry = context.session.query(models_v2.IPAllocation)
        try:
            ip_qry.filter_by(network_id=network_id,
                             subnet_id=subnet_id,
                             ip_address=ip_address).one()
        except exc.NoResultFound:
            return True
        return False

    @classmethod
    def _check_gateway_in_subnet(cls, cidr, gateway):
        """Validate that the gateway is on the subnet."""
        ip = netaddr.IPAddress(gateway)
        if ip.version == 4 or (ip.version == 6 and not ip.is_link_local()):
            return cls._check_subnet_ip(cidr, gateway)
        return True

    @classmethod
    def _check_subnet_ip(cls, cidr, ip_address):
        """Validate that the IP address is on the subnet."""
        ip = netaddr.IPAddress(ip_address)
        net = netaddr.IPNetwork(cidr)
        # Check that the IP is valid on subnet. This cannot be the
        # network or the broadcast address
        if (ip != net.network and
                ip != net[-1] and
                net.netmask & ip == net.network):
            return True
        return False

    @staticmethod
    def _check_ip_in_allocation_pool(context, subnet_id, gateway_ip,
                                     ip_address):
        """Validate IP in allocation pool.

        Validates that the IP address is either the default gateway or
        in the allocation pools of the subnet.
        """
        # Check if the IP is the gateway
        if ip_address == gateway_ip:
            # Gateway is not in allocation pool
            return False

        # Check if the requested IP is in a defined allocation pool
        pool_qry = context.session.query(models_v2.IPAllocationPool)
        allocation_pools = pool_qry.filter_by(subnet_id=subnet_id)
        ip = netaddr.IPAddress(ip_address)
        for allocation_pool in allocation_pools:
            allocation_pool_range = netaddr.IPRange(
                allocation_pool['first_ip'],
                allocation_pool['last_ip'])
            if ip in allocation_pool_range:
                return True
        return False

    def _test_fixed_ips_for_port(self, context, network_id, fixed_ips,
                                 device_owner):
        """Test fixed IPs for port.

        Check that configured subnets are valid prior to allocating any
        IPs. Include the subnet_id in the result if only an IP address is
        configured.

        :raises: InvalidInput, IpAddressInUse, InvalidIpForNetwork,
                 InvalidIpForSubnet
        """
        fixed_ip_set = []
        for fixed in fixed_ips:
            found = False
            if 'subnet_id' not in fixed:
                if 'ip_address' not in fixed:
                    msg = _('IP allocation requires subnet_id or ip_address')
                    raise n_exc.InvalidInput(error_message=msg)

                filter = {'network_id': [network_id]}
                subnets = self.get_subnets(context, filters=filter)
                for subnet in subnets:
                    if self._check_subnet_ip(subnet['cidr'],
                                             fixed['ip_address']):
                        found = True
                        subnet_id = subnet['id']
                        break
                if not found:
                    raise n_exc.InvalidIpForNetwork(
                        ip_address=fixed['ip_address'])
            else:
                subnet = self._get_subnet(context, fixed['subnet_id'])
                if subnet['network_id'] != network_id:
                    msg = (_("Failed to create port on network %(network_id)s"
                             ", because fixed_ips included invalid subnet "
                             "%(subnet_id)s") %
                           {'network_id': network_id,
                            'subnet_id': fixed['subnet_id']})
                    raise n_exc.InvalidInput(error_message=msg)
                subnet_id = subnet['id']

            is_auto_addr_subnet = ipv6_utils.is_auto_address_subnet(subnet)
            if 'ip_address' in fixed:
                # Ensure that the IP's are unique
                if not NeutronDbPluginV2._check_unique_ip(context, network_id,
                                                          subnet_id,
                                                          fixed['ip_address']):
                    raise n_exc.IpAddressInUse(net_id=network_id,
                                               ip_address=fixed['ip_address'])

                # Ensure that the IP is valid on the subnet
                if (not found and
                    not self._check_subnet_ip(subnet['cidr'],
                                              fixed['ip_address'])):
                    raise n_exc.InvalidIpForSubnet(
                        ip_address=fixed['ip_address'])
                if (is_auto_addr_subnet and
                    device_owner not in
                        constants.ROUTER_INTERFACE_OWNERS):
                    msg = (_("IPv6 address %(address)s can not be directly "
                            "assigned to a port on subnet %(id)s since the "
                            "subnet is configured for automatic addresses") %
                           {'address': fixed['ip_address'],
                            'id': subnet_id})
                    raise n_exc.InvalidInput(error_message=msg)
                fixed_ip_set.append({'subnet_id': subnet_id,
                                     'ip_address': fixed['ip_address']})
            else:
                # A scan for auto-address subnets on the network is done
                # separately so that all such subnets (not just those
                # listed explicitly here by subnet ID) are associated
                # with the port.
                if (device_owner in constants.ROUTER_INTERFACE_OWNERS or
                    device_owner == constants.DEVICE_OWNER_ROUTER_SNAT or
                    not is_auto_addr_subnet):
                    fixed_ip_set.append({'subnet_id': subnet_id})

        if len(fixed_ip_set) > cfg.CONF.max_fixed_ips_per_port:
            msg = _('Exceeded maximim amount of fixed ips per port')
            raise n_exc.InvalidInput(error_message=msg)
        return fixed_ip_set

    def _allocate_fixed_ips(self, context, fixed_ips, mac_address):
        """Allocate IP addresses according to the configured fixed_ips."""
        ips = []

        # we need to start with entries that asked for a specific IP in case
        # those IPs happen to be next in the line for allocation for ones that
        # didn't ask for a specific IP
        fixed_ips.sort(key=lambda x: 'ip_address' not in x)
        for fixed in fixed_ips:
            subnet = self._get_subnet(context, fixed['subnet_id'])
            is_auto_addr = ipv6_utils.is_auto_address_subnet(subnet)
            if 'ip_address' in fixed:
                if not is_auto_addr:
                    # Remove the IP address from the allocation pool
                    NeutronDbPluginV2._allocate_specific_ip(
                        context, fixed['subnet_id'], fixed['ip_address'])
                ips.append({'ip_address': fixed['ip_address'],
                            'subnet_id': fixed['subnet_id']})
            # Only subnet ID is specified => need to generate IP
            # from subnet
            else:
                if is_auto_addr:
                    ip_address = self._calculate_ipv6_eui64_addr(context,
                                                                 subnet,
                                                                 mac_address)
                    ips.append({'ip_address': ip_address.format(),
                                'subnet_id': subnet['id']})
                else:
                    subnets = [subnet]
                    # IP address allocation
                    result = self._generate_ip(context, subnets)
                    ips.append({'ip_address': result['ip_address'],
                                'subnet_id': result['subnet_id']})
        return ips

    def _update_ips_for_port(self, context, network_id, port_id, original_ips,
                             new_ips, mac_address, device_owner):
        """Add or remove IPs from the port."""
        ips = []
        # These ips are still on the port and haven't been removed
        prev_ips = []

        # the new_ips contain all of the fixed_ips that are to be updated
        if len(new_ips) > cfg.CONF.max_fixed_ips_per_port:
            msg = _('Exceeded maximim amount of fixed ips per port')
            raise n_exc.InvalidInput(error_message=msg)

        # Remove all of the intersecting elements
        for original_ip in original_ips[:]:
            for new_ip in new_ips[:]:
                if ('ip_address' in new_ip and
                    original_ip['ip_address'] == new_ip['ip_address']):
                    original_ips.remove(original_ip)
                    new_ips.remove(new_ip)
                    prev_ips.append(original_ip)
                    break
            else:
                # For ports that are not router ports, retain any automatic
                # (non-optional, e.g. IPv6 SLAAC) addresses.
                if device_owner not in constants.ROUTER_INTERFACE_OWNERS:
                    subnet = self._get_subnet(context,
                                              original_ip['subnet_id'])
                    if (ipv6_utils.is_auto_address_subnet(subnet)):
                        original_ips.remove(original_ip)
                        prev_ips.append(original_ip)

        # Check if the IP's to add are OK
        to_add = self._test_fixed_ips_for_port(context, network_id, new_ips,
                                               device_owner)
        for ip in original_ips:
            LOG.debug("Port update. Hold %s", ip)
            NeutronDbPluginV2._delete_ip_allocation(context,
                                                    network_id,
                                                    ip['subnet_id'],
                                                    ip['ip_address'])

        if to_add:
            LOG.debug("Port update. Adding %s", to_add)
            ips = self._allocate_fixed_ips(context, to_add, mac_address)
        return ips, prev_ips

    def _calculate_ipv6_eui64_addr(self, context, subnet, mac_addr):
        prefix = subnet['cidr']
        network_id = subnet['network_id']
        ip_address = ipv6_utils.get_ipv6_addr_by_EUI64(
            prefix, mac_addr).format()
        if not self._check_unique_ip(context, network_id,
                                     subnet['id'], ip_address):
            raise n_exc.IpAddressInUse(net_id=network_id,
                                       ip_address=ip_address)
        return ip_address

    def _allocate_ips_for_port(self, context, port):
        """Allocate IP addresses for the port.

        If port['fixed_ips'] is set to 'ATTR_NOT_SPECIFIED', allocate IP
        addresses for the port. If port['fixed_ips'] contains an IP address or
        a subnet_id then allocate an IP address accordingly.
        """
        p = port['port']
        ips = []
        v6_stateless = []
        net_id_filter = {'network_id': [p['network_id']]}
        subnets = self.get_subnets(context, filters=net_id_filter)
        is_router_port = (
            p['device_owner'] in constants.ROUTER_INTERFACE_OWNERS or
            p['device_owner'] == constants.DEVICE_OWNER_ROUTER_SNAT)

        fixed_configured = p['fixed_ips'] is not attributes.ATTR_NOT_SPECIFIED
        if fixed_configured:
            configured_ips = self._test_fixed_ips_for_port(context,
                                                           p["network_id"],
                                                           p['fixed_ips'],
                                                           p['device_owner'])
            ips = self._allocate_fixed_ips(context,
                                           configured_ips,
                                           p['mac_address'])

            # For ports that are not router ports, implicitly include all
            # auto-address subnets for address association.
            if not is_router_port:
                v6_stateless += [subnet for subnet in subnets
                                 if ipv6_utils.is_auto_address_subnet(subnet)]
        else:
            # Split into v4, v6 stateless and v6 stateful subnets
            v4 = []
            v6_stateful = []
            for subnet in subnets:
                if subnet['ip_version'] == 4:
                    v4.append(subnet)
                elif ipv6_utils.is_auto_address_subnet(subnet):
                    if not is_router_port:
                        v6_stateless.append(subnet)
                else:
                    v6_stateful.append(subnet)

            version_subnets = [v4, v6_stateful]
            for subnets in version_subnets:
                if subnets:
                    result = NeutronDbPluginV2._generate_ip(context, subnets)
                    ips.append({'ip_address': result['ip_address'],
                                'subnet_id': result['subnet_id']})

        for subnet in v6_stateless:
            # IP addresses for IPv6 SLAAC and DHCPv6-stateless subnets
            # are implicitly included.
            ip_address = self._calculate_ipv6_eui64_addr(context, subnet,
                                                         p['mac_address'])
            ips.append({'ip_address': ip_address.format(),
                        'subnet_id': subnet['id']})

        return ips

    def _validate_subnet_cidr(self, context, network, new_subnet_cidr):
        """Validate the CIDR for a subnet.

        Verifies the specified CIDR does not overlap with the ones defined
        for the other subnets specified for this network, or with any other
        CIDR if overlapping IPs are disabled.
        """
        new_subnet_ipset = netaddr.IPSet([new_subnet_cidr])
        # Disallow subnets with prefix length 0 as they will lead to
        # dnsmasq failures (see bug 1362651).
        # This is not a discrimination against /0 subnets.
        # A /0 subnet is conceptually possible but hardly a practical
        # scenario for neutron's use cases.
        for cidr in new_subnet_ipset.iter_cidrs():
            if cidr.prefixlen == 0:
                err_msg = _("0 is not allowed as CIDR prefix length")
                raise n_exc.InvalidInput(error_message=err_msg)

        if cfg.CONF.allow_overlapping_ips:
            subnet_list = network.subnets
        else:
            subnet_list = self._get_all_subnets(context)
        for subnet in subnet_list:
            if (netaddr.IPSet([subnet.cidr]) & new_subnet_ipset):
                # don't give out details of the overlapping subnet
                err_msg = (_("Requested subnet with cidr: %(cidr)s for "
                             "network: %(network_id)s overlaps with another "
                             "subnet") %
                           {'cidr': new_subnet_cidr,
                            'network_id': network.id})
                LOG.info(_LI("Validation for CIDR: %(new_cidr)s failed - "
                             "overlaps with subnet %(subnet_id)s "
                             "(CIDR: %(cidr)s)"),
                         {'new_cidr': new_subnet_cidr,
                          'subnet_id': subnet.id,
                          'cidr': subnet.cidr})
                raise n_exc.InvalidInput(error_message=err_msg)

    def _validate_network_subnetpools(self, network,
                                      new_subnetpool_id, ip_version):
        """Validate all subnets on the given network have been allocated from
           the same subnet pool as new_subnetpool_id
        """
        for subnet in network.subnets:
            if (subnet.ip_version == ip_version and
               new_subnetpool_id != subnet.subnetpool_id):
                raise n_exc.NetworkSubnetPoolAffinityError()

    def _validate_allocation_pools(self, ip_pools, subnet_cidr):
        """Validate IP allocation pools.

        Verify start and end address for each allocation pool are valid,
        ie: constituted by valid and appropriately ordered IP addresses.
        Also, verify pools do not overlap among themselves.
        Finally, verify that each range fall within the subnet's CIDR.
        """
        subnet = netaddr.IPNetwork(subnet_cidr)
        subnet_first_ip = netaddr.IPAddress(subnet.first + 1)
        subnet_last_ip = netaddr.IPAddress(subnet.last - 1)

        LOG.debug("Performing IP validity checks on allocation pools")
        ip_sets = []
        for ip_pool in ip_pools:
            try:
                start_ip = netaddr.IPAddress(ip_pool['start'])
                end_ip = netaddr.IPAddress(ip_pool['end'])
            except netaddr.AddrFormatError:
                LOG.info(_LI("Found invalid IP address in pool: "
                             "%(start)s - %(end)s:"),
                         {'start': ip_pool['start'],
                          'end': ip_pool['end']})
                raise n_exc.InvalidAllocationPool(pool=ip_pool)
            if (start_ip.version != subnet.version or
                    end_ip.version != subnet.version):
                LOG.info(_LI("Specified IP addresses do not match "
                             "the subnet IP version"))
                raise n_exc.InvalidAllocationPool(pool=ip_pool)
            if end_ip < start_ip:
                LOG.info(_LI("Start IP (%(start)s) is greater than end IP "
                             "(%(end)s)"),
                         {'start': ip_pool['start'], 'end': ip_pool['end']})
                raise n_exc.InvalidAllocationPool(pool=ip_pool)
            if start_ip < subnet_first_ip or end_ip > subnet_last_ip:
                LOG.info(_LI("Found pool larger than subnet "
                             "CIDR:%(start)s - %(end)s"),
                         {'start': ip_pool['start'],
                          'end': ip_pool['end']})
                raise n_exc.OutOfBoundsAllocationPool(
                    pool=ip_pool,
                    subnet_cidr=subnet_cidr)
            # Valid allocation pool
            # Create an IPSet for it for easily verifying overlaps
            ip_sets.append(netaddr.IPSet(netaddr.IPRange(
                ip_pool['start'],
                ip_pool['end']).cidrs()))

        LOG.debug("Checking for overlaps among allocation pools "
                  "and gateway ip")
        ip_ranges = ip_pools[:]

        # Use integer cursors as an efficient way for implementing
        # comparison and avoiding comparing the same pair twice
        for l_cursor in range(len(ip_sets)):
            for r_cursor in range(l_cursor + 1, len(ip_sets)):
                if ip_sets[l_cursor] & ip_sets[r_cursor]:
                    l_range = ip_ranges[l_cursor]
                    r_range = ip_ranges[r_cursor]
                    LOG.info(_LI("Found overlapping ranges: %(l_range)s and "
                                 "%(r_range)s"),
                             {'l_range': l_range, 'r_range': r_range})
                    raise n_exc.OverlappingAllocationPools(
                        pool_1=l_range,
                        pool_2=r_range,
                        subnet_cidr=subnet_cidr)

    def _validate_host_route(self, route, ip_version):
        try:
            netaddr.IPNetwork(route['destination'])
            netaddr.IPAddress(route['nexthop'])
        except netaddr.core.AddrFormatError:
            err_msg = _("Invalid route: %s") % route
            raise n_exc.InvalidInput(error_message=err_msg)
        except ValueError:
            # netaddr.IPAddress would raise this
            err_msg = _("Invalid route: %s") % route
            raise n_exc.InvalidInput(error_message=err_msg)
        self._validate_ip_version(ip_version, route['nexthop'], 'nexthop')
        self._validate_ip_version(ip_version, route['destination'],
                                  'destination')

    def _allocate_pools_for_subnet(self, context, subnet):
        """Create IP allocation pools for a given subnet

        Pools are defined by the 'allocation_pools' attribute,
        a list of dict objects with 'start' and 'end' keys for
        defining the pool range.
        """
        pools = []
        # Auto allocate the pool around gateway_ip
        net = netaddr.IPNetwork(subnet['cidr'])
        first_ip = net.first + 1
        last_ip = net.last - 1
        gw_ip = int(netaddr.IPAddress(subnet['gateway_ip'] or net.last))
        # Use the gw_ip to find a point for splitting allocation pools
        # for this subnet
        split_ip = min(max(gw_ip, net.first), net.last)
        if split_ip > first_ip:
            pools.append({'start': str(netaddr.IPAddress(first_ip)),
                          'end': str(netaddr.IPAddress(split_ip - 1))})
        if split_ip < last_ip:
            pools.append({'start': str(netaddr.IPAddress(split_ip + 1)),
                          'end': str(netaddr.IPAddress(last_ip))})
        # return auto-generated pools
        # no need to check for their validity
        return pools

    def _validate_shared_update(self, context, id, original, updated):
        # The only case that needs to be validated is when 'shared'
        # goes from True to False
        if updated['shared'] == original.shared or updated['shared']:
            return
        ports = self._model_query(
            context, models_v2.Port).filter(
                and_(
                    models_v2.Port.network_id == id,
                    models_v2.Port.device_owner !=
                    constants.DEVICE_OWNER_ROUTER_GW,
                    models_v2.Port.device_owner !=
                    constants.DEVICE_OWNER_FLOATINGIP))
        subnets = self._model_query(
            context, models_v2.Subnet).filter(
                models_v2.Subnet.network_id == id)
        tenant_ids = set([port['tenant_id'] for port in ports] +
                         [subnet['tenant_id'] for subnet in subnets])
        # raise if multiple tenants found or if the only tenant found
        # is not the owner of the network
        if (len(tenant_ids) > 1 or len(tenant_ids) == 1 and
            tenant_ids.pop() != original.tenant_id):
            raise n_exc.InvalidSharedSetting(network=original.name)

    def _validate_ipv6_attributes(self, subnet, cur_subnet):
        if cur_subnet:
            self._validate_ipv6_update_dhcp(subnet, cur_subnet)
            return
        ra_mode_set = attributes.is_attr_set(subnet.get('ipv6_ra_mode'))
        address_mode_set = attributes.is_attr_set(
            subnet.get('ipv6_address_mode'))
        self._validate_ipv6_dhcp(ra_mode_set, address_mode_set,
                                 subnet['enable_dhcp'])
        if ra_mode_set and address_mode_set:
            self._validate_ipv6_combination(subnet['ipv6_ra_mode'],
                                            subnet['ipv6_address_mode'])
        if address_mode_set or ra_mode_set:
            self._validate_eui64_applicable(subnet)

    def _validate_eui64_applicable(self, subnet):
        # Per RFC 4862, section 5.5.3, prefix length and interface
        # id together should be equal to 128. Currently neutron supports
        # EUI64 interface id only, thus limiting the prefix
        # length to be 64 only.
        if ipv6_utils.is_auto_address_subnet(subnet):
            if netaddr.IPNetwork(subnet['cidr']).prefixlen != 64:
                msg = _('Invalid CIDR %s for IPv6 address mode. '
                        'OpenStack uses the EUI-64 address format, '
                        'which requires the prefix to be /64.')
                raise n_exc.InvalidInput(
                    error_message=(msg % subnet['cidr']))

    def _validate_ipv6_combination(self, ra_mode, address_mode):
        if ra_mode != address_mode:
            msg = _("ipv6_ra_mode set to '%(ra_mode)s' with ipv6_address_mode "
                    "set to '%(addr_mode)s' is not valid. "
                    "If both attributes are set, they must be the same value"
                    ) % {'ra_mode': ra_mode, 'addr_mode': address_mode}
            raise n_exc.InvalidInput(error_message=msg)

    def _validate_ipv6_dhcp(self, ra_mode_set, address_mode_set, enable_dhcp):
        if (ra_mode_set or address_mode_set) and not enable_dhcp:
            msg = _("ipv6_ra_mode or ipv6_address_mode cannot be set when "
                    "enable_dhcp is set to False.")
            raise n_exc.InvalidInput(error_message=msg)

    def _validate_ipv6_update_dhcp(self, subnet, cur_subnet):
        if ('enable_dhcp' in subnet and not subnet['enable_dhcp']):
            msg = _("Cannot disable enable_dhcp with "
                    "ipv6 attributes set")

            ra_mode_set = attributes.is_attr_set(subnet.get('ipv6_ra_mode'))
            address_mode_set = attributes.is_attr_set(
                subnet.get('ipv6_address_mode'))

            if ra_mode_set or address_mode_set:
                raise n_exc.InvalidInput(error_message=msg)

            old_ra_mode_set = attributes.is_attr_set(
                cur_subnet.get('ipv6_ra_mode'))
            old_address_mode_set = attributes.is_attr_set(
                cur_subnet.get('ipv6_address_mode'))

            if old_ra_mode_set or old_address_mode_set:
                raise n_exc.InvalidInput(error_message=msg)

    def _make_network_dict(self, network, fields=None,
                           process_extensions=True):
        res = {'id': network['id'],
               'name': network['name'],
               'tenant_id': network['tenant_id'],
               'admin_state_up': network['admin_state_up'],
               'mtu': network.get('mtu', constants.DEFAULT_NETWORK_MTU),
               'status': network['status'],
               'shared': network['shared'],
               'subnets': [subnet['id']
                           for subnet in network['subnets']]}
        # TODO(pritesh): Move vlan_transparent to the extension module.
        # vlan_transparent here is only added if the vlantransparent
        # extension is enabled.
        if ('vlan_transparent' in network and network['vlan_transparent'] !=
            attributes.ATTR_NOT_SPECIFIED):
            res['vlan_transparent'] = network['vlan_transparent']
        # Call auxiliary extend functions, if any
        if process_extensions:
            self._apply_dict_extend_functions(
                attributes.NETWORKS, res, network)
        return self._fields(res, fields)

    def _make_subnet_dict(self, subnet, fields=None):
        res = {'id': subnet['id'],
               'name': subnet['name'],
               'tenant_id': subnet['tenant_id'],
               'network_id': subnet['network_id'],
               'ip_version': subnet['ip_version'],
               'cidr': subnet['cidr'],
               'subnetpool_id': subnet.get('subnetpool_id'),
               'allocation_pools': [{'start': pool['first_ip'],
                                     'end': pool['last_ip']}
                                    for pool in subnet['allocation_pools']],
               'gateway_ip': subnet['gateway_ip'],
               'enable_dhcp': subnet['enable_dhcp'],
               'ipv6_ra_mode': subnet['ipv6_ra_mode'],
               'ipv6_address_mode': subnet['ipv6_address_mode'],
               'dns_nameservers': [dns['address']
                                   for dns in subnet['dns_nameservers']],
               'host_routes': [{'destination': route['destination'],
                                'nexthop': route['nexthop']}
                               for route in subnet['routes']],
               'shared': subnet['shared']
               }
        # Call auxiliary extend functions, if any
        self._apply_dict_extend_functions(attributes.SUBNETS, res, subnet)
        return self._fields(res, fields)

    def _make_subnetpool_dict(self, subnetpool, fields=None):
        default_prefixlen = str(subnetpool['default_prefixlen'])
        min_prefixlen = str(subnetpool['min_prefixlen'])
        max_prefixlen = str(subnetpool['max_prefixlen'])
        res = {'id': subnetpool['id'],
               'name': subnetpool['name'],
               'tenant_id': subnetpool['tenant_id'],
               'default_prefixlen': default_prefixlen,
               'min_prefixlen': min_prefixlen,
               'max_prefixlen': max_prefixlen,
               'shared': subnetpool['shared'],
               'prefixes': [prefix['cidr']
                            for prefix in subnetpool['prefixes']],
               'ip_version': subnetpool['ip_version'],
               'default_quota': subnetpool['default_quota']}
        return self._fields(res, fields)

    def _make_port_dict(self, port, fields=None,
                        process_extensions=True):
        res = {"id": port["id"],
               'name': port['name'],
               "network_id": port["network_id"],
               'tenant_id': port['tenant_id'],
               "mac_address": port["mac_address"],
               "admin_state_up": port["admin_state_up"],
               "status": port["status"],
               "fixed_ips": [{'subnet_id': ip["subnet_id"],
                              'ip_address': ip["ip_address"]}
                             for ip in port["fixed_ips"]],
               "device_id": port["device_id"],
               "device_owner": port["device_owner"]}
        # Call auxiliary extend functions, if any
        if process_extensions:
            self._apply_dict_extend_functions(
                attributes.PORTS, res, port)
        return self._fields(res, fields)

    def _create_bulk(self, resource, context, request_items):
        objects = []
        collection = "%ss" % resource
        items = request_items[collection]
        context.session.begin(subtransactions=True)
        try:
            for item in items:
                obj_creator = getattr(self, 'create_%s' % resource)
                objects.append(obj_creator(context, item))
            context.session.commit()
        except Exception:
            context.session.rollback()
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("An exception occurred while creating "
                              "the %(resource)s:%(item)s"),
                          {'resource': resource, 'item': item})
        return objects

    def create_network_bulk(self, context, networks):
        return self._create_bulk('network', context, networks)

    def create_network(self, context, network):
        """Handle creation of a single network."""
        # single request processing
        n = network['network']
        # NOTE(jkoelker) Get the tenant_id outside of the session to avoid
        #                unneeded db action if the operation raises
        tenant_id = self._get_tenant_id_for_create(context, n)
        with context.session.begin(subtransactions=True):
            args = {'tenant_id': tenant_id,
                    'id': n.get('id') or uuidutils.generate_uuid(),
                    'name': n['name'],
                    'admin_state_up': n['admin_state_up'],
                    'mtu': n.get('mtu', constants.DEFAULT_NETWORK_MTU),
                    'shared': n['shared'],
                    'status': n.get('status', constants.NET_STATUS_ACTIVE)}
            # TODO(pritesh): Move vlan_transparent to the extension module.
            # vlan_transparent here is only added if the vlantransparent
            # extension is enabled.
            if ('vlan_transparent' in n and n['vlan_transparent'] !=
                attributes.ATTR_NOT_SPECIFIED):
                args['vlan_transparent'] = n['vlan_transparent']
            network = models_v2.Network(**args)
            context.session.add(network)
        return self._make_network_dict(network, process_extensions=False)

    def update_network(self, context, id, network):
        n = network['network']
        with context.session.begin(subtransactions=True):
            network = self._get_network(context, id)
            # validate 'shared' parameter
            if 'shared' in n:
                self._validate_shared_update(context, id, network, n)
            network.update(n)
            # also update shared in all the subnets for this network
            subnets = self._get_subnets_by_network(context, id)
            for subnet in subnets:
                subnet['shared'] = network['shared']
        return self._make_network_dict(network)

    def delete_network(self, context, id):
        with context.session.begin(subtransactions=True):
            network = self._get_network(context, id)

            context.session.query(models_v2.Port).filter_by(
                network_id=id).filter(
                models_v2.Port.device_owner.
                in_(AUTO_DELETE_PORT_OWNERS)).delete(synchronize_session=False)

            port_in_use = context.session.query(models_v2.Port).filter_by(
                network_id=id).first()

            if port_in_use:
                raise n_exc.NetworkInUse(net_id=id)

            # clean up subnets
            subnets = self._get_subnets_by_network(context, id)
            for subnet in subnets:
                self.delete_subnet(context, subnet['id'])

            context.session.delete(network)

    def get_network(self, context, id, fields=None):
        network = self._get_network(context, id)
        return self._make_network_dict(network, fields)

    def get_networks(self, context, filters=None, fields=None,
                     sorts=None, limit=None, marker=None,
                     page_reverse=False):
        marker_obj = self._get_marker_obj(context, 'network', limit, marker)
        return self._get_collection(context, models_v2.Network,
                                    self._make_network_dict,
                                    filters=filters, fields=fields,
                                    sorts=sorts,
                                    limit=limit,
                                    marker_obj=marker_obj,
                                    page_reverse=page_reverse)

    def get_networks_count(self, context, filters=None):
        return self._get_collection_count(context, models_v2.Network,
                                          filters=filters)

    def create_subnet_bulk(self, context, subnets):
        return self._create_bulk('subnet', context, subnets)

    def _validate_ip_version(self, ip_version, addr, name):
        """Check IP field of a subnet match specified ip version."""
        ip = netaddr.IPNetwork(addr)
        if ip.version != ip_version:
            data = {'name': name,
                    'addr': addr,
                    'ip_version': ip_version}
            msg = _("%(name)s '%(addr)s' does not match "
                    "the ip_version '%(ip_version)s'") % data
            raise n_exc.InvalidInput(error_message=msg)

    def _validate_subnet(self, context, s, cur_subnet=None):
        """Validate a subnet spec."""

        # This method will validate attributes which may change during
        # create_subnet() and update_subnet().
        # The method requires the subnet spec 's' has 'ip_version' field.
        # If 's' dict does not have 'ip_version' field in an API call
        # (e.g., update_subnet()), you need to set 'ip_version' field
        # before calling this method.

        ip_ver = s['ip_version']

        if attributes.is_attr_set(s.get('cidr')):
            self._validate_ip_version(ip_ver, s['cidr'], 'cidr')

        # TODO(watanabe.isao): After we found a way to avoid the re-sync
        # from the agent side, this restriction could be removed.
        if cur_subnet:
            dhcp_was_enabled = cur_subnet.enable_dhcp
        else:
            dhcp_was_enabled = False
        if s.get('enable_dhcp') and not dhcp_was_enabled:
            subnet_prefixlen = netaddr.IPNetwork(s['cidr']).prefixlen
            error_message = _("Subnet has a prefix length that is "
                              "incompatible with DHCP service enabled.")
            if ((ip_ver == 4 and subnet_prefixlen > 30) or
                (ip_ver == 6 and subnet_prefixlen > 126)):
                    raise n_exc.InvalidInput(error_message=error_message)
            else:
                # NOTE(watanabe.isao): The following restriction is necessary
                # only when updating subnet.
                if cur_subnet:
                    range_qry = context.session.query(models_v2.
                        IPAvailabilityRange).join(models_v2.IPAllocationPool)
                    ip_range = range_qry.filter_by(subnet_id=s['id']).first()
                    if not ip_range:
                        raise n_exc.IpAddressGenerationFailure(
                            net_id=cur_subnet.network_id)

        if attributes.is_attr_set(s.get('gateway_ip')):
            self._validate_ip_version(ip_ver, s['gateway_ip'], 'gateway_ip')
            if (cfg.CONF.force_gateway_on_subnet and
                not self._check_gateway_in_subnet(
                    s['cidr'], s['gateway_ip'])):
                error_message = _("Gateway is not valid on subnet")
                raise n_exc.InvalidInput(error_message=error_message)
            # Ensure the gateway IP is not assigned to any port
            # skip this check in case of create (s parameter won't have id)
            # NOTE(salv-orlando): There is slight chance of a race, when
            # a subnet-update and a router-interface-add operation are
            # executed concurrently
            if cur_subnet:
                alloc_qry = context.session.query(models_v2.IPAllocation)
                allocated = alloc_qry.filter_by(
                    ip_address=cur_subnet['gateway_ip'],
                    subnet_id=cur_subnet['id']).first()
                if allocated and allocated['port_id']:
                    raise n_exc.GatewayIpInUse(
                        ip_address=cur_subnet['gateway_ip'],
                        port_id=allocated['port_id'])

        if attributes.is_attr_set(s.get('dns_nameservers')):
            if len(s['dns_nameservers']) > cfg.CONF.max_dns_nameservers:
                raise n_exc.DNSNameServersExhausted(
                    subnet_id=s.get('id', _('new subnet')),
                    quota=cfg.CONF.max_dns_nameservers)
            for dns in s['dns_nameservers']:
                try:
                    netaddr.IPAddress(dns)
                except Exception:
                    raise n_exc.InvalidInput(
                        error_message=(_("Error parsing dns address %s") %
                                       dns))
                self._validate_ip_version(ip_ver, dns, 'dns_nameserver')

        if attributes.is_attr_set(s.get('host_routes')):
            if len(s['host_routes']) > cfg.CONF.max_subnet_host_routes:
                raise n_exc.HostRoutesExhausted(
                    subnet_id=s.get('id', _('new subnet')),
                    quota=cfg.CONF.max_subnet_host_routes)
            # check if the routes are all valid
            for rt in s['host_routes']:
                self._validate_host_route(rt, ip_ver)

        if ip_ver == 4:
            if attributes.is_attr_set(s.get('ipv6_ra_mode')):
                raise n_exc.InvalidInput(
                    error_message=(_("ipv6_ra_mode is not valid when "
                                     "ip_version is 4")))
            if attributes.is_attr_set(s.get('ipv6_address_mode')):
                raise n_exc.InvalidInput(
                    error_message=(_("ipv6_address_mode is not valid when "
                                     "ip_version is 4")))
        if ip_ver == 6:
            self._validate_ipv6_attributes(s, cur_subnet)

    def _validate_gw_out_of_pools(self, gateway_ip, pools):
        for allocation_pool in pools:
            pool_range = netaddr.IPRange(
                allocation_pool['start'],
                allocation_pool['end'])
            if netaddr.IPAddress(gateway_ip) in pool_range:
                raise n_exc.GatewayConflictWithAllocationPools(
                    pool=pool_range,
                    ip_address=gateway_ip)

    def _update_router_gw_ports(self, context, network, subnet):
        l3plugin = manager.NeutronManager.get_service_plugins().get(
                service_constants.L3_ROUTER_NAT)
        if l3plugin:
            gw_ports = self._get_router_gw_ports_by_network(context,
                    network['id'])
            router_ids = [p['device_id'] for p in gw_ports]
            ctx_admin = ctx.get_admin_context()
            ext_subnets_dict = {s['id']: s for s in network['subnets']}
            for id in router_ids:
                router = l3plugin.get_router(ctx_admin, id)
                external_gateway_info = router['external_gateway_info']
                # Get all stateful (i.e. non-SLAAC/DHCPv6-stateless) fixed ips
                fips = [f for f in external_gateway_info['external_fixed_ips']
                        if not ipv6_utils.is_auto_address_subnet(
                            ext_subnets_dict[f['subnet_id']])]
                num_fips = len(fips)
                # Don't add the fixed IP to the port if it already
                # has a stateful fixed IP of the same IP version
                if num_fips > 1:
                    continue
                if num_fips == 1 and netaddr.IPAddress(
                        fips[0]['ip_address']).version == subnet['ip_version']:
                    continue
                external_gateway_info['external_fixed_ips'].append(
                                             {'subnet_id': subnet['id']})
                info = {'router': {'external_gateway_info':
                    external_gateway_info}}
                l3plugin.update_router(context, id, info)

    def _save_subnet(self, context,
                     network,
                     subnet_args,
                     dns_nameservers,
                     host_routes,
                     allocation_pools):

        if not attributes.is_attr_set(allocation_pools):
            allocation_pools = self._allocate_pools_for_subnet(context,
                                                               subnet_args)
        else:
            self._validate_allocation_pools(allocation_pools,
                                            subnet_args['cidr'])
            if subnet_args['gateway_ip']:
                self._validate_gw_out_of_pools(subnet_args['gateway_ip'],
                                               allocation_pools)

        self._validate_subnet_cidr(context, network, subnet_args['cidr'])
        self._validate_network_subnetpools(network,
                                           subnet_args['subnetpool_id'],
                                           subnet_args['ip_version'])

        subnet = models_v2.Subnet(**subnet_args)
        context.session.add(subnet)
        if attributes.is_attr_set(dns_nameservers):
            for addr in dns_nameservers:
                ns = models_v2.DNSNameServer(address=addr,
                                             subnet_id=subnet.id)
                context.session.add(ns)

        if attributes.is_attr_set(host_routes):
            for rt in host_routes:
                route = models_v2.SubnetRoute(
                    subnet_id=subnet.id,
                    destination=rt['destination'],
                    nexthop=rt['nexthop'])
                context.session.add(route)

        for pool in allocation_pools:
            ip_pool = models_v2.IPAllocationPool(subnet=subnet,
                                                 first_ip=pool['start'],
                                                 last_ip=pool['end'])
            context.session.add(ip_pool)
            ip_range = models_v2.IPAvailabilityRange(
                ipallocationpool=ip_pool,
                first_ip=pool['start'],
                last_ip=pool['end'])
            context.session.add(ip_range)

        return subnet

    def _make_subnet_args(self, context, shared, detail,
                          subnet, subnetpool_id=None):
        args = {'tenant_id': detail.tenant_id,
                'id': detail.subnet_id,
                'name': subnet['name'],
                'network_id': subnet['network_id'],
                'ip_version': subnet['ip_version'],
                'cidr': str(detail.subnet.cidr),
                'subnetpool_id': subnetpool_id,
                'enable_dhcp': subnet['enable_dhcp'],
                'gateway_ip': self._gateway_ip_str(subnet, detail.subnet),
                'shared': shared}
        if subnet['ip_version'] == 6 and subnet['enable_dhcp']:
            if attributes.is_attr_set(subnet['ipv6_ra_mode']):
                args['ipv6_ra_mode'] = subnet['ipv6_ra_mode']
            if attributes.is_attr_set(subnet['ipv6_address_mode']):
                args['ipv6_address_mode'] = subnet['ipv6_address_mode']
        return args

    def _make_subnet_request(self, tenant_id, subnet, subnetpool):
        cidr = subnet.get('cidr')
        subnet_id = subnet.get('id', uuidutils.generate_uuid())
        is_any_subnetpool_request = not attributes.is_attr_set(cidr)

        if is_any_subnetpool_request:
            prefixlen = subnet['prefixlen']
            if not attributes.is_attr_set(prefixlen):
                prefixlen = int(subnetpool['default_prefixlen'])

            return ipam.AnySubnetRequest(
                          tenant_id,
                          subnet_id,
                          utils.ip_version_from_int(subnetpool['ip_version']),
                          prefixlen)
        else:
            return ipam.SpecificSubnetRequest(tenant_id,
                                              subnet_id,
                                              cidr)

    def _gateway_ip_str(self, subnet, cidr_net):
        if subnet.get('gateway_ip') is attributes.ATTR_NOT_SPECIFIED:
                return str(cidr_net.network + 1)
        return subnet.get('gateway_ip')

    @oslo_db_api.wrap_db_retry(max_retries=db_api.MAX_RETRIES,
                               retry_on_request=True,
                               retry_on_deadlock=True)
    def _create_subnet_from_pool(self, context, subnet, subnetpool_id):
        s = subnet['subnet']
        tenant_id = self._get_tenant_id_for_create(context, s)
        has_allocpool = attributes.is_attr_set(s['allocation_pools'])
        is_any_subnetpool_request = not attributes.is_attr_set(s['cidr'])
        if is_any_subnetpool_request and has_allocpool:
            reason = _("allocation_pools allowed only "
                       "for specific subnet requests.")
            raise n_exc.BadRequest(resource='subnets', msg=reason)

        with context.session.begin(subtransactions=True):
            subnetpool = self._get_subnetpool(context, subnetpool_id)
            ip_version = s.get('ip_version')
            has_ip_version = attributes.is_attr_set(ip_version)
            if has_ip_version and ip_version != subnetpool.ip_version:
                args = {'req_ver': str(s['ip_version']),
                        'pool_ver': str(subnetpool.ip_version)}
                reason = _("Cannot allocate IPv%(req_ver)s subnet from "
                           "IPv%(pool_ver)s subnet pool") % args
                raise n_exc.BadRequest(resource='subnets', msg=reason)

            network = self._get_network(context, s["network_id"])
            allocator = subnet_alloc.SubnetAllocator(subnetpool)
            req = self._make_subnet_request(tenant_id, s, subnetpool)

            ipam_subnet = allocator.allocate_subnet(context.session, req)
            detail = ipam_subnet.get_details()
            subnet = self._save_subnet(context,
                                       network,
                                       self._make_subnet_args(
                                              context,
                                              network.shared,
                                              detail,
                                              s,
                                              subnetpool_id=subnetpool['id']),
                                       s['dns_nameservers'],
                                       s['host_routes'],
                                       s['allocation_pools'])
        if network.external:
            self._update_router_gw_ports(context,
                                         network,
                                         subnet)
        return self._make_subnet_dict(subnet)

    def _create_subnet_from_implicit_pool(self, context, subnet):
        s = subnet['subnet']
        self._validate_subnet(context, s)
        tenant_id = self._get_tenant_id_for_create(context, s)
        id = s.get('id', uuidutils.generate_uuid())
        detail = ipam.SpecificSubnetRequest(tenant_id,
                                            id,
                                            s['cidr'])
        with context.session.begin(subtransactions=True):
            network = self._get_network(context, s["network_id"])
            self._validate_subnet_cidr(context, network, s['cidr'])
            subnet = self._save_subnet(context,
                                       network,
                                       self._make_subnet_args(context,
                                                              network.shared,
                                                              detail,
                                                              s),
                                       s['dns_nameservers'],
                                       s['host_routes'],
                                       s['allocation_pools'])
        if network.external:
            self._update_router_gw_ports(context,
                                         network,
                                         subnet)
        return self._make_subnet_dict(subnet)

    def _get_subnetpool_id(self, subnet):
        """Returns the subnetpool id for this request

        If the pool id was explicitly set in the request then that will be
        returned, even if it is None.

        Otherwise, the default pool for the IP version requested will be
        returned.  This will either be a pool id or None (the default for each
        configuration parameter).  This implies that the ip version must be
        either set implicitly with a specific cidr or explicitly using
        ip_version attribute.

        :param subnet: The subnet dict from the request
        """
        subnetpool_id = subnet.get('subnetpool_id',
                                   attributes.ATTR_NOT_SPECIFIED)
        if subnetpool_id != attributes.ATTR_NOT_SPECIFIED:
            return subnetpool_id

        cidr = subnet.get('cidr')
        if attributes.is_attr_set(cidr):
            ip_version = netaddr.IPNetwork(cidr).version
        else:
            ip_version = subnet.get('ip_version')
            if not attributes.is_attr_set(ip_version):
                msg = _('ip_version must be specified in the absence of '
                        'cidr and subnetpool_id')
                raise n_exc.BadRequest(resource='subnets', msg=msg)

        if ip_version == 4:
            return cfg.CONF.default_ipv4_subnet_pool
        return cfg.CONF.default_ipv6_subnet_pool

    def create_subnet(self, context, subnet):

        s = subnet['subnet']
        cidr = s.get('cidr', attributes.ATTR_NOT_SPECIFIED)
        prefixlen = s.get('prefixlen', attributes.ATTR_NOT_SPECIFIED)
        has_cidr = attributes.is_attr_set(cidr)
        has_prefixlen = attributes.is_attr_set(prefixlen)

        if has_cidr and has_prefixlen:
            msg = _('cidr and prefixlen must not be supplied together')
            raise n_exc.BadRequest(resource='subnets', msg=msg)

        if has_cidr:
            # turn the CIDR into a proper subnet
            net = netaddr.IPNetwork(s['cidr'])
            subnet['subnet']['cidr'] = '%s/%s' % (net.network, net.prefixlen)

        subnetpool_id = self._get_subnetpool_id(s)
        if not subnetpool_id:
            if not has_cidr:
                msg = _('A cidr must be specified in the absence of a '
                        'subnet pool')
                raise n_exc.BadRequest(resource='subnets', msg=msg)
            # Create subnet from the implicit(AKA null) pool
            created_subnet = self._create_subnet_from_implicit_pool(context,
                                                                    subnet)
        else:
            created_subnet = self._create_subnet_from_pool(context, subnet,
                                                           subnetpool_id)

        # If this subnet supports auto-addressing, then update any
        # internal ports on the network with addresses for this subnet.
        if ipv6_utils.is_auto_address_subnet(created_subnet):
            self._add_auto_addrs_on_network_ports(context, created_subnet)

        return created_subnet

    def _add_auto_addrs_on_network_ports(self, context, subnet):
        """For an auto-address subnet, add addrs for ports on the net."""
        with context.session.begin(subtransactions=True):
            network_id = subnet['network_id']
            port_qry = context.session.query(models_v2.Port)
            for port in port_qry.filter(
                and_(models_v2.Port.network_id == network_id,
                     models_v2.Port.device_owner !=
                     constants.DEVICE_OWNER_ROUTER_SNAT,
                     ~models_v2.Port.device_owner.in_(
                         constants.ROUTER_INTERFACE_OWNERS))):
                ip_address = self._calculate_ipv6_eui64_addr(
                    context, subnet, port['mac_address'])
                allocated = models_v2.IPAllocation(network_id=network_id,
                                                   port_id=port['id'],
                                                   ip_address=ip_address,
                                                   subnet_id=subnet['id'])
                try:
                    # Do the insertion of each IP allocation entry within
                    # the context of a nested transaction, so that the entry
                    # is rolled back independently of other entries whenever
                    # the corresponding port has been deleted.
                    with context.session.begin_nested():
                        context.session.add(allocated)
                except db_exc.DBReferenceError:
                    LOG.debug("Port %s was deleted while updating it with an "
                              "IPv6 auto-address. Ignoring.", port['id'])

    def _update_subnet_dns_nameservers(self, context, id, s):
        old_dns_list = self._get_dns_by_subnet(context, id)
        new_dns_addr_set = set(s["dns_nameservers"])
        old_dns_addr_set = set([dns['address']
                                for dns in old_dns_list])

        new_dns = list(new_dns_addr_set)
        for dns_addr in old_dns_addr_set - new_dns_addr_set:
            for dns in old_dns_list:
                if dns['address'] == dns_addr:
                    context.session.delete(dns)
        for dns_addr in new_dns_addr_set - old_dns_addr_set:
            dns = models_v2.DNSNameServer(
                address=dns_addr,
                subnet_id=id)
            context.session.add(dns)
        del s["dns_nameservers"]
        return new_dns

    def _update_subnet_host_routes(self, context, id, s):

        def _combine(ht):
            return ht['destination'] + "_" + ht['nexthop']

        old_route_list = self._get_route_by_subnet(context, id)

        new_route_set = set([_combine(route)
                             for route in s['host_routes']])

        old_route_set = set([_combine(route)
                             for route in old_route_list])

        for route_str in old_route_set - new_route_set:
            for route in old_route_list:
                if _combine(route) == route_str:
                    context.session.delete(route)
        for route_str in new_route_set - old_route_set:
            route = models_v2.SubnetRoute(
                destination=route_str.partition("_")[0],
                nexthop=route_str.partition("_")[2],
                subnet_id=id)
            context.session.add(route)

        # Gather host routes for result
        new_routes = []
        for route_str in new_route_set:
            new_routes.append(
                {'destination': route_str.partition("_")[0],
                 'nexthop': route_str.partition("_")[2]})
        del s["host_routes"]
        return new_routes

    def _update_subnet_allocation_pools(self, context, id, s):
        context.session.query(models_v2.IPAllocationPool).filter_by(
            subnet_id=id).delete()
        new_pools = [models_v2.IPAllocationPool(
            first_ip=p['start'], last_ip=p['end'],
            subnet_id=id) for p in s['allocation_pools']]
        context.session.add_all(new_pools)
        NeutronDbPluginV2._rebuild_availability_ranges(context, [s])
        #Gather new pools for result:
        result_pools = [{'start': pool['start'],
                         'end': pool['end']}
                        for pool in s['allocation_pools']]
        del s['allocation_pools']
        return result_pools

    def update_subnet(self, context, id, subnet):
        """Update the subnet with new info.

        The change however will not be realized until the client renew the
        dns lease or we support gratuitous DHCP offers
        """
        s = subnet['subnet']
        changed_host_routes = False
        changed_dns = False
        changed_allocation_pools = False
        db_subnet = self._get_subnet(context, id)
        # Fill 'ip_version' and 'allocation_pools' fields with the current
        # value since _validate_subnet() expects subnet spec has 'ip_version'
        # and 'allocation_pools' fields.
        s['ip_version'] = db_subnet.ip_version
        s['cidr'] = db_subnet.cidr
        s['id'] = db_subnet.id
        self._validate_subnet(context, s, cur_subnet=db_subnet)

        if s.get('gateway_ip') is not None:
            allocation_pools = [{'start': p['first_ip'], 'end': p['last_ip']}
                                for p in db_subnet.allocation_pools]
            self._validate_gw_out_of_pools(s["gateway_ip"], allocation_pools)

        with context.session.begin(subtransactions=True):
            if "dns_nameservers" in s:
                changed_dns = True
                new_dns = self._update_subnet_dns_nameservers(context, id, s)

            if "host_routes" in s:
                changed_host_routes = True
                new_routes = self._update_subnet_host_routes(context, id, s)

            if "allocation_pools" in s:
                self._validate_allocation_pools(s['allocation_pools'],
                                                s['cidr'])
                changed_allocation_pools = True
                new_pools = self._update_subnet_allocation_pools(context,
                                                                 id, s)
            subnet = self._get_subnet(context, id)
            subnet.update(s)
        result = self._make_subnet_dict(subnet)
        # Keep up with fields that changed
        if changed_dns:
            result['dns_nameservers'] = new_dns
        if changed_host_routes:
            result['host_routes'] = new_routes
        if changed_allocation_pools:
            result['allocation_pools'] = new_pools
        return result

    def _subnet_check_ip_allocations(self, context, subnet_id):
        return context.session.query(
            models_v2.IPAllocation).filter_by(
                subnet_id=subnet_id).join(models_v2.Port).first()

    def _subnet_check_ip_allocations_internal_router_ports(self, context,
                                                           subnet_id):
        # Do not delete the subnet if IP allocations for internal
        # router ports still exist
        allocs = context.session.query(models_v2.IPAllocation).filter_by(
                subnet_id=subnet_id).join(models_v2.Port).filter(
                        models_v2.Port.device_owner.in_(
                            constants.ROUTER_INTERFACE_OWNERS)
                ).first()
        if allocs:
            LOG.debug("Subnet %s still has internal router ports, "
                      "cannot delete", subnet_id)
            raise n_exc.SubnetInUse(subnet_id=id)

    def delete_subnet(self, context, id):
        with context.session.begin(subtransactions=True):
            subnet = self._get_subnet(context, id)
            # Delete all network owned ports
            qry_network_ports = (
                context.session.query(models_v2.IPAllocation).
                filter_by(subnet_id=subnet['id']).
                join(models_v2.Port))
            # Remove network owned ports, and delete IP allocations
            # for IPv6 addresses which were automatically generated
            # via SLAAC
            is_auto_addr_subnet = ipv6_utils.is_auto_address_subnet(subnet)
            if is_auto_addr_subnet:
                self._subnet_check_ip_allocations_internal_router_ports(
                        context, id)
            else:
                qry_network_ports = (
                    qry_network_ports.filter(models_v2.Port.device_owner.
                    in_(AUTO_DELETE_PORT_OWNERS)))
            network_ports = qry_network_ports.all()
            if network_ports:
                map(context.session.delete, network_ports)
            # Check if there are more IP allocations, unless
            # is_auto_address_subnet is True. In that case the check is
            # unnecessary. This additional check not only would be wasteful
            # for this class of subnet, but is also error-prone since when
            # the isolation level is set to READ COMMITTED allocations made
            # concurrently will be returned by this query
            if not is_auto_addr_subnet:
                alloc = self._subnet_check_ip_allocations(context, id)
                if alloc:
                    LOG.info(_LI("Found IP allocation %(alloc)s on subnet "
                                 "%(subnet)s, cannot delete"),
                             {'alloc': alloc,
                              'subnet': id})
                    raise n_exc.SubnetInUse(subnet_id=id)

            context.session.delete(subnet)

    def get_subnet(self, context, id, fields=None):
        subnet = self._get_subnet(context, id)
        return self._make_subnet_dict(subnet, fields)

    def get_subnets(self, context, filters=None, fields=None,
                    sorts=None, limit=None, marker=None,
                    page_reverse=False):
        marker_obj = self._get_marker_obj(context, 'subnet', limit, marker)
        return self._get_collection(context, models_v2.Subnet,
                                    self._make_subnet_dict,
                                    filters=filters, fields=fields,
                                    sorts=sorts,
                                    limit=limit,
                                    marker_obj=marker_obj,
                                    page_reverse=page_reverse)

    def get_subnets_count(self, context, filters=None):
        return self._get_collection_count(context, models_v2.Subnet,
                                          filters=filters)

    def _create_subnetpool_prefix(self, context, cidr, subnetpool_id):
        prefix_args = {'cidr': cidr, 'subnetpool_id': subnetpool_id}
        subnetpool_prefix = models_v2.SubnetPoolPrefix(**prefix_args)
        context.session.add(subnetpool_prefix)

    def create_subnetpool(self, context, subnetpool):
        """Create a subnetpool"""

        sp = subnetpool['subnetpool']
        sp_reader = subnet_alloc.SubnetPoolReader(sp)
        tenant_id = self._get_tenant_id_for_create(context, sp)
        with context.session.begin(subtransactions=True):
            pool_args = {'tenant_id': tenant_id,
                         'id': sp_reader.id,
                         'name': sp_reader.name,
                         'ip_version': sp_reader.ip_version,
                         'default_prefixlen':
                         sp_reader.default_prefixlen,
                         'min_prefixlen': sp_reader.min_prefixlen,
                         'max_prefixlen': sp_reader.max_prefixlen,
                         'shared': sp_reader.shared,
                         'default_quota': sp_reader.default_quota}
            subnetpool = models_v2.SubnetPool(**pool_args)
            context.session.add(subnetpool)
            for prefix in sp_reader.prefixes:
                self._create_subnetpool_prefix(context,
                                               prefix,
                                               subnetpool.id)

        return self._make_subnetpool_dict(subnetpool)

    def _update_subnetpool_prefixes(self, context, prefix_list, id):
        with context.session.begin(subtransactions=True):
            context.session.query(models_v2.SubnetPoolPrefix).filter_by(
                subnetpool_id=id).delete()
            for prefix in prefix_list:
                model_prefix = models_v2.SubnetPoolPrefix(cidr=prefix,
                                                      subnetpool_id=id)
                context.session.add(model_prefix)

    def _updated_subnetpool_dict(self, model, new_pool):
        updated = {}
        new_prefixes = new_pool.get('prefixes', attributes.ATTR_NOT_SPECIFIED)
        orig_prefixes = [str(x.cidr) for x in model['prefixes']]
        if new_prefixes is not attributes.ATTR_NOT_SPECIFIED:
            orig_set = netaddr.IPSet(orig_prefixes)
            new_set = netaddr.IPSet(new_prefixes)
            if not orig_set.issubset(new_set):
                msg = _("Existing prefixes must be "
                        "a subset of the new prefixes")
                raise n_exc.IllegalSubnetPoolPrefixUpdate(msg=msg)
            new_set.compact()
            updated['prefixes'] = [str(x.cidr) for x in new_set.iter_cidrs()]
        else:
            updated['prefixes'] = orig_prefixes

        for key in ['id', 'name', 'ip_version', 'min_prefixlen',
                    'max_prefixlen', 'default_prefixlen', 'shared',
                    'default_quota']:
            self._write_key(key, updated, model, new_pool)

        return updated

    def _write_key(self, key, update, orig, new_dict):
        new_val = new_dict.get(key, attributes.ATTR_NOT_SPECIFIED)
        if new_val is not attributes.ATTR_NOT_SPECIFIED:
            update[key] = new_dict[key]
        else:
            update[key] = orig[key]

    def update_subnetpool(self, context, id, subnetpool):
        """Update a subnetpool"""
        new_sp = subnetpool['subnetpool']

        with context.session.begin(subtransactions=True):
            orig_sp = self._get_subnetpool(context, id)
            updated = self._updated_subnetpool_dict(orig_sp, new_sp)
            updated['tenant_id'] = orig_sp.tenant_id
            reader = subnet_alloc.SubnetPoolReader(updated)
            orig_sp.update(self._filter_non_model_columns(
                                                      reader.subnetpool,
                                                      models_v2.SubnetPool))
            self._update_subnetpool_prefixes(context,
                                             reader.prefixes,
                                             id)
        for key in ['min_prefixlen', 'max_prefixlen', 'default_prefixlen']:
            updated['key'] = str(updated[key])

        return updated

    def get_subnetpool(self, context, id, fields=None):
        """Retrieve a subnetpool."""
        subnetpool = self._get_subnetpool(context, id)
        return self._make_subnetpool_dict(subnetpool, fields)

    def get_subnetpools(self, context, filters=None, fields=None,
                        sorts=None, limit=None, marker=None,
                        page_reverse=False):
        """Retrieve list of subnetpools."""
        marker_obj = self._get_marker_obj(context, 'subnetpool', limit, marker)
        collection = self._get_collection(context, models_v2.SubnetPool,
                                    self._make_subnetpool_dict,
                                    filters=filters, fields=fields,
                                    sorts=sorts,
                                    limit=limit,
                                    marker_obj=marker_obj,
                                    page_reverse=page_reverse)
        return collection

    def delete_subnetpool(self, context, id):
        """Delete a subnetpool."""
        with context.session.begin(subtransactions=True):
            subnetpool = self._get_subnetpool(context, id)
            subnets = self._get_subnets_by_subnetpool(context, id)
            if subnets:
                reason = _("Subnet pool has existing allocations")
                raise n_exc.SubnetPoolDeleteError(reason=reason)
            context.session.delete(subnetpool)

    def _check_mac_addr_update(self, context, port, new_mac, device_owner):
        if (device_owner and device_owner.startswith('network:')):
            raise n_exc.UnsupportedPortDeviceOwner(
                op=_("mac address update"), port_id=id,
                device_owner=device_owner)

    def create_port_bulk(self, context, ports):
        return self._create_bulk('port', context, ports)

    def _create_port_with_mac(self, context, network_id, port_data,
                              mac_address, nested=False):
        try:
            with context.session.begin(subtransactions=True, nested=nested):
                db_port = models_v2.Port(mac_address=mac_address, **port_data)
                context.session.add(db_port)
                return db_port
        except db_exc.DBDuplicateEntry:
            raise n_exc.MacAddressInUse(net_id=network_id, mac=mac_address)

    def _create_port(self, context, network_id, port_data):
        max_retries = cfg.CONF.mac_generation_retries
        for i in range(max_retries):
            mac = self._generate_mac()
            try:
                # nested = True frames an operation that may potentially fail
                # within a transaction, so that it can be rolled back to the
                # point before its failure while maintaining the enclosing
                # transaction
                return self._create_port_with_mac(
                    context, network_id, port_data, mac, nested=True)
            except n_exc.MacAddressInUse:
                LOG.debug('Generated mac %(mac_address)s exists on '
                          'network %(network_id)s',
                          {'mac_address': mac, 'network_id': network_id})

        LOG.error(_LE("Unable to generate mac address after %s attempts"),
                  max_retries)
        raise n_exc.MacAddressGenerationFailure(net_id=network_id)

    def create_port(self, context, port):
        p = port['port']
        port_id = p.get('id') or uuidutils.generate_uuid()
        network_id = p['network_id']
        # NOTE(jkoelker) Get the tenant_id outside of the session to avoid
        #                unneeded db action if the operation raises
        tenant_id = self._get_tenant_id_for_create(context, p)
        if p.get('device_owner'):
            self._enforce_device_owner_not_router_intf_or_device_id(
                context, p.get('device_owner'), p.get('device_id'), tenant_id)

        port_data = dict(tenant_id=tenant_id,
                         name=p['name'],
                         id=port_id,
                         network_id=network_id,
                         admin_state_up=p['admin_state_up'],
                         status=p.get('status', constants.PORT_STATUS_ACTIVE),
                         device_id=p['device_id'],
                         device_owner=p['device_owner'])

        with context.session.begin(subtransactions=True):
            # Ensure that the network exists.
            self._get_network(context, network_id)

            # Create the port
            if p['mac_address'] is attributes.ATTR_NOT_SPECIFIED:
                db_port = self._create_port(context, network_id, port_data)
                p['mac_address'] = db_port['mac_address']
            else:
                db_port = self._create_port_with_mac(
                    context, network_id, port_data, p['mac_address'])

            # Update the IP's for the port
            ips = self._allocate_ips_for_port(context, port)
            if ips:
                for ip in ips:
                    ip_address = ip['ip_address']
                    subnet_id = ip['subnet_id']
                    NeutronDbPluginV2._store_ip_allocation(
                        context, ip_address, network_id, subnet_id, port_id)

        return self._make_port_dict(db_port, process_extensions=False)

    def update_port(self, context, id, port):
        p = port['port']

        changed_ips = False
        with context.session.begin(subtransactions=True):
            port = self._get_port(context, id)
            changed_owner = 'device_owner' in p
            current_owner = p.get('device_owner') or port['device_owner']
            changed_device_id = p.get('device_id') != port['device_id']
            current_device_id = p.get('device_id') or port['device_id']

            if current_owner and changed_device_id or changed_owner:
                self._enforce_device_owner_not_router_intf_or_device_id(
                    context, current_owner, current_device_id,
                    port['tenant_id'])

            new_mac = p.get('mac_address')
            if new_mac and new_mac != port['mac_address']:
                self._check_mac_addr_update(
                    context, port, new_mac, current_owner)

            # Check if the IPs need to be updated
            network_id = port['network_id']
            if 'fixed_ips' in p:
                changed_ips = True
                original = self._make_port_dict(port, process_extensions=False)
                added_ips, prev_ips = self._update_ips_for_port(
                    context, network_id, id,
                    original["fixed_ips"], p['fixed_ips'],
                    original['mac_address'], port['device_owner'])

                # Update ips if necessary
                for ip in added_ips:
                    NeutronDbPluginV2._store_ip_allocation(
                        context, ip['ip_address'], network_id,
                        ip['subnet_id'], port.id)
                # Remove all attributes in p which are not in the port DB model
                # and then update the port
            try:
                port.update(self._filter_non_model_columns(p, models_v2.Port))
                context.session.flush()
            except db_exc.DBDuplicateEntry:
                raise n_exc.MacAddressInUse(net_id=network_id, mac=new_mac)

        result = self._make_port_dict(port)
        # Keep up with fields that changed
        if changed_ips:
            result['fixed_ips'] = prev_ips + added_ips
        return result

    def delete_port(self, context, id):
        with context.session.begin(subtransactions=True):
            self._delete_port(context, id)

    def delete_ports_by_device_id(self, context, device_id, network_id=None):
        query = (context.session.query(models_v2.Port.id)
                 .enable_eagerloads(False)
                 .filter(models_v2.Port.device_id == device_id))
        if network_id:
            query = query.filter(models_v2.Port.network_id == network_id)
        port_ids = [p[0] for p in query]
        for port_id in port_ids:
            try:
                self.delete_port(context, port_id)
            except n_exc.PortNotFound:
                # Don't raise if something else concurrently deleted the port
                LOG.debug("Ignoring PortNotFound when deleting port '%s'. "
                          "The port has already been deleted.",
                          port_id)

    def _delete_port(self, context, id):
        query = (context.session.query(models_v2.Port).
                 enable_eagerloads(False).filter_by(id=id))
        if not context.is_admin:
            query = query.filter_by(tenant_id=context.tenant_id)
        query.delete()

    def get_port(self, context, id, fields=None):
        port = self._get_port(context, id)
        return self._make_port_dict(port, fields)

    def _get_ports_query(self, context, filters=None, sorts=None, limit=None,
                         marker_obj=None, page_reverse=False):
        Port = models_v2.Port
        IPAllocation = models_v2.IPAllocation

        if not filters:
            filters = {}

        query = self._model_query(context, Port)

        fixed_ips = filters.pop('fixed_ips', {})
        ip_addresses = fixed_ips.get('ip_address')
        subnet_ids = fixed_ips.get('subnet_id')
        if ip_addresses or subnet_ids:
            query = query.join(Port.fixed_ips)
            if ip_addresses:
                query = query.filter(IPAllocation.ip_address.in_(ip_addresses))
            if subnet_ids:
                query = query.filter(IPAllocation.subnet_id.in_(subnet_ids))

        query = self._apply_filters_to_query(query, Port, filters)
        if limit and page_reverse and sorts:
            sorts = [(s[0], not s[1]) for s in sorts]
        query = sqlalchemyutils.paginate_query(query, Port, limit,
                                               sorts, marker_obj)
        return query

    def get_ports(self, context, filters=None, fields=None,
                  sorts=None, limit=None, marker=None,
                  page_reverse=False):
        marker_obj = self._get_marker_obj(context, 'port', limit, marker)
        query = self._get_ports_query(context, filters=filters,
                                      sorts=sorts, limit=limit,
                                      marker_obj=marker_obj,
                                      page_reverse=page_reverse)
        items = [self._make_port_dict(c, fields) for c in query]
        if limit and page_reverse:
            items.reverse()
        return items

    def get_ports_count(self, context, filters=None):
        return self._get_ports_query(context, filters).count()

    def _enforce_device_owner_not_router_intf_or_device_id(self, context,
                                                           device_owner,
                                                           device_id,
                                                           tenant_id):
        """Prevent tenants from replacing the device id of router ports with
        a router uuid belonging to another tenant.
        """
        if device_owner not in constants.ROUTER_INTERFACE_OWNERS:
            return
        if not context.is_admin:
            # check to make sure device_id does not match another tenants
            # router.
            if device_id:
                if hasattr(self, 'get_router'):
                    try:
                        ctx_admin = ctx.get_admin_context()
                        router = self.get_router(ctx_admin, device_id)
                    except l3.RouterNotFound:
                        return
                else:
                    l3plugin = (
                        manager.NeutronManager.get_service_plugins().get(
                            service_constants.L3_ROUTER_NAT))
                    if l3plugin:
                        try:
                            ctx_admin = ctx.get_admin_context()
                            router = l3plugin.get_router(ctx_admin,
                                                         device_id)
                        except l3.RouterNotFound:
                            return
                    else:
                        # raise as extension doesn't support L3 anyways.
                        raise n_exc.DeviceIDNotOwnedByTenant(
                            device_id=device_id)
                if tenant_id != router['tenant_id']:
                    raise n_exc.DeviceIDNotOwnedByTenant(device_id=device_id)
