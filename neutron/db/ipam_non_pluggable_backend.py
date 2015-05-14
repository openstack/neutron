# Copyright (c) 2015 OpenStack Foundation.
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
from oslo_db import exception as db_exc
from oslo_log import log as logging
from sqlalchemy import and_
from sqlalchemy import orm
from sqlalchemy.orm import exc

from neutron.api.v2 import attributes
from neutron.common import constants
from neutron.common import exceptions as n_exc
from neutron.common import ipv6_utils
from neutron.db import ipam_backend_mixin
from neutron.db import models_v2
from neutron.ipam import requests as ipam_req
from neutron.ipam import subnet_alloc

LOG = logging.getLogger(__name__)


class IpamNonPluggableBackend(ipam_backend_mixin.IpamBackendMixin):

    @staticmethod
    def _generate_ip(context, subnets):
        try:
            return IpamNonPluggableBackend._try_generate_ip(context, subnets)
        except n_exc.IpAddressGenerationFailure:
            IpamNonPluggableBackend._rebuild_availability_ranges(context,
                                                                 subnets)

        return IpamNonPluggableBackend._try_generate_ip(context, subnets)

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

    def save_allocation_pools(self, context, subnet, allocation_pools):
        for pool in allocation_pools:
            first_ip = str(netaddr.IPAddress(pool.first, pool.version))
            last_ip = str(netaddr.IPAddress(pool.last, pool.version))
            ip_pool = models_v2.IPAllocationPool(subnet=subnet,
                                                 first_ip=first_ip,
                                                 last_ip=last_ip)
            context.session.add(ip_pool)
            ip_range = models_v2.IPAvailabilityRange(
                ipallocationpool=ip_pool,
                first_ip=first_ip,
                last_ip=last_ip)
            context.session.add(ip_range)

    def allocate_ips_for_port_and_store(self, context, port, port_id):
        network_id = port['port']['network_id']
        ips = self._allocate_ips_for_port(context, port)
        if ips:
            for ip in ips:
                ip_address = ip['ip_address']
                subnet_id = ip['subnet_id']
                self._store_ip_allocation(context, ip_address, network_id,
                                          subnet_id, port_id)

    def update_port_with_ips(self, context, db_port, new_port, new_mac):
        changes = self.Changes(add=[], original=[], remove=[])
        # Check if the IPs need to be updated
        network_id = db_port['network_id']
        if 'fixed_ips' in new_port:
            original = self._make_port_dict(db_port, process_extensions=False)
            changes = self._update_ips_for_port(
                context, network_id,
                original["fixed_ips"], new_port['fixed_ips'],
                original['mac_address'], db_port['device_owner'])

            # Update ips if necessary
            for ip in changes.add:
                IpamNonPluggableBackend._store_ip_allocation(
                    context, ip['ip_address'], network_id,
                    ip['subnet_id'], db_port.id)
        self._update_db_port(context, db_port, new_port, network_id, new_mac)
        return changes

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
            subnet = self._get_subnet_for_fixed_ip(context, fixed, network_id)

            is_auto_addr_subnet = ipv6_utils.is_auto_address_subnet(subnet)
            if 'ip_address' in fixed:
                # Ensure that the IP's are unique
                if not IpamNonPluggableBackend._check_unique_ip(
                        context, network_id,
                        subnet['id'], fixed['ip_address']):
                    raise n_exc.IpAddressInUse(net_id=network_id,
                                               ip_address=fixed['ip_address'])

                if (is_auto_addr_subnet and
                    device_owner not in
                        constants.ROUTER_INTERFACE_OWNERS):
                    msg = (_("IPv6 address %(address)s can not be directly "
                            "assigned to a port on subnet %(id)s since the "
                            "subnet is configured for automatic addresses") %
                           {'address': fixed['ip_address'],
                            'id': subnet['id']})
                    raise n_exc.InvalidInput(error_message=msg)
                fixed_ip_set.append({'subnet_id': subnet['id'],
                                     'ip_address': fixed['ip_address']})
            else:
                # A scan for auto-address subnets on the network is done
                # separately so that all such subnets (not just those
                # listed explicitly here by subnet ID) are associated
                # with the port.
                if (device_owner in constants.ROUTER_INTERFACE_OWNERS_SNAT or
                    not is_auto_addr_subnet):
                    fixed_ip_set.append({'subnet_id': subnet['id']})

        self._validate_max_ips_per_port(fixed_ip_set)
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
                    IpamNonPluggableBackend._allocate_specific_ip(
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

    def _update_ips_for_port(self, context, network_id, original_ips,
                             new_ips, mac_address, device_owner):
        """Add or remove IPs from the port."""
        added = []
        changes = self._get_changed_ips_for_port(context, original_ips,
                                                 new_ips, device_owner)
        # Check if the IP's to add are OK
        to_add = self._test_fixed_ips_for_port(context, network_id,
                                               changes.add, device_owner)
        for ip in changes.remove:
            LOG.debug("Port update. Hold %s", ip)
            IpamNonPluggableBackend._delete_ip_allocation(context,
                                                          network_id,
                                                          ip['subnet_id'],
                                                          ip['ip_address'])

        if to_add:
            LOG.debug("Port update. Adding %s", to_add)
            added = self._allocate_fixed_ips(context, to_add, mac_address)
        return self.Changes(add=added,
                            original=changes.original,
                            remove=changes.remove)

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
        subnets = self._get_subnets(context, filters=net_id_filter)
        is_router_port = (
            p['device_owner'] in constants.ROUTER_INTERFACE_OWNERS_SNAT)

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
                    result = IpamNonPluggableBackend._generate_ip(context,
                                                                  subnets)
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

    def add_auto_addrs_on_network_ports(self, context, subnet, ipam_subnet):
        """For an auto-address subnet, add addrs for ports on the net."""
        with context.session.begin(subtransactions=True):
            network_id = subnet['network_id']
            port_qry = context.session.query(models_v2.Port)
            ports = port_qry.filter(
                and_(models_v2.Port.network_id == network_id,
                     ~models_v2.Port.device_owner.in_(
                         constants.ROUTER_INTERFACE_OWNERS_SNAT)))
            for port in ports:
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

    def allocate_subnet(self, context, network, subnet, subnetpool_id):
        subnetpool = None
        if subnetpool_id:
            subnetpool = self._get_subnetpool(context, subnetpool_id)
            self._validate_ip_version_with_subnetpool(subnet, subnetpool)

        # gateway_ip and allocation pools should be validated or generated
        # only for specific request
        if subnet['cidr'] is not attributes.ATTR_NOT_SPECIFIED:
            subnet['gateway_ip'] = self._gateway_ip_str(subnet,
                                                        subnet['cidr'])
            # allocation_pools are converted to list of IPRanges
            subnet['allocation_pools'] = self._prepare_allocation_pools(
                subnet['allocation_pools'],
                subnet['cidr'],
                subnet['gateway_ip'])

        subnet_request = ipam_req.SubnetRequestFactory.get_request(context,
                                                                   subnet,
                                                                   subnetpool)

        if subnetpool_id:
            driver = subnet_alloc.SubnetAllocator(subnetpool, context)
            ipam_subnet = driver.allocate_subnet(subnet_request)
            subnet_request = ipam_subnet.get_details()

        subnet = self._save_subnet(context,
                                   network,
                                   self._make_subnet_args(
                                       subnet_request,
                                       subnet,
                                       subnetpool_id),
                                   subnet['dns_nameservers'],
                                   subnet['host_routes'],
                                   subnet_request)
        # ipam_subnet is not expected to be allocated for non pluggable ipam,
        # so just return None for it (second element in returned tuple)
        return subnet, None
