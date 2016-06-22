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

import collections
import itertools
import random

import netaddr
from neutron_lib import constants
from neutron_lib import exceptions as n_exc
from oslo_db import exception as db_exc
from oslo_log import log as logging
from sqlalchemy import and_
from sqlalchemy.orm import exc

from neutron._i18n import _
from neutron.common import constants as n_const
from neutron.common import ipv6_utils
from neutron.db import ipam_backend_mixin
from neutron.db import models_v2
from neutron.extensions import portbindings
from neutron.ipam import requests as ipam_req
from neutron.ipam import subnet_alloc

LOG = logging.getLogger(__name__)


class IpamNonPluggableBackend(ipam_backend_mixin.IpamBackendMixin):

    @staticmethod
    def _generate_ip(context, subnets, filtered_ips=None, prefer_next=False):
        """Generate an IP address.

        The IP address will be generated from one of the subnets defined on
        the network.
        """
        filtered_ips = filtered_ips or []
        subnet_id_list = [subnet['id'] for subnet in subnets]
        pool_qry = context.session.query(models_v2.IPAllocationPool)
        pool_qry = pool_qry.filter(
            models_v2.IPAllocationPool.subnet_id.in_(subnet_id_list))

        allocation_qry = context.session.query(models_v2.IPAllocation)
        allocation_qry = allocation_qry.filter(
            models_v2.IPAllocation.subnet_id.in_(subnet_id_list))

        ip_allocations = collections.defaultdict(netaddr.IPSet)
        for ipallocation in allocation_qry:
            subnet_ip_allocs = ip_allocations[ipallocation.subnet_id]
            subnet_ip_allocs.add(netaddr.IPAddress(ipallocation.ip_address))

        ip_pools = collections.defaultdict(netaddr.IPSet)
        for ip_pool in pool_qry:
            subnet_ip_pools = ip_pools[ip_pool.subnet_id]
            subnet_ip_pools.add(netaddr.IPRange(ip_pool.first_ip,
                                                ip_pool.last_ip))

        for subnet_id in ip_pools:
            subnet_ip_pools = ip_pools[subnet_id]
            subnet_ip_allocs = ip_allocations[subnet_id]
            filter_set = netaddr.IPSet()
            for ip in filtered_ips:
                filter_set.add(netaddr.IPAddress(ip))

            av_set = subnet_ip_pools.difference(subnet_ip_allocs)
            av_set = av_set.difference(filter_set)

            av_set_size = av_set.size
            if av_set_size == 0:
                continue

            # Compute a window size, select an index inside the window, then
            # select the IP address at the selected index within the window
            if prefer_next:
                window = 1
            else:
                window = min(av_set_size, 10)
            ip_index = random.randint(1, window)
            candidate_ips = list(itertools.islice(av_set, ip_index))
            if candidate_ips:
                allocated_ip = candidate_ips[-1]
                return {'ip_address': str(allocated_ip),
                        'subnet_id': subnet_id}
        raise n_exc.IpAddressGenerationFailure(
                  net_id=subnets[0]['network_id'])

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
        return ips

    def update_port_with_ips(self, context, host, db_port, new_port, new_mac):
        changes = self.Changes(add=[], original=[], remove=[])
        # Check if the IPs need to be updated
        network_id = db_port['network_id']
        if 'fixed_ips' in new_port:
            original = self._make_port_dict(db_port, process_extensions=False)
            changes = self._update_ips_for_port(
                context, network_id, host,
                original["fixed_ips"], new_port['fixed_ips'],
                original['mac_address'], db_port['device_owner'])

            # Expire the fixed_ips of db_port in current transaction, because
            # it will be changed in the following operation and the latest
            # data is expected.
            context.session.expire(db_port, ['fixed_ips'])

            # Update ips if necessary
            for ip in changes.add:
                IpamNonPluggableBackend._store_ip_allocation(
                    context, ip['ip_address'], network_id,
                    ip['subnet_id'], db_port.id)
        self._update_db_port(context, db_port, new_port, network_id, new_mac)
        return changes

    def _test_fixed_ips_for_port(self, context, network_id, fixed_ips,
                                 device_owner, subnets):
        """Test fixed IPs for port.

        Check that configured subnets are valid prior to allocating any
        IPs. Include the subnet_id in the result if only an IP address is
        configured.

        :raises: InvalidInput, IpAddressInUse, InvalidIpForNetwork,
                 InvalidIpForSubnet
        """
        fixed_ip_set = []
        for fixed in fixed_ips:
            subnet = self._get_subnet_for_fixed_ip(context, fixed, subnets)

            is_auto_addr_subnet = ipv6_utils.is_auto_address_subnet(subnet)
            if ('ip_address' in fixed and
                subnet['cidr'] != n_const.PROVISIONAL_IPV6_PD_PREFIX):
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

        self._validate_max_ips_per_port(fixed_ip_set, device_owner)
        return fixed_ip_set

    def _allocate_fixed_ips(self, context, fixed_ips, mac_address,
                            prefer_next=False):
        """Allocate IP addresses according to the configured fixed_ips."""
        ips = []

        # we need to start with entries that asked for a specific IP in case
        # those IPs happen to be next in the line for allocation for ones that
        # didn't ask for a specific IP
        fixed_ips.sort(key=lambda x: 'ip_address' not in x)
        allocated_ips = []
        for fixed in fixed_ips:
            subnet = self._get_subnet(context, fixed['subnet_id'])
            is_auto_addr = ipv6_utils.is_auto_address_subnet(subnet)
            if 'ip_address' in fixed:
                allocated_ips.append(fixed['ip_address'])
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
                    result = self._generate_ip(context, subnets, allocated_ips,
                                               prefer_next)
                    allocated_ips.append(result['ip_address'])
                    ips.append({'ip_address': result['ip_address'],
                                'subnet_id': result['subnet_id']})
        return ips

    def _update_ips_for_port(self, context, network_id, host, original_ips,
                             new_ips, mac_address, device_owner):
        """Add or remove IPs from the port."""
        added = []
        changes = self._get_changed_ips_for_port(context, original_ips,
                                                 new_ips, device_owner)
        subnets = self._ipam_get_subnets(
            context, network_id=network_id, host=host)
        # Check if the IP's to add are OK
        to_add = self._test_fixed_ips_for_port(context, network_id,
                                               changes.add, device_owner,
                                               subnets)

        if device_owner not in constants.ROUTER_INTERFACE_OWNERS:
            to_add += self._update_ips_for_pd_subnet(
                context, subnets, changes.add)

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
        subnets = self._ipam_get_subnets(context,
                                         network_id=p['network_id'],
                                         host=p.get(portbindings.HOST_ID))

        v4, v6_stateful, v6_stateless = self._classify_subnets(
            context, subnets)

        # preserve previous behavior of DHCP ports choosing start of pool
        prefer_next = p['device_owner'] == constants.DEVICE_OWNER_DHCP
        fixed_configured = p['fixed_ips'] is not constants.ATTR_NOT_SPECIFIED
        if fixed_configured:
            configured_ips = self._test_fixed_ips_for_port(context,
                                                           p["network_id"],
                                                           p['fixed_ips'],
                                                           p['device_owner'],
                                                           subnets)
            ips = self._allocate_fixed_ips(context,
                                           configured_ips,
                                           p['mac_address'],
                                           prefer_next=prefer_next)

        else:
            ips = []
            version_subnets = [v4, v6_stateful]
            for subnets in version_subnets:
                if subnets:
                    result = IpamNonPluggableBackend._generate_ip(
                        context, subnets, prefer_next=prefer_next)
                    ips.append({'ip_address': result['ip_address'],
                                'subnet_id': result['subnet_id']})

        is_router_port = (
            p['device_owner'] in constants.ROUTER_INTERFACE_OWNERS_SNAT)
        if not is_router_port:
            # IP addresses for IPv6 SLAAC and DHCPv6-stateless subnets
            # are generated and implicitly included.
            for subnet in v6_stateless:
                ip_address = self._calculate_ipv6_eui64_addr(
                    context, subnet, p['mac_address'])
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
            updated_ports = []
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
                    updated_ports.append(port['id'])
                except db_exc.DBReferenceError:
                    LOG.debug("Port %s was deleted while updating it with an "
                              "IPv6 auto-address. Ignoring.", port['id'])
            return updated_ports

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
        if subnetpool_id and not subnetpool_id == constants.IPV6_PD_POOL_ID:
            subnetpool = self._get_subnetpool(context, id=subnetpool_id)
            self._validate_ip_version_with_subnetpool(subnet, subnetpool)

        # gateway_ip and allocation pools should be validated or generated
        # only for specific request
        if subnet['cidr'] is not constants.ATTR_NOT_SPECIFIED:
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

        if subnetpool_id and not subnetpool_id == constants.IPV6_PD_POOL_ID:
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
