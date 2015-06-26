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

import netaddr
from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_log import log as logging

from neutron.api.v2 import attributes
from neutron.common import constants
from neutron.common import exceptions as n_exc
from neutron.common import ipv6_utils
from neutron.db import db_base_plugin_common
from neutron.db import models_v2
from neutron.i18n import _LI

LOG = logging.getLogger(__name__)


class IpamBackendMixin(db_base_plugin_common.DbBasePluginCommon):
    """Contains IPAM specific code which is common for both backends.
    """

    # Tracks changes in ip allocation for port using namedtuple
    Changes = collections.namedtuple('Changes', 'add original remove')

    @staticmethod
    def _rebuild_availability_ranges(context, subnets):
        """Should be redefined for non-ipam backend only
        """
        pass

    def _validate_pools_with_subnetpool(self, subnet):
        """Verifies that allocation pools are set correctly

        Allocation pools can be set for specific subnet request only
        """
        has_allocpool = attributes.is_attr_set(subnet['allocation_pools'])
        is_any_subnetpool_request = not attributes.is_attr_set(subnet['cidr'])
        if is_any_subnetpool_request and has_allocpool:
            reason = _("allocation_pools allowed only "
                       "for specific subnet requests.")
            raise n_exc.BadRequest(resource='subnets', msg=reason)

    def _validate_ip_version_with_subnetpool(self, subnet, subnetpool):
        """Validates ip version for subnet_pool and requested subnet"""
        ip_version = subnet.get('ip_version')
        has_ip_version = attributes.is_attr_set(ip_version)
        if has_ip_version and ip_version != subnetpool.ip_version:
            args = {'req_ver': str(subnet['ip_version']),
                    'pool_ver': str(subnetpool.ip_version)}
            reason = _("Cannot allocate IPv%(req_ver)s subnet from "
                       "IPv%(pool_ver)s subnet pool") % args
            raise n_exc.BadRequest(resource='subnets', msg=reason)

    def _update_db_port(self, context, db_port, new_port, network_id, new_mac):
        # Remove all attributes in new_port which are not in the port DB model
        # and then update the port
        try:
            db_port.update(self._filter_non_model_columns(new_port,
                                                          models_v2.Port))
            context.session.flush()
        except db_exc.DBDuplicateEntry:
            raise n_exc.MacAddressInUse(net_id=network_id, mac=new_mac)

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

    def _update_subnet_allocation_pools(self, context, subnet_id, s):
        context.session.query(models_v2.IPAllocationPool).filter_by(
            subnet_id=subnet_id).delete()
        new_pools = [models_v2.IPAllocationPool(first_ip=p['start'],
                                                last_ip=p['end'],
                                                subnet_id=subnet_id)
                     for p in s['allocation_pools']]
        context.session.add_all(new_pools)
        # Call static method with self to redefine in child
        # (non-pluggable backend)
        self._rebuild_availability_ranges(context, [s])
        # Gather new pools for result:
        result_pools = [{'start': pool['start'],
                         'end': pool['end']}
                        for pool in s['allocation_pools']]
        del s['allocation_pools']
        return result_pools

    def _update_db_subnet(self, context, subnet_id, s):
        changes = {}
        if "dns_nameservers" in s:
            changes['dns_nameservers'] = (
                self._update_subnet_dns_nameservers(context, subnet_id, s))

        if "host_routes" in s:
            changes['host_routes'] = self._update_subnet_host_routes(
                context, subnet_id, s)

        if "allocation_pools" in s:
            self._validate_allocation_pools(s['allocation_pools'],
                                            s['cidr'])
            changes['allocation_pools'] = (
                self._update_subnet_allocation_pools(context, subnet_id, s))

        subnet = self._get_subnet(context, subnet_id)
        subnet.update(s)
        return subnet, changes

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

    def _prepare_allocation_pools(self, context, allocation_pools, subnet):
        if not attributes.is_attr_set(allocation_pools):
            return self._allocate_pools_for_subnet(context, subnet)

        self._validate_allocation_pools(allocation_pools, subnet['cidr'])
        if subnet['gateway_ip']:
            self._validate_gw_out_of_pools(subnet['gateway_ip'],
                                           allocation_pools)
        return allocation_pools

    def _validate_gw_out_of_pools(self, gateway_ip, pools):
        for allocation_pool in pools:
            pool_range = netaddr.IPRange(
                allocation_pool['start'],
                allocation_pool['end'])
            if netaddr.IPAddress(gateway_ip) in pool_range:
                raise n_exc.GatewayConflictWithAllocationPools(
                    pool=pool_range,
                    ip_address=gateway_ip)

    def _get_changed_ips_for_port(self, context, original_ips,
                                  new_ips, device_owner):
        """Calculate changes in IPs for the port."""
        # the new_ips contain all of the fixed_ips that are to be updated
        if len(new_ips) > cfg.CONF.max_fixed_ips_per_port:
            msg = _('Exceeded maximum amount of fixed ips per port')
            raise n_exc.InvalidInput(error_message=msg)

        # These ips are still on the port and haven't been removed
        prev_ips = []

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
        return self.Changes(add=new_ips,
                            original=prev_ips,
                            remove=original_ips)

    def _delete_port(self, context, port_id):
        query = (context.session.query(models_v2.Port).
                 enable_eagerloads(False).filter_by(id=port_id))
        if not context.is_admin:
            query = query.filter_by(tenant_id=context.tenant_id)
        query.delete()

    def _save_subnet(self, context,
                     network,
                     subnet_args,
                     dns_nameservers,
                     host_routes,
                     allocation_pools):
        allocation_pools = self._prepare_allocation_pools(context,
                                                          allocation_pools,
                                                          subnet_args)
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

        self._save_allocation_pools(context, subnet, allocation_pools)

        return subnet
