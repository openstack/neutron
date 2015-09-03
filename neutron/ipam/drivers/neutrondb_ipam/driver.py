# Copyright 2015 OpenStack LLC.
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
from oslo_log import log
from oslo_utils import uuidutils

from neutron.common import exceptions as n_exc
from neutron.common import ipv6_utils
from neutron.db import api as db_api
from neutron.i18n import _LE
from neutron.ipam import driver as ipam_base
from neutron.ipam.drivers.neutrondb_ipam import db_api as ipam_db_api
from neutron.ipam import exceptions as ipam_exc
from neutron.ipam import requests as ipam_req
from neutron.ipam import subnet_alloc
from neutron.ipam import utils as ipam_utils
from neutron import manager


LOG = log.getLogger(__name__)


class NeutronDbSubnet(ipam_base.Subnet):
    """Manage IP addresses for Neutron DB IPAM driver.

    This class implements the strategy for IP address allocation and
    deallocation for the Neutron DB IPAM driver.
    Allocation for IP addresses is based on the concept of availability
    ranges, which were already used in Neutron's DB base class for handling
    IPAM operations.
    """

    @classmethod
    def create_allocation_pools(cls, subnet_manager, session, pools, cidr):
        for pool in pools:
            # IPv6 addresses that start '::1', '::2', etc cause IP version
            # ambiguity when converted to integers by pool.first and pool.last.
            # Infer the IP version from the subnet cidr.
            ip_version = cidr.version
            subnet_manager.create_pool(
                session,
                netaddr.IPAddress(pool.first, ip_version).format(),
                netaddr.IPAddress(pool.last, ip_version).format())

    @classmethod
    def create_from_subnet_request(cls, subnet_request, ctx):
        ipam_subnet_id = uuidutils.generate_uuid()
        subnet_manager = ipam_db_api.IpamSubnetManager(
            ipam_subnet_id,
            subnet_request.subnet_id)
        # Create subnet resource
        session = ctx.session
        subnet_manager.create(session)
        # If allocation pools are not specified, define them around
        # the subnet's gateway IP
        if not subnet_request.allocation_pools:
            pools = ipam_utils.generate_pools(subnet_request.subnet_cidr,
                                              subnet_request.gateway_ip)
        else:
            pools = subnet_request.allocation_pools
        # Create IPAM allocation pools and availability ranges
        cls.create_allocation_pools(subnet_manager, session, pools,
                                    subnet_request.subnet_cidr)

        return cls(ipam_subnet_id,
                   ctx,
                   cidr=subnet_request.subnet_cidr,
                   allocation_pools=pools,
                   gateway_ip=subnet_request.gateway_ip,
                   tenant_id=subnet_request.tenant_id,
                   subnet_id=subnet_request.subnet_id)

    @classmethod
    def load(cls, neutron_subnet_id, ctx):
        """Load an IPAM subnet from the database given its neutron ID.

        :param neutron_subnet_id: neutron subnet identifier.
        """
        ipam_subnet = ipam_db_api.IpamSubnetManager.load_by_neutron_subnet_id(
            ctx.session, neutron_subnet_id)
        if not ipam_subnet:
            LOG.error(_LE("IPAM subnet referenced to "
                          "Neutron subnet %s does not exist"),
                      neutron_subnet_id)
            raise n_exc.SubnetNotFound(subnet_id=neutron_subnet_id)
        pools = []
        for pool in ipam_subnet.allocation_pools:
            pools.append(netaddr.IPRange(pool['first_ip'], pool['last_ip']))

        neutron_subnet = cls._fetch_subnet(ctx, neutron_subnet_id)

        return cls(ipam_subnet['id'],
                   ctx,
                   cidr=neutron_subnet['cidr'],
                   allocation_pools=pools,
                   gateway_ip=neutron_subnet['gateway_ip'],
                   tenant_id=neutron_subnet['tenant_id'],
                   subnet_id=neutron_subnet_id)

    @classmethod
    def _fetch_subnet(cls, context, id):
        plugin = manager.NeutronManager.get_plugin()
        return plugin._get_subnet(context, id)

    def __init__(self, internal_id, ctx, cidr=None,
                 allocation_pools=None, gateway_ip=None, tenant_id=None,
                 subnet_id=None):
        # NOTE: In theory it could have been possible to grant the IPAM
        # driver direct access to the database. While this is possible,
        # it would have led to duplicate code and/or non-trivial
        # refactorings in neutron.db.db_base_plugin_v2.
        # This is because in the Neutron V2 plugin logic DB management is
        # encapsulated within the plugin.
        self._cidr = cidr
        self._pools = allocation_pools
        self._gateway_ip = gateway_ip
        self._tenant_id = tenant_id
        self._subnet_id = subnet_id
        self.subnet_manager = ipam_db_api.IpamSubnetManager(internal_id,
                                                            self._subnet_id)
        self._context = ctx

    def _verify_ip(self, session, ip_address):
        """Verify whether IP address can be allocated on subnet.

        :param session: database session
        :param ip_address: String representing the IP address to verify
        :raises: InvalidInput, IpAddressAlreadyAllocated
        """
        # Ensure that the IP's are unique
        if not self.subnet_manager.check_unique_allocation(session,
                                                           ip_address):
            raise ipam_exc.IpAddressAlreadyAllocated(
                subnet_id=self.subnet_manager.neutron_id,
                ip=ip_address)

        # Ensure that the IP is valid on the subnet
        if not ipam_utils.check_subnet_ip(self._cidr, ip_address):
            raise ipam_exc.InvalidIpForSubnet(
                subnet_id=self.subnet_manager.neutron_id,
                ip=ip_address)

    def _allocate_specific_ip(self, session, ip_address,
                              allocation_pool_id=None):
        """Remove an IP address from subnet's availability ranges.

        This method is supposed to be called from within a database
        transaction, otherwise atomicity and integrity might not be
        enforced and the operation might result in incosistent availability
        ranges for the subnet.

        :param session: database session
        :param ip_address: ip address to mark as allocated
        :param allocation_pool_id: identifier of the allocation pool from
             which the ip address has been extracted. If not specified this
             routine will scan all allocation pools.
        :returns: list of IP ranges as instances of IPAvailabilityRange
        """
        # Return immediately for EUI-64 addresses. For this
        # class of subnets availability ranges do not apply
        if ipv6_utils.is_eui64_address(ip_address):
            return

        LOG.debug("Removing %(ip_address)s from availability ranges for "
                  "subnet id:%(subnet_id)s",
                  {'ip_address': ip_address,
                   'subnet_id': self.subnet_manager.neutron_id})
        # Netaddr's IPRange and IPSet objects work very well even with very
        # large subnets, including IPv6 ones.
        final_ranges = []
        if allocation_pool_id:
            av_ranges = self.subnet_manager.list_ranges_by_allocation_pool(
                session, allocation_pool_id, locking=True)
        else:
            av_ranges = self.subnet_manager.list_ranges_by_subnet_id(
                session, locking=True)
        for db_range in av_ranges:
            initial_ip_set = netaddr.IPSet(netaddr.IPRange(
                db_range['first_ip'], db_range['last_ip']))
            final_ip_set = initial_ip_set - netaddr.IPSet([ip_address])
            if not final_ip_set:
                # Range exhausted - bye bye
                session.delete(db_range)
                continue
            if initial_ip_set == final_ip_set:
                # IP address does not fall within the current range, move
                # to the next one
                final_ranges.append(db_range)
                continue
            for new_range in final_ip_set.iter_ipranges():
                # store new range in database
                # use netaddr.IPAddress format() method which is equivalent
                # to str(...) but also enables us to use different
                # representation formats (if needed) for IPv6.
                first_ip = netaddr.IPAddress(new_range.first)
                last_ip = netaddr.IPAddress(new_range.last)
                if (db_range['first_ip'] == first_ip.format() or
                    db_range['last_ip'] == last_ip.format()):
                    db_range['first_ip'] = first_ip.format()
                    db_range['last_ip'] = last_ip.format()
                    LOG.debug("Adjusted availability range for pool %s",
                              db_range['allocation_pool_id'])
                    final_ranges.append(db_range)
                else:
                    new_ip_range = self.subnet_manager.create_range(
                        session,
                        db_range['allocation_pool_id'],
                        first_ip.format(),
                        last_ip.format())
                    LOG.debug("Created availability range for pool %s",
                              new_ip_range['allocation_pool_id'])
                    final_ranges.append(new_ip_range)
        # Most callers might ignore this return value, which is however
        # useful for testing purposes
        LOG.debug("Availability ranges for subnet id %(subnet_id)s "
                  "modified: %(new_ranges)s",
                  {'subnet_id': self.subnet_manager.neutron_id,
                   'new_ranges': ", ".join(["[%s; %s]" %
                                            (r['first_ip'], r['last_ip']) for
                                            r in final_ranges])})
        return final_ranges

    def _rebuild_availability_ranges(self, session):
        """Rebuild availability ranges.

        This method should be called only when the availability ranges are
        exhausted or when the subnet's allocation pools are updated,
        which may trigger a deletion of the availability ranges.

        For this operation to complete successfully, this method uses a
        locking query to ensure that no IP is allocated while the regeneration
        of availability ranges is in progress.

        :param session: database session
        """
        # List all currently allocated addresses, and prevent further
        # allocations with a write-intent lock.
        # NOTE: because of this driver's logic the write intent lock is
        # probably unnecessary as this routine is called when the availability
        # ranges for a subnet are exhausted and no further address can be
        # allocated.
        # TODO(salv-orlando): devise, if possible, a more efficient solution
        # for building the IPSet to ensure decent performances even with very
        # large subnets.
        allocations = netaddr.IPSet(
            [netaddr.IPAddress(allocation['ip_address']) for
             allocation in self.subnet_manager.list_allocations(
                 session, locking=True)])

        # MEH MEH
        # There should be no need to set a write intent lock on the allocation
        # pool table. Indeed it is not important for the correctness of this
        # operation if the allocation pools are updated by another operation,
        # which will result in the generation of new availability ranges.
        # NOTE: it might be argued that an allocation pool update should in
        # theory preempt rebuilding the availability range. This is an option
        # to consider for future developments.
        LOG.debug("Rebuilding availability ranges for subnet %s",
                  self.subnet_manager.neutron_id)

        for pool in self.subnet_manager.list_pools(session):
            # Create a set of all addresses in the pool
            poolset = netaddr.IPSet(netaddr.IPRange(pool['first_ip'],
                                                    pool['last_ip']))
            # Use set difference to find free addresses in the pool
            available = poolset - allocations
            # Write the ranges to the db
            for ip_range in available.iter_ipranges():
                av_range = self.subnet_manager.create_range(
                    session,
                    pool['id'],
                    netaddr.IPAddress(ip_range.first).format(),
                    netaddr.IPAddress(ip_range.last).format())
                session.add(av_range)

    def _generate_ip(self, session):
        try:
            return self._try_generate_ip(session)
        except ipam_exc.IpAddressGenerationFailure:
            self._rebuild_availability_ranges(session)

        return self._try_generate_ip(session)

    def _try_generate_ip(self, session):
        """Generate an IP address from availability ranges."""
        ip_range = self.subnet_manager.get_first_range(session, locking=True)
        if not ip_range:
            LOG.debug("All IPs from subnet %(subnet_id)s allocated",
                      {'subnet_id': self.subnet_manager.neutron_id})
            raise ipam_exc.IpAddressGenerationFailure(
                subnet_id=self.subnet_manager.neutron_id)
        # A suitable range was found. Return IP address.
        ip_address = ip_range['first_ip']
        LOG.debug("Allocated IP - %(ip_address)s from range "
                  "[%(first_ip)s; %(last_ip)s]",
                  {'ip_address': ip_address,
                   'first_ip': ip_address,
                   'last_ip': ip_range['last_ip']})
        return ip_address, ip_range['allocation_pool_id']

    def allocate(self, address_request):
        # NOTE(salv-orlando): Creating a new db session might be a rather
        # dangerous thing to do, if executed from within another database
        # transaction. Therefore  the IPAM driver should never be
        # called from within a database transaction, which is also good
        # practice since in the general case these drivers may interact
        # with remote backends
        session = self._context.session
        all_pool_id = None
        # NOTE(salv-orlando): It would probably better to have a simpler
        # model for address requests and just check whether there is a
        # specific IP address specified in address_request
        if isinstance(address_request, ipam_req.SpecificAddressRequest):
            # This handles both specific and automatic address requests
            # Check availability of requested IP
            ip_address = str(address_request.address)
            self._verify_ip(session, ip_address)
        else:
            ip_address, all_pool_id = self._generate_ip(session)
        self._allocate_specific_ip(session, ip_address, all_pool_id)
        # Create IP allocation request object
        # The only defined status at this stage is 'ALLOCATED'.
        # More states will be available in the future - e.g.: RECYCLABLE
        self.subnet_manager.create_allocation(session, ip_address)
        return ip_address

    def deallocate(self, address):
        # This is almost a no-op because the Neutron DB IPAM driver does not
        # delete IPAllocation objects, neither rebuilds availability ranges
        # at every deallocation. The only operation it performs is to delete
        # an IPRequest entry.
        session = self._context.session

        count = self.subnet_manager.delete_allocation(
            session, address)
        # count can hardly be greater than 1, but it can be 0...
        if not count:
            raise ipam_exc.IpAddressAllocationNotFound(
                subnet_id=self.subnet_manager.neutron_id,
                ip_address=address)

    def update_allocation_pools(self, pools, cidr):
        # Pools have already been validated in the subnet request object which
        # was sent to the subnet pool driver. Further validation should not be
        # required.
        session = db_api.get_session()
        self.subnet_manager.delete_allocation_pools(session)
        self.create_allocation_pools(self.subnet_manager, session, pools, cidr)
        self._pools = pools

    def get_details(self):
        """Return subnet data as a SpecificSubnetRequest"""
        return ipam_req.SpecificSubnetRequest(
            self._tenant_id, self.subnet_manager.neutron_id,
            self._cidr, self._gateway_ip, self._pools)


class NeutronDbPool(subnet_alloc.SubnetAllocator):
    """Subnet pools backed by Neutron Database.

    As this driver does not implement yet the subnet pool concept, most
    operations are either trivial or no-ops.
    """

    def get_subnet(self, subnet_id):
        """Retrieve an IPAM subnet.

        :param subnet_id: Neutron subnet identifier
        :returns: a NeutronDbSubnet instance
        """
        return NeutronDbSubnet.load(subnet_id, self._context)

    def allocate_subnet(self, subnet_request):
        """Create an IPAMSubnet object for the provided cidr.

        This method does not actually do any operation in the driver, given
        its simplified nature.

        :param cidr: subnet's CIDR
        :returns: a NeutronDbSubnet instance
        """
        if self._subnetpool:
            subnet = super(NeutronDbPool, self).allocate_subnet(subnet_request)
            subnet_request = subnet.get_details()

        # SubnetRequest must be an instance of SpecificSubnet
        if not isinstance(subnet_request, ipam_req.SpecificSubnetRequest):
            raise ipam_exc.InvalidSubnetRequestType(
                subnet_type=type(subnet_request))
        return NeutronDbSubnet.create_from_subnet_request(subnet_request,
                                                          self._context)

    def update_subnet(self, subnet_request):
        """Update subnet info the in the IPAM driver.

        The only update subnet information the driver needs to be aware of
        are allocation pools.
        """
        if not subnet_request.subnet_id:
            raise ipam_exc.InvalidSubnetRequest(
                reason=("An identifier must be specified when updating "
                        "a subnet"))
        if not subnet_request.allocation_pools:
            LOG.debug("Update subnet request for subnet %s did not specify "
                      "new allocation pools, there is nothing to do",
                      subnet_request.subnet_id)
            return
        subnet = NeutronDbSubnet.load(subnet_request.subnet_id, self._context)
        cidr = netaddr.IPNetwork(subnet._cidr)
        subnet.update_allocation_pools(subnet_request.allocation_pools, cidr)
        return subnet

    def remove_subnet(self, subnet_id):
        """Remove data structures for a given subnet.

        IPAM-related data has no foreign key relationships to neutron subnet,
        so removing ipam subnet manually
        """
        count = ipam_db_api.IpamSubnetManager.delete(self._context.session,
                                                     subnet_id)
        if count < 1:
            LOG.error(_LE("IPAM subnet referenced to "
                          "Neutron subnet %s does not exist"),
                      subnet_id)
            raise n_exc.SubnetNotFound(subnet_id=subnet_id)
