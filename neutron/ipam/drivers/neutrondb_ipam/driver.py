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

import itertools
import random

import netaddr
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import directory
from oslo_db import exception as db_exc
from oslo_log import log
from oslo_utils import uuidutils

from neutron._i18n import _
from neutron.ipam import driver as ipam_base
from neutron.ipam.drivers.neutrondb_ipam import db_api as ipam_db_api
from neutron.ipam import exceptions as ipam_exc
from neutron.ipam import requests as ipam_req
from neutron.ipam import subnet_alloc
from neutron.ipam import utils as ipam_utils


LOG = log.getLogger(__name__)


class NeutronDbSubnet(ipam_base.Subnet):
    """Manage IP addresses for Neutron DB IPAM driver.

    This class implements the strategy for IP address allocation and
    deallocation for the Neutron DB IPAM driver.
    """

    @classmethod
    def create_allocation_pools(cls, subnet_manager, context, pools, cidr):
        for pool in pools:
            # IPv6 addresses that start '::1', '::2', etc cause IP version
            # ambiguity when converted to integers by pool.first and pool.last.
            # Infer the IP version from the subnet cidr.
            ip_version = cidr.version
            subnet_manager.create_pool(
                context,
                netaddr.IPAddress(pool.first, ip_version).format(),
                netaddr.IPAddress(pool.last, ip_version).format())

    @classmethod
    def create_from_subnet_request(cls, subnet_request, ctx):
        ipam_subnet_id = uuidutils.generate_uuid()
        subnet_manager = ipam_db_api.IpamSubnetManager(
            ipam_subnet_id,
            subnet_request.subnet_id)
        # Create subnet resource
        subnet_manager.create(ctx)
        # If allocation pools are not specified, define them around
        # the subnet's gateway IP
        if not subnet_request.allocation_pools:
            pools = ipam_utils.generate_pools(subnet_request.subnet_cidr,
                                              subnet_request.gateway_ip)
        else:
            pools = subnet_request.allocation_pools
        # Create IPAM allocation pools
        cls.create_allocation_pools(subnet_manager, ctx, pools,
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
            ctx, neutron_subnet_id)
        if not ipam_subnet:
            LOG.error("IPAM subnet referenced to "
                      "Neutron subnet %s does not exist", neutron_subnet_id)
            raise n_exc.SubnetNotFound(subnet_id=neutron_subnet_id)
        pools = []
        for pool in ipam_subnet.allocation_pools:
            pools.append(netaddr.IPRange(pool['first_ip'], pool['last_ip']))

        neutron_subnet_obj = cls._fetch_subnet(ctx, neutron_subnet_id)

        return cls(ipam_subnet['id'],
                   ctx,
                   cidr=neutron_subnet_obj.cidr,
                   allocation_pools=pools,
                   gateway_ip=neutron_subnet_obj.gateway_ip,
                   tenant_id=neutron_subnet_obj.tenant_id,
                   subnet_id=neutron_subnet_id)

    @classmethod
    def _fetch_subnet(cls, context, id):
        plugin = directory.get_plugin()
        return plugin._get_subnet_object(context, id)

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

    def _verify_ip(self, context, ip_address):
        """Verify whether IP address can be allocated on subnet.

        :param context: neutron api request context
        :param ip_address: String representing the IP address to verify
        :raises: InvalidInput, IpAddressAlreadyAllocated
        """
        # Ensure that the IP's are unique
        if not self.subnet_manager.check_unique_allocation(context,
                                                           ip_address):
            raise ipam_exc.IpAddressAlreadyAllocated(
                subnet_id=self.subnet_manager.neutron_id,
                ip=ip_address)

        # Ensure that the IP is valid on the subnet
        if not ipam_utils.check_subnet_ip(self._cidr, ip_address):
            raise ipam_exc.InvalidIpForSubnet(
                subnet_id=self.subnet_manager.neutron_id,
                ip=ip_address)

    def _generate_ip(self, context, prefer_next=False):
        """Generate an IP address from the set of available addresses."""
        ip_allocations = netaddr.IPSet()
        for ipallocation in self.subnet_manager.list_allocations(context):
            ip_allocations.add(ipallocation.ip_address)

        for ip_pool in self.subnet_manager.list_pools(context):
            ip_set = netaddr.IPSet()
            ip_set.add(netaddr.IPRange(ip_pool.first_ip, ip_pool.last_ip))
            av_set = ip_set.difference(ip_allocations)
            if av_set.size == 0:
                continue

            if prefer_next:
                window = 1
            else:
                # Compute a value for the selection window
                window = min(av_set.size, 30)
            ip_index = random.randint(1, window)
            candidate_ips = list(itertools.islice(av_set, ip_index))
            allocated_ip = candidate_ips[
                random.randint(0, len(candidate_ips) - 1)]
            return str(allocated_ip), ip_pool.id

        raise ipam_exc.IpAddressGenerationFailure(
                  subnet_id=self.subnet_manager.neutron_id)

    def allocate(self, address_request):
        # NOTE(pbondar): Ipam driver is always called in context of already
        # running transaction, which is started on create_port or upper level.
        # To be able to do rollback/retry actions correctly ipam driver
        # should not create new nested transaction blocks.
        all_pool_id = None
        # NOTE(salv-orlando): It would probably better to have a simpler
        # model for address requests and just check whether there is a
        # specific IP address specified in address_request
        if isinstance(address_request, ipam_req.SpecificAddressRequest):
            # This handles both specific and automatic address requests
            # Check availability of requested IP
            ip_address = str(address_request.address)
            self._verify_ip(self._context, ip_address)
        else:
            prefer_next = isinstance(address_request,
                                     ipam_req.PreferNextAddressRequest)
            ip_address, all_pool_id = self._generate_ip(self._context,
                                                        prefer_next)

        # Create IP allocation request object
        # The only defined status at this stage is 'ALLOCATED'.
        # More states will be available in the future - e.g.: RECYCLABLE
        try:
            # TODO(ataraday): revisit this after objects switched to
            # new enginefacade
            with self._context.session.begin(subtransactions=True):
                # NOTE(kevinbenton): we use a subtransaction to force
                # a flush here so we can capture DBReferenceErrors due
                # to concurrent subnet deletions. (galera would deadlock
                # later on final commit)
                self.subnet_manager.create_allocation(self._context,
                                                      ip_address)
        except db_exc.DBReferenceError:
            raise n_exc.SubnetNotFound(
                subnet_id=self.subnet_manager.neutron_id)
        return ip_address

    def deallocate(self, address):
        # This is almost a no-op because the Neutron DB IPAM driver does not
        # delete IPAllocation objects at every deallocation. The only
        # operation it performs is to delete an IPRequest entry.
        count = self.subnet_manager.delete_allocation(
            self._context, address)
        # count can hardly be greater than 1, but it can be 0...
        if not count:
            raise ipam_exc.IpAddressAllocationNotFound(
                subnet_id=self.subnet_manager.neutron_id,
                ip_address=address)

    def _no_pool_changes(self, context, pools):
        """Check if pool updates in db are required."""
        db_pools = self.subnet_manager.list_pools(context)
        iprange_pools = [netaddr.IPRange(pool.first_ip, pool.last_ip)
                         for pool in db_pools]
        return pools == iprange_pools

    def update_allocation_pools(self, pools, cidr):
        # Pools have already been validated in the subnet request object which
        # was sent to the subnet pool driver. Further validation should not be
        # required.
        if self._no_pool_changes(self._context, pools):
            return
        self.subnet_manager.delete_allocation_pools(self._context)
        self.create_allocation_pools(self.subnet_manager, self._context, pools,
                                     cidr)
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
                reason=_("An identifier must be specified when updating "
                         "a subnet"))
        if subnet_request.allocation_pools is None:
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
        count = ipam_db_api.IpamSubnetManager.delete(self._context,
                                                     subnet_id)
        if count < 1:
            LOG.error("IPAM subnet referenced to "
                      "Neutron subnet %s does not exist", subnet_id)
            raise n_exc.SubnetNotFound(subnet_id=subnet_id)

    def needs_rollback(self):
        return False
