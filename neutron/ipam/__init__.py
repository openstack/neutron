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

import abc
import netaddr

import six

from neutron.common import constants


@six.add_metaclass(abc.ABCMeta)
class SubnetPool(object):
    """Represents a pool of IPs available inside an address scope."""


@six.add_metaclass(abc.ABCMeta)
class SubnetRequest(object):
    """Carries the data needed to make a subnet request

    The data validated and carried by an instance of this class is the data
    that is common to any type of request.  This class shouldn't be
    instantiated on its own.  Rather, a subclass of this class should be used.
    """
    def __init__(self, tenant_id, subnet_id,
                 gateway_ip=None, allocation_pools=None):
        """Initialize and validate

        :param tenant_id: The tenant id who will own the subnet
        :type tenant_id: str uuid
        :param subnet_id: Neutron's subnet id
        :type subnet_id: str uuid
        :param gateway_ip: An IP to reserve for the subnet gateway.
        :type gateway_ip: None or convertible to netaddr.IPAddress
        :param allocation_pools: The pool from which IPAM should allocate
            addresses.   The allocator *may* allow allocating addresses outside
            of this range if specifically requested.
        :type allocation_pools: A list of netaddr.IPRange.  None if not
            specified.
        """
        self._tenant_id = tenant_id
        self._subnet_id = subnet_id
        self._gateway_ip = None
        self._allocation_pools = None

        if gateway_ip is not None:
            self._gateway_ip = netaddr.IPAddress(gateway_ip)

        if allocation_pools is not None:
            allocation_pools = sorted(allocation_pools)
            previous = None
            for pool in allocation_pools:
                if not isinstance(pool, netaddr.ip.IPRange):
                    raise TypeError("Ranges must be netaddr.IPRange")
                if previous and pool.first <= previous.last:
                    raise ValueError("Ranges must not overlap")
                previous = pool
            if 1 < len(allocation_pools):
                # Checks that all the ranges are in the same IP version.
                # IPRange sorts first by ip version so we can get by with just
                # checking the first and the last range having sorted them
                # above.
                first_version = allocation_pools[0].version
                last_version = allocation_pools[-1].version
                if first_version != last_version:
                    raise ValueError("Ranges must be in the same IP version")
            self._allocation_pools = allocation_pools

        if self.gateway_ip and self.allocation_pools:
            if self.gateway_ip.version != self.allocation_pools[0].version:
                raise ValueError("Gateway IP version inconsistent with "
                                 "allocation pool version")

    @property
    def tenant_id(self):
        return self._tenant_id

    @property
    def subnet_id(self):
        return self._subnet_id

    @property
    def gateway_ip(self):
        return self._gateway_ip

    @property
    def allocation_pools(self):
        return self._allocation_pools

    def _validate_with_subnet(self, subnet):
        if self.gateway_ip:
            if self.gateway_ip not in subnet:
                raise ValueError("gateway_ip is not in the subnet")

        if self.allocation_pools:
            if subnet.version != self.allocation_pools[0].version:
                raise ValueError("allocation_pools use the wrong ip version")
            for pool in self.allocation_pools:
                if pool not in subnet:
                    raise ValueError("allocation_pools are not in the subnet")


class AnySubnetRequest(SubnetRequest):
    """A template for allocating an unspecified subnet from IPAM

    A driver may not implement this type of request.  For example, The initial
    reference implementation will not support this.  The API has no way of
    creating a subnet without a specific address until subnet-allocation is
    implemented.
    """
    WILDCARDS = {constants.IPv4: '0.0.0.0',
                 constants.IPv6: '::'}

    def __init__(self, tenant_id, subnet_id, version, prefixlen,
                 gateway_ip=None, allocation_pools=None):
        """
        :param version: Either constants.IPv4 or constants.IPv6
        :param prefixlen: The prefix len requested.  Must be within the min and
            max allowed.
        :type prefixlen: int
        """
        super(AnySubnetRequest, self).__init__(
            tenant_id=tenant_id,
            subnet_id=subnet_id,
            gateway_ip=gateway_ip,
            allocation_pools=allocation_pools)

        net = netaddr.IPNetwork(self.WILDCARDS[version] + '/' + str(prefixlen))
        self._validate_with_subnet(net)

        self._prefixlen = prefixlen

    @property
    def prefixlen(self):
        return self._prefixlen


class SpecificSubnetRequest(SubnetRequest):
    """A template for allocating a specified subnet from IPAM

    The initial reference implementation will probably just allow any
    allocation, even overlapping ones.  This can be expanded on by future
    blueprints.
    """
    def __init__(self, tenant_id, subnet_id, subnet,
                 gateway_ip=None, allocation_pools=None):
        """
        :param subnet: The subnet requested.  Can be IPv4 or IPv6.  However,
            when IPAM tries to fulfill this request, the IP version must match
            the version of the address scope being used.
        :type subnet: netaddr.IPNetwork or convertible to one
        """
        super(SpecificSubnetRequest, self).__init__(
            tenant_id=tenant_id,
            subnet_id=subnet_id,
            gateway_ip=gateway_ip,
            allocation_pools=allocation_pools)

        self._subnet = netaddr.IPNetwork(subnet)
        self._validate_with_subnet(self._subnet)

    @property
    def subnet(self):
        return self._subnet

    @property
    def prefixlen(self):
        return self._subnet.prefixlen


@six.add_metaclass(abc.ABCMeta)
class AddressRequest(object):
    """Abstract base class for address requests"""


class SpecificAddressRequest(AddressRequest):
    """For requesting a specified address from IPAM"""
    def __init__(self, address):
        """
        :param address: The address being requested
        :type address: A netaddr.IPAddress or convertible to one.
        """
        super(SpecificAddressRequest, self).__init__()
        self._address = netaddr.IPAddress(address)

    @property
    def address(self):
        return self._address


class AnyAddressRequest(AddressRequest):
    """Used to request any available address from the pool."""


class RouterGatewayAddressRequest(AddressRequest):
    """Used to request allocating the special router gateway address."""
