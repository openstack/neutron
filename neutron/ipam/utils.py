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
from neutron_lib import constants


def check_subnet_ip(cidr, ip_address):
    """Validate that the IP address is on the subnet."""
    ip = netaddr.IPAddress(ip_address)
    net = netaddr.IPNetwork(cidr)
    # Check that the IP is valid on subnet. This cannot be the
    # network or the broadcast address (which exists only in IPv4)
    return (ip != net.network and
            (net.version == 6 or ip != net[-1]) and
            net.netmask & ip == net.network)


def check_gateway_invalid_in_subnet(cidr, gateway):
    """Check whether the gw IP address is invalid on the subnet."""
    ip = netaddr.IPAddress(gateway)
    net = netaddr.IPNetwork(cidr)
    # Check whether the gw IP is in-valid on subnet.
    # If gateway is in the subnet, it cannot be the
    # 'network' or the 'broadcast address (only in IPv4)'.
    # If gateway is out of subnet, there is no way to
    # check since we don't have gateway's subnet cidr.
    return (ip in net and
            (ip == net.network or
             (net.version == constants.IP_VERSION_4 and ip == net[-1])))


def generate_pools(cidr, gateway_ip):
    """Create IP allocation pools for a specified subnet

    The Neutron API defines a subnet's allocation pools as a list of
    IPRange objects for defining the pool range.
    """
    # Auto allocate the pool around gateway_ip
    net = netaddr.IPNetwork(cidr)
    ip_version = net.version
    first = netaddr.IPAddress(net.first, ip_version)
    last = netaddr.IPAddress(net.last, ip_version)
    if first == last:
        # handle single address subnet case
        return [netaddr.IPRange(first, last)]
    first_ip = first + 1
    # last address is broadcast in v4
    last_ip = last - (ip_version == 4)
    if first_ip >= last_ip:
        # /31 lands here
        return []
    ipset = netaddr.IPSet(netaddr.IPRange(first_ip, last_ip))
    if gateway_ip:
        ipset.remove(netaddr.IPAddress(gateway_ip, ip_version))
    return list(ipset.iter_ipranges())
