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


def check_subnet_ip(cidr, ip_address):
    """Validate that the IP address is on the subnet."""
    ip = netaddr.IPAddress(ip_address)
    net = netaddr.IPNetwork(cidr)
    # Check that the IP is valid on subnet. This cannot be the
    # network or the broadcast address
    return (ip != net.network and ip != net.broadcast
            and net.netmask & ip == net.network)


def generate_pools(cidr, gateway_ip):
    """Create IP allocation pools for a specified subnet

    The Neutron API defines a subnet's allocation pools as a list of
    IPRange objects for defining the pool range.
    """
    pools = []
    # Auto allocate the pool around gateway_ip
    net = netaddr.IPNetwork(cidr)
    first_ip = net.first + 1
    last_ip = net.last - 1
    gw_ip = int(netaddr.IPAddress(gateway_ip or net.last))
    # Use the gw_ip to find a point for splitting allocation pools
    # for this subnet
    split_ip = min(max(gw_ip, net.first), net.last)
    if split_ip > first_ip:
        pools.append(netaddr.IPRange(first_ip, split_ip - 1))
    if split_ip < last_ip:
        pools.append(netaddr.IPRange(split_ip + 1, last_ip))
    return pools
