# Copyright 2013 IBM Corp.
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

"""
IPv6-related utilities and helper functions.
"""
import netaddr
from neutron_lib import constants as const
from oslo_log import log
from oslo_utils import netutils

LOG = log.getLogger(__name__)


def is_auto_address_subnet(subnet):
    """Check if subnet is an auto address subnet."""
    modes = [const.IPV6_SLAAC, const.DHCPV6_STATELESS]
    return (subnet['ipv6_address_mode'] in modes or
            subnet['ipv6_ra_mode'] in modes)


def is_eui64_address(ip_address):
    """Check if ip address is EUI64."""
    ip = netaddr.IPAddress(ip_address)
    # '0xfffe' addition is used to build EUI-64 from MAC (RFC4291)
    # Look for it in the middle of the EUI-64 part of address
    return ip.version == 6 and not ((ip & 0xffff000000) ^ 0xfffe000000)


def is_ipv6_pd_enabled(subnet):
    """Returns True if the subnetpool_id of the given subnet is equal to
       constants.IPV6_PD_POOL_ID
    """
    return subnet.get('subnetpool_id') == const.IPV6_PD_POOL_ID


def valid_ipv6_url(host, port):
    """Given a host and a port returns a valid URL
       RFC2732 https://tools.ietf.org/html/rfc2732
       square brackets always required in ipv6 URI.
    """
    if netutils.is_valid_ipv6(host):
        uri = f'[{host}]:{port}'
    else:
        uri = f'{host}:{port}'
    return uri
