# Copyright 2026 OpenStack Foundation
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

"""Helpers that are safe to import from neutron.privileged.

Every module neutron.privileged imports stays resident in each privsep
daemon, so keep the imports here light. In particular, do not import
neutron.common.utils, which pulls in the DB, API and SDK layers.
"""

import netaddr
from neutron_lib import constants as n_const


def cidr_broadcast_address(cidr):
    """Returns the broadcast address of a cidr

    :param cidr: (string, netaddr.IPNetwork, netaddr.IPAddress) either an ipv4
                 or ipv6 cidr or a host IP.
    :returns: (string) broadcast address of the cidr, None if the cidr has no
              broadcast domain
    """
    broadcast = netaddr.IPNetwork(cidr).broadcast
    if broadcast:
        return str(broadcast)


def cidr_broadcast_address_alternative(cidr):
    """Wraps cidr_broadcast address and handles last cidr differently in
    respect to netaddr

    :param cidr: (string, netaddr.IPNetwork, netaddr.IPAddress) either an ipv4
                 or ipv6 cidr.
    :returns: (string) broadcast address of the cidr,
              IP of the cidr if IPv4 /32 CIDR, otherwise None
    """
    broadcast = cidr_broadcast_address(cidr)
    if broadcast:
        return str(broadcast)
    net = netaddr.IPNetwork(cidr)
    if net.prefixlen == 32 and net.version == n_const.IP_VERSION_4:
        return str(net.ip)
    # NOTE(mtomaska): netaddr ver >= 0.9.0 will start returning None
    # for IPv6 cidr /127 /128


def read_file(path: str) -> str:
    """Return the content of a text file as a string

    The output includes the empty lines too. If the file does not exist,
    returns an empty string.
    """
    try:
        with open(path) as file:
            return file.read()
    except FileNotFoundError:
        return ''
