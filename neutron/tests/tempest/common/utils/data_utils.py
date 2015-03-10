# Copyright 2012 OpenStack Foundation
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
import netaddr
import random
import uuid


def rand_uuid():
    return str(uuid.uuid4())


def rand_uuid_hex():
    return uuid.uuid4().hex


def rand_name(name=''):
    randbits = str(random.randint(1, 0x7fffffff))
    if name:
        return name + '-' + randbits
    else:
        return randbits


def rand_url():
    randbits = str(random.randint(1, 0x7fffffff))
    return 'https://url-' + randbits + '.com'


def rand_int_id(start=0, end=0x7fffffff):
    return random.randint(start, end)


def rand_mac_address():
    """Generate an Ethernet MAC address."""
    # NOTE(vish): We would prefer to use 0xfe here to ensure that linux
    #             bridge mac addresses don't change, but it appears to
    #             conflict with libvirt, so we use the next highest octet
    #             that has the unicast and locally administered bits set
    #             properly: 0xfa.
    #             Discussion: https://bugs.launchpad.net/nova/+bug/921838
    mac = [0xfa, 0x16, 0x3e,
           random.randint(0x00, 0xff),
           random.randint(0x00, 0xff),
           random.randint(0x00, 0xff)]
    return ':'.join(["%02x" % x for x in mac])


def parse_image_id(image_ref):
    """Return the image id from a given image ref."""
    return image_ref.rsplit('/')[-1]


def arbitrary_string(size=4, base_text=None):
    """
    Return size characters from base_text, repeating the base_text infinitely
    if needed.
    """
    if not base_text:
        base_text = 'test'
    return ''.join(itertools.islice(itertools.cycle(base_text), size))


def random_bytes(size=1024):
    """
    Return size randomly selected bytes as a string.
    """
    return ''.join([chr(random.randint(0, 255))
                    for i in range(size)])


def get_ipv6_addr_by_EUI64(cidr, mac):
    # Check if the prefix is IPv4 address
    is_ipv4 = netaddr.valid_ipv4(cidr)
    if is_ipv4:
        msg = "Unable to generate IP address by EUI64 for IPv4 prefix"
        raise TypeError(msg)
    try:
        eui64 = int(netaddr.EUI(mac).eui64())
        prefix = netaddr.IPNetwork(cidr)
        return netaddr.IPAddress(prefix.first + eui64 ^ (1 << 57))
    except (ValueError, netaddr.AddrFormatError):
        raise TypeError('Bad prefix or mac format for generating IPv6 '
                        'address by EUI-64: %(prefix)s, %(mac)s:'
                        % {'prefix': cidr, 'mac': mac})
    except TypeError:
        raise TypeError('Bad prefix type for generate IPv6 address by '
                        'EUI-64: %s' % cidr)
