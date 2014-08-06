# Copyright 2013 VMware, Inc.
# All Rights Reserved
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

import hashlib

from neutron.api.v2 import attributes
from neutron.openstack.common import log
from neutron import version


LOG = log.getLogger(__name__)
MAX_DISPLAY_NAME_LEN = 40
NEUTRON_VERSION = version.version_info.release_string()


# Allowed network types for the NSX Plugin
class NetworkTypes:
    """Allowed provider network types for the NSX Plugin."""
    L3_EXT = 'l3_ext'
    STT = 'stt'
    GRE = 'gre'
    FLAT = 'flat'
    VLAN = 'vlan'
    BRIDGE = 'bridge'


def get_tags(**kwargs):
    tags = ([dict(tag=value, scope=key)
            for key, value in kwargs.iteritems()])
    tags.append({"tag": NEUTRON_VERSION, "scope": "quantum"})
    return sorted(tags)


def device_id_to_vm_id(device_id, obfuscate=False):
    # device_id can be longer than 40 characters, for example
    # a device_id for a dhcp port is like the following:
    #
    # dhcp83b5fdeb-e3b4-5e18-ac5f-55161...80747326-47d7-46c2-a87a-cf6d5194877c
    #
    # To fit it into an NSX tag we need to hash it, however device_id
    # used for ports associated to VM's are small enough so let's skip the
    # hashing
    if len(device_id) > MAX_DISPLAY_NAME_LEN or obfuscate:
        return hashlib.sha1(device_id).hexdigest()
    else:
        return device_id


def check_and_truncate(display_name):
    if (attributes.is_attr_set(display_name) and
            len(display_name) > MAX_DISPLAY_NAME_LEN):
        LOG.debug(_("Specified name:'%s' exceeds maximum length. "
                    "It will be truncated on NSX"), display_name)
        return display_name[:MAX_DISPLAY_NAME_LEN]
    return display_name or ''
