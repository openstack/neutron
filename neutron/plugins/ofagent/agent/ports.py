# Copyright (C) 2014 VA Linux Systems Japan K.K.
# Copyright (C) 2014 YAMAMOTO Takashi <yamamoto at valinux co jp>
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

from neutron.common import constants as n_const


class OFPort(object):
    def __init__(self, port_name, ofport):
        self.port_name = port_name
        self.ofport = ofport

    @classmethod
    def from_ofp_port(cls, ofp_port):
        """Convert from ryu OFPPort."""
        return cls(port_name=ofp_port.name, ofport=ofp_port.port_no)


PORT_NAME_LEN = 14
PORT_NAME_PREFIXES = [
    n_const.TAP_DEVICE_PREFIX,  # common cases, including ovs_use_veth=True
    "qvo",  # nova hybrid interface driver
    "qr-",  # l3-agent INTERNAL_DEV_PREFIX  (ovs_use_veth=False)
    "qg-",  # l3-agent EXTERNAL_DEV_PREFIX  (ovs_use_veth=False)
]


def _is_neutron_port(name):
    """Return True if the port name looks like a neutron port."""
    if len(name) != PORT_NAME_LEN:
        return False
    for pref in PORT_NAME_PREFIXES:
        if name.startswith(pref):
            return True
    return False


def get_normalized_port_name(interface_id):
    """Convert from neutron device id (uuid) to "normalized" port name.

    This needs to be synced with ML2 plugin's _device_to_port_id().

    An assumption: The switch uses an OS's interface name as the
    corresponding OpenFlow port name.
    NOTE(yamamoto): While it's true for Open vSwitch, it isn't
    necessarily true everywhere.  For example, LINC uses something
    like "LogicalSwitch0-Port2".

    NOTE(yamamoto): The actual prefix might be different.  For example,
    with the hybrid interface driver, it's "qvo".  However, we always
    use "tap" prefix throughout the agent and plugin for simplicity.
    Some care should be taken when talking to the switch.
    """
    return (n_const.TAP_DEVICE_PREFIX + interface_id)[0:PORT_NAME_LEN]


def _normalize_port_name(name):
    """Normalize port name.

    See comments in _get_ofport_name.
    """
    for pref in PORT_NAME_PREFIXES:
        if name.startswith(pref):
            return n_const.TAP_DEVICE_PREFIX + name[len(pref):]
    return name


class Port(OFPort):
    def __init__(self, *args, **kwargs):
        super(Port, self).__init__(*args, **kwargs)
        self.vif_mac = None

    def is_neutron_port(self):
        """Return True if the port looks like a neutron port."""
        return _is_neutron_port(self.port_name)

    def normalized_port_name(self):
        return _normalize_port_name(self.port_name)
