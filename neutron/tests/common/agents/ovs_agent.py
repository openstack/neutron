#!/usr/bin/env python
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
import sys


from neutron.cmd.eventlet.plugins.ovs_neutron_agent import main as _main
from neutron.common import constants as n_const
from neutron.plugins.ml2.drivers.openvswitch.agent.ovs_neutron_agent \
    import OVSNeutronAgent


def get_tunnel_name_full(cls, network_type, local_ip, remote_ip):
    network_type = network_type[:3]
    remote_ip_hex = cls.get_ip_in_hex(remote_ip)
    if not remote_ip_hex:
        return None

    # Remove length of network_type and two dashes
    hashlen = (n_const.DEVICE_NAME_MAX_LEN - len(network_type) - 2) // 2
    remote_ip_hex = remote_ip_hex.encode('utf-8')
    remote_ip_hash = hashlib.sha1(remote_ip_hex).hexdigest()[0:hashlen]
    local_ip_hex = cls.get_ip_in_hex(local_ip).encode('utf-8')
    source_ip_hash = hashlib.sha1(local_ip_hex).hexdigest()[0:hashlen]
    return '%s-%s-%s' % (network_type, source_ip_hash, remote_ip_hash)

OVSNeutronAgent.get_tunnel_name = get_tunnel_name_full


def main():
    _main()

if __name__ == "__main__":
    sys.exit(main())
