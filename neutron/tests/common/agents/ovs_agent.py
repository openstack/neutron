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

from neutron_lib import constants as n_const
from oslo_utils import encodeutils

from neutron.cmd.eventlet.plugins.ovs_neutron_agent import main as _main
from neutron.plugins.ml2.drivers.openvswitch.agent import ovs_neutron_agent


def get_tunnel_name_full(cls, network_type, local_ip, remote_ip):
    network_type = network_type[:3]
    # Remove length of network_type and two dashes
    hashlen = (n_const.DEVICE_NAME_MAX_LEN - len(network_type) - 2) // 2

    remote_tunnel_hash = cls.get_tunnel_hash(remote_ip, hashlen)
    if not remote_tunnel_hash:
        return None

    remote_tunnel_hash = encodeutils.to_utf8(remote_tunnel_hash)
    remote_ip_hash = hashlib.sha1(remote_tunnel_hash).hexdigest()[:hashlen]

    local_tunnel_hash = cls.get_tunnel_hash(local_ip, hashlen)
    local_tunnel_hash = encodeutils.to_utf8(local_tunnel_hash)
    source_ip_hash = hashlib.sha1(local_tunnel_hash).hexdigest()[:hashlen]

    return '%s-%s-%s' % (network_type, source_ip_hash, remote_ip_hash)

ovs_neutron_agent.OVSNeutronAgent.get_tunnel_name = get_tunnel_name_full


def main():
    _main()

if __name__ == "__main__":
    sys.exit(main())
