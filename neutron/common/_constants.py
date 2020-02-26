# Copyright (c) 2012 OpenStack Foundation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from neutron_lib import constants

# NOTE(boden): This module is common constants for neutron only.
# Any constants used outside of neutron should go into neutron-lib.


# Security group protocols that support ports
SG_PORT_PROTO_NUMS = [
    constants.PROTO_NUM_DCCP,
    constants.PROTO_NUM_SCTP,
    constants.PROTO_NUM_TCP,
    constants.PROTO_NUM_UDP,
    constants.PROTO_NUM_UDPLITE
]

SG_PORT_PROTO_NAMES = [
    constants.PROTO_NAME_DCCP,
    constants.PROTO_NAME_SCTP,
    constants.PROTO_NAME_TCP,
    constants.PROTO_NAME_UDP,
    constants.PROTO_NAME_UDPLITE
]

# iptables protocols that only support --dport and --sport using -m multiport
IPTABLES_MULTIPORT_ONLY_PROTOCOLS = [
    constants.PROTO_NAME_UDPLITE
]

# Segmentation ID pool; DB select limit to improve the performace.
IDPOOL_SELECT_SIZE = 100
