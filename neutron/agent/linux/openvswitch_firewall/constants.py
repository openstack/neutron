# Copyright 2015
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

from neutron.common import constants

OF_STATE_NOT_TRACKED = "-trk"
OF_STATE_ESTABLISHED = "+trk+est-rel-inv"
OF_STATE_RELATED = "+trk+rel-est-inv"
OF_STATE_INVALID = "+trk+inv"

protocol_to_nw_proto = {
        constants.PROTO_NAME_ICMP: constants.PROTO_NUM_ICMP,
        constants.PROTO_NAME_TCP: constants.PROTO_NUM_TCP,
        constants.PROTO_NAME_UDP: constants.PROTO_NUM_UDP,
}

PROTOCOLS_WITH_PORTS = (constants.PROTO_NAME_TCP, constants.PROTO_NAME_UDP)

ethertype_to_dl_type_map = {
    constants.IPv4: constants.ETHERTYPE_IP,
    constants.IPv6: constants.ETHERTYPE_IPV6,
}
