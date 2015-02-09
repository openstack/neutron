#    Copyright 2014 OpenStack Foundation
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

"""iptables comments"""

# Do not translate these comments. These comments cannot contain a quote or
# an escape character because they will end up in a call to iptables and
# could interfere with other parameters.

SNAT_OUT = 'Perform source NAT on outgoing traffic.'
UNMATCH_DROP = 'Default drop rule for unmatched traffic.'
VM_INT_SG = 'Direct traffic from the VM interface to the security group chain.'
SG_TO_VM_SG = 'Jump to the VM specific chain.'
INPUT_TO_SG = 'Direct incoming traffic from VM to the security group chain.'
PAIR_ALLOW = 'Allow traffic from defined IP/MAC pairs.'
PAIR_DROP = 'Drop traffic without an IP/MAC allow rule.'
DHCP_CLIENT = 'Allow DHCP client traffic.'
DHCP_SPOOF = 'Prevent DHCP Spoofing by VM.'
UNMATCHED = 'Send unmatched traffic to the fallback chain.'
INVALID_DROP = ("Drop packets that appear related to an existing connection "
                "(e.g. TCP ACK/FIN) but do not have an entry in conntrack.")
ALLOW_ASSOC = ('Direct packets associated with a known session to the RETURN '
               'chain.')
IPV6_RA_ALLOW = 'Allow IPv6 ICMP traffic to allow RA packets.'
PORT_SEC_ACCEPT = 'Accept all packets when port security is disabled.'
