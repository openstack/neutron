# Copyright 2014 Mellanox Technologies, Ltd
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


import mock

from neutron.agent.linux import ip_link_support as ip_link
from neutron.tests import base


class TestIpLinkSupport(base.BaseTestCase):
    IP_LINK_HELP = """Usage: ip link add [link DEV] [ name ] NAME
                   [ txqueuelen PACKETS ]
                   [ address LLADDR ]
                   [ broadcast LLADDR ]
                   [ mtu MTU ] [index IDX ]
                   [ numtxqueues QUEUE_COUNT ]
                   [ numrxqueues QUEUE_COUNT ]
                   type TYPE [ ARGS ]
       ip link delete DEV type TYPE [ ARGS ]

       ip link set { dev DEVICE | group DEVGROUP } [ { up | down } ]
                          [ arp { on | off } ]
                          [ dynamic { on | off } ]
                          [ multicast { on | off } ]
                          [ allmulticast { on | off } ]
                          [ promisc { on | off } ]
                          [ trailers { on | off } ]
                          [ txqueuelen PACKETS ]
                          [ name NEWNAME ]
                          [ address LLADDR ]
                          [ broadcast LLADDR ]
                          [ mtu MTU ]
                          [ netns PID ]
                          [ netns NAME ]
                          [ alias NAME ]
                          [ vf NUM [ mac LLADDR ]
                                   [ vlan VLANID [ qos VLAN-QOS ] ]
                                   [ rate TXRATE ] ]
                                   [ spoofchk { on | off} ] ]
                                   [ state { auto | enable | disable} ] ]
                          [ master DEVICE ]
                          [ nomaster ]
       ip link show [ DEVICE | group GROUP ] [up]

TYPE := { vlan | veth | vcan | dummy | ifb | macvlan | macvtap |
          can | bridge | bond | ipoib | ip6tnl | ipip | sit |
          vxlan | gre | gretap | ip6gre | ip6gretap | vti }
    """

    IP_LINK_HELP_NO_STATE = """Usage: ip link add link DEV [ name ] NAME
                   [ txqueuelen PACKETS ]
                   [ address LLADDR ]
                   [ broadcast LLADDR ]
                   [ mtu MTU ]
                   type TYPE [ ARGS ]
       ip link delete DEV type TYPE [ ARGS ]

       ip link set DEVICE [ { up | down } ]
                          [ arp { on | off } ]
                          [ dynamic { on | off } ]
                          [ multicast { on | off } ]
                          [ allmulticast { on | off } ]
                          [ promisc { on | off } ]
                          [ trailers { on | off } ]
                          [ txqueuelen PACKETS ]
                          [ name NEWNAME ]
                          [ address LLADDR ]
                          [ broadcast LLADDR ]
                          [ mtu MTU ]
                          [ netns PID ]
                          [ alias NAME ]
                          [ vf NUM [ mac LLADDR ]
                                   [ vlan VLANID [ qos VLAN-QOS ] ]
                                   [ rate TXRATE ] ]
       ip link show [ DEVICE ]

TYPE := { vlan | veth | vcan | dummy | ifb | macvlan | can }
    """

    IP_LINK_HELP_NO_SPOOFCHK = IP_LINK_HELP_NO_STATE

    IP_LINK_HELP_NO_VF = """Usage: ip link set DEVICE { up | down |
                             arp { on | off } |
                             dynamic { on | off } |
                             multicast { on | off } |
                             allmulticast { on | off } |
                             promisc { on | off } |
                             trailers { on | off } |
                             txqueuelen PACKETS |
                             name NEWNAME |
                             address LLADDR | broadcast LLADDR |
                             mtu MTU }
       ip link show [ DEVICE ]

    """

    def _test_capability(self, capability, subcapability=None,
                         expected=True, stdout="", stderr=""):
        with mock.patch("neutron.agent.linux.utils.execute") as mock_exec:
            mock_exec.return_value = (stdout, stderr)
            vf_section = ip_link.IpLinkSupport.get_vf_mgmt_section()
            capable = ip_link.IpLinkSupport.vf_mgmt_capability_supported(
                vf_section, capability, subcapability)
            self.assertEqual(expected, capable)
            mock_exec.assert_called_once_with(['ip', 'link', 'help'],
                                              check_exit_code=False,
                                              return_stderr=True,
                                              log_fail_as_error=False)

    def test_vf_mgmt(self):
        self._test_capability(
            ip_link.IpLinkConstants.IP_LINK_CAPABILITY_STATE,
            stderr=self.IP_LINK_HELP)

    def test_execute_with_stdout(self):
        self._test_capability(
            ip_link.IpLinkConstants.IP_LINK_CAPABILITY_STATE,
            stdout=self.IP_LINK_HELP)

    def test_vf_mgmt_no_state(self):
        self._test_capability(
            ip_link.IpLinkConstants.IP_LINK_CAPABILITY_STATE,
            expected=False,
            stderr=self.IP_LINK_HELP_NO_STATE)

    def test_vf_mgmt_no_spoofchk(self):
        self._test_capability(
            ip_link.IpLinkConstants.IP_LINK_CAPABILITY_SPOOFCHK,
            expected=False,
            stderr=self.IP_LINK_HELP_NO_SPOOFCHK)

    def test_vf_mgmt_no_vf(self):
        self._test_capability(
            ip_link.IpLinkConstants.IP_LINK_CAPABILITY_STATE,
            expected=False,
            stderr=self.IP_LINK_HELP_NO_VF)

    def test_vf_mgmt_unknown_capability(self):
        self._test_capability(
            "state1",
            expected=False,
            stderr=self.IP_LINK_HELP)

    def test_vf_mgmt_sub_capability(self):
        self._test_capability(
            ip_link.IpLinkConstants.IP_LINK_CAPABILITY_VLAN,
            ip_link.IpLinkConstants.IP_LINK_SUB_CAPABILITY_QOS,
            stderr=self.IP_LINK_HELP)

    def test_vf_mgmt_sub_capability_mismatch(self):
        self._test_capability(
            ip_link.IpLinkConstants.IP_LINK_CAPABILITY_STATE,
            ip_link.IpLinkConstants.IP_LINK_SUB_CAPABILITY_QOS,
            expected=False,
            stderr=self.IP_LINK_HELP)

    def test_vf_mgmt_sub_capability_invalid(self):
        self._test_capability(
            ip_link.IpLinkConstants.IP_LINK_CAPABILITY_VLAN,
            "qos1",
            expected=False,
            stderr=self.IP_LINK_HELP)

    def test_vf_mgmt_error(self):
        with mock.patch("neutron.agent.linux.utils.execute") as mock_exec:
            mock_exec.side_effect = Exception()
            self.assertRaises(
                ip_link.UnsupportedIpLinkCommand,
                ip_link.IpLinkSupport.get_vf_mgmt_section)
