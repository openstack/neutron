# Copyright (c) 2017 Fujitsu Limited
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


import mock
from neutron_lib import constants
from neutron_lib import exceptions
import testtools

from neutron.privileged.agent.linux import netlink_constants as nl_constants
from neutron.privileged.agent.linux import netlink_lib as nl_lib
from neutron.tests import base

FAKE_ICMP_ENTRY = {'ipversion': 4, 'protocol': 'icmp',
                   'type': '8', 'code': '0', 'id': 1234,
                   'src': '1.1.1.1', 'dst': '2.2.2.2', 'zone': 1}
FAKE_TCP_ENTRY = {'ipversion': 4, 'protocol': 'tcp',
                  'sport': 1, 'dport': 2,
                  'src': '1.1.1.1', 'dst': '2.2.2.2', 'zone': 1}
FAKE_UDP_ENTRY = {'ipversion': 4, 'protocol': 'udp',
                  'sport': 1, 'dport': 2,
                  'src': '1.1.1.1', 'dst': '2.2.2.2', 'zone': 1}


class NetlinkLibTestCase(base.BaseTestCase):
    def setUp(self):
        super(NetlinkLibTestCase, self).setUp()
        nl_lib.nfct = mock.Mock()
        nl_lib.libc = mock.Mock()

    def test_open_new_conntrack_handler_failed(self):
        nl_lib.nfct.nfct_open.return_value = None
        with testtools.ExpectedException(exceptions.CTZoneExhaustedError):
            with nl_lib.ConntrackManager():
                nl_lib.nfct.nfct_open.assert_called_once_with()
            nl_lib.nfct.nfct_close.assert_not_called()

    def test_open_new_conntrack_handler_pass(self):
        with nl_lib.ConntrackManager():
            nl_lib.nfct.nfct_open.assert_called_once_with(
                nl_constants.NFNL_SUBSYS_CTNETLINK, nl_constants.CONNTRACK)
        nl_lib.nfct.nfct_close.assert_called_once_with(nl_lib.nfct.nfct_open(
            nl_constants.NFNL_SUBSYS_CTNETLINK, nl_constants.CONNTRACK))

    def test_conntrack_list_entries(self):
        with nl_lib.ConntrackManager() as conntrack:

            nl_lib.nfct.nfct_open.assert_called_once_with(
                nl_constants.NFNL_SUBSYS_CTNETLINK, nl_constants.CONNTRACK)

            conntrack.list_entries()

            nl_lib.nfct.nfct_callback_register.assert_has_calls(
                [mock.call(nl_lib.nfct.nfct_open(), nl_constants.NFCT_T_ALL,
                 mock.ANY, None)])
            nl_lib.nfct.nfct_query.assert_called_once_with(
                nl_lib.nfct.nfct_open(
                    nl_constants.NFNL_SUBSYS_CTNETLINK,
                    nl_constants.CONNTRACK),
                nl_constants.NFCT_Q_DUMP,
                mock.ANY)
        nl_lib.nfct.nfct_close.assert_called_once_with(nl_lib.nfct.nfct_open(
            nl_constants.NFNL_SUBSYS_CTNETLINK, nl_constants.CONNTRACK))

    def test_conntrack_new_failed(self):
        nl_lib.nfct.nfct_new.return_value = None
        with nl_lib.ConntrackManager() as conntrack:
            nl_lib.nfct.nfct_open.assert_called_once_with(
                nl_constants.NFNL_SUBSYS_CTNETLINK,
                nl_constants.CONNTRACK)
            conntrack.delete_entries([FAKE_ICMP_ENTRY])
            nl_lib.nfct.nfct_new.assert_called_once_with()
        nl_lib.nfct.nfct_destroy.assert_called_once_with(None)
        nl_lib.nfct.nfct_close.assert_called_once_with(nl_lib.nfct.nfct_open(
            nl_constants.NFNL_SUBSYS_CTNETLINK,
            nl_constants.CONNTRACK))

    def test_conntrack_delete_icmp_entry(self):
        conntrack_filter = mock.Mock()
        nl_lib.nfct.nfct_new.return_value = conntrack_filter
        with nl_lib.ConntrackManager() as conntrack:
            nl_lib.nfct.nfct_open.assert_called_once_with(
                nl_constants.NFNL_SUBSYS_CTNETLINK,
                nl_constants.CONNTRACK)
            conntrack.delete_entries([FAKE_ICMP_ENTRY])
            calls = [
                mock.call(conntrack_filter,
                          nl_constants.ATTR_L3PROTO,
                          nl_constants.IPVERSION_SOCKET[4]),
                mock.call(conntrack_filter,
                          nl_constants.ATTR_L4PROTO,
                          constants.IP_PROTOCOL_MAP['icmp']),
                mock.call(conntrack_filter,
                          nl_constants.ATTR_ICMP_CODE,
                          int(FAKE_ICMP_ENTRY['code'])),
                mock.call(conntrack_filter,
                          nl_constants.ATTR_ICMP_TYPE,
                          int(FAKE_ICMP_ENTRY['type']))
            ]
            nl_lib.nfct.nfct_set_attr_u8.assert_has_calls(calls,
                                                          any_order=True)
            calls = [
                mock.call(conntrack_filter,
                          nl_constants.ATTR_ICMP_ID,
                          nl_lib.libc.htons(FAKE_ICMP_ENTRY['id'])),
                mock.call(conntrack_filter,
                          nl_constants.ATTR_ZONE,
                          int(FAKE_ICMP_ENTRY['zone']))
            ]
            nl_lib.nfct.nfct_set_attr_u16.assert_has_calls(calls,
                                                           any_order=True)
            calls = [
                mock.call(conntrack_filter,
                          nl_constants.ATTR_IPV4_SRC,
                          conntrack._convert_text_to_binary(
                              FAKE_ICMP_ENTRY['src'], 4)
                          ),
                mock.call(conntrack_filter,
                          nl_constants.ATTR_IPV4_DST,
                          conntrack._convert_text_to_binary(
                              FAKE_ICMP_ENTRY['dst'], 4)
                          ),
            ]
            nl_lib.nfct.nfct_set_attr.assert_has_calls(calls, any_order=True)
            nl_lib.nfct.nfct_destroy.assert_called_once_with(conntrack_filter)
        nl_lib.nfct.nfct_close.assert_called_once_with(nl_lib.nfct.nfct_open(
            nl_constants.NFNL_SUBSYS_CTNETLINK,
            nl_constants.CONNTRACK))

    def test_conntrack_delete_udp_entry(self):
        conntrack_filter = mock.Mock()
        nl_lib.nfct.nfct_new.return_value = conntrack_filter
        with nl_lib.ConntrackManager() as conntrack:
            nl_lib.nfct.nfct_open.assert_called_once_with(
                nl_constants.NFNL_SUBSYS_CTNETLINK,
                nl_constants.CONNTRACK)
            conntrack.delete_entries([FAKE_UDP_ENTRY])
            calls = [
                mock.call(conntrack_filter,
                          nl_constants.ATTR_L3PROTO,
                          nl_constants.IPVERSION_SOCKET[4]),
                mock.call(conntrack_filter,
                          nl_constants.ATTR_L4PROTO,
                          constants.IP_PROTOCOL_MAP['udp'])
            ]
            nl_lib.nfct.nfct_set_attr_u8.assert_has_calls(calls,
                                                          any_order=True)
            calls = [
                mock.call(conntrack_filter,
                          nl_constants.ATTR_PORT_SRC,
                          nl_lib.libc.htons(FAKE_UDP_ENTRY['sport'])),
                mock.call(conntrack_filter,
                          nl_constants.ATTR_PORT_DST,
                          nl_lib.libc.htons(FAKE_UDP_ENTRY['dport'])),
                mock.call(conntrack_filter,
                          nl_constants.ATTR_ZONE,
                          int(FAKE_ICMP_ENTRY['zone']))
            ]
            nl_lib.nfct.nfct_set_attr_u16.assert_has_calls(calls,
                                                           any_order=True)
            calls = [
                mock.call(conntrack_filter,
                          nl_constants.ATTR_IPV4_SRC,
                          conntrack._convert_text_to_binary(
                              FAKE_UDP_ENTRY['src'], 4)
                          ),
                mock.call(conntrack_filter,
                          nl_constants.ATTR_IPV4_DST,
                          conntrack._convert_text_to_binary(
                              FAKE_UDP_ENTRY['dst'], 4)
                          ),
            ]
            nl_lib.nfct.nfct_set_attr.assert_has_calls(calls, any_order=True)
            nl_lib.nfct.nfct_destroy.assert_called_once_with(conntrack_filter)
        nl_lib.nfct.nfct_close.assert_called_once_with(nl_lib.nfct.nfct_open(
            nl_constants.NFNL_SUBSYS_CTNETLINK,
            nl_constants.CONNTRACK))

    def test_conntrack_delete_tcp_entry(self):
        conntrack_filter = mock.Mock()
        nl_lib.nfct.nfct_new.return_value = conntrack_filter
        with nl_lib.ConntrackManager() as conntrack:
            nl_lib.nfct.nfct_open.assert_called_once_with(
                nl_constants.NFNL_SUBSYS_CTNETLINK,
                nl_constants.CONNTRACK)
            conntrack.delete_entries([FAKE_TCP_ENTRY])
            calls = [
                mock.call(conntrack_filter,
                          nl_constants.ATTR_L3PROTO,
                          nl_constants.IPVERSION_SOCKET[4]),
                mock.call(conntrack_filter,
                          nl_constants.ATTR_L4PROTO,
                          constants.IP_PROTOCOL_MAP['tcp'])
            ]
            nl_lib.nfct.nfct_set_attr_u8.assert_has_calls(calls,
                                                          any_order=True)
            calls = [
                mock.call(conntrack_filter,
                          nl_constants.ATTR_PORT_SRC,
                          nl_lib.libc.htons(FAKE_TCP_ENTRY['sport'])),
                mock.call(conntrack_filter,
                          nl_constants.ATTR_PORT_DST,
                          nl_lib.libc.htons(FAKE_TCP_ENTRY['dport'])),
                mock.call(conntrack_filter,
                          nl_constants.ATTR_ZONE,
                          int(FAKE_ICMP_ENTRY['zone']))
            ]
            nl_lib.nfct.nfct_set_attr_u16.assert_has_calls(calls,
                                                           any_order=True)
            calls = [
                mock.call(conntrack_filter,
                          nl_constants.ATTR_IPV4_SRC,
                          conntrack._convert_text_to_binary(
                              FAKE_TCP_ENTRY['src'], 4)
                          ),
                mock.call(conntrack_filter,
                          nl_constants.ATTR_IPV4_DST,
                          conntrack._convert_text_to_binary(
                              FAKE_TCP_ENTRY['dst'], 4)
                          ),
            ]

            nl_lib.nfct.nfct_set_attr.assert_has_calls(calls, any_order=True)
            nl_lib.nfct.nfct_destroy.assert_called_once_with(conntrack_filter)
        nl_lib.nfct.nfct_close.assert_called_once_with(nl_lib.nfct.nfct_open(
            nl_constants.NFNL_SUBSYS_CTNETLINK,
            nl_constants.CONNTRACK))

    def test_conntrack_delete_entries(self):
        conntrack_filter = mock.Mock()
        nl_lib.nfct.nfct_new.return_value = conntrack_filter
        with nl_lib.ConntrackManager() as conntrack:
            nl_lib.nfct.nfct_open.assert_called_once_with(
                nl_constants.NFNL_SUBSYS_CTNETLINK,
                nl_constants.CONNTRACK)
            conntrack.delete_entries([FAKE_ICMP_ENTRY,
                                      FAKE_TCP_ENTRY,
                                      FAKE_UDP_ENTRY])
            calls = [
                mock.call(conntrack_filter,
                          nl_constants.ATTR_L3PROTO,
                          nl_constants.IPVERSION_SOCKET[4]),
                mock.call(conntrack_filter,
                          nl_constants.ATTR_L4PROTO,
                          constants.IP_PROTOCOL_MAP['tcp']),
                mock.call(conntrack_filter,
                          nl_constants.ATTR_L3PROTO,
                          nl_constants.IPVERSION_SOCKET[4]),
                mock.call(conntrack_filter,
                          nl_constants.ATTR_L4PROTO,
                          constants.IP_PROTOCOL_MAP['udp']),
                mock.call(conntrack_filter,
                          nl_constants.ATTR_L3PROTO,
                          nl_constants.IPVERSION_SOCKET[4]),
                mock.call(conntrack_filter,
                          nl_constants.ATTR_L4PROTO,
                          constants.IP_PROTOCOL_MAP['icmp']),
                mock.call(conntrack_filter,
                          nl_constants.ATTR_ICMP_CODE,
                          int(FAKE_ICMP_ENTRY['code'])),
                mock.call(conntrack_filter,
                          nl_constants.ATTR_ICMP_TYPE,
                          int(FAKE_ICMP_ENTRY['type']))
            ]
            nl_lib.nfct.nfct_set_attr_u8.assert_has_calls(calls,
                                                          any_order=True)
            calls = [
                mock.call(conntrack_filter,
                          nl_constants.ATTR_PORT_SRC,
                          nl_lib.libc.htons(FAKE_TCP_ENTRY['sport'])),
                mock.call(conntrack_filter,
                          nl_constants.ATTR_PORT_DST,
                          nl_lib.libc.htons(FAKE_TCP_ENTRY['dport'])),
                mock.call(conntrack_filter,
                          nl_constants.ATTR_ZONE,
                          int(FAKE_TCP_ENTRY['zone'])),
                mock.call(conntrack_filter,
                          nl_constants.ATTR_PORT_SRC,
                          nl_lib.libc.htons(FAKE_UDP_ENTRY['sport'])),
                mock.call(conntrack_filter,
                          nl_constants.ATTR_PORT_DST,
                          nl_lib.libc.htons(FAKE_UDP_ENTRY['dport'])),
                mock.call(conntrack_filter,
                          nl_constants.ATTR_ZONE,
                          int(FAKE_UDP_ENTRY['zone'])),
                mock.call(conntrack_filter,
                          nl_constants.ATTR_ICMP_ID,
                          nl_lib.libc.htons(FAKE_ICMP_ENTRY['id'])),
                mock.call(conntrack_filter,
                          nl_constants.ATTR_ZONE,
                          int(FAKE_ICMP_ENTRY['zone']))
            ]
            nl_lib.nfct.nfct_set_attr_u16.assert_has_calls(calls,
                                                           any_order=True)
            calls = [
                mock.call(conntrack_filter,
                          nl_constants.ATTR_IPV4_SRC,
                          conntrack._convert_text_to_binary(
                              FAKE_TCP_ENTRY['src'], 4)
                          ),
                mock.call(conntrack_filter,
                          nl_constants.ATTR_IPV4_DST,
                          conntrack._convert_text_to_binary(
                              FAKE_TCP_ENTRY['dst'], 4)),
                mock.call(conntrack_filter,
                          nl_constants.ATTR_IPV4_SRC,
                          conntrack._convert_text_to_binary(
                              FAKE_UDP_ENTRY['src'], 4)
                          ),
                mock.call(conntrack_filter,
                          nl_constants.ATTR_IPV4_DST,
                          conntrack._convert_text_to_binary(
                              FAKE_UDP_ENTRY['dst'], 4)
                          ),
                mock.call(conntrack_filter,
                          nl_constants.ATTR_IPV4_SRC,
                          conntrack._convert_text_to_binary(
                              FAKE_ICMP_ENTRY['src'], 4)
                          ),
                mock.call(conntrack_filter,
                          nl_constants.ATTR_IPV4_DST,
                          conntrack._convert_text_to_binary(
                              FAKE_ICMP_ENTRY['dst'], 4)
                          ),
            ]
            nl_lib.nfct.nfct_set_attr.assert_has_calls(calls, any_order=True)
            nl_lib.nfct.nfct_destroy.assert_called_once_with(conntrack_filter)
        nl_lib.nfct.nfct_close.assert_called_once_with(nl_lib.nfct.nfct_open(
            nl_constants.NFNL_SUBSYS_CTNETLINK,
            nl_constants.CONNTRACK))
