# Copyright 2022 Red Hat, Inc.
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

from pyroute2 import netlink
from pyroute2.netlink.rtnl import ifinfmsg

from neutron.privileged.agent import linux as priv_linux
from neutron.tests import base


class MakeSerializableTestCase(base.BaseTestCase):

    NLA_DATA1 = ifinfmsg.ifinfbase.state(data=b'54321')
    NLA_DATA2 = ifinfmsg.ifinfbase.state(data=b'abcdef')
    INPUT_1 = {'key1': 'value1', b'key2': b'value2', 'key3': ('a', 2),
               'key4': [1, 2, 'c'],
               b'key5': netlink.nla_slot('nla_name1', NLA_DATA1),
               'key6': netlink.nla_slot(b'nla_name2', NLA_DATA2)}
    OUTPUT_1 = {'key1': 'value1', 'key2': 'value2', 'key3': ('a', 2),
                'key4': [1, 2, 'c'],
                'key5': ['nla_name1', '54321'],
                'key6': ['nla_name2', 'abcdef']}

    def test_make_serializable(self):
        self.assertEqual(self.OUTPUT_1,
                         priv_linux.make_serializable(self.INPUT_1))
