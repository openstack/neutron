# Copyright 2016 Red Hat, Inc.
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

from neutron_lib import constants as n_const

from neutron.tests import base
from neutron.tests.common import net_helpers

ss_output = """
State      Recv-Q Send-Q        Local Address:Port          Peer Address:Port
LISTEN     0      10                127.0.0.1:6640                     *:*
LISTEN     0      128                       *:46675                    *:*
LISTEN     0      128                       *:22                       *:*
LISTEN     0      128                       *:5432                     *:*
LISTEN     0      128                       *:3260                     *:*
LISTEN     0      50                        *:3306                     *:*
ESTAB      0      36               10.0.0.202:22               10.0.0.44:45258
ESTAB      0      0                 127.0.0.1:32965            127.0.0.1:4369
ESTAB      0      0                10.0.0.202:22               10.0.0.44:36104
LISTEN     0      128                      :::80                      :::*
LISTEN     0      128                      :::4369                    :::*
LISTEN     0      128                      :::22                      :::*
LISTEN     0      128                      :::5432                    :::*
LISTEN     0      128                      :::3260                    :::*
LISTEN     0      128                      :::5672                    :::*
ESTAB      0      0          ::ffff:127.0.0.1:4369      ::ffff:127.0.0.1:32965
"""

ss_output_template = """
LISTEN     0      10                127.0.0.1:%d                     *:*
"""


class PortAllocationTestCase(base.DietTestCase):
    def test__get_source_ports_from_ss_output(self):
        result = net_helpers._get_source_ports_from_ss_output(ss_output)
        expected = {6640, 46675, 5432, 3260, 3306, 22, 32965,
                    4369, 5672, 80}
        self.assertEqual(expected, result)

    def test_get_free_namespace_port(self):
        ss_output2 = ss_output
        for p in range(1024, 32767):
            ss_output2 += ss_output_template % p

        with mock.patch('neutron.agent.linux.ip_lib.IPWrapper') \
            as ipwrapper, \
            mock.patch('neutron.agent.linux.utils.execute') as ex:
            m = mock.MagicMock()
            m.netns.execute.return_value = ss_output2
            ipwrapper.return_value = m
            local_port_range_start = 32768
            ex.return_value = "%s\t61000" % local_port_range_start
            result = net_helpers.get_free_namespace_port(
                n_const.PROTO_NAME_TCP)
            self.assertEqual((local_port_range_start - 1), result)

    def test_get_unused_port(self):
        with mock.patch('neutron.agent.linux.utils.execute') as ex:
            ex.return_value = "2048\t61000"
            result = net_helpers.get_unused_port(set(range(1025, 2048)))
            self.assertEqual(1024, result)
