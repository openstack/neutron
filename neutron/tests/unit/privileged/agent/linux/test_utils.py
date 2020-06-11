# Copyright 2020 Red Hat, Inc.
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

from unittest import mock

from oslo_concurrency import processutils

from neutron.privileged.agent.linux import utils as priv_utils
from neutron.tests import base


NETSTAT_NETNS_OUTPUT = ("""
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State\
       PID/Program name
tcp        0      0 0.0.0.0:9697            0.0.0.0:*               LISTEN\
      1347/python
raw        0      0 0.0.0.0:112             0.0.0.0:*               7\
           1279/keepalived
raw        0      0 0.0.0.0:112             0.0.0.0:*               7\
           1279/keepalived
raw6       0      0 :::58                   :::*                    7\
           1349/radvd
Active UNIX domain sockets (only servers)
Proto RefCnt Flags       Type       State         I-Node   PID/Program name\
     Path
unix  2      [ ACC ]     STREAM     LISTENING     82039530 1353/python\
          /tmp/rootwrap-VKSm8a/rootwrap.sock
""")

NETSTAT_NO_NAMESPACE = ("""
Cannot open network namespace "qrouter-e6f206b2-4e8d-4597-a7e1-c3a20337e9c6":\
 No such file or directory
""")

NETSTAT_NO_LISTEN_PROCS = ("""
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State\
       PID/Program name
Active UNIX domain sockets (only servers)
Proto RefCnt Flags       Type       State         I-Node   PID/Program name\
     Path
""")


class FindListenPidsNamespaceTestCase(base.BaseTestCase):

    def _test_find_listen_pids_namespace_helper(self, expected,
                                                netstat_output=None):
        with mock.patch.object(processutils, 'execute') as mock_execute:
            mock_execute.return_value = (netstat_output, mock.ANY)
            observed = priv_utils._find_listen_pids_namespace(mock.ANY)
            self.assertEqual(sorted(expected), sorted(observed))

    def test_find_listen_pids_namespace_correct_output(self):
        expected = ['1347', '1279', '1349', '1353']
        self._test_find_listen_pids_namespace_helper(expected,
                                                     NETSTAT_NETNS_OUTPUT)

    def test_find_listen_pids_namespace_no_procs(self):
        self._test_find_listen_pids_namespace_helper([],
                                                     NETSTAT_NO_LISTEN_PROCS)

    def test_find_listen_pids_namespace_no_namespace(self):
        self._test_find_listen_pids_namespace_helper([], NETSTAT_NO_NAMESPACE)
