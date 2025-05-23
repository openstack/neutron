# Copyright (c) 2015 UnitedStack, Inc.
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

from textwrap import dedent
from unittest import mock

from neutron.agent.linux import conntrackd
from neutron.tests.unit.agent.l3.test_agent import \
    BasicRouterOperationsFramework
from neutron.tests.unit.agent.l3.test_agent import FAKE_ID


class ConntrackdConfigTestCase(BasicRouterOperationsFramework):

    @staticmethod
    def get_expected(ha_confs_path):
        return dedent(
            """
            General {{
                HashSize 32768
                HashLimit 131072
                Syslog on
                LockFile {conf_path}/{uuid}/conntrackd.lock
                UNIX {{
                    Path {conf_path}/{uuid}/conntrackd.ctl
                    Backlog 20
                }}
                SocketBufferSize 262142
                SocketBufferSizeMaxGrown 655355
                Filter From Kernelspace {{
                    Protocol Accept {{
                        TCP
                        SCTP
                        DCCP
                        UDP
                        ICMP
                        IPv6-ICMP
                    }}
                    Address Ignore {{
                        IPv4_address 127.0.0.1
                        IPv6_address ::1
                        IPv4_address 192.168.0.5
                    }}
                }}
            }}
            Sync {{
                Mode FTFW {{
                }}
                Multicast Default {{
                    IPv4_address 225.0.0.50
                    IPv4_interface 192.168.0.5
                    Group 3783
                    Interface eth0
                    SndSocketBuffer 24985600
                    RcvSocketBuffer 24985600
                    Checksum on
                }}
            }}""".format(conf_path=ha_confs_path, uuid=FAKE_ID))

    def get_manager(self):
        return conntrackd.ConntrackdManager(
            FAKE_ID,
            self.process_monitor,
            self.conf,
            '192.168.0.5',
            3,
            'eth0',
        )

    def test_build_config(self):
        conntrackd = self.get_manager()

        with mock.patch('os.makedirs'):
            config = conntrackd.build_config()
            self.assertMultiLineEqual(
                ConntrackdConfigTestCase.get_expected(self.conf.ha_confs_path),
                config
            )

    def test_max_file_path_len(self):
        """The shortest file path affected by this will be the LockFile path.
        There "/<uuid>/conntrackd.lock" is appended and should in total not
        exceed 255 characters. So the maximum length for ha_confs_path is 202
        characters.
        """

        with mock.patch('os.makedirs'):
            self.conf.set_override('ha_confs_path', '/' + 'a' * 202)
            conntrackd = self.get_manager()
            self.assertRaisesRegex(
                ValueError,
                'maximum length of 255 characters.',
                conntrackd.build_config,
            )

            # If the path is below the file path limit, the UNIX socket path
            # limit is hit.
            self.conf.set_override('ha_confs_path', '/' + 'a' * 201)
            conntrackd = self.get_manager()
            self.assertRaisesRegex(
                ValueError,
                'maximum length of 107 characters.',
                conntrackd.build_config,
            )

    def test_max_socket_path_len(self):
        """The UNIX socket path has a shorter maximum length of 107
        characters. With "/<uuid>/conntrackd.ctl" appended this means the
        maximum length for ha_confs_path is 55 characters.
        """

        with mock.patch('os.makedirs'):
            self.conf.set_override('ha_confs_path', '/' + 'a' * 55)
            conntrackd = self.get_manager()
            self.assertRaisesRegex(
                ValueError,
                'maximum length of 107 characters.',
                conntrackd.build_config,
            )

            self.conf.set_override('ha_confs_path', '/' + 'a' * 54)
            conntrackd = self.get_manager()
            conntrackd.build_config()
