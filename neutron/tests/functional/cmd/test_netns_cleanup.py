# Copyright (c) 2015 Red Hat, Inc.
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

import os
import sys

import eventlet
import mock
from neutron_lib import constants as n_const

from neutron.agent.l3 import namespaces
from neutron.agent.linux import dhcp
from neutron.agent.linux import ip_lib
from neutron.agent.linux import utils
from neutron.cmd import netns_cleanup
from neutron.common import utils as common_utils
from neutron.conf.agent import cmd
from neutron.tests import base as basetest
from neutron.tests.common import net_helpers
from neutron.tests.functional import base
from neutron.tests.functional.cmd import process_spawn

GET_NAMESPACES = 'neutron.agent.linux.ip_lib.list_network_namespaces'
TEST_INTERFACE_DRIVER = 'neutron.agent.linux.interface.OVSInterfaceDriver'
NUM_SUBPROCESSES = 6


class NetnsCleanupTest(base.BaseSudoTestCase):
    def setUp(self):
        super(NetnsCleanupTest, self).setUp()

        self.get_namespaces_p = mock.patch(GET_NAMESPACES)
        self.get_namespaces = self.get_namespaces_p.start()

    def setup_config(self, args=None):
        if args is None:
            args = []
        # force option enabled to make sure non-empty namespaces are
        # cleaned up and deleted
        args.append('--force')

        self.conf = netns_cleanup.setup_conf()
        self.conf.set_override('interface_driver', TEST_INTERFACE_DRIVER)
        self.config_parse(conf=self.conf, args=args)

    def test_cleanup_network_namespaces_cleans_dhcp_and_l3_namespaces(self):
        dhcp_namespace = self.useFixture(
            net_helpers.NamespaceFixture(dhcp.NS_PREFIX)).name
        l3_namespace = self.useFixture(
            net_helpers.NamespaceFixture(namespaces.NS_PREFIX)).name
        bridge = self.useFixture(
            net_helpers.VethPortFixture(namespace=dhcp_namespace)).bridge
        self.useFixture(
            net_helpers.VethPortFixture(bridge, l3_namespace))

        # we scope the get_namespaces to our own ones not to affect other
        # tests, as otherwise cleanup will kill them all
        self.get_namespaces.return_value = [l3_namespace, dhcp_namespace]

        # launch processes in each namespace to make sure they're
        # killed during cleanup
        procs_launched = self._launch_processes([l3_namespace, dhcp_namespace])
        self.assertIsNot(procs_launched, 0)
        try:
            common_utils.wait_until_true(
                lambda: self._get_num_spawned_procs() == procs_launched,
                timeout=15)
        except eventlet.Timeout:
            num_spawned_procs = self._get_num_spawned_procs()
            err_str = ("Expected number/spawned number: {0}/{1}\nProcess "
                       "information:\n".format(num_spawned_procs,
                                               procs_launched))
            cmd = ['ps', '-f', '-u', 'root']
            err_str += utils.execute(cmd, run_as_root=True)

            raise Exception(err_str)

        netns_cleanup.cleanup_network_namespaces(self.conf)

        self.get_namespaces_p.stop()
        namespaces_now = ip_lib.list_network_namespaces()
        procs_after = self._get_num_spawned_procs()
        self.assertEqual(procs_after, 0)
        self.assertNotIn(l3_namespace, namespaces_now)
        self.assertNotIn(dhcp_namespace, namespaces_now)

    @staticmethod
    def _launch_processes(namespaces):
        """Launch processes in the specified namespaces.

        This function will spawn processes inside the given namespaces:
                - 6 processes listening on tcp ports (parent + 5 children)
                - 1 process + 5 subprocesses listening on unix sockets
                - 1 process + 5 subprocesses listening on udp6 sockets

        First two sets of processes will process SIGTERM so when the parent
        gets killed, it will kill all spawned children
        The last set of processes will ignore SIGTERM. This will allow us
        to test the cleanup functionality which will issue a SIGKILL
        to all remaining processes after the SIGTERM attempt
        """
        python_exec = os.path.basename(sys.executable)
        commands = [[python_exec, process_spawn.__file__,
                     '-n', NUM_SUBPROCESSES,
                     '-f', n_const.IPv4,
                     '-p', n_const.PROTO_NAME_TCP,
                     '--noignore_sigterm',
                     '--parent_listen'],
                    [python_exec, process_spawn.__file__,
                     '-n', NUM_SUBPROCESSES,
                     '-f', process_spawn.UNIX_FAMILY,
                     '-p', n_const.PROTO_NAME_TCP,
                     '--noignore_sigterm',
                     '--noparent_listen'],
                    [python_exec, process_spawn.__file__,
                     '-n', NUM_SUBPROCESSES,
                     '-f', n_const.IPv4,
                     '-p', n_const.PROTO_NAME_UDP,
                     '--ignore_sigterm',
                     '--noparent_listen']]

        proc_count = 0
        for netns in namespaces:
            ip = ip_lib.IPWrapper(namespace=netns)
            for command in commands:
                # The total amount of processes per command is
                # the process itself plus the number of subprocesses spawned by
                # it
                proc_count += (1 + NUM_SUBPROCESSES)
                # We need to pass the PATH env variable so that python
                # interpreter runs under the same virtual environment.
                # Otherwise, it won't find the necessary packages such as
                # oslo_config
                ip.netns.execute(command,
                                 addl_env={'PATH':
                                           os.environ.get('PATH')})
        return proc_count

    @staticmethod
    def _get_num_spawned_procs():
        cmd = ['ps', '-f', '-u', 'root']
        out = utils.execute(cmd, run_as_root=True)
        return sum([1 for line in out.splitlines() if 'process_spawn' in line])


class TestNETNSCLIConfig(basetest.BaseTestCase):

    def setup_config(self, args=None):
        self.conf = netns_cleanup.setup_conf()
        super(TestNETNSCLIConfig, self).setup_config(args=args)

    def test_netns_opts_registration(self):
        self.assertFalse(self.conf.force)
        # to unregister opts
        self.conf.reset()
        self.conf.unregister_opts(cmd.netns_opts)
