# Copyright 2019 Red Hat, Inc.
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

import signal
from unittest import mock

from neutron_lib import exceptions as n_exc

from neutron.agent.linux import ip_lib
from neutron.agent.linux import utils
from neutron.common import utils as n_utils
from neutron.tests import base as test_base
from neutron.tests.common import net_helpers
from neutron.tests.functional import base


class NetcatTesterTestCase(base.BaseSudoTestCase):

    def setUp(self):
        super().setUp()
        self.ns1 = self.useFixture(net_helpers.NamespaceFixture('nc-')).name
        self.ns2 = self.useFixture(net_helpers.NamespaceFixture('nc-')).name
        self.nc = net_helpers.NetcatTester(self.ns1, self.ns2, '10.30.0.2',
                                           '1234', 'tcp')
        ip_wrapper = ip_lib.IPWrapper(namespace=self.ns1)
        veth1, veth2 = ip_wrapper.add_veth('veth1', 'veth2', self.ns2)
        veth1.link.set_up()
        veth1.addr.add('10.30.0.1/24')
        veth2.link.set_up()
        veth2.addr.add('10.30.0.2/24')

    @test_base.unstable_test("bug 1862927")
    def test_stop_process(self):
        self.nc.test_connectivity()
        server_pid = self.nc.server_process.child_pid
        client_pid = self.nc.client_process.child_pid
        self.assertTrue(utils.process_is_running(server_pid))
        self.assertTrue(utils.process_is_running(client_pid))

        self.nc.stop_processes()
        self.assertFalse(utils.process_is_running(server_pid))
        self.assertFalse(utils.process_is_running(client_pid))

    @test_base.unstable_test("bug 1862927")
    def test_stop_process_no_process(self):
        self.nc.test_connectivity()
        client_pid = self.nc.client_process.child_pid
        utils.execute(['kill', '-%d' % signal.SIGKILL, client_pid],
                      run_as_root=True)
        n_utils.wait_until_true(
            lambda: not utils.process_is_running(client_pid), timeout=5)
        with mock.patch.object(net_helpers.RootHelperProcess, 'poll',
                               return_value=None):
            self.assertRaises(n_exc.ProcessExecutionError,
                              self.nc.stop_processes,
                              skip_errors=[])

    @test_base.unstable_test("bug 1862927")
    def test_stop_process_no_process_skip_no_process_exception(self):
        self.nc.test_connectivity()
        server_pid = self.nc.server_process.child_pid
        utils.execute(['kill', '-%d' % signal.SIGKILL, server_pid],
                      run_as_root=True)

        with mock.patch.object(net_helpers.RootHelperProcess, 'poll',
                               side_effect=[None, True, None, True]):
            self.nc.stop_processes()
