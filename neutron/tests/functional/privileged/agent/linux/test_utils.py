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

from neutron.agent.linux import ip_lib
from neutron.privileged.agent.linux import utils as priv_utils
from neutron.tests.common import net_helpers
from neutron.tests.functional import base as functional_base


class FindListenPidsNamespaceTestCase(functional_base.BaseSudoTestCase):

    def test_find_listen_pids_namespace(self):
        ns = self.useFixture(net_helpers.NamespaceFixture()).name
        ip_wrapper = ip_lib.IPWrapper(namespace=ns)
        ip_wrapper.add_dummy('device')
        device = ip_lib.IPDevice('device', namespace=ns)
        device.addr.add('10.20.30.40/24')
        device.link.set_up()

        self.assertEqual(tuple(), priv_utils.find_listen_pids_namespace(ns))

        netcat = net_helpers.NetcatTester(ns, ns, '10.20.30.40', 12345, 'udp')
        proc = netcat.server_process
        self.assertEqual((str(proc.child_pid), ),
                         priv_utils.find_listen_pids_namespace(ns))

        netcat.stop_processes()
        self.assertEqual(tuple(), priv_utils.find_listen_pids_namespace(ns))
