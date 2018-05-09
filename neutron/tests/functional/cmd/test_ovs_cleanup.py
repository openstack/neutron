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

import collections

from neutron.cmd import ovs_cleanup
from neutron.common import utils
from neutron.conf.agent import cmd
from neutron.plugins.ml2.drivers.openvswitch.agent.common import constants
from neutron.tests.common import net_helpers
from neutron.tests.functional.agent.linux import base


class TestOVSCLIConfig(base.BaseOVSLinuxTestCase):

    def setup_config(self, args=None):
        self.conf = ovs_cleanup.setup_conf()
        super(TestOVSCLIConfig, self).setup_config(args=args)

    def test_ovs_opts_registration(self):
        self.assertFalse(self.conf.ovs_all_ports)
        # to unregister opts
        self.conf.reset()
        self.conf.unregister_opts(cmd.ovs_opts)

    def test_do_main_default_options(self):
        int_br = self.useFixture(net_helpers.OVSBridgeFixture()).bridge
        self.conf.set_override("ovs_integration_bridge", int_br.br_name)
        self.conf.set_override("ovs_all_ports", False)

        noskip = collections.defaultdict(list)
        skip = collections.defaultdict(list)
        # add two vifs, one skipped, and a non-vif port to int_br
        for collection in (noskip, skip):
            collection[int_br].append(
                self.useFixture(net_helpers.OVSPortFixture(int_br)).port.name)
        # set skippable vif to be skipped
        int_br.ovsdb.db_set(
            'Interface', skip[int_br][0],
            ('external_ids', {constants.SKIP_CLEANUP: "True"})
        ).execute(check_error=True)
        device_name = utils.get_rand_name()
        skip[int_br].append(device_name)
        int_br.add_port(device_name, ('type', 'internal'))
        # sanity check
        for collection in (noskip, skip):
            for bridge, ports in collection.items():
                port_list = bridge.get_port_name_list()
                for port in ports:
                    self.assertIn(port, port_list)
        ovs_cleanup.do_main(self.conf)
        ports = int_br.get_port_name_list()
        for vif in noskip[int_br]:
            self.assertNotIn(vif, ports)
        for port in skip[int_br]:
            self.assertIn(port, ports)
