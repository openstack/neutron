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

from neutron.cmd import ovs_cleanup
from neutron.conf.agent import cmd
from neutron.tests import base


class TestOVSCLIConfig(base.BaseTestCase):

    def setup_config(self, args=None):
        self.conf = ovs_cleanup.setup_conf()
        super(TestOVSCLIConfig, self).setup_config(args=args)

    def test_ovs_opts_registration(self):
        self.assertFalse(self.conf.ovs_all_ports)
        # to unregister opts
        self.conf.reset()
        self.conf.unregister_opts(cmd.ovs_opts)
