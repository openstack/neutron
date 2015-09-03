# Copyright 2012 OpenStack Foundation
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

from neutron.agent.common import config
from neutron.tests import base


def test_setup_conf():
    conf = config.setup_conf()
    assert conf.state_path.endswith('/var/lib/neutron')


class TestRootHelper(base.BaseTestCase):

    def test_agent_root_helper(self):
        conf = config.setup_conf()
        config.register_root_helper(conf)
        conf.set_override('root_helper', 'my_root_helper', 'AGENT')
        self.assertEqual(config.get_root_helper(conf), 'my_root_helper')

    def test_root_default(self):
        conf = config.setup_conf()
        config.register_root_helper(conf)
        self.assertEqual(config.get_root_helper(conf), 'sudo')

    def test_agent_root_helper_daemon(self):
        conf = config.setup_conf()
        config.register_root_helper(conf)
        rhd = 'my_root_helper_daemon'
        conf.set_override('root_helper_daemon', rhd, 'AGENT')
        self.assertEqual(rhd, conf.AGENT.root_helper_daemon)
