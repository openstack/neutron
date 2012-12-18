# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (c) 2012 OpenStack LLC.
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

import mock
import unittest2 as unittest

from quantum.agent.linux import ovs_lib
from quantum.agent import ovs_cleanup_util as util
from quantum.openstack.common import uuidutils


class TestOVSCleanup(unittest.TestCase):
    def test_setup_conf(self):
        with mock.patch('quantum.common.config.setup_logging'):
            conf = util.setup_conf()
            self.assertEqual(conf.external_network_bridge, 'br-ex')
            self.assertEqual(conf.ovs_integration_bridge, 'br-int')
            self.assertFalse(conf.ovs_all_ports)

    def test_main(self):
        with mock.patch('quantum.common.config.setup_logging'):
            br_patch = mock.patch('quantum.agent.linux.ovs_lib.get_bridges')
            with br_patch as mock_get_bridges:
                mock_get_bridges.return_value = ['br-int', 'br-ex']
                with mock.patch(
                    'quantum.agent.linux.ovs_lib.OVSBridge') as ovs:
                    util.main()
                    ovs.assert_has_calls([mock.call().delete_ports(
                        all_ports=False)])
