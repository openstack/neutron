# Copyright (c) 2012 OpenStack Foundation.
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

from unittest import mock

from neutron.cmd import ovs_cleanup as util
from neutron.tests import base


class TestOVSCleanup(base.BaseTestCase):

    def test_clean_ovs_bridges(self):
        conf = mock.Mock()
        conf.ovs_all_ports = True
        conf.ovs_integration_bridge = 'br-int'
        conf.external_network_bridge = 'br-ex'
        bridges = [conf.ovs_integration_bridge, conf.external_network_bridge]
        with mock.patch('neutron.agent.common.ovs_lib.BaseOVS') as ovs_cls:
            ovs_base = mock.Mock()
            ovs_base.get_bridges.return_value = bridges
            ovs_cls.return_value = ovs_base

            util.do_main(conf)
            ovs_base.ovsdb.ovs_cleanup.assert_has_calls(
                [mock.call(conf.ovs_integration_bridge, True),
                 mock.call(conf.external_network_bridge, True)],
                any_order=True)
