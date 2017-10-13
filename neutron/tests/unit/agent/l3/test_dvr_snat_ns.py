# Copyright (c) 2016 OpenStack Foundation
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
from oslo_config import cfg
from oslo_utils import uuidutils

from neutron.agent.common import utils
from neutron.agent.l3 import dvr_snat_ns
from neutron.agent.linux import ip_lib
from neutron.tests import base

_uuid = uuidutils.generate_uuid


class TestDvrSnatNs(base.BaseTestCase):
    def setUp(self):
        super(TestDvrSnatNs, self).setUp()
        self.conf = mock.Mock()
        self.conf.state_path = cfg.CONF.state_path
        self.driver = mock.Mock()
        self.driver.DEV_NAME_LEN = 14
        self.router_id = _uuid()
        self.snat_ns = dvr_snat_ns.SnatNamespace(self.router_id,
                                                 self.conf,
                                                 self.driver,
                                                 use_ipv6=False)

    @mock.patch.object(utils, 'execute')
    @mock.patch.object(ip_lib, 'create_network_namespace')
    @mock.patch.object(ip_lib, 'network_namespace_exists')
    def test_create(self, exists, create, execute):
        exists.return_value = False
        self.snat_ns.create()

        netns_cmd = ['ip', 'netns', 'exec', self.snat_ns.name]
        loose_cmd = ['sysctl', '-w', 'net.netfilter.nf_conntrack_tcp_loose=0']
        expected = [mock.call(netns_cmd + loose_cmd,
                              check_exit_code=True, extra_ok_codes=None,
                              log_fail_as_error=True, run_as_root=True)]

        create.assert_called_once_with(self.snat_ns.name)
        execute.assert_has_calls(expected)
