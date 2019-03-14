# Copyright 2018 Red Hat Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import mock
from oslo_config import cfg
from oslo_upgradecheck.upgradecheck import Code

from neutron.cmd.upgrade_checks import checks
from neutron.tests import base


class TestChecks(base.BaseTestCase):

    def setUp(self):
        super(TestChecks, self).setUp()
        self.checks = checks.CoreChecks()

    def test_get_checks_list(self):
        self.assertIsInstance(self.checks.get_checks(), list)

    def test_worker_check_good(self):
        cfg.CONF.set_override("api_workers", 2)
        cfg.CONF.set_override("rpc_workers", 2)
        result = checks.CoreChecks.worker_count_check(mock.Mock())
        self.assertEqual(Code.SUCCESS, result.code)

    def test_worker_check_api_missing(self):
        cfg.CONF.set_override("api_workers", None)
        cfg.CONF.set_override("rpc_workers", 2)
        result = checks.CoreChecks.worker_count_check(mock.Mock())
        self.assertEqual(Code.WARNING, result.code)

    def test_worker_check_rpc_missing(self):
        cfg.CONF.set_override("api_workers", 2)
        cfg.CONF.set_override("rpc_workers", None)
        result = checks.CoreChecks.worker_count_check(mock.Mock())
        self.assertEqual(Code.WARNING, result.code)

    def test_worker_check_both_missing(self):
        cfg.CONF.set_override("api_workers", None)
        cfg.CONF.set_override("rpc_workers", None)
        result = checks.CoreChecks.worker_count_check(mock.Mock())
        self.assertEqual(Code.WARNING, result.code)

    def test_external_network_bridge_check_good(self):
        agents = [
            {'host': 'Host A', 'configurations': '{}'},
            {'host': 'Host B',
             'configurations': '{"external_network_bridge": ""}'}
        ]
        with mock.patch.object(checks, "get_l3_agents", return_value=agents):
            result = checks.CoreChecks.external_network_bridge_check(
                mock.Mock())
            self.assertEqual(Code.SUCCESS, result.code)

    def test_external_network_bridge_check_bad(self):
        agents = [
            {'host': 'Host A', 'configurations': '{}'},
            {'host': 'Host B',
             'configurations': '{"external_network_bridge": "br-ex"}'},
            {'host': 'Host C',
             'configurations': '{"external_network_bridge": ""}'}
        ]
        with mock.patch.object(checks, "get_l3_agents", return_value=agents):
            result = checks.CoreChecks.external_network_bridge_check(
                mock.Mock())
            self.assertEqual(Code.WARNING, result.code)
            self.assertIn('Host B', result.details)
            self.assertNotIn('Host A', result.details)
            self.assertNotIn('Host C', result.details)
