# Copyright (c) 2012 OpenStack Foundation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import mock
from oslo.config import cfg

from neutron.common import config  # noqa
from neutron.tests import base


class ConfigurationTest(base.BaseTestCase):

    def setup_config(self):
        # don't use default config
        pass

    def test_defaults(self):
        self.assertEqual('0.0.0.0', cfg.CONF.bind_host)
        self.assertEqual(9696, cfg.CONF.bind_port)
        self.assertEqual('api-paste.ini', cfg.CONF.api_paste_config)
        self.assertEqual('', cfg.CONF.api_extensions_path)
        self.assertEqual('policy.json', cfg.CONF.policy_file)
        self.assertEqual('keystone', cfg.CONF.auth_strategy)
        self.assertIsNone(cfg.CONF.core_plugin)
        self.assertEqual(0, len(cfg.CONF.service_plugins))
        self.assertEqual('fa:16:3e:00:00:00', cfg.CONF.base_mac)
        self.assertEqual(16, cfg.CONF.mac_generation_retries)
        self.assertTrue(cfg.CONF.allow_bulk)
        self.assertEqual(5, cfg.CONF.max_dns_nameservers)
        self.assertEqual(20, cfg.CONF.max_subnet_host_routes)
        self.assertEqual(86400, cfg.CONF.dhcp_lease_duration)
        self.assertFalse(cfg.CONF.allow_overlapping_ips)
        self.assertEqual('neutron', cfg.CONF.control_exchange)

    def test_load_paste_app_not_found(self):
        self.config(api_paste_config='no_such_file.conf')
        with mock.patch.object(cfg.CONF, 'find_file', return_value=None) as ff:
            e = self.assertRaises(cfg.ConfigFilesNotFoundError,
                                  config.load_paste_app, 'app')
            ff.assert_called_once_with('no_such_file.conf')
            self.assertEqual(['no_such_file.conf'], e.config_files)
