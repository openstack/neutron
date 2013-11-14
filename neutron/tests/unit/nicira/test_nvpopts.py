# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 Nicira Networks, Inc.
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
#

import fixtures
import testtools

import mock
from oslo.config import cfg

from neutron.common import config as q_config
from neutron.manager import NeutronManager
from neutron.openstack.common import uuidutils
from neutron.plugins.nicira.common import config  # noqa
from neutron.plugins.nicira.common import exceptions
from neutron.plugins.nicira.common import sync
from neutron.plugins.nicira import nvp_cluster
from neutron.tests.unit.nicira import get_fake_conf
from neutron.tests.unit.nicira import PLUGIN_NAME

BASE_CONF_PATH = get_fake_conf('neutron.conf.test')
NVP_BASE_CONF_PATH = get_fake_conf('neutron.conf.test')
NVP_INI_PATH = get_fake_conf('nvp.ini.basic.test')
NVP_INI_FULL_PATH = get_fake_conf('nvp.ini.full.test')
NVP_INI_AGENTLESS_PATH = get_fake_conf('nvp.ini.agentless.test')


class NVPClusterTest(testtools.TestCase):

    cluster_opts = {'default_tz_uuid': uuidutils.generate_uuid(),
                    'default_l2_gw_service_uuid': uuidutils.generate_uuid(),
                    'default_l2_gw_service_uuid': uuidutils.generate_uuid(),
                    'nvp_user': 'foo',
                    'nvp_password': 'bar',
                    'req_timeout': 45,
                    'http_timeout': 25,
                    'retries': 7,
                    'redirects': 23,
                    'default_interface_name': 'baz',
                    'nvp_controllers': ['1.1.1.1:443']}

    def setUp(self):
        super(NVPClusterTest, self).setUp()
        self.addCleanup(cfg.CONF.reset)

    def test_create_cluster(self):
        cluster = nvp_cluster.NVPCluster(**self.cluster_opts)
        for (k, v) in self.cluster_opts.iteritems():
            self.assertEqual(v, getattr(cluster, k))

    def test_create_cluster_default_port(self):
        opts = self.cluster_opts.copy()
        opts['nvp_controllers'] = ['1.1.1.1']
        cluster = nvp_cluster.NVPCluster(**opts)
        for (k, v) in self.cluster_opts.iteritems():
            self.assertEqual(v, getattr(cluster, k))

    def test_create_cluster_missing_required_attribute_raises(self):
        opts = self.cluster_opts.copy()
        opts.pop('default_tz_uuid')
        self.assertRaises(exceptions.NvpInvalidClusterConfiguration,
                          nvp_cluster.NVPCluster, **opts)


class ConfigurationTest(testtools.TestCase):

    def setUp(self):
        super(ConfigurationTest, self).setUp()
        self.addCleanup(cfg.CONF.reset)
        self.useFixture(fixtures.MonkeyPatch(
                        'neutron.manager.NeutronManager._instance',
                        None))
        # Avoid runs of the synchronizer looping call
        patch_sync = mock.patch.object(sync, '_start_loopingcall')
        patch_sync.start()
        self.addCleanup(patch_sync.stop)

    def _assert_required_options(self, cluster):
        self.assertEqual(cluster.nvp_controllers, ['fake_1:443', 'fake_2:443'])
        self.assertEqual(cluster.default_tz_uuid, 'fake_tz_uuid')
        self.assertEqual(cluster.nvp_user, 'foo')
        self.assertEqual(cluster.nvp_password, 'bar')

    def _assert_extra_options(self, cluster):
        self.assertEqual(14, cluster.req_timeout)
        self.assertEqual(13, cluster.http_timeout)
        self.assertEqual(12, cluster.redirects)
        self.assertEqual(11, cluster.retries)
        self.assertEqual('whatever', cluster.default_l2_gw_service_uuid)
        self.assertEqual('whatever', cluster.default_l3_gw_service_uuid)
        self.assertEqual('whatever', cluster.default_interface_name)

    def test_load_plugin_with_full_options(self):
        q_config.parse(['--config-file', BASE_CONF_PATH,
                        '--config-file', NVP_INI_FULL_PATH])
        cfg.CONF.set_override('core_plugin', PLUGIN_NAME)
        plugin = NeutronManager().get_plugin()
        cluster = plugin.cluster
        self._assert_required_options(cluster)
        self._assert_extra_options(cluster)

    def test_load_plugin_with_required_options_only(self):
        q_config.parse(['--config-file', BASE_CONF_PATH,
                        '--config-file', NVP_INI_PATH])
        cfg.CONF.set_override('core_plugin', PLUGIN_NAME)
        plugin = NeutronManager().get_plugin()
        self._assert_required_options(plugin.cluster)

    def test_defaults(self):
        self.assertEqual(5000, cfg.CONF.NVP.max_lp_per_bridged_ls)
        self.assertEqual(256, cfg.CONF.NVP.max_lp_per_overlay_ls)
        self.assertEqual(10, cfg.CONF.NVP.concurrent_connections)
        self.assertEqual('access_network', cfg.CONF.NVP.metadata_mode)
        self.assertEqual('stt', cfg.CONF.NVP.default_transport_type)

        self.assertIsNone(cfg.CONF.default_tz_uuid)
        self.assertEqual('admin', cfg.CONF.nvp_user)
        self.assertEqual('admin', cfg.CONF.nvp_password)
        self.assertEqual(30, cfg.CONF.req_timeout)
        self.assertEqual(10, cfg.CONF.http_timeout)
        self.assertEqual(2, cfg.CONF.retries)
        self.assertEqual(2, cfg.CONF.redirects)
        self.assertIsNone(cfg.CONF.nvp_controllers)
        self.assertIsNone(cfg.CONF.default_l3_gw_service_uuid)
        self.assertIsNone(cfg.CONF.default_l2_gw_service_uuid)
        self.assertEqual('breth0', cfg.CONF.default_interface_name)

    def test_load_api_extensions(self):
        q_config.parse(['--config-file', NVP_BASE_CONF_PATH,
                        '--config-file', NVP_INI_FULL_PATH])
        cfg.CONF.set_override('core_plugin', PLUGIN_NAME)
        # Load the configuration, and initialize the plugin
        NeutronManager().get_plugin()
        self.assertIn('extensions', cfg.CONF.api_extensions_path)

    def test_agentless_extensions(self):
        self.skipTest('Enable once agentless support is added')
        q_config.parse(['--config-file', NVP_BASE_CONF_PATH,
                        '--config-file', NVP_INI_AGENTLESS_PATH])
        cfg.CONF.set_override('core_plugin', PLUGIN_NAME)
        self.assertEqual(config.AgentModes.AGENTLESS,
                         cfg.CONF.NVP.agent_mode)
        plugin = NeutronManager().get_plugin()
        self.assertNotIn('agent',
                         plugin.supported_extension_aliases)
        self.assertNotIn('dhcp_agent_scheduler',
                         plugin.supported_extension_aliases)

    def test_agent_extensions(self):
        q_config.parse(['--config-file', NVP_BASE_CONF_PATH,
                        '--config-file', NVP_INI_FULL_PATH])
        cfg.CONF.set_override('core_plugin', PLUGIN_NAME)
        self.assertEqual(config.AgentModes.AGENT,
                         cfg.CONF.NVP.agent_mode)
        plugin = NeutronManager().get_plugin()
        self.assertIn('agent',
                      plugin.supported_extension_aliases)
        self.assertIn('dhcp_agent_scheduler',
                      plugin.supported_extension_aliases)
