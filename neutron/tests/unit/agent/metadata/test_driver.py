# Copyright 2014 OpenStack Foundation.
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
from oslo_config import cfg
from oslo_utils import uuidutils

from neutron.agent.common import config as agent_config
from neutron.agent.l3 import agent as l3_agent
from neutron.agent.l3 import router_info
from neutron.agent.linux import iptables_manager
from neutron.agent.metadata import driver as metadata_driver
from neutron.common import constants
from neutron.conf.agent.l3 import config as l3_config
from neutron.conf.agent.l3 import ha as ha_conf
from neutron.conf.agent.metadata import config as meta_conf
from neutron.tests import base


_uuid = uuidutils.generate_uuid


class TestMetadataDriverRules(base.BaseTestCase):

    def test_metadata_nat_rules(self):
        rules = ('PREROUTING', '-d 169.254.169.254/32 -i qr-+ '
                 '-p tcp -m tcp --dport 80 -j REDIRECT --to-ports 8775')
        self.assertEqual(
            [rules],
            metadata_driver.MetadataDriver.metadata_nat_rules(8775))

    def test_metadata_filter_rules(self):
        rules = [('INPUT', '-m mark --mark 0x1/%s -j ACCEPT' %
                  constants.ROUTER_MARK_MASK),
                 ('INPUT', '-p tcp -m tcp --dport 8775 -j DROP')]
        self.assertEqual(
            rules,
            metadata_driver.MetadataDriver.metadata_filter_rules(8775, '0x1'))

    def test_metadata_mangle_rules(self):
        rule = ('PREROUTING', '-d 169.254.169.254/32 -i qr-+ '
                '-p tcp -m tcp --dport 80 '
                '-j MARK --set-xmark 0x1/%s' %
                constants.ROUTER_MARK_MASK)
        self.assertEqual(
            [rule],
            metadata_driver.MetadataDriver.metadata_mangle_rules('0x1'))


class TestMetadataDriverProcess(base.BaseTestCase):

    EUID = 123
    EGID = 456
    EUNAME = 'neutron'

    def setUp(self):
        super(TestMetadataDriverProcess, self).setUp()
        mock.patch('eventlet.spawn').start()
        agent_config.register_interface_driver_opts_helper(cfg.CONF)
        cfg.CONF.set_override('interface_driver',
                              'neutron.agent.linux.interface.NullDriver')

        mock.patch('neutron.agent.l3.agent.L3PluginApi').start()
        mock.patch('neutron.agent.l3.ha.AgentMixin'
                   '._init_ha_conf_path').start()

        l3_config.register_l3_agent_config_opts(l3_config.OPTS, cfg.CONF)
        ha_conf.register_l3_agent_ha_opts()
        meta_conf.register_meta_conf_opts(meta_conf.SHARED_OPTS, cfg.CONF)
        meta_conf.register_meta_conf_opts(meta_conf.DRIVER_OPTS, cfg.CONF)

    def test_after_router_updated_called_on_agent_process_update(self):
        with mock.patch.object(metadata_driver, 'after_router_updated') as f,\
                mock.patch.object(router_info.RouterInfo, 'process'):
            agent = l3_agent.L3NATAgent('localhost')
            router_id = _uuid()
            router = {'id': router_id}
            ri = router_info.RouterInfo(mock.Mock(), router_id, router,
                                        agent.conf, mock.ANY)
            agent.router_info[router_id] = ri
            agent._process_updated_router(router)
            f.assert_called_once_with(
                'router', 'after_update', agent, router=ri)

    def test_after_router_updated_should_not_call_add_metadata_rules(self):
        with mock.patch.object(iptables_manager.IptablesTable,
                               'add_rule') as f,\
                mock.patch.object(iptables_manager.IptablesManager,
                                  'apply'),\
                mock.patch.object(metadata_driver.MetadataDriver,
                                  'spawn_monitored_metadata_proxy'),\
                mock.patch.object(router_info.RouterInfo, 'process'):
            agent = l3_agent.L3NATAgent('localhost')
            router_id = _uuid()
            router = {'id': router_id}
            ri = router_info.RouterInfo(mock.Mock(), router_id, router,
                                        agent.conf, mock.ANY)
            agent.router_info[router_id] = ri
            f.reset_mock()
            agent._process_updated_router(router)
            f.assert_not_called()

    def _test_spawn_metadata_proxy(self, expected_user, expected_group,
                                   user='', group='', watch_log=True):
        router_id = _uuid()
        router_ns = 'qrouter-%s' % router_id
        metadata_port = 8080
        ip_class_path = 'neutron.agent.linux.ip_lib.IPWrapper'
        is_effective_user = 'neutron.agent.linux.utils.is_effective_user'
        fake_is_effective_user = lambda x: x in [self.EUNAME, str(self.EUID)]

        cfg.CONF.set_override('metadata_proxy_user', user)
        cfg.CONF.set_override('metadata_proxy_group', group)
        cfg.CONF.set_override('log_file', 'test.log')
        cfg.CONF.set_override('debug', True)

        agent = l3_agent.L3NATAgent('localhost')
        with mock.patch('os.geteuid', return_value=self.EUID),\
                mock.patch('os.getegid', return_value=self.EGID),\
                mock.patch(is_effective_user,
                           side_effect=fake_is_effective_user),\
                mock.patch(ip_class_path) as ip_mock:
            agent.metadata_driver.spawn_monitored_metadata_proxy(
                agent.process_monitor,
                router_ns,
                metadata_port,
                agent.conf,
                router_id=router_id)
            netns_execute_args = [
                'neutron-ns-metadata-proxy',
                mock.ANY,
                mock.ANY,
                '--router_id=%s' % router_id,
                mock.ANY,
                '--metadata_port=%s' % metadata_port,
                '--metadata_proxy_user=%s' % expected_user,
                '--metadata_proxy_group=%s' % expected_group,
                '--debug',
                '--log-file=neutron-ns-metadata-proxy-%s.log' %
                router_id]
            if not watch_log:
                netns_execute_args.append(
                    '--nometadata_proxy_watch_log')
            ip_mock.assert_has_calls([
                mock.call(namespace=router_ns),
                mock.call().netns.execute(netns_execute_args, addl_env=None,
                                          run_as_root=False)
            ])

    def test_spawn_metadata_proxy_with_agent_user(self):
        self._test_spawn_metadata_proxy(
            self.EUNAME, str(self.EGID), user=self.EUNAME)

    def test_spawn_metadata_proxy_with_nonagent_user(self):
        self._test_spawn_metadata_proxy(
            'notneutron', str(self.EGID), user='notneutron', watch_log=False)

    def test_spawn_metadata_proxy_with_agent_uid(self):
        self._test_spawn_metadata_proxy(
            str(self.EUID), str(self.EGID), user=str(self.EUID))

    def test_spawn_metadata_proxy_with_nonagent_uid(self):
        self._test_spawn_metadata_proxy(
            '321', str(self.EGID), user='321', watch_log=False)

    def test_spawn_metadata_proxy_with_group(self):
        self._test_spawn_metadata_proxy(str(self.EUID), 'group', group='group')

    def test_spawn_metadata_proxy_with_gid(self):
        self._test_spawn_metadata_proxy(str(self.EUID), '654', group='654')

    def test_spawn_metadata_proxy(self):
        self._test_spawn_metadata_proxy(str(self.EUID), str(self.EGID))
