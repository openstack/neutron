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

import contextlib

import mock

from oslo_config import cfg

from neutron.agent.common import config as agent_config
from neutron.agent.l3 import agent as l3_agent
from neutron.agent.l3 import config as l3_config
from neutron.agent.l3 import ha as l3_ha_agent
from neutron.agent.metadata import config
from neutron.agent.metadata import driver as metadata_driver
from neutron.openstack.common import uuidutils
from neutron.tests import base


_uuid = uuidutils.generate_uuid


class TestMetadataDriverRules(base.BaseTestCase):

    def test_metadata_nat_rules(self):
        rules = ('PREROUTING', '-d 169.254.169.254/32 -i qr-+ '
                 '-p tcp -m tcp --dport 80 -j REDIRECT --to-port 8775')
        self.assertEqual(
            [rules],
            metadata_driver.MetadataDriver.metadata_nat_rules(8775))

    def test_metadata_filter_rules(self):
        rules = [('INPUT', '-m mark --mark 0x1 -j ACCEPT'),
                 ('INPUT', '-p tcp -m tcp --dport 8775 -j DROP')]
        self.assertEqual(
            rules,
            metadata_driver.MetadataDriver.metadata_filter_rules(8775, '0x1'))

    def test_metadata_mangle_rules(self):
        rule = ('PREROUTING', '-d 169.254.169.254/32 '
                '-p tcp -m tcp --dport 80 '
                '-j MARK --set-xmark 0x1/%s' %
                metadata_driver.METADATA_ACCESS_MARK_MASK)
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
        agent_config.register_use_namespaces_opts_helper(cfg.CONF)

        mock.patch('neutron.agent.l3.agent.L3PluginApi').start()
        mock.patch('neutron.agent.l3.ha.AgentMixin'
                   '._init_ha_conf_path').start()

        cfg.CONF.register_opts(l3_config.OPTS)
        cfg.CONF.register_opts(l3_ha_agent.OPTS)
        cfg.CONF.register_opts(config.SHARED_OPTS)
        cfg.CONF.register_opts(config.DRIVER_OPTS)

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
        with contextlib.nested(
                mock.patch('os.geteuid', return_value=self.EUID),
                mock.patch('os.getegid', return_value=self.EGID),
                mock.patch(is_effective_user,
                           side_effect=fake_is_effective_user),
                mock.patch(ip_class_path)) as (
                    geteuid, getegid, is_effective_user, ip_mock):
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
                '--verbose',
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
