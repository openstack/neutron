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
from neutron.agent.l3 import config as l3_config
from neutron.agent.metadata import driver as metadata_driver
from neutron.openstack.common import uuidutils
from neutron.tests import base


_uuid = uuidutils.generate_uuid


class TestMetadataDriver(base.BaseTestCase):

    EUID = 123
    EGID = 456

    def setUp(self):
        super(TestMetadataDriver, self).setUp()
        cfg.CONF.register_opts(l3_config.OPTS)
        cfg.CONF.register_opts(metadata_driver.MetadataDriver.OPTS)
        agent_config.register_root_helper(cfg.CONF)

    def test_metadata_nat_rules(self):
        rules = ('PREROUTING', '-s 0.0.0.0/0 -d 169.254.169.254/32 '
                 '-p tcp -m tcp --dport 80 -j REDIRECT --to-port 8775')
        self.assertEqual(
            [rules],
            metadata_driver.MetadataDriver.metadata_nat_rules(8775))

    def test_metadata_filter_rules(self):
        rules = [('INPUT', '-m mark --mark 0x1 -j ACCEPT'),
                 ('INPUT', '-s 0.0.0.0/0 -p tcp -m tcp --dport 8775 -j DROP')]
        self.assertEqual(
            rules,
            metadata_driver.MetadataDriver.metadata_filter_rules(8775, '0x1'))

    def test_metadata_mangle_rules(self):
        rule = ('PREROUTING', '-s 0.0.0.0/0 -d 169.254.169.254/32 '
                '-p tcp -m tcp --dport 80 '
                '-j MARK --set-xmark 0x1/%s' %
                metadata_driver.METADATA_ACCESS_MARK_MASK)
        self.assertEqual(
            [rule],
            metadata_driver.MetadataDriver.metadata_mangle_rules('0x1'))

    def _test_spawn_metadata_proxy(self, expected_user, expected_group,
                                   user='', group=''):
        router_id = _uuid()
        router_ns = 'qrouter-%s' % router_id
        metadata_port = 8080
        ip_class_path = 'neutron.agent.linux.ip_lib.IPWrapper'

        cfg.CONF.set_override('metadata_port', metadata_port)
        cfg.CONF.set_override('metadata_proxy_user', user)
        cfg.CONF.set_override('metadata_proxy_group', group)
        cfg.CONF.set_override('log_file', 'test.log')
        cfg.CONF.set_override('debug', True)

        driver = metadata_driver.MetadataDriver
        with contextlib.nested(
                mock.patch('os.geteuid', return_value=self.EUID),
                mock.patch('os.getegid', return_value=self.EGID),
                mock.patch(ip_class_path)) as (geteuid, getegid, ip_mock):
            driver._spawn_metadata_proxy(router_id, router_ns, cfg.CONF)
            ip_mock.assert_has_calls([
                mock.call('sudo', router_ns),
                mock.call().netns.execute([
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
                    router_id
                ], addl_env=None)
            ])

    def test_spawn_metadata_proxy_with_user(self):
        self._test_spawn_metadata_proxy('user', self.EGID, user='user')

    def test_spawn_metadata_proxy_with_uid(self):
        self._test_spawn_metadata_proxy('321', self.EGID, user='321')

    def test_spawn_metadata_proxy_with_group(self):
        self._test_spawn_metadata_proxy(self.EUID, 'group', group='group')

    def test_spawn_metadata_proxy_with_gid(self):
        self._test_spawn_metadata_proxy(self.EUID, '654', group='654')

    def test_spawn_metadata_proxy(self):
        self._test_spawn_metadata_proxy(self.EUID, self.EGID)
