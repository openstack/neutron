# Copyright (c) 2015 Red Hat Inc.
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

import os

import mock
from oslo_config import cfg

from neutron.agent.l3 import keepalived_state_change
from neutron.openstack.common import uuidutils
from neutron.tests.functional import base


class TestKeepalivedStateChange(base.BaseSudoTestCase):
    def setUp(self):
        super(TestKeepalivedStateChange, self).setUp()
        cfg.CONF.register_opt(
            cfg.StrOpt('metadata_proxy_socket',
                       default='$state_path/metadata_proxy',
                       help=_('Location of Metadata Proxy UNIX domain '
                              'socket')))

        self.router_id = uuidutils.generate_uuid()
        self.conf_dir = self.get_default_temp_dir().path
        self.cidr = '169.254.128.1/24'
        self.interface_name = 'interface'
        self.monitor = keepalived_state_change.MonitorDaemon(
            self.get_temp_file_path('monitor.pid'),
            self.router_id,
            1,
            2,
            'namespace',
            self.conf_dir,
            self.interface_name,
            self.cidr)
        mock.patch.object(self.monitor, 'notify_agent').start()
        self.line = '1: %s    inet %s' % (self.interface_name, self.cidr)

    def test_parse_and_handle_event_wrong_device_completes_without_error(self):
        self.monitor.parse_and_handle_event(
            '1: wrong_device    inet wrong_cidr')

    def _get_state(self):
        with open(os.path.join(self.monitor.conf_dir, 'state')) as state_file:
            return state_file.read()

    def test_parse_and_handle_event_writes_to_file(self):
        self.monitor.parse_and_handle_event('Deleted %s' % self.line)
        self.assertEqual('backup', self._get_state())

        self.monitor.parse_and_handle_event(self.line)
        self.assertEqual('master', self._get_state())

    def test_parse_and_handle_event_fails_writing_state(self):
        with mock.patch.object(
                self.monitor, 'write_state_change', side_effect=OSError):
            self.monitor.parse_and_handle_event(self.line)

    def test_parse_and_handle_event_fails_notifying_agent(self):
        with mock.patch.object(
                self.monitor, 'notify_agent', side_effect=Exception):
            self.monitor.parse_and_handle_event(self.line)
