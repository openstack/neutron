# Copyright (c) 2015 Thales Services SAS
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

import os
from unittest import mock

import fixtures
from neutron_lib import constants

from neutron.agent.linux import ip_lib
from neutron.plugins.ml2.drivers.linuxbridge.agent import \
    linuxbridge_neutron_agent as lb_agent
from neutron.tests import base as tests_base
from neutron.tests.common import config_fixtures
from neutron.tests.common import net_helpers
from neutron.tests.functional import base
from neutron.tests import tools


class LinuxbridgeCleanupTest(base.BaseSudoTestCase):

    def _test_linuxbridge_cleanup(self, bridge_exists, callback):
        br_fixture = self.useFixture(
            tools.SafeCleanupFixture(
                net_helpers.LinuxBridgeFixture(
                    prefix=lb_agent.BRIDGE_NAME_PREFIX))).fixture

        config = callback(br_fixture)
        # NOTE(slaweq): use of oslo.privsep inside neutron-linuxbridge-cleanup
        # script requires rootwrap helper to be configured in this script's
        # config
        privsep_helper = os.path.join(
            os.getenv('VIRTUAL_ENV'), 'bin', 'privsep-helper')
        config.update({
            'AGENT': {
                'root_helper': tests_base.get_rootwrap_cmd(),
                'root_helper_daemon': tests_base.get_rootwrap_daemon_cmd()
            },
            'privsep': {
                'helper_command': ' '.join(['sudo', '-E', privsep_helper]),
            },
            'privsep_link': {
                'helper_command': ' '.join(['sudo', '-E', privsep_helper]),
            },
        })

        config.update({'VXLAN': {'enable_vxlan': 'False'}})

        temp_dir = self.useFixture(fixtures.TempDir()).path
        conf = self.useFixture(config_fixtures.ConfigFileFixture(
            base_filename='neutron.conf',
            config=config,
            temp_dir=temp_dir))

        cmd = 'neutron-linuxbridge-cleanup', '--config-file', conf.filename
        ip_wrapper = ip_lib.IPWrapper(br_fixture.namespace)
        ip_wrapper.netns.execute(cmd, privsep_exec=True)

        self.assertEqual(bridge_exists, ip_lib.device_exists(
            br_fixture.bridge.name, br_fixture.namespace))

    def test_cleanup_empty_bridge(self):

        def callback(br_fixture):
            return config_fixtures.ConfigDict()

        self._test_linuxbridge_cleanup(False, callback)

    def test_no_cleanup_bridge_with_tap(self):

        def callback(br_fixture):
            # TODO(cbrandily): refactor net_helpers to avoid mocking it
            mock.patch.object(
                net_helpers, 'VETH0_PREFIX',
                new_callable=mock.PropertyMock(
                    return_value=constants.TAP_DEVICE_PREFIX + '0')).start()
            mock.patch.object(
                net_helpers, 'VETH1_PREFIX',
                new_callable=mock.PropertyMock(
                    return_value=constants.TAP_DEVICE_PREFIX + '1')).start()

            self.useFixture(
                tools.SafeCleanupFixture(
                    net_helpers.LinuxBridgePortFixture(
                        br_fixture.bridge, br_fixture.namespace)))
            return config_fixtures.ConfigDict()

        self._test_linuxbridge_cleanup(True, callback)

    def test_no_cleanup_bridge_in_bridge_mappings(self):

        def callback(br_fixture):
            br_name = br_fixture.bridge.name
            conf = config_fixtures.ConfigDict()
            conf.update(
                {'LINUX_BRIDGE': {'bridge_mappings': 'physnet:%s' % br_name}})
            return conf

        self._test_linuxbridge_cleanup(True, callback)
