# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (c) 2013 OpenStack Foundation
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
from oslo.config import cfg

from neutron.common import constants
from neutron.common.test_lib import test_config
from neutron.plugins.nicira.common import sync
from neutron.tests.unit.nicira import fake_nvpapiclient
from neutron.tests.unit.nicira import get_fake_conf
from neutron.tests.unit.nicira import NVPAPI_NAME
from neutron.tests.unit.nicira import PLUGIN_NAME
from neutron.tests.unit.nicira import STUBS_PATH
from neutron.tests.unit.openvswitch import test_agent_scheduler as test_base


class NVPDhcpAgentNotifierTestCase(test_base.OvsDhcpAgentNotifierTestCase):
    plugin_str = PLUGIN_NAME

    def setUp(self):
        test_config['config_files'] = [get_fake_conf('nsx.ini.full.test')]

        # mock nvp api client
        self.fc = fake_nvpapiclient.FakeClient(STUBS_PATH)
        self.mock_nvpapi = mock.patch(NVPAPI_NAME, autospec=True)
        instance = self.mock_nvpapi.start()
        # Avoid runs of the synchronizer looping call
        patch_sync = mock.patch.object(sync, '_start_loopingcall')
        patch_sync.start()

        def _fake_request(*args, **kwargs):
            return self.fc.fake_request(*args, **kwargs)

        # Emulate tests against NVP 2.x
        instance.return_value.get_nvp_version.return_value = "2.999"
        instance.return_value.request.side_effect = _fake_request
        super(NVPDhcpAgentNotifierTestCase, self).setUp()
        self.addCleanup(self.fc.reset_all)
        self.addCleanup(patch_sync.stop)
        self.addCleanup(self.mock_nvpapi.stop)
        self.addCleanup(cfg.CONF.reset)

    def _notification_mocks(self, hosts, mock_dhcp, net, subnet, port):
        host_calls = {}
        for host in hosts:
            expected_calls = [
                mock.call(
                    mock.ANY,
                    self.dhcp_notifier.make_msg(
                        'network_create_end',
                        payload={'network': net['network']}),
                    topic='dhcp_agent.' + host),
                mock.call(
                    mock.ANY,
                    self.dhcp_notifier.make_msg(
                        'subnet_create_end',
                        payload={'subnet': subnet['subnet']}),
                    topic='dhcp_agent.' + host),
                mock.call(
                    mock.ANY,
                    self.dhcp_notifier.make_msg(
                        'port_create_end',
                        payload={'port': port['port']}),
                    topic='dhcp_agent.' + host)]
            host_calls[host] = expected_calls
        return host_calls

    def _test_gateway_subnet_notification(self, gateway='10.0.0.1'):
        cfg.CONF.set_override('metadata_mode', 'dhcp_host_route', 'NSX')
        hosts = ['hosta']
        [mock_dhcp, net, subnet, port] = self._network_port_create(
            hosts, gateway=gateway, owner=constants.DEVICE_OWNER_DHCP)
        found = False
        for call, topic in mock_dhcp.call_args_list:
            method = call[1]['method']
            if method == 'subnet_update_end':
                found = True
                break
        self.assertTrue(found)
        self.assertEqual(subnet['subnet']['gateway_ip'], gateway)

    def test_gatewayless_subnet_notification(self):
        self._test_gateway_subnet_notification(gateway=None)

    def test_subnet_with_gateway_notification(self):
        self._test_gateway_subnet_notification()
