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
from neutron.plugins.vmware.common import sync
from neutron.plugins.vmware.dhcp_meta import rpc
from neutron.tests.unit.openvswitch import test_agent_scheduler as test_base
from neutron.tests.unit.vmware.apiclient import fake
from neutron.tests.unit.vmware import get_fake_conf
from neutron.tests.unit.vmware import NSXAPI_NAME
from neutron.tests.unit.vmware import PLUGIN_NAME
from neutron.tests.unit.vmware import STUBS_PATH


class DhcpAgentNotifierTestCase(test_base.OvsDhcpAgentNotifierTestCase):
    plugin_str = PLUGIN_NAME

    def setUp(self):
        test_config['config_files'] = [get_fake_conf('nsx.ini.full.test')]

        # mock api client
        self.fc = fake.FakeClient(STUBS_PATH)
        self.mock_nsx_api = mock.patch(NSXAPI_NAME, autospec=True)
        instance = self.mock_nsx_api.start()
        # Avoid runs of the synchronizer looping call
        patch_sync = mock.patch.object(sync, '_start_loopingcall')
        patch_sync.start()

        # Emulate tests against NSX 2.x
        instance.return_value.get_version.return_value = "2.999"
        instance.return_value.request.side_effect = self.fc.fake_request
        super(DhcpAgentNotifierTestCase, self).setUp()
        self.addCleanup(self.fc.reset_all)
        self.addCleanup(patch_sync.stop)
        self.addCleanup(self.mock_nsx_api.stop)

    def _test_gateway_subnet_notification(self, gateway='10.0.0.1'):
        cfg.CONF.set_override('metadata_mode', 'dhcp_host_route', 'NSX')
        hosts = ['hosta']
        with mock.patch.object(rpc.LOG, 'info') as mock_log:
            [mock_dhcp, net, subnet, port] = self._network_port_create(
                hosts, gateway=gateway, owner=constants.DEVICE_OWNER_DHCP)
            self.assertEqual(subnet['subnet']['gateway_ip'], gateway)
            called = 1 if gateway is None else 0
            self.assertEqual(called, mock_log.call_count)

    def test_gatewayless_subnet_notification(self):
        self._test_gateway_subnet_notification(gateway=None)

    def test_subnet_with_gateway_notification(self):
        self._test_gateway_subnet_notification()
