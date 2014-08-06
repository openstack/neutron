# Copyright 2014 Big Switch Networks, Inc.
# All Rights Reserved.
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

import contextlib
import mock

from neutron.tests.unit.bigswitch import test_router_db

PLUGIN = 'neutron.plugins.bigswitch.plugin'
SERVERMANAGER = PLUGIN + '.servermanager'
SERVERPOOL = SERVERMANAGER + '.ServerPool'
SERVERRESTCALL = SERVERMANAGER + '.ServerProxy.rest_call'
HTTPCON = SERVERMANAGER + '.httplib.HTTPConnection'


class CapabilitiesTests(test_router_db.RouterDBTestBase):

    def test_floating_ip_capability(self):
        with contextlib.nested(
            mock.patch(SERVERRESTCALL,
                       return_value=(200, None, '["floatingip"]', None)),
            mock.patch(SERVERPOOL + '.rest_create_floatingip',
                       return_value=(200, None, None, None)),
            mock.patch(SERVERPOOL + '.rest_delete_floatingip',
                       return_value=(200, None, None, None))
        ) as (mock_rest, mock_create, mock_delete):
            with self.floatingip_with_assoc() as fip:
                pass
            mock_create.assert_has_calls(
                [mock.call(fip['floatingip']['tenant_id'], fip['floatingip'])]
            )
            mock_delete.assert_has_calls(
                [mock.call(fip['floatingip']['tenant_id'],
                           fip['floatingip']['id'])]
            )

    def test_floating_ip_capability_neg(self):
        with contextlib.nested(
            mock.patch(SERVERRESTCALL,
                       return_value=(200, None, '[""]', None)),
            mock.patch(SERVERPOOL + '.rest_update_network',
                       return_value=(200, None, None, None))
        ) as (mock_rest, mock_netupdate):
            with self.floatingip_with_assoc() as fip:
                pass
            updates = [call[0][2]['floatingips']
                       for call in mock_netupdate.call_args_list]
            all_floats = [f['floating_ip_address']
                          for floats in updates for f in floats]
            self.assertIn(fip['floatingip']['floating_ip_address'], all_floats)

    def test_keep_alive_capability(self):
        with mock.patch(
            SERVERRESTCALL, return_value=(200, None, '["keep-alive"]', None)
        ):
            # perform a task to cause capabilities to be retrieved
            with self.floatingip_with_assoc():
                pass
        # stop default HTTP patch since we need a magicmock
        self.httpPatch.stop()
        # now mock HTTP class instead of REST so we can see headers
        conmock = mock.patch(HTTPCON).start()
        instance = conmock.return_value
        instance.getresponse.return_value.getheader.return_value = 'HASHHEADER'
        with self.network():
            callheaders = instance.request.mock_calls[0][1][3]
            self.assertIn('Connection', callheaders)
            self.assertEqual(callheaders['Connection'], 'keep-alive')
