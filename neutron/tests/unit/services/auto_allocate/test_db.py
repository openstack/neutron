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

from neutron.common import exceptions as n_exc
from neutron import context
from neutron.services.auto_allocate import db
from neutron.services.auto_allocate import exceptions
from neutron.tests import base


class AutoAllocateTestCase(base.BaseTestCase):

    def setUp(self):
        super(AutoAllocateTestCase, self).setUp()
        self.ctx = context.get_admin_context()
        self.mixin = db.AutoAllocatedTopologyMixin()
        self.mixin._l3_plugin = mock.Mock()

    def test__provision_external_connectivity_expected_cleanup(self):
        """Test that the right resources are cleaned up."""
        subnets = [
            {'id': 'subnet_foo_1', 'network_id': 'network_foo'},
            {'id': 'subnet_foo_2', 'network_id': 'network_foo'},
        ]
        with mock.patch.object(self.mixin, '_cleanup') as mock_cleanup:
            self.mixin.l3_plugin.create_router.return_value = (
                {'id': 'router_foo'})
            self.mixin.l3_plugin.add_router_interface.side_effect = (
                n_exc.BadRequest(resource='router', msg='doh!'))
            self.assertRaises(exceptions.AutoAllocationFailure,
                self.mixin._provision_external_connectivity,
                self.ctx, 'ext_net_foo', subnets, 'tenant_foo')
            # expect no subnets to be unplugged
            mock_cleanup.assert_called_once_with(
                self.ctx, network_id='network_foo',
                router_id='router_foo', subnets=[])
