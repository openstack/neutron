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
import testtools

from neutron_lib import context
from neutron_lib import exceptions as n_exc
from oslo_db import exception as db_exc
from oslo_utils import uuidutils

from neutron.common import exceptions as c_exc
from neutron.services.auto_allocate import db
from neutron.services.auto_allocate import exceptions
from neutron.tests.unit import testlib_api


DB_PLUGIN_KLASS = 'neutron.db.db_base_plugin_v2.NeutronDbPluginV2'


class AutoAllocateTestCase(testlib_api.SqlTestCase):

    def setUp(self):
        super(AutoAllocateTestCase, self).setUp()
        self.setup_coreplugin(core_plugin=DB_PLUGIN_KLASS)
        self.ctx = context.get_admin_context()
        self.mixin = db.AutoAllocatedTopologyMixin()
        self.mixin._l3_plugin = mock.Mock()
        self.mixin._core_plugin = mock.Mock()

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

    def test__provision_external_connectivity_fail_expected_cleanup(self):
        """Test that the right resources are cleaned up."""
        subnets = [
            {'id': 'subnet_foo_1', 'network_id': 'network_foo'},
        ]
        with mock.patch.object(self.mixin, '_cleanup') as mock_cleanup:
            self.mixin.l3_plugin.create_router.side_effect = (
                n_exc.BadRequest(resource='router', msg='doh!'))
            self.assertRaises(exceptions.AutoAllocationFailure,
                self.mixin._provision_external_connectivity,
                self.ctx, 'ext_net_foo', subnets, 'tenant_foo')
            # expected router_id to be None
            mock_cleanup.assert_called_once_with(
                self.ctx, network_id='network_foo',
                router_id=None, subnets=[])

    def test_get_auto_allocated_topology_dry_run_happy_path_for_kevin(self):
        with mock.patch.object(self.mixin, '_check_requirements') as f:
            self.mixin.get_auto_allocated_topology(
                self.ctx, mock.ANY, fields=['dry-run'])
            self.assertEqual(1, f.call_count)

    def test_get_auto_allocated_topology_dry_run_bad_input(self):
        self.assertRaises(n_exc.BadRequest,
            self.mixin.get_auto_allocated_topology,
            self.ctx, mock.ANY, fields=['foo'])

    def test__provision_tenant_private_network_handles_subnet_errors(self):
        network_id = uuidutils.generate_uuid()
        self.mixin._core_plugin.create_network.return_value = (
            {'id': network_id})
        self.mixin._core_plugin.create_subnet.side_effect = (
            c_exc.SubnetAllocationError(reason='disaster'))
        with mock.patch.object(self.mixin, "_get_supported_subnetpools") as f,\
                mock.patch.object(self.mixin, "_cleanup") as g:
            f.return_value = (
                [{'ip_version': 4, "id": uuidutils.generate_uuid()}])
            self.assertRaises(exceptions.AutoAllocationFailure,
                              self.mixin._provision_tenant_private_network,
                              self.ctx, 'foo_tenant')
            g.assert_called_once_with(self.ctx, network_id)

    def _test__build_topology(self, method, provisioning_exception):
        with mock.patch.object(self.mixin,
                               method,
                               side_effect=provisioning_exception), \
                mock.patch.object(self.mixin, '_cleanup') as f:
            self.assertRaises(provisioning_exception.error,
                              self.mixin._build_topology,
                              self.ctx, mock.ANY, 'foo_net')
            f.assert_called_once_with(
                self.ctx,
                network_id=provisioning_exception.network_id,
                router_id=provisioning_exception.router_id,
                subnets=provisioning_exception.subnets
            )

    def test__build_topology_provisioning_error_no_toplogy(self):
        provisioning_exception = exceptions.UnknownProvisioningError(
            db_exc.DBError)
        self._test__build_topology(
            '_provision_tenant_private_network',
            provisioning_exception)

    def test__build_topology_provisioning_error_network_only(self):
        provisioning_exception = exceptions.UnknownProvisioningError(
            Exception, network_id='foo')
        self._test__build_topology(
            '_provision_tenant_private_network',
            provisioning_exception)

    def test__build_topology_error_only_network_again(self):
        provisioning_exception = exceptions.UnknownProvisioningError(
            AttributeError, network_id='foo')
        with mock.patch.object(self.mixin,
                               '_provision_tenant_private_network') as f:
            f.return_value = [{'network_id': 'foo'}]
            self._test__build_topology(
                '_provision_external_connectivity',
                provisioning_exception)

    def test__build_topology_error_network_with_router(self):
        provisioning_exception = exceptions.UnknownProvisioningError(
            KeyError, network_id='foo_n', router_id='foo_r')
        with mock.patch.object(self.mixin,
                               '_provision_tenant_private_network') as f:
            f.return_value = [{'network_id': 'foo_n'}]
            self._test__build_topology(
                '_provision_external_connectivity',
                provisioning_exception)

    def test__build_topology_error_network_with_router_and_interfaces(self):
        provisioning_exception = exceptions.UnknownProvisioningError(
            db_exc.DBConnectionError,
            network_id='foo_n', router_id='foo_r', subnets=[{'id': 'foo_s'}])
        with mock.patch.object(self.mixin,
                               '_provision_tenant_private_network') as f,\
                mock.patch.object(self.mixin,
                                  '_provision_external_connectivity') as g:
            f.return_value = [{'network_id': 'foo_n'}]
            g.return_value = {'id': 'foo_r'}
            self._test__build_topology(
                '_save',
                provisioning_exception)

    def test__save_with_provisioning_error(self):
        self.mixin._core_plugin.update_network.side_effect = Exception
        with testtools.ExpectedException(
                exceptions.UnknownProvisioningError) as e:
            self.mixin._save(self.ctx, 'foo_t', 'foo_n', 'foo_r',
                             [{'id': 'foo_s'}])
            self.assertEqual('foo_n', e.network_id)
            self.assertEqual('foo_r', e.router_id)
            self.assertEqual([{'id': 'foo_s'}], e.subnets)

    def test__provision_external_connectivity_with_provisioning_error(self):
        self.mixin._l3_plugin.create_router.side_effect = Exception
        with testtools.ExpectedException(
                exceptions.UnknownProvisioningError) as e:
            self.mixin._provision_external_connectivity(
                self.ctx, 'foo_default',
                [{'id': 'foo_s', 'network_id': 'foo_n'}],
                'foo_tenant')
            self.assertEqual('foo_n', e.network_id)
            self.assertIsNone(e.router_id)
            self.assertIsNone(e.subnets)

    def test__provision_tenant_private_network_with_provisioning_error(self):
        self.mixin._core_plugin.create_network.side_effect = Exception
        with testtools.ExpectedException(
                exceptions.UnknownProvisioningError) as e:
            self.mixin._provision_tenant_private_network(
                self.ctx, 'foo_tenant')
            self.assertIsNone(e.network_id)

    def test__check_requirements_fail_on_missing_ext_net(self):
        self.assertRaises(exceptions.AutoAllocationFailure,
            self.mixin._check_requirements, self.ctx, 'foo_tenant')

    def test__check_requirements_fail_on_missing_pools(self):
        with mock.patch.object(
            self.mixin, '_get_default_external_network'),\
            mock.patch.object(
                self.mixin, '_get_supported_subnetpools') as g:
            g.side_effect = n_exc.NotFound()
            self.assertRaises(exceptions.AutoAllocationFailure,
                self.mixin._check_requirements, self.ctx, 'foo_tenant')

    def test__check_requirements_happy_path_for_kevin(self):
        with mock.patch.object(
            self.mixin, '_get_default_external_network'),\
            mock.patch.object(
                self.mixin, '_get_supported_subnetpools'):
            result = self.mixin._check_requirements(self.ctx, 'foo_tenant')
            expected = {'id': 'dry-run=pass', 'tenant_id': 'foo_tenant'}
            self.assertEqual(expected, result)

    def test__cleanup_handles_failures(self):
        notfound = n_exc.NotFound
        self.mixin._l3_plugin.remove_router_interface.side_effect = (
            notfound)
        self.mixin._l3_plugin.delete_router.side_effect = (
            notfound)
        self.mixin._core_plugin.delete_network.side_effect = (
            notfound)
        self.mixin._cleanup(self.ctx, network_id=44, router_id=45,
                            subnets=[{'id': 46}])
