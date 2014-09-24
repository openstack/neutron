# Copyright (c) 2014 OpenStack Foundation, all rights reserved.
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

from neutron.common import constants as l3_const
from neutron import context
from neutron.db import l3_dvr_db
from neutron import manager
from neutron.openstack.common import uuidutils
from neutron.tests.unit import testlib_api

_uuid = uuidutils.generate_uuid


class L3DvrTestCase(testlib_api.SqlTestCase):

    def setUp(self):
        super(L3DvrTestCase, self).setUp()
        self.ctx = context.get_admin_context()
        self.mixin = l3_dvr_db.L3_NAT_with_dvr_db_mixin()

    def _create_router(self, router):
        with self.ctx.session.begin(subtransactions=True):
            return self.mixin._create_router_db(self.ctx, router, 'foo_tenant')

    def _test__create_router_db(self, expected=False, distributed=None):
        router = {'name': 'foo_router', 'admin_state_up': True}
        if distributed is not None:
            router['distributed'] = distributed
        result = self._create_router(router)
        self.assertEqual(expected, result.extra_attributes['distributed'])

    def test_create_router_db_default(self):
        self._test__create_router_db(expected=False)

    def test_create_router_db_centralized(self):
        self._test__create_router_db(expected=False, distributed=False)

    def test_create_router_db_distributed(self):
        self._test__create_router_db(expected=True, distributed=True)

    def test__validate_router_migration_on_router_update(self):
        router = {
            'name': 'foo_router',
            'admin_state_up': True,
            'distributed': True
        }
        router_db = self._create_router(router)
        self.assertIsNone(self.mixin._validate_router_migration(
            router_db, {'name': 'foo_router_2'}))

    def test__validate_router_migration_raise_error(self):
        router = {
            'name': 'foo_router',
            'admin_state_up': True,
            'distributed': True
        }
        router_db = self._create_router(router)
        self.assertRaises(NotImplementedError,
                          self.mixin._validate_router_migration,
                          router_db, {'distributed': False})

    def test_update_router_db_centralized_to_distributed(self):
        router = {'name': 'foo_router', 'admin_state_up': True}
        distributed = {'distributed': True}
        router_db = self._create_router(router)
        router_id = router_db['id']
        self.assertFalse(router_db.extra_attributes.distributed)
        with mock.patch.object(self.mixin, '_update_distributed_attr') as f:
            with mock.patch.object(self.mixin, '_get_router') as g:
                g.return_value = router_db
                router_db = self.mixin._update_router_db(
                    self.ctx, router_id, distributed, mock.ANY)
                # Assert that the DB value has changed
                self.assertTrue(router_db.extra_attributes.distributed)
                self.assertEqual(1, f.call_count)

    def _test_get_device_owner(self, is_distributed=False,
                               expected=l3_const.DEVICE_OWNER_ROUTER_INTF,
                               pass_router_id=True):
        router = {
            'name': 'foo_router',
            'admin_state_up': True,
            'distributed': is_distributed
        }
        router_db = self._create_router(router)
        router_pass = router_db['id'] if pass_router_id else router_db
        with mock.patch.object(self.mixin, '_get_router') as f:
            f.return_value = router_db
            result = self.mixin._get_device_owner(self.ctx, router_pass)
            self.assertEqual(expected, result)

    def test_get_device_owner_by_router_id(self):
        self._test_get_device_owner()

    def test__get_device_owner_centralized(self):
        self._test_get_device_owner(pass_router_id=False)

    def test__get_device_owner_distributed(self):
        self._test_get_device_owner(
            is_distributed=True,
            expected=l3_dvr_db.DEVICE_OWNER_DVR_INTERFACE,
            pass_router_id=False)

    def _test__is_distributed_router(self, router, expected):
        result = l3_dvr_db.is_distributed_router(router)
        self.assertEqual(expected, result)

    def test__is_distributed_router_by_db_object(self):
        router = {'name': 'foo_router', 'admin_state_up': True}
        router_db = self._create_router(router)
        self.mixin._get_device_owner(mock.ANY, router_db)

    def test__is_distributed_router_default(self):
        router = {'id': 'foo_router_id'}
        self._test__is_distributed_router(router, False)

    def test__is_distributed_router_centralized(self):
        router = {'id': 'foo_router_id', 'distributed': False}
        self._test__is_distributed_router(router, False)

    def test__is_distributed_router_distributed(self):
        router = {'id': 'foo_router_id', 'distributed': True}
        self._test__is_distributed_router(router, True)

    def test_get_agent_gw_ports_exist_for_network(self):
        with mock.patch.object(manager.NeutronManager, 'get_plugin') as gp:
            plugin = mock.Mock()
            gp.return_value = plugin
            plugin.get_ports.return_value = []
            self.mixin.get_agent_gw_ports_exist_for_network(
                self.ctx, 'network_id', 'host', 'agent_id')
        plugin.get_ports.assert_called_with(self.ctx, {
            'network_id': ['network_id'],
            'device_id': ['agent_id'],
            'device_owner': [l3_const.DEVICE_OWNER_AGENT_GW]})

    def test__create_gw_port_with_no_gateway(self):
        router = {
            'name': 'foo_router',
            'admin_state_up': True,
            'distributed': True,
        }
        router_db = self._create_router(router)
        router_id = router_db['id']
        self.assertTrue(router_db.extra_attributes.distributed)
        with contextlib.nested(
            mock.patch.object(l3_dvr_db.l3_db.L3_NAT_db_mixin,
                              '_create_gw_port'),
            mock.patch.object(self.mixin,
                              'create_snat_intf_ports_if_not_exists')
                              ) as (cw, cs):
            self.mixin._create_gw_port(
                self.ctx, router_id, router_db, mock.ANY)
            self.assertFalse(cs.call_count)

    def test_build_routers_list_with_gw_port_mismatch(self):
        routers = [{'gw_port_id': 'foo_gw_port_id', 'id': 'foo_router_id'}]
        gw_ports = {}
        routers = self.mixin._build_routers_list(self.ctx, routers, gw_ports)
        self.assertIsNone(routers[0].get('gw_port'))

    def test_clear_unused_fip_agent_gw_port(self):
        floatingip = {
            'id': _uuid(),
            'fixed_port_id': _uuid(),
            'floating_network_id': _uuid()
        }
        fip_id = floatingip['id']
        with contextlib.nested(
            mock.patch.object(l3_dvr_db.l3_db.L3_NAT_db_mixin,
                              '_get_floatingip'),
            mock.patch.object(self.mixin,
                              'get_vm_port_hostid'),
            mock.patch.object(self.mixin,
                              'check_fips_availability_on_host'),
            mock.patch.object(self.mixin,
                              'delete_floatingip_agent_gateway_port')
                             ) as (gfips, gvm, cfips, dfips):
            gfips.return_value = floatingip
            gvm.return_value = 'my-host'
            cfips.return_value = True
            self.mixin.clear_unused_fip_agent_gw_port(
                self.ctx, floatingip, fip_id)
            self.assertTrue(dfips.called)
            self.assertTrue(cfips.called)
            self.assertTrue(gvm.called)

    def _delete_floatingip_test_setup(self, floatingip):
        fip_id = floatingip['id']
        with contextlib.nested(
            mock.patch.object(l3_dvr_db.l3_db.L3_NAT_db_mixin,
                              '_get_floatingip'),
            mock.patch.object(self.mixin,
                              'clear_unused_fip_agent_gw_port'),
            mock.patch.object(l3_dvr_db.l3_db.L3_NAT_db_mixin,
                              'delete_floatingip')) as (gf, vf, df):
            gf.return_value = floatingip
            self.mixin.delete_floatingip(self.ctx, fip_id)
            return vf

    def _disassociate_floatingip_setup(self, port_id=None, floatingip=None):
        with contextlib.nested(
            mock.patch.object(self.mixin, '_get_floatingip_on_port'),
            mock.patch.object(self.mixin,
                              'clear_unused_fip_agent_gw_port'),
                              ) as (gf, vf):
            gf.return_value = floatingip
            self.mixin.disassociate_floatingips(
                self.ctx, port_id, do_notify=False)
            return vf

    def test_disassociate_floatingip_with_vm_port(self):
        port_id = '1234'
        floatingip = {
            'id': _uuid(),
            'fixed_port_id': 1234,
            'floating_network_id': _uuid()
        }
        mock_disassociate_fip = self._disassociate_floatingip_setup(
            port_id=port_id, floatingip=floatingip)
        self.assertTrue(mock_disassociate_fip.called)

    def test_disassociate_floatingip_with_no_vm_port(self):
        mock_disassociate_fip = self._disassociate_floatingip_setup()
        self.assertFalse(mock_disassociate_fip.called)

    def test_delete_floatingip_without_internal_port(self):
        floatingip = {
            'id': _uuid(),
            'fixed_port_id': None,
            'floating_network_id': _uuid()
        }
        mock_fip_clear = self._delete_floatingip_test_setup(floatingip)
        self.assertFalse(mock_fip_clear.call_count)

    def test_delete_floatingip_with_internal_port(self):
        floatingip = {
            'id': _uuid(),
            'fixed_port_id': _uuid(),
            'floating_network_id': _uuid()
        }
        mock_fip_clear = self._delete_floatingip_test_setup(floatingip)
        self.assertTrue(mock_fip_clear.called)

    def _floatingip_on_port_test_setup(self, hostid):
        router = {'id': 'foo_router_id', 'distributed': True}
        floatingip = {
            'id': _uuid(),
            'port_id': _uuid(),
            'router_id': 'foo_router_id'
        }
        routers = {
            'foo_router_id': router
        }
        fipagent = {
            'id': _uuid()
        }

        # NOTE: mock.patch is not needed here since self.mixin is created fresh
        # for each test.  It doesn't work with some methods since the mixin is
        # tested in isolation (e.g. _get_agent_by_type_and_host).
        self.mixin.get_vm_port_hostid = mock.Mock(return_value=hostid)
        self.mixin._get_agent_by_type_and_host = mock.Mock(
            return_value=fipagent)
        self.mixin.get_fip_sync_interfaces = mock.Mock(
            return_value='fip_interface')

        self.mixin._process_floating_ips(self.ctx, routers, [floatingip])
        return (router, floatingip)

    def test_floatingip_on_port_no_host(self):
        router, fip = self._floatingip_on_port_test_setup(None)

        self.assertTrue(self.mixin.get_vm_port_hostid.called)
        self.assertFalse(self.mixin._get_agent_by_type_and_host.called)
        self.assertFalse(self.mixin.get_fip_sync_interfaces.called)

        self.assertNotIn(l3_const.FLOATINGIP_KEY, router)
        self.assertNotIn(l3_const.FLOATINGIP_AGENT_INTF_KEY, router)

    def test_floatingip_on_port_with_host(self):
        router, fip = self._floatingip_on_port_test_setup(_uuid())

        self.assertTrue(self.mixin.get_vm_port_hostid.called)
        self.assertTrue(self.mixin._get_agent_by_type_and_host.called)
        self.assertTrue(self.mixin.get_fip_sync_interfaces.called)

        self.assertIn(l3_const.FLOATINGIP_KEY, router)
        self.assertIn(l3_const.FLOATINGIP_AGENT_INTF_KEY, router)
        self.assertIn(fip, router[l3_const.FLOATINGIP_KEY])
        self.assertIn('fip_interface',
            router[l3_const.FLOATINGIP_AGENT_INTF_KEY])
