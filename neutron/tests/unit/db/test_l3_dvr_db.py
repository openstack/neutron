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

import mock

from neutron.common import constants as l3_const
from neutron.common import exceptions
from neutron import context
from neutron.db import common_db_mixin
from neutron.db import l3_dvr_db
from neutron import manager
from neutron.openstack.common import uuidutils
from neutron.plugins.common import constants as plugin_const
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

    def test_router_id_query(self):
        # need to create an object that has the common db method required
        class DVRwithCommon(l3_dvr_db.L3_NAT_with_dvr_db_mixin,
                            common_db_mixin.CommonDbMixin):
            pass
        self.mixin = DVRwithCommon()
        routers = [self._create_router({'name': '%s' % x,
                                        'admin_state_up': True})
                   for x in range(10)]
        expected = [router['id'] for router in routers]
        router_ids = self.mixin._get_router_ids(self.ctx)
        self.assertEqual(sorted(expected), sorted(router_ids))

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
            self.ctx, router_db, {'name': 'foo_router_2'}))

    def test__validate_router_migration_raise_error(self):
        router = {
            'name': 'foo_router',
            'admin_state_up': True,
            'distributed': True
        }
        router_db = self._create_router(router)
        self.assertRaises(NotImplementedError,
                          self.mixin._validate_router_migration,
                          self.ctx, router_db, {'distributed': False})

    def test_update_router_db_centralized_to_distributed(self):
        router = {'name': 'foo_router', 'admin_state_up': True}
        agent = {'id': _uuid()}
        distributed = {'distributed': True}
        router_db = self._create_router(router)
        router_id = router_db['id']
        self.assertFalse(router_db.extra_attributes.distributed)
        self.mixin._get_router = mock.Mock(return_value=router_db)
        self.mixin._validate_router_migration = mock.Mock()
        self.mixin._update_distributed_attr = mock.Mock()
        self.mixin.list_l3_agents_hosting_router = mock.Mock(
            return_value={'agents': [agent]})
        self.mixin._unbind_router = mock.Mock()
        router_db = self.mixin._update_router_db(
            self.ctx, router_id, distributed, mock.ANY)
        # Assert that the DB value has changed
        self.assertTrue(router_db.extra_attributes.distributed)
        self.assertEqual(1,
                         self.mixin._update_distributed_attr.call_count)

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

    def test__get_agent_gw_ports_exist_for_network(self):
        with mock.patch.object(manager.NeutronManager, 'get_plugin') as gp:
            plugin = mock.Mock()
            gp.return_value = plugin
            plugin.get_ports.return_value = []
            self.mixin._get_agent_gw_ports_exist_for_network(
                self.ctx, 'network_id', 'host', 'agent_id')
        plugin.get_ports.assert_called_with(self.ctx, {
            'network_id': ['network_id'],
            'device_id': ['agent_id'],
            'device_owner': [l3_const.DEVICE_OWNER_AGENT_GW]})

    def _test_prepare_direct_delete_dvr_internal_ports(self, port):
        with mock.patch.object(manager.NeutronManager, 'get_plugin') as gp:
            plugin = mock.Mock()
            gp.return_value = plugin
            plugin._get_port.return_value = port
            self.assertRaises(exceptions.ServicePortInUse,
                              self.mixin.prevent_l3_port_deletion,
                              self.ctx,
                              port['id'])

    def test_prevent__delete_floatingip_agent_gateway_port(self):
        port = {
            'id': 'my_port_id',
            'fixed_ips': mock.ANY,
            'device_owner': l3_const.DEVICE_OWNER_AGENT_GW
        }
        self._test_prepare_direct_delete_dvr_internal_ports(port)

    def test_prevent_delete_csnat_port(self):
        port = {
            'id': 'my_port_id',
            'fixed_ips': mock.ANY,
            'device_owner': l3_const.DEVICE_OWNER_ROUTER_SNAT
        }
        self._test_prepare_direct_delete_dvr_internal_ports(port)

    def test__create_gw_port_with_no_gateway(self):
        router = {
            'name': 'foo_router',
            'admin_state_up': True,
            'distributed': True,
        }
        router_db = self._create_router(router)
        router_id = router_db['id']
        self.assertTrue(router_db.extra_attributes.distributed)
        with mock.patch.object(l3_dvr_db.l3_db.L3_NAT_db_mixin,
                               '_create_gw_port'),\
                mock.patch.object(
                    self.mixin,
                    '_create_snat_intf_ports_if_not_exists') as cs:
            self.mixin._create_gw_port(
                self.ctx, router_id, router_db, mock.ANY,
                mock.ANY)
            self.assertFalse(cs.call_count)

    def test_build_routers_list_with_gw_port_mismatch(self):
        routers = [{'gw_port_id': 'foo_gw_port_id', 'id': 'foo_router_id'}]
        gw_ports = {}
        routers = self.mixin._build_routers_list(self.ctx, routers, gw_ports)
        self.assertIsNone(routers[0].get('gw_port'))

    def test__clear_unused_fip_agent_gw_port(self):
        floatingip = {
            'id': _uuid(),
            'fixed_port_id': _uuid(),
            'floating_network_id': _uuid()
        }
        with mock.patch.object(l3_dvr_db.l3_db.L3_NAT_db_mixin,
                               '_get_floatingip') as gfips,\
                mock.patch.object(self.mixin, '_get_vm_port_hostid') as gvm,\
                mock.patch.object(
                    self.mixin,
                    '_check_fips_availability_on_host_ext_net') as cfips,\
                mock.patch.object(
                    self.mixin,
                    '_delete_floatingip_agent_gateway_port') as dfips:
            gfips.return_value = floatingip
            gvm.return_value = 'my-host'
            cfips.return_value = True
            self.mixin._clear_unused_fip_agent_gw_port(
                self.ctx, floatingip)
            self.assertTrue(dfips.called)
            self.assertTrue(cfips.called)
            self.assertTrue(gvm.called)

    def test__delete_floatingip_agent_gateway_port(self):
        port = {
            'id': 'my_port_id',
            'binding:host_id': 'foo_host',
            'network_id': 'ext_network_id',
            'device_owner': l3_const.DEVICE_OWNER_AGENT_GW
        }
        with mock.patch.object(manager.NeutronManager, 'get_plugin') as gp,\
                mock.patch.object(self.mixin,
                                  '_get_vm_port_hostid') as vm_host:
            plugin = mock.Mock()
            gp.return_value = plugin
            plugin.get_ports.return_value = [port]
            vm_host.return_value = 'foo_host'
            self.mixin._delete_floatingip_agent_gateway_port(
                self.ctx, 'foo_host', 'network_id')
        plugin.get_ports.assert_called_with(self.ctx, filters={
            'network_id': ['network_id'],
            'device_owner': [l3_const.DEVICE_OWNER_AGENT_GW]})
        plugin._delete_port.assert_called_with(self.ctx, 'my_port_id')

    def _delete_floatingip_test_setup(self, floatingip):
        fip_id = floatingip['id']
        with mock.patch.object(l3_dvr_db.l3_db.L3_NAT_db_mixin,
                               '_get_floatingip') as gf,\
                mock.patch.object(self.mixin,
                                  '_clear_unused_fip_agent_gw_port') as vf,\
                mock.patch.object(l3_dvr_db.l3_db.L3_NAT_db_mixin,
                                  'delete_floatingip'):
            gf.return_value = floatingip
            self.mixin.delete_floatingip(self.ctx, fip_id)
            return vf

    def _disassociate_floatingip_setup(self, port_id=None, floatingip=None):
        with mock.patch.object(self.mixin, '_get_floatingip_on_port') as gf,\
                mock.patch.object(self.mixin,
                                  '_clear_unused_fip_agent_gw_port') as vf:
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
            'router_id': 'foo_router_id',
            'host': hostid
        }
        if not hostid:
            hostid = 'not_my_host_id'
        routers = {
            'foo_router_id': router
        }
        fipagent = {
            'id': _uuid()
        }

        # NOTE: mock.patch is not needed here since self.mixin is created fresh
        # for each test.  It doesn't work with some methods since the mixin is
        # tested in isolation (e.g. _get_agent_by_type_and_host).
        self.mixin._get_vm_port_hostid = mock.Mock(return_value=hostid)
        self.mixin._get_agent_by_type_and_host = mock.Mock(
            return_value=fipagent)
        self.mixin._get_fip_sync_interfaces = mock.Mock(
            return_value='fip_interface')
        agent = mock.Mock()
        agent.id = fipagent['id']

        self.mixin._process_floating_ips_dvr(self.ctx, routers, [floatingip],
                                             hostid, agent)
        return (router, floatingip)

    def test_floatingip_on_port_not_host(self):
        router, fip = self._floatingip_on_port_test_setup(None)

        self.assertNotIn(l3_const.FLOATINGIP_KEY, router)
        self.assertNotIn(l3_const.FLOATINGIP_AGENT_INTF_KEY, router)

    def test_floatingip_on_port_with_host(self):
        router, fip = self._floatingip_on_port_test_setup(_uuid())

        self.assertTrue(self.mixin._get_fip_sync_interfaces.called)

        self.assertIn(l3_const.FLOATINGIP_KEY, router)
        self.assertIn(l3_const.FLOATINGIP_AGENT_INTF_KEY, router)
        self.assertIn(fip, router[l3_const.FLOATINGIP_KEY])
        self.assertIn('fip_interface',
            router[l3_const.FLOATINGIP_AGENT_INTF_KEY])

    def test_delete_disassociated_floatingip_agent_port(self):
        fip = {
            'id': _uuid(),
            'port_id': None
        }
        floatingip = {
            'id': _uuid(),
            'fixed_port_id': 1234,
            'router_id': 'foo_router_id'
        }
        router = {'id': 'foo_router_id', 'distributed': True}
        with mock.patch.object(self.mixin, 'get_router') as grtr,\
                mock.patch.object(self.mixin,
                                  '_clear_unused_fip_agent_gw_port') as vf,\
                mock.patch.object(l3_dvr_db.l3_db.L3_NAT_db_mixin,
                                  '_update_fip_assoc'):
            grtr.return_value = router
            self.mixin._update_fip_assoc(
                self.ctx, fip, floatingip, mock.ANY)
            self.assertTrue(vf.called)

    def _setup_test_create_delete_floatingip(
        self, fip, floatingip_db, router_db):
        port = {
            'id': '1234',
            'binding:host_id': 'myhost',
            'network_id': 'external_net'
        }

        with mock.patch.object(self.mixin, 'get_router') as grtr,\
                mock.patch.object(self.mixin, '_get_vm_port_hostid') as vmp,\
                mock.patch.object(self.mixin,
                                  '_clear_unused_fip_agent_gw_port') as d_fip,\
                mock.patch.object(
                    self.mixin,
                    'create_fip_agent_gw_port_if_not_exists') as c_fip,\
                mock.patch.object(l3_dvr_db.l3_db.L3_NAT_db_mixin,
                                  '_update_fip_assoc'):
            grtr.return_value = router_db
            vmp.return_value = 'my-host'
            self.mixin._update_fip_assoc(
                self.ctx, fip, floatingip_db, port)
            return d_fip, c_fip

    def test_create_floatingip_agent_gw_port_with_dvr_router(self):
        floatingip = {
            'id': _uuid(),
            'router_id': 'foo_router_id'
        }
        router = {'id': 'foo_router_id', 'distributed': True}
        fip = {
            'id': _uuid(),
            'port_id': _uuid()
        }
        delete_fip, create_fip = (
            self._setup_test_create_delete_floatingip(
                fip, floatingip, router))
        self.assertTrue(create_fip.called)
        self.assertFalse(delete_fip.called)

    def test_create_floatingip_agent_gw_port_with_non_dvr_router(self):
        floatingip = {
            'id': _uuid(),
            'router_id': 'foo_router_id'
        }
        router = {'id': 'foo_router_id', 'distributed': False}
        fip = {
            'id': _uuid(),
            'port_id': _uuid()
        }
        delete_fip, create_fip = (
            self._setup_test_create_delete_floatingip(
                fip, floatingip, router))
        self.assertFalse(create_fip.called)
        self.assertFalse(delete_fip.called)

    def test_delete_floatingip_agent_gw_port_with_dvr_router(self):
        floatingip = {
            'id': _uuid(),
            'fixed_port_id': 1234,
            'router_id': 'foo_router_id'
        }
        router = {'id': 'foo_router_id', 'distributed': True}
        fip = {
            'id': _uuid(),
            'port_id': None
        }
        delete_fip, create_fip = (
            self._setup_test_create_delete_floatingip(
                fip, floatingip, router))
        self.assertTrue(delete_fip.called)
        self.assertFalse(create_fip.called)

    def test_delete_floatingip_agent_gw_port_with_non_dvr_router(self):
        floatingip = {
            'id': _uuid(),
            'fixed_port_id': 1234,
            'router_id': 'foo_router_id'
        }
        router = {'id': 'foo_router_id', 'distributed': False}
        fip = {
            'id': _uuid(),
            'port_id': None
        }
        delete_fip, create_fip = (
            self._setup_test_create_delete_floatingip(
                fip, floatingip, router))
        self.assertFalse(create_fip.called)
        self.assertFalse(delete_fip.called)

    def test_remove_router_interface_delete_router_l3agent_binding(self):
        interface_info = {'subnet_id': '123'}
        router = mock.MagicMock()
        router.extra_attributes.distributed = True
        plugin = mock.MagicMock()
        plugin.get_l3_agents_hosting_routers = mock.Mock(
            return_value=[mock.MagicMock()])
        plugin.check_ports_exist_on_l3agent = mock.Mock(
            return_value=False)
        plugin.remove_router_from_l3_agent = mock.Mock(
            return_value=None)
        with mock.patch.object(self.mixin, '_get_router') as grtr,\
                mock.patch.object(self.mixin, '_get_device_owner') as gdev,\
                mock.patch.object(self.mixin,
                                  '_remove_interface_by_subnet') as rmintf,\
                mock.patch.object(
                    self.mixin,
                    'delete_csnat_router_interface_ports') as delintf,\
                mock.patch.object(manager.NeutronManager,
                                  'get_service_plugins') as gplugin,\
                mock.patch.object(self.mixin,
                                  '_make_router_interface_info') as mkintf,\
                mock.patch.object(self.mixin,
                                  'notify_router_interface_action') as notify:
            grtr.return_value = router
            gdev.return_value = mock.Mock()
            rmintf.return_value = (mock.MagicMock(), mock.MagicMock())
            mkintf.return_value = mock.Mock()
            gplugin.return_value = {plugin_const.L3_ROUTER_NAT: plugin}
            delintf.return_value = None
            notify.return_value = None

            self.mixin.manager = manager
            self.mixin.remove_router_interface(
                self.ctx, mock.Mock(), interface_info)
            self.assertTrue(plugin.get_l3_agents_hosting_routers.called)
            self.assertTrue(plugin.check_ports_exist_on_l3agent.called)
            self.assertTrue(plugin.remove_router_from_l3_agent.called)

    def test__validate_router_migration_notify_advanced_services(self):
        router = {'name': 'foo_router', 'admin_state_up': True}
        router_db = self._create_router(router)
        with mock.patch.object(l3_dvr_db.registry, 'notify') as mock_notify:
            self.mixin._validate_router_migration(
                self.ctx, router_db, {'distributed': True})
            kwargs = {'context': self.ctx, 'router': router_db}
            mock_notify.assert_called_once_with(
                'router', 'before_update', self.mixin, **kwargs)
