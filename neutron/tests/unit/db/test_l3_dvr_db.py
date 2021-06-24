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

from unittest import mock

from neutron_lib.api.definitions import portbindings
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants as const
from neutron_lib import context
from neutron_lib.db import api as db_api
from neutron_lib import exceptions
from neutron_lib.exceptions import l3 as l3_exc
from neutron_lib.objects import exceptions as o_exc
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory
from neutron_lib.plugins import utils as plugin_utils
from oslo_utils import uuidutils

from neutron.common import utils as common_utils
from neutron.db import agents_db
from neutron.db import l3_dvr_db
from neutron.db import l3_dvrscheduler_db
from neutron.db.models import l3 as l3_models
from neutron.db import models_v2
from neutron.objects import agent as agent_obj
from neutron.objects import l3agent as rb_obj
from neutron.objects import ports as port_obj
from neutron.objects import router as router_obj
from neutron.tests.unit.db import test_db_base_plugin_v2
from neutron.tests.unit.extensions import test_l3

_uuid = uuidutils.generate_uuid


class FakeL3Plugin(test_l3.TestL3PluginBaseAttributes,
                   l3_dvr_db.L3_NAT_with_dvr_db_mixin,
                   l3_dvrscheduler_db.L3_DVRsch_db_mixin,
                   agents_db.AgentDbMixin):
    pass


class L3DvrTestCase(test_db_base_plugin_v2.NeutronDbPluginV2TestCase):

    def setUp(self):
        super(L3DvrTestCase, self).setUp(plugin='ml2')
        self.core_plugin = directory.get_plugin()
        self.ctx = context.get_admin_context()
        self.mixin = FakeL3Plugin()
        directory.add_plugin(plugin_constants.L3, self.mixin)

    def _create_router(self, router):
        with db_api.CONTEXT_WRITER.using(self.ctx):
            return self.mixin._create_router_db(self.ctx, router, 'foo_tenant')

    def create_port(self, net_id, port_info):
        with db_api.CONTEXT_WRITER.using(self.ctx):
            return self._create_port(self.fmt, net_id, **port_info)

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

    def _test__validate_router_migration_on_router_update(self, mock_arg):
        router = {
            'name': 'foo_router',
            'admin_state_up': True,
            'distributed': True
        }
        router_db = self._create_router(router)
        self.assertFalse(self.mixin._validate_router_migration(
            self.ctx, router_db, {'name': 'foo_router_2'}))

    # mock the check function to indicate that the variable
    # _admin_state_down_necessary set to True
    @mock.patch('neutron.db.l3_dvr_db.is_admin_state_down_necessary',
                return_value=True)
    def test__validate_router_migration_on_router_update_mock(self,
            mock_arg):
        # call test with admin_state_down_before_update ENABLED
        self._test__validate_router_migration_on_router_update(mock_arg)

    # mock the check function to indicate that the variable
    # _admin_state_down_necessary set to False
    @mock.patch('neutron.db.l3_dvr_db.is_admin_state_down_necessary',
                return_value=False)
    def test__validate_router_migration_on_router_update(self, mock_arg):
        # call test with admin_state_down_before_update DISABLED
        self._test__validate_router_migration_on_router_update(mock_arg)

    def _test__validate_router_migration_raise_error(self):
        router = {
            'name': 'foo_router',
            'admin_state_up': True,
            'distributed': True
        }
        router_db = self._create_router(router)
        self.assertRaises(exceptions.BadRequest,
                          self.mixin._validate_router_migration,
                          self.ctx, router_db, {'distributed': False})

    @mock.patch('neutron.db.l3_dvr_db.is_admin_state_down_necessary',
                return_value=True)
    def test__validate_router_migration_raise_error_mocked(self, mock_arg):
        # call test with admin_state_down_before_update ENABLED
        self._test__validate_router_migration_raise_error()

    @mock.patch('neutron.db.l3_dvr_db.is_admin_state_down_necessary',
                return_value=False)
    def test__validate_router_migration_raise_error(self, mock_arg):
        # call test with admin_state_down_before_update DISABLED
        self._test__validate_router_migration_raise_error()

    @mock.patch('neutron.db.l3_dvr_db.is_admin_state_down_necessary',
                return_value=True)
    def test__validate_router_migration_old_router_up_raise_error(self,
            mock_arg):
        # call test with admin_state_down_before_update ENABLED
        old_router = {
            'name': 'bar_router',
            'admin_state_up': True,
            'distributed': True
        }
        new_router = {
            'name': 'foo_router',
            'admin_state_up': False,
            'distributed': False
        }
        update = {'distributed': False}
        router_db = self._create_router(new_router)
        self.assertRaises(exceptions.BadRequest,
                          self.mixin._validate_router_migration,
                          self.ctx, router_db, update,
                          old_router)

    def _test_upgrade_inactive_router_to_distributed_validation_success(self):
        router = {'name': 'foo_router', 'admin_state_up': False,
                 'distributed': False}
        router_db = self._create_router(router)
        update = {'distributed': True}
        self.assertTrue(self.mixin._validate_router_migration(
            self.ctx, router_db, update))

    @mock.patch('neutron.db.l3_dvr_db.is_admin_state_down_necessary',
                return_value=True)
    def test_upgrade_inactive_router_to_distributed_validation_success_mocked(
            self, mock_arg):
        # call test with admin_state_down_before_update ENABLED
        self._test_upgrade_inactive_router_to_distributed_validation_success()

    @mock.patch('neutron.db.l3_dvr_db.is_admin_state_down_necessary',
                return_value=False)
    def test_upgrade_inactive_router_to_distributed_validation_success(self,
            mock_arg):
        # call test with admin_state_down_before_update DISABLED
        self._test_upgrade_inactive_router_to_distributed_validation_success()

    def _test_upgrade_active_router_to_distributed_validation_failure(self):
        router = {'name': 'foo_router', 'admin_state_up': True,
                 'distributed': False}
        router_db = self._create_router(router)
        update = {'distributed': True}
        self.assertRaises(exceptions.BadRequest,
                          self.mixin._validate_router_migration,
                          self.ctx, router_db, update)

    @mock.patch('neutron.db.l3_dvr_db.is_admin_state_down_necessary',
                return_value=True)
    def test_upgrade_active_router_to_distributed_validation_failure(self,
            mock_arg):
        # call test with admin_state_down_before_update ENABLED
        self._test_upgrade_active_router_to_distributed_validation_failure()

    @mock.patch('neutron.db.l3_dvr_db.is_admin_state_down_necessary',
                return_value=True)
    def test_downgrade_active_router_to_centralized_validation_failure(self,
            mock_arg):
        # call test with admin_state_down_before_update ENABLED
        router = {'name': 'foo_router', 'admin_state_up': True,
                'distributed': True}
        router_db = self._create_router(router)
        update = {'distributed': False}
        self.assertRaises(exceptions.BadRequest,
                          self.mixin._validate_router_migration,
                          self.ctx, router_db, update)

    def test_update_router_db_centralized_to_distributed(self):
        router = {'name': 'foo_router', 'admin_state_up': True}
        agent = {'id': _uuid()}
        distributed = {'distributed': True}
        router_db = self._create_router(router)
        router_id = router_db['id']
        self.assertFalse(router_db.extra_attributes.distributed)
        self.mixin._get_router = mock.Mock(return_value=router_db)
        self.mixin._validate_router_migration = mock.Mock()
        self.mixin._migrate_router_ports = mock.Mock()
        self.mixin.list_l3_agents_hosting_router = mock.Mock(
            return_value={'agents': [agent]})
        self.mixin._unbind_router = mock.Mock()
        router_db = self.mixin._update_router_db(
            self.ctx, router_id, distributed)
        # Assert that the DB value has changed
        self.assertTrue(router_db.extra_attributes.distributed)
        self.assertEqual(1,
                         self.mixin._migrate_router_ports.call_count)

    def test_update_router_db_distributed_to_centralized(self):
        router = {'name': 'foo_router', 'admin_state_up': True,
                  'distributed': True}
        agent = {'id': _uuid(), 'host': 'xyz'}
        router_db = self._create_router(router)
        router_id = router_db['id']
        self.assertTrue(router_db.extra_attributes.distributed)
        self.mixin._get_router = mock.Mock(return_value=router_db)
        self.mixin._validate_router_migration = mock.Mock()
        self.mixin._migrate_router_ports = mock.Mock()
        self.mixin._core_plugin.\
            delete_distributed_port_bindings_by_router_id = mock.Mock()
        self.mixin.list_l3_agents_hosting_router = mock.Mock(
            return_value={'agents': [agent]})
        self.mixin._unbind_router = mock.Mock()
        updated_router = self.mixin.update_router(self.ctx, router_id,
            {'router': {'distributed': False}})
        # Assert that the DB value has changed
        self.assertFalse(updated_router['distributed'])
        self.assertEqual(1,
                         self.mixin._migrate_router_ports.call_count)
        self.assertEqual(
            1,
            self.mixin._core_plugin.
            delete_distributed_port_bindings_by_router_id.call_count)

    def _test_get_device_owner(self, is_distributed=False,
                               expected=const.DEVICE_OWNER_ROUTER_INTF,
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
            expected=const.DEVICE_OWNER_DVR_INTERFACE,
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
        plugin = mock.Mock()
        directory.add_plugin(plugin_constants.CORE, plugin)
        plugin.get_ports.return_value = []
        self.mixin._get_agent_gw_ports_exist_for_network(
            self.ctx, 'network_id', 'host', 'agent_id')
        plugin.get_ports.assert_called_with(self.ctx, {
            'network_id': ['network_id'],
            'device_id': ['agent_id'],
            'device_owner': [const.DEVICE_OWNER_AGENT_GW]})

    def _help_check_and_create_fip_gw_port(self, fip=None):
        port = {
            'id': '1234',
            portbindings.HOST_ID: 'myhost',
            'floating_network_id': 'external_net'
        }
        ctxt = mock.Mock()
        with mock.patch.object(self.mixin,
                'create_fip_agent_gw_port_if_not_exists') as c_fip,\
                mock.patch.object(router_obj.FloatingIP, 'get_objects',
                                  return_value=[fip] if fip else None):
            (self.mixin.
             check_for_fip_and_create_agent_gw_port_on_host_if_not_exists(
                    ctxt, port, 'host'))
            if fip:
                c_fip.assert_called_once_with(
                    common_utils.get_elevated_context(ctxt),
                    fip['floating_network_id'], 'host')
            else:
                c_fip.assert_not_called()

    def test_check_for_fip_and_create_agent_gw_port_no_fip(self):
        self._help_check_and_create_fip_gw_port()

    def test_check_for_fip_and_create_agent_gw_port_with_dvr_true(self):
        fip = {
            'id': _uuid(),
            'floating_network_id': 'fake_net_id',
            'router_id': 'foo_router_id'
        }
        self._help_check_and_create_fip_gw_port(fip=fip)

    def _test_prepare_direct_delete_dvr_internal_ports(self, port):
        plugin = mock.Mock()
        directory.add_plugin(plugin_constants.CORE, plugin)
        plugin.get_port.return_value = port
        with mock.patch.object(router_obj.Router, 'objects_exist',
                               return_value=True):
            self.assertRaises(exceptions.ServicePortInUse,
                              self.mixin.prevent_l3_port_deletion,
                              self.ctx, port['id'])

    def test_prevent_delete_floatingip_agent_gateway_port(self):
        port = {
            'id': 'my_port_id',
            'fixed_ips': mock.ANY,
            'device_id': 'r_id',
            'device_owner': const.DEVICE_OWNER_AGENT_GW
        }
        self._test_prepare_direct_delete_dvr_internal_ports(port)

    def test_prevent_delete_csnat_port(self):
        port = {
            'id': 'my_port_id',
            'fixed_ips': mock.ANY,
            'device_id': 'r_id',
            'device_owner': const.DEVICE_OWNER_ROUTER_SNAT
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

    def _helper_delete_floatingip_agent_gateway_port(
            self, port_host, delete_dvr_fip_agent_port_side_effect=None):
        ports = [{
            'id': 'my_port_id',
            portbindings.HOST_ID: 'foo_host',
            'network_id': 'ext_network_id',
            'device_owner': const.DEVICE_OWNER_ROUTER_GW
        },
                {
            'id': 'my_new_port_id',
            portbindings.HOST_ID: 'my_foo_host',
            'network_id': 'ext_network_id',
            'device_owner': const.DEVICE_OWNER_ROUTER_GW
        }]
        plugin = mock.Mock()
        directory.add_plugin(plugin_constants.CORE, plugin)
        plugin.get_ports.return_value = ports
        self.mixin._get_agent_by_type_and_host = mock.Mock(
            return_value={'id': uuidutils.generate_uuid()})

        with mock.patch.object(
            router_obj, "DvrFipGatewayPortAgentBinding"
        ) as dvr_fip_agent_port_obj:
            dvr_fip_agent_port_obj_instance = (
                dvr_fip_agent_port_obj.return_value)
            dvr_fip_agent_port_obj_instance.delete.side_effect = (
                delete_dvr_fip_agent_port_side_effect)

            self.mixin.delete_floatingip_agent_gateway_port(
                self.ctx, port_host, 'ext_network_id')

        plugin.get_ports.assert_called_with(self.ctx, filters={
            'network_id': ['ext_network_id'],
            'device_owner': [const.DEVICE_OWNER_AGENT_GW]})
        if port_host:
            plugin.ipam.delete_port.assert_called_once_with(
                self.ctx, 'my_port_id')
            dvr_fip_agent_port_obj_instance.delete.assert_called_once()
        else:
            plugin.ipam.delete_port.assert_called_with(
                self.ctx, 'my_new_port_id')
            dvr_fip_agent_port_obj_instance.delete.assert_called()

    def test_delete_floatingip_agent_gateway_port_without_host_id(self):
        self._helper_delete_floatingip_agent_gateway_port(None)

    def test_delete_floatingip_agent_gateway_port_with_host_id(self):
        self._helper_delete_floatingip_agent_gateway_port(
            'foo_host')

    def test_delete_floatingip_agent_gateway_port_no_host_id_fip_gw_not_found(
            self):
        self._helper_delete_floatingip_agent_gateway_port(
                None, exceptions.ObjectNotFound(id='my_port_id'))

    def test_delete_floatingip_agent_gateway_port_host_id_fip_gw_not_found(
            self):
        self._helper_delete_floatingip_agent_gateway_port(
            'foo_host', exceptions.ObjectNotFound(id='my_port_id'))

    def _setup_delete_current_gw_port_deletes_dvr_internal_ports(
            self, port=None, gw_port=True, new_network_id='ext_net_id_2'):
        router_db = {
            'name': 'foo_router',
            'admin_state_up': True,
            'distributed': True
        }
        with db_api.CONTEXT_WRITER.using(self.ctx):
            router = self._create_router(router_db)
            if gw_port:
                with self.subnet(cidr='10.10.10.0/24') as subnet:
                    port_dict = {
                        'device_id': router.id,
                        'device_owner': const.DEVICE_OWNER_ROUTER_GW,
                        'admin_state_up': True,
                        'fixed_ips': [{'subnet_id': subnet['subnet']['id'],
                                       'ip_address': '10.10.10.100'}]
                    }
                net_id = subnet['subnet']['network_id']
                port_res = self.create_port(net_id, port_dict)
                port_res_dict = self.deserialize(self.fmt, port_res)
                port_db = self.ctx.session.query(models_v2.Port).filter_by(
                    id=port_res_dict['port']['id']).one()
                router.gw_port = port_db
                router_port = l3_models.RouterPort(
                    router_id=router.id,
                    port_id=port_db.id,
                    port_type=const.DEVICE_OWNER_ROUTER_GW
                )
                self.ctx.session.add(router)
                self.ctx.session.add(router_port)
            else:
                net_id = None

        plugin = mock.Mock()
        directory.add_plugin(plugin_constants.CORE, plugin)
        with mock.patch.object(l3_dvr_db.l3_db.L3_NAT_db_mixin,
                               'router_gw_port_has_floating_ips',
                               return_value=False),\
            mock.patch.object(
                self.mixin,
                '_get_router') as grtr,\
            mock.patch.object(
                self.mixin,
                'delete_csnat_router_interface_ports') as del_csnat_port,\
            mock.patch.object(
                self.mixin,
                'delete_floatingip_agent_gateway_port') as del_agent_gw_port,\
            mock.patch.object(
                self.mixin.l3_rpc_notifier,
                'delete_fipnamespace_for_ext_net') as del_fip:
            plugin.get_ports.return_value = port
            grtr.return_value = router
            self.mixin._delete_current_gw_port(
                self.ctx, router['id'], router, new_network_id)
            return router, plugin, net_id, del_csnat_port,\
                del_agent_gw_port, del_fip

    def test_delete_current_gw_port_deletes_fip_agent_gw_port_and_fipnamespace(
            self):
        rtr, plugin, ext_net_id, d_csnat_port, d_agent_gw_port, del_fip = (
            self._setup_delete_current_gw_port_deletes_dvr_internal_ports())
        self.assertFalse(d_csnat_port.called)
        self.assertTrue(d_agent_gw_port.called)
        d_agent_gw_port.assert_called_once_with(mock.ANY, None, ext_net_id)
        del_fip.assert_called_once_with(self.ctx, ext_net_id)

    def test_delete_current_gw_port_never_calls_delete_fip_agent_gw_port(self):
        port = [{
            'id': 'my_port_id',
            'network_id': 'ext_net_id',
            'device_owner': const.DEVICE_OWNER_ROUTER_GW
        },
                {
            'id': 'my_new_port_id',
            'network_id': 'ext_net_id',
            'device_owner': const.DEVICE_OWNER_ROUTER_GW
        }]
        rtr, plugin, ext_net_id, d_csnat_port, d_agent_gw_port, del_fip = (
            self._setup_delete_current_gw_port_deletes_dvr_internal_ports(
                port=port))
        self.assertFalse(d_csnat_port.called)
        self.assertFalse(d_agent_gw_port.called)
        self.assertFalse(del_fip.called)
        self.assertIsNotNone(ext_net_id)

    def test_delete_current_gw_port_never_calls_delete_fipnamespace(self):
        rtr, plugin, ext_net_id, d_csnat_port, d_agent_gw_port, del_fip = (
            self._setup_delete_current_gw_port_deletes_dvr_internal_ports(
                gw_port=False))
        self.assertFalse(d_csnat_port.called)
        self.assertFalse(d_agent_gw_port.called)
        self.assertFalse(del_fip.called)
        self.assertIsNone(ext_net_id)

    def test_delete_current_gw_port_deletes_csnat_port(self):
        rtr, plugin, ext_net_id, d_csnat_port, d_agent_gw_port, del_fip = (
            self._setup_delete_current_gw_port_deletes_dvr_internal_ports(
                new_network_id=None))
        self.assertTrue(d_csnat_port.called)
        self.assertTrue(d_agent_gw_port.called)
        d_csnat_port.assert_called_once_with(mock.ANY, rtr)
        d_agent_gw_port.assert_called_once_with(mock.ANY, None, ext_net_id)
        del_fip.assert_called_once_with(mock.ANY, ext_net_id)

    def _floatingip_on_port_test_setup(self, hostid):
        router = {'id': 'foo_router_id', 'distributed': True}
        floatingip = {
            'id': _uuid(),
            'port_id': _uuid(),
            'router_id': 'foo_router_id',
        }
        if hostid is not None:
            floatingip['host'] = hostid
        else:
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
        self.mixin._get_dvr_service_port_hostid = mock.Mock(
            return_value=hostid)
        self.mixin._get_agent_by_type_and_host = mock.Mock(
            return_value=fipagent)
        self.mixin._get_fip_agent_gw_ports = mock.Mock(
            return_value='fip_interface')
        agent = mock.Mock()
        agent.id = fipagent['id']
        self.mixin._process_floating_ips_dvr(self.ctx, routers, [floatingip],
                                             hostid, agent)
        return (router, floatingip)

    def test_floatingip_on_port_no_host_key(self):
        router, fip = self._floatingip_on_port_test_setup(None)

        self.assertNotIn(const.FLOATINGIP_KEY, router)

    def test_floatingip_on_port_with_host(self):
        router, fip = self._floatingip_on_port_test_setup(_uuid())

        self.assertIn(const.FLOATINGIP_KEY, router)
        self.assertIn(fip, router[const.FLOATINGIP_KEY])

    def _setup_test_create_floatingip(self, fip, floatingip_db, router_db):
        port = {
            'id': '1234',
            portbindings.HOST_ID: 'myhost',
            'network_id': 'external_net'
        }

        with mock.patch.object(self.mixin, 'get_router') as grtr,\
                mock.patch.object(self.mixin,
                                  '_get_dvr_service_port_hostid') as vmp,\
                mock.patch.object(
                    self.mixin,
                    '_get_dvr_migrating_service_port_hostid'
                                 ) as mvmp,\
                mock.patch.object(
                    self.mixin,
                    'create_fip_agent_gw_port_if_not_exists') as c_fip,\
                mock.patch.object(l3_dvr_db.l3_db.L3_NAT_db_mixin,
                                  '_update_fip_assoc'):
            grtr.return_value = router_db
            vmp.return_value = 'my-host'
            mvmp.return_value = 'my-future-host'
            registry.notify(resources.FLOATING_IP, events.AFTER_UPDATE, self,
                            context=mock.Mock(), router_id=router_db['id'],
                            fixed_port_id=port['id'], floating_ip_id=fip['id'],
                            floating_network_id=fip['floating_network_id'],
                            fixed_ip_address='1.2.3.4', association_event=True)
            return c_fip

    def test_create_floatingip_agent_gw_port_with_dvr_router(self):
        floatingip = {
            'id': _uuid(),
            'router_id': 'foo_router_id'
        }
        router = {'id': 'foo_router_id', 'distributed': True}
        fip = {
            'id': _uuid(),
            'floating_network_id': _uuid(),
            'port_id': _uuid()
        }
        create_fip = (
            self._setup_test_create_floatingip(
                fip, floatingip, router))
        self.assertTrue(create_fip.called)

    def test_create_fip_agent_gw_port_if_not_exists_with_l3_agent(self):
        network_id = _uuid()
        fport_db = {'id': _uuid()}
        self.mixin._get_agent_gw_ports_exist_for_network = mock.Mock(
            return_value=fport_db)

        fipagent = agent_obj.Agent(
                self.ctx,
                id=_uuid(),
                binary='foo-agent',
                host='host',
                agent_type='L3 agent',
                topic='foo_topic',
                configurations={"agent_mode": "dvr_no_external"})
        self.mixin._get_agent_by_type_and_host = mock.Mock(
            return_value=fipagent)
        fport = self.mixin.create_fip_agent_gw_port_if_not_exists(
                                                self.ctx,
                                                network_id,
                                                'host')
        self.assertIsNone(fport)

        fipagent = agent_obj.Agent(
                self.ctx,
                id=_uuid(),
                binary='foo-agent',
                host='host',
                agent_type='L3 agent',
                topic='foo_topic',
                configurations={"agent_mode": "dvr"})
        self.mixin._get_agent_by_type_and_host = mock.Mock(
            return_value=fipagent)
        with mock.patch.object(
            router_obj, "DvrFipGatewayPortAgentBinding",
        ) as dvr_fip_agent_port_obj:
            dvr_fip_agent_port_obj_instance = (
                dvr_fip_agent_port_obj.return_value)
            fport = self.mixin.create_fip_agent_gw_port_if_not_exists(
                                                    self.ctx,
                                                    network_id,
                                                    'host')

        dvr_fip_agent_port_obj_instance.create.assert_not_called()
        self.assertIsNotNone(fport)
        dvr_fip_agent_port_obj_instance.delete.assert_not_called()

    def test_create_fip_agent_gw_port_agent_port_not_created(self):
        network_id = _uuid()
        self.mixin._get_agent_gw_ports_exist_for_network = mock.Mock(
            return_value=None)
        fipagent = agent_obj.Agent(
                self.ctx,
                id=_uuid(),
                binary='foo-agent',
                host='host',
                agent_type='L3 agent',
                topic='foo_topic',
                configurations={"agent_mode": "dvr"})
        self.mixin._get_agent_by_type_and_host = mock.Mock(
            return_value=fipagent)

        with mock.patch.object(
            router_obj, "DvrFipGatewayPortAgentBinding",
        ) as dvr_fip_agent_port_obj,\
            mock.patch.object(
                plugin_utils, "create_port", return_value=None):

            dvr_fip_agent_port_obj_instance = (
                dvr_fip_agent_port_obj.return_value)

            self.assertRaises(
                exceptions.BadRequest,
                self.mixin.create_fip_agent_gw_port_if_not_exists,
                self.ctx, network_id, 'host')

        dvr_fip_agent_port_obj_instance.create.assert_called_once_with()
        self.mixin._get_agent_gw_ports_exist_for_network.\
            assert_called_once_with(
                self.ctx, network_id, 'host', fipagent['id'])
        dvr_fip_agent_port_obj_instance.delete.assert_called_once_with()

    def test_create_fip_agent_gw_port_if_not_exists_duplicate_port(self):
        network_id = _uuid()
        fport_db = {'id': _uuid()}
        self.mixin._get_agent_gw_ports_exist_for_network = mock.Mock(
            side_effect=[None, fport_db])
        fipagent = agent_obj.Agent(
                self.ctx,
                id=_uuid(),
                binary='foo-agent',
                host='host',
                agent_type='L3 agent',
                topic='foo_topic',
                configurations={"agent_mode": "dvr"})
        self.mixin._get_agent_by_type_and_host = mock.Mock(
            return_value=fipagent)

        with mock.patch.object(
            router_obj.DvrFipGatewayPortAgentBinding, 'create',
            side_effect=o_exc.NeutronDbObjectDuplicateEntry(
                mock.Mock(), mock.Mock())
        ) as dvr_fip_gateway_port_agent_binding_create:
            fport = self.mixin.create_fip_agent_gw_port_if_not_exists(
                                                    self.ctx,
                                                    network_id,
                                                    'host')
        dvr_fip_gateway_port_agent_binding_create.assert_called_once_with()
        self.mixin._get_agent_gw_ports_exist_for_network.assert_has_calls([
            mock.call(self.ctx, network_id, 'host', fipagent['id']),
            mock.call(self.ctx, network_id, 'host', fipagent['id'])])
        self.assertIsNotNone(fport)

    def test_create_fip_agent_gw_port_agent_binding_exists(self):
        network_id = _uuid()
        fport_db = {'id': _uuid()}
        self.mixin._get_agent_gw_ports_exist_for_network = mock.Mock(
            side_effect=[None, None])
        fipagent = agent_obj.Agent(
                self.ctx,
                id=_uuid(),
                binary='foo-agent',
                host='host',
                agent_type='L3 agent',
                topic='foo_topic',
                configurations={"agent_mode": "dvr"})
        self.mixin._get_agent_by_type_and_host = mock.Mock(
            return_value=fipagent)
        self.mixin._populate_mtu_and_subnets_for_ports = mock.Mock()

        with mock.patch.object(
            router_obj.DvrFipGatewayPortAgentBinding, 'create',
            side_effect=o_exc.NeutronDbObjectDuplicateEntry(
                mock.Mock(), mock.Mock())
        ) as dvr_fip_gateway_port_agent_binding_create,\
            mock.patch.object(
                plugin_utils, "create_port", return_value=fport_db):
            fport = self.mixin.create_fip_agent_gw_port_if_not_exists(
                                                    self.ctx,
                                                    network_id,
                                                    'host')
        dvr_fip_gateway_port_agent_binding_create.assert_called_once_with()
        self.mixin._get_agent_gw_ports_exist_for_network.assert_has_calls([
            mock.call(self.ctx, network_id, 'host', fipagent['id']),
            mock.call(self.ctx, network_id, 'host', fipagent['id'])])
        self.mixin._populate_mtu_and_subnets_for_ports.assert_has_calls([
            mock.call(self.ctx, [fport_db])])
        self.assertIsNotNone(fport)

    def test_create_floatingip_agent_gw_port_with_non_dvr_router(self):
        floatingip = {
            'id': _uuid(),
            'router_id': 'foo_router_id'
        }
        router = {'id': 'foo_router_id', 'distributed': False}
        fip = {
            'id': _uuid(),
            'floating_network_id': _uuid(),
            'port_id': _uuid()
        }
        create_fip = (
            self._setup_test_create_floatingip(
                fip, floatingip, router))
        self.assertFalse(create_fip.called)

    def test_get_ext_nets_by_host(self):
        ports = [mock.Mock(id=_uuid()) for _ in range(3)]
        fips = [mock.Mock(fixed_port_id=p.id, floating_network_id=_uuid())
                for p in ports]
        expected_ext_nets = set([fip.floating_network_id for fip in fips])
        with mock.patch.object(
            port_obj.Port, 'get_ports_by_host',
            return_value=[p.id for p in ports]
        ) as get_ports_by_host, mock.patch.object(
            self.mixin, '_get_floatingips_by_port_id', return_value=fips
        ) as get_floatingips_by_port_id:
            self.assertEqual(
                expected_ext_nets,
                self.mixin._get_ext_nets_by_host(self.ctx, 'host'))
            get_ports_by_host.assert_called_once_with(self.ctx, 'host')
            get_floatingips_by_port_id.assert_has_calls(
                [mock.call(self.ctx, p.id) for p in ports])

    def _test_create_fip_agent_gw_ports(self, agent_type, agent_mode=None):
        agent = {
            'id': _uuid(),
            'host': 'host',
            'agent_type': agent_type,
            'configurations': {'agent_mode': agent_mode}}
        payload = events.DBEventPayload(
            self.ctx, states=(agent,), resource_id=agent['id'])

        ext_nets = ['ext-net-1', 'ext-net-2']
        with mock.patch.object(
            self.mixin,
            'create_fip_agent_gw_port_if_not_exists'
        ) as create_fip_gw, mock.patch.object(
            self.mixin, "_get_ext_nets_by_host",
            return_value=ext_nets
        ) as get_ext_nets_by_host:

            registry.publish(resources.AGENT, events.AFTER_CREATE, mock.Mock(),
                             payload=payload)

            if agent_type == 'L3 agent' and agent_mode in ['dvr', 'dvr_snat']:
                get_ext_nets_by_host.assert_called_once_with(
                    mock.ANY, 'host')
                create_fip_gw.assert_has_calls(
                    [mock.call(mock.ANY, ext_net, 'host') for
                        ext_net in ext_nets])
            else:
                get_ext_nets_by_host.assert_not_called()
                create_fip_gw.assert_not_called()

    def test_create_fip_agent_gw_ports(self):
        self._test_create_fip_agent_gw_ports(
            agent_type='L3 agent', agent_mode='dvr')
        self._test_create_fip_agent_gw_ports(
            agent_type='L3 agent', agent_mode='dvr_snat')

    def test_create_fip_agent_gw_ports_dvr_no_external_agent(self):
        self._test_create_fip_agent_gw_ports(
            agent_type='L3 agent', agent_mode='dvr_no_external')

    def test_create_fip_agent_gw_ports_non_dvr_agent(self):
        self._test_create_fip_agent_gw_ports(
            agent_type='L3 agent', agent_mode='legacy')

    def test_create_fip_agent_gw_ports_deleted_non_l3_agent(self):
        self._test_create_fip_agent_gw_ports('Other agent type')

    def _test_delete_fip_agent_gw_ports(self, agent_type, agent_mode=None):
        agent = agent_obj.Agent(
            self.ctx, id=_uuid(), agent_type=agent_type,
            configurations={"agent_mode": agent_mode})
        payload = events.DBEventPayload(
            self.ctx, states=(agent,), resource_id=agent.id)

        gw_port = {'id': _uuid(), 'network_id': _uuid()}
        with mock.patch.object(
            self.mixin, '_get_agent_gw_ports',
            return_value=[gw_port]
        ) as get_agent_gw_ports, mock.patch.object(
            self.core_plugin, 'delete_port'
        ) as delete_port:
            registry.publish(resources.AGENT, events.AFTER_DELETE, mock.Mock(),
                             payload=payload)

            if agent_type == 'L3 agent' and agent_mode in ['dvr', 'dvr_snat']:
                get_agent_gw_ports.assert_called_once_with(payload.context,
                                                           agent['id'])
                delete_port.assert_called_once_with(payload.context,
                                                    gw_port['id'])
            else:
                get_agent_gw_ports.assert_not_called()
                delete_port.assert_not_called()

    def test_delete_fip_agent_gw_ports(self):
        self._test_delete_fip_agent_gw_ports(
            agent_type='L3 agent', agent_mode='dvr')
        self._test_delete_fip_agent_gw_ports(
            agent_type='L3 agent', agent_mode='dvr_snat')

    def test_delete_fip_agent_gw_ports_dvr_no_external_agent(self):
        self._test_delete_fip_agent_gw_ports(
            agent_type='L3 agent', agent_mode='dvr_no_external')

    def test_delete_fip_agent_gw_ports_non_dvr_agent(self):
        self._test_delete_fip_agent_gw_ports(
            agent_type='L3 agent', agent_mode='legacy')

    def test_delete_fip_agent_gw_ports_deleted_non_l3_agent(self):
        self._test_delete_fip_agent_gw_ports('Other agent type')

    def _test_update_router_gw_info_external_network_change(self):
        router_dict = {'name': 'test_router', 'admin_state_up': True,
                       'distributed': True}
        router = self._create_router(router_dict)
        with self.network() as net_ext_1,\
                self.network() as net_ext_2,\
                self.subnet() as subnet:
            ext_net_1_id = net_ext_1['network']['id']
            self.core_plugin.update_network(
                self.ctx, ext_net_1_id,
                {'network': {'router:external': True}})
            self.mixin.update_router(
                self.ctx, router['id'],
                {'router': {'external_gateway_info':
                            {'network_id': ext_net_1_id}}})
            self.mixin.add_router_interface(self.ctx, router['id'],
                {'subnet_id': subnet['subnet']['id']})

            ext_net_2_id = net_ext_2['network']['id']
            self.core_plugin.update_network(
                self.ctx, ext_net_2_id,
                {'network': {'router:external': True}})
            self.mixin.update_router(
                self.ctx, router['id'],
                {'router': {'external_gateway_info':
                            {'network_id': ext_net_2_id}}})

            csnat_filters = {'device_owner': [const.DEVICE_OWNER_ROUTER_SNAT]}
            csnat_ports = self.core_plugin.get_ports(
                self.ctx, filters=csnat_filters)
            self.assertEqual(1, len(csnat_ports))

    @mock.patch('neutron.db.l3_dvr_db.is_admin_state_down_necessary',
                return_value=True)
    def test_update_router_gw_info_external_network_change_mocked(self,
            mock_arg):
        # call test with admin_state_down_before_update ENABLED
        self._test_update_router_gw_info_external_network_change()

    @mock.patch('neutron.db.l3_dvr_db.is_admin_state_down_necessary',
                return_value=False)
    def test_update_router_gw_info_external_network_change(self, mock_arg):
        # call test with admin_state_down_before_update DISABLED
        self._test_update_router_gw_info_external_network_change()

    def _test_csnat_ports_removal(self, ha=False):
        router_dict = {'name': 'test_router', 'admin_state_up': True,
                       'distributed': True}
        router = self._create_router(router_dict)
        with self.network() as net_ext,\
                self.subnet() as subnet:
            ext_net_id = net_ext['network']['id']
            self.core_plugin.update_network(
                self.ctx, ext_net_id,
                {'network': {'router:external': True}})
            self.mixin.update_router(
                self.ctx, router['id'],
                {'router': {'external_gateway_info':
                            {'network_id': ext_net_id}}})
            self.mixin.add_router_interface(self.ctx, router['id'],
                {'subnet_id': subnet['subnet']['id']})

            csnat_filters = {'device_owner':
                             [const.DEVICE_OWNER_ROUTER_SNAT]}
            csnat_ports = self.core_plugin.get_ports(
                self.ctx, filters=csnat_filters)
            self.assertEqual(1, len(csnat_ports))

            self.mixin.update_router(
                self.ctx, router['id'],
                {'router': {'admin_state_up': False}})
            self.mixin.update_router(
                self.ctx, router['id'],
                {'router': {'distributed': False, 'ha': ha}})

            csnat_ports = self.core_plugin.get_ports(
                self.ctx, filters=csnat_filters)
            self.assertEqual(0, len(csnat_ports))

    def test_distributed_to_centralized_csnat_ports_removal(self):
        self._test_csnat_ports_removal()

    def test_distributed_to_ha_csnat_ports_removal(self):
        self._test_csnat_ports_removal(ha=True)

    def test_update_router_gw_info_csnat_ports_add(self):
        router_dict = {'name': 'test_router',
                       'admin_state_up': True,
                       'distributed': True}
        router = self._create_router(router_dict)
        with self.network() as net_ext,\
                self.network() as net_int,\
                self.subnet(
                    network=net_int,
                    cidr='2001:db8:1::/64',
                    gateway_ip='2001:db8:1::1',
                    ip_version=const.IP_VERSION_6) as v6_subnet1,\
                self.subnet(
                    network=net_int,
                    cidr='2001:db8:2::/64',
                    gateway_ip='2001:db8:2::1',
                    ip_version=const.IP_VERSION_6) as v6_subnet2,\
                self.subnet(
                    network=net_int,
                    cidr='10.10.10.0/24') as v4_subnet:

            self.core_plugin.update_network(
                self.ctx, net_ext['network']['id'],
                {'network': {'router:external': True}})

            # Add router interface, then set router gateway
            self.mixin.add_router_interface(self.ctx, router['id'],
                {'subnet_id': v6_subnet1['subnet']['id']})
            self.mixin.add_router_interface(self.ctx, router['id'],
                {'subnet_id': v6_subnet2['subnet']['id']})
            self.mixin.add_router_interface(self.ctx, router['id'],
                {'subnet_id': v4_subnet['subnet']['id']})

            dvr_filters = {'device_owner':
                           [const.DEVICE_OWNER_DVR_INTERFACE]}
            dvr_ports = self.core_plugin.get_ports(
                self.ctx, filters=dvr_filters)
            # One for IPv4, one for two IPv6 subnets
            self.assertEqual(2, len(dvr_ports))

            self.mixin.update_router(
                self.ctx, router['id'],
                {'router': {'external_gateway_info':
                            {'network_id': net_ext['network']['id']}}})

            csnat_filters = {'device_owner':
                             [const.DEVICE_OWNER_ROUTER_SNAT]}
            csnat_ports = self.core_plugin.get_ports(
                self.ctx, filters=csnat_filters)
            # One for IPv4, one for two IPv6 subnets
            self.assertEqual(2, len(csnat_ports))

            # Remove v4 subnet interface from router
            self.mixin.remove_router_interface(
                self.ctx, router['id'],
                {'subnet_id': v4_subnet['subnet']['id']})

            dvr_ports = self.core_plugin.get_ports(
                self.ctx, filters=dvr_filters)
            self.assertEqual(1, len(dvr_ports))

            csnat_ports = self.core_plugin.get_ports(
                self.ctx, filters=csnat_filters)
            self.assertEqual(1, len(csnat_ports))
            self.assertEqual(2, len(csnat_ports[0]['fixed_ips']))

    def _test_update_router_interface_port_ip_not_allowed(self, device_owner):
        router, subnet_v4, subnet_v6 = self._setup_router_with_v4_and_v6()
        device_filter = {'device_owner': [device_owner]}
        ports = self.core_plugin.get_ports(self.ctx, filters=device_filter)
        self.assertRaises(
            exceptions.BadRequest,
            self.core_plugin.update_port,
            self.ctx, ports[0]['id'],
            {'port': {'fixed_ips': [
                {'ip_address': "20.0.0.100",
                 'subnet_id': subnet_v4['subnet']['id']},
                {'ip_address': "20.0.0.101",
                 'subnet_id': subnet_v4['subnet']['id']}]}})

    def test_update_router_centralized_snat_port_ip_not_allowed(self):
        self._test_update_router_interface_port_ip_not_allowed(
            const.DEVICE_OWNER_ROUTER_SNAT)

    def test_update_router_interface_distributed_port_ip_not_allowed(self):
        self._test_update_router_interface_port_ip_not_allowed(
            const.DEVICE_OWNER_DVR_INTERFACE)

    def test_remove_router_interface_csnat_ports_removal(self):
        router_dict = {'name': 'test_router', 'admin_state_up': True,
                       'distributed': True}
        router = self._create_router(router_dict)
        with self.network() as net_ext,\
                self.subnet() as subnet1,\
                self.subnet(cidr='20.0.0.0/24') as subnet2:
            ext_net_id = net_ext['network']['id']
            self.core_plugin.update_network(
                self.ctx, ext_net_id,
                {'network': {'router:external': True}})
            self.mixin.update_router(
                self.ctx, router['id'],
                {'router': {'external_gateway_info':
                            {'network_id': ext_net_id}}})
            self.mixin.add_router_interface(self.ctx, router['id'],
                {'subnet_id': subnet1['subnet']['id']})
            self.mixin.add_router_interface(self.ctx, router['id'],
                {'subnet_id': subnet2['subnet']['id']})

            csnat_filters = {'device_owner':
                             [const.DEVICE_OWNER_ROUTER_SNAT]}
            csnat_ports = self.core_plugin.get_ports(
                self.ctx, filters=csnat_filters)
            self.assertEqual(2, len(csnat_ports))

            dvr_filters = {'device_owner':
                           [const.DEVICE_OWNER_DVR_INTERFACE]}
            dvr_ports = self.core_plugin.get_ports(
                self.ctx, filters=dvr_filters)
            self.assertEqual(2, len(dvr_ports))

            self.mixin.remove_router_interface(
                self.ctx, router['id'], {'port_id': dvr_ports[0]['id']})

            csnat_ports = self.core_plugin.get_ports(
                self.ctx, filters=csnat_filters)
            self.assertEqual(1, len(csnat_ports))
            self.assertEqual(dvr_ports[1]['fixed_ips'][0]['subnet_id'],
                             csnat_ports[0]['fixed_ips'][0]['subnet_id'])

            dvr_ports = self.core_plugin.get_ports(
                self.ctx, filters=dvr_filters)
            self.assertEqual(1, len(dvr_ports))

    def _setup_router_with_v4_and_v6(self):
        router_dict = {'name': 'test_router', 'admin_state_up': True,
                       'distributed': True}
        router = self._create_router(router_dict)
        with self.network() as net_ext, self.network() as net_int:
            ext_net_id = net_ext['network']['id']
            self.core_plugin.update_network(
                self.ctx, ext_net_id,
                {'network': {'router:external': True}})
            self.mixin.update_router(
                self.ctx, router['id'],
                {'router': {'external_gateway_info':
                            {'network_id': ext_net_id}}})
            with self.subnet(
                network=net_int, cidr='20.0.0.0/24') as subnet_v4,\
                self.subnet(network=net_int, cidr='fe80::/64',
                            gateway_ip='fe80::1', ip_version=const.IP_VERSION_6
                            ) as subnet_v6:
                self.mixin.add_router_interface(self.ctx, router['id'],
                    {'subnet_id': subnet_v4['subnet']['id']})
                self.mixin.add_router_interface(self.ctx, router['id'],
                    {'subnet_id': subnet_v6['subnet']['id']})
                return router, subnet_v4, subnet_v6

    def test_undo_router_interface_change_on_csnat_error(self):
        self._test_undo_router_interface_change_on_csnat_error(False)

    def test_undo_router_interface_change_on_csnat_error_revert_failure(self):
        self._test_undo_router_interface_change_on_csnat_error(True)

    def _test_undo_router_interface_change_on_csnat_error(self, fail_revert):
        router, subnet_v4, subnet_v6 = self._setup_router_with_v4_and_v6()
        net = {'network': {'id': subnet_v6['subnet']['network_id'],
                           'tenant_id': subnet_v6['subnet']['tenant_id']}}
        orig_update = self.mixin._core_plugin.update_port

        def update_port(*args, **kwargs):
            # 1st port update is the interface, 2nd is csnat, 3rd is revert
            # we want to simulate errors after the 1st
            update_port.calls += 1
            if update_port.calls == 2:
                raise RuntimeError('csnat update failure')
            if update_port.calls == 3 and fail_revert:
                # this is to ensure that if the revert fails, the original
                # exception is raised (not this ValueError)
                raise ValueError('failure from revert')
            return orig_update(*args, **kwargs)
        update_port.calls = 0
        self.mixin._core_plugin.update_port = update_port

        with self.subnet(network=net, cidr='fe81::/64',
                         gateway_ip='fe81::1', ip_version=const.IP_VERSION_6
                         ) as subnet2_v6:
            self.mixin.add_router_interface(self.ctx, router['id'],
                {'subnet_id': subnet2_v6['subnet']['id']})
            if fail_revert:
                # a revert failure will mean the interface is still added
                # so we can't re-add it
                return
            # starting over should work if first interface was cleaned up
            self.mixin.add_router_interface(self.ctx, router['id'],
                {'subnet_id': subnet2_v6['subnet']['id']})

    def test_remove_router_interface_csnat_ports_removal_with_ipv6(self):
        router, subnet_v4, subnet_v6 = self._setup_router_with_v4_and_v6()
        csnat_filters = {'device_owner':
                         [const.DEVICE_OWNER_ROUTER_SNAT]}
        csnat_ports = self.core_plugin.get_ports(
            self.ctx, filters=csnat_filters)
        self.assertEqual(2, len(csnat_ports))
        dvr_filters = {'device_owner':
                       [const.DEVICE_OWNER_DVR_INTERFACE]}
        dvr_ports = self.core_plugin.get_ports(
            self.ctx, filters=dvr_filters)
        self.assertEqual(2, len(dvr_ports))
        self.mixin.remove_router_interface(
            self.ctx, router['id'],
            {'subnet_id': subnet_v4['subnet']['id']})
        csnat_ports = self.core_plugin.get_ports(
            self.ctx, filters=csnat_filters)
        self.assertEqual(1, len(csnat_ports))
        self.assertEqual(
            subnet_v6['subnet']['id'],
            csnat_ports[0]['fixed_ips'][0]['subnet_id'])

        dvr_ports = self.core_plugin.get_ports(
            self.ctx, filters=dvr_filters)
        self.assertEqual(1, len(dvr_ports))

    def _test__validate_router_migration_notify_advanced_services(self):
        router = {'name': 'foo_router', 'admin_state_up': False}
        router_db = self._create_router(router)
        with mock.patch.object(l3_dvr_db.registry, 'notify') as mock_notify:
            self.mixin._validate_router_migration(
                self.ctx, router_db, {'distributed': True})
            kwargs = {'context': self.ctx, 'router': router_db}
            mock_notify.assert_called_once_with(
                'router', 'before_update', self.mixin, **kwargs)

    def _assert_mock_called_with_router(self, mock_fn, router_id):
        router = mock_fn.call_args[1].get('router_db')
        self.assertEqual(router_id, router.id)

    def test__validate_router_migration_notify_advanced_services_mocked(self):
        # call test with admin_state_down_before_update ENABLED
        self._test__validate_router_migration_notify_advanced_services()

    def test__validate_router_migration_notify_advanced_services(self):
        # call test with admin_state_down_before_update DISABLED
        self._test__validate_router_migration_notify_advanced_services()

    def test_validate_add_router_interface_by_subnet_notify_advanced_services(
            self):
        router = {'name': 'foo_router', 'admin_state_up': False}
        router_db = self._create_router(router)
        with self.network() as net, \
                self.subnet(network={'network': net['network']}) as sub, \
                mock.patch.object(
                    self.mixin,
                    '_notify_attaching_interface') as mock_notify:
            interface_info = {'subnet_id': sub['subnet']['id']}
            self.mixin.add_router_interface(self.ctx, router_db.id,
                                            interface_info)
            # NOTE(slaweq): here we are just checking if mock_notify was called
            # with kwargs which we are expecting, but we can't check exactly if
            # router_db was object which we are expecting and because of that
            # below we are checking if router_db used as argument in
            # mock_notify call is the has same id as the one which we are
            # expecting
            mock_notify.assert_called_once_with(self.ctx, router_db=mock.ANY,
                                                port=mock.ANY,
                                                interface_info=interface_info)
            self._assert_mock_called_with_router(mock_notify, router_db.id)

    def test_validate_add_router_interface_by_port_notify_advanced_services(
            self):
        router = {'name': 'foo_router', 'admin_state_up': False}
        router_db = self._create_router(router)
        with self.network() as net, \
                self.subnet(network={'network': net['network']}) as sub, \
                self.port(subnet=sub) as port, \
                mock.patch.object(
                    self.mixin,
                    '_notify_attaching_interface') as mock_notify:
            interface_info = {'port_id': port['port']['id']}
            self.mixin.add_router_interface(self.ctx, router_db.id,
                                            interface_info)
            # NOTE(slaweq): here we are just checking if mock_notify was called
            # with kwargs which we are expecting, but we can't check exactly if
            # router_db was object which we are expecting and because of that
            # below we are checking if router_db used as argument in
            # mock_notify call is the has same id as the one which we are
            # expecting.
            mock_notify.assert_called_once_with(self.ctx, router_db=mock.ANY,
                                                port=mock.ANY,
                                                interface_info=interface_info)
            self._assert_mock_called_with_router(mock_notify, router_db.id)

    def test__generate_arp_table_and_notify_agent(self):
        fixed_ip = {
            'ip_address': '1.2.3.4',
            'subnet_id': _uuid()}
        mac_address = "00:11:22:33:44:55"
        expected_arp_table = {
            'ip_address': fixed_ip['ip_address'],
            'subnet_id': fixed_ip['subnet_id'],
            'mac_address': mac_address}
        notifier = mock.Mock()
        ports = [{'id': _uuid(), 'device_id': 'router_1'},
                 {'id': _uuid(), 'device_id': 'router_2'}]
        with mock.patch.object(self.core_plugin, "get_ports",
                               return_value=ports):
            self.mixin._generate_arp_table_and_notify_agent(
                self.ctx, fixed_ip, mac_address, notifier)
        notifier.assert_has_calls([
            mock.call(self.ctx, "router_1", expected_arp_table),
            mock.call(self.ctx, "router_2", expected_arp_table)])

    def _test_update_arp_entry_for_dvr_service_port(
            self, device_owner, action):
        router_dict = {'name': 'test_router', 'admin_state_up': True,
                       'distributed': True}
        router = self._create_router(router_dict)
        plugin = mock.Mock()
        directory.add_plugin(plugin_constants.CORE, plugin)
        l3_notify = self.mixin.l3_rpc_notifier = mock.Mock()
        port = {
            'id': 'my_port_id',
            'fixed_ips': [
                {'subnet_id': '51edc9e0-24f9-47f2-8e1e-2a41cb691323',
                 'ip_address': '10.0.0.11'},
                {'subnet_id': '2b7c8a07-6f8e-4937-8701-f1d5da1a807c',
                 'ip_address': '10.0.0.21'},
                {'subnet_id': '48534187-f077-4e81-93ff-81ec4cc0ad3b',
                 'ip_address': 'fd45:1515:7e0:0:f816:3eff:fe1a:1111'}],
            'mac_address': 'my_mac',
            'device_owner': device_owner
        }
        dvr_port = {
            'id': 'dvr_port_id',
            'fixed_ips': mock.ANY,
            'device_owner': const.DEVICE_OWNER_DVR_INTERFACE,
            'device_id': router['id']
        }
        plugin.get_ports.return_value = [dvr_port]
        if action == 'add':
            self.mixin.update_arp_entry_for_dvr_service_port(
                self.ctx, port)
            self.assertEqual(3, l3_notify.add_arp_entry.call_count)
        elif action == 'del':
            self.mixin.delete_arp_entry_for_dvr_service_port(
                self.ctx, port)
            self.assertEqual(3, l3_notify.del_arp_entry.call_count)

    def test_update_arp_entry_for_dvr_service_port_added(self):
        action = 'add'
        device_owner = const.DEVICE_OWNER_LOADBALANCER
        self._test_update_arp_entry_for_dvr_service_port(device_owner, action)

    def test_update_arp_entry_for_dvr_service_port_deleted(self):
        action = 'del'
        device_owner = const.DEVICE_OWNER_LOADBALANCER
        self._test_update_arp_entry_for_dvr_service_port(device_owner, action)

    def test_add_router_interface_csnat_ports_failure(self):
        router_dict = {'name': 'test_router', 'admin_state_up': True,
                       'distributed': True}
        router = self._create_router(router_dict)
        with self.network() as net_ext,\
                self.subnet() as subnet:
            ext_net_id = net_ext['network']['id']
            self.core_plugin.update_network(
                self.ctx, ext_net_id,
                {'network': {'router:external': True}})
            self.mixin.update_router(
                self.ctx, router['id'],
                {'router': {'external_gateway_info':
                            {'network_id': ext_net_id}}})
            with mock.patch.object(self.mixin,
                                   '_add_csnat_router_interface_port') as f:
                f.side_effect = RuntimeError()
                self.assertRaises(
                    l3_exc.RouterInterfaceAttachmentConflict,
                    self.mixin.add_router_interface,
                    self.ctx, router['id'],
                    {'subnet_id': subnet['subnet']['id']})
                filters = {
                    'device_id': [router['id']],
                }
                router_ports = self.core_plugin.get_ports(self.ctx, filters)
                self.assertEqual(1, len(router_ports))
                self.assertEqual(const.DEVICE_OWNER_ROUTER_GW,
                                 router_ports[0]['device_owner'])

    def test_csnat_port_not_created_on_RouterPort_update_exception(self):
        router_dict = {'name': 'test_router', 'admin_state_up': True,
                       'distributed': True}
        router = self._create_router(router_dict)
        with self.network() as net_ext,\
                self.subnet() as subnet:
            ext_net_id = net_ext['network']['id']
            self.core_plugin.update_network(
                self.ctx, ext_net_id,
                {'network': {'router:external': True}})
            self.mixin.update_router(
                self.ctx, router['id'],
                {'router': {'external_gateway_info':
                            {'network_id': ext_net_id}}})
            net_id = subnet['subnet']['network_id']
            with mock.patch.object(router_obj.RouterPort,
                                   'create') as rtrport_update:
                rtrport_update.side_effect = Exception()
                self.assertRaises(
                    l3_exc.RouterInterfaceAttachmentConflict,
                    self.mixin.add_router_interface,
                    self.ctx, router['id'],
                    {'subnet_id': subnet['subnet']['id']})
                filters = {
                    'network_id': [net_id],
                    'device_owner': [const.DEVICE_OWNER_ROUTER_SNAT]
                }
                router_ports = self.core_plugin.get_ports(self.ctx, filters)
                self.assertEqual(0, len(router_ports))

    def test_add_router_interface_by_port_failure(self):
        router_dict = {'name': 'test_router',
                       'admin_state_up': True,
                       'distributed': True}
        router = self._create_router(router_dict)
        with self.subnet(cidr='10.10.10.0/24') as subnet:
            port_dict = {
                'device_id': '',
                'device_owner': '',
                'admin_state_up': True,
                'fixed_ips': [{'subnet_id': subnet['subnet']['id'],
                               'ip_address': '10.10.10.100'}]
            }
            net_id = subnet['subnet']['network_id']
            port_res = self.create_port(net_id, port_dict)
            port = self.deserialize(self.fmt, port_res)
            self.assertIn('port', port, message='Create port failed.')

            orig_update_port = self.mixin._core_plugin.update_port
            call_info = {'count': 0}

            def _fake_update_port(*args, **kwargs):
                call_info['count'] += 1
                if call_info['count'] == 2:
                    raise RuntimeError()
                else:
                    return orig_update_port(*args, **kwargs)

            # NOTE(trananhkma): expect that update_port() only raises an error
            # at the 2nd function call (Update owner after actual process
            # again in order).
            with mock.patch.object(self.mixin._core_plugin, 'update_port',
                                   side_effect=_fake_update_port):
                self.assertRaises(
                    RuntimeError,
                    self.mixin.add_router_interface,
                    self.ctx, router['id'], {'port_id': port['port']['id']})
            # expire since we are re-using the session which might have stale
            # ports in it
            self.ctx.session.expire_all()
            port_info = self.core_plugin.get_port(self.ctx, port['port']['id'])
            self.assertEqual(port_dict['device_id'], port_info['device_id'])
            self.assertEqual(port_dict['device_owner'],
                             port_info['device_owner'])

    def test__get_sync_routers_check_gw_port_host(self):
        router_dict = {'name': 'test_router', 'admin_state_up': True,
                       'distributed': True}
        router = self._create_router(router_dict)
        with self.network() as public,\
                self.subnet() as subnet:
            ext_net_1_id = public['network']['id']
            self.core_plugin.update_network(
                self.ctx, ext_net_1_id,
                {'network': {'router:external': True}})
            self.mixin.update_router(
                self.ctx, router['id'],
                {'router': {'external_gateway_info':
                            {'network_id': ext_net_1_id}}})
            self.mixin.add_router_interface(self.ctx, router['id'],
                {'subnet_id': subnet['subnet']['id']})
            routers = self.mixin._get_sync_routers(self.ctx,
                                                   router_ids=[router['id']])
            self.assertIsNone(routers[0]['gw_port_host'])

            agent = mock.Mock()
            agent.host = "fake-host"
            bind = mock.Mock()
            bind.l3_agent_id = "fake-id"
            with mock.patch.object(
                rb_obj.RouterL3AgentBinding, 'get_objects',
                return_value=[bind]), mock.patch.object(
                    agent_obj.Agent, 'get_object',
                    return_value=agent):
                routers = self.mixin._get_sync_routers(
                    self.ctx, router_ids=[router['id']])
                self.assertEqual("fake-host", routers[0]['gw_port_host'])

    def test_is_router_distributed(self):
        router_id = 'router_id'
        with mock.patch.object(self.mixin, 'get_router') as \
                mock_get_router:
            mock_get_router.return_value = {'distributed': True}
            self.assertTrue(
                self.mixin.is_router_distributed(self.ctx, router_id))

    @mock.patch.object(l3_dvr_db, "is_port_bound")
    def test_get_ports_under_dvr_connected_subnet(self, is_port_bound_mock):
        router_dict = {'name': 'test_router', 'admin_state_up': True,
                       'distributed': True}
        router = self._create_router(router_dict)
        with self.network() as network,\
                self.subnet(network=network) as subnet:
            self.mixin._core_plugin.get_allowed_address_pairs_for_ports = (
                mock.Mock())
            fake_bound_ports_ids = []

            def fake_is_port_bound(port):
                return port['id'] in fake_bound_ports_ids

            is_port_bound_mock.side_effect = fake_is_port_bound

            for _ in range(4):
                port_res = self.create_port(
                    network['network']['id'],
                    {'fixed_ips': [{'subnet_id': subnet['subnet']['id']}]})
                port_id = self.deserialize(self.fmt, port_res)['port']['id']
                if len(fake_bound_ports_ids) < 2:
                    fake_bound_ports_ids.append(port_id)

            self.mixin.add_router_interface(self.ctx, router['id'],
                {'subnet_id': subnet['subnet']['id']})
            dvr_subnet_ports = self.mixin.get_ports_under_dvr_connected_subnet(
                self.ctx, subnet['subnet']['id'])
            dvr_subnet_ports_ids = [p['id'] for p in dvr_subnet_ports]
            self.assertItemsEqual(fake_bound_ports_ids, dvr_subnet_ports_ids)
            (self.mixin._core_plugin.get_allowed_address_pairs_for_ports.
                assert_called_once_with(self.ctx, dvr_subnet_ports_ids))

    @mock.patch.object(plugin_utils, 'can_port_be_bound_to_virtual_bridge',
                       return_value=True)
    def test__get_assoc_data_valid_vnic_type(self, *args):
        with mock.patch.object(self.mixin, '_internal_fip_assoc_data') as \
                mock_fip_assoc_data, \
                mock.patch.object(self.mixin, '_get_router_for_floatingip') \
                as mock_router_fip, \
                mock.patch.object(self.mixin, 'is_router_distributed',
                                  return_value=True):
            port = {portbindings.VNIC_TYPE: portbindings.VNIC_NORMAL}
            mock_fip_assoc_data.return_value = (port, 'subnet_id', 'ip_addr')
            mock_router_fip.return_value = 'router_id'
            fip = {'port_id': 'port_id'}
            self.assertEqual(
                ('port_id', 'ip_addr', 'router_id'),
                self.mixin._get_assoc_data(self.ctx, fip, mock.Mock()))

    @mock.patch.object(plugin_utils, 'can_port_be_bound_to_virtual_bridge',
                       return_value=False)
    def test__get_assoc_data_invalid_vnic_type(self, *args):
        with mock.patch.object(self.mixin, '_internal_fip_assoc_data') as \
                mock_fip_assoc_data, \
                mock.patch.object(self.mixin, '_get_router_for_floatingip') \
                as mock_router_fip, \
                mock.patch.object(self.mixin, 'is_router_distributed',
                                  return_value=True):
            port = {portbindings.VNIC_TYPE: portbindings.VNIC_NORMAL}
            mock_fip_assoc_data.return_value = (port, 'subnet_id', 'ip_addr')
            mock_router_fip.return_value = 'router_id'
            self.assertRaises(
                exceptions.BadRequest,
                self.mixin._get_assoc_data, self.ctx, mock.ANY, mock.Mock())

    def test__delete_dvr_internal_ports(self):
        payload = mock.Mock()
        payload.context = mock.Mock()
        payload.latest_state = {'distributed': True}
        payload.metadata = {'new_network_id': 'fake-net-1',
                            'network_id': 'fake-net-2'}
        plugin = mock.Mock()
        directory.add_plugin(plugin_constants.CORE, plugin)
        plugin.get_ports.return_value = []
        with mock.patch.object(self.mixin,
                               'delete_floatingip_agent_gateway_port') as \
            del_port, \
            mock.patch.object(
                self.mixin.l3_rpc_notifier,
                'delete_fipnamespace_for_ext_net') as \
            del_fip_ns, \
            mock.patch.object(router_obj.DvrFipGatewayPortAgentBinding,
                              "delete_objects") as del_binding:
            self.mixin._delete_dvr_internal_ports(
                None, None, resources.ROUTER_GATEWAY, payload)
            del_port.assert_called_once()
            del_fip_ns.assert_called_once()
            del_binding.assert_called_once()
