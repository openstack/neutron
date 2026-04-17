# Copyright (c) 2026 Red Hat Inc.
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

from unittest import mock

from neutron_lib.callbacks import events
from neutron_lib.callbacks import resources
from neutron_lib.services.pvlan import constants as pvlan_const
from oslo_config import cfg
from oslo_utils import uuidutils

from neutron.common.ovn import constants as ovn_const
from neutron.services.pvlan.drivers.ovn import driver as pvlan_ovn
from neutron.tests import base


@mock.patch('neutron_lib.callbacks.registry.subscribe')
class TestRegister(base.BaseTestCase):

    def setUp(self):
        super().setUp()
        self.mech_driver = mock.Mock()
        self.trigger = mock.Mock()

    def _invoke_callback(self, mock_subscribe, is_loaded):
        pvlan_ovn.register(self.mech_driver)
        # First subscribe call is the driver registration callback
        callback = mock_subscribe.call_args_list[0][0][0]
        with mock.patch.object(pvlan_ovn.PVLANDriver, 'is_loaded',
                               new_callable=mock.PropertyMock,
                               return_value=is_loaded):
            callback(pvlan_ovn.PVLAN_PLUGIN, events.BEFORE_SPAWN,
                     self.trigger, payload=None)

    def test_register_creates_both_subscriptions(self, mock_subscribe):
        pvlan_ovn.register(self.mech_driver)
        self.assertEqual(2, mock_subscribe.call_count)
        mock_subscribe.assert_any_call(
            mock.ANY, pvlan_ovn.PVLAN_PLUGIN, events.BEFORE_SPAWN)
        mock_subscribe.assert_any_call(
            pvlan_ovn._initialize_pvlan_pg_drop,
            resources.PROCESS, events.AFTER_INIT)

    def test_callback_registers_driver(self, mock_subscribe):
        self._invoke_callback(mock_subscribe, is_loaded=True)
        self.trigger.register_driver.assert_called_once()

    def test_callback_skips_registration_when_not_loaded(self,
                                                         mock_subscribe):
        self._invoke_callback(mock_subscribe, is_loaded=False)
        self.trigger.register_driver.assert_not_called()


class TestPVLANDriverBase(base.BaseTestCase):

    def setUp(self):
        super().setUp()
        self.mech_driver = mock.Mock()
        self.nb_ovn = self.mech_driver.nb_ovn
        self.nb_ovn.transaction.return_value.__enter__ = mock.Mock()
        self.nb_ovn.transaction.return_value.__exit__ = mock.Mock(
            return_value=False)
        self.driver = pvlan_ovn.PVLANDriver.create(
            mech_driver=self.mech_driver)
        self.txn = mock.Mock()
        self.context = mock.Mock()
        self.network_id = uuidutils.generate_uuid()

    def _make_port(self, port_id=None, network_id=None, pvlan_type=None,
                   pvlan_community=None):
        port = mock.Mock()
        port.id = port_id or uuidutils.generate_uuid()
        port.network_id = network_id or self.network_id
        port.pvlan_type = pvlan_type
        port.pvlan_community = pvlan_community
        return port


class TestPVLANDriver(TestPVLANDriverBase):

    def test_create_isolated_port_group(self):
        self.driver._create_isolated_port_group(self.network_id, self.txn)
        pg_name = self.driver._get_pg_name(
            self.network_id, pvlan_const.ISOLATED_TYPE)
        self.nb_ovn.pg_add.assert_called_once_with(
            name=pg_name, acls=[],
            external_ids={"neutron:network_id": self.network_id})
        # 1 pg_add + 1 to-lport ALLOW (prm→iso)
        self.assertEqual(2, self.txn.add.call_count)

    def test_create_promiscuous_port_group(self):
        self.driver._create_promiscuous_port_group(self.network_id, self.txn)
        pg_name = self.driver._get_pg_name(
            self.network_id, pvlan_const.PROMISCUOUS_TYPE)
        self.nb_ovn.pg_add.assert_called_once_with(
            name=pg_name, acls=[],
            external_ids={"neutron:network_id": self.network_id})
        # 1 pg_add + 3 ACLs (to-lport prm, from-lport prm, from-lport iso)
        self.assertEqual(4, self.txn.add.call_count)

    def test_create_network_resources_with_txn(self):
        self.driver.create_network_resources(self.network_id, txn=self.txn)
        iso_pg = self.driver._get_pg_name(
            self.network_id, pvlan_const.ISOLATED_TYPE)
        prm_pg = self.driver._get_pg_name(
            self.network_id, pvlan_const.PROMISCUOUS_TYPE)
        pg_names = [call[1]['name']
                    for call in self.nb_ovn.pg_add.call_args_list]
        self.assertIn(iso_pg, pg_names)
        self.assertIn(prm_pg, pg_names)

    def test_create_network_resources_creates_own_txn(self):
        self.driver.create_network_resources(self.network_id)
        self.nb_ovn.transaction.assert_called_once_with(check_error=True)

    def test_delete_network_resources(self):
        self.nb_ovn.tables = {'Port_Group': mock.Mock()}
        self.nb_ovn.tables['Port_Group'].rows.values.return_value = []
        self.driver.delete_network_resources(self.network_id)
        iso_pg = self.driver._get_pg_name(
            self.network_id, pvlan_const.ISOLATED_TYPE)
        prm_pg = self.driver._get_pg_name(
            self.network_id, pvlan_const.PROMISCUOUS_TYPE)
        self.nb_ovn.pg_del.assert_any_call(iso_pg, if_exists=True)
        self.nb_ovn.pg_del.assert_any_call(prm_pg, if_exists=True)

    def test_delete_network_resources_cleans_community_pgs(self):
        comm_pg_name = self.driver._get_pg_name(
            self.network_id, pvlan_const.COMMUNITY_TYPE, community='web')
        mock_pg = mock.Mock()
        mock_pg.name = comm_pg_name
        self.nb_ovn.tables = {'Port_Group': mock.Mock()}
        self.nb_ovn.tables['Port_Group'].rows.values.return_value = [mock_pg]
        self.driver.delete_network_resources(self.network_id)
        self.nb_ovn.pg_del.assert_any_call(comm_pg_name, if_exists=True)
        prm_pg = self.driver._get_pg_name(
            self.network_id, pvlan_const.PROMISCUOUS_TYPE)
        self.nb_ovn.pg_acl_del.assert_any_call(
            prm_pg, direction="from-lport",
            priority=pvlan_ovn.PROMISCUOUS_PRIORITY,
            match="inport == @%s" % comm_pg_name, if_exists=True)

    def test_is_loaded_true_when_ovn_in_mechanism_drivers(self):
        cfg.CONF.set_override('mechanism_drivers',
                              [ovn_const.OVN_ML2_MECH_DRIVER_NAME],
                              group='ml2')
        self.assertTrue(self.driver.is_loaded)

    def test_is_loaded_false_when_ovn_not_in_mechanism_drivers(self):
        cfg.CONF.set_override('mechanism_drivers', ['openvswitch'],
                              group='ml2')
        self.assertFalse(self.driver.is_loaded)

    def test_is_loaded_false_when_no_ml2_config(self):
        self.assertFalse(self.driver.is_loaded)


class TestCommunityPortGroup(TestPVLANDriverBase):

    def test_add_port_to_existing_pg(self):
        port = self._make_port()
        self.nb_ovn.get_port_group.return_value = mock.Mock()
        self.driver._add_port_to_pg(port.id, self.network_id,
                                    pvlan_const.COMMUNITY_TYPE,
                                    self.txn, community='web')
        pg_name = self.driver._get_pg_name(
            self.network_id, pvlan_const.COMMUNITY_TYPE, community='web')
        self.txn.add.assert_called_once_with(
            self.nb_ovn.pg_add_ports(pg_name, port.id))

    def test_add_port_creates_pg_if_missing(self):
        port = self._make_port()
        self.nb_ovn.get_port_group.return_value = None
        self.driver._add_port_to_pg(port.id, self.network_id,
                                    pvlan_const.COMMUNITY_TYPE,
                                    self.txn, community='web')
        # 1 pg_add + 2 to-lport ACLs + 1 from-lport ACL on prm PG
        # + 1 pg_add_ports
        self.assertEqual(5, self.txn.add.call_count)

    def test_remove_last_port_deletes_pg(self):
        port = self._make_port()
        pg = mock.Mock()
        pg.ports = [port.id]
        self.nb_ovn.get_port_group.return_value = pg
        self.driver._remove_port_from_pg(port.id, self.network_id,
                                         pvlan_const.COMMUNITY_TYPE,
                                         self.txn, community='web')
        pg_name = self.driver._get_pg_name(
            self.network_id, pvlan_const.COMMUNITY_TYPE, community='web')
        self.nb_ovn.pg_del.assert_any_call(pg_name)
        promiscuous_pg = self.driver._get_pg_name(
            self.network_id, pvlan_const.PROMISCUOUS_TYPE)
        self.nb_ovn.pg_acl_del.assert_any_call(
            promiscuous_pg, direction="from-lport",
            priority=pvlan_ovn.PROMISCUOUS_PRIORITY,
            match="inport == @%s" % pg_name, if_exists=True)

    def test_remove_port_keeps_pg_when_others_remain(self):
        port = self._make_port()
        pg = mock.Mock()
        pg.ports = [port.id, 'other-port']
        self.nb_ovn.get_port_group.return_value = pg
        self.driver._remove_port_from_pg(port.id, self.network_id,
                                         pvlan_const.COMMUNITY_TYPE,
                                         self.txn, community='web')
        self.assertEqual(1, self.txn.add.call_count)
        self.nb_ovn.pg_del.assert_not_called()
        self.nb_ovn.pg_acl_del.assert_not_called()


class TestPorts(TestPVLANDriverBase):

    def test_create_port_community(self):
        port_id = uuidutils.generate_uuid()
        port = {'id': port_id, 'network_id': self.network_id,
                'pvlan_type': pvlan_const.COMMUNITY_TYPE,
                'pvlan_community': 'web'}
        self.nb_ovn.get_port_group.return_value = mock.Mock()
        self.driver.create_port(self.context, self.txn, port)
        pg_name = self.driver._get_pg_name(
            self.network_id, pvlan_const.COMMUNITY_TYPE, community='web')
        self.txn.add.assert_any_call(
            self.nb_ovn.pg_add_ports(pg_name, port_id))

    def test_update_port_type_change(self):
        port = self._make_port(pvlan_type=pvlan_const.ISOLATED_TYPE)
        self.driver.update_port(
            self.context, port,
            prev_pvlan_type=pvlan_const.PROMISCUOUS_TYPE)
        iso_pg = self.driver._get_pg_name(
            self.network_id, pvlan_const.ISOLATED_TYPE)
        prm_pg = self.driver._get_pg_name(
            self.network_id, pvlan_const.PROMISCUOUS_TYPE)
        self.nb_ovn.pg_add_ports.assert_called_once_with(iso_pg, port.id)
        self.nb_ovn.pg_del_ports.assert_called_once_with(
            prm_pg, port.id, if_exists=True)

    def test_update_port_remove_pvlan_from_community(self):
        port = self._make_port(pvlan_type=None)
        pg = mock.Mock()
        pg.ports = [port.id]
        self.nb_ovn.get_port_group.return_value = pg
        self.driver.update_port(
            self.context, port,
            prev_pvlan_type=pvlan_const.COMMUNITY_TYPE,
            prev_pvlan_community='web')
        self.nb_ovn.pg_add_ports.assert_not_called()
        comm_pg = self.driver._get_pg_name(
            self.network_id, pvlan_const.COMMUNITY_TYPE, community='web')
        self.nb_ovn.pg_del_ports.assert_any_call(
            comm_pg, port.id, if_exists=True)
        self.nb_ovn.pg_del_ports.assert_any_call(
            pvlan_ovn.DROP_PORT_GROUP_NAME, port.id)

    def test_update_port_same_type_no_remove(self):
        port = self._make_port(pvlan_type=pvlan_const.ISOLATED_TYPE)
        self.driver.update_port(
            self.context, port,
            prev_pvlan_type=pvlan_const.ISOLATED_TYPE)
        self.nb_ovn.pg_add_ports.assert_called_once_with(
            self.driver._get_pg_name(
                self.network_id, pvlan_const.ISOLATED_TYPE), port.id)
        self.nb_ovn.pg_del_ports.assert_not_called()

    def test_delete_port_isolated(self):
        port = self._make_port(pvlan_type=pvlan_const.ISOLATED_TYPE)
        self.driver.delete_port(
            port.id, self.network_id, pvlan_const.ISOLATED_TYPE)
        iso_pg = self.driver._get_pg_name(
            self.network_id, pvlan_const.ISOLATED_TYPE)
        self.nb_ovn.pg_del_ports.assert_any_call(
            iso_pg, port.id, if_exists=True)
        self.nb_ovn.pg_del_ports.assert_any_call(
            pvlan_ovn.DROP_PORT_GROUP_NAME, port.id)

    def test_delete_port_community(self):
        port = self._make_port(pvlan_type=pvlan_const.COMMUNITY_TYPE,
                               pvlan_community='web')
        pg = mock.Mock()
        pg.ports = [port.id]
        self.nb_ovn.get_port_group.return_value = pg
        self.driver.delete_port(
            port.id, self.network_id,
            pvlan_const.COMMUNITY_TYPE, pvlan_community='web')
        comm_pg = self.driver._get_pg_name(
            self.network_id, pvlan_const.COMMUNITY_TYPE, community='web')
        self.nb_ovn.pg_del_ports.assert_any_call(
            comm_pg, port.id, if_exists=True)
        self.nb_ovn.pg_del_ports.assert_any_call(
            pvlan_ovn.DROP_PORT_GROUP_NAME, port.id)

    def test_update_port_community_change_removes_old(self):
        port = self._make_port(pvlan_type=pvlan_const.COMMUNITY_TYPE,
                               pvlan_community='new_comm')
        pg = mock.Mock()
        pg.ports = [port.id]
        self.nb_ovn.get_port_group.side_effect = [
            mock.Mock(),  # new community PG exists
            pg,           # old community PG exists check
            pg,           # old community PG empty check
        ]
        self.driver.update_port(
            self.context, port,
            prev_pvlan_type=pvlan_const.COMMUNITY_TYPE,
            prev_pvlan_community='old_comm')
        old_pg = self.driver._get_pg_name(
            self.network_id, pvlan_const.COMMUNITY_TYPE, community='old_comm')
        self.nb_ovn.pg_del_ports.assert_any_call(
            old_pg, port.id, if_exists=True)
