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
#

from unittest import mock

from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants as const
from neutron_lib.plugins import constants as plugin_constants
from oslo_utils import uuidutils
from ovsdbapp import constants as ovsdbapp_const

from neutron.common.ovn import constants as ovn_const
from neutron.common.ovn import exceptions as ovn_exc
from neutron.common.ovn import utils as ovn_utils
from neutron.conf.plugins.ml2.drivers.ovn import ovn_conf
from neutron.objects import port_forwarding as port_forwarding_obj
from neutron.services.portforwarding.constants import PORT_FORWARDING
from neutron.services.portforwarding.constants import PORT_FORWARDING_PLUGIN
from neutron.services.portforwarding.drivers.ovn import driver \
    as port_forwarding
from neutron.tests import base
from neutron.tests.unit import fake_resources


class TestOVNPortForwardingBase(base.BaseTestCase):
    def setUp(self):
        super(TestOVNPortForwardingBase, self).setUp()
        self.context = mock.Mock()
        self.l3_plugin = mock.Mock()
        self.l3_plugin._nb_ovn = fake_resources.FakeOvsdbNbOvnIdl()
        self.txn = self.l3_plugin._nb_ovn.transaction

    def _fake_pf_obj(self, is_object=False, **kwargs):
        pf_obj_defaults_dict = {
            'id': 'id',
            'floatingip_id': 'fip_id',
            'protocol': 'udp',
            'floating_ip_address': 'fip_addr',
            'external_port': 'ext_port',
            'internal_ip_address': 'internal_addr',
            'internal_port': 'internal_port',
            'router_id': 'rtr_id'
        }
        pf_obj_dict = {**pf_obj_defaults_dict, **kwargs}
        if is_object:
            return port_forwarding_obj.PortForwarding(**pf_obj_dict)
        return mock.Mock(**pf_obj_dict)

    def _fake_pf_payload_entry(self, curr_pf_id, orig_pf_id=None, **kwargs):
        mock_pf_payload = mock.Mock()
        states = []
        if 'context' not in kwargs:
            mock_pf_payload.context = self.context
        if orig_pf_id:
            fake_pf_obj = self._fake_pf_obj(**kwargs)
            fake_pf_obj.floatingip_id = orig_pf_id
            states.append(fake_pf_obj)
        if curr_pf_id:
            fake_pf_obj = self._fake_pf_obj(**kwargs)
            mock_pf_payload.latest_state = fake_pf_obj
            mock_pf_payload.latest_state.floatingip_id = curr_pf_id
            states.append(fake_pf_obj)
        else:
            mock_pf_payload.latest_state = None

        mock_pf_payload.states = states
        return mock_pf_payload


class TestOVNPortForwardingHandler(TestOVNPortForwardingBase):
    def setUp(self):
        super(TestOVNPortForwardingHandler, self).setUp()
        self.handler = port_forwarding.OVNPortForwardingHandler()

    def test_get_lb_protocol(self):
        fake_pf_obj = self._fake_pf_obj(protocol='udp')
        self.assertEqual(ovsdbapp_const.PROTO_UDP,
                         self.handler._get_lb_protocol(fake_pf_obj))
        fake_pf_obj = self._fake_pf_obj(protocol='tcp')
        self.assertEqual(ovsdbapp_const.PROTO_TCP,
                         self.handler._get_lb_protocol(fake_pf_obj))
        fake_pf_obj = self._fake_pf_obj(protocol='xxx')
        self.assertRaises(KeyError, self.handler._get_lb_protocol,
                          fake_pf_obj)

    def test_lb_names(self):
        expected_names = ['pf-floatingip-id-udp', 'pf-floatingip-id-tcp']
        names = self.handler.lb_names('id')
        self.assertCountEqual(expected_names, names)

    def test_get_lb_attributes(self):
        fake_pf_obj = self._fake_pf_obj()
        lb_name, vip, internal_ip, rtr_name = self.handler._get_lb_attributes(
            fake_pf_obj)
        self.assertEqual('pf-floatingip-fip_id-udp', lb_name)
        self.assertEqual('fip_addr:ext_port', vip)
        self.assertCountEqual(['internal_addr:internal_port'], internal_ip)
        self.assertEqual('neutron-rtr_id', rtr_name)

    @mock.patch.object(port_forwarding.LOG, 'info')
    def test_port_forwarding_created(self, m_info):
        fake_pf_obj = self._fake_pf_obj(
            is_object=True,
            id=uuidutils.generate_uuid(),
            floatingip_id=uuidutils.generate_uuid(),
            router_id=uuidutils.generate_uuid(),
            protocol='udp',
            floating_ip_address='10.0.0.1',
            external_port=2222,
            internal_ip_address='192.168.0.1',
            internal_port=22,
        )
        exp_lb_name, exp_vip, exp_internal_ips, exp_rtr_name = (
            self.handler._get_lb_attributes(fake_pf_obj))
        exp_protocol = self.handler._get_lb_protocol(fake_pf_obj)
        self.handler.port_forwarding_created(
            self.txn, self.l3_plugin._nb_ovn, fake_pf_obj)
        info_args, _info_kwargs = m_info.call_args_list[0]
        self.assertIn('CREATE for port-forwarding', info_args[0])
        self.assertEqual(2, len(self.txn.add.call_args_list))
        exp_external_ids = {
            ovn_const.OVN_DEVICE_OWNER_EXT_ID_KEY: PORT_FORWARDING_PLUGIN,
            ovn_const.OVN_FIP_EXT_ID_KEY: fake_pf_obj.floatingip_id,
            ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY: exp_rtr_name,
        }
        self.l3_plugin._nb_ovn.lb_add.assert_called_once_with(
            exp_lb_name, exp_vip, exp_internal_ips, exp_protocol,
            may_exist=True, external_ids=exp_external_ids)
        self.l3_plugin._nb_ovn.lr_lb_add.assert_called_once_with(
            exp_rtr_name, exp_lb_name, may_exist=True)

    @mock.patch.object(port_forwarding.LOG, 'info')
    def test_port_forwarding_created_with_ranges(self, m_info):
        id = uuidutils.generate_uuid()
        floatingip_id = uuidutils.generate_uuid()
        router_id = uuidutils.generate_uuid()
        fake_pf_obj_ranges = self._fake_pf_obj(
            is_object=True,
            id=id,
            floatingip_id=floatingip_id,
            router_id=router_id,
            protocol='udp',
            floating_ip_address='10.0.0.1',
            external_port=None,
            external_port_range='2222:2223',
            internal_ip_address='192.168.0.1',
            internal_port=None,
            internal_port_range='22:23'
        )
        fake_pf_obj_1 = self._fake_pf_obj(
            is_object=True,
            id=id,
            floatingip_id=floatingip_id,
            router_id=router_id,
            protocol='udp',
            floating_ip_address='10.0.0.1',
            external_port=2222,
            external_port_range=None,
            internal_ip_address='192.168.0.1',
            internal_port=22,
            internal_port_range=None
        )
        fake_pf_obj_2 = self._fake_pf_obj(
            is_object=True,
            id=id,
            floatingip_id=floatingip_id,
            router_id=router_id,
            protocol='udp',
            floating_ip_address='10.0.0.1',
            external_port=2223,
            external_port_range=None,
            internal_ip_address='192.168.0.1',
            internal_port=23,
            internal_port_range=None
        )
        exp_lb_name_1, exp_vip_1, exp_internal_ips_1, exp_rtr_name_1 = (
            self.handler._get_lb_attributes(fake_pf_obj_1, True))
        exp_lb_name_2, exp_vip_2, exp_internal_ips_2, exp_rtr_name_2 = (
            self.handler._get_lb_attributes(fake_pf_obj_2, True))
        exp_protocol_1 = self.handler._get_lb_protocol(fake_pf_obj_1)
        exp_protocol_2 = self.handler._get_lb_protocol(fake_pf_obj_2)
        self.handler.port_forwarding_created(
            self.txn, self.l3_plugin._nb_ovn, fake_pf_obj_ranges)
        info_args, _info_kwargs = m_info.call_args_list[0]
        self.assertIn('CREATE for port-forwarding', info_args[0])
        self.assertEqual(4, len(self.txn.add.call_args_list))
        info_args, _info_kwargs = m_info.call_args_list[1]
        self.assertIn('CREATE for port-forwarding', info_args[0])
        self.assertEqual(4, len(self.txn.add.call_args_list))
        exp_external_ids_1 = {
            ovn_const.OVN_DEVICE_OWNER_EXT_ID_KEY: PORT_FORWARDING_PLUGIN,
            ovn_const.OVN_FIP_EXT_ID_KEY: fake_pf_obj_1.floatingip_id,
            ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY: exp_rtr_name_1,
        }
        exp_external_ids_2 = {
            ovn_const.OVN_DEVICE_OWNER_EXT_ID_KEY: PORT_FORWARDING_PLUGIN,
            ovn_const.OVN_FIP_EXT_ID_KEY: fake_pf_obj_1.floatingip_id,
            ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY: exp_rtr_name_2,
        }
        self.l3_plugin._nb_ovn.lb_add.assert_any_call(
            exp_lb_name_1, exp_vip_1, exp_internal_ips_1, exp_protocol_1,
            may_exist=True, external_ids=exp_external_ids_1)
        self.l3_plugin._nb_ovn.lr_lb_add.assert_any_call(
            exp_rtr_name_1, exp_lb_name_1, may_exist=True)
        self.l3_plugin._nb_ovn.lb_add.assert_any_call(
            exp_lb_name_2, exp_vip_2, exp_internal_ips_2, exp_protocol_2,
            may_exist=True, external_ids=exp_external_ids_2)
        self.l3_plugin._nb_ovn.lr_lb_add.assert_any_call(
            exp_rtr_name_2, exp_lb_name_2, may_exist=True)

    @mock.patch.object(port_forwarding.LOG, 'info')
    @mock.patch.object(
        port_forwarding.OVNPortForwardingHandler, '_port_forwarding_deleted')
    @mock.patch.object(
        port_forwarding.OVNPortForwardingHandler, '_port_forwarding_created')
    def test_port_forwarding_updated_with_ranges(self, m_created, m_deleted,
                                                 m_info):
        id = uuidutils.generate_uuid()
        floatingip_id = uuidutils.generate_uuid()
        router_id = uuidutils.generate_uuid()
        fake_pf_obj_ranges_old = self._fake_pf_obj(
            is_object=True,
            id=id,
            floatingip_id=floatingip_id,
            router_id=router_id,
            protocol='udp',
            floating_ip_address='10.0.0.1',
            external_port=None,
            external_port_range='2222:2223',
            internal_ip_address='192.168.0.1',
            internal_port=None,
            internal_port_range='22:23'
        )
        fake_pf_obj_1_old = self._fake_pf_obj(
            is_object=True,
            id=id,
            floatingip_id=floatingip_id,
            router_id=router_id,
            protocol='udp',
            floating_ip_address='10.0.0.1',
            external_port=2222,
            external_port_range=None,
            internal_ip_address='192.168.0.1',
            internal_port=22,
            internal_port_range=None
        )
        fake_pf_obj_2_old = self._fake_pf_obj(
            is_object=True,
            id=id,
            floatingip_id=floatingip_id,
            router_id=router_id,
            protocol='udp',
            floating_ip_address='10.0.0.1',
            external_port=2223,
            external_port_range=None,
            internal_ip_address='192.168.0.1',
            internal_port=23,
            internal_port_range=None
        )
        fake_pf_obj_ranges = self._fake_pf_obj(
            is_object=True,
            id=id,
            floatingip_id=floatingip_id,
            router_id=router_id,
            protocol='tcp',
            floating_ip_address='10.0.0.1',
            external_port=None,
            external_port_range='2222:2223',
            internal_ip_address='192.168.0.1',
            internal_port=None,
            internal_port_range='22:23'
        )
        fake_pf_obj_1 = self._fake_pf_obj(
            is_object=True,
            id=id,
            floatingip_id=floatingip_id,
            router_id=router_id,
            protocol='tcp',
            floating_ip_address='10.0.0.1',
            external_port=2222,
            external_port_range=None,
            internal_ip_address='192.168.0.1',
            internal_port=22,
            internal_port_range=None
        )
        fake_pf_obj_2 = self._fake_pf_obj(
            is_object=True,
            id=id,
            floatingip_id=floatingip_id,
            router_id=router_id,
            protocol='tcp',
            floating_ip_address='10.0.0.1',
            external_port=2223,
            external_port_range=None,
            internal_ip_address='192.168.0.1',
            internal_port=23,
            internal_port_range=None
        )

        def do_simple_comparation(pf_1, pf_2):
            pf_1_dict = {f: getattr(pf_1, f)
                         for f in pf_1.fields if hasattr(pf_1, f)}
            pf_2_dict = {f: getattr(pf_2, f)
                         for f in pf_2.fields if hasattr(pf_2, f)}
            self.assertEqual(pf_1_dict, pf_2_dict)

        self.handler.port_forwarding_updated(
            self.txn, self.l3_plugin._nb_ovn, fake_pf_obj_ranges,
            fake_pf_obj_ranges_old)
        info_args, _info_kwargs = m_info.call_args_list[0]
        self.assertIn('UPDATE for port-forwarding', info_args[0])
        deleted_pf_1 = m_deleted.call_args_list[0][0][2]
        deleted_pf_2 = m_deleted.call_args_list[1][0][2]
        do_simple_comparation(deleted_pf_1, fake_pf_obj_1_old)
        do_simple_comparation(deleted_pf_2, fake_pf_obj_2_old)
        created_pf_1 = m_created.call_args_list[0][0][2]
        created_pf_2 = m_created.call_args_list[1][0][2]
        do_simple_comparation(created_pf_1, fake_pf_obj_1)
        do_simple_comparation(created_pf_2, fake_pf_obj_2)

    @mock.patch.object(port_forwarding.LOG, 'info')
    @mock.patch.object(
        port_forwarding.OVNPortForwardingHandler, '_port_forwarding_deleted')
    @mock.patch.object(
        port_forwarding.OVNPortForwardingHandler, '_port_forwarding_created')
    def test_port_forwarding_updated(self, m_created, m_deleted, m_info):
        fake_pf_obj = self._fake_pf_obj(
            is_object=True,
            id=uuidutils.generate_uuid(),
            floatingip_id=uuidutils.generate_uuid(),
            router_id=uuidutils.generate_uuid(),
            protocol='udp',
            floating_ip_address='10.0.0.1',
            external_port=2222,
            internal_ip_address='192.168.0.1',
            internal_port=22,
        )
        fake_orig_pf_obj = self._fake_pf_obj(
            is_object=True,
            id=uuidutils.generate_uuid(),
            floatingip_id=uuidutils.generate_uuid(),
            router_id=uuidutils.generate_uuid(),
            protocol='tcp',
            floating_ip_address='10.0.0.1',
            external_port=2222,
            internal_ip_address='192.168.0.1',
            internal_port=22,
        )
        self.handler.port_forwarding_updated(
            self.txn, self.l3_plugin._nb_ovn, fake_pf_obj, fake_orig_pf_obj)
        info_args, _info_kwargs = m_info.call_args_list[0]
        self.assertIn('UPDATE for port-forwarding', info_args[0])
        m_deleted.assert_called_once_with(self.txn, self.l3_plugin._nb_ovn,
                                          fake_orig_pf_obj, is_range=False)
        m_created.assert_called_once_with(self.txn, self.l3_plugin._nb_ovn,
                                          fake_pf_obj, is_range=False)

    @mock.patch.object(port_forwarding.LOG, 'info')
    def test_port_forwarding_deleted_with_ranges(self, m_info):
        id = uuidutils.generate_uuid()
        floatingip_id = uuidutils.generate_uuid()
        router_id = uuidutils.generate_uuid()
        fake_pf_obj_ranges = self._fake_pf_obj(
            is_object=True,
            id=id,
            floatingip_id=floatingip_id,
            router_id=router_id,
            protocol='udp',
            floating_ip_address='10.0.0.1',
            external_port=None,
            external_port_range='2222:2223',
            internal_ip_address='192.168.0.1',
            internal_port=None,
            internal_port_range='22:23'
        )
        fake_pf_obj_1 = self._fake_pf_obj(
            is_object=True,
            id=id,
            floatingip_id=floatingip_id,
            router_id=router_id,
            protocol='udp',
            floating_ip_address='10.0.0.1',
            external_port=2222,
            external_port_range=None,
            internal_ip_address='192.168.0.1',
            internal_port=22,
            internal_port_range=None
        )
        fake_pf_obj_2 = self._fake_pf_obj(
            is_object=True,
            id=id,
            floatingip_id=floatingip_id,
            router_id=router_id,
            protocol='udp',
            floating_ip_address='10.0.0.1',
            external_port=2223,
            external_port_range=None,
            internal_ip_address='192.168.0.1',
            internal_port=23,
            internal_port_range=None
        )

        exp_lb_name_1, exp_vip_1, _, _ = self.handler._get_lb_attributes(
            fake_pf_obj_1, True)
        exp_lb_name_2, exp_vip_2, _, _ = self.handler._get_lb_attributes(
            fake_pf_obj_2, True)
        self.handler.port_forwarding_deleted(
            self.txn, self.l3_plugin._nb_ovn, fake_pf_obj_ranges)
        info_args, _info_kwargs = m_info.call_args_list[0]
        self.assertIn('DELETE for port-forwarding', info_args[0])
        self.assertEqual(2, len(self.txn.add.call_args_list))
        self.l3_plugin._nb_ovn.lb_del.assert_any_call(
            exp_lb_name_1, exp_vip_1, if_exists=mock.ANY)
        self.l3_plugin._nb_ovn.lb_del.assert_any_call(
            exp_lb_name_2, exp_vip_2, if_exists=mock.ANY)

    @mock.patch.object(port_forwarding.LOG, 'info')
    def test_port_forwarding_deleted(self, m_info):
        fake_pf_obj = self._fake_pf_obj(
            is_object=True,
            id=uuidutils.generate_uuid(),
            floatingip_id=uuidutils.generate_uuid(),
            router_id=uuidutils.generate_uuid(),
            protocol='udp',
            floating_ip_address='10.0.0.1',
            external_port=2222,
            internal_ip_address='192.168.0.1',
            internal_port=22,
        )
        exp_lb_name, exp_vip, _, _ = self.handler._get_lb_attributes(
            fake_pf_obj)
        self.handler.port_forwarding_deleted(
            self.txn, self.l3_plugin._nb_ovn, fake_pf_obj)
        info_args, _info_kwargs = m_info.call_args_list[0]
        self.assertIn('DELETE for port-forwarding', info_args[0])
        self.assertEqual(1, len(self.txn.add.call_args_list))
        self.l3_plugin._nb_ovn.lb_del.assert_called_once_with(
            exp_lb_name, exp_vip, if_exists=mock.ANY)

    @mock.patch.object(port_forwarding.LOG, 'warning')
    def test__validate_router_networks_provider_networks(self, mock_warning):
        lr_ports = [
            mock.MagicMock(external_ids={
                ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY: 'neutron-ext-net-id',
                ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY: 'True'}),
            mock.MagicMock(external_ids={
                ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY: 'neutron-net-id',
                ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY: 'False'})]
        lr_mock = mock.MagicMock(ports=lr_ports)
        ovn_nb_mock = mock.Mock()
        ovn_nb_mock.get_lrouter.return_value = lr_mock
        with mock.patch.object(
                ovn_conf, 'is_ovn_distributed_floating_ip',
                return_value=True), mock.patch.object(
                    ovn_utils, 'is_provider_network',
                    return_value=True):
            self.handler._validate_router_networks(
                ovn_nb_mock, 'router-id')
        self.assertEqual(1, mock_warning.call_count)

    @mock.patch.object(port_forwarding.LOG, 'warning')
    def test__validate_router_networks_tunnel_networks(self, mock_warning):
        lr_ports = [
            mock.MagicMock(external_ids={
                ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY: 'neutron-ext-net-id',
                ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY: 'True'}),
            mock.MagicMock(external_ids={
                ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY: 'neutron-net-id',
                ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY: 'False'})]
        lr_mock = mock.MagicMock(ports=lr_ports)
        ovn_nb_mock = mock.Mock()
        ovn_nb_mock.get_lrouter.return_value = lr_mock
        with mock.patch.object(
                ovn_conf, 'is_ovn_distributed_floating_ip',
                return_value=True), mock.patch.object(
                    ovn_utils, 'is_provider_network',
                    return_value=False):
            self.handler._validate_router_networks(
                ovn_nb_mock, 'router-id')
        mock_warning.assert_not_called()


class TestOVNPortForwarding(TestOVNPortForwardingBase):
    def setUp(self):
        super(TestOVNPortForwarding, self).setUp()
        ovn_conf.register_opts()
        self.pf_plugin = mock.Mock()
        self.handler = mock.Mock()
        get_mock_pf_plugin = lambda alias: self.pf_plugin if (
                alias == plugin_constants.PORTFORWARDING) else None
        self.fake_get_dir_object = mock.patch(
            "neutron_lib.plugins.directory.get_plugin",
            side_effect=get_mock_pf_plugin).start()
        self.fake_handler_object = mock.patch(
            "neutron.services.portforwarding.drivers.ovn.driver."
            "OVNPortForwardingHandler",
            return_value=self.handler).start()
        self._ovn_pf = port_forwarding.OVNPortForwarding(self.l3_plugin)
        self.mock_pf_revs = mock.Mock()
        self.fake_check_rev = mock.patch.object(
            self._ovn_pf, '_add_check_rev',
            return_value=self.mock_pf_revs).start()
        self.fake_db_rev = mock.patch.object(
            self._ovn_pf, '_do_db_rev_bump_revision').start()

    def test_init(self):
        self.assertIsNotNone(self._ovn_pf)
        self.assertEqual(self._ovn_pf._l3_plugin, self.l3_plugin)
        self.assertEqual(self._ovn_pf._handler, self.handler)
        self.assertEqual(self._ovn_pf._pf_plugin, self.pf_plugin)

    def test__validate_configuration_ok(self):
        with mock.patch.object(
                port_forwarding.LOG, "warning") as mock_warning, \
                mock.patch.object(ovn_utils,
                                  "validate_port_forwarding_configuration"):

            self._ovn_pf._validate_configuration()
            mock_warning.assert_not_called()

    def test__validate_configuration_wrong(self):
        with mock.patch.object(
                port_forwarding.LOG, "warning") as mock_warning, \
                mock.patch.object(
                    ovn_utils,
                    "validate_port_forwarding_configuration",
                    side_effect=ovn_exc.InvalidPortForwardingConfiguration):
            self._ovn_pf._validate_configuration()
            mock_warning.assert_called_once_with(mock.ANY)

    def test_register(self):
        with mock.patch.object(registry, 'subscribe') as mock_subscribe:
            self._ovn_pf.register(mock.ANY, mock.ANY, mock.Mock())
            calls = [mock.call.mock_subscribe(mock.ANY,
                                              PORT_FORWARDING,
                                              events.AFTER_CREATE),
                     mock.call.mock_subscribe(mock.ANY,
                                              resources.ROUTER_INTERFACE,
                                              events.AFTER_CREATE),
                     mock.call.mock_subscribe(mock.ANY,
                                              PORT_FORWARDING,
                                              events.AFTER_UPDATE),
                     mock.call.mock_subscribe(mock.ANY,
                                              PORT_FORWARDING,
                                              events.AFTER_DELETE),
                     mock.call.mock_subscribe(mock.ANY,
                                              resources.ROUTER_INTERFACE,
                                              events.AFTER_DELETE)]
            mock_subscribe.assert_has_calls(calls)

    def test_get_pf_objs(self):
        _uuid = uuidutils.generate_uuid
        fip_id = _uuid()
        fake_pf_dicts = [{'id': _uuid(),
                          'floatingip_id': fip_id,
                          'external_port': pf_port,
                          'protocol': 'tcp',
                          'internal_port_id': _uuid(),
                          'internal_ip_address': '1.1.1.2',
                          'internal_port': pf_port,
                          'floating_ip_address': '111.111.111.111',
                          'router_id': _uuid()} for pf_port in range(22, 32)]

        self.pf_plugin.get_floatingip_port_forwardings = mock.Mock(
            return_value=fake_pf_dicts)
        pf_objs = self._ovn_pf._get_pf_objs(self.context, fip_id)
        self.pf_plugin.get_floatingip_port_forwardings.assert_called_once_with(
            self.context, fip_id)
        for index, fake_pf_dict in enumerate(fake_pf_dicts):
            self.assertEqual(fake_pf_dict['id'], pf_objs[index].id)
            self.assertEqual(fake_pf_dict['floatingip_id'],
                             pf_objs[index].floatingip_id)
            self.assertEqual(fake_pf_dict['external_port'],
                             pf_objs[index].external_port)
            self.assertEqual(fake_pf_dict['internal_port_id'],
                             pf_objs[index].internal_port_id)
            self.assertEqual(fake_pf_dict['router_id'],
                             pf_objs[index].router_id)

    def test_get_fip_objs(self):
        payload = self._fake_pf_payload_entry(1, 2)
        self.l3_plugin.get_floatingip = lambda _, fip_id: fip_id * 10
        fip_objs = self._ovn_pf._get_fip_objs(self.context, payload)
        self.assertEqual({1: 10, 2: 20}, fip_objs)

    def _handle_notification_common(self, event_type, payload=None,
                                    fip_objs=None):
        if not payload:
            payload = []
        if not fip_objs:
            fip_objs = {}
        self.fake_db_rev.reset_mock()
        with mock.patch.object(self._ovn_pf, '_get_fip_objs',
                               return_value=fip_objs) as mock_get_fip_objs:
            self._ovn_pf._handle_notification(None, event_type,
                                              self.pf_plugin, payload)
            self.assertTrue(self.fake_db_rev.called or not fip_objs)
            if not payload:
                return
            mock_get_fip_objs.assert_called_once_with(self.context, payload)
            if fip_objs:
                calls = [
                    mock.call(mock.ANY, self.l3_plugin._nb_ovn, fip_id,
                              fip_obj)
                    for fip_id, fip_obj in fip_objs.items()]
                self.fake_check_rev.assert_has_calls(calls)
                self.fake_db_rev.assert_called_once_with(
                    self.context, self.mock_pf_revs)

    def test_handle_notification_noop(self):
        self._handle_notification_common(events.AFTER_CREATE)
        weird_event_type = 666
        fake_payload = self._fake_pf_payload_entry(None)
        self._handle_notification_common(weird_event_type, fake_payload)

    def test_handle_notification_basic(self):
        fake_payload_entry = self._fake_pf_payload_entry(1)
        self._handle_notification_common(events.AFTER_CREATE,
                                         fake_payload_entry)
        self.handler.port_forwarding_created.assert_called_once_with(
            mock.ANY, self.l3_plugin._nb_ovn, fake_payload_entry.latest_state)

    def test_handle_notification_create(self):
        fip_objs = {1: {'description': 'one'},
                    3: {'description': 'three', 'revision_number': '321'}}
        for id in range(1, 4):
            fake_payload = self._fake_pf_payload_entry(id)
            self._handle_notification_common(events.AFTER_CREATE,
                                             fake_payload,
                                             fip_objs)
            calls = [mock.call(mock.ANY, self.l3_plugin._nb_ovn,
                               fake_payload.latest_state)]
            self.handler.port_forwarding_created.assert_has_calls(calls)
            update_calls = [mock.call(
                self.context, fake_payload.latest_state.floatingip_id,
                const.FLOATINGIP_STATUS_ACTIVE)]
            self.l3_plugin.update_floatingip_status.assert_has_calls(
                update_calls)

    def test_handle_notification_update(self):
        fip_objs = {100: {'description': 'hundred'}, 101: {}}
        fake_payload = self._fake_pf_payload_entry(100, 100)
        self._handle_notification_common(events.AFTER_UPDATE, fake_payload,
                                         fip_objs)
        calls = [mock.call(mock.ANY, self.l3_plugin._nb_ovn,
                           fake_payload.latest_state,
                           fake_payload.states[0])]
        self.handler.port_forwarding_updated.assert_has_calls(calls)

        fake_payload = self._fake_pf_payload_entry(101, 101)
        self._handle_notification_common(events.AFTER_UPDATE, fake_payload,
                                         fip_objs)
        calls = [mock.call(mock.ANY, self.l3_plugin._nb_ovn,
                           fake_payload.latest_state,
                           fake_payload.states[0])]
        self.handler.port_forwarding_updated.assert_has_calls(calls)

    def test_handle_notification_delete(self):
        fip_objs = {1: {'description': 'one'},
                    2: {'description': 'two', 'revision_number': '222'}}
        for id in range(1, 4):
            fake_payload = self._fake_pf_payload_entry(None, id)

            with mock.patch.object(
                    self.pf_plugin, 'get_floatingip_port_forwardings',
                    return_value=[]):
                self._handle_notification_common(events.AFTER_DELETE,
                                                 fake_payload, fip_objs)
                calls = [mock.call(
                    mock.ANY, self.l3_plugin._nb_ovn, fake_payload.states[0])]
                self.handler.port_forwarding_deleted.assert_has_calls(calls)
                update_calls = [mock.call(
                    self.context, fake_payload.states[0].floatingip_id,
                    const.FLOATINGIP_STATUS_DOWN)]
                self.l3_plugin.update_floatingip_status.assert_has_calls(
                    update_calls)

    def test_maintenance_create_or_update(self):
        pf_objs = [self._fake_pf_obj()]
        fip_id = pf_objs[0].floatingip_id
        fake_fip_obj = {'floatingip_id': fip_id}
        fake_lb_names = ['lb1', 'lb2']
        self.handler.lb_names = mock.Mock(return_value=fake_lb_names)
        self.handler.port_forwarding_created = mock.Mock()
        self.l3_plugin.get_floatingip = mock.Mock(return_value=fake_fip_obj)
        with mock.patch.object(self._ovn_pf, '_get_pf_objs',
                               return_value=pf_objs) as mock_get_pf_objs:
            self._ovn_pf._maintenance_create_update(self.context, fip_id)
            self.l3_plugin._nb_ovn.transaction.assert_called_once_with(
                check_error=True)
            calls = [mock.call(lb_name, vip=None, if_exists=True)
                     for lb_name in fake_lb_names]
            self.l3_plugin._nb_ovn.lb_del.assert_has_calls(calls)
            calls = [mock.call(mock.ANY, self.l3_plugin._nb_ovn, pf_obj)
                     for pf_obj in pf_objs]
            self.handler.port_forwarding_created.assert_has_calls(calls)
            mock_get_pf_objs.assert_called_once_with(self.context, fip_id)
            self.l3_plugin.get_floatingip.assert_called_once_with(
                self.context, fip_id)
            self.fake_db_rev.assert_called_once_with(
                self.context, self.mock_pf_revs)

    def test_maintenance_delete(self):
        pf_objs = [self._fake_pf_obj()]
        fip_id = pf_objs[0].floatingip_id
        fake_fip_obj = {'floatingip_id': fip_id}
        fake_lb_names = ['lb1', 'lb2']
        self.handler.lb_names = mock.Mock(return_value=fake_lb_names)
        self.handler.port_forwarding_created = mock.Mock()
        self.l3_plugin.get_floatingip = mock.Mock(return_value=fake_fip_obj)
        with mock.patch.object(self._ovn_pf, '_get_pf_objs',
                               return_value=pf_objs) as mock_get_pf_objs:
            self._ovn_pf.maintenance_delete(self.context, fip_id)
            self.l3_plugin._nb_ovn.transaction.assert_called_once_with(
                check_error=True)
            calls = [mock.call(lb_name, vip=None, if_exists=True)
                     for lb_name in fake_lb_names]
            self.l3_plugin._nb_ovn.lb_del.assert_has_calls(calls)
            self.handler.port_forwarding_created.assert_not_called()
            mock_get_pf_objs.assert_not_called()
            self.l3_plugin.get_floatingip.assert_not_called()
            self.fake_db_rev.assert_not_called()

    @mock.patch.object(port_forwarding.LOG, 'info')
    def test_db_sync_create_or_update(self, m_info):
        pf_objs = [self._fake_pf_obj()]
        fip_id = pf_objs[0].floatingip_id
        fake_fip_obj = {'floatingip_id': fip_id, 'revision_number': 123456789}
        fake_lb_names = ['lb1', 'lb2']
        self.handler.lb_names = mock.Mock(return_value=fake_lb_names)
        self.handler.port_forwarding_created = mock.Mock()
        self.l3_plugin.get_floatingip = mock.Mock(return_value=fake_fip_obj)
        with mock.patch.object(self._ovn_pf, '_get_pf_objs',
                               return_value=pf_objs) as mock_get_pf_objs:
            self._ovn_pf.db_sync_create_or_update(
                self.context, fip_id, self.txn)
            info_args, _info_kwargs = m_info.call_args_list[0]
            self.assertIn('db_sync UPDATE entries', info_args[0])
            mock_get_pf_objs.assert_called_once_with(self.context, fip_id)
            calls = [mock.call(lb_name, vip=None, if_exists=True)
                     for lb_name in fake_lb_names]
            self.l3_plugin._nb_ovn.lb_del.assert_has_calls(calls)
            calls = [mock.call(mock.ANY, self.l3_plugin._nb_ovn, pf_obj)
                     for pf_obj in pf_objs]
            self.handler.port_forwarding_created.assert_has_calls(calls)
            self.l3_plugin.get_floatingip.assert_called_once_with(
                self.context, fip_id)
            self.fake_check_rev.assert_called_once_with(
                self.txn, self.l3_plugin._nb_ovn, fip_id, fake_fip_obj)

    @mock.patch.object(port_forwarding.LOG, 'info')
    def test_db_sync_delete(self, m_info):
        fip_id = 'fip_id'
        fake_lb_names = ['lb1', 'lb2', 'lb3', 'lb4', 'lb5']
        self.handler.lb_names = mock.Mock(return_value=fake_lb_names)
        self._ovn_pf.db_sync_delete(self.context, fip_id, self.txn)
        info_args, _info_kwargs = m_info.call_args_list[0]
        self.assertIn('db_sync DELETE entries', info_args[0])
        calls = [mock.call(lb_name, vip=None, if_exists=True)
                 for lb_name in fake_lb_names]
        self.l3_plugin._nb_ovn.lb_del.assert_has_calls(calls)
