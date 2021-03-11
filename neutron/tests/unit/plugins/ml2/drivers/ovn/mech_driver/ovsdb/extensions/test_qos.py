# Copyright 2020 Red Hat, Inc.
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

import netaddr
from neutron_lib.api.definitions import qos as qos_api
from neutron_lib import constants
from neutron_lib import context
from neutron_lib.db import api as db_api
from neutron_lib.services.qos import constants as qos_constants
from oslo_config import cfg
from oslo_utils import uuidutils

from neutron.api import extensions
from neutron.common.ovn import constants as ovn_const
from neutron.core_extensions import qos as core_qos
from neutron.objects import network as network_obj
from neutron.objects import ports as port_obj
from neutron.objects.qos import policy as policy_obj
from neutron.objects.qos import rule as rule_obj
from neutron.objects import router as router_obj
from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb.extensions \
    import qos as qos_extension
from neutron.tests.unit.plugins.ml2 import test_plugin


QOS_RULE_BW_1 = {'max_kbps': 200, 'max_burst_kbps': 100}
QOS_RULE_BW_2 = {'max_kbps': 300}
QOS_RULE_DSCP_1 = {'dscp_mark': 16}
QOS_RULE_DSCP_2 = {'dscp_mark': 20}
QOS_RULE_MINBW_1 = {'min_kbps': 500}


class _Context(object):

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return


class TestOVNClientQosExtension(test_plugin.Ml2PluginV2TestCase):

    CORE_PLUGIN_CLASS = 'neutron.plugins.ml2.plugin.Ml2Plugin'
    _extension_drivers = [qos_api.ALIAS]
    l3_plugin = ('neutron.tests.unit.extensions.test_qos_fip.'
                 'TestFloatingIPQoSL3NatServicePlugin')

    def setUp(self):
        cfg.CONF.set_override('extension_drivers', self._extension_drivers,
                              group='ml2')
        cfg.CONF.set_override('enable_distributed_floating_ip', 'False',
                              group='ovn')
        extensions.register_custom_supported_check(qos_api.ALIAS, lambda: True,
                                                   plugin_agnostic=True)
        super(TestOVNClientQosExtension, self).setUp()
        self.setup_coreplugin(self.CORE_PLUGIN_CLASS, load_plugins=True)
        self._mock_qos_loaded = mock.patch.object(
            core_qos.QosCoreResourceExtension, 'plugin_loaded')
        self.mock_qos_loaded = self._mock_qos_loaded.start()
        self.txn = _Context()
        mock_driver = mock.Mock()
        mock_driver._nb_idl.transaction.return_value = self.txn
        self.qos_driver = qos_extension.OVNClientQosExtension(mock_driver)
        self._mock_rules = mock.patch.object(self.qos_driver,
                                             '_update_port_qos_rules')
        self.mock_rules = self._mock_rules.start()
        self.addCleanup(self._mock_rules.stop)
        self.ctx = context.get_admin_context()
        self.project_id = uuidutils.generate_uuid()
        self._initialize_objs()

    def _get_random_db_fields(self, obj_cls=None):
        obj_cls = obj_cls or self._test_class
        return obj_cls.modify_fields_to_db(
            self.get_random_object_fields(obj_cls))

    def _create_one_port(self, mac_address_int, network_id):
        mac_address = netaddr.EUI(mac_address_int)
        port = port_obj.Port(
            self.ctx, project_id=self.project_id,
            network_id=network_id, device_owner='',
            admin_state_up=True, status='DOWN', device_id='2',
            mac_address=mac_address)
        port.create()
        return port

    def _create_one_router(self):
        self.router_gw_port = self._create_one_port(2000, self.fips_network.id)
        self.router = router_obj.Router(self.ctx, id=uuidutils.generate_uuid(),
                                        gw_port_id=self.router_gw_port.id)
        self.router.create()

    def _initialize_objs(self):
        self.qos_policies = []
        self.ports = []
        self.networks = []
        self.fips = []
        self.fips_network = network_obj.Network(
            self.ctx, id=uuidutils.generate_uuid(), project_id=self.project_id)
        self.fips_network.create()
        self._create_one_router()
        self.fips_ports = []
        fip_cidr = netaddr.IPNetwork('10.10.0.0/24')

        for net_idx in range(2):
            qos_policy = policy_obj.QosPolicy(
                self.ctx, id=uuidutils.generate_uuid(),
                project_id=self.project_id)
            qos_policy.create()
            self.qos_policies.append(qos_policy)

            # Any QoS policy should have at least one rule, in order to have
            # the port dictionary extended with the QoS policy information; see
            # QoSPlugin._extend_port_resource_request
            qos_rule = rule_obj.QosDscpMarkingRule(
                self.ctx, dscp_mark=20, id=uuidutils.generate_uuid(),
                qos_policy_id=qos_policy.id)
            qos_rule.create()

            self.fips_ports.append(self._create_one_port(1000 + net_idx,
                                                         self.fips_network.id))
            fip_ip = str(netaddr.IPAddress(fip_cidr.ip + net_idx + 1))
            fip = router_obj.FloatingIP(
                self.ctx, id=uuidutils.generate_uuid(),
                project_id=self.project_id, floating_ip_address=fip_ip,
                floating_network_id=self.fips_network.id,
                floating_port_id=self.fips_ports[-1].id)
            fip.create()
            self.fips.append(fip)

            network = network_obj.Network(
                self.ctx, id=uuidutils.generate_uuid(),
                project_id=self.project_id)
            network.create()
            self.networks.append(network)

            for port_idx in range(3):
                self.ports.append(
                    self._create_one_port(net_idx * 16 + port_idx, network.id))

    @mock.patch.object(qos_extension.LOG, 'warning')
    @mock.patch.object(rule_obj, 'get_rules')
    def test__qos_rules(self, mock_get_rules, mock_warning):
        rules = [
            rule_obj.QosBandwidthLimitRule(
                direction=constants.EGRESS_DIRECTION, **QOS_RULE_BW_1),
            rule_obj.QosBandwidthLimitRule(
                direction=constants.INGRESS_DIRECTION, **QOS_RULE_BW_2),
            rule_obj.QosDscpMarkingRule(**QOS_RULE_DSCP_1),
            rule_obj.QosMinimumBandwidthRule(**QOS_RULE_MINBW_1)]
        mock_get_rules.return_value = rules
        expected = {
            constants.EGRESS_DIRECTION: {
                qos_constants.RULE_TYPE_BANDWIDTH_LIMIT: QOS_RULE_BW_1,
                qos_constants.RULE_TYPE_DSCP_MARKING: QOS_RULE_DSCP_1},
            constants.INGRESS_DIRECTION: {
                qos_constants.RULE_TYPE_BANDWIDTH_LIMIT: QOS_RULE_BW_2}
        }
        self.assertEqual(expected, self.qos_driver._qos_rules(mock.ANY,
                                                              'policy_id1'))
        msg = ('Rule type %(rule_type)s from QoS policy %(policy_id)s is not '
               'supported in OVN')
        mock_warning.assert_called_once_with(
            msg, {'rule_type': qos_constants.RULE_TYPE_MINIMUM_BANDWIDTH,
                  'policy_id': 'policy_id1'})

    @mock.patch.object(rule_obj, 'get_rules')
    def test__qos_rules_no_rules(self, mock_get_rules):
        mock_get_rules.return_value = []
        expected = {constants.EGRESS_DIRECTION: {},
                    constants.INGRESS_DIRECTION: {}}
        self.assertEqual(expected,
                         self.qos_driver._qos_rules(mock.ANY, mock.ANY))

    def _test__ovn_qos_rule_ingress(self, fip_id=None, ip_address=None):
        direction = constants.INGRESS_DIRECTION
        rule = {qos_constants.RULE_TYPE_BANDWIDTH_LIMIT: QOS_RULE_BW_1}
        match = self.qos_driver._ovn_qos_rule_match(
            direction, 'port_id', ip_address, 'resident_port')
        expected = {'burst': 100, 'rate': 200, 'direction': 'to-lport',
                    'match': match,
                    'priority': qos_extension.OVN_QOS_DEFAULT_RULE_PRIORITY,
                    'switch': 'neutron-network_id'}
        if fip_id:
            expected['external_ids'] = {ovn_const.OVN_FIP_EXT_ID_KEY: fip_id}
        result = self.qos_driver._ovn_qos_rule(
            direction, rule, 'port_id', 'network_id', fip_id=fip_id,
            ip_address=ip_address, resident_port='resident_port')
        self.assertEqual(expected, result)

    def test__ovn_qos_rule_ingress(self):
        self._test__ovn_qos_rule_ingress()

    def test__ovn_qos_rule_ingress_fip(self):
        self._test__ovn_qos_rule_ingress(fip_id='fipid', ip_address='1.2.3.4')

    def _test__ovn_qos_rule_egress(self, fip_id=None, ip_address=None):
        direction = constants.EGRESS_DIRECTION
        rule = {qos_constants.RULE_TYPE_DSCP_MARKING: QOS_RULE_DSCP_1}
        match = self.qos_driver._ovn_qos_rule_match(
            direction, 'port_id', ip_address, 'resident_port')
        expected = {'direction': 'from-lport', 'match': match,
                    'dscp': 16, 'switch': 'neutron-network_id',
                    'priority': qos_extension.OVN_QOS_DEFAULT_RULE_PRIORITY}
        if fip_id:
            expected['external_ids'] = {ovn_const.OVN_FIP_EXT_ID_KEY: fip_id}
        result = self.qos_driver._ovn_qos_rule(
            direction, rule, 'port_id', 'network_id', fip_id=fip_id,
            ip_address=ip_address, resident_port='resident_port')
        self.assertEqual(expected, result)

        rule = {qos_constants.RULE_TYPE_BANDWIDTH_LIMIT: QOS_RULE_BW_2,
                qos_constants.RULE_TYPE_DSCP_MARKING: QOS_RULE_DSCP_2}
        expected = {'direction': 'from-lport', 'match': match,
                    'rate': 300, 'dscp': 20, 'switch': 'neutron-network_id',
                    'priority': qos_extension.OVN_QOS_DEFAULT_RULE_PRIORITY}
        if fip_id:
            expected['external_ids'] = {ovn_const.OVN_FIP_EXT_ID_KEY: fip_id}
        result = self.qos_driver._ovn_qos_rule(
            direction, rule, 'port_id', 'network_id', fip_id=fip_id,
            ip_address=ip_address, resident_port='resident_port')
        self.assertEqual(expected, result)

    def test__ovn_qos_rule_egress(self):
        self._test__ovn_qos_rule_egress()

    def test__ovn_qos_rule_egress_fip(self):
        self._test__ovn_qos_rule_egress(fip_id='fipid', ip_address='1.2.3.4')

    def test__port_effective_qos_policy_id(self):
        port = {'qos_policy_id': 'qos1'}
        self.assertEqual(('qos1', 'port'),
                         self.qos_driver._port_effective_qos_policy_id(port))

        port = {'qos_network_policy_id': 'qos1'}
        self.assertEqual(('qos1', 'network'),
                         self.qos_driver._port_effective_qos_policy_id(port))

        port = {'qos_policy_id': 'qos_port',
                'qos_network_policy_id': 'qos_network'}
        self.assertEqual(('qos_port', 'port'),
                         self.qos_driver._port_effective_qos_policy_id(port))

        port = {}
        self.assertEqual((None, None),
                         self.qos_driver._port_effective_qos_policy_id(port))

        port = {'qos_policy_id': None, 'qos_network_policy_id': None}
        self.assertEqual((None, None),
                         self.qos_driver._port_effective_qos_policy_id(port))

        port = {'qos_policy_id': 'qos1', 'device_owner': 'neutron:port'}
        self.assertEqual((None, None),
                         self.qos_driver._port_effective_qos_policy_id(port))

    def test_update_port(self):
        port = self.ports[0]
        original_port = self.ports[1]

        # Remove QoS policy
        original_port.qos_policy_id = self.qos_policies[0].id
        self.qos_driver.update_port(mock.ANY, port, original_port)
        self.mock_rules.assert_called_once_with(
            mock.ANY, port.id, port.network_id, None, None)

        # Change from port policy (qos_policy0) to network policy (qos_policy1)
        self.mock_rules.reset_mock()
        port.qos_network_policy_id = self.qos_policies[1].id
        self.qos_driver.update_port(mock.ANY, port, original_port)
        self.mock_rules.assert_called_once_with(
            mock.ANY, port.id, port.network_id, self.qos_policies[1].id, None)

        # No change (qos_policy0)
        self.mock_rules.reset_mock()
        port.qos_policy_id = self.qos_policies[0].id
        original_port.qos_policy_id = self.qos_policies[0].id
        self.qos_driver.update_port(mock.ANY, port, original_port)
        self.mock_rules.assert_not_called()

        # No change (no policy)
        self.mock_rules.reset_mock()
        port.qos_policy_id = None
        port.qos_network_policy_id = None
        original_port.qos_policy_id = None
        original_port.qos_network_policy_id = None
        self.qos_driver.update_port(mock.ANY, port, original_port)
        self.mock_rules.assert_not_called()

        # Reset (no policy)
        self.qos_driver.update_port(mock.ANY, port, original_port, reset=True)
        self.mock_rules.assert_called_once_with(
            mock.ANY, port.id, port.network_id, None, None)

        # Reset (qos_policy0, regardless of being the same a in the previous
        # state)
        self.mock_rules.reset_mock()
        port.qos_policy_id = self.qos_policies[0].id
        original_port.qos_policy_id = self.qos_policies[1].id
        self.qos_driver.update_port(mock.ANY, port, original_port, reset=True)
        self.mock_rules.assert_called_once_with(
            mock.ANY, port.id, port.network_id, self.qos_policies[0].id, None)

        # External port, OVN QoS extension does not apply.
        self.mock_rules.reset_mock()
        port.qos_policy_id = self.qos_policies[0].id
        self.qos_driver.update_port(mock.ANY, port, original_port,
                                    port_type=ovn_const.LSP_TYPE_EXTERNAL)
        self.mock_rules.assert_not_called()

    def test_delete_port(self):
        self.mock_rules.reset_mock()
        self.qos_driver.delete_port(mock.ANY, self.ports[1])

        # Assert that rules are deleted
        self.mock_rules.assert_called_once_with(
            mock.ANY, self.ports[1].id, self.ports[1].network_id, None, None)

    def test_update_network(self):
        """Test update network.

        net1: [(1) from qos_policy0 to no QoS policy,
               (2) from qos_policy0 to qos_policy1]
        - port10: no QoS port policy
        - port11: qos_policy0
        - port12: qos_policy1
        """
        policies_ports = [
            (None, {self.ports[0].id}),
            (self.qos_policies[1].id, {self.ports[0].id})]

        self.ports[1].qos_policy_id = self.qos_policies[0].id
        self.ports[1].update()
        self.ports[2].qos_policy_id = self.qos_policies[1].id
        self.ports[2].update()
        for qos_policy_id, reference_ports in policies_ports:
            self.networks[0].qos_policy_id = qos_policy_id
            self.networks[0].update()
            original_network = {'qos_policy_id': self.qos_policies[0]}
            reviewed_port_ids = self.qos_driver.update_network(
                mock.ANY, self.networks[0], original_network)
            self.assertEqual(reference_ports, reviewed_port_ids)
            calls = [mock.call(mock.ANY, self.ports[0].id,
                               self.ports[0].network_id, qos_policy_id,
                               None)]
            self.mock_rules.assert_has_calls(calls)
            self.mock_rules.reset_mock()

    def test_update_network_no_policy_change(self):
        """Test update network if the QoS policy is the same.

        net1: [(1) from qos_policy0 to qos_policy0,
               (2) from no QoS policy to no QoS policy]
        """
        for qos_policy_id in (self.qos_policies[0].id, None):
            self.networks[0].qos_policy_id = qos_policy_id
            self.networks[0].update()
            original_network = {'qos_policy_id': qos_policy_id}
            reviewed_port_ids = self.qos_driver.update_network(
                mock.ANY, self.networks[0], original_network)
            self.assertEqual(set([]), reviewed_port_ids)
            self.mock_rules.assert_not_called()

    def test_update_network_reset(self):
        """Test update network.

        net1: [(1) from qos_policy1 to qos_policy1,
               (2) from no QoS policy to no QoS policy]
        - port10: no QoS port policy
        - port11: qos_policy0
        - port12: qos_policy1
        """
        policies_ports = [
            (self.qos_policies[1].id, {self.ports[0].id}),
            (None, {self.ports[0].id})]

        self.ports[1].qos_policy_id = self.qos_policies[0].id
        self.ports[1].update()
        self.ports[2].qos_policy_id = self.qos_policies[1].id
        self.ports[2].update()
        for qos_policy_id, reference_ports in policies_ports:
            self.networks[0].qos_policy_id = qos_policy_id
            self.networks[0].update()
            original_network = {'qos_policy_id': self.qos_policies[0]}
            reviewed_port_ids = self.qos_driver.update_network(
                mock.ANY, self.networks[0], original_network, reset=True)
            self.assertEqual(reference_ports, reviewed_port_ids)
            calls = [mock.call(mock.ANY, self.ports[0].id,
                               self.ports[0].network_id, qos_policy_id, None)]
            self.mock_rules.assert_has_calls(calls)
            self.mock_rules.reset_mock()

    def test_update_policy(self):
        """Test update QoS policy, networks and ports bound are updated.

        QoS policy updated: qos_policy0
        net1: no QoS policy
        - port10: no port QoS policy
        - port11: qos_policy0  --> handled during "update_port" and updated
        - port12: qos_policy1
        net2: qos_policy0
        - port20: no port QoS policy  --> handled during "update_network"
                                          and updated
        - port21: qos_policy0  --> handled during "update_network", not updated
                                   handled during "update_port" and updated
        - port22: qos_policy1  --> handled during "update_network", not updated
        fip1: qos_policy0
        fip2: qos_policy1
        """
        self.ports[1].qos_policy_id = self.qos_policies[0].id
        self.ports[1].update()
        self.ports[2].qos_policy_id = self.qos_policies[1].id
        self.ports[2].update()
        self.ports[4].qos_policy_id = self.qos_policies[0].id
        self.ports[4].update()
        self.ports[5].qos_policy_id = self.qos_policies[1].id
        self.ports[5].update()
        self.networks[1].qos_policy_id = self.qos_policies[0].id
        self.networks[1].update()
        self.fips[0].qos_policy_id = self.qos_policies[0].id
        self.fips[0].update()
        self.fips[1].qos_policy_id = self.qos_policies[1].id
        self.fips[1].update()
        mock_qos_rules = mock.Mock()
        with mock.patch.object(self.qos_driver, '_qos_rules',
                               return_value=mock_qos_rules), \
                mock.patch.object(self.qos_driver, 'update_floatingip') as \
                mock_update_fip:
            self.qos_driver.update_policy(self.ctx, self.qos_policies[0])
        updated_ports = [self.ports[1], self.ports[3], self.ports[4]]
        calls = [mock.call(self.txn, port.id, port.network_id,
                           self.qos_policies[0].id, mock_qos_rules)
                 for port in updated_ports]
        # We can't ensure the call order because we are not enforcing any order
        # when retrieving the port and the network list.
        self.mock_rules.assert_has_calls(calls, any_order=True)
        with db_api.CONTEXT_READER.using(self.ctx):
            fip = self.qos_driver._plugin_l3.get_floatingip(self.ctx,
                                                            self.fips[0].id)
        mock_update_fip.assert_called_once_with(self.txn, fip)

    def test_update_floatingip(self):
        nb_idl = self.qos_driver._driver._nb_idl
        fip = self.fips[0]
        original_fip = self.fips[1]
        txn = mock.Mock()

        # Update FIP, no QoS policy nor port/router
        self.qos_driver.update_floatingip(txn, fip)
        nb_idl.qos_del_ext_ids.assert_called_once()
        nb_idl.qos_add.assert_not_called()
        nb_idl.reset_mock()

        # Attach a port and a router, not QoS policy
        fip.router_id = self.router.id
        fip.fixed_port_id = self.fips_ports[0].id
        fip.update()
        self.qos_driver.update_floatingip(txn, fip)
        nb_idl.qos_del_ext_ids.assert_called_once()
        nb_idl.qos_add.assert_not_called()
        nb_idl.reset_mock()

        # Add a QoS policy
        fip.qos_policy_id = self.qos_policies[0].id
        fip.update()
        self.qos_driver.update_floatingip(txn, fip)
        nb_idl.qos_del_ext_ids.assert_called_once()
        nb_idl.qos_add.assert_called_once()
        nb_idl.reset_mock()

        # Remove QoS
        fip.qos_policy_id = None
        fip.update()
        original_fip.qos_policy_id = self.qos_policies[0].id
        original_fip.update()
        self.qos_driver.update_floatingip(txn, fip)
        nb_idl.qos_del_ext_ids.assert_called_once()
        nb_idl.qos_add.assert_not_called()
        nb_idl.reset_mock()

        # Add again another QoS policy
        fip.qos_policy_id = self.qos_policies[1].id
        fip.update()
        original_fip.qos_policy_id = None
        original_fip.update()
        self.qos_driver.update_floatingip(txn, fip)
        nb_idl.qos_del_ext_ids.assert_called_once()
        nb_idl.qos_add.assert_called_once()
        nb_idl.reset_mock()

        # Detach the port and the router
        fip.router_id = None
        fip.fixed_port_id = None
        fip.update()
        original_fip.router_id = self.router.id
        original_fip.fixed_port_id = self.fips_ports[0].id
        original_fip.qos_policy_id = self.qos_policies[1].id
        original_fip.update()
        self.qos_driver.update_floatingip(txn, fip)
        nb_idl.qos_del_ext_ids.assert_called_once()
        nb_idl.qos_add.assert_not_called()
        nb_idl.reset_mock()

        # Force reset (delete any QoS)
        fip_dict = {'floating_network_id': fip.floating_network_id,
                    'id': fip.id}
        self.qos_driver.update_floatingip(txn, fip_dict)
        nb_idl.qos_del_ext_ids.assert_called_once()
        nb_idl.qos_add.assert_not_called()
