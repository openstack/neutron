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

import random
from unittest import mock

import ddt
import netaddr
from neutron_lib.api.definitions import external_net as enet_api
from neutron_lib.api.definitions import l3 as l3_apidef
from neutron_lib.api.definitions import portbindings as portbindings_api
from neutron_lib.api.definitions import provider_net as pnet_api
from neutron_lib.api.definitions import qos as qos_api
from neutron_lib.api.definitions import qos_fip as qos_fip_apidef
from neutron_lib import constants
from neutron_lib import context
from neutron_lib.db import api as db_api
from neutron_lib.services.qos import constants as qos_constants
from oslo_config import cfg
from oslo_utils import uuidutils

from neutron.api import extensions
from neutron.common import config as common_config
from neutron.common.ovn import constants as ovn_const
from neutron.conf.plugins.ml2.drivers import driver_type
from neutron.conf.plugins.ml2.drivers.ovn import ovn_conf
from neutron.core_extensions import qos as core_qos
from neutron.db import l3_fip_qos
from neutron.db import l3_gateway_ip_qos
from neutron.objects import ports as port_obj
from neutron.objects.qos import policy as policy_obj
from neutron.objects.qos import rule as rule_obj
from neutron.objects import router as router_obj
from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb.extensions \
    import qos as qos_extension
from neutron.tests.unit.extensions import test_l3
from neutron.tests.unit.plugins.ml2 import test_plugin


QOS_RULE_BW_1 = {'max_kbps': 200, 'max_burst_kbps': 100}
QOS_RULE_BW_2 = {'max_kbps': 300}
QOS_RULE_DSCP_1 = {'dscp_mark': 16}
QOS_RULE_DSCP_2 = {'dscp_mark': 20}
QOS_RULE_MINBW_1 = {'min_kbps': 500}
QOS_RULE_MINBW_2 = {'min_kbps': 700}


class _Context:

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return


class TestFloatingIPQoSL3NatServicePlugin(
        test_l3.TestL3NatServicePlugin,
        l3_fip_qos.FloatingQoSDbMixin,
        l3_gateway_ip_qos.L3_gw_ip_qos_db_mixin):
    supported_extension_aliases = [l3_apidef.ALIAS, 'qos',
                                   qos_fip_apidef.ALIAS]


@ddt.ddt
class TestOVNClientQosExtension(test_plugin.Ml2PluginV2TestCase):

    CORE_PLUGIN_CLASS = 'neutron.plugins.ml2.plugin.Ml2Plugin'
    _extension_drivers = [qos_api.ALIAS]
    l3_plugin = ('neutron.tests.unit.plugins.ml2.drivers.ovn.'
                 'mech_driver.ovsdb.extensions.'
                 'test_qos.TestFloatingIPQoSL3NatServicePlugin')

    def setUp(self):
        common_config.register_common_config_options()
        ovn_conf.register_opts()
        driver_type.register_ml2_drivers_geneve_opts()
        self.tenant_type = constants.TYPE_GENEVE
        cfg.CONF.set_override('extension_drivers', self._extension_drivers,
                              group='ml2')
        cfg.CONF.set_override('enable_distributed_floating_ip', 'False',
                              group='ovn')
        cfg.CONF.set_override('external_network_type', 'vlan',
                              group='ml2')
        cfg.CONF.set_override('tenant_network_types', [self.tenant_type],
                              group='ml2')
        cfg.CONF.set_override('vni_ranges', ['1:200'], group='ml2_type_geneve')
        cfg.CONF.set_override('max_header_size', 38, group='ml2_type_geneve')
        extensions.register_custom_supported_check(qos_api.ALIAS, lambda: True,
                                                   plugin_agnostic=True)
        super().setUp()
        self.setup_coreplugin(self.CORE_PLUGIN_CLASS, load_plugins=True)
        self._mock_qos_loaded = mock.patch.object(
            core_qos.QosCoreResourceExtension, 'plugin_loaded')
        self.mock_qos_loaded = self._mock_qos_loaded.start()
        self.txn = _Context()
        mock_driver = mock.Mock()
        mock_driver._nb_idl.transaction.return_value = self.txn
        self.qos_driver = qos_extension.OVNClientQosExtension(
            driver=mock_driver)
        self._mock_rules = mock.patch.object(self.qos_driver,
                                             '_update_port_qos_rules')
        self.mock_rules = self._mock_rules.start()
        self.mock_lsp_get = mock.patch.object(self.qos_driver._driver._nb_idl,
                                              'ls_get').start()
        self.mock_lsp_get.return_value.execute.return_value = mock.Mock(
            external_ids={ovn_const.OVN_NETTYPE_EXT_ID_KEY: mock.ANY})
        self.addCleanup(self._mock_rules.stop)
        self.ctx = context.get_admin_context()
        self.project_id = uuidutils.generate_uuid()
        self._initialize_objs()

    def _get_random_db_fields(self, obj_cls=None):
        obj_cls = obj_cls or self._test_class
        return obj_cls.modify_fields_to_db(
            self.get_random_object_fields(obj_cls))

    def _update_network(self, network_id, qos_policy_id):
        data = {'network': {'qos_policy_id': qos_policy_id}}
        return self._update('networks', network_id, data,
                            as_admin=True)['network']

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
        kwargs = {enet_api.EXTERNAL: True}
        network = self._make_network(self.fmt, 'fip_net', True, as_admin=True,
                                     **kwargs)['network']
        router_gw_port = self._create_one_port(random.randint(10**6, 10**7),
                                               network['id'])
        router = router_obj.Router(self.ctx, id=uuidutils.generate_uuid(),
                                   gw_port_id=router_gw_port.id)
        router.create()
        return router, network

    @db_api.CONTEXT_WRITER
    def _update_router_qos(self, context, router_id, qos_policy_id,
                           attach=True):
        # NOTE(ralonsoh): router QoS policy is not yet implemented in Router
        # OVO. Once we have this feature, this method can be removed.
        qos = policy_obj.QosPolicy.get_policy_obj(context, qos_policy_id)
        if attach:
            qos.attach_router(router_id)
        else:
            qos.detach_router(router_id)

    def _get_router(self, router_id):
        return self.qos_driver._plugin_l3.get_router(self.ctx, router_id)

    def _initialize_objs(self):
        self.qos_policies = []
        self.ports = []
        self.networks = []
        self.fips = []
        self.router_fips, self.fips_network = self._create_one_router()
        self.fips_ports = []
        self.routers = []
        self.router_networks = []
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

            self.fips_ports.append(self._create_one_port(
                1000 + net_idx, self.fips_network['id']))
            fip_ip = str(netaddr.IPAddress(fip_cidr.ip + net_idx + 1))
            fip = router_obj.FloatingIP(
                self.ctx, id=uuidutils.generate_uuid(),
                project_id=self.project_id, floating_ip_address=fip_ip,
                floating_network_id=self.fips_network['id'],
                floating_port_id=self.fips_ports[-1].id)
            fip.create()
            self.fips.append(fip)

            network = self._make_network(
                self.fmt, f'net_{net_idx}', True,
                as_admin=True)['network']
            self.networks.append(network)

            for port_idx in range(3):
                self.ports.append(
                    self._create_one_port(net_idx * 16 + port_idx,
                                          network['id']))

            router, router_network = self._create_one_router()
            self.routers.append(router)
            self.router_networks.append(router_network)

    @mock.patch.object(qos_extension.LOG, 'warning')
    @mock.patch.object(rule_obj, 'get_rules')
    def test__qos_rules(self, mock_get_rules, mock_warning):
        rules = [
            rule_obj.QosBandwidthLimitRule(
                direction=constants.EGRESS_DIRECTION, **QOS_RULE_BW_1),
            rule_obj.QosBandwidthLimitRule(
                direction=constants.INGRESS_DIRECTION, **QOS_RULE_BW_2),
            rule_obj.QosDscpMarkingRule(**QOS_RULE_DSCP_1),
            rule_obj.QosMinimumBandwidthRule(
                direction=constants.EGRESS_DIRECTION, **QOS_RULE_MINBW_1),
            rule_obj.QosMinimumBandwidthRule(
                direction=constants.INGRESS_DIRECTION, **QOS_RULE_MINBW_2),
        ]
        mock_get_rules.return_value = rules
        expected = {
            constants.EGRESS_DIRECTION: {
                qos_constants.RULE_TYPE_BANDWIDTH_LIMIT: QOS_RULE_BW_1,
                qos_constants.RULE_TYPE_DSCP_MARKING: QOS_RULE_DSCP_1,
                qos_constants.RULE_TYPE_MINIMUM_BANDWIDTH: QOS_RULE_MINBW_1},
            constants.INGRESS_DIRECTION: {
                qos_constants.RULE_TYPE_BANDWIDTH_LIMIT: QOS_RULE_BW_2}
        }
        self.assertEqual(expected, self.qos_driver._qos_rules(mock.ANY,
                                                              'policy_id1'))
        mock_warning.assert_called_once_with(
            'ML2/OVN QoS driver does not support minimum bandwidth rules '
            'enforcement with ingress direction')

    @mock.patch.object(rule_obj, 'get_rules')
    def test__qos_rules_no_rules(self, mock_get_rules):
        mock_get_rules.return_value = []
        expected = {constants.EGRESS_DIRECTION: {},
                    constants.INGRESS_DIRECTION: {}}
        self.assertEqual(expected,
                         self.qos_driver._qos_rules(mock.ANY, mock.ANY))

    def _test__ovn_qos_rule_ingress(self, fip_id=None, ip_address=None):
        if fip_id:
            external_ids = {ovn_const.OVN_FIP_EXT_ID_KEY: fip_id}
        else:
            external_ids = {ovn_const.OVN_PORT_EXT_ID_KEY: 'port_id'}
        direction = constants.INGRESS_DIRECTION
        rule = {qos_constants.RULE_TYPE_BANDWIDTH_LIMIT: QOS_RULE_BW_1}
        match = self.qos_driver._ovn_qos_rule_match(
            direction, 'port_id', ip_address, 'resident_port')
        priority = (qos_extension.OVN_QOS_FIP_RULE_PRIORITY if fip_id else
                    qos_extension.OVN_QOS_DEFAULT_RULE_PRIORITY)
        expected = {'burst': 100, 'rate': 200, 'direction': 'to-lport',
                    'match': match,
                    'priority': priority,
                    'switch': 'neutron-network_id',
                    'external_ids': external_ids}
        result = self.qos_driver._ovn_qos_rule(
            direction, rule, 'port_id', 'network_id', fip_id=fip_id,
            ip_address=ip_address, resident_port='resident_port')
        self.assertEqual(expected, result)

    def test__ovn_qos_rule_ingress(self):
        self._test__ovn_qos_rule_ingress()

    def test__ovn_qos_rule_ingress_fip(self):
        self._test__ovn_qos_rule_ingress(fip_id='fipid', ip_address='1.2.3.4')

    def _test__ovn_qos_rule_egress(self, fip_id=None, ip_address=None):
        if fip_id:
            external_ids = {ovn_const.OVN_FIP_EXT_ID_KEY: fip_id}
        else:
            external_ids = {ovn_const.OVN_PORT_EXT_ID_KEY: 'port_id'}
        direction = constants.EGRESS_DIRECTION
        rule = {qos_constants.RULE_TYPE_DSCP_MARKING: QOS_RULE_DSCP_1}
        match = self.qos_driver._ovn_qos_rule_match(
            direction, 'port_id', ip_address, 'resident_port')
        priority = (qos_extension.OVN_QOS_FIP_RULE_PRIORITY if fip_id else
                    qos_extension.OVN_QOS_DEFAULT_RULE_PRIORITY)
        expected = {'direction': 'from-lport', 'match': match,
                    'dscp': 16, 'switch': 'neutron-network_id',
                    'priority': priority, 'external_ids': external_ids}
        result = self.qos_driver._ovn_qos_rule(
            direction, rule, 'port_id', 'network_id', fip_id=fip_id,
            ip_address=ip_address, resident_port='resident_port')
        self.assertEqual(expected, result)

        rule = {qos_constants.RULE_TYPE_BANDWIDTH_LIMIT: QOS_RULE_BW_2,
                qos_constants.RULE_TYPE_DSCP_MARKING: QOS_RULE_DSCP_2}
        expected = {'direction': 'from-lport', 'match': match,
                    'rate': 300, 'dscp': 20, 'switch': 'neutron-network_id',
                    'priority': priority, 'external_ids': external_ids}
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
                         self.qos_driver.port_effective_qos_policy_id(port))

        port = {'qos_network_policy_id': 'qos1'}
        self.assertEqual(('qos1', 'network'),
                         self.qos_driver.port_effective_qos_policy_id(port))

        port = {'qos_policy_id': 'qos_port',
                'qos_network_policy_id': 'qos_network'}
        self.assertEqual(('qos_port', 'port'),
                         self.qos_driver.port_effective_qos_policy_id(port))

        port = {}
        self.assertEqual((None, None),
                         self.qos_driver.port_effective_qos_policy_id(port))

        port = {'qos_policy_id': None, 'qos_network_policy_id': None}
        self.assertEqual((None, None),
                         self.qos_driver.port_effective_qos_policy_id(port))

        port = {'qos_policy_id': 'qos1', 'device_owner': 'neutron:port'}
        self.assertEqual((None, None),
                         self.qos_driver.port_effective_qos_policy_id(port))

    def test_update_port(self):
        port = self.ports[0]
        original_port = self.ports[1]

        # Remove QoS policy
        original_port.qos_policy_id = self.qos_policies[0].id
        self.qos_driver.update_port(self.context, mock.ANY, port,
                                    original_port)
        self.mock_rules.assert_called_once_with(
            mock.ANY, mock.ANY, port.id, mock.ANY, port.network_id, None, None,
            lsp=None)

        # Change from port policy (qos_policy0) to network policy (qos_policy1)
        self.mock_rules.reset_mock()
        port.qos_network_policy_id = self.qos_policies[1].id
        self.qos_driver.update_port(self.context, mock.ANY, port,
                                    original_port)
        self.mock_rules.assert_called_once_with(
            mock.ANY, mock.ANY, port.id, port.network_id, mock.ANY,
            self.qos_policies[1].id, None, lsp=None)

        # No change (qos_policy0)
        self.mock_rules.reset_mock()
        port.qos_policy_id = self.qos_policies[0].id
        original_port.qos_policy_id = self.qos_policies[0].id
        self.qos_driver.update_port(self.context, mock.ANY, port,
                                    original_port)
        self.mock_rules.assert_not_called()

        # No change (no policy)
        self.mock_rules.reset_mock()
        port.qos_policy_id = None
        port.qos_network_policy_id = None
        original_port.qos_policy_id = None
        original_port.qos_network_policy_id = None
        self.qos_driver.update_port(self.context, mock.ANY, port,
                                    original_port)
        self.mock_rules.assert_not_called()

        # Reset (no policy)
        self.qos_driver.update_port(self.context, mock.ANY, port,
                                    original_port, reset=True)
        self.mock_rules.assert_called_once_with(
            mock.ANY, mock.ANY, port.id, port.network_id, mock.ANY, None, None,
            lsp=None)

        # Reset (qos_policy0, regardless of being the same a in the previous
        # state)
        self.mock_rules.reset_mock()
        port.qos_policy_id = self.qos_policies[0].id
        original_port.qos_policy_id = self.qos_policies[1].id
        self.qos_driver.update_port(self.context, mock.ANY, port,
                                    original_port, reset=True)
        self.mock_rules.assert_called_once_with(
            mock.ANY, mock.ANY, port.id, port.network_id, mock.ANY,
            self.qos_policies[0].id, None, lsp=None)

        # External port, OVN QoS extension does not apply.
        self.mock_rules.reset_mock()
        port.qos_policy_id = self.qos_policies[0].id
        port_obj.PortBinding(self.ctx, port_id=port.id, host='host',
                             profile={}, vif_type='',
                             vnic_type=portbindings_api.VNIC_DIRECT).create()
        # NOTE(ralonsoh): this OVO retrieval must include, in the port object,
        # the port binding register created.
        port = port_obj.Port.get_object(self.ctx, id=port.id)
        self.qos_driver.update_port(self.context, mock.ANY, port,
                                    original_port)
        self.mock_rules.assert_not_called()

    @ddt.data(constants.TYPE_VLAN, constants.TYPE_GENEVE)
    def test_delete_port(self, network_type):
        self.mock_rules.reset_mock()
        self.mock_lsp_get.return_value.execute.return_value = mock.Mock(
            external_ids={ovn_const.OVN_NETTYPE_EXT_ID_KEY: network_type})
        self.qos_driver.delete_port(self.context, mock.ANY, self.ports[1])

        # Assert that rules are deleted
        self.mock_rules.assert_called_once_with(
            mock.ANY, mock.ANY, self.ports[1].id, self.ports[1].network_id,
            network_type, None, None, lsp=None)

    def test_update_network(self):
        """Test update network (internal ports).

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
            self.networks[0] = self._update_network(self.networks[0]['id'],
                                                    qos_policy_id)
            original_network = {'qos_policy_id': self.qos_policies[0],
                                pnet_api.NETWORK_TYPE: mock.ANY,
                                }
            reviewed_port_ids, _, _ = self.qos_driver.update_network(
                self.context, mock.ANY, self.networks[0], original_network)
            self.assertEqual(reference_ports, reviewed_port_ids)
            calls = [mock.call(mock.ANY, mock.ANY, self.ports[0].id,
                               self.ports[0].network_id, self.tenant_type,
                               qos_policy_id, None)]
            self.mock_rules.assert_has_calls(calls)
            self.mock_rules.reset_mock()

    def test_update_external_network(self):
        """Test update external network (floating IPs and GW IPs).

        - fip0: qos_policy0
        - fip1: no QoS FIP policy (inherits from external network QoS)
        - router_fips: no QoS FIP policy (inherits from external network QoS)
        """
        network_policies = [(self.qos_policies[1].id,
                             {self.fips[1].id},
                             {self.router_fips.id}),
                            (None,
                             {self.fips[1].id},
                             {self.router_fips.id})]

        self.fips[0].qos_policy_id = self.qos_policies[0].id
        self.fips[0].update()
        for qos_policy_id, ref_fips, ref_routers in network_policies:
            self.fips_network = self._update_network(self.fips_network['id'],
                                                     qos_policy_id)
            original_network = {'qos_policy_id': self.qos_policies[0],
                                pnet_api.NETWORK_TYPE: mock.ANY,
                                }
            _, reviewed_fips_ids, reviewed_router_ids = (
                self.qos_driver.update_network(
                    self.context, mock.Mock(), self.fips_network,
                    original_network))
            self.assertEqual(ref_fips, reviewed_fips_ids)
            self.assertEqual(ref_routers, reviewed_router_ids)

    def test_update_network_no_policy_change(self):
        """Test update network if the QoS policy is the same.

        net1: [(1) from qos_policy0 to qos_policy0,
               (2) from no QoS policy to no QoS policy]
        """
        for qos_policy_id in (self.qos_policies[0].id, None):
            self.networks[0] = self._update_network(
                self.networks[0]['id'], qos_policy_id)
            original_network = {'qos_policy_id': qos_policy_id}
            port_ids, fip_ids, router_ids = self.qos_driver.update_network(
                self.context, mock.ANY, self.networks[0], original_network)
            self.assertEqual(set(), port_ids)
            self.assertEqual(set(), fip_ids)
            self.assertEqual(set(), router_ids)
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
            self.networks[0] = self._update_network(
                self.networks[0]['id'], qos_policy_id)
            original_network = {'qos_policy_id': self.qos_policies[0]}
            reviewed_port_ids, _, _ = self.qos_driver.update_network(
                self.context, mock.ANY, self.networks[0], original_network,
                reset=True)
            self.assertEqual(reference_ports, reviewed_port_ids)
            calls = [mock.call(mock.ANY, mock.ANY, self.ports[0].id,
                               self.ports[0].network_id, self.tenant_type,
                               qos_policy_id, None)]
            self.mock_rules.assert_has_calls(calls)
            self.mock_rules.reset_mock()

    def test_update_network_external_ports(self):
        """Test update network with external ports.

        - port10: no QoS port policy
        - port11: no QoS port policy but external
        - port12: qos_policy0
        """
        policies_ports = [(self.qos_policies[0].id, {self.ports[0].id})]
        self.ports[2].qos_policy_id = self.qos_policies[0].id
        self.ports[2].update()
        port_obj.PortBinding(self.ctx, port_id=self.ports[1].id, host='host',
                             profile={}, vif_type='',
                             vnic_type=portbindings_api.VNIC_DIRECT).create()
        with mock.patch.object(self.qos_driver._driver._nb_idl,
                               'get_lswitch_port') as mock_lsp:
            mock_lsp.side_effect = [
                mock.Mock(type=ovn_const.LSP_TYPE_LOCALNET),
                mock.Mock(type=ovn_const.LSP_TYPE_EXTERNAL)]
            for qos_policy_id, reference_ports in policies_ports:
                self.networks[0] = self._update_network(self.networks[0]['id'],
                                                        qos_policy_id)
                original_network = {'qos_policy_id': self.qos_policies[0]}
                reviewed_port_ids, _, _ = self.qos_driver.update_network(
                    self.context, mock.ANY, self.networks[0], original_network,
                    reset=True)
                self.assertEqual(reference_ports, reviewed_port_ids)
                calls = [mock.call(
                    mock.ANY, mock.ANY, self.ports[0].id,
                    self.ports[0].network_id, self.tenant_type, qos_policy_id,
                    None)]
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
        router1: qos_policy0
        router2: qos_policy1
        """
        self.ports[1].qos_policy_id = self.qos_policies[0].id
        self.ports[1].update()
        self.ports[2].qos_policy_id = self.qos_policies[1].id
        self.ports[2].update()
        self.ports[4].qos_policy_id = self.qos_policies[0].id
        self.ports[4].update()
        self.ports[5].qos_policy_id = self.qos_policies[1].id
        self.ports[5].update()
        self.networks[1] = self._update_network(
            self.networks[1]['id'], self.qos_policies[0].id)
        self.fips[0].qos_policy_id = self.qos_policies[0].id
        self.fips[0].update()
        self.fips[1].qos_policy_id = self.qos_policies[1].id
        self.fips[1].update()
        self._update_router_qos(self.ctx, self.routers[0].id,
                                self.qos_policies[0].id)
        self._update_router_qos(self.ctx, self.routers[1].id,
                                self.qos_policies[1].id)
        mock_qos_rules = mock.Mock()
        with mock.patch.object(self.qos_driver, '_qos_rules',
                               return_value=mock_qos_rules), \
                mock.patch.object(self.qos_driver, 'update_floatingip') as \
                mock_update_fip, \
                mock.patch.object(self.qos_driver, 'update_router') as \
                mock_update_router:
            self.qos_driver.update_policy(self.ctx, self.qos_policies[0])
        # Ports updated from "update_port": self.ports[1], self.ports[4]
        updated_ports = [self.ports[1], self.ports[4]]
        calls = [mock.call(mock.ANY, self.txn, port.id,
                           port.network_id, self.tenant_type,
                           self.qos_policies[0].id, mock_qos_rules, lsp=None)
                 for port in updated_ports]
        # Port updated from "update_network": self.ports[3]
        calls.append(mock.call(mock.ANY, self.txn, self.ports[3].id,
                               self.ports[3].network_id, self.tenant_type,
                               self.qos_policies[0].id, mock_qos_rules))

        # We can't ensure the call order because we are not enforcing any order
        # when retrieving the port and the network list.
        self.mock_rules.assert_has_calls(calls, any_order=True)
        with db_api.CONTEXT_READER.using(self.ctx):
            fip = self.qos_driver._plugin_l3.get_floatingip(self.ctx,
                                                            self.fips[0].id)
        mock_update_fip.assert_called_once_with(self.ctx, self.txn, fip)

        with db_api.CONTEXT_READER.using(self.ctx):
            router = self.qos_driver._plugin_l3.get_router(self.ctx,
                                                           self.routers[0].id)
        mock_update_router.assert_called_once_with(
            self.ctx, self.txn, router)

    def test_update_floatingip(self):
        # NOTE(ralonsoh): this rule will always apply:
        # - If the FIP is being deleted, "qos_del_ext_ids" is called;
        #   "qos_add" and "qos_del" won't.
        # - If the FIP is added or updated, "qos_del_ext_ids" won't be called
        #   and "qos_add" or "qos_del" will, depending on the rule directions.
        nb_idl = self.qos_driver._driver._nb_idl
        fip = self.fips[0]
        original_fip = self.fips[1]
        txn = mock.Mock()

        # Update FIP, no QoS policy nor port/router
        self.qos_driver.update_floatingip(self.context, txn, fip)
        nb_idl.qos_del_ext_ids.assert_called_once()
        nb_idl.qos_add.assert_not_called()
        nb_idl.qos_del.assert_not_called()
        nb_idl.reset_mock()

        # Attach a port and a router, not QoS policy
        fip.router_id = self.router_fips.id
        fip.fixed_port_id = self.fips_ports[0].id
        fip.update()
        self.qos_driver.update_floatingip(self.context, txn, fip)
        nb_idl.qos_del_ext_ids.assert_called_once()
        nb_idl.qos_add.assert_not_called()
        nb_idl.qos_del.assert_not_called()
        nb_idl.reset_mock()

        # Add a QoS policy
        fip.qos_policy_id = self.qos_policies[0].id
        fip.update()
        self.qos_driver.update_floatingip(self.context, txn, fip)
        nb_idl.qos_del_ext_ids.assert_not_called()
        # QoS DSCP rule has only egress direction, ingress one is deleted.
        # Check "OVNClientQosExtension.update_floatingip" and how the OVN QoS
        # rules are added (if there is a rule in this direction) or deleted.
        nb_idl.qos_add.assert_called_once()
        nb_idl.qos_del.assert_called_once()
        nb_idl.reset_mock()

        # Remove QoS
        fip.qos_policy_id = None
        fip.update()
        original_fip.qos_policy_id = self.qos_policies[0].id
        original_fip.update()
        self.qos_driver.update_floatingip(self.context, txn, fip)
        nb_idl.qos_del_ext_ids.assert_called_once()
        nb_idl.qos_add.assert_not_called()
        nb_idl.qos_del.assert_not_called()
        nb_idl.reset_mock()

        # Add network QoS policy
        fip.qos_network_policy_id = self.qos_policies[0].id
        fip.update()
        self.qos_driver.update_floatingip(self.context, txn, fip)
        nb_idl.qos_del_ext_ids.assert_not_called()
        nb_idl.qos_add.assert_called_once()
        nb_idl.qos_del.assert_called_once()
        nb_idl.reset_mock()

        # Add again another QoS policy
        fip.qos_policy_id = self.qos_policies[1].id
        fip.update()
        original_fip.qos_policy_id = None
        original_fip.update()
        self.qos_driver.update_floatingip(self.context, txn, fip)
        nb_idl.qos_del_ext_ids.assert_not_called()
        nb_idl.qos_add.assert_called_once()
        nb_idl.qos_del.assert_called_once()
        nb_idl.reset_mock()

        # Detach the port and the router
        fip.router_id = None
        fip.fixed_port_id = None
        fip.update()
        original_fip.router_id = self.router_fips.id
        original_fip.fixed_port_id = self.fips_ports[0].id
        original_fip.qos_policy_id = self.qos_policies[1].id
        original_fip.update()
        self.qos_driver.update_floatingip(self.context, txn, fip)
        nb_idl.qos_del_ext_ids.assert_called_once()
        nb_idl.qos_add.assert_not_called()
        nb_idl.qos_del.assert_not_called()
        nb_idl.reset_mock()

        # Force reset (delete any QoS)
        fip_dict = {'floating_network_id': fip.floating_network_id,
                    'id': fip.id}
        self.qos_driver.update_floatingip(self.context, txn, fip_dict)
        nb_idl.qos_del_ext_ids.assert_called_once()
        nb_idl.qos_add.assert_not_called()
        nb_idl.qos_del.assert_not_called()

    def test_update_router(self):
        nb_idl = self.qos_driver._driver._nb_idl
        txn = mock.Mock()

        # Update router, no QoS policy set.
        router = self._get_router(self.routers[0].id)
        self.qos_driver.update_router(self.context, txn, router)
        nb_idl.qos_add.assert_not_called()
        self.assertEqual(2, nb_idl.qos_del.call_count)
        nb_idl.reset_mock()

        # Add QoS policy.
        self._update_router_qos(self.ctx, router['id'],
                                self.qos_policies[0].id)
        router = self._get_router(self.routers[0].id)
        self.qos_driver.update_router(self.context, txn, router)
        nb_idl.qos_add.assert_called_once()
        nb_idl.qos_del.assert_called_once()
        nb_idl.reset_mock()

        # Remove QoS
        self._update_router_qos(self.ctx, router['id'],
                                self.qos_policies[0].id, attach=False)
        router = self._get_router(self.routers[0].id)
        self.qos_driver.update_router(self.context, txn, router)
        nb_idl.qos_add.assert_not_called()
        self.assertEqual(2, nb_idl.qos_del.call_count)
        nb_idl.reset_mock()

        # Add network QoS policy
        ext_net = self.router_networks[0]
        self.networks[1] = self._update_network(ext_net['id'],
                                                self.qos_policies[1].id)
        router = self._get_router(self.routers[0].id)
        self.qos_driver.update_router(self.context, txn, router)
        nb_idl.qos_add.assert_called_once()
        nb_idl.qos_del.assert_called_once()
        nb_idl.reset_mock()
