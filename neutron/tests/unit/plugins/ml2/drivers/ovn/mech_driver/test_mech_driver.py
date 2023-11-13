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

import abc
import collections
import copy
import datetime
import shlex
from unittest import mock
import uuid

import netaddr
from neutron_lib.api.definitions import availability_zone as az_def
from neutron_lib.api.definitions import external_net
from neutron_lib.api.definitions import extra_dhcp_opt as edo_ext
from neutron_lib.api.definitions import portbindings
from neutron_lib.api.definitions import provider_net as pnet
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants as const
from neutron_lib import context
from neutron_lib import exceptions as n_exc
from neutron_lib.placement import utils as place_utils
from neutron_lib.plugins import directory
from neutron_lib.plugins import utils as p_utils
from neutron_lib.tests import tools
from neutron_lib.utils import net as n_net
from oslo_concurrency import processutils
from oslo_config import cfg
from oslo_db import exception as os_db_exc
from oslo_serialization import jsonutils
from oslo_utils import timeutils
from oslo_utils import uuidutils
from ovsdbapp.backend.ovs_idl import idlutils
from webob import exc

from neutron.common import config
from neutron.common.ovn import acl as ovn_acl
from neutron.common.ovn import constants as ovn_const
from neutron.common.ovn import exceptions as ovn_exceptions
from neutron.common.ovn import hash_ring_manager
from neutron.common.ovn import utils as ovn_utils
from neutron.conf.plugins.ml2.drivers.ovn import ovn_conf
from neutron.db import db_base_plugin_v2
from neutron.db import ovn_revision_numbers_db
from neutron.db import provisioning_blocks
from neutron.db import securitygroups_db
from neutron.db import segments_db
from neutron.plugins.ml2.drivers.ovn.agent import neutron_agent
from neutron.plugins.ml2.drivers.ovn.mech_driver import mech_driver
from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb import impl_idl_ovn
from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb import ovn_client
from neutron.plugins.ml2.drivers import type_geneve  # noqa
from neutron.services.revisions import revision_plugin
from neutron.tests.unit.extensions import test_segment
from neutron.tests.unit import fake_resources as fakes
from neutron.tests.unit.plugins.ml2 import _test_mech_agent as test_mech_agent
from neutron.tests.unit.plugins.ml2 import test_ext_portsecurity
from neutron.tests.unit.plugins.ml2 import test_plugin
from neutron.tests.unit.plugins.ml2 import test_security_group


OVN_PROFILE = ovn_const.OVN_PORT_BINDING_PROFILE
CLASS_PLACEMENT_REPORT = ('neutron.services.placement_report.plugin.'
                          'PlacementReportPlugin')

OvnRevNumberRow = collections.namedtuple(
    'OvnRevNumberRow', ['created_at'])


class MechDriverSetupBase(abc.ABC):
    def setUp(self):
        config.register_common_config_options()
        super().setUp()
        mm = directory.get_plugin().mechanism_manager
        self.mech_driver = mm.mech_drivers['ovn'].obj
        self.mech_driver.nb_ovn = fakes.FakeOvsdbNbOvnIdl()
        self.mech_driver.sb_ovn = fakes.FakeOvsdbSbOvnIdl()
        self.mech_driver._post_fork_event.set()
        self.mech_driver._ovn_client._qos_driver = mock.Mock()
        neutron_agent.AgentCache(self.mech_driver)
        # Because AgentCache is a singleton and we get a new mech_driver each
        # setUp(), override the AgentCache driver.
        neutron_agent.AgentCache().driver = self.mech_driver
        agent1 = self._add_agent('agent1')
        neutron_agent.AgentCache().get_agents = mock.Mock()
        neutron_agent.AgentCache().get_agents.return_value = [agent1]
        self.mock_vp_parents = mock.patch.object(
            ovn_utils, 'get_virtual_port_parents', return_value=None).start()

    def _add_chassis(self, nb_cfg, name=None):
        chassis_private = mock.Mock()
        chassis_private.nb_cfg = nb_cfg
        chassis_private.uuid = uuid.uuid4()
        chassis_private.name = name if name else str(uuid.uuid4())
        return chassis_private

    def _add_chassis_agent(self, nb_cfg, agent_type, chassis_private=None):
        chassis_private = chassis_private or self._add_chassis(nb_cfg)
        if hasattr(chassis_private, 'nb_cfg_timestamp') and isinstance(
                chassis_private.nb_cfg_timestamp, mock.Mock):
            del chassis_private.nb_cfg_timestamp
        chassis_private.external_ids = {}
        chassis_private.other_config = {}
        if agent_type == ovn_const.OVN_METADATA_AGENT:
            chassis_private.external_ids.update({
                ovn_const.OVN_AGENT_METADATA_SB_CFG_KEY: nb_cfg,
                ovn_const.OVN_AGENT_METADATA_ID_KEY: str(uuid.uuid4())})
        chassis_private.chassis = [chassis_private]
        return neutron_agent.AgentCache().update(agent_type, chassis_private)

    def _add_agent(self, name, nb_cfg_offset=0):
        nb_cfg = 5
        self.mech_driver.nb_ovn.nb_global.nb_cfg = nb_cfg + nb_cfg_offset
        chassis = self._add_chassis(nb_cfg, name=name)
        return self._add_chassis_agent(
            nb_cfg, ovn_const.OVN_CONTROLLER_AGENT, chassis)


class TestOVNMechanismDriverBase(MechDriverSetupBase,
                                 test_plugin.Ml2PluginV2TestCase):

    _mechanism_drivers = ['logger', 'ovn']
    _extension_drivers = ['port_security', 'dns']

    def setUp(self):
        cfg.CONF.set_override('extension_drivers',
                              self._extension_drivers,
                              group='ml2')
        cfg.CONF.set_override('tenant_network_types',
                              ['geneve'],
                              group='ml2')
        cfg.CONF.set_override('vni_ranges',
                              ['1:65536'],
                              group='ml2_type_geneve')
        # ensure viable minimum is set for OVN's Geneve
        cfg.CONF.set_override('max_header_size', 38,
                              group='ml2_type_geneve')
        ovn_conf.register_opts()
        ovn_conf.cfg.CONF.set_override('ovn_metadata_enabled', False,
                                       group='ovn')
        ovn_conf.cfg.CONF.set_override('dns_servers', ['8.8.8.8'],
                                       group='ovn')
        # Need to register here for 'vlan_transparent' config before
        # setting up test_plugin
        config.register_common_config_options()
        cfg.CONF.set_override('vlan_transparent', True)
        cfg.CONF.set_override('ovsdb_connection_timeout', 30, group='ovn')
        mock.patch.object(impl_idl_ovn.Backend, 'schema_helper').start()
        super().setUp()

        self.nb_ovn = self.mech_driver.nb_ovn
        self.sb_ovn = self.mech_driver.sb_ovn
        self.rp_ns = self.mech_driver.resource_provider_uuid5_namespace
        self.placement_ext = self.mech_driver._ovn_client.placement_extension
        self.placement_ext._reset(self.placement_ext._driver)

        self.fake_subnet = fakes.FakeSubnet.create_one_subnet().info()

        self.fake_sg_rule = \
            fakes.FakeSecurityGroupRule.create_one_security_group_rule().info()
        self.fake_sg = fakes.FakeSecurityGroup.create_one_security_group(
            attrs={'security_group_rules': [self.fake_sg_rule]}
        ).info()

        self.sg_cache = {self.fake_sg['id']: self.fake_sg}
        self.subnet_cache = {self.fake_subnet['id']: self.fake_subnet}
        mock.patch.object(ovn_acl, '_acl_columns_name_severity_supported',
                          return_value=True).start()
        revision_plugin.RevisionPlugin()
        p = mock.patch.object(ovn_utils, 'get_revision_number', return_value=1)
        p.start()
        self.addCleanup(p.stop)
        p = mock.patch.object(ovn_revision_numbers_db, 'bump_revision')
        p.start()
        self.addCleanup(p.stop)

    def get_additional_service_plugins(self):
        p = super().get_additional_service_plugins()
        p.update({'placement_report': CLASS_PLACEMENT_REPORT})
        return p

    def test_delete_mac_binding_entries(self):
        self.config(group='ovn', ovn_sb_private_key=None)
        expected = ('ovsdb-client transact tcp:127.0.0.1:6642 --timeout 30 '
                   '\'["OVN_Southbound", {"op": "delete", "table": '
                   '"MAC_Binding", "where": [["ip", "==", "1.1.1.1"]]}]\'')
        with mock.patch.object(processutils, 'execute') as mock_execute:
            self.mech_driver.delete_mac_binding_entries('1.1.1.1')
            mock_execute.assert_called_once_with(*shlex.split(expected),
                    log_errors=processutils.LOG_FINAL_ERROR)

    def test_delete_mac_binding_entries_ssl(self):
        self.config(group='ovn', ovn_sb_private_key='pk')
        self.config(group='ovn', ovn_sb_certificate='cert')
        self.config(group='ovn', ovn_sb_ca_cert='ca')
        expected = ('ovsdb-client transact tcp:127.0.0.1:6642 --timeout 30 '
                   '-p pk -c cert -C ca '
                   '\'["OVN_Southbound", {"op": "delete", "table": '
                   '"MAC_Binding", "where": [["ip", "==", "1.1.1.1"]]}]\'')
        with mock.patch.object(processutils, 'execute') as mock_execute:
            self.mech_driver.delete_mac_binding_entries('1.1.1.1')
            mock_execute.assert_called_once_with(*shlex.split(expected),
                    log_errors=processutils.LOG_FINAL_ERROR)


class TestOVNMechanismDriver(TestOVNMechanismDriverBase):
    def test__get_max_tunid_no_key_set(self):
        self.mech_driver.nb_ovn.nb_global.options.get.return_value = None
        self.assertIsNone(self.mech_driver._get_max_tunid())

    def test__get_max_tunid_wrong_key_value(self):
        self.mech_driver.nb_ovn.nb_global.options.get.return_value = '11wrong'
        self.assertIsNone(self.mech_driver._get_max_tunid())

    def test__get_max_tunid_key_set(self):
        self.mech_driver.nb_ovn.nb_global.options.get.return_value = '100'
        self.assertEqual(100, self.mech_driver._get_max_tunid())

    def _test__validate_network_segments_id_succeed(self, val):
        segment = {
            "network_type": const.TYPE_VXLAN,
            "segmentation_id": val,
            "physical_network": "physnet1",
        }
        self.mech_driver.nb_ovn.nb_global.options.get.return_value = '200'
        self.mech_driver._validate_network_segments([segment])

    def test__validate_network_segments_id_below_max_limit(self):
        self._test__validate_network_segments_id_succeed(100)

    def test__validate_network_segments_id_eq_max_limit(self):
        self._test__validate_network_segments_id_succeed(200)

    def test__validate_network_segments_id_above_max_limit(self):
        self.assertRaises(
            n_exc.InvalidInput,
            self._test__validate_network_segments_id_succeed, 300)

    @mock.patch.object(ovn_revision_numbers_db, 'bump_revision')
    def _test__create_security_group(
            self, stateful, stateless_supported, mock_bump):
        self.fake_sg["stateful"] = stateful
        with mock.patch.object(self.mech_driver._ovn_client,
                               'is_allow_stateless_supported',
                               return_value=stateless_supported):
            self.mech_driver._create_security_group(
                resources.SECURITY_GROUP, events.AFTER_CREATE, {},
                payload=events.DBEventPayload(
                    self.context, states=(self.fake_sg,)))
        external_ids = {ovn_const.OVN_SG_EXT_ID_KEY: self.fake_sg['id']}
        pg_name = ovn_utils.ovn_port_group_name(self.fake_sg['id'])

        self.nb_ovn.pg_add.assert_called_once_with(
            name=pg_name, acls=[], external_ids=external_ids)

        if stateful or not stateless_supported:
            expected = ovn_const.ACL_ACTION_ALLOW_RELATED
        else:
            expected = ovn_const.ACL_ACTION_ALLOW_STATELESS
        for c in self.nb_ovn.pg_acl_add.call_args_list:
            self.assertEqual(expected, c[1]["action"])

        mock_bump.assert_called_once_with(
            mock.ANY, self.fake_sg, ovn_const.TYPE_SECURITY_GROUPS)

    def test__create_security_group_stateful_supported(self):
        self._test__create_security_group(True, True)

    def test__create_security_group_stateful_not_supported(self):
        self._test__create_security_group(True, False)

    def test__create_security_group_stateless_supported(self):
        self._test__create_security_group(False, True)

    def test__create_security_group_stateless_not_supported(self):
        self._test__create_security_group(False, False)

    @mock.patch.object(ovn_revision_numbers_db, 'delete_revision')
    def test__delete_security_group(self, mock_del_rev):
        self.mech_driver._delete_security_group(
            resources.SECURITY_GROUP, events.AFTER_CREATE, {},
            payload=events.DBEventPayload(
                self.context, states=(self.fake_sg,),
                resource_id=self.fake_sg['id']))

        pg_name = ovn_utils.ovn_port_group_name(self.fake_sg['id'])

        self.nb_ovn.pg_del.assert_called_once_with(
            if_exists=True, name=pg_name)

        mock_del_rev.assert_called_once_with(
            mock.ANY, self.fake_sg['id'], ovn_const.TYPE_SECURITY_GROUPS)

    @mock.patch.object(ovn_revision_numbers_db, 'bump_revision')
    def test__process_sg_rule_notifications_sgr_create(self, mock_bump):
        with mock.patch.object(
                self.mech_driver,
                '_sg_has_rules_with_same_normalized_cidr') as has_same_rules, \
                mock.patch.object(
                    ovn_acl, 'update_acls_for_security_group') as ovn_acl_up:
            rule = {'security_group_id': 'sg_id'}
            self.mech_driver._process_sg_rule_notification(
                resources.SECURITY_GROUP_RULE, events.AFTER_CREATE, {},
                payload=events.DBEventPayload(
                    self.context, states=(rule,)))
            has_same_rules.assert_not_called()
            ovn_acl_up.assert_called_once_with(
                mock.ANY, mock.ANY, mock.ANY,
                'sg_id', rule, is_add_acl=True, stateless_supported=False)
            mock_bump.assert_called_once_with(
                mock.ANY, rule, ovn_const.TYPE_SECURITY_GROUP_RULES)

    @mock.patch.object(ovn_revision_numbers_db, 'bump_revision')
    def test__process_sg_rule_notifications_sgr_create_with_remote_ip_prefix(
            self, mock_bump):
        with mock.patch.object(
                self.mech_driver,
                '_sg_has_rules_with_same_normalized_cidr') as has_same_rules, \
                mock.patch.object(
                    ovn_acl, 'update_acls_for_security_group') as ovn_acl_up:
            rule = {'security_group_id': 'sg_id',
                    'remote_ip_prefix': '1.0.0.0/24'}
            self.mech_driver._process_sg_rule_notification(
                resources.SECURITY_GROUP_RULE, events.AFTER_CREATE, {},
                payload=events.DBEventPayload(
                    self.context, states=(rule,)))
            has_same_rules.assert_not_called()
            ovn_acl_up.assert_called_once_with(
                mock.ANY, mock.ANY, mock.ANY,
                'sg_id', rule, is_add_acl=True, stateless_supported=False)
            mock_bump.assert_called_once_with(
                mock.ANY, rule, ovn_const.TYPE_SECURITY_GROUP_RULES)

    @mock.patch.object(ovn_revision_numbers_db, 'delete_revision')
    def test_process_sg_rule_notifications_sgr_delete(self, mock_delrev):
        rule = {'id': 'sgr_id', 'security_group_id': 'sg_id'}
        with mock.patch.object(ovn_acl, 'update_acls_for_security_group') \
                as ovn_acl_up, \
                mock.patch.object(securitygroups_db.SecurityGroupDbMixin,
                                  'get_security_group_rule',
                                  return_value=rule):
            self.mech_driver._process_sg_rule_notification(
                resources.SECURITY_GROUP_RULE, events.BEFORE_DELETE, {},
                payload=events.DBEventPayload(
                    self.context, states=(rule,)))
            ovn_acl_up.assert_called_once_with(
                mock.ANY, mock.ANY, mock.ANY,
                'sg_id', rule, is_add_acl=False, stateless_supported=False)
            mock_delrev.assert_called_once_with(
                mock.ANY, rule['id'], ovn_const.TYPE_SECURITY_GROUP_RULES)

    def test__sg_has_rules_with_same_normalized_cidr(self):
        scenarios = [
            ({'id': 'rule-id', 'security_group_id': 'sec-group-uuid',
              'remote_ip_prefix': '10.10.10.175/26',
              'normalized_cidr': str(
                  netaddr.IPNetwork('10.10.10.175/26').cidr),
              'protocol': 'tcp'}, False),
            ({'id': 'rule-id', 'security_group_id': 'sec-group-uuid',
              'remote_ip_prefix': '10.10.10.175/26',
              'normalized_cidr': str(
                  netaddr.IPNetwork('10.10.10.175/26').cidr),
              'protocol': 'udp'}, False),
            ({'id': 'rule-id', 'security_group_id': 'sec-group-uuid',
              'remote_ip_prefix': '10.10.10.175/26',
              'normalized_cidr': str(
                  netaddr.IPNetwork('10.10.10.175/26').cidr),
              'protocol': 'tcp'}, False),
            ({'id': 'rule-id', 'security_group_id': 'sec-group-uuid',
              'remote_ip_prefix': '10.10.10.175/26',
              'normalized_cidr': str(
                  netaddr.IPNetwork('10.10.10.175/26').cidr),
              'protocol': 'tcp',
              'port_range_min': '2000', 'port_range_max': '2100'}, False),
            ({'id': 'rule-id', 'security_group_id': 'sec-group-uuid',
              'remote_ip_prefix': '192.168.0.0/24',
              'normalized_cidr': str(netaddr.IPNetwork('192.168.0.0/24').cidr),
              'protocol': 'tcp',
              'port_range_min': '2000', 'port_range_max': '3000',
              'direction': 'ingress'}, False),
            ({'id': 'rule-id', 'security_group_id': 'sec-group-uuid',
              'remote_ip_prefix': '10.10.10.175/26',
              'normalized_cidr': str(
                  netaddr.IPNetwork('10.10.10.175/26').cidr),
              'protocol': 'tcp',
              'port_range_min': '2000', 'port_range_max': '3000',
              'direction': 'egress'}, False),
            ({'id': 'rule-id', 'security_group_id': 'sec-group-uuid',
              'remote_ip_prefix': '10.10.10.175/26',
              'normalized_cidr': str(
                  netaddr.IPNetwork('10.10.10.175/26').cidr),
              'protocol': 'tcp',
              'port_range_min': '2000', 'port_range_max': '3000',
              'direction': 'ingress'}, True)]

        rules = [
            {
                'id': 'rule-1-id',
                'protocol': 'udp',
            }, {
                'id': 'rule-2-id',
                'remote_ip_prefix': '10.10.10.128/26',
                'normalized_cidr': str(
                    netaddr.IPNetwork('10.10.10.128/26').cidr),
                'protocol': 'tcp',
                'port_range_min': '2000',
                'port_range_max': '3000',
                'direction': 'ingress'
            }]

        with mock.patch.object(securitygroups_db.SecurityGroupDbMixin,
                               'get_security_group_rules',
                               return_value=rules):
            for rule, expected_result in scenarios:
                self.assertEqual(
                    expected_result,
                    self.mech_driver._sg_has_rules_with_same_normalized_cidr(
                        rule))

    def test_port_invalid_binding_profile(self):
        invalid_binding_profiles = [
            {'tag': 0,
             'parent_name': 'fakename'},
            {'tag': 1024},
            {'tag': 1024, 'parent_name': 1024},
            {'parent_name': 'test'},
            {'tag': 'test'},
            {'vtep-physical-switch': 'psw1'},
            {'vtep-logical-switch': 'lsw1'},
            {'vtep-physical-switch': 'psw1', 'vtep-logical-switch': 1234},
            {'vtep-physical-switch': 1234, 'vtep-logical-switch': 'lsw1'},
            {'vtep-physical-switch': 'psw1', 'vtep-logical-switch': 'lsw1',
             'tag': 1024},
            {'vtep-physical-switch': 'psw1', 'vtep-logical-switch': 'lsw1',
             'parent_name': 'fakename'},
            {'vtep-physical-switch': 'psw1', 'vtep-logical-switch': 'lsw1',
             'tag': 1024, 'parent_name': 'fakename'},
        ]
        with self.network() as net1:
            with self.subnet(network=net1) as subnet1:
                # succeed without binding:profile
                with self.port(subnet=subnet1):
                    pass
                # fail with invalid binding profiles
                for invalid_profile in invalid_binding_profiles:
                    try:
                        kwargs = {ovn_const.OVN_PORT_BINDING_PROFILE:
                                  invalid_profile}
                        with self.port(
                                subnet=subnet1,
                                expected_res_status=403,
                                arg_list=(
                                ovn_const.OVN_PORT_BINDING_PROFILE,),
                                **kwargs):
                            pass
                    except exc.HTTPClientError:
                        pass

    def test__validate_ignored_port_update_from_fip_port(self):
        p = {'id': 'id', 'device_owner': 'test'}
        ori_p = {'id': 'id', 'device_owner': const.DEVICE_OWNER_FLOATINGIP}
        self.assertRaises(mech_driver.OVNPortUpdateError,
                          self.mech_driver._validate_ignored_port,
                          p, ori_p)

    def test__validate_ignored_port_update_to_fip_port(self):
        p = {'id': 'id', 'device_owner': const.DEVICE_OWNER_FLOATINGIP}
        ori_p = {'id': 'port-id', 'device_owner': 'test'}
        self.assertRaises(mech_driver.OVNPortUpdateError,
                          self.mech_driver._validate_ignored_port,
                          p, ori_p)

    def test__validate_port_extra_dhcp_opts(self):
        opt = {'opt_name': 'bootfile-name',
               'opt_value': 'homer_simpson.bin',
               'ip_version': 4}
        port = {edo_ext.EXTRADHCPOPTS: [opt], 'id': 'fake-port'}
        self.assertIsNone(
            self.mech_driver._validate_port_extra_dhcp_opts(port))

    @mock.patch.object(mech_driver.LOG, 'info')
    def test__validate_port_extra_dhcp_opts_invalid(self, mock_log):
        port_id = 'fake-port'
        opt = {'opt_name': 'not-valid',
               'opt_value': 'spongebob squarepants',
               'ip_version': 4}
        port = {edo_ext.EXTRADHCPOPTS: [opt], 'id': port_id}
        self.mech_driver._validate_port_extra_dhcp_opts(port)
        # Assert the log message contained the invalid DHCP options
        expected_call = mock.call(
            mock.ANY, {'port_id': port_id, 'ipv4_opts': 'not-valid',
                       'ipv6_opts': ''})
        mock_log.assert_has_calls([expected_call])

    @mock.patch.object(mech_driver.LOG, 'info')
    def test_create_port_invalid_extra_dhcp_opts(self, mock_log):
        extra_dhcp_opts = {
            'extra_dhcp_opts': [{'ip_version': 4, 'opt_name': 'banana',
                                 'opt_value': 'banana'},
                                {'ip_version': 6, 'opt_name': 'orange',
                                 'opt_value': 'orange'}]
        }
        with self.network() as n:
            with self.subnet(n):
                res = self._create_port(self.fmt, n['network']['id'],
                                  arg_list=('extra_dhcp_opts',),
                                  **extra_dhcp_opts)
                port_id = self.deserialize(self.fmt, res)['port']['id']
                # Assert the log message contained the invalid DHCP options
                expected_call = mock.call(
                    mock.ANY, {'port_id': port_id, 'ipv4_opts': 'banana',
                               'ipv6_opts': 'orange'})
                mock_log.assert_has_calls([expected_call])

    @mock.patch.object(mech_driver.LOG, 'info')
    def test_update_port_invalid_extra_dhcp_opts(self, mock_log):
        data = {
            'port': {'extra_dhcp_opts': [{'ip_version': 4, 'opt_name': 'apple',
                                         'opt_value': 'apple'},
                                         {'ip_version': 6, 'opt_name': 'grape',
                                         'opt_value': 'grape'}]}}
        with self.network() as net:
            with self.subnet(network=net) as subnet:
                with self.port(subnet=subnet) as port:
                    port_id = port['port']['id']
                    self._update('ports', port_id, data)

                    # Assert the log message contained the invalid DHCP options
                    expected_call = mock.call(
                        mock.ANY, {'port_id': port_id, 'ipv4_opts': 'apple',
                                   'ipv6_opts': 'grape'})
                    mock_log.assert_has_calls([expected_call])

    def test_create_and_update_ignored_fip_port(self):
        with self.network() as net1:
            with self.subnet(network=net1) as subnet1:
                with self.port(
                        subnet=subnet1,
                        is_admin=True,
                        device_owner=const.DEVICE_OWNER_FLOATINGIP) as port:
                    self.nb_ovn.create_lswitch_port.assert_not_called()
                    data = {'port': {'name': 'new'}}
                    req = self.new_update_request('ports', data,
                                                  port['port']['id'])
                    res = req.get_response(self.api)
                    self.assertEqual(exc.HTTPOk.code, res.status_int)
                    self.nb_ovn.set_lswitch_port.assert_not_called()

    def test_update_ignored_port_from_fip_device_owner(self):
        with self.network() as net1:
            with self.subnet(network=net1) as subnet1:
                with self.port(
                        subnet=subnet1,
                        is_admin=True,
                        device_owner=const.DEVICE_OWNER_FLOATINGIP) as port:
                    self.nb_ovn.create_lswitch_port.assert_not_called()
                    data = {'port': {'device_owner': 'test'}}
                    req = self.new_update_request('ports', data,
                                                  port['port']['id'],
                                                  as_admin=True)
                    res = req.get_response(self.api)
                    self.assertEqual(exc.HTTPBadRequest.code, res.status_int)
                    msg = jsonutils.loads(res.body)['NeutronError']['message']
                    expect_msg = ('Bad port request: Updating device_owner for'
                                  ' port %s owned by network:floatingip is'
                                  ' not supported.' % port['port']['id'])
                    self.assertEqual(msg, expect_msg)
                    self.nb_ovn.set_lswitch_port.assert_not_called()

    def test_update_ignored_port_to_fip_device_owner(self):
        with self.network() as net1:
            with self.subnet(network=net1) as subnet1:
                with self.port(subnet=subnet1,
                               is_admin=True,
                               device_owner='test') as port:
                    self.assertEqual(
                        1, self.nb_ovn.create_lswitch_port.call_count)
                    data = {'port': {'device_owner':
                                     const.DEVICE_OWNER_FLOATINGIP}}
                    req = self.new_update_request('ports', data,
                                                  port['port']['id'],
                                                  as_admin=True)
                    res = req.get_response(self.api)
                    self.assertEqual(exc.HTTPBadRequest.code, res.status_int)
                    msg = jsonutils.loads(res.body)['NeutronError']['message']
                    expect_msg = ('Bad port request: Updating device_owner to'
                                  ' network:floatingip for port %s is'
                                  ' not supported.' % port['port']['id'])
                    self.assertEqual(msg, expect_msg)
                    self.nb_ovn.set_lswitch_port.assert_not_called()

    def test_create_port_security(self):
        kwargs = {'mac_address': '00:00:00:00:00:01',
                  'fixed_ips': [{'ip_address': '10.0.0.2'},
                                {'ip_address': '10.0.0.4'}]}
        with self.network() as net1:
            with self.subnet(network=net1) as subnet1:
                with self.port(subnet=subnet1,
                               is_admin=True,
                               arg_list=('mac_address', 'fixed_ips'),
                               **kwargs) as port:
                    self.assertTrue(self.nb_ovn.create_lswitch_port.called)
                    called_args_dict = (
                        (self.nb_ovn.create_lswitch_port
                         ).call_args_list[0][1])
                    self.assertEqual(['00:00:00:00:00:01 10.0.0.2 10.0.0.4'],
                                     called_args_dict.get('port_security'))

                    data = {'port': {'mac_address': '00:00:00:00:00:02'}}
                    req = self.new_update_request(
                        'ports',
                        data, port['port']['id'],
                        as_admin=True)
                    req.get_response(self.api)
                    self.assertTrue(self.nb_ovn.set_lswitch_port.called)
                    called_args_dict = (
                        (self.nb_ovn.set_lswitch_port
                         ).call_args_list[0][1])
                    self.assertEqual(['00:00:00:00:00:02 10.0.0.2 10.0.0.4'],
                                     called_args_dict.get('port_security'))

    def test_create_port_with_disabled_security(self):
        # NOTE(mjozefcz): Lets pretend this is nova port to not
        # be treated as VIP.
        kwargs = {'port_security_enabled': False,
                  'device_owner': 'compute:nova'}
        with self.network() as net1:
            with self.subnet(network=net1) as subnet1:
                with self.port(subnet=subnet1,
                               arg_list=('port_security_enabled',),
                               **kwargs) as port:
                    self.assertTrue(self.nb_ovn.create_lswitch_port.called)
                    called_args_dict = (
                        (self.nb_ovn.create_lswitch_port
                         ).call_args_list[0][1])
                    self.assertEqual([],
                                     called_args_dict.get('port_security'))

                    self.assertIn(ovn_const.UNKNOWN_ADDR,
                            called_args_dict.get('addresses'))
                    data = {'port': {'mac_address': '00:00:00:00:00:01'}}
                    req = self.new_update_request(
                        'ports',
                        data, port['port']['id'],
                        as_admin=True)
                    req.get_response(self.api)
                    self.assertTrue(self.nb_ovn.set_lswitch_port.called)
                    called_args_dict = (
                        (self.nb_ovn.set_lswitch_port
                         ).call_args_list[0][1])
                    self.assertEqual([],
                                     called_args_dict.get('port_security'))
                    self.assertIn(ovn_const.UNKNOWN_ADDR,
                            called_args_dict.get('addresses'))

                    # Enable port security
                    data = {'port': {'port_security_enabled': 'True'}}
                    req = self.new_update_request(
                        'ports',
                        data, port['port']['id'])
                    req.get_response(self.api)
                    called_args_dict = (
                        (self.nb_ovn.set_lswitch_port
                         ).call_args_list[1][1])
                    self.assertEqual(2,
                                     self.nb_ovn.set_lswitch_port.call_count)
                    self.assertEqual(1, len(called_args_dict.get('addresses')))
                    self.assertNotIn(ovn_const.UNKNOWN_ADDR,
                                     called_args_dict.get('addresses'))

    def test_create_port_security_allowed_address_pairs(self):
        # NOTE(mjozefcz): Lets pretend this is nova port to not
        # be treated as VIP.
        kwargs = {'allowed_address_pairs':
                  [{"ip_address": "1.1.1.1"},
                   {"ip_address": "2.2.2.2",
                    "mac_address": "22:22:22:22:22:22"}],
                  'device_owner': 'compute:nova'}
        with self.network() as net1:
            with self.subnet(network=net1) as subnet1:
                with self.port(subnet=subnet1,
                               is_admin=True,
                               arg_list=('allowed_address_pairs',),
                               **kwargs) as port:
                    port_ip = port['port'].get('fixed_ips')[0]['ip_address']
                    self.assertTrue(self.nb_ovn.create_lswitch_port.called)
                    called_args_dict = (
                        (self.nb_ovn.create_lswitch_port
                         ).call_args_list[0][1])
                    self.assertEqual(
                        tools.UnorderedList(
                            ["22:22:22:22:22:22 2.2.2.2",
                             port['port']['mac_address'] + ' ' + port_ip +
                             ' ' + '1.1.1.1']),
                        called_args_dict.get('port_security'))
                    self.assertEqual(
                        tools.UnorderedList(
                            ["22:22:22:22:22:22",
                             port['port']['mac_address'] + ' ' + port_ip]),
                        called_args_dict.get('addresses'))

                    old_mac = port['port']['mac_address']

                    # we are updating only the port mac address. So the
                    # mac address of the allowed address pair ip 1.1.1.1
                    # will have old mac address
                    data = {'port': {'mac_address': '00:00:00:00:00:01'}}
                    req = self.new_update_request(
                        'ports',
                        data, port['port']['id'],
                        as_admin=True)
                    req.get_response(self.api)
                    self.assertTrue(self.nb_ovn.set_lswitch_port.called)
                    called_args_dict = (
                        (self.nb_ovn.set_lswitch_port
                         ).call_args_list[0][1])
                    self.assertEqual(tools.UnorderedList(
                        ["22:22:22:22:22:22 2.2.2.2",
                         "00:00:00:00:00:01 " + port_ip,
                         old_mac + " 1.1.1.1"]),
                        called_args_dict.get('port_security'))
                    self.assertEqual(
                        tools.UnorderedList(
                            ["22:22:22:22:22:22",
                             "00:00:00:00:00:01 " + port_ip,
                             old_mac]),
                        called_args_dict.get('addresses'))

    def test_create_port_ovn_octavia_vip(self):
        with self.network() as net1,\
                self.subnet(network=net1) as subnet1,\
                self.port(name=ovn_const.LB_VIP_PORT_PREFIX + 'foo',
                          subnet=subnet1):

            self.assertTrue(self.nb_ovn.create_lswitch_port.called)
            called_args_dict = (
                self.nb_ovn.create_lswitch_port.call_args_list[0][1])
            self.assertEqual([],
                             called_args_dict.get('addresses'))

    def _create_fake_network_context(self,
                                     network_type,
                                     physical_network=None,
                                     segmentation_id=None):
        network_attrs = {'provider:network_type': network_type,
                         'provider:physical_network': physical_network,
                         'provider:segmentation_id': segmentation_id}
        segment_attrs = {'network_type': network_type,
                         'physical_network': physical_network,
                         'segmentation_id': segmentation_id}
        fake_network = \
            fakes.FakeNetwork.create_one_network(attrs=network_attrs).info()
        fake_segments = \
            [fakes.FakeSegment.create_one_segment(attrs=segment_attrs).info()]
        return fakes.FakeNetworkContext(fake_network, fake_segments)

    def _create_fake_mp_network_context(self):
        network_type = 'flat'
        network_attrs = {'segments': []}
        fake_segments = []
        for physical_network in ['physnet1', 'physnet2']:
            network_attrs['segments'].append(
                {'provider:network_type': network_type,
                 'provider:physical_network': physical_network})
            segment_attrs = {'network_type': network_type,
                             'physical_network': physical_network}
            fake_segments.append(
                fakes.FakeSegment.create_one_segment(
                    attrs=segment_attrs).info())
        fake_network = \
            fakes.FakeNetwork.create_one_network(attrs=network_attrs).info()
        fake_network.pop('provider:network_type')
        fake_network.pop('provider:physical_network')
        fake_network.pop('provider:segmentation_id')
        return fakes.FakeNetworkContext(fake_network, fake_segments)

    def test_network_precommit(self):
        # Test supported network types.
        fake_network_context = self._create_fake_network_context('local')
        self.mech_driver.create_network_precommit(fake_network_context)

        fake_network_context = self._create_fake_network_context(
            'flat', physical_network='physnet')
        self.mech_driver.update_network_precommit(fake_network_context)

        fake_network_context = self._create_fake_network_context(
            'geneve', segmentation_id=10)
        self.mech_driver.create_network_precommit(fake_network_context)

        fake_network_context = self._create_fake_network_context(
            'vlan', physical_network='physnet', segmentation_id=11)
        self.mech_driver.update_network_precommit(fake_network_context)
        fake_mp_network_context = self._create_fake_mp_network_context()
        self.mech_driver.create_network_precommit(fake_mp_network_context)

        fake_network_context = self._create_fake_network_context(
            'vxlan', segmentation_id=12)
        self.mech_driver.create_network_precommit(fake_network_context)

        # Test unsupported network types.
        fake_network_context = self._create_fake_network_context(
            'gre', segmentation_id=13)
        self.assertRaises(n_exc.InvalidInput,
                          self.mech_driver.update_network_precommit,
                          fake_network_context)

    def _create_network_igmp_snoop(self, enabled):
        cfg.CONF.set_override('igmp_snooping_enable', enabled, group='OVS')
        nb_idl = self.mech_driver._ovn_client._nb_idl
        net = self._make_network(self.fmt, name='net1',
                                 admin_state_up=True)['network']
        value = 'true' if enabled else 'false'
        nb_idl.ls_add.assert_called_once_with(
            ovn_utils.ovn_name(net['id']), external_ids=mock.ANY,
            may_exist=True,
            other_config={ovn_const.MCAST_SNOOP: value,
                          ovn_const.MCAST_FLOOD_UNREGISTERED: 'false',
                          ovn_const.VLAN_PASSTHRU: 'false'})

    def test_create_network_igmp_snoop_enabled(self):
        self._create_network_igmp_snoop(enabled=True)

    def test_create_network_igmp_snoop_disabled(self):
        self._create_network_igmp_snoop(enabled=False)

    def _create_network_vlan_passthru(self, enabled):
        nb_idl = self.mech_driver._ovn_client._nb_idl
        net = self._make_network(self.fmt, name='net1',
                                 admin_state_up=True,
                                 vlan_transparent=enabled)['network']
        value = 'true' if enabled else 'false'
        nb_idl.ls_add.assert_called_once_with(
            ovn_utils.ovn_name(net['id']), external_ids=mock.ANY,
            may_exist=True,
            other_config={ovn_const.MCAST_SNOOP: 'false',
                          ovn_const.MCAST_FLOOD_UNREGISTERED: 'false',
                          ovn_const.VLAN_PASSTHRU: value})

    def test_create_network_vlan_passthru_enabled(self):
        self._create_network_vlan_passthru(enabled=True)

    def test_create_network_vlan_passthru_disabled(self):
        self._create_network_vlan_passthru(enabled=False)

    def test_create_network_create_localnet_port_tunnel_network_type(self):
        nb_idl = self.mech_driver._ovn_client._nb_idl
        self._make_network(self.fmt, name='net1',
                           admin_state_up=True)['network']
        # net1 is not physical network
        nb_idl.create_lswitch_port.assert_not_called()

    def test_create_network_create_localnet_port_physical_network_type(self):
        nb_idl = self.mech_driver._ovn_client._nb_idl
        net_arg = {pnet.NETWORK_TYPE: 'vlan',
                   pnet.PHYSICAL_NETWORK: 'physnet1',
                   pnet.SEGMENTATION_ID: '2'}
        net = self._make_network(self.fmt, 'net1', True,
                                 as_admin=True,
                                 arg_list=(pnet.NETWORK_TYPE,
                                           pnet.PHYSICAL_NETWORK,
                                           pnet.SEGMENTATION_ID,),
                                 **net_arg)['network']
        segments = segments_db.get_network_segments(
            self.context, net['id'])
        nb_idl.create_lswitch_port.assert_called_once_with(
            addresses=[ovn_const.UNKNOWN_ADDR],
            external_ids={},
            lport_name=ovn_utils.ovn_provnet_port_name(segments[0]['id']),
            lswitch_name=ovn_utils.ovn_name(net['id']),
            options={'network_name': 'physnet1',
                     ovn_const.LSP_OPTIONS_MCAST_FLOOD_REPORTS: 'true',
                     ovn_const.LSP_OPTIONS_MCAST_FLOOD: 'false',
                     ovn_const.LSP_OPTIONS_LOCALNET_LEARN_FDB: 'false'},
            tag=2,
            type='localnet')

    def test_create_port_without_security_groups(self):
        kwargs = {'security_groups': []}
        with self.network() as net1:
            with self.subnet(network=net1) as subnet1:
                with self.port(subnet=subnet1,
                               arg_list=('security_groups',),
                               **kwargs):
                    self.assertEqual(
                        1, self.nb_ovn.create_lswitch_port.call_count)
                    self.assertFalse(self.nb_ovn.add_acl.called)

    def test_create_port_without_security_groups_no_ps(self):
        kwargs = {'security_groups': [], 'port_security_enabled': False}
        with self.network() as net1:
            with self.subnet(network=net1) as subnet1:
                with self.port(subnet=subnet1,
                               arg_list=('security_groups',
                                         'port_security_enabled'),
                               **kwargs):
                    self.assertEqual(
                        1, self.nb_ovn.create_lswitch_port.call_count)
                    self.nb_ovn.add_acl.assert_not_called()

    def test_update_port_changed_security_groups(self):
        with self.network() as net1:
            with self.subnet(network=net1) as subnet1:
                with self.port(subnet=subnet1) as port1:
                    sg_id = port1['port']['security_groups'][0]
                    fake_lsp = (
                        fakes.FakeOVNPort.from_neutron_port(
                            port1['port']))
                    self.nb_ovn.lookup.return_value = fake_lsp

                    # Remove the default security group.
                    self.nb_ovn.set_lswitch_port.reset_mock()
                    self.nb_ovn.update_acls.reset_mock()
                    data = {'port': {'security_groups': []}}
                    self._update('ports', port1['port']['id'], data)
                    self.assertEqual(
                        1, self.nb_ovn.set_lswitch_port.call_count)
                    self.assertFalse(self.nb_ovn.update_acls.called)
                    self.assertTrue(self.nb_ovn.pg_add_ports.called)

                    # Add the default security group.
                    self.nb_ovn.set_lswitch_port.reset_mock()
                    self.nb_ovn.update_acls.reset_mock()
                    fake_lsp.external_ids.pop(ovn_const.OVN_SG_IDS_EXT_ID_KEY)
                    data = {'port': {'security_groups': [sg_id]}}
                    self._update('ports', port1['port']['id'], data)
                    self.assertFalse(self.nb_ovn.update_acls.called)
                    self.assertTrue(self.nb_ovn.pg_add_ports.called)

    def test_update_port_unchanged_security_groups(self):
        with self.network() as net1:
            with self.subnet(network=net1) as subnet1:
                with self.port(subnet=subnet1) as port1:
                    fake_lsp = (
                        fakes.FakeOVNPort.from_neutron_port(
                            port1['port']))
                    self.nb_ovn.lookup.return_value = fake_lsp

                    # Update the port name.
                    self.nb_ovn.set_lswitch_port.reset_mock()
                    self.nb_ovn.update_acls.reset_mock()
                    data = {'port': {'name': 'rtheis'}}
                    self._update('ports', port1['port']['id'], data)
                    self.assertEqual(
                        1, self.nb_ovn.set_lswitch_port.call_count)
                    self.nb_ovn.update_acls.assert_not_called()

                    # Update the port fixed IPs
                    self.nb_ovn.set_lswitch_port.reset_mock()
                    self.nb_ovn.update_acls.reset_mock()
                    data = {'port': {'fixed_ips': []}}
                    self._update('ports', port1['port']['id'], data)
                    self.assertEqual(
                        1, self.nb_ovn.set_lswitch_port.call_count)
                    self.assertFalse(self.nb_ovn.update_acls.called)

    def _test_update_port_vip(self, is_vip=True):
        kwargs = {}
        with self.network() as net1, \
                self.subnet(network=net1) as subnet1, \
                self.port(subnet=subnet1, **kwargs) as port1:
            fake_lsp = (
                fakes.FakeOVNPort.from_neutron_port(
                    port1['port']))
            self.nb_ovn.lookup.return_value = fake_lsp
            self.nb_ovn.set_lswitch_port.reset_mock()
            if is_vip:
                data = {'port': {'name': ovn_const.LB_VIP_PORT_PREFIX + 'foo'}}
            else:
                data = {'port': {}}
            self._update('ports', port1['port']['id'], data)
            self.assertEqual(
                1, self.nb_ovn.set_lswitch_port.call_count)
            called_args_dict = (
                self.nb_ovn.set_lswitch_port.call_args_list[0][1])
            if is_vip:
                self.assertEqual([],
                                 called_args_dict.get('addresses'))
            else:
                self.assertNotEqual([],
                                    called_args_dict.get('addresses'))

    def test_update_port_not_vip_port(self):
        self._test_update_port_vip(is_vip=False)

    def test_update_port_vip_port(self):
        self._test_update_port_vip()

    def test_delete_port_without_security_groups(self):
        kwargs = {'security_groups': []}
        with self.network() as net1:
            with self.subnet(network=net1) as subnet1:
                with self.port(subnet=subnet1,
                               arg_list=('security_groups',),
                               **kwargs) as port1:
                    fake_lsp = (
                        fakes.FakeOVNPort.from_neutron_port(
                            port1['port']))
                    self.nb_ovn.lookup.return_value = fake_lsp
                    self.nb_ovn.delete_lswitch_port.reset_mock()
                    self.nb_ovn.delete_acl.reset_mock()
                    self._delete('ports', port1['port']['id'])
                    self.assertEqual(
                        1, self.nb_ovn.delete_lswitch_port.call_count)

    @mock.patch.object(ovn_revision_numbers_db, 'delete_revision')
    @mock.patch.object(ovn_client.OVNClient, '_delete_port')
    def test_delete_port_exception_delete_revision(self, mock_del_port,
                                                   mock_del_rev):
        mock_del_port.side_effect = Exception('BoOoOoOoOmmmmm!!!')
        with self.network() as net:
            with self.subnet(network=net) as subnet:
                with self.port(subnet=subnet) as port:
                    self._delete('ports', port['port']['id'])
                    # Assert that delete_revision wasn't invoked
                    mock_del_rev.assert_not_called()

    @mock.patch.object(ovn_revision_numbers_db, 'delete_revision')
    @mock.patch.object(ovn_client.OVNClient, '_delete_port')
    def test_delete_port_not_exist_in_ovn(self, mock_del_port,
                                          mock_del_rev):
        mock_del_port.side_effect = idlutils.RowNotFound
        with self.network() as net:
            with self.subnet(network=net) as subnet:
                with self.port(subnet=subnet) as port:
                    self._delete('ports', port['port']['id'])
                    # Assert that delete_revision wasn't invoked
                    mock_del_rev.assert_not_called()

    @mock.patch.object(ovn_revision_numbers_db, 'delete_revision')
    @mock.patch.object(ovn_client.OVNClient, '_delete_port')
    def test_delete_port_stale_entry(self, mock_del_port,
                                     mock_del_rev):
        created_at = timeutils.utcnow() - datetime.timedelta(
            seconds=ovn_const.DB_CONSISTENCY_CHECK_INTERVAL * 2)
        mock_del_port.side_effect = idlutils.RowNotFound
        with self.network() as net:
            with self.subnet(network=net) as subnet:
                with self.port(subnet=subnet) as port, \
                    mock.patch.object(ovn_revision_numbers_db,
                                      'get_revision_row',
                                      return_value=OvnRevNumberRow(
                                          created_at=created_at)):
                    self._delete('ports', port['port']['id'])
                    # Assert that delete_revision was invoked
                    mock_del_rev.assert_called_once_with(mock.ANY,
                                                         port['port']['id'],
                                                         ovn_const.TYPE_PORTS)

    def _test_set_port_status_up(self, is_compute_port=False):
        port_device_owner = 'compute:nova' if is_compute_port else ''
        self.mech_driver._plugin.nova_notifier = mock.Mock()
        with self.network() as net1, \
                self.subnet(network=net1) as subnet1, \
                self.port(subnet=subnet1, is_admin=True,
                          device_owner=port_device_owner) as port1, \
                mock.patch.object(provisioning_blocks,
                                  'provisioning_complete') as pc, \
                mock.patch.object(self.mech_driver,
                                  '_update_dnat_entry_if_needed') as ude, \
                mock.patch.object(self.mech_driver, '_should_notify_nova',
                                  return_value=is_compute_port), \
                mock.patch.object(self.mech_driver._ovn_client,
                                  'update_lsp_host_info') as ulsp:
            self.mech_driver.set_port_status_up(port1['port']['id'])
            pc.assert_called_once_with(
                mock.ANY,
                port1['port']['id'],
                resources.PORT,
                provisioning_blocks.L2_AGENT_ENTITY
            )
            ude.assert_called_once_with(port1['port']['id'])

            # If the port does NOT bellong to compute, do not notify Nova
            # about it's status changes
            if not is_compute_port:
                self.mech_driver._plugin.nova_notifier.\
                    notify_port_active_direct.assert_not_called()
            else:
                self.mech_driver._plugin.nova_notifier.\
                    notify_port_active_direct.assert_called_once_with(
                        mock.ANY)

            ulsp.assert_called_once_with(mock.ANY, mock.ANY)

    def test_set_port_status_up(self):
        self._test_set_port_status_up(is_compute_port=False)

    def test_set_compute_port_status_up(self):
        self._test_set_port_status_up(is_compute_port=True)

    def _test_set_port_status_down(self, is_compute_port=False):
        port_device_owner = 'compute:nova' if is_compute_port else ''
        self.mech_driver._plugin.nova_notifier = mock.Mock()
        with self.network() as net1, \
                self.subnet(network=net1) as subnet1, \
                self.port(subnet=subnet1, is_admin=True,
                          device_owner=port_device_owner) as port1, \
                mock.patch.object(provisioning_blocks,
                                  'add_provisioning_component') as apc, \
                mock.patch.object(self.mech_driver,
                                  '_update_dnat_entry_if_needed') as ude, \
                mock.patch.object(self.mech_driver, '_should_notify_nova',
                                  return_value=is_compute_port), \
                mock.patch.object(self.mech_driver._ovn_client,
                                  'update_lsp_host_info') as ulsp:
            self.mech_driver.set_port_status_down(port1['port']['id'])
            apc.assert_called_once_with(
                mock.ANY,
                port1['port']['id'],
                resources.PORT,
                provisioning_blocks.L2_AGENT_ENTITY
            )
            ude.assert_called_once_with(port1['port']['id'], False)

            # If the port does NOT bellong to compute, do not notify Nova
            # about it's status changes
            if not is_compute_port:
                self.mech_driver._plugin.nova_notifier.\
                    record_port_status_changed.assert_not_called()
                self.mech_driver._plugin.nova_notifier.\
                    send_port_status.assert_not_called()
            else:
                self.mech_driver._plugin.nova_notifier.\
                    record_port_status_changed.assert_called_once_with(
                        mock.ANY, const.PORT_STATUS_ACTIVE,
                        const.PORT_STATUS_DOWN, None)
                self.mech_driver._plugin.nova_notifier.\
                    send_port_status.assert_called_once_with(
                        None, None, mock.ANY)

            ulsp.assert_called_once_with(mock.ANY, mock.ANY, up=False)

    def test_set_port_status_down(self):
        self._test_set_port_status_down(is_compute_port=False)

    def test_set_compute_port_status_down(self):
        self._test_set_port_status_down(is_compute_port=True)

    def test_set_port_status_down_not_found(self):
        with mock.patch.object(provisioning_blocks,
                               'add_provisioning_component') as apc, \
                mock.patch.object(self.mech_driver,
                                  '_update_dnat_entry_if_needed'):
            self.mech_driver.set_port_status_down('foo')
            apc.assert_not_called()

    def test_set_port_status_concurrent_delete(self):
        exc = os_db_exc.DBReferenceError('', '', '', '')
        with self.network() as net1, \
                self.subnet(network=net1) as subnet1, \
                self.port(subnet=subnet1) as port1, \
                mock.patch.object(provisioning_blocks,
                                  'add_provisioning_component',
                                  side_effect=exc) as apc, \
                mock.patch.object(self.mech_driver,
                                  '_update_dnat_entry_if_needed') as ude:
            self.mech_driver.set_port_status_down(port1['port']['id'])
            apc.assert_called_once_with(
                mock.ANY,
                port1['port']['id'],
                resources.PORT,
                provisioning_blocks.L2_AGENT_ENTITY
            )
            ude.assert_called_once_with(port1['port']['id'], False)

    def test_bind_port_unsupported_vnic_type(self):
        fake_port = fakes.FakePort.create_one_port(
            attrs={'binding:vnic_type': 'unknown'}).info()
        fake_port_context = fakes.FakePortContext(fake_port, 'host', [])
        self.mech_driver.bind_port(fake_port_context)
        neutron_agent.AgentCache().get_agents.assert_not_called()
        fake_port_context.set_binding.assert_not_called()

    def _test_bind_port_failed(self, fake_segments):
        fake_port = fakes.FakePort.create_one_port().info()
        fake_host = 'host'
        fake_port_context = fakes.FakePortContext(
            fake_port, fake_host, fake_segments)
        self.mech_driver.bind_port(fake_port_context)
        neutron_agent.AgentCache().get_agents.assert_called_once_with(
            {'host': fake_host,
             'agent_type': ovn_const.OVN_CONTROLLER_TYPES})
        fake_port_context.set_binding.assert_not_called()

    def test_bind_port_host_not_found(self):
        neutron_agent.AgentCache().get_agents.return_value = []
        self._test_bind_port_failed([])

    def test_bind_port_no_segments_to_bind(self):
        self._test_bind_port_failed([])

    def test_bind_port_physnet_not_found(self):
        segment_attrs = {'network_type': 'vlan',
                         'physical_network': 'unknown-physnet',
                         'segmentation_id': 23}
        fake_segments = \
            [fakes.FakeSegment.create_one_segment(attrs=segment_attrs).info()]
        self._test_bind_port_failed(fake_segments)

    def test_bind_port_host_not_alive(self):
        agent = self._add_agent('agent_no_alive', 2)
        now = timeutils.utcnow(with_timezone=True)
        fake_now = now + datetime.timedelta(cfg.CONF.agent_down_time + 1)
        with mock.patch.object(timeutils, 'utcnow') as get_now:
            get_now.return_value = fake_now
            neutron_agent.AgentCache().get_agents.return_value = [agent]
            self._test_bind_port_failed([])

    def _test_bind_port(self, fake_segments):
        fake_port = fakes.FakePort.create_one_port().info()
        fake_host = 'host'
        fake_port_context = fakes.FakePortContext(
            fake_port, fake_host, fake_segments)
        self.mech_driver.bind_port(fake_port_context)
        neutron_agent.AgentCache().get_agents.assert_called_once_with(
            {'host': fake_host,
             'agent_type': ovn_const.OVN_CONTROLLER_TYPES})
        fake_port_context.set_binding.assert_called_once_with(
            fake_segments[0]['id'],
            portbindings.VIF_TYPE_OVS,
            self.mech_driver.vif_details[portbindings.VIF_TYPE_OVS])

    def _test_bind_port_sriov(self, fake_segments):
        fake_port = fakes.FakePort.create_one_port(
            attrs={'binding:vnic_type': 'direct',
                   'binding:profile': {
                       ovn_const.PORT_CAP_PARAM: [
                           ovn_const.PORT_CAP_SWITCHDEV]}}).info()
        fake_host = 'host'
        fake_port_context = fakes.FakePortContext(
            fake_port, fake_host, fake_segments)
        self.mech_driver.bind_port(fake_port_context)
        neutron_agent.AgentCache().get_agents.assert_called_once_with(
            {'host': fake_host,
             'agent_type': ovn_const.OVN_CONTROLLER_TYPES})
        fake_port_context.set_binding.assert_called_once_with(
            fake_segments[0]['id'],
            portbindings.VIF_TYPE_OVS,
            self.mech_driver.vif_details[portbindings.VIF_TYPE_OVS])

    def _test_bind_port_virtio_forwarder(self, fake_segments):
        fake_port = fakes.FakePort.create_one_port(
            attrs={'binding:vnic_type': 'virtio-forwarder'}).info()
        fake_host = 'host'
        fake_port_context = fakes.FakePortContext(
            fake_port, fake_host, fake_segments)
        self.mech_driver.bind_port(fake_port_context)

        vif_details = self.mech_driver.\
            vif_details[portbindings.VIF_TYPE_AGILIO_OVS]
        vif_details.update({"vhostuser_socket": ovn_utils.ovn_vhu_sockpath(
            ovn_conf.get_ovn_vhost_sock_dir(), fake_port['id'])})
        vif_details.update({"vhostuser_mode": "client"})

        neutron_agent.AgentCache().get_agents.assert_called_once_with(
            {'host': fake_host,
             'agent_type': ovn_const.OVN_CONTROLLER_TYPES})
        fake_port_context.set_binding.assert_called_once_with(
            fake_segments[0]['id'],
            portbindings.VIF_TYPE_AGILIO_OVS,
            vif_details)

    def _test_bind_port_remote_managed(self, fake_segments):
        fake_serial = 'fake-serial'
        fake_port = fakes.FakePort.create_one_port(
            attrs={'binding:vnic_type': 'remote-managed',
                   'binding:profile': {
                       'pci_vendor_info': 'fake-pci-vendor-info',
                       'pci_slot': 'fake-pci-slot',
                       'physical_network': fake_segments[0][
                           'physical_network'],
                       'card_serial_number': fake_serial,
                       'pf_mac_address': '00:53:00:00:00:42',
                       'vf_num': 42}}).info()
        fake_smartnic_dpu = 'fake-smartnic-dpu'
        ch_smartnic_dpu = fakes.FakeChassis.create(
            attrs={'hostname': fake_smartnic_dpu},
            card_serial_number=fake_serial)

        self.sb_ovn.get_chassis_by_card_serial_from_cms_options.\
            return_value = ch_smartnic_dpu
        fake_host = 'host'
        fake_port_context = fakes.FakePortContext(
            fake_port, fake_host, fake_segments)
        self.mech_driver.bind_port(fake_port_context)
        neutron_agent.AgentCache().get_agents.assert_called_once_with(
            {'host': fake_smartnic_dpu,
             'agent_type': ovn_const.OVN_CONTROLLER_TYPES})
        fake_port_context.set_binding.assert_called_once_with(
            fake_segments[0]['id'],
            portbindings.VIF_TYPE_OVS,
            self.mech_driver.vif_details[portbindings.VIF_TYPE_OVS])

    def test_bind_port_vdpa(self):
        segment_attrs = {'network_type': 'geneve',
                         'physical_network': None,
                         'segmentation_id': 1023}
        fake_segments = \
            [fakes.FakeSegment.create_one_segment(attrs=segment_attrs).info()]

        fake_port = fakes.FakePort.create_one_port(
            attrs={'binding:vnic_type': 'vdpa',
                   'binding:profile': {'pci_slot': "0000:04:00.0"}}).info()
        fake_host = 'host'
        fake_port_context = fakes.FakePortContext(
            fake_port, fake_host, fake_segments)
        self.mech_driver.bind_port(fake_port_context)
        neutron_agent.AgentCache().get_agents.assert_called_once_with(
            {'host': fake_host,
             'agent_type': ovn_const.OVN_CONTROLLER_TYPES})
        fake_port_context.set_binding.assert_called_once_with(
            fake_segments[0]['id'],
            portbindings.VIF_TYPE_OVS,
            self.mech_driver.vif_details[portbindings.VIF_TYPE_OVS])

    def test_bind_port_geneve(self):
        segment_attrs = {'network_type': 'geneve',
                         'physical_network': None,
                         'segmentation_id': 1023}
        fake_segments = \
            [fakes.FakeSegment.create_one_segment(attrs=segment_attrs).info()]
        self._test_bind_port(fake_segments)

    def test_bind_sriov_port_geneve(self):
        """Test binding a SR-IOV port to a geneve segment."""
        segment_attrs = {'network_type': 'geneve',
                         'physical_network': None,
                         'segmentation_id': 1023}
        fake_segments = \
            [fakes.FakeSegment.create_one_segment(attrs=segment_attrs).info()]
        self._test_bind_port_sriov(fake_segments)

    def test_bind_remote_managed_port_geneve(self):
        """Test binding a REMOTE_MANAGED port to a geneve segment."""
        segment_attrs = {'network_type': 'geneve',
                         'physical_network': None,
                         'segmentation_id': 1023}
        fake_segments = \
            [fakes.FakeSegment.create_one_segment(attrs=segment_attrs).info()]
        self._test_bind_port_remote_managed(fake_segments)

    def test_bind_virtio_forwarder_port_geneve(self):
        """Test binding a VIRTIO_FORWARDER port to a geneve segment."""
        segment_attrs = {'network_type': 'geneve',
                         'physical_network': None,
                         'segmentation_id': 1023}
        fake_segments = \
            [fakes.FakeSegment.create_one_segment(attrs=segment_attrs).info()]
        self._test_bind_port_virtio_forwarder(fake_segments)

    def test_bind_remote_managed_port_vlan(self):
        """Test binding a REMOTE_MANAGED port to a geneve segment."""
        segment_attrs = {'network_type': 'vlan',
                         'physical_network': 'fake-physnet',
                         'segmentation_id': 42}
        fake_segments = \
            [fakes.FakeSegment.create_one_segment(attrs=segment_attrs).info()]
        self._test_bind_port_remote_managed(fake_segments)

    def test_bind_port_vlan(self):
        segment_attrs = {'network_type': 'vlan',
                         'physical_network': 'fake-physnet',
                         'segmentation_id': 23}
        fake_segments = \
            [fakes.FakeSegment.create_one_segment(attrs=segment_attrs).info()]
        self._test_bind_port(fake_segments)

    def test_bind_port_flat(self):
        segment_attrs = {'network_type': 'flat',
                         'physical_network': 'fake-physnet',
                         'segmentation_id': None}
        fake_segments = \
            [fakes.FakeSegment.create_one_segment(attrs=segment_attrs).info()]
        self._test_bind_port(fake_segments)

    def test_bind_port_vxlan(self):
        segment_attrs = {'network_type': 'vxlan',
                         'physical_network': None,
                         'segmentation_id': 1024}
        fake_segments = \
            [fakes.FakeSegment.create_one_segment(attrs=segment_attrs).info()]
        self._test_bind_port(fake_segments)

    def test_bind_virtio_forwarder_port_vxlan(self):
        """Test binding a VIRTIO_FORWARDER port to a vxlan segment."""
        segment_attrs = {'network_type': 'vxlan',
                         'physical_network': None,
                         'segmentation_id': 1024}
        fake_segments = \
            [fakes.FakeSegment.create_one_segment(attrs=segment_attrs).info()]
        self._test_bind_port_virtio_forwarder(fake_segments)

    def test__is_port_provisioning_required(self):
        fake_port = fakes.FakePort.create_one_port(
            attrs={'binding:vnic_type': 'normal',
                   'status': const.PORT_STATUS_DOWN}).info()
        fake_host = 'fake-physnet'

        # Test host not changed
        self.assertFalse(self.mech_driver._is_port_provisioning_required(
            fake_port, fake_host, fake_host))

        # Test invalid vnic type.
        fake_port['binding:vnic_type'] = 'unknown'
        self.assertFalse(self.mech_driver._is_port_provisioning_required(
            fake_port, fake_host, None))
        fake_port['binding:vnic_type'] = 'normal'

        # Test invalid status.
        fake_port['status'] = const.PORT_STATUS_ACTIVE
        self.assertFalse(self.mech_driver._is_port_provisioning_required(
            fake_port, fake_host, None))
        fake_port['status'] = const.PORT_STATUS_DOWN

        # Test no host.
        self.assertFalse(self.mech_driver._is_port_provisioning_required(
            fake_port, None, None))

        # Test invalid host.
        self.sb_ovn.chassis_exists.return_value = False
        self.assertFalse(self.mech_driver._is_port_provisioning_required(
            fake_port, fake_host, None))
        self.sb_ovn.chassis_exists.return_value = True

        # Test port provisioning required.
        self.assertTrue(self.mech_driver._is_port_provisioning_required(
            fake_port, fake_host, None))

    def _test_add_subnet_dhcp_options_in_ovn(self, subnet, ovn_dhcp_opts=None,
                                             call_get_dhcp_opts=True,
                                             call_add_dhcp_opts=True):
        subnet['id'] = 'fake_id'
        with mock.patch.object(self.mech_driver._ovn_client,
                               '_get_ovn_dhcp_options') as get_opts:
            self.mech_driver._ovn_client._add_subnet_dhcp_options(
                subnet, mock.ANY, ovn_dhcp_opts)
            self.assertEqual(call_get_dhcp_opts, get_opts.called)
            self.assertEqual(
                call_add_dhcp_opts,
                self.mech_driver.nb_ovn.add_dhcp_options.called)

    def test_add_subnet_dhcp_options_in_ovn(self):
        subnet = {'ip_version': const.IP_VERSION_4}
        self._test_add_subnet_dhcp_options_in_ovn(subnet)

    def test_add_subnet_dhcp_options_in_ovn_with_given_ovn_dhcp_opts(self):
        subnet = {'ip_version': const.IP_VERSION_4}
        self._test_add_subnet_dhcp_options_in_ovn(
            subnet, ovn_dhcp_opts={'foo': 'bar', 'external_ids': {}},
            call_get_dhcp_opts=False)

    def test_add_subnet_dhcp_options_in_ovn_with_slaac_v6_subnet(self):
        subnet = {'ip_version': const.IP_VERSION_6,
                  'ipv6_address_mode': const.IPV6_SLAAC}
        self._test_add_subnet_dhcp_options_in_ovn(
            subnet, call_get_dhcp_opts=False, call_add_dhcp_opts=False)

    @mock.patch.object(db_base_plugin_v2.NeutronDbPluginV2, 'get_ports')
    @mock.patch.object(n_net, 'get_random_mac')
    def test_enable_subnet_dhcp_options_in_ovn_ipv4(self, grm, gps):
        grm.return_value = '01:02:03:04:05:06'
        gps.return_value = [
            {'id': 'port-id-1', 'device_owner': 'nova:compute'},
            {'id': 'port-id-2', 'device_owner': 'nova:compute',
             'extra_dhcp_opts': [
                 {'opt_value': '10.0.0.33', 'ip_version': 4,
                   'opt_name': 'router'}]},
            {'id': 'port-id-3', 'device_owner': 'nova:compute',
             'extra_dhcp_opts': [
                 {'opt_value': '1200', 'ip_version': 4,
                   'opt_name': 'mtu'}]},
            {'id': 'port-id-10', 'device_owner': 'network:foo'}]
        subnet = {'id': 'subnet-id', 'ip_version': 4, 'cidr': '10.0.0.0/24',
                  'network_id': 'network-id',
                  'gateway_ip': '10.0.0.1', 'enable_dhcp': True,
                  'dns_nameservers': [], 'host_routes': []}
        network = {'id': 'network-id', 'mtu': 1000}
        txn = self.mech_driver.nb_ovn.transaction().__enter__.return_value
        dhcp_option_command = mock.Mock()
        txn.add.return_value = dhcp_option_command

        self.mech_driver._ovn_client._enable_subnet_dhcp_options(
            subnet, network, txn)
        # Check adding DHCP_Options rows
        subnet_dhcp_options = {
            'external_ids': {'subnet_id': subnet['id'],
                             ovn_const.OVN_REV_NUM_EXT_ID_KEY: '1'},
            'cidr': subnet['cidr'], 'options': {
                'router': subnet['gateway_ip'],
                'server_id': subnet['gateway_ip'],
                'server_mac': '01:02:03:04:05:06',
                'dns_server': '{8.8.8.8}',
                'lease_time': str(12 * 60 * 60),
                'mtu': str(1000)}}
        ports_dhcp_options = [{
            'external_ids': {'subnet_id': subnet['id'],
                             ovn_const.OVN_REV_NUM_EXT_ID_KEY: '1',
                             'port_id': 'port-id-2'},
            'cidr': subnet['cidr'], 'options': {
                'router': '10.0.0.33',
                'server_id': subnet['gateway_ip'],
                'dns_server': '{8.8.8.8}',
                'server_mac': '01:02:03:04:05:06',
                'lease_time': str(12 * 60 * 60),
                'mtu': str(1000)}}, {
            'external_ids': {'subnet_id': subnet['id'],
                             ovn_const.OVN_REV_NUM_EXT_ID_KEY: '1',
                             'port_id': 'port-id-3'},
            'cidr': subnet['cidr'], 'options': {
                'router': subnet['gateway_ip'],
                'server_id': subnet['gateway_ip'],
                'dns_server': '{8.8.8.8}',
                'server_mac': '01:02:03:04:05:06',
                'lease_time': str(12 * 60 * 60),
                'mtu': str(1200)}}]
        add_dhcp_calls = [mock.call('subnet-id', **subnet_dhcp_options)]
        add_dhcp_calls.extend([mock.call(
            'subnet-id', port_id=port_dhcp_options['external_ids']['port_id'],
            **port_dhcp_options) for port_dhcp_options in ports_dhcp_options])
        self.assertEqual(len(add_dhcp_calls),
                         self.mech_driver.nb_ovn.add_dhcp_options.call_count)
        self.mech_driver.nb_ovn.add_dhcp_options.assert_has_calls(
            add_dhcp_calls, any_order=True)

        # Check setting lport rows
        set_lsp_calls = [mock.call(lport_name='port-id-1',
                                   dhcpv4_options=dhcp_option_command),
                         mock.call(lport_name='port-id-2',
                                   dhcpv4_options=dhcp_option_command),
                         mock.call(lport_name='port-id-3',
                                   dhcpv4_options=dhcp_option_command)]
        self.assertEqual(len(set_lsp_calls),
                         self.mech_driver.nb_ovn.set_lswitch_port.call_count)
        self.mech_driver.nb_ovn.set_lswitch_port.assert_has_calls(
            set_lsp_calls, any_order=True)

    @mock.patch.object(db_base_plugin_v2.NeutronDbPluginV2, 'get_ports')
    @mock.patch.object(n_net, 'get_random_mac')
    def test_enable_subnet_dhcp_options_in_ovn_ipv6(self, grm, gps):
        grm.return_value = '01:02:03:04:05:06'
        gps.return_value = [
            {'id': 'port-id-1', 'device_owner': 'nova:compute'},
            {'id': 'port-id-2', 'device_owner': 'nova:compute',
             'extra_dhcp_opts': [
                 {'opt_value': '11:22:33:44:55:66', 'ip_version': 6,
                   'opt_name': 'server-id'}]},
            {'id': 'port-id-3', 'device_owner': 'nova:compute',
             'extra_dhcp_opts': [
                 {'opt_value': '10::34', 'ip_version': 6,
                   'opt_name': 'dns-server'}]},
            {'id': 'port-id-10', 'device_owner': 'network:foo'}]
        subnet = {'id': 'subnet-id', 'ip_version': 6, 'cidr': '10::0/64',
                  'gateway_ip': '10::1', 'enable_dhcp': True,
                  'ipv6_address_mode': 'dhcpv6-stateless',
                  'dns_nameservers': [], 'host_routes': []}
        network = {'id': 'network-id', 'mtu': 1000}
        txn = self.mech_driver.nb_ovn.transaction().__enter__.return_value
        dhcp_option_command = mock.Mock()
        txn.add.return_value = dhcp_option_command

        self.mech_driver._ovn_client._enable_subnet_dhcp_options(
            subnet, network, txn)
        # Check adding DHCP_Options rows
        subnet_dhcp_options = {
            'external_ids': {'subnet_id': subnet['id'],
                             ovn_const.OVN_REV_NUM_EXT_ID_KEY: '1'},
            'cidr': subnet['cidr'], 'options': {
                'dhcpv6_stateless': 'true',
                'server_id': '01:02:03:04:05:06'}}
        ports_dhcp_options = [{
            'external_ids': {'subnet_id': subnet['id'],
                             ovn_const.OVN_REV_NUM_EXT_ID_KEY: '1',
                             'port_id': 'port-id-2'},
            'cidr': subnet['cidr'], 'options': {
                'dhcpv6_stateless': 'true',
                'server_id': '11:22:33:44:55:66'}}, {
            'external_ids': {'subnet_id': subnet['id'],
                             ovn_const.OVN_REV_NUM_EXT_ID_KEY: '1',
                             'port_id': 'port-id-3'},
            'cidr': subnet['cidr'], 'options': {
                'dhcpv6_stateless': 'true',
                'server_id': '01:02:03:04:05:06',
                'dns_server': '10::34'}}]
        add_dhcp_calls = [mock.call('subnet-id', **subnet_dhcp_options)]
        add_dhcp_calls.extend([mock.call(
            'subnet-id', port_id=port_dhcp_options['external_ids']['port_id'],
            **port_dhcp_options) for port_dhcp_options in ports_dhcp_options])
        self.assertEqual(len(add_dhcp_calls),
                         self.mech_driver.nb_ovn.add_dhcp_options.call_count)
        self.mech_driver.nb_ovn.add_dhcp_options.assert_has_calls(
            add_dhcp_calls, any_order=True)

        # Check setting lport rows
        set_lsp_calls = [mock.call(lport_name='port-id-1',
                                   dhcpv6_options=dhcp_option_command),
                         mock.call(lport_name='port-id-2',
                                   dhcpv6_options=dhcp_option_command),
                         mock.call(lport_name='port-id-3',
                                   dhcpv6_options=dhcp_option_command)]
        self.assertEqual(len(set_lsp_calls),
                         self.mech_driver.nb_ovn.set_lswitch_port.call_count)
        self.mech_driver.nb_ovn.set_lswitch_port.assert_has_calls(
            set_lsp_calls, any_order=True)

    def test_enable_subnet_dhcp_options_in_ovn_ipv6_slaac(self):
        subnet = {'id': 'subnet-id', 'ip_version': 6, 'enable_dhcp': True,
                  'ipv6_address_mode': 'slaac'}
        network = {'id': 'network-id'}

        self.mech_driver._ovn_client._enable_subnet_dhcp_options(
            subnet, network, mock.Mock())
        self.mech_driver.nb_ovn.add_dhcp_options.assert_not_called()
        self.mech_driver.nb_ovn.set_lswitch_port.assert_not_called()

    def _test_remove_subnet_dhcp_options_in_ovn(self, ip_version):
        opts = {'subnet': {'uuid': 'subnet-uuid'},
                'ports': [{'uuid': 'port1-uuid'}]}
        self.mech_driver.nb_ovn.get_subnet_dhcp_options.return_value = opts
        self.mech_driver._ovn_client._remove_subnet_dhcp_options(
            'subnet-id', mock.Mock())

        # Check deleting DHCP_Options rows
        delete_dhcp_calls = [mock.call('subnet-uuid'), mock.call('port1-uuid')]
        self.assertEqual(
            len(delete_dhcp_calls),
            self.mech_driver.nb_ovn.delete_dhcp_options.call_count)
        self.mech_driver.nb_ovn.delete_dhcp_options.assert_has_calls(
            delete_dhcp_calls, any_order=True)

    def test_remove_subnet_dhcp_options_in_ovn_ipv4(self):
        self._test_remove_subnet_dhcp_options_in_ovn(4)

    def test_remove_subnet_dhcp_options_in_ovn_ipv6(self):
        self._test_remove_subnet_dhcp_options_in_ovn(6)

    def test_update_subnet_dhcp_options_in_ovn_ipv4(self):
        subnet = {'id': 'subnet-id', 'ip_version': 4, 'cidr': '10.0.0.0/24',
                  'network_id': 'network-id',
                  'gateway_ip': '10.0.0.1', 'enable_dhcp': True,
                  'dns_nameservers': [], 'host_routes': []}
        network = {'id': 'network-id', 'mtu': 1000}
        orignal_options = {'subnet': {
            'external_ids': {'subnet_id': subnet['id']},
            'cidr': subnet['cidr'], 'options': {
                'router': '10.0.0.2',
                'server_id': '10.0.0.2',
                'server_mac': '01:02:03:04:05:06',
                'dns_server': '{8.8.8.8}',
                'lease_time': str(12 * 60 * 60),
                'mtu': str(1000)}}, 'ports': []}
        self.mech_driver.nb_ovn.get_subnet_dhcp_options.return_value =\
            orignal_options

        self.mech_driver._ovn_client._update_subnet_dhcp_options(
            subnet, network, mock.Mock())
        new_options = {
            'external_ids': {'subnet_id': subnet['id'],
                             ovn_const.OVN_REV_NUM_EXT_ID_KEY: '1'},
            'cidr': subnet['cidr'], 'options': {
                'router': subnet['gateway_ip'],
                'server_id': subnet['gateway_ip'],
                'dns_server': '{8.8.8.8}',
                'server_mac': '01:02:03:04:05:06',
                'lease_time': str(12 * 60 * 60),
                'mtu': str(1000)}}
        self.mech_driver.nb_ovn.add_dhcp_options.assert_called_once_with(
            subnet['id'], **new_options)

    def test_update_subnet_dhcp_options_in_ovn_ipv4_not_change(self):
        subnet = {'id': 'subnet-id', 'ip_version': 4, 'cidr': '10.0.0.0/24',
                  'network_id': 'network-id',
                  'gateway_ip': '10.0.0.1', 'enable_dhcp': True,
                  'dns_nameservers': [], 'host_routes': []}
        network = {'id': 'network-id', 'mtu': 1000}
        orignal_options = {'subnet': {
            'external_ids': {'subnet_id': subnet['id']},
            'cidr': subnet['cidr'], 'options': {
                'router': subnet['gateway_ip'],
                'server_id': subnet['gateway_ip'],
                'server_mac': '01:02:03:04:05:06',
                'dns_server': '{8.8.8.8}',
                'lease_time': str(12 * 60 * 60),
                'mtu': str(1000)}}, 'ports': []}
        self.mech_driver.nb_ovn.get_subnet_dhcp_options.return_value =\
            orignal_options

        self.mech_driver._ovn_client._update_subnet_dhcp_options(
            subnet, network, mock.Mock())
        self.mech_driver.nb_ovn.add_dhcp_options.assert_not_called()

    def test_update_subnet_dhcp_options_in_ovn_ipv6(self):
        subnet = {'id': 'subnet-id', 'ip_version': 6, 'cidr': '10::0/64',
                  'network_id': 'network-id',
                  'gateway_ip': '10::1', 'enable_dhcp': True,
                  'ipv6_address_mode': 'dhcpv6-stateless',
                  'dns_nameservers': ['10::3'], 'host_routes': []}
        network = {'id': 'network-id', 'mtu': 1000}
        orignal_options = {'subnet': {
            'external_ids': {'subnet_id': subnet['id']},
            'cidr': subnet['cidr'], 'options': {
                'dhcpv6_stateless': 'true',
                'server_id': '01:02:03:04:05:06'}}, 'ports': []}
        self.mech_driver.nb_ovn.get_subnet_dhcp_options.return_value =\
            orignal_options
        self.mech_driver._ovn_client._update_subnet_dhcp_options(
            subnet, network, mock.Mock())

        new_options = {
            'external_ids': {'subnet_id': subnet['id'],
                             ovn_const.OVN_REV_NUM_EXT_ID_KEY: '1'},
            'cidr': subnet['cidr'], 'options': {
                'dhcpv6_stateless': 'true',
                'dns_server': '{10::3}',
                'server_id': '01:02:03:04:05:06'}}
        self.mech_driver.nb_ovn.add_dhcp_options.assert_called_once_with(
            subnet['id'], **new_options)

    def test_update_subnet_dhcp_options_in_ovn_ipv6_not_change(self):
        subnet = {'id': 'subnet-id', 'ip_version': 6, 'cidr': '10::0/64',
                  'gateway_ip': '10::1', 'enable_dhcp': True,
                  'ipv6_address_mode': 'dhcpv6-stateless',
                  'dns_nameservers': [], 'host_routes': []}
        network = {'id': 'network-id', 'mtu': 1000}
        orignal_options = {'subnet': {
            'external_ids': {'subnet_id': subnet['id']},
            'cidr': subnet['cidr'], 'options': {
                'dhcpv6_stateless': 'true',
                'server_id': '01:02:03:04:05:06'}}, 'ports': []}
        self.mech_driver.nb_ovn.get_subnet_dhcp_options.return_value =\
            orignal_options

        self.mech_driver._ovn_client._update_subnet_dhcp_options(
            subnet, network, mock.Mock())
        self.mech_driver.nb_ovn.add_dhcp_options.assert_not_called()

    def test_update_subnet_dhcp_options_in_ovn_ipv6_slaac(self):
        subnet = {'id': 'subnet-id', 'ip_version': 6, 'enable_dhcp': True,
                  'ipv6_address_mode': 'slaac'}
        network = {'id': 'network-id'}
        self.mech_driver._ovn_client._update_subnet_dhcp_options(
            subnet, network, mock.Mock())
        self.mech_driver.nb_ovn.get_subnet_dhcp_options.assert_not_called()
        self.mech_driver.nb_ovn.add_dhcp_options.assert_not_called()

    def test_update_subnet_postcommit_ovn_do_nothing(self):
        context = fakes.FakeSubnetContext(
            subnet={'enable_dhcp': False, 'ip_version': 4, 'network_id': 'id',
                    'id': 'subnet_id'},
            network={'id': 'id'})
        with mock.patch.object(
                self.mech_driver._ovn_client,
                '_enable_subnet_dhcp_options') as esd,\
                mock.patch.object(
                    self.mech_driver._ovn_client,
                    '_remove_subnet_dhcp_options') as dsd,\
                mock.patch.object(
                    self.mech_driver._ovn_client,
                    '_update_subnet_dhcp_options') as usd,\
                mock.patch.object(
                    self.mech_driver._ovn_client,
                    '_find_metadata_port') as fmd,\
                mock.patch.object(
                    self.mech_driver._ovn_client,
                    'update_metadata_port') as umd:
            self.mech_driver.update_subnet_postcommit(context)
            esd.assert_not_called()
            dsd.assert_not_called()
            usd.assert_not_called()
            fmd.assert_not_called()
            umd.assert_not_called()

    def test_update_subnet_postcommit_enable_dhcp(self):
        subnet = {'enable_dhcp': True, 'ip_version': 4, 'network_id': 'id',
                  'id': 'subnet_id'}
        context = fakes.FakeSubnetContext(subnet=subnet, network={'id': 'id'})
        with mock.patch.object(
                self.mech_driver._ovn_client,
                '_enable_subnet_dhcp_options') as esd,\
                mock.patch.object(
                self.mech_driver._ovn_client,
                'update_metadata_port') as umd:
            self.mech_driver.update_subnet_postcommit(context)
            esd.assert_called_once_with(
                context.current, context.network.current, mock.ANY)
            umd.assert_called_once_with(mock.ANY, context.network.current,
                                        subnet=subnet)

    def test_update_subnet_postcommit_disable_dhcp(self):
        self.mech_driver.nb_ovn.get_subnet_dhcp_options.return_value = {
            'subnet': mock.sentinel.subnet, 'ports': []}
        subnet = {'enable_dhcp': False, 'id': 'subnet_id', 'ip_version': 4,
                  'network_id': 'id'}
        context = fakes.FakeSubnetContext(subnet=subnet, network={'id': 'id'})
        with mock.patch.object(
                self.mech_driver._ovn_client,
                '_remove_subnet_dhcp_options') as dsd,\
                mock.patch.object(
                self.mech_driver._ovn_client,
                'update_metadata_port') as umd:
            self.mech_driver.update_subnet_postcommit(context)
            dsd.assert_called_once_with(context.current['id'], mock.ANY)
            umd.assert_called_once_with(mock.ANY, context.network.current,
                                        subnet=subnet)

    def test_update_subnet_postcommit_update_dhcp(self):
        self.mech_driver.nb_ovn.get_subnet_dhcp_options.return_value = {
            'subnet': mock.sentinel.subnet, 'ports': []}
        subnet = {'enable_dhcp': True, 'id': 'subnet_id', 'ip_version': 4,
                  'network_id': 'id'}
        context = fakes.FakeSubnetContext(subnet=subnet, network={'id': 'id'})
        with mock.patch.object(
                self.mech_driver._ovn_client,
                '_update_subnet_dhcp_options') as usd,\
                mock.patch.object(
                self.mech_driver._ovn_client,
                'update_metadata_port') as umd:
            self.mech_driver.update_subnet_postcommit(context)
            usd.assert_called_once_with(
                context.current, context.network.current, mock.ANY)
            umd.assert_called_once_with(mock.ANY, context.network.current,
                                        subnet=subnet)

    def test__get_port_options(self):
        with mock.patch.object(self.mech_driver._plugin, 'get_subnets') as \
                mock_get_subnets:
            port = {'id': 'virt-port',
                    'mac_address': '00:00:00:00:00:00',
                    'device_owner': 'device_owner',
                    'network_id': 'foo',
                    'fixed_ips': [{'subnet_id': 'subnet-1',
                                   'ip_address': '10.0.0.55'},
                                  {'subnet_id': 'subnet-2',
                                   'ip_address': '10.0.1.55'},
                                  ],
                    portbindings.PROFILE: {},
                    }
            subnet_ids = [
                ip['subnet_id']
                for ip in port.get('fixed_ips')
            ]
            self.mech_driver._ovn_client._get_port_options(port)
            mock_get_subnets.assert_called_once_with(
                mock.ANY,
                filters={'id': subnet_ids})

    def test__get_port_options_with_addr_scope(self):
        with mock.patch.object(
            self.mech_driver._plugin, "get_subnets"
        ) as mock_get_subnets, mock.patch.object(
            self.mech_driver._plugin,
            "get_subnetpool",
        ) as mock_get_subnetpool:
            port = {
                "id": "virt-port",
                "mac_address": "00:00:00:00:00:00",
                "device_owner": "device_owner",
                "network_id": "foo",
                "fixed_ips": [
                    {"subnet_id": "subnet-1", "ip_address": "10.0.0.55"},
                    {"subnet_id": "subnet-2", "ip_address": "aef0::4"},
                ],
                portbindings.PROFILE: {},
            }

            subnet_ids = [ip["subnet_id"] for ip in port.get("fixed_ips")]
            mock_get_subnets.return_value = [
                {
                    "id": "subnet-1",
                    "subnetpool_id": "subnetpool1",
                    "cidr": "10.0.0.0/24",
                },
                {
                    "id": "subnet-2",
                    "subnetpool_id": "subnetpool2",
                    "cidr": "aef0::/64",
                },
            ]
            mock_get_subnetpool.side_effect = [
                {
                    "ip_version": const.IP_VERSION_4,
                    "address_scope_id": "address_scope_v4",
                },
                {
                    "ip_version": const.IP_VERSION_6,
                    "address_scope_id": "address_scope_v6",
                },
            ]
            options = self.mech_driver._ovn_client._get_port_options(port)
            mock_get_subnets.assert_called_once_with(
                mock.ANY, filters={"id": subnet_ids}
            )

            expected_calls = [
                mock.call(mock.ANY, id="subnetpool1"),
                mock.call(mock.ANY, id="subnetpool2"),
            ]

            mock_get_subnetpool.assert_has_calls(expected_calls)

            self.assertEqual("address_scope_v4", options.address4_scope_id)
            self.assertEqual("address_scope_v6", options.address6_scope_id)

    def test__get_port_options_migrating_additional_chassis_missing(self):
        port = {
            'id': 'virt-port',
            'mac_address': '00:00:00:00:00:00',
            'device_owner': 'device_owner',
            'network_id': 'foo',
            'fixed_ips': [],
            portbindings.HOST_ID: 'fake-src',
            portbindings.PROFILE: {
                ovn_const.MIGRATING_ATTR: 'fake-dest',
            }
        }
        options = self.mech_driver._ovn_client._get_port_options(port)
        self.assertNotIn('activation-strategy', options.options)
        self.assertEqual('fake-src', options.options['requested-chassis'])

    def test__get_port_options_migrating_additional_chassis_present(self):
        port = {
            'id': 'virt-port',
            'mac_address': '00:00:00:00:00:00',
            'device_owner': 'device_owner',
            'network_id': 'foo',
            'fixed_ips': [],
            portbindings.HOST_ID: 'fake-src',
            portbindings.PROFILE: {
                ovn_const.MIGRATING_ATTR: 'fake-dest',
            }
        }
        with mock.patch.object(
                self.mech_driver._ovn_client._sb_idl, 'is_col_present',
                return_value=True):
            options = self.mech_driver._ovn_client._get_port_options(port)
        self.assertEqual('rarp', options.options['activation-strategy'])
        self.assertEqual('fake-src,fake-dest',
                         options.options['requested-chassis'])

    def test__get_port_options_not_migrating_additional_chassis_present(self):
        port = {
            'id': 'virt-port',
            'mac_address': '00:00:00:00:00:00',
            'device_owner': 'device_owner',
            'network_id': 'foo',
            'fixed_ips': [],
            portbindings.HOST_ID: 'fake-src',
            portbindings.PROFILE: {},
        }
        with mock.patch.object(
                self.mech_driver._ovn_client._sb_idl, 'is_col_present',
                return_value=True):
            options = self.mech_driver._ovn_client._get_port_options(port)
        self.assertNotIn('activation-strategy', options.options)
        self.assertEqual('fake-src',
                         options.options['requested-chassis'])

    def test_update_port(self):
        with mock.patch.object(
                ovn_utils, 'is_ovn_metadata_port') as \
                mock_is_ovn_metadata_port, \
                mock.patch.object(self.mech_driver._plugin, 'get_subnets') as \
                mock_get_subnets, \
                mock.patch.object(self.mech_driver._plugin, 'get_network') as \
                mock_get_network:
            net_attrs = {az_def.AZ_HINTS: ['az0', 'az1', 'az2']}
            fake_net = (
                fakes.FakeNetwork.create_one_network(attrs=net_attrs).info())
            port = {'id': 'virt-port',
                    'mac_address': '00:00:00:00:00:00',
                    'name': 'port-foo',
                    'device_id': 'device_id-foo',
                    'project_id': 'project_id-foo',
                    'device_owner': 'device_owner',
                    'network_id': 'foo',
                    'admin_state_up': True,
                    'fixed_ips': [{'subnet_id': 'subnet-1',
                                   'ip_address': '10.0.0.55'},
                                  {'subnet_id': 'subnet-2',
                                   'ip_address': '10.0.1.55'},
                                  ],
                    portbindings.PROFILE: {},
                    }
            subnet_ids = [
                ip['subnet_id']
                for ip in port.get('fixed_ips')
            ]

            mock_is_ovn_metadata_port.return_value = [True]
            mock_get_network.return_value = fake_net
            self.mech_driver._ovn_client.update_port(
                self.context, port)
            self.assertEqual(mock_get_subnets.call_count, 2)
            mock_get_subnets.assert_called_with(
                mock.ANY,
                filters={'id': subnet_ids})

    def test_update_metadata_port_with_subnet(self):
        ovn_conf.cfg.CONF.set_override('ovn_metadata_enabled', True,
                                       group='ovn')

        with mock.patch.object(
                self.mech_driver._ovn_client, '_find_metadata_port') as \
                mock_metaport, \
                mock.patch.object(self.mech_driver._plugin, 'get_subnets') as \
                mock_get_subnets, \
                mock.patch.object(self.mech_driver._plugin, 'update_port') as \
                mock_update_port:
            # Subnet with DHCP, present in port.
            fixed_ips = [{'subnet_id': 'subnet1', 'ip_address': 'ip_add1'}]
            mock_metaport.return_value = {'fixed_ips': fixed_ips,
                                          'id': 'metadata_id'}
            mock_get_subnets.return_value = [{'id': 'subnet1'}]
            network = {'id': 'net_id'}
            subnet = {'id': 'subnet1', 'enable_dhcp': True}
            self.mech_driver._ovn_client.update_metadata_port(
                self.context, network, subnet=subnet)
            mock_update_port.assert_not_called()

            # Subnet without DHCP, present in port.
            fixed_ips = [{'subnet_id': 'subnet1', 'ip_address': 'ip_add1'}]
            mock_metaport.return_value = {'fixed_ips': fixed_ips,
                                          'id': 'metadata_id'}
            mock_get_subnets.return_value = [{'id': 'subnet1'}]
            subnet = {'id': 'subnet1', 'enable_dhcp': False}
            self.mech_driver._ovn_client.update_metadata_port(
                self.context, network, subnet=subnet)
            port = {'id': 'metadata_id',
                    'port': {'network_id': 'net_id', 'fixed_ips': []}}
            mock_update_port.assert_called_once_with(mock.ANY, 'metadata_id',
                                                     port)
            mock_update_port.reset_mock()

            # Subnet with DHCP, not present in port.
            mock_metaport.return_value = {'fixed_ips': [],
                                          'id': 'metadata_id'}
            mock_get_subnets.return_value = []
            subnet = {'id': 'subnet1', 'enable_dhcp': True}
            self.mech_driver._ovn_client.update_metadata_port(
                self.context, network, subnet=subnet)
            fixed_ips = [{'subnet_id': 'subnet1'}]
            port = {'id': 'metadata_id',
                    'port': {'network_id': 'net_id', 'fixed_ips': fixed_ips}}
            mock_update_port.assert_called_once_with(mock.ANY, 'metadata_id',
                                                     port)
            mock_update_port.reset_mock()

            # Subnet without DHCP, not present in port.
            mock_metaport.return_value = {'fixed_ips': [],
                                          'id': 'metadata_id'}
            mock_get_subnets.return_value = []
            subnet = {'id': 'subnet1', 'enable_dhcp': False}
            self.mech_driver._ovn_client.update_metadata_port(
                self.context, network, subnet=subnet)
            mock_update_port.assert_not_called()

    def test_update_metadata_port_no_subnet(self):
        ovn_conf.cfg.CONF.set_override('ovn_metadata_enabled', True,
                                       group='ovn')
        with mock.patch.object(
                self.mech_driver._ovn_client, '_find_metadata_port') as \
                mock_metaport, \
                mock.patch.object(self.mech_driver._plugin, 'get_subnets') as \
                mock_get_subnets, \
                mock.patch.object(self.mech_driver._plugin, 'update_port') as \
                mock_update_port:
            # Port with IP in subnet1; subnet1 and subnet2 with DHCP.
            mock_get_subnets.return_value = [{'id': 'subnet1'},
                                             {'id': 'subnet2'}]
            fixed_ips = [{'subnet_id': 'subnet1', 'ip_address': 'ip_add1'}]
            network = {'id': 'net_id'}
            mock_metaport.return_value = {'fixed_ips': fixed_ips,
                                          'id': 'metadata_id'}
            self.mech_driver._ovn_client.update_metadata_port(self.context,
                                                              network)
            port = {'id': 'metadata_id',
                    'port': {'network_id': 'net_id', 'fixed_ips': fixed_ips}}
            fixed_ips.append({'subnet_id': 'subnet2'})
            mock_update_port.assert_called_once_with(
                mock.ANY, 'metadata_id', port)
            mock_update_port.reset_mock()

            # Port with IP in subnet1; subnet1 with DHCP, subnet2 without DHCP.
            mock_get_subnets.return_value = [{'id': 'subnet1'}]
            fixed_ips = [{'subnet_id': 'subnet1', 'ip_address': 'ip_add1'}]
            network = {'id': 'net_id'}
            mock_metaport.return_value = {'fixed_ips': fixed_ips,
                                          'id': 'metadata_id'}
            self.mech_driver._ovn_client.update_metadata_port(self.context,
                                                              network)
            mock_update_port.assert_not_called()

            # Port with IP in subnet1; subnet1 without DHCP.
            mock_get_subnets.return_value = []
            fixed_ips = [{'subnet_id': 'subnet1', 'ip_address': 'ip_add1'}]
            mock_metaport.return_value = {'fixed_ips': fixed_ips,
                                          'id': 'metadata_id'}
            self.mech_driver._ovn_client.update_metadata_port(self.context,
                                                              network)
            port = {'id': 'metadata_id',
                    'port': {'network_id': 'net_id', 'fixed_ips': []}}
            mock_update_port.assert_called_once_with(
                mock.ANY, 'metadata_id', port)
            mock_update_port.reset_mock()

    def test_update_metadata_port_no_port(self):
        ovn_conf.cfg.CONF.set_override('ovn_metadata_enabled', True,
                                       group='ovn')

        with mock.patch.object(
                self.mech_driver._ovn_client, '_find_metadata_port') as \
                mock_find_metaport, \
                mock.patch.object(self.mech_driver._plugin, 'get_subnets') as \
                mock_get_subnets, \
                mock.patch.object(p_utils, 'create_port') as \
                mock_create_port:
            # Subnet with DHCP, no port, port created.
            network = {'id': 'net_id', 'project_id': 'project_id-foo'}
            subnet = {'id': 'subnet1', 'enable_dhcp': True}
            fixed_ips = [{'subnet_id': 'subnet1', 'ip_address': 'ip_add1'}]
            port = {'id': 'metadata_id',
                    'network_id': 'net_id',
                    'device_owner': const.DEVICE_OWNER_DISTRIBUTED,
                    'device_id': 'ovnmeta-%s' % 'net_id',
                    'fixed_ips': fixed_ips}
            mock_get_subnets.return_value = [subnet]
            mock_find_metaport.return_value = None

            # Subnet with DHCP, no port, port create failure.
            mock_create_port.return_value = None
            ret_status = self.mech_driver._ovn_client.update_metadata_port(
                self.context, network, subnet=subnet)
            self.assertFalse(ret_status)
            mock_create_port.assert_called_once()

            # Subnet with DHCP, no port, port created successfully.
            mock_create_port.reset_mock()
            mock_create_port.return_value = port
            ret_status = self.mech_driver._ovn_client.update_metadata_port(
                self.context, network, subnet=subnet)
            self.assertTrue(ret_status)
            mock_create_port.assert_called_once()

    @mock.patch.object(provisioning_blocks, 'is_object_blocked')
    @mock.patch.object(provisioning_blocks, 'provisioning_complete')
    def test_notify_dhcp_updated(self, mock_prov_complete, mock_is_obj_block):
        port_id = 'fake-port-id'
        mock_is_obj_block.return_value = True
        self.mech_driver._notify_dhcp_updated(port_id)
        mock_prov_complete.assert_called_once_with(
            mock.ANY, port_id, resources.PORT,
            provisioning_blocks.DHCP_ENTITY)

        mock_is_obj_block.return_value = False
        mock_prov_complete.reset_mock()
        self.mech_driver._notify_dhcp_updated(port_id)
        mock_prov_complete.assert_not_called()

    @mock.patch.object(mech_driver.OVNMechanismDriver,
                       '_is_port_provisioning_required', lambda *_: True)
    @mock.patch.object(mech_driver.OVNMechanismDriver, '_notify_dhcp_updated')
    @mock.patch.object(ovn_client.OVNClient, 'create_port')
    def test_create_port_postcommit(self, mock_create_port, mock_notify_dhcp):
        fake_port = fakes.FakePort.create_one_port(
            attrs={'status': const.PORT_STATUS_DOWN}).info()
        fake_ctx = mock.Mock(current=fake_port)
        self.mech_driver.create_port_postcommit(fake_ctx)
        passed_fake_port = copy.deepcopy(fake_port)
        passed_fake_port['network'] = fake_ctx.network.current
        mock_create_port.assert_called_once_with(mock.ANY, passed_fake_port)
        mock_notify_dhcp.assert_called_once_with(fake_port['id'])

    @mock.patch.object(mech_driver.OVNMechanismDriver,
                       '_is_port_provisioning_required', lambda *_: True)
    @mock.patch.object(mech_driver.OVNMechanismDriver, '_notify_dhcp_updated')
    @mock.patch.object(ovn_client.OVNClient, 'update_port')
    def test_update_port_postcommit(self, mock_update_port,
                                    mock_notify_dhcp):
        fake_port = fakes.FakePort.create_one_port(
            attrs={'status': const.PORT_STATUS_ACTIVE}).info()
        fake_ctx = mock.Mock(current=fake_port, original=fake_port)
        self.mech_driver.update_port_postcommit(fake_ctx)

        passed_fake_port = copy.deepcopy(fake_port)
        passed_fake_port['network'] = fake_ctx.network.current
        passed_fake_port_orig = copy.deepcopy(fake_ctx.original)
        passed_fake_port_orig['network'] = fake_ctx.network.current

        mock_update_port.assert_called_once_with(
            mock.ANY, passed_fake_port, port_object=passed_fake_port_orig)
        mock_notify_dhcp.assert_called_once_with(fake_port['id'])

    @mock.patch.object(mech_driver.OVNMechanismDriver,
                       '_is_port_provisioning_required', lambda *_: True)
    @mock.patch.object(mech_driver.OVNMechanismDriver, '_notify_dhcp_updated')
    @mock.patch.object(ovn_client.OVNClient, 'update_port')
    def test_update_port_postcommit_live_migration(
            self, mock_update_port, mock_notify_dhcp):
        self.plugin.update_port_status = mock.Mock()
        fake_context = 'fake_context'
        fake_port = fakes.FakePort.create_one_port(
            attrs={
                'status': const.PORT_STATUS_DOWN,
                portbindings.PROFILE: {ovn_const.MIGRATING_ATTR: 'foo'},
                portbindings.VIF_TYPE: portbindings.VIF_TYPE_OVS}).info()
        fake_ctx = mock.Mock(current=fake_port, original=fake_port,
                             plugin_context=fake_context)

        self.mech_driver.update_port_postcommit(fake_ctx)

        mock_update_port.assert_not_called()
        mock_notify_dhcp.assert_not_called()
        self.plugin.update_port_status.assert_called_once_with(
            fake_context, fake_port['id'], const.PORT_STATUS_ACTIVE)

    @mock.patch.object(mech_driver.OVNMechanismDriver,
                       '_is_port_provisioning_required', lambda *_: True)
    @mock.patch.object(mech_driver.OVNMechanismDriver, '_notify_dhcp_updated')
    @mock.patch.object(ovn_client.OVNClient, 'update_port')
    def test_update_port_postcommit_live_migration_revision_mismatch_always(
            self, mock_update_port, mock_notify_dhcp):
        self.plugin.update_port_status = mock.Mock()
        self.plugin.get_port = mock.Mock(return_value=mock.MagicMock())

        fake_context = mock.MagicMock()
        fake_port = fakes.FakePort.create_one_port(
            attrs={
                'status': const.PORT_STATUS_ACTIVE,
                portbindings.PROFILE: {},
                portbindings.VIF_TYPE: portbindings.VIF_TYPE_OVS}).info()
        original_fake_port = fakes.FakePort.create_one_port(
            attrs={
                'status': const.PORT_STATUS_ACTIVE,
                portbindings.PROFILE: {
                    ovn_const.MIGRATING_ATTR: fake_port[portbindings.HOST_ID]},
                portbindings.VIF_TYPE: portbindings.VIF_TYPE_OVS}).info()

        fake_ctx = mock.Mock(current=fake_port, original=original_fake_port,
                             plugin_context=fake_context)
        mock_update_port.side_effect = ovn_exceptions.RevisionConflict(
            resource_id=fake_port['id'],
            resource_type=ovn_const.TYPE_PORTS)

        self.mech_driver.update_port_postcommit(fake_ctx)

        self.plugin.update_port_status.assert_not_called()
        self.plugin.get_port.assert_called_once_with(
            mock.ANY, fake_port['id'])
        self.assertEqual(2, mock_update_port.call_count)
        mock_notify_dhcp.assert_called_with(fake_port['id'])

    @mock.patch.object(mech_driver.OVNMechanismDriver,
                       '_is_port_provisioning_required', lambda *_: True)
    @mock.patch.object(mech_driver.OVNMechanismDriver, '_notify_dhcp_updated')
    @mock.patch.object(ovn_client.OVNClient, 'update_port')
    def test_update_port_postcommit_live_migration_revision_mismatch_once(
            self, mock_update_port, mock_notify_dhcp):
        self.plugin.update_port_status = mock.Mock()
        self.plugin.get_port = mock.Mock(return_value=mock.MagicMock())

        fake_context = mock.MagicMock()
        fake_port = fakes.FakePort.create_one_port(
            attrs={
                'status': const.PORT_STATUS_ACTIVE,
                portbindings.PROFILE: {},
                portbindings.VIF_TYPE: portbindings.VIF_TYPE_OVS}).info()
        original_fake_port = fakes.FakePort.create_one_port(
            attrs={
                'status': const.PORT_STATUS_ACTIVE,
                portbindings.PROFILE: {
                    ovn_const.MIGRATING_ATTR: fake_port[portbindings.HOST_ID]},
                portbindings.VIF_TYPE: portbindings.VIF_TYPE_OVS}).info()

        fake_ctx = mock.Mock(current=fake_port, original=original_fake_port,
                             plugin_context=fake_context)
        mock_update_port.side_effect = [
            ovn_exceptions.RevisionConflict(
                resource_id=fake_port['id'],
                resource_type=ovn_const.TYPE_PORTS),
            None]

        self.mech_driver.update_port_postcommit(fake_ctx)

        self.plugin.update_port_status.assert_not_called()
        self.plugin.get_port.assert_called_once_with(
            mock.ANY, fake_port['id'])
        self.assertEqual(2, mock_update_port.call_count)
        mock_notify_dhcp.assert_called_with(fake_port['id'])

    @mock.patch.object(mech_driver.OVNMechanismDriver,
                       '_is_port_provisioning_required', lambda *_: True)
    @mock.patch.object(mech_driver.OVNMechanismDriver, '_notify_dhcp_updated')
    @mock.patch.object(ovn_client.OVNClient, 'update_port')
    def test_update_port_postcommit_revision_mismatch_not_after_live_migration(
            self, mock_update_port, mock_notify_dhcp):
        self.plugin.update_port_status = mock.Mock()
        self.plugin.get_port = mock.Mock(return_value=mock.MagicMock())

        fake_context = mock.MagicMock()
        fake_port = fakes.FakePort.create_one_port(
            attrs={
                'status': const.PORT_STATUS_ACTIVE,
                portbindings.PROFILE: {},
                portbindings.VIF_TYPE: portbindings.VIF_TYPE_OVS}).info()
        original_fake_port = fakes.FakePort.create_one_port(
            attrs={
                'status': const.PORT_STATUS_DOWN,
                portbindings.PROFILE: {},
                portbindings.VIF_TYPE: portbindings.VIF_TYPE_OVS}).info()

        fake_ctx = mock.Mock(current=fake_port, original=original_fake_port,
                             plugin_context=fake_context)
        mock_update_port.side_effect = [
            ovn_exceptions.RevisionConflict(
                resource_id=fake_port['id'],
                resource_type=ovn_const.TYPE_PORTS),
            None]

        self.mech_driver.update_port_postcommit(fake_ctx)

        self.plugin.update_port_status.assert_not_called()
        self.plugin.get_port.assert_not_called()
        self.assertEqual(1, mock_update_port.call_count)
        mock_notify_dhcp.assert_called_with(fake_port['id'])

    def test_agent_alive_true(self):
        chassis_private = self._add_chassis(5)
        for agent_type in (ovn_const.OVN_CONTROLLER_AGENT,
                           ovn_const.OVN_METADATA_AGENT):
            self.mech_driver.nb_ovn.nb_global.nb_cfg = 5
            agent = self._add_chassis_agent(5, agent_type, chassis_private)
            self.assertTrue(agent.alive, "Agent of type %s alive=%s" %
                                         (agent.agent_type, agent.alive))

    def test_agent_alive_true_one_diff(self):
        # Agent should be reported as alive when the nb_cfg delta is 1
        # even if the last update time was old enough.
        nb_cfg = 5
        chassis_private = self._add_chassis(nb_cfg)
        for agent_type in (ovn_const.OVN_CONTROLLER_AGENT,
                           ovn_const.OVN_METADATA_AGENT):
            self.mech_driver.nb_ovn.nb_global.nb_cfg = nb_cfg + 1
            agent = self._add_chassis_agent(nb_cfg, agent_type,
                                            chassis_private)
            now = timeutils.utcnow()
            fake_now = now + datetime.timedelta(cfg.CONF.agent_down_time + 1)
            with mock.patch.object(timeutils, 'utcnow') as get_now:
                get_now.return_value = fake_now
                self.assertTrue(agent.alive, "Agent of type %s alive=%s" %
                                             (agent.agent_type, agent.alive))

    def test_agent_alive_not_timed_out(self):
        nb_cfg = 3
        chassis_private = self._add_chassis(nb_cfg)
        for agent_type in (ovn_const.OVN_CONTROLLER_AGENT,
                           ovn_const.OVN_METADATA_AGENT):
            self.mech_driver.nb_ovn.nb_global.nb_cfg = nb_cfg + 2
            agent = self._add_chassis_agent(nb_cfg, agent_type,
                                            chassis_private)
            self.assertTrue(agent.alive, "Agent of type %s alive=%s" %
                                         (agent.agent_type, agent.alive))

    def test_agent_alive_timed_out(self):
        nb_cfg = 3
        chassis_private = self._add_chassis(nb_cfg)
        for agent_type in (ovn_const.OVN_CONTROLLER_AGENT,
                           ovn_const.OVN_METADATA_AGENT):
            self.mech_driver.nb_ovn.nb_global.nb_cfg = nb_cfg + 2
            now = timeutils.utcnow(with_timezone=True)
            agent = self._add_chassis_agent(nb_cfg, agent_type,
                                            chassis_private)
            fake_now = now + datetime.timedelta(cfg.CONF.agent_down_time + 1)
            with mock.patch.object(timeutils, 'utcnow') as get_now:
                get_now.return_value = fake_now
                self.assertFalse(agent.alive, "Agent of type %s alive=%s" %
                                 (agent.agent_type, agent.alive))

    def test_agent_with_nb_cfg_timestamp_timeout(self):
        nb_cfg = 3
        chassis_private = self._add_chassis(nb_cfg)

        self.mech_driver.nb_ovn.nb_global.nb_cfg = nb_cfg + 2
        updated_at = (timeutils.utcnow_ts() - cfg.CONF.agent_down_time - 1
                      ) * 1000
        chassis_private.nb_cfg_timestamp = updated_at
        agent_type = ovn_const.OVN_CONTROLLER_AGENT
        agent = self._add_chassis_agent(nb_cfg, agent_type,
                                        chassis_private)
        self.assertFalse(agent.alive, "Agent of type %s alive=%s" %
                         (agent.agent_type, agent.alive))

    def test_agent_with_nb_cfg_timestamp_not_timeout(self):
        nb_cfg = 3
        chassis_private = self._add_chassis(nb_cfg)

        self.mech_driver.nb_ovn.nb_global.nb_cfg = nb_cfg + 2
        updated_at = timeutils.utcnow_ts() * 1000
        chassis_private.nb_cfg_timestamp = updated_at
        agent_type = ovn_const.OVN_CONTROLLER_AGENT
        agent = self._add_chassis_agent(nb_cfg, agent_type,
                                        chassis_private)
        self.assertTrue(agent.alive, "Agent of type %s alive=%s" % (
            agent.agent_type, agent.alive))

    def _test__update_dnat_entry_if_needed(self, up=True, dvr=True):
        if dvr:
            ovn_conf.cfg.CONF.set_override(
                'enable_distributed_floating_ip', True, group='ovn')
        port_id = 'fake-port-id'
        fake_ext_mac_key = 'fake-ext-mac-key'
        fake_nat_uuid = uuidutils.generate_uuid()
        nat_row = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'_uuid': fake_nat_uuid, 'external_ids': {
                ovn_const.OVN_FIP_EXT_MAC_KEY: fake_ext_mac_key},
                'external_mac': 'aa:aa:aa:aa:aa:aa'})

        fake_db_find = mock.Mock()
        fake_db_find.execute.return_value = [nat_row]
        self.nb_ovn.db_find.return_value = fake_db_find

        self.mech_driver._update_dnat_entry_if_needed(port_id, up=up)

        if up and dvr:
            # Assert that we are setting the external_mac in the NAT table
            self.nb_ovn.db_set.assert_called_once_with(
                'NAT', fake_nat_uuid, ('external_mac', fake_ext_mac_key))
        else:
            if dvr:
                self.nb_ovn.db_set.assert_not_called()
            else:
                # Assert that we are cleaning the external_mac from the NAT
                # table
                self.nb_ovn.db_clear.assert_called_once_with(
                    'NAT', fake_nat_uuid, 'external_mac')

    def test__update_dnat_entry_if_needed_up_dvr(self):
        self._test__update_dnat_entry_if_needed()

    def test__update_dnat_entry_if_needed_up_no_dvr(self):
        self._test__update_dnat_entry_if_needed(dvr=False)

    def test__update_dnat_entry_if_needed_down_dvr(self):
        self._test__update_dnat_entry_if_needed(up=False)

    def test__update_dnat_entry_if_needed_down_no_dvr(self):
        self._test__update_dnat_entry_if_needed(up=False, dvr=False)

    @mock.patch('neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb.'
                'ovn_client.OVNClient._get_router_ports')
    def _test_update_network_fragmentation(self, new_mtu, expected_opts, grps):
        network_attrs = {external_net.EXTERNAL: True}
        network = self._make_network(
            self.fmt, 'net1', True, as_admin=True,
            arg_list=(external_net.EXTERNAL,),
            **network_attrs)

        with self.subnet(network=network) as subnet:
            with self.port(subnet=subnet,
                           device_owner=const.DEVICE_OWNER_ROUTER_GW) as port:

                grps.return_value = [{'port_id': port['port']['id'],
                    'network_id':network['network']['id']}]

                # Let's update the MTU to something different
                network['network']['mtu'] = new_mtu
                fake_ctx = mock.MagicMock(current=network['network'])
                fake_ctx.plugin_context.session.is_active = False

                self.mech_driver.update_network_postcommit(fake_ctx)

                lrp_name = ovn_utils.ovn_lrouter_port_name(port['port']['id'])
                self.nb_ovn.lrp_set_options.assert_called_once_with(
                    lrp_name, **expected_opts)

    def test_update_network_need_to_frag_enabled(self):
        ovn_conf.cfg.CONF.set_override('ovn_emit_need_to_frag', True,
                                       group='ovn')
        new_mtu = 1234
        expected_opts = {ovn_const.OVN_ROUTER_PORT_GW_MTU_OPTION:
                         str(new_mtu)}
        self._test_update_network_fragmentation(new_mtu, expected_opts)

    def test_update_network_need_to_frag_disabled(self):
        ovn_conf.cfg.CONF.set_override('ovn_emit_need_to_frag', False,
                                       group='ovn')
        new_mtu = 1234
        # Assert that the options column is empty (cleaning up an '
        # existing value if set before)
        expected_opts = {}
        self._test_update_network_fragmentation(new_mtu, expected_opts)

    def test_ping_all_chassis(self):
        self.nb_ovn.nb_global.external_ids = {}
        self.mech_driver.ping_all_chassis()
        self.nb_ovn.check_liveness.assert_called_once_with()

    def test_ping_all_chassis_interval_expired(self):
        timeout = 10
        ovn_conf.cfg.CONF.set_override('agent_down_time', timeout)

        # Pretend the interval is already expired
        time = (timeutils.utcnow(with_timezone=True) -
                datetime.timedelta(seconds=timeout))
        self.nb_ovn.nb_global.external_ids = {
            ovn_const.OVN_LIVENESS_CHECK_EXT_ID_KEY: str(time)}

        update_db = self.mech_driver.ping_all_chassis()
        # Since the interval has expired, assert that the "check_liveness"
        # command has been invoked
        self.nb_ovn.check_liveness.assert_called_once_with()
        # Assert that ping_all_chassis returned True as it updated the db
        self.assertTrue(update_db)

    def test_ping_all_chassis_interval_not_expired(self):
        ovn_conf.cfg.CONF.set_override('agent_down_time', 10)

        # Pretend the interval has NOT yet expired
        time = timeutils.utcnow(with_timezone=True)
        self.nb_ovn.nb_global.external_ids = {
            ovn_const.OVN_LIVENESS_CHECK_EXT_ID_KEY: str(time)}

        update_db = self.mech_driver.ping_all_chassis()
        # Assert that "check_liveness" wasn't invoked
        self.assertFalse(self.nb_ovn.check_liveness.called)
        # Assert ping_all_chassis returned False as it didn't update the db
        self.assertFalse(update_db)

    def test_get_candidates_for_scheduling_availability_zones(self):
        ovn_client = self.mech_driver._ovn_client
        ch0 = fakes.FakeChassis.create(az_list=['az0', 'az1'],
                                       chassis_as_gw=True)
        ch1 = fakes.FakeChassis.create(az_list=['az3', 'az4'],
                                       chassis_as_gw=True)
        ch2 = fakes.FakeChassis.create(az_list=['az2'], chassis_as_gw=True)
        ch3 = fakes.FakeChassis.create(az_list=[], chassis_as_gw=True)
        ch4 = fakes.FakeChassis.create(az_list=['az0'], chassis_as_gw=True)
        ch5 = fakes.FakeChassis.create(az_list=['az2'], chassis_as_gw=False)

        # Fake ovsdbapp lookup
        def fake_lookup(table, chassis_name, default):
            for ch in [ch0, ch1, ch2, ch3, ch4, ch5]:
                if ch.name == chassis_name:
                    return ch
        ovn_client._sb_idl.lookup = fake_lookup

        # The target physnet and availability zones
        physnet = 'public'
        az_hints = ['az0', 'az2']

        cms = [ch0.name, ch1.name, ch2.name, ch3.name, ch4.name, ch5.name]
        ch_physnet = {ch0.name: [physnet], ch1.name: [physnet],
                      ch2.name: [physnet], ch3.name: [physnet],
                      ch4.name: ['another-physnet'],
                      ch5.name: ['yet-another-physnet']}

        candidates = ovn_client.get_candidates_for_scheduling(
            physnet, cms=cms, chassis_physnets=ch_physnet,
            availability_zone_hints=az_hints)

        # Only chassis ch0 and ch2 should match the availability zones
        # hints and physnet we passed to get_candidates_for_scheduling()
        expected_candidates = [ch0.name, ch2.name]
        self.assertEqual(sorted(expected_candidates), sorted(candidates))

    def test_sync_ha_chassis_group(self):
        fake_txn = mock.MagicMock()
        net_attrs = {az_def.AZ_HINTS: ['az0', 'az1', 'az2']}
        fake_net = (
            fakes.FakeNetwork.create_one_network(attrs=net_attrs).info())
        mock.patch.object(self.mech_driver._plugin,
                          'get_network', return_value=fake_net).start()

        ch0 = fakes.FakeChassis.create(az_list=['az0', 'az1'],
                                       chassis_as_gw=True)
        ch1 = fakes.FakeChassis.create(az_list=['az2'], chassis_as_gw=True)
        ch2 = fakes.FakeChassis.create(az_list=['az3'], chassis_as_gw=True)
        ch3 = fakes.FakeChassis.create(az_list=[], chassis_as_gw=True)
        ch4 = fakes.FakeChassis.create(az_list=[], chassis_as_gw=False)
        self.sb_ovn.get_gateway_chassis_from_cms_options.return_value = [
            ch0, ch1, ch2, ch3, ch4]

        # Invoke the method
        hcg_cmd = ovn_utils.sync_ha_chassis_group(
            self.context, fake_net['id'], self.nb_ovn, self.sb_ovn, fake_txn)

        # Assert it attempts to add the chassis group for that network
        ha_ch_grp_name = ovn_utils.ovn_name(fake_net['id'])
        ext_ids = {ovn_const.OVN_AZ_HINTS_EXT_ID_KEY: 'az0,az1,az2'}
        self.nb_ovn.ha_chassis_group_add.assert_called_once_with(
            ha_ch_grp_name, may_exist=True, external_ids=ext_ids)

        # Assert that only Chassis belonging to the AZ hints are
        # added to the HA Chassis Group for that network
        expected_calls = [
            mock.call(hcg_cmd, ch0.name, priority=mock.ANY),
            mock.call(hcg_cmd, ch1.name, priority=mock.ANY)]
        self.nb_ovn.ha_chassis_group_add_chassis.assert_has_calls(
            expected_calls, any_order=True)

    def test_sync_ha_chassis_group_no_az_hints(self):
        fake_txn = mock.MagicMock()
        # No AZ hints are specified for that network
        net_attrs = {az_def.AZ_HINTS: []}
        fake_net = (
            fakes.FakeNetwork.create_one_network(attrs=net_attrs).info())
        mock.patch.object(self.mech_driver._plugin,
                          'get_network', return_value=fake_net).start()

        ch0 = fakes.FakeChassis.create(az_list=['az0', 'az1'],
                                       chassis_as_gw=True)
        ch1 = fakes.FakeChassis.create(az_list=['az2'], chassis_as_gw=True)
        ch2 = fakes.FakeChassis.create(az_list=[], chassis_as_gw=True)
        ch3 = fakes.FakeChassis.create(az_list=[], chassis_as_gw=True)
        ch4 = fakes.FakeChassis.create(az_list=[], chassis_as_gw=False)
        self.sb_ovn.get_gateway_chassis_from_cms_options.return_value = [
            ch0, ch1, ch2, ch3, ch4]

        # Invoke the method
        hcg_cmd = ovn_utils.sync_ha_chassis_group(
            self.context, fake_net['id'], self.nb_ovn, self.sb_ovn, fake_txn)

        # Assert it attempts to add the chassis group for that network
        ha_ch_grp_name = ovn_utils.ovn_name(fake_net['id'])
        ext_ids = {ovn_const.OVN_AZ_HINTS_EXT_ID_KEY: ''}
        self.nb_ovn.ha_chassis_group_add.assert_called_once_with(
            ha_ch_grp_name, may_exist=True, external_ids=ext_ids)

        # Assert that only Chassis that are gateways and DOES NOT
        # belong to any AZs are added
        expected_calls = [
            mock.call(hcg_cmd, ch2.name, priority=mock.ANY),
            mock.call(hcg_cmd, ch3.name, priority=mock.ANY)]
        self.nb_ovn.ha_chassis_group_add_chassis.assert_has_calls(
            expected_calls, any_order=True)

    @mock.patch.object(mech_driver, 'LOG')
    def test_responsible_for_ports_allocation(self, mock_log):
        rp1 = str(place_utils.device_resource_provider_uuid(
            namespace=self.rp_ns, host='compute1', device='br-ext1'))
        allocation = {'rp_group1': rp1}
        context = test_mech_agent.FakePortContext(
            'agent', 'agents', 'segments', profile={'allocation': allocation})
        chassis = fakes.FakeChassis.create(
            az_list=['az2'], chassis_as_gw=True,
            bridge_mappings=['public1:br-ext1', 'public2:br-ext2',
                             'public3:br-ext3'],
            rp_bandwidths=['br-ext1:1000:2000', 'br-ext2:3000:4000'],
            rp_inventory_defaults={'allocation_ratio': 1.0, 'min_unit': 5},
            rp_hypervisors=['br-ext1:compute1', 'br-ext2:compute2'])
        self.placement_ext._driver._sb_idl.chassis_list.return_value.execute. \
            return_value = [chassis]
        with mock.patch.object(self.placement_ext, 'name2uuid') as \
                mock_name2uuid:
            mock_name2uuid.return_value = {'compute1': 'uuid_compute1',
                                           'compute2': 'uuid_compute2'}
            self.assertTrue(
                self.mech_driver.responsible_for_ports_allocation(context))
        mock_log.debug.assert_called_once_with(
            'Chassis %s is reponsible of the resource provider %s',
            chassis.name, mock.ANY)

    def test_responsible_for_ports_allocation_hostname_not_present(self):
        rp1 = str(place_utils.device_resource_provider_uuid(
            namespace=self.rp_ns, host='compute1', device='br-ext1'))
        allocation = {'rp_group1': rp1}
        context = test_mech_agent.FakePortContext(
            'agent', 'agents', 'segments', profile={'allocation': allocation})
        # "compute1" is not present in "rp_hypervisors"
        chassis = fakes.FakeChassis.create(
            az_list=['az2'], chassis_as_gw=True,
            bridge_mappings=['public1:br-ext1', 'public2:br-ext2',
                             'public3:br-ext3'],
            rp_bandwidths=['br-ext1:1000:2000', 'br-ext2:3000:4000'],
            rp_inventory_defaults={'allocation_ratio': 1.0, 'min_unit': 5},
            rp_hypervisors=['br-ext2:compute2'])
        self.placement_ext._driver._sb_idl.chassis_list.return_value.execute. \
            return_value = [chassis]
        with mock.patch.object(self.placement_ext, 'name2uuid') as \
                mock_name2uuid:
            mock_name2uuid.return_value = {'compute2': 'uuid_compute2'}
        self.assertFalse(
            self.mech_driver.responsible_for_ports_allocation(context))

    @mock.patch.object(mech_driver, 'LOG')
    def test_responsible_for_ports_allocation_multiple_chassis(self, mock_log):
        rp1 = str(place_utils.device_resource_provider_uuid(
            namespace=self.rp_ns, host='compute1', device='br-ext1'))
        allocation = {'rp_group1': rp1}
        context = test_mech_agent.FakePortContext(
            'agent', 'agents', 'segments', profile={'allocation': allocation})
        chassis = []
        for _ in range(2):
            chassis.append(fakes.FakeChassis.create(
                az_list=['az2'], chassis_as_gw=True,
                bridge_mappings=['public1:br-ext1', 'public2:br-ext2',
                                 'public3:br-ext3'],
                rp_bandwidths=['br-ext1:1000:2000', 'br-ext2:3000:4000'],
                rp_inventory_defaults={'allocation_ratio': 1.0, 'min_unit': 5},
                rp_hypervisors=['br-ext1:compute1', 'br-ext2:compute2']))
        self.placement_ext._driver._sb_idl.chassis_list.return_value.execute. \
            return_value = chassis
        with mock.patch.object(self.placement_ext, 'name2uuid') as \
                mock_name2uuid:
            mock_name2uuid.return_value = {'compute1': 'uuid_compute1',
                                           'compute2': 'uuid_compute2'}
            self.assertFalse(
                self.mech_driver.responsible_for_ports_allocation(context))
        mock_log.error.assert_called_once()

    def test_responsible_for_ports_allocation_no_chassis(self):
        rp1 = str(place_utils.device_resource_provider_uuid(
            namespace=self.rp_ns, host='host0', device='eth1'))
        context = test_mech_agent.FakePortContext(
            'agent', 'agents', 'segments', profile={'allocation': rp1})
        self.assertFalse(
            self.mech_driver.responsible_for_ports_allocation(context))

    def test_update_network_segmentation_id(self):
        new_vlan_tag = 123
        net_arg = {pnet.NETWORK_TYPE: 'vlan',
                   pnet.PHYSICAL_NETWORK: 'physnet1',
                   pnet.SEGMENTATION_ID: '1'}
        net = self._make_network(self.fmt, 'net1', True,
                                 as_admin=True,
                                 arg_list=(pnet.NETWORK_TYPE,
                                           pnet.PHYSICAL_NETWORK,
                                           pnet.SEGMENTATION_ID,),
                                 **net_arg)['network']
        # Make sure the network was created with 1 VLAN segment
        segments = segments_db.get_network_segments(self.context, net['id'])
        segment = segments[0]
        self.assertEqual(len(segments), 1)
        self.assertEqual(segment['segmentation_id'], 1)

        # Issue an update to the network changing the segmentation_id
        data = {'network': {pnet.SEGMENTATION_ID: new_vlan_tag}}
        req = self.new_update_request('networks', data, net['id'],
                                      as_admin=True)
        res = self.deserialize(self.fmt, req.get_response(self.api))
        self.assertEqual(new_vlan_tag, res['network'][pnet.SEGMENTATION_ID])

        # Assert the tag was changed in the Neutron database
        segments = segments_db.get_network_segments(self.context, net['id'])
        segment = segments[0]
        self.assertEqual(len(segments), 1)
        self.assertEqual(segment['segmentation_id'], new_vlan_tag)

        # Assert the tag was changed in the OVN database
        expected_call = mock.call(
            lport_name=ovn_utils.ovn_provnet_port_name(segment['id']),
            tag=new_vlan_tag, if_exists=True)
        self.nb_ovn.set_lswitch_port.assert_has_calls([expected_call])


class OVNMechanismDriverTestCase(MechDriverSetupBase,
                                 test_plugin.Ml2PluginV2TestCase):
    _mechanism_drivers = ['logger', 'ovn']

    def setUp(self):
        ovn_conf.register_opts()
        cfg.CONF.set_override('tenant_network_types',
                              ['geneve'],
                              group='ml2')
        cfg.CONF.set_override('vni_ranges',
                              ['1:65536'],
                              group='ml2_type_geneve')
        # ensure viable minimum is set for OVN's Geneve
        cfg.CONF.set_override('max_header_size', 38,
                              group='ml2_type_geneve')
        ovn_conf.cfg.CONF.set_override('dns_servers', ['8.8.8.8'], group='ovn')
        mock.patch.object(impl_idl_ovn.Backend, 'schema_helper').start()
        super(OVNMechanismDriverTestCase, self).setUp()
        cfg.CONF.set_override('global_physnet_mtu', 1550)
        # Make sure the node and target_node for the hash ring in the
        # mechanism driver matches
        node_uuid = uuidutils.generate_uuid()
        p = mock.patch.object(hash_ring_manager.HashRingManager, 'get_node',
                              return_value=node_uuid)
        p.start()
        self.addCleanup(p.stop)
        self.driver.node_uuid = node_uuid
        self.driver.hash_ring_group = 'fake_hash_ring_group'

        self.mech_driver._insert_port_provisioning_block = mock.Mock()
        p = mock.patch.object(ovn_utils, 'get_revision_number', return_value=1)
        p.start()
        self.addCleanup(p.stop)


class TestOVNMechanismDriverBasicGet(test_plugin.TestMl2BasicGet,
                                     OVNMechanismDriverTestCase):
    pass


class TestOVNMechanismDriverV2HTTPResponse(test_plugin.TestMl2V2HTTPResponse,
                                           OVNMechanismDriverTestCase):
    pass


class TestOVNMechanismDriverNetworksV2(test_plugin.TestMl2NetworksV2,
                                       OVNMechanismDriverTestCase):

    def test__update_segmentation_id_ports_wrong_vif_type(self):
        """Skip the Update Segmentation ID tests

        Currently Segmentation ID cannot be updated till
        https://review.openstack.org/#/c/632984/ is merged
        to allow OVS Agents and thus OVN Mechanism Driver to allow
        updation of Segmentation IDs. Till then the test  needs to be skipped
        """
        pass

    def test__update_segmentation_id_ports(self):
        """Skip the Update Segmentation ID tests

        Currently Segmentation ID cannot be updated till
        https://review.openstack.org/#/c/632984/ is merged
        to allow OVS Agents and thus OVN Mechanism Driver to allow
        updation of Segmentation IDs. Till then the test  needs to be skipped
        """
        pass


class TestOVNMechanismDriverSubnetsV2(test_plugin.TestMl2SubnetsV2,
                                      OVNMechanismDriverTestCase):

    def setUp(self):
        ovn_conf.register_opts()
        # Disable metadata so that we don't interfere with existing tests
        # in Neutron tree. Doing this because some of the tests assume that
        # first IP address in a subnet will be available and this is not true
        # with metadata since it will book an IP address on each subnet.
        ovn_conf.cfg.CONF.set_override('ovn_metadata_enabled', False,
                                       group='ovn')
        super(TestOVNMechanismDriverSubnetsV2, self).setUp()

    # NOTE(rtheis): Mock the OVN port update since it is getting subnet
    # information for ACL processing. This interferes with the update_port
    # mock already done by the test.
    def test_subnet_update_ipv4_and_ipv6_pd_v6stateless_subnets(self):
        with mock.patch.object(self.mech_driver._ovn_client, 'update_port'),\
                mock.patch.object(self.mech_driver._ovn_client,
                                  '_get_subnet_dhcp_options_for_port',
                                  return_value={}):
            super(TestOVNMechanismDriverSubnetsV2, self).\
                test_subnet_update_ipv4_and_ipv6_pd_v6stateless_subnets()

    # NOTE(rtheis): Mock the OVN port update since it is getting subnet
    # information for ACL processing. This interferes with the update_port
    # mock already done by the test.
    def test_subnet_update_ipv4_and_ipv6_pd_slaac_subnets(self):
        with mock.patch.object(self.mech_driver._ovn_client, 'update_port'),\
                mock.patch.object(self.mech_driver._ovn_client,
                                  '_get_subnet_dhcp_options_for_port',
                                  return_value={}):
            super(TestOVNMechanismDriverSubnetsV2, self).\
                test_subnet_update_ipv4_and_ipv6_pd_slaac_subnets()

    # NOTE(numans) Overriding the base test case here because the base test
    # case creates a network with vxlan type and OVN mech driver doesn't
    # support it.
    def test_create_subnet_check_mtu_in_mech_context(self):
        plugin = directory.get_plugin()
        plugin.mechanism_manager.create_subnet_precommit = mock.Mock()
        net_arg = {pnet.NETWORK_TYPE: 'geneve',
                   pnet.SEGMENTATION_ID: '1'}
        network = self._make_network(self.fmt, 'net1', True,
                                     as_admin=True,
                                     arg_list=(pnet.NETWORK_TYPE,
                                               pnet.SEGMENTATION_ID,),
                                     **net_arg)
        with self.subnet(network=network):
            mock_subnet_pre = plugin.mechanism_manager.create_subnet_precommit
            observerd_mech_context = mock_subnet_pre.call_args_list[0][0][0]
            self.assertEqual(network['network']['mtu'],
                             observerd_mech_context.network.current['mtu'])


class TestOVNMechanismDriverPortsV2(test_plugin.TestMl2PortsV2,
                                    OVNMechanismDriverTestCase):

    def setUp(self):
        ovn_conf.register_opts()
        # Disable metadata so that we don't interfere with existing tests
        # in Neutron tree. Doing this because some of the tests assume that
        # first IP address in a subnet will be available and this is not true
        # with metadata since it will book an IP address on each subnet.
        ovn_conf.cfg.CONF.set_override('ovn_metadata_enabled', False,
                                       group='ovn')
        super(TestOVNMechanismDriverPortsV2, self).setUp()

    # NOTE(rtheis): Override this test to verify that updating
    # a port MAC fails when the port is bound.
    def test_update_port_mac(self):
        self.check_update_port_mac(
            host_arg={portbindings.HOST_ID: 'fake-host'},
            arg_list=(portbindings.HOST_ID,),
            expected_status=exc.HTTPConflict.code,
            expected_error='PortBound')


class TestOVNMechanismDriverAllowedAddressPairs(
        test_plugin.TestMl2AllowedAddressPairs,
        OVNMechanismDriverTestCase):
    pass


class TestOVNMechanismDriverPortSecurity(
        test_ext_portsecurity.PSExtDriverTestCase,
        OVNMechanismDriverTestCase):
    pass


class TestOVNMechanismDriverSegment(MechDriverSetupBase,
                                    test_segment.HostSegmentMappingTestCase):
    _mechanism_drivers = ['logger', 'ovn']

    def setUp(self):
        cfg.CONF.set_override('max_header_size', 38,
                              group='ml2_type_geneve')
        mock.patch.object(impl_idl_ovn.Backend, 'schema_helper').start()
        super(TestOVNMechanismDriverSegment, self).setUp()
        p = mock.patch.object(ovn_utils, 'get_revision_number', return_value=1)
        p.start()
        self.addCleanup(p.stop)
        self.context = context.get_admin_context()

    def _test_segment_host_mapping(self):
        # Disable the callback to update SegmentHostMapping by default, so
        # that update_segment_host_mapping is the only path to add the mapping
        registry.unsubscribe(
            self.mech_driver._add_segment_host_mapping_for_segment,
            resources.SEGMENT, events.AFTER_CREATE)
        host = 'hostname'
        with self.network() as network:
            network = network['network']
        segment1 = self._test_create_segment(
            network_id=network['id'], physical_network='physnet1',
            segmentation_id=200, network_type='vlan')['segment']

        # As geneve networks mtu shouldn't be more than 1442 considering the
        # Geneve max_header_size for OVN must be at least 38), update it
        data = {'network': {'mtu': 1442}}
        req = self.new_update_request('networks', data, network['id'])
        res = self.deserialize(self.fmt, req.get_response(self.api))
        self.assertEqual(1442, res['network']['mtu'])

        self._test_create_segment(
            network_id=network['id'],
            segmentation_id=200,
            network_type='geneve')
        self.mech_driver.update_segment_host_mapping(host, ['physnet1'])
        segments_host_db = self._get_segments_for_host(host)
        self.assertEqual({segment1['id']}, set(segments_host_db))
        return network['id'], host

    def test_update_segment_host_mapping(self):
        network_id, host = self._test_segment_host_mapping()

        # Update the mapping
        segment2 = self._test_create_segment(
            network_id=network_id, physical_network='physnet2',
            segmentation_id=201, network_type='vlan')['segment']
        self.mech_driver.update_segment_host_mapping(host, ['physnet2'])
        segments_host_db = self._get_segments_for_host(host)
        self.assertEqual({segment2['id']}, set(segments_host_db))

    def test_clear_segment_host_mapping(self):
        _, host = self._test_segment_host_mapping()

        # Clear the mapping
        self.mech_driver.update_segment_host_mapping(host, [])
        segments_host_db = self._get_segments_for_host(host)
        self.assertEqual({}, segments_host_db)

    def test_update_segment_host_mapping_with_new_segment(self):
        hostname_with_physnets = {'hostname1': ['physnet1', 'physnet2'],
                                  'hostname2': ['physnet1']}
        ovn_sb_api = self.mech_driver.sb_ovn
        ovn_sb_api.get_chassis_hostname_and_physnets.return_value = (
            hostname_with_physnets)
        self.mech_driver.subscribe()
        with self.network() as network:
            network_id = network['network']['id']
        segment = self._test_create_segment(
            network_id=network_id, physical_network='physnet2',
            segmentation_id=201, network_type='vlan')['segment']
        segments_host_db1 = self._get_segments_for_host('hostname1')
        # A new SegmentHostMapping should be created for hostname1
        self.assertEqual({segment['id']}, set(segments_host_db1))

        segments_host_db2 = self._get_segments_for_host('hostname2')
        self.assertFalse(set(segments_host_db2))

    def test_create_segment_create_localnet_port(self):
        ovn_nb_api = self.mech_driver.nb_ovn
        with self.network() as network:
            net = network['network']
        new_segment = self._test_create_segment(
            network_id=net['id'], physical_network='physnet1',
            segmentation_id=200, network_type='vlan')['segment']
        ovn_nb_api.create_lswitch_port.assert_called_once_with(
            addresses=[ovn_const.UNKNOWN_ADDR],
            external_ids={},
            lport_name=ovn_utils.ovn_provnet_port_name(new_segment['id']),
            lswitch_name=ovn_utils.ovn_name(net['id']),
            options={'network_name': 'physnet1',
                     ovn_const.LSP_OPTIONS_MCAST_FLOOD_REPORTS: 'true',
                     ovn_const.LSP_OPTIONS_MCAST_FLOOD: 'false',
                     ovn_const.LSP_OPTIONS_LOCALNET_LEARN_FDB: 'false'},
            tag=200,
            type='localnet')
        ovn_nb_api.create_lswitch_port.reset_mock()
        new_segment = self._test_create_segment(
            network_id=net['id'], physical_network='physnet2',
            segmentation_id=300, network_type='vlan')['segment']
        ovn_nb_api.create_lswitch_port.assert_called_once_with(
            addresses=[ovn_const.UNKNOWN_ADDR],
            external_ids={},
            lport_name=ovn_utils.ovn_provnet_port_name(new_segment['id']),
            lswitch_name=ovn_utils.ovn_name(net['id']),
            options={'network_name': 'physnet2',
                     ovn_const.LSP_OPTIONS_MCAST_FLOOD_REPORTS: 'true',
                     ovn_const.LSP_OPTIONS_MCAST_FLOOD: 'false',
                     ovn_const.LSP_OPTIONS_LOCALNET_LEARN_FDB: 'false'},
            tag=300,
            type='localnet')
        segments = segments_db.get_network_segments(
            self.context, net['id'])
        self.assertEqual(len(segments), 3)

    def test_delete_segment_delete_localnet_port(self):
        ovn_nb_api = self.mech_driver.nb_ovn
        with self.network() as network:
            net = network['network']
        segment = self._test_create_segment(
            network_id=net['id'], physical_network='physnet1',
            segmentation_id=200, network_type='vlan')['segment']
        self._delete('segments', segment['id'], as_admin=True)
        ovn_nb_api.delete_lswitch_port.assert_called_once_with(
            lport_name=ovn_utils.ovn_provnet_port_name(segment['id']),
            lswitch_name=ovn_utils.ovn_name(net['id']))

    def test_delete_segment_delete_localnet_port_compat_name(self):
        ovn_nb_api = self.mech_driver.nb_ovn
        with self.network() as network:
            net = network['network']
        seg_1 = self._test_create_segment(
            network_id=net['id'], physical_network='physnet1',
            segmentation_id=200, network_type='vlan')['segment']
        seg_2 = self._test_create_segment(
            network_id=net['id'], physical_network='physnet2',
            segmentation_id=300, network_type='vlan')['segment']
        # Lets pretend that segment_1 is old and its localnet
        # port is based on neutron network id.
        ovn_nb_api.fake_ls_row.ports = [
            fakes.FakeOVNPort.create_one_port(
                attrs={
                    'options': {'network_name': 'physnet1'},
                    'tag': 200,
                    'name': ovn_utils.ovn_provnet_port_name(net['id'])}),
            fakes.FakeOVNPort.create_one_port(
                attrs={
                    'options': {'network_name': 'physnet2'},
                    'tag': 300,
                    'name': ovn_utils.ovn_provnet_port_name(seg_2['id'])})]
        self._delete('segments', seg_1['id'], as_admin=True)
        ovn_nb_api.delete_lswitch_port.assert_called_once_with(
            lport_name=ovn_utils.ovn_provnet_port_name(net['id']),
            lswitch_name=ovn_utils.ovn_name(net['id']))
        ovn_nb_api.delete_lswitch_port.reset_mock()
        self._delete('segments', seg_2['id'], as_admin=True)
        ovn_nb_api.delete_lswitch_port.assert_called_once_with(
            lport_name=ovn_utils.ovn_provnet_port_name(seg_2['id']),
            lswitch_name=ovn_utils.ovn_name(net['id']))

    def _test_segments_helper(self):
        self.mech_driver.nb_ovn.get_subnet_dhcp_options.return_value = {
            'subnet': {'uuid': 'foo-uuid',
                       'options': {'server_mac': 'ca:fe:ca:fe:ca:fe'},
                       'cidr': '1.2.3.4/5'},
            'ports': {}}
        ovn_conf.cfg.CONF.set_override('ovn_metadata_enabled', True,
                                       group='ovn')

        # Create first segment and associate subnet to it.
        with self.network() as n:
            self.net = n
        self.seg_1 = self._test_create_segment(
            network_id=self.net['network']['id'], physical_network='physnet1',
            segmentation_id=200, network_type='vlan')['segment']
        with self.subnet(network=self.net, cidr='10.0.1.0/24',
                         segment_id=self.seg_1['id']) as subnet:
            self.sub_1 = subnet

        # Create second segment and subnet linked to it
        self.seg_2 = self._test_create_segment(
            network_id=self.net['network']['id'], physical_network='physnet2',
            segmentation_id=300, network_type='vlan')['segment']
        with self.subnet(network=self.net, cidr='10.0.2.0/24',
                         segment_id=self.seg_2['id']) as subnet:
            self.sub_2 = subnet

    # TODO(lucasagomes): This test should use <mock>.assert_has_calls()
    # to validate if the method was called with the correct values instead
    # of peeking at call_args_list otherwise every time there's a new
    # call to the mocked method the indexes will change
    def test_create_segments_subnet_metadata_ip_allocation(self):
        self._test_segments_helper()
        ovn_nb_api = self.mech_driver.nb_ovn

        # Assert that metadata address has been allocated from previously
        # created subnet.
        self.assertIn(
            '10.0.1.2',
            ovn_nb_api.set_lswitch_port.call_args_list[2][1]['addresses'][0])

        # Assert that the second subnet address also has been allocated for
        # metadata port.
        self.assertIn(
            '10.0.2.2',
            ovn_nb_api.set_lswitch_port.call_args_list[6][1]['addresses'][0])
        # Assert also that the first subnet address is in this update
        self.assertIn(
            '10.0.1.2',
            ovn_nb_api.set_lswitch_port.call_args_list[6][1]['addresses'][0])
        self.assertEqual(
            ovn_nb_api.set_lswitch_port.call_count, 7)

        # Make sure both updates where on same metadata port
        args_list = ovn_nb_api.set_lswitch_port.call_args_list
        self.assertEqual(
            'ovnmeta-%s' % self.net['network']['id'],
            args_list[6][1]['external_ids']['neutron:device_id'])
        self.assertEqual(
            args_list[6][1]['external_ids']['neutron:device_id'],
            args_list[2][1]['external_ids']['neutron:device_id'])
        self.assertEqual(
            args_list[6][1]['external_ids']['neutron:device_owner'],
            args_list[2][1]['external_ids']['neutron:device_owner'])
        self.assertEqual(
            const.DEVICE_OWNER_DISTRIBUTED,
            args_list[6][1]['external_ids']['neutron:device_owner'])

    def test_create_segments_mixed_allocation_prohibited(self):
        self._test_segments_helper()

        # Try to create 'normal' port with ip address
        # allocations from multiple segments
        kwargs = {'fixed_ips': [{'ip_address': '10.0.1.100',
                                 'subnet_id': self.sub_1['subnet']['id']},
                                {'ip_address': '10.0.2.100',
                                 'subnet_id': self.sub_2['subnet']['id']}]}

        # Make sure that this allocation is prohibited.
        self._create_port(
            self.fmt, self.net['network']['id'],
            arg_list=('fixed_ips',), **kwargs,
            expected_res_status=400)

    def test_create_delete_segment_distributed_service_port_not_touched(self):
        self._test_segments_helper()
        ovn_nb_api = self.mech_driver.nb_ovn

        # Delete second subnet
        self._delete('subnets', self.sub_2['subnet']['id'])
        # Make sure that shared metadata port wasn't deleted.
        ovn_nb_api.delete_lswitch_port.assert_not_called()

        # Delete first subnet
        self._delete('subnets', self.sub_1['subnet']['id'])
        # Make sure that the metadata port wasn't deleted.
        ovn_nb_api.delete_lswitch_port.assert_not_called()

        # Delete both segments
        self._delete('segments', self.seg_2['id'], as_admin=True)
        self._delete('segments', self.seg_1['id'], as_admin=True)

        # Make sure that the metadata port wasn't deleted.
        deleted_ports = [
            port[1]['lport_name']
            for port in ovn_nb_api.delete_lswitch_port.call_args_list]
        self.assertNotIn(
            'ovnmeta-%s' % self.net['network']['id'],
            deleted_ports)
        self.assertEqual(
            2,
            ovn_nb_api.delete_lswitch_port.call_count)

        # Only on network deletion the metadata port is deleted.
        self._delete('networks', self.net['network']['id'])
        self.assertEqual(
            3,
            ovn_nb_api.delete_lswitch_port.call_count)

    def test_check_segment_for_agent(self):
        segment = {'physical_network': 'physnet1'}
        agent = {'agent_type': ovn_const.OVN_METADATA_AGENT}
        self.assertFalse(
            self.mech_driver.check_segment_for_agent(segment, agent))

        agent = {'agent_type': ovn_const.OVN_CONTROLLER_AGENT,
                 'configurations': {}}
        self.assertFalse(
            self.mech_driver.check_segment_for_agent(segment, agent))

        agent['configurations'] = {'bridge-mappings': 'physnet2:br-ex2'}
        self.assertFalse(
            self.mech_driver.check_segment_for_agent(segment, agent))

        agent['configurations'] = {'bridge-mappings': 'physnet1:br-ex1'}
        self.assertTrue(
            self.mech_driver.check_segment_for_agent(segment, agent))

        agent['configurations'] = {
            'bridge-mappings': 'physnet1:br-ex1,physnet1:br-ex2'}
        self.assertRaises(ValueError, self.mech_driver.check_segment_for_agent,
            segment, agent)


@mock.patch.object(n_net, 'get_random_mac', lambda *_: '01:02:03:04:05:06')
class TestOVNMechanismDriverDHCPOptions(OVNMechanismDriverTestCase):

    def _test_get_ovn_dhcp_options_helper(self, subnet, network,
                                          expected_dhcp_options,
                                          service_mac=None):
        dhcp_options = self.mech_driver._ovn_client._get_ovn_dhcp_options(
            subnet, network, service_mac)
        self.assertEqual(expected_dhcp_options, dhcp_options)

    def test_get_ovn_dhcp_options(self):
        subnet = {'id': 'foo-subnet', 'network_id': 'network-id',
                  'cidr': '10.0.0.0/24',
                  'ip_version': 4,
                  'enable_dhcp': True,
                  'gateway_ip': '10.0.0.1',
                  'dns_nameservers': ['7.7.7.7', '8.8.8.8'],
                  'host_routes': [{'destination': '20.0.0.4',
                                   'nexthop': '10.0.0.100'}]}
        network = {'id': 'network-id', 'mtu': 1400}

        expected_dhcp_options = {'cidr': '10.0.0.0/24',
                                 'external_ids': {
                                     'subnet_id': 'foo-subnet',
                                     ovn_const.OVN_REV_NUM_EXT_ID_KEY: '1'}}
        expected_dhcp_options['options'] = {
            'server_id': subnet['gateway_ip'],
            'server_mac': '01:02:03:04:05:06',
            'lease_time': str(12 * 60 * 60),
            'mtu': '1400',
            'router': subnet['gateway_ip'],
            'dns_server': '{7.7.7.7, 8.8.8.8}',
            'classless_static_route':
            '{20.0.0.4,10.0.0.100, 0.0.0.0/0,10.0.0.1}'
        }

        self._test_get_ovn_dhcp_options_helper(subnet, network,
                                               expected_dhcp_options)
        expected_dhcp_options['options']['server_mac'] = '11:22:33:44:55:66'
        self._test_get_ovn_dhcp_options_helper(subnet, network,
                                               expected_dhcp_options,
                                               service_mac='11:22:33:44:55:66')

    def test_get_ovn_dhcp_options_dhcp_disabled(self):
        subnet = {'id': 'foo-subnet', 'network_id': 'network-id',
                  'cidr': '10.0.0.0/24',
                  'ip_version': 4,
                  'enable_dhcp': False,
                  'gateway_ip': '10.0.0.1',
                  'dns_nameservers': ['7.7.7.7', '8.8.8.8'],
                  'host_routes': [{'destination': '20.0.0.4',
                                   'nexthop': '10.0.0.100'}]}
        network = {'id': 'network-id', 'mtu': 1400}

        expected_dhcp_options = {'cidr': '10.0.0.0/24',
                                 'external_ids': {
                                     'subnet_id': 'foo-subnet',
                                     ovn_const.OVN_REV_NUM_EXT_ID_KEY: '1'},
                                 'options': {}}

        self._test_get_ovn_dhcp_options_helper(subnet, network,
                                               expected_dhcp_options)

    def test_get_ovn_dhcp_options_no_gw_ip(self):
        subnet = {'id': 'foo-subnet', 'network_id': 'network-id',
                  'cidr': '10.0.0.0/24',
                  'ip_version': 4,
                  'enable_dhcp': True,
                  'gateway_ip': None,
                  'dns_nameservers': ['7.7.7.7', '8.8.8.8'],
                  'host_routes': [{'destination': '20.0.0.4',
                                   'nexthop': '10.0.0.100'}]}
        network = {'id': 'network-id', 'mtu': 1400}

        expected_dhcp_options = {'cidr': '10.0.0.0/24',
                                 'external_ids': {
                                     'subnet_id': 'foo-subnet',
                                     ovn_const.OVN_REV_NUM_EXT_ID_KEY: '1'},
                                 'options': {}}

        self._test_get_ovn_dhcp_options_helper(subnet, network,
                                               expected_dhcp_options)

    def test_get_ovn_dhcp_options_no_gw_ip_but_metadata_ip(self):
        subnet = {'id': 'foo-subnet', 'network_id': 'network-id',
                  'cidr': '10.0.0.0/24',
                  'ip_version': 4,
                  'enable_dhcp': True,
                  'dns_nameservers': [],
                  'host_routes': [],
                  'gateway_ip': None}
        network = {'id': 'network-id', 'mtu': 1400}

        expected_dhcp_options = {
            'cidr': '10.0.0.0/24',
            'external_ids': {'subnet_id': 'foo-subnet',
                             ovn_const.OVN_REV_NUM_EXT_ID_KEY: '1'},
            'options': {'server_id': '10.0.0.2',
                        'server_mac': '01:02:03:04:05:06',
                        'dns_server': '{8.8.8.8}',
                        'lease_time': str(12 * 60 * 60),
                        'mtu': '1400',
                        'classless_static_route':
                            '{169.254.169.254/32,10.0.0.2}'}}

        with mock.patch.object(self.mech_driver._ovn_client,
                               '_find_metadata_port_ip',
                               return_value='10.0.0.2'):
            self._test_get_ovn_dhcp_options_helper(subnet, network,
                                                   expected_dhcp_options)

    def test_get_ovn_dhcpv4_options_ovn_conf_ip4_ip6_dns(self):
        ovn_conf.cfg.CONF.set_override('dns_servers',
                                       '8.8.8.8,2001:db8::8888',
                                       group='ovn')
        subnet = {'id': 'foo-subnet', 'network_id': 'network-id',
                  'cidr': '10.0.0.0/24',
                  'ip_version': 4,
                  'enable_dhcp': True,
                  'host_routes': [],
                  'gateway_ip': '10.0.0.1'}
        network = {'id': 'network-id', 'mtu': 1400}

        expected_dhcpv4_options = {'cidr': subnet['cidr'],
                                   'external_ids': {
                                   'subnet_id': subnet['id'],
                                   ovn_const.OVN_REV_NUM_EXT_ID_KEY: '1'}}
        expected_dhcpv4_options['options'] = {
            'server_id': subnet['gateway_ip'],
            'server_mac': '01:02:03:04:05:06',
            'lease_time': str(12 * 60 * 60),
            'mtu': str(network['mtu']),
            'router': subnet['gateway_ip'],
            'dns_server': '{8.8.8.8}'
        }

        self._test_get_ovn_dhcp_options_helper(subnet, network,
                                               expected_dhcpv4_options)

    def test_get_ovn_dhcpv6_options_ovn_conf_ip4_ip6_dns(self):
        ovn_conf.cfg.CONF.set_override('dns_servers',
                                       '8.8.8.8,2001:db8::8888',
                                       group='ovn')
        subnet = {'id': 'foo-subnet', 'network_id': 'network-id',
                  'cidr': '2001:db8::/64',
                  'ip_version': 6,
                  'enable_dhcp': True,
                  'host_routes': [],
                  'gateway_ip': '2001:db8::1'}
        network = {'id': 'network-id', 'mtu': 1400}

        expected_dhcpv6_options = {'cidr': subnet['cidr'],
                                   'external_ids': {
                                   'subnet_id': subnet['id'],
                                   ovn_const.OVN_REV_NUM_EXT_ID_KEY: '1'}}
        expected_dhcpv6_options['options'] = {
            'server_id': '01:02:03:04:05:06',
            'dns_server': '{2001:db8::8888}'
        }

        self._test_get_ovn_dhcp_options_helper(subnet, network,
                                               expected_dhcpv6_options)

    def test_get_ovn_dhcp_options_with_global_options(self):
        ovn_conf.cfg.CONF.set_override('ovn_dhcp4_global_options',
                                       'ntp_server:8.8.8.8,'
                                       'mtu:9000,'
                                       'wpad:',
                                       group='ovn')

        subnet = {'id': 'foo-subnet', 'network_id': 'network-id',
                  'cidr': '10.0.0.0/24',
                  'ip_version': 4,
                  'enable_dhcp': True,
                  'gateway_ip': '10.0.0.1',
                  'dns_nameservers': ['7.7.7.7', '8.8.8.8'],
                  'host_routes': [{'destination': '20.0.0.4',
                                   'nexthop': '10.0.0.100'}]}
        network = {'id': 'network-id', 'mtu': 1400}

        expected_dhcp_options = {'cidr': '10.0.0.0/24',
                                 'external_ids': {
                                     'subnet_id': 'foo-subnet',
                                     ovn_const.OVN_REV_NUM_EXT_ID_KEY: '1'}}
        expected_dhcp_options['options'] = {
            'server_id': subnet['gateway_ip'],
            'server_mac': '01:02:03:04:05:06',
            'lease_time': str(12 * 60 * 60),
            'mtu': '1400',
            'router': subnet['gateway_ip'],
            'ntp_server': '8.8.8.8',
            'dns_server': '{7.7.7.7, 8.8.8.8}',
            'classless_static_route':
            '{20.0.0.4,10.0.0.100, 0.0.0.0/0,10.0.0.1}'
        }

        self._test_get_ovn_dhcp_options_helper(subnet, network,
                                               expected_dhcp_options)
        expected_dhcp_options['options']['server_mac'] = '11:22:33:44:55:66'
        self._test_get_ovn_dhcp_options_helper(subnet, network,
                                               expected_dhcp_options,
                                               service_mac='11:22:33:44:55:66')

    def test_get_ovn_dhcp_options_with_global_options_ipv6(self):
        ovn_conf.cfg.CONF.set_override('ovn_dhcp6_global_options',
                                       'ntp_server:8.8.8.8,'
                                       'server_id:01:02:03:04:05:04,'
                                       'wpad:',
                                       group='ovn')

        subnet = {'id': 'foo-subnet', 'network_id': 'network-id',
                  'cidr': 'ae70::/24',
                  'ip_version': 6,
                  'enable_dhcp': True,
                  'dns_nameservers': ['2001:db8::4444', '2001:db8::8888']}
        network = {'id': 'network-id', 'mtu': 1400}

        ext_ids = {'subnet_id': 'foo-subnet',
                   ovn_const.OVN_REV_NUM_EXT_ID_KEY: '1'}
        expected_dhcp_options = {
            'cidr': 'ae70::/24', 'external_ids': ext_ids,
            'options': {'server_id': '01:02:03:04:05:06',
                        'ntp_server': '8.8.8.8',
                        'dns_server': '{2001:db8::4444, 2001:db8::8888}'}}

        self._test_get_ovn_dhcp_options_helper(subnet, network,
                                               expected_dhcp_options)
        expected_dhcp_options['options']['server_id'] = '11:22:33:44:55:66'
        self._test_get_ovn_dhcp_options_helper(subnet, network,
                                               expected_dhcp_options,
                                               service_mac='11:22:33:44:55:66')

    def test_get_ovn_dhcp_options_ipv6_subnet(self):
        subnet = {'id': 'foo-subnet', 'network_id': 'network-id',
                  'cidr': 'ae70::/24',
                  'ip_version': 6,
                  'enable_dhcp': True,
                  'dns_nameservers': ['2001:db8::4444', '2001:db8::8888']}
        network = {'id': 'network-id', 'mtu': 1400}

        ext_ids = {'subnet_id': 'foo-subnet',
                   ovn_const.OVN_REV_NUM_EXT_ID_KEY: '1'}
        expected_dhcp_options = {
            'cidr': 'ae70::/24', 'external_ids': ext_ids,
            'options': {'server_id': '01:02:03:04:05:06',
                        'dns_server': '{2001:db8::4444, 2001:db8::8888}'}}

        self._test_get_ovn_dhcp_options_helper(subnet, network,
                                               expected_dhcp_options)
        expected_dhcp_options['options']['server_id'] = '11:22:33:44:55:66'
        self._test_get_ovn_dhcp_options_helper(subnet, network,
                                               expected_dhcp_options,
                                               service_mac='11:22:33:44:55:66')

    def test_get_ovn_dhcp_options_dhcpv6_stateless_subnet(self):
        subnet = {'id': 'foo-subnet', 'network_id': 'network-id',
                  'cidr': 'ae70::/24',
                  'ip_version': 6,
                  'enable_dhcp': True,
                  'dns_nameservers': ['2001:db8::4444', '2001:db8::8888'],
                  'ipv6_address_mode': const.DHCPV6_STATELESS}
        network = {'id': 'network-id', 'mtu': 1400}

        ext_ids = {'subnet_id': 'foo-subnet',
                   ovn_const.OVN_REV_NUM_EXT_ID_KEY: '1'}
        expected_dhcp_options = {
            'cidr': 'ae70::/24', 'external_ids': ext_ids,
            'options': {'server_id': '01:02:03:04:05:06',
                        'dns_server': '{2001:db8::4444, 2001:db8::8888}',
                        'dhcpv6_stateless': 'true'}}

        self._test_get_ovn_dhcp_options_helper(subnet, network,
                                               expected_dhcp_options)
        expected_dhcp_options['options']['server_id'] = '11:22:33:44:55:66'
        self._test_get_ovn_dhcp_options_helper(subnet, network,
                                               expected_dhcp_options,
                                               service_mac='11:22:33:44:55:66')

    def test_get_ovn_dhcp_options_metadata_route(self):
        subnet = {'id': 'foo-subnet', 'network_id': 'network-id',
                  'cidr': '10.0.0.0/24',
                  'ip_version': 4,
                  'enable_dhcp': True,
                  'gateway_ip': '10.0.0.1',
                  'dns_nameservers': ['7.7.7.7', '8.8.8.8'],
                  'host_routes': []}
        network = {'id': 'network-id', 'mtu': 1400}

        expected_dhcp_options = {'cidr': '10.0.0.0/24',
                                 'external_ids': {
                                     'subnet_id': 'foo-subnet',
                                     ovn_const.OVN_REV_NUM_EXT_ID_KEY: '1'}}
        expected_dhcp_options['options'] = {
            'server_id': subnet['gateway_ip'],
            'server_mac': '01:02:03:04:05:06',
            'lease_time': str(12 * 60 * 60),
            'mtu': '1400',
            'router': subnet['gateway_ip'],
            'dns_server': '{7.7.7.7, 8.8.8.8}',
            'classless_static_route':
            '{169.254.169.254/32,10.0.0.2, 0.0.0.0/0,10.0.0.1}'
        }

        with mock.patch.object(self.mech_driver._ovn_client,
                               '_find_metadata_port_ip',
                               return_value='10.0.0.2'):
            self._test_get_ovn_dhcp_options_helper(subnet, network,
                                                   expected_dhcp_options)

    def test_get_ovn_dhcp_options_domain_name(self):
        cfg.CONF.set_override('dns_domain', 'foo.com')
        subnet = {'id': 'foo-subnet', 'network_id': 'network-id',
                  'cidr': '10.0.0.0/24',
                  'ip_version': 4,
                  'enable_dhcp': True,
                  'gateway_ip': '10.0.0.1',
                  'dns_nameservers': ['7.7.7.7', '8.8.8.8'],
                  'host_routes': [{'destination': '20.0.0.4',
                                   'nexthop': '10.0.0.100'}]}
        network = {'id': 'network-id', 'mtu': 1400}

        expected_dhcp_options = {'cidr': '10.0.0.0/24',
                                 'external_ids': {
                                     'subnet_id': 'foo-subnet',
                                     ovn_const.OVN_REV_NUM_EXT_ID_KEY: '1'}}
        expected_dhcp_options['options'] = {
            'server_id': subnet['gateway_ip'],
            'server_mac': '01:02:03:04:05:06',
            'lease_time': str(12 * 60 * 60),
            'mtu': '1400',
            'router': subnet['gateway_ip'],
            'domain_name': '"foo.com"',
            'dns_server': '{7.7.7.7, 8.8.8.8}',
            'classless_static_route':
            '{20.0.0.4,10.0.0.100, 0.0.0.0/0,10.0.0.1}'
        }

        self._test_get_ovn_dhcp_options_helper(subnet, network,
                                               expected_dhcp_options)
        expected_dhcp_options['options']['server_mac'] = '11:22:33:44:55:66'
        self._test_get_ovn_dhcp_options_helper(subnet, network,
                                               expected_dhcp_options,
                                               service_mac='11:22:33:44:55:66')

    def _test__get_port_dhcp_options_port_dhcp_opts_set(self, ip_version=4):
        if ip_version == 4:
            ip_address = '10.0.0.11'
        else:
            ip_address = 'aef0::4'

        port = {
            'id': 'foo-port',
            'device_owner': 'compute:None',
            'fixed_ips': [{'subnet_id': 'foo-subnet',
                           'ip_address': ip_address}]}
        if ip_version == 4:
            port['extra_dhcp_opts'] = [
                {'ip_version': 4, 'opt_name': 'mtu', 'opt_value': '1200'},
                {'ip_version': 4, 'opt_name': 'ntp-server',
                 'opt_value': '8.8.8.8'}]
        else:
            port['extra_dhcp_opts'] = [
                {'ip_version': 6, 'opt_name': 'domain-search',
                 'opt_value': 'foo-domain'},
                {'ip_version': 4, 'opt_name': 'dns-server',
                 'opt_value': '7.7.7.7'}]

        self.mech_driver._ovn_client._get_subnet_dhcp_options_for_port = (
            mock.Mock(
                return_value=({
                    'cidr': '10.0.0.0/24' if ip_version == 4 else 'aef0::/64',
                    'external_ids': {'subnet_id': 'foo-subnet'},
                    'options': (ip_version == 4) and {
                        'router': '10.0.0.1', 'mtu': '1400'} or {
                        'server_id': '01:02:03:04:05:06'},
                    'uuid': 'foo-uuid'})))

        if ip_version == 4:
            expected_dhcp_options = {
                'cidr': '10.0.0.0/24',
                'external_ids': {'subnet_id': 'foo-subnet',
                                 'port_id': 'foo-port'},
                'options': {'router': '10.0.0.1', 'mtu': '1200',
                            'ntp_server': '8.8.8.8'}}
        else:
            expected_dhcp_options = {
                'cidr': 'aef0::/64',
                'external_ids': {'subnet_id': 'foo-subnet',
                                 'port_id': 'foo-port'},
                'options': {'server_id': '01:02:03:04:05:06',
                            'domain_search': 'foo-domain'}}

        self.mech_driver.nb_ovn.add_dhcp_options.return_value = 'foo-val'
        dhcp_options = self.mech_driver._ovn_client._get_port_dhcp_options(
            port, ip_version)
        self.assertEqual({'cmd': 'foo-val'}, dhcp_options)
        self.mech_driver.nb_ovn.add_dhcp_options.assert_called_once_with(
            'foo-subnet', port_id='foo-port', **expected_dhcp_options)

    def test__get_port_dhcp_options_port_dhcp_opts_set_v4(self):
        self._test__get_port_dhcp_options_port_dhcp_opts_set(ip_version=4)

    def test__get_port_dhcp_options_port_dhcp_opts_set_v6(self):
        self._test__get_port_dhcp_options_port_dhcp_opts_set(ip_version=6)

    def _test__get_port_dhcp_options_port_dhcp_opts_not_set(self,
                                                            ip_version=4):
        if ip_version == 4:
            port = {'id': 'foo-port',
                    'device_owner': 'compute:None',
                    'fixed_ips': [{'subnet_id': 'foo-subnet',
                                   'ip_address': '10.0.0.11'}]}
        else:
            port = {'id': 'foo-port',
                    'device_owner': 'compute:None',
                    'fixed_ips': [{'subnet_id': 'foo-subnet',
                                   'ip_address': 'aef0::4'}]}

        if ip_version == 4:
            expected_dhcp_opts = {
                'cidr': '10.0.0.0/24',
                'external_ids': {'subnet_id': 'foo-subnet'},
                'options': {'router': '10.0.0.1', 'mtu': '1400'}}
        else:
            expected_dhcp_opts = {
                'cidr': 'aef0::/64',
                'external_ids': {'subnet_id': 'foo-subnet'},
                'options': {'server_id': '01:02:03:04:05:06'}}

        self.mech_driver._ovn_client._get_subnet_dhcp_options_for_port = (
            mock.Mock(return_value=expected_dhcp_opts))

        self.assertEqual(
            expected_dhcp_opts,
            self.mech_driver._ovn_client._get_port_dhcp_options(
                port, ip_version=ip_version))

        # Since the port has no extra DHCPv4/v6 options defined, no new
        # DHCP_Options row should be created and logical switch port DHCPv4/v6
        # options should point to the subnet DHCPv4/v6 options.
        self.mech_driver.nb_ovn.add_dhcp_options.assert_not_called()

    def test__get_port_dhcp_options_port_dhcp_opts_not_set_v4(self):
        self._test__get_port_dhcp_options_port_dhcp_opts_not_set(ip_version=4)

    def test__get_port_dhcp_options_port_dhcp_opts_not_set_v6(self):
        self._test__get_port_dhcp_options_port_dhcp_opts_not_set(ip_version=6)

    def _test__get_port_dhcp_options_port_dhcp_disabled(self, ip_version=4):
        port = {
            'id': 'foo-port',
            'device_owner': 'compute:None',
            'fixed_ips': [{'subnet_id': 'foo-subnet',
                           'ip_address': '10.0.0.11'},
                          {'subnet_id': 'foo-subnet-v6',
                           'ip_address': 'aef0::11'}],
            'extra_dhcp_opts': [{'ip_version': 4, 'opt_name': 'dhcp_disabled',
                                 'opt_value': 'False'},
                                {'ip_version': 6, 'opt_name': 'dhcp_disabled',
                                 'opt_value': 'False'}]
        }

        subnet_dhcp_opts = mock.Mock()
        self.mech_driver._ovn_client._get_subnet_dhcp_options_for_port = (
            mock.Mock(return_value=subnet_dhcp_opts))

        # No dhcp_disabled set to true, subnet dhcp options will be get for
        # this port. Since it doesn't have any other extra dhcp options, but
        # dhcp_disabled, no port dhcp options will be created.
        self.assertEqual(
            subnet_dhcp_opts,
            self.mech_driver._ovn_client._get_port_dhcp_options(
                port, ip_version))
        self.assertEqual(
            1,
            self.mech_driver._ovn_client._get_subnet_dhcp_options_for_port.
            call_count)
        self.mech_driver.nb_ovn.add_dhcp_options.assert_not_called()

        # Set dhcp_disabled with ip_version specified by this test case to
        # true, no dhcp options will be get since it's dhcp_disabled now for
        # ip_version be tested.
        opt_index = 0 if ip_version == 4 else 1
        port['extra_dhcp_opts'][opt_index]['opt_value'] = 'True'
        self.mech_driver._ovn_client._get_subnet_dhcp_options_for_port.\
            reset_mock()
        self.assertIsNone(
            self.mech_driver._ovn_client._get_port_dhcp_options(
                port, ip_version))
        self.assertEqual(
            0,
            self.mech_driver._ovn_client._get_subnet_dhcp_options_for_port.
            call_count)
        self.mech_driver.nb_ovn.add_dhcp_options.assert_not_called()

        # Set dhcp_disabled with ip_version specified by this test case to
        # false, and set dhcp_disabled with ip_version not in test to true.
        # Subnet dhcp options will be get, since dhcp_disabled with ip_version
        # not in test should not affect.
        opt_index_1 = 1 if ip_version == 4 else 0
        port['extra_dhcp_opts'][opt_index]['opt_value'] = 'False'
        port['extra_dhcp_opts'][opt_index_1]['opt_value'] = 'True'
        self.assertEqual(
            subnet_dhcp_opts,
            self.mech_driver._ovn_client._get_port_dhcp_options(
                port, ip_version))
        self.assertEqual(
            1,
            self.mech_driver._ovn_client._get_subnet_dhcp_options_for_port.
            call_count)
        self.mech_driver.nb_ovn.add_dhcp_options.assert_not_called()

    def test__get_port_dhcp_options_port_dhcp_disabled_v4(self):
        self._test__get_port_dhcp_options_port_dhcp_disabled(ip_version=4)

    def test__get_port_dhcp_options_port_dhcp_disabled_v6(self):
        self._test__get_port_dhcp_options_port_dhcp_disabled(ip_version=6)

    def test__get_port_dhcp_options_port_with_invalid_device_owner(self):
        port = {'id': 'foo-port',
                'device_owner': 'neutron:router_interface',
                'fixed_ips': ['fake']}

        self.assertIsNone(
            self.mech_driver._ovn_client._get_port_dhcp_options(
                port, mock.ANY))

    def _test__get_subnet_dhcp_options_for_port(self, ip_version=4,
                                                enable_dhcp=True):
        port = {'fixed_ips': [
            {'ip_address': '10.0.0.4',
             'subnet_id': 'v4_snet_id_1' if enable_dhcp else 'v4_snet_id_2'},
            {'ip_address': '2001:dba::4',
             'subnet_id': 'v6_snet_id_1' if enable_dhcp else 'v6_snet_id_2'},
            {'ip_address': '2001:dbb::4', 'subnet_id': 'v6_snet_id_3'}]}

        def fake(subnets):
            fake_rows = {
                'v4_snet_id_1': 'foo',
                'v6_snet_id_1': {'options': {}},
                'v6_snet_id_3': {'options': {
                    ovn_const.DHCPV6_STATELESS_OPT: 'true'}}}
            return [fake_rows[row] for row in fake_rows if row in subnets]

        self.mech_driver.nb_ovn.get_subnets_dhcp_options.side_effect = fake

        if ip_version == 4:
            expected_opts = 'foo' if enable_dhcp else None
        else:
            expected_opts = {
                'options': {} if enable_dhcp else {
                    ovn_const.DHCPV6_STATELESS_OPT: 'true'}}

        self.assertEqual(
            expected_opts,
            self.mech_driver._ovn_client._get_subnet_dhcp_options_for_port(
                port, ip_version))

    def test__get_subnet_dhcp_options_for_port_v4(self):
        self._test__get_subnet_dhcp_options_for_port()

    def test__get_subnet_dhcp_options_for_port_v4_dhcp_disabled(self):
        self._test__get_subnet_dhcp_options_for_port(enable_dhcp=False)

    def test__get_subnet_dhcp_options_for_port_v6(self):
        self._test__get_subnet_dhcp_options_for_port(ip_version=6)

    def test__get_subnet_dhcp_options_for_port_v6_dhcp_disabled(self):
        self._test__get_subnet_dhcp_options_for_port(ip_version=6,
                                                     enable_dhcp=False)


class TestOVNMechanismDriverSecurityGroup(MechDriverSetupBase,
        test_security_group.Ml2SecurityGroupsTestCase):
    # This set of test cases is supplement to test_acl.py, the purpose is to
    # test acl methods invoking. Content correctness of args of acl methods
    # is mainly guaranteed by acl_test.py.

    _extension_drivers = ['port_security']

    def setUp(self):
        ovn_conf.register_opts()
        cfg.CONF.set_override('extension_drivers',
                              self._extension_drivers,
                              group='ml2')
        cfg.CONF.set_override('mechanism_drivers',
                              ['logger', 'ovn'],
                              'ml2')
        # ensure viable minimum is set for OVN's Geneve
        cfg.CONF.set_override('max_header_size', 38,
                              group='ml2_type_geneve')
        cfg.CONF.set_override('dns_servers', ['8.8.8.8'], group='ovn')
        mock.patch.object(impl_idl_ovn.Backend, 'schema_helper').start()
        super(TestOVNMechanismDriverSecurityGroup, self).setUp()
        self.ctx = context.get_admin_context()
        revision_plugin.RevisionPlugin()

    def _delete_default_sg_rules(self, security_group_id):
        res = self._list(
            'security-group-rules',
            query_params='security_group_id=%s' % security_group_id)
        for r in res['security_group_rules']:
            self._delete('security-group-rules', r['id'])

    def _create_sg(self, sg_name, **kwargs):
        sg = self._make_security_group(self.fmt, sg_name, '', **kwargs)
        return sg['security_group']

    def _create_empty_sg(self, sg_name):
        sg = self._create_sg(sg_name)
        self._delete_default_sg_rules(sg['id'])
        return sg

    def _create_sg_rule(self, sg_id, direction, proto,
                        port_range_min=None, port_range_max=None,
                        remote_ip_prefix=None, remote_group_id=None,
                        ethertype=const.IPv4):
        r = self._build_security_group_rule(sg_id, direction, proto,
                                            port_range_min=port_range_min,
                                            port_range_max=port_range_max,
                                            remote_ip_prefix=remote_ip_prefix,
                                            remote_group_id=remote_group_id,
                                            ethertype=ethertype)
        res = self._create_security_group_rule(self.fmt, r)
        rule = self.deserialize(self.fmt, res)
        return rule['security_group_rule']

    def _delete_sg_rule(self, rule_id):
        self._delete('security-group-rules', rule_id)

    def test_create_security_group(self):
        sg = self._create_sg('sg')

        expected_pg_name = ovn_utils.ovn_port_group_name(sg['id'])
        expected_pg_add_calls = [
            mock.call(acls=[],
                      external_ids={'neutron:security_group_id': sg['id']},
                      name=expected_pg_name),
        ]
        self.mech_driver.nb_ovn.pg_add.assert_has_calls(
            expected_pg_add_calls)

    def test_delete_security_group(self):
        sg = self._create_sg('sg')
        self._delete('security-groups', sg['id'])

        expected_pg_name = ovn_utils.ovn_port_group_name(sg['id'])
        expected_pg_del_calls = [
            mock.call(if_exists=True, name=expected_pg_name),
        ]
        self.mech_driver.nb_ovn.pg_del.assert_has_calls(
            expected_pg_del_calls)

    def test_create_port(self):
        with self.network() as n, self.subnet(n):
            sg = self._create_empty_sg('sg')
            self._make_port(self.fmt, n['network']['id'],
                            security_groups=[sg['id']])

            # Assert the port has been added to the right security groups
            expected_pg_name = ovn_utils.ovn_port_group_name(sg['id'])
            expected_pg_add_ports_calls = [
                mock.call('neutron_pg_drop', mock.ANY),
                mock.call(expected_pg_name, mock.ANY)
            ]
            self.mech_driver.nb_ovn.pg_add_ports.assert_has_calls(
                expected_pg_add_ports_calls)

            # Assert add_acl() is not used anymore
            self.assertFalse(self.mech_driver.nb_ovn.add_acl.called)

    def test_create_port_with_sg_default_rules(self):
        with self.network() as n, self.subnet(n):
            self.mech_driver.nb_ovn.pg_acl_add.reset_mock()
            sg = self._create_sg('sg')
            self._make_port(self.fmt, n['network']['id'],
                            security_groups=[sg['id']])
            # egress traffic for ipv4 and ipv6 is allowed by default
            self.assertEqual(
                2, self.mech_driver.nb_ovn.pg_acl_add.call_count)

    def test_create_port_with_empty_sg(self):
        with self.network() as n, self.subnet(n):
            self.mech_driver.nb_ovn.pg_acl_add.reset_mock()
            sg = self._create_empty_sg('sg')
            # Implicit egress rules for ipv4 and ipv6
            self.assertEqual(2, self.mech_driver.nb_ovn.pg_acl_add.call_count)
            self.mech_driver.nb_ovn.pg_acl_add.reset_mock()
            self.mech_driver.nb_ovn.pg_add.reset_mock()
            self.mech_driver.nb_ovn.pg_add_ports.reset_mock()

            self._make_port(self.fmt, n['network']['id'],
                            security_groups=[sg['id']])
            self.assertFalse(self.mech_driver.nb_ovn.pg_acl_add.called)
            self.assertFalse(self.mech_driver.nb_ovn.pg_add.called)
            self.assertEqual(1, self.mech_driver.nb_ovn.pg_add_ports.called)

    def test_create_port_with_multi_sgs_duplicate_rules(self):
        with self.network() as n, self.subnet(n):
            self.mech_driver.nb_ovn.pg_add.reset_mock()
            sg1 = self._create_empty_sg('sg1')
            sg2 = self._create_empty_sg('sg2')
            self.assertEqual(
                2, self.mech_driver.nb_ovn.pg_add.call_count)

            self.mech_driver.nb_ovn.pg_acl_add.reset_mock()
            self._create_sg_rule(sg1['id'], 'ingress', const.PROTO_NAME_TCP,
                                 port_range_min=22, port_range_max=23,
                                 remote_ip_prefix='20.0.0.0/24')
            self._create_sg_rule(sg2['id'], 'ingress', const.PROTO_NAME_TCP,
                                 port_range_min=22, port_range_max=23,
                                 remote_ip_prefix='20.0.0.0/24')
            self.assertEqual(
                2, self.mech_driver.nb_ovn.pg_acl_add.call_count)

            self._make_port(self.fmt, n['network']['id'],
                            security_groups=[sg1['id'], sg2['id']])
            # Default drop group, two security groups
            self.assertEqual(
                3, self.mech_driver.nb_ovn.pg_add_ports.call_count)

    @mock.patch('neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb.'
                'ovn_client.OVNClient.is_external_ports_supported',
                lambda *_: True)
    @mock.patch.object(ovn_utils, 'sync_ha_chassis_group')
    def _test_create_port_with_vnic_type(self, vnic_type, sync_mock):
        fake_grp = 'fake-default-ha-group-uuid'
        sync_mock.return_value = fake_grp

        with self.network() as n, self.subnet(n):
            net_id = n['network']['id']
            self._create_port(
                self.fmt, net_id,
                arg_list=(portbindings.VNIC_TYPE,),
                **{portbindings.VNIC_TYPE: vnic_type})

            # Assert create_lswitch_port was called with the relevant
            # parameters
            _, kwargs = self.mech_driver.nb_ovn.create_lswitch_port.call_args
            self.assertEqual(
                1, self.mech_driver.nb_ovn.create_lswitch_port.call_count)
            if vnic_type in ovn_const.EXTERNAL_PORT_TYPES:
                self.assertEqual(ovn_const.LSP_TYPE_EXTERNAL, kwargs['type'])
                self.assertEqual(fake_grp, kwargs['ha_chassis_group'])
                sync_mock.assert_called_once_with(
                    mock.ANY, net_id, self.mech_driver.nb_ovn,
                    self.mech_driver.sb_ovn, mock.ANY)

    def test_create_port_with_vnic_direct(self):
        self._test_create_port_with_vnic_type(portbindings.VNIC_DIRECT)

    def test_create_port_with_vnic_direct_physical(self):
        self._test_create_port_with_vnic_type(
            portbindings.VNIC_DIRECT_PHYSICAL)

    def test_create_port_with_vnic_macvtap(self):
        self._test_create_port_with_vnic_type(
            portbindings.VNIC_MACVTAP)

    def test_create_port_with_vnic_remote_managed(self):
        self._test_create_port_with_vnic_type(
            portbindings.VNIC_REMOTE_MANAGED)
        # Confirm LSP options are not populated when there is no binding
        # profile yet.
        _, kwargs = self.mech_driver.nb_ovn.create_lswitch_port.call_args
        self.assertNotIn('vif-plug-type', kwargs['options'])

    def test_create_port_with_vnic_baremetal(self):
        self._test_create_port_with_vnic_type(
            portbindings.VNIC_BAREMETAL)

    def test_create_port_with_vnic_virtio_forwarder(self):
        self._test_create_port_with_vnic_type(
            portbindings.VNIC_VIRTIO_FORWARDER)

    def test_update_port_with_sgs(self):
        with self.network() as n, self.subnet(n):
            sg1 = self._create_empty_sg('sg1')
            self._create_sg_rule(sg1['id'], 'ingress', const.PROTO_NAME_TCP,
                                 ethertype=const.IPv6)

            p = self._make_port(self.fmt, n['network']['id'],
                                security_groups=[sg1['id']])['port']

            sg2 = self._create_empty_sg('sg2')
            self._create_sg_rule(sg2['id'], 'egress', const.PROTO_NAME_UDP,
                                 remote_ip_prefix='30.0.0.0/24')
            data = {'port': {'security_groups': [sg1['id'], sg2['id']]}}

            self.mech_driver.nb_ovn.pg_add_ports.reset_mock()
            req = self.new_update_request('ports', data, p['id'])
            req.get_response(self.api)

            # Default neutron_pg_drop, 2 security group
            self.assertEqual(
                3, self.mech_driver.nb_ovn.pg_add_ports.call_count)

    def test_update_sg_change_rule(self):
        with self.network() as n, self.subnet(n):
            sg = self._create_empty_sg('sg')

            self._make_port(self.fmt, n['network']['id'],
                            security_groups=[sg['id']])

            self.mech_driver.nb_ovn.pg_acl_add.reset_mock()
            sg_r = self._create_sg_rule(sg['id'], 'ingress',
                                        const.PROTO_NAME_UDP,
                                        ethertype=const.IPv6)
            self.assertEqual(
                1, self.mech_driver.nb_ovn.pg_acl_add.call_count)

            self.mech_driver.nb_ovn.pg_acl_del.reset_mock()
            self._delete_sg_rule(sg_r['id'])
            self.assertEqual(
                1, self.mech_driver.nb_ovn.pg_acl_del.call_count)

    def test_update_sg_duplicate_rule(self):
        with self.network() as n, self.subnet(n):
            sg1 = self._create_empty_sg('sg1')
            sg2 = self._create_empty_sg('sg2')
            self._create_sg_rule(sg1['id'], 'ingress',
                                 const.PROTO_NAME_UDP,
                                 port_range_min=22, port_range_max=23)
            self._make_port(self.fmt, n['network']['id'],
                            security_groups=[sg1['id'], sg2['id']])
            # One default drop rule, two SGs
            self.assertEqual(
                3, self.mech_driver.nb_ovn.pg_add_ports.call_count)

            self.mech_driver.nb_ovn.pg_acl_add.reset_mock()
            # Add a new duplicate rule to sg2. It's expected to be added.
            sg2_r = self._create_sg_rule(sg2['id'], 'ingress',
                                         const.PROTO_NAME_UDP,
                                         port_range_min=22, port_range_max=23)
            self.assertEqual(
                1, self.mech_driver.nb_ovn.pg_acl_add.call_count)

            self.mech_driver.nb_ovn.pg_acl_del.reset_mock()
            # Delete the duplicate rule. It's expected to be deleted.
            self._delete_sg_rule(sg2_r['id'])
            self.assertEqual(
                1, self.mech_driver.nb_ovn.pg_acl_del.call_count)

    def test_update_sg_duplicate_rule_multi_ports(self):
        with self.network() as n, self.subnet(n):
            sg1 = self._create_empty_sg('sg1')
            sg2 = self._create_empty_sg('sg2')
            sg3 = self._create_empty_sg('sg3')

            self.mech_driver.nb_ovn.pg_acl_add.reset_mock()
            self._create_sg_rule(sg1['id'], 'ingress',
                                 const.PROTO_NAME_UDP,
                                 remote_group_id=sg3['id'])
            self._create_sg_rule(sg2['id'], 'egress', const.PROTO_NAME_TCP,
                                 port_range_min=60, port_range_max=70)

            self._make_port(self.fmt, n['network']['id'],
                            security_groups=[sg1['id'], sg2['id']])
            self._make_port(self.fmt, n['network']['id'],
                            security_groups=[sg1['id'], sg2['id']])
            self._make_port(self.fmt, n['network']['id'],
                            security_groups=[sg2['id'], sg3['id']])

            # No matter how many ports are there, there are two rules only
            self.assertEqual(
                2, self.mech_driver.nb_ovn.pg_acl_add.call_count)

            # Add a rule to sg1 duplicate with sg2. It's expected to be added.
            self.mech_driver.nb_ovn.pg_acl_add.reset_mock()
            sg1_r = self._create_sg_rule(sg1['id'], 'egress',
                                         const.PROTO_NAME_TCP,
                                         port_range_min=60, port_range_max=70)
            self.assertEqual(
                1, self.mech_driver.nb_ovn.pg_acl_add.call_count)

            # Add a rule to sg2 duplicate with sg1 but not duplicate with sg3.
            # It's expected to be added as well.
            self.mech_driver.nb_ovn.pg_acl_add.reset_mock()
            sg2_r = self._create_sg_rule(sg2['id'], 'ingress',
                                         const.PROTO_NAME_UDP,
                                         remote_group_id=sg3['id'])
            self.assertEqual(
                1, self.mech_driver.nb_ovn.pg_acl_add.call_count)

            # Delete the duplicate rule in sg1. It's expected to be deleted.
            self.mech_driver.nb_ovn.pg_acl_del.reset_mock()
            self._delete_sg_rule(sg1_r['id'])
            self.assertEqual(
                1, self.mech_driver.nb_ovn.pg_acl_del.call_count)

            # Delete the duplicate rule in sg2. It's expected to be deleted.
            self.mech_driver.nb_ovn.pg_acl_del.reset_mock()
            self._delete_sg_rule(sg2_r['id'])
            self.assertEqual(
                1, self.mech_driver.nb_ovn.pg_acl_del.call_count)

    def test_delete_port_with_security_groups_port_doesnt_remove_pg(self):
        with self.network() as net1:
            with self.subnet(network=net1):
                sg = self._create_sg('sg')
                port = self._make_port(
                    self.fmt, net1['network']['id'],
                    security_groups=[sg['id']])['port']
                fake_lsp = fakes.FakeOVNPort.from_neutron_port(port)
                self.mech_driver.nb_ovn.lookup.return_value = fake_lsp
                self.mech_driver.nb_ovn.delete_lswitch_port.reset_mock()
                self.mech_driver.nb_ovn.delete_acl.reset_mock()
                self._delete('ports', port['id'])
                self.assertEqual(
                    1, self.mech_driver.nb_ovn.delete_lswitch_port.call_count)
                self.assertFalse(self.mech_driver.nb_ovn.pg_del.called)
                self.assertFalse(self.mech_driver.nb_ovn.delete_acl.called)


class TestOVNMechanismDriverMetadataPort(MechDriverSetupBase,
                                         test_plugin.Ml2PluginV2TestCase):

    _mechanism_drivers = ['logger', 'ovn']

    def setUp(self):
        mock.patch.object(impl_idl_ovn.Backend, 'schema_helper').start()
        cfg.CONF.set_override('max_header_size', 38,
                              group='ml2_type_geneve')
        super(TestOVNMechanismDriverMetadataPort, self).setUp()
        self.nb_ovn = self.mech_driver.nb_ovn
        self.sb_ovn = self.mech_driver.sb_ovn
        self.ctx = context.get_admin_context()
        # ensure viable minimum is set for OVN's Geneve
        ovn_conf.cfg.CONF.set_override('ovn_metadata_enabled', True,
                                       group='ovn')
        p = mock.patch.object(ovn_utils, 'get_revision_number', return_value=1)
        p.start()
        self.addCleanup(p.stop)

    def _create_fake_dhcp_port(self, device_id, neutron_port=False):
        port = {'network_id': 'fake',
                'device_owner': const.DEVICE_OWNER_DISTRIBUTED,
                'device_id': device_id}
        if neutron_port:
            port['device_owner'] = const.DEVICE_OWNER_DHCP
        return port

    def test_metadata_port_on_network_create(self):
        """Check metadata port create.

        Check that a localport is created when a neutron network is
        created.
        """
        with self.network():
            self.assertEqual(1, self.nb_ovn.create_lswitch_port.call_count)
            args, kwargs = self.nb_ovn.create_lswitch_port.call_args
            self.assertEqual(ovn_const.LSP_TYPE_LOCALPORT,
                             kwargs['type'])

    def test_metadata_port_not_created_if_exists(self):
        """Check that metadata port is not created if it already exists.

        In the event of a sync, it might happen that a metadata port exists
        already. When we are creating the logical switch in OVN we don't want
        this port to be created again.
        """
        with mock.patch.object(
            self.mech_driver._ovn_client, '_find_metadata_port',
                return_value={'port': {'id': 'metadata_port1'}}):
            with self.network():
                self.assertEqual(0, self.nb_ovn.create_lswitch_port.call_count)

    def test_metadata_ip_on_subnet_create(self):
        """Check metadata port update.

        Check that the metadata port is updated with a new IP address when a
        subnet is created.
        """
        self.mech_driver.nb_ovn.get_subnet_dhcp_options.return_value = {
            'subnet': {}, 'ports': {}}
        with self.network() as net1:
            with self.subnet(network=net1, cidr='10.0.0.0/24') as subnet1:
                with self.subnet(network=net1,
                                 cidr='20.0.0.0/24') as subnet2:
                    self.assertEqual(
                        2, self.nb_ovn.set_lswitch_port.call_count)
                    args, kwargs = self.nb_ovn.set_lswitch_port.call_args
                    self.assertEqual(ovn_const.LSP_TYPE_LOCALPORT,
                                     kwargs['type'])
        port_ips = kwargs['external_ids'].get(
            ovn_const.OVN_CIDRS_EXT_ID_KEY, '').split()
        port_cidrs = [str(netaddr.IPNetwork(cidr).cidr) for cidr in port_ips]
        self.assertListEqual(
            [subnet1['subnet']['cidr'], subnet2['subnet']['cidr']],
            port_cidrs)

    def test_metadata_port_on_network_delete(self):
        """Check metadata port delete.

        Check that the metadata port is deleted when a network is deleted.
        """
        nb_idl = self.mech_driver._ovn_client._nb_idl
        nb_idl.ls_get.return_value.execute.return_value = (
            fakes.FakeOvsdbRow.create_one_ovsdb_row(attrs={'ports': []}))
        net = self._make_network(self.fmt, name="net1", admin_state_up=True)
        network_id = net['network']['id']
        req = self.new_delete_request('networks', network_id)
        res = req.get_response(self.api)
        self.assertEqual(exc.HTTPNoContent.code,
                         res.status_int)
        self.assertEqual(1, self.nb_ovn.delete_lswitch_port.call_count)


class TestOVNParentTagPortBinding(OVNMechanismDriverTestCase):
    def test_create_port_with_invalid_parent(self):
        binding = {OVN_PROFILE: {"parent_name": 'invalid', 'tag': 1}}
        with self.network() as n:
            with self.subnet(n):
                self._create_port(
                    self.fmt, n['network']['id'],
                    expected_res_status=404,
                    is_admin=True,
                    arg_list=(OVN_PROFILE,),
                    **binding)

    @mock.patch.object(db_base_plugin_v2.NeutronDbPluginV2, 'get_port')
    def test_create_port_with_parent_and_tag(self, mock_get_port):
        binding = {OVN_PROFILE: {"parent_name": '', 'tag': 1}}
        with self.network() as n:
            with self.subnet(n) as s:
                with self.port(s) as p:
                    binding[OVN_PROFILE]['parent_name'] = p['port']['id']
                    res = self._create_port(self.fmt, n['network']['id'],
                                            is_admin=True,
                                            arg_list=(OVN_PROFILE,),
                                            **binding)
                    port = self.deserialize(self.fmt, res)
                    self.assertEqual(port['port'][OVN_PROFILE],
                                     binding[OVN_PROFILE])
                    mock_get_port.assert_called_with(mock.ANY, p['port']['id'])

    def test_create_port_with_invalid_tag(self):
        binding = {OVN_PROFILE: {"parent_name": '', 'tag': 'a'}}
        with self.network() as n:
            with self.subnet(n) as s:
                with self.port(s) as p:
                    binding[OVN_PROFILE]['parent_name'] = p['port']['id']
                    self._create_port(self.fmt, n['network']['id'],
                                      is_admin=True,
                                      arg_list=(OVN_PROFILE,),
                                      expected_res_status=400,
                                      **binding)


class TestOVNVtepPortBinding(OVNMechanismDriverTestCase):

    def test_create_port_with_vtep_options(self):
        binding = {OVN_PROFILE: {"vtep-physical-switch": 'psw1',
                   "vtep-logical-switch": 'lsw1'}}
        with self.network() as n:
            with self.subnet(n):
                res = self._create_port(self.fmt, n['network']['id'],
                                        is_admin=True,
                                        arg_list=(OVN_PROFILE,),
                                        **binding)
                port = self.deserialize(self.fmt, res)
                self.assertEqual(binding[OVN_PROFILE],
                                 port['port'][OVN_PROFILE])

    def test_create_port_with_only_vtep_physical_switch(self):
        binding = {OVN_PROFILE: {"vtep-physical-switch": 'psw'}}
        with self.network() as n:
            with self.subnet(n):
                self._create_port(self.fmt, n['network']['id'],
                                  is_admin=True,
                                  arg_list=(OVN_PROFILE,),
                                  expected_res_status=400,
                                  **binding)

    def test_create_port_with_only_vtep_logical_switch(self):
        binding = {OVN_PROFILE: {"vtep-logical-switch": 'lsw1'}}
        with self.network() as n:
            with self.subnet(n):
                self._create_port(self.fmt, n['network']['id'],
                                  is_admin=True,
                                  arg_list=(OVN_PROFILE,),
                                  expected_res_status=400,
                                  **binding)

    def test_create_port_with_invalid_vtep_logical_switch(self):
        binding = {OVN_PROFILE: {"vtep-logical-switch": 1234,
                                 "vtep-physical-switch": "psw1"}}
        with self.network() as n:
            with self.subnet(n):
                self._create_port(self.fmt, n['network']['id'],
                                  is_admin=True,
                                  arg_list=(OVN_PROFILE,),
                                  expected_res_status=400,
                                  **binding)

    def test_create_port_with_vtep_options_and_parent_name_tag(self):
        binding = {OVN_PROFILE: {"vtep-logical-switch": "lsw1",
                                 "vtep-physical-switch": "psw1",
                                 "parent_name": "pname", "tag": 22}}
        with self.network() as n:
            with self.subnet(n):
                self._create_port(self.fmt, n['network']['id'],
                                  is_admin=True,
                                  arg_list=(OVN_PROFILE,),
                                  expected_res_status=404,
                                  **binding)

    def test_create_port_with_vtep_options_and_check_vtep_keys(self):
        port = {
            'id': 'foo-port',
            'device_owner': 'compute:None',
            'fixed_ips': [{'subnet_id': 'foo-subnet',
                           'ip_address': '10.0.0.11'}],
            OVN_PROFILE: {"vtep-logical-switch": "lsw1",
                          "vtep-physical-switch": "psw1"}
        }
        ovn_port_info = (
            self.mech_driver._ovn_client._get_port_options(port))
        self.assertEqual(port[OVN_PROFILE]["vtep-physical-switch"],
                         ovn_port_info.options["vtep-physical-switch"])
        self.assertEqual(port[OVN_PROFILE]["vtep-logical-switch"],
                         ovn_port_info.options["vtep-logical-switch"])


class TestOVNVVirtualPort(OVNMechanismDriverTestCase):

    def setUp(self):
        super(TestOVNVVirtualPort, self).setUp()
        self.context = context.get_admin_context()
        self.nb_idl = self.mech_driver._ovn_client._nb_idl
        self.net = self._make_network(
            self.fmt, name='net1', admin_state_up=True)['network']
        self.subnet = self._make_subnet(
            self.fmt, {'network': self.net},
            '10.0.0.1', '10.0.0.0/24')

    @mock.patch.object(ovn_utils, 'determine_bind_host')
    def test_create_port_with_virtual_type_and_options(self, *args):
        fake_parents = ['parent-0', 'parent-1']
        self.mock_vp_parents.return_value = fake_parents
        for device_owner in ('', 'myVIPowner'):
            port = {'id': 'virt-port',
                    'mac_address': '00:00:00:00:00:00',
                    'device_owner': device_owner,
                    'network_id': self.net['id'],
                    'fixed_ips': [{'subnet_id': self.subnet['subnet']['id'],
                                   'ip_address': '10.0.0.55'}],
                    portbindings.PROFILE: {},
                    }
            port_info = self.mech_driver._ovn_client._get_port_options(port)
            self.assertEqual(ovn_const.LSP_TYPE_VIRTUAL, port_info.type)
            self.assertEqual(
                '10.0.0.55',
                port_info.options[ovn_const.LSP_OPTIONS_VIRTUAL_IP_KEY])
            self.assertIn(
                'parent-0',
                port_info.options[ovn_const.LSP_OPTIONS_VIRTUAL_PARENTS_KEY])
            self.assertIn(
                'parent-1',
                port_info.options[ovn_const.LSP_OPTIONS_VIRTUAL_PARENTS_KEY])

    @mock.patch.object(db_base_plugin_v2.NeutronDbPluginV2, 'get_ports')
    def _test_set_unset_virtual_port_type(self, mock_get_ports, unset=False):
        cmd = self.nb_idl.set_lswitch_port_to_virtual_type
        if unset:
            cmd = self.nb_idl.unset_lswitch_port_to_virtual_type

        fake_txn = mock.Mock()
        parent_port = {'id': 'parent-port', 'network_id': 'fake-network'}
        port = {'id': 'virt-port'}
        mock_get_ports.return_value = [port]
        self.mech_driver._ovn_client._set_unset_virtual_port_type(
            self.context, fake_txn, parent_port, ['10.0.0.55'], unset=unset)

        args = {'lport_name': 'virt-port',
                'virtual_parent': 'parent-port',
                'if_exists': True}
        if not unset:
            args['vip'] = '10.0.0.55'

        cmd.assert_called_once_with(**args)

    def test__set_unset_virtual_port_type_set(self):
        self._test_set_unset_virtual_port_type(unset=False)

    def test__set_unset_virtual_port_type_unset(self):
        self._test_set_unset_virtual_port_type(unset=True)

    def test_delete_virtual_port_parent(self):
        self.nb_idl.ls_get.return_value.execute.return_value = (
            fakes.FakeOvsdbRow.create_one_ovsdb_row(attrs={'ports': []}))
        virt_port = self._make_port(self.fmt, self.net['id'])['port']
        virt_ip = virt_port['fixed_ips'][0]['ip_address']
        parent = self._make_port(
            self.fmt, self.net['id'],
            allowed_address_pairs=[{'ip_address': virt_ip}])['port']
        fake_row = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'name': virt_port['id'],
                   'type': ovn_const.LSP_TYPE_VIRTUAL,
                   'options': {ovn_const.LSP_OPTIONS_VIRTUAL_PARENTS_KEY:
                               parent['id']}})
        self.nb_idl.ls_get.return_value.execute.return_value = (
            mock.Mock(ports=[fake_row]))

        self.mech_driver._ovn_client.delete_port(self.context, parent['id'])
        self.nb_idl.unset_lswitch_port_to_virtual_type.assert_called_once_with(
            virt_port['id'], parent['id'], if_exists=True)

    def test_update_port_bound(self):
        with self.port(subnet=self.subnet, is_admin=True) as port:
            port = port['port']
            updated_port = copy.deepcopy(port)
            updated_port['device_id'] = 'device_id_new'
            updated_port[portbindings.HOST_ID] = 'host_id_new'
            _context = mock.Mock(current=updated_port, original=port)
            with mock.patch.object(self.mech_driver._plugin, 'get_subnets') \
                    as mock_get_subnets:
                mock_get_subnets.return_value = [self.subnet['subnet']]
                # 1) The port is not virtual, it has no parents.
                self.mock_vp_parents.return_value = ''
                self.mech_driver.update_port_precommit(_context)
                # 2) The port (LSP) has parents, that means it is a virtual
                # port.
                self.mock_vp_parents.return_value = ['parent-0', 'parent-1']
                self.assertRaises(n_exc.BadRequest,
                                  self.mech_driver.update_port_precommit,
                                  _context)


class TestOVNAvailabilityZone(OVNMechanismDriverTestCase):

    def setUp(self):
        super(TestOVNAvailabilityZone, self).setUp()
        self.context = context.get_admin_context()
        self.sb_idl = self.mech_driver._ovn_client._sb_idl

    def test_list_availability_zones(self):
        ch0 = fakes.FakeChassis.create(az_list=['az0', 'az1'],
                                       chassis_as_gw=True)
        ch1 = fakes.FakeChassis.create(az_list=[], chassis_as_gw=False)
        ch2 = fakes.FakeChassis.create(az_list=['az2'], chassis_as_gw=True)
        ch3 = fakes.FakeChassis.create(az_list=[], chassis_as_gw=True)
        self.sb_idl.chassis_list.return_value.execute.return_value = [
            ch0, ch1, ch2, ch3]

        azs = self.mech_driver.list_availability_zones(self.context)
        expected_azs = {'az0': {'name': 'az0', 'resource': 'router',
                                'state': 'available', 'tenant_id': mock.ANY},
                        'az1': {'name': 'az1', 'resource': 'router',
                                'state': 'available', 'tenant_id': mock.ANY},
                        'az2': {'name': 'az2', 'resource': 'router',
                                'state': 'available', 'tenant_id': mock.ANY}}
        self.assertEqual(expected_azs, azs)

    def test_list_availability_zones_no_azs(self):
        ch0 = fakes.FakeChassis.create(az_list=[], chassis_as_gw=True)
        ch1 = fakes.FakeChassis.create(az_list=[], chassis_as_gw=True)
        self.sb_idl.chassis_list.return_value.execute.return_value = [
            ch0, ch1]

        azs = self.mech_driver.list_availability_zones(mock.Mock())
        self.assertEqual({}, azs)
