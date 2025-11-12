# Copyright 2019 Red Hat, Inc.
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

import collections
from unittest import mock

from neutron_lib import constants as const
from neutron_lib.services.logapi import constants as log_const
from oslo_utils import uuidutils

from neutron.common.ovn import acl
from neutron.common.ovn import constants as ovn_const
from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb import impl_idl_ovn
from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb import ovn_client
from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb import ovn_db_sync
from neutron.services.ovn_l3 import plugin as ovn_plugin
from neutron.tests.unit import fake_resources as fakes
from neutron.tests.unit.plugins.ml2.drivers.ovn.mech_driver import \
    test_mech_driver
from neutron.tests.unit.services.logapi.drivers.ovn import test_driver

OvnPortInfo = collections.namedtuple('OvnPortInfo', ['name'])


@mock.patch.object(ovn_plugin.OVNL3RouterPlugin, '_sb_ovn', mock.Mock())
class TestOvnNbSyncML2(test_mech_driver.OVNMechanismDriverTestCase):

    l3_plugin = 'ovn-router'

    def setUp(self):
        # We want metadata enabled to increase coverage
        super().setUp(enable_metadata=True)

        self.test_log_driver = test_driver.TestOVNDriver()
        self.subnet = {'cidr': '10.0.0.0/24',
                       'id': 'subnet1',
                       'subnetpool_id': None,
                       'name': 'private-subnet',
                       'enable_dhcp': True,
                       'network_id': 'n1',
                       'tenant_id': 'tenant1',
                       'gateway_ip': '10.0.0.1',
                       'ip_version': 4,
                       'shared': False}
        self.matches = ["", "", "", ""]

        self.networks = [{'id': 'n1',
                          'mtu': 1450,
                          'provider:physical_network': 'physnet1',
                          'provider:segmentation_id': 1000},
                         {'id': 'n2',
                          'mtu': 1450},
                         {'id': 'n4',
                          'mtu': 1450,
                          'provider:physical_network': 'physnet2'}]

        self.segments = [{'id': 'seg1',
                          'network_id': 'n1',
                          'physical_network': 'physnet1',
                          'network_type': 'vlan',
                          'segmentation_id': 1000},
                         {'id': 'seg2',
                          'network_id': 'n2',
                          'physical_network': None,
                          'network_type': 'geneve'},
                         {'id': 'seg4',
                          'network_id': 'n4',
                          'physical_network': 'physnet2',
                          'network_type': 'flat'}]
        self.segments_map = {
            k['network_id']: k
            for k in self.segments}

        self.subnets = [{'id': 'n1-s1',
                         'network_id': 'n1',
                         'enable_dhcp': True,
                         'cidr': '10.0.0.0/24',
                         'tenant_id': 'tenant1',
                         'gateway_ip': '10.0.0.1',
                         'dns_nameservers': [],
                         'host_routes': [],
                         'ip_version': 4},
                        {'id': 'n1-s2',
                         'network_id': 'n1',
                         'enable_dhcp': True,
                         'cidr': 'fd79:e1c:a55::/64',
                         'tenant_id': 'tenant1',
                         'gateway_ip': 'fd79:e1c:a55::1',
                         'dns_nameservers': [],
                         'host_routes': [],
                         'ip_version': 6},
                        {'id': 'n2',
                         'network_id': 'n2',
                         'enable_dhcp': True,
                         'cidr': '20.0.0.0/24',
                         'tenant_id': 'tenant1',
                         'gateway_ip': '20.0.0.1',
                         'dns_nameservers': [],
                         'host_routes': [],
                         'ip_version': 4},
                        # A subnet without a known network should be skipped,
                        # see bug #2045811
                        {'id': 'notfound',
                         'network_id': 'notfound',
                         'enable_dhcp': True,
                         'cidr': '30.0.0.0/24',
                         'tenant_id': 'tenant1',
                         'gateway_ip': '30.0.0.1',
                         'dns_nameservers': [],
                         'host_routes': [],
                         'ip_version': 4}]

        self.security_groups = [
            {'id': 'sg1', 'tenant_id': 'tenant1',
             'security_group_rules': [{'remote_group_id': None,
                                       'direction': 'ingress',
                                       'remote_ip_prefix': const.IPv4_ANY,
                                       'protocol': 'tcp',
                                       'ethertype': 'IPv4',
                                       'tenant_id': 'tenant1',
                                       'port_range_max': 65535,
                                       'port_range_min': 1,
                                       'id': 'ruleid1',
                                       'security_group_id': 'sg1'}],
             'name': 'all-tcp'},
            {'id': 'sg2', 'tenant_id': 'tenant1',
             'security_group_rules': [{'remote_group_id': 'sg2',
                                       'direction': 'egress',
                                       'remote_ip_prefix': const.IPv4_ANY,
                                       'protocol': 'tcp',
                                       'ethertype': 'IPv4',
                                       'tenant_id': 'tenant1',
                                       'port_range_max': 65535,
                                       'port_range_min': 1,
                                       'id': 'ruleid1',
                                       'security_group_id': 'sg2'}],
             'name': 'all-tcpe'}]

        self.sg_port_groups_ovn = [mock.Mock(), mock.Mock(), mock.Mock(), mock.Mock()]
        self.sg_port_groups_ovn[0].configure_mock(
            name='pg_sg1',
            external_ids={ovn_const.OVN_SG_EXT_ID_KEY: 'sg1'},
            ports=[],
            acls=[])
        self.sg_port_groups_ovn[1].configure_mock(
            name='pg_unknown_del',
            external_ids={ovn_const.OVN_SG_EXT_ID_KEY: 'sg2'},
            ports=[],
            acls=[])
        self.sg_port_groups_ovn[2].configure_mock(
            name=ovn_const.OVN_DROP_PORT_GROUP_NAME,
            external_ids={},
            ports=[],
            acls=[])
        self.sg_port_groups_ovn[3].configure_mock(
            name='external_pg',
            external_ids={'owner': 'not-owned-by-neutron'},
            ports=[],
            acls=[])

        self.ports = [
            {'id': 'p1n1',
             'device_owner': 'compute:None',
             'fixed_ips':
                 [{'subnet_id': 'b142f5e3-d434-4740-8e88-75e8e5322a40',
                   'ip_address': '10.0.0.4'},
                  {'subnet_id': 'subnet1',
                   'ip_address': 'fd79:e1c:a55::816:eff:eff:ff2'}],
             'security_groups': ['sg1'],
             'network_id': 'n1'},
            {'id': 'p2n1',
             'device_owner': 'compute:None',
             'fixed_ips':
                 [{'subnet_id': 'b142f5e3-d434-4740-8e88-75e8e5322a40',
                   'ip_address': '10.0.0.4'},
                  {'subnet_id': 'subnet1',
                   'ip_address': 'fd79:e1c:a55::816:eff:eff:ff2'}],
             'security_groups': ['sg2'],
             'network_id': 'n1',
             'extra_dhcp_opts': [{'ip_version': 6,
                                  'opt_name': 'domain-search',
                                  'opt_value': 'foo-domain'}]},
            {'id': 'p1n2',
             'device_owner': 'compute:None',
             'fixed_ips':
                 [{'subnet_id': 'b142f5e3-d434-4740-8e88-75e8e5322a40',
                   'ip_address': '10.0.0.4'},
                  {'subnet_id': 'subnet1',
                   'ip_address': 'fd79:e1c:a55::816:eff:eff:ff2'}],
             'security_groups': ['sg1'],
             'network_id': 'n2',
             'extra_dhcp_opts': [{'ip_version': 4,
                                  'opt_name': 'tftp-server',
                                  'opt_value': '20.0.0.20'},
                                 {'ip_version': 4,
                                  'opt_name': 'dns-server',
                                  'opt_value': '8.8.8.8'},
                                 {'ip_version': 6,
                                  'opt_name': 'domain-search',
                                  'opt_value': 'foo-domain'}]},
            {'id': 'p2n2',
             'device_owner': 'compute:None',
             'fixed_ips':
                 [{'subnet_id': 'b142f5e3-d434-4740-8e88-75e8e5322a40',
                   'ip_address': '10.0.0.4'},
                  {'subnet_id': 'subnet1',
                   'ip_address': 'fd79:e1c:a55::816:eff:eff:ff2'}],
             'security_groups': ['sg2'],
             'network_id': 'n2'},
            {'id': 'fp1',
             'device_owner': 'network:floatingip',
             'fixed_ips':
                 [{'subnet_id': 'ext-subnet',
                   'ip_address': '90.0.0.10'}],
             'network_id': 'ext-net'}]

        self.ports_ovn = [OvnPortInfo('p1n1'), OvnPortInfo('p1n2'),
                          OvnPortInfo('p2n1'), OvnPortInfo('p2n2'),
                          OvnPortInfo('p3n1'), OvnPortInfo('p3n3')]

        self.acls_ovn = {
            'lport1':
            # ACLs need to be removed by the sync tool
            [{'id': 'acl1', 'priority': 00, 'policy': 'allow',
              'lswitch': 'lswitch1', 'lport': 'lport1'}],
            'lport2':
            [{'id': 'acl2', 'priority': 00, 'policy': 'drop',
             'lswitch': 'lswitch2', 'lport': 'lport2'},
             {'id': 'aclr3', 'priority': 00, 'log': True,
              'policy': 'drop', 'lswitch': 'lswitch2',
              'meter': 'acl_log_meter', 'label': 1, 'lport': 'lport2'}],
            # ACLs need to be kept as-is by the sync tool
            'p2n2':
            [{'lport': 'p2n2', 'direction': 'to-lport',
              'log': False, 'lswitch': 'neutron-n2',
              'priority': 1001, 'action': 'drop',
             'external_ids': {'neutron:lport': 'p2n2'},
              'match': 'outport == "p2n2" && ip'},
             {'lport': 'p2n2', 'direction': 'to-lport',
              'log': False, 'lswitch': 'neutron-n2',
              'priority': 1002, 'action': 'allow',
              'external_ids': {'neutron:lport': 'p2n2'},
              'match': 'outport == "p2n2" && ip4 && '
              'ip4.src == 10.0.0.0/24 && udp && '
              'udp.src == 67 && udp.dst == 68'}]}

        self.routers = [{'id': 'r1', 'routes': [{'nexthop': '20.0.0.100',
                         'destination': '11.0.0.0/24'}, {
                         'nexthop': '20.0.0.101',
                         'destination': '12.0.0.0/24',
                         'external_ids': {}}],
                         'gw_port_id': 'gpr1',
                         'enable_snat': True,
                         'external_gateway_info': {
                             'network_id': "ext-net", 'enable_snat': True,
                             'external_fixed_ips': [
                                 {'subnet_id': 'ext-subnet',
                                  'ip_address': '90.0.0.2'}]}},
                        {'id': 'r2', 'routes': [{'nexthop': '40.0.0.100',
                         'destination': '30.0.0.0/24',
                                                 'external_ids': {}}],
                         'gw_port_id': 'gpr2',
                         'enable_snat': True,
                         'external_gateway_info': {
                             'network_id': "ext-net", 'enable_snat': True,
                             'external_fixed_ips': [
                                 {'subnet_id': 'ext-subnet',
                                  'ip_address': '100.0.0.2'}]}},
                        {'id': 'r4', 'routes': []},
                        {'id': 'r5', 'routes': [],
                         'flavor_id': 'user-defined'}]

        self.get_sync_router_ports = [
            {'fixed_ips': [{'subnet_id': 'subnet1',
                            'ip_address': '192.168.1.1'}],
             'id': 'p1r1',
             'device_id': 'r1',
             'mac_address': 'fa:16:3e:d7:fd:5f'},
            {'fixed_ips': [{'subnet_id': 'subnet2',
                            'ip_address': '192.168.2.1'}],
             'id': 'p1r2',
             'device_id': 'r2',
             'mac_address': 'fa:16:3e:d6:8b:ce'},
            {'fixed_ips': [{'subnet_id': 'subnet4',
                            'ip_address': '192.168.4.1'}],
             'id': 'p1r4',
             'device_id': 'r4',
             'mac_address': 'fa:16:3e:12:34:56'}]

        self.floating_ips = [{'id': 'fip1', 'router_id': 'r1',
                              'floating_ip_address': '90.0.0.10',
                              'fixed_ip_address': '172.16.0.10'},
                             {'id': 'fip2', 'router_id': 'r1',
                              'floating_ip_address': '90.0.0.12',
                              'fixed_ip_address': '172.16.2.12'},
                             {'id': 'fip3', 'router_id': 'r2',
                              'floating_ip_address': '100.0.0.10',
                              'fixed_ip_address': '192.168.2.10'},
                             {'id': 'fip4', 'router_id': 'r2',
                              'floating_ip_address': '100.0.0.11',
                              'fixed_ip_address': '192.168.2.11'}]

        self.lrouters_with_rports = [{'name': 'r3',
                                      'ports': {'p1r3': ['fake']},
                                      'static_routes': [],
                                      'snats': [],
                                      'dnat_and_snats': []},
                                     {'name': 'r4',
                                      'ports': {'p1r4':
                                                ['fdad:123:456::1/64',
                                                 'fdad:789:abc::1/64']},
                                      'static_routes': [],
                                      'snats': [],
                                      'dnat_and_snats': []},
                                     {'name': 'r1',
                                      'ports': {'p3r1': ['fake']},
                                      'static_routes':
                                      [{'nexthop': '20.0.0.100',
                                        'destination': '11.0.0.0/24'},
                                       {'nexthop': '20.0.0.100',
                                        'destination': '10.0.0.0/24'}],
                                      'snats':
                                      [{'logical_ip': '172.16.0.0/24',
                                        'external_ip': '90.0.0.2',
                                        'type': 'snat'},
                                       {'logical_ip': '172.16.1.0/24',
                                        'external_ip': '90.0.0.2',
                                        'type': 'snat'}],
                                      'dnat_and_snats':
                                      [{'logical_ip': '172.16.0.10',
                                        'external_ip': '90.0.0.10',
                                        'type': 'dnat_and_snat'},
                                       {'logical_ip': '172.16.1.11',
                                        'external_ip': '90.0.0.11',
                                        'type': 'dnat_and_snat'},
                                       {'logical_ip': '192.168.2.11',
                                        'external_ip': '100.0.0.11',
                                        'type': 'dnat_and_snat',
                                        'external_mac': '01:02:03:04:05:06',
                                        'logical_port': 'vm1'}]}]

        self.lswitches_with_ports = [{'name': 'neutron-n1',
                                      'ports': ['p1n1', 'p3n1'],
                                      'provnet_ports': []},
                                     {'name': 'neutron-n3',
                                      'ports': ['p1n3', 'p2n3'],
                                      'provnet_ports': []},
                                     {'name': 'neutron-n4',
                                      'ports': [],
                                      'provnet_ports': [
                                          'provnet-seg4',
                                          'provnet-orphaned-segment']}]

        self.lrport_networks = ['fdad:123:456::1/64', 'fdad:cafe:a1b2::1/64']

    def get_additional_service_plugins(self):
        p = super().get_additional_service_plugins()
        p.update({'segments': 'neutron.services.segments.plugin.Plugin'})
        return p

    def _fake_get_ovn_dhcp_options(self, context, subnet, network,
                                   server_mac=None):
        if subnet['id'] == 'n1-s1':
            return {'cidr': '10.0.0.0/24',
                    'options': {'server_id': '10.0.0.1',
                                'server_mac': '01:02:03:04:05:06',
                                'lease_time': str(12 * 60 * 60),
                                'mtu': '1450',
                                'router': '10.0.0.1'},
                    'external_ids': {'subnet_id': 'n1-s1'}}
        return {'cidr': '', 'options': '', 'external_ids': {}}

    def _fake_get_gw_info(self, ctx, port):
        return {
            'p1r1': [ovn_client.GW_INFO(router_ip='90.0.0.2',
                                        gateway_ip='90.0.0.1',
                                        network_id='', subnet_id='ext-subnet',
                                        ip_version=4,
                                        ip_prefix=const.IPv4_ANY)],
            'p1r2': [ovn_client.GW_INFO(router_ip='100.0.0.2',
                                        gateway_ip='100.0.0.1',
                                        network_id='', subnet_id='ext-subnet',
                                        ip_version=4,
                                        ip_prefix=const.IPv4_ANY)]
        }.get(port['id'], [])

    def _fake_get_snat_cidrs_for_external_router(self, ctx, router_id):
        return {'r1': ['172.16.0.0/24', '172.16.2.0/24'],
                'r2': ['192.168.2.0/24']}.get(router_id, [])

    def _test_mocks_helper(self, ovn_nb_synchronizer, test_logging=False):
        core_plugin = ovn_nb_synchronizer.core_plugin
        ovn_api = ovn_nb_synchronizer.ovn_api
        ovn_driver = ovn_nb_synchronizer.ovn_driver
        l3_plugin = ovn_nb_synchronizer.l3_plugin
        pf_plugin = ovn_nb_synchronizer.pf_plugin
        segments_plugin = ovn_nb_synchronizer.segments_plugin

        core_plugin.get_networks = mock.Mock()
        core_plugin.get_networks.return_value = self.networks
        core_plugin.get_subnets = mock.Mock()
        core_plugin.get_subnets.return_value = self.subnets

        def get_segments(self, filters):
            segs = []
            for segment in self.segments:
                if segment['network_id'] == filters['network_id'][0]:
                    segs.append(segment)
            return segs

        def get_ports():
            def wrapper(*args, **kwargs):
                # We need to do this since blindly returning self.ports
                # if caller specified a filter could lead to failed tests,
                # for example, it will not filter out non-metadata ports.
                filters = kwargs.get('filters')
                if not filters:
                    return self.ports
                ports = [port for port in self.ports if
                         all(port[k] in v for k, v in filters.items())]
                return ports

            return wrapper

        segments_plugin.get_segments = mock.Mock()
        segments_plugin.get_segments.side_effect = (
            lambda x, filters: get_segments(self, filters))

        # following block is used for acl syncing unit-test

        # With the given set of values in the unit testing,
        # 19 neutron acls should have been there,
        # 4 acls are returned as current ovn acls,
        # two of which will match with neutron.
        # So, in this example 17 will be added, 2 removed

        core_plugin.get_ports = mock.Mock()
        core_plugin.get_ports.side_effect = get_ports()
        mock.patch.object(acl, '_get_subnet_from_cache',
                          return_value=self.subnet).start()
        mock.patch.object(acl, 'acl_remote_group_id',
                          side_effect=self.matches).start()
        if test_logging:
            log_objs = [self.test_log_driver._fake_log_obj(
                event=log_const.DROP_EVENT, resource_id=None, id='1111')]
            mock.patch.object(ovn_nb_synchronizer.ovn_log_driver, '_get_logs',
                              return_value=log_objs).start()
            mock.patch.object(ovn_nb_synchronizer.ovn_log_driver,
                              '_pgs_from_log_obj', return_value=[
                                  {'name': 'neutron_pg_drop',
                                   'external_ids': {},
                                   'acls': [uuidutils.generate_uuid()]}]
                              ).start()

        core_plugin.get_security_group = mock.MagicMock(
            side_effect=self.security_groups)
        ovn_nb_synchronizer.get_acls = mock.Mock()
        ovn_nb_synchronizer.get_acls.return_value = self.acls_ovn
        core_plugin.get_security_groups = mock.MagicMock(
            return_value=self.security_groups)
        get_sg_port_groups = mock.MagicMock()
        get_sg_port_groups.execute.return_value = self.sg_port_groups_ovn
        ovn_api.db_list_rows.return_value = get_sg_port_groups
        ovn_api.lsp_list.execute.return_value = self.ports_ovn
        # end of acl-sync block

        # The following block is used for router and router port syncing tests
        # With the give set of values in the unit test,
        # The Neutron db has Routers r1 and r2 present.
        # The OVN db has Routers r1 and r3 present.
        # During the sync r2 will need to be created and r3 will need
        # to be deleted from the OVN db. When Router r3 is deleted, all LRouter
        # ports associated with r3 is deleted too.
        #
        # Neutron db has Router ports p1r1 in Router r1 and p1r2 in Router r2
        # OVN db has p1r3 in Router 3 and p3r1 in Router 1.
        # During the sync p1r1 and p1r2 will be added and p1r3 and p3r1
        # will be deleted from the OVN db
        l3_plugin.get_routers = mock.Mock()
        l3_plugin.get_routers.return_value = self.routers
        l3_plugin._get_sync_interfaces = mock.Mock()
        l3_plugin._get_sync_interfaces.return_value = (
            self.get_sync_router_ports)
        ovn_client = mock.Mock()
        ovn_nb_synchronizer._ovn_client = ovn_client
        ovn_client._get_nets_and_ipv6_ra_confs_for_router_port.return_value = (
                self.lrport_networks, {'fixed_ips': {}})
        ovn_client._get_snat_cidrs_for_external_router.side_effect = (
            self._fake_get_snat_cidrs_for_external_router)
        ovn_client._get_gw_info = mock.Mock()
        ovn_client._get_gw_info.side_effect = self._fake_get_gw_info
        # end of router-sync block
        l3_plugin.get_floatingips = mock.Mock()
        l3_plugin.get_floatingips.return_value = self.floating_ips
        pf_plugin.get_floatingip_port_forwardings = mock.Mock(return_value=[])
        ovn_api.get_all_logical_switches_with_ports = mock.Mock()
        ovn_api.get_all_logical_switches_with_ports.return_value = (
            self.lswitches_with_ports)

        ovn_api.get_all_logical_routers_with_rports = mock.Mock()
        ovn_api.get_all_logical_routers_with_rports.return_value = (
            self.lrouters_with_rports)

        ovn_api.transaction = mock.MagicMock()

        ovn_nb_synchronizer._ovn_client.create_network = mock.Mock()
        ovn_driver.validate_and_get_data_from_binding_profile = mock.Mock()
        ovn_nb_synchronizer._ovn_client.create_port = mock.Mock()
        ovn_nb_synchronizer._ovn_client.create_port.return_value = mock.ANY
        ovn_nb_synchronizer._ovn_client.create_metadata_port = mock.Mock()
        ovn_nb_synchronizer._ovn_client.create_provnet_port = mock.Mock()
        ovn_api.ls_del = mock.Mock()
        ovn_api.delete_lswitch_port = mock.Mock()

        ovn_api.delete_lrouter = mock.Mock()
        ovn_api.delete_lrouter_port = mock.Mock()
        ovn_api.add_static_route = mock.Mock()
        ovn_api.delete_static_routes = mock.Mock()
        ovn_api.get_all_dhcp_options.return_value = {
            'subnets': {'n1-s1': {'cidr': '10.0.0.0/24',
                                  'options':
                                  {'server_id': '10.0.0.1',
                                   'server_mac': '01:02:03:04:05:06',
                                   'lease_time': str(12 * 60 * 60),
                                   'mtu': '1450',
                                   'router': '10.0.0.1'},
                                  'external_ids': {'subnet_id': 'n1-s1'},
                                  'uuid': 'UUID1'},
                        'n1-s3': {'cidr': '30.0.0.0/24',
                                  'options':
                                  {'server_id': '30.0.0.1',
                                   'server_mac': '01:02:03:04:05:06',
                                   'lease_time': str(12 * 60 * 60),
                                   'mtu': '1450',
                                   'router': '30.0.0.1'},
                                  'external_ids': {'subnet_id': 'n1-s3'},
                                  'uuid': 'UUID2'}},
            'ports_v4': {'p1n2': {'cidr': '10.0.0.0/24',
                                  'options': {'server_id': '10.0.0.1',
                                              'server_mac':
                                                  '01:02:03:04:05:06',
                                              'lease_time': '1000',
                                              'mtu': '1400',
                                              'router': '10.0.0.1'},
                                  'external_ids': {'subnet_id': 'n1-s1',
                                                   'port_id': 'p1n2'},
                                  'uuid': 'UUID3'},
                         'p5n2': {'cidr': '10.0.0.0/24',
                                  'options': {'server_id': '10.0.0.1',
                                              'server_mac':
                                                  '01:02:03:04:05:06',
                                              'lease_time': '1000',
                                              'mtu': '1400',
                                              'router': '10.0.0.1'},
                                  'external_ids': {'subnet_id': 'n1-s1',
                                                   'port_id': 'p5n2'},
                                  'uuid': 'UUID4'}},
            'ports_v6': {'p1n1': {'cidr': 'fd79:e1c:a55::/64',
                                  'options': {'server_id': '01:02:03:04:05:06',
                                              'mtu': '1450'},
                                  'external_ids': {'subnet_id': 'fake',
                                                   'port_id': 'p1n1'},
                                  'uuid': 'UUID5'},
                         'p1n2': {'cidr': 'fd79:e1c:a55::/64',
                                  'options': {'server_id': '01:02:03:04:05:06',
                                              'mtu': '1450'},
                                  'external_ids': {'subnet_id': 'fake',
                                                   'port_id': 'p1n2'},
                                  'uuid': 'UUID6'}}}

        ovn_nb_synchronizer._ovn_client._add_subnet_dhcp_options = mock.Mock()
        ovn_nb_synchronizer._ovn_client._get_ovn_dhcp_options = mock.Mock()
        ovn_nb_synchronizer._ovn_client._get_ovn_dhcp_options.side_effect = (
            self._fake_get_ovn_dhcp_options)
        ovn_api.delete_dhcp_options = mock.Mock()
        ovn_nb_synchronizer._ovn_client.get_port_dns_records = mock.Mock()
        ovn_nb_synchronizer._ovn_client.get_port_dns_records.return_value = {}
        ovn_nb_synchronizer._ovn_client._get_router_gw_ports.side_effect = (
            [self.get_sync_router_ports[0]],
            [self.get_sync_router_ports[1]],
            [self.get_sync_router_ports[2]],
        )

    def _test_ovn_nb_sync_helper(self, ovn_nb_synchronizer,
                                 networks, ports,
                                 routers, router_ports,
                                 create_router_list, create_router_port_list,
                                 update_router_port_list,
                                 del_router_list, del_router_port_list,
                                 create_network_list, create_port_list,
                                 create_provnet_port_list,
                                 del_network_list, del_port_list,
                                 add_static_route_list, del_static_route_list,
                                 add_snat_list, del_snat_list,
                                 add_floating_ip_list, del_floating_ip_list,
                                 add_subnet_dhcp_options_list,
                                 delete_dhcp_options_list,
                                 add_port_groups_list,
                                 del_port_groups_list,
                                 create_metadata_list,
                                 test_logging=False):
        self._test_mocks_helper(ovn_nb_synchronizer, test_logging)

        ovn_api = ovn_nb_synchronizer.ovn_api
        mock.patch.object(impl_idl_ovn.OvsdbNbOvnIdl, 'from_worker').start()

        ovn_nb_synchronizer.do_sync()

        create_port_groups_calls = [mock.call(**a)
                                    for a in add_port_groups_list]
        self.assertEqual(
            len(add_port_groups_list),
            ovn_api.pg_add.call_count)
        ovn_api.pg_add.assert_has_calls(
            create_port_groups_calls, any_order=True)

        del_port_groups_calls = [mock.call(d)
                                 for d in del_port_groups_list]
        self.assertEqual(
            len(del_port_groups_list),
            ovn_api.pg_del.call_count)
        ovn_api.pg_del.assert_has_calls(
            del_port_groups_calls, any_order=True)

        self.assertEqual(
            len(create_network_list),
            ovn_nb_synchronizer._ovn_client.create_network.call_count)
        create_network_calls = [mock.call(mock.ANY, net['net'])
                                for net in create_network_list]
        ovn_nb_synchronizer._ovn_client.create_network.assert_has_calls(
            create_network_calls, any_order=True)

        create_metadata_calls = [mock.call(mock.ANY, net)
                                 for net in create_metadata_list]
        self.assertEqual(
            len(create_metadata_list),
            ovn_nb_synchronizer._ovn_client.create_metadata_port.call_count)
        ovn_nb_synchronizer._ovn_client.create_metadata_port.assert_has_calls(
            create_metadata_calls, any_order=True)

        self.assertEqual(
            len(create_port_list),
            ovn_nb_synchronizer._ovn_client.create_port.call_count)
        create_port_calls = [mock.call(mock.ANY, port)
                             for port in create_port_list]
        ovn_nb_synchronizer._ovn_client.create_port.assert_has_calls(
            create_port_calls, any_order=True)

        create_provnet_port_calls = [
            mock.call(
                mock.ANY,
                network['id'],
                self.segments_map[network['id']],
                txn=mock.ANY,
                network=network)
            for network in create_provnet_port_list
            if network.get('provider:physical_network')]
        self.assertEqual(
            len(create_provnet_port_list),
            ovn_nb_synchronizer._ovn_client.create_provnet_port.call_count)
        ovn_nb_synchronizer._ovn_client.create_provnet_port.assert_has_calls(
            create_provnet_port_calls, any_order=True)

        self.assertEqual(len(del_network_list),
                         ovn_api.ls_del.call_count)
        ls_del_calls = [mock.call(net_name)
                        for net_name in del_network_list]
        ovn_api.ls_del.assert_has_calls(
            ls_del_calls, any_order=True)

        self.assertEqual(len(del_port_list),
                         ovn_api.delete_lswitch_port.call_count)
        delete_lswitch_port_calls = [mock.call(lport_name=port['id'],
                                               lswitch_name=port['lswitch'])
                                     for port in del_port_list]
        ovn_api.delete_lswitch_port.assert_has_calls(
            delete_lswitch_port_calls, any_order=True)

        add_route_calls = [mock.call(mock.ANY, ip_prefix=route['destination'],
                                     nexthop=route['nexthop'],
                                     external_ids=route.get('external_ids',
                                     {}))
                           for route in add_static_route_list]
        ovn_api.add_static_route.assert_has_calls(add_route_calls,
                                                  any_order=True)
        self.assertEqual(len(add_static_route_list),
                         ovn_api.add_static_route.call_count)
        routes_to_delete = [(route['destination'], route['nexthop'])
                            for route in del_static_route_list]
        del_route_call = [mock.call(mock.ANY, routes_to_delete)] \
            if routes_to_delete else []

        ovn_api.delete_static_routes.assert_has_calls(del_route_call)
        self.assertEqual(1 if len(del_static_route_list) else 0,
                         ovn_api.delete_static_routes.call_count)

        add_nat_calls = [mock.call(mock.ANY, **nat) for nat in add_snat_list]
        ovn_api.add_nat_rule_in_lrouter.assert_has_calls(add_nat_calls,
                                                         any_order=True)
        self.assertEqual(len(add_snat_list),
                         ovn_api.add_nat_rule_in_lrouter.call_count)

        add_fip_calls = [mock.call(mock.ANY, nat, txn=mock.ANY)
                         for nat in add_floating_ip_list]
        (ovn_nb_synchronizer._ovn_client._create_or_update_floatingip.
            assert_has_calls(add_fip_calls))
        self.assertEqual(
            len(add_floating_ip_list),
            ovn_nb_synchronizer._ovn_client._create_or_update_floatingip.
            call_count)

        del_nat_calls = [mock.call(mock.ANY, **nat) for nat in del_snat_list]
        ovn_api.delete_nat_rule_in_lrouter.assert_has_calls(del_nat_calls,
                                                            any_order=True)
        self.assertEqual(len(del_snat_list),
                         ovn_api.delete_nat_rule_in_lrouter.call_count)

        del_fip_calls = [mock.call(mock.ANY, nat, mock.ANY, txn=mock.ANY)
                         for nat in del_floating_ip_list]
        ovn_nb_synchronizer._ovn_client._delete_floatingip.assert_has_calls(
            del_fip_calls, any_order=True)
        self.assertEqual(
            len(del_floating_ip_list),
            ovn_nb_synchronizer._ovn_client._delete_floatingip.call_count)

        create_router_calls = [mock.call(mock.ANY, r,
                                         add_external_gateway=False)
                               for r in create_router_list]
        self.assertEqual(
            len(create_router_list),
            ovn_nb_synchronizer._ovn_client.create_router.call_count)
        ovn_nb_synchronizer._ovn_client.create_router.assert_has_calls(
            create_router_calls, any_order=True)

        create_router_port_calls = [
            mock.call(mock.ANY, self.routers[i], mock.ANY)
            for i, p in enumerate(create_router_port_list)]
        self.assertEqual(
            len(create_router_port_list),
            ovn_nb_synchronizer._ovn_client._create_lrouter_port.call_count)
        ovn_nb_synchronizer._ovn_client._create_lrouter_port.assert_has_calls(
            create_router_port_calls,
            any_order=True)

        self.assertEqual(len(del_router_list), ovn_api.lr_del.call_count)
        update_router_port_calls = [mock.call(mock.ANY, p)
                                    for p in update_router_port_list]
        self.assertEqual(
            len(update_router_port_list),
            ovn_nb_synchronizer._ovn_client.update_router_port.call_count)
        ovn_nb_synchronizer._ovn_client.update_router_port.assert_has_calls(
            update_router_port_calls,
            any_order=True)

        delete_lrouter_calls = [mock.call(r['router'], if_exists=True)
                                for r in del_router_list]
        ovn_api.lr_del.assert_has_calls(delete_lrouter_calls, any_order=True)

        self.assertEqual(
            len(del_router_port_list),
            ovn_api.delete_lrouter_port.call_count)
        delete_lrouter_port_calls = [mock.call(port['id'],
                                               port['router'], if_exists=False)
                                     for port in del_router_port_list]
        ovn_api.delete_lrouter_port.assert_has_calls(
            delete_lrouter_port_calls, any_order=True)

        self.assertEqual(
            len(add_subnet_dhcp_options_list),
            ovn_nb_synchronizer._ovn_client._add_subnet_dhcp_options.
            call_count)
        add_subnet_dhcp_options_calls = [
            mock.call(mock.ANY, subnet, net, mock.ANY)
            for (subnet, net) in add_subnet_dhcp_options_list]
        ovn_nb_synchronizer._ovn_client._add_subnet_dhcp_options. \
            assert_has_calls(add_subnet_dhcp_options_calls, any_order=True)

        self.assertEqual(ovn_api.delete_dhcp_options.call_count,
                         len(delete_dhcp_options_list))
        delete_dhcp_options_calls = [
            mock.call(dhcp_opt_uuid)
            for dhcp_opt_uuid in delete_dhcp_options_list]
        ovn_api.delete_dhcp_options.assert_has_calls(
            delete_dhcp_options_calls, any_order=True)

        if test_logging:
            # 2 times when doing add_logging_options_to_acls and then
            # 2 times because of the add_label_related used 2 times for the
            # from-port and to-port drop acls
            self.assertEqual(4, ovn_nb_synchronizer.ovn_log_driver.
                             _pgs_from_log_obj.call_count)

    def _test_ovn_nb_sync_mode_repair(self, test_logging=False):

        create_network_list = [{'net': {'id': 'n2', 'mtu': 1450},
                                'ext_ids': {}}]
        del_network_list = ['neutron-n3']
        del_port_list = [{'id': 'p3n1', 'lswitch': 'neutron-n1'},
                         {'id': 'p1n1', 'lswitch': 'neutron-n1'},
                         {'id': 'provnet-orphaned-segment',
                          'lswitch': 'neutron-n4'}]
        create_port_list = self.ports
        for port in create_port_list.copy():
            if port['id'] in ['p1n1', 'fp1']:
                # this will be skipped by the logic,
                # because p1n1 is already in lswitch-port list
                # and fp1 is a floating IP port
                create_port_list.remove(port)
        create_provnet_port_list = [{'id': 'n1', 'mtu': 1450,
                                     'provider:physical_network': 'physnet1',
                                     'provider:segmentation_id': 1000}]
        create_router_list = [{
            'id': 'r2', 'routes': [
                {'nexthop': '40.0.0.100', 'destination': '30.0.0.0/24',
                 'external_ids': {}}],
            'gw_port_id': 'gpr2',
            'enable_snat': True,
            'external_gateway_info': {
                'network_id': "ext-net", 'enable_snat': True,
                'external_fixed_ips': [{
                    'subnet_id': 'ext-subnet',
                    'ip_address': '100.0.0.2'}]}}]

        # Test adding and deleting routes snats fips behaviors for router r1
        # existing in both neutron DB and OVN DB.
        # Test adding behaviors for router r2 only existing in neutron DB.
        # Static routes with destination 0.0.0.0/0 are default gateway routes
        add_static_route_list = [{'nexthop': '20.0.0.101',
                                  'destination': '12.0.0.0/24',
                                  'external_ids': {}},
                                 {'nexthop': '90.0.0.1',
                                  'destination': const.IPv4_ANY,
                                  'external_ids': {
                                      ovn_const.OVN_ROUTER_IS_EXT_GW: 'true',
                                      ovn_const.OVN_SUBNET_EXT_ID_KEY:
                                      'ext-subnet'}},
                                 {'nexthop': '40.0.0.100',
                                  'destination': '30.0.0.0/24',
                                  'external_ids': {}},
                                 {'nexthop': '100.0.0.1',
                                  'destination': const.IPv4_ANY,
                                  'external_ids': {
                                      ovn_const.OVN_ROUTER_IS_EXT_GW: 'true',
                                      ovn_const.OVN_SUBNET_EXT_ID_KEY:
                                      'ext-subnet'}}]
        del_static_route_list = [{'nexthop': '20.0.0.100',
                                  'destination': '10.0.0.0/24',
                                  'external_ids': {}}]
        add_snat_list = [{'logical_ip': '172.16.2.0/24',
                          'external_ip': '90.0.0.2',
                          'type': 'snat'},
                         {'logical_ip': '192.168.2.0/24',
                          'external_ip': '100.0.0.2',
                          'type': 'snat'}]
        del_snat_list = [{'logical_ip': '172.16.1.0/24',
                          'external_ip': '90.0.0.2',
                          'type': 'snat'}]
        # fip 100.0.0.11 exists in OVN with distributed type and in Neutron
        # with centralized type. This fip is used to test
        # enable_distributed_floating_ip switch and migration
        add_floating_ip_list = [{'id': 'fip2', 'router_id': 'r1',
                                 'floating_ip_address': '90.0.0.12',
                                 'fixed_ip_address': '172.16.2.12'},
                                {'id': 'fip3', 'router_id': 'r2',
                                 'floating_ip_address': '100.0.0.10',
                                 'fixed_ip_address': '192.168.2.10'},
                                {'id': 'fip4', 'router_id': 'r2',
                                 'floating_ip_address': '100.0.0.11',
                                 'fixed_ip_address': '192.168.2.11'}]
        del_floating_ip_list = [{'logical_ip': '172.16.1.11',
                                 'external_ip': '90.0.0.11',
                                 'type': 'dnat_and_snat'},
                                {'logical_ip': '192.168.2.11',
                                 'external_ip': '100.0.0.11',
                                 'type': 'dnat_and_snat',
                                 'external_mac': '01:02:03:04:05:06',
                                 'logical_port': 'vm1'}]

        del_router_list = [{'router': 'neutron-r3'}]
        del_router_port_list = [{'id': 'lrp-p3r1', 'router': 'neutron-r1'}]
        create_router_port_list = self.get_sync_router_ports[:2]
        update_router_port_list = [self.get_sync_router_ports[2]]
        update_router_port_list[0].update(
            {'networks': self.lrport_networks})

        add_port_groups_list = [
            {'external_ids': {ovn_const.OVN_SG_EXT_ID_KEY: 'sg2'},
             'name': 'pg_sg2',
             'acls': []}]
        del_port_groups_list = ['pg_unknown_del']

        add_subnet_dhcp_options_list = [(self.subnets[2], self.networks[1]),
                                        (self.subnets[1], self.networks[0])]
        delete_dhcp_options_list = ['UUID2', 'UUID4', 'UUID5']
        create_metadata_list = self.networks

        ovn_nb_synchronizer = ovn_db_sync.OvnNbSynchronizer(
            self.plugin, self.mech_driver.nb_ovn, self.mech_driver.sb_ovn,
            ovn_const.OVN_DB_SYNC_MODE_REPAIR, self.mech_driver)
        self._test_ovn_nb_sync_helper(ovn_nb_synchronizer,
                                      self.networks,
                                      self.ports,
                                      self.routers,
                                      self.get_sync_router_ports,
                                      create_router_list,
                                      create_router_port_list,
                                      update_router_port_list,
                                      del_router_list, del_router_port_list,
                                      create_network_list, create_port_list,
                                      create_provnet_port_list,
                                      del_network_list, del_port_list,
                                      add_static_route_list,
                                      del_static_route_list,
                                      add_snat_list,
                                      del_snat_list,
                                      add_floating_ip_list,
                                      del_floating_ip_list,
                                      add_subnet_dhcp_options_list,
                                      delete_dhcp_options_list,
                                      add_port_groups_list,
                                      del_port_groups_list,
                                      create_metadata_list,
                                      test_logging)

    def test_ovn_nb_sync_mode_repair(self):
        self._test_ovn_nb_sync_mode_repair(test_logging=False)

    def test_ovn_nb_sync_mode_repair_logs_created(self):
        self._test_ovn_nb_sync_mode_repair(test_logging=True)

    def test_ovn_nb_sync_mode_log(self):
        create_network_list = []
        create_port_list = []
        create_provnet_port_list = []
        del_network_list = []
        del_port_list = []
        create_router_list = []
        create_router_port_list = []
        update_router_port_list = []
        del_router_list = []
        del_router_port_list = []
        add_static_route_list = []
        del_static_route_list = []
        add_snat_list = []
        del_snat_list = []
        add_floating_ip_list = []
        del_floating_ip_list = []
        add_subnet_dhcp_options_list = []
        delete_dhcp_options_list = []
        add_port_groups_list = []
        del_port_groups_list = []
        create_metadata_list = []

        ovn_nb_synchronizer = ovn_db_sync.OvnNbSynchronizer(
            self.plugin, self.mech_driver.nb_ovn, self.mech_driver.sb_ovn,
            ovn_const.OVN_DB_SYNC_MODE_LOG, self.mech_driver)
        self._test_ovn_nb_sync_helper(ovn_nb_synchronizer,
                                      self.networks,
                                      self.ports,
                                      self.routers,
                                      self.get_sync_router_ports,
                                      create_router_list,
                                      create_router_port_list,
                                      update_router_port_list,
                                      del_router_list, del_router_port_list,
                                      create_network_list, create_port_list,
                                      create_provnet_port_list,
                                      del_network_list, del_port_list,
                                      add_static_route_list,
                                      del_static_route_list,
                                      add_snat_list,
                                      del_snat_list,
                                      add_floating_ip_list,
                                      del_floating_ip_list,
                                      add_subnet_dhcp_options_list,
                                      delete_dhcp_options_list,
                                      add_port_groups_list,
                                      del_port_groups_list,
                                      create_metadata_list)

    def _test_ovn_nb_sync_calculate_routes_helper(self,
                                                  ovn_routes,
                                                  db_routes,
                                                  expected_added,
                                                  expected_deleted):
        ovn_nb_synchronizer = ovn_db_sync.OvnNbSynchronizer(
            self.plugin, self.mech_driver.nb_ovn, self.mech_driver.sb_ovn,
            ovn_const.OVN_DB_SYNC_MODE_REPAIR, self.mech_driver)
        add_routes, del_routes = ovn_nb_synchronizer. \
            _calculate_routes_differences(ovn_routes, db_routes)
        self.assertEqual(add_routes, expected_added)
        self.assertEqual(del_routes, expected_deleted)

    def test_ovn_nb_sync_calculate_routes_add_two_routes(self):

        # add 2 routes to ovn
        ovn_routes = []
        db_routes = [{'nexthop': '20.0.0.100',
                      'destination': '11.0.0.0/24',
                      'external_ids': {}},
                     {'nexthop': '90.0.0.1',
                      'destination': const.IPv4_ANY,
                      'external_ids': {
                          ovn_const.OVN_ROUTER_IS_EXT_GW: 'true',
                          ovn_const.OVN_SUBNET_EXT_ID_KEY: 'ext-subnet'}}]
        expected_added = db_routes
        expected_deleted = []
        self._test_ovn_nb_sync_calculate_routes_helper(ovn_routes,
                                                       db_routes,
                                                       expected_added,
                                                       expected_deleted)

    def test_ovn_nb_sync_calculate_routes_remove_two_routes(self):

        # remove 2 routes from ovn
        ovn_routes = [{'nexthop': '20.0.0.100',
                       'destination': '11.0.0.0/24',
                       'external_ids': {}},
                      {'nexthop': '90.0.0.1',
                       'destination': const.IPv4_ANY,
                       'external_ids': {
                            ovn_const.OVN_ROUTER_IS_EXT_GW: 'true',
                            ovn_const.OVN_SUBNET_EXT_ID_KEY: 'ext-subnet'}}]
        db_routes = []
        expected_added = []
        expected_deleted = ovn_routes
        self._test_ovn_nb_sync_calculate_routes_helper(ovn_routes,
                                                       db_routes,
                                                       expected_added,
                                                       expected_deleted)

    def test_ovn_nb_sync_calculate_routes_remove_and_add_two_routes(self):

        # remove 2 routes from ovn, add 2 routes to ovn
        ovn_routes = [{'nexthop': '90.0.0.1',
                       'destination': const.IPv4_ANY,
                       'external_ids': {
                            ovn_const.OVN_ROUTER_IS_EXT_GW: 'true',
                            ovn_const.OVN_SUBNET_EXT_ID_KEY: 'ext-subnet'}},
                      {'nexthop': '20.0.0.100',
                       'destination': '13.0.0.0/24',
                       'external_ids': {}}]
        db_routes = [{'nexthop': '20.0.0.100',
                      'destination': '11.0.0.0/24',
                      'external_ids': {}},
                     {'nexthop': '20.0.0.100',
                     'destination': '12.0.0.0/24',
                      'external_ids': {}}]
        expected_added = db_routes
        expected_deleted = ovn_routes
        self._test_ovn_nb_sync_calculate_routes_helper(ovn_routes,
                                                       db_routes,
                                                       expected_added,
                                                       expected_deleted)

    def test_ovn_nb_sync_calculate_routes_remove_and_keep_two_routes(self):

        # remove 2 routes from ovn, keep 2 routes
        ovn_routes = [{'nexthop': '20.0.0.100',
                       'destination': '11.0.0.0/24',
                       'external_ids': {}},
                      {'nexthop': '20.0.0.100',
                       'destination': '12.0.0.0/24',
                       'external_ids': {}},
                      {'nexthop': '90.0.0.1',
                       'destination': const.IPv4_ANY,
                       'external_ids': {
                            ovn_const.OVN_ROUTER_IS_EXT_GW: 'true',
                            ovn_const.OVN_SUBNET_EXT_ID_KEY: 'ext-subnet'}},
                      {'nexthop': '20.0.0.100',
                       'destination': '13.0.0.0/24',
                       'external_ids': {}}]
        db_routes = [{'nexthop': '20.0.0.100',
                      'destination': '11.0.0.0/24',
                      'external_ids': {}},
                     {'nexthop': '20.0.0.100',
                     'destination': '12.0.0.0/24',
                      'external_ids': {}}]
        expected_added = []
        expected_deleted = [{'nexthop': '90.0.0.1',
                             'destination': const.IPv4_ANY,
                             'external_ids': {
                                 ovn_const.OVN_ROUTER_IS_EXT_GW: 'true',
                                 ovn_const.OVN_SUBNET_EXT_ID_KEY:
                                     'ext-subnet'}},
                            {'nexthop': '20.0.0.100',
                             'destination': '13.0.0.0/24',
                             'external_ids': {}}]
        self._test_ovn_nb_sync_calculate_routes_helper(ovn_routes,
                                                       db_routes,
                                                       expected_added,
                                                       expected_deleted)

    def test_ovn_nb_sync_calculate_routes_add_and_keep_two_routes(self):

        # add 2 routes to ovn, keep 2 routes
        ovn_routes = [{'nexthop': '20.0.0.100',
                       'destination': '11.0.0.0/24',
                       'external_ids': {}},
                      {'nexthop': '20.0.0.100',
                       'destination': '12.0.0.0/24',
                       'external_ids': {}}]
        db_routes = [{'nexthop': '20.0.0.100',
                      'destination': '11.0.0.0/24',
                      'external_ids': {}},
                     {'nexthop': '20.0.0.100',
                      'destination': '12.0.0.0/24',
                      'external_ids': {}},
                     {'nexthop': '90.0.0.1',
                      'destination': const.IPv4_ANY,
                      'external_ids': {
                          ovn_const.OVN_ROUTER_IS_EXT_GW: 'true',
                          ovn_const.OVN_SUBNET_EXT_ID_KEY: 'ext-subnet'}},
                     {'nexthop': '20.0.0.100',
                      'destination': '13.0.0.0/24',
                      'external_ids': {}}]
        expected_added = [{'nexthop': '90.0.0.1',
                           'destination': const.IPv4_ANY,
                           'external_ids': {
                               ovn_const.OVN_ROUTER_IS_EXT_GW: 'true',
                               ovn_const.OVN_SUBNET_EXT_ID_KEY: 'ext-subnet'}},
                          {'nexthop': '20.0.0.100',
                           'destination': '13.0.0.0/24',
                           'external_ids': {}}]
        expected_deleted = []
        self._test_ovn_nb_sync_calculate_routes_helper(ovn_routes,
                                                       db_routes,
                                                       expected_added,
                                                       expected_deleted)

    def test_ovn_nb_sync_calculate_routes_add_remove_keep_two_routes(self):

        # add 2 routes to ovn, remove 2 routes from ovn, keep 2 routes
        ovn_routes = [{'nexthop': '20.0.0.100',
                       'destination': '13.0.0.0/24',
                       'external_ids': {}},
                      {'nexthop': '90.0.0.1',
                       'destination': const.IPv4_ANY,
                       'external_ids': {
                            ovn_const.OVN_ROUTER_IS_EXT_GW: 'true',
                            ovn_const.OVN_SUBNET_EXT_ID_KEY: 'ext-subnet'}},
                      {'nexthop': '20.0.0.100',
                       'destination': '14.0.0.0/24',
                       'external_ids': {}},
                      {'nexthop': '20.0.0.100',
                       'destination': '15.0.0.0/24',
                       'external_ids': {}}]
        db_routes = [{'nexthop': '20.0.0.100',
                      'destination': '11.0.0.0/24',
                      'external_ids': {}},
                     {'nexthop': '20.0.0.100',
                      'destination': '12.0.0.0/24',
                      'external_ids': {}},
                     {'nexthop': '20.0.0.100',
                      'destination': '13.0.0.0/24',
                      'external_ids': {}},
                     {'nexthop': '90.0.0.1',
                      'destination': const.IPv4_ANY,
                      'external_ids': {
                          ovn_const.OVN_ROUTER_IS_EXT_GW: 'true',
                          ovn_const.OVN_SUBNET_EXT_ID_KEY: 'ext-subnet'}}]

        expected_added = [{'nexthop': '20.0.0.100',
                           'destination': '11.0.0.0/24',
                           'external_ids': {}},
                          {'nexthop': '20.0.0.100',
                           'destination': '12.0.0.0/24',
                           'external_ids': {}}]
        expected_deleted = [{'nexthop': '20.0.0.100',
                             'destination': '14.0.0.0/24',
                             'external_ids': {}},
                            {'nexthop': '20.0.0.100',
                             'destination': '15.0.0.0/24',
                             'external_ids': {}}]
        self._test_ovn_nb_sync_calculate_routes_helper(ovn_routes,
                                                       db_routes,
                                                       expected_added,
                                                       expected_deleted)


class TestIsRouterPortChanged(test_mech_driver.OVNMechanismDriverTestCase):

    def setUp(self):
        super().setUp()
        self.ovn_nb_synchronizer = ovn_db_sync.OvnNbSynchronizer(
            self.plugin, self.mech_driver.nb_ovn, self.mech_driver.sb_ovn,
            ovn_const.OVN_DB_SYNC_MODE_LOG, self.mech_driver)

        self.db_router_port = {
            'id': 'aa076509-915d-4b1c-8d9d-3db53d9c5faf',
            'networks': ['fdf9:ad62:3a04::1/64'],
            'ipv6_ra_configs': {'address_mode': 'slaac',
                                'send_periodic': 'true',
                                'mtu': '1442'}
        }
        self.lrport_nets = ['fdf9:ad62:3a04::1/64']
        self.ovn_lrport = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'ipv6_ra_configs': {'address_mode': 'slaac',
                                       'send_periodic': 'true',
                                       'mtu': '1442'}})

        self.ovn_nb_synchronizer.ovn_api.is_col_present.return_value = True
        self.ovn_nb_synchronizer.ovn_api.lrp_get().execute.return_value = (
            self.ovn_lrport)

    def test__is_router_port_changed_not_changed(self):
        self.assertFalse(self.ovn_nb_synchronizer._is_router_port_changed(
            self.db_router_port, self.lrport_nets))

    def test__is_router_port_changed_network_changed(self):
        self.db_router_port['networks'] = ['172.24.4.26/24',
                                           '2001:db8::206/64']
        self.assertTrue(self.ovn_nb_synchronizer._is_router_port_changed(
            self.db_router_port, self.lrport_nets))

    def test__is_router_port_changed_ipv6_ra_configs_changed(self):
        self.db_router_port['ipv6_ra_configs']['mtu'] = '1500'
        self.assertTrue(self.ovn_nb_synchronizer._is_router_port_changed(
            self.db_router_port, self.lrport_nets))


class TestOvnSbSyncML2(test_mech_driver.OVNMechanismDriverTestCase):

    def test_ovn_sb_sync(self):
        ovn_sb_synchronizer = ovn_db_sync.OvnSbSynchronizer(
            self.plugin,
            self.mech_driver.sb_ovn,
            self.mech_driver)
        ovn_api = ovn_sb_synchronizer.ovn_api
        hostname_with_physnets = {'hostname1': ['physnet1', 'physnet2'],
                                  'hostname2': ['physnet1']}
        ovn_api.get_chassis_hostname_and_physnets.return_value = (
            hostname_with_physnets)
        ovn_driver = ovn_sb_synchronizer.ovn_driver
        ovn_driver.update_segment_host_mapping = mock.Mock()
        hosts_in_neutron = {'hostname2', 'hostname3'}

        with mock.patch.object(ovn_db_sync.segments_db,
                               'get_hosts_mapped_with_segments',
                               return_value=hosts_in_neutron) as mock_ghmws:
            ovn_sb_synchronizer.sync_hostname_and_physical_networks(mock.ANY)
            mock_ghmws.assert_called_once_with(
                mock.ANY, include_agent_types=set(ovn_const.OVN_CONTROLLER_TYPES))
            all_hosts = set(hostname_with_physnets.keys()) | hosts_in_neutron
            self.assertEqual(
                len(all_hosts),
                ovn_driver.update_segment_host_mapping.call_count)
            update_segment_host_mapping_calls = [mock.call(
                host, hostname_with_physnets[host])
                for host in hostname_with_physnets]
            update_segment_host_mapping_calls += [
                mock.call(host, []) for host in
                hosts_in_neutron - set(hostname_with_physnets.keys())]
            ovn_driver.update_segment_host_mapping.assert_has_calls(
                update_segment_host_mapping_calls, any_order=True)
