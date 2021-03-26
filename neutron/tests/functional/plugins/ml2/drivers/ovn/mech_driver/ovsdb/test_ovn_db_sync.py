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

from neutron.common.ovn import acl as acl_utils
from neutron.common.ovn import constants as ovn_const
from neutron.common.ovn import utils
from neutron.conf.plugins.ml2.drivers.ovn import ovn_conf as ovn_config
from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb import ovn_db_sync
from neutron.services.segments import db as segments_db
from neutron.tests.functional import base
from neutron.tests.unit.api import test_extensions
from neutron.tests.unit.extensions import test_extraroute
from neutron.tests.unit.extensions import test_securitygroup
from neutron_lib.api.definitions import dns as dns_apidef
from neutron_lib.api.definitions import l3
from neutron_lib.api.definitions import port_security as ps
from neutron_lib import constants
from neutron_lib import context
from oslo_utils import uuidutils
from ovsdbapp.backend.ovs_idl import idlutils


class TestOvnNbSync(base.TestOVNFunctionalBase):

    _extension_drivers = ['port_security', 'dns']

    def setUp(self):
        ovn_config.cfg.CONF.set_override('dns_domain', 'ovn.test')
        super(TestOvnNbSync, self).setUp(maintenance_worker=True)
        ext_mgr = test_extraroute.ExtraRouteTestExtensionManager()
        self.ext_api = test_extensions.setup_extensions_middleware(ext_mgr)
        sg_mgr = test_securitygroup.SecurityGroupTestExtensionManager()
        self._sg_api = test_extensions.setup_extensions_middleware(sg_mgr)
        self.create_lswitches = []
        self.create_lswitch_ports = []
        self.create_lrouters = []
        self.create_lrouter_ports = []
        self.create_lrouter_routes = []
        self.create_lrouter_nats = []
        self.update_lrouter_ports = []
        self.create_acls = []
        self.delete_lswitches = []
        self.delete_lswitch_ports = []
        self.delete_lrouters = []
        self.delete_lrouter_ports = []
        self.delete_lrouter_routes = []
        self.delete_lrouter_nats = []
        self.delete_acls = []
        self.create_port_groups = []
        self.delete_port_groups = []
        self.expected_dhcp_options_rows = []
        self.reset_lport_dhcpv4_options = []
        self.reset_lport_dhcpv6_options = []
        self.stale_lport_dhcpv4_options = []
        self.stale_lport_dhcpv6_options = []
        self.orphaned_lport_dhcp_options = []
        self.lport_dhcpv4_disabled = {}
        self.lport_dhcpv6_disabled = {}
        self.missed_dhcp_options = []
        self.dirty_dhcp_options = []
        self.lport_dhcp_ignored = []
        self.match_old_mac_dhcp_subnets = []
        self.expected_dns_records = []
        self.expected_ports_with_unknown_addr = []
        self.ctx = context.get_admin_context()
        ovn_config.cfg.CONF.set_override('ovn_metadata_enabled', True,
                                         group='ovn')
        ovn_config.cfg.CONF.set_override(
            'enable_distributed_floating_ip', True, group='ovn')

    def _api_for_resource(self, resource):
        if resource in ['security-groups']:
            return self._sg_api
        else:
            return super(TestOvnNbSync, self)._api_for_resource(resource)

    def _create_resources(self, restart_ovsdb_processes=False):
        net_kwargs = {dns_apidef.DNSDOMAIN: 'ovn.test.'}
        net_kwargs['arg_list'] = (dns_apidef.DNSDOMAIN,)
        res = self._create_network(self.fmt, 'n1', True, **net_kwargs)
        n1 = self.deserialize(self.fmt, res)

        self.expected_dns_records = [
            {'external_ids': {'ls_name': utils.ovn_name(n1['network']['id'])},
             'records': {}}
        ]

        res = self._create_subnet(self.fmt, n1['network']['id'],
                                  '10.0.0.0/24')
        n1_s1 = self.deserialize(self.fmt, res)
        res = self._create_subnet(self.fmt, n1['network']['id'],
                                  '2001:dba::/64', ip_version=6,
                                  enable_dhcp=True)
        n1_s2 = self.deserialize(self.fmt, res)
        res = self._create_subnet(self.fmt, n1['network']['id'],
                                  '2001:dbb::/64', ip_version=6,
                                  ipv6_address_mode='slaac',
                                  ipv6_ra_mode='slaac')
        n1_s3 = self.deserialize(self.fmt, res)
        self.expected_dhcp_options_rows.append({
            'cidr': '10.0.0.0/24',
            'external_ids': {'subnet_id': n1_s1['subnet']['id'],
                             ovn_const.OVN_REV_NUM_EXT_ID_KEY: '0'},
            'options': {'classless_static_route':
                        '{169.254.169.254/32,10.0.0.2, 0.0.0.0/0,10.0.0.1}',
                        'server_id': '10.0.0.1',
                        'server_mac': '01:02:03:04:05:06',
                        'dns_server': '{10.10.10.10}',
                        'lease_time': str(12 * 60 * 60),
                        'mtu': str(n1['network']['mtu']),
                        'domain_name': '"ovn.test"',
                        'router': n1_s1['subnet']['gateway_ip']}})
        self.expected_dhcp_options_rows.append({
            'cidr': '2001:dba::/64',
            'external_ids': {'subnet_id': n1_s2['subnet']['id'],
                             ovn_const.OVN_REV_NUM_EXT_ID_KEY: '0'},
            'options': {'server_id': '01:02:03:04:05:06'}})

        n1_s1_dhcp_options_uuid = (
            self.mech_driver._nb_ovn.get_subnet_dhcp_options(
                n1_s1['subnet']['id'])['subnet']['uuid'])
        n1_s2_dhcpv6_options_uuid = (
            self.mech_driver._nb_ovn.get_subnet_dhcp_options(
                n1_s2['subnet']['id'])['subnet']['uuid'])
        update_port_ids_v4 = []
        update_port_ids_v6 = []
        n1_port_dict = {}
        for p in ['p1', 'p2', 'p3', 'p4', 'p5', 'p6', 'p7']:
            if p in ['p1', 'p5']:
                port_kwargs = {
                    'arg_list': (dns_apidef.DNSNAME, ps.PORTSECURITY),
                    dns_apidef.DNSNAME: 'n1-' + p,
                    ps.PORTSECURITY: 'False',
                    'device_id': 'n1-' + p}
            else:
                port_kwargs = {}

            res = self._create_port(self.fmt, n1['network']['id'],
                                    name='n1-' + p,
                                    device_owner='compute:None',
                                    **port_kwargs)
            port = self.deserialize(self.fmt, res)
            n1_port_dict[p] = port['port']['id']
            lport_name = port['port']['id']

            lswitch_name = 'neutron-' + n1['network']['id']
            if p in ['p1', 'p5']:
                port_ips = " ".join([f['ip_address']
                                     for f in port['port']['fixed_ips']])
                hname = 'n1-' + p
                self.expected_dns_records[0]['records'][hname] = port_ips
                hname = 'n1-' + p + '.ovn.test'
                self.expected_dns_records[0]['records'][hname] = port_ips
                self.expected_ports_with_unknown_addr.append(lport_name)

            if p == 'p1':
                fake_subnet = {'cidr': '11.11.11.11/24'}
                dhcp_acls = acl_utils.add_acl_dhcp(port['port'], fake_subnet)
                for dhcp_acl in dhcp_acls:
                    self.create_acls.append(dhcp_acl)
            elif p == 'p2':
                self.delete_lswitch_ports.append((lport_name, lswitch_name))
                update_port_ids_v4.append(port['port']['id'])
                update_port_ids_v6.append(port['port']['id'])
                self.expected_dhcp_options_rows.append({
                    'cidr': '10.0.0.0/24',
                    'external_ids': {'subnet_id': n1_s1['subnet']['id'],
                                     ovn_const.OVN_REV_NUM_EXT_ID_KEY: '0',
                                     'port_id': port['port']['id']},
                    'options': {
                        'classless_static_route':
                        '{169.254.169.254/32,10.0.0.2, 0.0.0.0/0,10.0.0.1}',
                        'server_id': '10.0.0.1',
                        'server_mac': '01:02:03:04:05:06',
                        'lease_time': str(12 * 60 * 60),
                        'mtu': str(n1['network']['mtu']),
                        'router': n1_s1['subnet']['gateway_ip'],
                        'tftp_server': '20.0.0.20',
                        'domain_name': '"ovn.test"',
                        'dns_server': '8.8.8.8'}})
                self.expected_dhcp_options_rows.append({
                    'cidr': '2001:dba::/64',
                    'external_ids': {'subnet_id': n1_s2['subnet']['id'],
                                     ovn_const.OVN_REV_NUM_EXT_ID_KEY: '0',
                                     'port_id': port['port']['id']},
                    'options': {'server_id': '01:02:03:04:05:06',
                                'domain_search': 'foo-domain'}})
                self.dirty_dhcp_options.append({
                    'subnet_id': n1_s1['subnet']['id'],
                    'port_id': lport_name})
                self.dirty_dhcp_options.append({
                    'subnet_id': n1_s2['subnet']['id'],
                    'port_id': lport_name})
            elif p == 'p3':
                self.delete_acls.append((lport_name, lswitch_name))
                self.reset_lport_dhcpv4_options.append(lport_name)
                self.lport_dhcpv6_disabled.update({
                    lport_name: n1_s2_dhcpv6_options_uuid})
                data = {'port': {
                    'extra_dhcp_opts': [{'ip_version': 6,
                                         'opt_name': 'dhcp_disabled',
                                         'opt_value': 'True'}]}}
                port_req = self.new_update_request('ports', data, lport_name)
                port_req.get_response(self.api)
            elif p == 'p4':
                self.lport_dhcpv4_disabled.update({
                    lport_name: n1_s1_dhcp_options_uuid})
                data = {'port': {
                    'extra_dhcp_opts': [{'ip_version': 4,
                                         'opt_name': 'dhcp_disabled',
                                         'opt_value': 'True'}]}}
                port_req = self.new_update_request('ports', data, lport_name)
                port_req.get_response(self.api)
                self.reset_lport_dhcpv6_options.append(lport_name)
            elif p == 'p5':
                self.stale_lport_dhcpv4_options.append({
                    'subnet_id': n1_s1['subnet']['id'],
                    'port_id': port['port']['id'],
                    'cidr': '10.0.0.0/24',
                    'options': {'server_id': '10.0.0.254',
                                'server_mac': '01:02:03:04:05:06',
                                'lease_time': str(3 * 60 * 60),
                                'mtu': str(n1['network']['mtu'] / 2),
                                'router': '10.0.0.254',
                                'tftp_server': '20.0.0.234',
                                'domain_name': '"ovn.test"',
                                'dns_server': '8.8.8.8'},
                    'external_ids': {'subnet_id': n1_s1['subnet']['id'],
                                     'port_id': port['port']['id']}})
            elif p == 'p6':
                self.delete_lswitch_ports.append((lport_name, lswitch_name))
            elif p == 'p7':
                update_port_ids_v4.append(port['port']['id'])
                update_port_ids_v6.append(port['port']['id'])
                self.expected_dhcp_options_rows.append({
                    'cidr': '10.0.0.0/24',
                    'external_ids': {'subnet_id': n1_s1['subnet']['id'],
                                     ovn_const.OVN_REV_NUM_EXT_ID_KEY: '0',
                                     'port_id': port['port']['id']},
                    'options': {
                        'classless_static_route':
                        '{169.254.169.254/32,10.0.0.2, 0.0.0.0/0,10.0.0.1}',
                        'server_id': '10.0.0.1',
                        'server_mac': '01:02:03:04:05:06',
                        'lease_time': str(12 * 60 * 60),
                        'mtu': str(n1['network']['mtu']),
                        'router': n1_s1['subnet']['gateway_ip'],
                        'tftp_server': '20.0.0.20',
                        'domain_name': '"ovn.test"',
                        'dns_server': '8.8.8.8'}})
                self.expected_dhcp_options_rows.append({
                    'cidr': '2001:dba::/64',
                    'external_ids': {'subnet_id': n1_s2['subnet']['id'],
                                     ovn_const.OVN_REV_NUM_EXT_ID_KEY: '0',
                                     'port_id': port['port']['id']},
                    'options': {'server_id': '01:02:03:04:05:06',
                                'domain_search': 'foo-domain'}})
                self.reset_lport_dhcpv4_options.append(lport_name)
                self.reset_lport_dhcpv6_options.append(lport_name)
        self.dirty_dhcp_options.append({'subnet_id': n1_s1['subnet']['id']})
        self.dirty_dhcp_options.append({'subnet_id': n1_s2['subnet']['id']})

        res = self._create_network(self.fmt, 'n2', True, **net_kwargs)
        n2 = self.deserialize(self.fmt, res)
        res = self._create_subnet(self.fmt, n2['network']['id'],
                                  '20.0.0.0/24')
        n2_s1 = self.deserialize(self.fmt, res)
        res = self._create_subnet(self.fmt, n2['network']['id'],
                                  '2001:dbd::/64', ip_version=6)
        n2_s2 = self.deserialize(self.fmt, res)
        self.expected_dhcp_options_rows.append({
            'cidr': '20.0.0.0/24',
            'external_ids': {'subnet_id': n2_s1['subnet']['id'],
                             ovn_const.OVN_REV_NUM_EXT_ID_KEY: '0'},
            'options': {'classless_static_route':
                        '{169.254.169.254/32,20.0.0.2, 0.0.0.0/0,20.0.0.1}',
                        'server_id': '20.0.0.1',
                        'server_mac': '01:02:03:04:05:06',
                        'dns_server': '{10.10.10.10}',
                        'lease_time': str(12 * 60 * 60),
                        'mtu': str(n2['network']['mtu']),
                        'domain_name': '"ovn.test"',
                        'router': n2_s1['subnet']['gateway_ip']}})
        self.expected_dhcp_options_rows.append({
            'cidr': '2001:dbd::/64',
            'external_ids': {'subnet_id': n2_s2['subnet']['id'],
                             ovn_const.OVN_REV_NUM_EXT_ID_KEY: '0'},
            'options': {'server_id': '01:02:03:04:05:06'}})

        for p in ['p1', 'p2']:
            port = self._make_port(self.fmt, n2['network']['id'],
                                   name='n2-' + p,
                                   device_owner='compute:None')
            if p == 'p1':
                update_port_ids_v4.append(port['port']['id'])
                self.expected_dhcp_options_rows.append({
                    'cidr': '20.0.0.0/24',
                    'external_ids': {'subnet_id': n2_s1['subnet']['id'],
                                     ovn_const.OVN_REV_NUM_EXT_ID_KEY: '0',
                                     'port_id': port['port']['id']},
                    'options': {
                        'classless_static_route':
                        '{169.254.169.254/32,20.0.0.2, 0.0.0.0/0,20.0.0.1}',
                        'server_id': '20.0.0.1',
                        'server_mac': '01:02:03:04:05:06',
                        'lease_time': str(12 * 60 * 60),
                        'mtu': str(n1['network']['mtu']),
                        'router': n2_s1['subnet']['gateway_ip'],
                        'tftp_server': '20.0.0.20',
                        'domain_name': '"ovn.test"',
                        'dns_server': '8.8.8.8'}})
        self.missed_dhcp_options.extend([
            opts['uuid']
            for opts in self.mech_driver._nb_ovn.get_subnets_dhcp_options(
                [n2_s1['subnet']['id'], n2_s2['subnet']['id']])])

        for port_id in update_port_ids_v4:
            data = {'port': {'extra_dhcp_opts': [{'ip_version': 4,
                                                  'opt_name': 'tftp-server',
                                                  'opt_value': '20.0.0.20'},
                                                 {'ip_version': 4,
                                                  'opt_name': 'dns-server',
                                                  'opt_value': '8.8.8.8'}]}}
            port_req = self.new_update_request('ports', data, port_id)
            port_req.get_response(self.api)
        for port_id in update_port_ids_v6:
            data = {'port': {'extra_dhcp_opts': [{'ip_version': 6,
                                                  'opt_name': 'domain-search',
                                                  'opt_value': 'foo-domain'}]}}
            port_req = self.new_update_request('ports', data, port_id)
            port_req.get_response(self.api)

        # External network and subnet
        e1 = self._make_network(self.fmt, 'e1', True,
                                arg_list=('router:external',
                                          'provider:network_type',
                                          'provider:physical_network'),
                                **{'router:external': True,
                                   'provider:network_type': 'flat',
                                   'provider:physical_network': 'public'})
        self.assertTrue(e1['network']['router:external'])
        self.assertEqual('flat', e1['network']['provider:network_type'])
        self.assertEqual('public', e1['network']['provider:physical_network'])
        res = self._create_subnet(self.fmt, e1['network']['id'],
                                  '100.0.0.0/24', gateway_ip='100.0.0.254',
                                  allocation_pools=[{'start': '100.0.0.2',
                                                     'end': '100.0.0.253'}],
                                  enable_dhcp=False)
        e1_s1 = self.deserialize(self.fmt, res)
        res = self._create_subnet(self.fmt, e1['network']['id'],
                                  '2001:db8::/64',
                                  gateway_ip='fd05:59e4:ef16::1',
                                  ip_version=constants.IP_VERSION_6,
                                  enable_dhcp=False)
        e1_s2 = self.deserialize(self.fmt, res)

        self.create_lswitches.append('neutron-' + uuidutils.generate_uuid())
        self.create_lswitch_ports.append(('neutron-' +
                                          uuidutils.generate_uuid(),
                                          'neutron-' + n1['network']['id']))
        self.create_lswitch_ports.append(('neutron-' +
                                          uuidutils.generate_uuid(),
                                          'neutron-' + n1['network']['id']))
        self.delete_lswitches.append('neutron-' + n2['network']['id'])
        for seg in self.segments_plugin.get_segments(
            self.context,
                filters={'network_id': [e1['network']['id']]}):
            if seg.get('physical_network'):
                self.delete_lswitch_ports.append(
                    (utils.ovn_provnet_port_name(seg['id']),
                     utils.ovn_name(e1['network']['id'])))

        r1 = self.l3_plugin.create_router(
            self.context,
            {'router': {
                'name': 'r1', 'admin_state_up': True,
                'tenant_id': self._tenant_id,
                'external_gateway_info': {
                    'enable_snat': True,
                    'network_id': e1['network']['id'],
                    'external_fixed_ips': [
                        {'ip_address': '100.0.0.2',
                         'subnet_id': e1_s1['subnet']['id']},
                        {'ip_address': '2001:db8::23a',
                         'subnet_id': e1_s2['subnet']['id']}]}}})
        self.l3_plugin.add_router_interface(
            self.context, r1['id'], {'subnet_id': n1_s1['subnet']['id']})
        r1_p2 = self.l3_plugin.add_router_interface(
            self.context, r1['id'], {'subnet_id': n1_s2['subnet']['id']})
        self.l3_plugin.add_router_interface(
            self.context, r1['id'], {'subnet_id': n1_s3['subnet']['id']})
        r1_p3 = self.l3_plugin.add_router_interface(
            self.context, r1['id'], {'subnet_id': n2_s1['subnet']['id']})
        self.update_lrouter_ports.append(('lrp-' + r1_p2['port_id'],
                                          'neutron-' + r1['id'],
                                          n1_s2['subnet']['gateway_ip']))
        self.delete_lrouter_ports.append(('lrp-' + r1_p3['port_id'],
                                          'neutron-' + r1['id']))
        self.delete_lrouter_ports.append(('lrp-' + r1['gw_port_id'],
                                          'neutron-' + r1['id']))
        self.l3_plugin.update_router(
            self.context, r1['id'],
            {'router': {'routes': [{'destination': '10.10.0.0/24',
                                    'nexthop': '20.0.0.10'},
                                   {'destination': '10.11.0.0/24',
                                    'nexthop': '20.0.0.11'}]}})
        r1_f1 = self.l3_plugin.create_floatingip(
            self.context, {'floatingip': {
                'tenant_id': self._tenant_id,
                'floating_network_id': e1['network']['id'],
                'floating_ip_address': '100.0.0.20',
                'subnet_id': None,
                'port_id': n1_port_dict['p1']}})
        r1_f2 = self.l3_plugin.create_floatingip(
            self.context, {'floatingip': {
                'tenant_id': self._tenant_id,
                'floating_network_id': e1['network']['id'],
                'subnet_id': None,
                'floating_ip_address': '100.0.0.21'}})
        self.l3_plugin.update_floatingip(
            self.context, r1_f2['id'], {'floatingip': {
                'port_id': n1_port_dict['p2']}})

        # update External subnet gateway ip to test function _subnet_update
        #  of L3 OVN plugin.
        data = {'subnet': {'gateway_ip': '100.0.0.1'}}
        subnet_req = self.new_update_request(
            'subnets', data, e1_s1['subnet']['id'])
        subnet_req.get_response(self.api)

        # Static routes
        self.create_lrouter_routes.append(('neutron-' + r1['id'],
                                           '10.12.0.0/24',
                                           '20.0.0.12'))
        self.create_lrouter_routes.append(('neutron-' + r1['id'],
                                           '10.13.0.0/24',
                                           '20.0.0.13'))
        self.delete_lrouter_routes.append(('neutron-' + r1['id'],
                                           '10.10.0.0/24',
                                           '20.0.0.10'))
        # Gateway default route
        self.delete_lrouter_routes.append(('neutron-' + r1['id'],
                                           '0.0.0.0/0',
                                           '100.0.0.1'))
        # Gateway sNATs
        self.create_lrouter_nats.append(('neutron-' + r1['id'],
                                         {'external_ip': '100.0.0.100',
                                          'logical_ip': '200.0.0.0/24',
                                          'type': 'snat'}))
        self.delete_lrouter_nats.append(('neutron-' + r1['id'],
                                         {'external_ip': '100.0.0.2',
                                          'logical_ip': '10.0.0.0/24',
                                          'type': 'snat'}))
        # Floating IPs
        self.create_lrouter_nats.append(('neutron-' + r1['id'],
                                         {'external_ip': '100.0.0.200',
                                          'logical_ip': '200.0.0.200',
                                          'type': 'dnat_and_snat'}))
        self.create_lrouter_nats.append(('neutron-' + r1['id'],
                                         {'external_ip': '100.0.0.201',
                                          'logical_ip': '200.0.0.201',
                                          'type': 'dnat_and_snat',
                                          'external_mac': '01:02:03:04:05:06',
                                          'logical_port': 'vm1'
                                          }))
        self.delete_lrouter_nats.append(('neutron-' + r1['id'],
                                         {'external_ip':
                                             r1_f1['floating_ip_address'],
                                          'logical_ip':
                                             r1_f1['fixed_ip_address'],
                                          'type': 'dnat_and_snat'}))

        res = self._create_network(self.fmt, 'n4', True, **net_kwargs)
        n4 = self.deserialize(self.fmt, res)
        res = self._create_subnet(self.fmt, n4['network']['id'],
                                  '40.0.0.0/24', enable_dhcp=False)
        self.expected_dns_records.append(
            {'external_ids': {'ls_name': utils.ovn_name(n4['network']['id'])},
             'records': {}}
        )
        n4_s1 = self.deserialize(self.fmt, res)
        n4_port_dict = {}
        for p in ['p1', 'p2', 'p3']:
            if p in ['p1', 'p2']:
                port_kwargs = {'arg_list': (dns_apidef.DNSNAME,),
                               dns_apidef.DNSNAME: 'n4-' + p,
                               'device_id': 'n4-' + p}
            else:
                port_kwargs = {}

            res = self._create_port(self.fmt, n4['network']['id'],
                                    name='n4-' + p,
                                    device_owner='compute:None',
                                    **port_kwargs)
            port = self.deserialize(self.fmt, res)

            if p in ['p1', 'p2']:
                port_ips = " ".join([f['ip_address']
                                     for f in port['port']['fixed_ips']])
                hname = 'n4-' + p
                self.expected_dns_records[1]['records'][hname] = port_ips
                hname = 'n4-' + p + '.ovn.test'
                self.expected_dns_records[1]['records'][hname] = port_ips

            n4_port_dict[p] = port['port']['id']
            self.lport_dhcp_ignored.append(port['port']['id'])

        r2 = self.l3_plugin.create_router(
            self.context,
            {'router': {'name': 'r2', 'admin_state_up': True,
                        'tenant_id': self._tenant_id}})
        n1_prtr = self._make_port(self.fmt, n1['network']['id'],
                                  name='n1-p-rtr')
        self.l3_plugin.add_router_interface(
            self.context, r2['id'], {'port_id': n1_prtr['port']['id']})
        self.l3_plugin.add_router_interface(
            self.context, r2['id'], {'subnet_id': n4_s1['subnet']['id']})
        self.l3_plugin.update_router(
            self.context, r2['id'],
            # FIXME(lucasagomes): Add "routes" back, it has been
            # removed to avoid a race condition that was happening from
            # time to time. The error was: "Invalid format for routes:
            # [{'destination': '10.20.0.0/24', 'nexthop': '10.0.0.20'}],
            # the nexthop is used by route". It seems to be a race within
            # the tests itself, running the functional tests without
            # any concurrency doesn't fail when the "routes" are set.
            #
            # {'router': {'routes': [{'destination': '10.20.0.0/24',
            #                         'nexthop': '10.0.0.20'}],
            #             ...
            {'router': {'external_gateway_info': {
                        'enable_snat': False,
                        'network_id': e1['network']['id'],
                        'external_fixed_ips': [
                            {'ip_address': '100.0.0.3',
                             'subnet_id': e1_s1['subnet']['id']}]}}})
        self.l3_plugin.create_floatingip(
            self.context, {'floatingip': {
                'tenant_id': self._tenant_id,
                'floating_network_id': e1['network']['id'],
                'floating_ip_address': '100.0.0.30',
                'subnet_id': None,
                'port_id': n4_port_dict['p1']}})
        self.l3_plugin.create_floatingip(
            self.context, {'floatingip': {
                'tenant_id': self._tenant_id,
                'floating_network_id': e1['network']['id'],
                'floating_ip_address': '100.0.0.31',
                'subnet_id': None,
                'port_id': n4_port_dict['p2']}})
        # To test l3_plugin.disassociate_floatingips, associating floating IP
        # to port p3 and then deleting p3.
        self.l3_plugin.create_floatingip(
            self.context, {'floatingip': {
                'tenant_id': self._tenant_id,
                'floating_network_id': e1['network']['id'],
                'floating_ip_address': '100.0.0.32',
                'subnet_id': None,
                'port_id': n4_port_dict['p3']}})
        self._delete('ports', n4_port_dict['p3'])

        self.create_lrouters.append('neutron-' + uuidutils.generate_uuid())
        self.create_lrouter_ports.append(('lrp-' + uuidutils.generate_uuid(),
                                          'neutron-' + r1['id']))
        self.create_lrouter_ports.append(('lrp-' + uuidutils.generate_uuid(),
                                          'neutron-' + r1['id']))
        self.delete_lrouters.append('neutron-' + r2['id'])

        self.create_port_groups.extend([{'name': 'pg1', 'acls': []},
                                        {'name': 'pg2', 'acls': []}])
        self.delete_port_groups.append(
            utils.ovn_port_group_name(n1_prtr['port']['security_groups'][0]))
        # Create a network and subnet with orphaned OVN resources.
        n3 = self._make_network(self.fmt, 'n3', True)
        res = self._create_subnet(self.fmt, n3['network']['id'],
                                  '30.0.0.0/24')
        n3_s1 = self.deserialize(self.fmt, res)
        res = self._create_subnet(self.fmt, n3['network']['id'],
                                  '2001:dbc::/64', ip_version=6)
        n3_s2 = self.deserialize(self.fmt, res)
        if not restart_ovsdb_processes:
            # Test using original mac when syncing.
            dhcp_mac_v4 = (self.mech_driver._nb_ovn.get_subnet_dhcp_options(
                n3_s1['subnet']['id'])['subnet'].get('options', {})
                .get('server_mac'))
            dhcp_mac_v6 = (self.mech_driver._nb_ovn.get_subnet_dhcp_options(
                n3_s2['subnet']['id'])['subnet'].get('options', {})
                .get('server_id'))
            self.assertTrue(dhcp_mac_v4 is not None)
            self.assertTrue(dhcp_mac_v6 is not None)
            self.match_old_mac_dhcp_subnets.append(n3_s1['subnet']['id'])
            self.match_old_mac_dhcp_subnets.append(n3_s2['subnet']['id'])
        else:
            dhcp_mac_v4 = '01:02:03:04:05:06'
            dhcp_mac_v6 = '01:02:03:04:05:06'
        self.expected_dhcp_options_rows.append({
            'cidr': '30.0.0.0/24',
            'external_ids': {'subnet_id': n3_s1['subnet']['id'],
                             ovn_const.OVN_REV_NUM_EXT_ID_KEY: '0'},
            'options': {'classless_static_route':
                        '{169.254.169.254/32,30.0.0.2, 0.0.0.0/0,30.0.0.1}',
                        'server_id': '30.0.0.1',
                        'domain_name': '"ovn.test"',
                        'dns_server': '{10.10.10.10}',
                        'server_mac': dhcp_mac_v4,
                        'lease_time': str(12 * 60 * 60),
                        'mtu': str(n3['network']['mtu']),
                        'router': n3_s1['subnet']['gateway_ip']}})
        self.expected_dhcp_options_rows.append({
            'cidr': '2001:dbc::/64',
            'external_ids': {'subnet_id': n3_s2['subnet']['id'],
                             ovn_const.OVN_REV_NUM_EXT_ID_KEY: '0'},
            'options': {'server_id': dhcp_mac_v6}})
        fake_port_id1 = uuidutils.generate_uuid()
        fake_port_id2 = uuidutils.generate_uuid()
        self.create_lswitch_ports.append(('neutron-' + fake_port_id1,
                                          'neutron-' + n3['network']['id']))
        self.create_lswitch_ports.append(('neutron-' + fake_port_id2,
                                          'neutron-' + n3['network']['id']))
        stale_dhcpv4_options1 = {
            'subnet_id': n3_s1['subnet']['id'],
            'port_id': fake_port_id1,
            'cidr': '30.0.0.0/24',
            'options': {'server_id': '30.0.0.254',
                        'server_mac': dhcp_mac_v4,
                        'lease_time': str(3 * 60 * 60),
                        'mtu': str(n3['network']['mtu'] / 2),
                        'router': '30.0.0.254',
                        'tftp_server': '30.0.0.234',
                        'dns_server': '8.8.8.8'},
            'external_ids': {'subnet_id': n3_s1['subnet']['id'],
                             'port_id': fake_port_id1}}
        self.stale_lport_dhcpv4_options.append(stale_dhcpv4_options1)
        stale_dhcpv4_options2 = stale_dhcpv4_options1.copy()
        stale_dhcpv4_options2.update({
            'port_id': fake_port_id2,
            'external_ids': {'subnet_id': n3_s1['subnet']['id'],
                             'port_id': fake_port_id2}})
        self.stale_lport_dhcpv4_options.append(stale_dhcpv4_options2)
        self.orphaned_lport_dhcp_options.append(fake_port_id2)
        stale_dhcpv6_options1 = {
            'subnet_id': n3_s2['subnet']['id'],
            'port_id': fake_port_id1,
            'cidr': '2001:dbc::/64',
            'options': {'server_id': dhcp_mac_v6,
                        'domain-search': 'foo-domain'},
            'external_ids': {'subnet_id': n3_s2['subnet']['id'],
                             'port_id': fake_port_id1}}
        self.stale_lport_dhcpv6_options.append(stale_dhcpv6_options1)
        stale_dhcpv6_options2 = stale_dhcpv6_options1.copy()
        stale_dhcpv6_options2.update({
            'port_id': fake_port_id2,
            'external_ids': {'subnet_id': n3_s2['subnet']['id'],
                             'port_id': fake_port_id2}})
        self.stale_lport_dhcpv6_options.append(stale_dhcpv6_options2)
        fake_port = {'id': fake_port_id1, 'network_id': n3['network']['id']}
        dhcp_acls = acl_utils.add_acl_dhcp(fake_port, n3_s1['subnet'])
        for dhcp_acl in dhcp_acls:
            self.create_acls.append(dhcp_acl)
        columns = list(self.nb_api.tables['ACL'].columns)
        if not (('name' in columns) and ('severity' in columns)):
            for acl in self.create_acls:
                acl.pop('name')
                acl.pop('severity')

    def _modify_resources_in_nb_db(self):
        self._delete_metadata_ports()

        with self.nb_api.transaction(check_error=True) as txn:
            for lswitch_name in self.create_lswitches:
                external_ids = {ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY:
                                lswitch_name}
                txn.add(self.nb_api.ls_add(lswitch_name, True,
                                           external_ids=external_ids))

            for lswitch_name in self.delete_lswitches:
                txn.add(self.nb_api.ls_del(lswitch_name, True))

            for lport_name, lswitch_name in self.create_lswitch_ports:
                external_ids = {ovn_const.OVN_PORT_NAME_EXT_ID_KEY:
                                lport_name}
                txn.add(self.nb_api.create_lswitch_port(
                    lport_name, lswitch_name, True, external_ids=external_ids))

            for lport_name, lswitch_name in self.delete_lswitch_ports:
                txn.add(self.nb_api.delete_lswitch_port(lport_name,
                                                        lswitch_name, True))

            for lrouter_name in self.create_lrouters:
                external_ids = {ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY:
                                lrouter_name}
                txn.add(self.nb_api.create_lrouter(lrouter_name, True,
                                                   external_ids=external_ids))

            for lrouter_name in self.delete_lrouters:
                txn.add(self.nb_api.delete_lrouter(lrouter_name, True))

            for lrport, lrouter_name in self.create_lrouter_ports:
                txn.add(self.nb_api.add_lrouter_port(lrport, lrouter_name))

            for lrport, lrouter_name, networks in self.update_lrouter_ports:
                txn.add(self.nb_api.update_lrouter_port(
                    lrport, True, **{'networks': [networks],
                                     'ipv6_ra_configs': {'foo': 'bar'}}))

            for lrport, lrouter_name in self.delete_lrouter_ports:
                txn.add(self.nb_api.delete_lrouter_port(lrport,
                                                        lrouter_name, True))

            for lrouter_name, ip_prefix, nexthop in self.create_lrouter_routes:
                txn.add(self.nb_api.add_static_route(lrouter_name,
                                                     ip_prefix=ip_prefix,
                                                     nexthop=nexthop))

            for lrouter_name, ip_prefix, nexthop in self.delete_lrouter_routes:
                txn.add(self.nb_api.delete_static_route(lrouter_name,
                                                        ip_prefix, nexthop,
                                                        True))

            for lrouter_name, nat_dict in(
                    self.create_lrouter_nats):
                txn.add(self.nb_api.add_nat_rule_in_lrouter(
                    lrouter_name, **nat_dict))

            for lrouter_name, nat_dict in(
                    self.delete_lrouter_nats):
                txn.add(self.nb_api.delete_nat_rule_in_lrouter(
                    lrouter_name, if_exists=True, **nat_dict))

            for acl in self.create_acls:
                txn.add(self.nb_api.add_acl(**acl))

            for lport_name, lswitch_name in self.delete_acls:
                txn.add(self.nb_api.delete_acl(lswitch_name,
                                               lport_name, True))

            for pg in self.create_port_groups:
                txn.add(self.nb_api.pg_add(**pg))
            for pg in self.delete_port_groups:
                txn.add(self.nb_api.pg_del(pg))

            for lport_name in self.reset_lport_dhcpv4_options:
                txn.add(self.nb_api.set_lswitch_port(lport_name, True,
                                                     dhcpv4_options=[]))

            for lport_name in self.reset_lport_dhcpv6_options:
                txn.add(self.nb_api.set_lswitch_port(lport_name, True,
                                                     dhcpv6_options=[]))

            for dhcp_opts in self.stale_lport_dhcpv4_options:
                dhcpv4_opts = txn.add(self.nb_api.add_dhcp_options(
                    dhcp_opts['subnet_id'],
                    port_id=dhcp_opts['port_id'],
                    cidr=dhcp_opts['cidr'],
                    options=dhcp_opts['options'],
                    external_ids=dhcp_opts['external_ids'],
                    may_exist=False))
                if dhcp_opts['port_id'] in self.orphaned_lport_dhcp_options:
                    continue
                txn.add(self.nb_api.set_lswitch_port(
                    lport_name, True, dhcpv4_options=dhcpv4_opts))

            for dhcp_opts in self.stale_lport_dhcpv6_options:
                dhcpv6_opts = txn.add(self.nb_api.add_dhcp_options(
                    dhcp_opts['subnet_id'],
                    port_id=dhcp_opts['port_id'],
                    cidr=dhcp_opts['cidr'],
                    options=dhcp_opts['options'],
                    external_ids=dhcp_opts['external_ids'],
                    may_exist=False))
                if dhcp_opts['port_id'] in self.orphaned_lport_dhcp_options:
                    continue
                txn.add(self.nb_api.set_lswitch_port(
                    lport_name, True, dhcpv6_options=dhcpv6_opts))

            for row_uuid in self.missed_dhcp_options:
                txn.add(self.nb_api.delete_dhcp_options(row_uuid))

            for dhcp_opts in self.dirty_dhcp_options:
                external_ids = {'subnet_id': dhcp_opts['subnet_id']}
                if dhcp_opts.get('port_id'):
                    external_ids['port_id'] = dhcp_opts['port_id']
                txn.add(self.nb_api.add_dhcp_options(
                    dhcp_opts['subnet_id'],
                    port_id=dhcp_opts.get('port_id'),
                    external_ids=external_ids,
                    options={'foo': 'bar'}))

            for port_id in self.lport_dhcpv4_disabled:
                txn.add(self.nb_api.set_lswitch_port(
                    port_id, True,
                    dhcpv4_options=[self.lport_dhcpv4_disabled[port_id]]))

            for port_id in self.lport_dhcpv6_disabled:
                txn.add(self.nb_api.set_lswitch_port(
                    port_id, True,
                    dhcpv6_options=[self.lport_dhcpv6_disabled[port_id]]))

            # Delete the first DNS record and clear the second row records
            i = 0
            for dns_row in self.nb_api.tables['DNS'].rows.values():
                if i == 0:
                    txn.add(self.nb_api.dns_del(dns_row.uuid))
                else:
                    txn.add(self.nb_api.dns_set_records(dns_row.uuid, **{}))
                i += 1

    def _validate_networks(self, should_match=True):
        db_networks = self._list('networks')
        db_net_ids = [net['id'] for net in db_networks['networks']]
        db_provnet_ports = []
        for net in db_networks['networks']:
            for seg in self.segments_plugin.get_segments(
                self.context,
                    filters={'network_id': [net['id']]}):
                if seg.get('physical_network'):
                    db_provnet_ports.append(
                        utils.ovn_provnet_port_name(seg['id']))

        # Get the list of lswitch ids stored in the OVN plugin IDL
        _plugin_nb_ovn = self.mech_driver._nb_ovn
        plugin_lswitch_ids = [
            row.name.replace('neutron-', '') for row in (
                _plugin_nb_ovn._tables['Logical_Switch'].rows.values())]

        # Get the list of lswitch ids stored in the monitor IDL connection
        monitor_lswitch_ids = [
            row.name.replace('neutron-', '') for row in (
                self.nb_api.tables['Logical_Switch'].rows.values())]

        # Get the list of provnet ports stored in the OVN plugin IDL
        plugin_provnet_ports = [row.name for row in (
            _plugin_nb_ovn._tables['Logical_Switch_Port'].rows.values())
            if row.name.startswith(ovn_const.OVN_PROVNET_PORT_NAME_PREFIX)]

        # Get the list of provnet ports stored in the monitor IDL connection
        monitor_provnet_ports = [row.name for row in (
            self.nb_api.tables['Logical_Switch_Port'].rows.values())
            if row.name.startswith(ovn_const.OVN_PROVNET_PORT_NAME_PREFIX)]

        if should_match:
            self.assertItemsEqual(db_net_ids, plugin_lswitch_ids)
            self.assertItemsEqual(db_net_ids, monitor_lswitch_ids)
            self.assertItemsEqual(db_provnet_ports, plugin_provnet_ports)
            self.assertItemsEqual(db_provnet_ports, monitor_provnet_ports)
        else:
            self.assertRaises(
                AssertionError, self.assertItemsEqual, db_net_ids,
                plugin_lswitch_ids)

            self.assertRaises(
                AssertionError, self.assertItemsEqual, db_net_ids,
                monitor_lswitch_ids)

            self.assertRaises(
                AssertionError, self.assertItemsEqual, db_provnet_ports,
                plugin_provnet_ports)

            self.assertRaises(
                AssertionError, self.assertItemsEqual, db_provnet_ports,
                monitor_provnet_ports)

    def _validate_metadata_ports(self, should_match=True):
        """Validate metadata ports.

        This method will check that all networks have one and only one metadata
        port and that every metadata port in Neutron also exists in OVN.
        """
        db_ports = self._list('ports')
        db_metadata_ports_ids = set()
        db_metadata_ports_nets = set()
        for port in db_ports['ports']:
            if (port['device_owner'] == constants.DEVICE_OWNER_DHCP and
                    port['device_id'].startswith('ovnmeta')):
                db_metadata_ports_ids.add(port['id'])
                db_metadata_ports_nets.add(port['network_id'])
        db_networks = self._list('networks')
        db_net_ids = {net['id'] for net in db_networks['networks']}

        # Retrieve all localports in OVN
        _plugin_nb_ovn = self.mech_driver._nb_ovn
        plugin_metadata_ports = [row.name for row in (
            _plugin_nb_ovn._tables['Logical_Switch_Port'].rows.values())
            if row.type == 'localport']

        if should_match:
            # Check that metadata ports exist in both Neutron and OVN dbs.
            self.assertItemsEqual(db_metadata_ports_ids, plugin_metadata_ports)
            # Check that all networks have one and only one metadata port.
            self.assertItemsEqual(db_metadata_ports_nets, db_net_ids)
        else:
            metadata_sync = (sorted(db_metadata_ports_ids) ==
                             sorted(plugin_metadata_ports))
            metadata_unique = (sorted(db_net_ids) ==
                               sorted(db_metadata_ports_nets))
            self.assertFalse(metadata_sync and metadata_unique)

    def _validate_ports(self, should_match=True):
        db_ports = self._list('ports')
        db_port_ids = [port['id'] for port in db_ports['ports'] if
                       not utils.is_lsp_ignored(port)]
        db_port_ids_dhcp_valid = set(
            port['id'] for port in db_ports['ports']
            if not utils.is_network_device_port(port) and
            port['id'] not in self.lport_dhcp_ignored)

        _plugin_nb_ovn = self.mech_driver._nb_ovn
        plugin_lport_ids = [
            row.name for row in (
                _plugin_nb_ovn._tables['Logical_Switch_Port'].rows.values())
            if ovn_const.OVN_PORT_NAME_EXT_ID_KEY in row.external_ids]
        plugin_lport_ids_dhcpv4_enabled = [
            row.name for row in (
                _plugin_nb_ovn._tables['Logical_Switch_Port'].rows.values())
            if row.dhcpv4_options]
        plugin_lport_ids_dhcpv6_enabled = [
            row.name for row in (
                _plugin_nb_ovn._tables['Logical_Switch_Port'].rows.values())
            if row.dhcpv6_options]

        monitor_lport_ids = [
            row.name for row in (
                self.nb_api.tables['Logical_Switch_Port'].
                rows.values())
            if ovn_const.OVN_PORT_NAME_EXT_ID_KEY in row.external_ids]
        monitor_lport_ids_dhcpv4_enabled = [
            row.name for row in (
                _plugin_nb_ovn._tables['Logical_Switch_Port'].rows.values())
            if row.dhcpv4_options]
        monitor_lport_ids_dhcpv6_enabled = [
            row.name for row in (
                _plugin_nb_ovn._tables['Logical_Switch_Port'].rows.values())
            if row.dhcpv6_options]

        if should_match:
            self.assertItemsEqual(db_port_ids, plugin_lport_ids)
            self.assertItemsEqual(db_port_ids, monitor_lport_ids)

            expected_dhcpv4_options_ports_ids = (
                db_port_ids_dhcp_valid.difference(
                    set(self.lport_dhcpv4_disabled.keys())))
            self.assertItemsEqual(expected_dhcpv4_options_ports_ids,
                                  plugin_lport_ids_dhcpv4_enabled)
            self.assertItemsEqual(expected_dhcpv4_options_ports_ids,
                                  monitor_lport_ids_dhcpv4_enabled)

            expected_dhcpv6_options_ports_ids = (
                db_port_ids_dhcp_valid.difference(
                    set(self.lport_dhcpv6_disabled.keys())))
            self.assertItemsEqual(expected_dhcpv6_options_ports_ids,
                                  plugin_lport_ids_dhcpv6_enabled)
            self.assertItemsEqual(expected_dhcpv6_options_ports_ids,
                                  monitor_lport_ids_dhcpv6_enabled)

            # Check if unknow address is set for the expected lports.
            for row in (
                    self.nb_api.tables['Logical_Switch_Port'].rows.values()):
                if row.name in self.expected_ports_with_unknown_addr:
                    self.assertIn('unknown', row.addresses)

        else:
            self.assertRaises(
                AssertionError, self.assertItemsEqual, db_port_ids,
                plugin_lport_ids)

            self.assertRaises(
                AssertionError, self.assertItemsEqual, db_port_ids,
                monitor_lport_ids)

            self.assertRaises(
                AssertionError, self.assertItemsEqual, db_port_ids,
                plugin_lport_ids_dhcpv4_enabled)

            self.assertRaises(
                AssertionError, self.assertItemsEqual, db_port_ids,
                monitor_lport_ids_dhcpv4_enabled)

    @staticmethod
    def _build_acl_for_pgs(priority, direction, log, name, action,
                           severity, match, port_group, **kwargs):
        return {
            'priority': priority,
            'direction': direction,
            'log': log,
            'name': name,
            'action': action,
            'severity': severity,
            'match': match,
            'external_ids': kwargs}

    def _validate_dhcp_opts(self, should_match=True):
        observed_plugin_dhcp_options_rows = []
        _plugin_nb_ovn = self.mech_driver._nb_ovn
        for row in _plugin_nb_ovn._tables['DHCP_Options'].rows.values():
            opts = dict(row.options)
            ids = dict(row.external_ids)
            if ids.get('subnet_id') not in self.match_old_mac_dhcp_subnets:
                if 'server_mac' in opts:
                    opts['server_mac'] = '01:02:03:04:05:06'
                else:
                    opts['server_id'] = '01:02:03:04:05:06'
            observed_plugin_dhcp_options_rows.append({
                'cidr': row.cidr, 'external_ids': row.external_ids,
                'options': opts})

        observed_monitor_dhcp_options_rows = []
        for row in self.nb_api.tables['DHCP_Options'].rows.values():
            opts = dict(row.options)
            ids = dict(row.external_ids)
            if ids.get('subnet_id') not in self.match_old_mac_dhcp_subnets:
                if 'server_mac' in opts:
                    opts['server_mac'] = '01:02:03:04:05:06'
                else:
                    opts['server_id'] = '01:02:03:04:05:06'
            observed_monitor_dhcp_options_rows.append({
                'cidr': row.cidr, 'external_ids': row.external_ids,
                'options': opts})

        if should_match:
            self.assertItemsEqual(self.expected_dhcp_options_rows,
                                  observed_plugin_dhcp_options_rows)
            self.assertItemsEqual(self.expected_dhcp_options_rows,
                                  observed_monitor_dhcp_options_rows)
        else:
            self.assertRaises(
                AssertionError, self.assertItemsEqual,
                self.expected_dhcp_options_rows,
                observed_plugin_dhcp_options_rows)

            self.assertRaises(
                AssertionError, self.assertItemsEqual,
                self.expected_dhcp_options_rows,
                observed_monitor_dhcp_options_rows)

    def _build_acl_to_compare(self, acl, extra_fields=None):
        acl_to_compare = {}
        for acl_key in getattr(acl, "_data", {}):
            try:
                acl_to_compare[acl_key] = getattr(acl, acl_key)
            except AttributeError:
                pass
        return acl_utils.filter_acl_dict(acl_to_compare, extra_fields)

    def _validate_acls(self, should_match=True):
        # Get the neutron DB ACLs.
        db_acls = []

        _plugin_nb_ovn = self.mech_driver._nb_ovn

        # ACLs due to SGs and default drop port group
        for sg in self._list('security-groups')['security_groups']:
            for sgr in sg['security_group_rules']:
                acl = acl_utils._add_sg_rule_acl_for_port_group(
                    utils.ovn_port_group_name(sg['id']), sgr)
                db_acls.append(TestOvnNbSync._build_acl_for_pgs(**acl))

        for acl in acl_utils.add_acls_for_drop_port_group(
                ovn_const.OVN_DROP_PORT_GROUP_NAME):
            db_acls.append(TestOvnNbSync._build_acl_for_pgs(**acl))

        # Get the list of ACLs stored in the OVN plugin IDL.
        plugin_acls = []
        for row in _plugin_nb_ovn._tables['Logical_Switch'].rows.values():
            for acl in getattr(row, 'acls', []):
                plugin_acls.append(self._build_acl_to_compare(acl))
        for row in _plugin_nb_ovn._tables['Port_Group'].rows.values():
            for acl in getattr(row, 'acls', []):
                plugin_acls.append(
                    self._build_acl_to_compare(
                        acl, extra_fields=['external_ids']))

        # Get the list of ACLs stored in the OVN monitor IDL.
        monitor_acls = []
        for row in self.nb_api.tables['Logical_Switch'].rows.values():
            for acl in getattr(row, 'acls', []):
                monitor_acls.append(self._build_acl_to_compare(acl))
        for row in self.nb_api.tables['Port_Group'].rows.values():
            for acl in getattr(row, 'acls', []):
                monitor_acls.append(self._build_acl_to_compare(acl))

        if should_match:
            self.assertItemsEqual(db_acls, plugin_acls)
            self.assertItemsEqual(db_acls, monitor_acls)
        else:
            self.assertRaises(
                AssertionError, self.assertItemsEqual,
                db_acls, plugin_acls)
            self.assertRaises(
                AssertionError, self.assertItemsEqual,
                db_acls, monitor_acls)

    def _validate_routers_and_router_ports(self, should_match=True):
        db_routers = self._list('routers')
        db_router_ids = []
        db_routes = {}
        db_nats = {}
        for db_router in db_routers['routers']:
            db_router_ids.append(db_router['id'])
            db_routes[db_router['id']] = [db_route['destination'] +
                                          db_route['nexthop']
                                          for db_route in db_router['routes']]
            db_nats[db_router['id']] = []
            if db_router.get(l3.EXTERNAL_GW_INFO):
                gateways = self.l3_plugin._ovn_client._get_gw_info(
                    self.context, db_router)
                for gw_info in gateways:
                    # Add gateway default route and snats
                    if gw_info.gateway_ip:
                        db_routes[db_router['id']].append(gw_info.ip_prefix +
                                                          gw_info.gateway_ip)
                    if (gw_info.ip_version == constants.IP_VERSION_4 and
                            gw_info.router_ip and
                            utils.is_snat_enabled(db_router)):
                        networks = self.l3_plugin._ovn_client.\
                            _get_v4_network_of_all_router_ports(
                                self.context, db_router['id'])
                        db_nats[db_router['id']].extend(
                            [gw_info.router_ip + network + 'snat'
                             for network in networks])
        fips = self._list('floatingips')
        fip_macs = {}
        if ovn_config.is_ovn_distributed_floating_ip():
            params = 'device_owner=%s' % constants.DEVICE_OWNER_FLOATINGIP
            fports = self._list('ports', query_params=params)['ports']
            fip_macs = {p['device_id']: p['mac_address'] for p in fports
                        if p['device_id']}
        for fip in fips['floatingips']:
            if fip['router_id']:
                mac_address = ''
                fip_port = ''
                if fip['id'] in fip_macs:
                    fip_port = fip['port_id']
                db_nats[fip['router_id']].append(
                    fip['floating_ip_address'] + fip['fixed_ip_address'] +
                    'dnat_and_snat' + mac_address + fip_port)

        _plugin_nb_ovn = self.mech_driver._nb_ovn
        plugin_lrouter_ids = [
            row.name.replace('neutron-', '') for row in (
                _plugin_nb_ovn._tables['Logical_Router'].rows.values())]

        monitor_lrouter_ids = [
            row.name.replace('neutron-', '') for row in (
                self.nb_api.tables['Logical_Router'].rows.values())]

        if should_match:
            self.assertItemsEqual(db_router_ids, plugin_lrouter_ids)
            self.assertItemsEqual(db_router_ids, monitor_lrouter_ids)
        else:
            self.assertRaises(
                AssertionError, self.assertItemsEqual, db_router_ids,
                plugin_lrouter_ids)

            self.assertRaises(
                AssertionError, self.assertItemsEqual, db_router_ids,
                monitor_lrouter_ids)

        def _get_networks_for_router_port(port):
            _ovn_client = self.l3_plugin._ovn_client
            networks, _ = (
                _ovn_client._get_nets_and_ipv6_ra_confs_for_router_port(
                    self.ctx, port))
            return networks

        def _get_ipv6_ra_configs_for_router_port(port):
            _ovn_client = self.l3_plugin._ovn_client
            networks, ipv6_ra_configs = (
                _ovn_client._get_nets_and_ipv6_ra_confs_for_router_port(
                    self.ctx, port))
            return ipv6_ra_configs

        for router_id in db_router_ids:
            r_ports = self._list('ports',
                                 query_params='device_id=%s' % (router_id))
            r_port_ids = [p['id'] for p in r_ports['ports']]
            r_port_networks = {
                p['id']:
                    _get_networks_for_router_port(p)
                    for p in r_ports['ports']}
            r_port_ipv6_ra_configs = {
                p['id']: _get_ipv6_ra_configs_for_router_port(p)
                for p in r_ports['ports']}
            r_routes = db_routes[router_id]
            r_nats = db_nats[router_id]

            try:
                lrouter = idlutils.row_by_value(
                    self.mech_driver._nb_ovn.idl, 'Logical_Router', 'name',
                    'neutron-' + str(router_id), None)
                lports = getattr(lrouter, 'ports', [])
                plugin_lrouter_port_ids = [lport.name.replace('lrp-', '')
                                           for lport in lports]
                plugin_lport_networks = {
                    lport.name.replace('lrp-', ''): lport.networks
                    for lport in lports}
                plugin_lport_ra_configs = {
                    lport.name.replace('lrp-', ''): lport.ipv6_ra_configs
                    for lport in lports}
                sroutes = getattr(lrouter, 'static_routes', [])
                plugin_routes = [sroute.ip_prefix + sroute.nexthop
                                 for sroute in sroutes]
                nats = getattr(lrouter, 'nat', [])
                plugin_nats = [
                    nat.external_ip + nat.logical_ip + nat.type +
                    (nat.external_mac[0] if nat.external_mac else '') +
                    (nat.logical_port[0] if nat.logical_port else '')
                    for nat in nats]
            except idlutils.RowNotFound:
                plugin_lrouter_port_ids = []
                plugin_routes = []
                plugin_nats = []

            try:
                lrouter = idlutils.row_by_value(
                    self.nb_api.idl, 'Logical_Router', 'name',
                    'neutron-' + router_id, None)
                lports = getattr(lrouter, 'ports', [])
                monitor_lrouter_port_ids = [lport.name.replace('lrp-', '')
                                            for lport in lports]
                monitor_lport_networks = {
                    lport.name.replace('lrp-', ''): lport.networks
                    for lport in lports}
                monitor_lport_ra_configs = {
                    lport.name.replace('lrp-', ''): lport.ipv6_ra_configs
                    for lport in lports}
                sroutes = getattr(lrouter, 'static_routes', [])
                monitor_routes = [sroute.ip_prefix + sroute.nexthop
                                  for sroute in sroutes]
                nats = getattr(lrouter, 'nat', [])
                monitor_nats = [
                    nat.external_ip + nat.logical_ip + nat.type +
                    (nat.external_mac[0] if nat.external_mac else '') +
                    (nat.logical_port[0] if nat.logical_port else '')
                    for nat in nats]
            except idlutils.RowNotFound:
                monitor_lrouter_port_ids = []
                monitor_routes = []
                monitor_nats = []

            if should_match:
                self.assertItemsEqual(r_port_ids, plugin_lrouter_port_ids)
                self.assertItemsEqual(r_port_ids, monitor_lrouter_port_ids)
                for p in plugin_lport_networks:
                    self.assertItemsEqual(r_port_networks[p],
                                          plugin_lport_networks[p])
                    self.assertItemsEqual(r_port_ipv6_ra_configs[p],
                                          plugin_lport_ra_configs[p])
                for p in monitor_lport_networks:
                    self.assertItemsEqual(r_port_networks[p],
                                          monitor_lport_networks[p])
                    self.assertItemsEqual(r_port_ipv6_ra_configs[p],
                                          monitor_lport_ra_configs[p])
                self.assertItemsEqual(r_routes, plugin_routes)
                self.assertItemsEqual(r_routes, monitor_routes)
                self.assertItemsEqual(r_nats, plugin_nats)
                self.assertItemsEqual(r_nats, monitor_nats)
            else:
                self.assertRaises(
                    AssertionError, self.assertItemsEqual, r_port_ids,
                    plugin_lrouter_port_ids)

                self.assertRaises(
                    AssertionError, self.assertItemsEqual, r_port_ids,
                    monitor_lrouter_port_ids)

                for _p in self.update_lrouter_ports:
                    p = _p[0].replace('lrp-', '')
                    if p in plugin_lport_networks:
                        self.assertRaises(
                            AssertionError, self.assertItemsEqual,
                            r_port_networks[p], plugin_lport_networks[p])
                        self.assertRaises(
                            AssertionError, self.assertItemsEqual,
                            r_port_ipv6_ra_configs[p],
                            plugin_lport_ra_configs[p])
                    if p in monitor_lport_networks:
                        self.assertRaises(
                            AssertionError, self.assertItemsEqual,
                            r_port_networks[p], monitor_lport_networks[p])
                        self.assertRaises(
                            AssertionError, self.assertItemsEqual,
                            r_port_ipv6_ra_configs[p],
                            monitor_lport_ra_configs[p])

                self.assertRaises(
                    AssertionError, self.assertItemsEqual, r_routes,
                    plugin_routes)

                self.assertRaises(
                    AssertionError, self.assertItemsEqual, r_routes,
                    monitor_routes)

                self.assertRaises(
                    AssertionError, self.assertItemsEqual, r_nats,
                    plugin_nats)

                self.assertRaises(
                    AssertionError, self.assertItemsEqual, r_nats,
                    monitor_nats)

    def _validate_port_groups(self, should_match=True):
        _plugin_nb_ovn = self.mech_driver._nb_ovn

        db_pgs = []
        for sg in self._list('security-groups')['security_groups']:
            db_pgs.append(utils.ovn_port_group_name(sg['id']))
        db_pgs.append(ovn_const.OVN_DROP_PORT_GROUP_NAME)

        nb_pgs = _plugin_nb_ovn.get_port_groups()

        mn_pgs = []
        for row in self.nb_api.tables['Port_Group'].rows.values():
            mn_pgs.append(getattr(row, 'name', ''))

        if should_match:
            self.assertItemsEqual(nb_pgs, db_pgs)
            self.assertItemsEqual(mn_pgs, db_pgs)
        else:
            self.assertRaises(AssertionError, self.assertItemsEqual,
                              nb_pgs, db_pgs)
            self.assertRaises(AssertionError, self.assertItemsEqual,
                              mn_pgs, db_pgs)

    def _delete_metadata_ports(self):
        """Delete some metadata ports.

        This method will delete one half of the metadata ports from Neutron and
        the remaining ones only from OVN. This way we can exercise the metadata
        sync completely: ie., that metadata ports are recreated in Neutron when
        missing and that the corresponding OVN localports are also created.
        """
        db_ports = self._list('ports')
        db_metadata_ports = [port for port in db_ports['ports'] if
                             port['device_owner'] ==
                             constants.DEVICE_OWNER_DHCP and
                             port['device_id'].startswith('ovnmeta')]
        lswitches = {}
        ports_to_delete = len(db_metadata_ports) / 2
        for port in db_metadata_ports:
            lswitches[port['id']] = 'neutron-' + port['network_id']
            if ports_to_delete:
                self._delete('ports', port['id'])
                ports_to_delete -= 1

        _plugin_nb_ovn = self.mech_driver._nb_ovn
        plugin_metadata_ports = [row.name for row in (
            _plugin_nb_ovn._tables['Logical_Switch_Port'].rows.values())
            if row.type == 'localport']

        with self.nb_api.transaction(check_error=True) as txn:
            for port in plugin_metadata_ports:
                txn.add(self.nb_api.delete_lswitch_port(port, lswitches[port],
                                                        True))

    def _validate_dns_records(self, should_match=True):
        observed_dns_records = []
        for dns_row in self.nb_api.tables['DNS'].rows.values():
            observed_dns_records.append(
                {'external_ids': dns_row.external_ids,
                 'records': dns_row.records})
        if should_match:
            self.assertItemsEqual(self.expected_dns_records,
                                  observed_dns_records)
        else:
            self.assertRaises(AssertionError, self.assertItemsEqual,
                              self.expected_dns_records, observed_dns_records)

    def _validate_resources(self, should_match=True):
        self._validate_networks(should_match=should_match)
        self._validate_metadata_ports(should_match=should_match)
        self._validate_ports(should_match=should_match)
        self._validate_dhcp_opts(should_match=should_match)
        self._validate_acls(should_match=should_match)
        self._validate_routers_and_router_ports(should_match=should_match)
        self._validate_port_groups(should_match=should_match)
        self._validate_dns_records(should_match=should_match)

    def _sync_resources(self, mode):
        nb_synchronizer = ovn_db_sync.OvnNbSynchronizer(
            self.plugin, self.mech_driver._nb_ovn, self.mech_driver._sb_ovn,
            mode, self.mech_driver)
        self.addCleanup(nb_synchronizer.stop)
        nb_synchronizer.do_sync()

    def _test_ovn_nb_sync_helper(self, mode, modify_resources=True,
                                 restart_ovsdb_processes=False,
                                 should_match_after_sync=True):
        self._create_resources(restart_ovsdb_processes)
        self._validate_resources(should_match=True)

        if modify_resources:
            self._modify_resources_in_nb_db()

        if restart_ovsdb_processes:
            # Restart the ovsdb-server and plugin idl.
            # This causes a new ovsdb-server to be started with empty
            # OVN NB DB
            self.restart()

        if modify_resources or restart_ovsdb_processes:
            self._validate_resources(should_match=False)

        self._sync_resources(mode)
        self._validate_resources(should_match=should_match_after_sync)

    def test_ovn_nb_sync_repair(self):
        self._test_ovn_nb_sync_helper('repair')

    def test_ovn_nb_sync_repair_delete_ovn_nb_db(self):
        # In this test case, the ovsdb-server for OVN NB DB is restarted
        # with empty OVN NB DB.
        self._test_ovn_nb_sync_helper('repair', modify_resources=False,
                                      restart_ovsdb_processes=True)

    def test_ovn_nb_sync_log(self):
        self._test_ovn_nb_sync_helper('log', should_match_after_sync=False)

    def test_ovn_nb_sync_off(self):
        self._test_ovn_nb_sync_helper('off', should_match_after_sync=False)


class TestOvnSbSync(base.TestOVNFunctionalBase):

    def setUp(self):
        super(TestOvnSbSync, self).setUp(maintenance_worker=True)
        self.sb_synchronizer = ovn_db_sync.OvnSbSynchronizer(
            self.plugin, self.mech_driver._sb_ovn, self.mech_driver)
        self.addCleanup(self.sb_synchronizer.stop)
        self.ctx = context.get_admin_context()

    def _sync_resources(self):
        self.sb_synchronizer.sync_hostname_and_physical_networks(self.ctx)

    def create_segment(self, network_id, physical_network, segmentation_id):
        segment_data = {'network_id': network_id,
                        'physical_network': physical_network,
                        'segmentation_id': segmentation_id,
                        'network_type': 'vlan',
                        'name': constants.ATTR_NOT_SPECIFIED,
                        'description': constants.ATTR_NOT_SPECIFIED}
        return self.segments_plugin.create_segment(
            self.ctx, segment={'segment': segment_data})

    def test_ovn_sb_sync_add_new_host(self):
        with self.network() as network:
            network_id = network['network']['id']
        self.create_segment(network_id, 'physnet1', 50)
        self.add_fake_chassis('host1', ['physnet1'])
        segment_hosts = segments_db.get_hosts_mapped_with_segments(self.ctx)
        self.assertFalse(segment_hosts)
        self._sync_resources()
        segment_hosts = segments_db.get_hosts_mapped_with_segments(self.ctx)
        self.assertEqual({'host1'}, segment_hosts)

    def test_ovn_sb_sync_update_existing_host(self):
        with self.network() as network:
            network_id = network['network']['id']
        segment = self.create_segment(network_id, 'physnet1', 50)
        segments_db.update_segment_host_mapping(
            self.ctx, 'host1', {segment['id']})
        segment_hosts = segments_db.get_hosts_mapped_with_segments(self.ctx)
        self.assertEqual({'host1'}, segment_hosts)
        self.add_fake_chassis('host1', ['physnet2'])
        self._sync_resources()
        segment_hosts = segments_db.get_hosts_mapped_with_segments(self.ctx)
        self.assertFalse(segment_hosts)

    def test_ovn_sb_sync_delete_stale_host(self):
        with self.network() as network:
            network_id = network['network']['id']
        segment = self.create_segment(network_id, 'physnet1', 50)
        segments_db.update_segment_host_mapping(
            self.ctx, 'host1', {segment['id']})
        segment_hosts = segments_db.get_hosts_mapped_with_segments(self.ctx)
        self.assertEqual({'host1'}, segment_hosts)
        # Since there is no chassis in the sb DB, host1 is the stale host
        # recorded in neutron DB. It should be deleted after sync.
        self._sync_resources()
        segment_hosts = segments_db.get_hosts_mapped_with_segments(self.ctx)
        self.assertFalse(segment_hosts)

    def test_ovn_sb_sync(self):
        with self.network() as network:
            network_id = network['network']['id']
        seg1 = self.create_segment(network_id, 'physnet1', 50)
        self.create_segment(network_id, 'physnet2', 51)
        segments_db.update_segment_host_mapping(
            self.ctx, 'host1', {seg1['id']})
        segments_db.update_segment_host_mapping(
            self.ctx, 'host2', {seg1['id']})
        segments_db.update_segment_host_mapping(
            self.ctx, 'host3', {seg1['id']})
        segment_hosts = segments_db.get_hosts_mapped_with_segments(self.ctx)
        self.assertEqual({'host1', 'host2', 'host3'}, segment_hosts)
        self.add_fake_chassis('host2', ['physnet2'])
        self.add_fake_chassis('host3', ['physnet3'])
        self.add_fake_chassis('host4', ['physnet1'])
        self._sync_resources()
        segment_hosts = segments_db.get_hosts_mapped_with_segments(self.ctx)
        # host1 should be cleared since it is not in the chassis DB. host3
        # should be cleared since there is no segment for mapping.
        self.assertEqual({'host2', 'host4'}, segment_hosts)


class TestOvnNbSyncOverTcp(TestOvnNbSync):
    def get_ovsdb_server_protocol(self):
        return 'tcp'


class TestOvnSbSyncOverTcp(TestOvnSbSync):
    def get_ovsdb_server_protocol(self):
        return 'tcp'


class TestOvnNbSyncOverSsl(TestOvnNbSync):
    def get_ovsdb_server_protocol(self):
        return 'ssl'


class TestOvnSbSyncOverSsl(TestOvnSbSync):
    def get_ovsdb_server_protocol(self):
        return 'ssl'
