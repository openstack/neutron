# Copyright 2014 Alcatel-Lucent USA Inc.
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

import contextlib

from neutron import context
from neutron.openstack.common import uuidutils
from neutron.plugins.nuage import nuage_models
from neutron.plugins.nuage import syncmanager as sync
from neutron.tests.unit.nuage import test_netpartition
from neutron.tests.unit.nuage import test_nuage_plugin
from neutron.tests.unit import test_extension_extraroute as extraroute_test
from neutron.tests.unit import test_extension_security_group as test_sg
from neutron.tests.unit import test_l3_plugin

_uuid = uuidutils.generate_uuid


class TestL3Sync(test_nuage_plugin.NuagePluginV2TestCase,
                 test_l3_plugin.L3NatDBIntTestCase):

    def setUp(self):
        self.session = context.get_admin_context().session
        self.syncmanager = sync.SyncManager(
            test_nuage_plugin.getNuageClient())
        super(TestL3Sync, self).setUp()

    def _make_floatingip_for_tenant_port(self, net_id, port_id, tenant_id):
        data = {'floatingip': {'floating_network_id': net_id,
                               'tenant_id': tenant_id,
                               'port_id': port_id}}
        floatingip_req = self.new_create_request('floatingips', data, self.fmt)
        res = floatingip_req.get_response(self.ext_api)
        return self.deserialize(self.fmt, res)

    def test_router_sync(self):
        # If the router exists in neutron and not in VSD,
        # sync will create it in VSD. But the nuage_router_id
        # will now change and will be updated in neutron
        # accordingly
        rtr_res = self._create_router('json', 'foo', 'test-router', True)
        router = self.deserialize('json', rtr_res)

        self.syncmanager.synchronize('250')

        # Check that the nuage_router_id is updated in entrtrmapping table
        router_db = self.session.query(
            nuage_models.NetPartitionRouter).filter_by(
                router_id=router['router']['id']).first()

        self.assertEqual('2d782c02-b88e-44ad-a79b-4bdf11f7df3d',
                         router_db['nuage_router_id'])

        self._delete('routers', router['router']['id'])

    def test_router_deleted_get(self):
        data = self.syncmanager._get_router_data(_uuid())
        self.assertIsNone(data[0])
        self.assertIsNone(data[1])

    def test_fip_sync(self):
        with self.subnet(cidr='200.0.0.0/24') as public_sub:
            self._set_net_external(public_sub['subnet']['network_id'])
            with contextlib.nested(self.port(), self.port(), self.port()) as (
                p1, p2, p3):
                p1_id = p1['port']['id']
                p2_id = p2['port']['id']
                p3_id = p3['port']['id']
                with contextlib.nested(self.floatingip_with_assoc(
                    port_id=p1_id), self.floatingip_with_assoc(
                    port_id=p2_id), self.floatingip_with_assoc(
                    port_id=p3_id)) as (fip1, fip2, fip3):
                    fip_dict = {'fip': {
                        'add': [fip1['floatingip']['id']],
                        'associate': [fip2['floatingip']['id']],
                        'disassociate': [fip3['floatingip']['id']]
                    }}
                    self.syncmanager._sync_fips(fip_dict)

    def test_deleted_fip_sync(self):
        fip_dict = {'fip': {
            'add': [_uuid()],
            'associate': [_uuid()],
            'disassociate': [_uuid()]
        }}
        self.syncmanager._sync_fips(fip_dict)

    def test_fip_and_ipalloc_get(self):
        with self.subnet(cidr='200.0.0.0/24') as public_sub:
            self._set_net_external(public_sub['subnet']['network_id'])
            with self.port() as port:
                p_id = port['port']['id']
                with self.floatingip_with_assoc(port_id=p_id) as fip:

                    data = self.syncmanager._get_fip_data(
                        fip['floatingip']['id'])

                    self.assertEqual(fip['floatingip']['id'], data['id'])

                    data = self.syncmanager._get_ipalloc_for_fip(
                        fip['floatingip'])
                    self.assertEqual(fip['floatingip']['floating_ip_address'],
                                     data['ip_address'])

    def test_fip_and_ipalloc_deleted_get(self):
        data = self.syncmanager._get_fip_data(_uuid())
        self.assertIsNone(data)

        fip = {
            'id': _uuid(),
            'floating_network_id': _uuid(),
            'floating_ip_address': '176.176.10.10'
        }
        data = self.syncmanager._get_ipalloc_for_fip(fip)
        self.assertIsNone(data)

    def test_domainsubnet_sync(self):
        with self.subnet() as s1:
            with contextlib.nested(
                    self.router(),
                    self.port()) as (r1, p1):
                self._router_interface_action(
                    'add', r1['router']['id'],
                    s1['subnet']['id'], p1['port']['id'])
                domainsubn_dict = {
                    'domainsubnet': {'add': [s1['subnet']['id']]},
                    'port': {'sub_rtr_intf_port_dict': {s1['subnet']['id']:
                                                        p1['port']['id']}}}
                self.syncmanager.sync_domainsubnets(domainsubn_dict)
                self._router_interface_action('remove', r1['router']['id'],
                                              s1['subnet']['id'], None)

    def test_floatingip_update_different_router(self):
        self._test_floatingip_update_different_router()

    def test_floatingip_update_different_fixed_ip_same_port(self):
        self._test_floatingip_update_different_fixed_ip_same_port()

    def test_floatingip_create_different_fixed_ip_same_port(self):
        self._test_floatingip_create_different_fixed_ip_same_port()

    def test_network_update_external_failure(self):
        self._test_network_update_external_failure()


class TestExtraRouteSync(extraroute_test.ExtraRouteDBIntTestCase):

    def setUp(self):
        self.session = context.get_admin_context().session
        self.syncmanager = sync.SyncManager(
            test_nuage_plugin.getNuageClient())
        super(TestExtraRouteSync, self).setUp()

    def test_route_sync(self):
        route = {'destination': '135.207.0.0/16', 'nexthop': '10.0.1.3'}
        with self.router() as r:
            with self.subnet(cidr='10.0.1.0/24') as s:
                net_id = s['subnet']['network_id']
                res = self._create_port('json', net_id)
                p = self.deserialize(self.fmt, res)
                self._routes_update_prepare(r['router']['id'],
                                            None, p['port']['id'], [route])

                route_dict = {'route': {'add': [route]}}
                self.syncmanager.sync_routes(route_dict)

                self._routes_update_cleanup(p['port']['id'],
                                            None, r['router']['id'], [])

    def test_route_get(self):
        routes = [{'destination': '135.207.0.0/16', 'nexthop': '10.0.1.3'}]
        with self.router() as r:
            with self.subnet(cidr='10.0.1.0/24') as s:
                net_id = s['subnet']['network_id']
                res = self._create_port('json', net_id)
                p = self.deserialize(self.fmt, res)
                self._routes_update_prepare(r['router']['id'],
                                            None, p['port']['id'], routes)

                data = self.syncmanager._get_route_data(routes[0])
                self.assertEqual(routes[0]['destination'], data['destination'])
                self.assertEqual(routes[0]['nexthop'], data['nexthop'])
                self._routes_update_cleanup(p['port']['id'],
                                            None, r['router']['id'], [])

    def test_route_deleted_get(self):
        route = {'destination': '135.207.0.0/16', 'nexthop': '10.0.1.3'}
        data = self.syncmanager._get_route_data(route)
        self.assertIsNone(data)


class TestNetPartSync(test_netpartition.NetPartitionTestCase):

    def setUp(self):
        self.session = context.get_admin_context().session
        self.syncmanager = sync.SyncManager(
            test_nuage_plugin.getNuageClient())
        super(TestNetPartSync, self).setUp()

    def test_net_partition_sync(self):
        # If the net-partition exists in neutron and not in VSD,
        # sync will create it in VSD. But the net-partition
        # id will now change and has to be updated in neutron
        # accordingly
        netpart = self._make_netpartition('json', 'sync-new-netpartition')

        self.syncmanager.synchronize('250')

        # Check that the net-partition id is updated in db
        netpart_db = self.session.query(
            nuage_models.NetPartition).filter_by(name=netpart['net_partition'][
                'name']).first()

        self.assertEqual('a917924f-3139-4bdb-a4c3-ea7c8011582f',
                         netpart_db['id'])
        self._del_netpartition(netpart_db['id'])

    def test_net_partition_deleted_get(self):
        data = self.syncmanager._get_netpart_data(_uuid())
        self.assertIsNone(data)


class TestL2Sync(test_nuage_plugin.NuagePluginV2TestCase):

    def setUp(self):
        self.session = context.get_admin_context().session
        self.syncmanager = sync.SyncManager(
            test_nuage_plugin.getNuageClient())
        super(TestL2Sync, self).setUp()

    def test_subnet_sync(self):
        # If the subnet exists in neutron and not in VSD,
        # sync will create it in VSD. But the nuage_subnet_id
        # will now change and will be updated in neutron
        # accordingly
        net_res = self._create_network("json", "pub", True)
        network = self.deserialize('json', net_res)

        sub_res = self._create_subnet("json", network['network']['id'],
                                      '10.0.0.0/24')
        subnet = self.deserialize('json', sub_res)

        self.syncmanager.synchronize('250')

        # Check that the nuage_subnet_id is updated in db
        subl2dom_db = self.session.query(
            nuage_models.SubnetL2Domain).filter_by(subnet_id=subnet[
                'subnet']['id']).first()
        self.assertEqual('52daa465-cf33-4efd-91d3-f5bc2aebd',
                         subl2dom_db['nuage_subnet_id'])

        self._delete('subnets', subnet['subnet']['id'])
        self._delete('networks', network['network']['id'])

    def test_subnet_deleted_get(self):
        data = self.syncmanager._get_subnet_data(_uuid())
        self.assertIsNone(data[0])
        self.assertIsNone(data[1])

    def test_sharednetwork_sync(self):
        with self.subnet(cidr='200.0.0.0/24') as public_sub:
            sharednet_dict = {'sharednetwork': {'add': [public_sub['subnet'][
                                                        'id']]}}
            self.syncmanager.sync_sharednetworks(sharednet_dict)

    def test_vm_sync(self):
        with self.port() as p:
            port_dict = {'port': {'vm': [p['port']['id']]}}
            self.syncmanager.sync_vms(port_dict)


class TestSecurityGroupSync(test_sg.TestSecurityGroups):

    def setUp(self):
        self.session = context.get_admin_context().session
        self.syncmanager = sync.SyncManager(
            test_nuage_plugin.getNuageClient())
        super(TestSecurityGroupSync, self).setUp()

    def test_sg_get(self):
        with self.security_group() as sg:
            data = self.syncmanager._get_sec_grp_data(
                sg['security_group']['id'])
            self.assertEqual(sg['security_group']['id'], data['id'])

    def test_sg_deleted_get(self):
        data = self.syncmanager._get_sec_grp_data(_uuid())
        self.assertIsNone(data)

    def test_sg_rule_get(self):
        with self.security_group() as sg:
            sg_rule_id = sg['security_group']['security_group_rules'][0]['id']
            data = self.syncmanager._get_sec_grp_rule_data(sg_rule_id)
            self.assertEqual(sg_rule_id, data['id'])

    def test_sg_rule_deleted_get(self):
        data = self.syncmanager._get_sec_grp_rule_data(_uuid())
        self.assertIsNone(data)

    def test_sg_grp_sync(self):
        with contextlib.nested(self.security_group(),
                               self.security_group()) as (sg1, sg2):
            sg1_id = sg1['security_group']['id']
            sg2_id = sg2['security_group']['id']
            sg_dict = {'security': {'secgroup': {'l2domain': {'add': {sg1_id: [
                _uuid()]}}, 'domain': {'add': {sg2_id: [_uuid()]}}}}}
            self.syncmanager.sync_secgrps(sg_dict)

    def test_deleted_sg_grp_sync(self):
        sg_dict = {'security': {'secgroup': {'l2domain': {'add': {_uuid(): [
            _uuid()]}}, 'domain': {'add': {_uuid(): [_uuid()]}}}}}
        self.syncmanager.sync_secgrps(sg_dict)

    def test_sg_rule_sync(self):
        with contextlib.nested(self.security_group(),
                               self.security_group()) as (sg1, sg2):
            sg1_rule_id = (
                sg1['security_group']['security_group_rules'][0]['id'])
            sg2_rule_id = (
                sg2['security_group']['security_group_rules'][0]['id'])

            sg_dict = {'security': {'secgrouprule': {'l2domain': {
                'add': [sg1_rule_id]}, 'domain': {'add': [sg2_rule_id]}}}}
            self.syncmanager.sync_secgrp_rules(sg_dict)

    def test_deleted_sg_grp_rule_sync(self):
        sg_dict = {'security': {'secgrouprule':
                                {'l2domain': {'add': [_uuid()]},
                                 'domain': {'add': [_uuid()]}}}}
        self.syncmanager.sync_secgrp_rules(sg_dict)
