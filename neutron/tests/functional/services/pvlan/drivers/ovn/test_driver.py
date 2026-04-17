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

from neutron_lib.services.pvlan import constants as pvlan_const

from neutron.common.ovn import constants as ovn_const
from neutron.objects import ports as port_objects
from neutron.objects import pvlan as pvlan_objects
from neutron.services.pvlan.drivers.ovn import driver as pvlan_ovn
from neutron.tests.functional import base


class TestOVNPVLANDriver(base.TestOVNFunctionalBase):

    def setUp(self):
        super().setUp()
        self.driver = pvlan_ovn.PVLANDriver.create(
            mech_driver=self.mech_driver)
        with self.nb_api.transaction(check_error=True) as txn:
            txn.add(self.nb_api.pg_add(
                name=pvlan_ovn.DROP_PORT_GROUP_NAME,
                acls=[], may_exist=True))

    def _create_pvlan_port(self, port_id, network_id, pvlan_type,
                           pvlan_community=None):
        pp = pvlan_objects.PortPVLAN(
            self.context, port_id=port_id,
            pvlan_type=pvlan_type, pvlan_community=pvlan_community)
        pp.create()
        with self.nb_api.transaction(check_error=True) as txn:
            self.driver.create_port(self.context, txn,
                                    {'id': port_id,
                                     'network_id': network_id,
                                     'pvlan_type': pvlan_type,
                                     'pvlan_community': pvlan_community})
        return pp

    def _update_pvlan_port(self, port_id, prev_pvlan_type,
                           prev_pvlan_community=None):
        port_obj = port_objects.Port.get_object(self.context, id=port_id)
        self.driver.update_port(
            self.context, port_obj,
            prev_pvlan_type=prev_pvlan_type,
            prev_pvlan_community=prev_pvlan_community)

    def _pg_port_names(self, pg):
        return {p.name for p in pg.ports}

    def test_create_port_community(self):
        with self.network() as net, \
                self.subnet(network=net) as subnet, \
                self.port(subnet=subnet) as port:
            port_id = port['port']['id']
            network_id = net['network']['id']
            self.driver.create_network_resources(network_id)

            self._create_pvlan_port(
                port_id, network_id, pvlan_const.COMMUNITY_TYPE, 'web')
            pg_name = self.driver._get_pg_name(
                network_id, pvlan_const.COMMUNITY_TYPE, community='web')

            pg = self.nb_api.get_port_group(pg_name)
            self.assertIsNotNone(pg)
            self.assertIn(port_id, self._pg_port_names(pg))
            self.assertEqual(2, len(pg.acls))
            for acl in pg.acls:
                self.assertEqual('to-lport', acl.direction)
                self.assertEqual(ovn_const.ACL_ACTION_ALLOW_STATELESS,
                                 acl.action)
                self.assertEqual(pvlan_ovn.COMMUNITY_PRIORITY, acl.priority)

            prm_pg_name = self.driver._get_pg_name(
                network_id, pvlan_const.PROMISCUOUS_TYPE)
            prm_pg = self.nb_api.get_port_group(prm_pg_name)
            from_lport_matches = {a.match for a in prm_pg.acls
                                  if a.direction == 'from-lport'}
            self.assertIn("inport == @%s" % pg_name, from_lport_matches)

    def test_create_port_isolated(self):
        with self.network() as net, \
                self.subnet(network=net) as subnet, \
                self.port(subnet=subnet) as port:
            port_id = port['port']['id']
            network_id = net['network']['id']
            self.driver.create_network_resources(network_id)

            self._create_pvlan_port(port_id, network_id,
                                   pvlan_const.ISOLATED_TYPE)

            pg_name = self.driver._get_pg_name(
                network_id, pvlan_const.ISOLATED_TYPE)
            pg = self.nb_api.get_port_group(pg_name)
            self.assertIn(port_id, self._pg_port_names(pg))

    def test_update_port_moves_between_port_groups(self):
        with self.network() as net, \
                self.subnet(network=net) as subnet, \
                self.port(subnet=subnet) as port:
            port_id = port['port']['id']
            network_id = net['network']['id']
            self.driver.create_network_resources(network_id)

            pp = self._create_pvlan_port(
                port_id, network_id, pvlan_const.ISOLATED_TYPE)

            pp.pvlan_type = pvlan_const.PROMISCUOUS_TYPE
            pp.update()
            self._update_pvlan_port(port_id, pvlan_const.ISOLATED_TYPE)

            iso_pg_name = self.driver._get_pg_name(
                network_id, pvlan_const.ISOLATED_TYPE)
            prm_pg_name = self.driver._get_pg_name(
                network_id, pvlan_const.PROMISCUOUS_TYPE)
            iso_pg = self.nb_api.get_port_group(iso_pg_name)
            prm_pg = self.nb_api.get_port_group(prm_pg_name)
            self.assertNotIn(port_id, self._pg_port_names(iso_pg))
            self.assertIn(port_id, self._pg_port_names(prm_pg))

    def test_update_port_community_change(self):
        with self.network() as net, \
                self.subnet(network=net) as subnet, \
                self.port(subnet=subnet) as port:
            port_id = port['port']['id']
            network_id = net['network']['id']
            self.driver.create_network_resources(network_id)

            pp = self._create_pvlan_port(
                port_id, network_id, pvlan_const.COMMUNITY_TYPE, 'old_comm')
            old_pg = self.driver._get_pg_name(
                network_id, pvlan_const.COMMUNITY_TYPE, community='old_comm')
            new_pg = self.driver._get_pg_name(
                network_id, pvlan_const.COMMUNITY_TYPE, community='new_comm')

            pp.pvlan_community = 'new_comm'
            pp.update()
            self._update_pvlan_port(
                port_id, pvlan_const.COMMUNITY_TYPE, 'old_comm')

            self.assertIsNone(self.nb_api.get_port_group(old_pg))
            pg = self.nb_api.get_port_group(new_pg)
            self.assertIsNotNone(pg)
            self.assertIn(port_id, self._pg_port_names(pg))

    def test_update_port_community_to_isolated(self):
        with self.network() as net, \
                self.subnet(network=net) as subnet, \
                self.port(subnet=subnet) as port:
            port_id = port['port']['id']
            network_id = net['network']['id']
            self.driver.create_network_resources(network_id)

            pp = self._create_pvlan_port(
                port_id, network_id, pvlan_const.COMMUNITY_TYPE, 'web')
            pg_name = self.driver._get_pg_name(
                network_id, pvlan_const.COMMUNITY_TYPE, community='web')

            pp.pvlan_type = pvlan_const.ISOLATED_TYPE
            pp.pvlan_community = None
            pp.update()
            self._update_pvlan_port(
                port_id, pvlan_const.COMMUNITY_TYPE, 'web')

            self.assertIsNone(self.nb_api.get_port_group(pg_name))
            iso_pg_name = self.driver._get_pg_name(
                network_id, pvlan_const.ISOLATED_TYPE)
            iso_pg = self.nb_api.get_port_group(iso_pg_name)
            self.assertIn(port_id, self._pg_port_names(iso_pg))

            prm_pg_name = self.driver._get_pg_name(
                network_id, pvlan_const.PROMISCUOUS_TYPE)
            prm_pg = self.nb_api.get_port_group(prm_pg_name)
            from_lport_matches = {a.match for a in prm_pg.acls
                                  if a.direction == 'from-lport'}
            self.assertNotIn("inport == @%s" % pg_name, from_lport_matches)

    def test_update_port_community_keeps_pg_when_others_remain(self):
        with self.network() as net, \
                self.subnet(network=net) as subnet, \
                self.port(subnet=subnet) as port1, \
                self.port(subnet=subnet) as port2:
            port1_id = port1['port']['id']
            port2_id = port2['port']['id']
            network_id = net['network']['id']
            self.driver.create_network_resources(network_id)

            port_a = self._create_pvlan_port(
                port1_id, network_id, pvlan_const.COMMUNITY_TYPE, 'web')
            self._create_pvlan_port(
                port2_id, network_id, pvlan_const.COMMUNITY_TYPE, 'web')
            pg_name = self.driver._get_pg_name(
                network_id, pvlan_const.COMMUNITY_TYPE, community='web')

            port_a.pvlan_type = pvlan_const.ISOLATED_TYPE
            port_a.pvlan_community = None
            port_a.update()
            self._update_pvlan_port(
                port1_id, pvlan_const.COMMUNITY_TYPE, 'web')

            pg = self.nb_api.get_port_group(pg_name)
            self.assertIsNotNone(pg)
            self.assertEqual(2, len(pg.acls))
            names = self._pg_port_names(pg)
            self.assertNotIn(port_a.port_id, names)
            self.assertIn(port2_id, names)

    def test_port_groups_are_per_network(self):
        with self.network() as net1, \
                self.network() as net2, \
                self.subnet(network=net1) as subnet1, \
                self.subnet(network=net2) as subnet2, \
                self.port(subnet=subnet1) as port1, \
                self.port(subnet=subnet2) as port2:
            net1_id = net1['network']['id']
            net2_id = net2['network']['id']
            port1_id = port1['port']['id']
            port2_id = port2['port']['id']

            self.driver.create_network_resources(net1_id)
            self.driver.create_network_resources(net2_id)

            self._create_pvlan_port(
                port1_id, net1_id, pvlan_const.ISOLATED_TYPE)
            self._create_pvlan_port(
                port2_id, net2_id, pvlan_const.ISOLATED_TYPE)

            net1_pg_name = self.driver._get_pg_name(
                net1_id, pvlan_const.ISOLATED_TYPE)
            net2_pg_name = self.driver._get_pg_name(
                net2_id, pvlan_const.ISOLATED_TYPE)
            self.assertNotEqual(net1_pg_name, net2_pg_name)

            net1_pg = self.nb_api.get_port_group(net1_pg_name)
            net2_pg = self.nb_api.get_port_group(net2_pg_name)
            self.assertIsNotNone(net1_pg)
            self.assertIsNotNone(net2_pg)

            self.assertIn(port1_id, self._pg_port_names(net1_pg))
            self.assertNotIn(port2_id, self._pg_port_names(net1_pg))
            self.assertIn(port2_id, self._pg_port_names(net2_pg))
            self.assertNotIn(port1_id, self._pg_port_names(net2_pg))

            for acl in net1_pg.acls:
                self.assertIn(net1_pg_name, acl.match)
                self.assertNotIn(net2_pg_name, acl.match)
            for acl in net2_pg.acls:
                self.assertIn(net2_pg_name, acl.match)
                self.assertNotIn(net1_pg_name, acl.match)

    def test_delete_port_removes_from_type_pg_and_drop_pg(self):
        with self.network() as net, \
                self.subnet(network=net) as subnet, \
                self.port(subnet=subnet) as port:
            port_id = port['port']['id']
            network_id = net['network']['id']
            self.driver.create_network_resources(network_id)

            self._create_pvlan_port(
                port_id, network_id, pvlan_const.ISOLATED_TYPE)

            iso_pg_name = self.driver._get_pg_name(
                network_id, pvlan_const.ISOLATED_TYPE)
            iso_pg = self.nb_api.get_port_group(iso_pg_name)
            self.assertIn(port_id, self._pg_port_names(iso_pg))
            drop_pg = self.nb_api.get_port_group(
                pvlan_ovn.DROP_PORT_GROUP_NAME)
            self.assertIn(port_id, self._pg_port_names(drop_pg))

            self.driver.delete_port(
                port_id, network_id, pvlan_const.ISOLATED_TYPE)

            iso_pg = self.nb_api.get_port_group(iso_pg_name)
            self.assertNotIn(port_id, self._pg_port_names(iso_pg))
            drop_pg = self.nb_api.get_port_group(
                pvlan_ovn.DROP_PORT_GROUP_NAME)
            self.assertNotIn(port_id, self._pg_port_names(drop_pg))

    def test_delete_port_community_cleans_up_pg(self):
        with self.network() as net, \
                self.subnet(network=net) as subnet, \
                self.port(subnet=subnet) as port:
            port_id = port['port']['id']
            network_id = net['network']['id']
            self.driver.create_network_resources(network_id)

            self._create_pvlan_port(
                port_id, network_id,
                pvlan_const.COMMUNITY_TYPE, 'web')
            comm_pg_name = self.driver._get_pg_name(
                network_id, pvlan_const.COMMUNITY_TYPE, community='web')
            self.assertIsNotNone(self.nb_api.get_port_group(comm_pg_name))

            self.driver.delete_port(
                port_id, network_id,
                pvlan_const.COMMUNITY_TYPE, pvlan_community='web')

            self.assertIsNone(self.nb_api.get_port_group(comm_pg_name))
            drop_pg = self.nb_api.get_port_group(
                pvlan_ovn.DROP_PORT_GROUP_NAME)
            self.assertNotIn(port_id, self._pg_port_names(drop_pg))

    def test_delete_network_resources(self):
        with self.network() as net, \
                self.subnet(network=net) as subnet, \
                self.port(subnet=subnet) as port:
            network_id = net['network']['id']
            port_id = port['port']['id']
            self.driver.create_network_resources(network_id)
            self._create_pvlan_port(
                port_id, network_id, pvlan_const.COMMUNITY_TYPE, 'web')

            iso_pg = self.driver._get_pg_name(
                network_id, pvlan_const.ISOLATED_TYPE)
            prm_pg = self.driver._get_pg_name(
                network_id, pvlan_const.PROMISCUOUS_TYPE)
            comm_pg = self.driver._get_pg_name(
                network_id, pvlan_const.COMMUNITY_TYPE, community='web')

            self.driver.delete_network_resources(
                network_id, self.context)

            self.assertIsNone(self.nb_api.get_port_group(iso_pg))
            self.assertIsNone(self.nb_api.get_port_group(prm_pg))
            self.assertIsNone(self.nb_api.get_port_group(comm_pg))
            drop_pg = self.nb_api.get_port_group(
                pvlan_ovn.DROP_PORT_GROUP_NAME)
            self.assertNotIn(port_id, self._pg_port_names(drop_pg))
