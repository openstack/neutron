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

from neutron_lib.api.definitions import external_net
from neutron_lib.api.definitions import l3 as l3_apidef
from neutron_lib.api.definitions import portbindings
from neutron_lib.api.definitions import provider_net as pnet
from neutron_lib import constants as n_consts
from neutron_lib.plugins import directory
from oslo_db import exception as db_exc
from ovsdbapp.backend.ovs_idl import idlutils

from neutron.common.ovn import constants as ovn_const
from neutron.common.ovn import utils as ovn_utils
from neutron.common import utils as n_utils
from neutron.conf.plugins.ml2.drivers.ovn import ovn_conf
from neutron.scheduler import l3_ovn_scheduler as l3_sched
from neutron.tests.functional import base
from neutron.tests.functional.resources.ovsdb import events


class TestRouter(base.TestOVNFunctionalBase):
    def setUp(self, **kwargs):
        super().setUp(**kwargs)
        self.chassis1 = self.add_fake_chassis(
            'ovs-host1', physical_nets=['physnet1', 'physnet3'],
            enable_chassis_as_gw=True, azs=[])
        self.chassis2 = self.add_fake_chassis(
            'ovs-host2', physical_nets=['physnet2', 'physnet3'],
            enable_chassis_as_gw=True, azs=[])
        self.physnet_used = ['physnet1', 'physnet2', 'physnet3']
        self.cr_lrp_pb_event = events.WaitForCrLrpPortBindingEvent()
        self.sb_api.idl.notify_handler.watch_event(self.cr_lrp_pb_event)

    def _create_router(self, name, gw_info=None, az_hints=None,
                       enable_ecmp=None, enable_bfd=None):
        router = {'router':
                  {'name': name,
                   'admin_state_up': True,
                   'tenant_id': self._tenant_id}}
        if az_hints:
            router['router']['availability_zone_hints'] = az_hints
        if gw_info:
            router['router']['external_gateway_info'] = gw_info
        if enable_bfd:
            router['router']['enable_default_route_bfd'] = enable_bfd
        if enable_ecmp:
            router['router']['enable_default_route_ecmp'] = enable_ecmp
        return self.l3_plugin.create_router(self.context, router)

    def _add_external_gateways(self, router_id, external_gateways):
        router = {'router': {'external_gateways': external_gateways}}
        return self.l3_plugin.add_external_gateways(
            self.context, router_id, body=router)

    def _remove_external_gateways(self, router_id, external_gateways):
        router = {'router': {'external_gateways': external_gateways}}
        return self.l3_plugin.remove_external_gateways(
            self.context, router_id, body=router)

    def _create_ext_network(self, name, net_type, physnet, seg,
                            gateway, cidr):
        arg_list = (pnet.NETWORK_TYPE, external_net.EXTERNAL,)
        net_arg = {pnet.NETWORK_TYPE: net_type,
                   external_net.EXTERNAL: True}
        if seg:
            arg_list = arg_list + (pnet.SEGMENTATION_ID,)
            net_arg[pnet.SEGMENTATION_ID] = seg
        if physnet:
            arg_list = arg_list + (pnet.PHYSICAL_NETWORK,)
            net_arg[pnet.PHYSICAL_NETWORK] = physnet
        network = self._make_network(self.fmt, name, True, as_admin=True,
                                     arg_list=arg_list, **net_arg)
        if cidr:
            self._make_subnet(self.fmt, network, gateway, cidr,
                              ip_version=n_consts.IP_VERSION_4)
        return network

    def _unset_lrp_gw_chassis(self, ovn_client):
        with ovn_client._nb_idl.transaction(check_error=True) as txn:
            for lrp in self.nb_api.tables['Logical_Router_Port'].rows.values():
                txn.add(ovn_client._nb_idl.update_lrouter_port(
                    lrp.name, gateway_chassis=[]))

    def _get_gwc_dict(self):
        sched_info = {}
        for row in self.nb_api.db_list_rows("Logical_Router_Port").execute(
                check_error=True):
            for gwc in row.gateway_chassis:
                chassis = sched_info.setdefault(gwc.chassis_name, {})
                chassis[gwc.priority] = chassis.get(gwc.priority, 0) + 1
        return sched_info

    def _create_routers_wait_pb(self, begin, n, gw_info=None,
                                bind_chassis=None):
        routers = []
        for i in range(begin, n + begin):
            try:
                router = self._create_router('router%d' % i, gw_info=gw_info)
                routers.append(router)
            except db_exc.DBReferenceError:
                # NOTE(ralonsoh): this is a workaround for LP#1956344. There
                # seems to be a bug in SQLite3. The "port" DB object is not
                # persistently stored in the DB and raises a "DBReferenceError"
                # exception occasionally.
                continue

            if bind_chassis:
                gw_port_id = router.get('gw_port_id')
                logical_port = 'cr-lrp-%s' % gw_port_id
                self.assertTrue(self.cr_lrp_pb_event.wait(logical_port),
                                msg='lrp %s failed to bind' % logical_port)
                self.sb_api.lsp_bind(logical_port, bind_chassis,
                                     may_exist=True).execute(check_error=True)
        return routers

    def _add_chassis(self, begin, n, physical_nets):
        chassis_added = []
        for i in range(begin, begin + n):
            chassis_added.append(
                self.add_fake_chassis(
                    'ovs-host%s' % i,
                    name=f'chassis-{i:02d}',
                    physical_nets=physical_nets,
                    other_config={
                        'ovn-cms-options': 'enable-chassis-as-gw'}))
        return chassis_added

    def test_gateway_chassis_on_router_gateway_port(self):
        ext2 = self._create_ext_network(
            'ext2', 'flat', 'physnet3', None, "20.0.0.1", "20.0.0.0/24")
        gw_info = {'network_id': ext2['network']['id']}
        self._create_router('router1', gw_info=gw_info)
        expected = [row.name for row in
                    self.sb_api.tables['Chassis'].rows.values()]
        for row in self.nb_api.tables[
                'Logical_Router_Port'].rows.values():
            chassis = [gwc.chassis_name for gwc in row.gateway_chassis]
            self.assertCountEqual(expected, chassis)

    def _check_gateway_chassis_candidates(self, candidates,
                                          router_az_hints=None,
                                          physnet='physnet1'):
        # In this test, fake_select() is called once from _create_router()
        # and later from schedule_unhosted_gateways()
        ovn_client = self.l3_plugin._ovn_client
        net_type = 'vlan' if physnet else 'geneve'
        ext1 = self._create_ext_network(
            'ext1', net_type, physnet, 1, "10.0.0.1", "10.0.0.0/24")
        # mock select function and check if it is called with expected
        # candidates.

        def fake_select(*args, **kwargs):
            self.assertCountEqual(candidates, kwargs['candidates'])
            # We are not interested in further processing, let us return
            # a random chassis name to avoid errors. If there are no
            # candidates, this method returns None.
            return ['a-random-chassis'] if candidates else None

        with mock.patch.object(self.l3_plugin.scheduler, 'select',
                               side_effect=fake_select) as plugin_select:
            gw_info = {'network_id': ext1['network']['id']}
            self._create_router('router1', gw_info=gw_info,
                                az_hints=router_az_hints)
            # If the network is tunnelled, the scheduler is not called.
            check = self.assertTrue if physnet else self.assertFalse
            check(plugin_select.called)
            plugin_select.reset_mock()

            # Unset the redirect-chassis so that schedule_unhosted_gateways
            # will try to schedule it.
            self._unset_lrp_gw_chassis(ovn_client)
            self.l3_plugin.schedule_unhosted_gateways()
            check = self.assertTrue if candidates else self.assertFalse
            check(plugin_select.called)

    def test_gateway_chassis_with_cms_and_bridge_mappings(self):
        # Both chassis1 and chassis3 are having proper bridge mappings,
        # but only chassis1 is having enable-chassis-as-gw.
        # Test if chassis1 is selected as candidate or not.
        self.chassis3 = self.add_fake_chassis(
            'ovs-host3', physical_nets=['physnet1'], azs=[])
        self._check_gateway_chassis_candidates([self.chassis1])

    def test_gateway_chassis_with_cms_and_no_bridge_mappings(self):
        # chassis1 is having proper bridge mappings.
        # chassis3 is having enable-chassis-as-gw, but no bridge mappings.
        self.chassis3 = self.add_fake_chassis(
            'ovs-host3',
            other_config={'ovn-cms-options': 'enable-chassis-as-gw'})
        ovn_client = self.l3_plugin._ovn_client
        ext1 = self._create_ext_network(
            'ext1', 'vlan', 'physnet1', 1, "10.0.0.1", "10.0.0.0/24")
        # As we have 'gateways' in the system, but without required
        # chassis we should not schedule gw in that case at all.
        self._unset_lrp_gw_chassis(ovn_client)
        with mock.patch.object(self.l3_plugin.scheduler, 'select',
                               side_effect=[self.chassis1]):
            gw_info = {'network_id': ext1['network']['id']}
            self._create_router('router1', gw_info=gw_info)

        with mock.patch.object(
                ovn_client._nb_idl, 'update_lrouter_port') as ulrp:
            self.l3_plugin.schedule_unhosted_gateways()
            # Make sure that we don't schedule on chassis3
            # and do not updated the lrp port.
            ulrp.assert_not_called()

    def test_gateway_chassis_with_cms_and_azs(self):
        # Both chassis3 and chassis4 are having azs,
        # but only chassis3's azs is ['ovn'].
        # Test if chassis3 is selected as candidate or not.
        self.chassis3 = self.add_fake_chassis(
            'ovs-host3', physical_nets=['physnet1'],
            azs=['ovn'], enable_chassis_as_gw=True)
        self.chassis4 = self.add_fake_chassis(
            'ovs-host4', physical_nets=['physnet1'],
            azs=['ovn2'], enable_chassis_as_gw=True)
        self._check_gateway_chassis_candidates([self.chassis3],
                                               router_az_hints=['ovn'])

    def test_gateway_chassis_with_cms_and_not_match_azs(self):
        # add chassis3 is having azs [ovn], match router az_hints,
        # if not add chassis3, create router will fail with
        # AvailabilityZoneNotFound. after create will delete if.
        # add chassis4 is having azs [ovn2], not match routers az_hints [ovn]
        self.chassis3 = self.add_fake_chassis(
            'ovs-host3', physical_nets=['physnet1'], enable_chassis_as_gw=True)
        self.chassis4 = self.add_fake_chassis(
            'ovs-host4', physical_nets=['physnet1'], enable_chassis_as_gw=True,
            azs=['ovn2'])
        ovn_client = self.l3_plugin._ovn_client
        ext1 = self._create_ext_network(
            'ext1', 'vlan', 'physnet1', 1, "10.0.0.1", "10.0.0.0/24")
        # As we have 'gateways' in the system, but without required
        # chassis we should not schedule gw in that case at all.
        self._unset_lrp_gw_chassis(ovn_client)
        with mock.patch.object(self.l3_plugin.scheduler, 'select',
                               side_effect=[self.chassis1]):
            gw_info = {'network_id': ext1['network']['id']}
            self._create_router('router1', gw_info=gw_info, az_hints=['ovn'])
        self.del_fake_chassis(self.chassis3)
        with mock.patch.object(
                ovn_client._nb_idl, 'update_lrouter_port') as ulrp:
            self.l3_plugin.schedule_unhosted_gateways()
            # Make sure that we don't schedule on chassis3
            # and do not updated the lrp port.
            ulrp.assert_not_called()

    def test_gateway_chassis_with_bridge_mappings_and_no_cms(self):
        # chassis1 is configured with proper bridge mappings,
        # but none of the chassis having enable-chassis-as-gw.
        # Test if chassis1 is selected as candidate or not.
        self._check_gateway_chassis_candidates([self.chassis1])

    def test_gateway_chassis_no_physnet_tunnelled_network(self):
        # The GW network is tunnelled, no physnet defined --> no possible
        # candidates.
        self._check_gateway_chassis_candidates(None, physnet=None)

    def test_gateway_chassis_least_loaded_scheduler(self):
        # This test will create 4 routers each with its own gateway.
        # Using the least loaded policy for scheduling gateway ports, we
        # expect that they are equally distributed across the two available
        # chassis.
        ovn_client = self.l3_plugin._ovn_client
        ovn_client._ovn_scheduler = l3_sched.OVNGatewayLeastLoadedScheduler()
        ext1 = self._create_ext_network(
            'ext1', 'flat', 'physnet3', None, "20.0.0.1", "20.0.0.0/24")
        gw_info = {'network_id': ext1['network']['id']}

        # Create 4 routers with a gateway. Since we're using physnet3, the
        # chassis candidates will be chassis1 and chassis2.
        for i in range(1, 5):
            self._create_router('router%d' % i, gw_info=gw_info)

        # At this point we expect two gateways to be present in chassis1
        # and two in chassis2. If schema supports L3 HA, we expect each
        # chassis to host 2 priority 2 gateways and 2 priority 1 ones.
        # Each chassis contains a dict of (priority, # of ports hosted).
        # {1: 2, 2: 2} means that this chassis hosts 2 ports of prio 1
        # and two ports of prio 2.
        expected = {self.chassis1: {1: 2, 2: 2},
                    self.chassis2: {1: 2, 2: 2}}
        sched_info = {}
        for row in self.nb_api.tables[
                'Logical_Router_Port'].rows.values():
            for gwc in row.gateway_chassis:
                chassis = sched_info.setdefault(gwc.chassis_name, {})
                chassis[gwc.priority] = chassis.get(gwc.priority, 0) + 1
        self.assertEqual(expected, sched_info)

    def test_gateway_chassis_least_loaded_scheduler_anti_affinity(self):
        ovn_client = self.l3_plugin._ovn_client
        ovn_client._ovn_scheduler = l3_sched.OVNGatewayLeastLoadedScheduler()
        ext1 = self._create_ext_network(
            'ext1', 'flat', 'physnet5', None, "10.10.50.1", "10.10.50.0/24")
        gw_info = {'network_id': ext1['network']['id']}

        chassis_list = []
        # first fill a few chassis with normal routers
        chassis_list.extend(
            self._add_chassis(0, ovn_const.MAX_GW_CHASSIS * 2, ['physnet5']))
        for i in range(1, (ovn_const.MAX_GW_CHASSIS * 4) + 1):
            router = self._create_router('router%d' % i, gw_info=gw_info)

        # add more chassis and create a set of routers with multiple gateway
        # ports
        #
        # This will stage a situation where a few chassis have higher load
        # which we can use to confirm that the anti-affinity algorithm works as
        # expected.
        #
        # Each router created below will have three LRPs, which should fit
        # in ovn_const.MAX_GW_CHASSIS * 3 chassis without duplicates when
        # using the anti affinity scheduler.
        chassis_list.extend(
            self._add_chassis(
                len(chassis_list), ovn_const.MAX_GW_CHASSIS, ['physnet5']))
        router_lrps = {}
        for i in range(1, 2 + 1):
            router = self._create_router('router-multi-gw%d' % i)
            router_lrps[router['id']] = []
            self._add_external_gateways(
                router['id'],
                [
                    {'network_id': ext1['network']['id']},
                    {'network_id': ext1['network']['id']},
                    {'network_id': ext1['network']['id']},
                ])
            for row in self.nb_api.tables[
                    'Logical_Router_Port'].rows.values():
                if (ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY
                        not in row.external_ids):
                    continue
                ext_ids_rtr_name = row.external_ids[
                    ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY]
                if ext_ids_rtr_name == ovn_utils.ovn_name(router['id']):
                    chassis = {}
                    for gwc in row.gateway_chassis:
                        chassis[gwc.priority] = gwc.chassis_name
                    router_lrps[router['id']].append(chassis)
        for router, lrp_lists in router_lrps.items():
            while lrp_lists:
                try:
                    lrps = lrp_lists.pop()
                except IndexError:
                    break
                for lrp_list in lrp_lists:
                    for n in range(1, ovn_const.MAX_GW_CHASSIS + 1):
                        self.assertNotEqual(
                            lrps[n],
                            lrp_list[n])

    def _get_gw_port(self, router_id):
        router = self.l3_plugin._get_router(self.context, router_id)
        gw_port_id = router.get('gw_port_id', '')
        for row in self.nb_api.tables['Logical_Router_Port'].rows.values():
            if row.name == 'lrp-%s' % gw_port_id:
                return row

    def test_gateway_chassis_with_subnet_changes(self):
        """Launchpad bug #1843485: logical router port is getting lost

        Test cases when subnets are added to an external network after router
        has been configured to use that network via "set --external-gateway"
        """
        with mock.patch.object(self.l3_plugin.scheduler, 'select',
                               return_value=self.chassis1) as plugin_select:
            router1 = self._create_router('router1', gw_info=None)
            router_id = router1['id']
            self.assertIsNone(self._get_gw_port(router_id),
                              "router logical port unexpected before ext net")

            # Create external network with no subnets and assign it to router
            ext1 = self._create_ext_network(
                'ext1', 'flat', 'physnet3', None, gateway=None, cidr=None)
            net_id = ext1['network']['id']

            gw_info = {'network_id': ext1['network']['id']}
            self.l3_plugin.update_router(
                self.context, router_id,
                {'router': {l3_apidef.EXTERNAL_GW_INFO: gw_info}})
            self.assertIsNotNone(self._get_gw_port(router_id),
                                 "router logical port must exist after gw add")

            # Add subnets to external network. This should percolate
            # into l3_plugin.update_router()
            kwargs = {'ip_version': n_consts.IP_VERSION_4,
                      'gateway_ip': '10.0.0.1', 'cidr': '10.0.0.0/24'}
            subnet4_res = self._create_subnet(
                self.fmt, net_id, **kwargs)
            subnet4 = self.deserialize(self.fmt, subnet4_res).get('subnet')
            self.assertIsNotNone(self._get_gw_port(router_id),
                                 "router logical port must exist after v4 add")

            kwargs = {'ip_version': n_consts.IP_VERSION_6,
                      'gateway_ip': 'fe81::1', 'cidr': 'fe81::/64',
                      'ipv6_ra_mode': n_consts.IPV6_SLAAC,
                      'ipv6_address_mode': n_consts.IPV6_SLAAC}
            subnet6_res = self._create_subnet(
                self.fmt, net_id, **kwargs)
            subnet6 = self.deserialize(self.fmt, subnet6_res).get('subnet')
            self.assertIsNotNone(self._get_gw_port(router_id),
                                 "router logical port must exist after v6 add")

            self.assertGreaterEqual(plugin_select.call_count, 3)

            # Verify that ports have had the subnets created
            kwargs = {'device_owner': n_consts.DEVICE_OWNER_ROUTER_GW}
            ports_res = self._list_ports(self.fmt, net_id=net_id, **kwargs)
            ports = self.deserialize(self.fmt, ports_res).get('ports')
            subnet4_ip = None
            subnet6_ip = None
            for port in ports:
                for fixed_ip in port.get('fixed_ips', []):
                    if fixed_ip.get('subnet_id') == subnet4['id']:
                        subnet4_ip = fixed_ip.get('ip_address')
                    if fixed_ip.get('subnet_id') == subnet6['id']:
                        subnet6_ip = fixed_ip.get('ip_address')
            self.assertIsNotNone(subnet4_ip)
            self.assertIsNotNone(subnet6_ip)

            # Verify that logical router port is properly configured
            gw_port = self._get_gw_port(router_id)
            self.assertIsNotNone(gw_port)

            expected_networks = ['%s/24' % subnet4_ip, '%s/64' % subnet6_ip]
            self.assertCountEqual(
                expected_networks, gw_port.networks,
                'networks in ovn port must match fixed_ips in neutron')

    def test_logical_router_port_creation(self):
        """Launchpad bug #1844652: Verify creation and removal of lrp

        This test verifies that logical router port is created and removed
        based on attaching and detaching the external network to a router.
        """
        router = self._create_router('router1', gw_info=None)
        router_id = router['id']
        self.assertIsNone(self._get_gw_port(router_id),
                          "router logical port unexpected before ext net")

        # Create external network and assign it to router
        ext1 = self._create_ext_network(
            'ext1', 'flat', 'physnet3', None, gateway=None, cidr=None)
        gw_info = {'network_id': ext1['network']['id']}
        self.l3_plugin.update_router(
            self.context, router_id,
            {'router': {l3_apidef.EXTERNAL_GW_INFO: gw_info}})
        self.assertIsNotNone(self._get_gw_port(router_id),
                             "router logical port missing after ext net add")

        # Un-assign external network from router
        self.l3_plugin.update_router(
            self.context, router_id,
            {'router': {l3_apidef.EXTERNAL_GW_INFO: None}})
        self.assertIsNone(self._get_gw_port(router_id),
                          "router logical port exists after ext net removal")

    def test_gateway_chassis_with_bridge_mappings(self):
        """Check selected ovn chassis based on external network

        This test sets different gateway values to ensure that the proper
        chassis are candidates, based on the physical network mappings.
        """

        ovn_client = self.l3_plugin._ovn_client
        # Create external networks with vlan, flat and geneve network types
        ext1 = self._create_ext_network(
            'ext1', 'vlan', 'physnet1', 1, "10.0.0.1", "10.0.0.0/24")
        ext2 = self._create_ext_network(
            'ext2', 'flat', 'physnet3', None, "20.0.0.1", "20.0.0.0/24")
        ext3 = self._create_ext_network(
            'ext3', 'geneve', None, 10, "30.0.0.1", "30.0.0.0/24")
        # mock select function and check if it is called with expected
        # candidates.
        self.candidates = []

        def fake_select(*args, **kwargs):
            self.assertCountEqual(self.candidates, kwargs['candidates'])
            # We are not interested in further processing, let us return
            # a random chassis name to avoid errors.
            return ['a-random-chassis']

        with mock.patch.object(self.l3_plugin.scheduler, 'select',
                               side_effect=fake_select) as plugin_select:
            self.candidates = [self.chassis1]
            gw_info = {'network_id': ext1['network']['id']}
            router1 = self._create_router('router1', gw_info=gw_info)

            # Unset the redirect-chassis so that schedule_unhosted_gateways
            # will try to schedule it.
            self._unset_lrp_gw_chassis(ovn_client)
            self.l3_plugin.schedule_unhosted_gateways()

            self.candidates = [self.chassis1, self.chassis2]
            gw_info = {'network_id': ext2['network']['id']}
            self.l3_plugin.update_router(
                self.context, router1['id'],
                {'router': {l3_apidef.EXTERNAL_GW_INFO: gw_info}})
            self._unset_lrp_gw_chassis(ovn_client)
            self.l3_plugin.schedule_unhosted_gateways()

            self.candidates = []
            gw_info = {'network_id': ext3['network']['id']}
            self.l3_plugin.update_router(
                self.context, router1['id'],
                {'router': {l3_apidef.EXTERNAL_GW_INFO: gw_info}})
            self._unset_lrp_gw_chassis(ovn_client)
            self.l3_plugin.schedule_unhosted_gateways()

            # We can't test call_count for these mocks, as we have disabled
            # maintenance_worker which will trigger chassis events
            # and eventually calling schedule_unhosted_gateways.
            # The router is created with a gateway port and updated twice.
            # However, the "plugin_select" is called only twice because the
            # third gateway network used is type "geneve" and the LRP are not
            # hosted in any chassis.
            self.assertGreaterEqual(plugin_select.call_count, 2)

    def _find_port_binding(self, port_id):
        cmd = self.sb_api.db_find_rows('Port_Binding',
                                       ('logical_port', '=', port_id))
        rows = cmd.execute(check_error=True)
        return rows[0] if rows else None

    def test_router_gateway_port_binding_host_id(self):
        # Test setting chassis on chassisredirect port in Port_Binding table,
        # will update host_id of corresponding router gateway port
        # with this chassis.
        chassis = idlutils.row_by_value(self.sb_api.idl, 'Chassis',
                                        'name', self.chassis1)
        host_id = chassis.hostname
        ext = self._create_ext_network(
            'ext1', 'vlan', 'physnet1', 1, "10.0.0.1", "10.0.0.0/24")
        gw_info = {'network_id': ext['network']['id']}
        router = self._create_router('router1', gw_info=gw_info)
        core_plugin = directory.get_plugin()
        gw_port_id = router.get('gw_port_id')

        # Set chassis on chassisredirect port in Port_Binding table
        logical_port = 'cr-lrp-%s' % gw_port_id
        self.assertTrue(self.cr_lrp_pb_event.wait(logical_port),
                        msg='lrp %s failed to bind' % logical_port)
        self.sb_api.lsp_bind(logical_port, self.chassis1,
                             may_exist=True).execute(check_error=True)

        def check_port_binding_host_id(port_id):
            # Get port from Neutron DB
            port = core_plugin.get_ports(
                self.context, filters={'id': [port_id]})[0]
            # Get port from OVN DB
            bp = self._find_port_binding(port_id)
            ovn_host_id = bp.external_ids.get(ovn_const.OVN_HOST_ID_EXT_ID_KEY)
            return port[portbindings.HOST_ID] == host_id == ovn_host_id

        # Test if router gateway port updated with this chassis
        n_utils.wait_until_true(lambda: check_port_binding_host_id(
            gw_port_id))

        # Simulate failover to another chassis and check host_id in Neutron DB
        # and external_ids:neutron:host_id in OVN DB are updated
        chassis = idlutils.row_by_value(
            self.sb_api.idl, "Chassis", "name", self.chassis2
        )
        host_id = chassis.hostname
        self.sb_api.lsp_unbind(logical_port).execute(check_error=True)
        self.sb_api.lsp_bind(logical_port, self.chassis2).execute(
            check_error=True
        )
        n_utils.wait_until_true(lambda: check_port_binding_host_id(gw_port_id))

    def _validate_router_ipv6_ra_configs(self, lrp_name, expected_ra_confs):
        lrp = idlutils.row_by_value(self.nb_api.idl,
                                    'Logical_Router_Port', 'name', lrp_name)
        self.assertEqual(expected_ra_confs, lrp.ipv6_ra_configs)

    def _test_router_port_ipv6_ra_configs_helper(
            self, cidr='aef0::/64', ip_version=6,
            address_mode=n_consts.IPV6_SLAAC,):
        router1 = self._create_router('router1')
        n1 = self._make_network(self.fmt, 'n1', True)
        if ip_version == 6:
            kwargs = {'ip_version': 6, 'cidr': 'aef0::/64',
                      'ipv6_address_mode': address_mode,
                      'ipv6_ra_mode': address_mode}
        else:
            kwargs = {'ip_version': 4, 'cidr': '10.0.0.0/24'}

        res = self._create_subnet(self.fmt, n1['network']['id'],
                                  **kwargs)

        n1_s1 = self.deserialize(self.fmt, res)
        n1_s1_id = n1_s1['subnet']['id']
        router_iface_info = self.l3_plugin.add_router_interface(
            self.context, router1['id'], {'subnet_id': n1_s1_id})

        lrp_name = ovn_utils.ovn_lrouter_port_name(
            router_iface_info['port_id'])
        if ip_version == 6:
            expected_ra_configs = {
                'address_mode': ovn_utils.get_ovn_ipv6_address_mode(
                    address_mode),
                'send_periodic': 'true',
                'mtu': '1442'}
        else:
            expected_ra_configs = {}
        self._validate_router_ipv6_ra_configs(lrp_name, expected_ra_configs)

    def test_router_port_ipv6_ra_configs_addr_mode_slaac(self):
        self._test_router_port_ipv6_ra_configs_helper()

    def test_router_port_ipv6_ra_configs_addr_mode_dhcpv6_stateful(self):
        self._test_router_port_ipv6_ra_configs_helper(
            address_mode=n_consts.DHCPV6_STATEFUL)

    def test_router_port_ipv6_ra_configs_addr_mode_dhcpv6_stateless(self):
        self._test_router_port_ipv6_ra_configs_helper(
            address_mode=n_consts.DHCPV6_STATELESS)

    def test_router_port_ipv6_ra_configs_ipv4(self):
        self._test_router_port_ipv6_ra_configs_helper(
            ip_version=4)

    def test_create_delete_router_multiple_gw_ports(self):
        ext4 = self._create_ext_network(
            'ext4', 'flat', self.physnet_used[0], None, '40.0.0.1',
            '40.0.0.0/24')
        router = self._create_router('router4')
        gws = self._add_external_gateways(
            router['id'],
            [
                {'network_id': ext4['network']['id']},
                {'network_id': ext4['network']['id']},
            ]
        )
        lr = self.nb_api.lookup('Logical_Router',
                                ovn_utils.ovn_name(router['id']))
        self.assertEqual(
            len(lr.ports),
            len(gws['router']['external_gateways']))

        self.assertEqual(
            len(lr.static_routes),
            1)

        self.l3_plugin.delete_router(self.context, id=router['id'])
        self.assertRaises(idlutils.RowNotFound, self.nb_api.lookup,
                          'Logical_Router', ovn_utils.ovn_name(router['id']))

    def test_create_router_multiple_gw_ports_ecmp(self):
        ext5 = self._create_ext_network(
            'ext5', 'flat', self.physnet_used[1], None, '10.0.50.1',
            '10.0.50.0/24')
        router = self._create_router('router5', enable_ecmp=True)
        gws = self._add_external_gateways(
            router['id'],
            [
                {'network_id': ext5['network']['id']},
                {'network_id': ext5['network']['id']},
            ]
        )
        lr = self.nb_api.lookup('Logical_Router',
                                ovn_utils.ovn_name(router['id']))
        # Check that the expected number of ports are created
        self.assertEqual(
            len(lr.ports),
            len(gws['router']['external_gateways']))
        # Check that the expected number of static routes are created
        self.assertEqual(
            len(lr.static_routes),
            len(gws['router']['external_gateways']))

    def test_create_delete_router_multiple_gw_ports_ecmp_and_bfd(self):
        default_gw = "10.0.60.1"
        ext6 = self._create_ext_network(
            'ext6', 'flat', 'physnet6', None, default_gw, "10.0.60.0/24")
        router = self._create_router('router6', gw_info=None,
                                     enable_bfd=True, enable_ecmp=True)
        gws = self._add_external_gateways(
            router['id'],
            [
                {'network_id': ext6['network']['id']},
                {'network_id': ext6['network']['id']},
            ])
        lr = self.nb_api.lookup('Logical_Router',
                                ovn_utils.ovn_name(router['id']))

        # Check that the expected number of ports are created
        self.assertEqual(
            len(lr.ports),
            len(gws['router']['external_gateways']))
        # Check that the expected number of static routes are created
        self.assertEqual(
            len(lr.static_routes),
            len(gws['router']['external_gateways']))
        # Check that static_route bfd and output_port attributes is set to the
        # expected values
        for static_route in lr.static_routes:
            self.assertNotEqual(
                [],
                static_route.bfd)
            self.assertNotEqual(
                [],
                static_route.output_port)
            self.assertIn(static_route.output_port[0],
                          [lrp.name
                           for lrp in lr.ports])
            self.assertIn(static_route.bfd[0].logical_port,
                          [lrp.name
                           for lrp in lr.ports])
            self.assertEqual(static_route.bfd[0].logical_port,
                             static_route.output_port[0])

        router_ips = set()
        for ext_gws in gws['router']['external_gateways']:
            for ext_fip in ext_gws['external_fixed_ips']:
                router_ips.add(ext_fip['ip_address'])

        lrps = set()
        for lrp in lr.ports:
            for network in lrp.networks:
                self.assertIn(
                    network.split('/')[0],
                    router_ips)
            lrps.add(lrp.name)
            bfd_rows = self.nb_api.bfd_find(
                    lrp.name, default_gw).execute(check_error=True)
            if not bfd_rows:
                raise AssertionError('None of the expected BFD rows found.')
            for bfd_row in bfd_rows:
                self.assertEqual(
                    bfd_row.logical_port,
                    lrp.name)
                self.assertEqual(
                    bfd_row.dst_ip,
                    default_gw)

        self.l3_plugin.delete_router(self.context, id=router['id'])
        self.assertRaises(idlutils.RowNotFound, self.nb_api.lookup,
                          'Logical_Router', ovn_utils.ovn_name(router['id']))
        for lrp_name in lrps:
            if self.nb_api.bfd_find(
                    lrp_name, default_gw).execute(check_error=True):
                raise AssertionError('Unexpectedly found BFD rows.')

    def test_update_router_single_gw_bfd(self):
        ext1 = self._create_ext_network(
            'ext7', 'flat', 'physnet1', None, "10.0.70.1", "10.0.70.0/24")
        gw_info = {'network_id': ext1['network']['id']}
        router = self._create_router('router7', gw_info=gw_info)
        self.assertFalse(router['enable_default_route_bfd'])
        lr = self.nb_api.lr_get(ovn_utils.ovn_name(router['id'])).execute()
        for route in ovn_utils.get_lrouter_ext_gw_static_route(lr):
            self.assertEqual(
                [],
                route.bfd)

        router = self.l3_plugin.update_router(
            self.context, router['id'],
            {'router': {'enable_default_route_bfd': True}})
        self.assertTrue(router['enable_default_route_bfd'])
        lr = self.nb_api.lr_get(ovn_utils.ovn_name(router['id'])).execute()
        for route in ovn_utils.get_lrouter_ext_gw_static_route(lr):
            self.assertNotEqual(
                [],
                route.bfd)

    def test_gateway_chassis_rebalance(self):
        ovn_client = self.l3_plugin._ovn_client
        chassis4 = self.add_fake_chassis(
            'ovs-host4', physical_nets=['physnet4'], other_config={
                'ovn-cms-options': 'enable-chassis-as-gw'})
        ovn_client._ovn_scheduler = l3_sched.OVNGatewayLeastLoadedScheduler()
        ext1 = self._create_ext_network(
            'ext1', 'flat', 'physnet4', None, "30.0.0.1", "30.0.0.0/24")
        gw_info = {'network_id': ext1['network']['id']}
        # Tries to create 5 routers with a gateway. Since we're using
        # physnet4, the chassis candidates will be chassis4 initially.
        num_routers = len(self._create_routers_wait_pb(
            1, 5, gw_info=gw_info, bind_chassis=chassis4))
        self.l3_plugin.schedule_unhosted_gateways()
        expected = {chassis4: {1: num_routers}}
        self.assertEqual(expected, self._get_gwc_dict())

        # Add another chassis as a gateway chassis
        chassis5 = self.add_fake_chassis(
            'ovs-host5', physical_nets=['physnet4'], other_config={
                'ovn-cms-options': 'enable-chassis-as-gw'})
        # Add a node as compute node. Compute node wont be
        # used to schedule the router gateway ports therefore
        # priority values wont be changed. Therefore chassis4 would
        # still have priority 2
        self.add_fake_chassis('ovs-host6', physical_nets=['physnet4'])

        # Chassis4 should have all ports at Priority 2
        self.l3_plugin.schedule_unhosted_gateways()
        self.assertEqual({2: num_routers}, self._get_gwc_dict()[chassis4])
        # Chassis5 should have all ports at Priority 1
        self.assertEqual({1: num_routers}, self._get_gwc_dict()[chassis5])

        # delete chassis that hosts all the gateways
        self.del_fake_chassis(chassis4)
        self.l3_plugin.schedule_unhosted_gateways()

        # As Chassis4 has been removed so all gateways that were
        # hosted there are now primaries on chassis5 and have
        # priority 1.
        self.assertEqual({1: num_routers}, self._get_gwc_dict()[chassis5])

    def test_gateway_chassis_rebalance_max_chassis(self):
        chassis_list = []
        # spawn 6 chassis and check if port has MAX_CHASSIS candidates.
        for i in range(0, ovn_const.MAX_GW_CHASSIS + 1):
            chassis_list.append(
                self.add_fake_chassis(
                    'ovs-host%s' % i, physical_nets=['physnet1'],
                    other_config={'ovn-cms-options': 'enable-chassis-as-gw'}))

        ext1 = self._create_ext_network(
            'ext1', 'vlan', 'physnet1', 1, "10.0.0.1", "10.0.0.0/24")
        gw_info = {'network_id': ext1['network']['id']}
        router = self._create_router('router', gw_info=gw_info)
        gw_port_id = router.get('gw_port_id')
        logical_port = 'cr-lrp-%s' % gw_port_id
        self.assertTrue(self.cr_lrp_pb_event.wait(logical_port),
                        msg='lrp %s failed to bind' % logical_port)
        self.sb_api.lsp_bind(logical_port, chassis_list[0],
                             may_exist=True).execute(check_error=True)

        self.l3_plugin.schedule_unhosted_gateways()
        for row in self.nb_api.tables[
                'Logical_Router_Port'].rows.values():
            self.assertEqual(ovn_const.MAX_GW_CHASSIS,
                             len(row.gateway_chassis))

    def test_set_router_mac_age_limit(self):
        name = "macage_router1"
        router = self._create_router(name)
        lr_name = ovn_utils.ovn_name(router['id'])
        options = self.nb_api.db_get(
            "Logical_Router", lr_name, "options").execute(check_error=True)
        self.assertEqual(ovn_conf.get_ovn_mac_binding_age_threshold(),
                         options[ovn_const.LR_OPTIONS_MAC_AGE_LIMIT])

    def test_schedule_unhosted_gateways_single_transaction(self):
        ext1 = self._create_ext_network(
            'ext1', 'flat', 'physnet6', None, "10.0.60.1", "10.0.60.0/24")
        gw_info = {'network_id': ext1['network']['id']}

        # Attempt to add 4 routers, since there are no chassis, none of them
        # will be scheduled on any chassis.
        num_routers = len(self._create_routers_wait_pb(1, 4, gw_info=gw_info))
        self.assertEqual({}, self._get_gwc_dict())

        # Add 2 chassis and rebalance gateways.
        #
        # The ovsdb_monitor.ChassisEvent handler will attempt to schedule
        # unhosted gateways as chassis are added.
        #
        # Temporarily mock it out while adding the chassis so that we can get a
        # predictable result for the purpose of this test.
        chassis_list = []
        with mock.patch.object(
                self.l3_plugin, 'schedule_unhosted_gateways'):
            chassis_list.extend(self._add_chassis(1, 2, ['physnet6']))
        self.assertEqual({}, self._get_gwc_dict())

        # Wrap `self.l3_plugin._nb_ovn.transaction` so that we can assert on
        # number of calls.
        with mock.patch.object(
                self.l3_plugin._nb_ovn, 'transaction',
                wraps=self.l3_plugin._nb_ovn.transaction) as wrap_txn:
            self.l3_plugin.schedule_unhosted_gateways()
            # The server is alive and we can't control the exact number of
            # calls made to `_nb_ovn.transaction`. We can however check that
            # the number of calls is less than number of unhosted gateways.
            self.assertLess(len(wrap_txn.mock_calls), num_routers)

        # Ensure the added gateways are spread evenly on the added chassis.
        self.assertEqual(
            {'chassis-01': {1: 2, 2: 2},
             'chassis-02': {1: 2, 2: 2}},
            self._get_gwc_dict())
