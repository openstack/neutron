# Copyright (c) 2013 OpenStack Foundation
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

import functools

import fixtures
import mock
import six
import testtools
import uuid
import webob

from oslo_db import exception as db_exc
from oslo_utils import uuidutils
from sqlalchemy.orm import exc as sqla_exc

from neutron.callbacks import registry
from neutron.common import constants
from neutron.common import exceptions as exc
from neutron.common import utils
from neutron import context
from neutron.db import api as db_api
from neutron.db import db_base_plugin_v2 as base_plugin
from neutron.db import l3_db
from neutron.db import models_v2
from neutron.extensions import external_net
from neutron.extensions import multiprovidernet as mpnet
from neutron.extensions import portbindings
from neutron.extensions import providernet as pnet
from neutron import manager
from neutron.plugins.common import constants as p_const
from neutron.plugins.ml2.common import exceptions as ml2_exc
from neutron.plugins.ml2 import config
from neutron.plugins.ml2 import db as ml2_db
from neutron.plugins.ml2 import driver_api
from neutron.plugins.ml2 import driver_context
from neutron.plugins.ml2.drivers import type_vlan
from neutron.plugins.ml2 import models
from neutron.plugins.ml2 import plugin as ml2_plugin
from neutron.tests import base
from neutron.tests.unit import _test_extension_portbindings as test_bindings
from neutron.tests.unit.agent import test_securitygroups_rpc as test_sg_rpc
from neutron.tests.unit.db import test_allowedaddresspairs_db as test_pair
from neutron.tests.unit.db import test_db_base_plugin_v2 as test_plugin
from neutron.tests.unit.extensions import test_extra_dhcp_opt as test_dhcpopts
from neutron.tests.unit.plugins.ml2.drivers import mechanism_logger as \
     mech_logger
from neutron.tests.unit.plugins.ml2.drivers import mechanism_test as mech_test


config.cfg.CONF.import_opt('network_vlan_ranges',
                           'neutron.plugins.ml2.drivers.type_vlan',
                           group='ml2_type_vlan')


PLUGIN_NAME = 'neutron.plugins.ml2.plugin.Ml2Plugin'

DEVICE_OWNER_COMPUTE = 'compute:None'
HOST = 'fake_host'


# TODO(marun) - Move to somewhere common for reuse
class PluginConfFixture(fixtures.Fixture):
    """Plugin configuration shared across the unit and functional tests."""

    def __init__(self, plugin_name, parent_setup=None):
        super(PluginConfFixture, self).__init__()
        self.plugin_name = plugin_name
        self.parent_setup = parent_setup

    def _setUp(self):
        if self.parent_setup:
            self.parent_setup()


class Ml2ConfFixture(PluginConfFixture):

    def __init__(self, parent_setup=None):
        super(Ml2ConfFixture, self).__init__(PLUGIN_NAME, parent_setup)


class Ml2PluginV2TestCase(test_plugin.NeutronDbPluginV2TestCase):

    _mechanism_drivers = ['logger', 'test']

    def setup_parent(self):
        """Perform parent setup with the common plugin configuration class."""
        l3_plugin = ('neutron.tests.unit.extensions.test_l3.'
                     'TestL3NatServicePlugin')
        service_plugins = {'l3_plugin_name': l3_plugin}
        # Ensure that the parent setup can be called without arguments
        # by the common configuration setUp.
        parent_setup = functools.partial(
            super(Ml2PluginV2TestCase, self).setUp,
            plugin=PLUGIN_NAME,
            service_plugins=service_plugins,
        )
        self.useFixture(Ml2ConfFixture(parent_setup))
        self.port_create_status = 'DOWN'

    def setUp(self):
        # Enable the test mechanism driver to ensure that
        # we can successfully call through to all mechanism
        # driver apis.
        config.cfg.CONF.set_override('mechanism_drivers',
                                     self._mechanism_drivers,
                                     group='ml2')
        self.physnet = 'physnet1'
        self.vlan_range = '1:100'
        self.vlan_range2 = '200:300'
        self.physnet2 = 'physnet2'
        self.phys_vrange = ':'.join([self.physnet, self.vlan_range])
        self.phys2_vrange = ':'.join([self.physnet2, self.vlan_range2])
        config.cfg.CONF.set_override('network_vlan_ranges',
                                     [self.phys_vrange, self.phys2_vrange],
                                     group='ml2_type_vlan')
        self.setup_parent()
        self.driver = ml2_plugin.Ml2Plugin()
        self.context = context.get_admin_context()


class TestMl2BulkToggleWithoutBulkless(Ml2PluginV2TestCase):

    _mechanism_drivers = ['logger', 'test']

    def test_bulk_enabled_with_bulk_drivers(self):
        self.assertFalse(self._skip_native_bulk)


class TestMl2BasicGet(test_plugin.TestBasicGet,
                      Ml2PluginV2TestCase):
    pass


class TestMl2V2HTTPResponse(test_plugin.TestV2HTTPResponse,
                            Ml2PluginV2TestCase):
    pass


class TestMl2NetworksV2(test_plugin.TestNetworksV2,
                        Ml2PluginV2TestCase):
    def setUp(self, plugin=None):
        super(TestMl2NetworksV2, self).setUp()
        # provider networks
        self.pnets = [{'name': 'net1',
                       pnet.NETWORK_TYPE: 'vlan',
                       pnet.PHYSICAL_NETWORK: 'physnet1',
                       pnet.SEGMENTATION_ID: 1,
                       'tenant_id': 'tenant_one'},
                      {'name': 'net2',
                       pnet.NETWORK_TYPE: 'vlan',
                       pnet.PHYSICAL_NETWORK: 'physnet2',
                       pnet.SEGMENTATION_ID: 210,
                       'tenant_id': 'tenant_one'},
                      {'name': 'net3',
                       pnet.NETWORK_TYPE: 'vlan',
                       pnet.PHYSICAL_NETWORK: 'physnet2',
                       pnet.SEGMENTATION_ID: 220,
                       'tenant_id': 'tenant_one'}
                      ]
        # multiprovider networks
        self.mp_nets = [{'name': 'net4',
                         mpnet.SEGMENTS:
                             [{pnet.NETWORK_TYPE: 'vlan',
                               pnet.PHYSICAL_NETWORK: 'physnet2',
                               pnet.SEGMENTATION_ID: 1},
                              {pnet.NETWORK_TYPE: 'vlan',
                               pnet.PHYSICAL_NETWORK: 'physnet2',
                               pnet.SEGMENTATION_ID: 202}],
                         'tenant_id': 'tenant_one'}
                        ]
        self.nets = self.mp_nets + self.pnets

    def test_port_delete_helper_tolerates_failure(self):
        plugin = manager.NeutronManager.get_plugin()
        with mock.patch.object(plugin, "delete_port",
                               side_effect=exc.PortNotFound(port_id="123")):
            plugin._delete_ports(mock.MagicMock(), [mock.MagicMock()])
        with mock.patch.object(plugin, "delete_port",
                               side_effect=sqla_exc.ObjectDeletedError(None)):
            plugin._delete_ports(mock.MagicMock(), [mock.MagicMock()])

    def test_subnet_delete_helper_tolerates_failure(self):
        plugin = manager.NeutronManager.get_plugin()
        with mock.patch.object(plugin, "delete_subnet",
                               side_effect=exc.SubnetNotFound(subnet_id="1")):
            plugin._delete_subnets(mock.MagicMock(), [mock.MagicMock()])
        with mock.patch.object(plugin, "delete_subnet",
                               side_effect=sqla_exc.ObjectDeletedError(None)):
            plugin._delete_subnets(mock.MagicMock(), [mock.MagicMock()])

    def _create_and_verify_networks(self, networks):
        for net_idx, net in enumerate(networks):
            # create
            req = self.new_create_request('networks',
                                          {'network': net})
            # verify
            network = self.deserialize(self.fmt,
                                       req.get_response(self.api))['network']
            if mpnet.SEGMENTS not in net:
                for k, v in six.iteritems(net):
                    self.assertEqual(net[k], network[k])
                    self.assertNotIn(mpnet.SEGMENTS, network)
            else:
                segments = network[mpnet.SEGMENTS]
                expected_segments = net[mpnet.SEGMENTS]
                self.assertEqual(len(expected_segments), len(segments))
                for expected, actual in zip(expected_segments, segments):
                    self.assertEqual(expected, actual)

    def _lookup_network_by_segmentation_id(self, seg_id, num_expected_nets):
        params_str = "%s=%s" % (pnet.SEGMENTATION_ID, seg_id)
        net_req = self.new_list_request('networks', None,
                                        params=params_str)
        networks = self.deserialize(self.fmt, net_req.get_response(self.api))
        if num_expected_nets:
            self.assertIsNotNone(networks)
            self.assertEqual(num_expected_nets, len(networks['networks']))
        else:
            self.assertIsNone(networks)
        return networks

    def test_list_networks_with_segmentation_id(self):
        self._create_and_verify_networks(self.pnets)
        # verify we can find the network that we expect
        lookup_vlan_id = 1
        expected_net = [n for n in self.pnets
                        if n[pnet.SEGMENTATION_ID] == lookup_vlan_id].pop()
        networks = self._lookup_network_by_segmentation_id(lookup_vlan_id, 1)
        # verify all provider attributes
        network = networks['networks'][0]
        for attr in pnet.ATTRIBUTES:
            self.assertEqual(expected_net[attr], network[attr])

    def test_list_mpnetworks_with_segmentation_id(self):
        self._create_and_verify_networks(self.nets)

        # get all networks with seg_id=1 (including multisegment networks)
        lookup_vlan_id = 1
        networks = self._lookup_network_by_segmentation_id(lookup_vlan_id, 2)

        # get the mpnet
        networks = [n for n in networks['networks'] if mpnet.SEGMENTS in n]
        network = networks.pop()
        # verify attributes of the looked up item
        segments = network[mpnet.SEGMENTS]
        expected_segments = self.mp_nets[0][mpnet.SEGMENTS]
        self.assertEqual(len(expected_segments), len(segments))
        for expected, actual in zip(expected_segments, segments):
            self.assertEqual(expected, actual)

    def test_create_network_segment_allocation_fails(self):
        plugin = manager.NeutronManager.get_plugin()
        with mock.patch.object(plugin.type_manager, 'create_network_segments',
            side_effect=db_exc.RetryRequest(ValueError())) as f:
            self.assertRaises(ValueError,
                              plugin.create_network,
                              context.get_admin_context(),
                              {'network': {'tenant_id': 'sometenant',
                                           'name': 'dummy',
                                           'admin_state_up': True,
                                           'shared': False}})
            self.assertEqual(db_api.MAX_RETRIES + 1, f.call_count)


class TestExternalNetwork(Ml2PluginV2TestCase):

    def _create_external_network(self):
        data = {'network': {'name': 'net1',
                            'router:external': 'True',
                            'tenant_id': 'tenant_one'}}
        network_req = self.new_create_request('networks', data)
        network = self.deserialize(self.fmt,
                                   network_req.get_response(self.api))
        return network

    def test_external_network_type_none(self):
        config.cfg.CONF.set_default('external_network_type',
                                    None,
                                    group='ml2')

        network = self._create_external_network()
        # For external network, expected network type to be
        # tenant_network_types which is by default 'local'.
        self.assertEqual(p_const.TYPE_LOCAL,
                         network['network'][pnet.NETWORK_TYPE])
        # No physical network specified, expected 'None'.
        self.assertIsNone(network['network'][pnet.PHYSICAL_NETWORK])
        # External network will not have a segmentation id.
        self.assertIsNone(network['network'][pnet.SEGMENTATION_ID])
        # External network will not have multiple segments.
        self.assertNotIn(mpnet.SEGMENTS, network['network'])

    def test_external_network_type_vlan(self):
        config.cfg.CONF.set_default('external_network_type',
                                    p_const.TYPE_VLAN,
                                    group='ml2')

        network = self._create_external_network()
        # For external network, expected network type to be 'vlan'.
        self.assertEqual(p_const.TYPE_VLAN,
                         network['network'][pnet.NETWORK_TYPE])
        # Physical network is expected.
        self.assertIsNotNone(network['network'][pnet.PHYSICAL_NETWORK])
        # External network will have a segmentation id.
        self.assertIsNotNone(network['network'][pnet.SEGMENTATION_ID])
        # External network will not have multiple segments.
        self.assertNotIn(mpnet.SEGMENTS, network['network'])


class TestMl2NetworksWithVlanTransparencyAndMTU(TestMl2NetworksV2):
    def setUp(self, plugin=None):
        config.cfg.CONF.set_override('path_mtu', 1000, group='ml2')
        config.cfg.CONF.set_override('segment_mtu', 1000, group='ml2')
        config.cfg.CONF.set_override('advertise_mtu', True)
        config.cfg.CONF.set_override('vlan_transparent', True)
        super(TestMl2NetworksWithVlanTransparencyAndMTU, self).setUp(plugin)

    def test_create_network_vlan_transparent_and_mtu(self):
        data = {'network': {'name': 'net1',
                            mpnet.SEGMENTS:
                            [{pnet.NETWORK_TYPE: 'vlan',
                              pnet.PHYSICAL_NETWORK: 'physnet1'}],
                            'tenant_id': 'tenant_one'}}
        network_req = self.new_create_request('networks', data)
        res = network_req.get_response(self.api)
        self.assertEqual(201, res.status_int)
        network = self.deserialize(self.fmt, res)['network']
        self.assertEqual(network['mtu'], 1000)
        self.assertIn('vlan_transparent', network)


class TestMl2SubnetsV2(test_plugin.TestSubnetsV2,
                       Ml2PluginV2TestCase):
    def test_delete_subnet_race_with_dhcp_port_creation(self):
        with self.network() as network:
            with self.subnet(network=network) as subnet:
                subnet_id = subnet['subnet']['id']
                attempt = [0]

                def check_and_create_ports(context, subnet_id):
                    """A method to emulate race condition.

                    Adds dhcp port in the middle of subnet delete
                    """
                    if attempt[0] > 0:
                        return False
                    attempt[0] += 1
                    data = {'port': {'network_id': network['network']['id'],
                                     'tenant_id':
                                     network['network']['tenant_id'],
                                     'name': 'port1',
                                     'admin_state_up': 1,
                                     'device_owner':
                                     constants.DEVICE_OWNER_DHCP,
                                     'fixed_ips': [{'subnet_id': subnet_id}]}}
                    port_req = self.new_create_request('ports', data)
                    port_res = port_req.get_response(self.api)
                    self.assertEqual(201, port_res.status_int)
                    return (context.session.query(models_v2.IPAllocation).
                            filter_by(subnet_id=subnet_id).
                            join(models_v2.Port).first())

                plugin = manager.NeutronManager.get_plugin()
                # we mock _subnet_check_ip_allocations with method
                # that creates DHCP port 'in the middle' of subnet_delete
                # causing retry this way subnet is deleted on the
                # second attempt
                with mock.patch.object(plugin, '_subnet_check_ip_allocations',
                                       side_effect=check_and_create_ports):
                    req = self.new_delete_request('subnets', subnet_id)
                    res = req.get_response(self.api)
                    self.assertEqual(204, res.status_int)


class TestMl2PortsV2(test_plugin.TestPortsV2, Ml2PluginV2TestCase):

    def test_update_port_status_build(self):
        with self.port() as port:
            self.assertEqual('DOWN', port['port']['status'])
            self.assertEqual('DOWN', self.port_create_status)

    def test_update_port_status_short_id(self):
        ctx = context.get_admin_context()
        plugin = manager.NeutronManager.get_plugin()
        with self.port() as port:
            with mock.patch.object(ml2_db, 'get_binding_levels',
                                   return_value=[]) as mock_gbl:
                port_id = port['port']['id']
                short_id = port_id[:11]
                plugin.update_port_status(ctx, short_id, 'UP')
                mock_gbl.assert_called_once_with(mock.ANY, port_id, mock.ANY)

    def test_update_port_fixed_ip_changed(self):
        ctx = context.get_admin_context()
        plugin = manager.NeutronManager.get_plugin()
        with self.port() as port, mock.patch.object(
                plugin.notifier,
                'security_groups_member_updated') as sg_member_update:
            port['port']['fixed_ips'][0]['ip_address'] = '10.0.0.3'
            plugin.update_port(ctx, port['port']['id'], port)
            self.assertTrue(sg_member_update.called)

    def test_update_port_status_with_network(self):
        ctx = context.get_admin_context()
        plugin = manager.NeutronManager.get_plugin()
        with self.port() as port:
            net = plugin.get_network(ctx, port['port']['network_id'])
            with mock.patch.object(plugin, 'get_network') as get_net:
                plugin.update_port_status(ctx, port['port']['id'], 'UP',
                                          network=net)
                self.assertFalse(get_net.called)

    def test_update_port_mac(self):
        self.check_update_port_mac(
            host_arg={portbindings.HOST_ID: HOST},
            arg_list=(portbindings.HOST_ID,))

    def test_update_non_existent_port(self):
        ctx = context.get_admin_context()
        plugin = manager.NeutronManager.get_plugin()
        data = {'port': {'admin_state_up': False}}
        self.assertRaises(exc.PortNotFound, plugin.update_port, ctx,
                          'invalid-uuid', data)

    def test_delete_non_existent_port(self):
        ctx = context.get_admin_context()
        plugin = manager.NeutronManager.get_plugin()
        with mock.patch.object(ml2_plugin.LOG, 'debug') as log_debug:
            plugin.delete_port(ctx, 'invalid-uuid', l3_port_check=False)
            log_debug.assert_has_calls([
                mock.call(_("Deleting port %s"), 'invalid-uuid'),
                mock.call(_("The port '%s' was deleted"), 'invalid-uuid')
            ])

    def test_l3_cleanup_on_net_delete(self):
        l3plugin = manager.NeutronManager.get_service_plugins().get(
            p_const.L3_ROUTER_NAT)
        kwargs = {'arg_list': (external_net.EXTERNAL,),
                  external_net.EXTERNAL: True}
        with self.network(**kwargs) as n:
            with self.subnet(network=n, cidr='200.0.0.0/22'):
                l3plugin.create_floatingip(
                    context.get_admin_context(),
                    {'floatingip': {'floating_network_id': n['network']['id'],
                                    'tenant_id': n['network']['tenant_id']}}
                )
        self._delete('networks', n['network']['id'])
        flips = l3plugin.get_floatingips(context.get_admin_context())
        self.assertFalse(flips)

    def test_create_ports_bulk_port_binding_failure(self):
        ctx = context.get_admin_context()
        with self.network() as net:
            plugin = manager.NeutronManager.get_plugin()

            with mock.patch.object(plugin, '_bind_port_if_needed',
                side_effect=ml2_exc.MechanismDriverError(
                    method='create_port_bulk')) as _bind_port_if_needed:

                res = self._create_port_bulk(self.fmt, 2, net['network']['id'],
                                             'test', True, context=ctx)

                self.assertTrue(_bind_port_if_needed.called)
                # We expect a 500 as we injected a fault in the plugin
                self._validate_behavior_on_bulk_failure(
                    res, 'ports', webob.exc.HTTPServerError.code)

    def test_create_ports_bulk_with_sec_grp(self):
        ctx = context.get_admin_context()
        plugin = manager.NeutronManager.get_plugin()
        with self.network() as net,\
                mock.patch.object(plugin.notifier,
                                  'security_groups_member_updated') as m_upd,\
                mock.patch.object(plugin.notifier,
                                  'security_groups_provider_updated') as p_upd:

            res = self._create_port_bulk(self.fmt, 3, net['network']['id'],
                                         'test', True, context=ctx)
            ports = self.deserialize(self.fmt, res)
            used_sg = ports['ports'][0]['security_groups']
            m_upd.assert_called_once_with(ctx, used_sg)
            self.assertFalse(p_upd.called)

    def _check_security_groups_provider_updated_args(self, p_upd_mock, net_id):
        query_params = "network_id=%s" % net_id
        network_ports = self._list('ports', query_params=query_params)
        network_ports_ids = [port['id'] for port in network_ports['ports']]
        self.assertTrue(p_upd_mock.called)
        p_upd_args = p_upd_mock.call_args
        ports_ids = p_upd_args[0][1]
        self.assertEqual(sorted(network_ports_ids), sorted(ports_ids))

    def test_create_ports_bulk_with_sec_grp_member_provider_update(self):
        ctx = context.get_admin_context()
        plugin = manager.NeutronManager.get_plugin()
        with self.network() as net,\
                mock.patch.object(plugin.notifier,
                                  'security_groups_member_updated') as m_upd,\
                mock.patch.object(plugin.notifier,
                                  'security_groups_provider_updated') as p_upd:

            net_id = net['network']['id']
            data = [{
                    'network_id': net_id,
                    'tenant_id': self._tenant_id
                    },
                    {
                    'network_id': net_id,
                    'tenant_id': self._tenant_id,
                    'device_owner': constants.DEVICE_OWNER_DHCP
                    }
                    ]

            res = self._create_bulk_from_list(self.fmt, 'port',
                                              data, context=ctx)
            ports = self.deserialize(self.fmt, res)
            used_sg = ports['ports'][0]['security_groups']
            m_upd.assert_called_once_with(ctx, used_sg)
            self._check_security_groups_provider_updated_args(p_upd, net_id)
            m_upd.reset_mock()
            p_upd.reset_mock()
            data[0]['device_owner'] = constants.DEVICE_OWNER_DHCP
            self._create_bulk_from_list(self.fmt, 'port',
                                        data, context=ctx)
            self.assertFalse(m_upd.called)
            self._check_security_groups_provider_updated_args(p_upd, net_id)

    def test_create_ports_bulk_with_sec_grp_provider_update_ipv6(self):
        ctx = context.get_admin_context()
        plugin = manager.NeutronManager.get_plugin()
        fake_prefix = '2001:db8::/64'
        fake_gateway = 'fe80::1'
        with self.network() as net:
            with self.subnet(net,
                             gateway_ip=fake_gateway,
                             cidr=fake_prefix,
                             ip_version=6) as snet_v6,\
                    mock.patch.object(
                        plugin.notifier,
                        'security_groups_member_updated') as m_upd,\
                    mock.patch.object(
                        plugin.notifier,
                        'security_groups_provider_updated') as p_upd:

                net_id = net['network']['id']
                data = [{
                        'network_id': net_id,
                        'tenant_id': self._tenant_id,
                        'fixed_ips': [{'subnet_id': snet_v6['subnet']['id']}],
                        'device_owner': constants.DEVICE_OWNER_ROUTER_INTF
                        }
                        ]
                self._create_bulk_from_list(self.fmt, 'port',
                                            data, context=ctx)
                self.assertFalse(m_upd.called)
                self._check_security_groups_provider_updated_args(
                    p_upd, net_id)

    def test_delete_port_no_notify_in_disassociate_floatingips(self):
        ctx = context.get_admin_context()
        plugin = manager.NeutronManager.get_plugin()
        l3plugin = manager.NeutronManager.get_service_plugins().get(
            p_const.L3_ROUTER_NAT)
        with self.port() as port,\
                mock.patch.object(
                    l3plugin,
                    'disassociate_floatingips') as disassociate_floatingips,\
                mock.patch.object(registry, 'notify') as notify:

            port_id = port['port']['id']
            plugin.delete_port(ctx, port_id)

            # check that no notification was requested while under
            # transaction
            disassociate_floatingips.assert_has_calls([
                mock.call(ctx, port_id, do_notify=False)
            ])

            # check that notifier was still triggered
            self.assertTrue(notify.call_counts)

    def test_check_if_compute_port_serviced_by_dvr(self):
        self.assertTrue(utils.is_dvr_serviced('compute:None'))

    def test_check_if_lbaas_vip_port_serviced_by_dvr(self):
        self.assertTrue(utils.is_dvr_serviced(
            constants.DEVICE_OWNER_LOADBALANCER))

    def test_check_if_dhcp_port_serviced_by_dvr(self):
        self.assertTrue(utils.is_dvr_serviced(constants.DEVICE_OWNER_DHCP))

    def test_check_if_port_not_serviced_by_dvr(self):
        self.assertFalse(utils.is_dvr_serviced(
            constants.DEVICE_OWNER_ROUTER_INTF))

    def test_disassociate_floatingips_do_notify_returns_nothing(self):
        ctx = context.get_admin_context()
        l3plugin = manager.NeutronManager.get_service_plugins().get(
            p_const.L3_ROUTER_NAT)
        with self.port() as port:

            port_id = port['port']['id']
            # check that nothing is returned when notifications are handled
            # by the called method
            self.assertIsNone(l3plugin.disassociate_floatingips(ctx, port_id))

    def test_delete_port_tolerates_db_deadlock(self):
        ctx = context.get_admin_context()
        plugin = manager.NeutronManager.get_plugin()
        with self.port() as port:
            port_db, binding = ml2_db.get_locked_port_and_binding(
                ctx.session, port['port']['id'])
            with mock.patch('neutron.plugins.ml2.plugin.'
                            'db.get_locked_port_and_binding') as lock:
                lock.side_effect = [db_exc.DBDeadlock,
                                    (port_db, binding)]
                plugin.delete_port(ctx, port['port']['id'])
                self.assertEqual(2, lock.call_count)
                self.assertRaises(
                    exc.PortNotFound, plugin.get_port, ctx, port['port']['id'])


class TestMl2PluginOnly(Ml2PluginV2TestCase):
    """For testing methods that don't call drivers"""

    def _test_check_mac_update_allowed(self, vif_type, expect_change=True):
        plugin = manager.NeutronManager.get_plugin()
        port = {'mac_address': "fake_mac", 'id': "fake_id"}
        if expect_change:
            new_attrs = {"mac_address": "dummy_mac"}
        else:
            new_attrs = {"mac_address": port['mac_address']}
        binding = mock.Mock()
        binding.vif_type = vif_type
        mac_changed = plugin._check_mac_update_allowed(port, new_attrs,
                                                       binding)
        self.assertEqual(expect_change, mac_changed)

    def test_check_mac_update_allowed_if_no_mac_change(self):
        self._test_check_mac_update_allowed(portbindings.VIF_TYPE_UNBOUND,
                                            expect_change=False)

    def test_check_mac_update_allowed_unless_bound(self):
        with testtools.ExpectedException(exc.PortBound):
            self._test_check_mac_update_allowed(portbindings.VIF_TYPE_OVS)

    def test__device_to_port_id_prefix_names(self):
        input_output = [('sg-abcdefg', 'abcdefg'),
                        ('tap123456', '123456'),
                        ('qvo567890', '567890')]
        for device, expected in input_output:
            self.assertEqual(expected,
                             ml2_plugin.Ml2Plugin._device_to_port_id(
                                 self.context, device))

    def test__device_to_port_id_mac_address(self):
        with self.port() as p:
            mac = p['port']['mac_address']
            port_id = p['port']['id']
            self.assertEqual(port_id,
                             ml2_plugin.Ml2Plugin._device_to_port_id(
                                 self.context, mac))

    def test__device_to_port_id_not_uuid_not_mac(self):
        dev = '1234567'
        self.assertEqual(dev, ml2_plugin.Ml2Plugin._device_to_port_id(
            self.context, dev))

    def test__device_to_port_id_UUID(self):
        port_id = uuidutils.generate_uuid()
        self.assertEqual(port_id, ml2_plugin.Ml2Plugin._device_to_port_id(
            self.context, port_id))


class TestMl2DvrPortsV2(TestMl2PortsV2):
    def setUp(self):
        super(TestMl2DvrPortsV2, self).setUp()
        extensions = ['router',
                      constants.L3_AGENT_SCHEDULER_EXT_ALIAS,
                      constants.L3_DISTRIBUTED_EXT_ALIAS]
        self.plugin = manager.NeutronManager.get_plugin()
        self.l3plugin = mock.Mock()
        type(self.l3plugin).supported_extension_aliases = (
            mock.PropertyMock(return_value=extensions))
        self.service_plugins = {'L3_ROUTER_NAT': self.l3plugin}

    def _test_delete_dvr_serviced_port(self, device_owner, floating_ip=False):
        ns_to_delete = {'host': 'myhost', 'agent_id': 'vm_l3_agent',
                        'router_id': 'my_router'}
        fip_set = set()
        if floating_ip:
            fip_set.add(ns_to_delete['router_id'])

        with mock.patch.object(manager.NeutronManager,
                               'get_service_plugins',
                               return_value=self.service_plugins),\
                self.port(device_owner=device_owner) as port,\
                mock.patch.object(registry, 'notify') as notify,\
                mock.patch.object(self.l3plugin,
                                  'disassociate_floatingips',
                                  return_value=fip_set),\
                mock.patch.object(
                    self.l3plugin,
                    'dvr_deletens_if_no_port',
                    return_value=[ns_to_delete]) as dvr_delns_ifno_port:

            port_id = port['port']['id']
            self.plugin.delete_port(self.context, port_id)

            self.assertTrue(notify.call_count)
            dvr_delns_ifno_port.assert_called_once_with(self.context,
                                                        port['port']['id'])

    def test_delete_last_vm_port(self):
        self._test_delete_dvr_serviced_port(device_owner='compute:None')

    def test_delete_last_vm_port_with_floatingip(self):
        self._test_delete_dvr_serviced_port(device_owner='compute:None',
                                            floating_ip=True)

    def test_delete_lbaas_vip_port(self):
        self._test_delete_dvr_serviced_port(
            device_owner=constants.DEVICE_OWNER_LOADBALANCER)

    def test_concurrent_csnat_port_delete(self):
        plugin = manager.NeutronManager.get_service_plugins()[
            p_const.L3_ROUTER_NAT]
        r = plugin.create_router(
            self.context,
            {'router': {'name': 'router', 'admin_state_up': True}})
        with self.subnet() as s:
            p = plugin.add_router_interface(self.context, r['id'],
                                            {'subnet_id': s['subnet']['id']})

        # lie to turn the port into an SNAT interface
        with self.context.session.begin():
            rp = self.context.session.query(l3_db.RouterPort).filter_by(
                port_id=p['port_id']).first()
            rp.port_type = constants.DEVICE_OWNER_ROUTER_SNAT

        # take the port away before csnat gets a chance to delete it
        # to simulate a concurrent delete
        orig_get_ports = plugin._core_plugin.get_ports

        def get_ports_with_delete_first(*args, **kwargs):
            plugin._core_plugin.delete_port(self.context,
                                            p['port_id'],
                                            l3_port_check=False)
            return orig_get_ports(*args, **kwargs)
        plugin._core_plugin.get_ports = get_ports_with_delete_first

        # This should be able to handle a concurrent delete without raising
        # an exception
        router = plugin._get_router(self.context, r['id'])
        plugin.delete_csnat_router_interface_ports(self.context, router)


class TestMl2PortBinding(Ml2PluginV2TestCase,
                         test_bindings.PortBindingsTestCase):
    # Test case does not set binding:host_id, so ml2 does not attempt
    # to bind port
    VIF_TYPE = portbindings.VIF_TYPE_UNBOUND
    HAS_PORT_FILTER = False
    ENABLE_SG = True
    FIREWALL_DRIVER = test_sg_rpc.FIREWALL_HYBRID_DRIVER

    def setUp(self, firewall_driver=None):
        test_sg_rpc.set_firewall_driver(self.FIREWALL_DRIVER)
        config.cfg.CONF.set_override(
            'enable_security_group', self.ENABLE_SG,
            group='SECURITYGROUP')
        super(TestMl2PortBinding, self).setUp()

    def _check_port_binding_profile(self, port, profile=None):
        self.assertIn('id', port)
        self.assertIn(portbindings.PROFILE, port)
        value = port[portbindings.PROFILE]
        self.assertEqual(profile or {}, value)

    def test_create_port_binding_profile(self):
        self._test_create_port_binding_profile({'a': 1, 'b': 2})

    def test_update_port_binding_profile(self):
        self._test_update_port_binding_profile({'c': 3})

    def test_create_port_binding_profile_too_big(self):
        s = 'x' * 5000
        profile_arg = {portbindings.PROFILE: {'d': s}}
        try:
            with self.port(expected_res_status=400,
                           arg_list=(portbindings.PROFILE,),
                           **profile_arg):
                pass
        except webob.exc.HTTPClientError:
            pass

    def test_remove_port_binding_profile(self):
        profile = {'e': 5}
        profile_arg = {portbindings.PROFILE: profile}
        with self.port(arg_list=(portbindings.PROFILE,),
                       **profile_arg) as port:
            self._check_port_binding_profile(port['port'], profile)
            port_id = port['port']['id']
            profile_arg = {portbindings.PROFILE: None}
            port = self._update('ports', port_id,
                                {'port': profile_arg})['port']
            self._check_port_binding_profile(port)
            port = self._show('ports', port_id)['port']
            self._check_port_binding_profile(port)

    def test_return_on_concurrent_delete_and_binding(self):
        # create a port and delete it so we have an expired mechanism context
        with self.port() as port:
            plugin = manager.NeutronManager.get_plugin()
            binding = ml2_db.get_locked_port_and_binding(self.context.session,
                                                         port['port']['id'])[1]
            binding['host'] = 'test'
            mech_context = driver_context.PortContext(
                plugin, self.context, port['port'],
                plugin.get_network(self.context, port['port']['network_id']),
                binding, None)
        with mock.patch(
            'neutron.plugins.ml2.plugin.' 'db.get_locked_port_and_binding',
            return_value=(None, None)) as glpab_mock,\
                mock.patch('neutron.plugins.ml2.plugin.Ml2Plugin.'
                           '_make_port_dict') as mpd_mock:
            plugin._bind_port_if_needed(mech_context)
            # called during deletion to get port
            self.assertTrue(glpab_mock.mock_calls)
            # should have returned before calling _make_port_dict
            self.assertFalse(mpd_mock.mock_calls)

    def test_port_binding_profile_not_changed(self):
        profile = {'e': 5}
        profile_arg = {portbindings.PROFILE: profile}
        with self.port(arg_list=(portbindings.PROFILE,),
                       **profile_arg) as port:
            self._check_port_binding_profile(port['port'], profile)
            port_id = port['port']['id']
            state_arg = {'admin_state_up': True}
            port = self._update('ports', port_id,
                                {'port': state_arg})['port']
            self._check_port_binding_profile(port, profile)
            port = self._show('ports', port_id)['port']
            self._check_port_binding_profile(port, profile)

    def test_update_port_binding_host_id_none(self):
        with self.port() as port:
            plugin = manager.NeutronManager.get_plugin()
            binding = ml2_db.get_locked_port_and_binding(self.context.session,
                                                         port['port']['id'])[1]
            binding['host'] = 'test'
            mech_context = driver_context.PortContext(
                plugin, self.context, port['port'],
                plugin.get_network(self.context, port['port']['network_id']),
                binding, None)
        with mock.patch('neutron.plugins.ml2.plugin.Ml2Plugin.'
                        '_update_port_dict_binding') as update_mock:
            attrs = {portbindings.HOST_ID: None}
            plugin._process_port_binding(mech_context, attrs)
            self.assertTrue(update_mock.mock_calls)
            self.assertEqual('', binding.host)

    def test_update_port_binding_host_id_not_changed(self):
        with self.port() as port:
            plugin = manager.NeutronManager.get_plugin()
            binding = ml2_db.get_locked_port_and_binding(self.context.session,
                                                         port['port']['id'])[1]
            binding['host'] = 'test'
            mech_context = driver_context.PortContext(
                plugin, self.context, port['port'],
                plugin.get_network(self.context, port['port']['network_id']),
                binding, None)
        with mock.patch('neutron.plugins.ml2.plugin.Ml2Plugin.'
                        '_update_port_dict_binding') as update_mock:
            attrs = {portbindings.PROFILE: {'e': 5}}
            plugin._process_port_binding(mech_context, attrs)
            self.assertTrue(update_mock.mock_calls)
            self.assertEqual('test', binding.host)

    def test_process_dvr_port_binding_update_router_id(self):
        host_id = 'host'
        binding = models.DVRPortBinding(
                            port_id='port_id',
                            host=host_id,
                            router_id='old_router_id',
                            vif_type=portbindings.VIF_TYPE_OVS,
                            vnic_type=portbindings.VNIC_NORMAL,
                            status=constants.PORT_STATUS_DOWN)
        plugin = manager.NeutronManager.get_plugin()
        mock_network = {'id': 'net_id'}
        mock_port = {'id': 'port_id'}
        context = mock.Mock()
        new_router_id = 'new_router'
        attrs = {'device_id': new_router_id, portbindings.HOST_ID: host_id}
        with mock.patch.object(plugin, '_update_port_dict_binding'):
            with mock.patch.object(ml2_db, 'get_network_segments',
                                   return_value=[]):
                mech_context = driver_context.PortContext(
                    self, context, mock_port, mock_network, binding, None)
                plugin._process_dvr_port_binding(mech_context, context, attrs)
                self.assertEqual(new_router_id,
                                 mech_context._binding.router_id)
                self.assertEqual(host_id, mech_context._binding.host)

    def test_update_dvr_port_binding_on_non_existent_port(self):
        plugin = manager.NeutronManager.get_plugin()
        port = {
            'id': 'foo_port_id',
            'binding:host_id': 'foo_host',
        }
        with mock.patch.object(ml2_db, 'ensure_dvr_port_binding') as mock_dvr:
            plugin.update_dvr_port_binding(
                self.context, 'foo_port_id', {'port': port})
        self.assertFalse(mock_dvr.called)


class TestMl2PortBindingNoSG(TestMl2PortBinding):
    HAS_PORT_FILTER = False
    ENABLE_SG = False
    FIREWALL_DRIVER = test_sg_rpc.FIREWALL_NOOP_DRIVER


class TestMl2PortBindingHost(Ml2PluginV2TestCase,
                             test_bindings.PortBindingsHostTestCaseMixin):
    pass


class TestMl2PortBindingVnicType(Ml2PluginV2TestCase,
                                 test_bindings.PortBindingsVnicTestCaseMixin):
    pass


class TestMultiSegmentNetworks(Ml2PluginV2TestCase):

    def setUp(self, plugin=None):
        super(TestMultiSegmentNetworks, self).setUp()

    def test_allocate_dynamic_segment(self):
        data = {'network': {'name': 'net1',
                            'tenant_id': 'tenant_one'}}
        network_req = self.new_create_request('networks', data)
        network = self.deserialize(self.fmt,
                                   network_req.get_response(self.api))
        segment = {driver_api.NETWORK_TYPE: 'vlan',
                   driver_api.PHYSICAL_NETWORK: 'physnet1'}
        network_id = network['network']['id']
        self.driver.type_manager.allocate_dynamic_segment(
            self.context.session, network_id, segment)
        dynamic_segment = ml2_db.get_dynamic_segment(self.context.session,
                                                     network_id,
                                                     'physnet1')
        self.assertEqual('vlan', dynamic_segment[driver_api.NETWORK_TYPE])
        self.assertEqual('physnet1',
                         dynamic_segment[driver_api.PHYSICAL_NETWORK])
        self.assertTrue(dynamic_segment[driver_api.SEGMENTATION_ID] > 0)
        segment2 = {driver_api.NETWORK_TYPE: 'vlan',
                    driver_api.SEGMENTATION_ID: 1234,
                    driver_api.PHYSICAL_NETWORK: 'physnet3'}
        self.driver.type_manager.allocate_dynamic_segment(
            self.context.session, network_id, segment2)
        dynamic_segment = ml2_db.get_dynamic_segment(self.context.session,
                                                     network_id,
                                                     segmentation_id='1234')
        self.assertEqual('vlan', dynamic_segment[driver_api.NETWORK_TYPE])
        self.assertEqual('physnet3',
                         dynamic_segment[driver_api.PHYSICAL_NETWORK])
        self.assertEqual(dynamic_segment[driver_api.SEGMENTATION_ID], 1234)

    def test_allocate_dynamic_segment_multiple_physnets(self):
        data = {'network': {'name': 'net1',
                            'tenant_id': 'tenant_one'}}
        network_req = self.new_create_request('networks', data)
        network = self.deserialize(self.fmt,
                                   network_req.get_response(self.api))
        segment = {driver_api.NETWORK_TYPE: 'vlan',
                   driver_api.PHYSICAL_NETWORK: 'physnet1'}
        network_id = network['network']['id']
        self.driver.type_manager.allocate_dynamic_segment(
            self.context.session, network_id, segment)
        dynamic_segment = ml2_db.get_dynamic_segment(self.context.session,
                                                     network_id,
                                                     'physnet1')
        self.assertEqual('vlan', dynamic_segment[driver_api.NETWORK_TYPE])
        self.assertEqual('physnet1',
                         dynamic_segment[driver_api.PHYSICAL_NETWORK])
        dynamic_segmentation_id = dynamic_segment[driver_api.SEGMENTATION_ID]
        self.assertTrue(dynamic_segmentation_id > 0)
        dynamic_segment1 = ml2_db.get_dynamic_segment(self.context.session,
                                                      network_id,
                                                      'physnet1')
        dynamic_segment1_id = dynamic_segment1[driver_api.SEGMENTATION_ID]
        self.assertEqual(dynamic_segmentation_id, dynamic_segment1_id)
        segment2 = {driver_api.NETWORK_TYPE: 'vlan',
                    driver_api.PHYSICAL_NETWORK: 'physnet2'}
        self.driver.type_manager.allocate_dynamic_segment(
            self.context.session, network_id, segment2)
        dynamic_segment2 = ml2_db.get_dynamic_segment(self.context.session,
                                                      network_id,
                                                      'physnet2')
        dynamic_segmentation2_id = dynamic_segment2[driver_api.SEGMENTATION_ID]
        self.assertNotEqual(dynamic_segmentation_id, dynamic_segmentation2_id)

    def test_allocate_release_dynamic_segment(self):
        data = {'network': {'name': 'net1',
                            'tenant_id': 'tenant_one'}}
        network_req = self.new_create_request('networks', data)
        network = self.deserialize(self.fmt,
                                   network_req.get_response(self.api))
        segment = {driver_api.NETWORK_TYPE: 'vlan',
                   driver_api.PHYSICAL_NETWORK: 'physnet1'}
        network_id = network['network']['id']
        self.driver.type_manager.allocate_dynamic_segment(
            self.context.session, network_id, segment)
        dynamic_segment = ml2_db.get_dynamic_segment(self.context.session,
                                                     network_id,
                                                     'physnet1')
        self.assertEqual('vlan', dynamic_segment[driver_api.NETWORK_TYPE])
        self.assertEqual('physnet1',
                         dynamic_segment[driver_api.PHYSICAL_NETWORK])
        dynamic_segmentation_id = dynamic_segment[driver_api.SEGMENTATION_ID]
        self.assertTrue(dynamic_segmentation_id > 0)
        self.driver.type_manager.release_dynamic_segment(
            self.context.session, dynamic_segment[driver_api.ID])
        self.assertIsNone(ml2_db.get_dynamic_segment(
            self.context.session, network_id, 'physnet1'))

    def test_create_network_provider(self):
        data = {'network': {'name': 'net1',
                            pnet.NETWORK_TYPE: 'vlan',
                            pnet.PHYSICAL_NETWORK: 'physnet1',
                            pnet.SEGMENTATION_ID: 1,
                            'tenant_id': 'tenant_one'}}
        network_req = self.new_create_request('networks', data)
        network = self.deserialize(self.fmt,
                                   network_req.get_response(self.api))
        self.assertEqual('vlan', network['network'][pnet.NETWORK_TYPE])
        self.assertEqual('physnet1', network['network'][pnet.PHYSICAL_NETWORK])
        self.assertEqual(1, network['network'][pnet.SEGMENTATION_ID])
        self.assertNotIn(mpnet.SEGMENTS, network['network'])

    def test_create_network_single_multiprovider(self):
        data = {'network': {'name': 'net1',
                            mpnet.SEGMENTS:
                            [{pnet.NETWORK_TYPE: 'vlan',
                              pnet.PHYSICAL_NETWORK: 'physnet1',
                              pnet.SEGMENTATION_ID: 1}],
                            'tenant_id': 'tenant_one'}}
        net_req = self.new_create_request('networks', data)
        network = self.deserialize(self.fmt, net_req.get_response(self.api))
        self.assertEqual('vlan', network['network'][pnet.NETWORK_TYPE])
        self.assertEqual('physnet1', network['network'][pnet.PHYSICAL_NETWORK])
        self.assertEqual(1, network['network'][pnet.SEGMENTATION_ID])
        self.assertNotIn(mpnet.SEGMENTS, network['network'])

        # Tests get_network()
        net_req = self.new_show_request('networks', network['network']['id'])
        network = self.deserialize(self.fmt, net_req.get_response(self.api))
        self.assertEqual('vlan', network['network'][pnet.NETWORK_TYPE])
        self.assertEqual('physnet1', network['network'][pnet.PHYSICAL_NETWORK])
        self.assertEqual(1, network['network'][pnet.SEGMENTATION_ID])
        self.assertNotIn(mpnet.SEGMENTS, network['network'])

    def test_create_network_multiprovider(self):
        data = {'network': {'name': 'net1',
                            mpnet.SEGMENTS:
                            [{pnet.NETWORK_TYPE: 'vlan',
                              pnet.PHYSICAL_NETWORK: 'physnet1',
                              pnet.SEGMENTATION_ID: 1},
                             {pnet.NETWORK_TYPE: 'vlan',
                              pnet.PHYSICAL_NETWORK: 'physnet1',
                              pnet.SEGMENTATION_ID: 2}],
                            'tenant_id': 'tenant_one'}}
        network_req = self.new_create_request('networks', data)
        network = self.deserialize(self.fmt,
                                   network_req.get_response(self.api))
        segments = network['network'][mpnet.SEGMENTS]
        for segment_index, segment in enumerate(data['network']
                                                [mpnet.SEGMENTS]):
            for field in [pnet.NETWORK_TYPE, pnet.PHYSICAL_NETWORK,
                          pnet.SEGMENTATION_ID]:
                self.assertEqual(segment.get(field),
                            segments[segment_index][field])

        # Tests get_network()
        net_req = self.new_show_request('networks', network['network']['id'])
        network = self.deserialize(self.fmt, net_req.get_response(self.api))
        segments = network['network'][mpnet.SEGMENTS]
        for segment_index, segment in enumerate(data['network']
                                                [mpnet.SEGMENTS]):
            for field in [pnet.NETWORK_TYPE, pnet.PHYSICAL_NETWORK,
                          pnet.SEGMENTATION_ID]:
                self.assertEqual(segment.get(field),
                            segments[segment_index][field])

    def test_create_network_with_provider_and_multiprovider_fail(self):
        data = {'network': {'name': 'net1',
                            mpnet.SEGMENTS:
                            [{pnet.NETWORK_TYPE: 'vlan',
                              pnet.PHYSICAL_NETWORK: 'physnet1',
                              pnet.SEGMENTATION_ID: 1}],
                            pnet.NETWORK_TYPE: 'vlan',
                            pnet.PHYSICAL_NETWORK: 'physnet1',
                            pnet.SEGMENTATION_ID: 1,
                            'tenant_id': 'tenant_one'}}

        network_req = self.new_create_request('networks', data)
        res = network_req.get_response(self.api)
        self.assertEqual(400, res.status_int)

    def test_create_network_duplicate_full_segments(self):
        data = {'network': {'name': 'net1',
                            mpnet.SEGMENTS:
                            [{pnet.NETWORK_TYPE: 'vlan',
                              pnet.PHYSICAL_NETWORK: 'physnet1',
                              pnet.SEGMENTATION_ID: 1},
                             {pnet.NETWORK_TYPE: 'vlan',
                              pnet.PHYSICAL_NETWORK: 'physnet1',
                              pnet.SEGMENTATION_ID: 1}],
                            'tenant_id': 'tenant_one'}}
        network_req = self.new_create_request('networks', data)
        res = network_req.get_response(self.api)
        self.assertEqual(400, res.status_int)

    def test_create_network_duplicate_partial_segments(self):
        data = {'network': {'name': 'net1',
                            mpnet.SEGMENTS:
                            [{pnet.NETWORK_TYPE: 'vlan',
                              pnet.PHYSICAL_NETWORK: 'physnet1'},
                             {pnet.NETWORK_TYPE: 'vlan',
                              pnet.PHYSICAL_NETWORK: 'physnet1'}],
                            'tenant_id': 'tenant_one'}}
        network_req = self.new_create_request('networks', data)
        res = network_req.get_response(self.api)
        self.assertEqual(201, res.status_int)

    def test_release_network_segments(self):
        data = {'network': {'name': 'net1',
                            'admin_state_up': True,
                            'shared': False,
                            pnet.NETWORK_TYPE: 'vlan',
                            pnet.PHYSICAL_NETWORK: 'physnet1',
                            pnet.SEGMENTATION_ID: 1,
                            'tenant_id': 'tenant_one'}}
        network_req = self.new_create_request('networks', data)
        res = network_req.get_response(self.api)
        network = self.deserialize(self.fmt, res)
        network_id = network['network']['id']
        segment = {driver_api.NETWORK_TYPE: 'vlan',
                   driver_api.PHYSICAL_NETWORK: 'physnet2'}
        self.driver.type_manager.allocate_dynamic_segment(
            self.context.session, network_id, segment)
        dynamic_segment = ml2_db.get_dynamic_segment(self.context.session,
                                                     network_id,
                                                     'physnet2')
        self.assertEqual('vlan', dynamic_segment[driver_api.NETWORK_TYPE])
        self.assertEqual('physnet2',
                         dynamic_segment[driver_api.PHYSICAL_NETWORK])
        self.assertTrue(dynamic_segment[driver_api.SEGMENTATION_ID] > 0)

        with mock.patch.object(type_vlan.VlanTypeDriver,
                               'release_segment') as rs:
            req = self.new_delete_request('networks', network_id)
            res = req.get_response(self.api)
            self.assertEqual(2, rs.call_count)
        self.assertEqual(ml2_db.get_network_segments(
            self.context.session, network_id), [])
        self.assertIsNone(ml2_db.get_dynamic_segment(
            self.context.session, network_id, 'physnet2'))

    def test_release_segment_no_type_driver(self):
        data = {'network': {'name': 'net1',
                            'admin_state_up': True,
                            'shared': False,
                            pnet.NETWORK_TYPE: 'vlan',
                            pnet.PHYSICAL_NETWORK: 'physnet1',
                            pnet.SEGMENTATION_ID: 1,
                            'tenant_id': 'tenant_one'}}
        network_req = self.new_create_request('networks', data)
        res = network_req.get_response(self.api)
        network = self.deserialize(self.fmt, res)
        network_id = network['network']['id']

        segment = {driver_api.NETWORK_TYPE: 'faketype',
                   driver_api.PHYSICAL_NETWORK: 'physnet1',
                   driver_api.ID: 1}
        with mock.patch('neutron.plugins.ml2.managers.LOG') as log:
            with mock.patch('neutron.plugins.ml2.managers.db') as db:
                db.get_network_segments.return_value = (segment,)
                self.driver.type_manager.release_network_segments(
                    self.context.session, network_id)

                log.error.assert_called_once_with(
                    "Failed to release segment '%s' because "
                    "network type is not supported.", segment)

    def test_create_provider_fail(self):
        segment = {pnet.NETWORK_TYPE: None,
                   pnet.PHYSICAL_NETWORK: 'phys_net',
                   pnet.SEGMENTATION_ID: None}
        with testtools.ExpectedException(exc.InvalidInput):
            self.driver.type_manager._process_provider_create(segment)

    def test_create_network_plugin(self):
        data = {'network': {'name': 'net1',
                            'admin_state_up': True,
                            'shared': False,
                            pnet.NETWORK_TYPE: 'vlan',
                            pnet.PHYSICAL_NETWORK: 'physnet1',
                            pnet.SEGMENTATION_ID: 1,
                            'tenant_id': 'tenant_one'}}

        def raise_mechanism_exc(*args, **kwargs):
            raise ml2_exc.MechanismDriverError(
                method='create_network_postcommit')

        with mock.patch('neutron.plugins.ml2.managers.MechanismManager.'
                        'create_network_precommit', new=raise_mechanism_exc):
            with testtools.ExpectedException(ml2_exc.MechanismDriverError):
                self.driver.create_network(self.context, data)

    def test_extend_dictionary_no_segments(self):
        network = dict(name='net_no_segment', id='5', tenant_id='tenant_one')
        self.driver.type_manager.extend_network_dict_provider(self.context,
                                                              network)
        self.assertIsNone(network[pnet.NETWORK_TYPE])
        self.assertIsNone(network[pnet.PHYSICAL_NETWORK])
        self.assertIsNone(network[pnet.SEGMENTATION_ID])


class TestMl2AllowedAddressPairs(Ml2PluginV2TestCase,
                                 test_pair.TestAllowedAddressPairs):
    _extension_drivers = ['port_security']

    def setUp(self, plugin=None):
        config.cfg.CONF.set_override('extension_drivers',
                                     self._extension_drivers,
                                     group='ml2')
        super(test_pair.TestAllowedAddressPairs, self).setUp(
            plugin=PLUGIN_NAME)


class DHCPOptsTestCase(test_dhcpopts.TestExtraDhcpOpt):

    def setUp(self, plugin=None):
        super(test_dhcpopts.ExtraDhcpOptDBTestCase, self).setUp(
            plugin=PLUGIN_NAME)


class Ml2PluginV2FaultyDriverTestCase(test_plugin.NeutronDbPluginV2TestCase):

    def setUp(self):
        # Enable the test mechanism driver to ensure that
        # we can successfully call through to all mechanism
        # driver apis.
        config.cfg.CONF.set_override('mechanism_drivers',
                                     ['test', 'logger'],
                                     group='ml2')
        super(Ml2PluginV2FaultyDriverTestCase, self).setUp(PLUGIN_NAME)
        self.port_create_status = 'DOWN'


class TestFaultyMechansimDriver(Ml2PluginV2FaultyDriverTestCase):

    def test_create_network_faulty(self):

        with mock.patch.object(mech_test.TestMechanismDriver,
                               'create_network_postcommit',
                               side_effect=ml2_exc.MechanismDriverError):
            tenant_id = str(uuid.uuid4())
            data = {'network': {'name': 'net1',
                                'tenant_id': tenant_id}}
            req = self.new_create_request('networks', data)
            res = req.get_response(self.api)
            self.assertEqual(500, res.status_int)
            error = self.deserialize(self.fmt, res)
            self.assertEqual('MechanismDriverError',
                             error['NeutronError']['type'])
            query_params = "tenant_id=%s" % tenant_id
            nets = self._list('networks', query_params=query_params)
            self.assertFalse(nets['networks'])

    def test_delete_network_faulty(self):

        with mock.patch.object(mech_test.TestMechanismDriver,
                               'delete_network_postcommit',
                               side_effect=ml2_exc.MechanismDriverError):
            with mock.patch.object(mech_logger.LoggerMechanismDriver,
                                   'delete_network_postcommit') as dnp:

                data = {'network': {'name': 'net1',
                                    'tenant_id': 'tenant_one'}}
                network_req = self.new_create_request('networks', data)
                network_res = network_req.get_response(self.api)
                self.assertEqual(201, network_res.status_int)
                network = self.deserialize(self.fmt, network_res)
                net_id = network['network']['id']
                req = self.new_delete_request('networks', net_id)
                res = req.get_response(self.api)
                self.assertEqual(204, res.status_int)
                # Test if other mechanism driver was called
                self.assertTrue(dnp.called)
                self._show('networks', net_id,
                           expected_code=webob.exc.HTTPNotFound.code)

    def test_update_network_faulty(self):

        with mock.patch.object(mech_test.TestMechanismDriver,
                               'update_network_postcommit',
                               side_effect=ml2_exc.MechanismDriverError):
            with mock.patch.object(mech_logger.LoggerMechanismDriver,
                                   'update_network_postcommit') as unp:

                data = {'network': {'name': 'net1',
                                    'tenant_id': 'tenant_one'}}
                network_req = self.new_create_request('networks', data)
                network_res = network_req.get_response(self.api)
                self.assertEqual(201, network_res.status_int)
                network = self.deserialize(self.fmt, network_res)
                net_id = network['network']['id']

                new_name = 'a_brand_new_name'
                data = {'network': {'name': new_name}}
                req = self.new_update_request('networks', data, net_id)
                res = req.get_response(self.api)
                self.assertEqual(500, res.status_int)
                error = self.deserialize(self.fmt, res)
                self.assertEqual('MechanismDriverError',
                                 error['NeutronError']['type'])
                # Test if other mechanism driver was called
                self.assertTrue(unp.called)
                net = self._show('networks', net_id)
                self.assertEqual(new_name, net['network']['name'])

                self._delete('networks', net_id)

    def test_create_subnet_faulty(self):

        with mock.patch.object(mech_test.TestMechanismDriver,
                               'create_subnet_postcommit',
                               side_effect=ml2_exc.MechanismDriverError):

            with self.network() as network:
                net_id = network['network']['id']
                data = {'subnet': {'network_id': net_id,
                                   'cidr': '10.0.20.0/24',
                                   'ip_version': '4',
                                   'name': 'subnet1',
                                   'tenant_id':
                                   network['network']['tenant_id'],
                                   'gateway_ip': '10.0.20.1'}}
                req = self.new_create_request('subnets', data)
                res = req.get_response(self.api)
                self.assertEqual(500, res.status_int)
                error = self.deserialize(self.fmt, res)
                self.assertEqual('MechanismDriverError',
                                 error['NeutronError']['type'])
                query_params = "network_id=%s" % net_id
                subnets = self._list('subnets', query_params=query_params)
                self.assertFalse(subnets['subnets'])

    def test_delete_subnet_faulty(self):

        with mock.patch.object(mech_test.TestMechanismDriver,
                               'delete_subnet_postcommit',
                               side_effect=ml2_exc.MechanismDriverError):
            with mock.patch.object(mech_logger.LoggerMechanismDriver,
                                   'delete_subnet_postcommit') as dsp:

                with self.network() as network:
                    data = {'subnet': {'network_id':
                                       network['network']['id'],
                                       'cidr': '10.0.20.0/24',
                                       'ip_version': '4',
                                       'name': 'subnet1',
                                       'tenant_id':
                                       network['network']['tenant_id'],
                                       'gateway_ip': '10.0.20.1'}}
                    subnet_req = self.new_create_request('subnets', data)
                    subnet_res = subnet_req.get_response(self.api)
                    self.assertEqual(201, subnet_res.status_int)
                    subnet = self.deserialize(self.fmt, subnet_res)
                    subnet_id = subnet['subnet']['id']

                    req = self.new_delete_request('subnets', subnet_id)
                    res = req.get_response(self.api)
                    self.assertEqual(204, res.status_int)
                    # Test if other mechanism driver was called
                    self.assertTrue(dsp.called)
                    self._show('subnets', subnet_id,
                               expected_code=webob.exc.HTTPNotFound.code)

    def test_update_subnet_faulty(self):

        with mock.patch.object(mech_test.TestMechanismDriver,
                               'update_subnet_postcommit',
                               side_effect=ml2_exc.MechanismDriverError):
            with mock.patch.object(mech_logger.LoggerMechanismDriver,
                                   'update_subnet_postcommit') as usp:

                with self.network() as network:
                    data = {'subnet': {'network_id':
                                       network['network']['id'],
                                       'cidr': '10.0.20.0/24',
                                       'ip_version': '4',
                                       'name': 'subnet1',
                                       'tenant_id':
                                       network['network']['tenant_id'],
                                       'gateway_ip': '10.0.20.1'}}
                    subnet_req = self.new_create_request('subnets', data)
                    subnet_res = subnet_req.get_response(self.api)
                    self.assertEqual(201, subnet_res.status_int)
                    subnet = self.deserialize(self.fmt, subnet_res)
                    subnet_id = subnet['subnet']['id']
                    new_name = 'a_brand_new_name'
                    data = {'subnet': {'name': new_name}}
                    req = self.new_update_request('subnets', data, subnet_id)
                    res = req.get_response(self.api)
                    self.assertEqual(500, res.status_int)
                    error = self.deserialize(self.fmt, res)
                    self.assertEqual('MechanismDriverError',
                                     error['NeutronError']['type'])
                    # Test if other mechanism driver was called
                    self.assertTrue(usp.called)
                    subnet = self._show('subnets', subnet_id)
                    self.assertEqual(new_name, subnet['subnet']['name'])

                    self._delete('subnets', subnet['subnet']['id'])

    def test_create_port_faulty(self):

        with mock.patch.object(mech_test.TestMechanismDriver,
                               'create_port_postcommit',
                               side_effect=ml2_exc.MechanismDriverError):

            with self.network() as network:
                net_id = network['network']['id']
                data = {'port': {'network_id': net_id,
                                 'tenant_id':
                                 network['network']['tenant_id'],
                                 'name': 'port1',
                                 'admin_state_up': 1,
                                 'fixed_ips': []}}
                req = self.new_create_request('ports', data)
                res = req.get_response(self.api)
                self.assertEqual(500, res.status_int)
                error = self.deserialize(self.fmt, res)
                self.assertEqual('MechanismDriverError',
                                 error['NeutronError']['type'])
                query_params = "network_id=%s" % net_id
                ports = self._list('ports', query_params=query_params)
                self.assertFalse(ports['ports'])

    def test_update_port_faulty(self):

        with mock.patch.object(mech_test.TestMechanismDriver,
                               'update_port_postcommit',
                               side_effect=ml2_exc.MechanismDriverError):
            with mock.patch.object(mech_logger.LoggerMechanismDriver,
                                   'update_port_postcommit') as upp:

                with self.network() as network:
                    data = {'port': {'network_id': network['network']['id'],
                                     'tenant_id':
                                     network['network']['tenant_id'],
                                     'name': 'port1',
                                     'admin_state_up': 1,
                                     'fixed_ips': []}}
                    port_req = self.new_create_request('ports', data)
                    port_res = port_req.get_response(self.api)
                    self.assertEqual(201, port_res.status_int)
                    port = self.deserialize(self.fmt, port_res)
                    port_id = port['port']['id']

                    new_name = 'a_brand_new_name'
                    data = {'port': {'name': new_name}}
                    req = self.new_update_request('ports', data, port_id)
                    res = req.get_response(self.api)
                    self.assertEqual(200, res.status_int)
                    # Test if other mechanism driver was called
                    self.assertTrue(upp.called)
                    port = self._show('ports', port_id)
                    self.assertEqual(new_name, port['port']['name'])

                    self._delete('ports', port['port']['id'])

    def test_update_dvr_router_interface_port(self):
        """Test validate dvr router interface update succeeds."""
        host_id = 'host'
        binding = models.DVRPortBinding(
                            port_id='port_id',
                            host=host_id,
                            router_id='old_router_id',
                            vif_type=portbindings.VIF_TYPE_OVS,
                            vnic_type=portbindings.VNIC_NORMAL,
                            status=constants.PORT_STATUS_DOWN)
        with mock.patch.object(
            mech_test.TestMechanismDriver,
            'update_port_postcommit',
            side_effect=ml2_exc.MechanismDriverError) as port_post,\
                mock.patch.object(
                    mech_test.TestMechanismDriver,
                    'update_port_precommit') as port_pre,\
                mock.patch.object(ml2_db,
                                  'get_dvr_port_bindings') as dvr_bindings:
                dvr_bindings.return_value = [binding]
                port_pre.return_value = True
                with self.network() as network:
                    with self.subnet(network=network) as subnet:
                        subnet_id = subnet['subnet']['id']
                        data = {'port': {
                            'network_id': network['network']['id'],
                            'tenant_id':
                            network['network']['tenant_id'],
                            'name': 'port1',
                            'device_owner':
                            'network:router_interface_distributed',
                            'admin_state_up': 1,
                            'fixed_ips':
                            [{'subnet_id': subnet_id}]}}
                        port_req = self.new_create_request('ports', data)
                        port_res = port_req.get_response(self.api)
                        self.assertEqual(201, port_res.status_int)
                        port = self.deserialize(self.fmt, port_res)
                        port_id = port['port']['id']
                        new_name = 'a_brand_new_name'
                        data = {'port': {'name': new_name}}
                        req = self.new_update_request('ports', data, port_id)
                        res = req.get_response(self.api)
                        self.assertEqual(200, res.status_int)
                        self.assertTrue(dvr_bindings.called)
                        self.assertTrue(port_pre.called)
                        self.assertTrue(port_post.called)
                        port = self._show('ports', port_id)
                        self.assertEqual(new_name, port['port']['name'])


class TestMl2PluginCreateUpdateDeletePort(base.BaseTestCase):
    def setUp(self):
        super(TestMl2PluginCreateUpdateDeletePort, self).setUp()
        self.context = mock.MagicMock()
        self.notify_p = mock.patch('neutron.callbacks.registry.notify')
        self.notify = self.notify_p.start()

    def _ensure_transaction_is_closed(self):
        transaction = self.context.session.begin(subtransactions=True)
        enter = transaction.__enter__.call_count
        exit = transaction.__exit__.call_count
        self.assertEqual(enter, exit)

    def _create_plugin_for_create_update_port(self, new_host_port):
        plugin = ml2_plugin.Ml2Plugin()
        plugin.extension_manager = mock.Mock()
        plugin.type_manager = mock.Mock()
        plugin.mechanism_manager = mock.Mock()
        plugin.notifier = mock.Mock()
        plugin._get_host_port_if_changed = mock.Mock(
            return_value=new_host_port)
        plugin._check_mac_update_allowed = mock.Mock(return_value=True)

        self.notify.side_effect = (
            lambda r, e, t, **kwargs: self._ensure_transaction_is_closed())

        return plugin

    def test_create_port_rpc_outside_transaction(self):
        with mock.patch.object(ml2_plugin.Ml2Plugin, '__init__') as init,\
                mock.patch.object(base_plugin.NeutronDbPluginV2,
                                  'create_port'):
            init.return_value = None

            new_host_port = mock.Mock()
            plugin = self._create_plugin_for_create_update_port(new_host_port)

            plugin.create_port(self.context, mock.MagicMock())

            kwargs = {'context': self.context, 'port': new_host_port}
            self.notify.assert_called_once_with('port', 'after_create',
                plugin, **kwargs)

    def test_update_port_rpc_outside_transaction(self):
        with mock.patch.object(ml2_plugin.Ml2Plugin, '__init__') as init,\
                mock.patch.object(base_plugin.NeutronDbPluginV2,
                                  'update_port'):
            init.return_value = None
            new_host_port = mock.Mock()
            plugin = self._create_plugin_for_create_update_port(new_host_port)

            plugin.update_port(self.context, 'fake_id', mock.MagicMock())

            kwargs = {
                'context': self.context,
                'port': new_host_port,
                'mac_address_updated': True,
            }
            self.notify.assert_called_once_with('port', 'after_update',
                plugin, **kwargs)

    def test_notify_outside_of_delete_transaction(self):
        self.notify.side_effect = (
            lambda r, e, t, **kwargs: self._ensure_transaction_is_closed())
        l3plugin = mock.Mock()
        l3plugin.supported_extension_aliases = [
            'router', constants.L3_AGENT_SCHEDULER_EXT_ALIAS,
            constants.L3_DISTRIBUTED_EXT_ALIAS
        ]
        with mock.patch.object(ml2_plugin.Ml2Plugin,
                               '__init__',
                               return_value=None),\
                mock.patch.object(manager.NeutronManager,
                                  'get_service_plugins',
                                  return_value={'L3_ROUTER_NAT': l3plugin}):
            plugin = self._create_plugin_for_create_update_port(mock.Mock())
            # Set backend manually here since __init__ was mocked
            plugin.set_ipam_backend()
            # deleting the port will call registry.notify, which will
            # run the transaction balancing function defined in this test
            plugin.delete_port(self.context, 'fake_id')
            self.assertTrue(self.notify.call_count)
