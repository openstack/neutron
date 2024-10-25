# Copyright (c) 2014 OpenStack Foundation, all rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import re
from unittest import mock
import warnings

import netaddr
from neutron_lib.api.definitions import portbindings
from neutron_lib import constants
from neutron_lib import context
from neutron_lib.db import api as db_api
from neutron_lib.plugins import directory
from neutron_lib.plugins.ml2 import api
from oslo_utils import uuidutils
from sqlalchemy.orm import exc
from sqlalchemy.orm import query

from neutron.db import db_base_plugin_v2
from neutron.db.models import l3 as l3_models
from neutron.db import segments_db
from neutron.objects import network as network_obj
from neutron.objects import ports as port_obj
from neutron.plugins.ml2 import db as ml2_db
from neutron.plugins.ml2 import models
from neutron.services.segments import exceptions as seg_exc
from neutron.tests.unit import testlib_api


PLUGIN_NAME = 'ml2'


class Ml2DBTestCase(testlib_api.SqlTestCase):

    def setUp(self):
        super().setUp()
        self.ctx = context.get_admin_context()
        self.setup_coreplugin(PLUGIN_NAME)

    def _setup_neutron_network(self, network_id):
        network_obj.Network(self.ctx, id=network_id).create()

    def _setup_neutron_port(self, network_id, port_id):
        mac_address = db_base_plugin_v2.NeutronDbPluginV2._generate_macs()[0]
        port = port_obj.Port(self.ctx,
                             id=port_id,
                             network_id=network_id,
                             mac_address=netaddr.EUI(mac_address),
                             admin_state_up=True,
                             status='DOWN',
                             device_id='',
                             device_owner='')
        port.create()
        return port

    def _setup_neutron_portbinding(self, port_id, vif_type, host,
                                   status=constants.ACTIVE):
        with db_api.CONTEXT_WRITER.using(self.ctx):
            self.ctx.session.add(models.PortBinding(port_id=port_id,
                                                    vif_type=vif_type,
                                                    host=host,
                                                    status=status))

    @staticmethod
    def _sort_segments(segments):
        return sorted(segments, key=lambda d: d['segmentation_id'])

    def _create_segments(self, segments, is_seg_dynamic=False,
                         network_id=uuidutils.generate_uuid()):
        self._setup_neutron_network(network_id)
        for segment in segments:
            segments_db.add_network_segment(
                self.ctx, network_id, segment,
                is_dynamic=is_seg_dynamic)
            segment['network_id'] = network_id

        net_segments = segments_db.get_network_segments(
                           self.ctx, network_id,
                           filter_dynamic=is_seg_dynamic)
        net_segments = self._sort_segments(net_segments)

        for segment_index, segment in enumerate(segments):
            self.assertEqual(segment, net_segments[segment_index])

        return net_segments

    def test_network_segments_for_provider_network(self):
        segment = {api.NETWORK_TYPE: 'vlan',
                   api.PHYSICAL_NETWORK: 'physnet1',
                   api.SEGMENTATION_ID: 1}
        self._create_segments([segment])

    def test_network_segments_is_dynamic_true(self):
        segment = {api.NETWORK_TYPE: 'vlan',
                   api.PHYSICAL_NETWORK: 'physnet1',
                   api.SEGMENTATION_ID: 1}
        self._create_segments([segment], is_seg_dynamic=True)

    def test_network_segments_for_multiprovider_network(self):
        segments = [{api.NETWORK_TYPE: 'vlan',
                    api.PHYSICAL_NETWORK: 'physnet1',
                    api.SEGMENTATION_ID: 1},
                    {api.NETWORK_TYPE: 'vlan',
                     api.PHYSICAL_NETWORK: 'physnet2',
                     api.SEGMENTATION_ID: 2}]
        self._create_segments(segments)

    def test_get_networks_segments(self):
        net_id1 = uuidutils.generate_uuid()
        net_id2 = uuidutils.generate_uuid()
        segments1 = [{api.NETWORK_TYPE: 'vlan',
                      api.PHYSICAL_NETWORK: 'physnet1',
                      api.SEGMENTATION_ID: 1},
                     {api.NETWORK_TYPE: 'vlan',
                      api.PHYSICAL_NETWORK: 'physnet2',
                      api.SEGMENTATION_ID: 2}]
        segments2 = [{api.NETWORK_TYPE: 'vlan',
                      api.PHYSICAL_NETWORK: 'physnet1',
                      api.SEGMENTATION_ID: 3},
                     {api.NETWORK_TYPE: 'vlan',
                      api.PHYSICAL_NETWORK: 'physnet2',
                      api.SEGMENTATION_ID: 4}]
        net1segs = self._create_segments(segments1, network_id=net_id1)
        net2segs = self._create_segments(segments2, network_id=net_id2)
        segs = segments_db.get_networks_segments(
            self.ctx, [net_id1, net_id2])
        self.assertEqual(net1segs, self._sort_segments(segs[net_id1]))
        self.assertEqual(net2segs, self._sort_segments(segs[net_id2]))

    def test_get_networks_segments_no_segments(self):
        net_id1 = uuidutils.generate_uuid()
        net_id2 = uuidutils.generate_uuid()
        self._create_segments([], network_id=net_id1)
        self._create_segments([], network_id=net_id2)
        segs = segments_db.get_networks_segments(
            self.ctx, [net_id1, net_id2])
        self.assertEqual([], segs[net_id1])
        self.assertEqual([], segs[net_id2])

    def test_get_segment_by_id(self):
        segment = {api.NETWORK_TYPE: 'vlan',
                   api.PHYSICAL_NETWORK: 'physnet1',
                   api.SEGMENTATION_ID: 1}

        net_segment = self._create_segments([segment])[0]
        segment_uuid = net_segment[api.ID]

        net_segment = segments_db.get_segment_by_id(self.ctx,
                                                    segment_uuid)
        self.assertEqual(segment, net_segment)

    def test_get_segment_by_id_result_not_found(self):
        segment_uuid = uuidutils.generate_uuid()
        net_segment = segments_db.get_segment_by_id(self.ctx,
                                                    segment_uuid)
        self.assertIsNone(net_segment)

    def test_delete_network_segment(self):
        segment = {api.NETWORK_TYPE: 'vlan',
                   api.PHYSICAL_NETWORK: 'physnet1',
                   api.SEGMENTATION_ID: 1}

        net_segment = self._create_segments([segment])[0]
        segment_uuid = net_segment[api.ID]

        segments_db.delete_network_segment(self.ctx, segment_uuid)
        # Get segment and verify its empty
        net_segment = segments_db.get_segment_by_id(self.ctx,
                                                    segment_uuid)
        self.assertIsNone(net_segment)

    def test_get_dynamic_segment(self):
        net_id = uuidutils.generate_uuid()
        segment1 = {api.NETWORK_TYPE: 'vlan',
                    api.PHYSICAL_NETWORK: 'physnet1',
                    api.SEGMENTATION_ID: 1}

        self._create_segments(
            [segment1], is_seg_dynamic=True, network_id=net_id)

        segs1 = segments_db.get_dynamic_segment(
            self.ctx, net_id)
        self.assertEqual('vlan', segs1[api.NETWORK_TYPE])
        self.assertEqual('physnet1', segs1[api.PHYSICAL_NETWORK])
        self.assertEqual(1, segs1[api.SEGMENTATION_ID])

        segs2 = segments_db.get_dynamic_segment(
            self.ctx, net_id, physical_network='physnet1')
        self.assertEqual('vlan', segs2[api.NETWORK_TYPE])
        self.assertEqual('physnet1', segs2[api.PHYSICAL_NETWORK])
        self.assertEqual(1, segs2[api.SEGMENTATION_ID])

        segs3 = segments_db.get_dynamic_segment(
            self.ctx, net_id, segmentation_id=1)
        self.assertEqual('vlan', segs3[api.NETWORK_TYPE])
        self.assertEqual('physnet1', segs3[api.PHYSICAL_NETWORK])
        self.assertEqual(1, segs3[api.SEGMENTATION_ID])

    def test_add_port_binding(self):
        network_id = uuidutils.generate_uuid()
        port_id = uuidutils.generate_uuid()
        self._setup_neutron_network(network_id)
        self._setup_neutron_port(network_id, port_id)

        port = ml2_db.add_port_binding(self.ctx, port_id)
        self.assertEqual(port_id, port.port_id)
        self.assertEqual(portbindings.VIF_TYPE_UNBOUND, port.vif_type)

    def test_get_port_binding_host(self):
        network_id = uuidutils.generate_uuid()
        port_id = uuidutils.generate_uuid()
        host = 'fake_host'
        other_host = 'other_fake_host'
        vif_type = portbindings.VIF_TYPE_UNBOUND
        self._setup_neutron_network(network_id)
        self._setup_neutron_port(network_id, port_id)
        self._setup_neutron_portbinding(port_id, vif_type, host)
        self._setup_neutron_portbinding(port_id, vif_type, other_host,
                                        status=constants.INACTIVE)

        port_host = ml2_db.get_port_binding_host(self.ctx, port_id)
        self.assertEqual(host, port_host)

    def test_get_port_binding_host_multiple_results_found(self):
        network_id = uuidutils.generate_uuid()
        port_id = uuidutils.generate_uuid()
        port_id_one = uuidutils.generate_uuid()
        port_id_two = uuidutils.generate_uuid()
        # NOTE(manjeets) to check startswith testcase we
        # need port ids with same prefix
        port_id_one = port_id[:8] + port_id_one[8:]
        port_id_two = port_id[:8] + port_id_two[8:]
        host = 'fake_host'
        vif_type = portbindings.VIF_TYPE_UNBOUND
        self._setup_neutron_network(network_id)
        self._setup_neutron_port(network_id, port_id_one)
        self._setup_neutron_portbinding(port_id_one, vif_type, host)
        self._setup_neutron_port(network_id, port_id_two)
        self._setup_neutron_portbinding(port_id_two, vif_type, host)

        port_host = ml2_db.get_port_binding_host(self.ctx, port_id[:8])
        self.assertIsNone(port_host)

    def test_get_port_binding_host_result_not_found(self):
        port_id = uuidutils.generate_uuid()

        port_host = ml2_db.get_port_binding_host(self.ctx, port_id)
        self.assertIsNone(port_host)

    def test_get_port(self):
        network_id = uuidutils.generate_uuid()
        port_id = uuidutils.generate_uuid()
        self._setup_neutron_network(network_id)
        self._setup_neutron_port(network_id, port_id)

        port = ml2_db.get_port(self.ctx, port_id)
        self.assertEqual(port_id, port.id)

    def test_get_port_multiple_results_found(self):
        with mock.patch(
                'sqlalchemy.orm.query.Query.one',
                side_effect=exc.MultipleResultsFound):
            port = ml2_db.get_port(self.ctx, 'unused')
        self.assertIsNone(port)

    def test_get_port_result_not_found(self):
        port_id = uuidutils.generate_uuid()
        port = ml2_db.get_port(self.ctx, port_id)
        self.assertIsNone(port)

    def test_generating_multiple_mac_addresses(self):
        mac_regex = "^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$"

        macs = db_base_plugin_v2.NeutronDbPluginV2._generate_macs()
        self.assertEqual(1, len(macs))
        self.assertIsNotNone(re.search(mac_regex, macs[0]))

        macs = db_base_plugin_v2.NeutronDbPluginV2._generate_macs(5)
        self.assertEqual(5, len(macs))
        for mac in macs:
            self.assertIsNotNone(re.search(mac_regex, mac))

    def test__prevent_segment_delete_with_port_bound_raise(self):
        payload_mock = mock.Mock()
        payload_mock.metadata.get.return_value = False
        payload_mock.context = self.ctx
        with mock.patch.object(
                 port_obj.Port,
                 'get_auto_deletable_port_ids_and_proper_port_count_by_segment'
             ) as mock_get:
            mock_get.return_value = ([], 1)
            self.assertRaises(
                seg_exc.SegmentInUse,
                ml2_db._prevent_segment_delete_with_port_bound,
                resource=mock.Mock(),
                event=mock.Mock(),
                trigger=mock.Mock(),
                payload=payload_mock,
            )

    def test__prevent_segment_delete_with_port_bound_auto_delete(self):
        payload_mock = mock.Mock()
        payload_mock.metadata.get.return_value = False
        payload_mock.context = self.ctx
        plugin = directory.get_plugin()
        with mock.patch.object(
                 port_obj.Port,
                 'get_auto_deletable_port_ids_and_proper_port_count_by_segment'
             ) as mock_get, \
                mock.patch.object(plugin, 'delete_port') as mock_delete_port:
            mock_get.return_value = (['fake-port'], 0)
            ml2_db._prevent_segment_delete_with_port_bound(
                resource=mock.Mock(),
                event=mock.Mock(),
                trigger=mock.Mock(),
                payload=payload_mock,
            )
            mock_delete_port.assert_called_with(mock.ANY, 'fake-port')


class Ml2DvrDBTestCase(testlib_api.SqlTestCase):

    def setUp(self):
        super().setUp()
        self.ctx = context.get_admin_context()
        self.setup_coreplugin(PLUGIN_NAME)

    def _setup_neutron_network(self, network_id, port_ids):
        with db_api.CONTEXT_WRITER.using(self.ctx):
            network_obj.Network(self.ctx, id=network_id).create()
            ports = []
            for port_id in port_ids:
                mac_address = (db_base_plugin_v2.NeutronDbPluginV2.
                               _generate_macs()[0])
                port = port_obj.Port(self.ctx,
                                     id=port_id,
                                     network_id=network_id,
                                     mac_address=netaddr.EUI(mac_address),
                                     admin_state_up=True,
                                     status='ACTIVE',
                                     device_id='',
                                     device_owner='')
                port.create()
                ports.append(port)
            return ports

    def _setup_neutron_router(self):
        with db_api.CONTEXT_WRITER.using(self.ctx):
            router = l3_models.Router()
            self.ctx.session.add(router)
            return router

    def _setup_distributed_binding(self, network_id,
                                   port_id, router_id, host_id):
        with db_api.CONTEXT_WRITER.using(self.ctx):
            record = models.DistributedPortBinding(
                port_id=port_id,
                host=host_id,
                router_id=router_id,
                vif_type=portbindings.VIF_TYPE_UNBOUND,
                vnic_type=portbindings.VNIC_NORMAL,
                status='DOWN')
            self.ctx.session.add(record)
            return record

    def _setup_port_binding_level(self, network_id, port_id, host_id,
                                  level=0, driver='openvswitch'):
        with db_api.CONTEXT_WRITER.using(self.ctx):
            record = models.PortBindingLevel(
                port_id=port_id,
                host=host_id,
                level=level,
                driver=driver,
                segment_id=network_id)
            self.ctx.session.add(record)
            return record

    def _setup_neutron_network_segment(self, segment_id, network_id):
        with db_api.CONTEXT_WRITER.using(self.ctx):
            segment = network_obj.NetworkSegment(
                self.ctx,
                id=segment_id, network_id=network_id,
                network_type=constants.TYPE_FLAT)
            segment.create()

    def test_ensure_distributed_port_binding_deals_with_db_duplicate(self):
        network_id = uuidutils.generate_uuid()
        port_id = uuidutils.generate_uuid()
        router_id = 'foo_router_id'
        host_id = 'foo_host_id'
        self._setup_neutron_network(network_id, [port_id])
        self._setup_distributed_binding(network_id, port_id,
                                        router_id, host_id)
        with mock.patch.object(query.Query, 'first') as query_first:
            query_first.return_value = []
            with mock.patch.object(ml2_db.LOG, 'debug') as log_trace:
                binding = ml2_db.ensure_distributed_port_binding(
                    self.ctx, port_id, host_id, router_id)
        self.assertTrue(query_first.called)
        self.assertTrue(log_trace.called)
        self.assertEqual(port_id, binding.port_id)

    def test_ensure_distributed_port_binding(self):
        network_id = uuidutils.generate_uuid()
        port_id = uuidutils.generate_uuid()
        self._setup_neutron_network(network_id, [port_id])
        router = self._setup_neutron_router()
        ml2_db.ensure_distributed_port_binding(
            self.ctx, port_id, 'foo_host', router.id)
        expected = (self.ctx.session.query(models.DistributedPortBinding).
                    filter_by(port_id=port_id).one())
        self.assertEqual(port_id, expected.port_id)

    def test_ensure_distributed_port_binding_multiple_bindings(self):
        network_id = uuidutils.generate_uuid()
        port_id = uuidutils.generate_uuid()
        self._setup_neutron_network(network_id, [port_id])
        router = self._setup_neutron_router()
        ml2_db.ensure_distributed_port_binding(
            self.ctx, port_id, 'foo_host_1', router.id)
        ml2_db.ensure_distributed_port_binding(
            self.ctx, port_id, 'foo_host_2', router.id)
        bindings = (self.ctx.session.query(models.DistributedPortBinding).
                    filter_by(port_id=port_id).all())
        self.assertEqual(2, len(bindings))

    def test_delete_distributed_port_binding_if_stale(self):
        network_id = uuidutils.generate_uuid()
        segment_id = uuidutils.generate_uuid()
        port_id = uuidutils.generate_uuid()
        host_id = 'foo_host_id'
        self._setup_neutron_network(network_id, [port_id])
        self._setup_neutron_network_segment(segment_id, network_id)

        binding = self._setup_distributed_binding(
            network_id, port_id, None, host_id)
        binding_levels = self._setup_port_binding_level(
            segment_id, port_id, host_id)

        ml2_db.delete_distributed_port_binding_if_stale(
            self.ctx, binding)
        count = (self.ctx.session.query(models.DistributedPortBinding).
                 filter_by(port_id=binding.port_id, host=host_id).count())
        self.assertFalse(count)

        count = (self.ctx.session.query(models.PortBindingLevel).
                 filter_by(port_id=binding_levels.port_id,
                           host=host_id).count())
        self.assertFalse(count)

    def test_update_distributed_port_binding_by_host(self):
        network_id = uuidutils.generate_uuid()
        router_id = uuidutils.generate_uuid()
        port_id = uuidutils.generate_uuid()
        host_id = 'foo_host_id'
        self._setup_neutron_network(network_id, [port_id])

        binding = self._setup_distributed_binding(
            network_id, port_id, router_id, host_id)

        ml2_db.update_distributed_port_binding_by_host(
            self.ctx, binding.port_id, host_id, None)
        binding = (self.ctx.session.query(models.DistributedPortBinding).
                   filter_by(port_id=port_id, host=host_id).one())
        self.assertFalse(binding.router_id)

    def test_get_distributed_port_binding_by_host_not_found(self):
        port = ml2_db.get_distributed_port_binding_by_host(
            self.ctx, 'foo_port_id', 'foo_host_id')
        self.assertIsNone(port)

    def test_get_distributed_port_bindings_not_found(self):
        port = ml2_db.get_distributed_port_bindings(self.ctx,
                                                    'foo_port_id')
        self.assertFalse(len(port))

    def test_get_distributed_port_bindings(self):
        network_id = uuidutils.generate_uuid()
        port_id_1 = uuidutils.generate_uuid()
        port_id_2 = uuidutils.generate_uuid()
        self._setup_neutron_network(network_id, [port_id_1, port_id_2])
        router = self._setup_neutron_router()
        self._setup_distributed_binding(
            network_id, port_id_1, router.id, 'foo_host_id_1')
        self._setup_distributed_binding(
            network_id, port_id_1, router.id, 'foo_host_id_2')
        ports = ml2_db.get_distributed_port_bindings(self.ctx,
                                                     port_id_1)
        self.assertEqual(2, len(ports))

    def test_distributed_port_binding_deleted_by_port_deletion(self):
        network_id = uuidutils.generate_uuid()
        network_obj.Network(self.ctx, id=network_id).create()
        device_owner = constants.DEVICE_OWNER_DVR_INTERFACE
        port = port_obj.Port(
            self.ctx,
            id=uuidutils.generate_uuid(),
            network_id=network_id,
            mac_address=netaddr.EUI('00-11-22-33-44-55'),
            admin_state_up=True,
            status=constants.PORT_STATUS_ACTIVE,
            device_id='device_id',
            device_owner=device_owner)
        port.create()
        port_obj.DistributedPortBinding(
            self.ctx,
            port_id=port.id,
            host='host',
            vif_type=portbindings.VIF_TYPE_UNBOUND,
            vnic_type=portbindings.VNIC_NORMAL,
            router_id='router_id',
            status=constants.PORT_STATUS_DOWN).create()
        port_obj.DistributedPortBinding(
            self.ctx,
            port_id=port.id,
            host='another-host',
            vif_type=portbindings.VIF_TYPE_UNBOUND,
            vnic_type=portbindings.VNIC_NORMAL,
            router_id='router_id',
            status=constants.PORT_STATUS_DOWN).create()
        with warnings.catch_warnings(record=True) as warning_list:
            port.delete()
            self.assertEqual(
                [], warning_list,
                'Warnings: %s' % ';'.join([str(w) for w in warning_list]))
        ports = ml2_db.get_distributed_port_bindings(self.ctx,
                                                     port.id)
        self.assertEqual(0, len(ports))
