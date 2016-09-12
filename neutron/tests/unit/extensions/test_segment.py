# Copyright (c) 2016 Hewlett Packard Enterprise Development Company, L.P.
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

import mock
import netaddr
from neutron_lib import constants
from neutron_lib import exceptions as n_exc
from oslo_utils import uuidutils
import webob.exc

from neutron.api.v2 import attributes
from neutron.callbacks import events
from neutron.callbacks import exceptions
from neutron.callbacks import registry
from neutron.callbacks import resources
from neutron import context
from neutron.db import agents_db
from neutron.db import agentschedulers_db
from neutron.db import db_base_plugin_v2
from neutron.db import portbindings_db
from neutron.db import segments_db
from neutron.extensions import ip_allocation
from neutron.extensions import l2_adjacency
from neutron.extensions import portbindings
from neutron.extensions import segment as ext_segment
from neutron.plugins.common import constants as p_constants
from neutron.plugins.ml2 import config
from neutron.services.segments import db
from neutron.services.segments import exceptions as segment_exc
from neutron.tests.common import helpers
from neutron.tests.unit.db import test_db_base_plugin_v2

SERVICE_PLUGIN_KLASS = 'neutron.services.segments.plugin.Plugin'
TEST_PLUGIN_KLASS = (
    'neutron.tests.unit.extensions.test_segment.SegmentTestPlugin')
DHCP_HOSTA = 'dhcp-host-a'
DHCP_HOSTB = 'dhcp-host-b'
HTTP_NOT_FOUND = 404


class SegmentTestExtensionManager(object):

    def get_resources(self):
        # Add the resources to the global attribute map
        # This is done here as the setup process won't
        # initialize the main API router which extends
        # the global attribute map
        attributes.RESOURCE_ATTRIBUTE_MAP.update(
            ext_segment.RESOURCE_ATTRIBUTE_MAP)
        return ext_segment.Segment.get_resources()

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


class SegmentTestCase(test_db_base_plugin_v2.NeutronDbPluginV2TestCase):

    def setUp(self, plugin=None):
        if not plugin:
            plugin = TEST_PLUGIN_KLASS
        service_plugins = {'segments_plugin_name': SERVICE_PLUGIN_KLASS}
        ext_mgr = SegmentTestExtensionManager()
        super(SegmentTestCase, self).setUp(plugin=plugin, ext_mgr=ext_mgr,
                                           service_plugins=service_plugins)

    def _create_segment(self, fmt, expected_res_status=None, **kwargs):
        segment = {'segment': {}}
        for k, v in kwargs.items():
            segment['segment'][k] = None if v is None else str(v)

        segment_req = self.new_create_request(
            'segments', segment, fmt)

        segment_res = segment_req.get_response(self.ext_api)
        if expected_res_status:
            self.assertEqual(segment_res.status_int, expected_res_status)
        return segment_res

    def _make_segment(self, fmt, **kwargs):
        res = self._create_segment(fmt, **kwargs)
        if res.status_int >= webob.exc.HTTPClientError.code:
            res.charset = 'utf8'
            raise webob.exc.HTTPClientError(
                code=res.status_int, explanation=str(res))
        return self.deserialize(fmt, res)

    def segment(self, **kwargs):
        kwargs.setdefault('network_type', 'net_type')
        return self._make_segment(
            self.fmt, tenant_id=self._tenant_id, **kwargs)

    def _test_create_segment(self, expected=None, **kwargs):
        keys = kwargs.copy()
        segment = self.segment(**keys)
        self._validate_resource(segment, keys, 'segment')
        if expected:
            self._compare_resource(segment, expected, 'segment')
        return segment


class SegmentTestPlugin(db_base_plugin_v2.NeutronDbPluginV2,
                        portbindings_db.PortBindingMixin,
                        db.SegmentDbMixin):
    __native_pagination_support = True
    __native_sorting_support = True

    supported_extension_aliases = ["segment", "binding", "ip_allocation"]

    def get_plugin_description(self):
        return "Network Segments"

    @classmethod
    def get_plugin_type(cls):
        return "segments"

    def create_port(self, context, port):
        port_dict = super(SegmentTestPlugin, self).create_port(context, port)
        self._process_portbindings_create_and_update(
            context, port['port'], port_dict)
        return port_dict

    def update_port(self, context, id, port):
        port_dict = super(SegmentTestPlugin, self).update_port(
            context, id, port)
        self._process_portbindings_create_and_update(
            context, port['port'], port_dict)
        return port_dict


class TestSegmentNameDescription(SegmentTestCase):
    def setUp(self):
        super(TestSegmentNameDescription, self).setUp()
        with self.network() as network:
            self.network = network['network']

    def _test_create_segment(self, expected=None, **kwargs):
        for d in (kwargs, expected):
            if d is None:
                continue
            d.setdefault('network_id', self.network['id'])
            d.setdefault('name', None)
            d.setdefault('description', None)
            d.setdefault('physical_network', 'phys_net')
            d.setdefault('network_type', 'net_type')
            d.setdefault('segmentation_id', 200)
        return super(TestSegmentNameDescription, self)._test_create_segment(
            expected, **kwargs)

    def test_create_segment_no_name_description(self):
        self._test_create_segment(expected={})

    def test_create_segment_with_name(self):
        expected_segment = {'name': 'segment_name'}
        self._test_create_segment(name='segment_name',
                                  expected=expected_segment)

    def test_create_segment_with_description(self):
        expected_segment = {'description': 'A segment'}
        self._test_create_segment(description='A segment',
                                  expected=expected_segment)

    def test_update_segment_set_name(self):
        segment = self._test_create_segment()
        result = self._update('segments',
                              segment['segment']['id'],
                              {'segment': {'name': 'Segment name'}},
                              expected_code=webob.exc.HTTPOk.code)
        self.assertEqual('Segment name', result['segment']['name'])

    def test_update_segment_set_description(self):
        segment = self._test_create_segment()
        result = self._update('segments',
                              segment['segment']['id'],
                              {'segment': {'description': 'Segment desc'}},
                              expected_code=webob.exc.HTTPOk.code)
        self.assertEqual('Segment desc', result['segment']['description'])

    def test_update_segment_set_name_to_none(self):
        segment = self._test_create_segment(
            description='A segment', name='segment')
        result = self._update('segments',
                              segment['segment']['id'],
                              {'segment': {'name': None}},
                              expected_code=webob.exc.HTTPOk.code)
        self.assertIsNone(result['segment']['name'])

    def test_update_segment_set_description_to_none(self):
        segment = self._test_create_segment(
            description='A segment', name='segment')
        result = self._update('segments',
                              segment['segment']['id'],
                              {'segment': {'description': None}},
                              expected_code=webob.exc.HTTPOk.code)
        self.assertIsNone(result['segment']['description'])


class TestSegment(SegmentTestCase):

    def test_create_segment(self):
        with self.network() as network:
            network = network['network']
        expected_segment = {'network_id': network['id'],
                            'physical_network': 'phys_net',
                            'network_type': 'net_type',
                            'segmentation_id': 200}
        self._test_create_segment(network_id=network['id'],
                                  physical_network='phys_net',
                                  segmentation_id=200,
                                  expected=expected_segment)

    def test_create_segment_non_existent_network(self):
        exc = self.assertRaises(webob.exc.HTTPClientError,
                                self._test_create_segment,
                                network_id=uuidutils.generate_uuid(),
                                physical_network='phys_net',
                                segmentation_id=200)
        self.assertEqual(HTTP_NOT_FOUND, exc.code)
        self.assertIn('NetworkNotFound', exc.explanation)

    def test_create_segment_no_phys_net(self):
        with self.network() as network:
            network = network['network']
        expected_segment = {'network_id': network['id'],
                            'physical_network': None,
                            'network_type': 'net_type',
                            'segmentation_id': 200}
        self._test_create_segment(network_id=network['id'],
                                  segmentation_id=200,
                                  expected=expected_segment)

    def test_create_segment_no_segmentation_id(self):

        def _mock_reserve_segmentation_id(rtype, event, trigger,
                                          context, segment):
            if not segment.get('segmentation_id'):
                segment['segmentation_id'] = 200

        with self.network() as network:
            network = network['network']

        registry.subscribe(_mock_reserve_segmentation_id, resources.SEGMENT,
                           events.PRECOMMIT_CREATE)
        expected_segment = {'network_id': network['id'],
                            'physical_network': 'phys_net',
                            'network_type': 'net_type',
                            'segmentation_id': 200}
        self._test_create_segment(network_id=network['id'],
                                  physical_network='phys_net',
                                  expected=expected_segment)

    def test_create_segment_with_exception_in_core_plugin(self):
        cxt = context.get_admin_context()
        with self.network() as network:
            network = network['network']

        with mock.patch.object(registry, 'notify') as notify:
            notify.side_effect = exceptions.CallbackFailure(errors=Exception)
            self.assertRaises(webob.exc.HTTPClientError,
                              self.segment,
                              network_id=network['id'],
                              segmentation_id=200)

        network_segments = segments_db.get_network_segments(cxt.session,
                                                            network['id'])
        self.assertEqual([], network_segments)

    def test_create_segments_in_certain_order(self):
        cxt = context.get_admin_context()
        with self.network() as network:
            network = network['network']
            segment1 = self.segment(
                network_id=network['id'], segmentation_id=200)
            segment2 = self.segment(
                network_id=network['id'], segmentation_id=201)
            segment3 = self.segment(
                network_id=network['id'], segmentation_id=202)
            network_segments = segments_db.get_network_segments(cxt.session,
                                                                network['id'])
            self.assertEqual(segment1['segment']['id'],
                             network_segments[0]['id'])
            self.assertEqual(segment2['segment']['id'],
                             network_segments[1]['id'])
            self.assertEqual(segment3['segment']['id'],
                             network_segments[2]['id'])

    def test_delete_segment(self):
        with self.network() as network:
            network = network['network']
        self.segment(network_id=network['id'], segmentation_id=200)
        segment = self.segment(network_id=network['id'], segmentation_id=201)
        self._delete('segments', segment['segment']['id'])
        self._show('segments', segment['segment']['id'],
                   expected_code=webob.exc.HTTPNotFound.code)

    def test_delete_segment_failed_with_subnet_associated(self):
        with self.network() as network:
            net = network['network']

            segment = self._test_create_segment(network_id=net['id'],
                                                segmentation_id=200)
            segment_id = segment['segment']['id']
            with self.subnet(network=network, segment_id=segment_id):
                self._delete('segments', segment_id,
                             expected_code=webob.exc.HTTPConflict.code)
                exist_segment = self._show('segments', segment_id)
                self.assertEqual(segment_id, exist_segment['segment']['id'])

    def test_get_segment(self):
        with self.network() as network:
            network = network['network']
        segment = self._test_create_segment(network_id=network['id'],
                                            physical_network='phys_net',
                                            segmentation_id=200)
        req = self.new_show_request('segments', segment['segment']['id'])
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        self.assertEqual(segment['segment']['id'], res['segment']['id'])

    def test_list_segments(self):
        with self.network() as network:
            network = network['network']
        self._test_create_segment(network_id=network['id'],
                                  physical_network='phys_net1',
                                  segmentation_id=200)
        self._test_create_segment(network_id=network['id'],
                                  physical_network='phys_net2',
                                  segmentation_id=201)
        res = self._list('segments')
        self.assertEqual(2, len(res['segments']))

    def test_update_segments(self):
        with self.network() as network:
            net = network['network']
            segment = self._test_create_segment(network_id=net['id'],
                                                segmentation_id=200)
            segment['segment']['segmentation_id'] = '201'
            self._update('segments', segment['segment']['id'], segment,
                         expected_code=webob.exc.HTTPClientError.code)


class TestSegmentML2(SegmentTestCase):
    def setUp(self):
        super(TestSegmentML2, self).setUp(plugin='ml2')

    def test_segment_notification_on_create_network(self):
        with mock.patch.object(registry, 'notify') as notify:
            with self.network():
                pass
        notify.assert_any_call(resources.SEGMENT,
                               events.PRECOMMIT_CREATE,
                               context=mock.ANY,
                               segment=mock.ANY,
                               trigger=mock.ANY)


class TestSegmentSubnetAssociation(SegmentTestCase):
    def test_basic_association(self):
        with self.network() as network:
            net = network['network']

        segment = self._test_create_segment(network_id=net['id'],
                                            segmentation_id=200)
        segment_id = segment['segment']['id']

        with self.subnet(network=network, segment_id=segment_id) as subnet:
            subnet = subnet['subnet']

        request = self.new_show_request('subnets', subnet['id'])
        response = request.get_response(self.api)
        res = self.deserialize(self.fmt, response)
        self.assertEqual(segment_id,
                         res['subnet']['segment_id'])

    def test_association_network_mismatch(self):
        with self.network() as network1:
            with self.network() as network2:
                net = network1['network']

        segment = self._test_create_segment(network_id=net['id'],
                                            segmentation_id=200)

        res = self._create_subnet(self.fmt,
                                  net_id=network2['network']['id'],
                                  tenant_id=network2['network']['tenant_id'],
                                  gateway_ip=constants.ATTR_NOT_SPECIFIED,
                                  cidr='10.0.0.0/24',
                                  segment_id=segment['segment']['id'])
        self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)

    def test_association_segment_not_found(self):
        with self.network() as network:
            net = network['network']

        segment_id = uuidutils.generate_uuid()

        res = self._create_subnet(self.fmt,
                                  net_id=net['id'],
                                  tenant_id=net['tenant_id'],
                                  gateway_ip=constants.ATTR_NOT_SPECIFIED,
                                  cidr='10.0.0.0/24',
                                  segment_id=segment_id)
        self.assertEqual(webob.exc.HTTPNotFound.code, res.status_int)

    def test_only_some_subnets_associated_not_allowed(self):
        with self.network() as network:
            with self.subnet(network=network):
                net = network['network']

        segment = self._test_create_segment(network_id=net['id'],
                                            segmentation_id=200)

        res = self._create_subnet(self.fmt,
                                  net_id=net['id'],
                                  tenant_id=net['tenant_id'],
                                  gateway_ip=constants.ATTR_NOT_SPECIFIED,
                                  cidr='10.0.1.0/24',
                                  segment_id=segment['segment']['id'])
        self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)

    def test_association_to_dynamic_segment_not_allowed(self):
        cxt = context.get_admin_context()
        with self.network() as network:
            net = network['network']

        # Can't create a dynamic segment through the API
        segment = {segments_db.NETWORK_TYPE: 'phys_net',
                   segments_db.PHYSICAL_NETWORK: 'net_type',
                   segments_db.SEGMENTATION_ID: 200}
        segments_db.add_network_segment(cxt,
                                        network_id=net['id'],
                                        segment=segment,
                                        is_dynamic=True)

        res = self._create_subnet(self.fmt,
                                  net_id=net['id'],
                                  tenant_id=net['tenant_id'],
                                  gateway_ip=constants.ATTR_NOT_SPECIFIED,
                                  cidr='10.0.0.0/24',
                                  segment_id=segment['id'])
        self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)


class HostSegmentMappingTestCase(SegmentTestCase):
    _mechanism_drivers = ['logger']

    def setUp(self, plugin=None):
        config.cfg.CONF.set_override('mechanism_drivers',
                                     self._mechanism_drivers,
                                     group='ml2')
        config.cfg.CONF.set_override('network_vlan_ranges',
                                     ['phys_net1', 'phys_net2'],
                                     group='ml2_type_vlan')
        if not plugin:
            plugin = 'ml2'
        super(HostSegmentMappingTestCase, self).setUp(plugin=plugin)
        db.subscribe()

    def _get_segments_for_host(self, host):
        ctx = context.get_admin_context()
        segments_host_list = ctx.session.query(
            db.SegmentHostMapping).filter_by(host=host)
        return {seg_host['segment_id']: seg_host
                for seg_host in segments_host_list}

    def _register_agent(self, host, mappings=None, plugin=None,
                        start_flag=True):
        helpers.register_ovs_agent(host=host, bridge_mappings=mappings,
                                   plugin=self.plugin, start_flag=start_flag)

    def _test_one_segment_one_host(self, host):
        physical_network = 'phys_net1'
        with self.network() as network:
            network = network['network']
        segment = self._test_create_segment(
            network_id=network['id'], physical_network=physical_network,
            segmentation_id=200, network_type=p_constants.TYPE_VLAN)['segment']
        self._register_agent(host, mappings={physical_network: 'br-eth-1'},
                             plugin=self.plugin)
        segments_host_db = self._get_segments_for_host(host)
        self.assertEqual(1, len(segments_host_db))
        self.assertEqual(segment['id'],
                         segments_host_db[segment['id']]['segment_id'])
        self.assertEqual(host, segments_host_db[segment['id']]['host'])
        return segment


class TestMl2HostSegmentMappingNoAgent(HostSegmentMappingTestCase):

    def setUp(self, plugin=None):
        if not plugin:
            plugin = TEST_PLUGIN_KLASS
        super(TestMl2HostSegmentMappingNoAgent, self).setUp(plugin=plugin)

    def test_update_segment_host_mapping(self):
        ctx = context.get_admin_context()
        host = 'host1'
        physnets = ['phys_net1']
        with self.network() as network:
            network = network['network']
        segment = self._test_create_segment(
            network_id=network['id'], physical_network='phys_net1',
            segmentation_id=200, network_type=p_constants.TYPE_VLAN)['segment']
        self._test_create_segment(
            network_id=network['id'], physical_network='phys_net2',
            segmentation_id=201, network_type=p_constants.TYPE_VLAN)['segment']
        segments = db.get_segments_with_phys_nets(ctx, physnets)
        segment_ids = {segment['id'] for segment in segments}
        db.update_segment_host_mapping(ctx, host, segment_ids)
        segments_host_db = self._get_segments_for_host(host)
        self.assertEqual(1, len(segments_host_db))
        self.assertEqual(segment['id'],
                         segments_host_db[segment['id']]['segment_id'])
        self.assertEqual(host, segments_host_db[segment['id']]['host'])

    def test_map_segment_to_hosts(self):
        ctx = context.get_admin_context()
        hosts = {'host1', 'host2', 'host3'}
        with self.network() as network:
            network = network['network']
        segment = self._test_create_segment(
            network_id=network['id'], physical_network='phys_net1',
            segmentation_id=200, network_type=p_constants.TYPE_VLAN)['segment']
        db.map_segment_to_hosts(ctx, segment['id'], hosts)
        updated_segment = self.plugin.get_segment(ctx, segment['id'])
        self.assertEqual(hosts, set(updated_segment['hosts']))

    def test_get_all_hosts_mapped_with_segments(self):
        ctx = context.get_admin_context()
        hosts = set()
        with self.network() as network:
            network_id = network['network']['id']
        for i in range(1, 3):
            host = "host%s" % i
            segment = self._test_create_segment(
                network_id=network_id, physical_network='phys_net%s' % i,
                segmentation_id=200 + i, network_type=p_constants.TYPE_VLAN)
            db.update_segment_host_mapping(
                ctx, host, {segment['segment']['id']})
            hosts.add(host)

        # Now they are 2 hosts with segment being mapped.
        actual_hosts = db.get_hosts_mapped_with_segments(ctx)
        self.assertEqual(hosts, actual_hosts)


class TestMl2HostSegmentMappingOVS(HostSegmentMappingTestCase):
    _mechanism_drivers = ['openvswitch', 'logger']
    mock_path = 'neutron.services.segments.db.update_segment_host_mapping'

    def test_new_agent(self):
        host = 'host1'
        self._test_one_segment_one_host(host)

    def test_updated_agent_changed_physical_networks(self):
        host = 'host1'
        physical_networks = ['phys_net1', 'phys_net2']
        networks = []
        segments = []
        for i in range(len(physical_networks)):
            with self.network() as network:
                networks.append(network['network'])
            segments.append(self._test_create_segment(
                network_id=networks[i]['id'],
                physical_network=physical_networks[i],
                segmentation_id=200,
                network_type=p_constants.TYPE_VLAN)['segment'])
        self._register_agent(host, mappings={physical_networks[0]: 'br-eth-1',
                                             physical_networks[1]: 'br-eth-2'},
                             plugin=self.plugin)
        segments_host_db = self._get_segments_for_host(host)
        self.assertEqual(len(physical_networks), len(segments_host_db))
        for segment in segments:
            self.assertEqual(segment['id'],
                             segments_host_db[segment['id']]['segment_id'])
            self.assertEqual(host, segments_host_db[segment['id']]['host'])
        self._register_agent(host, mappings={physical_networks[0]: 'br-eth-1'},
                             plugin=self.plugin)
        segments_host_db = self._get_segments_for_host(host)
        self.assertEqual(1, len(segments_host_db))
        self.assertEqual(segments[0]['id'],
                         segments_host_db[segments[0]['id']]['segment_id'])
        self.assertEqual(host, segments_host_db[segments[0]['id']]['host'])

    def test_same_segment_two_hosts(self):
        host1 = 'host1'
        host2 = 'host2'
        physical_network = 'phys_net1'
        segment = self._test_one_segment_one_host(host1)
        self._register_agent(host2, mappings={physical_network: 'br-eth-1'},
                             plugin=self.plugin)
        segments_host_db = self._get_segments_for_host(host2)
        self.assertEqual(1, len(segments_host_db))
        self.assertEqual(segment['id'],
                         segments_host_db[segment['id']]['segment_id'])
        self.assertEqual(host2, segments_host_db[segment['id']]['host'])

    def test_update_agent_only_change_agent_host_mapping(self):
        host1 = 'host1'
        host2 = 'host2'
        physical_network = 'phys_net1'
        with self.network() as network:
            network = network['network']
        segment1 = self._test_create_segment(
            network_id=network['id'],
            physical_network=physical_network,
            segmentation_id=200,
            network_type=p_constants.TYPE_VLAN)['segment']
        self._register_agent(host1, mappings={physical_network: 'br-eth-1'},
                             plugin=self.plugin)
        self._register_agent(host2, mappings={physical_network: 'br-eth-1'},
                             plugin=self.plugin)

        # Update agent at host2 should only change mapping with host2.
        other_phys_net = 'phys_net2'
        segment2 = self._test_create_segment(
            network_id=network['id'],
            physical_network=other_phys_net,
            segmentation_id=201,
            network_type=p_constants.TYPE_VLAN)['segment']
        self._register_agent(host2, mappings={other_phys_net: 'br-eth-2'},
                             plugin=self.plugin)
        # We should have segment1 map to host1 and segment2 map to host2 now
        segments_host_db1 = self._get_segments_for_host(host1)
        self.assertEqual(1, len(segments_host_db1))
        self.assertEqual(segment1['id'],
                         segments_host_db1[segment1['id']]['segment_id'])
        self.assertEqual(host1, segments_host_db1[segment1['id']]['host'])
        segments_host_db2 = self._get_segments_for_host(host2)
        self.assertEqual(1, len(segments_host_db2))
        self.assertEqual(segment2['id'],
                         segments_host_db2[segment2['id']]['segment_id'])
        self.assertEqual(host2, segments_host_db2[segment2['id']]['host'])

    def test_new_segment_after_host_reg(self):
        host1 = 'host1'
        physical_network = 'phys_net1'
        segment = self._test_one_segment_one_host(host1)
        with self.network() as network:
            network = network['network']
        segment2 = self._test_create_segment(
            network_id=network['id'], physical_network=physical_network,
            segmentation_id=201, network_type=p_constants.TYPE_VLAN)['segment']
        segments_host_db = self._get_segments_for_host(host1)
        self.assertEqual(set((segment['id'], segment2['id'])),
                         set(segments_host_db))

    def test_segment_deletion_removes_host_mapping(self):
        host = 'host1'
        segment = self._test_one_segment_one_host(host)
        self._delete('segments', segment['id'])
        segments_host_db = self._get_segments_for_host(host)
        self.assertFalse(segments_host_db)

    @mock.patch(mock_path)
    def test_agent_with_no_mappings(self, mock):
        host = 'host1'
        physical_network = 'phys_net1'
        with self.network() as network:
            network = network['network']
        self._test_create_segment(
            network_id=network['id'], physical_network=physical_network,
            segmentation_id=200, network_type=p_constants.TYPE_VLAN)
        self._register_agent(host, plugin=self.plugin)
        segments_host_db = self._get_segments_for_host(host)
        self.assertFalse(segments_host_db)
        self.assertFalse(mock.mock_calls)


class TestMl2HostSegmentMappingLinuxBridge(TestMl2HostSegmentMappingOVS):
    _mechanism_drivers = ['linuxbridge', 'logger']

    def _register_agent(self, host, mappings=None, plugin=None):
        helpers.register_linuxbridge_agent(host=host,
                                           bridge_mappings=mappings,
                                           plugin=self.plugin)


class TestMl2HostSegmentMappingMacvtap(TestMl2HostSegmentMappingOVS):
    _mechanism_drivers = ['macvtap', 'logger']

    def _register_agent(self, host, mappings=None, plugin=None):
        helpers.register_macvtap_agent(host=host, interface_mappings=mappings,
                                       plugin=self.plugin)


class TestMl2HostSegmentMappingSriovNicSwitch(TestMl2HostSegmentMappingOVS):
    _mechanism_drivers = ['sriovnicswitch', 'logger']

    def _register_agent(self, host, mappings=None, plugin=None):
        helpers.register_sriovnicswitch_agent(host=host,
                                              device_mappings=mappings,
                                              plugin=self.plugin)


class NoSupportHostSegmentMappingPlugin(db_base_plugin_v2.NeutronDbPluginV2,
                                        db.SegmentDbMixin,
                                        agents_db.AgentDbMixin):
    __native_pagination_support = True
    __native_sorting_support = True

    supported_extension_aliases = []


class TestHostSegmentMappingNoSupportFromPlugin(HostSegmentMappingTestCase):
    mock_path = 'neutron.services.segments.db.update_segment_host_mapping'

    def setUp(self):
        plugin = ('neutron.tests.unit.extensions.test_segment.'
                  'NoSupportHostSegmentMappingPlugin')
        super(TestHostSegmentMappingNoSupportFromPlugin, self).setUp(
              plugin=plugin)

    @mock.patch(mock_path)
    def test_host_segments_not_updated(self, mock):
        host = 'host1'
        physical_network = 'phys_net1'
        with self.network() as network:
            network = network['network']
        self._test_create_segment(network_id=network['id'],
                                  physical_network=physical_network,
                                  segmentation_id=200,
                                  network_type=p_constants.TYPE_VLAN)
        self._register_agent(host, mappings={physical_network: 'br-eth-1'},
                             plugin=self.plugin)
        segments_host_db = self._get_segments_for_host(host)
        self.assertFalse(segments_host_db)
        self.assertFalse(mock.mock_calls)


class TestMl2HostSegmentMappingAgentServerSynch(HostSegmentMappingTestCase):
    _mechanism_drivers = ['openvswitch', 'logger']
    mock_path = 'neutron.services.segments.db.update_segment_host_mapping'

    @mock.patch(mock_path)
    def test_starting_server_processes_agents(self, mock_function):
        host = 'agent_updating_starting_server'
        physical_network = 'phys_net1'
        self._register_agent(host, mappings={physical_network: 'br-eth-1'},
                             plugin=self.plugin, start_flag=False)
        self.assertTrue(host in db.reported_hosts)
        self.assertEqual(1, mock_function.call_count)
        expected_call = mock.call(mock.ANY, host, set())
        mock_function.assert_has_calls([expected_call])

    @mock.patch(mock_path)
    def test_starting_agent_is_processed(self, mock_function):
        host = 'starting_agent'
        physical_network = 'phys_net1'
        self._register_agent(host, mappings={physical_network: 'br-eth-1'},
                             plugin=self.plugin, start_flag=False)
        self.assertTrue(host in db.reported_hosts)
        self._register_agent(host, mappings={physical_network: 'br-eth-1'},
                             plugin=self.plugin, start_flag=True)
        self.assertTrue(host in db.reported_hosts)
        self.assertEqual(2, mock_function.call_count)
        expected_call = mock.call(mock.ANY, host, set())
        mock_function.assert_has_calls([expected_call, expected_call])

    @mock.patch(mock_path)
    def test_no_starting_agent_is_not_processed(self, mock_function):
        host = 'agent_with_no_start_update'
        physical_network = 'phys_net1'
        self._register_agent(host, mappings={physical_network: 'br-eth-1'},
                             plugin=self.plugin, start_flag=False)
        self.assertTrue(host in db.reported_hosts)
        mock_function.reset_mock()
        self._register_agent(host, mappings={physical_network: 'br-eth-1'},
                             plugin=self.plugin, start_flag=False)
        self.assertTrue(host in db.reported_hosts)
        mock_function.assert_not_called()


class TestSegmentAwareIpam(SegmentTestCase):
    def _setup_host_mappings(self, mappings=()):
        ctx = context.get_admin_context()
        with ctx.session.begin(subtransactions=True):
            for segment_id, host in mappings:
                record = db.SegmentHostMapping(
                    segment_id=segment_id,
                    host=host)
                ctx.session.add(record)

    def _create_test_segment_with_subnet(self,
                                         network=None,
                                         cidr='2001:db8:0:0::/64',
                                         physnet='physnet'):
        """Creates one network with one segment and one subnet"""
        if not network:
            with self.network() as network:
                pass

        segment = self._test_create_segment(
            network_id=network['network']['id'],
            physical_network=physnet,
            network_type=p_constants.TYPE_VLAN)

        ip_version = netaddr.IPNetwork(cidr).version if cidr else None
        with self.subnet(network=network,
                         segment_id=segment['segment']['id'],
                         ip_version=ip_version,
                         cidr=cidr) as subnet:
            self._validate_l2_adjacency(network['network']['id'],
                                        is_adjacent=False)
            return network, segment, subnet

    def _create_test_segments_with_subnets(self, num):
        """Creates one network with num segments and num subnets"""
        with self.network() as network:
            segments, subnets = [], []
            for i in range(num):
                cidr = '2001:db8:0:%s::/64' % i
                physnet = 'physnet%s' % i
                _net, segment, subnet = self._create_test_segment_with_subnet(
                    network=network, cidr=cidr, physnet=physnet)
                segments.append(segment)
                subnets.append(subnet)
            return network, segments, subnets

    def test_port_create_with_segment_subnets(self):
        """No binding information is provided, defer IP allocation"""
        network, segment, subnet = self._create_test_segment_with_subnet()
        response = self._create_port(self.fmt,
                                     net_id=network['network']['id'],
                                     tenant_id=network['network']['tenant_id'])
        res = self.deserialize(self.fmt, response)
        # Don't allocate IPs in this case because we didn't give binding info
        self.assertEqual(0, len(res['port']['fixed_ips']))

    def _assert_one_ip_in_subnet(self, response, cidr):
        res = self.deserialize(self.fmt, response)
        self.assertEqual(1, len(res['port']['fixed_ips']))
        ip = res['port']['fixed_ips'][0]['ip_address']
        ip_net = netaddr.IPNetwork(cidr)
        self.assertIn(ip, ip_net)

    def test_port_create_with_binding_information(self):
        """Binding information is provided, subnets are on segments"""
        network, segments, subnets = self._create_test_segments_with_subnets(3)

        # Map the host to the middle segment (by mocking host/segment mapping)
        self._setup_host_mappings([
            (segments[1]['segment']['id'], 'fakehost'),
            (segments[1]['segment']['id'], 'otherhost'),
            (segments[0]['segment']['id'], 'thirdhost')])

        response = self._create_port(self.fmt,
                                     net_id=network['network']['id'],
                                     tenant_id=network['network']['tenant_id'],
                                     arg_list=(portbindings.HOST_ID,),
                                     **{portbindings.HOST_ID: 'fakehost'})
        res = self.deserialize(self.fmt, response)
        self._validate_immediate_ip_allocation(res['port']['id'])

        # Since host mapped to middle segment, IP must come from middle subnet
        self._assert_one_ip_in_subnet(response, subnets[1]['subnet']['cidr'])

    def test_port_create_with_binding_and_no_subnets(self):
        """Binding information is provided, no subnets."""
        with self.network() as network:
            segment = self._test_create_segment(
                network_id=network['network']['id'],
                physical_network='physnet',
                network_type=p_constants.TYPE_VLAN)

        # Map the host to the segment
        self._setup_host_mappings([(segment['segment']['id'], 'fakehost')])

        response = self._create_port(self.fmt,
                                     net_id=network['network']['id'],
                                     tenant_id=network['network']['tenant_id'],
                                     arg_list=(portbindings.HOST_ID,),
                                     **{portbindings.HOST_ID: 'fakehost'})
        res = self.deserialize(self.fmt, response)

        # No subnets, so no allocation.  But, it shouldn't be an error.
        self.assertEqual(0, len(res['port']['fixed_ips']))

    def test_port_create_with_binding_information_fallback(self):
        """Binding information is provided, subnets not on segments"""
        with self.network() as network:
            with self.subnet(network=network,
                             ip_version=6,
                             cidr='2001:db8:0:0::/64') as subnet:
                segment = self._test_create_segment(
                    network_id=network['network']['id'],
                    physical_network='physnet',
                    network_type=p_constants.TYPE_VLAN)

        self._validate_l2_adjacency(network['network']['id'], is_adjacent=True)

        # Map the host to the segment
        self._setup_host_mappings([(segment['segment']['id'], 'fakehost')])

        response = self._create_port(self.fmt,
                                     net_id=network['network']['id'],
                                     tenant_id=network['network']['tenant_id'],
                                     arg_list=(portbindings.HOST_ID,),
                                     **{portbindings.HOST_ID: 'fakehost'})

        res = self.deserialize(self.fmt, response)
        self._validate_immediate_ip_allocation(res['port']['id'])

        # Since the subnet is not on a segment, fall back to it
        self._assert_one_ip_in_subnet(response, subnet['subnet']['cidr'])

    def test_port_create_on_unconnected_host(self):
        """Binding information provided, host not connected to any segment"""
        network, segment, _subnet = self._create_test_segment_with_subnet()
        response = self._create_port(self.fmt,
                                     net_id=network['network']['id'],
                                     tenant_id=network['network']['tenant_id'],
                                     arg_list=(portbindings.HOST_ID,),
                                     **{portbindings.HOST_ID: 'fakehost'})
        res = self.deserialize(self.fmt, response)

        self.assertEqual(webob.exc.HTTPConflict.code, response.status_int)
        self.assertEqual(segment_exc.HostNotConnectedToAnySegment.__name__,
                         res['NeutronError']['type'])

        # Ensure that mapping the segment to other hosts doesn't trip it up
        self._setup_host_mappings([(segment['segment']['id'], 'otherhost')])
        response = self._create_port(self.fmt,
                                     net_id=network['network']['id'],
                                     tenant_id=network['network']['tenant_id'],
                                     arg_list=(portbindings.HOST_ID,),
                                     **{portbindings.HOST_ID: 'fakehost'})
        res = self.deserialize(self.fmt, response)

        self.assertEqual(webob.exc.HTTPConflict.code, response.status_int)
        self.assertEqual(segment_exc.HostNotConnectedToAnySegment.__name__,
                         res['NeutronError']['type'])

    def test_port_create_on_multiconnected_host(self):
        """Binding information provided, host connected to multiple segments"""
        network, segments, subnets = self._create_test_segments_with_subnets(2)

        # This host is bound to multiple hosts
        self._setup_host_mappings([(segments[0]['segment']['id'], 'fakehost'),
                                   (segments[1]['segment']['id'], 'fakehost')])

        response = self._create_port(self.fmt,
                                     net_id=network['network']['id'],
                                     tenant_id=network['network']['tenant_id'],
                                     arg_list=(portbindings.HOST_ID,),
                                     **{portbindings.HOST_ID: 'fakehost'})
        res = self.deserialize(self.fmt, response)

        self.assertEqual(webob.exc.HTTPConflict.code, response.status_int)
        self.assertEqual(segment_exc.HostConnectedToMultipleSegments.__name__,
                         res['NeutronError']['type'])

    def test_port_update_excludes_hosts_on_segments(self):
        """No binding information is provided, subnets on segments"""
        with self.network() as network:
            segment = self._test_create_segment(
                network_id=network['network']['id'],
                physical_network='physnet',
                network_type=p_constants.TYPE_VLAN)

        # Create a port with no IP address (since there is no subnet)
        port = self._create_deferred_ip_port(network)

        # Create the subnet and try to update the port to get an IP
        with self.subnet(network=network,
                         segment_id=segment['segment']['id']) as subnet:
            # Try requesting an IP (but the only subnet is on a segment)
            data = {'port': {
                'fixed_ips': [{'subnet_id': subnet['subnet']['id']}]}}
            port_id = port['port']['id']
            port_req = self.new_update_request('ports', data, port_id)
            response = port_req.get_response(self.api)

        # Gets bad request because there are no eligible subnets.
        self.assertEqual(webob.exc.HTTPBadRequest.code, response.status_int)

    def _create_port_and_show(self, network, **kwargs):
        response = self._create_port(
            self.fmt,
            net_id=network['network']['id'],
            tenant_id=network['network']['tenant_id'],
            **kwargs)
        port = self.deserialize(self.fmt, response)
        request = self.new_show_request('ports', port['port']['id'])
        return self.deserialize(self.fmt, request.get_response(self.api))

    def test_port_create_with_no_fixed_ips_no_ipam_on_routed_network(self):
        """Ports requesting no fixed_ips not deferred, even on routed net"""
        with self.network() as network:
            segment = self._test_create_segment(
                network_id=network['network']['id'],
                physical_network='physnet',
                network_type=p_constants.TYPE_VLAN)
            with self.subnet(network=network,
                             segment_id=segment['segment']['id']):
                pass

        # Create an unbound port requesting no IP addresses
        response = self._create_port_and_show(network, fixed_ips=[])
        self.assertEqual([], response['port']['fixed_ips'])
        self.assertEqual(ip_allocation.IP_ALLOCATION_NONE,
                         response['port'][ip_allocation.IP_ALLOCATION])

    def test_port_create_with_no_fixed_ips_no_ipam(self):
        """Ports without addresses on non-routed networks are not deferred"""
        with self.network() as network:
            with self.subnet(network=network):
                pass

        # Create an unbound port requesting no IP addresses
        response = self._create_port_and_show(network, fixed_ips=[])

        self.assertEqual([], response['port']['fixed_ips'])
        self.assertEqual(ip_allocation.IP_ALLOCATION_NONE,
                         response['port'][ip_allocation.IP_ALLOCATION])

    def test_port_without_ip_not_deferred(self):
        """Ports without addresses on non-routed networks are not deferred"""
        with self.network() as network:
            pass

        # Create a bound port with no IP address (since there is no subnet)
        response = self._create_port(self.fmt,
                                     net_id=network['network']['id'],
                                     tenant_id=network['network']['tenant_id'],
                                     arg_list=(portbindings.HOST_ID,),
                                     **{portbindings.HOST_ID: 'fakehost'})
        port = self.deserialize(self.fmt, response)
        request = self.new_show_request('ports', port['port']['id'])
        response = self.deserialize(self.fmt, request.get_response(self.api))

        self.assertEqual([], response['port']['fixed_ips'])
        self.assertEqual(ip_allocation.IP_ALLOCATION_IMMEDIATE,
                         response['port'][ip_allocation.IP_ALLOCATION])

    def test_port_without_ip_not_deferred_no_binding(self):
        """Ports without addresses on non-routed networks are not deferred"""
        with self.network() as network:
            pass

        # Create a unbound port with no IP address (since there is no subnet)
        response = self._create_port_and_show(network)
        self.assertEqual([], response['port']['fixed_ips'])
        self.assertEqual(ip_allocation.IP_ALLOCATION_IMMEDIATE,
                         response['port'][ip_allocation.IP_ALLOCATION])

    def test_port_update_is_host_aware(self):
        """Binding information is provided, subnets on segments"""
        with self.network() as network:
            segment = self._test_create_segment(
                network_id=network['network']['id'],
                physical_network='physnet',
                network_type=p_constants.TYPE_VLAN)

        # Map the host to the segment
        self._setup_host_mappings([(segment['segment']['id'], 'fakehost')])

        # Create a bound port with no IP address (since there is no subnet)
        response = self._create_port(self.fmt,
                                     net_id=network['network']['id'],
                                     tenant_id=network['network']['tenant_id'],
                                     arg_list=(portbindings.HOST_ID,),
                                     **{portbindings.HOST_ID: 'fakehost'})
        port = self.deserialize(self.fmt, response)

        # Create the subnet and try to update the port to get an IP
        with self.subnet(network=network,
                         segment_id=segment['segment']['id']) as subnet:
            self._validate_l2_adjacency(network['network']['id'],
                                        is_adjacent=False)
            # Try requesting an IP (but the only subnet is on a segment)
            data = {'port': {
                'fixed_ips': [{'subnet_id': subnet['subnet']['id']}]}}
            port_id = port['port']['id']
            port_req = self.new_update_request('ports', data, port_id)
            response = port_req.get_response(self.api)

        # Since port is bound and there is a mapping to segment, it succeeds.
        self.assertEqual(webob.exc.HTTPOk.code, response.status_int)
        self._assert_one_ip_in_subnet(response, subnet['subnet']['cidr'])

    def _validate_l2_adjacency(self, network_id, is_adjacent):
        request = self.new_show_request('networks', network_id)
        response = self.deserialize(self.fmt, request.get_response(self.api))
        self.assertEqual(is_adjacent,
                         response['network'][l2_adjacency.L2_ADJACENCY])

    def _validate_deferred_ip_allocation(self, port_id):
        request = self.new_show_request('ports', port_id)
        response = self.deserialize(self.fmt, request.get_response(self.api))

        self.assertEqual(ip_allocation.IP_ALLOCATION_DEFERRED,
                         response['port'][ip_allocation.IP_ALLOCATION])
        ips = response['port']['fixed_ips']
        self.assertEqual(0, len(ips))

    def _validate_immediate_ip_allocation(self, port_id):
        request = self.new_show_request('ports', port_id)
        response = self.deserialize(self.fmt, request.get_response(self.api))

        self.assertEqual(ip_allocation.IP_ALLOCATION_IMMEDIATE,
                         response['port'][ip_allocation.IP_ALLOCATION])
        ips = response['port']['fixed_ips']
        self.assertNotEqual(0, len(ips))

    def _create_deferred_ip_port(self, network):
        response = self._create_port(self.fmt,
                                     net_id=network['network']['id'],
                                     tenant_id=network['network']['tenant_id'])
        port = self.deserialize(self.fmt, response)
        ips = port['port']['fixed_ips']
        self.assertEqual(0, len(ips))

        return port

    def test_port_update_deferred_allocation(self):
        """Binding information is provided on update, subnets on segments"""
        network, segment, subnet = self._create_test_segment_with_subnet()

        # Map the host to the segment
        self._setup_host_mappings([(segment['segment']['id'], 'fakehost')])

        port = self._create_deferred_ip_port(network)
        self._validate_deferred_ip_allocation(port['port']['id'])

        # Try requesting an IP (but the only subnet is on a segment)
        data = {'port': {portbindings.HOST_ID: 'fakehost'}}
        port_id = port['port']['id']
        port_req = self.new_update_request('ports', data, port_id)
        response = port_req.get_response(self.api)

        # Port update succeeds and allocates a new IP address.
        self.assertEqual(webob.exc.HTTPOk.code, response.status_int)
        self._assert_one_ip_in_subnet(response, subnet['subnet']['cidr'])

    def test_port_update_deferred_allocation_no_segments(self):
        """Binding information is provided, subnet created after port"""
        with self.network() as network:
            pass

        port = self._create_deferred_ip_port(network)

        # Create the subnet and try to update the port to get an IP
        with self.subnet(network=network):
            data = {'port': {portbindings.HOST_ID: 'fakehost'}}
            port_id = port['port']['id']
            port_req = self.new_update_request('ports', data, port_id)
            response = port_req.get_response(self.api)

        self.assertEqual(webob.exc.HTTPOk.code, response.status_int)
        res = self.deserialize(self.fmt, response)
        self.assertEqual(0, len(res['port']['fixed_ips']))

    def test_port_update_deferred_allocation_no_ipam(self):
        """Binding information is provided on update. Don't allocate."""
        with self.network() as network:
            with self.subnet(network=network):
                pass

        response = self._create_port(self.fmt,
                                     net_id=network['network']['id'],
                                     tenant_id=network['network']['tenant_id'],
                                     fixed_ips=[])
        port = self.deserialize(self.fmt, response)
        ips = port['port']['fixed_ips']
        self.assertEqual(0, len(ips))

        # Create the subnet and try to update the port to get an IP
        data = {'port': {portbindings.HOST_ID: 'fakehost'}}
        port_id = port['port']['id']
        port_req = self.new_update_request('ports', data, port_id)
        response = port_req.get_response(self.api)

        self.assertEqual(webob.exc.HTTPOk.code, response.status_int)
        res = self.deserialize(self.fmt, response)
        self.assertEqual(0, len(res['port']['fixed_ips']))

    def test_port_update_deferred_allocation_no_segments_manual_alloc(self):
        """Binding information is provided, subnet created after port"""
        with self.network() as network:
            pass

        port = self._create_deferred_ip_port(network)

        # Create the subnet and try to update the port to get an IP
        with self.subnet(network=network) as subnet:
            data = {'port': {
                portbindings.HOST_ID: 'fakehost',
                'fixed_ips': [{'subnet_id': subnet['subnet']['id']}]}}
            port_id = port['port']['id']
            port_req = self.new_update_request('ports', data, port_id)
            response = port_req.get_response(self.api)

        self.assertEqual(webob.exc.HTTPOk.code, response.status_int)
        self._assert_one_ip_in_subnet(response, subnet['subnet']['cidr'])

        # Do a show to be sure that only one IP is recorded
        port_req = self.new_show_request('ports', port_id)
        response = port_req.get_response(self.api)
        self.assertEqual(webob.exc.HTTPOk.code, response.status_int)
        self._assert_one_ip_in_subnet(response, subnet['subnet']['cidr'])

    def test_port_update_deferred_allocation_no_segments_empty_alloc(self):
        """Binding information is provided, subnet created after port"""
        with self.network() as network:
            pass

        port = self._create_deferred_ip_port(network)

        # Create the subnet and update the port but specify no IPs
        with self.subnet(network=network):
            data = {'port': {
                portbindings.HOST_ID: 'fakehost',
                'fixed_ips': []}}
            port_id = port['port']['id']
            port_req = self.new_update_request('ports', data, port_id)
            response = port_req.get_response(self.api)

        self.assertEqual(webob.exc.HTTPOk.code, response.status_int)
        res = self.deserialize(self.fmt, response)
        # Since I specifically requested no IP addresses, I shouldn't get one.
        self.assertEqual(0, len(res['port']['fixed_ips']))

    def test_port_update_deferred_allocation_no_host_mapping(self):
        """Binding information is provided on update, subnets on segments"""
        network, segment, subnet = self._create_test_segment_with_subnet()

        port = self._create_deferred_ip_port(network)
        self._validate_deferred_ip_allocation(port['port']['id'])

        # Try requesting an IP (but the only subnet is on a segment)
        data = {'port': {portbindings.HOST_ID: 'fakehost'}}
        port_id = port['port']['id']
        port_req = self.new_update_request('ports', data, port_id)
        response = port_req.get_response(self.api)
        res = self.deserialize(self.fmt, response)

        # Gets conflict because it can't map the host to a segment
        self.assertEqual(webob.exc.HTTPConflict.code, response.status_int)
        self.assertEqual(segment_exc.HostNotConnectedToAnySegment.__name__,
                         res['NeutronError']['type'])

    def test_port_update_deferred_allocation_multiple_host_mapping(self):
        """Binding information is provided on update, subnets on segments"""
        network, segments, _s = self._create_test_segments_with_subnets(2)

        port = self._create_deferred_ip_port(network)
        self._validate_deferred_ip_allocation(port['port']['id'])

        # This host is bound to multiple segments
        self._setup_host_mappings([(segments[0]['segment']['id'], 'fakehost'),
                                   (segments[1]['segment']['id'], 'fakehost')])

        # Try requesting an IP (but the only subnet is on a segment)
        data = {'port': {portbindings.HOST_ID: 'fakehost'}}
        port_id = port['port']['id']
        port_req = self.new_update_request('ports', data, port_id)
        response = port_req.get_response(self.api)
        res = self.deserialize(self.fmt, response)

        # Gets conflict because it can't map the host to a segment
        self.assertEqual(webob.exc.HTTPConflict.code, response.status_int)
        self.assertEqual(segment_exc.HostConnectedToMultipleSegments.__name__,
                         res['NeutronError']['type'])

    def test_port_update_allocate_no_segments(self):
        """Binding information is provided, subnet created after port"""
        with self.network() as network:
            pass

        # Create a bound port with no IP address (since there is not subnet)
        port = self._create_deferred_ip_port(network)

        # Create the subnet and try to update the port to get an IP
        with self.subnet(network=network) as subnet:
            # Try requesting an IP (but the only subnet is on a segment)
            data = {'port': {
                'fixed_ips': [{'subnet_id': subnet['subnet']['id']}]}}
            port_id = port['port']['id']
            port_req = self.new_update_request('ports', data, port_id)
            response = port_req.get_response(self.api)

        # Since port is bound and there is a mapping to segment, it succeeds.
        self.assertEqual(webob.exc.HTTPOk.code, response.status_int)
        self._assert_one_ip_in_subnet(response, subnet['subnet']['cidr'])

    def test_port_update_deferred_allocation_no_ips(self):
        """Binding information is provided on update, subnets on segments"""
        network, segments, subnets = self._create_test_segments_with_subnets(2)

        self._setup_host_mappings([(segments[0]['segment']['id'], 'fakehost2'),
                                   (segments[1]['segment']['id'], 'fakehost')])

        port = self._create_deferred_ip_port(network)

        # Update the subnet on the second segment to be out of IPs
        subnet_data = {'subnet': {'allocation_pools': []}}
        subnet_req = self.new_update_request('subnets',
                                             subnet_data,
                                             subnets[1]['subnet']['id'])
        subnet_response = subnet_req.get_response(self.api)
        res = self.deserialize(self.fmt, subnet_response)

        # Try requesting an IP (but the subnet ran out of ips)
        data = {'port': {portbindings.HOST_ID: 'fakehost'}}
        port_id = port['port']['id']
        port_req = self.new_update_request('ports', data, port_id)
        response = port_req.get_response(self.api)
        res = self.deserialize(self.fmt, response)

        # Since port is bound and there is a mapping to segment, it succeeds.
        self.assertEqual(webob.exc.HTTPConflict.code, response.status_int)
        self.assertEqual(n_exc.IpAddressGenerationFailure.__name__,
                         res['NeutronError']['type'])

    def test_port_update_fails_if_host_on_wrong_segment(self):
        """Update a port with existing IPs to a host where they don't work"""
        network, segments, subnets = self._create_test_segments_with_subnets(2)

        self._setup_host_mappings([(segments[0]['segment']['id'], 'fakehost2'),
                                   (segments[1]['segment']['id'], 'fakehost')])

        # Create a bound port with an IP address
        response = self._create_port(self.fmt,
                                     net_id=network['network']['id'],
                                     tenant_id=network['network']['tenant_id'],
                                     arg_list=(portbindings.HOST_ID,),
                                     **{portbindings.HOST_ID: 'fakehost'})
        self._assert_one_ip_in_subnet(response, subnets[1]['subnet']['cidr'])
        port = self.deserialize(self.fmt, response)

        # Now, try to update binding to a host on the other segment
        data = {'port': {portbindings.HOST_ID: 'fakehost2'}}
        port_req = self.new_update_request('ports', data, port['port']['id'])
        response = port_req.get_response(self.api)

        # It fails since the IP address isn't compatible with the new segment
        self.assertEqual(webob.exc.HTTPConflict.code, response.status_int)

    def test_port_update_fails_if_host_on_good_segment(self):
        """Update a port with existing IPs to a host where they don't work"""
        network, segments, subnets = self._create_test_segments_with_subnets(2)

        self._setup_host_mappings([(segments[0]['segment']['id'], 'fakehost2'),
                                   (segments[1]['segment']['id'], 'fakehost1'),
                                   (segments[1]['segment']['id'], 'fakehost')])

        # Create a bound port with an IP address
        response = self._create_port(self.fmt,
                                     net_id=network['network']['id'],
                                     tenant_id=network['network']['tenant_id'],
                                     arg_list=(portbindings.HOST_ID,),
                                     **{portbindings.HOST_ID: 'fakehost'})
        self._assert_one_ip_in_subnet(response, subnets[1]['subnet']['cidr'])
        port = self.deserialize(self.fmt, response)

        # Now, try to update binding to another host in same segment
        data = {'port': {portbindings.HOST_ID: 'fakehost1'}}
        port_req = self.new_update_request('ports', data, port['port']['id'])
        response = port_req.get_response(self.api)

        # Since the new host is in the same segment, it succeeds.
        self.assertEqual(webob.exc.HTTPOk.code, response.status_int)


class TestSegmentAwareIpamML2(TestSegmentAwareIpam):
    def setUp(self):
        config.cfg.CONF.set_override('network_vlan_ranges',
                                     ['physnet:200:209', 'physnet0:200:209',
                                      'physnet1:200:209', 'physnet2:200:209'],
                                     group='ml2_type_vlan')
        super(TestSegmentAwareIpamML2, self).setUp(plugin='ml2')


class TestDhcpAgentSegmentScheduling(HostSegmentMappingTestCase):

    _mechanism_drivers = ['openvswitch', 'logger']
    mock_path = 'neutron.services.segments.db.update_segment_host_mapping'

    def setUp(self):
        super(TestDhcpAgentSegmentScheduling, self).setUp()
        self.dhcp_agent_db = agentschedulers_db.DhcpAgentSchedulerDbMixin()
        self.ctx = context.get_admin_context()

    def _test_create_network_and_segment(self, phys_net):
        with self.network() as net:
            network = net['network']
        segment = self._test_create_segment(network_id=network['id'],
                                            physical_network=phys_net,
                                            segmentation_id=200,
                                            network_type='vlan')
        dhcp_agents = self.dhcp_agent_db.get_dhcp_agents_hosting_networks(
            self.ctx, [network['id']])
        self.assertEqual(0, len(dhcp_agents))
        return network, segment['segment']

    def _test_create_subnet(self, network, segment, cidr=None,
                            enable_dhcp=True):
        cidr = cidr or '10.0.0.0/24'
        ip_version = 4
        with self.subnet(network={'network': network},
                         segment_id=segment['id'],
                         ip_version=ip_version,
                         cidr=cidr,
                         enable_dhcp=enable_dhcp) as subnet:
            pass
        return subnet['subnet']

    def _register_dhcp_agents(self, hosts=None):
        hosts = hosts or [DHCP_HOSTA, DHCP_HOSTB]
        for host in hosts:
            helpers.register_dhcp_agent(host)

    def test_network_scheduling_on_segment_creation(self):
        self._register_dhcp_agents()
        self._test_create_network_and_segment('phys_net1')

    def test_segment_scheduling_no_host_mapping(self):
        self._register_dhcp_agents()
        network, segment = self._test_create_network_and_segment('phys_net1')
        self._test_create_subnet(network, segment)
        dhcp_agents = self.dhcp_agent_db.get_dhcp_agents_hosting_networks(
            self.ctx, [network['id']])
        self.assertEqual(0, len(dhcp_agents))

    def test_segment_scheduling_with_host_mapping(self):
        phys_net1 = 'phys_net1'
        self._register_dhcp_agents()
        network, segment = self._test_create_network_and_segment(phys_net1)
        self._register_agent(DHCP_HOSTA,
                             mappings={phys_net1: 'br-eth-1'},
                             plugin=self.plugin)
        self._test_create_subnet(network, segment)
        dhcp_agents = self.dhcp_agent_db.get_dhcp_agents_hosting_networks(
            self.ctx, [network['id']])
        self.assertEqual(1, len(dhcp_agents))
        self.assertEqual(DHCP_HOSTA, dhcp_agents[0]['host'])

    def test_segment_scheduling_with_multiple_host_mappings(self):
        phys_net1 = 'phys_net1'
        phys_net2 = 'phys_net2'
        self._register_dhcp_agents([DHCP_HOSTA, DHCP_HOSTB, 'MEHA', 'MEHB'])
        network, segment1 = self._test_create_network_and_segment(phys_net1)
        segment2 = self._test_create_segment(network_id=network['id'],
                                             physical_network=phys_net2,
                                             segmentation_id=200,
                                             network_type='vlan')['segment']
        self._register_agent(DHCP_HOSTA,
                             mappings={phys_net1: 'br-eth-1'},
                             plugin=self.plugin)
        self._register_agent(DHCP_HOSTB,
                             mappings={phys_net2: 'br-eth-1'},
                             plugin=self.plugin)
        self._test_create_subnet(network, segment1)
        self._test_create_subnet(network, segment2, cidr='11.0.0.0/24')
        dhcp_agents = self.dhcp_agent_db.get_dhcp_agents_hosting_networks(
            self.ctx, [network['id']])
        self.assertEqual(2, len(dhcp_agents))
        agent_hosts = [agent['host'] for agent in dhcp_agents]
        self.assertIn(DHCP_HOSTA, agent_hosts)
        self.assertIn(DHCP_HOSTB, agent_hosts)
