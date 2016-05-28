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
from neutron_lib import constants
from oslo_utils import uuidutils
import webob.exc

from neutron.api.v2 import attributes
from neutron import context
from neutron.db import agents_db
from neutron.db import db_base_plugin_v2
from neutron.db import segments_db
from neutron.extensions import segment as ext_segment
from neutron.plugins.common import constants as p_constants
from neutron.plugins.ml2 import config
from neutron.services.segments import db
from neutron.tests.common import helpers
from neutron.tests.unit.db import test_db_base_plugin_v2

SERVICE_PLUGIN_KLASS = 'neutron.services.segments.plugin.Plugin'
TEST_PLUGIN_KLASS = (
    'neutron.tests.unit.extensions.test_segment.SegmentTestPlugin')


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
            segment['segment'][k] = str(v)

        segment_req = self.new_create_request(
            'segments', segment, fmt)

        segment_res = segment_req.get_response(self.ext_api)
        if expected_res_status:
            self.assertEqual(segment_res.status_int, expected_res_status)
        return segment_res

    def _make_segment(self, fmt, **kwargs):
        res = self._create_segment(fmt, **kwargs)
        if res.status_int >= webob.exc.HTTPClientError.code:
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
                        db.SegmentDbMixin):
    __native_pagination_support = True
    __native_sorting_support = True

    supported_extension_aliases = ["segment"]

    def get_plugin_description(self):
        return "Network Segments"

    def get_plugin_type(self):
        return "segments"


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
        with self.network() as network:
            network = network['network']
        expected_segment = {'network_id': network['id'],
                            'physical_network': 'phys_net',
                            'network_type': 'net_type',
                            'segmentation_id': None}
        self._test_create_segment(network_id=network['id'],
                                  physical_network='phys_net',
                                  expected=expected_segment)

    def test_delete_segment(self):
        with self.network() as network:
            network = network['network']
        segment = self.segment(network_id=network['id'])
        self._delete('segments', segment['segment']['id'])
        self._show('segments', segment['segment']['id'],
                   expected_code=webob.exc.HTTPNotFound.code)

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
                                  segmentation_id=200)
        res = self._list('segments')
        self.assertEqual(2, len(res['segments']))


class TestSegmentSubnetAssociation(SegmentTestCase):
    def test_basic_association(self):
        with self.network() as network:
            net = network['network']

        segment = self._test_create_segment(network_id=net['id'])
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

        segment = self._test_create_segment(network_id=net['id'])

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

        segment = self._test_create_segment(network_id=net['id'])

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
        segments_db.add_network_segment(cxt.session,
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

    def test_port_create_with_segment_subnets(self):
        with self.network() as network:
            net = network['network']

        segment = self._test_create_segment(network_id=net['id'])
        segment_id = segment['segment']['id']

        with self.subnet(network=network, segment_id=segment_id) as subnet:
            subnet = subnet['subnet']

        response = self._create_port(self.fmt,
                                     net_id=net['id'],
                                     tenant_id=net['tenant_id'])
        res = self.deserialize(self.fmt, response)
        # Don't allocate IPs in this case because it doesn't have binding info
        self.assertEqual(0, len(res['port']['fixed_ips']))


class HostSegmentMappingTestCase(SegmentTestCase):
    _mechanism_drivers = ['logger']

    def setUp(self, plugin=None):
        config.cfg.CONF.set_override('mechanism_drivers',
                                     self._mechanism_drivers,
                                     group='ml2')
        if not plugin:
            plugin = 'neutron.plugins.ml2.plugin.Ml2Plugin'
        super(HostSegmentMappingTestCase, self).setUp(plugin=plugin)

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
