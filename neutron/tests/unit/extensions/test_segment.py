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

import copy

import mock
import netaddr
from neutron_lib.api.definitions import ip_allocation as ipalloc_apidef
from neutron_lib.api.definitions import l2_adjacency as l2adj_apidef
from neutron_lib.api.definitions import port as port_apidef
from neutron_lib.api.definitions import portbindings
from neutron_lib.api.definitions import segment as seg_apidef
from neutron_lib.callbacks import events
from neutron_lib.callbacks import exceptions
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants
from neutron_lib import context
from neutron_lib import exceptions as n_exc
from neutron_lib.exceptions import placement as placement_exc
from neutron_lib.plugins import directory
from novaclient import exceptions as nova_exc
from oslo_config import cfg
from oslo_utils import uuidutils
import webob.exc

from neutron.conf.plugins.ml2 import config as ml2_config
from neutron.conf.plugins.ml2.drivers import driver_type
from neutron.db import agents_db
from neutron.db import agentschedulers_db
from neutron.db import db_base_plugin_v2
from neutron.db import portbindings_db
from neutron.db import segments_db
from neutron.extensions import segment as ext_segment
from neutron.extensions import standardattrdescription as ext_stddesc
from neutron.objects import network
from neutron.services.segments import db
from neutron.services.segments import exceptions as segment_exc
from neutron.services.segments import plugin as seg_plugin
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
        ext_segment.Segment().update_attributes_map(
            {ext_segment.SEGMENTS: ext_stddesc.DESCRIPTION_BODY})
        return ext_segment.Segment.get_resources()

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


class SegmentTestCase(test_db_base_plugin_v2.NeutronDbPluginV2TestCase):

    def setUp(self, plugin=None):
        # Remove MissingAuthPlugin exception from logs
        self.patch_notifier = mock.patch(
            'neutron.notifiers.batch_notifier.BatchNotifier._notify')
        self.patch_notifier.start()
        if not plugin:
            plugin = TEST_PLUGIN_KLASS
        service_plugins = {'segments_plugin_name': SERVICE_PLUGIN_KLASS}
        cfg.CONF.set_override('service_plugins', [SERVICE_PLUGIN_KLASS])
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

    supported_extension_aliases = [seg_apidef.ALIAS, portbindings.ALIAS,
                                   ipalloc_apidef.ALIAS]

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
            d.setdefault('description', 'desc')
            d.setdefault('physical_network', 'phys_net')
            d.setdefault('network_type', 'net_type')
            d.setdefault('segmentation_id', 200)
        return super(TestSegmentNameDescription, self)._test_create_segment(
            expected, **kwargs)

    def test_create_segment_no_name(self):
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
        self._update('segments', segment['segment']['id'],
                     {'segment': {'description': None}},
                     expected_code=webob.exc.HTTPBadRequest.code)


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

        network_segments = segments_db.get_network_segments(cxt, network['id'])
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
            network_segments = segments_db.get_network_segments(cxt,
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

    def test_list_segments_with_sort(self):
        with self.network() as network:
            network = network['network']
        s1 = self._test_create_segment(network_id=network['id'],
                                       physical_network='phys_net1',
                                       segmentation_id=200)
        s2 = self._test_create_segment(network_id=network['id'],
                                       physical_network='phys_net2',
                                       segmentation_id=201)
        self._test_list_with_sort('segment',
                                  (s2, s1),
                                  [('physical_network', 'desc')],
                                  query_params='network_id=%s' % network['id'])

    def test_list_segments_with_pagination(self):
        with self.network() as network:
            network = network['network']
        s1 = self._test_create_segment(network_id=network['id'],
                                       physical_network='phys_net1',
                                       segmentation_id=200)
        s2 = self._test_create_segment(network_id=network['id'],
                                       physical_network='phys_net2',
                                       segmentation_id=201)
        s3 = self._test_create_segment(network_id=network['id'],
                                       physical_network='phys_net3',
                                       segmentation_id=202)
        self._test_list_with_pagination(
            'segment',
            (s1, s2, s3),
            ('physical_network', 'asc'), 2, 2,
            query_params='network_id=%s' % network['id'])

    def test_list_segments_with_pagination_reverse(self):
        with self.network() as network:
            network = network['network']
        s1 = self._test_create_segment(network_id=network['id'],
                                       physical_network='phys_net1',
                                       segmentation_id=200)
        s2 = self._test_create_segment(network_id=network['id'],
                                       physical_network='phys_net2',
                                       segmentation_id=201)
        s3 = self._test_create_segment(network_id=network['id'],
                                       physical_network='phys_net3',
                                       segmentation_id=202)
        self._test_list_with_pagination_reverse(
            'segment',
            (s1, s2, s3),
            ('physical_network', 'asc'), 2, 2,
            query_params='network_id=%s' % network['id'])

    def test_update_segments(self):
        with self.network() as network:
            net = network['network']
            segment = self._test_create_segment(network_id=net['id'],
                                                segmentation_id=200)
            segment['segment']['segmentation_id'] = '201'
            self._update('segments', segment['segment']['id'], segment,
                         expected_code=webob.exc.HTTPClientError.code)

    def test_segment_notification_on_delete_network(self):
        with mock.patch.object(db, '_delete_segments_for_network') as dsn:
            db.subscribe()
            with self.network() as network:
                network = network['network']
                self._delete('networks', network['id'])
        dsn.assert_called_with(resources.NETWORK,
                               events.PRECOMMIT_DELETE,
                               mock.ANY,
                               context=mock.ANY,
                               network_id=mock.ANY,
                               network=mock.ANY)


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

    def test_associate_existing_subnet_with_segment(self):
        with self.network() as network:
            net = network['network']

        segment = self._test_create_segment(network_id=net['id'],
                                            physical_network='phys_net',
                                            segmentation_id=200)['segment']
        with self.subnet(network=network, segment_id=None) as subnet:
            subnet = subnet['subnet']

        data = {'subnet': {'segment_id': segment['id']}}
        request = self.new_update_request('subnets', data, subnet['id'])
        response = request.get_response(self.api)
        res = self.deserialize(self.fmt, response)

        self.assertEqual(webob.exc.HTTPOk.code, response.status_int)
        self.assertEqual(res['subnet']['segment_id'], segment['id'])

    def test_update_subnet_with_current_segment_id(self):
        with self.network() as network:
            net = network['network']

        segment1 = self._test_create_segment(network_id=net['id'],
                                            physical_network='phys_net1',
                                            segmentation_id=200)['segment']
        self._test_create_segment(network_id=net['id'],
                                  physical_network='phys_net2',
                                  segmentation_id=200)['segment']
        with self.subnet(network=network, segment_id=segment1['id']) as subnet:
            subnet = subnet['subnet']

        data = {'subnet': {'segment_id': segment1['id']}}
        request = self.new_update_request('subnets', data, subnet['id'])
        response = request.get_response(self.api)
        res = self.deserialize(self.fmt, response)

        self.assertEqual(webob.exc.HTTPOk.code, response.status_int)
        self.assertEqual(res['subnet']['segment_id'], segment1['id'])

    def test_associate_existing_subnet_fail_if_multiple_segments(self):
        with self.network() as network:
            net = network['network']

        segment1 = self._test_create_segment(network_id=net['id'],
                                             physical_network='phys_net1',
                                             segmentation_id=201)['segment']
        self._test_create_segment(network_id=net['id'],
                                  physical_network='phys_net2',
                                  segmentation_id=202)['segment']

        with self.subnet(network=network, segment_id=None) as subnet:
            subnet = subnet['subnet']

        data = {'subnet': {'segment_id': segment1['id']}}
        request = self.new_update_request('subnets', data, subnet['id'])
        response = request.get_response(self.api)

        self.assertEqual(webob.exc.HTTPBadRequest.code, response.status_int)

    def test_associate_existing_subnet_fail_if_multiple_subnets(self):
        with self.network() as network:
            net = network['network']

        segment1 = self._test_create_segment(network_id=net['id'],
                                             physical_network='phys_net1',
                                             segmentation_id=201)['segment']

        with self.subnet(network=network, segment_id=None,
                         ip_version=constants.IP_VERSION_4,
                         cidr='10.0.0.0/24') as subnet1, \
                self.subnet(network=network, segment_id=None,
                            ip_version=constants.IP_VERSION_4,
                            cidr='10.0.1.0/24') as subnet2:
            subnet1 = subnet1['subnet']
            subnet2 = subnet2['subnet']

        data = {'subnet': {'segment_id': segment1['id']}}
        request = self.new_update_request('subnets', data, subnet1['id'])
        response = request.get_response(self.api)

        self.assertEqual(webob.exc.HTTPBadRequest.code, response.status_int)

    def test_change_existing_subnet_segment_association_not_allowed(self):
        with self.network() as network:
            net = network['network']

        segment1 = self._test_create_segment(network_id=net['id'],
                                            physical_network='phys_net2',
                                            segmentation_id=201)['segment']

        with self.subnet(network=network, segment_id=segment1['id']) as subnet:
            subnet = subnet['subnet']

        segment2 = self._test_create_segment(network_id=net['id'],
                                             physical_network='phys_net2',
                                             segmentation_id=202)['segment']

        data = {'subnet': {'segment_id': segment2['id']}}
        request = self.new_update_request('subnets', data, subnet['id'])
        response = request.get_response(self.api)

        self.assertEqual(webob.exc.HTTPBadRequest.code, response.status_int)


class HostSegmentMappingTestCase(SegmentTestCase):
    _mechanism_drivers = ['logger']

    def setUp(self, plugin=None):
        cfg.CONF.set_override('mechanism_drivers',
                              self._mechanism_drivers,
                              group='ml2')

        # NOTE(dasm): ml2_type_vlan requires to be registered before used.
        # This piece was refactored and removed from .config, so it causes
        # a problem, when tests are executed with pdb.
        # There is no problem when tests are running without debugger.
        driver_type.register_ml2_drivers_vlan_opts()

        cfg.CONF.set_override('network_vlan_ranges',
                              ['phys_net1', 'phys_net2'],
                              group='ml2_type_vlan')
        if not plugin:
            plugin = 'ml2'
        super(HostSegmentMappingTestCase, self).setUp(plugin=plugin)
        db.subscribe()

    def _get_segments_for_host(self, host):
        ctx = context.get_admin_context()
        segment_host_mapping = network.SegmentHostMapping.get_objects(
            ctx, host=host)
        return {seg_host['segment_id']: seg_host
                for seg_host in segment_host_mapping}

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
            segmentation_id=200, network_type=constants.TYPE_VLAN)['segment']
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
            segmentation_id=200, network_type=constants.TYPE_VLAN)['segment']
        self._test_create_segment(
            network_id=network['id'], physical_network='phys_net2',
            segmentation_id=201, network_type=constants.TYPE_VLAN)['segment']
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
            segmentation_id=200, network_type=constants.TYPE_VLAN)['segment']
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
                segmentation_id=200 + i, network_type=constants.TYPE_VLAN)
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
                network_type=constants.TYPE_VLAN)['segment'])
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
            network_type=constants.TYPE_VLAN)['segment']
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
            network_type=constants.TYPE_VLAN)['segment']
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
            segmentation_id=201, network_type=constants.TYPE_VLAN)['segment']
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
            segmentation_id=200, network_type=constants.TYPE_VLAN)
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
                                  network_type=constants.TYPE_VLAN)
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
        self.assertIn(host, db.reported_hosts)
        self.assertEqual(1, mock_function.call_count)
        expected_call = mock.call(mock.ANY, host, set())
        mock_function.assert_has_calls([expected_call])

    @mock.patch(mock_path)
    def test_starting_agent_is_processed(self, mock_function):
        host = 'starting_agent'
        physical_network = 'phys_net1'
        self._register_agent(host, mappings={physical_network: 'br-eth-1'},
                             plugin=self.plugin, start_flag=False)
        self.assertIn(host, db.reported_hosts)
        self._register_agent(host, mappings={physical_network: 'br-eth-1'},
                             plugin=self.plugin, start_flag=True)
        self.assertIn(host, db.reported_hosts)
        self.assertEqual(2, mock_function.call_count)
        expected_call = mock.call(mock.ANY, host, set())
        mock_function.assert_has_calls([expected_call, expected_call])

    @mock.patch(mock_path)
    def test_no_starting_agent_is_not_processed(self, mock_function):
        host = 'agent_with_no_start_update'
        physical_network = 'phys_net1'
        self._register_agent(host, mappings={physical_network: 'br-eth-1'},
                             plugin=self.plugin, start_flag=False)
        self.assertIn(host, db.reported_hosts)
        mock_function.reset_mock()
        self._register_agent(host, mappings={physical_network: 'br-eth-1'},
                             plugin=self.plugin, start_flag=False)
        self.assertIn(host, db.reported_hosts)
        mock_function.assert_not_called()


class SegmentAwareIpamTestCase(SegmentTestCase):

    def _setup_host_mappings(self, mappings=()):
        ctx = context.get_admin_context()
        for segment_id, host in mappings:
            network.SegmentHostMapping(
                ctx, segment_id=segment_id, host=host).create()

    def _create_test_segment_with_subnet(self,
                                         network=None,
                                         cidr='2001:db8:0:0::/64',
                                         physnet='physnet'):
        """Creates one network with one segment and one subnet"""
        network, segment = self._create_test_network_and_segment(network,
                                                                 physnet)
        subnet = self._create_test_subnet_with_segment(network, segment, cidr)
        return network, segment, subnet

    def _create_test_network_and_segment(self, network=None,
                                         physnet='physnet'):
        if not network:
            with self.network() as network:
                pass

        segment = self._test_create_segment(
            network_id=network['network']['id'],
            physical_network=physnet,
            network_type=constants.TYPE_VLAN)
        return network, segment

    def _create_test_subnet_with_segment(self, network, segment,
                                         cidr='2001:db8:0:0::/64',
                                         allocation_pools=None):
        ip_version = netaddr.IPNetwork(cidr).version if cidr else None
        with self.subnet(network=network,
                         segment_id=segment['segment']['id'],
                         ip_version=ip_version,
                         cidr=cidr,
                         allocation_pools=allocation_pools) as subnet:
            self._validate_l2_adjacency(network['network']['id'],
                                        is_adjacent=False)
            return subnet

    def _create_test_slaac_subnet_with_segment(
            self, network, segment, cidr='2001:db8:0:0::/64'):
        with self.subnet(network=network,
                         segment_id=segment['segment']['id'],
                         ip_version=constants.IP_VERSION_6,
                         ipv6_ra_mode=constants.IPV6_SLAAC,
                         ipv6_address_mode=constants.IPV6_SLAAC,
                         cidr=cidr,
                         allocation_pools=None) as subnet:
            self._validate_l2_adjacency(network['network']['id'],
                                        is_adjacent=False)
            return subnet

    def _validate_l2_adjacency(self, network_id, is_adjacent):
        request = self.new_show_request('networks', network_id)
        response = self.deserialize(self.fmt, request.get_response(self.api))
        self.assertEqual(is_adjacent,
                         response['network'][l2adj_apidef.L2_ADJACENCY])


class TestSegmentAwareIpam(SegmentAwareIpamTestCase):

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

    def _create_net_two_segments_four_slaac_subnets(self):
        with self.network() as network:
            segment_a = self._test_create_segment(
                network_id=network['network']['id'],
                physical_network='physnet_a',
                network_type=constants.TYPE_FLAT)
            segment_b = self._test_create_segment(
                network_id=network['network']['id'],
                physical_network='physnet_b',
                network_type=constants.TYPE_FLAT)
            subnet_a0 = self._create_test_slaac_subnet_with_segment(
                network, segment_a, '2001:db8:a:0::/64')
            subnet_a1 = self._create_test_slaac_subnet_with_segment(
                network, segment_a, '2001:db8:a:1::/64')
            subnet_b0 = self._create_test_slaac_subnet_with_segment(
                network, segment_b, '2001:db8:b:0::/64')
            subnet_b1 = self._create_test_slaac_subnet_with_segment(
                network, segment_b, '2001:db8:b:1::/64')
            return (network, segment_a, segment_b, subnet_a0, subnet_a1,
                    subnet_b0, subnet_b1)

    def test_port_create_with_segment_subnets(self):
        """No binding information is provided, defer IP allocation"""
        network, segment, subnet = self._create_test_segment_with_subnet()
        response = self._create_port(self.fmt,
                                     net_id=network['network']['id'],
                                     tenant_id=network['network']['tenant_id'])
        res = self.deserialize(self.fmt, response)
        # Don't allocate IPs in this case because we didn't give binding info
        self.assertEqual(0, len(res['port']['fixed_ips']))

    def test_port_create_fixed_ips_with_segment_subnets_no_binding_info(self):
        """Fixed IP provided and no binding info, do not defer IP allocation"""
        network, segment, subnet = self._create_test_segment_with_subnet()
        response = self._create_port(self.fmt,
                                     net_id=network['network']['id'],
                                     tenant_id=network['network']['tenant_id'],
                                     fixed_ips=[
                                         {'subnet_id': subnet['subnet']['id']}
                                     ])
        res = self.deserialize(self.fmt, response)
        # We gave fixed_ips, allocate IPs in this case despite no binding info
        self._validate_immediate_ip_allocation(res['port']['id'])

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
                network_type=constants.TYPE_VLAN)

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
                             ip_version=constants.IP_VERSION_6,
                             cidr='2001:db8:0:0::/64') as subnet:
                segment = self._test_create_segment(
                    network_id=network['network']['id'],
                    physical_network='physnet',
                    network_type=constants.TYPE_VLAN)

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

    def test_port_update_with_fixed_ips_ok_if_no_binding_host(self):
        """No binding host information is provided, subnets on segments"""
        with self.network() as network:
            segment = self._test_create_segment(
                network_id=network['network']['id'],
                physical_network='physnet',
                network_type=constants.TYPE_VLAN)

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

        # The IP is allocated since there is no binding host info any
        # subnet can be used for allocation.
        self.assertEqual(webob.exc.HTTPOk.code, response.status_int)

    def test_port_update_with_fixed_ips_fail_if_host_not_on_segment(self):
        """Binding information is provided, subnets on segments. Update to
        subnet on different segment fails.
        """
        network, segments, subnets = self._create_test_segments_with_subnets(2)

        # Setup host mappings
        self._setup_host_mappings([(segments[0]['segment']['id'], 'fakehost')])

        # Create a port and validate immediate ip allocation
        res = self._create_port_and_show(network,
                                         arg_list=(portbindings.HOST_ID,),
                                         **{portbindings.HOST_ID: 'fakehost'})
        self._validate_immediate_ip_allocation(res['port']['id'])

        # Try requesting an new IP, but the subnet does not match host segment
        port_id = res['port']['id']
        data = {'port': {
            'fixed_ips': [{'subnet_id': subnets[1]['subnet']['id']}]}}
        port_req = self.new_update_request('ports', data, port_id)
        response = port_req.get_response(self.api)

        # Port update fails.
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
                network_type=constants.TYPE_VLAN)
            with self.subnet(network=network,
                             segment_id=segment['segment']['id']):
                pass

        # Create an unbound port requesting no IP addresses
        response = self._create_port_and_show(network, fixed_ips=[])
        self.assertEqual([], response['port']['fixed_ips'])
        self.assertEqual(ipalloc_apidef.IP_ALLOCATION_NONE,
                         response['port'][ipalloc_apidef.IP_ALLOCATION])

    def test_port_create_with_no_fixed_ips_no_ipam(self):
        """Ports without addresses on non-routed networks are not deferred"""
        with self.network() as network:
            with self.subnet(network=network):
                pass

        # Create an unbound port requesting no IP addresses
        response = self._create_port_and_show(network, fixed_ips=[])

        self.assertEqual([], response['port']['fixed_ips'])
        self.assertEqual(ipalloc_apidef.IP_ALLOCATION_NONE,
                         response['port'][ipalloc_apidef.IP_ALLOCATION])

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
        self.assertEqual(ipalloc_apidef.IP_ALLOCATION_IMMEDIATE,
                         response['port'][ipalloc_apidef.IP_ALLOCATION])

    def test_port_without_ip_not_deferred_no_binding(self):
        """Ports without addresses on non-routed networks are not deferred"""
        with self.network() as network:
            pass

        # Create a unbound port with no IP address (since there is no subnet)
        response = self._create_port_and_show(network)
        self.assertEqual([], response['port']['fixed_ips'])
        self.assertEqual(ipalloc_apidef.IP_ALLOCATION_IMMEDIATE,
                         response['port'][ipalloc_apidef.IP_ALLOCATION])

    def test_port_update_is_host_aware(self):
        """Binding information is provided, subnets on segments"""
        with self.network() as network:
            segment = self._test_create_segment(
                network_id=network['network']['id'],
                physical_network='physnet',
                network_type=constants.TYPE_VLAN)

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

    def _validate_deferred_ip_allocation(self, port_id):
        request = self.new_show_request('ports', port_id)
        response = self.deserialize(self.fmt, request.get_response(self.api))

        self.assertEqual(ipalloc_apidef.IP_ALLOCATION_DEFERRED,
                         response['port'][ipalloc_apidef.IP_ALLOCATION])
        ips = response['port']['fixed_ips']
        self.assertEqual(0, len(ips))

    def _validate_immediate_ip_allocation(self, port_id):
        request = self.new_show_request('ports', port_id)
        response = self.deserialize(self.fmt, request.get_response(self.api))

        self.assertEqual(ipalloc_apidef.IP_ALLOCATION_IMMEDIATE,
                         response['port'][ipalloc_apidef.IP_ALLOCATION])
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

    def test_port_update_deferred_allocation_binding_info_and_new_mac(self):
        """Binding information and new mac address is provided on update"""
        network, segment, subnet = self._create_test_segment_with_subnet()

        # Map the host to the segment
        self._setup_host_mappings([(segment['segment']['id'], 'fakehost')])

        port = self._create_deferred_ip_port(network)
        self._validate_deferred_ip_allocation(port['port']['id'])

        # Try requesting an IP (but the only subnet is on a segment)
        data = {'port': {portbindings.HOST_ID: 'fakehost',
                         port_apidef.PORT_MAC_ADDRESS: '00:00:00:00:00:01'}}
        port_id = port['port']['id']
        port_req = self.new_update_request('ports', data, port_id)
        response = port_req.get_response(self.api)

        # Port update succeeds and allocates a new IP address.
        self.assertEqual(webob.exc.HTTPOk.code, response.status_int)
        self._assert_one_ip_in_subnet(response, subnet['subnet']['cidr'])

    def test_slaac_segment_aware_no_binding_info(self):
        (network, segment_a, segment_b, subnet_a0, subnet_a1, subnet_b0,
         subnet_b1) = self._create_net_two_segments_four_slaac_subnets()

        # Create a port with no IP address (since there is no subnet)
        port_deferred = self._create_deferred_ip_port(network)
        self._validate_deferred_ip_allocation(port_deferred['port']['id'])

    def test_slaac_segment_aware_immediate_fixed_ips_no_binding_info_(self):
        (network, segment_a, segment_b, subnet_a0, subnet_a1, subnet_b0,
         subnet_b1) = self._create_net_two_segments_four_slaac_subnets()

        # Create two ports, port_a with subnet_a0 in fixed_ips and port_b
        # with subnet_b0 in fixed_ips
        port_a = self._create_port_and_show(
            network, fixed_ips=[{'subnet_id': subnet_a0['subnet']['id']}])
        port_b = self._create_port_and_show(
            network, fixed_ips=[{'subnet_id': subnet_b0['subnet']['id']}])
        self._validate_immediate_ip_allocation(port_a['port']['id'])
        self._validate_immediate_ip_allocation(port_b['port']['id'])
        self.assertEqual(2, len(port_a['port']['fixed_ips']))
        self.assertEqual(2, len(port_b['port']['fixed_ips']))
        port_a_snet_ids = [f['subnet_id'] for f in port_a['port']['fixed_ips']]
        port_b_snet_ids = [f['subnet_id'] for f in port_b['port']['fixed_ips']]
        self.assertIn(subnet_a0['subnet']['id'], port_a_snet_ids)
        self.assertIn(subnet_a1['subnet']['id'], port_a_snet_ids)
        self.assertIn(subnet_b0['subnet']['id'], port_b_snet_ids)
        self.assertIn(subnet_b1['subnet']['id'], port_b_snet_ids)
        self.assertNotIn(subnet_a0['subnet']['id'], port_b_snet_ids)
        self.assertNotIn(subnet_a1['subnet']['id'], port_b_snet_ids)
        self.assertNotIn(subnet_b0['subnet']['id'], port_a_snet_ids)
        self.assertNotIn(subnet_b1['subnet']['id'], port_a_snet_ids)

    def test_slaac_segment_aware_immediate_with_binding_info(self):
        (network, segment_a, segment_b, subnet_a0, subnet_a1, subnet_b0,
         subnet_b1) = self._create_net_two_segments_four_slaac_subnets()

        self._setup_host_mappings([(segment_a['segment']['id'], 'fakehost_a')])

        # Create a port with host ID, validate immediate allocation on subnets
        # with correct segment_id.
        response = self._create_port(self.fmt,
                                     net_id=network['network']['id'],
                                     tenant_id=network['network']['tenant_id'],
                                     arg_list=(portbindings.HOST_ID,),
                                     **{portbindings.HOST_ID: 'fakehost_a'})
        res = self.deserialize(self.fmt, response)
        self._validate_immediate_ip_allocation(res['port']['id'])
        # Since host mapped to segment_a, IP's must come from subnets:
        #   subnet_a0 and subnet_a1
        self.assertEqual(2, len(res['port']['fixed_ips']))
        res_subnet_ids = [f['subnet_id'] for f in res['port']['fixed_ips']]
        self.assertIn(subnet_a0['subnet']['id'], res_subnet_ids)
        self.assertIn(subnet_a1['subnet']['id'], res_subnet_ids)
        self.assertNotIn(subnet_b0['subnet']['id'], res_subnet_ids)
        self.assertNotIn(subnet_b1['subnet']['id'], res_subnet_ids)

    def test_slaac_segment_aware_add_subnet(self):
        (network, segment_a, segment_b, subnet_a0, subnet_a1, subnet_b0,
         subnet_b1) = self._create_net_two_segments_four_slaac_subnets()

        # Create a port with no IP address (since there is no subnet)
        port_deferred = self._create_deferred_ip_port(network)
        self._validate_deferred_ip_allocation(port_deferred['port']['id'])

        # Create two ports, port_a with subnet_a0 in fixed_ips and port_b
        # with subnet_b0 in fixed_ips
        port_a = self._create_port_and_show(
            network, fixed_ips=[{'subnet_id': subnet_a0['subnet']['id']}])
        port_b = self._create_port_and_show(
            network, fixed_ips=[{'subnet_id': subnet_b0['subnet']['id']}])
        self._validate_immediate_ip_allocation(port_a['port']['id'])
        self._validate_immediate_ip_allocation(port_b['port']['id'])
        self.assertEqual(2, len(port_a['port']['fixed_ips']))
        self.assertEqual(2, len(port_b['port']['fixed_ips']))

        # Add another subnet on segment_a
        subnet_a2 = self._create_test_slaac_subnet_with_segment(
            network, segment_a, '2001:db8:a:2::/64')
        # The port with deferred allocation should not have an allocation
        req = self.new_show_request('ports', port_deferred['port']['id'])
        res = req.get_response(self.api)
        port_deferred = self.deserialize(self.fmt, res)
        self._validate_deferred_ip_allocation(port_deferred['port']['id'])
        self.assertEqual(0, len(port_deferred['port']['fixed_ips']))
        # port_a should get an allocation on the new subnet.
        # port_b does not get an allocation.
        req = self.new_show_request('ports', port_a['port']['id'])
        res = req.get_response(self.api)
        port_a = self.deserialize(self.fmt, res)
        req = self.new_show_request('ports', port_b['port']['id'])
        res = req.get_response(self.api)
        port_b = self.deserialize(self.fmt, res)
        self.assertEqual(3, len(port_a['port']['fixed_ips']))
        self.assertEqual(2, len(port_b['port']['fixed_ips']))
        port_a_snet_ids = [f['subnet_id'] for f in port_a['port']['fixed_ips']]
        self.assertIn(subnet_a2['subnet']['id'], port_a_snet_ids)

    def test_slaac_segment_aware_delete_subnet(self):
        (network, segment_a, segment_b, subnet_a0, subnet_a1, subnet_b0,
         subnet_b1) = self._create_net_two_segments_four_slaac_subnets()

        # Create two ports, port_a with subnet_a0 in fixed_ips and port_b
        # with subnet_b0 in fixed_ips
        port_a = self._create_port_and_show(
            network, fixed_ips=[{'subnet_id': subnet_a0['subnet']['id']}])
        port_b = self._create_port_and_show(
            network, fixed_ips=[{'subnet_id': subnet_b0['subnet']['id']}])
        self._validate_immediate_ip_allocation(port_a['port']['id'])
        self._validate_immediate_ip_allocation(port_b['port']['id'])
        self.assertEqual(2, len(port_a['port']['fixed_ips']))
        self.assertEqual(2, len(port_b['port']['fixed_ips']))

        # Delete subnet_b1 on segment_b, port_a should keep it's allocations
        # on the new subnet. Allocation for deleted subnet removed on port_b.
        req = self.new_delete_request('subnets', subnet_b1['subnet']['id'])
        res = req.get_response(self.api)
        self.assertEqual(webob.exc.HTTPNoContent.code, res.status_int)
        req = self.new_show_request('ports', port_a['port']['id'])
        res = req.get_response(self.api)
        port_a = self.deserialize(self.fmt, res)
        req = self.new_show_request('ports', port_b['port']['id'])
        res = req.get_response(self.api)
        port_b = self.deserialize(self.fmt, res)
        self.assertEqual(2, len(port_a['port']['fixed_ips']))
        self.assertEqual(1, len(port_b['port']['fixed_ips']))
        port_b_snet_ids = [f['subnet_id'] for f in port_b['port']['fixed_ips']]
        self.assertNotIn(subnet_b1['subnet']['id'], port_b_snet_ids)

    def test_slaac_segment_aware_delete_last_subnet_on_segment_fails(self):
        (network, segment_a, segment_b, subnet_a0, subnet_a1, subnet_b0,
         subnet_b1) = self._create_net_two_segments_four_slaac_subnets()

        # Create two ports, port_a with subnet_a0 in fixed_ips and port_b
        # with subnet_b0 in fixed_ips
        port_a = self._create_port_and_show(
            network, fixed_ips=[{'subnet_id': subnet_a0['subnet']['id']}])
        port_b = self._create_port_and_show(
            network, fixed_ips=[{'subnet_id': subnet_b0['subnet']['id']}])
        self._validate_immediate_ip_allocation(port_a['port']['id'])
        self._validate_immediate_ip_allocation(port_b['port']['id'])
        self.assertEqual(2, len(port_a['port']['fixed_ips']))
        self.assertEqual(2, len(port_b['port']['fixed_ips']))
        # Delete subnet_b1 on segment_b
        req = self.new_delete_request('subnets', subnet_b1['subnet']['id'])
        res = req.get_response(self.api)
        self.assertEqual(webob.exc.HTTPNoContent.code, res.status_int)
        # Delete subnet_b0 on segment_b fails because port_b has no other
        # allocation, SubnetInUse
        req = self.new_delete_request('subnets', subnet_b0['subnet']['id'])
        res = req.get_response(self.api)
        self.assertEqual(webob.exc.HTTPConflict.code, res.status_int)
        # Delete port_b
        req = self.new_delete_request('ports', port_b['port']['id'])
        res = req.get_response(self.api)
        self.assertEqual(webob.exc.HTTPNoContent.code, res.status_int)
        # Try to delete subnet_b0 again, should not fail with no ports
        req = self.new_delete_request('subnets', subnet_b0['subnet']['id'])
        res = req.get_response(self.api)
        self.assertEqual(webob.exc.HTTPNoContent.code, res.status_int)


class TestSegmentAwareIpamML2(TestSegmentAwareIpam):

    VLAN_MIN = 200
    VLAN_MAX = 209

    def setUp(self):
        # NOTE(mlavalle): ml2_type_vlan requires to be registered before used.
        # This piece was refactored and removed from .config, so it causes
        # a problem, when tests are executed with pdb.
        # There is no problem when tests are running without debugger.
        driver_type.register_ml2_drivers_vlan_opts()
        cfg.CONF.set_override(
            'network_vlan_ranges',
            ['physnet:%s:%s' % (self.VLAN_MIN, self.VLAN_MAX),
             'physnet0:%s:%s' % (self.VLAN_MIN, self.VLAN_MAX),
             'physnet1:%s:%s' % (self.VLAN_MIN, self.VLAN_MAX),
             'physnet2:%s:%s' % (self.VLAN_MIN, self.VLAN_MAX)],
            group='ml2_type_vlan')
        super(TestSegmentAwareIpamML2, self).setUp(plugin='ml2')

    def test_segmentation_id_stored_in_db(self):
        network, segment, subnet = self._create_test_segment_with_subnet()
        self.assertTrue(self.VLAN_MIN <=
                        segment['segment']['segmentation_id'] <= self.VLAN_MAX)
        retrieved_segment = self._show('segments', segment['segment']['id'])
        self.assertEqual(segment['segment']['segmentation_id'],
                         retrieved_segment['segment']['segmentation_id'])


class TestNovaSegmentNotifier(SegmentAwareIpamTestCase):
    _mechanism_drivers = ['openvswitch', 'logger']

    def setUp(self):
        ml2_config.register_ml2_plugin_opts()
        driver_type.register_ml2_drivers_vlan_opts()
        cfg.CONF.set_override('mechanism_drivers',
                              self._mechanism_drivers,
                              group='ml2')
        cfg.CONF.set_override('network_vlan_ranges',
                              ['physnet:200:209', 'physnet0:200:209',
                               'physnet1:200:209', 'physnet2:200:209'],
                              group='ml2_type_vlan')
        super(TestNovaSegmentNotifier, self).setUp(plugin='ml2')
        # Need notifier here
        self.patch_notifier.stop()
        self._mock_keystone_auth()
        self.segments_plugin = directory.get_plugin(ext_segment.SEGMENTS)

        nova_updater = self.segments_plugin.nova_updater
        nova_updater.p_client = mock.MagicMock()
        self.mock_p_client = nova_updater.p_client
        nova_updater.n_client = mock.MagicMock()
        self.mock_n_client = nova_updater.n_client
        self.batch_notifier = nova_updater.batch_notifier
        self.batch_notifier._waiting_to_send = True

    def _mock_keystone_auth(self):
        # Use to remove MissingAuthPlugin exception when notifier is needed
        self.mock_load_auth_p = mock.patch(
            'keystoneauth1.loading.load_auth_from_conf_options')
        self.mock_load_auth = self.mock_load_auth_p.start()
        self.mock_request_p = mock.patch(
            'keystoneauth1.session.Session.request')
        self.mock_request = self.mock_request_p.start()

    def _calculate_inventory_total_and_reserved(self, subnet):
        total = 0
        reserved = 0
        allocation_pools = subnet.get('allocation_pools') or []
        for pool in allocation_pools:
            total += int(netaddr.IPAddress(pool['end']) -
                         netaddr.IPAddress(pool['start'])) + 1
        if total:
            if subnet.get('gateway_ip'):
                total += 1
                reserved += 1
            if subnet.get('enable_dhcp'):
                reserved += 1
        return total, reserved

    def test__create_nova_inventory_no_microversion(self):
        network, segment = self._create_test_network_and_segment()
        segment_id = segment['segment']['id']
        aggregate = mock.Mock(spec=["id"])
        aggregate.id = 1
        self.mock_n_client.aggregates.create.return_value = aggregate
        with mock.patch.object(seg_plugin.LOG, 'exception') as log:
            self.assertRaises(
                AttributeError,
                self.segments_plugin.nova_updater._create_nova_inventory,
                segment_id, 63, 2, [])
            self.assertTrue(log.called)

    def _assert_inventory_creation(self, segment_id, aggregate, subnet):
        self.batch_notifier._notify()
        self.mock_p_client.get_inventory.assert_called_with(
            segment_id, seg_plugin.IPV4_RESOURCE_CLASS)
        self.mock_p_client.update_resource_provider_inventory.\
            assert_not_called()
        name = seg_plugin.SEGMENT_NAME_STUB % segment_id
        resource_provider = {'name': name, 'uuid': segment_id}
        self.mock_p_client.create_resource_provider.assert_called_with(
            resource_provider)
        self.mock_n_client.aggregates.create.assert_called_with(name, None)
        self.mock_p_client.associate_aggregates.assert_called_with(
            segment_id, [aggregate.uuid])
        self.mock_n_client.aggregates.add_host.assert_called_with(aggregate.id,
            'fakehost')
        total, reserved = self._calculate_inventory_total_and_reserved(
            subnet['subnet'])
        inventory, _ = self._get_inventory(total, reserved)
        ipv4_classname = seg_plugin.IPV4_RESOURCE_CLASS
        self.mock_p_client.update_resource_provider_inventories.\
            assert_called_with(segment_id, {ipv4_classname: inventory})
        self.assertEqual(
            inventory['total'],
            self.mock_p_client.update_resource_provider_inventories.
            call_args[0][1][ipv4_classname]['total'])
        self.assertEqual(
            inventory['reserved'],
            self.mock_p_client.update_resource_provider_inventories.
            call_args[0][1][ipv4_classname]['reserved'])
        self.mock_p_client.reset_mock()
        self.mock_p_client.get_inventory.side_effect = None
        self.mock_n_client.reset_mock()

    def _test_first_subnet_association_with_segment(self, cidr='10.0.0.0/24',
                                                    allocation_pools=None):
        network, segment = self._create_test_network_and_segment()
        segment_id = segment['segment']['id']
        self._setup_host_mappings([(segment_id, 'fakehost')])
        self.mock_p_client.get_inventory.side_effect = (
            placement_exc.PlacementResourceProviderNotFound(
                resource_provider=segment_id,
                resource_class=seg_plugin.IPV4_RESOURCE_CLASS))
        aggregate = mock.MagicMock()
        aggregate.uuid = uuidutils.generate_uuid()
        aggregate.id = 1
        self.mock_n_client.aggregates.create.return_value = aggregate
        subnet = self._create_test_subnet_with_segment(
            network, segment, cidr=cidr, allocation_pools=allocation_pools)
        self._assert_inventory_creation(segment_id, aggregate, subnet)
        return network, segment, subnet

    def test_first_subnet_association_with_segment(self):
        self._test_first_subnet_association_with_segment()

    def test_update_subnet_association_with_segment(self, cidr='10.0.0.0/24',
                                                    allocation_pools=None):
        with self.network() as network:
            segment_id = self._list('segments')['segments'][0]['id']
            network_id = network['network']['id']

        self._setup_host_mappings([(segment_id, 'fakehost')])
        self.mock_p_client.get_inventory.side_effect = (
            placement_exc.PlacementResourceProviderNotFound(
                resource_provider=segment_id,
                resource_class=seg_plugin.IPV4_RESOURCE_CLASS))
        aggregate = mock.MagicMock()
        aggregate.uuid = uuidutils.generate_uuid()
        aggregate.id = 1
        self.mock_n_client.aggregates.create.return_value = aggregate
        ip_version = netaddr.IPNetwork(cidr).version
        with self.subnet(network=network, cidr=cidr, ip_version=ip_version,
                         allocation_pools=allocation_pools,
                         segment_id=None) as subnet:
            self._validate_l2_adjacency(network_id, is_adjacent=True)
            data = {'subnet': {'segment_id': segment_id}}
            self.new_update_request('subnets', data, subnet['subnet']['id'])
            self.new_update_request(
                'subnets', data, subnet['subnet']['id']).get_response(self.api)
            self._validate_l2_adjacency(network_id, is_adjacent=False)
            self._assert_inventory_creation(segment_id, aggregate, subnet)

    def _assert_inventory_update(self, segment_id, inventory, subnet=None,
                                 original_subnet=None):
        self.batch_notifier._notify()
        self.mock_p_client.get_inventory.assert_called_with(
            segment_id, seg_plugin.IPV4_RESOURCE_CLASS)
        original_total = original_reserved = total = reserved = 0
        if original_subnet:
            original_total, original_reserved = (
                self._calculate_inventory_total_and_reserved(original_subnet))
        if subnet:
            total, reserved = self._calculate_inventory_total_and_reserved(
                subnet)
        inventory['total'] += total - original_total
        inventory['reserved'] += reserved - original_reserved
        self.mock_p_client.update_resource_provider_inventory.\
            assert_called_with(segment_id, inventory,
                               seg_plugin.IPV4_RESOURCE_CLASS)
        self.assertEqual(
            inventory['total'],
            self.mock_p_client.update_resource_provider_inventory.
            call_args[0][1]['total'])
        self.assertEqual(
            inventory['reserved'],
            self.mock_p_client.update_resource_provider_inventory.
            call_args[0][1]['reserved'])
        self.mock_p_client.reset_mock()
        self.mock_n_client.reset_mock()

    def _get_inventory(self, total, reserved):
        inventory = {'total': total, 'reserved': reserved, 'min_unit': 1,
                     'max_unit': 1, 'step_size': 1, 'allocation_ratio': 1.0}
        return inventory, copy.deepcopy(inventory)

    def _test_second_subnet_association_with_segment(self):
        network, segment, first_subnet = (
            self._test_first_subnet_association_with_segment())
        segment_id = segment['segment']['id']
        # Associate an IPv6 subnet with the segment
        self._create_test_subnet_with_segment(network, segment)
        first_total, first_reserved = (
            self._calculate_inventory_total_and_reserved(
                first_subnet['subnet']))
        inventory, original_inventory = self._get_inventory(first_total,
                                                            first_reserved)
        self.mock_p_client.get_inventory.return_value = inventory
        second_subnet = self._create_test_subnet_with_segment(
            network, segment, cidr='10.0.1.0/24')
        self._assert_inventory_update(segment_id, original_inventory,
                                      subnet=second_subnet['subnet'])
        return segment_id, first_subnet, second_subnet

    def test_second_subnet_association_with_segment(self):
        self._test_second_subnet_association_with_segment()

    def test_delete_last_ipv4_subnet(self):
        network, segment, subnet = (
            self._test_first_subnet_association_with_segment())
        # Associate an IPv6 subnet with the segment
        self._create_test_subnet_with_segment(network, segment)
        segment_id = segment['segment']['id']
        aggregate = mock.MagicMock()
        aggregate.uuid = uuidutils.generate_uuid()
        aggregate.id = 1
        aggregate.hosts = ['fakehost1']
        self.mock_p_client.list_aggregates.return_value = {
            'aggregates': [aggregate.uuid]}
        self.mock_n_client.aggregates.list.return_value = [aggregate]
        self.mock_n_client.aggregates.get_details.return_value = aggregate
        self._delete('subnets', subnet['subnet']['id'])
        self.batch_notifier._notify()
        self._assert_inventory_delete(segment_id, aggregate)

    def _assert_inventory_delete(self, segment_id, aggregate):
        self.mock_p_client.list_aggregates.assert_called_with(segment_id)
        self.assertEqual(1, self.mock_n_client.aggregates.list.call_count)
        self.mock_n_client.aggregates.get_details.assert_called_with(
            aggregate.id)
        calls = [mock.call(aggregate.id, host) for host in aggregate.hosts]
        self.mock_n_client.aggregates.remove_host.assert_has_calls(calls)
        self.mock_n_client.aggregates.delete.assert_called_with(aggregate.id)
        self.mock_p_client.delete_resource_provider.assert_called_with(
            segment_id)
        self.mock_p_client.reset_mock()
        self.mock_n_client.reset_mock()

    def test_delete_ipv4_subnet(self):
        segment_id, first_subnet, second_subnet = (
            self._test_second_subnet_association_with_segment())
        first_total, first_reserved = (
            self._calculate_inventory_total_and_reserved(
                first_subnet['subnet']))
        second_total, second_reserved = (
            self._calculate_inventory_total_and_reserved(
                second_subnet['subnet']))
        inventory, original_inventory = self._get_inventory(
            first_total + second_total, first_reserved + second_reserved)
        self.mock_p_client.get_inventory.return_value = inventory
        self._delete('subnets', first_subnet['subnet']['id'])
        self._assert_inventory_update(segment_id, original_inventory,
                                      original_subnet=first_subnet['subnet'])

    def _test_update_ipv4_subnet_allocation_pools(self, allocation_pools,
                                                  new_allocation_pools):
        network, segment, original_subnet = (
            self._test_first_subnet_association_with_segment(
                cidr='10.0.0.0/24', allocation_pools=allocation_pools))
        segment_id = segment['segment']['id']
        self.mock_p_client.reset_mock()
        self.mock_n_client.reset_mock()
        total, reserved = self._calculate_inventory_total_and_reserved(
            original_subnet['subnet'])
        inventory, original_inventory = self._get_inventory(total, reserved)
        self.mock_p_client.get_inventory.return_value = inventory
        subnet_data = {'subnet': {'allocation_pools': new_allocation_pools}}
        subnet_req = self.new_update_request('subnets',
                                             subnet_data,
                                             original_subnet['subnet']['id'])
        subnet = self.deserialize(self.fmt, subnet_req.get_response(self.api))
        self._assert_inventory_update(
            segment_id, original_inventory, subnet=subnet['subnet'],
            original_subnet=original_subnet['subnet'])

    def test_update_ipv4_subnet_expand_allocation_pool(self):
        self._test_update_ipv4_subnet_allocation_pools(
            [{'start': '10.0.0.2', 'end': '10.0.0.100'}],
            [{'start': '10.0.0.2', 'end': '10.0.0.254'}])

    def test_update_ipv4_subnet_add_allocation_pool(self):
        self._test_update_ipv4_subnet_allocation_pools(
            [{'start': '10.0.0.2', 'end': '10.0.0.100'}],
            [{'start': '10.0.0.2', 'end': '10.0.0.100'},
             {'start': '10.0.0.200', 'end': '10.0.0.254'}])

    def test_update_ipv4_subnet_contract_allocation_pool(self):
        self._test_update_ipv4_subnet_allocation_pools(
            [{'start': '10.0.0.2', 'end': '10.0.0.254'}],
            [{'start': '10.0.0.2', 'end': '10.0.0.100'}])

    def test_update_ipv4_subnet_remove_allocation_pool(self):
        self._test_update_ipv4_subnet_allocation_pools(
            [{'start': '10.0.0.2', 'end': '10.0.0.100'},
             {'start': '10.0.0.200', 'end': '10.0.0.254'}],
            [{'start': '10.0.0.2', 'end': '10.0.0.100'}])

    def _test_update_ipv4_subnet_delete_allocation_pools(self):
        segment_id, first_subnet, second_subnet = (
            self._test_second_subnet_association_with_segment())
        first_total, first_reserved = (
            self._calculate_inventory_total_and_reserved(
                first_subnet['subnet']))
        second_total, second_reserved = (
            self._calculate_inventory_total_and_reserved(
                second_subnet['subnet']))
        inventory, original_inventory = self._get_inventory(
            first_total + second_total, first_reserved + second_reserved)
        self.mock_p_client.get_inventory.return_value = inventory
        subnet_data = {'subnet': {'allocation_pools': []}}
        subnet_req = self.new_update_request('subnets',
                                             subnet_data,
                                             first_subnet['subnet']['id'])
        subnet_req.get_response(self.api)
        self._assert_inventory_update(segment_id, original_inventory,
                                      original_subnet=first_subnet['subnet'])
        return segment_id, second_subnet

    def test_update_ipv4_subnet_delete_allocation_pools(self):
        self._test_update_ipv4_subnet_delete_allocation_pools()

    def test_update_ipv4_subnet_delete_restore_last_allocation_pool(self):
        segment_id, subnet = (
            self._test_update_ipv4_subnet_delete_allocation_pools())
        self.mock_p_client.reset_mock()
        self.mock_n_client.reset_mock()
        allocation_pools = subnet['subnet']['allocation_pools']
        aggregate = mock.MagicMock()
        aggregate.uuid = uuidutils.generate_uuid()
        aggregate.id = 1
        aggregate.hosts = ['fakehost1']
        self.mock_p_client.list_aggregates.return_value = {
            'aggregates': [aggregate.uuid]}
        self.mock_n_client.aggregates.list.return_value = [aggregate]
        self.mock_n_client.aggregates.get_details.return_value = aggregate
        subnet_data = {'subnet': {'allocation_pools': []}}
        self._update('subnets', subnet['subnet']['id'], subnet_data)
        self.batch_notifier._notify()
        self._assert_inventory_delete(segment_id, aggregate)
        self.mock_p_client.get_inventory.side_effect = (
            placement_exc.PlacementResourceProviderNotFound(
                resource_provider=segment_id,
                resource_class=seg_plugin.IPV4_RESOURCE_CLASS))
        aggregate.hosts = []
        self.mock_n_client.aggregates.create.return_value = aggregate
        subnet_data = {'subnet': {'allocation_pools': allocation_pools}}
        subnet = self._update('subnets', subnet['subnet']['id'], subnet_data)
        self._assert_inventory_creation(segment_id, aggregate, subnet)

    def test_add_host_to_segment_aggregate(self):
        db.subscribe()
        network, segment, first_subnet = (
            self._test_first_subnet_association_with_segment())
        segment_id = segment['segment']['id']
        aggregate = mock.MagicMock()
        aggregate.uuid = uuidutils.generate_uuid()
        aggregate.id = 1
        aggregate.hosts = ['fakehost1']
        self.mock_p_client.list_aggregates.return_value = {
            'aggregates': [aggregate.uuid]}
        self.mock_n_client.aggregates.list.return_value = [aggregate]
        host = 'otherfakehost'
        helpers.register_ovs_agent(host=host,
                                   bridge_mappings={'physnet': 'br-eth-1'},
                                   plugin=self.plugin, start_flag=True)
        self.batch_notifier._notify()
        self.mock_p_client.list_aggregates.assert_called_with(segment_id)
        self.assertEqual(1, self.mock_n_client.aggregates.list.call_count)
        self.mock_n_client.aggregates.add_host.assert_called_with(aggregate.id,
                                                                  host)

    def test_add_host_to_non_existent_segment_aggregate(self):
        self._mock_keystone_auth()
        db.subscribe()
        network, segment, first_subnet = (
            self._test_first_subnet_association_with_segment())
        with mock.patch.object(seg_plugin.LOG, 'info') as log:
            segment_id = segment['segment']['id']
            aggregate = mock.MagicMock()
            aggregate.uuid = uuidutils.generate_uuid()
            aggregate.id = 1
            aggregate.hosts = ['fakehost1']
            self.mock_p_client.list_aggregates.side_effect = (
                placement_exc.PlacementAggregateNotFound(
                    resource_provider=segment_id))
            self.mock_n_client.aggregates.list.return_value = [aggregate]
            host = 'otherfakehost'
            helpers.register_ovs_agent(host=host,
                                       bridge_mappings={'physnet': 'br-eth-1'},
                                       plugin=self.plugin, start_flag=True)
            self.batch_notifier._notify()
            self.mock_p_client.list_aggregates.assert_called_with(segment_id)
            self.assertTrue(log.called)
            self.mock_n_client.aggregates.add_host.assert_not_called()

    def test_add_host_segment_aggregate_conflict(self):
        db.subscribe()
        network, segment, first_subnet = (
            self._test_first_subnet_association_with_segment())
        with mock.patch.object(seg_plugin.LOG, 'info') as log:
            segment_id = segment['segment']['id']
            aggregate = mock.MagicMock()
            aggregate.uuid = uuidutils.generate_uuid()
            aggregate.id = 1
            aggregate.hosts = ['fakehost1']
            self.mock_p_client.list_aggregates.return_value = {
                'aggregates': [aggregate.uuid]}
            self.mock_n_client.aggregates.add_host.side_effect = (
                nova_exc.Conflict(nova_exc.Conflict.http_status))
            self.mock_n_client.aggregates.list.return_value = [aggregate]
            host = 'otherfakehost'
            helpers.register_ovs_agent(host=host,
                                       bridge_mappings={'physnet': 'br-eth-1'},
                                       plugin=self.plugin, start_flag=True)
            self.batch_notifier._notify()
            self.mock_p_client.list_aggregates.assert_called_with(segment_id)
            self.mock_n_client.aggregates.add_host.assert_called_with(
                aggregate.id, host)
            self.assertTrue(log.called)

    def _assert_inventory_update_port(self, segment_id, inventory,
                                      num_fixed_ips):
        inventory['reserved'] += num_fixed_ips
        self.mock_p_client.get_inventory.assert_called_with(
            segment_id, seg_plugin.IPV4_RESOURCE_CLASS)
        self.mock_p_client.update_resource_provider_inventory.\
            assert_called_with(segment_id, inventory,
                               seg_plugin.IPV4_RESOURCE_CLASS)
        self.assertEqual(
            inventory['total'],
            self.mock_p_client.update_resource_provider_inventory.
            call_args[0][1]['total'])
        self.assertEqual(
            inventory['reserved'],
            self.mock_p_client.update_resource_provider_inventory.
            call_args[0][1]['reserved'])
        self.mock_p_client.reset_mock()
        self.mock_n_client.reset_mock()

    def _create_test_port(self, network_id, tenant_id, subnet, **kwargs):
        port = self._make_port(self.fmt, network_id, tenant_id=tenant_id,
                               arg_list=(portbindings.HOST_ID,), **kwargs)
        self.batch_notifier._notify()
        return port

    def _test_create_port(self, **kwargs):
        network, segment, subnet = (
            self._test_first_subnet_association_with_segment())
        total, reserved = self._calculate_inventory_total_and_reserved(
            subnet['subnet'])
        inventory, original_inventory = self._get_inventory(total, reserved)
        self.mock_p_client.get_inventory.return_value = inventory
        port = self._create_test_port(network['network']['id'],
                                      network['network']['tenant_id'], subnet,
                                      **kwargs)
        return segment['segment']['id'], original_inventory, port

    def test_create_bound_port(self):
        kwargs = {portbindings.HOST_ID: 'fakehost'}
        segment_id, original_inventory, _ = self._test_create_port(**kwargs)
        self._assert_inventory_update_port(segment_id, original_inventory, 1)

    def test_create_bound_port_compute_owned(self):
        kwargs = {portbindings.HOST_ID: 'fakehost',
                  'device_owner': constants.DEVICE_OWNER_COMPUTE_PREFIX}
        self._test_create_port(**kwargs)
        self.mock_p_client.get_inventory.assert_not_called()
        self.mock_p_client.update_resource_provider_inventory.\
            assert_not_called()

    def test_create_bound_port_dhcp_owned(self):
        kwargs = {portbindings.HOST_ID: 'fakehost',
                  'device_owner': constants.DEVICE_OWNER_DHCP}
        self._test_create_port(**kwargs)
        self.mock_p_client.get_inventory.assert_not_called()
        self.mock_p_client.update_resource_provider_inventory.\
            assert_not_called()

    def test_create_unbound_port(self):
        self._test_create_port()
        self.mock_p_client.get_inventory.assert_not_called()
        self.mock_p_client.update_resource_provider_inventory.\
            assert_not_called()

    def test_delete_bound_port(self):
        kwargs = {portbindings.HOST_ID: 'fakehost'}
        segment_id, before_create_inventory, port = self._test_create_port(
            **kwargs)
        self.mock_p_client.reset_mock()
        inventory, original_inventory = self._get_inventory(
            before_create_inventory['total'],
            before_create_inventory['reserved'] + 1)
        self.mock_p_client.get_inventory.return_value = inventory
        self._delete('ports', port['port']['id'])
        self.batch_notifier._notify()
        self._assert_inventory_update_port(segment_id, original_inventory, -1)

    def _create_port_for_update_test(self, num_fixed_ips=1, dhcp_owned=False,
                                     compute_owned=False):
        segment_id, first_subnet, second_subnet = (
            self._test_second_subnet_association_with_segment())
        first_total, first_reserved = (
            self._calculate_inventory_total_and_reserved(
                first_subnet['subnet']))
        second_total, second_reserved = (
            self._calculate_inventory_total_and_reserved(
                second_subnet['subnet']))
        inventory, original_inventory = self._get_inventory(
            first_total + second_total, first_reserved + second_reserved)
        self.mock_p_client.get_inventory.return_value = inventory
        kwargs = {portbindings.HOST_ID: 'fakehost',
                  'fixed_ips': [{'subnet_id': first_subnet['subnet']['id']}]}
        created_fixed_ips = num_fixed_ips
        if num_fixed_ips > 1:
            kwargs['fixed_ips'].append(
                {'subnet_id': second_subnet['subnet']['id']})
        if dhcp_owned:
            kwargs['device_owner'] = constants.DEVICE_OWNER_DHCP
        if compute_owned:
            kwargs['device_owner'] = constants.DEVICE_OWNER_COMPUTE_PREFIX
        port = self._create_test_port(first_subnet['subnet']['network_id'],
                                      first_subnet['subnet']['tenant_id'],
                                      first_subnet, **kwargs)
        if dhcp_owned or compute_owned:
            self.mock_p_client.get_inventory.assert_not_called()
            self.mock_p_client.update_resource_provider_inventory.\
                assert_not_called()
        else:
            self._assert_inventory_update_port(segment_id, original_inventory,
                                               created_fixed_ips)
        return first_subnet, second_subnet, port

    def _port_update(self, first_subnet, second_subnet, fixed_ips_subnets,
                     port, reserved_increment_before=1,
                     reserved_increment_after=1, dhcp_owned=False,
                     compute_owned=False):
        first_total, first_reserved = (
            self._calculate_inventory_total_and_reserved(
                first_subnet['subnet']))
        second_total, second_reserved = (
            self._calculate_inventory_total_and_reserved(
                second_subnet['subnet']))
        inventory, original_inventory = self._get_inventory(
            first_total + second_total,
            first_reserved + second_reserved + reserved_increment_before)
        self.mock_p_client.get_inventory.return_value = inventory
        port_data = {'port': {'device_owner': ''}}
        if fixed_ips_subnets:
            port_data['port']['fixed_ips'] = []
            for subnet in fixed_ips_subnets:
                port_data['port']['fixed_ips'].append(
                    {'subnet_id': subnet['subnet']['id']})
        if dhcp_owned:
            port_data['port']['device_owner'] = constants.DEVICE_OWNER_DHCP
        if compute_owned:
            port_data['port']['device_owner'] = (
                constants.DEVICE_OWNER_COMPUTE_PREFIX)
        self._update('ports', port['port']['id'], port_data)
        self.batch_notifier._notify()
        self._assert_inventory_update_port(
            first_subnet['subnet']['segment_id'], original_inventory,
            reserved_increment_after)

    def test_update_port_add_fixed_ip(self):
        first_subnet, second_subnet, port = self._create_port_for_update_test()
        self._port_update(first_subnet, second_subnet,
                          [first_subnet, second_subnet], port)

    def test_update_port_remove_fixed_ip(self):
        first_subnet, second_subnet, port = self._create_port_for_update_test(
            num_fixed_ips=2)
        self._port_update(first_subnet, second_subnet,
                          [first_subnet], port, reserved_increment_before=2,
                          reserved_increment_after=-1)

    def test_update_port_change_to_dhcp_owned(self):
        first_subnet, second_subnet, port = self._create_port_for_update_test()
        self._port_update(first_subnet, second_subnet, [], port,
                          reserved_increment_after=-1, dhcp_owned=True)

    def test_update_port_change_to_no_dhcp_owned(self):
        first_subnet, second_subnet, port = self._create_port_for_update_test(
            dhcp_owned=True)
        self._port_update(first_subnet, second_subnet, [], port,
                          reserved_increment_before=0,
                          reserved_increment_after=1)

    def test_update_port_change_to_compute_owned(self):
        first_subnet, second_subnet, port = self._create_port_for_update_test()
        self._port_update(first_subnet, second_subnet, [], port,
                          reserved_increment_after=-1, compute_owned=True)

    def test_update_port_change_to_no_compute_owned(self):
        first_subnet, second_subnet, port = self._create_port_for_update_test(
            compute_owned=True)
        self._port_update(first_subnet, second_subnet, [], port,
                          reserved_increment_before=0,
                          reserved_increment_after=1)

    def test_placement_api_inventory_update_conflict(self):
        with mock.patch.object(seg_plugin.LOG, 'debug') as log_debug:
            with mock.patch.object(seg_plugin.LOG, 'error') as log_error:
                event = seg_plugin.Event(mock.ANY, mock.ANY, total=1,
                                         reserved=0)
                inventory, original_inventory = self._get_inventory(100, 2)
                self.mock_p_client.get_inventory.return_value = inventory
                self.mock_p_client.update_resource_provider_inventory.\
                    side_effect = (
                        placement_exc.
                        PlacementResourceProviderGenerationConflict(
                            resource_provider=mock.ANY, generation=1))
                self.segments_plugin.nova_updater._update_nova_inventory(event)
                self.assertEqual(seg_plugin.MAX_INVENTORY_UPDATE_RETRIES,
                                 self.mock_p_client.get_inventory.call_count)
                self.assertEqual(
                    seg_plugin.MAX_INVENTORY_UPDATE_RETRIES,
                    self.mock_p_client.update_resource_provider_inventory.
                    call_count)
                self.assertEqual(
                    seg_plugin.MAX_INVENTORY_UPDATE_RETRIES,
                    log_debug.call_count)
                self.assertTrue(log_error.called)

    def test_placement_api_not_available(self):
        with mock.patch.object(seg_plugin.LOG, 'debug') as log:
            event = seg_plugin.Event(
                self.segments_plugin.nova_updater._update_nova_inventory,
                mock.ANY, total=1, reserved=0)
            self.mock_p_client.get_inventory.side_effect = (
                placement_exc.PlacementEndpointNotFound())
            self.segments_plugin.nova_updater._send_notifications([event])
            self.assertTrue(log.called)

    def _test_create_network_and_segment(self, phys_net):
        with self.network() as net:
            network = net['network']
        segment = self._test_create_segment(
            network_id=network['id'], physical_network=phys_net,
            segmentation_id=200, network_type='vlan')
        return network, segment['segment']

    def test_delete_network_and_owned_segments(self):
        db.subscribe()
        aggregate = mock.MagicMock()
        aggregate.uuid = uuidutils.generate_uuid()
        aggregate.id = 1
        aggregate.hosts = ['fakehost1']
        self.mock_p_client.list_aggregates.return_value = {
            'aggregates': [aggregate.uuid]}
        self.mock_n_client.aggregates.list.return_value = [aggregate]
        self.mock_n_client.aggregates.get_details.return_value = aggregate
        network, segment = self._test_create_network_and_segment('physnet')
        self._delete('networks', network['id'])
        self.mock_n_client.aggregates.remove_host.assert_has_calls(
            [mock.call(aggregate.id, 'fakehost1')])
        self.mock_n_client.aggregates.delete.assert_has_calls(
            [mock.call(aggregate.id)])
        self.mock_p_client.delete_resource_provider.assert_has_calls(
            [mock.call(segment['id'])])


class TestDhcpAgentSegmentScheduling(HostSegmentMappingTestCase):

    _mechanism_drivers = ['openvswitch', 'logger']
    mock_path = 'neutron.services.segments.db.update_segment_host_mapping'
    block_dhcp_notifier = False

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
        ip_version = constants.IP_VERSION_4
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


class TestSegmentHostRoutes(TestSegmentML2):

    VLAN_MIN = 200
    VLAN_MAX = 209

    def setUp(self):
        # NOTE(mlavalle): ml2_type_vlan requires to be registered before used.
        # This piece was refactored and removed from .config, so it causes
        # a problem, when tests are executed with pdb.
        # There is no problem when tests are running without debugger.
        driver_type.register_ml2_drivers_vlan_opts()
        cfg.CONF.set_override(
            'network_vlan_ranges',
            ['physnet:%s:%s' % (self.VLAN_MIN, self.VLAN_MAX),
             'physnet0:%s:%s' % (self.VLAN_MIN, self.VLAN_MAX),
             'physnet1:%s:%s' % (self.VLAN_MIN, self.VLAN_MAX),
             'physnet2:%s:%s' % (self.VLAN_MIN, self.VLAN_MAX)],
            group='ml2_type_vlan')
        super(TestSegmentHostRoutes, self).setUp()

    def _create_subnets_segments(self, gateway_ips, cidrs):
        with self.network() as network:
            net = network['network']
            segment0 = self._test_create_segment(
                network_id=net['id'],
                physical_network='physnet1',
                network_type=constants.TYPE_VLAN,
                segmentation_id=201)['segment']
            segment1 = self._test_create_segment(
                network_id=net['id'],
                physical_network='physnet2',
                network_type=constants.TYPE_VLAN,
                segmentation_id=202)['segment']

            with self.subnet(network=network,
                             segment_id=segment0['id'],
                             gateway_ip=gateway_ips[0],
                             cidr=cidrs[0]) as subnet0, \
                    self.subnet(network=network,
                                segment_id=segment1['id'],
                                gateway_ip=gateway_ips[1],
                                cidr=cidrs[1]) as subnet1:
                pass

        return net, subnet0['subnet'], subnet1['subnet']

    def test_host_routes_two_subnets_with_segments_association(self):
        """Creates two subnets associated to different segments.

        Since the two subnets are associated with different segments on the
        same network host routes will be created.
        """
        gateway_ips = ['10.0.1.1', '10.0.2.1']
        cidrs = ['10.0.1.0/24', '10.0.2.0/24']
        host_routes = [{'destination': cidrs[1], 'nexthop': gateway_ips[0]},
                       {'destination': cidrs[0], 'nexthop': gateway_ips[1]}]
        net, subnet0, subnet1 = self._create_subnets_segments(gateway_ips,
                                                              cidrs)

        net_req = self.new_show_request('networks', net['id'])
        raw_res = net_req.get_response(self.api)
        net_res = self.deserialize(self.fmt, raw_res)
        for subnet_id in net_res['network']['subnets']:
            sub_req = self.new_show_request('subnets', subnet_id)
            raw_res = sub_req.get_response(self.api)
            sub_res = self.deserialize(self.fmt, raw_res)['subnet']
            self.assertIn(sub_res['cidr'], cidrs)
            self.assertIn(sub_res['gateway_ip'], gateway_ips)
            self.assertIn(sub_res['host_routes'][0], host_routes)

    def test_host_routes_two_subnets_with_same_segment_association(self):
        """Creates two subnets associated to the same segment.

        Since the two subnets are both associated with the same segment no host
        routes will be created.
        """
        gateway_ips = ['10.0.1.1', '10.0.2.1']
        cidrs = ['10.0.1.0/24', '10.0.2.0/24']
        with self.network() as network:
            net = network['network']
            segment = self._test_create_segment(
                network_id=net['id'],
                physical_network='physnet1',
                network_type=constants.TYPE_VLAN,
                segmentation_id=201)['segment']

            with self.subnet(network=network,
                             segment_id=segment['id'],
                             gateway_ip=gateway_ips[0],
                             cidr=cidrs[0]) as subnet0, \
                    self.subnet(network=network,
                                segment_id=segment['id'],
                                gateway_ip=gateway_ips[1],
                                cidr=cidrs[1]) as subnet1:
                subnet0 = subnet0['subnet']
                subnet1 = subnet1['subnet']

        req = self.new_show_request('subnets', subnet0['id'])
        res = req.get_response(self.api)
        res_subnet0 = self.deserialize(self.fmt, res)

        req = self.new_show_request('subnets', subnet1['id'])
        res = req.get_response(self.api)
        res_subnet1 = self.deserialize(self.fmt, res)

        self.assertEqual([], res_subnet0['subnet']['host_routes'])
        self.assertEqual([], res_subnet1['subnet']['host_routes'])

    def test_host_routes_create_two_subnets_then_delete_one(self):
        """Delete subnet after creating two subnets associated same segment.

        Host routes with destination to the subnet that is deleted are removed
        from the remaining subnets.
        """
        gateway_ips = ['10.0.1.1', '10.0.2.1']
        cidrs = ['10.0.1.0/24', '10.0.2.0/24']
        net, subnet0, subnet1 = self._create_subnets_segments(gateway_ips,
                                                              cidrs)

        sh_req = self.new_show_request('subnets', subnet1['id'])
        raw_res = sh_req.get_response(self.api)
        sub_res = self.deserialize(self.fmt, raw_res)
        self.assertEqual([{'destination': cidrs[0],
                           'nexthop': gateway_ips[1]}],
                         sub_res['subnet']['host_routes'])

        del_req = self.new_delete_request('subnets', subnet0['id'])
        del_req.get_response(self.api)

        sh_req = self.new_show_request('subnets', subnet1['id'])
        raw_res = sh_req.get_response(self.api)
        sub_res = self.deserialize(self.fmt, raw_res)

        self.assertEqual([], sub_res['subnet']['host_routes'])

    def test_host_routes_two_subnets_then_change_gateway_ip(self):
        gateway_ips = ['10.0.1.1', '10.0.2.1']
        cidrs = ['10.0.1.0/24', '10.0.2.0/24']
        host_routes = [{'destination': cidrs[1], 'nexthop': gateway_ips[0]},
                       {'destination': cidrs[0], 'nexthop': gateway_ips[1]}]
        net, subnet0, subnet1 = self._create_subnets_segments(gateway_ips,
                                                              cidrs)

        net_req = self.new_show_request('networks', net['id'])
        raw_res = net_req.get_response(self.api)
        net_res = self.deserialize(self.fmt, raw_res)
        for subnet_id in net_res['network']['subnets']:
            sub_req = self.new_show_request('subnets', subnet_id)
            raw_res = sub_req.get_response(self.api)
            sub_res = self.deserialize(self.fmt, raw_res)['subnet']
            self.assertIn(sub_res['cidr'], cidrs)
            self.assertIn(sub_res['gateway_ip'], gateway_ips)
            self.assertIn(sub_res['host_routes'][0], host_routes)

        new_gateway_ip = '10.0.1.254'
        data = {'subnet': {'gateway_ip': new_gateway_ip,
                           'allocation_pools': [{'start': '10.0.1.1',
                                                 'end': '10.0.1.253'}]}}
        self.new_update_request(
            'subnets', data, subnet0['id']).get_response(self.api)

        sh_req = self.new_show_request('subnets', subnet0['id'])
        raw_res = sh_req.get_response(self.api)
        sub_res = self.deserialize(self.fmt, raw_res)

        self.assertEqual([{'destination': cidrs[1],
                           'nexthop': new_gateway_ip}],
                         sub_res['subnet']['host_routes'])

    def test_host_routes_two_subnets_summary_route_in_request(self):
        gateway_ips = ['10.0.1.1', '10.0.2.1']
        cidrs = ['10.0.1.0/24', '10.0.2.0/24']
        summary_net = '10.0.0.0/16'
        host_routes = [{'destination': summary_net, 'nexthop': gateway_ips[0]},
                       {'destination': summary_net, 'nexthop': gateway_ips[1]}]

        with self.network() as network:
            net = network['network']
            segment0 = self._test_create_segment(
                network_id=net['id'],
                physical_network='physnet1',
                network_type=constants.TYPE_VLAN,
                segmentation_id=201)['segment']
            segment1 = self._test_create_segment(
                network_id=net['id'],
                physical_network='physnet2',
                network_type=constants.TYPE_VLAN,
                segmentation_id=202)['segment']

            self.subnet(network=network, segment_id=segment0['id'],
                        gateway_ip=gateway_ips[0], cidr=cidrs[0],
                        host_routes=[host_routes[0]])
            self.subnet(network=network, segment_id=segment1['id'],
                        gateway_ip=gateway_ips[1],
                        cidr=cidrs[1], host_routes=[host_routes[1]])

        net_req = self.new_show_request('networks', net['id'])
        raw_res = net_req.get_response(self.api)
        net_res = self.deserialize(self.fmt, raw_res)

        for subnet_id in net_res['network']['subnets']:
            sub_req = self.new_show_request('subnets', subnet_id)
            raw_res = sub_req.get_response(self.api)
            sub_res = self.deserialize(self.fmt, raw_res)['subnet']
            self.assertIn(sub_res['cidr'], cidrs)
            self.assertIn(sub_res['gateway_ip'], gateway_ips)
            self.assertEqual(len(sub_res['host_routes']), 1)
            self.assertIn(sub_res['host_routes'][0], host_routes)


class TestSegmentHostMappingNoStore(
        test_db_base_plugin_v2.NeutronDbPluginV2TestCase):

    def setUp(self):
        driver_type.register_ml2_drivers_vlan_opts()
        cfg.CONF.set_override('network_vlan_ranges', ['phys_net1'],
                              group='ml2_type_vlan')
        cfg.CONF.set_override('service_plugins', [])
        super(TestSegmentHostMappingNoStore, self).setUp(
            plugin='neutron.plugins.ml2.plugin.Ml2Plugin')
        # set to None for simulating server start
        db._USER_CONFIGURED_SEGMENT_PLUGIN = None
        db.subscribe()

    @mock.patch('neutron.services.segments.db.update_segment_host_mapping')
    @mock.patch('neutron.services.segments.db.map_segment_to_hosts')
    def test_no_segmenthostmapping_when_disable_segment(
            self, mock_map_segment_to_hosts, mock_update_segment_mapping):
        with self.network(
                arg_list=('provider:network_type',
                          'provider:physical_network',
                          'provider:segmentation_id'),
                **{'provider:network_type': 'vlan',
                   'provider:physical_network': 'phys_net1',
                   'provider:segmentation_id': '400'}) as network:
            network['network']
        mock_map_segment_to_hosts.assert_not_called()

        host1 = 'test_host'
        physical_network = 'phys_net1'
        helpers.register_ovs_agent(
            host=host1,
            bridge_mappings={physical_network: 'br-eth-1'},
            plugin=self.plugin)
        mock_update_segment_mapping.assert_not_called()
