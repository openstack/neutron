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

from neutron_lib import constants
from oslo_utils import uuidutils
import webob.exc

from neutron.api.v2 import attributes
from neutron import context
from neutron.db import db_base_plugin_v2
from neutron.db import segments_db
from neutron.extensions import segment as ext_segment
from neutron.services.segments import db
from neutron.tests.unit.db import test_db_base_plugin_v2

DB_PLUGIN_KLASS = ('neutron.tests.unit.extensions.test_segment.'
                   'SegmentTestPlugin')


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

    def setUp(self):
        plugin = DB_PLUGIN_KLASS
        ext_mgr = SegmentTestExtensionManager()
        super(SegmentTestCase, self).setUp(plugin=plugin, ext_mgr=ext_mgr)

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
