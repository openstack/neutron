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

import webob.exc

from neutron.api.v2 import attributes
from neutron.db import db_base_plugin_v2
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
