# Copyright 2014 Hewlett-Packard Development Company, L.P
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

import json

from six.moves.urllib import parse

from neutron.tests.tempest.common import service_client


class RegionClientJSON(service_client.ServiceClient):
    api_version = "v3"

    def create_region(self, description, **kwargs):
        """Create region."""
        req_body = {
            'description': description,
        }
        if kwargs.get('parent_region_id'):
            req_body['parent_region_id'] = kwargs.get('parent_region_id')
        req_body = json.dumps({'region': req_body})
        if kwargs.get('unique_region_id'):
            resp, body = self.put(
                'regions/%s' % kwargs.get('unique_region_id'), req_body)
        else:
            resp, body = self.post('regions', req_body)
        self.expected_success(201, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body['region'])

    def update_region(self, region_id, **kwargs):
        """Updates a region."""
        post_body = {}
        if 'description' in kwargs:
            post_body['description'] = kwargs.get('description')
        if 'parent_region_id' in kwargs:
            post_body['parent_region_id'] = kwargs.get('parent_region_id')
        post_body = json.dumps({'region': post_body})
        resp, body = self.patch('regions/%s' % region_id, post_body)
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body['region'])

    def get_region(self, region_id):
        """Get region."""
        url = 'regions/%s' % region_id
        resp, body = self.get(url)
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body['region'])

    def list_regions(self, params=None):
        """List regions."""
        url = 'regions'
        if params:
            url += '?%s' % parse.urlencode(params)
        resp, body = self.get(url)
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBodyList(resp, body['regions'])

    def delete_region(self, region_id):
        """Delete region."""
        resp, body = self.delete('regions/%s' % region_id)
        self.expected_success(204, resp.status)
        return service_client.ResponseBody(resp, body)
