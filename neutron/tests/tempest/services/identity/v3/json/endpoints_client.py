# Copyright 2013 OpenStack Foundation
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

from neutron.tests.tempest.common import service_client


class EndPointClientJSON(service_client.ServiceClient):
    api_version = "v3"

    def list_endpoints(self):
        """GET endpoints."""
        resp, body = self.get('endpoints')
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBodyList(resp, body['endpoints'])

    def create_endpoint(self, service_id, interface, url, **kwargs):
        """Create endpoint.

        Normally this function wouldn't allow setting values that are not
        allowed for 'enabled'. Use `force_enabled` to set a non-boolean.

        """
        region = kwargs.get('region', None)
        if 'force_enabled' in kwargs:
            enabled = kwargs.get('force_enabled', None)
        else:
            enabled = kwargs.get('enabled', None)
        post_body = {
            'service_id': service_id,
            'interface': interface,
            'url': url,
            'region': region,
            'enabled': enabled
        }
        post_body = json.dumps({'endpoint': post_body})
        resp, body = self.post('endpoints', post_body)
        self.expected_success(201, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body['endpoint'])

    def update_endpoint(self, endpoint_id, service_id=None, interface=None,
                        url=None, region=None, enabled=None, **kwargs):
        """Updates an endpoint with given parameters.

        Normally this function wouldn't allow setting values that are not
        allowed for 'enabled'. Use `force_enabled` to set a non-boolean.

        """
        post_body = {}
        if service_id is not None:
            post_body['service_id'] = service_id
        if interface is not None:
            post_body['interface'] = interface
        if url is not None:
            post_body['url'] = url
        if region is not None:
            post_body['region'] = region
        if 'force_enabled' in kwargs:
            post_body['enabled'] = kwargs['force_enabled']
        elif enabled is not None:
            post_body['enabled'] = enabled
        post_body = json.dumps({'endpoint': post_body})
        resp, body = self.patch('endpoints/%s' % endpoint_id, post_body)
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body['endpoint'])

    def delete_endpoint(self, endpoint_id):
        """Delete endpoint."""
        resp_header, resp_body = self.delete('endpoints/%s' % endpoint_id)
        self.expected_success(204, resp_header.status)
        return service_client.ResponseBody(resp_header, resp_body)
