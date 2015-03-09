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


class ServiceClientJSON(service_client.ServiceClient):
    api_version = "v3"

    def update_service(self, service_id, **kwargs):
        """Updates a service."""
        body = self.get_service(service_id)
        name = kwargs.get('name', body['name'])
        type = kwargs.get('type', body['type'])
        desc = kwargs.get('description', body['description'])
        patch_body = {
            'description': desc,
            'type': type,
            'name': name
        }
        patch_body = json.dumps({'service': patch_body})
        resp, body = self.patch('services/%s' % service_id, patch_body)
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body['service'])

    def get_service(self, service_id):
        """Get Service."""
        url = 'services/%s' % service_id
        resp, body = self.get(url)
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body['service'])

    def create_service(self, serv_type, name=None, description=None,
                       enabled=True):
        body_dict = {
            'name': name,
            'type': serv_type,
            'enabled': enabled,
            'description': description,
        }
        body = json.dumps({'service': body_dict})
        resp, body = self.post("services", body)
        self.expected_success(201, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body["service"])

    def delete_service(self, serv_id):
        url = "services/" + serv_id
        resp, body = self.delete(url)
        self.expected_success(204, resp.status)
        return service_client.ResponseBody(resp, body)

    def list_services(self):
        resp, body = self.get('services')
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBodyList(resp, body['services'])
