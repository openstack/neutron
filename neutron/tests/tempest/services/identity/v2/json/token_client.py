# Copyright 2015 NEC Corporation.  All rights reserved.
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
from tempest_lib.common import rest_client
from tempest_lib import exceptions as lib_exc

from neutron.tests.tempest.common import service_client
from neutron.tests.tempest import exceptions


class TokenClientJSON(rest_client.RestClient):

    def __init__(self, auth_url, disable_ssl_certificate_validation=None,
                 ca_certs=None, trace_requests=None):
        dscv = disable_ssl_certificate_validation
        super(TokenClientJSON, self).__init__(
            None, None, None, disable_ssl_certificate_validation=dscv,
            ca_certs=ca_certs, trace_requests=trace_requests)

        # Normalize URI to ensure /tokens is in it.
        if 'tokens' not in auth_url:
            auth_url = auth_url.rstrip('/') + '/tokens'

        self.auth_url = auth_url

    def auth(self, user, password, tenant=None):
        creds = {
            'auth': {
                'passwordCredentials': {
                    'username': user,
                    'password': password,
                },
            }
        }

        if tenant:
            creds['auth']['tenantName'] = tenant

        body = json.dumps(creds)
        resp, body = self.post(self.auth_url, body=body)
        self.expected_success(200, resp.status)

        return service_client.ResponseBody(resp, body['access'])

    def auth_token(self, token_id, tenant=None):
        creds = {
            'auth': {
                'token': {
                    'id': token_id,
                },
            }
        }

        if tenant:
            creds['auth']['tenantName'] = tenant

        body = json.dumps(creds)
        resp, body = self.post(self.auth_url, body=body)
        self.expected_success(200, resp.status)

        return service_client.ResponseBody(resp, body['access'])

    def request(self, method, url, extra_headers=False, headers=None,
                body=None):
        """A simple HTTP request interface."""
        if headers is None:
            headers = self.get_headers(accept_type="json")
        elif extra_headers:
            try:
                headers.update(self.get_headers(accept_type="json"))
            except (ValueError, TypeError):
                headers = self.get_headers(accept_type="json")

        resp, resp_body = self.raw_request(url, method,
                                           headers=headers, body=body)
        self._log_request(method, url, resp)

        if resp.status in [401, 403]:
            resp_body = json.loads(resp_body)
            raise lib_exc.Unauthorized(resp_body['error']['message'])
        elif resp.status not in [200, 201]:
            raise exceptions.IdentityError(
                'Unexpected status code {0}'.format(resp.status))

        if isinstance(resp_body, str):
            resp_body = json.loads(resp_body)
        return resp, resp_body

    def get_token(self, user, password, tenant, auth_data=False):
        """
        Returns (token id, token data) for supplied credentials
        """
        body = self.auth(user, password, tenant)

        if auth_data:
            return body['token']['id'], body
        else:
            return body['token']['id']
