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


class V3TokenClientJSON(rest_client.RestClient):

    def __init__(self, auth_url, disable_ssl_certificate_validation=None,
                 ca_certs=None, trace_requests=None):
        dscv = disable_ssl_certificate_validation
        super(V3TokenClientJSON, self).__init__(
            None, None, None, disable_ssl_certificate_validation=dscv,
            ca_certs=ca_certs, trace_requests=trace_requests)
        if not auth_url:
            raise exceptions.InvalidConfiguration('you must specify a v3 uri '
                                                  'if using the v3 identity '
                                                  'api')
        if 'auth/tokens' not in auth_url:
            auth_url = auth_url.rstrip('/') + '/auth/tokens'

        self.auth_url = auth_url

    def auth(self, user=None, password=None, project=None, user_type='id',
             user_domain=None, project_domain=None, token=None):
        """
        :param user: user id or name, as specified in user_type
        :param user_domain: the user domain
        :param project_domain: the project domain
        :param token: a token to re-scope.

        Accepts different combinations of credentials. Restrictions:
        - project and domain are only name (no id)
        Sample sample valid combinations:
        - token
        - token, project, project_domain
        - user_id, password
        - username, password, user_domain
        - username, password, project, user_domain, project_domain
        Validation is left to the server side.
        """
        creds = {
            'auth': {
                'identity': {
                    'methods': [],
                }
            }
        }
        id_obj = creds['auth']['identity']
        if token:
            id_obj['methods'].append('token')
            id_obj['token'] = {
                'id': token
            }
        if user and password:
            id_obj['methods'].append('password')
            id_obj['password'] = {
                'user': {
                    'password': password,
                }
            }
            if user_type == 'id':
                id_obj['password']['user']['id'] = user
            else:
                id_obj['password']['user']['name'] = user
            if user_domain is not None:
                _domain = dict(name=user_domain)
                id_obj['password']['user']['domain'] = _domain
        if project is not None:
            _domain = dict(name=project_domain)
            _project = dict(name=project, domain=_domain)
            scope = dict(project=_project)
            creds['auth']['scope'] = scope

        body = json.dumps(creds)
        resp, body = self.post(self.auth_url, body=body)
        self.expected_success(201, resp.status)
        return service_client.ResponseBody(resp, body)

    def request(self, method, url, extra_headers=False, headers=None,
                body=None):
        """A simple HTTP request interface."""
        if headers is None:
            # Always accept 'json', for xml token client too.
            # Because XML response is not easily
            # converted to the corresponding JSON one
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
        elif resp.status not in [200, 201, 204]:
            raise exceptions.IdentityError(
                'Unexpected status code {0}'.format(resp.status))

        return resp, json.loads(resp_body)

    def get_token(self, user, password, project=None, project_domain='Default',
                  user_domain='Default', auth_data=False):
        """
        :param user: username
        Returns (token id, token data) for supplied credentials
        """
        body = self.auth(user, password, project, user_type='name',
                         user_domain=user_domain,
                         project_domain=project_domain)

        token = body.response.get('x-subject-token')
        if auth_data:
            return token, body['token']
        else:
            return token
