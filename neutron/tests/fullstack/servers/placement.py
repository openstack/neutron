#!/usr/bin/env python
# Copyright (c) 2019 Ericsson
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
import sys
import urllib
import uuid
from wsgiref import simple_server as wsgi_simple_server

from oslo_config import cfg
from oslo_config import types
from oslo_log import log as logging
from oslo_serialization import jsonutils

from neutron.common import config as common_config

LOG = logging.getLogger(__name__)


PortType = types.Integer(1, 65535)
placement_opts = [
    cfg.Opt('placement_port', type=PortType)
]
cfg.CONF.register_opts(placement_opts)


class FakePlacement(object):

    rp_template = {
        "uuid": None,
        "generation": 0,
        "parent_provider_uuid": None,
        "name": None,
    }

    def __init__(self):
        self.host_rp_uuid = str(uuid.uuid4())
        host_rp = copy.deepcopy(self.rp_template)
        host_rp['uuid'] = self.host_rp_uuid
        self.resource_providers = {
            self.host_rp_uuid: host_rp
        }

    def get_resource_providers(self, **kwargs):
        id = kwargs.get('id', None)
        if not id:
            return jsonutils.dumps(
                {
                    'resource_providers':
                        [self.resource_providers[self.host_rp_uuid]]
                })
        else:
            return jsonutils.dumps(self.resource_providers[id])

    def put_traits(self, **kwargs):
        # Return empty sting otherwise wsgiref goes mad
        return ''

    def put_resource_providers(self, **kwargs):
        id = kwargs.get('id', None)
        req_body = kwargs.get('body', None)
        if id:
            rp_dict = copy.deepcopy(self.rp_template)
            rp_dict['uuid'] = id
            rp_dict['parent_provider_uuid'] = req_body['parent_provider_uuid']
            rp_dict['name'] = req_body['name']
            self.resource_providers[rp_dict['uuid']] = rp_dict
            return jsonutils.dumps(rp_dict)

    def put_resource_providers_traits(self, **kwargs):
        resp = kwargs['body']
        resp['resource_provider_generation'] += 1
        return jsonutils.dumps(resp)

    def put_resource_providers_inventories(self, **kwargs):
        resp = kwargs['body']
        resp['resource_provider_generation'] += 1
        return jsonutils.dumps(resp)

    def build_method_name(self, action, path_info):
        path_info = urllib.parse.urlparse(path_info).path
        path_info_list = path_info.strip('/').split('/')
        method_name = action.lower()
        for path_chunk in path_info_list:
            if any(s in path_chunk for s in ['placement', 'CUSTOM']):
                continue
            # If there is uuid in the path, that should be thrown out
            try:
                uuid.UUID(path_chunk)
            except ValueError:
                method_name += '_' + path_chunk
        return method_name

    def wsgi_app(self, env, start_response):
        response_headers = [('Content-Type', 'application/json')]
        http_status = '200 OK'

        # Poor men's routing
        meth_name = self.build_method_name(env['REQUEST_METHOD'],
                                           env['PATH_INFO'])
        params = {}
        # Fetch params from url
        try:
            params['id'] = env['PATH_INFO'].split('/')[3]
        except IndexError:
            pass
        # Fetch body
        try:
            request_body_size = int(env.get('CONTENT_LENGTH', 0))
            if request_body_size > 0:
                req_body = env['wsgi.input'].read(request_body_size)
                params['body'] = jsonutils.loads(req_body.decode('utf-8'))
        except ValueError:
            pass
        LOG.debug('Request on %s (%s) with body: %s',
                  env['PATH_INFO'], env['REQUEST_METHOD'], params)
        response = getattr(self, meth_name)(**params)
        LOG.debug('Response from %s: %s', meth_name, response)

        response = response.encode('utf-8')
        start_response(http_status, response_headers)
        return [response]


if __name__ == "__main__":
    common_config.register_common_config_options()
    common_config.init(sys.argv[1:])
    common_config.setup_logging()
    placement_port = cfg.CONF.placement_port

    LOG.info("Placement fixture started on port: %s", placement_port)

    mock_placement = FakePlacement()
    wsgi_simple_server.make_server(
        '', placement_port, mock_placement.wsgi_app).serve_forever()
