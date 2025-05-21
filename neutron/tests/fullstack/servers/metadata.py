#!/usr/bin/env python
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

import sys
from wsgiref import simple_server as wsgi_simple_server

from oslo_config import cfg
from oslo_log import log as logging

from neutron.common import config as common_config

LOG = logging.getLogger(__name__)


metadata_opts = [
    cfg.StrOpt('metadata_host', default='127.0.0.1'),
    cfg.IntOpt('metadata_port', default=8775)
]
cfg.CONF.register_opts(metadata_opts)


class FakeMetadata:

    def wsgi_app(self, env, start_response):
        response_headers = [('Content-Type', 'application/json')]
        http_status = '200 OK'
        LOG.info("HTTP_X_INSTANCE_ID: %s", env.get('HTTP_X_INSTANCE_ID'))
        LOG.info("HTTP_X_TENANT_ID: %s", env.get('HTTP_X_TENANT_ID'))
        LOG.info("HTTP_X_INSTANCE_ID_SIGNATURE: %s",
                 env.get('HTTP_X_INSTANCE_ID_SIGNATURE'))

        # Send the headers back for verify the path
        response_headers += [
            ('RESP_INSTANCE_ID', env.get('HTTP_X_INSTANCE_ID')),
            ('RESP_TENANT_ID', env.get('HTTP_X_TENANT_ID')),
            ('RESP_INSTANCE_ID_SIGNATURE',
             env.get('HTTP_X_INSTANCE_ID_SIGNATURE'))]

        start_response(http_status, response_headers)
        return [b"Metadata OK"]


if __name__ == "__main__":
    common_config.register_common_config_options()
    common_config.init(sys.argv[1:])
    common_config.setup_logging()
    metadata_host = cfg.CONF.metadata_host
    metadata_port = cfg.CONF.metadata_port

    LOG.info("Metadata fixture started on port: %s", metadata_port)

    mock_metadata = FakeMetadata()
    wsgi_simple_server.make_server(
        metadata_host, metadata_port, mock_metadata.wsgi_app).serve_forever()
