#!/usr/bin/env python
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

import logging as std_logging
from wsgiref import simple_server

from oslo_config import cfg
from oslo_log import log
from six.moves import socketserver

from neutron._i18n import _LI, _LW
from neutron.common import rpc as n_rpc
from neutron.pecan_wsgi import app as pecan_app
from neutron import server

LOG = log.getLogger(__name__)


class ThreadedSimpleServer(socketserver.ThreadingMixIn,
                           simple_server.WSGIServer):
    pass


def _pecan_wsgi_server():
    LOG.info(_LI("Pecan WSGI server starting..."))
    # No AMQP connection should be created within this process
    n_rpc.RPC_DISABLED = True
    application = pecan_app.setup_app()

    host = cfg.CONF.bind_host
    port = cfg.CONF.bind_port

    wsgi = simple_server.make_server(
        host,
        port,
        application,
        server_class=ThreadedSimpleServer
    )
    # Log option values
    cfg.CONF.log_opt_values(LOG, std_logging.DEBUG)
    LOG.warning(
        _LW("Development Server Serving on http://%(host)s:%(port)s"),
        {'host': host, 'port': port}
    )

    wsgi.serve_forever()


def main():
    server.boot_server(_pecan_wsgi_server)
