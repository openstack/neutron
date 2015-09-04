# Copyright 2013 Hewlett-Packard Development Company, L.P.
# Copyright 2014 Yahoo Inc
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

# Much of this module is based on the work of the Ironic team
# see http://git.openstack.org/cgit/openstack/ironic/tree/ironic/cmd/api.py

import logging as std_logging
import sys
from wsgiref import simple_server

from oslo_config import cfg
from oslo_log import log as logging
from six.moves import socketserver

from neutron.common import config
from neutron.pecan_wsgi import app
from neutron.i18n import _LI, _LW


CONF = cfg.CONF
LOG = logging.getLogger(__name__)


class ThreadedSimpleServer(socketserver.ThreadingMixIn,
                           simple_server.WSGIServer):
    """A Mixin class to make the API service greenthread-able."""
    pass


def main():
    config.init(sys.argv[1:])
    config.setup_logging()
    application = app.setup_app()

    host = CONF.bind_host
    port = CONF.bind_port

    wsgi = simple_server.make_server(
        host,
        port,
        application,
        server_class=ThreadedSimpleServer
    )

    LOG.warning(
        _LW("Stand-alone Server Serving on http://%(host)s:%(port)s"),
        {'host': host, 'port': port}
    )
    LOG.info(_LI("Configuration:"))
    CONF.log_opt_values(LOG, std_logging.INFO)

    try:
        wsgi.serve_forever()
    except KeyboardInterrupt:
        pass
