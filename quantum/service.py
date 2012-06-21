# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2011 Nicira Networks, Inc
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

import logging

from quantum.common import config
from quantum.openstack.common import cfg
from quantum import wsgi


LOG = logging.getLogger(__name__)


class WsgiService(object):
    """Base class for WSGI based services.

    For each api you define, you must also define these flags:
    :<api>_listen: The address on which to listen
    :<api>_listen_port: The port on which to listen

    """

    def __init__(self, app_name):
        self.app_name = app_name
        self.wsgi_app = None

    def start(self):
        self.wsgi_app = _run_wsgi(self.app_name)

    def wait(self):
        self.wsgi_app.wait()


class QuantumApiService(WsgiService):
    """Class for quantum-api service."""

    @classmethod
    def create(cls):
        app_name = "quantum"

        # Setup logging early, supplying both the CLI options and the
        # configuration mapping from the config file
        # We only update the conf dict for the verbose and debug
        # flags. Everything else must be set up in the conf file...
        # Log the options used when starting if we're in debug mode...

        config.setup_logging(cfg.CONF)
        LOG.debug("*" * 80)
        LOG.debug("Configuration options gathered from config file:")
        LOG.debug("================================================")
        items = dict([(k, v) for k, v in cfg.CONF.items()
                      if k not in ('__file__', 'here')])
        for key, value in sorted(items.items()):
            LOG.debug("%(key)-30s %(value)s" % {'key': key,
                                                'value': value,
                                                })
        LOG.debug("*" * 80)
        service = cls(app_name)
        return service


def serve_wsgi(cls):
    try:
        service = cls.create()
    except Exception:
        logging.exception('in WsgiService.create()')
        raise

    service.start()

    return service


def _run_wsgi(app_name):
    app = config.load_paste_app(app_name)
    if not app:
        LOG.error(_('No known API applications configured.'))
        return
    server = wsgi.Server("Quantum")
    server.start(app, cfg.CONF.bind_port, cfg.CONF.bind_host)
    return server
