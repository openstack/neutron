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
from quantum.common import exceptions as exception
from quantum import wsgi


LOG = logging.getLogger(__name__)


class WsgiService(object):
    """Base class for WSGI based services.

    For each api you define, you must also define these flags:
    :<api>_listen: The address on which to listen
    :<api>_listen_port: The port on which to listen

    """

    def __init__(self, app_name, conf_file, conf):
        self.app_name = app_name
        self.conf_file = conf_file
        self.conf = conf
        self.wsgi_app = None

    def start(self):
        self.wsgi_app = _run_wsgi(self.app_name, self.conf, self.conf_file)

    def wait(self):
        self.wsgi_app.wait()


class QuantumApiService(WsgiService):
    """Class for quantum-api service."""

    @classmethod
    def create(cls, conf=None, options=None, args=None):
        app_name = "quantum"
        if not conf:
            conf_file, conf = config.load_paste_config(app_name, options, args)
            if not conf:
                message = (_('No paste configuration found for: %s'), app_name)
                raise exception.Error(message)

        # Setup logging early, supplying both the CLI options and the
        # configuration mapping from the config file
        # We only update the conf dict for the verbose and debug
        # flags. Everything else must be set up in the conf file...
        # Log the options used when starting if we're in debug mode...

        config.setup_logging(options, conf)
        debug = (options.get('debug') or
                 config.get_option(conf, 'debug', type='bool', default=False))
        verbose = (options.get('verbose') or
                   config.get_option(conf, 'verbose', type='bool',
                                     default=False))
        conf['debug'] = debug
        conf['verbose'] = verbose
        LOG.debug("*" * 80)
        LOG.debug("Configuration options gathered from config file:")
        LOG.debug(conf_file)
        LOG.debug("================================================")
        items = dict([(k, v) for k, v in conf.items()
                      if k not in ('__file__', 'here')])
        for key, value in sorted(items.items()):
            LOG.debug("%(key)-30s %(value)s" % {'key': key,
                                                'value': value,
                                                })
        LOG.debug("*" * 80)
        service = cls(app_name, conf_file, conf)
        return service


def serve_wsgi(cls, conf=None, options=None, args=None):
    try:
        service = cls.create(conf, options, args)
    except Exception:
        logging.exception('in WsgiService.create()')
        raise

    service.start()

    return service


def _run_wsgi(app_name, paste_conf, paste_config_file):
    LOG.info(_('Using paste.deploy config at: %s'), paste_config_file)
    conf, app = config.load_paste_app(app_name,
                                      {'config_file': paste_config_file},
                                      None)
    if not app:
        LOG.error(_('No known API applications configured in %s.'),
                  paste_config_file)
        return
    server = wsgi.Server("Quantum")
    server.start(app, int(paste_conf['bind_port']), paste_conf['bind_host'])
    return server
