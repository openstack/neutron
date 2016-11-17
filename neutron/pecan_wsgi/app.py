# Copyright (c) 2015 Mirantis, Inc.
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

from keystonemiddleware import auth_token
from neutron_lib import exceptions as n_exc
from oslo_config import cfg
from oslo_middleware import cors
from oslo_middleware import http_proxy_to_wsgi
from oslo_middleware import request_id
import pecan

from neutron.api import versions
from neutron.pecan_wsgi import hooks
from neutron.pecan_wsgi import startup

CONF = cfg.CONF
CONF.import_opt('bind_host', 'neutron.conf.common')
CONF.import_opt('bind_port', 'neutron.conf.common')


def setup_app(*args, **kwargs):
    config = {
        'server': {
            'port': CONF.bind_port,
            'host': CONF.bind_host
        },
        'app': {
            'root': 'neutron.pecan_wsgi.controllers.root.RootController',
            'modules': ['neutron.pecan_wsgi'],
        }
        #TODO(kevinbenton): error templates
    }
    pecan_config = pecan.configuration.conf_from_dict(config)

    app_hooks = [
        hooks.ExceptionTranslationHook(),  # priority 100
        hooks.ContextHook(),  # priority 95
        hooks.BodyValidationHook(),  # priority 120
        hooks.OwnershipValidationHook(),  # priority 125
        hooks.QuotaEnforcementHook(),  # priority 130
        hooks.NotifierHook(),  # priority 135
        hooks.QueryParametersHook(),  # priority 139
        hooks.PolicyHook(),  # priority 140
    ]

    app = pecan.make_app(
        pecan_config.app.root,
        debug=False,
        wrap_app=_wrap_app,
        force_canonical=False,
        hooks=app_hooks,
        guess_content_type_from_ext=True
    )
    startup.initialize_all()

    return app


def _wrap_app(app):
    app = request_id.RequestId(app)
    if cfg.CONF.auth_strategy == 'noauth':
        pass
    elif cfg.CONF.auth_strategy == 'keystone':
        app = auth_token.AuthProtocol(app, {})
    else:
        raise n_exc.InvalidConfigurationOption(
            opt_name='auth_strategy', opt_value=cfg.CONF.auth_strategy)

    # version can be unauthenticated so it goes outside of auth
    app = versions.Versions(app)

    # handle cases where neutron-server is behind a proxy
    app = http_proxy_to_wsgi.HTTPProxyToWSGI(app)

    # This should be the last middleware in the list (which results in
    # it being the first in the middleware chain). This is to ensure
    # that any errors thrown by other middleware, such as an auth
    # middleware - are annotated with CORS headers, and thus accessible
    # by the browser.
    app = cors.CORS(app, cfg.CONF)
    cors.set_defaults(
        allow_headers=['X-Auth-Token', 'X-Identity-Status', 'X-Roles',
                       'X-Service-Catalog', 'X-User-Id', 'X-Tenant-Id',
                       'X-OpenStack-Request-ID',
                       'X-Trace-Info', 'X-Trace-HMAC'],
        allow_methods=['GET', 'PUT', 'POST', 'DELETE', 'PATCH'],
        expose_headers=['X-Auth-Token', 'X-Subject-Token', 'X-Service-Token',
                        'X-OpenStack-Request-ID',
                        'X-Trace-Info', 'X-Trace-HMAC']
    )

    return app
