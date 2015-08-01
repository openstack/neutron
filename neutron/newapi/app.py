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

from oslo_config import cfg
from oslo_middleware import request_id
import pecan

CONF = cfg.CONF
CONF.import_opt('bind_host', 'neutron.common.config')
CONF.import_opt('bind_port', 'neutron.common.config')


def setup_app(*args, **kwargs):
    config = {
        'server': {
            'port': CONF.bind_port,
            'host': CONF.bind_host
        },
        'app': {
            'root': 'neutron.newapi.controllers.root.RootController',
            'modules': ['neutron.newapi'],
        }
        #TODO(kevinbenton): error templates
    }
    pecan_config = pecan.configuration.conf_from_dict(config)

    app_hooks = []

    app = pecan.make_app(
        pecan_config.app.root,
        debug=False,
        wrap_app=_wrap_app,
        force_canonical=False,
        hooks=app_hooks,
        guess_content_type_from_ext=True
    )

    return app


def _wrap_app(app):
    app = request_id.RequestId(app)
    return app
