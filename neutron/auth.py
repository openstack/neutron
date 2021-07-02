#    Copyright 2012 OpenStack Foundation
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

from neutron_lib import context
from oslo_config import cfg
from oslo_log import log as logging
from oslo_middleware import base
import webob.dec
import webob.exc

LOG = logging.getLogger(__name__)


class NeutronKeystoneContext(base.ConfigurableMiddleware):
    """Make a request context from keystone headers."""

    @webob.dec.wsgify
    def __call__(self, req):
        ctx = context.Context.from_environ(req.environ)

        if not ctx.user_id:
            LOG.debug("X_USER_ID is not found in request")
            return webob.exc.HTTPUnauthorized()

        # Inject the context...
        req.environ['neutron.context'] = ctx

        return self.application


class NoauthFakeProjectId(base.ConfigurableMiddleware):
    """Add fake project_id for noauth auth_strategy."""

    @webob.dec.wsgify
    def __call__(self, req):
        ctx = context.Context.from_environ(req.environ)
        if not ctx.project_id:
            # Inject project_id
            ctx.project_id = 'fake_project_id'
            # Inject the context with the admin flag set
            req.environ['neutron.context'] = ctx.elevated()

        return self.application


def pipeline_factory(loader, global_conf, **local_conf):
    """Create a paste pipeline based on the 'auth_strategy' config option."""
    pipeline = local_conf[cfg.CONF.auth_strategy]
    pipeline = pipeline.split()
    filters = [loader.get_filter(n) for n in pipeline[:-1]]
    app = loader.get_app(pipeline[-1])
    filters.reverse()
    for filter in filters:
        app = filter(app)
    return app
