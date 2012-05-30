# vim: tabstop=4 shiftwidth=4 softtabstop=4

#    Copyright 2012 OpenStack LLC
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

import webob.dec
import webob.exc

from quantum import context
from quantum import wsgi


LOG = logging.getLogger(__name__)


class QuantumKeystoneContext(wsgi.Middleware):
    """Make a request context from keystone headers."""

    @webob.dec.wsgify
    def __call__(self, req):
        # Determine the user ID
        user_id = req.headers.get('X_USER_ID', req.headers.get('X_USER'))
        if not user_id:
            LOG.debug("Neither X_USER_ID nor X_USER found in request")
            return webob.exc.HTTPUnauthorized()

        # Determine the tenant
        tenant_id = req.headers.get('X_TENANT_ID', req.headers.get('X_TENANT'))

        # Suck out the roles
        roles = [r.strip() for r in req.headers.get('X_ROLE', '').split(',')]

        # Create a context with the authentication data
        ctx = context.Context(user_id, tenant_id, roles=roles)

        # Inject the context...
        req.environ['quantum.context'] = ctx

        return self.application
