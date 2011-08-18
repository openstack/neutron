#!/usr/bin/env python
# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2010-2011 OpenStack, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

""" Middleware for authorizing Quantum Operations
    This is a first and very trivial implementation of a middleware
    for authorizing requests to Quantum API.
    It only verifies that the tenant requesting the operation owns the
    network (and thus the port) on which it is going to operate.
    It also verifies, if the operation involves an interface, that
    the tenant owns that interface by querying an API on the service
    where the interface is defined.
"""

import logging

from webob.exc import HTTPUnauthorized, HTTPForbidden

LOG = logging.getLogger('quantum.common.authorization')


#TODO(salvatore-orlando): This class should extend Middleware class
# defined in common/wsgi.py
class QuantumAuthorization(object):
    """ Authorizes an operation before it reaches the API WSGI app"""

    def __init__(self, app, conf):
        """ Common initialization code """
        LOG.info("Starting the Authorization component")
        self.conf = conf
        self.app = app

    def __call__(self, req, start_response):
        """ Handle incoming request. Authorize. And send downstream. """
        LOG.debug("entering QuantumAuthorization.__call__")
        self.start_response = start_response
        self.req = req

        # Retrieves TENANT ID from headers as the request
        # should already have been authenticated with Keystone
        self.headers = req.copy()
        LOG.debug("Looking for X_TENANT header")
        LOG.debug("Headers:%s" % self.headers)
        if not "HTTP_X_TENANT" in self.headers:
            # This is bad, very bad
            return self._reject()
        LOG.debug("X_TENANT header found:%s", self.headers['HTTP_X_TENANT'])
        auth_tenant_id = self.headers['HTTP_X_TENANT']
        path = self.req['PATH_INFO']
        parts = path.split('/')
        LOG.debug("Request parts:%s", parts)
        #TODO (salvatore-orlando): need bound checking here
        idx = parts.index('tenants') + 1
        req_tenant_id = parts[idx]
        LOG.debug("Tenant ID from request:%s", req_tenant_id)
        if auth_tenant_id != req_tenant_id:
            # This is bad, very bad
            return self._forbid()

        # Okay, authorize it - pass downstream
        return self.app(self.req, self.start_response)

    def _reject(self):
        """Apparently the request has not been authenticated """
        return HTTPUnauthorized()(self.req, self.start_response)

    def _forbid(self):
        """Cannot authorize. Operating on non-owned resources"""
        return HTTPForbidden()(self.req, self.start_response)


def filter_factory(global_conf, **local_conf):
    """Returns a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    def authz_filter(app):
        return QuantumAuthorization(app, conf)
    return authz_filter
