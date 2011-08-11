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
from webob.exc import Request, Response

LOG = logging.getLogger('quantum.common.authorization')

class QuantumAuthorization(object):
    """ Authorizes an operation before it reaches the API WSGI app"""

    def __call__(self, req, start_response):
        """ Handle incoming request. Authorize. And send downstream. """
        LOG.debug("entering QuantumAuthorization.__call__")
        self.start_response = start_response
        self.req = req

        # Retrieves TENANT ID from headers as the request 
        # should already have been authenticated with Keystone
        self.headers = req.copy()
        if not "X_TENANT" in self.headers:
            # This is bad, very bad
            self._reject()
        
        auth_tenant_id = self.headers['X_TENANT']
        path = self.req.path
        parts=path.split('/')
        #TODO (salvatore-orlando): need bound checking here
        idx = parts.index('tenants') + 1
        req_tenant_id = parts[idx]
        
        if auth_tenant_id != req_tenant_id:
            # This is bad, very bad
            self._forbid()
        
        # Okay, authorize it!
        
    def _reject(self):
        """Apparently the request has not been authenticated """
        return HTTPUnauthorized()(self.env,
            self.start_response)
    
    
    def _forbid(self):
        """Cannot authorize. Operating on non-owned resources"""
        return HTTPForbidden()(self.env,
            self.start_response)
        
        
    
def filter_factory(global_conf, **local_conf):
    """Returns a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    def authz_filter(app):
        return QuantumAuthorization(app, conf)
    return authz_filter
