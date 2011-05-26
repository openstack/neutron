# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright 2011 Citrix Systems
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
# @author: Salvatore Orlando, Citrix Systems

"""
Quantum API controllers.
"""

import logging
import routes
import webob.dec
import webob.exc

from quantum.api import faults
from quantum.api import networks
from quantum.common import flags
from quantum.common import wsgi


LOG = logging.getLogger('quantum.api')
FLAGS = flags.FLAGS

class FaultWrapper(wsgi.Middleware):
    """Calls down the middleware stack, making exceptions into faults."""

    @webob.dec.wsgify(RequestClass=wsgi.Request)
    def __call__(self, req):
        try:
            return req.get_response(self.application)
        except Exception as ex:
            LOG.exception(_("Caught error: %s"), unicode(ex))
            exc = webob.exc.HTTPInternalServerError(explanation=unicode(ex))
            return faults.Fault(exc)


class APIRouterV01(wsgi.Router):
    """
    Routes requests on the Quantum API to the appropriate controller
    """

    def __init__(self, ext_mgr=None):
        mapper = routes.Mapper()
        self._setup_routes(mapper)
        super(APIRouterV01, self).__init__(mapper)

    def _setup_routes(self, mapper):
        #server_members = self.server_members
        #server_members['action'] = 'POST'

        #server_members['pause'] = 'POST'
        #server_members['unpause'] = 'POST'
        #server_members['diagnostics'] = 'GET'
        #server_members['actions'] = 'GET'
        #server_members['suspend'] = 'POST'
        #server_members['resume'] = 'POST'
        #server_members['rescue'] = 'POST'
        #server_members['unrescue'] = 'POST'
        #server_members['reset_network'] = 'POST'
        #server_members['inject_network_info'] = 'POST'
        mapper.resource("/tenants/{tenant_id}/network", "/tenants/{tenant_id}/networks", controller=networks.Controller())
        print "AFTER MAPPING"
        print mapper
        for route in mapper.matchlist:
            print "Found route:%s %s" %(route.defaults,route.conditions)            
        #mapper.resource("port", "ports", controller=ports.Controller(),
        #        collection=dict(public='GET', private='GET'),
        #        parent_resource=dict(member_name='network',
        #                             collection_name='networks'))

