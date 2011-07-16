# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2011 Cisco Systems, Inc.  All rights reserved.
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
#
# @author: Ying Liu, Cisco Systems, Inc.
#

import logging
import routes
import webob.dec
import webob.exc

from quantum import manager
from quantum.api import faults
from quantum.api import networks
from quantum.api import ports
from quantum.common import flags
from quantum.common import wsgi
from cisco_extensions import portprofiles
from cisco_extensions import extensions


LOG = logging.getLogger('quantum_extension.api')
FLAGS = flags.FLAGS


class ExtRouterV01(wsgi.Router):
    """
    Routes requests on the Quantum API to the appropriate controller
    """
    
    def __init__(self, ext_mgr=None):
        uri_prefix = '/tenants/{tenant_id}/'
       
        mapper = routes.Mapper()
        plugin = manager.QuantumManager().get_plugin() 
        controller = portprofiles.Controller(plugin)
        ext_controller = extensions.Controller(plugin)
        mapper.connect("home", "/", controller=ext_controller, 
                       action="list_extension", 
                       conditions=dict(method=['GET']))
        #mapper.redirect("/", "www.google.com")
        mapper.resource("portprofiles", "portprofiles",
                        controller=controller,
                        path_prefix=uri_prefix)
        mapper.connect("associate_portprofile",
                       uri_prefix 
                       + 'portprofiles/{portprofile_id}/assignment{.format}',
                       controller=controller,
                       action="associate_portprofile",
                       conditions=dict(method=['PUT']))
        mapper.connect("disassociate_portprofile",
                       uri_prefix 
                       + 'portprofiles/{portprofile_id}/assignment{.format}',
                       controller=controller,
                       action="disassociate_portprofile",
                       conditions=dict(method=['DELETE']))
      
        super(ExtRouterV01, self).__init__(mapper)
