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

import json
import routes
from webob import Response

from common import wsgi

class NetworkController(wsgi.Controller):
        
    def version(self,request):
        return "Quantum version 0.1"

class API(wsgi.Router):                                                                
    def __init__(self, options):                                                       
        self.options = options
        mapper = routes.Mapper()                                                       
        network_controller = NetworkController()
        mapper.resource("net_controller", "/network", controller=network_controller)
        mapper.connect("/", controller=network_controller, action="version")
        super(API, self).__init__(mapper)
                                                                                      
def app_factory(global_conf, **local_conf):                                            
    conf = global_conf.copy()                                                          
    conf.update(local_conf)
    return API(conf)
