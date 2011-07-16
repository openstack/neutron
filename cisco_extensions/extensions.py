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
import webob.dec

from quantum.common import wsgi
from quantum.api import api_common as common


LOG = logging.getLogger('quantum.api.cisco_extension.extensions')


class Controller(common.QuantumController):

    def __init__(self, plugin):
        #self._plugin = plugin
        #super(QuantumController, self).__init__()
        self._resource_name = 'extensions'
        super(Controller, self).__init__(plugin)
        
    def list_extension(self, req):
        """Respond to a request for listing all extension api."""
        response = "extensions api list"
        return response
    
        