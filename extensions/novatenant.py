# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2011 OpenStack LLC.
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

from webob import exc

from extensions import _novatenant_view as novatenant_view
from extensions import _exceptions as exception
from extensions import _faults as faults

from quantum.api import api_common as common
from quantum.common import wsgi
from quantum.common import extensions
from quantum.manager import QuantumManager


class Novatenant(object):

    def __init__(self):
        pass

    def get_name(self):
        return "Cisco Nova Tenant"

    def get_alias(self):
        return "Cisco Nova Tenant"

    def get_description(self):
        return "novatenant resource is used by nova side to invoke quantum api"

    def get_namespace(self):
        return ""

    def get_updated(self):
        return "2011-08-09T13:25:27-06:00"

    def get_resources(self):
        parent_resource = dict(member_name="tenant", 
                               collection_name="extensions/csco/tenants")
        member_actions = {'get_host': "PUT",
                          'get_instance_port': "PUT"}
        controller = NovatenantsController(QuantumManager.get_plugin())
        return [extensions.ResourceExtension('novatenants', controller,
                                             parent=parent_resource,
                                             member_actions=member_actions)]


class NovatenantsController(common.QuantumController):
    """ Novatenant API controller
        based on QuantumController """

    _Novatenant_ops_param_list = [{
        'param-name': 'novatenant_name',
        'required': True}]
    
    _get_host_ops_param_list = [{
        'param-name': 'instance_id',
        'required': True}, {
        'param-name': 'instance_desc',
        'required': True}]
    
    _serialization_metadata = {
        "application/xml": {
            "attributes": {
                "novatenant": ["id", "name"],
            },
        },
    }

    def __init__(self, plugin):
        self._resource_name = 'novatenant'
        super(NovatenantsController, self).__init__(plugin)
             
    def index(self, request, tenant_id):
        """ Returns a list of novatenant ids """
        return "novatenant is a dummy resource"

    def _items(self, request, tenant_id, is_detail):
        """ Returns a list of novatenants. """
        return "novatenant is a dummy resource"

    def show(self, request, tenant_id, id):
        """ Returns novatenant details for the given novatenant id """
        return "novatenant is a dummy resource"

    def create(self, request, tenant_id):
        """ Creates a new novatenant for a given tenant """
        return "novatenant is a dummy resource"

    def update(self, request, tenant_id, id):
        """ Updates the name for the novatenant with the given id """
        return "novatenant is a dummy resource"

    def delete(self, request, tenant_id, id):
        """ Destroys the Novatenant with the given id """
        return "novatenant is a dummy resource"
         
    #added for cisco's extension
    def get_host(self, request, tenant_id, id):
        content_type = request.best_match_content_type()
        print "Content type:%s" % content_type
        
        try:
            req_params = \
                self._parse_request_params(request,
                                           self._get_host_ops_param_list)
        except exc.HTTPError as e:
            return faults.Fault(e)
        instance_id = req_params['instance_id']
        
        instance_desc = req_params['instance_desc']
        try:
            host = self._plugin.get_host(tenant_id, instance_id, instance_desc)
            builder = novatenant_view.get_view_builder(request)
            result = builder.build_host(host)
            return result
            #return exc.HTTPAccepted()
        except exception.NovatenantNotFound as e:
            return faults.Fault(faults.NovatenantNotFound(e))
        except exception.PortNotFound as e:
            return faults.Fault(faults.PortNotFound(e))
        
     #added for Cisco extension
    def get_instance_port(self, request, tenant_id, id):
        content_type = request.best_match_content_type()
        print "Content type:%s" % content_type
        
        try:
            req_params = \
                self._parse_request_params(request,
                                           self._get_host_ops_param_list)
        except exc.HTTPError as e:
            return faults.Fault(e)
        instance_id = req_params['instance_id']
       
        instance_desc = req_params['instance_desc']
        try:
            vif = self._plugin. \
            get_instance_port(tenant_id, instance_id, instance_desc)
            builder = novatenant_view.get_view_builder(request)
            result = builder.build_vif(vif)
            return result
            
            return exc.HTTPAccepted()
        except exception.NovatenantNotFound as e:
            return faults.Fault(faults.NovatenantNotFound(e))
        except exception.PortNotFound as e:
            return faults.Fault(faults.PortNotFound(e))
