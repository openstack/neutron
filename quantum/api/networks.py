# Copyright 2011 Citrix Systems.
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

import httplib
import logging

from webob import exc
from xml.dom import minidom

from quantum import manager
from quantum.common import exceptions as exception
from quantum.common import flags
from quantum.common import wsgi
from quantum.api import faults
from quantum.api.views import networks as networks_view

LOG = logging.getLogger('quantum.api.networks')
FLAGS = flags.FLAGS


class Controller(wsgi.Controller):
    """ Network API controller for Quantum API """

    _network_ops_param_list = [{
        'param-name': 'network-name', 
        'required': True},]
    
    _serialization_metadata = {
        "application/xml": {
            "attributes": {
                "network": ["id","name"],
                "link": ["rel", "type", "href"],
            },
        },
    }

    def __init__(self, plugin_conf_file=None):
        self._setup_network_manager()
        super(Controller, self).__init__()

    def _parse_request_params(self, req, params):
        results = {}
        for param in params:
            param_name = param['param-name']
            # 1- parse request body
            # 2- parse request headers
            # prepend param name with a 'x-' prefix
            param_value = req.headers.get("x-" + param_name, None)
            # 3- parse request query parameters
            if not param_value:
                param_value = req.str_GET[param_name]
            if not param_value and param['required']: 
                msg = ("Failed to parse request. " +
                       "Parameter: %(param)s not specified" % locals())
                for line in msg.split('\n'):
                    LOG.error(line)
                raise exc.HTTPBadRequest(msg)
            results[param_name]=param_value
        return results             
        
    def _setup_network_manager(self):
        self.network_manager=manager.QuantumManager().get_manager()
    
    def index(self, req, tenant_id):
        """ Returns a list of network names and ids """
        #TODO: this should be for a given tenant!!!
        return self._items(req, tenant_id, is_detail=False)

    def _items(self, req, tenant_id, is_detail):
        """ Returns a list of networks. """
        networks = self.network_manager.get_all_networks(tenant_id)
        builder = networks_view.get_view_builder(req)
        result = [builder.build(network, is_detail)['network']
                  for network in networks]
        return dict(networks=result)
    
    def show(self, req, tenant_id, id):
        """ Returns network details by network id """
        try:
            network = self.network_manager.get_network_details(
                            tenant_id,id)
            builder = networks_view.get_view_builder(req)
            #build response with details
            result = builder.build(network, True)
            return dict(networks=result)
        except exception.NotFound:
            return faults.Fault(exc.HTTPNotFound())

    def create(self, req, tenant_id):
        """ Creates a new network for a given tenant """
        #look for network name in request
        req_params = \
            self._parse_request_params(req, self._network_ops_param_list)
        network = self.network_manager.create_network(tenant_id, req_params['network-name'])
        builder = networks_view.get_view_builder(req)
        result = builder.build(network)
        return dict(networks=result)

    def update(self, req, tenant_id, id):
        """ Updates the name for the network with the given id """
        try:
            network_name = req.headers['x-network-name']
        except KeyError as e:
            msg = ("Failed to create network. Got error: %(e)s" % locals())
            for line in msg.split('\n'):
                LOG.error(line)
            raise exc.HTTPBadRequest(msg)            

        network = self.network_manager.rename_network(tenant_id,
                 id,network_name)
        if not network:
            raise exc.HTTPNotFound("Network %(id)s could not be found" % locals())
        builder = networks_view.get_view_builder(req)
        result = builder.build(network, True)
        return dict(networks=result)


    def delete(self, req, tenant_id, id):
        """ Destroys the network with the given id """
        try:
            network_name = req.headers['x-network-name']
        except KeyError as e:
            msg = ("Failed to create network. Got error: %(e)s" % locals())
            for line in msg.split('\n'):
                LOG.error(line)
            raise exc.HTTPBadRequest(msg)            

        network = self.network_manager.delete_network(tenant_id, id)
        if not network:
            raise exc.HTTPNotFound("Network %(id)s could not be found" % locals())

        return exc.HTTPAccepted()


