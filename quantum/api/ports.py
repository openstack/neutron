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

import logging

from webob import exc

from quantum.api import api_common as common
from quantum.api import faults
from quantum.api.views import ports as ports_view
from quantum.common import exceptions as exception

LOG = logging.getLogger('quantum.api.ports')


class Controller(common.QuantumController):
    """ Port API controller for Quantum API """

    _port_ops_param_list = [{
        'param-name': 'state',
        'default-value': 'DOWN',
        'required': False}, ]

    _serialization_metadata = {
        "application/xml": {
            "attributes": {
                "port": ["id", "state"],
                "attachment": ["id"]},
            "plurals": {"ports": "port"}},
    }

    def __init__(self, plugin):
        self._resource_name = 'port'
        super(Controller, self).__init__(plugin)

    def _items(self, request, tenant_id, network_id,
               port_details=False):
        """ Returns a list of ports. """
        try:
            port_list = self._plugin.get_all_ports(tenant_id, network_id)
            builder = ports_view.get_view_builder(request)

            # Load extra data for ports if required.
            if port_details:
                port_list_detail = \
                    [self._plugin.get_port_details(
                                tenant_id, network_id, port['port-id'])
                      for port in port_list]
                port_list = port_list_detail

            result = [builder.build(port, port_details)['port']
                      for port in port_list]
            return dict(ports=result)
        except exception.NetworkNotFound as e:
            return faults.Fault(faults.NetworkNotFound(e))

    def _item(self, request, tenant_id, network_id, port_id,
              att_details=False):
        """ Returns a specific port. """
        port = self._plugin.get_port_details(
                        tenant_id, network_id, port_id)
        builder = ports_view.get_view_builder(request)
        result = builder.build(port, port_details=True,
                               att_details=att_details)['port']
        return dict(port=result)

    def index(self, request, tenant_id, network_id):
        """ Returns a list of port ids for a given network """
        return self._items(request, tenant_id, network_id, port_details=False)

    def show(self, request, tenant_id, network_id, id):
        """ Returns port details for given port and network """
        try:
            return self._item(request, tenant_id, network_id, id)
        except exception.NetworkNotFound as e:
            return faults.Fault(faults.NetworkNotFound(e))
        except exception.PortNotFound as e:
            return faults.Fault(faults.PortNotFound(e))

    def detail(self, request, **kwargs):
        tenant_id = kwargs.get('tenant_id')
        network_id = kwargs.get('network_id')
        port_id = kwargs.get('id')
        if port_id:
            # show details for a given network
            return self._item(request, tenant_id,
                              network_id, port_id, att_details=True)
        else:
            # show details for all port
            return self._items(request, tenant_id,
                               network_id, port_details=True)

    def create(self, request, tenant_id, network_id):
        """ Creates a new port for a given network """
        #look for port state in request
        try:
            request_params = \
                self._parse_request_params(request, self._port_ops_param_list)
        except exc.HTTPError as e:
            return faults.Fault(e)
        try:
            port = self._plugin.create_port(tenant_id,
                                            network_id,
                                            request_params['state'])
            builder = ports_view.get_view_builder(request)
            result = builder.build(port)['port']
            return dict(port=result)
        except exception.NetworkNotFound as e:
            return faults.Fault(faults.NetworkNotFound(e))
        except exception.StateInvalid as e:
            return faults.Fault(faults.RequestedStateInvalid(e))

    def update(self, request, tenant_id, network_id, id):
        """ Updates the state of a port for a given network """
        #look for port state in request
        try:
            request_params = \
                self._parse_request_params(request, self._port_ops_param_list)
        except exc.HTTPError as e:
            return faults.Fault(e)
        try:
            self._plugin.update_port(tenant_id, network_id, id,
                                     request_params['state'])
            return exc.HTTPNoContent()
        except exception.NetworkNotFound as e:
            return faults.Fault(faults.NetworkNotFound(e))
        except exception.PortNotFound as e:
            return faults.Fault(faults.PortNotFound(e))
        except exception.StateInvalid as e:
            return faults.Fault(faults.RequestedStateInvalid(e))

    def delete(self, request, tenant_id, network_id, id):
        """ Destroys the port with the given id """
        #look for port state in request
        try:
            self._plugin.delete_port(tenant_id, network_id, id)
            return exc.HTTPNoContent()
        except exception.NetworkNotFound as e:
            return faults.Fault(faults.NetworkNotFound(e))
        except exception.PortNotFound as e:
            return faults.Fault(faults.PortNotFound(e))
        except exception.PortInUse as e:
            return faults.Fault(faults.PortInUse(e))
