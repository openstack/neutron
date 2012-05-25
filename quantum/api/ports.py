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

from quantum.api import api_common as common
from quantum.api.views import filters
from quantum.api.views import ports as ports_view
from quantum.common import exceptions as exception


LOG = logging.getLogger(__name__)


def create_resource(plugin, version):
    controller_dict = {
        '1.0': [ControllerV10(plugin),
                ControllerV10._serialization_metadata,
                common.XML_NS_V10],
        '1.1': [ControllerV11(plugin),
                ControllerV11._serialization_metadata,
                common.XML_NS_V11],
        }
    return common.create_resource(version, controller_dict)


class Controller(common.QuantumController):
    """ Port API controller for Quantum API """
    _resource_name = 'port'
    # version will be redefined in child class
    version = None
    _port_ops_param_list = [
        {'param-name': 'state', 'default-value': 'DOWN', 'required': False},
        ]

    def _items(self, request, tenant_id, network_id,
               port_details=False):
        """ Returns a list of ports.
        Ideally, the plugin would perform filtering,
        returning only the items matching filters specified
        on the request query string.
        However, plugins are not required to support filtering.
        In this case, this function will filter the complete list
        of ports returned by the plugin
        """
        filter_opts = {}
        filter_opts.update(request.GET)
        port_list = self._plugin.get_all_ports(tenant_id,
                                               network_id,
                                               filter_opts=filter_opts)

        builder = ports_view.get_view_builder(request, self.version)

        # Load extra data for ports if required.
        # This can be inefficient.
        # TODO(salvatore-orlando): the fix for bug #834012 should deal with it
        if port_details:
            port_list_detail = [
                self._plugin.get_port_details(tenant_id, network_id,
                                              port['port-id'])
                for port in port_list]
            port_list = port_list_detail

        # Perform manual filtering if not supported by plugin
        # Inefficient, API-layer filtering
        # will be performed only if the plugin does
        # not support filtering
        # NOTE(salvatore-orlando): the plugin is supposed to leave only filters
        # it does not implement in filter_opts
        port_list = filters.filter_ports(port_list, self._plugin,
                                         tenant_id, network_id,
                                         filter_opts)

        result = [builder.build(port, port_details)['port']
                  for port in port_list]
        return dict(ports=result)

    def _item(self, request, tenant_id, network_id, port_id,
              att_details=False):
        """ Returns a specific port. """
        port = self._plugin.get_port_details(tenant_id, network_id, port_id)
        builder = ports_view.get_view_builder(request, self.version)
        result = builder.build(port, port_details=True,
                               att_details=att_details)['port']
        return dict(port=result)

    @common.APIFaultWrapper([exception.NetworkNotFound])
    def index(self, request, tenant_id, network_id):
        """ Returns a list of port ids for a given network """
        return self._items(request, tenant_id, network_id, port_details=False)

    @common.APIFaultWrapper([exception.NetworkNotFound,
                             exception.PortNotFound])
    def show(self, request, tenant_id, network_id, id):
        """ Returns port details for given port and network """
        return self._item(request, tenant_id, network_id, id)

    @common.APIFaultWrapper([exception.NetworkNotFound,
                             exception.PortNotFound])
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

    @common.APIFaultWrapper([exception.NetworkNotFound,
                             exception.StateInvalid])
    def create(self, request, tenant_id, network_id, body=None):
        """ Creates a new port for a given network
            The request body is optional for a port object.

        """
        body = self._prepare_request_body(body, self._port_ops_param_list)
        port = self._plugin.create_port(tenant_id,
                                        network_id, body['port']['state'],
                                        **body)
        builder = ports_view.get_view_builder(request, self.version)
        result = builder.build(port)['port']
        return dict(port=result)

    @common.APIFaultWrapper([exception.NetworkNotFound,
                             exception.PortNotFound,
                             exception.StateInvalid])
    def update(self, request, tenant_id, network_id, id, body):
        """ Updates the state of a port for a given network """
        body = self._prepare_request_body(body, self._port_ops_param_list)
        self._plugin.update_port(tenant_id, network_id, id, **body['port'])

    @common.APIFaultWrapper([exception.NetworkNotFound,
                             exception.PortNotFound,
                             exception.PortInUse])
    def delete(self, request, tenant_id, network_id, id):
        """ Destroys the port with the given id """
        self._plugin.delete_port(tenant_id, network_id, id)


class ControllerV10(Controller):
    """Port resources controller for Quantum v1.0 API"""

    _serialization_metadata = {
        "attributes": {
            "port": ["id", "state"],
            "attachment": ["id"],
            },
        "plurals": {
            "ports": "port",
            },
        }

    version = "1.0"


class ControllerV11(Controller):
    """Port resources controller for Quantum v1.1 API"""

    _serialization_metadata = {
        "attributes": {
            "port": ["id", "state", "op-status"],
            "attachment": ["id"],
            },
        "plurals": {
            "ports": "port",
            },
        }

    version = "1.1"
