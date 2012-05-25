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
from quantum.api.views import networks as networks_view
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
    """ Network API controller for Quantum API """
    _resource_name = 'network'
    # version will be redefined in child class
    version = None
    _network_ops_param_list = [
        {'param-name': 'name', 'required': True},
        ]

    def _item(self, request, tenant_id, network_id,
              net_details=True, port_details=False):
        # We expect get_network_details to return information
        # concerning logical ports as well.
        network = self._plugin.get_network_details(tenant_id, network_id)
        # Doing this in the API is inefficient
        # TODO(salvatore-orlando): This should be fixed with Bug #834012
        # Don't pass filter options
        ports_data = None
        if port_details:
            port_list = self._plugin.get_all_ports(tenant_id, network_id)
            ports_data = [
                self._plugin.get_port_details(tenant_id, network_id,
                                              port['port-id'])
                for port in port_list]
        builder = networks_view.get_view_builder(request, self.version)
        result = builder.build(network, net_details,
                               ports_data, port_details)['network']
        return dict(network=result)

    def _items(self, request, tenant_id, net_details=False):
        """ Returns a list of networks.
        Ideally, the plugin would perform filtering,
        returning only the items matching filters specified
        on the request query string.
        However, plugins are not required to support filtering.
        In this case, this function will filter the complete list
        of networks returned by the plugin

        """
        filter_opts = {}
        filter_opts.update(request.GET)
        networks = self._plugin.get_all_networks(tenant_id,
                                                 filter_opts=filter_opts)
        # Inefficient, API-layer filtering
        # will be performed only for the filters not implemented by the plugin
        # NOTE(salvatore-orlando): the plugin is supposed to leave only filters
        # it does not implement in filter_opts
        networks = filters.filter_networks(networks,
                                           self._plugin,
                                           tenant_id,
                                           filter_opts)
        builder = networks_view.get_view_builder(request, self.version)
        result = [builder.build(network, net_details)['network']
                  for network in networks]
        return dict(networks=result)

    @common.APIFaultWrapper()
    def index(self, request, tenant_id):
        """ Returns a list of network ids """
        return self._items(request, tenant_id)

    @common.APIFaultWrapper([exception.NetworkNotFound])
    def show(self, request, tenant_id, id):
        """ Returns network details for the given network id """
        return self._item(request, tenant_id, id,
                          net_details=True, port_details=False)

    @common.APIFaultWrapper([exception.NetworkNotFound])
    def detail(self, request, **kwargs):
        tenant_id = kwargs.get('tenant_id')
        network_id = kwargs.get('id')
        if network_id:
            # show details for a given network
            return self._item(request, tenant_id, network_id,
                              net_details=True, port_details=True)
        else:
            # show details for all networks
            return self._items(request, tenant_id, net_details=True)

    @common.APIFaultWrapper()
    def create(self, request, tenant_id, body):
        """ Creates a new network for a given tenant """
        # NOTE(bgh): We're currently passing both request_params['name'] and
        # the entire request_params dict because their may be pieces of
        # information (data extensions) inside the request params that the
        # actual plugin will want to parse.  We could just pass only
        # request_params but that would mean all the plugins would need to
        # change.
        body = self._prepare_request_body(body, self._network_ops_param_list)
        network = self._plugin.create_network(tenant_id,
                                              body['network']['name'],
                                              **body)
        builder = networks_view.get_view_builder(request, self.version)
        result = builder.build(network)['network']
        return dict(network=result)

    @common.APIFaultWrapper([exception.NetworkNotFound])
    def update(self, request, tenant_id, id, body):
        """ Updates the name for the network with the given id """
        body = self._prepare_request_body(body, self._network_ops_param_list)
        self._plugin.update_network(tenant_id, id, **body['network'])

    @common.APIFaultWrapper([exception.NetworkNotFound,
                             exception.NetworkInUse])
    def delete(self, request, tenant_id, id):
        """ Destroys the network with the given id """
        self._plugin.delete_network(tenant_id, id)


class ControllerV10(Controller):
    """Network resources controller for Quantum v1.0 API"""

    _serialization_metadata = {
        "attributes": {
            "network": ["id", "name"],
            "port": ["id", "state"],
            "attachment": ["id"],
            },
        "plurals": {
            "networks": "network",
            "ports": "port",
            },
        }

    version = "1.0"


class ControllerV11(Controller):
    """Network resources controller for Quantum v1.1 API

       Note: at this state this class only adds serialization
       metadata for the operational status concept.
       API filters, pagination, and atom links will be handled by
       this class as well.
    """

    _serialization_metadata = {
        "attributes": {
            "network": ["id", "name", "op-status"],
            "port": ["id", "state", "op-status"],
            "attachment": ["id"],
            },
        "plurals": {
            "networks": "network",
            "ports": "port",
            },
        }

    version = "1.1"
