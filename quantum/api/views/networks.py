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

from quantum.api.api_common import OperationalStatus


def get_view_builder(req, version):
    base_url = req.application_url
    view_builder = {
        '1.0': ViewBuilder10,
        '1.1': ViewBuilder11,
    }[version](base_url)
    return view_builder


class ViewBuilder10(object):

    def __init__(self, base_url=None):
        """
        :param base_url: url of the root wsgi application
        """
        self.base_url = base_url

    def build(self, network_data, net_detail=False,
              ports_data=None, port_detail=False):
        """Generic method used to generate a network entity."""
        if net_detail:
            network = self._build_detail(network_data)
        else:
            network = self._build_simple(network_data)
        if port_detail:
            ports = [self._build_port(port_data) for port_data in ports_data]
            network['network']['ports'] = ports
        return network

    def _build_simple(self, network_data):
        """Return a simple model of a network."""
        return dict(network=dict(id=network_data['net-id']))

    def _build_detail(self, network_data):
        """Return a detailed model of a network."""
        return dict(network=dict(id=network_data['net-id'],
                                name=network_data['net-name']))

    def _build_port(self, port_data):
        """Return details about a specific logical port."""
        port_dict = dict(id=port_data['port-id'],
                         state=port_data['port-state'])
        if port_data['attachment']:
            port_dict['attachment'] = dict(id=port_data['attachment'])
        return port_dict


class ViewBuilder11(ViewBuilder10):

    def _build_simple(self, network_data):
        """Return a simple model of a network."""
        return dict(network=dict(id=network_data['net-id']))

    def _build_detail(self, network_data):
        """Return a detailed model of a network. """
        op_status = network_data.get('net-op-status',
                                     OperationalStatus.UNKNOWN)
        return dict(network={'id': network_data['net-id'],
                             'name': network_data['net-name'],
                             'op-status': op_status})

    def _build_port(self, port_data):
        """Return details about a specific logical port."""
        op_status = port_data.get('port-op-status',
                                    OperationalStatus.UNKNOWN)
        port_dict = {'id': port_data['port-id'],
                     'state': port_data['port-state'],
                     'op-status': op_status}
        if port_data['attachment']:
            port_dict['attachment'] = dict(id=port_data['attachment'])
        return port_dict
