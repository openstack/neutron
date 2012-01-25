# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 Citrix Systems
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


LOG = logging.getLogger('quantum.api.views.filters')


def _load_network_ports_details(network, **kwargs):
    plugin = kwargs.get('plugin', None)
    tenant_id = kwargs.get('tenant_id', None)
    #load network details only if required
    if not 'net-ports' in network:
        # Don't pass filter options, don't care about unused filters
        port_list = plugin.get_all_ports(tenant_id, network['net-id'])
        ports_data = [plugin.get_port_details(
                                   tenant_id, network['net-id'],
                                   port['port-id'])
                      for port in port_list]
        network['net-ports'] = ports_data


def _filter_network_by_name(network, name, **kwargs):
    return network.get('net-name', None) == name


def _filter_network_with_operational_port(network, port_op_status,
                                          **kwargs):
    _load_network_ports_details(network, **kwargs)
    return any([port['port-op-status'] == port_op_status
                for port in network['net-ports']])


def _filter_network_with_active_port(network, port_state, **kwargs):
    _load_network_ports_details(network, **kwargs)
    return any([port['port-state'] == port_state
                for port in network['net-ports']])


def _filter_network_has_interface(network, has_interface, **kwargs):
    _load_network_ports_details(network, **kwargs)
    # convert to bool
    match_has_interface = has_interface.lower() == 'true'
    really_has_interface = any([port['attachment'] is not None
                                for port in network['net-ports']])
    return match_has_interface == really_has_interface


def _filter_network_by_port(network, port_id, **kwargs):
    _load_network_ports_details(network, **kwargs)
    return any([port['port-id'] == port_id
                for port in network['net-ports']])


def _filter_network_by_interface(network, interface_id, **kwargs):
    _load_network_ports_details(network, **kwargs)
    return any([port.get('attachment', None) == interface_id
                for port in network['net-ports']])


def _filter_port_by_state(port, state, **kwargs):
    return port.get('port-state', None) == state


def _filter_network_by_op_status(network, op_status, **kwargs):
    return network.get('net-op-status', None) == op_status


def _filter_port_by_op_status(port, op_status, **kwargs):
    return port.get('port-op-status', None) == op_status


def _filter_port_by_interface(port, interface_id, **kwargs):
    return port.get('attachment', None) == interface_id


def _filter_port_has_interface(port, has_interface, **kwargs):
    # convert to bool
    match_has_interface = has_interface.lower() == 'true'
    really_has_interface = 'attachment' in port and port['attachment'] != None
    return match_has_interface == really_has_interface


def _do_filtering(items, filters, filter_opts, plugin,
                  tenant_id, network_id=None):
    filtered_items = []
    for item in items:
        is_filter_match = False
        for flt in filters:
            if flt in filter_opts:
                is_filter_match = filters[flt](item,
                                               filter_opts[flt],
                                               plugin=plugin,
                                               tenant_id=tenant_id,
                                               network_id=network_id)
                if not is_filter_match:
                    break
        if is_filter_match:
            filtered_items.append(item)
    return filtered_items


def filter_networks(networks, plugin, tenant_id, filter_opts):
    # Do filtering only if the plugin supports it
    # and if filtering options have been specific
    if len(filter_opts) == 0:
        return networks

    # load filter functions
    filters = {
        'name': _filter_network_by_name,
        'op-status': _filter_network_by_op_status,
        'port-op-status': _filter_network_with_operational_port,
        'port-state': _filter_network_with_active_port,
        'has-attachment': _filter_network_has_interface,
        'attachment': _filter_network_by_interface,
        'port': _filter_network_by_port}
    # filter networks
    return _do_filtering(networks, filters, filter_opts, plugin, tenant_id)


def filter_ports(ports, plugin, tenant_id, network_id, filter_opts):
    # Do filtering only if the plugin supports it
    # and if filtering options have been specific
    if len(filter_opts) == 0:
        return ports

    # load filter functions
    filters = {
        'state': _filter_port_by_state,
        'op-status': _filter_port_by_op_status,
        'has-attachment': _filter_port_has_interface,
        'attachment': _filter_port_by_interface}
    # port details are need for filtering
    ports = [plugin.get_port_details(tenant_id, network_id,
                                     port['port-id'])
              for port in ports]
    # filter ports
    return _do_filtering(ports,
                         filters,
                         filter_opts,
                         plugin,
                         tenant_id,
                         network_id)
