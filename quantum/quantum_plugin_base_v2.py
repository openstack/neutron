# Copyright 2011 Nicira Networks, Inc.
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
# @author: Dan Wendlandt, Nicira, Inc.

"""
v2 Quantum Plug-in API specification.

QuantumPluginBase provides the definition of minimum set of
methods that needs to be implemented by a v2 Quantum Plug-in.
"""

from abc import ABCMeta, abstractmethod


class QuantumPluginBaseV2(object):

    __metaclass__ = ABCMeta

    @abstractmethod
    def create_subnet(self, context, subnet):
        """
        Create a subnet, which represents a range of IP addresses
        that can be allocated to devices
        : param subnet_data: data describing the prefix
          {
            "network_id": UUID of the network to which this subnet
                          is bound.
            "ip_version": integer indicating IP protocol version.
                          example: 4
            "prefix": string indicating IP prefix indicating addresses
                      that can be allocated for devices on this subnet.
                      example: "10.0.0.0/24"
            "gateway_ip": string indicating the default gateway
                          for devices on this subnet. example: "10.0.0.1"
            "dns_nameservers": list of strings stricting indication the
                               DNS name servers for devices on this
                               subnet.  example: [ "8.8.8.8", "8.8.4.4" ]
            "excluded_ranges" : list of dicts indicating pairs of IPs that
                                should not be allocated from the prefix.
                                example: [ { "start" : "10.0.0.2",
                                             "end" : "10.0.0.5" } ]
            "additional_routes": list of dicts indicating routes beyond
                                 the default gateway and local prefix route
                                 that should be injected into the device.
                                 example: [{"destination": "192.168.0.0/16",
                                              "nexthop": "10.0.0.5" } ]
          }
        """
        pass

    @abstractmethod
    def update_subnet(self, context, id, subnet):
        pass

    @abstractmethod
    def get_subnet(self, context, id, fields=None, verbose=None):
        pass

    @abstractmethod
    def delete_subnet(self, context, id):
        pass

    @abstractmethod
    def get_subnets(self, context, filters=None, fields=None, verbose=None):
        pass

    @abstractmethod
    def create_network(self, context, network):
        """
        Creates a new Virtual Network, assigns a name and associates

        :param net_data:
          {
           'name': a human-readable name associated
                   with network referenced by net-id
                   example: "net-1"
           'admin-state-up': indicates whether this network should
                             be operational.
           'subnets': list of subnet uuids associated with this
                      network.
          }
        :raises:
        """
        pass

    @abstractmethod
    def update_network(self, context, id, network):
        pass

    @abstractmethod
    def delete_network(self, context, id):
        pass

    @abstractmethod
    def get_network(self, context, id, fields=None, verbose=None):
        pass

    @abstractmethod
    def get_networks(self, context, filters=None, fields=None, verbose=None):
        pass

    @abstractmethod
    def create_port(self, context, port):
        """
        Creates a port on the specified Virtual Network. Optionally
        specify customization of port IP-related attributes, otherwise
        the port gets the default values of these attributes associated with
        the subnet.

        :param port_data:
          {"network_id" : UUID of network that this port is attached to.
           "admin-state-up" : boolean indicating whether this port should be
                              operational.
           "mac_address" : (optional) mac address used on this port.  If no
                           value is specified, the plugin will generate a
                           MAC address based on internal configuration.
           "fixed_ips" : (optional) list of dictionaries describing the
                         fixed IPs to be allocated for use by the device on
                         this port. If not specified, the plugin will
                         attempt to find a v4 and v6 subnet associated
                         with the network and allocate an IP for that
                         subnet.
                         Note: "address" is optional, in which case an
                               address from the specified subnet is
                               selected.
                         example: [{"subnet": "<uuid>",
                                    "address": "10.0.0.9"}]
           "routes" : (optional) list of routes to be injected into this
                      device. If not specified, the port will get a
                      route for its local subnet, a route for the default
                      gateway, and each of the routes in the
                      'additional_routes' field of the subnet.
                      example: [ { "destination" : "192.168.0.0/16",
                                   "nexthop" : "10.0.0.5" } ]
          }
        :raises: exception.NetworkNotFound
        :raises: exception.RequestedFixedIPNotAvailable
        :raises: exception.FixedIPNotAvailable
        :raises: exception.RouteInvalid
        """
        pass

    @abstractmethod
    def update_port(self, context, id, port):
        """
        Updates the attributes of a specific port on the
        specified Virtual Network.

        :returns: a mapping sequence with the following signature:
                    {'port-id': uuid representing the
                                 updated port on specified quantum network
                     'port-state': update port state( UP or DOWN)
                    }
        :raises: exception.StateInvalid
        :raises: exception.PortNotFound
        """
        pass

    @abstractmethod
    def delete_port(self, context, id):
        """
        Deletes a port on a specified Virtual Network,
        if the port contains a remote interface attachment,
        the remote interface is first un-plugged and then the port
        is deleted.

        :returns: a mapping sequence with the following signature:
                    {'port-id': uuid representing the deleted port
                                 on specified quantum network
                    }
        :raises: exception.PortInUse
        :raises: exception.PortNotFound
        :raises: exception.NetworkNotFound
        """
        pass

    @abstractmethod
    def get_port(self, context, id, fields=None, verbose=None):
        pass

    @abstractmethod
    def get_ports(self, context, filters=None, fields=None, verbose=None):
        pass
