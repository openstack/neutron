# Copyright 2014 Cisco Systems, Inc.  All rights reserved.
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

import abc
import six


@six.add_metaclass(abc.ABCMeta)
class RoutingDriverBase(object):
    """Base class that defines an abstract interface for the Routing Driver.

    This class defines the abstract interface/API for the Routing and
    NAT related operations. Driver class corresponding to a hosting device
    should inherit this base driver and implement its methods.
    RouterInfo object (neutron.plugins.cisco.cfg_agent.router_info.RouterInfo)
    is a wrapper around the router dictionary, with attributes for easy access
    to parameters.
    """

    @abc.abstractmethod
    def router_added(self, router_info):
        """A logical router was assigned to the hosting device.

        :param router_info: RouterInfo object for this router
        :return None
        """
        pass

    @abc.abstractmethod
    def router_removed(self, router_info):
        """A logical router was de-assigned from the hosting device.

        :param router_info: RouterInfo object for this router
        :return None
        """

        pass

    @abc.abstractmethod
    def internal_network_added(self, router_info, port):
        """An internal network was connected to a router.

        :param router_info: RouterInfo object for this router
        :param port : port dictionary for the port where the internal
                      network is connected
        :return None
        """
        pass

    @abc.abstractmethod
    def internal_network_removed(self, router_info, port):
        """An internal network was removed from a router.

        :param router_info: RouterInfo object for this router
        :param port : port dictionary for the port where the internal
                     network was connected
        :return None
        """
        pass

    @abc.abstractmethod
    def external_gateway_added(self, router_info, ex_gw_port):
        """An external network was added to a router.

        :param router_info: RouterInfo object of the router
        :param ex_gw_port : port dictionary for the port where the external
                           gateway network is connected
        :return None
        """
        pass

    @abc.abstractmethod
    def external_gateway_removed(self, router_info, ex_gw_port):
        """An external network was removed from the router.

        :param router_info: RouterInfo object of the router
        :param ex_gw_port : port dictionary for the port where the external
                           gateway network was connected
        :return None
        """
        pass

    @abc.abstractmethod
    def enable_internal_network_NAT(self, router_info, port, ex_gw_port):
        """Enable NAT on an internal network.

        :param router_info: RouterInfo object for this router
        :param port       : port dictionary for the port where the internal
                           network is connected
        :param ex_gw_port : port dictionary for the port where the external
                           gateway network is connected
        :return None
        """
        pass

    @abc.abstractmethod
    def disable_internal_network_NAT(self, router_info, port, ex_gw_port):
        """Disable NAT on an internal network.

        :param router_info: RouterInfo object for this router
        :param port       : port dictionary for the port where the internal
                           network is connected
        :param ex_gw_port : port dictionary for the port where the external
                           gateway network is connected
        :return None
        """
        pass

    @abc.abstractmethod
    def floating_ip_added(self, router_info, ex_gw_port,
                          floating_ip, fixed_ip):
        """A floating IP was added.

        :param router_info: RouterInfo object for this router
        :param ex_gw_port : port dictionary for the port where the external
                           gateway network is connected
        :param floating_ip: Floating IP as a string
        :param fixed_ip   : Fixed IP of internal internal interface as
                           a string
        :return None
        """
        pass

    @abc.abstractmethod
    def floating_ip_removed(self, router_info, ex_gw_port,
                            floating_ip, fixed_ip):
        """A floating IP was removed.

        :param router_info: RouterInfo object for this router
        :param ex_gw_port : port dictionary for the port where the external
                            gateway network is connected
        :param floating_ip: Floating IP as a string
        :param fixed_ip: Fixed IP of internal internal interface as a string
        :return None
        """
        pass

    @abc.abstractmethod
    def routes_updated(self, router_info, action, route):
        """Routes were updated for router.

        :param router_info: RouterInfo object for this router
        :param action : Action on the route , either 'replace' or 'delete'
        :param route: route dictionary with keys 'destination' & 'next_hop'
        :return None
        """
        pass
