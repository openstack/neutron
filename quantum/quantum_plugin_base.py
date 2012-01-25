# vim: tabstop=4 shiftwidth=4 softtabstop=4
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
# @author: Somik Behera, Nicira Networks, Inc.

"""
Quantum Plug-in API specification.

QuantumPluginBase provides the definition of minimum set of
methods that needs to be implemented by a Quantum Plug-in.
"""

import inspect
from abc import ABCMeta, abstractmethod


class QuantumPluginBase(object):

    __metaclass__ = ABCMeta

    @abstractmethod
    def get_all_networks(self, tenant_id, **kwargs):
        """
        Returns a dictionary containing all
        <network_uuid, network_name> for
        the specified tenant.
        :param tenant_id: unique identifier for the tenant whose networks
            are being retrieved by this method
        :param **kwargs: options to be passed to the plugin. The following
            keywork based-options can be specified:
            filter_opts - options for filtering network list
        :returns: a list of mapping sequences with the following signature:
                     [ {'net-id': uuid that uniquely identifies
                                      the particular quantum network,
                        'net-name': a human-readable name associated
                                      with network referenced by net-id
                       },
                       ....
                       {'net-id': uuid that uniquely identifies the
                                       particular quantum network,
                        'net-name': a human-readable name associated
                                       with network referenced by net-id
                       }
                    ]
        :raises: None
        """
        pass

    @abstractmethod
    def create_network(self, tenant_id, net_name, **kwargs):
        """
        Creates a new Virtual Network, and assigns it
        a symbolic name.

        :returns: a sequence of mappings with the following signature:
                    {'net-id': uuid that uniquely identifies the
                                     particular quantum network,
                     'net-name': a human-readable name associated
                                    with network referenced by net-id
                    }
        :raises:
        """
        pass

    @abstractmethod
    def delete_network(self, tenant_id, net_id):
        """
        Deletes the network with the specified network identifier
        belonging to the specified tenant.

        :returns: a sequence of mappings with the following signature:
                    {'net-id': uuid that uniquely identifies the
                                 particular quantum network
                    }
        :raises: exception.NetworkInUse
        :raises: exception.NetworkNotFound
        """
        pass

    @abstractmethod
    def get_network_details(self, tenant_id, net_id):
        """
        Retrieves a list of all the remote vifs that
        are attached to the network.

        :returns: a sequence of mappings with the following signature:
                    {'net-id': uuid that uniquely identifies the
                                particular quantum network
                     'net-name': a human-readable name associated
                                 with network referenced by net-id
                     'net-ifaces': ['vif1_on_network_uuid',
                                    'vif2_on_network_uuid',...,'vifn_uuid']
                    }
        :raises: exception.NetworkNotFound
        """
        pass

    @abstractmethod
    def update_network(self, tenant_id, net_id, **kwargs):
        """
        Updates the attributes of a particular Virtual Network.

        :returns: a sequence of mappings representing the new network
                    attributes, with the following signature:
                    {'net-id': uuid that uniquely identifies the
                                 particular quantum network
                     'net-name': the new human-readable name
                                  associated with network referenced by net-id
                    }
        :raises: exception.NetworkNotFound
        """
        pass

    @abstractmethod
    def get_all_ports(self, tenant_id, net_id, **kwargs):
        """
        Retrieves all port identifiers belonging to the
        specified Virtual Network.
        :param tenant_id: unique identifier for the tenant for which this
            method is going to retrieve ports
        :param net_id: unique identifiers for the network whose ports are
            about to be retrieved
        :param **kwargs: options to be passed to the plugin. The following
            keywork based-options can be specified:
            filter_opts - options for filtering network list
        :returns: a list of mapping sequences with the following signature:
                     [ {'port-id': uuid representing a particular port
                                    on the specified quantum network
                       },
                       ....
                       {'port-id': uuid representing a particular port
                                     on the specified quantum network
                       }
                    ]
        :raises: exception.NetworkNotFound
        """
        pass

    @abstractmethod
    def create_port(self, tenant_id, net_id, port_state=None, **kwargs):
        """
        Creates a port on the specified Virtual Network.

        :returns: a mapping sequence with the following signature:
                    {'port-id': uuid representing the created port
                                   on specified quantum network
                    }
        :raises: exception.NetworkNotFound
        :raises: exception.StateInvalid
        """
        pass

    @abstractmethod
    def update_port(self, tenant_id, net_id, port_id, **kwargs):
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
    def delete_port(self, tenant_id, net_id, port_id):
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
    def get_port_details(self, tenant_id, net_id, port_id):
        """
        This method allows the user to retrieve a remote interface
        that is attached to this particular port.

        :returns: a mapping sequence with the following signature:
                    {'port-id': uuid representing the port on
                                 specified quantum network
                     'net-id': uuid representing the particular
                                quantum network
                     'attachment': uuid of the virtual interface
                                   bound to the port, None otherwise
                    }
        :raises: exception.PortNotFound
        :raises: exception.NetworkNotFound
        """
        pass

    @abstractmethod
    def plug_interface(self, tenant_id, net_id, port_id, remote_interface_id):
        """
        Attaches a remote interface to the specified port on the
        specified Virtual Network.

        :returns: None
        :raises: exception.NetworkNotFound
        :raises: exception.PortNotFound
        :raises: exception.AlreadyAttached
                    (? should the network automatically unplug/replug)
        """
        pass

    @abstractmethod
    def unplug_interface(self, tenant_id, net_id, port_id):
        """
        Detaches a remote interface from the specified port on the
        specified Virtual Network.

        :returns: None
        :raises: exception.NetworkNotFound
        :raises: exception.PortNotFound
        """
        pass

    @classmethod
    def __subclasshook__(cls, klass):
        """
        The __subclasshook__ method is a class method
        that will be called everytime a class is tested
        using issubclass(klass, Plugin).
        In that case, it will check that every method
        marked with the abstractmethod decorator is
        provided by the plugin class.
        """
        if cls is QuantumPluginBase:
            for method in cls.__abstractmethods__:
                method_ok = False
                for base in klass.__mro__:
                    if method in base.__dict__:
                        fn_obj = base.__dict__[method]
                        if inspect.isfunction(fn_obj):
                            abstract_fn_obj = cls.__dict__[method]
                            arg_count = fn_obj.func_code.co_argcount
                            expected_arg_count = \
                                abstract_fn_obj.func_code.co_argcount
                            method_ok = arg_count == expected_arg_count
                if method_ok:
                    continue
                return NotImplemented
            return True
        return NotImplemented
