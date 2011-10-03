"""
# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2011 Cisco Systems, Inc.  All rights reserved.
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
#
# @author: Sumit Naiksatam, Cisco Systems, Inc.
#
"""

import inspect
from abc import ABCMeta, abstractmethod


class L2NetworkDeviceInventoryBase(object):
    """
    Base class for L2 Network Device Inventory
    This is used by the L2Nework Model to get information about
    the actual devices of a particular type in a given deployment.
    For instance, an implementation in the context of UCS will
    know what UCSMs, chasses, blades, and dynamic vnics are
    present in a particular deployment.
    Similarly, an implementation in the context of Nexus switches
    will know which switches are present in the system, and how they
    are interconnected to other switches/devices.
    """

    __metaclass__ = ABCMeta

    @abstractmethod
    def get_all_networks(self, args):
        """
        Returns a dictionary containing the first element as a device
        IP address list. The model then invokes the device-specific plugin
        for each device IP in that list. This is followed by zero or more
        key-value pairs (specific to each operation, device type, and
        deployment.
        The model implementation may or may not process the returned
        values, but needs to pass them to the device-specific plugin.
        Since the device-specific plugin and this inventory implementation
        are assumed to be implemented by the same entity, the
        device-sepcific knows how to process this dictionary.
        :returns: a dictionary with the following signature:
                     {'device_ip': []
                      'key-1': "value 1",
                      ...
                      'key-n': "value n"
                     }
        :raises:
        """
        pass

    @abstractmethod
    def create_network(self, args):
        """
        Returns a dictionary containing the first element as a device
        IP address list. The model then invokes the device-specific plugin
        for each device IP in that list. This is followed by zero or more
        key-value pairs (specific to each operation, device type, and
        deployment.
        The model implementation may or may not process the returned
        values, but needs to pass them to the device-specific plugin.
        Since the device-specific plugin and this inventory implementation
        are assumed to be implemented by the same entity, the
        device-sepcific knows how to process this dictionary.
        :returns: a dictionary with the following signature:
                     {'device_ip': []
                      'key-1': "value 1",
                      ...
                      'key-n': "value n"
                     }
        :raises:
        """
        pass

    @abstractmethod
    def delete_network(self, args):
        """
        Returns a dictionary containing the first element as a device
        IP address list. The model then invokes the device-specific plugin
        for each device IP in that list. This is followed by zero or more
        key-value pairs (specific to each operation, device type, and
        deployment.
        The model implementation may or may not process the returned
        values, but needs to pass them to the device-specific plugin.
        Since the device-specific plugin and this inventory implementation
        are assumed to be implemented by the same entity, the
        device-sepcific knows how to process this dictionary.
        :returns: a dictionary with the following signature:
                     {'device_ip': []
                      'key-1': "value 1",
                      ...
                      'key-n': "value n"
                     }
        :raises:
        """
        pass

    @abstractmethod
    def get_network_details(self, args):
        """
        Returns a dictionary containing the first element as a device
        IP address list. The model then invokes the device-specific plugin
        for each device IP in that list. This is followed by zero or more
        key-value pairs (specific to each operation, device type, and
        deployment.
        The model implementation may or may not process the returned
        values, but needs to pass them to the device-specific plugin.
        Since the device-specific plugin and this inventory implementation
        are assumed to be implemented by the same entity, the
        device-sepcific knows how to process this dictionary.
        :returns: a dictionary with the following signature:
                     {'device_ip': []
                      'key-1': "value 1",
                      ...
                      'key-n': "value n"
                     }
        :raises:
        """
        pass

    @abstractmethod
    def update_network(self, args):
        """
        Returns a dictionary containing the first element as a device
        IP address list. The model then invokes the device-specific plugin
        for each device IP in that list. This is followed by zero or more
        key-value pairs (specific to each operation, device type, and
        deployment.
        The model implementation may or may not process the returned
        values, but needs to pass them to the device-specific plugin.
        Since the device-specific plugin and this inventory implementation
        are assumed to be implemented by the same entity, the
        device-sepcific knows how to process this dictionary.
        :returns: a dictionary with the following signature:
                     {'device_ip': []
                      'key-1': "value 1",
                      ...
                      'key-n': "value n"
                     }
        :raises:
        """
        pass

    @abstractmethod
    def get_all_ports(self, args):
        """
        Returns a dictionary containing the first element as a device
        IP address list. The model then invokes the device-specific plugin
        for each device IP in that list. This is followed by zero or more
        key-value pairs (specific to each operation, device type, and
        deployment.
        The model implementation may or may not process the returned
        values, but needs to pass them to the device-specific plugin.
        Since the device-specific plugin and this inventory implementation
        are assumed to be implemented by the same entity, the
        device-sepcific knows how to process this dictionary.
        :returns: a dictionary with the following signature:
                     {'device_ip': []
                      'key-1': "value 1",
                      ...
                      'key-n': "value n"
                     }
        :raises:
        """
        pass

    @abstractmethod
    def create_port(self, args):
        """
        Returns a dictionary containing the first element as a device
        IP address list. The model then invokes the device-specific plugin
        for each device IP in that list. This is followed by zero or more
        key-value pairs (specific to each operation, device type, and
        deployment.
        The model implementation may or may not process the returned
        values, but needs to pass them to the device-specific plugin.
        Since the device-specific plugin and this inventory implementation
        are assumed to be implemented by the same entity, the
        device-sepcific knows how to process this dictionary.
        :returns: a dictionary with the following signature:
                     {'device_ip': []
                      'key-1': "value 1",
                      ...
                      'key-n': "value n"
                     }
        :raises:
        """
        pass

    @abstractmethod
    def delete_port(self, args):
        """
        Returns a dictionary containing the first element as a device
        IP address list. The model then invokes the device-specific plugin
        for each device IP in that list. This is followed by zero or more
        key-value pairs (specific to each operation, device type, and
        deployment.
        The model implementation may or may not process the returned
        values, but needs to pass them to the device-specific plugin.
        Since the device-specific plugin and this inventory implementation
        are assumed to be implemented by the same entity, the
        device-sepcific knows how to process this dictionary.
        :returns: a dictionary with the following signature:
                     {'device_ip': []
                      'key-1': "value 1",
                      ...
                      'key-n': "value n"
                     }
        :raises:
        """
        pass

    @abstractmethod
    def update_port(self, args):
        """
        Returns a dictionary containing the first element as a device
        IP address list. The model then invokes the device-specific plugin
        for each device IP in that list. This is followed by zero or more
        key-value pairs (specific to each operation, device type, and
        deployment.
        The model implementation may or may not process the returned
        values, but needs to pass them to the device-specific plugin.
        Since the device-specific plugin and this inventory implementation
        are assumed to be implemented by the same entity, the
        device-sepcific knows how to process this dictionary.
        :returns: a dictionary with the following signature:
                     {'device_ip': []
                      'key-1': "value 1",
                      ...
                      'key-n': "value n"
                     }
        :raises:
        """
        pass

    @abstractmethod
    def get_port_details(self, args):
        """
        Returns a dictionary containing the first element as a device
        IP address list. The model then invokes the device-specific plugin
        for each device IP in that list. This is followed by zero or more
        key-value pairs (specific to each operation, device type, and
        deployment.
        The model implementation may or may not process the returned
        values, but needs to pass them to the device-specific plugin.
        Since the device-specific plugin and this inventory implementation
        are assumed to be implemented by the same entity, the
        device-sepcific knows how to process this dictionary.
        :returns: a dictionary with the following signature:
                     {'device_ip': []
                      'key-1': "value 1",
                      ...
                      'key-n': "value n"
                     }
        :raises:
        """
        pass

    @abstractmethod
    def plug_interface(self, args):
        """
        Returns a dictionary containing the first element as a device
        IP address list. The model then invokes the device-specific plugin
        for each device IP in that list. This is followed by zero or more
        key-value pairs (specific to each operation, device type, and
        deployment.
        The model implementation may or may not process the returned
        values, but needs to pass them to the device-specific plugin.
        Since the device-specific plugin and this inventory implementation
        are assumed to be implemented by the same entity, the
        device-sepcific knows how to process this dictionary.
        :returns: a dictionary with the following signature:
                     {'device_ip': []
                      'key-1': "value 1",
                      ...
                      'key-n': "value n"
                     }
        :raises:
        """
        pass

    @abstractmethod
    def unplug_interface(self, args):
        """
        Returns a dictionary containing the first element as a device
        IP address list. The model then invokes the device-specific plugin
        for each device IP in that list. This is followed by zero or more
        key-value pairs (specific to each operation, device type, and
        deployment.
        The model implementation may or may not process the returned
        values, but needs to pass them to the device-specific plugin.
        Since the device-specific plugin and this inventory implementation
        are assumed to be implemented by the same entity, the
        device-sepcific knows how to process this dictionary.
        :returns: a dictionary with the following signature:
                     {'device_ip': []
                      'key-1': "value 1",
                      ...
                      'key-n': "value n"
                     }
        :raises:
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
        if cls is L2NetworkDeviceInventoryBase:
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
