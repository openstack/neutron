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


class L2NetworkModelBase(object):
    """
    Base class for L2 Network Model
    It relies on a pluggable network configuration module  to gather
    knowledge of the system, but knows which device-specific plugins
    to invoke for a corresponding core API call, and what parameters to pass
    to that plugin.
    """

    __metaclass__ = ABCMeta

    @abstractmethod
    def get_all_networks(self, args):
        """
        :returns:
        :raises:
        """
        pass

    @abstractmethod
    def create_network(self, args):
        """
        :returns:
        :raises:
        """
        pass

    @abstractmethod
    def delete_network(self, args):
        """
        :returns:
        :raises:
        """
        pass

    @abstractmethod
    def get_network_details(self, args):
        """
        :returns:
        :raises:
        """
        pass

    @abstractmethod
    def update_network(self, args):
        """
        :returns:
        :raises:
        """
        pass

    @abstractmethod
    def get_all_ports(self, args):
        """
        :returns:
        :raises:
        """
        pass

    @abstractmethod
    def create_port(self, args):
        """
        :returns:
        :raises:
        """
        pass

    @abstractmethod
    def delete_port(self, args):
        """
        :returns:
        :raises:
        """
        pass

    @abstractmethod
    def update_port(self, args):
        """
        :returns:
        :raises:
        """
        pass

    @abstractmethod
    def get_port_details(self, args):
        """
        :returns:
        :raises:
        """
        pass

    @abstractmethod
    def plug_interface(self, args):
        """
        :returns:
        :raises:
        """
        pass

    @abstractmethod
    def unplug_interface(self, args):
        """
        :returns:
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
        if cls is L2NetworkModelBase:
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
