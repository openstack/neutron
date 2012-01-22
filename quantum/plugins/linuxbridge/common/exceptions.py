# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2012 Cisco Systems, Inc.  All rights reserved.
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
# @author: Rohit Agarwalla, Cisco Systems, Inc.

"""
Exceptions used by the LinuxBridge plugin
"""
from quantum.common import exceptions


class NetworksLimit(exceptions.QuantumException):
    """Total number of network objects limit has been hit"""
    message = _("Unable to create new network. Number of networks" \
                "for the system has exceeded the limit")


class NetworkVlanBindingAlreadyExists(exceptions.QuantumException):
    """Binding cannot be created, since it already exists"""
    message = _("NetworkVlanBinding for %(vlan_id)s and network " \
                "%(network_id)s already exists")


class NetworkVlanBindingNotFound(exceptions.QuantumException):
    """Binding could not be found"""
    message = _("NetworkVlanBinding for network " \
                "%(network_id)s does not exist")


class VlanIDNotFound(exceptions.QuantumException):
    """VLAN ID cannot be found"""
    message = _("Vlan ID %(vlan_id)s not found")


class VlanIDNotAvailable(exceptions.QuantumException):
    """No VLAN ID available"""
    message = _("No Vlan ID available")


class UnableToChangeVlanRange(exceptions.QuantumException):
    """No VLAN ID available"""
    message = _("Current VLAN ID range %(range_start)s to %(range_end)s " \
                "cannot be changed. Please check plugin conf file.")


try:
    _("test")
except NameError:

    def _(a_string):
        """
        Default implementation of the gettext string
        translation function: no translation
        """
        return a_string
except TypeError:
    # during doctesting, _ might mean something else
    pass
