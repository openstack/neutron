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
# @author: Rohit Agarwalla, Cisco Systems, Inc.

"""
Exceptions used by the Cisco plugin
"""

from quantum.common import exceptions


class NoMoreNics(exceptions.QuantumException):
    """No more dynamic nics are available in the system"""
    message = _("Unable to complete operation. No more dynamic nics are "
                "available in the system.")


class PortProfileLimit(exceptions.QuantumException):
    """Port profile limit has been hit"""
    message = _("Unable to complete operation on port %(port_id)s "
                "for network %(net_id)s. The system has reached the maximum"
                "limit of allowed port profiles.")


class UCSMPortProfileLimit(exceptions.QuantumException):
    """UCSM Port profile limit has been hit"""
    message = _("Unable to complete operation on port %(port_id)s "
                "for network %(net_id)s. The system has reached the maximum"
                "limit of allowed UCSM port profiles.")


class NetworksLimit(exceptions.QuantumException):
    """Total number of network objects limit has been hit"""
    message = _("Unable to create new network. Number of networks"
                "for the system has exceeded the limit")


class PortProfileNotFound(exceptions.QuantumException):
    """Port profile cannot be found"""
    message = _("Port profile %(portprofile_id)s could not be found "
                "for tenant %(tenant_id)s")


class MultiportNotFound(exceptions.QuantumException):
    """Multiport cannot be found"""
    message = _("Multiports %(port_id)s could not be found "
                "for tenant %(tenant_id)s")


class PortProfileInvalidDelete(exceptions.QuantumException):
    """Port profile cannot be deleted since its being used"""
    message = _("Port profile %(profile_id)s could not be deleted "
                "for tenant %(tenant_id)s since port associations exist")


class NetworkVlanBindingAlreadyExists(exceptions.QuantumException):
    """Binding cannot be created, since it already exists"""
    message = _("NetworkVlanBinding for %(vlan_id)s and network "
                "%(network_id)s already exists")


class PortProfileAlreadyExists(exceptions.QuantumException):
    """Port profile cannot be created since it already exisits"""
    message = _("PortProfile %(pp_name)s for %(tenant_id)s "
                "already exists")


class PortProfileBindingAlreadyExists(exceptions.QuantumException):
    """Binding cannot be created, since it already exists"""
    message = _("PortProfileBinding for port profile %(pp_id)s to "
                "port %(port_id)s already exists")


class VlanIDNotFound(exceptions.QuantumException):
    """VLAN ID cannot be found"""
    message = _("Vlan ID %(vlan_id)s not found")


class VlanIDNotAvailable(exceptions.QuantumException):
    """No VLAN ID available"""
    message = _("No Vlan ID available")


class QosNotFound(exceptions.QuantumException):
    """QoS level with this ID cannot be found"""
    message = _("QoS level %(qos_id)s could not be found "
                "for tenant %(tenant_id)s")


class QoSLevelInvalidDelete(exceptions.QuantumException):
    """QoS is associated with a port profile, hence cannot be deleted"""
    message = _("QoS level %(qos_id)s could not be deleted "
                "for tenant %(tenant_id)s since association exists")


class QosNameAlreadyExists(exceptions.QuantumException):
    """QoS Name already exists"""
    message = _("QoS level with name %(qos_name)s already exists "
                "for tenant %(tenant_id)s")


class CredentialNotFound(exceptions.QuantumException):
    """Credential with this ID cannot be found"""
    message = _("Credential %(credential_id)s could not be found "
                "for tenant %(tenant_id)s")


class CredentialNameNotFound(exceptions.QuantumException):
    """Credential Name could not be found"""
    message = _("Credential %(credential_name)s could not be found "
                "for tenant %(tenant_id)s")


class CredentialAlreadyExists(exceptions.QuantumException):
    """Credential ID already exists"""
    message = _("Credential %(credential_id)s already exists "
                "for tenant %(tenant_id)s")


class NexusPortBindingNotFound(exceptions.QuantumException):
    """NexusPort Binding is not present"""
    message = _("Nexus Port Binding %(port_id)s is not present")


class NexusPortBindingAlreadyExists(exceptions.QuantumException):
    """NexusPort Binding alredy exists"""
    message = _("Nexus Port Binding %(port_id)s already exists")


class UcsmBindingNotFound(exceptions.QuantumException):
    """Ucsm Binding is not present"""
    message = _("Ucsm Binding with ip %(ucsm_ip)s is not present")


class UcsmBindingAlreadyExists(exceptions.QuantumException):
    """Ucsm Binding already exists"""
    message = _("Ucsm Binding with ip %(ucsm_ip)s already exists")


class DynamicVnicNotFound(exceptions.QuantumException):
    """Ucsm Binding is not present"""
    message = _("Dyanmic Vnic %(vnic_id)s is not present")


class DynamicVnicAlreadyExists(exceptions.QuantumException):
    """Ucsm Binding already exists"""
    message = _("Dynamic Vnic with name %(device_name)s already exists")


class BladeNotFound(exceptions.QuantumException):
    """Blade is not present"""
    message = _("Blade %(blade_id)s is not present")


class BladeAlreadyExists(exceptions.QuantumException):
    """Blade already exists"""
    message = _("Blade with mgmt_ip %(mgmt_ip)s already exists")


class PortVnicBindingAlreadyExists(exceptions.QuantumException):
    """PortVnic Binding already exists"""
    message = _("PortVnic Binding %(port_id)s already exists")


class PortVnicNotFound(exceptions.QuantumException):
    """PortVnic Binding is not present"""
    message = _("PortVnic Binding %(port_id)s is not present")


class InvalidAttach(exceptions.QuantumException):
    message = _("Unable to plug the attachment %(att_id)s into port "
                "%(port_id)s for network %(net_id)s. Association of "
                "attachment ID with port ID happens implicitly when "
                "VM is instantiated; attach operation can be "
                "performed subsequently.")


class InvalidDetach(exceptions.QuantumException):
    message = _("Unable to unplug the attachment %(att_id)s from port "
                "%(port_id)s for network %(net_id)s. The attachment "
                "%(att_id)s does not exist.")
