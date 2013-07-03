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

"""Exceptions used by the Cisco plugin."""

from neutron.common import exceptions


class NetworkSegmentIDNotFound(exceptions.NeutronException):
    """Segmentation ID for network is not found."""
    message = _("Segmentation ID for network %(net_id)s is not found.")


class NoMoreNics(exceptions.NeutronException):
    """No more dynamic nics are available in the system."""
    message = _("Unable to complete operation. No more dynamic nics are "
                "available in the system.")


class NetworkVlanBindingAlreadyExists(exceptions.NeutronException):
    """Binding cannot be created, since it already exists."""
    message = _("NetworkVlanBinding for %(vlan_id)s and network "
                "%(network_id)s already exists")


class VlanIDNotFound(exceptions.NeutronException):
    """VLAN ID cannot be found."""
    message = _("Vlan ID %(vlan_id)s not found")


class VlanIDNotAvailable(exceptions.NeutronException):
    """No VLAN ID available."""
    message = _("No Vlan ID available")


class QosNotFound(exceptions.NeutronException):
    """QoS level with this ID cannot be found."""
    message = _("QoS level %(qos_id)s could not be found "
                "for tenant %(tenant_id)s")


class QosNameAlreadyExists(exceptions.NeutronException):
    """QoS Name already exists."""
    message = _("QoS level with name %(qos_name)s already exists "
                "for tenant %(tenant_id)s")


class CredentialNotFound(exceptions.NeutronException):
    """Credential with this ID cannot be found."""
    message = _("Credential %(credential_id)s could not be found "
                "for tenant %(tenant_id)s")


class CredentialNameNotFound(exceptions.NeutronException):
    """Credential Name could not be found."""
    message = _("Credential %(credential_name)s could not be found "
                "for tenant %(tenant_id)s")


class CredentialAlreadyExists(exceptions.NeutronException):
    """Credential ID already exists."""
    message = _("Credential %(credential_id)s already exists "
                "for tenant %(tenant_id)s")


class NexusComputeHostNotConfigured(exceptions.NeutronException):
    """Connection to compute host is not configured."""
    message = _("Connection to %(host)s is not configured.")


class NexusConnectFailed(exceptions.NeutronException):
    """Failed to connect to Nexus switch."""
    message = _("Unable to connect to Nexus %(nexus_host)s. Reason: %(exc)s.")


class NexusConfigFailed(exceptions.NeutronException):
    """Failed to configure Nexus switch."""
    message = _("Failed to configure Nexus: %(config)s. Reason: %(exc)s.")


class NexusPortBindingNotFound(exceptions.NeutronException):
    """NexusPort Binding is not present."""
    message = _("Nexus Port Binding (%(filters)s) is not present")

    def __init__(self, **kwargs):
        filters = ','.join('%s=%s' % i for i in kwargs.items())
        super(NexusPortBindingNotFound, self).__init__(filters=filters)


class NoNexusSviSwitch(exceptions.NeutronException):
    """No usable nexus switch found."""
    message = _("No usable Nexus switch found to create SVI interface")


class PortVnicBindingAlreadyExists(exceptions.NeutronException):
    """PortVnic Binding already exists."""
    message = _("PortVnic Binding %(port_id)s already exists")


class PortVnicNotFound(exceptions.NeutronException):
    """PortVnic Binding is not present."""
    message = _("PortVnic Binding %(port_id)s is not present")


class SubnetNotSpecified(exceptions.NeutronException):
    """Subnet id not specified."""
    message = _("No subnet_id specified for router gateway")


class SubnetInterfacePresent(exceptions.NeutronException):
    """Subnet SVI interface already exists."""
    message = _("Subnet %(subnet_id)s has an interface on %(router_id)s")


class PortIdForNexusSvi(exceptions.NeutronException):
        """Port Id specified for Nexus SVI."""
        message = _('Nexus hardware router gateway only uses Subnet Ids')
