# Copyright (c) 2013 OpenStack Foundation
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

"""Exceptions used by Cisco Nexus ML2 mechanism driver."""

from neutron.common import exceptions


class CredentialNotFound(exceptions.NeutronException):
    """Credential with this ID cannot be found."""
    message = _("Credential %(credential_id)s could not be found.")


class CredentialNameNotFound(exceptions.NeutronException):
    """Credential Name could not be found."""
    message = _("Credential %(credential_name)s could not be found.")


class CredentialAlreadyExists(exceptions.NeutronException):
    """Credential name already exists."""
    message = _("Credential %(credential_name)s already exists "
                "for tenant %(tenant_id)s.")


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


class NexusMissingRequiredFields(exceptions.NeutronException):
    """Missing required fields to configure nexus switch."""
    message = _("Missing required field(s) to configure nexus switch: "
                "%(fields)s")


class NoNexusSviSwitch(exceptions.NeutronException):
    """No usable nexus switch found."""
    message = _("No usable Nexus switch found to create SVI interface.")


class SubnetNotSpecified(exceptions.NeutronException):
    """Subnet id not specified."""
    message = _("No subnet_id specified for router gateway.")


class SubnetInterfacePresent(exceptions.NeutronException):
    """Subnet SVI interface already exists."""
    message = _("Subnet %(subnet_id)s has an interface on %(router_id)s.")


class PortIdForNexusSvi(exceptions.NeutronException):
        """Port Id specified for Nexus SVI."""
        message = _('Nexus hardware router gateway only uses Subnet Ids.')
