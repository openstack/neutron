# Copyright (c) 2014 Cisco Systems
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
#
# @author: Henry Gessau, Cisco Systems

"""Exceptions used by Cisco APIC ML2 mechanism driver."""

from neutron.common import exceptions


class ApicHostNoResponse(exceptions.NotFound):
    """No response from the APIC via the specified URL."""
    message = _("No response from APIC at %(url)s")


class ApicResponseNotOk(exceptions.NeutronException):
    """A response from the APIC was not HTTP OK."""
    message = _("APIC responded with HTTP status %(status)s: %(reason)s, "
                "Request: '%(request)s', "
                "APIC error code %(err_code)s: %(err_text)s")


class ApicResponseNoCookie(exceptions.NeutronException):
    """A response from the APIC did not contain an expected cookie."""
    message = _("APIC failed to provide cookie for %(request)s request")


class ApicSessionNotLoggedIn(exceptions.NotAuthorized):
    """Attempted APIC operation while not logged in to APIC."""
    message = _("Authorized APIC session not established")


class ApicHostNotConfigured(exceptions.NotAuthorized):
    """The switch and port for the specified host are not configured."""
    message = _("The switch and port for host '%(host)s' are not configured")


class ApicManagedObjectNotSupported(exceptions.NeutronException):
    """Attempted to use an unsupported Managed Object."""
    message = _("Managed Object '%(mo_class)s' is not supported")


class ApicMultipleVlanRanges(exceptions.NeutronException):
    """Multiple VLAN ranges specified."""
    message = _("Multiple VLAN ranges are not supported in the APIC plugin. "
                "Please specify a single VLAN range. "
                "Current config: '%(vlan_ranges)s'")
