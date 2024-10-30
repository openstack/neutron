# Copyright 2015 OpenStack LLC.
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

from neutron_lib import exceptions

from neutron._i18n import _


class InvalidSubnetRequestType(exceptions.BadRequest):
    message = _("Cannot handle subnet of type %(subnet_type)s")


class AddressCalculationFailure(exceptions.NeutronException):
    message = _("Unable to calculate %(address_type)s address because of:"
                "%(reason)s")


class InvalidAddressType(exceptions.NeutronException):
    message = _("Unknown address type %(address_type)s")


class IpAddressAlreadyAllocated(exceptions.Conflict):
    message = _("IP address %(ip)s already allocated in subnet %(subnet_id)s")


class InvalidIpForSubnet(exceptions.BadRequest):
    message = _("IP address %(ip)s does not belong to subnet %(subnet_id)s")


class InvalidAddressRequest(exceptions.BadRequest):
    message = _("The address allocation request could not be satisfied "
                "because: %(reason)s")


class InvalidSubnetRequest(exceptions.BadRequest):
    message = _("The subnet request could not be satisfied because: "
                "%(reason)s")


class IPAddressChangeNotAllowed(exceptions.BadRequest):
    message = _("IP updates for port %(port_id)s are not allowed")


class AllocationOnAutoAddressSubnet(exceptions.InvalidInput):
    message = _("IPv6 address %(ip)s cannot be directly "
                "assigned to a port on subnet %(subnet_id)s as the "
                "subnet is configured for automatic addresses")


class IpAddressGenerationFailure(exceptions.Conflict):
    message = _("No more IP addresses available for subnet %(subnet_id)s.")


class IpAddressGenerationFailureAllSubnets(IpAddressGenerationFailure):
    message = _("No more IP addresses available.")


class IpAddressGenerationFailureNoMatchingSubnet(IpAddressGenerationFailure):
    message = _("No valid service subnet for the given device owner, "
                "network %(network_id)s, service type %(service_type)s.")


class IPAllocationFailed(exceptions.NeutronException):
    message = _("IP allocation failed. Try again later.")


class IpamValueInvalid(exceptions.Conflict):
    def __init__(self, message=None):
        self.message = message
        super().__init__()


class DeferIpam(exceptions.NeutronException):
    message = _("Exception used to signal that IP allocation is deferred")
