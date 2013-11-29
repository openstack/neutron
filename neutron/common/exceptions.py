# Copyright 2011 VMware, Inc
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

"""
Neutron base exception handling.
"""

from neutron.openstack.common import excutils


class NeutronException(Exception):
    """Base Neutron Exception.

    To correctly use this class, inherit from it and define
    a 'message' property. That message will get printf'd
    with the keyword arguments provided to the constructor.
    """
    message = _("An unknown exception occurred.")

    def __init__(self, **kwargs):
        try:
            super(NeutronException, self).__init__(self.message % kwargs)
            self.msg = self.message % kwargs
        except Exception:
            with excutils.save_and_reraise_exception() as ctxt:
                if not self.use_fatal_exceptions():
                    ctxt.reraise = False
                    # at least get the core message out if something happened
                    super(NeutronException, self).__init__(self.message)

    def __unicode__(self):
        return unicode(self.msg)

    def use_fatal_exceptions(self):
        return False


class BadRequest(NeutronException):
    message = _('Bad %(resource)s request: %(msg)s')


class NotFound(NeutronException):
    pass


class Conflict(NeutronException):
    pass


class NotAuthorized(NeutronException):
    message = _("Not authorized.")


class ServiceUnavailable(NeutronException):
    message = _("The service is unavailable")


class AdminRequired(NotAuthorized):
    message = _("User does not have admin privileges: %(reason)s")


class PolicyNotAuthorized(NotAuthorized):
    message = _("Policy doesn't allow %(action)s to be performed.")


class NetworkNotFound(NotFound):
    message = _("Network %(net_id)s could not be found")


class SubnetNotFound(NotFound):
    message = _("Subnet %(subnet_id)s could not be found")


class PortNotFound(NotFound):
    message = _("Port %(port_id)s could not be found")


class PortNotFoundOnNetwork(NotFound):
    message = _("Port %(port_id)s could not be found "
                "on network %(net_id)s")


class PolicyFileNotFound(NotFound):
    message = _("Policy configuration policy.json could not be found")


class PolicyRuleNotFound(NotFound):
    message = _("Requested rule:%(rule)s cannot be found")


class PolicyInitError(NeutronException):
    message = _("Failed to init policy %(policy)s because %(reason)s")


class PolicyCheckError(NeutronException):
    message = _("Failed to check policy %(policy)s because %(reason)s")


class StateInvalid(BadRequest):
    message = _("Unsupported port state: %(port_state)s")


class InUse(NeutronException):
    message = _("The resource is inuse")


class NetworkInUse(InUse):
    message = _("Unable to complete operation on network %(net_id)s. "
                "There are one or more ports still in use on the network.")


class SubnetInUse(InUse):
    message = _("Unable to complete operation on subnet %(subnet_id)s. "
                "One or more ports have an IP allocation from this subnet.")


class PortInUse(InUse):
    message = _("Unable to complete operation on port %(port_id)s "
                "for network %(net_id)s. Port already has an attached"
                "device %(device_id)s.")


class MacAddressInUse(InUse):
    message = _("Unable to complete operation for network %(net_id)s. "
                "The mac address %(mac)s is in use.")


class HostRoutesExhausted(BadRequest):
    # NOTE(xchenum): probably make sense to use quota exceeded exception?
    message = _("Unable to complete operation for %(subnet_id)s. "
                "The number of host routes exceeds the limit %(quota)s.")


class DNSNameServersExhausted(BadRequest):
    # NOTE(xchenum): probably make sense to use quota exceeded exception?
    message = _("Unable to complete operation for %(subnet_id)s. "
                "The number of DNS nameservers exceeds the limit %(quota)s.")


class IpAddressInUse(InUse):
    message = _("Unable to complete operation for network %(net_id)s. "
                "The IP address %(ip_address)s is in use.")


class VlanIdInUse(InUse):
    message = _("Unable to create the network. "
                "The VLAN %(vlan_id)s on physical network "
                "%(physical_network)s is in use.")


class FlatNetworkInUse(InUse):
    message = _("Unable to create the flat network. "
                "Physical network %(physical_network)s is in use.")


class TunnelIdInUse(InUse):
    message = _("Unable to create the network. "
                "The tunnel ID %(tunnel_id)s is in use.")


class TenantNetworksDisabled(ServiceUnavailable):
    message = _("Tenant network creation is not enabled.")


class ResourceExhausted(ServiceUnavailable):
    pass


class NoNetworkAvailable(ResourceExhausted):
    message = _("Unable to create the network. "
                "No tenant network is available for allocation.")


class SubnetMismatchForPort(BadRequest):
    message = _("Subnet on port %(port_id)s does not match "
                "the requested subnet %(subnet_id)s")


class MalformedRequestBody(BadRequest):
    message = _("Malformed request body: %(reason)s")


class Invalid(NeutronException):
    def __init__(self, message=None):
        self.message = message
        super(Invalid, self).__init__()


class InvalidInput(BadRequest):
    message = _("Invalid input for operation: %(error_message)s.")


class InvalidAllocationPool(BadRequest):
    message = _("The allocation pool %(pool)s is not valid.")


class OverlappingAllocationPools(Conflict):
    message = _("Found overlapping allocation pools:"
                "%(pool_1)s %(pool_2)s for subnet %(subnet_cidr)s.")


class OutOfBoundsAllocationPool(BadRequest):
    message = _("The allocation pool %(pool)s spans "
                "beyond the subnet cidr %(subnet_cidr)s.")


class MacAddressGenerationFailure(ServiceUnavailable):
    message = _("Unable to generate unique mac on network %(net_id)s.")


class IpAddressGenerationFailure(Conflict):
    message = _("No more IP addresses available on network %(net_id)s.")


class BridgeDoesNotExist(NeutronException):
    message = _("Bridge %(bridge)s does not exist.")


class PreexistingDeviceFailure(NeutronException):
    message = _("Creation failed. %(dev_name)s already exists.")


class SudoRequired(NeutronException):
    message = _("Sudo privilege is required to run this command.")


class QuotaResourceUnknown(NotFound):
    message = _("Unknown quota resources %(unknown)s.")


class OverQuota(Conflict):
    message = _("Quota exceeded for resources: %(overs)s")


class QuotaMissingTenant(BadRequest):
    message = _("Tenant-id was missing from Quota request")


class InvalidQuotaValue(Conflict):
    message = _("Change would make usage less than 0 for the following "
                "resources: %(unders)s")


class InvalidSharedSetting(Conflict):
    message = _("Unable to reconfigure sharing settings for network "
                "%(network)s. Multiple tenants are using it")


class InvalidExtensionEnv(BadRequest):
    message = _("Invalid extension environment: %(reason)s")


class ExtensionsNotFound(NotFound):
    message = _("Extensions not found: %(extensions)s")


class InvalidContentType(NeutronException):
    message = _("Invalid content type %(content_type)s")


class ExternalIpAddressExhausted(BadRequest):
    message = _("Unable to find any IP address on external "
                "network %(net_id)s.")


class TooManyExternalNetworks(NeutronException):
    message = _("More than one external network exists")


class InvalidConfigurationOption(NeutronException):
    message = _("An invalid value was provided for %(opt_name)s: "
                "%(opt_value)s")


class GatewayConflictWithAllocationPools(InUse):
    message = _("Gateway ip %(ip_address)s conflicts with "
                "allocation pool %(pool)s")


class GatewayIpInUse(InUse):
    message = _("Current gateway ip %(ip_address)s already in use "
                "by port %(port_id)s. Unable to update.")


class NetworkVlanRangeError(NeutronException):
    message = _("Invalid network VLAN range: '%(vlan_range)s' - '%(error)s'")

    def __init__(self, **kwargs):
        # Convert vlan_range tuple to 'start:end' format for display
        if isinstance(kwargs['vlan_range'], tuple):
            kwargs['vlan_range'] = "%d:%d" % kwargs['vlan_range']
        super(NetworkVlanRangeError, self).__init__(**kwargs)


class NetworkVxlanPortRangeError(NeutronException):
    message = _("Invalid network VXLAN port range: '%(vxlan_range)s'")


class VxlanNetworkUnsupported(NeutronException):
    message = _("VXLAN Network unsupported.")


class DuplicatedExtension(NeutronException):
    message = _("Found duplicate extension: %(alias)s")


class DeviceIDNotOwnedByTenant(Conflict):
    message = _("The following device_id %(device_id)s is not owned by your "
                "tenant or matches another tenants router.")


class InvalidCIDR(BadRequest):
    message = _("Invalid CIDR %(input)s given as IP prefix")
