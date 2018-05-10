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

from neutron_lib import exceptions as e

from neutron._i18n import _


class SubnetPoolNotFound(e.NotFound):
    message = _("Subnet pool %(subnetpool_id)s could not be found.")


class QosPolicyNotFound(e.NotFound):
    message = _("QoS policy %(policy_id)s could not be found.")


class QosRuleNotFound(e.NotFound):
    message = _("QoS rule %(rule_id)s for policy %(policy_id)s "
                "could not be found.")


class QoSPolicyDefaultAlreadyExists(e.Conflict):
    message = _("A default QoS policy exists for project %(project_id)s.")


class PortQosBindingNotFound(e.NotFound):
    message = _("QoS binding for port %(port_id)s and policy %(policy_id)s "
                "could not be found.")


class PortQosBindingError(e.NeutronException):
    message = _("QoS binding for port %(port_id)s and policy %(policy_id)s "
                "could not be created: %(db_error)s.")


class NetworkQosBindingNotFound(e.NotFound):
    message = _("QoS binding for network %(net_id)s and policy %(policy_id)s "
                "could not be found.")


class FloatingIPQosBindingNotFound(e.NotFound):
    message = _("QoS binding for floating IP %(fip_id)s and policy "
                "%(policy_id)s could not be found.")


class FloatingIPQosBindingError(e.NeutronException):
    message = _("QoS binding for floating IP %(fip_id)s and policy "
                "%(policy_id)s could not be created: %(db_error)s.")


class NetworkQosBindingError(e.NeutronException):
    message = _("QoS binding for network %(net_id)s and policy %(policy_id)s "
                "could not be created: %(db_error)s.")


class PlacementEndpointNotFound(e.NotFound):
    message = _("Placement API endpoint not found")


class PlacementResourceProviderNotFound(e.NotFound):
    message = _("Placement resource provider not found %(resource_provider)s.")


class PlacementInventoryNotFound(e.NotFound):
    message = _("Placement inventory not found for resource provider "
                "%(resource_provider)s, resource class %(resource_class)s.")


class PlacementAggregateNotFound(e.NotFound):
    message = _("Aggregate not found for resource provider "
                "%(resource_provider)s.")


class PolicyRemoveAuthorizationError(e.NotAuthorized):
    message = _("Failed to remove provided policy %(policy_id)s "
                "because you are not authorized.")


class StateInvalid(e.BadRequest):
    message = _("Unsupported port state: %(port_state)s.")


class QosPolicyInUse(e.InUse):
    message = _("QoS Policy %(policy_id)s is used by "
                "%(object_type)s %(object_id)s.")


class DhcpPortInUse(e.InUse):
    message = _("Port %(port_id)s is already acquired by another DHCP agent")


class HostRoutesExhausted(e.BadRequest):
    # NOTE(xchenum): probably make sense to use quota exceeded exception?
    message = _("Unable to complete operation for %(subnet_id)s. "
                "The number of host routes exceeds the limit %(quota)s.")


class DNSNameServersExhausted(e.BadRequest):
    # NOTE(xchenum): probably make sense to use quota exceeded exception?
    message = _("Unable to complete operation for %(subnet_id)s. "
                "The number of DNS nameservers exceeds the limit %(quota)s.")


class FlatNetworkInUse(e.InUse):
    message = _("Unable to create the flat network. "
                "Physical network %(physical_network)s is in use.")


class TenantNetworksDisabled(e.ServiceUnavailable):
    # NOTE(vvargaszte): May be removed in the future as it is not used in
    # Neutron, only in the Neutron plugin of OpenContrail.
    message = _("Tenant network creation is not enabled.")


class NoNetworkFoundInMaximumAllowedAttempts(e.ServiceUnavailable):
    message = _("Unable to create the network. "
                "No available network found in maximum allowed attempts.")


class MalformedRequestBody(e.BadRequest):
    message = _("Malformed request body: %(reason)s.")


class InvalidAllocationPool(e.BadRequest):
    message = _("The allocation pool %(pool)s is not valid.")


class QosRuleNotSupported(e.Conflict):
    message = _("Rule %(rule_type)s is not supported by port %(port_id)s")


class UnsupportedPortDeviceOwner(e.Conflict):
    message = _("Operation %(op)s is not supported for device_owner "
                "%(device_owner)s on port %(port_id)s.")


class OverlappingAllocationPools(e.Conflict):
    message = _("Found overlapping allocation pools: "
                "%(pool_1)s %(pool_2)s for subnet %(subnet_cidr)s.")


class PlacementInventoryUpdateConflict(e.Conflict):
    message = _("Placement inventory update conflict for resource provider "
                "%(resource_provider)s, resource class %(resource_class)s.")


class OutOfBoundsAllocationPool(e.BadRequest):
    message = _("The allocation pool %(pool)s spans "
                "beyond the subnet cidr %(subnet_cidr)s.")


class MacAddressGenerationFailure(e.ServiceUnavailable):
    message = _("Unable to generate unique mac on network %(net_id)s.")


class BridgeDoesNotExist(e.NeutronException):
    message = _("Bridge %(bridge)s does not exist.")


class QuotaResourceUnknown(e.NotFound):
    message = _("Unknown quota resources %(unknown)s.")


class QuotaMissingTenant(e.BadRequest):
    message = _("Tenant-id was missing from quota request.")


class InvalidQuotaValue(e.Conflict):
    message = _("Change would make usage less than 0 for the following "
                "resources: %(unders)s.")


class InvalidSharedSetting(e.Conflict):
    message = _("Unable to reconfigure sharing settings for network "
                "%(network)s. Multiple tenants are using it.")


class QoSRuleParameterConflict(e.Conflict):
    message = _("Unable to add the rule with value %(rule_value)s to the "
                "policy %(policy_id)s as the existing rule of type "
                "%(existing_rule)s restricts the bandwidth to "
                "%(existing_value)s.")


class QoSRulesConflict(e.Conflict):
    message = _("Rule %(new_rule_type)s conflicts with "
                "rule %(rule_id)s which already exists in "
                "QoS Policy %(policy_id)s.")


class ExtensionsNotFound(e.NotFound):
    message = _("Extensions not found: %(extensions)s.")


class GatewayConflictWithAllocationPools(e.InUse):
    message = _("Gateway ip %(ip_address)s conflicts with "
                "allocation pool %(pool)s.")


class GatewayIpInUse(e.InUse):
    message = _("Current gateway ip %(ip_address)s already in use "
                "by port %(port_id)s. Unable to update.")


class NetworkVlanRangeError(e.NeutronException):
    message = _("Invalid network VLAN range: '%(vlan_range)s' - '%(error)s'.")

    def __init__(self, **kwargs):
        # Convert vlan_range tuple to 'start:end' format for display
        if isinstance(kwargs['vlan_range'], tuple):
            kwargs['vlan_range'] = "%d:%d" % kwargs['vlan_range']
        super(NetworkVlanRangeError, self).__init__(**kwargs)


class PhysicalNetworkNameError(e.NeutronException):
    message = _("Empty physical network name.")


class NetworkVxlanPortRangeError(e.NeutronException):
    message = _("Invalid network VXLAN port range: '%(vxlan_range)s'.")


class VxlanNetworkUnsupported(e.NeutronException):
    message = _("VXLAN network unsupported.")


class DuplicatedExtension(e.NeutronException):
    message = _("Found duplicate extension: %(alias)s.")


class DriverCallError(e.MultipleExceptions):
    def __init__(self, exc_list=None):
        super(DriverCallError, self).__init__(exc_list or [])


class DeviceIDNotOwnedByTenant(e.Conflict):
    message = _("The following device_id %(device_id)s is not owned by your "
                "tenant or matches another tenants router.")


class InvalidCIDR(e.BadRequest):
    message = _("Invalid CIDR %(input)s given as IP prefix.")


class RouterNotCompatibleWithAgent(e.NeutronException):
    message = _("Router '%(router_id)s' is not compatible with this agent.")


class FailToDropPrivilegesExit(SystemExit):
    """Exit exception raised when a drop privileges action fails."""
    code = 99


class FloatingIpSetupException(e.NeutronException):
    def __init__(self, message=None):
        self.message = message
        super(FloatingIpSetupException, self).__init__()


class IpTablesApplyException(e.NeutronException):
    def __init__(self, message=None):
        self.message = message
        super(IpTablesApplyException, self).__init__()


class NetworkIdOrRouterIdRequiredError(e.NeutronException):
    message = _('Both network_id and router_id are None. '
                'One must be provided.')


class AbortSyncRouters(e.NeutronException):
    message = _("Aborting periodic_sync_routers_task due to an error.")


class EmptySubnetPoolPrefixList(e.BadRequest):
    message = _("Empty subnet pool prefix list.")


class PrefixVersionMismatch(e.BadRequest):
    message = _("Cannot mix IPv4 and IPv6 prefixes in a subnet pool.")


class UnsupportedMinSubnetPoolPrefix(e.BadRequest):
    message = _("Prefix '%(prefix)s' not supported in IPv%(version)s pool.")


class IllegalSubnetPoolPrefixBounds(e.BadRequest):
    message = _("Illegal prefix bounds: %(prefix_type)s=%(prefixlen)s, "
                "%(base_prefix_type)s=%(base_prefixlen)s.")


class IllegalSubnetPoolPrefixUpdate(e.BadRequest):
    message = _("Illegal update to prefixes: %(msg)s.")


class SubnetAllocationError(e.NeutronException):
    message = _("Failed to allocate subnet: %(reason)s.")


class AddressScopePrefixConflict(e.Conflict):
    message = _("Failed to associate address scope: subnetpools "
                "within an address scope must have unique prefixes.")


class IllegalSubnetPoolAssociationToAddressScope(e.BadRequest):
    message = _("Illegal subnetpool association: subnetpool %(subnetpool_id)s "
                "cannot be associated with address scope "
                "%(address_scope_id)s.")


class IllegalSubnetPoolIpVersionAssociationToAddressScope(e.BadRequest):
    message = _("Illegal subnetpool association: subnetpool %(subnetpool_id)s "
                "cannot associate with address scope %(address_scope_id)s "
                "because subnetpool ip_version is not %(ip_version)s.")


class IllegalSubnetPoolUpdate(e.BadRequest):
    message = _("Illegal subnetpool update : %(reason)s.")


class MinPrefixSubnetAllocationError(e.BadRequest):
    message = _("Unable to allocate subnet with prefix length %(prefixlen)s, "
                "minimum allowed prefix is %(min_prefixlen)s.")


class MaxPrefixSubnetAllocationError(e.BadRequest):
    message = _("Unable to allocate subnet with prefix length %(prefixlen)s, "
                "maximum allowed prefix is %(max_prefixlen)s.")


class SubnetPoolDeleteError(e.BadRequest):
    message = _("Unable to delete subnet pool: %(reason)s.")


class SubnetPoolQuotaExceeded(e.OverQuota):
    message = _("Per-tenant subnet pool prefix quota exceeded.")


class NetworkSubnetPoolAffinityError(e.BadRequest):
    message = _("Subnets hosted on the same network must be allocated from "
                "the same subnet pool.")


class ObjectActionError(e.NeutronException):
    message = _('Object action %(action)s failed because: %(reason)s.')


class CTZoneExhaustedError(e.NeutronException):
    message = _("IPtables conntrack zones exhausted, iptables rules cannot "
                "be applied.")


class TenantQuotaNotFound(e.NotFound):
    message = _("Quota for tenant %(tenant_id)s could not be found.")


class TenantIdProjectIdFilterConflict(e.BadRequest):
    message = _("Both tenant_id and project_id passed as filters.")


class MultipleFilterIDForIPFound(e.Conflict):
    message = _("Multiple filter IDs for IP %(ip)s found.")


class FilterIDForIPNotFound(e.NotFound):
    message = _("Filter ID for IP %(ip)s could not be found.")


class FailedToAddQdiscToDevice(e.NeutronException):
    message = _("Failed to add %(direction)s qdisc "
                "to device %(device)s.")


class ProcessExecutionError(RuntimeError):
    def __init__(self, message, returncode):
        super(ProcessExecutionError, self).__init__(message)
        self.returncode = returncode
