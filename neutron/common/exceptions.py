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

from neutron_lib import exceptions
from neutron_lib.exceptions import l3
from neutron_lib.exceptions import qos

from neutron._i18n import _


# TODO(boden): remove lib shims
SubnetPoolNotFound = exceptions.SubnetPoolNotFound
StateInvalid = exceptions.StateInvalid
DhcpPortInUse = exceptions.DhcpPortInUse
HostRoutesExhausted = exceptions.HostRoutesExhausted
DNSNameServersExhausted = exceptions.DNSNameServersExhausted
FlatNetworkInUse = exceptions.FlatNetworkInUse
NoNetworkFoundInMaximumAllowedAttempts = \
    exceptions.NoNetworkFoundInMaximumAllowedAttempts
MalformedRequestBody = exceptions.MalformedRequestBody
InvalidAllocationPool = exceptions.InvalidAllocationPool
UnsupportedPortDeviceOwner = \
    exceptions.UnsupportedPortDeviceOwner
OverlappingAllocationPools = exceptions.OverlappingAllocationPools
OutOfBoundsAllocationPool = exceptions.OutOfBoundsAllocationPool
BridgeDoesNotExist = exceptions.BridgeDoesNotExist
QuotaResourceUnknown = exceptions.QuotaResourceUnknown
QuotaMissingTenant = exceptions.QuotaMissingTenant
InvalidQuotaValue = exceptions.InvalidQuotaValue
InvalidSharedSetting = exceptions.InvalidSharedSetting
ExtensionsNotFound = exceptions.ExtensionsNotFound
GatewayConflictWithAllocationPools = \
    exceptions.GatewayConflictWithAllocationPools
GatewayIpInUse = exceptions.GatewayIpInUse
NetworkVxlanPortRangeError = exceptions.NetworkVxlanPortRangeError
VxlanNetworkUnsupported = exceptions.VxlanNetworkUnsupported
DuplicatedExtension = exceptions.DuplicatedExtension
DriverCallError = exceptions.DriverCallError
DeviceIDNotOwnedByTenant = exceptions.DeviceIDNotOwnedByTenant
InvalidCIDR = exceptions.InvalidCIDR
FailToDropPrivilegesExit = exceptions.FailToDropPrivilegesExit
NetworkIdOrRouterIdRequiredError = exceptions.NetworkIdOrRouterIdRequiredError
EmptySubnetPoolPrefixList = exceptions.EmptySubnetPoolPrefixList
PrefixVersionMismatch = exceptions.PrefixVersionMismatch
UnsupportedMinSubnetPoolPrefix = exceptions.UnsupportedMinSubnetPoolPrefix
IllegalSubnetPoolPrefixBounds = exceptions.IllegalSubnetPoolPrefixBounds
IllegalSubnetPoolPrefixUpdate = exceptions.IllegalSubnetPoolPrefixUpdate
SubnetAllocationError = exceptions.SubnetAllocationError
AddressScopePrefixConflict = exceptions.AddressScopePrefixConflict
IllegalSubnetPoolAssociationToAddressScope = \
    exceptions.IllegalSubnetPoolAssociationToAddressScope
IllegalSubnetPoolIpVersionAssociationToAddressScope = \
    exceptions.IllegalSubnetPoolIpVersionAssociationToAddressScope
IllegalSubnetPoolUpdate = exceptions.IllegalSubnetPoolUpdate
MinPrefixSubnetAllocationError = exceptions.MinPrefixSubnetAllocationError
MaxPrefixSubnetAllocationError = exceptions.MaxPrefixSubnetAllocationError
SubnetPoolDeleteError = exceptions.SubnetPoolDeleteError
SubnetPoolQuotaExceeded = exceptions.SubnetPoolQuotaExceeded
NetworkSubnetPoolAffinityError = exceptions.NetworkSubnetPoolAffinityError
ObjectActionError = exceptions.ObjectActionError
CTZoneExhaustedError = exceptions.CTZoneExhaustedError
TenantQuotaNotFound = exceptions.TenantQuotaNotFound
MultipleFilterIDForIPFound = exceptions.MultipleFilterIDForIPFound
FilterIDForIPNotFound = exceptions.FilterIDForIPNotFound
FailedToAddQdiscToDevice = exceptions.FailedToAddQdiscToDevice
PortBindingNotFound = exceptions.PortBindingNotFound

QosPolicyNotFound = qos.QosPolicyNotFound
QosRuleNotFound = qos.QosRuleNotFound
QoSPolicyDefaultAlreadyExists = qos.QoSPolicyDefaultAlreadyExists
PortQosBindingNotFound = qos.PortQosBindingNotFound
PortQosBindingError = qos.PortQosBindingError
NetworkQosBindingNotFound = qos.NetworkQosBindingNotFound
FloatingIPQosBindingNotFound = qos.FloatingIPQosBindingNotFound
FloatingIPQosBindingError = qos.FloatingIPQosBindingError
NetworkQosBindingError = qos.NetworkQosBindingError
PolicyRemoveAuthorizationError = qos.PolicyRemoveAuthorizationError
QosPolicyInUse = qos.QosPolicyInUse
QosRuleNotSupported = qos.QosRuleNotSupported
QoSRuleParameterConflict = qos.QoSRuleParameterConflict
QoSRulesConflict = qos.QoSRulesConflict

RouterNotCompatibleWithAgent = l3.RouterNotCompatibleWithAgent
FloatingIpSetupException = l3.FloatingIpSetupException
IpTablesApplyException = l3.IpTablesApplyException
AbortSyncRouters = l3.AbortSyncRouters


# TODO(boden): rehome these

class PortBindingAlreadyActive(exceptions.Conflict):
    message = _("Binding for port %(port_id)s on host %(host)s is already "
                "active.")


class PortBindingAlreadyExists(exceptions.Conflict):
    message = _("Binding for port %(port_id)s on host %(host)s already "
                "exists.")


class PortBindingError(exceptions.NeutronException):
    message = _("Binding for port %(port_id)s on host %(host)s could not be "
                "created or updated.")


class ProcessExecutionError(RuntimeError):
    def __init__(self, message, returncode):
        super(ProcessExecutionError, self).__init__(message)
        self.returncode = returncode


class RouterQosBindingNotFound(exceptions.NotFound):
    message = _("QoS binding for router %(router_id)s gateway and policy "
                "%(policy_id)s could not be found.")


class RouterQosBindingError(exceptions.NeutronException):
    message = _("QoS binding for router %(router_id)s gateway and policy "
                "%(policy_id)s could not be created: %(db_error)s.")
