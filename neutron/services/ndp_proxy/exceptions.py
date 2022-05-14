# Copyright 2022 Troila
# All rights reserved.
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

from neutron_lib import exceptions as n_exc

from neutron._i18n import _


class RouterGatewayInUseByNDPProxy(n_exc.Conflict):
    message = _("Unable to unset external gateway of router "
                "%(router_id)s, There are one or more ndp proxies "
                "still in use on the router.")


class RouterInterfaceInUseByNDPProxy(n_exc.Conflict):
    message = _("Unable to remove subnet %(subnet_id)s from router "
                "%(router_id)s, There are one or more ndp proxies "
                "still in use on the subnet.")


class AddressScopeConflict(n_exc.Conflict):
    message = _("The IPv6 address scope %(ext_address_scope)s of external "
                "network conflict with internal network's IPv6 address "
                "scope %(internal_address_scope)s.")


class RouterGatewayNotValid(n_exc.Conflict):
    message = _("Can not enable ndp proxy on "
                "router %(router_id)s, %(reason)s.")


class RouterNDPProxyNotEnable(n_exc.Conflict):
    message = _("The enable_ndp_proxy parameter of router %(router_id)s must "
                "be set as True while create ndp proxy entry on it.")


class PortUnreachableRouter(n_exc.Conflict):
    message = _("The port %(port_id)s cannot reach the router %(router_id)s "
                "by IPv6 subnet.")


class InvalidAddress(n_exc.BadRequest):
    message = _("The address %(address)s is invalid, reason: %(reason)s.")


class RouterIPv6GatewayInUse(n_exc.Conflict):
    message = _("Can't remove the IPv6 subnet from external gateway of "
                "router %(router_id)s, the IPv6 subnet in use by the "
                "router's ndp proxy.")


class NDPProxyNotFound(n_exc.NotFound):
    message = _("Ndp proxy %(id)s could not be found.")
