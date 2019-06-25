# Copyright 2018 OpenStack Foundation.
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

from neutron._i18n import _
from neutron_lib import exceptions as n_exc


class PortForwardingNotFound(n_exc.NotFound):
    message = _("Port Forwarding %(id)s could not be found.")


class PortForwardingNotSupportFilterField(n_exc.BadRequest):
    message = _("Port Forwarding filter %(filter)s is not supported.")


class PortHasPortForwarding(n_exc.BadRequest):
    message = _("Cannot associate floating IP to port "
                "%(port_id)s because it already has a "
                "Port Forwarding binding.")


class FipInUseByPortForwarding(n_exc.InUse):
    message = _("Floating IP %(id)s in use by Port Forwarding resources.")


class PortHasBindingFloatingIP(n_exc.InUse):
    message = _("Cannot create port forwarding to floating IP "
                "%(floating_ip_address)s (%(fip_id)s) with port %(port_id)s "
                "using fixed IP %(fixed_ip)s, as that port already "
                "has a binding floating IP.")
