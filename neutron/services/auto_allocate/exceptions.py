# Copyright 2015-2016 Hewlett Packard Enterprise Development Company, LP
#
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

from neutron_lib import exceptions as n_exc

from neutron._i18n import _


class AutoAllocationFailure(n_exc.Conflict):
    message = _("Deployment error: %(reason)s.")


class DefaultExternalNetworkExists(n_exc.Conflict):
    message = _("A default external network already exists: %(net_id)s.")


class UnknownProvisioningError(Exception):
    """To track unknown errors and partial provisioning steps."""

    def __init__(self, error, network_id=None, router_id=None, subnets=None):
        self.error = error
        self.network_id = network_id
        self.router_id = router_id
        self.subnets = subnets

    def __str__(self):
        return str(self.error)
