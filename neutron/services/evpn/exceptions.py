# Copyright 2026 Red Hat, LLC
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
from neutron_lib import exceptions


class EVPNVNIInUse(exceptions.Conflict):
    message = _("EVPN VNI %(vni)s is already in use.")


class EVPNVNINotFound(exceptions.NotFound):
    message = _("EVPN VNI not found for router %(router_id)s.")


class EVPNNoVniAvailable(exceptions.Conflict):
    message = _("No EVPN VNI available in range [%(min_vni)s, %(max_vni)s].")

    def __init__(self, min_val, max_val):
        super().__init__(min_vni=min_val, max_vni=max_val)


class EVPNNoVlanAvailable(exceptions.Conflict):
    message = _("No EVPN VLAN ID available in range "
                "[%(min_vlan)s, %(max_vlan)s].")

    def __init__(self, min_val, max_val):
        super().__init__(min_vlan=min_val, max_vlan=max_val)
