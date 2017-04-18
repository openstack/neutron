# Copyright (c) 2015 OpenStack Foundation
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

from neutron_lib import constants as lib_constants

from neutron.agent.l3 import router_info as router
from neutron.agent.linux import ip_lib


class LegacyRouter(router.RouterInfo):
    def add_floating_ip(self, fip, interface_name, device):
        if not self._add_fip_addr_to_device(fip, device):
            return lib_constants.FLOATINGIP_STATUS_ERROR

        # As GARP is processed in a distinct thread the call below
        # won't raise an exception to be handled.
        ip_lib.send_ip_addr_adv_notif(self.ns_name,
                                      interface_name,
                                      fip['floating_ip_address'])
        return lib_constants.FLOATINGIP_STATUS_ACTIVE
