# Copyright (C) 2013 Midokura PTE LTD
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

from neutron.agent.linux import dhcp
from neutron.openstack.common import log as logging
from neutron.plugins.midonet.common import config  # noqa

LOG = logging.getLogger(__name__)


class DhcpNoOpDriver(dhcp.DhcpLocalProcess):

    @classmethod
    def existing_dhcp_networks(cls, conf, root_helper):
        """Return a list of existing networks ids that we have configs for."""
        return []

    @classmethod
    def check_version(cls):
        """Execute version checks on DHCP server."""
        return float(1.0)

    def disable(self, retain_port=False):
        """Disable DHCP for this network."""
        if not retain_port:
            self.device_manager.destroy(self.network, self.interface_name)
        self._remove_config_files()

    def reload_allocations(self):
        """Force the DHCP server to reload the assignment database."""
        pass

    def spawn_process(self):
        pass
