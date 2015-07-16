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

from oslo_log import log as logging

from neutron.agent.l3 import router_info as router
from neutron.common import constants as l3_constants
from neutron.i18n import _LE

LOG = logging.getLogger(__name__)


class DvrRouterBase(router.RouterInfo):
    def __init__(self, agent, host, *args, **kwargs):
        super(DvrRouterBase, self).__init__(*args, **kwargs)

        self.agent = agent
        self.host = host

    def get_snat_interfaces(self):
        return self.router.get(l3_constants.SNAT_ROUTER_INTF_KEY, [])

    def get_snat_port_for_internal_port(self, int_port):
        """Return the SNAT port for the given internal interface port."""
        snat_ports = self.get_snat_interfaces()
        fixed_ip = int_port['fixed_ips'][0]
        subnet_id = fixed_ip['subnet_id']
        match_port = [p for p in snat_ports
                      if p['fixed_ips'][0]['subnet_id'] == subnet_id]
        if match_port:
            return match_port[0]
        else:
            LOG.error(_LE('DVR: no map match_port found!'))
