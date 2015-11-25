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

    def process(self, agent, delete=False):
        super(DvrRouterBase, self).process(agent, delete)
        # NOTE:  Keep a copy of the interfaces around for when they are removed
        self.snat_ports = self.get_snat_interfaces()

    def get_snat_interfaces(self):
        return self.router.get(l3_constants.SNAT_ROUTER_INTF_KEY, [])

    def get_snat_port_for_internal_port(self, int_port, snat_ports=None):
        """Return the SNAT port for the given internal interface port."""
        if snat_ports is None:
            snat_ports = self.get_snat_interfaces()
        fixed_ip = int_port['fixed_ips'][0]
        subnet_id = fixed_ip['subnet_id']
        if snat_ports:
            match_port = [p for p in snat_ports
                          if p['fixed_ips'][0]['subnet_id'] == subnet_id]
            if match_port:
                return match_port[0]
            else:
                LOG.error(_LE('DVR: SNAT port not found in the list '
                              '%(snat_list)s for the given router '
                              ' internal port %(int_p)s'), {
                                  'snat_list': snat_ports,
                                  'int_p': int_port})
