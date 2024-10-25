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

from neutron_lib import constants
from oslo_log import log as logging

from neutron.agent.l3 import router_info as router

LOG = logging.getLogger(__name__)


class DvrRouterBase(router.RouterInfo):
    def __init__(self, host, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.host = host
        self.snat_ports = None

    def process(self):
        super().process()
        # NOTE:  Keep a copy of the interfaces around for when they are removed
        self.snat_ports = self.get_snat_interfaces()

    def get_snat_interfaces(self):
        return self.router.get(constants.SNAT_ROUTER_INTF_KEY, [])

    def get_snat_port_for_internal_port(self, int_port, snat_ports=None):
        """Return the SNAT port for the given internal interface port."""
        if snat_ports is None:
            snat_ports = self.get_snat_interfaces()
        if not snat_ports:
            return
        fixed_ips = int_port['fixed_ips']
        subnet_ids = [fixed_ip['subnet_id'] for fixed_ip in fixed_ips]
        for p in snat_ports:
            for ip in p['fixed_ips']:
                if ip['subnet_id'] in subnet_ids:
                    return p

        LOG.error('DVR: SNAT port not found in the list '
                  '%(snat_list)s for the given router '
                  'internal port %(int_p)s', {
                      'snat_list': snat_ports,
                      'int_p': int_port})
