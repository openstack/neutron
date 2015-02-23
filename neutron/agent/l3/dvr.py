# Copyright (c) 2014 Openstack Foundation
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

import weakref

from oslo_log import log as logging

from neutron.agent.l3 import dvr_fip_ns
from neutron.agent.l3 import dvr_snat_ns

LOG = logging.getLogger(__name__)

# TODO(Carl) Following constants retained to increase SNR during refactoring
SNAT_INT_DEV_PREFIX = dvr_snat_ns.SNAT_INT_DEV_PREFIX
SNAT_NS_PREFIX = dvr_snat_ns.SNAT_NS_PREFIX


class AgentMixin(object):
    def __init__(self, host):
        # dvr data
        self._fip_namespaces = weakref.WeakValueDictionary()
        super(AgentMixin, self).__init__(host)

    def get_fip_ns(self, ext_net_id):
        # TODO(Carl) is this necessary?  Code that this replaced was careful to
        # convert these to string like this so I preserved that.
        ext_net_id = str(ext_net_id)

        fip_ns = self._fip_namespaces.get(ext_net_id)
        if fip_ns and not fip_ns.destroyed:
            return fip_ns

        fip_ns = dvr_fip_ns.FipNamespace(ext_net_id,
                                         self.conf,
                                         self.driver,
                                         self.use_ipv6)
        self._fip_namespaces[ext_net_id] = fip_ns

        return fip_ns

    def _destroy_fip_namespace(self, ns):
        ex_net_id = ns[len(dvr_fip_ns.FIP_NS_PREFIX):]
        fip_ns = self.get_fip_ns(ex_net_id)
        fip_ns.delete()

    def get_ports_by_subnet(self, subnet_id):
        return self.plugin_rpc.get_ports_by_subnet(self.context, subnet_id)

    def add_arp_entry(self, context, payload):
        """Add arp entry into router namespace.  Called from RPC."""
        router_id = payload['router_id']
        ri = self.router_info.get(router_id)
        if not ri:
            return

        arp_table = payload['arp_table']
        ip = arp_table['ip_address']
        mac = arp_table['mac_address']
        subnet_id = arp_table['subnet_id']
        ri._update_arp_entry(ip, mac, subnet_id, 'add')

    def del_arp_entry(self, context, payload):
        """Delete arp entry from router namespace.  Called from RPC."""
        router_id = payload['router_id']
        ri = self.router_info.get(router_id)
        if not ri:
            return

        arp_table = payload['arp_table']
        ip = arp_table['ip_address']
        mac = arp_table['mac_address']
        subnet_id = arp_table['subnet_id']
        ri._update_arp_entry(ip, mac, subnet_id, 'delete')
