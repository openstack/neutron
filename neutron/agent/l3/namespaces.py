# Copyright 2015 Hewlett-Packard Development Company, L.P.
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
#

from oslo_log import log as logging

from neutron.agent.linux import ip_lib
from neutron.i18n import _LE

LOG = logging.getLogger(__name__)

NS_PREFIX = 'qrouter-'
INTERNAL_DEV_PREFIX = 'qr-'
EXTERNAL_DEV_PREFIX = 'qg-'
# TODO(Carl) It is odd that this file needs this.  It is a dvr detail.
ROUTER_2_FIP_DEV_PREFIX = 'rfp-'


class Namespace(object):

    def __init__(self, name, agent_conf, driver, use_ipv6):
        self.name = name
        self.ip_wrapper_root = ip_lib.IPWrapper()
        self.agent_conf = agent_conf
        self.driver = driver
        self.use_ipv6 = use_ipv6

    def create(self):
        ip_wrapper = self.ip_wrapper_root.ensure_namespace(self.name)
        cmd = ['sysctl', '-w', 'net.ipv4.ip_forward=1']
        ip_wrapper.netns.execute(cmd)
        if self.use_ipv6:
            cmd = ['sysctl', '-w', 'net.ipv6.conf.all.forwarding=1']
            ip_wrapper.netns.execute(cmd)

    def delete(self):
        if self.agent_conf.router_delete_namespaces:
            try:
                self.ip_wrapper_root.netns.delete(self.name)
            except RuntimeError:
                msg = _LE('Failed trying to delete namespace: %s')
                LOG.exception(msg, self.name)


class RouterNamespace(Namespace):

    def __init__(self, router_id, agent_conf, driver, use_ipv6):
        self.router_id = router_id
        name = self._get_ns_name(router_id)
        super(RouterNamespace, self).__init__(
            name, agent_conf, driver, use_ipv6)

    @staticmethod
    def _get_ns_name(router_id):
        return (NS_PREFIX + router_id)

    def delete(self):
        ns_ip = ip_lib.IPWrapper(namespace=self.name)
        for d in ns_ip.get_devices(exclude_loopback=True):
            if d.name.startswith(INTERNAL_DEV_PREFIX):
                # device is on default bridge
                self.driver.unplug(d.name, namespace=self.name,
                                   prefix=INTERNAL_DEV_PREFIX)
            elif d.name.startswith(ROUTER_2_FIP_DEV_PREFIX):
                ns_ip.del_veth(d.name)
            elif d.name.startswith(EXTERNAL_DEV_PREFIX):
                self.driver.unplug(
                    d.name,
                    bridge=self.agent_conf.external_network_bridge,
                    namespace=self.name,
                    prefix=EXTERNAL_DEV_PREFIX)

        super(RouterNamespace, self).delete()
