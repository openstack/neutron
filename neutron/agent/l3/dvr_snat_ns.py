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

from neutron.agent.l3 import namespaces
from neutron.agent.linux import ip_lib
from neutron.common import constants

LOG = logging.getLogger(__name__)
SNAT_NS_PREFIX = 'snat-'
SNAT_INT_DEV_PREFIX = constants.SNAT_INT_DEV_PREFIX


class SnatNamespace(namespaces.Namespace):

    def __init__(self, router_id, agent_conf, driver, use_ipv6):
        self.router_id = router_id
        name = self.get_snat_ns_name(router_id)
        super(SnatNamespace, self).__init__(
            name, agent_conf, driver, use_ipv6)

    @classmethod
    def get_snat_ns_name(cls, router_id):
        return namespaces.build_ns_name(SNAT_NS_PREFIX, router_id)

    @namespaces.check_ns_existence
    def delete(self):
        ns_ip = ip_lib.IPWrapper(namespace=self.name)
        for d in ns_ip.get_devices(exclude_loopback=True):
            if d.name.startswith(SNAT_INT_DEV_PREFIX):
                LOG.debug('Unplugging DVR device %s', d.name)
                self.driver.unplug(d.name, namespace=self.name,
                                   prefix=SNAT_INT_DEV_PREFIX)

        # TODO(mrsmith): delete ext-gw-port
        LOG.debug('DVR: destroy snat ns: %s', self.name)
        super(SnatNamespace, self).delete()
