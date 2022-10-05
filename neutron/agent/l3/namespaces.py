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

import functools

from oslo_log import log as logging
from oslo_utils import excutils

from neutron.agent.linux import ip_lib

LOG = logging.getLogger(__name__)

NS_PREFIX = 'qrouter-'
INTERNAL_DEV_PREFIX = 'qr-'
EXTERNAL_DEV_PREFIX = 'qg-'
# TODO(Carl) It is odd that this file needs this.  It is a dvr detail.
ROUTER_2_FIP_DEV_PREFIX = 'rfp-'


def build_ns_name(prefix, identifier):
    """Builds a namespace name from the given prefix and identifier

    :param prefix: The prefix which must end with '-' for legacy reasons
    :param identifier: The id associated with the namespace
    """
    return prefix + identifier


def get_prefix_from_ns_name(ns_name):
    """Parses prefix from prefix-identifier

    :param ns_name: The name of a namespace
    :returns: The prefix ending with a '-' or None if there is no '-'
    """
    dash_index = ns_name.find('-')
    if dash_index >= 0:
        return ns_name[:dash_index + 1]


def get_id_from_ns_name(ns_name):
    """Parses identifier from prefix-identifier

    :param ns_name: The name of a namespace
    :returns: Identifier or None if there is no - to end the prefix
    """
    dash_index = ns_name.find('-')
    if dash_index >= 0:
        return ns_name[dash_index + 1:]


def check_ns_existence(f):
    @functools.wraps(f)
    def wrapped(self, *args, **kwargs):
        if not self.exists():
            LOG.warning('Namespace %(name)s does not exist. Skipping '
                        '%(func)s',
                        {'name': self.name, 'func': f.__name__})
            return
        try:
            return f(self, *args, **kwargs)
        except RuntimeError:
            with excutils.save_and_reraise_exception() as ctx:
                if not self.exists():
                    LOG.debug('Namespace %(name)s was concurrently deleted',
                              self.name)
                    ctx.reraise = False
    return wrapped


class Namespace(object):

    def __init__(self, name, agent_conf, driver, use_ipv6):
        self.name = name
        self.ip_wrapper_root = ip_lib.IPWrapper()
        self.agent_conf = agent_conf
        self.driver = driver
        self.use_ipv6 = use_ipv6

    def create(self, ipv6_forwarding=True):
        # See networking (netdev) tree, file
        # Documentation/networking/ip-sysctl.txt for an explanation of
        # these sysctl values.
        ip_wrapper = self.ip_wrapper_root.ensure_namespace(self.name)
        cmd = ['sysctl', '-w', 'net.ipv4.ip_forward=1']
        ip_wrapper.netns.execute(cmd, privsep_exec=True)
        # 1. Reply only if the target IP address is local address configured
        #    on the incoming interface; and
        # 2. Always use the best local address
        cmd = ['sysctl', '-w', 'net.ipv4.conf.all.arp_ignore=1']
        ip_wrapper.netns.execute(cmd, privsep_exec=True)
        cmd = ['sysctl', '-w', 'net.ipv4.conf.all.arp_announce=2']
        ip_wrapper.netns.execute(cmd, privsep_exec=True)
        if self.use_ipv6:
            cmd = ['sysctl', '-w',
                   'net.ipv6.conf.all.forwarding=%d' % int(ipv6_forwarding)]
            ip_wrapper.netns.execute(cmd, privsep_exec=True)

    def delete(self):
        try:
            self.ip_wrapper_root.netns.delete(self.name)
        except RuntimeError:
            msg = 'Failed trying to delete namespace: %s'
            LOG.exception(msg, self.name)

    def exists(self):
        return self.ip_wrapper_root.netns.exists(self.name)


class RouterNamespace(Namespace):

    def __init__(self, router_id, agent_conf, driver, use_ipv6):
        self.router_id = router_id
        name = self._get_ns_name(router_id)
        super(RouterNamespace, self).__init__(
            name, agent_conf, driver, use_ipv6)

    @classmethod
    def _get_ns_name(cls, router_id):
        return build_ns_name(NS_PREFIX, router_id)

    @check_ns_existence
    def delete(self):
        ns_ip = ip_lib.IPWrapper(namespace=self.name)
        for d in ns_ip.get_devices():
            if d.name.startswith(INTERNAL_DEV_PREFIX):
                # device is on default bridge
                self.driver.unplug(d.name, namespace=self.name,
                                   prefix=INTERNAL_DEV_PREFIX)
            elif d.name.startswith(ROUTER_2_FIP_DEV_PREFIX):
                ns_ip.del_veth(d.name)
            elif d.name.startswith(EXTERNAL_DEV_PREFIX):
                self.driver.unplug(
                    d.name,
                    namespace=self.name,
                    prefix=EXTERNAL_DEV_PREFIX)

        super(RouterNamespace, self).delete()
