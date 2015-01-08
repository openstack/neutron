# Copyright 2014 OpenStack Foundation.
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

import os

from oslo_config import cfg

from neutron.agent.common import config
from neutron.agent.linux import external_process
from neutron.openstack.common import log as logging
from neutron.services import advanced_service

LOG = logging.getLogger(__name__)

# Access with redirection to metadata proxy iptables mark mask
METADATA_ACCESS_MARK_MASK = '0xffffffff'


class MetadataDriver(advanced_service.AdvancedService):

    OPTS = [
        cfg.StrOpt('metadata_proxy_socket',
                   default='$state_path/metadata_proxy',
                   help=_('Location of Metadata Proxy UNIX domain '
                          'socket')),
        cfg.StrOpt('metadata_proxy_user',
                   default='',
                   help=_("User (uid or name) running metadata proxy after "
                          "its initialization (if empty: L3 agent effective "
                          "user)")),
        cfg.StrOpt('metadata_proxy_group',
                   default='',
                   help=_("Group (gid or name) running metadata proxy after "
                          "its initialization (if empty: L3 agent effective "
                          "group)"))
    ]

    def __init__(self, l3_agent):
        super(MetadataDriver, self).__init__(l3_agent)
        self.metadata_port = l3_agent.conf.metadata_port
        self.metadata_access_mark = l3_agent.conf.metadata_access_mark

    def after_router_added(self, router):
        for c, r in self.metadata_filter_rules(self.metadata_port,
                                               self.metadata_access_mark):
            router.iptables_manager.ipv4['filter'].add_rule(c, r)
        for c, r in self.metadata_mangle_rules(self.metadata_access_mark):
            router.iptables_manager.ipv4['mangle'].add_rule(c, r)
        for c, r in self.metadata_nat_rules(self.metadata_port):
            router.iptables_manager.ipv4['nat'].add_rule(c, r)
        router.iptables_manager.apply()

        if not router.is_ha:
            self._spawn_monitored_metadata_proxy(router.router_id,
                                                 router.ns_name)

    def before_router_removed(self, router):
        for c, r in self.metadata_filter_rules(self.metadata_port,
                                               self.metadata_access_mark):
            router.iptables_manager.ipv4['filter'].remove_rule(c, r)
        for c, r in self.metadata_mangle_rules(self.metadata_access_mark):
            router.iptables_manager.ipv4['mangle'].remove_rule(c, r)
        for c, r in self.metadata_nat_rules(self.metadata_port):
            router.iptables_manager.ipv4['nat'].remove_rule(c, r)
        router.iptables_manager.apply()

        self._destroy_monitored_metadata_proxy(router.router['id'],
                                               router.ns_name)

    @classmethod
    def metadata_filter_rules(cls, port, mark):
        return [('INPUT', '-m mark --mark %s -j ACCEPT' % mark),
                ('INPUT', '-s 0.0.0.0/0 -p tcp -m tcp --dport %s '
                 '-j DROP' % port)]

    @classmethod
    def metadata_mangle_rules(cls, mark):
        return [('PREROUTING', '-s 0.0.0.0/0 -d 169.254.169.254/32 '
                 '-p tcp -m tcp --dport 80 '
                 '-j MARK --set-xmark %(value)s/%(mask)s' %
                 {'value': mark,
                  'mask': METADATA_ACCESS_MARK_MASK})]

    @classmethod
    def metadata_nat_rules(cls, port):
        return [('PREROUTING', '-s 0.0.0.0/0 -d 169.254.169.254/32 '
                 '-p tcp -m tcp --dport 80 -j REDIRECT '
                 '--to-port %s' % port)]

    @classmethod
    def _get_metadata_proxy_user_group(cls, conf):
        user = conf.metadata_proxy_user or os.geteuid()
        group = conf.metadata_proxy_group or os.getegid()
        return user, group

    @classmethod
    def _get_metadata_proxy_callback(cls, router_id, conf):

        def callback(pid_file):
            metadata_proxy_socket = conf.metadata_proxy_socket
            user, group = cls._get_metadata_proxy_user_group(conf)
            proxy_cmd = ['neutron-ns-metadata-proxy',
                         '--pid_file=%s' % pid_file,
                         '--metadata_proxy_socket=%s' % metadata_proxy_socket,
                         '--router_id=%s' % router_id,
                         '--state_path=%s' % conf.state_path,
                         '--metadata_port=%s' % conf.metadata_port,
                         '--metadata_proxy_user=%s' % user,
                         '--metadata_proxy_group=%s' % group]
            proxy_cmd.extend(config.get_log_args(
                conf, 'neutron-ns-metadata-proxy-%s.log' %
                router_id))
            return proxy_cmd

        return callback

    def _spawn_monitored_metadata_proxy(self, router_id, ns_name):
        callback = self._get_metadata_proxy_callback(
            router_id, self.l3_agent.conf)
        self.l3_agent.process_monitor.enable(router_id, callback, ns_name)

    def _destroy_monitored_metadata_proxy(self, router_id, ns_name):
        self.l3_agent.process_monitor.disable(router_id, ns_name)

    # TODO(mangelajo): remove the unmonitored _get_*_process_manager,
    #                  _spawn_* and _destroy* when keepalived stops
    #                  spawning and killing proxies on its own.
    @classmethod
    def _get_metadata_proxy_process_manager(cls, router_id, ns_name, conf):
        return external_process.ProcessManager(
            conf,
            router_id,
            config.get_root_helper(conf),
            ns_name)

    @classmethod
    def _spawn_metadata_proxy(cls, router_id, ns_name, conf):
        callback = cls._get_metadata_proxy_callback(router_id, conf)
        pm = cls._get_metadata_proxy_process_manager(router_id, ns_name, conf)
        pm.enable(callback)

    @classmethod
    def _destroy_metadata_proxy(cls, router_id, ns_name, conf):
        pm = cls._get_metadata_proxy_process_manager(router_id, ns_name, conf)
        pm.disable()
