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

from oslo_log import log as logging

from neutron.agent.common import config
from neutron.agent.l3 import namespaces
from neutron.agent.linux import external_process
from neutron.agent.linux import utils
from neutron.callbacks import events
from neutron.callbacks import registry
from neutron.callbacks import resources
from neutron.common import exceptions

LOG = logging.getLogger(__name__)

# Access with redirection to metadata proxy iptables mark mask
METADATA_ACCESS_MARK_MASK = '0xffffffff'
METADATA_SERVICE_NAME = 'metadata-proxy'


class MetadataDriver(object):

    def __init__(self, l3_agent):
        self.metadata_port = l3_agent.conf.metadata_port
        self.metadata_access_mark = l3_agent.conf.metadata_access_mark
        registry.subscribe(
            after_router_added, resources.ROUTER, events.AFTER_CREATE)
        registry.subscribe(
            before_router_removed, resources.ROUTER, events.BEFORE_DELETE)

    @classmethod
    def metadata_filter_rules(cls, port, mark):
        return [('INPUT', '-m mark --mark %s -j ACCEPT' % mark),
                ('INPUT', '-p tcp -m tcp --dport %s '
                 '-j DROP' % port)]

    @classmethod
    def metadata_mangle_rules(cls, mark):
        return [('PREROUTING', '-d 169.254.169.254/32 '
                 '-p tcp -m tcp --dport 80 '
                 '-j MARK --set-xmark %(value)s/%(mask)s' %
                 {'value': mark,
                  'mask': METADATA_ACCESS_MARK_MASK})]

    @classmethod
    def metadata_nat_rules(cls, port):
        return [('PREROUTING', '-d 169.254.169.254/32 '
                 '-i %(interface_name)s '
                 '-p tcp -m tcp --dport 80 -j REDIRECT '
                 '--to-port %(port)s' %
                 {'interface_name': namespaces.INTERNAL_DEV_PREFIX + '+',
                  'port': port})]

    @classmethod
    def _get_metadata_proxy_user_group_watchlog(cls, conf):
        user = conf.metadata_proxy_user or str(os.geteuid())
        group = conf.metadata_proxy_group or str(os.getegid())

        watch_log = conf.metadata_proxy_watch_log
        if watch_log is None:
            # NOTE(cbrandily): Commonly, log watching can be enabled only
            # when metadata proxy user is agent effective user (id/name).
            watch_log = utils.is_effective_user(user)

        return user, group, watch_log

    @classmethod
    def _get_metadata_proxy_callback(cls, port, conf, network_id=None,
                                     router_id=None):
        uuid = network_id or router_id
        if uuid is None:
            raise exceptions.NetworkIdOrRouterIdRequiredError()

        if network_id:
            lookup_param = '--network_id=%s' % network_id
        else:
            lookup_param = '--router_id=%s' % router_id

        def callback(pid_file):
            metadata_proxy_socket = conf.metadata_proxy_socket
            user, group, watch_log = (
                cls._get_metadata_proxy_user_group_watchlog(conf))
            proxy_cmd = ['neutron-ns-metadata-proxy',
                         '--pid_file=%s' % pid_file,
                         '--metadata_proxy_socket=%s' % metadata_proxy_socket,
                         lookup_param,
                         '--state_path=%s' % conf.state_path,
                         '--metadata_port=%s' % port,
                         '--metadata_proxy_user=%s' % user,
                         '--metadata_proxy_group=%s' % group]
            proxy_cmd.extend(config.get_log_args(
                conf, 'neutron-ns-metadata-proxy-%s.log' % uuid,
                metadata_proxy_watch_log=watch_log))
            return proxy_cmd

        return callback

    @classmethod
    def spawn_monitored_metadata_proxy(cls, monitor, ns_name, port, conf,
                                       network_id=None, router_id=None):
        uuid = network_id or router_id
        callback = cls._get_metadata_proxy_callback(
            port, conf, network_id=network_id, router_id=router_id)
        pm = cls._get_metadata_proxy_process_manager(uuid, ns_name, conf,
                                                     callback=callback)
        pm.enable()
        monitor.register(uuid, METADATA_SERVICE_NAME, pm)

    @classmethod
    def destroy_monitored_metadata_proxy(cls, monitor, uuid, ns_name, conf):
        monitor.unregister(uuid, METADATA_SERVICE_NAME)
        pm = cls._get_metadata_proxy_process_manager(uuid, ns_name, conf)
        pm.disable()

    @classmethod
    def _get_metadata_proxy_process_manager(cls, router_id, ns_name, conf,
                                            callback=None):
        return external_process.ProcessManager(
            conf=conf,
            uuid=router_id,
            namespace=ns_name,
            default_cmd_callback=callback)


def after_router_added(resource, event, l3_agent, **kwargs):
    router = kwargs['router']
    proxy = l3_agent.metadata_driver
    for c, r in proxy.metadata_filter_rules(proxy.metadata_port,
                                           proxy.metadata_access_mark):
        router.iptables_manager.ipv4['filter'].add_rule(c, r)
    for c, r in proxy.metadata_mangle_rules(proxy.metadata_access_mark):
        router.iptables_manager.ipv4['mangle'].add_rule(c, r)
    for c, r in proxy.metadata_nat_rules(proxy.metadata_port):
        router.iptables_manager.ipv4['nat'].add_rule(c, r)
    router.iptables_manager.apply()

    if not router.is_ha:
        proxy.spawn_monitored_metadata_proxy(
            l3_agent.process_monitor,
            router.ns_name,
            proxy.metadata_port,
            l3_agent.conf,
            router_id=router.router_id)


def before_router_removed(resource, event, l3_agent, **kwargs):
    router = kwargs['router']
    proxy = l3_agent.metadata_driver
    for c, r in proxy.metadata_filter_rules(proxy.metadata_port,
                                           proxy.metadata_access_mark):
        router.iptables_manager.ipv4['filter'].remove_rule(c, r)
    for c, r in proxy.metadata_mangle_rules(proxy.metadata_access_mark):
        router.iptables_manager.ipv4['mangle'].remove_rule(c, r)
    for c, r in proxy.metadata_nat_rules(proxy.metadata_port):
        router.iptables_manager.ipv4['nat'].remove_rule(c, r)
    router.iptables_manager.apply()

    proxy.destroy_monitored_metadata_proxy(l3_agent.process_monitor,
                                          router.router['id'],
                                          router.ns_name,
                                          l3_agent.conf)
