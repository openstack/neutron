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

from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants
from oslo_log import log as logging
from oslo_utils import netutils

from neutron.agent.l3 import ha_router
from neutron.agent.l3 import namespaces
from neutron.agent.metadata import driver_base
from neutron.common import coordination


LOG = logging.getLogger(__name__)

_HEADER_CONFIG_TEMPLATE = """
    http-request del-header X-Neutron-%(res_type_del)s-ID
    http-request set-header X-Neutron-%(res_type)s-ID %(res_id)s
"""


class HaproxyConfigurator(driver_base.HaproxyConfiguratorBase):
    PROXY_CONFIG_DIR = "ns-metadata-proxy"
    HEADER_CONFIG_TEMPLATE = _HEADER_CONFIG_TEMPLATE


class MetadataDriver(driver_base.MetadataDriverBase):
    def __init__(self, l3_agent=None):
        if not l3_agent:
            return
        self.metadata_port = l3_agent.conf.metadata_port
        self.metadata_access_mark = l3_agent.conf.metadata_access_mark
        registry.subscribe(
            after_router_added, resources.ROUTER, events.AFTER_CREATE)
        registry.subscribe(
            after_router_updated, resources.ROUTER, events.AFTER_UPDATE)
        registry.subscribe(
            before_router_removed, resources.ROUTER, events.BEFORE_DELETE)

    @staticmethod
    def haproxy_configurator():
        return HaproxyConfigurator


def metadata_filter_rules(port, mark):
    return [('INPUT', '-m mark --mark %s/%s -j ACCEPT' %
             (mark, constants.ROUTER_MARK_MASK)),
            ('INPUT', '-p tcp -m tcp --dport %s '
             '-j DROP' % port)]


def metadata_nat_rules(port, metadata_address=constants.METADATA_V4_CIDR):
    return [('PREROUTING', '-d %(metadata_address)s '
             '-i %(interface_name)s '
             '-p tcp -m tcp --dport 80 -j REDIRECT '
             '--to-ports %(port)s' %
             {'metadata_address': metadata_address,
              'interface_name': namespaces.INTERNAL_DEV_PREFIX + '+',
              'port': port})]


def after_router_added(resource, event, l3_agent, payload):
    router = payload.latest_state
    proxy = l3_agent.metadata_driver
    apply_metadata_nat_rules(router, proxy)
    if not isinstance(router, ha_router.HaRouter):
        spawn_kwargs = {}
        if netutils.is_ipv6_enabled():
            spawn_kwargs['bind_address'] = '::'
        proxy.spawn_monitored_metadata_proxy(
            l3_agent.process_monitor,
            router.ns_name,
            proxy.metadata_port,
            l3_agent.conf,
            router_id=router.router_id,
            **spawn_kwargs)


def after_router_updated(resource, event, l3_agent, payload):
    router = payload.latest_state
    proxy = l3_agent.metadata_driver
    if (not proxy.monitors.get(router.router_id) and
            not isinstance(router, ha_router.HaRouter)):
        spawn_kwargs = {}
        if netutils.is_ipv6_enabled():
            spawn_kwargs['bind_address'] = '::'
        proxy.spawn_monitored_metadata_proxy(
            l3_agent.process_monitor,
            router.ns_name,
            proxy.metadata_port,
            l3_agent.conf,
            router_id=router.router_id,
            **spawn_kwargs)


def before_router_removed(resource, event, l3_agent, payload=None):
    router = payload.latest_state
    proxy = l3_agent.metadata_driver

    proxy.destroy_monitored_metadata_proxy(l3_agent.process_monitor,
                                           router.router['id'],
                                           l3_agent.conf,
                                           router.ns_name)


@coordination.synchronized('router-lock-ns-{router.ns_name}')
def apply_metadata_nat_rules(router, proxy):
    for c, r in metadata_filter_rules(proxy.metadata_port,
                                      proxy.metadata_access_mark):
        router.iptables_manager.ipv4['filter'].add_rule(c, r)
    if netutils.is_ipv6_enabled():
        for c, r in metadata_filter_rules(proxy.metadata_port,
                                          proxy.metadata_access_mark):
            router.iptables_manager.ipv6['filter'].add_rule(c, r)
    for c, r in metadata_nat_rules(proxy.metadata_port):
        router.iptables_manager.ipv4['nat'].add_rule(c, r)
    if netutils.is_ipv6_enabled():
        for c, r in metadata_nat_rules(
                proxy.metadata_port,
                metadata_address=(constants.METADATA_V6_CIDR)):
            router.iptables_manager.ipv6['nat'].add_rule(c, r)
    router.iptables_manager.apply()
