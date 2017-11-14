# Copyright 2015 Cisco Systems
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

import functools
import signal

import eventlet
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants as n_const
from neutron_lib.utils import runtime
from oslo_log import log as logging
from oslo_utils import netutils
import six
from stevedore import driver

from neutron.common import constants as l3_constants
from neutron.common import utils

LOG = logging.getLogger(__name__)


class PrefixDelegation(object):
    def __init__(self, context, pmon, intf_driver, notifier, pd_update_cb,
                 agent_conf):
        self.context = context
        self.pmon = pmon
        self.intf_driver = intf_driver
        self.notifier = notifier
        self.routers = {}
        self.pd_update_cb = pd_update_cb
        self.agent_conf = agent_conf
        self.pd_dhcp_driver = driver.DriverManager(
            namespace='neutron.agent.linux.pd_drivers',
            name=agent_conf.prefix_delegation_driver,
        ).driver
        registry.subscribe(add_router,
                           resources.ROUTER,
                           events.BEFORE_CREATE)
        registry.subscribe(update_router,
                           resources.ROUTER,
                           events.AFTER_UPDATE)
        registry.subscribe(remove_router,
                           resources.ROUTER,
                           events.AFTER_DELETE)
        self._get_sync_data()

    def _is_pd_master_router(self, router):
        return router['master']

    @runtime.synchronized("l3-agent-pd")
    def enable_subnet(self, router_id, subnet_id, prefix, ri_ifname, mac):
        router = self.routers.get(router_id)
        if router is None:
            return

        pd_info = router['subnets'].get(subnet_id)
        if not pd_info:
            pd_info = PDInfo(ri_ifname=ri_ifname, mac=mac)
            router['subnets'][subnet_id] = pd_info

        pd_info.bind_lla = self._get_lla(mac)
        if pd_info.sync:
            pd_info.mac = mac
            pd_info.old_prefix = prefix
        elif self._is_pd_master_router(router):
            self._add_lla(router, pd_info.get_bind_lla_with_mask())

    def _delete_pd(self, router, pd_info):
        if not self._is_pd_master_router(router):
            return
        self._delete_lla(router, pd_info.get_bind_lla_with_mask())
        if pd_info.client_started:
            pd_info.driver.disable(self.pmon, router['ns_name'])

    @runtime.synchronized("l3-agent-pd")
    def disable_subnet(self, router_id, subnet_id):
        prefix_update = {}
        router = self.routers.get(router_id)
        if not router:
            return
        pd_info = router['subnets'].get(subnet_id)
        if not pd_info:
            return
        self._delete_pd(router, pd_info)
        if self._is_pd_master_router(router):
            prefix_update[subnet_id] = n_const.PROVISIONAL_IPV6_PD_PREFIX
            LOG.debug("Update server with prefixes: %s", prefix_update)
            self.notifier(self.context, prefix_update)
        del router['subnets'][subnet_id]

    @runtime.synchronized("l3-agent-pd")
    def update_subnet(self, router_id, subnet_id, prefix):
        router = self.routers.get(router_id)
        if router is not None:
            pd_info = router['subnets'].get(subnet_id)
            if pd_info and pd_info.old_prefix != prefix:
                old_prefix = pd_info.old_prefix
                pd_info.old_prefix = prefix
                pd_info.prefix = prefix
                return old_prefix

    @runtime.synchronized("l3-agent-pd")
    def add_gw_interface(self, router_id, gw_ifname):
        router = self.routers.get(router_id)
        if not router:
            return
        router['gw_interface'] = gw_ifname
        if not self._is_pd_master_router(router):
            return
        prefix_update = {}
        for pd_info in six.itervalues(router['subnets']):
            # gateway is added after internal router ports.
            # If a PD is being synced, and if the prefix is available,
            # send update if prefix out of sync; If not available,
            # start the PD client
            bind_lla_with_mask = pd_info.get_bind_lla_with_mask()
            if pd_info.sync:
                pd_info.sync = False
                if pd_info.client_started:
                    if pd_info.prefix != pd_info.old_prefix:
                        prefix_update['subnet_id'] = pd_info.prefix
                else:
                    self._delete_lla(router, bind_lla_with_mask)
                    self._add_lla(router, bind_lla_with_mask)
            else:
                self._add_lla(router, bind_lla_with_mask)
        if prefix_update:
            LOG.debug("Update server with prefixes: %s", prefix_update)
            self.notifier(self.context, prefix_update)

    def delete_router_pd(self, router):
        if not self._is_pd_master_router(router):
            return
        prefix_update = {}
        for subnet_id, pd_info in router['subnets'].items():
            self._delete_lla(router, pd_info.get_bind_lla_with_mask())
            if pd_info.client_started:
                pd_info.driver.disable(self.pmon, router['ns_name'])
                pd_info.prefix = None
                pd_info.client_started = False
                prefix = n_const.PROVISIONAL_IPV6_PD_PREFIX
                prefix_update[subnet_id] = prefix
        if prefix_update:
            LOG.debug("Update server with prefixes: %s", prefix_update)
            self.notifier(self.context, prefix_update)

    @runtime.synchronized("l3-agent-pd")
    def remove_gw_interface(self, router_id):
        router = self.routers.get(router_id)
        if router is not None:
            router['gw_interface'] = None
            self.delete_router_pd(router)

    @runtime.synchronized("l3-agent-pd")
    def get_preserve_ips(self, router_id):
        preserve_ips = []
        router = self.routers.get(router_id)
        if router is not None:
            for pd_info in six.itervalues(router['subnets']):
                preserve_ips.append(pd_info.get_bind_lla_with_mask())
        return preserve_ips

    @runtime.synchronized("l3-agent-pd")
    def sync_router(self, router_id):
        router = self.routers.get(router_id)
        if router is not None and router['gw_interface'] is None:
            self.delete_router_pd(router)

    @runtime.synchronized("l3-agent-pd")
    def remove_stale_ri_ifname(self, router_id, stale_ifname):
        router = self.routers.get(router_id)
        if router is not None:
            subnet_to_delete = None
            for subnet_id, pd_info in six.iteritems(router['subnets']):
                if pd_info.ri_ifname == stale_ifname:
                    self._delete_pd(router, pd_info)
                    subnet_to_delete = subnet_id
                    break
            if subnet_to_delete:
                del router['subnets'][subnet_to_delete]

    @staticmethod
    def _get_lla(mac):
        lla = netutils.get_ipv6_addr_by_EUI64(n_const.IPv6_LLA_PREFIX,
                                              mac)
        return lla

    def _get_llas(self, gw_ifname, ns_name):
        try:
            return self.intf_driver.get_ipv6_llas(gw_ifname, ns_name)
        except RuntimeError:
            # The error message was printed as part of the driver call
            # This could happen if the gw_ifname was removed
            # simply return and exit the thread
            return

    def _add_lla(self, router, lla_with_mask):
        if router['gw_interface']:
            self.intf_driver.add_ipv6_addr(router['gw_interface'],
                                           lla_with_mask,
                                           router['ns_name'],
                                           'link')
            # There is a delay before the LLA becomes active.
            # This is because the kernel runs DAD to make sure LLA uniqueness
            # Spawn a thread to wait for the interface to be ready
            self._spawn_lla_thread(router['gw_interface'],
                                   router['ns_name'],
                                   lla_with_mask)

    def _spawn_lla_thread(self, gw_ifname, ns_name, lla_with_mask):
        eventlet.spawn_n(self._ensure_lla_task,
                         gw_ifname,
                         ns_name,
                         lla_with_mask)

    def _delete_lla(self, router, lla_with_mask):
        if lla_with_mask and router['gw_interface']:
            try:
                self.intf_driver.delete_ipv6_addr(router['gw_interface'],
                                                  lla_with_mask,
                                                  router['ns_name'])
            except RuntimeError:
                # Ignore error if the lla doesn't exist
                pass

    def _ensure_lla_task(self, gw_ifname, ns_name, lla_with_mask):
        # It would be insane for taking so long unless DAD test failed
        # In that case, the subnet would never be assigned a prefix.
        utils.wait_until_true(functools.partial(self._lla_available,
                                                gw_ifname,
                                                ns_name,
                                                lla_with_mask),
                              timeout=l3_constants.LLA_TASK_TIMEOUT,
                              sleep=2)

    def _lla_available(self, gw_ifname, ns_name, lla_with_mask):
        llas = self._get_llas(gw_ifname, ns_name)
        if self._is_lla_active(lla_with_mask, llas):
            LOG.debug("LLA %s is active now", lla_with_mask)
            self.pd_update_cb()
            return True

    @staticmethod
    def _is_lla_active(lla_with_mask, llas):
        for lla in llas:
            if lla_with_mask == lla['cidr']:
                return not lla['tentative']
        return False

    @runtime.synchronized("l3-agent-pd")
    def process_ha_state(self, router_id, master):
        router = self.routers.get(router_id)
        if router is None or router['master'] == master:
            return

        router['master'] = master
        if master:
            for pd_info in six.itervalues(router['subnets']):
                bind_lla_with_mask = pd_info.get_bind_lla_with_mask()
                self._add_lla(router, bind_lla_with_mask)
        else:
            for pd_info in six.itervalues(router['subnets']):
                self._delete_lla(router, pd_info.get_bind_lla_with_mask())
                if pd_info.client_started:
                    pd_info.driver.disable(self.pmon,
                                           router['ns_name'],
                                           switch_over=True)
                    pd_info.client_started = False

    @runtime.synchronized("l3-agent-pd")
    def process_prefix_update(self):
        LOG.debug("Processing IPv6 PD Prefix Update")

        prefix_update = {}
        for router_id, router in self.routers.items():
            if not (self._is_pd_master_router(router) and
                    router['gw_interface']):
                continue

            llas = None
            for subnet_id, pd_info in router['subnets'].items():
                if pd_info.client_started:
                    prefix = pd_info.driver.get_prefix()
                    if prefix != pd_info.prefix:
                        pd_info.prefix = prefix
                        prefix_update[subnet_id] = prefix
                else:
                    if not llas:
                        llas = self._get_llas(router['gw_interface'],
                                              router['ns_name'])

                    if self._is_lla_active(pd_info.get_bind_lla_with_mask(),
                                           llas):
                        if not pd_info.driver:
                            pd_info.driver = self.pd_dhcp_driver(
                                router_id, subnet_id, pd_info.ri_ifname)
                        prefix = None
                        if (pd_info.prefix !=
                                n_const.PROVISIONAL_IPV6_PD_PREFIX):
                            prefix = pd_info.prefix

                        pd_info.driver.enable(self.pmon, router['ns_name'],
                                              router['gw_interface'],
                                              pd_info.bind_lla,
                                              prefix)
                        pd_info.client_started = True

        if prefix_update:
            LOG.debug("Update server with prefixes: %s", prefix_update)
            self.notifier(self.context, prefix_update)

    def after_start(self):
        LOG.debug('SIGUSR1 signal handler set')
        signal.signal(signal.SIGUSR1, self._handle_sigusr1)

    def _handle_sigusr1(self, signum, frame):
        """Update PD on receiving SIGUSR1.

        The external DHCPv6 client uses SIGUSR1 to notify agent
        of prefix changes.
        """
        self.pd_update_cb()

    def _get_sync_data(self):
        sync_data = self.pd_dhcp_driver.get_sync_data()
        for pd_info in sync_data:
            router_id = pd_info.router_id
            if not self.routers.get(router_id):
                self.routers[router_id] = {'master': True,
                                           'gw_interface': None,
                                           'ns_name': None,
                                           'subnets': {}}
            new_pd_info = PDInfo(pd_info=pd_info)
            subnets = self.routers[router_id]['subnets']
            subnets[pd_info.subnet_id] = new_pd_info


@runtime.synchronized("l3-agent-pd")
def remove_router(resource, event, l3_agent, **kwargs):
    router_id = kwargs['router'].router_id
    router = l3_agent.pd.routers.get(router_id)
    l3_agent.pd.delete_router_pd(router)
    del l3_agent.pd.routers[router_id]['subnets']
    del l3_agent.pd.routers[router_id]


def get_router_entry(ns_name, master):
    return {'master': master,
            'gw_interface': None,
            'ns_name': ns_name,
            'subnets': {}}


@runtime.synchronized("l3-agent-pd")
def add_router(resource, event, l3_agent, **kwargs):
    added_router = kwargs['router']
    router = l3_agent.pd.routers.get(added_router.router_id)
    gw_ns_name = added_router.get_gw_ns_name()
    master = added_router.is_router_master()
    if not router:
        l3_agent.pd.routers[added_router.router_id] = (
            get_router_entry(gw_ns_name, master))
    else:
        # This will happen during l3 agent restart
        router['ns_name'] = gw_ns_name
        router['master'] = master


@runtime.synchronized("l3-agent-pd")
def update_router(resource, event, l3_agent, **kwargs):
    updated_router = kwargs['router']
    router = l3_agent.pd.routers.get(updated_router.router_id)
    if not router:
        LOG.exception("Router to be updated is not in internal routers "
                      "list: %s", updated_router.router_id)
    else:
        router['ns_name'] = updated_router.get_gw_ns_name()


class PDInfo(object):
    """A class to simplify storing and passing of information relevant to
    Prefix Delegation operations for a given subnet.
    """
    def __init__(self, pd_info=None, ri_ifname=None, mac=None):
        if pd_info is None:
            self.prefix = n_const.PROVISIONAL_IPV6_PD_PREFIX
            self.old_prefix = n_const.PROVISIONAL_IPV6_PD_PREFIX
            self.ri_ifname = ri_ifname
            self.mac = mac
            self.bind_lla = None
            self.sync = False
            self.driver = None
            self.client_started = False
        else:
            self.prefix = pd_info.prefix
            self.old_prefix = None
            self.ri_ifname = pd_info.ri_ifname
            self.mac = None
            self.bind_lla = None
            self.sync = True
            self.driver = pd_info.driver
            self.client_started = pd_info.client_started

    def get_bind_lla_with_mask(self):
        bind_lla_with_mask = '%s/64' % self.bind_lla
        return bind_lla_with_mask
