# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2014 Blue Box Group, Inc.
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
# @author: Dustin Lundquist, Blue Box Group

from neutron.services.loadbalancer.drivers import driver_base
from neutron.services.loadbalancer.drivers.shim import converter
from neutron.services.loadblanacer.drivers.shim import plugin


class LBShimDriver(driver_base.LoadBalancerBaseDriver):
    """Wrap a v1 LBaaS driver to present the v2 interface"""

    def __init__(self, plugin_v2, driver):
        self.converter = converter.LBObjectModelConverter()
        self._plugin_v2 = plugin_v2
        self.driver = driver
        self.plugin = plugin.Plugin(self._plugin_v2, self.converter)

        self.load_balancer = LBShimLoadBalancerManager(self)
        self.listener = LBShimListenerManager(self)
        self.pool = LBShimPoolManager(self)
        self.member = LBShimMemberManager(self)
        self.health_monitor = LBShimHealthMonitorManager(self)


class LBShimLoadBalancerManager(driver_base.BaseLoadBalancerManager):

    def __init__(self, shim):
        self._shim = shim

    def create(self, context, load_balancer):
        vip = self._shim.converter.lb_to_vip(load_balancer)

        self.shim.driver.create_vip(context, vip)

    def update(self, context, old_load_balancer, load_balancer):
        old_vip = self._shim.converter.lb_to_vip(old_load_balancer)
        vip = self._shim.converter.lb_to_vip(load_balancer)

        self.shim.driver.update_vip(context, old_vip, vip)

    def delete(self, context, load_balancer):
        vip = self._shim.converter.lb_to_vip(load_balancer)

        self._shim.driver.delete_vip(context, vip)

    def stats(self, context, load_balancer):
        listener = (load_balancer.listeners or [{}])[0]

        self._shim.driver.stats(context, pool.default_pool_id)


class LBShimListenerManager(driver_base.BaseListenerManager):

    def __init__(self, shim):
        self._shim = shim

    def create(self, context, listener):
        vip = self._shim.converter.listener_to_vip(listener)

        self.shim.driver.create_vip(context, vip)

    def update(self, context, old_listener, listener):
        vip = self._shim.converter.listener_to_vip(listener)
        old_vip = self._shim.converter.listener_to_vip(old_listener)

        self._shim.driver.update_vip(context, old_vip, vip)

    def delete(self, context, listener):
        vip = self._shim.converter.listener_to_vip(listener)

        self._shim.driver.delete_vip(context, vip)


class LBShimPoolManager(driver_base.BasePoolManager):

    def __init__(self, shim):
        self._shim = shim

    def create(self, context, pool):
        pool = self._shim.converter.pool(pool)

        self._shim.driver.create_pool(context, pool)

    def update(self, context, old_pool, pool):
        old_pool = self._shim.converter.pool(old_pool)
        pool = self._shim.converter.pool(pool)

        self._shim.driver.update_pool(context, old_pool, pool)

    def delete(self, context, pool):
        pool = self._shim.converter.pool(pool)

        self._shim.driver.delete_pool(context, pool)


class LBShimMemberManager(driver_base.BaseMemberManager):

    def __init__(self, shim):
        self._shim = shim

    def create(self, context, member):
        member = self._shim.converter.member(member)

        self._shim.driver.create_member(context, member)

    def update(self, context, old_member, member):
        member = self._shim.converter.member(member)
        old_member = self._shim.converter.member(old_member)

        self._shim.driver.update_member(context, old_member, member)

    def delete(self, context, member):
        member = self._shim.converter.member(member)

        self._shim.driver.delete_member(context, member)


class LBShimHealthMonitorManager(driver_base.BaseHealthMonitorManager):

    def __init__(self, shim):
        self._shim = shim

    # TODO(convert health monitors)
