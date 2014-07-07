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
from neutron.services.loadbalancer.drivers.shim import plugin


class LBShimDriver(driver_base.LoadBalancerBaseDriver):
    """Wrap a v1 LBaaS driver to present the v2 interface"""

    def __init__(self, plugin_v2, driver_cls):
        self.converter = converter.LBObjectModelConverter(self)
        self.plugin = plugin_v2
        self.wrapped_plugin = plugin.Plugin(self.plugin, self.converter)
        self.wrapped_driver = driver_cls(self.wrapped_plugin)

        self.load_balancer = LBShimLoadBalancerManager(self)
        self.listener = LBShimListenerManager(self)
        self.pool = LBShimPoolManager(self)
        self.member = LBShimMemberManager(self)
        self.health_monitor = LBShimHealthMonitorManager(self)


class LBShimLoadBalancerManager(driver_base.BaseLoadBalancerManager):

    def create(self, context, load_balancer):
        vip = self.driver.converter.lb_to_vip(load_balancer)

        self.driver.wrapped_driver.create_vip(context, vip)

    def update(self, context, old_load_balancer, load_balancer):
        old_vip = self.driver.converter.lb_to_vip(old_load_balancer)
        vip = self.driver.converter.lb_to_vip(load_balancer)

        self.shim.driver.update_vip(context, old_vip, vip)

    def delete(self, context, load_balancer):
        vip = self.driver.converter.lb_to_vip(load_balancer)

        self.driver.wrapped_driver.delete_vip(context, vip)

    def stats(self, context, load_balancer):
        listener = (load_balancer.listeners or [{}])[0]

        self.driver.wrapped_driver.stats(context, listener.default_pool_id)

    def refresh(self, context, load_balancer):
        pass


class LBShimListenerManager(driver_base.BaseListenerManager):

    def create(self, context, listener):
        vip = self.driver.converter.listener_to_vip(listener)

        self.driver.wrapped_driver.create_vip(context, vip)

    def update(self, context, old_listener, listener):
        vip = self.driver.converter.listener_to_vip(listener)
        old_vip = self.driver.converter.listener_to_vip(old_listener)

        self.driver.wrapped_driver.update_vip(context, old_vip, vip)

    def delete(self, context, listener):
        vip = self.driver.converter.listener_to_vip(listener)

        self.driver.wrapped_driver.delete_vip(context, vip)


class LBShimPoolManager(driver_base.BasePoolManager):

    def create(self, context, pool):
        pool = self.driver.converter.pool(pool)

        self.driver.wrapped_driver.create_pool(context, pool)

    def update(self, context, old_pool, pool):
        old_pool = self.driver.converter.pool(old_pool)
        pool = self.driver.converter.pool(pool)

        self.driver.wrapped_driver.update_pool(context, old_pool, pool)

    def delete(self, context, pool):
        pool = self.driver.converter.pool(pool)

        self.driver.wrapped_driver.delete_pool(context, pool)


class LBShimMemberManager(driver_base.BaseMemberManager):

    def create(self, context, member):
        member = self.driver.converter.member(member)

        self.driver.wrapped_driver.create_member(context, member)

    def update(self, context, old_member, member):
        member = self.driver.converter.member(member)
        old_member = self.driver.converter.member(old_member)

        self.driver.wrapped_driver.update_member(context, old_member, member)

    def delete(self, context, member):
        member = self.driver.converter.member(member)

        self.driver.wrapped_driver.delete_member(context, member)


class LBShimHealthMonitorManager(driver_base.BaseHealthMonitorManager):

    def create(self, context, member):
        pass

    def update(self, context, old_member, member):
        pass

    def delete(self, context, member):
        pass
