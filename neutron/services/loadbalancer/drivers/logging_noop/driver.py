# Copyright 2014, Doug Wiegley (dougwig), A10 Networks
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

from neutron.openstack.common import log as logging
from neutron.services.loadbalancer.drivers import driver_base

LOG = logging.getLogger(__name__)


class LoggingNoopLoadBalancerDriver(driver_base.LoadBalancerBaseDriver):

    def __init__(self, plugin):
        self.plugin = plugin

        # Each of the major LBaaS objects in the neutron database
        # need a corresponding manager/handler class.
        #
        # Put common things that are shared across the entire driver, like
        # config or a rest client handle, here.
        #
        # This function is executed when neutron-server starts.

        self.load_balancer = LoggingNoopLoadBalancerManager(self)
        self.listener = LoggingNoopListenerManager(self)
        self.pool = LoggingNoopPoolManager(self)
        self.member = LoggingNoopMemberManager(self)
        self.health_monitor = LoggingNoopHealthMonitorManager(self)


class LoggingNoopCommonManager(object):

    def create(self, context, obj):
        LOG.debug("LB %s no-op, create %s", self.__class__.__name__, obj.id)
        self.active(context, obj.id)

    def update(self, context, old_obj, obj):
        LOG.debug("LB %s no-op, update %s", self.__class__.__name__, obj.id)
        self.active(context, obj.id)

    def delete(self, context, obj):
        LOG.debug("LB %s no-op, delete %s", self.__class__.__name__, obj.id)


class LoggingNoopLoadBalancerManager(LoggingNoopCommonManager,
                                     driver_base.BaseLoadBalancerManager):

    def refresh(self, context, lb_obj, force=False):
        # This is intended to trigger the backend to check and repair
        # the state of this load balancer and all of its dependent objects
        LOG.debug("LB pool refresh %s, force=%s", lb_obj.id, force)

    def stats(self, context, lb_obj):
        LOG.debug("LB stats %s", lb_obj.id)
        return {
            "bytes_in": 0,
            "bytes_out": 0,
            "active_connections": 0,
            "total_connections": 0
        }


class LoggingNoopListenerManager(LoggingNoopCommonManager,
                                 driver_base.BaseListenerManager):

    def create(self, context, obj):
        LOG.debug("LB listener no-op, create %s", self.__class__.__name__,
                  obj.id)

    def update(self, context, old_obj, obj):
        LOG.debug("LB listener no-op, update %s", self.__class__.__name__,
                  obj.id)


class LoggingNoopPoolManager(LoggingNoopCommonManager,
                             driver_base.BasePoolManager):
    pass


class LoggingNoopMemberManager(LoggingNoopCommonManager,
                               driver_base.BaseMemberManager):
    pass


class LoggingNoopHealthMonitorManager(LoggingNoopCommonManager,
                                      driver_base.BaseHealthMonitorManager):

    def create(self, context, obj):
        LOG.debug("LB health monitor no-op, create %s",
                  self.__class__.__name__, obj.id)
        self.active(context, obj.id, obj.id)

    def update(self, context, old_obj, obj):
        LOG.debug("LB health monitor no-op, update %s",
                  self.__class__.__name__, obj.id)
        self.active(context, obj.id, obj.id)
