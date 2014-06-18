# Copyright 2014 A10 Networks
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

from neutron.db.loadbalancer import loadbalancer_db as lb_db
from neutron.services.loadbalancer.drivers import driver_mixins


class NotImplementedManager(object):
    """Helper class to make any subclass of LBAbstractDriver explode if it
    is missing any of the required object managers.
    """

    def create(self, context, obj):
        raise NotImplementedError()

    def update(self, context, old_obj, obj):
        raise NotImplementedError()

    def delete(self, context, obj):
        raise NotImplementedError()


class LoadBalancerBaseDriver(object):
    """LBaaSv2 object model drivers should subclass LBAbstractDriver, and
    initialize the following manager classes to create, update, and delete
    the various load balancer objects.
    """

    load_balancer = NotImplementedManager()
    listener = NotImplementedManager()
    pool = NotImplementedManager()
    member = NotImplementedManager()
    health_monitor = NotImplementedManager()

    def __init__(self, plugin):
        self.plugin = plugin


class BaseLoadBalancerManager(driver_mixins.BaseRefreshMixin,
                              driver_mixins.BaseStatsMixin,
                              driver_mixins.BaseStatusUpdateMixin,
                              driver_mixins.BaseManagerMixin):

    def __init__(self, driver):
        super(BaseLoadBalancerManager, self).__init__(driver)
        # TODO(dougw), use lb_db.LoadBalancer when v2 lbaas
        # TODO(dougw), get rid of __init__() in StatusHelperManager, and
        # the if is not None clauses; after fixing this next line,
        # it can become a mandatory variable for that subclass.
        self.model_class = None


class BaseListenerManager(driver_mixins.BaseManagerMixin):
    pass


class BasePoolManager(driver_mixins.BaseStatusUpdateMixin,
                      driver_mixins.BaseManagerMixin):

    def __init__(self, driver):
        super(BasePoolManager, self).__init__(driver)
        self.model_class = lb_db.Pool


class BaseMemberManager(driver_mixins.BaseStatusUpdateMixin,
                        driver_mixins.BaseManagerMixin):

    def __init__(self, driver):
        super(BaseMemberManager, self).__init__(driver)
        self.model_class = lb_db.Member


class BaseHealthMonitorManager(
                              driver_mixins.BaseHealthMonitorStatusUpdateMixin,
                              driver_mixins.BaseManagerMixin):
    pass
