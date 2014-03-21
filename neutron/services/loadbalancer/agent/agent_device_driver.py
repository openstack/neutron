# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013 OpenStack Foundation.  All rights reserved
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

import abc

import six


@six.add_metaclass(abc.ABCMeta)
class AgentDeviceDriver(object):
    """Abstract device driver that defines the API required by LBaaS agent."""

    @abc.abstractmethod
    def get_name(cls):
        """Returns unique name across all LBaaS device drivers."""
        pass

    @abc.abstractmethod
    def deploy_instance(self, logical_config):
        """Fully deploys a loadbalancer instance from a given config."""
        pass

    @abc.abstractmethod
    def undeploy_instance(self, pool_id):
        """Fully undeploys the loadbalancer instance."""
        pass

    @abc.abstractmethod
    def get_stats(self, pool_id):
        pass

    def remove_orphans(self, known_pool_ids):
        # Not all drivers will support this
        raise NotImplementedError()

    @abc.abstractmethod
    def create_vip(self, vip):
        pass

    @abc.abstractmethod
    def update_vip(self, old_vip, vip):
        pass

    @abc.abstractmethod
    def delete_vip(self, vip):
        pass

    @abc.abstractmethod
    def create_pool(self, pool):
        pass

    @abc.abstractmethod
    def update_pool(self, old_pool, pool):
        pass

    @abc.abstractmethod
    def delete_pool(self, pool):
        pass

    @abc.abstractmethod
    def create_member(self, member):
        pass

    @abc.abstractmethod
    def update_member(self, old_member, member):
        pass

    @abc.abstractmethod
    def delete_member(self, member):
        pass

    @abc.abstractmethod
    def create_pool_health_monitor(self, health_monitor, pool_id):
        pass

    @abc.abstractmethod
    def update_pool_health_monitor(self,
                                   old_health_monitor,
                                   health_monitor,
                                   pool_id):
        pass

    @abc.abstractmethod
    def delete_pool_health_monitor(self, health_monitor, pool_id):
        pass
