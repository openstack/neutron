# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013 Radware LTD.
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
# @author: Avishay Balderman, Radware

import abc

import six


@six.add_metaclass(abc.ABCMeta)
class LoadBalancerAbstractDriver(object):
    """Abstract lbaas driver that expose ~same API as lbaas plugin.

    The configuration elements (Vip,Member,etc) are the dicts that
    are returned to the tenant.
    Get operations are not part of the API - it will be handled
    by the lbaas plugin.
    """

    @abc.abstractmethod
    def create_vip(self, context, vip):
        """A real driver would invoke a call to his backend
        and set the Vip status to ACTIVE/ERROR according
        to the backend call result
        self.plugin.update_status(context, Vip, vip["id"],
                                  constants.ACTIVE)
        """
        pass

    @abc.abstractmethod
    def update_vip(self, context, old_vip, vip):
        """Driver may call the code below in order to update the status.
        self.plugin.update_status(context, Vip, id, constants.ACTIVE)
        """
        pass

    @abc.abstractmethod
    def delete_vip(self, context, vip):
        """A real driver would invoke a call to his backend
        and try to delete the Vip.
        if the deletion was successful, delete the record from the database.
        if the deletion has failed, set the Vip status to ERROR.
        """
        pass

    @abc.abstractmethod
    def create_pool(self, context, pool):
        """Driver may call the code below in order to update the status.
        self.plugin.update_status(context, Pool, pool["id"],
                                  constants.ACTIVE)
        """
        pass

    @abc.abstractmethod
    def update_pool(self, context, old_pool, pool):
        """Driver may call the code below in order to update the status.
        self.plugin.update_status(context,
                                  Pool,
                                  pool["id"], constants.ACTIVE)
        """
        pass

    @abc.abstractmethod
    def delete_pool(self, context, pool):
        """Driver can call the code below in order to delete the pool.
        self.plugin._delete_db_pool(context, pool["id"])
        or set the status to ERROR if deletion failed
        """
        pass

    @abc.abstractmethod
    def stats(self, context, pool_id):
        pass

    @abc.abstractmethod
    def create_member(self, context, member):
        """Driver may call the code below in order to update the status.
        self.plugin.update_status(context, Member, member["id"],
                                   constants.ACTIVE)
        """
        pass

    @abc.abstractmethod
    def update_member(self, context, old_member, member):
        """Driver may call the code below in order to update the status.
        self.plugin.update_status(context, Member,
                                  member["id"], constants.ACTIVE)
        """
        pass

    @abc.abstractmethod
    def delete_member(self, context, member):
        pass

    @abc.abstractmethod
    def update_pool_health_monitor(self, context,
                                   old_health_monitor,
                                   health_monitor,
                                   pool_id):
        pass

    @abc.abstractmethod
    def create_pool_health_monitor(self, context,
                                   health_monitor,
                                   pool_id):
        """Driver may call the code below in order to update the status.
        self.plugin.update_pool_health_monitor(context,
                                               health_monitor["id"],
                                               pool_id,
                                               constants.ACTIVE)
        """
        pass

    @abc.abstractmethod
    def delete_pool_health_monitor(self, context, health_monitor, pool_id):
        pass
