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


class LoggingApiBase(metaclass=abc.ABCMeta):
    """Logging API methods"""

    @abc.abstractmethod
    def create_log(self, context, log_obj):
        """Create a log_obj invocation.

        This method can be implemented by the specific driver subclass
        to update the backend where necessary with a specific log object.

        :param context: current running context information
        :param log_obj: a log objects being created

        """

    @abc.abstractmethod
    def create_log_precommit(self, context, log_obj):
        """Create a log_obj precommit.

        This method can be implemented by the specific driver subclass
        to handle the precommit event of a log_object that is being created.

        :param context: current running context information
        :param log_obj: a log object being created
        """

    @abc.abstractmethod
    def update_log(self, context, log_obj):
        """Update a log_obj invocation.

        This method can be implemented by the specific driver subclass
        to update the backend where necessary with a specific log object.

        :param context: current running context information
        :param log_obj: a log object being updated

        """

    @abc.abstractmethod
    def update_log_precommit(self, context, log_obj):
        """Update a log_obj precommit.

        This method can be implemented by the specific driver subclass
        to handle update precommit event of a log_object that is being updated.

        :param context: current running context information
        :param log_obj: a log_object being updated.
        """

    @abc.abstractmethod
    def delete_log(self, context, log_obj):
        """Delete a log_obj invocation.

        This method can be implemented by the specific driver subclass
        to delete the backend where necessary with a specific log object.

        :param context: current running context information
        :param log_obj: a log_object being deleted

        """

    @abc.abstractmethod
    def delete_log_precommit(self, context, log_obj):
        """Delete a log_obj precommit.

        This method can be implemented by the specific driver subclass
        to handle delete precommit event of a log_object that is being deleted.

        :param context: current running context information
        :param log_obj: a log_object being deleted
        """
