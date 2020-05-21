# Copyright (c) 2015 Red Hat Inc.
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

import abc


NETWORK = 'network'
PORT = 'port'
EVENT_CREATE = 'create'
EVENT_UPDATE = 'update'


CORE_RESOURCES = [NETWORK, PORT]


class CoreResourceExtension(object, metaclass=abc.ABCMeta):

    @abc.abstractmethod
    def process_fields(self, context, resource_type, event_type,
                       requested_resource, actual_resource):
        """Process extension fields.

        :param context: neutron api request context
        :param resource_type: core resource type (one of CORE_RESOURCES)
        :param event_type: kind of event triggering this action (update,
               create)
        :param requested_resource: resource dict that contains extension fields
        :param actual_resource: actual resource dict known to plugin
        """

    @abc.abstractmethod
    def extract_fields(self, resource_type, resource):
        """Extract extension fields.

        :param resource_type: core resource type (one of CORE_RESOURCES)
        :param resource: resource dict that contains extension fields
        """
