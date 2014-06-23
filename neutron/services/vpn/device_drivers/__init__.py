# Copyright 2013, Nachi Ueno, NTT I3, Inc.
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

import six


@six.add_metaclass(abc.ABCMeta)
class DeviceDriver(object):

    def __init__(self, agent, host):
        pass

    @abc.abstractmethod
    def sync(self, context, processes):
        pass

    @abc.abstractmethod
    def create_router(self, process_id):
        pass

    @abc.abstractmethod
    def destroy_router(self, process_id):
        pass
