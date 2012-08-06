# Copyright 2009-2012 Nicira Networks, Inc.
# All Rights Reserved
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
# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Author: David Lapsley <dlapsley@nicira.com>, Nicira Networks, Inc.

from abc import ABCMeta
from abc import abstractmethod
from abc import abstractproperty


class NvpApiClient(object):
    '''An abstract baseclass for all NvpApiClient implementations.

    This defines the interface and property structure for synchronous and
    coroutine-based classes.
    '''

    __metaclass__ = ABCMeta

    CONN_IDLE_TIMEOUT = 60 * 15

    @abstractmethod
    def update_providers(self, api_providers):
        pass

    @abstractproperty
    def user(self):
        pass

    @abstractproperty
    def password(self):
        pass

    @abstractproperty
    def auth_cookie(self):
        pass

    @abstractmethod
    def acquire_connection(self):
        pass

    @abstractmethod
    def release_connection(self, http_conn, bad_state=False):
        pass

    @abstractproperty
    def need_login(self):
        pass

    @abstractmethod
    def wait_for_login(self):
        pass

    @abstractmethod
    def login(self):
        pass
