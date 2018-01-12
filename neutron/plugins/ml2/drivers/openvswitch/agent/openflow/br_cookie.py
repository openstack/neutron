# Copyright 2016 Intel Corporation.
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

import copy

from neutron.agent.common import ovs_lib


class OVSBridgeCookieMixin(object):
    '''Mixin to provide cookie retention functionality
    to the OVSAgentBridge
    '''

    def __init__(self, *args, **kwargs):
        super(OVSBridgeCookieMixin, self).__init__(*args, **kwargs)
        self._reserved_cookies = set()

    @property
    def reserved_cookies(self):
        if self._default_cookie not in self._reserved_cookies:
            self._reserved_cookies.add(self._default_cookie)
        return set(self._reserved_cookies)

    def request_cookie(self):
        if self._default_cookie not in self._reserved_cookies:
            self._reserved_cookies.add(self._default_cookie)

        uuid_stamp = ovs_lib.generate_random_cookie()
        while uuid_stamp in self._reserved_cookies:
            uuid_stamp = ovs_lib.generate_random_cookie()

        self._reserved_cookies.add(uuid_stamp)
        return uuid_stamp

    def unset_cookie(self, cookie):
        self._reserved_cookies.discard(cookie)

    def set_agent_uuid_stamp(self, val):
        self._reserved_cookies.add(val)
        if self._default_cookie in self._reserved_cookies:
            self._reserved_cookies.remove(self._default_cookie)
        super(OVSBridgeCookieMixin, self).set_agent_uuid_stamp(val)

    def clone(self):
        '''Used by OVSCookieBridge, can be overridden by subclasses if a
        behavior different from copy.copy is needed.
        '''
        return copy.copy(self)
