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

from neutron.agent.common import ovs_lib


class OVSCookieBridge(object):
    '''Passthrough bridge adding cookies before calling the underlying bridge

    This class creates a bridge that will pass all calls to its underlying
    bridge, except (add/mod/del/dump)_flow calls for which a cookie (reserved
    at init from the underlying bridge) will be added before calling the
    underlying bridge.
    '''

    def __init__(self, bridge):
        """:param bridge: underlying bridge
        :type bridge: OVSBridge
        """
        self.bridge = bridge
        self._cookie = self.bridge.request_cookie()

    @property
    def default_cookie(self):
        return self._cookie

    def do_action_flows(self, action, kwargs_list):
        # NOTE(tmorin): the OVSBridge code is excluding the 'del'
        # action from this step where a cookie
        # is added, but I think we need to keep it so that
        # an extension does not delete flows of another
        # extension
        for kw in kwargs_list:
            kw.setdefault('cookie', self._cookie)

            if action is 'mod' or action is 'del':
                kw['cookie'] = ovs_lib.check_cookie_mask(str(kw['cookie']))

        self.bridge.do_action_flows(action, kwargs_list)

    def add_flow(self, **kwargs):
        self.do_action_flows('add', [kwargs])

    def mod_flow(self, **kwargs):
        self.do_action_flows('mod', [kwargs])

    def delete_flows(self, **kwargs):
        self.do_action_flows('del', [kwargs])

    def __getattr__(self, name):
        # for all other methods this class is a passthrough
        return getattr(self.bridge, name)

    def deferred(self, **kwargs):
        # NOTE(tmorin): we can't passthrough for deferred() or else the
        # resulting DeferredOVSBridge apply_flows method would call
        # the (non-cookie-filtered) do_action_flow of the underlying bridge
        return ovs_lib.DeferredOVSBridge(self, **kwargs)


class OVSAgentExtensionAPI(object):
    '''Implements the Agent API for Open vSwitch agent.

    Extensions can gain access to this API by overriding the consume_api
    method which has been added to the AgentExtension class.
    '''

    def __init__(self, int_br, tun_br):
        super(OVSAgentExtensionAPI, self).__init__()
        self.br_int = int_br
        self.br_tun = tun_br

    def request_int_br(self):
        """Allows extensions to request an integration bridge to use for
        extension specific flows.
        """
        return OVSCookieBridge(self.br_int)

    def request_tun_br(self):
        """Allows extensions to request a tunnel bridge to use for
        extension specific flows.

        If tunneling is not enabled, this method will return None.
        """
        if not self.br_tun:
            return None

        return OVSCookieBridge(self.br_tun)
