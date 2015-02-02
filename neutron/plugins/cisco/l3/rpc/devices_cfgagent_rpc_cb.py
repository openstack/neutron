# Copyright 2014 Cisco Systems, Inc.  All rights reserved.
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


class DeviceCfgRpcCallbackMixin(object):
    """Mixin for Cisco cfg agent device reporting rpc support."""

    def report_non_responding_hosting_devices(self, context, host,
                                              hosting_device_ids):
        """Report that a hosting device cannot be contacted.

        @param: context - contains user information
        @param: host - originator of callback
        @param: hosting_device_ids - list of non-responding hosting devices
        @return: -
        """
        self._l3plugin.handle_non_responding_hosting_devices(
            context, host, hosting_device_ids)

    def register_for_duty(self, context, host):
        """Report that Cisco cfg agent is ready for duty.

        This function is supposed to be called when the agent has started,
        is ready to take on assignments and before any callbacks to fetch
        logical resources are issued.

        @param: context - contains user information
        @param: host - originator of callback
        @return: True if successfully registered, False if not successfully
                 registered, None if no handler found
                 If unsuccessful the agent should retry registration a few
                 seconds later
        """
        # schedule any non-handled hosting devices
        return self._l3plugin.auto_schedule_hosting_devices(context, host)
