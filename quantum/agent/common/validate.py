# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright 2013 Cisco Systems, Inc.
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
# @author: Paul Michali, Cisco Systems, Inc.


def core_config_options(options):
    '''Validate core configuration options.

    Make sure that core configuration options that are needed are present and,
    if not, generate warnings/errors, based on the severity. Will be used
    only by the agents that require the option(s).
    '''

    if options.core_plugin is None:
        raise Exception(_('Quantum core_plugin not configured!'))
