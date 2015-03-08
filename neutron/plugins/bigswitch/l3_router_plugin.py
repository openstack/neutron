# Copyright 2014 Big Switch Networks, Inc.
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
#

"""
Neutron L3 REST Proxy Plugin for Big Switch and Floodlight Controllers.

This plugin handles the L3 router calls for Big Switch Floodlight deployments.
It is intended to be used in conjunction with the Big Switch ML2 driver or the
Big Switch core plugin.
"""

from bsnstacklib.plugins.bigswitch import l3_router_plugin


L3RestProxy = l3_router_plugin.L3RestProxy
