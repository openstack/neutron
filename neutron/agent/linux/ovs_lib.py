# Copyright 2015 Cloudbase Solutions.
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

# This is a placeholder so that the vendor code that import the ovs_lib
# module from agent/linux doesn't fail
# TODO(atuvenie) remove this module after opening the liberty cycle

from neutron.agent.common import ovs_lib

INVALID_OFPORT = ovs_lib.INVALID_OFPORT
BaseOVS = ovs_lib.BaseOVS
OVSBridge = ovs_lib.OVSBridge
DeferredOVSBridge = ovs_lib.DeferredOVSBridge
VifPort = ovs_lib.VifPort
_build_flow_expr_str = ovs_lib._build_flow_expr_str
