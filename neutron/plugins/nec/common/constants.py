# Copyright 2013 NEC Corporation.  All rights reserved.
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

ROUTER_PROVIDER_L3AGENT = 'l3-agent'
ROUTER_PROVIDER_OPENFLOW = 'openflow'

DEFAULT_ROUTER_PROVIDERS = [ROUTER_PROVIDER_L3AGENT, ROUTER_PROVIDER_OPENFLOW]
DEFAULT_ROUTER_PROVIDER = ROUTER_PROVIDER_L3AGENT

ROUTER_STATUS_ACTIVE = 'ACTIVE'
ROUTER_STATUS_ERROR = 'ERROR'
