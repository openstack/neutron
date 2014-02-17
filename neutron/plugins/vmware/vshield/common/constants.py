# Copyright 2013 OpenStack Foundation.
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

EDGE_ID = 'edge_id'
ROUTER_ID = 'router_id'

# Interface
EXTERNAL_VNIC_INDEX = 0
INTERNAL_VNIC_INDEX = 1
EXTERNAL_VNIC_NAME = "external"
INTERNAL_VNIC_NAME = "internal"

INTEGRATION_LR_IPADDRESS = "169.254.2.1/28"
INTEGRATION_EDGE_IPADDRESS = "169.254.2.3"
INTEGRATION_SUBNET_NETMASK = "255.255.255.240"

# SNAT rule location
PREPEND = 0
APPEND = -1

# error code
VCNS_ERROR_CODE_EDGE_NOT_RUNNING = 10013

SUFFIX_LENGTH = 8


# router status by number
class RouterStatus(object):
    ROUTER_STATUS_ACTIVE = 0
    ROUTER_STATUS_DOWN = 1
    ROUTER_STATUS_PENDING_CREATE = 2
    ROUTER_STATUS_PENDING_DELETE = 3
    ROUTER_STATUS_ERROR = 4
