# Copyright 2014 VMware, Inc.
#
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
from neutron.common import constants as const
from neutron.db import l3_db

# A unique MAC to quickly identify the LSN port used for metadata services
# when dhcp on the subnet is off. Inspired by leet-speak for 'metadata'.
METADATA_MAC = "fa:15:73:74:d4:74"
METADATA_PORT_ID = 'metadata:id'
METADATA_PORT_NAME = 'metadata:name'
METADATA_DEVICE_ID = 'metadata:device'
SPECIAL_OWNERS = (const.DEVICE_OWNER_DHCP,
                  const.DEVICE_OWNER_ROUTER_GW,
                  l3_db.DEVICE_OWNER_ROUTER_INTF)
