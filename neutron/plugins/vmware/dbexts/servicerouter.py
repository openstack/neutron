# Copyright 2013 VMware, Inc.  All rights reserved.
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

from neutron.db import l3_dvr_db
from neutron.plugins.vmware.extensions import servicerouter


class ServiceRouter_mixin(l3_dvr_db.L3_NAT_with_dvr_db_mixin):
    """Mixin class to enable service router support."""

    extra_attributes = (
        l3_dvr_db.L3_NAT_with_dvr_db_mixin.extra_attributes + [{
            'name': servicerouter.SERVICE_ROUTER,
            'default': False
        }])
