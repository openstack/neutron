# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 VMware, Inc.
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

from neutron.openstack.common import log

LOG = log.getLogger(__name__)
MAX_DISPLAY_NAME_LEN = 40


def check_and_truncate(display_name):
    if display_name and len(display_name) > MAX_DISPLAY_NAME_LEN:
        LOG.debug(_("Specified name:'%s' exceeds maximum length. "
                    "It will be truncated on NVP"), display_name)
        return display_name[:MAX_DISPLAY_NAME_LEN]
    return display_name or ''
