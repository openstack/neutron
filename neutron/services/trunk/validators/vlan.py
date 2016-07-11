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

from oslo_log import log as logging

from neutron.callbacks import events
from neutron.callbacks import registry
from neutron.plugins.common import constants as common_consts
from neutron.services.trunk import constants as trunk_consts

LOG = logging.getLogger(__name__)


def register():
    registry.subscribe(handler, trunk_consts.TRUNK_PLUGIN,
                       events.AFTER_INIT)
    LOG.debug('Registering for trunk support')


def handler(resource, event, trigger, **kwargs):
    trigger.add_segmentation_type(trunk_consts.VLAN, vlan_range)
    LOG.debug('Registration complete')


def vlan_range(segmentation_id):
    min_vid, max_vid = common_consts.MIN_VLAN_TAG, common_consts.MAX_VLAN_TAG
    return min_vid <= segmentation_id <= max_vid
