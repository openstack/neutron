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

from neutron_lib.plugins import utils as plugin_utils

from neutron._i18n import _
from neutron.services.trunk import constants as trunk_consts

# Base map of segmentation types supported with their respective validator
# functions. In multi-driver deployments all drivers must support the same
# set of segmentation types consistently. Drivers can add their own type
# and respective validator, however this is a configuration that may be
# supported only in single-driver deployments.
_supported = {
    trunk_consts.VLAN: plugin_utils.is_valid_vlan_tag,
}


def get_validator(segmentation_type):
    """Get validator for the segmentation type or KeyError if not found."""
    return _supported[segmentation_type]


def add_validator(segmentation_type, validator_function):
    """Introduce new entry to the map of supported segmentation types."""
    if segmentation_type in _supported:
        msg = _("Cannot redefine existing %s "
                "segmentation type") % segmentation_type
        raise KeyError(msg)
    _supported[segmentation_type] = validator_function
