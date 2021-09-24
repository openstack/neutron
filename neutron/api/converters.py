# Copyright (c) 2021 Ericsson Software Technology
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

import uuid

from neutron_lib.placement import utils as pl_utils


# TODO(przszc): Delete when https://review.opendev.org/813650 is released
def convert_to_sanitized_binding_profile_allocation(allocation, port_id,
                                                    min_bw_rules):
    """Return binding-profile.allocation in the new format

    :param allocation: binding-profile.allocation attribute containting a
                       string with RP UUID
    :param port_id: ID of the port that is being sanitized
    :param min_bw_rules: A list of minimum bandwidth rules associated with the
                         port.
    :return: A dict with allocation in {'<group_uuid>': '<rp_uuid>'} format.
    """
    if isinstance(allocation, dict):
        return allocation

    group_id = str(
        pl_utils.resource_request_group_uuid(uuid.UUID(port_id), min_bw_rules))
    return {group_id: allocation}
