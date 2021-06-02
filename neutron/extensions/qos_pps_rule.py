# Copyright (c) 2021 China Unicom Cloud Data Co.,Ltd.
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

from neutron_lib.api.definitions import qos_bw_minimum_ingress
from neutron_lib.api.definitions import qos_pps_rule as apidef
from neutron_lib.api import extensions as api_extensions
from neutron_lib.plugins import constants
from neutron_lib.plugins import directory

from neutron.api import extensions
from neutron.api.v2 import base

COLLECTION_NAME = 'packet_rate_limit_rules'
RESOURCE_NAME = 'packet_rate_limit_rule'

# A quick align for subresource minimum bandwidth ingress direction.
# TODO(liuyulong): Move to neutron-lib
apidef.SUB_RESOURCE_ATTRIBUTE_MAP.update(
    qos_bw_minimum_ingress.SUB_RESOURCE_ATTRIBUTE_MAP)


class Qos_pps_rule(api_extensions.APIExtensionDescriptor):

    api_definition = apidef

    @classmethod
    def get_resources(cls):
        plugin = directory.get_plugin(constants.QOS)
        params = apidef.SUB_RESOURCE_ATTRIBUTE_MAP[
            COLLECTION_NAME]['parameters']
        parent = apidef.SUB_RESOURCE_ATTRIBUTE_MAP[
            COLLECTION_NAME]['parent']
        controller = base.create_resource(
            COLLECTION_NAME,
            RESOURCE_NAME,
            plugin,
            params,
            parent=parent,
            allow_pagination=True,
            allow_sorting=True)
        exts = [
            extensions.ResourceExtension(
                COLLECTION_NAME,
                controller,
                parent,
                attr_map=params)
        ]
        return exts
