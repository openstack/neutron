# Copyright 2016 Hewlett Packard Enterprise Development, LP
#
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


from neutron.api.v2 import attributes
from neutron.db import common_db_mixin
from neutron.extensions import segment
from neutron.services.segments import db


def _extend_subnet_dict_binding(plugin, subnet_res, subnet_db):
    subnet_res['segment_id'] = subnet_db.get('segment_id')


class Plugin(db.SegmentDbMixin, segment.SegmentPluginBase):

    _instance = None

    supported_extension_aliases = ["segment"]

    def __init__(self):
        common_db_mixin.CommonDbMixin.register_dict_extend_funcs(
            attributes.SUBNETS, [_extend_subnet_dict_binding])

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance
