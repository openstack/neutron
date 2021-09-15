# Copyright (c) 2018 Orange.
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

import itertools

from neutron_lib.db import standard_attr


def stdattrs_extended_resources(attributes):
    r_map = standard_attr.get_standard_attr_resource_model_map(
        include_resources=True,
        include_sub_resources=False)
    sr_map = standard_attr.get_standard_attr_resource_model_map(
        include_resources=False,
        include_sub_resources=True)
    return dict(itertools.chain(
        {r: attributes for r in r_map}.items(),
        {sr: {'parameters': attributes} for sr in sr_map}.items()
    ))
