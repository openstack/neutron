# Copyright 2014 Deutsche Telekom AG
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

import copy

from oslo_log import log as logging

import neutron.tests.tempest.common.generator.base_generator as base
import neutron.tests.tempest.common.generator.valid_generator as valid

LOG = logging.getLogger(__name__)


class NegativeTestGenerator(base.BasicGeneratorSet):
    @base.generator_type("string")
    @base.simple_generator
    def gen_int(self, _):
        return 4

    @base.generator_type("integer")
    @base.simple_generator
    def gen_string(self, _):
        return "XXXXXX"

    @base.generator_type("integer", "string")
    def gen_none(self, schema):
        # Note(mkoderer): it's not using the decorator otherwise it'd be
        # filtered
        expected_result = base._check_for_expected_result('gen_none', schema)
        return ('gen_none', None, expected_result)

    @base.generator_type("string")
    @base.simple_generator
    def gen_str_min_length(self, schema):
        min_length = schema.get("minLength", 0)
        if min_length > 0:
            return "x" * (min_length - 1)

    @base.generator_type("string", needed_property="maxLength")
    @base.simple_generator
    def gen_str_max_length(self, schema):
        max_length = schema.get("maxLength", -1)
        return "x" * (max_length + 1)

    @base.generator_type("integer", needed_property="minimum")
    @base.simple_generator
    def gen_int_min(self, schema):
        minimum = schema["minimum"]
        if "exclusiveMinimum" not in schema:
            minimum -= 1
        return minimum

    @base.generator_type("integer", needed_property="maximum")
    @base.simple_generator
    def gen_int_max(self, schema):
        maximum = schema["maximum"]
        if "exclusiveMaximum" not in schema:
            maximum += 1
        return maximum

    @base.generator_type("object", needed_property="additionalProperties")
    @base.simple_generator
    def gen_obj_add_attr(self, schema):
        valid_schema = valid.ValidTestGenerator().generate_valid(schema)
        new_valid = copy.deepcopy(valid_schema)
        new_valid["$$$$$$$$$$"] = "xxx"
        return new_valid
