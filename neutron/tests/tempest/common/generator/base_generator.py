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
import functools

import jsonschema

from oslo_log import log as logging

LOG = logging.getLogger(__name__)


def _check_for_expected_result(name, schema):
    expected_result = None
    if "results" in schema:
        if name in schema["results"]:
            expected_result = schema["results"][name]
    return expected_result


def generator_type(*args, **kwargs):
    def wrapper(func):
        func.types = args
        for key in kwargs:
            setattr(func, key, kwargs[key])
        return func
    return wrapper


def simple_generator(fn):
    """
    Decorator for simple generators that return one value
    """
    @functools.wraps(fn)
    def wrapped(self, schema):
        result = fn(self, schema)
        if result is not None:
            expected_result = _check_for_expected_result(fn.__name__, schema)
            return (fn.__name__, result, expected_result)
        return
    return wrapped


class BasicGeneratorSet(object):
    _instance = None

    schema = {
        "type": "object",
        "properties": {
            "name": {"type": "string"},
            "http-method": {
                "enum": ["GET", "PUT", "HEAD",
                         "POST", "PATCH", "DELETE", 'COPY']
            },
            "admin_client": {"type": "boolean"},
            "url": {"type": "string"},
            "default_result_code": {"type": "integer"},
            "json-schema": {},
            "resources": {
                "type": "array",
                "items": {
                    "oneOf": [
                        {"type": "string"},
                        {
                            "type": "object",
                            "properties": {
                                "name": {"type": "string"},
                                "expected_result": {"type": "integer"}
                            }
                        }
                    ]
                }
            },
            "results": {
                "type": "object",
                "properties": {}
            }
        },
        "required": ["name", "http-method", "url"],
        "additionalProperties": False,
    }

    def __init__(self):
        self.types_dict = {}
        for m in dir(self):
            if callable(getattr(self, m)) and not'__' in m:
                method = getattr(self, m)
                if hasattr(method, "types"):
                    for type in method.types:
                        if type not in self.types_dict:
                            self.types_dict[type] = []
                        self.types_dict[type].append(method)

    def validate_schema(self, schema):
        if "json-schema" in schema:
            jsonschema.Draft4Validator.check_schema(schema['json-schema'])
        jsonschema.validate(schema, self.schema)

    def generate_scenarios(self, schema, path=None):
        """
        Generates the scenario (all possible test cases) out of the given
        schema.

        :param schema: a dict style schema (see ``BasicGeneratorSet.schema``)
        :param path: the schema path if the given schema is a subschema
        """
        schema_type = schema['type']
        scenarios = []

        if schema_type == 'object':
            properties = schema["properties"]
            for attribute, definition in properties.iteritems():
                current_path = copy.copy(path)
                if path is not None:
                    current_path.append(attribute)
                else:
                    current_path = [attribute]
                scenarios.extend(
                    self.generate_scenarios(definition, current_path))
        elif isinstance(schema_type, list):
            if "integer" in schema_type:
                schema_type = "integer"
            else:
                raise Exception("non-integer list types not supported")
        for generator in self.types_dict[schema_type]:
            if hasattr(generator, "needed_property"):
                prop = generator.needed_property
                if (prop not in schema or
                    schema[prop] is None or
                    schema[prop] is False):
                    continue

            name = generator.__name__
            if ("exclude_tests" in schema and
               name in schema["exclude_tests"]):
                continue
            if path is not None:
                name = "%s_%s" % ("_".join(path), name)
            scenarios.append({
                "_negtest_name": name,
                "_negtest_generator": generator,
                "_negtest_schema": schema,
                "_negtest_path": path})
        return scenarios

    def generate_payload(self, test, schema):
        """
        Generates one jsonschema out of the given test. It's mandatory to use
        generate_scenarios before to register all needed variables to the test.

        :param test: A test object (scenario) with all _negtest variables on it
        :param schema: schema for the test
        """
        generator = test._negtest_generator
        ret = generator(test._negtest_schema)
        path = copy.copy(test._negtest_path)
        expected_result = None

        if ret is not None:
            generator_result = generator(test._negtest_schema)
            invalid_snippet = generator_result[1]
            expected_result = generator_result[2]
            element = path.pop()
            if len(path) > 0:
                schema_snip = reduce(dict.get, path, schema)
                schema_snip[element] = invalid_snippet
            else:
                schema[element] = invalid_snippet
        return expected_result
