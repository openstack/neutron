# Copyright 2015 Red Hat, Inc.
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

import configparser
import os.path

import fixtures

from neutron.tests import base


class ConfigDict(base.AttributeDict):
    def update(self, other):
        self.convert_to_attr_dict(other)
        super().update(other)

    def convert_to_attr_dict(self, other):
        """Convert nested dicts to AttributeDict.

        :param other: dictionary to be directly modified.
        """
        for key, value in other.items():
            if isinstance(value, dict):
                if not isinstance(value, base.AttributeDict):
                    other[key] = base.AttributeDict(value)
                self.convert_to_attr_dict(value)


class ConfigFileFixture(fixtures.Fixture):
    """A fixture that knows how to translate configurations to files.

    :param base_filename: the filename to use on disk.
    :param config: a ConfigDict instance.
    :param temp_dir: an existing temporary directory to use for storage.
    """

    def __init__(self, base_filename, config, temp_dir):
        super().__init__()
        self.base_filename = base_filename
        self.config = config
        self.temp_dir = temp_dir

    def _setUp(self):
        self.write_config_to_configfile()

    def write_config_to_configfile(self):
        config_parser = self.dict_to_config_parser(self.config)
        # Need to randomly generate a unique folder to put the file in
        self.filename = os.path.join(self.temp_dir, self.base_filename)
        with open(self.filename, 'w') as f:
            config_parser.write(f)
            f.flush()

    def dict_to_config_parser(self, config_dict):
        config_parser = configparser.ConfigParser()
        for section, section_dict in config_dict.items():
            if section != 'DEFAULT':
                config_parser.add_section(section)
            for option, value in section_dict.items():
                try:
                    config_parser.set(section, option, value)
                except TypeError as te:
                    raise TypeError(
                        "%(msg)s: section %(section)s, option %(option)s, "
                        "value: %(value)s" % {
                            'msg': te.args[0],
                            'section': section,
                            'option': option,
                            'value': value,
                        })
        return config_parser
