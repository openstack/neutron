# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2011 Nicira Networks, Inc
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
# @author: Somik Behera, Nicira Networks, Inc.


"""
Quantum's Manager class is responsible for parsing a config file and
instantiating the correct plugin that concretely implement quantum_plugin_base
class.
The caller should make sure that QuantumManager is a singleton.
"""
import gettext
import logging
import os

gettext.install('quantum', unicode=1)

from quantum.common import utils
from quantum.common.config import find_config_file
from quantum.common.exceptions import ClassNotFound
from quantum_plugin_base import QuantumPluginBase

LOG = logging.getLogger('quantum.manager')
CONFIG_FILE = "plugins.ini"
LOG = logging.getLogger('quantum.manager')


def find_config(basepath):
    for root, dirs, files in os.walk(basepath):
        if CONFIG_FILE in files:
            return os.path.join(root, CONFIG_FILE)
    return None


class QuantumManager(object):

    _instance = None

    def __init__(self, options=None, config_file=None):
        # If no options have been provided, create an empty dict
        if not options:
            options = {}

        if config_file:
            config_file = [config_file]

        self.configuration_file = find_config_file(options, config_file,
                                                   CONFIG_FILE)
        if not 'plugin_provider' in options:
            options['plugin_provider'] = \
                utils.get_plugin_from_config(self.configuration_file)
        LOG.debug("Plugin location:%s", options['plugin_provider'])

        # If the plugin can't be found let them know gracefully
        try:
            plugin_klass = utils.import_class(options['plugin_provider'])
        except ClassNotFound:
            raise Exception("Plugin not found.  You can install a " \
                            "plugin with: pip install <plugin-name>\n" \
                            "Example: pip install quantum-sample-plugin")

        if not issubclass(plugin_klass, QuantumPluginBase):
            raise Exception("Configured Quantum plug-in " \
                            "didn't pass compatibility test")
        else:
            LOG.debug("Successfully imported Quantum plug-in." \
                      "All compatibility tests passed")
        self.plugin = plugin_klass()

    @classmethod
    def get_plugin(cls, options=None, config_file=None):
        if cls._instance is None:
            cls._instance = cls(options, config_file)
        return cls._instance.plugin
