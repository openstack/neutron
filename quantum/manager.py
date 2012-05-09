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

import logging
import os

from quantum.common import utils
from quantum.common.config import find_config_file
from quantum.common.exceptions import ClassNotFound
from quantum.openstack.common import importutils


LOG = logging.getLogger(__name__)


CONFIG_FILE = "plugins.ini"


def find_config(basepath):
    for root, dirs, files in os.walk(basepath):
        if CONFIG_FILE in files:
            return os.path.join(root, CONFIG_FILE)
    return None


def get_plugin(plugin_provider):
    # If the plugin can't be found let them know gracefully
    try:
        LOG.info("Loading Plugin: %s" % plugin_provider)
        plugin_klass = importutils.import_class(plugin_provider)
    except ClassNotFound:
        LOG.exception("Error loading plugin")
        raise Exception("Plugin not found.  You can install a "
                        "plugin with: pip install <plugin-name>\n"
                        "Example: pip install quantum-sample-plugin")
    return plugin_klass()


def get_plugin_provider(options, config_file=None):
    if config_file:
        config_file = [config_file]

    if not 'plugin_provider' in options:
        cf = find_config_file(options, config_file, CONFIG_FILE)
        options['plugin_provider'] = utils.get_plugin_from_config(cf)
    return options['plugin_provider']


class QuantumManager(object):

    _instance = None

    def __init__(self, options=None, config_file=None):
        # If no options have been provided, create an empty dict
        if not options:
            options = {}

        # NOTE(jkoelker) Testing for the subclass with the __subclasshook__
        #                breaks tach monitoring. It has been removed
        #                intentianally to allow v2 plugins to be monitored
        #                for performance metrics.
        plugin_provider = get_plugin_provider(options, config_file)
        LOG.debug("Plugin location:%s", plugin_provider)
        self.plugin = get_plugin(plugin_provider)

    @classmethod
    def get_plugin(cls, options=None, config_file=None):
        if cls._instance is None:
            cls._instance = cls(options, config_file)
        return cls._instance.plugin
