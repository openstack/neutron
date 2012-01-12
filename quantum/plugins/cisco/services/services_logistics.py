# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2011 Cisco Systems, Inc.  All rights reserved.
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
#
#    @author: Edgar Magana, Cisco Systems
"""
Logistic components for Service Insertion utility
"""

import logging
import subprocess
import re
import time

from quantum.common import utils
from quantum.plugins.cisco import l2network_plugin_configuration as conf
from quantum.plugins.cisco.db import services_db as sdb
from quantum.plugins.cisco.common import cisco_constants as const
from quantum.plugins.cisco.services import services_constants as servconts

LOG = logging.getLogger(__name__)


class ServicesLogistics():
    """
    Services Logistics Modules
    """
    def __init__(self):
        pass

    def image_shutdown_verification(self, image_name):
        """
        Verifies that the VM has been properly shutdown
        """
        try:
            service_args = []
            service_args.append(servconts.DESCRIBE_VM_CMD)
            service_args.append(image_name)
            counter = 0
            flag = False
            while not flag and counter <= 5:
                counter = counter + 1
                time.sleep(2.5)
                process = subprocess.Popen(service_args, \
                                           stdout=subprocess.PIPE)
                result = process.stdout.readlines()
                if not result:
                    flag = True
        except Exception, exc:
            print exc

    def image_status(self, image_name):
        """
        Checks the status of the image
        """
        try:
            service_args = []
            service_args.append(servconts.DESCRIBE_VM_CMD)
            service_args.append(image_name)
            counter = 0
            flag = False
            while not flag and counter <= 10:
                counter = counter + 1
                time.sleep(2.5)
                process = subprocess.Popen(service_args, \
                                    stdout=subprocess.PIPE)
                result = process.stdout.readlines()
                if result:
                    tokens = re.search("running", str(result[1]))
                    if tokens:
                        service_status = tokens.group(0)
                        if service_status == "running":
                            flag = True
        except Exception as exc:
            print exc

    def image_exist(self, image_name):
        """
        Verifies that the image id is available
        """
        try:
            service_vm = sdb.get_service_bindings(image_name)
            if service_vm:
                return True
            else:
                return False
        except Exception as exc:
            print exc

    def verify_plugin(self, plugin_key):
        """
        Verifies the PlugIn available
        """
        _plugins = {}
        for key in conf.PLUGINS[const.PLUGINS].keys():
            _plugins[key] = \
                utils.import_object(conf.PLUGINS[const.PLUGINS][key])
        if not plugin_key in _plugins.keys():
            LOG.debug("No %s Plugin loaded" % plugin_key)
            return False
        else:
            LOG.debug("Plugin %s founded" % const.UCS_PLUGIN)
            return True

    def press_key(self):
        """
        Waits for en external input
        """
        key = raw_input("Press any key to continue")
        return key
