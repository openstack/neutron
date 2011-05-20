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
Quantum's Manager class is responsible for parsing a config file and instantiating the correct
plugin that concretely implement quantum_plugin_base class

The caller should make sure that QuantumManager is a singleton.
"""

from common import utils
from quantum_plugin_base import QuantumPluginBase

CONFIG_FILE = "plugins.ini"

class QuantumManager(object):
    
   def __init__(self,config=CONFIG_FILE):
        self.configuration_file = CONFIG_FILE
        plugin_location = utils.getPluginFromConfig(CONFIG_FILE)
        plugin_klass = utils.import_class(plugin_location)
        if not issubclass(plugin_klass, QuantumPluginBase):
            raise Exception("Configured Quantum plug-in didn't pass compatibility test")
        else:
            print("Successfully imported Quantum plug-in. All compatibility tests passed\n") 
        self.plugin = plugin_klass()
        
   def get_manager(self):
       return self.plugin

# TODO(somik): rmove the main class
# Added for temporary testing purposes
def main():
    manager = QuantumManager()
    myManager = manager.get_manager()
    myManager.get_all_networks("tesst")
    #print("is a plugin")

# Standard boilerplate to call the main() function.
if __name__ == '__main__':
    main()

