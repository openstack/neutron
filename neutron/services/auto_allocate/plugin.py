# Copyright 2015-2016 Hewlett Packard Enterprise Development Company, LP
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


from neutron.services.auto_allocate import db


class Plugin(db.AutoAllocatedTopologyMixin):

    _instance = None

    supported_extension_aliases = ["auto-allocated-topology"]

    __filter_validation_support = True

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def get_plugin_description(self):
        return "Auto Allocated Topology - aka get me a network."

    @classmethod
    def get_plugin_type(cls):
        return "auto-allocated-topology"
