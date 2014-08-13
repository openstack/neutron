# Copyright 2013 VMware, Inc.  All rights reserved.
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

# TODO(armando-migliaccio): This is deprecated in Juno, and
# to be removed in Kilo.

from neutron.extensions import dvr


class Distributedrouter(dvr.Dvr):
    """(Deprecated) Extension class supporting distributed router."""

    @classmethod
    def get_name(cls):
        return "Distributed Router"

    @classmethod
    def get_alias(cls):
        return "dist-router"

    @classmethod
    def get_description(cls):
        return ("Enables configuration of NSX "
                "Distributed routers (Deprecated).")

    @classmethod
    def get_namespace(cls):
        return "http://docs.openstack.org/ext/dist-router/api/v1.0"
