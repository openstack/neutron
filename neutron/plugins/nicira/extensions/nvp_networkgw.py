# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 VMware, Inc.
# All Rights Reserved
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
# TODO(armando-migliaccio): This is deprecated in Icehouse, and
# to be removed in Juno.

from neutron.plugins.nicira.extensions import networkgw


class Nvp_networkgw(networkgw.Networkgw):
    """(Deprecated) API extension for Layer-2 Gateway support."""

    @classmethod
    def get_name(cls):
        return "Neutron-NVP Network Gateway"

    @classmethod
    def get_alias(cls):
        return "network-gateway"

    @classmethod
    def get_description(cls):
        return ("Connects Neutron networks with external "
                "networks at layer 2 (deprecated).")

    @classmethod
    def get_namespace(cls):
        return "http://docs.openstack.org/ext/neutron/network-gateway/api/v1.0"
