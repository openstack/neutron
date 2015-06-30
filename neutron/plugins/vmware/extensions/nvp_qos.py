# Copyright 2013 VMware, Inc.
#
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
# TODO(arosen): This is deprecated in Juno, and
# to be removed in Kxxxx.

from neutron.plugins.vmware.extensions import qos


class Nvp_qos(qos.Qos):
    """(Deprecated) Port Queue extension."""

    @classmethod
    def get_name(cls):
        return "nvp-qos"

    @classmethod
    def get_alias(cls):
        return "nvp-qos"

    @classmethod
    def get_description(cls):
        return "NVP QoS extension (deprecated)."
