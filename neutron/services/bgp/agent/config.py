# Copyright 2016 Huawei Technologies India Pvt. Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from oslo_config import cfg

from neutron._i18n import _

BGP_DRIVER_OPTS = [
    cfg.StrOpt('bgp_speaker_driver',
               help=_("BGP speaker driver class to be instantiated."))
]

BGP_PROTO_CONFIG_OPTS = [
    cfg.StrOpt('bgp_router_id',
               help=_("32-bit BGP identifier, typically an IPv4 address "
                      "owned by the system running the BGP DrAgent."))
]
