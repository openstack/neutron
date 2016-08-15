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

from oslo_config import cfg

from neutron._i18n import _


allowed_address_pair_opts = [
    #TODO(limao): use quota framework when it support quota for attributes
    cfg.IntOpt('max_allowed_address_pair', default=10,
               help=_("Maximum number of allowed address pairs")),
]


def register_allowed_address_pair_opts(cfg=cfg.CONF):
    cfg.register_opts(allowed_address_pair_opts)
