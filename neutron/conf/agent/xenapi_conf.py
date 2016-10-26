# Copyright 2016 Citrix Systems.
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

from oslo_config import cfg

from neutron._i18n import _

XENAPI_CONF_SECTION = 'xenapi'

XENAPI_OPTS = [
    cfg.StrOpt('connection_url',
               help=_("URL for connection to XenServer/Xen Cloud Platform.")),
    cfg.StrOpt('connection_username',
               help=_("Username for connection to XenServer/Xen Cloud "
                      "Platform.")),
    cfg.StrOpt('connection_password',
               help=_("Password for connection to XenServer/Xen Cloud "
                      "Platform."),
               secret=True)
]


def register_xenapi_opts(cfg=cfg.CONF):
    cfg.register_opts(XENAPI_OPTS, group=XENAPI_CONF_SECTION)
