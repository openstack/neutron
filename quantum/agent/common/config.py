# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
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


from quantum.common import config
from quantum.openstack.common import cfg
from quantum.openstack.common import log as logging


LOG = logging.getLogger(__name__)


ROOT_HELPER_OPTS = [
    cfg.StrOpt('root_helper', default='sudo',
               help=_('Root helper application.')),
]


def register_root_helper(conf):
    # The first call is to ensure backward compatibility
    conf.register_opts(ROOT_HELPER_OPTS)
    conf.register_opts(ROOT_HELPER_OPTS, 'AGENT')


def get_root_helper(conf):
    root_helper = conf.AGENT.root_helper
    if root_helper is not 'sudo':
        return root_helper

    root_helper = conf.root_helper
    if root_helper is not 'sudo':
        LOG.deprecated(_('DEFAULT.root_helper is deprecated!'))
        return root_helper

    return 'sudo'


def setup_conf():
    bind_opts = [
        cfg.StrOpt('state_path',
                   default='/var/lib/quantum',
                   help=_('Top-level directory for maintaining dhcp state')),
    ]

    conf = cfg.ConfigOpts()
    conf.register_opts(bind_opts)
    return conf

# add a logging setup method here for convenience
setup_logging = config.setup_logging
