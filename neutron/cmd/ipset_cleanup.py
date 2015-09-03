# Copyright (c) 2015 OpenStack Foundation.
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
from oslo_log import log as logging

from neutron.agent.linux import ipset_manager
from neutron.agent.linux import utils
from neutron.common import config
from neutron.i18n import _LE, _LI


LOG = logging.getLogger(__name__)


def setup_conf():
    """Setup the cfg for the clean up utility.

    Use separate setup_conf for the utility because there are many options
    from the main config that do not apply during clean-up.
    """

    cli_opts = [
        cfg.BoolOpt('allsets',
                    default=False,
                    help=_('Destroy all IPsets.')),
        cfg.BoolOpt('force',
                    default=False,
                    help=_('Destroy IPsets even if there is an iptables '
                           'reference.')),
        cfg.StrOpt('prefix',
                   default=ipset_manager.NET_PREFIX,
                   help=_('String prefix used to match IPset names.')),
    ]

    conf = cfg.CONF
    conf.register_cli_opts(cli_opts)
    return conf


def remove_iptables_reference(ipset):
    # Remove any iptables reference to this IPset
    cmd = ['iptables-save'] if 'IPv4' in ipset else ['ip6tables-save']
    iptables_save = utils.execute(cmd, run_as_root=True)

    if ipset in iptables_save:
        cmd = ['iptables'] if 'IPv4' in ipset else ['ip6tables']
        LOG.info(_LI("Removing iptables rule for IPset: %s"), ipset)
        for rule in iptables_save.splitlines():
            if '--match-set %s ' % ipset in rule and rule.startswith('-A'):
                # change to delete
                params = rule.split()
                params[0] = '-D'
                try:
                    utils.execute(cmd + params, run_as_root=True)
                except Exception:
                    LOG.exception(_LE('Error, unable to remove iptables rule '
                                      'for IPset: %s'), ipset)


def destroy_ipset(conf, ipset):
    # If there is an iptables reference and we don't remove it, the
    # IPset removal will fail below
    if conf.force:
        remove_iptables_reference(ipset)

    LOG.info(_LI("Destroying IPset: %s"), ipset)
    cmd = ['ipset', 'destroy', ipset]
    try:
        utils.execute(cmd, run_as_root=True)
    except Exception:
        LOG.exception(_LE('Error, unable to destroy IPset: %s'), ipset)


def cleanup_ipsets(conf):
    # Identify ipsets for destruction.
    LOG.info(_LI("Destroying IPsets with prefix: %s"), conf.prefix)

    cmd = ['ipset', '-L', '-n']
    ipsets = utils.execute(cmd, run_as_root=True)
    for ipset in ipsets.split('\n'):
        if conf.allsets or ipset.startswith(conf.prefix):
            destroy_ipset(conf, ipset)

    LOG.info(_LI("IPset cleanup completed successfully"))


def main():
    """Main method for cleaning up IPsets.

    The utility is designed to clean-up after the forced or unexpected
    termination of Neutron agents.

    The --allsets flag should only be used as part of the cleanup of a devstack
    installation as it will blindly destroy all IPsets.
    """
    conf = setup_conf()
    conf()
    config.setup_logging()
    cleanup_ipsets(conf)
