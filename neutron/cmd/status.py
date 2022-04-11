# Copyright 2018 Red Hat Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from neutron_lib.utils import runtime
from oslo_config import cfg
from oslo_db import options as db_options
from oslo_log import log as logging
from oslo_upgradecheck import upgradecheck

from neutron.common import config as common_config
from neutron.conf import common as neutron_conf_base
from neutron.conf import service as neutron_conf_service

CHECKS_ENTRYPOINTS = 'neutron.status.upgrade.checks'
LOG = logging.getLogger(__name__)


def load_checks():
    checks = []
    ns_plugin = runtime.NamespacedPlugins(CHECKS_ENTRYPOINTS)
    # TODO(slaweq): stop using private attribute of runtime.NamespacedPlugins
    # class when it will provide some better way to access extensions
    for module_name, module in ns_plugin._extensions.items():
        try:
            project_checks_class = module.entry_point.load()
            project_checks = project_checks_class().get_checks()
            if project_checks:
                checks += project_checks
        except Exception as e:
            LOG.exception("Checks class %(entrypoint)s failed to load. "
                          "Error: %(err)s",
                          {'entrypoint': module_name, 'err': e})
            continue
    return tuple(checks)


def setup_conf(conf=cfg.CONF):
    """Setup the cfg for the status check utility.

    Use separate setup_conf for the utility because there are many options
    from the main config that do not apply during checks.
    """
    common_config.register_common_config_options()
    neutron_conf_base.register_core_common_config_opts(conf)
    neutron_conf_service.register_service_opts(
        neutron_conf_service.SERVICE_OPTS, cfg.CONF)
    db_options.set_defaults(conf)
    return conf


class Checker(upgradecheck.UpgradeCommands):

    """Various upgrade checks should be added as separate methods in this class
    and added to _upgrade_checks tuple.

    Check methods here must not rely on the neutron object model since they
    should be able to run against both N and N-1 releases. Any queries to
    the database should be done through the sqlalchemy query language directly
    like the database schema migrations.
    """

    # The format of the check functions is to return an
    # oslo_upgradecheck.upgradecheck.Result
    # object with the appropriate
    # oslo_upgradecheck.upgradecheck.Code and details set.
    # If the check hits warnings or failures then those should be stored
    # in the returned Result's "details" attribute. The
    # summary will be rolled up at the end of the check() method.
    _upgrade_checks = load_checks()


def main():
    conf = setup_conf()
    return upgradecheck.main(
        conf, project='neutron', upgrade_command=Checker())
