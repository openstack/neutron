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

from oslo_config import cfg
from oslo_upgradecheck import upgradecheck

from neutron._i18n import _
from neutron.cmd.upgrade_checks import base


class CoreChecks(base.BaseChecks):

    def get_checks(self):
        return [
            (_("Worker counts configured"), self.worker_count_check)
        ]

    @staticmethod
    def worker_count_check(checker):

        if cfg.CONF.api_workers and cfg.CONF.rpc_workers:
            return upgradecheck.Result(
                upgradecheck.Code.SUCCESS, _("Number of workers already "
                "defined in config"))
        else:
            return upgradecheck.Result(
                upgradecheck.Code.WARNING, _("The default number of workers "
                "has changed. Please see release notes for the new values, "
                "but it is strongly encouraged for deployers to manually set "
                "the values for api_workers and rpc_workers."))
