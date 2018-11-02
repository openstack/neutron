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

from oslo_upgradecheck import upgradecheck

from neutron._i18n import _
from neutron.cmd.upgrade_checks import base


class CoreChecks(base.BaseChecks):

    def get_checks(self):
        return (
            (_("Check nothing"), self.noop_check)
        )

    @staticmethod
    def noop_check(checker):
        # NOTE(slaweq) This is only example Noop check, it can be removed when
        # some real check methods will be added
        return upgradecheck.Result(
            upgradecheck.Code.SUCCESS, _("Always succeed (placeholder)"))
