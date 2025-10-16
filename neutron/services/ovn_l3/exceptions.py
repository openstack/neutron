# Copyright 2020 Canonical Ltd.
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

from neutron._i18n import _
from neutron_lib import exceptions as n_exc


class MechanismDriverNotFound(n_exc.NotFound):
    message = _("None of the supported mechanism drivers found: "
                "%(mechanism_drivers)s. Check your configuration.")


class MechanismDriverOVNNotReady(n_exc.ServiceUnavailable):
    message = _('Mechanism driver OVN connection not ready. This service '
                'plugin must be initialized after the mechanism driver.')
