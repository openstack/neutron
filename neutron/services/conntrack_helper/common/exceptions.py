# Copyright (c) 2019 Red Hat, Inc.
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

from neutron._i18n import _
from neutron_lib import exceptions as n_exc


class ConntrackHelperNotFound(n_exc.NotFound):
    message = _("Conntrack Helper %(id)s could not be found.")


class ConntrackHelperNotAllowed(n_exc.BadRequest):
    message = _("Conntrack Helper %(helper)s is not allowed.")


class InvalidProtocolForHelper(n_exc.BadRequest):
    message = _("Conntrack Helper %(helper)s does not support: %(protocol)s. "
                "Supported protocols are: %(supported_protocols)s")
