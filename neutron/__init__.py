# Copyright 2011 OpenStack Foundation
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

# NOTE(ralonsoh): remove once the default backend is ``BackendType.THREADING``
from oslo_service import backend as oslo_service_backend
import warnings
try:
    oslo_service_backend.init_backend(
        oslo_service_backend.BackendType.THREADING)
except oslo_service_backend.exceptions.BackendAlreadySelected:
    # NOTE(ralonsoh): this code could be called by other services, like
    # ``oslo-config-generator``, still not migrated.
    warnings.warn('The selected oslo_service backend is "eventlet"')


# pylint: disable=wrong-import-position
import builtins  # noqa: E402
import gettext  # noqa: E402

from neutron._i18n import _ as n_under  # noqa: E402


gettext.install('neutron')


# gettext will install its own translation function, override it to be
# the one from neutron
builtins.__dict__['_'] = n_under
