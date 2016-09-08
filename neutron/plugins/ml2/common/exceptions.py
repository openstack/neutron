# Copyright (c) 2013 OpenStack Foundation
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

"""Exceptions used by ML2."""

from neutron_lib import exceptions

from neutron._i18n import _


class MechanismDriverError(exceptions.MultipleExceptions):
    """Mechanism driver call failed."""

    def __init__(self, method, errors=None):
        # The message is not used by api, because api will unwrap
        # MultipleExceptions and return inner exceptions. Keep it
        # for backward-compatibility, in case other code use it.
        self.message = _("%s failed.") % method
        super(MechanismDriverError, self).__init__(errors or [])


class ExtensionDriverError(exceptions.InvalidInput):
    """Extension driver call failed."""
    message = _("Extension %(driver)s failed.")


class ExtensionDriverNotFound(exceptions.InvalidConfigurationOption):
    """Required extension driver not found in ML2 config."""
    message = _("Extension driver %(driver)s required for "
                "service plugin %(service_plugin)s not found.")


class UnknownNetworkType(exceptions.NeutronException):
    """Network with unknown type."""
    message = _("Unknown network type %(network_type)s.")
