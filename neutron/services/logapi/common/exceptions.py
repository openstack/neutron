# Copyright 2017 Fujitsu Limited.
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


class LogResourceNotFound(n_exc.NotFound):
    message = _("Log resource %(log_id)s could not be found.")


class InvalidLogResourceType(n_exc.InvalidInput):
    message = _("Invalid log resource_type: %(resource_type)s.")


class LoggingTypeNotSupported(n_exc.Conflict):
    message = _("Logging type %(log_type)s is not supported on "
                "port %(port_id)s.")


class TargetResourceNotFound(n_exc.NotFound):
    message = _("Target resource %(target_id)s could not be found.")


class ResourceNotFound(n_exc.NotFound):
    message = _("Resource %(resource_id)s could not be found.")


class InvalidResourceConstraint(n_exc.InvalidInput):
    message = _("Invalid resource constraint between resource "
                "(%(resource)s %(resource_id)s) and target resource "
                "(%(target_resource)s %(target_id)s).")


class LogapiDriverException(n_exc.NeutronException):
    """A log api driver Exception"""
    message = _("Driver exception: %(exception_msg)s")


class CookieNotFound(n_exc.NotFound):
    message = _("Cookie %(cookie_id)s could not be found.")


class ValidatedMethodNotFound(n_exc.NeutronException):
    """A validated method not found Exception"""
    message = _('Validated method for %(resource_type)s log '
                'could not be found.')


class ResourceIdNotSpecified(n_exc.InvalidInput):
    message = _('resource_id should be specified for %(resource_type)s.')


class RouterNotEnabledSnat(n_exc.NeutronException):
    message = _('SNAT is not enabled for router %(resource_id)s.')


class EventsDisabled(n_exc.InvalidInput):
    message = _('List of events %(events)s were disabled for '
                '%(resource_type)s.')


class RouterGatewayNotSet(n_exc.NeutronException):
    message = _('Router gateway is not set for router %(resource_id)s.')
