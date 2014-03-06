# Copyright 2014 OneConvergence, Inc. All Rights Reserved.
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
#

"""NVSD Exception Definitions."""

from neutron.common import exceptions as n_exc


class NVSDAPIException(n_exc.NeutronException):
    '''Base NVSDplugin Exception.'''
    message = _("An unknown nvsd plugin exception occurred: %(reason)s")


class RequestTimeout(NVSDAPIException):
    message = _("The request has timed out.")


class UnAuthorizedException(NVSDAPIException):
    message = _("Invalid access credentials to the Server.")


class NotFoundException(NVSDAPIException):
    message = _("A resource is not found: %(reason)s")


class BadRequestException(NVSDAPIException):
    message = _("Request sent to server is invalid: %(reason)s")


class ServerException(NVSDAPIException):
    message = _("Internal Server Error: %(reason)s")


class ConnectionClosedException(NVSDAPIException):
    message = _("Connection is closed by the server.")


class ForbiddenException(NVSDAPIException):
    message = _("The request is forbidden access to the resource: %(reason)s")


class InternalServerError(NVSDAPIException):
    message = _("Internal Server Error from NVSD controller: %(reason)s")
