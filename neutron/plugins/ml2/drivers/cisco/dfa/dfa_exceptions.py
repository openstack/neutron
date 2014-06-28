# Copyright 2014 Cisco Systems, Inc.
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
#

"""Exceptions used by DFA ML2 mechanism drivers."""

from neutron.common import exceptions


class NetworkNotFound(exceptions.NotFound):
    """Network cannot be found."""

    message = _("Network %(network_id)s could not be found.")


class ConfigProfileNotFound(exceptions.NotFound):
    """Config Profile cannot be found."""

    message = _("Config profile for network %(network_id)s"
                " could not be found.")


class ConfigProfileFwdModeNotFound(exceptions.NotFound):
    """Config Profile forwarding mode cannot be found."""

    message = _("Forwarding Mode for network %(network_id)s"
                " could not be found.")


class ConfigProfileIdNotFound(exceptions.NotFound):
    """Config Profile ID cannot be found."""

    message = _("Config Profile %(profile_id)s could not be found.")


class ConfigProfileNameNotFound(exceptions.NotFound):
    """Config Profile name cannot be found."""

    message = _("Config Profile %(name)s could not be found.")


class ProjectIdNotFound(exceptions.NotFound):
    """Project ID cannot be found."""

    message = _("Project ID %(project_id)s could not be found.")


class DFAClientRequestFailed(exceptions.ServiceUnavailable):
    """Request to DCNM failed."""

    message = _("Request to DCNM failed: %(reason)s.")
