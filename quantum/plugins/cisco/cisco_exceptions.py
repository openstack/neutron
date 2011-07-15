# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2011 Cisco Systems, Inc.  All rights reserved.
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
# @author: Sumit Naiksatam, Cisco Systems, Inc.
#

"""
Exceptions used by the Cisco plugin
"""

from quantum.common import exceptions


class NoMoreNics(exceptions.QuantumException):
    message = _("Unable to complete operation on port %(port_id)s " \
                "for network %(net_id)s. No more dynamic nics are available" \
                "in the system.")


class PortProfileLimit(exceptions.QuantumException):
    message = _("Unable to complete operation on port %(port_id)s " \
                "for network %(net_id)s. The system has reached the maximum" \
                "limit of allowed port profiles.")


class UCSMPortProfileLimit(exceptions.QuantumException):
    message = _("Unable to complete operation on port %(port_id)s " \
                "for network %(net_id)s. The system has reached the maximum" \
                "limit of allowed UCSM port profiles.")


class NetworksLimit(exceptions.QuantumException):
    message = _("Unable to create new network. Number of networks" \
                "for the system has exceeded the limit")


class PortProfileNotFound(exceptions.QuantumException):
    message = _("Port profile %(portprofile_id)s could not be found " \
                "for tenant %(tenant_id)s")


class PortProfileInvalidDelete(exceptions.QuantumException):
    message = _("Port profile %(profile_id)s could not be deleted " \
                "for tenant %(tenant_id)s since port associations exist")
