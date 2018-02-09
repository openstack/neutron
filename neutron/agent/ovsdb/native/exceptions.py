# Copyright 2018 Red Hat, Inc.
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

from neutron_lib import exceptions as e

from neutron._i18n import _


class OvsdbSslConfigNotFound(e.NeutronException):
    message = _("Specified SSL file %(ssl_file)s could not be found")


class OvsdbSslRequiredOptError(e.NeutronException):
    message = _("Required 'ovs' group option %(ssl_opt)s not set.  SSL "
                "configuration options are required when using SSL "
                "ovsdb_connection URI")
