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
#

from neutron.plugins.ml2.drivers.cisco.nexus import config
from neutron.plugins.ml2.drivers.cisco.nexus import constants as const
from neutron.plugins.ml2.drivers.cisco.nexus import exceptions as cexc
from neutron.plugins.ml2.drivers.cisco.nexus import network_db_v2 as cdb


TENANT = const.NETWORK_ADMIN


class Store(object):
    """ML2 Cisco Mechanism Driver Credential Store."""

    @staticmethod
    def initialize():
        _nexus_dict = config.ML2MechCiscoConfig.nexus_dict
        for ipaddr, keyword in _nexus_dict.keys():
            if keyword == const.USERNAME:
                try:
                    cdb.add_credential(TENANT, ipaddr,
                                       _nexus_dict[ipaddr, const.USERNAME],
                                       _nexus_dict[ipaddr, const.PASSWORD])
                except cexc.CredentialAlreadyExists:
                    # We are quietly ignoring this, since it only happens
                    # if this class module is loaded more than once, in which
                    # case, the credentials are already populated
                    pass

    @staticmethod
    def put_credential(cred_name, username, password):
        """Set the username and password."""
        cdb.add_credential(TENANT, cred_name, username, password)

    @staticmethod
    def get_username(cred_name):
        """Get the username."""
        credential = cdb.get_credential_name(TENANT, cred_name)
        return credential[const.CREDENTIAL_USERNAME]

    @staticmethod
    def get_password(cred_name):
        """Get the password."""
        credential = cdb.get_credential_name(TENANT, cred_name)
        return credential[const.CREDENTIAL_PASSWORD]

    @staticmethod
    def get_credential(cred_name):
        """Get the username and password."""
        credential = cdb.get_credential_name(TENANT, cred_name)
        return {const.USERNAME: credential[const.CREDENTIAL_USERNAME],
                const.PASSWORD: credential[const.CREDENTIAL_PASSWORD]}

    @staticmethod
    def delete_credential(cred_name):
        """Delete a credential."""
        cdb.remove_credential(TENANT, cred_name)
