"""
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

import logging as LOG
import os

from quantum.plugins.cisco.common import cisco_constants as const
from quantum.plugins.cisco.common import cisco_configparser as confp

LOG.basicConfig(level=LOG.WARN)
LOG.getLogger(const.LOGGER_COMPONENT_NAME)

CREDENTIALS_FILE = "../conf/credentials.ini"

cp = confp.CiscoConfigParser(os.path.dirname(os.path.realpath(__file__)) \
                             + "/" + CREDENTIALS_FILE)
_creds_dictionary = cp.walk(cp.dummy)


class Store(object):
    """Credential Store"""

    @staticmethod
    def putCredential(id, username, password):
        """Set the username and password"""
        _creds_dictionary[id] = {const.USERNAME: username,
                                const.PASSWORD: password}

    @staticmethod
    def getUsername(id):
        """Get the username"""
        return _creds_dictionary[id][const.USERNAME]

    @staticmethod
    def getPassword(id):
        """Get the password"""
        return _creds_dictionary[id][const.PASSWORD]

    @staticmethod
    def getCredential(id):
        """Get the username and password"""
        return _creds_dictionary[id]

    @staticmethod
    def getCredentials():
        """Get all usernames and passwords"""
        return _creds_dictionary

    @staticmethod
    def deleteCredential(id):
        """Delete a credential"""
        return _creds_dictionary.pop(id)
