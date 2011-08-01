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

import logging as LOG

from quantum.plugins.cisco.common import cisco_constants as const

LOG.basicConfig(level=LOG.WARN)
LOG.getLogger(const.LOGGER_COMPONENT_NAME)

_creds_dictionary = {'10.10.10.10': ["username", "password"],
                     '127.0.0.1': ["root", "nova"]}


class Store(object):
    # The format for this store is {"ip-address" :{"username", "password"}}
    def __init__(self):
        pass

    @staticmethod
    def putId(id):
        _creds_dictionary[id] = []

    @staticmethod
    def putUsername(id, username):
        creds = _creds_dictionary.get(id)
        creds.insert(0, username)

    @staticmethod
    def putPassword(id, password):
        creds = _creds_dictionary.get(id)
        creds.insert(1, password)

    @staticmethod
    def getUsername(id):
        creds = _creds_dictionary.get(id)
        return creds[0]

    @staticmethod
    def getPassword(id):
        creds = _creds_dictionary.get(id)
        return creds[1]


def main():
    LOG.debug("username %s\n" % Store.getUsername("172.20.231.27"))
    LOG.debug("password %s\n" % Store.getPassword("172.20.231.27"))
    Store.putId("192.168.1.1")
    Store.putUsername("192.168.1.1", "guest-username")
    Store.putPassword("192.168.1.1", "guest-password")
    LOG.debug("username %s\n" % Store.getUsername("192.168.1.1"))
    LOG.debug("password %s\n" % Store.getPassword("192.168.1.1"))

if __name__ == '__main__':
    main()
