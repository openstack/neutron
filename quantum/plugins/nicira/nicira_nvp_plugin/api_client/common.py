# Copyright 2009-2012 Nicira Networks, Inc.
# All Rights Reserved
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
# vim: tabstop=4 shiftwidth=4 softtabstop=4
#

import httplib
import mock


def _conn_str(conn):
    if isinstance(conn, httplib.HTTPSConnection):
        proto = "https://"
    elif isinstance(conn, httplib.HTTPConnection):
        proto = "http://"
    elif isinstance(conn, mock.Mock):
        proto = "http://"
    else:
        raise TypeError('_conn_str() invalid connection type: %s' % type(conn))

    return "%s%s:%s" % (proto, conn.host, conn.port)
