# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright 2013 PLUMgrid, Inc. All Rights Reserved.
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
# @author: Edgar Magana, emagana@plumgrid.com, PLUMgrid, Inc.
# @author: Brenden Blanco, bblanco@plumgrid.com, PLUMgrid, Inc.

"""
Quantum PLUMgrid Plug-in for PLUMgrid Virtual Technology
This plugin will forward authenticated REST API calls
to the Network Operating System by PLUMgrid called NOS
"""

import httplib
import urllib2

from quantum.openstack.common import jsonutils as json
from quantum.openstack.common import log as logging
from quantum.plugins.plumgrid.common import exceptions as plum_excep


LOG = logging.getLogger(__name__)


class RestConnection(object):
    """REST Connection to PLUMgrid NOS Server."""

    def __init__(self, server, port, timeout):
        LOG.debug(_('QuantumPluginPLUMgrid Status: REST Connection Started'))
        self.server = server
        self.port = port
        self.timeout = timeout

    def nos_rest_conn(self, nos_url, action, data, headers):
        self.nos_url = nos_url
        body_data = json.dumps(data)
        if not headers:
            headers = {}
        headers['Content-type'] = 'application/json'
        headers['Accept'] = 'application/json'

        LOG.debug(_("PLUMgrid_NOS_Server: %s %s %s"), self.server, self.port,
                  action)

        conn = httplib.HTTPConnection(self.server, self.port,
                                      timeout=self.timeout)
        if conn is None:
            LOG.error(_('PLUMgrid_NOS_Server: Could not establish HTTP '
                        'connection'))
            return

        try:
            LOG.debug(_("PLUMgrid_NOS_Server Sending Data: %s %s %s"),
                      nos_url, body_data, headers)
            conn.request(action, nos_url, body_data, headers)
            resp = conn.getresponse()
            resp_str = resp.read()

            LOG.debug(_("PLUMgrid_NOS_Server Connection Data: %s, %s"),
                      resp, resp_str)

            if resp.status is httplib.OK:
                try:
                    respdata = json.loads(resp_str)
                    LOG.debug(_("PLUMgrid_NOS_Server Connection RESP: %s"),
                              respdata)
                    pass
                except ValueError:
                    err_message = _("PLUMgrid HTTP Connection Failed: ")
                    LOG.Exception(err_message)
                    raise plum_excep.PLUMgridException(err_message)

            ret = (resp.status, resp.reason, resp_str)
        except urllib2.HTTPError:
            LOG.error(_('PLUMgrid_NOS_Server: %(action)s failure, %(e)r'))
            ret = 0, None, None, None
        conn.close()
        LOG.debug(_("PLUMgrid_NOS_Server: status=%(status)d, "
                  "reason=%(reason)r, ret=%(ret)s"),
                  {'status': ret[0], 'reason': ret[1], 'ret': ret[2]})
        return ret
