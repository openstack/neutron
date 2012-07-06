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
Quantum Port Aware Scheduler Implementation
"""

from nova import exception as excp
from nova import flags
from nova.openstack.common import cfg
from nova.openstack.common import log as logging
from nova.scheduler import chance
from quantumclient import Client


LOG = logging.getLogger(__name__)


quantum_opts = [
    cfg.StrOpt('quantum_connection_host',
               default='127.0.0.1',
               help='HOST for connecting to quantum'),
    cfg.StrOpt('quantum_connection_port',
               default='9696',
               help='PORT for connecting to quantum'),
    cfg.StrOpt('quantum_default_tenant_id',
               default="default",
               help='Default tenant id when creating quantum networks'),
]


FLAGS = flags.FLAGS
FLAGS.register_opts(quantum_opts)

HOST = FLAGS.quantum_connection_host
PORT = FLAGS.quantum_connection_port
USE_SSL = False
VERSION = '1.0'
URI_PREFIX_CSCO = '/extensions/csco/tenants/{tenant_id}'
TENANT_ID = 'nova'
CSCO_EXT_NAME = 'Cisco Nova Tenant'
ACTION = '/schedule_host'


class QuantumPortAwareScheduler(chance.ChanceScheduler):
    """
    Quantum network service dependent scheduler
    Obtains the hostname from Quantum using an extension API
    """
    def __init__(self):
        # We have to send a dummy tenant name here since the client
        # needs some tenant name, but the tenant name will not be used
        # since the extensions URL does not require it
        LOG.debug("Initializing Cisco Quantum Port-aware Scheduler...")
        super(QuantumPortAwareScheduler, self).__init__()
        client = Client(HOST, PORT, USE_SSL, format='json', version=VERSION,
                        uri_prefix="", tenant="dummy", logger=LOG)
        request_url = "/extensions"
        data = client.do_request('GET', request_url)
        LOG.debug("Obtained supported extensions from Quantum: %s" % data)
        for ext in data['extensions']:
            name = ext['name']
            if name == CSCO_EXT_NAME:
                LOG.debug("Quantum plugin supports required \"%s\" extension"
                          "for the scheduler." % name)
                return

        LOG.error("Quantum plugin does not support required \"%s\" extension"
                  " for the scheduler. Scheduler will quit." % CSCO_EXT_NAME)
        raise excp.ServiceUnavailable()

    def _schedule(self, context, topic, request_spec, **kwargs):
        """Gets the host name from the Quantum service"""
        LOG.debug("Cisco Quantum Port-aware Scheduler is scheduling...")
        instance_id = request_spec['instance_properties']['uuid']
        user_id = request_spec['instance_properties']['user_id']
        project_id = request_spec['instance_properties']['project_id']

        instance_data_dict = {'novatenant':
                              {'instance_id': instance_id,
                               'instance_desc':
                               {'user_id': user_id,
                                'project_id': project_id}}}

        client = Client(HOST, PORT, USE_SSL, format='json', version=VERSION,
                        uri_prefix=URI_PREFIX_CSCO, tenant=TENANT_ID,
                        logger=LOG)
        request_url = "/novatenants/" + project_id + ACTION
        data = client.do_request('PUT', request_url, body=instance_data_dict)

        hostname = data["host_list"]["host_1"]
        if not hostname:
            raise excp.NoValidHost(_("Scheduler was unable to locate a host"
                                     " for this request. Is the appropriate"
                                     " service running?"))

        LOG.debug(_("Quantum service returned host: %s") % hostname)
        return hostname
