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

from nova import flags
from nova import log as logging
from nova.scheduler import driver
from quantum.client import Client
from quantum.common.wsgi import Serializer

LOG = logging.getLogger('nova.scheduler.quantum_aware_scheduler')

FLAGS = flags.FLAGS
flags.DEFINE_string('quantum_host', "127.0.0.1",
                     'IP address of the quantum network service.')
flags.DEFINE_integer('quantum_port', 9696,
                     'Listening port for Quantum network service')

HOST = FLAGS.quantum_host
PORT = FLAGS.quantum_port
USE_SSL = False
TENANT_ID = 'nova'


class QuantumScheduler(driver.Scheduler):
    """
    Quantum network service dependent scheduler
    Obtains the hostname from Quantum using an extension API
    """

    def schedule(self, context, topic, *_args, **_kwargs):
        """Gets the host name from the Quantum service"""
        instance_id = _kwargs['instance_id']
        user_id = \
                _kwargs['request_spec']['instance_properties']['user_id']
        project_id = \
                _kwargs['request_spec']['instance_properties']['project_id']

        instance_data_dict = \
                {'novatenant': \
                 {'instance-id': instance_id,
                  'instance-desc': \
                  {'user_id': user_id, 'project_id': project_id}}}
        client = Client(HOST, PORT, USE_SSL, format='json')
        request_url = "/novatenants/" + project_id + "/get_host"
        data = client.do_request(TENANT_ID, 'PUT', request_url,
                                 body=instance_data_dict)
        hostname = data["host_list"]["host_1"]

        if not hostname:
            raise driver.NoValidHost(_("Scheduler was unable to locate a host"
                                       " for this request. Is the appropriate"
                                       " service running?"))

        LOG.debug(_("Quantum service returned host: %s\n") % hostname)
        return hostname
