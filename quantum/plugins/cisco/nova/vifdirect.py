"""
# vim: tabstop=4 shiftwidth=4 softtabstop=4
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
"""VIF drivers for interface type direct."""

from nova import flags
from nova import log as logging
from nova import utils
from nova.network import linux_net
from nova.virt.libvirt import netutils
from nova.virt.vif import VIFDriver
from quantum.client import Client
from quantum.common.wsgi import Serializer

LOG = logging.getLogger('nova.virt.libvirt.vif')

FLAGS = flags.FLAGS
flags.DEFINE_string('quantum_host', "127.0.0.1",
                     'IP address of the quantum network service.')
flags.DEFINE_integer('quantum_port', 9696,
                     'Listening port for Quantum network service')

HOST = FLAGS.quantum_host
PORT = FLAGS.quantum_port
USE_SSL = False
TENANT_ID = 'nova'


class Libvirt802dot1QbhDriver(VIFDriver):
    """VIF driver for Linux bridge."""

    def _get_configurations(self, instance, network, mapping):
        """Gets the device name and the profile name from Quantum"""

        instance_id = instance['id']
        user_id = instance['user_id']
        project_id = instance['project_id']

        instance_data_dict = \
                {'novatenant': \
                 {'instance-id': instance_id,
                  'instance-desc': \
                  {'user_id': user_id, 'project_id': project_id}}}

        client = Client(HOST, PORT, USE_SSL, format='json')
        request_url = "/novatenants/" + project_id + "/get_instance_port"
        data = client.do_request(TENANT_ID, 'PUT', request_url,
                                 body=instance_data_dict)
        device = data['vif_desc']['device']
        portprofile = data['vif_desc']['portprofile']

        LOG.debug(_("Quantum returned device: %s\n") % device)
        LOG.debug(_("Quantum returned portprofile: %s\n") % portprofile)
        mac_id = mapping['mac'].replace(':', '')

        result = {
            'id': mac_id,
            'mac_address': mapping['mac'],
            'device_name': device,
            'profile_name': portprofile,
        }

        return result

    def plug(self, instance, network, mapping):
        return self._get_configurations(instance, network, mapping)

    def unplug(self, instance, network, mapping):
        pass
