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

"""VIF drivers for interface type direct."""

from nova import exception as excp
from nova import flags
from nova import log as logging
from nova.network import linux_net
from nova.virt.libvirt import netutils
from nova import utils
from nova.virt.vif import VIFDriver
from quantum.client import Client
from quantum.common.wsgi import Serializer

LOG = logging.getLogger('quantum.plugins.cisco.nova.vifdirect')

FLAGS = flags.FLAGS
flags.DEFINE_string('quantum_host', "127.0.0.1",
                     'IP address of the quantum network service.')
flags.DEFINE_integer('quantum_port', 9696,
                     'Listening port for Quantum network service')

HOST = FLAGS.quantum_host
PORT = FLAGS.quantum_port
USE_SSL = False
TENANT_ID = 'nova'
ACTION_PREFIX_EXT = '/v1.0'
ACTION_PREFIX_CSCO = ACTION_PREFIX_EXT + \
        '/extensions/csco/tenants/{tenant_id}'
TENANT_ID = 'nova'
CSCO_EXT_NAME = 'Cisco Nova Tenant'
ASSOCIATE_ACTION = '/associate_port'
DETACH_ACTION = '/detach_port'


class Libvirt802dot1QbhDriver(VIFDriver):
    """VIF driver for 802.1Qbh"""
    def __init__(self):
        # We have to send a dummy tenant name here since the client
        # needs some tenant name, but the tenant name will not be used
        # since the extensions URL does not require it
        client = Client(HOST, PORT, USE_SSL, format='json',
                        action_prefix=ACTION_PREFIX_EXT, tenant="dummy")
        request_url = "/extensions"
        data = client.do_request('GET', request_url)
        LOG.debug("Obtained supported extensions from Quantum: %s" % data)
        for ext in data['extensions']:
            name = ext['name']
            if name == CSCO_EXT_NAME:
                LOG.debug("Quantum plugin supports required \"%s\" extension"
                          "for the VIF driver." % name)
                return
        LOG.error("Quantum plugin does not support required \"%s\" extension"
                  " for the VIF driver. nova-compute will quit." \
                  % CSCO_EXT_NAME)
        raise excp.ServiceUnavailable()

    def _update_configurations(self, instance, network, mapping, action):
        """Gets the device name and the profile name from Quantum"""

        instance_id = instance['id']
        user_id = instance['user_id']
        project_id = instance['project_id']
        vif_id = mapping['vif_uuid']

        instance_data_dict = \
                {'novatenant': \
                 {'instance_id': instance_id,
                  'instance_desc': \
                  {'user_id': user_id,
                   'project_id': project_id,
                   'vif_id': vif_id}}}

        client = Client(HOST, PORT, USE_SSL, format='json', tenant=TENANT_ID,
                        action_prefix=ACTION_PREFIX_CSCO)
        request_url = "/novatenants/" + project_id + action
        data = client.do_request('PUT', request_url, body=instance_data_dict)

        if action == ASSOCIATE_ACTION:
            device = data['vif_desc']['device']
            portprofile = data['vif_desc']['portprofile']
            LOG.debug(_("Quantum provided the device: %s") % device)
            LOG.debug(_("Quantum provided the portprofile: %s") % portprofile)
            mac_id = mapping['mac'].replace(':', '')

            result = {
                'id': mac_id,
                'mac_address': mapping['mac'],
                'device_name': device,
                'profile_name': portprofile,
            }

            return result
        else:
            return data

    def plug(self, instance, network, mapping):
        return self._update_configurations(instance, network, mapping,
                                           ASSOCIATE_ACTION)

    def unplug(self, instance, network, mapping):
        self._update_configurations(instance, network, mapping,
                                    DETACH_ACTION)
