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
from nova.openstack.common import cfg
from nova.openstack.common import log as logging
from nova.virt.vif import VIFDriver
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
ASSOCIATE_ACTION = '/associate_port'
DETACH_ACTION = '/detach_port'


class Libvirt802dot1QbhDriver(VIFDriver):
    """VIF driver for 802.1Qbh"""
    def __init__(self):
        # We have to send a dummy tenant name here since the client
        # needs some tenant name, but the tenant name will not be used
        # since the extensions URL does not require it
        LOG.debug("Initializing Cisco Quantum VIF driver...")
        client = Client(HOST, PORT, USE_SSL, format='json', version=VERSION,
                        uri_prefix="", tenant="dummy", logger=LOG)
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
                  " for the VIF driver. nova-compute will quit."
                  % CSCO_EXT_NAME)
        raise excp.ServiceUnavailable()

    def _update_configurations(self, instance, network, mapping, action):
        """Gets the device name and the profile name from Quantum"""
        LOG.debug("Cisco Quantum VIF driver performing: %s" % (action))
        instance_id = instance['uuid']
        user_id = instance['user_id']
        project_id = instance['project_id']
        vif_id = mapping['vif_uuid']

        instance_data_dict = {
            'novatenant': {
                'instance_id': instance_id,
                'instance_desc': {
                    'user_id': user_id,
                    'project_id': project_id,
                    'vif_id': vif_id}}}

        client = Client(HOST, PORT, USE_SSL, format='json', version=VERSION,
                        uri_prefix=URI_PREFIX_CSCO, tenant=TENANT_ID,
                        logger=LOG)
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
