# Copyright (c) 2019 OpenStack Foundation.
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

from ironicclient import client
from ironicclient import exc as ironic_exc
from keystoneauth1 import loading as ks_loading
from neutron_lib.api.definitions import port as port_def
from neutron_lib.api.definitions import portbindings as portbindings_def
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants as n_const
from oslo_config import cfg
from oslo_log import log as logging

from neutron.notifiers import batch_notifier

LOG = logging.getLogger(__name__)

BAREMETAL_EVENT_TYPE = 'network'
IRONIC_API_VERSION = 'latest'
IRONIC_SESSION = None
IRONIC_CONF_SECTION = 'ironic'
IRONIC_CLIENT_VERSION = 1


@registry.has_registry_receivers
class Notifier(object):

    _instance = None

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __init__(self):
        self.batch_notifier = batch_notifier.BatchNotifier(
            cfg.CONF.send_events_interval, self.send_events)
        self.irclient = self._get_ironic_client()

    def _get_session(self, group):
        auth = ks_loading.load_auth_from_conf_options(cfg.CONF, group)
        session = ks_loading.load_session_from_conf_options(
            cfg.CONF, group, auth=auth)
        return session

    def _get_ironic_client(self):
        """Get Ironic client instance."""

        # NOTE: To support standalone ironic without keystone
        if cfg.CONF.ironic.auth_strategy == 'noauth':
            args = {'token': 'noauth',
                    'endpoint': cfg.CONF.ironic.ironic_url}
        else:
            global IRONIC_SESSION
            if not IRONIC_SESSION:
                IRONIC_SESSION = self._get_session(IRONIC_CONF_SECTION)
            args = {'session': IRONIC_SESSION,
                    'region_name': cfg.CONF.ironic.region_name,
                    'endpoint_type': cfg.CONF.ironic.endpoint_type}
        args['os_ironic_api_version'] = IRONIC_API_VERSION
        args['max_retries'] = cfg.CONF.ironic.max_retries
        args['retry_interval'] = cfg.CONF.ironic.retry_interval
        return client.Client(IRONIC_CLIENT_VERSION, **args)

    def send_events(self, batched_events):
        # NOTE(TheJulia): Friendly exception handling so operators
        # can decouple updates.
        try:
            self.irclient.events.create(events=batched_events)
        except ironic_exc.NotFound:
            LOG.error('The ironic API appears to not support posting events. '
                      'The API likely needs to be upgraded.')
        except Exception as e:
            LOG.error('Unknown error encountered posting the event to '
                      'ironic. {error}'.format(error=e))

    @registry.receives(resources.PORT, [events.AFTER_UPDATE])
    def process_port_update_event(self, resource, event, trigger,
                                  original_port=None, port=None,
                                  **kwargs):
        # We only want to notify about baremetal ports.
        if not (port[portbindings_def.VNIC_TYPE] ==
                portbindings_def.VNIC_BAREMETAL):
            # TODO(TheJulia): Add the smartnic flag at some point...
            return

        original_port_status = original_port['status']
        current_port_status = port['status']
        port_event = None
        if (original_port_status == n_const.PORT_STATUS_ACTIVE and
                current_port_status in [n_const.PORT_STATUS_DOWN,
                                        n_const.PORT_STATUS_ERROR]):
            port_event = 'unbind_port'
        elif (original_port_status == n_const.PORT_STATUS_DOWN and
                current_port_status in [n_const.PORT_STATUS_ACTIVE,
                                        n_const.PORT_STATUS_ERROR]):
            port_event = 'bind_port'
        LOG.debug('Queuing event for {event_type} for port {port} '
                  'for status {status}.'.format(event_type=port_event,
                                                port=port['id'],
                                                status=current_port_status))
        if port_event:
            notify_event = {
                'event': '.'.join([BAREMETAL_EVENT_TYPE, port_event]),
                'port_id': port['id'],
                'mac_address': port[port_def.PORT_MAC_ADDRESS],
                'status': current_port_status,
                'device_id': port['device_id'],
                'binding:host_id': port[portbindings_def.HOST_ID],
                'binding:vnic_type': port[portbindings_def.VNIC_TYPE]
            }
            # Filter keys with empty string as value. In case a type UUID field
            # or similar is not set the API won't accept empty string.
            self.batch_notifier.queue_event(
                {k: v for k, v in notify_event.items() if v != ''})

    @registry.receives(resources.PORT, [events.AFTER_DELETE])
    def process_port_delete_event(self, resource, event, trigger,
                                  original_port=None, port=None,
                                  **kwargs):
        # We only want to notify about baremetal ports.
        if not (port[portbindings_def.VNIC_TYPE] ==
                portbindings_def.VNIC_BAREMETAL):
            # TODO(TheJulia): Add the smartnic flag at some point...
            return

        port_event = 'delete_port'
        LOG.debug('Queuing event for {event_type} for port {port} '
                  'for status {status}.'.format(event_type=port_event,
                                                port=port['id'],
                                                status='DELETED'))
        notify_event = {
            'event': '.'.join([BAREMETAL_EVENT_TYPE, port_event]),
            'port_id': port['id'],
            'mac_address': port[port_def.PORT_MAC_ADDRESS],
            'status': 'DELETED',
            'device_id': port['device_id'],
            'binding:host_id': port[portbindings_def.HOST_ID],
            'binding:vnic_type': port[portbindings_def.VNIC_TYPE]
        }
        # Filter keys with empty string as value. In case a type UUID field
        # or similar is not set the API won't accept empty string.
        self.batch_notifier.queue_event(
            {k: v for k, v in notify_event.items() if v != ''})
