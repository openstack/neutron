# Copyright (c) 2013 OpenStack Foundation.
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

import collections
import copy

from oslo_log import log as logging
import oslo_messaging

from neutron.common import rpc as n_rpc
from neutron.common import topics


LOG = logging.getLogger(__name__)


PortInfo = collections.namedtuple("PortInfo", "mac_address ip_address")


class L2populationAgentNotifyAPI(object):

    def __init__(self, topic=topics.AGENT):
        self.topic = topic
        self.topic_l2pop_update = topics.get_topic_name(topic,
                                                        topics.L2POPULATION,
                                                        topics.UPDATE)
        target = oslo_messaging.Target(topic=topic, version='1.0')
        self.client = n_rpc.get_client(target)

    def _notification_fanout(self, context, method, fdb_entries):
        LOG.debug('Fanout notify l2population agents at %(topic)s '
                  'the message %(method)s with %(fdb_entries)s',
                  {'topic': self.topic,
                   'method': method,
                   'fdb_entries': fdb_entries})

        marshalled_fdb_entries = self._marshall_fdb_entries(fdb_entries)
        cctxt = self.client.prepare(topic=self.topic_l2pop_update, fanout=True)
        cctxt.cast(context, method, fdb_entries=marshalled_fdb_entries)

    def _notification_host(self, context, method, fdb_entries, host):
        LOG.debug('Notify l2population agent %(host)s at %(topic)s the '
                  'message %(method)s with %(fdb_entries)s',
                  {'host': host,
                   'topic': self.topic,
                   'method': method,
                   'fdb_entries': fdb_entries})

        marshalled_fdb_entries = self._marshall_fdb_entries(fdb_entries)
        cctxt = self.client.prepare(topic=self.topic_l2pop_update, server=host)
        cctxt.cast(context, method, fdb_entries=marshalled_fdb_entries)

    def add_fdb_entries(self, context, fdb_entries, host=None):
        if fdb_entries:
            if host:
                self._notification_host(context, 'add_fdb_entries',
                                        fdb_entries, host)
            else:
                self._notification_fanout(context, 'add_fdb_entries',
                                          fdb_entries)

    def remove_fdb_entries(self, context, fdb_entries, host=None):
        if fdb_entries:
            if host:
                self._notification_host(context, 'remove_fdb_entries',
                                        fdb_entries, host)
            else:
                self._notification_fanout(context, 'remove_fdb_entries',
                                          fdb_entries)

    def update_fdb_entries(self, context, fdb_entries, host=None):
        if fdb_entries:
            if host:
                self._notification_host(context, 'update_fdb_entries',
                                        fdb_entries, host)
            else:
                self._notification_fanout(context, 'update_fdb_entries',
                                          fdb_entries)

    @staticmethod
    def _marshall_fdb_entries(fdb_entries):
        """Prepares fdb_entries for serialization to JSON for RPC.

        All methods in this class that send messages should call this to
        marshall fdb_entries for the wire.

        :param fdb_entries: Original fdb_entries data-structure.  Looks like:
            {
                <uuid>: {
                    ...,
                    'ports': {
                        <ip address>: [ PortInfo, ...  ],
                        ...

        :returns: Deep copy with PortInfo converted to [mac, ip]
        """
        marshalled = copy.deepcopy(fdb_entries)
        for value in marshalled.values():
            if 'ports' in value:
                for address, port_infos in value['ports'].items():
                    value['ports'][address] = [[mac, ip]
                                               for mac, ip in port_infos]
        return marshalled
