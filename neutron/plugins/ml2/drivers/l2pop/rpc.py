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

from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.openstack.common import log as logging


LOG = logging.getLogger(__name__)


class L2populationAgentNotifyAPI(n_rpc.RpcProxy):
    BASE_RPC_API_VERSION = '1.0'

    def __init__(self, topic=topics.AGENT):
        super(L2populationAgentNotifyAPI, self).__init__(
            topic=topic, default_version=self.BASE_RPC_API_VERSION)

        self.topic_l2pop_update = topics.get_topic_name(topic,
                                                        topics.L2POPULATION,
                                                        topics.UPDATE)

    def _notification_fanout(self, context, method, fdb_entries):
        LOG.debug(_('Fanout notify l2population agents at %(topic)s '
                    'the message %(method)s with %(fdb_entries)s'),
                  {'topic': self.topic,
                   'method': method,
                   'fdb_entries': fdb_entries})

        self.fanout_cast(context,
                         self.make_msg(method, fdb_entries=fdb_entries),
                         topic=self.topic_l2pop_update)

    def _notification_host(self, context, method, fdb_entries, host):
        LOG.debug(_('Notify l2population agent %(host)s at %(topic)s the '
                    'message %(method)s with %(fdb_entries)s'),
                  {'host': host,
                   'topic': self.topic,
                   'method': method,
                   'fdb_entries': fdb_entries})
        self.cast(context,
                  self.make_msg(method, fdb_entries=fdb_entries),
                  topic='%s.%s' % (self.topic_l2pop_update, host))

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
