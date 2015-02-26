# Copyright (c) 2013 OpenStack Foundation
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

import re

from oslo_config import cfg
from oslo_log import log
from oslo_serialization import jsonutils
import requests

from neutron.plugins.ml2 import driver_api as api

LOG = log.getLogger(__name__)

ncs_opts = [
    cfg.StrOpt('url',
               help=_("HTTP URL of Tail-f NCS REST interface.")),
    cfg.StrOpt('username',
               help=_("HTTP username for authentication")),
    cfg.StrOpt('password', secret=True,
               help=_("HTTP password for authentication")),
    cfg.IntOpt('timeout', default=10,
               help=_("HTTP timeout in seconds."))
]

cfg.CONF.register_opts(ncs_opts, "ml2_ncs")


class NCSMechanismDriver(api.MechanismDriver):

    """Mechanism Driver for Tail-f Network Control System (NCS).

    This driver makes portions of the Neutron database available for
    service provisioning in NCS. For example, NCS can use this
    information to provision physical switches and routers in response
    to OpenStack configuration changes.

    The database is replicated from Neutron to NCS using HTTP and JSON.

    The driver has two states: out-of-sync (initially) and in-sync.

    In the out-of-sync state each driver event triggers an attempt
    to synchronize the complete database. On success the driver
    transitions to the in-sync state.

    In the in-sync state each driver event triggers synchronization
    of one network or port. On success the driver stays in-sync and
    on failure it transitions to the out-of-sync state.
    """
    out_of_sync = True

    def initialize(self):
        self.url = cfg.CONF.ml2_ncs.url
        self.timeout = cfg.CONF.ml2_ncs.timeout
        self.username = cfg.CONF.ml2_ncs.username
        self.password = cfg.CONF.ml2_ncs.password

    # Postcommit hooks are used to trigger synchronization.

    def create_network_postcommit(self, context):
        self.synchronize('create', 'network', context)

    def update_network_postcommit(self, context):
        self.synchronize('update', 'network', context)

    def delete_network_postcommit(self, context):
        self.synchronize('delete', 'network', context)

    def create_subnet_postcommit(self, context):
        self.synchronize('create', 'subnet', context)

    def update_subnet_postcommit(self, context):
        self.synchronize('update', 'subnet', context)

    def delete_subnet_postcommit(self, context):
        self.synchronize('delete', 'subnet', context)

    def create_port_postcommit(self, context):
        self.synchronize('create', 'port', context)

    def update_port_postcommit(self, context):
        self.synchronize('update', 'port', context)

    def delete_port_postcommit(self, context):
        self.synchronize('delete', 'port', context)

    def synchronize(self, operation, object_type, context):
        """Synchronize NCS with Neutron following a configuration change."""
        if self.out_of_sync:
            self.sync_full(context)
        else:
            self.sync_object(operation, object_type, context)

    def sync_full(self, context):
        """Resync the entire database to NCS.
        Transition to the in-sync state on success.
        """
        dbcontext = context._plugin_context
        networks = context._plugin.get_networks(dbcontext)
        subnets = context._plugin.get_subnets(dbcontext)
        ports = context._plugin.get_ports(dbcontext)
        for port in ports:
            self.add_security_groups(context, dbcontext, port)
        json = {'openstack': {'network': networks,
                              'subnet': subnets,
                              'port': ports}}
        self.sendjson('put', '', json)
        self.out_of_sync = False

    def sync_object(self, operation, object_type, context):
        """Synchronize the single modified record to NCS.
        Transition to the out-of-sync state on failure.
        """
        self.out_of_sync = True
        dbcontext = context._plugin_context
        id = context.current['id']
        urlpath = object_type + '/' + id
        if operation == 'delete':
            self.sendjson('delete', urlpath, None)
        else:
            assert operation == 'create' or operation == 'update'
            if object_type == 'network':
                network = context._plugin.get_network(dbcontext, id)
                self.sendjson('put', urlpath, {'network': network})
            elif object_type == 'subnet':
                subnet = context._plugin.get_subnet(dbcontext, id)
                self.sendjson('put', urlpath, {'subnet': subnet})
            else:
                assert object_type == 'port'
                port = context._plugin.get_port(dbcontext, id)
                self.add_security_groups(context, dbcontext, port)
                self.sendjson('put', urlpath, {'port': port})
        self.out_of_sync = False

    def add_security_groups(self, context, dbcontext, port):
        """Populate the 'security_groups' field with entire records."""
        groups = [context._plugin.get_security_group(dbcontext, sg)
                  for sg in port['security_groups']]
        port['security_groups'] = groups

    def sendjson(self, method, urlpath, obj):
        obj = self.escape_keys(obj)
        headers = {'Content-Type': 'application/vnd.yang.data+json'}
        if obj is None:
            data = None
        else:
            data = jsonutils.dumps(obj, indent=2)
        auth = None
        if self.username and self.password:
            auth = (self.username, self.password)
        if self.url:
            url = '/'.join([self.url, urlpath])
            r = requests.request(method, url=url,
                                 headers=headers, data=data,
                                 auth=auth, timeout=self.timeout)
            r.raise_for_status()

    def escape_keys(self, obj):
        """Escape JSON keys to be NCS compatible.
        NCS does not allow period (.) or colon (:) characters.
        """
        if isinstance(obj, dict):
            obj = dict((self.escape(k), self.escape_keys(v))
                       for k, v in obj.iteritems())
        if isinstance(obj, list):
            obj = [self.escape_keys(x) for x in obj]
        return obj

    def escape(self, string):
        return re.sub('[:._]', '-', string)
