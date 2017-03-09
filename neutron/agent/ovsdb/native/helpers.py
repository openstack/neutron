# Copyright (c) 2015 Red Hat, Inc.
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

from oslo_config import cfg

from neutron.agent.ovsdb import api as ovsdb

cfg.CONF.import_opt('ovs_vsctl_timeout', 'neutron.agent.common.ovs_lib')


def _connection_to_manager_uri(conn_uri):
    proto, addr = conn_uri.split(':', 1)
    if ':' in addr:
        ip, port = addr.split(':', 1)
        return 'p%s:%s:%s' % (proto, port, ip)
    else:
        return 'p%s:%s' % (proto, addr)


def enable_connection_uri(conn_uri, set_timeout=False):
    class OvsdbVsctlContext(object):
        vsctl_timeout = cfg.CONF.ovs_vsctl_timeout

    manager_uri = _connection_to_manager_uri(conn_uri)
    api = ovsdb.API.get(OvsdbVsctlContext, 'vsctl')
    with api.transaction() as txn:
        txn.add(api.add_manager(manager_uri))
        if set_timeout:
            timeout = cfg.CONF.ovs_vsctl_timeout * 1000
            txn.add(api.db_set('Manager', manager_uri,
                               ('inactivity_probe', timeout)))
