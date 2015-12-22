# Copyright (c) 2015 Hewlett-Packard Enterprise Development Company, L.P.
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

import netaddr
import os
import six

from oslo_log import log as logging

from neutron.agent.common import utils as common_utils
from neutron.agent.linux import ip_lib
from neutron.common import constants
from neutron.common import exceptions
from neutron.common import utils

LOG = logging.getLogger(__name__)


class NamespaceEtcDir(object):
    """Creates a directory where namespace local /etc/iproute2 files can live

    Directories are created under /etc/netns/<namespace_name>/iproute2 so that
    when you exec a command inside a namespace, the directory is available as
    /etc/iproute2 locally to the namespace.

    The directory ownership is changed to the owner of the L3 agent process
    so that root is no longer required to manage the file.  This limits the
    scope of where root is needed.  Changing ownership is justified because
    the directory lives under a namespace specific sub-directory of /etc, it
    should be considered owned by the L3 agent process, which also manages the
    namespace itself.

    The directory and its contents should not be considered config.  Nothing
    needs to be done for upgrade.  The only reason for it to live under /etc
    within the namespace is that is the only place from where the ip command
    will read it.
    """

    BASE_DIR = "/etc/netns"

    def __init__(self, namespace):
        self._directory = os.path.join(self.BASE_DIR, namespace)

    def create(self):
        common_utils.execute(['mkdir', '-p', self._directory],
                             run_as_root=True)

        user_id = os.geteuid()
        common_utils.execute(['chown', user_id, self._directory],
                             run_as_root=True)

    def destroy(self):
        common_utils.execute(['rm', '-r', '-f', self._directory],
                             run_as_root=True)

    def get_full_path(self):
        return self._directory


class RoutingTable(object):
    def __init__(self, namespace, table_id, name):
        self.name = name
        self.table_id = table_id
        self.ip_route = ip_lib.IPRoute(namespace=namespace, table=name)
        self._keep = set()

    def __eq__(self, other):
        return self.table_id == other.table_id

    def __hash__(self):
        return self.table_id

    def add(self, device, cidr):
        table = device.route.table(self.name)
        cidr = netaddr.IPNetwork(cidr)
        # Get the network cidr (e.g. 192.168.5.135/23 -> 192.168.4.0/23)
        net = utils.ip_to_cidr(cidr.network, cidr.prefixlen)
        self._keep.add((net, device.name))
        table.add_onlink_route(net)

    def add_gateway(self, device, gateway_ip):
        table = device.route.table(self.name)
        ip_version = ip_lib.get_ip_version(gateway_ip)
        self._keep.add((constants.IP_ANY[ip_version], device.name))
        table.add_gateway(gateway_ip)

    def __enter__(self):
        self._keep = set()
        return self

    def __exit__(self, exc_type, value, traceback):
        if exc_type:
            return False

        keep = self._keep
        self._keep = None

        ipv4_routes = self.ip_route.route.list_routes(constants.IP_VERSION_4)
        ipv6_routes = self.ip_route.route.list_routes(constants.IP_VERSION_6)
        all_routes = {(r['cidr'], r['dev'])
                      for r in ipv4_routes + ipv6_routes}

        for cidr, dev in all_routes - keep:
            try:
                self.ip_route.route.delete_route(cidr, dev=dev)
            except exceptions.DeviceNotFoundError:
                pass

        return True


class RoutingTablesManager(object):
    """Manages mapping from routing table name to routing tables

    The iproute2 package can read a mapping from /etc/iproute2/rt_tables.  When
    namespaces are used, it is possible to maintain an rt_tables file that is
    unique to the namespace.

    It is necessary to maintain this mapping on disk somewhere because it must
    survive agent restarts.  Otherwise, we'd be remapping each time.  It is not
    necessary to maintain it in the Neutron database because it is an
    agent-local implementation detail.

    While it could be kept in any local file, it is convenient to keep it in
    the rt_tables file so that we can simply pass the table name to the
    ip route commands.  It will also be helpful for debugging to be able to use
    the table name on the command line manually.
    """

    FILENAME = 'iproute2/rt_tables'
    ALL_IDS = set(range(1024, 2048))
    DEFAULT_TABLES = {"local": 255,
                      "main": 254,
                      "default": 253,
                      "unspec": 0}

    def __init__(self, namespace):
        self._namespace = namespace
        self.etc = NamespaceEtcDir(namespace)
        self._rt_tables_filename = os.path.join(
            self.etc.get_full_path(), self.FILENAME)
        self._tables = {}
        self.initialize_map()

    def initialize_map(self):
        # Create a default table if one is not already found
        self.etc.create()
        utils.ensure_dir(os.path.dirname(self._rt_tables_filename))
        if not os.path.exists(self._rt_tables_filename):
            self._write_map(self.DEFAULT_TABLES)
        self._keep = set()

    def _get_or_create(self, table_id, table_name):
        table = self._tables.get(table_id)
        if not table:
            self._tables[table_id] = table = RoutingTable(
                 self._namespace, table_id, table_name)
        return table

    def get(self, table_name):
        """Returns the table ID for the given table name"""
        table_id = self._read_map().get(table_name)
        if table_id is not None:
            return self._get_or_create(table_id, table_name)

    def get_all(self):
        return set(self._get_or_create(t_id, name)
                   for name, t_id in self._read_map().items())

    def add(self, table_name):
        """Ensures there is a single table id available for the table name"""
        name_to_id = self._read_map()

        def get_and_keep(table_id, table_name):
            table = self._get_or_create(table_id, table_name)
            self._keep.add(table)
            return table

        # If it is already there, just return it.
        if table_name in name_to_id:
            return get_and_keep(name_to_id[table_name], table_name)

        # Otherwise, find an available id and write the new file
        table_ids = set(name_to_id.values())
        available_ids = self.ALL_IDS - table_ids
        name_to_id[table_name] = table_id = available_ids.pop()
        self._write_map(name_to_id)
        return get_and_keep(table_id, table_name)

    def delete(self, table_name):
        """Removes the table from the file"""
        name_to_id = self._read_map()

        # If it is already there, remove it
        table_id = name_to_id.pop(table_name, None)
        self._tables.pop(table_id, None)

        # Write the new file
        self._write_map(name_to_id)

    def _write_map(self, name_to_id):
        buf = six.StringIO()
        for name, table_id in name_to_id.items():
            buf.write("%s\t%s\n" % (table_id, name))
        utils.replace_file(self._rt_tables_filename, buf.getvalue())

    def _read_map(self):
        result = {}
        with open(self._rt_tables_filename, "r") as rt_file:
            for line in rt_file:
                fields = line.split()
                if len(fields) != 2:
                    continue
                table_id_str, name = fields
                try:
                    table_id = int(table_id_str)
                except ValueError:
                    continue
                result[name] = table_id
        return result

    def destroy(self):
        self.etc.destroy()

    def __enter__(self):
        for rt in self.get_all():
            if rt.table_id not in self.DEFAULT_TABLES.values():
                rt.__enter__()
        self._keep = set()
        return self

    def __exit__(self, exc_type, value, traceback):
        if exc_type:
            return False

        all_tables = set(rt for rt in self.get_all()
                         if rt.table_id not in self.DEFAULT_TABLES.values())
        for rt in all_tables:
            rt.__exit__(None, None, None)

        for rt in all_tables - self._keep:
            self.delete(rt.name)

        return True
