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
#    @author: Edgar Magana, Cisco Systems
#
"""
Network Library to insert services using Quantum APIs
Currently has four functionalities:
1. insert_inpath_service <tenant_id> <service_image_id>
    <management_net_name> <northbound_net_name> <southbound_net_name>
2. delete_service <tenant_id> <service_instance_id>
3. connect_vm <tenant_id> <vm_image_id> <service_instance_id>
4. disconnect_vm <vm_instance_id>
"""


import logging
import logging.handlers
import os
import subprocess
import re
import sys

from optparse import OptionParser
from quantum.client import Client
from quantum.plugins.cisco.db import api as db
from quantum.plugins.cisco.db import l2network_db as l2db
from quantum.plugins.cisco.db import services_db as sdb
from quantum.plugins.cisco.common import cisco_constants as const
from quantum.plugins.cisco.services import services_constants as servconts
from quantum.plugins.cisco.services import services_logistics as servlogcs


LOG = logging.getLogger(__name__)


def insert_inpath_service(tenant_id, service_image_id,
             management_net_name, northbound_net_name,
             southbound_net_name, *args):
    """Inserting a network service between two networks"""
    print ("Creating Network for Services and Servers")
    service_logic = servlogcs.ServicesLogistics()
    net_list = {}
    multiport_net_list = []
    networks_name_list = [management_net_name, northbound_net_name, \
                          southbound_net_name]
    client = Client(HOST, PORT, USE_SSL, format='json', tenant=tenant_id)
    for net in networks_name_list:
        data = {servconts.NETWORK: {servconts.NAME: net}}
        net_list[net] = client.create_network(data)
        net_list[net][servconts.PORTS] = []
        LOG.debug("Network %s Created with ID: %s " % (net, \
                        net_list[net][servconts.NETWORK][servconts.ID]))
    print "Completed"
    print ("Creating Ports on Services and Server Networks")
    LOG.debug("Operation 'create_port' executed.")
    if not service_logic.verify_plugin(const.UCS_PLUGIN):
        for net in networks_name_list:
            net_list[net][servconts.PORTS].append
            (client.create_port
            (net_list[net][servconts.NETWORK][servconts.ID]))
        LOG.debug("Operation 'create_port' executed.")
    else:
        for net in networks_name_list:
            nets = net_list[net][servconts.NETWORK][servconts.ID]
            multiport_net_list.append(nets)
        data = create_multiport(tenant_id, multiport_net_list)
        net_idx = 0
        for net in networks_name_list:
            port_id = data[servconts.PORTS][net_idx][servconts.ID]
            net_list[net][servconts.PORTS].append(port_id)
            LOG.debug("Port UUID: %s on network: %s" % \
                       (data[servconts.PORTS][net_idx][servconts.ID], net))
            net_idx = net_idx + 1
    print "Completed"
    try:
        create_vm_args = []
        create_vm_args.append(servconts.CREATE_VM_CMD)
        create_vm_args.append(service_image_id)
        print ("Creating VM with image: %s" % (service_image_id))
        process = subprocess.Popen(create_vm_args, stdout=subprocess.PIPE)
        result = process.stdout.readlines()
        tokens = re.search("i-[a-f0-9]*", str(result[1]))
        service_vm_name = tokens.group(0)
        print ("Image: %s instantiated successfully" % (service_vm_name))

    except Exception as exc:
        print exc

    service_logic.image_status(service_vm_name)
    print "Completed"
    print "Attaching Ports To VM Service interfaces"
    try:
        idx = 0
        for net in networks_name_list:
            network_id = net_list[net][servconts.NETWORK][servconts.ID]
            port_id = net_list[net][servconts.PORTS][idx]
            attachment = client.show_port_attachment(network_id, port_id)
            attachment = attachment[servconts.ATTACHMENT][servconts.ID][:36]
            LOG.debug("Plugging virtual interface: %s of VM %s \
                            into port: %s on network: %s" %
                            (attachment, service_vm_name, port_id, net))
            attach_data = {servconts.ATTACHMENT: {servconts.ID: '%s' %
                                                  attachment}}
            client.attach_resource(network_id, port_id, attach_data)
    except Exception as exc:
        print exc
    print "Completed"
    try:
        LOG.debug("Registering Service in DB")
        l2db.initialize()
        for uuid_net in db.network_id(networks_name_list[0]):
            mngnet_id = str(uuid_net.uuid)
        for uuid_net in db.network_id(networks_name_list[1]):
            nbnet_id = str(uuid_net.uuid)
        for uuid_net in db.network_id(networks_name_list[2]):
            sbnet_id = str(uuid_net.uuid)
        sdb.add_services_binding(service_vm_name, mngnet_id, nbnet_id,
                                 sbnet_id)
    except Exception as exc:
        print exc


def delete_service(tenant_id, service_instance_id, *args):
    """
    Removes a service and all the network configuration
    """
    l2db.initialize()
    print ("Terminating Service VM")
    service_logic = servlogcs.ServicesLogistics()
    vms_list = []
    vms_list.append(servconts.DELETE_VM_CMD)
    vms_list.append(service_instance_id)

    if not service_logic.image_exist(service_instance_id):
        print ("Service VM does not exist")
        sys.exit()

    result = subprocess.call(vms_list)
    service_logic.image_shutdown_verification(service_instance_id)

    client = Client(HOST, PORT, USE_SSL, format='json', tenant=tenant_id)
    service_nets = sdb.get_service_bindings(service_instance_id)
    print ("Terminating Ports and Networks")
    network_name = db.network_get(service_nets.mngnet_id)
    port_id_net = db.port_list(service_nets.mngnet_id)
    for ports_uuid in port_id_net:
        client.delete_port(service_nets.mngnet_id, ports_uuid.uuid)
    client.delete_network(service_nets.mngnet_id)
    network_name = db.network_get(service_nets.nbnet_id)
    port_id_net = db.port_list(service_nets.nbnet_id)
    for ports_uuid in port_id_net:
        client.delete_port(service_nets.nbnet_id, ports_uuid.uuid)
    client.delete_network(service_nets.nbnet_id)
    network_name = db.network_get(service_nets.sbnet_id)
    port_id_net = db.port_list(service_nets.sbnet_id)
    for ports_uuid in port_id_net:
        client.delete_port(service_nets.sbnet_id, ports_uuid.uuid)
    client.delete_network(service_nets.sbnet_id)
    service_list = sdb.remove_services_binding(service_instance_id)
    print ("Configuration Removed Successfully")


def disconnect_vm(vm_instance_id, *args):
    """
    Deletes VMs and Port connection
    """
    l2db.initialize()
    print ("Terminating Service VM")
    service_logic = servlogcs.ServicesLogistics()
    vms_list = []
    vms_list.append(servconts.DELETE_VM_CMD)
    vms_list.append(vm_instance_id)
    result = subprocess.call(vms_list)
    service_logic.image_shutdown_verification(vm_instance_id)
    print ("VM Server Off")


def connect_vm(tenant_id, vm_image_id, service_instance_id, *args):
    """
    Starts a VMs and is connected to southbound network
    """
    l2db.initialize()
    client = Client(HOST, PORT, USE_SSL, format='json', tenant=tenant_id)
    print ("Connecting %s to Service %s " % (vm_image_id, service_instance_id))
    service_logic = servlogcs.ServicesLogistics()
    service_nets = sdb.get_service_bindings(service_instance_id)
    client.create_port(service_nets.mngnet_id)
    client.create_port(service_nets.nbnet_id)
    sb_port_id = client.create_port(service_nets.sbnet_id)
    LOG.debug("Operation 'create_port' executed.")
    new_port_id = sb_port_id[servconts.PORT][servconts.ID]
    try:
        create_vm_args = []
        create_vm_args.append(servconts.CREATE_VM_CMD)
        create_vm_args.append(vm_image_id)
        print ("Creating VM with image: %s" % (vm_image_id))
        process = subprocess.Popen(create_vm_args, stdout=subprocess.PIPE)
        result = process.stdout.readlines()
        tokens = re.search("i-[a-f0-9]*", str(result[1]))
        vm_name = tokens.group(0)
        print ("Image: %s instantiated successfully" % (vm_name))
    except Exception as exc:
        print exc

    service_logic.image_status(vm_name)
    print "Completed"
    print "Attaching Ports To VM Service interfaces"
    south_net = service_nets.sbnet_id
    attachment = client.show_port_attachment(south_net, new_port_id)
    attachment = attachment[servconts.ATTACHMENT][servconts.ID][:36]
    LOG.debug("Plugging virtual interface: %s of VM %s \
                into port: %s on network: %s" %
                (attachment, vm_name, new_port_id, service_nets.sbnet_id))
    attach_data = {servconts.ATTACHMENT: {servconts.ID: '%s' % attachment}}
    client.attach_resource(service_nets.sbnet_id, new_port_id, attach_data)
    print ("Connect VM Ended")


def create_multiport(tenant_id, networks_list, *args):
    """Creates ports on a single host"""
    ports_info = {'multiport': \
                  {'status': 'ACTIVE',
                   'net_id_list': networks_list,
                   'ports_desc': {'key': 'value'}}}
    request_url = "/multiport"
    client = Client(HOST, PORT, USE_SSL, format='json', tenant=tenant_id,
                action_prefix=servconts.ACTION_PREFIX_CSCO)
    data = client.do_request('POST', request_url, body=ports_info)
    return data


def build_args(cmd, cmdargs, arglist):
    """Building the list of args for a particular CLI"""
    args = []
    orig_arglist = arglist[:]
    try:
        for cmdarg in cmdargs:
            args.append(arglist[0])
            del arglist[0]
    except:
        LOG.debug("Not enough arguments for \"%s\" (expected: %d, got: %d)"
                  % (cmd, len(cmdargs), len(orig_arglist)))
        print "Service Insertion Usage:\n    %s %s" % (cmd,
          " ".join(["<%s>" % y for y in SERVICE_COMMANDS[cmd]["args"]]))
        sys.exit()
    if len(arglist) > 0:
        LOG.debug("Too many arguments for \"%s\" (expected: %d, got: %d)" \
                  % (cmd, len(cmdargs), len(orig_arglist)))
        print "Service Insertion Usage:\n    %s %s" % (cmd,
          " ".join(["<%s>" % y for y in SERVICE_COMMANDS[cmd]["args"]]))
        sys.exit()
    return args


SERVICE_COMMANDS = {
  "insert_inpath_service": {
    "func": insert_inpath_service,
    "args": ["tenant_id", "service_image_id",
             "management_net_name", "northbound_net_name",
             "southbound_net_name"]},
  "delete_service": {
    "func": delete_service,
    "args": ["tenant_id", "service_instance_id"]},
  "connect_vm": {
    "func": connect_vm,
    "args": ["tenant_id", "vm_image_id",
             "service_instance_id"]},
  "disconnect_vm": {
    "func": disconnect_vm,
    "args": ["vm_instance_id"]}}


if __name__ == "__main__":
    os.system("clear")
    usagestr = "Usage: %prog [OPTIONS] <command> [args]"
    PARSER = OptionParser(usage=usagestr)
    PARSER.add_option("-H", "--host", dest="host",
      type="string", default="127.0.0.1", help="ip address of api host")
    PARSER.add_option("-p", "--port", dest="port",
      type="int", default=9696, help="api port")
    PARSER.add_option("-s", "--ssl", dest="ssl",
      action="store_true", default=False, help="use ssl")
    PARSER.add_option("-v", "--verbose", dest="verbose",
      action="store_true", default=False, help="turn on verbose logging")
    PARSER.add_option("-f", "--logfile", dest="logfile",
      type="string", default="syslog", help="log file path")
    options, args = PARSER.parse_args()
    if options.verbose:
        LOG.setLevel(logging.DEBUG)
    else:
        LOG.setLevel(logging.WARN)
    if options.logfile == "syslog":
        LOG.addHandler(logging.handlers.SysLogHandler(address='/dev/log'))
    else:
        LOG.addHandler(logging.handlers.WatchedFileHandler(options.logfile))
        os.chmod(options.logfile, 0644)
    service_logic = servlogcs.ServicesLogistics()
    HOST = options.host
    PORT = options.port
    USE_SSL = options.ssl
    CMD = args[0]
    args = build_args(CMD, SERVICE_COMMANDS[CMD]["args"], args[1:])
    SERVICE_COMMANDS[CMD]["func"](*args)
    sys.exit(0)
