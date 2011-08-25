# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2011 Nicira Networks, Inc.
# Copyright 2011 Citrix Systems
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
# @author: Somik Behera, Nicira Networks, Inc.
# @author: Brad Hall, Nicira Networks, Inc.
# @author: Salvatore Orlando, Citrix

import Cheetah.Template as cheetah_template
import logging
import os
import sys

from client import Client
from optparse import OptionParser

FORMAT = "json"
CLI_TEMPLATE = "../quantum/cli_output.template"
LOG = logging.getLogger('cli')


def _handle_exception(ex):
    status_code = None
    message = None
    # Retrieve dict at 1st element of tuple at last argument
    if ex.args and isinstance(ex.args[-1][0], dict):
        status_code = ex.args[-1][0].get('status_code', None)
        message = ex.args[-1][0].get('message', None)
    msg_1 = "Command failed with error code: %s" % (status_code or '<missing>')
    msg_2 = "Error message:%s" % (message or '<missing>')
    LOG.exception(msg_1 + "-" + msg_2)
    print msg_1
    print msg_2


def prepare_output(cmd, tenant_id, response):
    """ Fills a cheetah template with the response """
    #add command and tenant to response for output generation
    response['cmd'] = cmd
    response['tenant_id'] = tenant_id
    template_file = open(CLI_TEMPLATE).read()
    output = str(cheetah_template.Template(template_file,
                                           searchList=response))
    LOG.debug("Finished preparing output for command:%s", cmd)
    return output


def list_nets(client, *args):
    tenant_id = args[0]
    res = client.list_networks()
    LOG.debug("Operation 'list_networks' executed.")
    output = prepare_output("list_nets", tenant_id, res)
    print output


def create_net(client, *args):
    tenant_id, name = args
    data = {'network': {'net-name': name}}
    new_net_id = None
    try:
        res = client.create_network(data)
        new_net_id = res["networks"]["network"]["id"]
        LOG.debug("Operation 'create_network' executed.")
        output = prepare_output("create_net", tenant_id,
                                dict(network_id=new_net_id))
        print output
    except Exception as ex:
        _handle_exception(ex)


def delete_net(client, *args):
    tenant_id, network_id = args
    try:
        client.delete_network(network_id)
        LOG.debug("Operation 'delete_network' executed.")
        output = prepare_output("delete_net", tenant_id,
                            dict(network_id=network_id))
        print output
    except Exception as ex:
        _handle_exception(ex)


def detail_net(client, *args):
    tenant_id, network_id = args
    try:
        res = client.list_network_details(network_id)["networks"]["network"]
        LOG.debug("Operation 'list_network_details' executed.")
        ports = client.list_ports(network_id)
        LOG.debug("Operation 'list_ports' executed.")
        res['ports'] = ports
        for port in ports["ports"]:
            att_data = client.list_port_attachments(network_id, port['id'])
            LOG.debug("Operation 'list_attachments' executed.")
            port['attachment'] = att_data["attachment"]

        output = prepare_output("detail_net", tenant_id, dict(network=res))
        print output
    except Exception as ex:
        _handle_exception(ex)


def rename_net(client, *args):
    tenant_id, network_id, name = args
    data = {'network': {'net-name': '%s' % name}}
    try:
        client.update_network(network_id, data)
        LOG.debug("Operation 'update_network' executed.")
        # Response has no body. Use data for populating output
        data['network']['id'] = network_id
        output = prepare_output("rename_net", tenant_id, data)
        print output
    except Exception as ex:
        _handle_exception(ex)


def list_ports(client, *args):
    tenant_id, network_id = args
    try:
        ports = client.list_ports(network_id)
        LOG.debug("Operation 'list_ports' executed.")
        data = ports
        data['network_id'] = network_id
        output = prepare_output("list_ports", tenant_id, data)
        print output
    except Exception as ex:
        _handle_exception(ex)


def create_port(client, *args):
    tenant_id, network_id = args
    try:
        res = client.create_port(network_id)
        LOG.debug("Operation 'create_port' executed.")
        new_port_id = res["ports"]["port"]["id"]
        output = prepare_output("create_port", tenant_id,
                                dict(network_id=network_id,
                                     port_id=new_port_id))
        print output
    except Exception as ex:
        _handle_exception(ex)


def delete_port(client, *args):
    tenant_id, network_id, port_id = args
    try:
        client.delete_port(network_id, port_id)
        LOG.debug("Operation 'delete_port' executed.")
        output = prepare_output("delete_port", tenant_id,
                                dict(network_id=network_id,
                                     port_id=port_id))
        print output
    except Exception as ex:
        _handle_exception(ex)
        return


def detail_port(client, *args):
    tenant_id, network_id, port_id = args
    try:
        port = client.list_port_details(network_id, port_id)["port"]
        LOG.debug("Operation 'list_port_details' executed.")
        #NOTE(salvatore-orland): current API implementation does not
        #return attachment with GET operation on port. Once API alignment
        #branch is merged, update client to use the detail action
        port['attachment'] = '<unavailable>'
        output = prepare_output("detail_port", tenant_id,
                                dict(network_id=network_id,
                                     port=port))
        print output
    except Exception as ex:
        _handle_exception(ex)


def set_port_state(client, *args):
    tenant_id, network_id, port_id, new_state = args
    data = {'port': {'port-state': '%s' % new_state}}
    try:
        client.set_port_state(network_id, port_id, data)
        LOG.debug("Operation 'set_port_state' executed.")
        # Response has no body. Use data for populating output
        data['network_id'] = network_id
        data['port']['id'] = port_id
        output = prepare_output("set_port_state", tenant_id, data)
        print output
    except Exception as ex:
        _handle_exception(ex)


def plug_iface(client, *args):
    tenant_id, network_id, port_id, attachment = args
    try:
        data = {'port': {'attachment': '%s' % attachment}}
        client.attach_resource(network_id, port_id, data)
        LOG.debug("Operation 'attach_resource' executed.")
        output = prepare_output("plug_interface", tenant_id,
                                dict(network_id=network_id,
                                     port_id=port_id,
                                     attachment=attachment))
        print output
    except Exception as ex:
        _handle_exception(ex)


def unplug_iface(client, *args):
    tenant_id, network_id, port_id = args
    try:
        client.detach_resource(network_id, port_id)
        LOG.debug("Operation 'detach_resource' executed.")
        output = prepare_output("unplug_interface", tenant_id,
                                dict(network_id=network_id,
                                     port_id=port_id))
        print output
    except Exception as ex:
        _handle_exception(ex)


commands = {
  "list_nets": {
    "func": list_nets,
    "args": ["tenant-id"]},
  "create_net": {
    "func": create_net,
    "args": ["tenant-id", "net-name"]},
  "delete_net": {
    "func": delete_net,
    "args": ["tenant-id", "net-id"]},
  "detail_net": {
    "func": detail_net,
    "args": ["tenant-id", "net-id"]},
  "rename_net": {
    "func": rename_net,
    "args": ["tenant-id", "net-id", "new-name"]},
  "list_ports": {
    "func": list_ports,
    "args": ["tenant-id", "net-id"]},
  "create_port": {
    "func": create_port,
    "args": ["tenant-id", "net-id"]},
  "delete_port": {
    "func": delete_port,
    "args": ["tenant-id", "net-id", "port-id"]},
  "set_port_state": {
    "func": set_port_state,
    "args": ["tenant-id", "net-id", "port-id", "new_state"]},
  "detail_port": {
    "func": detail_port,
    "args": ["tenant-id", "net-id", "port-id"]},
  "plug_iface": {
    "func": plug_iface,
    "args": ["tenant-id", "net-id", "port-id", "iface-id"]},
  "unplug_iface": {
    "func": unplug_iface,
    "args": ["tenant-id", "net-id", "port-id"]}, }


def help():
    print "\nCommands:"
    for k in commands.keys():
        print "    %s %s" % (k,
          " ".join(["<%s>" % y for y in commands[k]["args"]]))


def build_args(cmd, cmdargs, arglist):
    args = []
    orig_arglist = arglist[:]
    try:
        for x in cmdargs:
            args.append(arglist[0])
            del arglist[0]
    except:
        LOG.error("Not enough arguments for \"%s\" (expected: %d, got: %d)" % (
          cmd, len(cmdargs), len(orig_arglist)))
        print "Usage:\n    %s %s" % (cmd,
          " ".join(["<%s>" % y for y in commands[cmd]["args"]]))
        return None
    if len(arglist) > 0:
        LOG.error("Too many arguments for \"%s\" (expected: %d, got: %d)" % (
          cmd, len(cmdargs), len(orig_arglist)))
        print "Usage:\n    %s %s" % (cmd,
          " ".join(["<%s>" % y for y in commands[cmd]["args"]]))
        return None
    return args


if __name__ == "__main__":
    usagestr = "Usage: %prog [OPTIONS] <command> [args]"
    parser = OptionParser(usage=usagestr)
    parser.add_option("-H", "--host", dest="host",
      type="string", default="127.0.0.1", help="ip address of api host")
    parser.add_option("-p", "--port", dest="port",
      type="int", default=9696, help="api poort")
    parser.add_option("-s", "--ssl", dest="ssl",
      action="store_true", default=False, help="use ssl")
    parser.add_option("-v", "--verbose", dest="verbose",
      action="store_true", default=False, help="turn on verbose logging")
    parser.add_option("-lf", "--logfile", dest="logfile",
      type="string", default="syslog", help="log file path")
    options, args = parser.parse_args()

    if options.verbose:
        LOG.setLevel(logging.DEBUG)
    else:
        LOG.setLevel(logging.WARN)
    #logging.handlers.WatchedFileHandler

    if options.logfile == "syslog":
        LOG.addHandler(logging.handlers.SysLogHandler(address='/dev/log'))
    else:
        LOG.addHandler(logging.handlers.WatchedFileHandler(options.logfile))
        # Set permissions on log file
        os.chmod(options.logfile, 0644)

    if len(args) < 1:
        parser.print_help()
        help()
        sys.exit(1)

    cmd = args[0]
    if cmd not in commands.keys():
        LOG.error("Unknown command: %s" % cmd)
        help()
        sys.exit(1)

    args = build_args(cmd, commands[cmd]["args"], args[1:])
    if not args:
        sys.exit(1)
    LOG.info("Executing command \"%s\" with args: %s" % (cmd, args))

    client = Client(options.host, options.port, options.ssl,
                    args[0], FORMAT)
    commands[cmd]["func"](client, *args)

    LOG.info("Command execution completed")
    sys.exit(0)
