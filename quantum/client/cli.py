#!/usr/bin/env python
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

import gettext
import logging
import logging.handlers
import os
import sys

from optparse import OptionParser


possible_topdir = os.path.normpath(os.path.join(os.path.abspath(sys.argv[0]),
                                   os.pardir,
                                   os.pardir))
if os.path.exists(os.path.join(possible_topdir, 'quantum', '__init__.py')):
    sys.path.insert(0, possible_topdir)

gettext.install('quantum', unicode=1)

from quantum.client import cli_lib
from quantum.client import Client

#Configure logger for client - cli logger is a child of it
#NOTE(salvatore-orlando): logger name does not map to package
#this is deliberate. Simplifies logger configuration
LOG = logging.getLogger('quantum')
FORMAT = 'json'
commands = {
  "list_nets": {
    "func": cli_lib.list_nets,
    "args": ["tenant-id"]},
  "create_net": {
    "func": cli_lib.create_net,
    "args": ["tenant-id", "net-name"]},
  "delete_net": {
    "func": cli_lib.delete_net,
    "args": ["tenant-id", "net-id"]},
  "show_net": {
    "func": cli_lib.show_net,
    "args": ["tenant-id", "net-id"]},
  "update_net": {
    "func": cli_lib.update_net,
    "args": ["tenant-id", "net-id", "new-name"]},
  "list_ports": {
    "func": cli_lib.list_ports,
    "args": ["tenant-id", "net-id"]},
  "create_port": {
    "func": cli_lib.create_port,
    "args": ["tenant-id", "net-id"]},
  "delete_port": {
    "func": cli_lib.delete_port,
    "args": ["tenant-id", "net-id", "port-id"]},
  "update_port": {
    "func": cli_lib.update_port,
    "args": ["tenant-id", "net-id", "port-id", "params"]},
  "show_port": {
    "func": cli_lib.show_port,
    "args": ["tenant-id", "net-id", "port-id"]},
  "plug_iface": {
    "func": cli_lib.plug_iface,
    "args": ["tenant-id", "net-id", "port-id", "iface-id"]},
  "unplug_iface": {
    "func": cli_lib.unplug_iface,
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


def main():
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
    parser.add_option("-f", "--logfile", dest="logfile",
      type="string", default="syslog", help="log file path")
    parser.add_option("-t", "--token", dest="token",
      type="string", default=None, help="authentication token")
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
                    args[0], FORMAT,
                    auth_token=options.token)
    commands[cmd]["func"](client, *args)

    LOG.info("Command execution completed")
    sys.exit(0)
