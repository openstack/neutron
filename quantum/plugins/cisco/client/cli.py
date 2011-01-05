"""
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
# Initial structure and framework of this CLI has been borrowed from Quantum,
# written by the following authors
# @author: Somik Behera, Nicira Networks, Inc.
# @author: Brad Hall, Nicira Networks, Inc.
# @author: Salvatore Orlando, Citrix
#
# Cisco adaptation for extensions
# @author: Sumit Naiksatam, Cisco Systems, Inc.
# @author: Ying Liu, Cisco Systems, Inc.
#
"""

import gettext
import logging
import logging.handlers
import os
import sys
import subprocess

from optparse import OptionParser

sys.path.append(os.getcwd())
import quantum.client.cli as qcli

POSSIBLE_TOPDIR = os.path.normpath(os.path.join(os.path.abspath(sys.argv[0]),
                                   os.pardir,
                                   os.pardir))
if os.path.exists(os.path.join(POSSIBLE_TOPDIR, 'quantum', '__init__.py')):
    sys.path.insert(0, POSSIBLE_TOPDIR)

gettext.install('quantum', unicode=1)

from quantum.client import Client

from quantum.plugins.cisco.common import cisco_constants as const

LOG = logging.getLogger('quantum')
FORMAT = 'json'
ACTION_PREFIX_EXT = '/v1.0'
ACTION_PREFIX_CSCO = ACTION_PREFIX_EXT + \
        '/extensions/csco/tenants/{tenant_id}'
TENANT_ID = 'nova'
CSCO_EXT_NAME = 'Cisco Nova Tenant'


def help():
    """Help for CLI"""
    print "\nCisco Extension Commands:"
    for key in COMMANDS.keys():
        print "    %s %s" % (key,
          " ".join(["<%s>" % y for y in COMMANDS[key]["args"]]))


def build_args(cmd, cmdargs, arglist):
    """Building the list of args for a particular CLI"""
    args = []
    orig_arglist = arglist[:]
    try:
        for cmdarg in cmdargs:
            args.append(arglist[0])
            del arglist[0]
    except:
        LOG.error("Not enough arguments for \"%s\" (expected: %d, got: %d)" % (
          cmd, len(cmdargs), len(orig_arglist)))
        print "Usage:\n    %s %s" % (cmd,
          " ".join(["<%s>" % y for y in COMMANDS[cmd]["args"]]))
        sys.exit()
    if len(arglist) > 0:
        LOG.error("Too many arguments for \"%s\" (expected: %d, got: %d)" % (
          cmd, len(cmdargs), len(orig_arglist)))
        print "Usage:\n    %s %s" % (cmd,
          " ".join(["<%s>" % y for y in COMMANDS[cmd]["args"]]))
        sys.exit()
    return args


def list_extensions(*args):
    """Invoking the action to get the supported extensions"""
    request_url = "/extensions"
    client = Client(HOST, PORT, USE_SSL, format='json',
                    action_prefix=ACTION_PREFIX_EXT, tenant="dummy")
    data = client.do_request('GET', request_url)
    print("Obtained supported extensions from Quantum: %s" % data)


def schedule_host(tenant_id, instance_id, user_id=None):
    """Gets the host name from the Quantum service"""
    project_id = tenant_id

    instance_data_dict = \
            {'novatenant': \
             {'instance_id': instance_id,
              'instance_desc': \
              {'user_id': user_id,
               'project_id': project_id}}}

    request_url = "/novatenants/" + project_id + "/schedule_host"
    client = Client(HOST, PORT, USE_SSL, format='json', tenant=TENANT_ID,
                    action_prefix=ACTION_PREFIX_CSCO)
    data = client.do_request('PUT', request_url, body=instance_data_dict)

    hostname = data["host_list"]["host_1"]
    if not hostname:
        print("Scheduler was unable to locate a host" + \
              " for this request. Is the appropriate" + \
              " service running?")

    print("Quantum service returned host: %s" % hostname)


def create_multiport(tenant_id, net_id_list, *args):
    """Creates ports on a single host"""
    net_list = net_id_list.split(",")
    ports_info = {'multiport': \
                  {'status': 'ACTIVE',
                   'net_id_list': net_list,
                   'ports_desc': {'key': 'value'}}}

    request_url = "/multiport"
    client = Client(HOST, PORT, USE_SSL, format='json', tenant=tenant_id,
                    action_prefix=ACTION_PREFIX_CSCO)
    data = client.do_request('POST', request_url, body=ports_info)

    print("Created ports: %s" % data)


COMMANDS = {
  "create_multiport": {
    "func": create_multiport,
    "args": ["tenant-id",
             "net-id-list (comma separated list of netword IDs)"]},
  "list_extensions": {
    "func": list_extensions,
    "args": []},
  "schedule_host": {
    "func": schedule_host,
    "args": ["tenant-id", "instance-id"]}, }


def main():
    import cli
    usagestr = "Usage: %prog [OPTIONS] <command> [args]"
    PARSER = OptionParser(usage=usagestr)
    PARSER.add_option("-H", "--host", dest="host",
      type="string", default="127.0.0.1", help="ip address of api host")
    PARSER.add_option("-p", "--port", dest="port",
      type="int", default=9696, help="api poort")
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

    if len(args) < 1:
        PARSER.print_help()
        qcli.help()
        help()
        sys.exit(1)

    CMD = args[0]
    if CMD in qcli.commands.keys():
        qcli.main()
        sys.exit(1)
    if CMD not in COMMANDS.keys():
        LOG.error("Unknown command: %s" % CMD)
        qcli.help()
        help()
        sys.exit(1)

    args = build_args(CMD, COMMANDS[CMD]["args"], args[1:])

    LOG.info("Executing command \"%s\" with args: %s" % (CMD, args))

    HOST = options.host
    PORT = options.port
    USE_SSL = options.ssl
    COMMANDS[CMD]["func"](*args)

    LOG.info("Command execution completed")
    sys.exit(0)


if __name__ == "__main__":
    main()
