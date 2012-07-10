# Copyright (C) 2009-2012 Nicira Networks, Inc. All Rights Reserved.
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

import logging
from optparse import OptionParser
import os
import sys

from quantum.plugins.nicira.nicira_nvp_plugin import nvplib
from quantum.plugins.nicira.nicira_nvp_plugin.QuantumPlugin import (
    NvpPlugin as QuantumManager,
)


logging.basicConfig(level=logging.INFO)
LOG = logging.getLogger('nvp-plugin-cli')


def print_help():
    """Help for CLI"""
    print "\nNVP Plugin Commands:"
    for key in COMMANDS.keys():
        print ("    %s %s" %
              (key, " ".join(["<%s>" % y for y in COMMANDS[key]["args"]])))


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
        print ("Usage:\n    %s %s" %
              (cmd, " ".join(["<%s>" % y for y in COMMANDS[cmd]["args"]])))
        sys.exit()
    if len(arglist) > 0:
        LOG.error("Too many arguments for \"%s\" (expected: %d, got: %d)" % (
                  cmd, len(cmdargs), len(orig_arglist)))
        print ("Usage:\n    %s %s" %
              (cmd, " ".join(["<%s>" % y for y in COMMANDS[cmd]["args"]])))
        sys.exit()
    return args


def check_config(manager):
    """A series of checks to make sure the plugin is correctly configured."""
    checks = [{"function": nvplib.check_default_transport_zone,
               "desc": "Transport zone check:"}]
    any_failed = False
    for c in checks:
        result, msg = "PASS", ""
        try:
            c["function"]()
        except Exception, e:
            any_failed = True
            result = "FAIL"
            msg = "(%s)" % str(e)
        print "%s %s%s" % (c["desc"], result, msg)
    sys.exit({False: 0, True: 1}[any_failed])


COMMANDS = {
    "check_config": {
        "need_login": True,
        "func": check_config,
        "args": []
    },
}


def main():
    usagestr = "Usage: %prog [OPTIONS] <command> [args]"
    PARSER = OptionParser(usage=usagestr)
    PARSER.add_option("-v", "--verbose", dest="verbose",
                      action="store_true", default=False,
                      help="turn on verbose logging")
    PARSER.add_option("-c", "--configfile", dest="configfile", type="string",
                      default="/etc/quantum/plugins/nvp/nvp.ini",
                      help="nvp plugin config file path (nvp.ini)")
    options, args = PARSER.parse_args()

    loglevel = logging.INFO
    if options.verbose:
        loglevel = logging.DEBUG

    LOG.setLevel(loglevel)

    if len(args) < 1:
        PARSER.print_help()
        print_help()
        sys.exit(1)

    CMD = args[0]
    if CMD not in COMMANDS.keys():
        LOG.error("Unknown command: %s" % CMD)
        print_help()
        sys.exit(1)

    args = build_args(CMD, COMMANDS[CMD]["args"], args[1:])

    LOG.debug("Executing command \"%s\" with args: %s" % (CMD, args))

    manager = None
    if COMMANDS[CMD]["need_login"] is True:
        if not os.path.exists(options.configfile):
            LOG.error("NVP plugin configuration file \"%s\" doesn't exist!" %
                      options.configfile)
            sys.exit(1)
        manager = QuantumManager(options.configfile, loglevel, cli=True)

    COMMANDS[CMD]["func"](manager, *args)

    sys.exit(0)

if __name__ == "__main__":
    main()
