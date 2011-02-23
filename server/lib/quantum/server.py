#!/usr/bin/env python
# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2011 Nicira Neworks, Inc.
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

# If ../quantum/__init__.py exists, add ../ to Python search path, so that
# it will override what happens to be installed in /usr/(local/)lib/python...

import gettext
import optparse
import os
import sys


possible_topdir = os.path.normpath(os.path.join(os.path.abspath(sys.argv[0]),
                                   os.pardir,
                                   os.pardir))
if os.path.exists(os.path.join(possible_topdir, 'quantum', '__init__.py')):
    sys.path.insert(0, possible_topdir)

gettext.install('quantum', unicode=1)

from quantum import service
from quantum.common import config


def create_options(parser):
    """
    Sets up the CLI and config-file options that may be
    parsed and program commands.
    :param parser: The option parser
    """
    config.add_common_options(parser)
    config.add_log_options(parser)


def main():
    oparser = optparse.OptionParser(version='%%prog VERSION')
    create_options(oparser)
    (options, args) = config.parse_options(oparser)

    try:
        quantum_service = service.serve_wsgi(service.QuantumApiService,
                                     options=options,
                                     args=args)
        quantum_service.wait()
    except RuntimeError, e:
        sys.exit("ERROR: %s" % e)

if __name__ == "__main__":
    main()
