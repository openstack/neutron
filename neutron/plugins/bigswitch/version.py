#!/usr/bin/env python
# Copyright 2012 OpenStack Foundation
# Copyright 2012, Big Switch Networks, Inc.
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

"""Determine version of NeutronRestProxy plugin"""
from __future__ import print_function

from neutron.plugins.bigswitch import vcsversion


YEAR, COUNT, REVISION = vcsversion.NEUTRONRESTPROXY_VERSION


def canonical_version_string():
    return '.'.join(filter(None,
                           vcsversion.NEUTRONRESTPROXY_VERSION))


def version_string():
    if vcsversion.FINAL:
        return canonical_version_string()
    else:
        return '%s-dev' % (canonical_version_string(),)


def vcs_version_string():
    return "%s:%s" % (vcsversion.version_info['branch_nick'],
                      vcsversion.version_info['revision_id'])


def version_string_with_vcs():
    return "%s-%s" % (canonical_version_string(), vcs_version_string())


if __name__ == "__main__":
    print(version_string_with_vcs())
