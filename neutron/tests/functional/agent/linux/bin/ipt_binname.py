#! /usr/bin/env python

# Copyright (C) 2014 VA Linux Systems Japan K.K.
# Copyright (C) 2014 YAMAMOTO Takashi <yamamoto at valinux co jp>
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

from __future__ import print_function

import sys

import eventlet


def print_binary_name():
    # NOTE(yamamoto): Don't move this import to module-level.
    # The aim is to test importing from eventlet non-main thread.
    # See Bug #1367075 for details.
    from neutron.agent.linux import iptables_manager

    print(iptables_manager.binary_name)


if __name__ == "__main__":
    if 'spawn' in sys.argv:
        eventlet.spawn(print_binary_name).wait()
    else:
        print_binary_name()
