# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (c) 2012 OpenStack, LLC.
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

"""
Policy engine for quantum.  Largely copied from nova.
"""

import os.path

from quantum.common import exceptions
from quantum.openstack.common import cfg
import quantum.common.utils as utils
from quantum.openstack.common import policy


_POLICY_PATH = None
_POLICY_CACHE = {}


def reset():
    global _POLICY_PATH
    _POLICY_PATH = None
    _POLICY_CACHE = {}
    policy.reset()


def init():
    global _POLICY_PATH
    global _POLICY_CACHE
    if not _POLICY_PATH:
        _POLICY_PATH = utils.find_config_file({}, cfg.CONF.policy_file)
        if not _POLICY_PATH:
            raise exceptions.PolicyNotFound(path=cfg.CONF.policy_file)
    # pass _set_brain to read_cached_file so that the policy brain
    # is reset only if the file has changed
    utils.read_cached_file(_POLICY_PATH, _POLICY_CACHE,
                           reload_func=_set_brain)


def _set_brain(data):
    default_rule = 'default'
    policy.set_brain(policy.Brain.load_json(data, default_rule))


def check(context, action, target):
    """Verifies that the action is valid on the target in this context.

    :param context: quantum context
    :param action: string representing the action to be checked
        this should be colon separated for clarity.
    :param object: dictionary representing the object of the action
        for object creation this should be a dictionary representing the
        location of the object e.g. ``{'project_id': context.project_id}``

    :return: Returns True if access is permitted else False.
    """
    init()
    match_list = ('rule:%s' % action,)
    credentials = context.to_dict()
    return policy.enforce(match_list, target, credentials)


def enforce(context, action, target):
    """Verifies that the action is valid on the target in this context.

    :param context: quantum context
    :param action: string representing the action to be checked
        this should be colon separated for clarity.
    :param object: dictionary representing the object of the action
        for object creation this should be a dictionary representing the
        location of the object e.g. ``{'project_id': context.project_id}``

    :raises quantum.exceptions.PolicyNotAllowed: if verification fails.
    """

    init()

    match_list = ('rule:%s' % action,)
    credentials = context.to_dict()

    policy.enforce(match_list, target, credentials,
                   exceptions.PolicyNotAuthorized, action=action)
