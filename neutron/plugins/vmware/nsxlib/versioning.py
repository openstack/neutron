# Copyright 2014 VMware, Inc.
# All Rights Reserved
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

import inspect

from neutron.plugins.vmware.api_client import exception

DEFAULT_VERSION = -1


def versioned(func_table):

    def versioned_function(wrapped_func):
        func_name = wrapped_func.__name__

        def dispatch_versioned_function(cluster, *args, **kwargs):
            # Call the wrapper function, in case we need to
            # run validation checks regarding versions. It
            # should return the NSX version
            v = (wrapped_func(cluster, *args, **kwargs) or
                 cluster.api_client.get_version())
            func = get_function_by_version(func_table, func_name, v)
            func_kwargs = kwargs
            arg_spec = inspect.getargspec(func)
            if not arg_spec.keywords and not arg_spec.varargs:
                # drop args unknown to function from func_args
                arg_set = set(func_kwargs.keys())
                for arg in arg_set - set(arg_spec.args):
                    del func_kwargs[arg]
            # NOTE(salvatore-orlando): shall we fail here if a required
            # argument is not passed, or let the called function raise?
            return func(cluster, *args, **func_kwargs)

        return dispatch_versioned_function
    return versioned_function


def get_function_by_version(func_table, func_name, ver):
    if ver:
        if ver.major not in func_table[func_name]:
            major = max(func_table[func_name].keys())
            minor = max(func_table[func_name][major].keys())
            if major > ver.major:
                raise NotImplementedError(_("Operation may not be supported"))
        else:
            major = ver.major
            minor = ver.minor
            if ver.minor not in func_table[func_name][major]:
                minor = DEFAULT_VERSION
        return func_table[func_name][major][minor]
    else:
        msg = _('NSX version is not set. Unable to complete request '
                'correctly. Check log for NSX communication errors.')
        raise exception.ServiceUnavailable(message=msg)
