# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2011, Nicira Networks, Inc.
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
# Borrowed from nova code base, more utilities will be added/borrowed as and
# when needed.
# @author: Somik Behera, Nicira Networks, Inc.

"""Utilities and helper functions."""


import logging
import os
import signal
import uuid

from eventlet.green import subprocess

from quantum.openstack.common import cfg

TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def boolize(subject):
    """
    Quak like a boolean
    """
    if isinstance(subject, bool):
        return subject
    elif isinstance(subject, basestring):
        sub = subject.strip().lower()
        if sub == 'true':
            return True
        elif sub == 'false':
            return False
    return subject


def read_cached_file(filename, cache_info, reload_func=None):
    """Read from a file if it has been modified.

    :param cache_info: dictionary to hold opaque cache.
    :param reload_func: optional function to be called with data when
                        file is reloaded due to a modification.

    :returns: data from file

    """
    mtime = os.path.getmtime(filename)
    if not cache_info or mtime != cache_info.get('mtime'):
        logging.debug(_("Reloading cached file %s") % filename)
        with open(filename) as fap:
            cache_info['data'] = fap.read()
        cache_info['mtime'] = mtime
        if reload_func:
            reload_func(cache_info['data'])
    return cache_info['data']


def find_config_file(options, config_file):
    """
    Return the first config file found.

    We search for the paste config file in the following order:
    * If --config-file option is used, use that
    * Search for the configuration files via common cfg directories
    :retval Full path to config file, or None if no config file found
    """
    fix_path = lambda p: os.path.abspath(os.path.expanduser(p))
    if options.get('config_file'):
        if os.path.exists(options['config_file']):
            return fix_path(options['config_file'])

    dir_to_common = os.path.dirname(os.path.abspath(__file__))
    root = os.path.join(dir_to_common, '..', '..', '..', '..')
    # Handle standard directory search for the config file
    config_file_dirs = [fix_path(os.path.join(os.getcwd(), 'etc')),
                        fix_path(os.path.join('~', '.quantum-venv', 'etc',
                                              'quantum')),
                        fix_path('~'),
                        os.path.join(cfg.CONF.state_path, 'etc'),
                        os.path.join(cfg.CONF.state_path, 'etc', 'quantum'),
                        fix_path(os.path.join('~', '.local',
                                              'etc', 'quantum')),
                        '/usr/etc/quantum',
                        '/usr/local/etc/quantum',
                        '/etc/quantum/',
                        '/etc']

    if 'plugin' in options:
        config_file_dirs = [
            os.path.join(x, 'quantum', 'plugins', options['plugin'])
            for x in config_file_dirs
        ]

    if os.path.exists(os.path.join(root, 'plugins')):
        plugins = [fix_path(os.path.join(root, 'plugins', p, 'etc'))
                   for p in os.listdir(os.path.join(root, 'plugins'))]
        plugins = [p for p in plugins if os.path.isdir(p)]
        config_file_dirs.extend(plugins)

    for cfg_dir in config_file_dirs:
        cfg_file = os.path.join(cfg_dir, config_file)
        if os.path.exists(cfg_file):
            return cfg_file


def str_uuid():
    """Return a uuid as a string"""
    return str(uuid.uuid4())


def _subprocess_setup():
    # Python installs a SIGPIPE handler by default. This is usually not what
    # non-Python subprocesses expect.
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)


def subprocess_popen(args, stdin=None, stdout=None, stderr=None, shell=False,
                     env=None):
    return subprocess.Popen(args, shell=shell, stdin=stdin, stdout=stdout,
                            stderr=stderr, preexec_fn=_subprocess_setup,
                            env=env)
