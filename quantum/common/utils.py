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


import ConfigParser
import logging
import os
import subprocess

from quantum.common import exceptions as exception
from quantum.common.exceptions import ProcessExecutionError
from quantum.common import flags


TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
FLAGS = flags.FLAGS


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


def execute(cmd, process_input=None, addl_env=None, check_exit_code=True):
    logging.debug("Running cmd: %s", cmd)
    env = os.environ.copy()
    if addl_env:
        env.update(addl_env)
    obj = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           env=env)
    result = None
    if process_input is not None:
        result = obj.communicate(process_input)
    else:
        result = obj.communicate()
    obj.stdin.close()
    if obj.returncode:
        logging.debug("Result was %s" % (obj.returncode))
        if check_exit_code and obj.returncode != 0:
            (stdout, stderr) = result
            raise ProcessExecutionError(exit_code=obj.returncode,
                                        stdout=stdout,
                                        stderr=stderr,
                                        cmd=cmd)
    return result


def get_plugin_from_config(file="config.ini"):
    Config = ConfigParser.ConfigParser()
    Config.read(file)
    return Config.get("PLUGIN", "provider")


class LazyPluggable(object):
    """A pluggable backend loaded lazily based on some value."""

    def __init__(self, pivot, **backends):
        self.__backends = backends
        self.__pivot = pivot
        self.__backend = None

    def __get_backend(self):
        if not self.__backend:
            backend_name = self.__pivot.value
            if backend_name not in self.__backends:
                raise exception.Error('Invalid backend: %s' % backend_name)

            backend = self.__backends[backend_name]
            if isinstance(backend, tuple):
                name = backend[0]
                fromlist = backend[1]
            else:
                name = backend
                fromlist = backend

            self.__backend = __import__(name, None, None, fromlist)
            logging.info('backend %s', self.__backend)
        return self.__backend

    def __getattr__(self, key):
        backend = self.__get_backend()
        return getattr(backend, key)
