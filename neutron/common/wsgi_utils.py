# Copyright (c) 2024 Red Hat, Inc.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from oslo_utils import timeutils

from neutron.common import utils


FIRST_WORKER_ID = 1


def get_start_time(default=None, current_time=False):
    """Return the 'start-time=%t' config varible in the WSGI config

    This variable contains the start time of the WSGI server. Check
    https://uwsgi-docs.readthedocs.io/en/latest/Configuration.html
    #magic-variables

    :param default: (int or float) in case the uwsgi option 'start-time' is not
                    available or the uwsgi module cannot be loaded, the method
                    will return this value.
    :param current_time: (bool) if ``default`` is None and this flag is set,
                         the method will return the current time.
    :return: (int) start time in seconds.
    """
    if not default and current_time:
        default = utils.datetime_to_ts(timeutils.utcnow())
    default = int(default) if default else None
    try:
        # pylint: disable=import-outside-toplevel
        import uwsgi
        start_time = uwsgi.opt.get('start-time')
        if not start_time:
            return default
        return int(start_time.decode(encoding='utf-8'))
    except ImportError:
        return default


def get_api_worker_id() -> int | None:
    """Return the worker ID number provided by uWSGI"""
    try:
        # pylint: disable=import-outside-toplevel
        import uwsgi
        return uwsgi.worker_id()
    except ImportError:
        return None
