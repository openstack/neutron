# Copyright (c) 2016 OpenStack Foundation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from oslo_log import log as logging
import oslo_messaging
from oslo_utils import excutils

LOG = logging.getLogger(__name__)


def _call_with_retry(max_attempts):
    """A wrapper to retry a function using rpc call in case of
       MessagingException.

    Retries the decorated function in case of MessagingException of some kind
    (a timeout, client send error etc).
    If maximum attempts are exceeded, the exception which occurred during last
    attempt is reraised.
    """
    def wrapper(f):
        def func_wrapper(*args, **kwargs):
            # (ivasilevskaya) think of a more informative data to log
            action = '%(func)s' % {'func': getattr(f, '__name__', f)}
            for attempt in range(1, max_attempts + 1):
                try:
                    return f(*args, **kwargs)
                except oslo_messaging.MessagingException:
                    with excutils.save_and_reraise_exception(
                            reraise=False) as ctxt:
                        LOG.warning(
                            'Failed to execute %(action)s. %(attempt)d out'
                            ' of %(max_attempts)d',
                            {'attempt': attempt,
                             'max_attempts': max_attempts,
                             'action': action})
                        if attempt == max_attempts:
                            ctxt.reraise = True
        return func_wrapper
    return wrapper


def retry(func, max_attempts):
    """Adds the retry logic to original function and returns a partial.

    The returned partial can be called with the same arguments as the original
    function.
    """
    return _call_with_retry(max_attempts)(func)
