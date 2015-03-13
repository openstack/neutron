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


import time

from oslo_log import log as logging
from tempest_lib.common.utils import misc as misc_utils

from neutron.tests.tempest import config
from neutron.tests.tempest import exceptions

CONF = config.CONF
LOG = logging.getLogger(__name__)


# NOTE(afazekas): This function needs to know a token and a subject.
def wait_for_server_status(client, server_id, status, ready_wait=True,
                           extra_timeout=0, raise_on_error=True):
    """Waits for a server to reach a given status."""

    def _get_task_state(body):
        return body.get('OS-EXT-STS:task_state', None)

    # NOTE(afazekas): UNKNOWN status possible on ERROR
    # or in a very early stage.
    body = client.get_server(server_id)
    old_status = server_status = body['status']
    old_task_state = task_state = _get_task_state(body)
    start_time = int(time.time())
    timeout = client.build_timeout + extra_timeout
    while True:
        # NOTE(afazekas): Now the BUILD status only reached
        # between the UNKNOWN->ACTIVE transition.
        # TODO(afazekas): enumerate and validate the stable status set
        if status == 'BUILD' and server_status != 'UNKNOWN':
            return
        if server_status == status:
            if ready_wait:
                if status == 'BUILD':
                    return
                # NOTE(afazekas): The instance is in "ready for action state"
                # when no task in progress
                # NOTE(afazekas): Converted to string bacuse of the XML
                # responses
                if str(task_state) == "None":
                    # without state api extension 3 sec usually enough
                    time.sleep(CONF.compute.ready_wait)
                    return
            else:
                return

        time.sleep(client.build_interval)
        body = client.get_server(server_id)
        server_status = body['status']
        task_state = _get_task_state(body)
        if (server_status != old_status) or (task_state != old_task_state):
            LOG.info('State transition "%s" ==> "%s" after %d second wait',
                     '/'.join((old_status, str(old_task_state))),
                     '/'.join((server_status, str(task_state))),
                     time.time() - start_time)
        if (server_status == 'ERROR') and raise_on_error:
            if 'fault' in body:
                raise exceptions.BuildErrorException(body['fault'],
                                                     server_id=server_id)
            else:
                raise exceptions.BuildErrorException(server_id=server_id)

        timed_out = int(time.time()) - start_time >= timeout

        if timed_out:
            expected_task_state = 'None' if ready_wait else 'n/a'
            message = ('Server %(server_id)s failed to reach %(status)s '
                       'status and task state "%(expected_task_state)s" '
                       'within the required time (%(timeout)s s).' %
                       {'server_id': server_id,
                        'status': status,
                        'expected_task_state': expected_task_state,
                        'timeout': timeout})
            message += ' Current status: %s.' % server_status
            message += ' Current task state: %s.' % task_state
            caller = misc_utils.find_test_caller()
            if caller:
                message = '(%s) %s' % (caller, message)
            raise exceptions.TimeoutException(message)
        old_status = server_status
        old_task_state = task_state


def wait_for_image_status(client, image_id, status):
    """Waits for an image to reach a given status.

    The client should have a get_image(image_id) method to get the image.
    The client should also have build_interval and build_timeout attributes.
    """
    image = client.get_image(image_id)
    start = int(time.time())

    while image['status'] != status:
        time.sleep(client.build_interval)
        image = client.get_image(image_id)
        status_curr = image['status']
        if status_curr == 'ERROR':
            raise exceptions.AddImageException(image_id=image_id)

        # check the status again to avoid a false negative where we hit
        # the timeout at the same time that the image reached the expected
        # status
        if status_curr == status:
            return

        if int(time.time()) - start >= client.build_timeout:
            message = ('Image %(image_id)s failed to reach %(status)s state'
                       '(current state %(status_curr)s) '
                       'within the required time (%(timeout)s s).' %
                       {'image_id': image_id,
                        'status': status,
                        'status_curr': status_curr,
                        'timeout': client.build_timeout})
            caller = misc_utils.find_test_caller()
            if caller:
                message = '(%s) %s' % (caller, message)
            raise exceptions.TimeoutException(message)


def wait_for_bm_node_status(client, node_id, attr, status):
    """Waits for a baremetal node attribute to reach given status.

    The client should have a show_node(node_uuid) method to get the node.
    """
    _, node = client.show_node(node_id)
    start = int(time.time())

    while node[attr] != status:
        time.sleep(client.build_interval)
        _, node = client.show_node(node_id)
        status_curr = node[attr]
        if status_curr == status:
            return

        if int(time.time()) - start >= client.build_timeout:
            message = ('Node %(node_id)s failed to reach %(attr)s=%(status)s '
                       'within the required time (%(timeout)s s).' %
                       {'node_id': node_id,
                        'attr': attr,
                        'status': status,
                        'timeout': client.build_timeout})
            message += ' Current state of %s: %s.' % (attr, status_curr)
            caller = misc_utils.find_test_caller()
            if caller:
                message = '(%s) %s' % (caller, message)
            raise exceptions.TimeoutException(message)
