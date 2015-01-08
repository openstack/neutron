# Copyright 2014 Cisco Systems, Inc.  All rights reserved.
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

import datetime

from oslo_config import cfg
from oslo_utils import timeutils

from neutron.agent.linux import utils as linux_utils
from neutron.i18n import _LI, _LW
from neutron.openstack.common import log as logging


LOG = logging.getLogger(__name__)


STATUS_OPTS = [
    cfg.IntOpt('device_connection_timeout', default=30,
               help=_("Time in seconds for connecting to a hosting device")),
    cfg.IntOpt('hosting_device_dead_timeout', default=300,
               help=_("The time in seconds until a backlogged hosting device "
                      "is presumed dead. This value should be set up high "
                      "enough to recover from a period of connectivity loss "
                      "or high load when the device may not be responding.")),
]

cfg.CONF.register_opts(STATUS_OPTS, "cfg_agent")


def _is_pingable(ip):
    """Checks whether an IP address is reachable by pinging.

    Use linux utils to execute the ping (ICMP ECHO) command.
    Sends 5 packets with an interval of 0.2 seconds and timeout of 1
    seconds. Runtime error implies unreachability else IP is pingable.
    :param ip: IP to check
    :return: bool - True or False depending on pingability.
    """
    ping_cmd = ['ping',
                '-c', '5',
                '-W', '1',
                '-i', '0.2',
                ip]
    try:
        linux_utils.execute(ping_cmd, check_exit_code=True)
        return True
    except RuntimeError:
        LOG.warning(_LW("Cannot ping ip address: %s"), ip)
        return False


class DeviceStatus(object):
    """Device status and backlog processing."""

    _instance = None

    def __new__(cls):
        if not cls._instance:
            cls._instance = super(DeviceStatus, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        self.backlog_hosting_devices = {}

    def get_backlogged_hosting_devices(self):
        return self.backlog_hosting_devices.keys()

    def get_backlogged_hosting_devices_info(self):
        wait_time = datetime.timedelta(
            seconds=cfg.CONF.cfg_agent.hosting_device_dead_timeout)
        resp = []
        for hd_id in self.backlog_hosting_devices:
            hd = self.backlog_hosting_devices[hd_id]['hd']
            created_time = hd['created_at']
            boottime = datetime.timedelta(seconds=hd['booting_time'])
            backlogged_at = hd['backlog_insertion_ts']
            booted_at = created_time + boottime
            dead_at = backlogged_at + wait_time
            resp.append({'host id': hd['id'],
                         'created at': str(created_time),
                         'backlogged at': str(backlogged_at),
                         'estimate booted at': str(booted_at),
                         'considered dead at': str(dead_at)})
        return resp

    def is_hosting_device_reachable(self, hosting_device):
        """Check the hosting device which hosts this resource is reachable.

        If the resource is not reachable, it is added to the backlog.

        :param hosting_device : dict of the hosting device
        :return True if device is reachable, else None
        """
        hd = hosting_device
        hd_id = hosting_device['id']
        hd_mgmt_ip = hosting_device['management_ip_address']
        # Modifying the 'created_at' to a date time object
        hosting_device['created_at'] = datetime.datetime.strptime(
            hosting_device['created_at'], '%Y-%m-%d %H:%M:%S')

        if hd_id not in self.backlog_hosting_devices:
            if _is_pingable(hd_mgmt_ip):
                LOG.debug("Hosting device: %(hd_id)s@%(ip)s is reachable.",
                          {'hd_id': hd_id, 'ip': hd_mgmt_ip})
                return True
            LOG.debug("Hosting device: %(hd_id)s@%(ip)s is NOT reachable.",
                      {'hd_id': hd_id, 'ip': hd_mgmt_ip})
            hd['backlog_insertion_ts'] = max(
                timeutils.utcnow(),
                hd['created_at'] +
                datetime.timedelta(seconds=hd['booting_time']))
            self.backlog_hosting_devices[hd_id] = {'hd': hd}
            LOG.debug("Hosting device: %(hd_id)s @ %(ip)s is now added "
                      "to backlog", {'hd_id': hd_id, 'ip': hd_mgmt_ip})

    def check_backlogged_hosting_devices(self):
        """"Checks the status of backlogged hosting devices.

        Skips newly spun up instances during their booting time as specified
        in the boot time parameter.

        :return A dict of the format:
        {'reachable': [<hd_id>,..], 'dead': [<hd_id>,..]}
        """
        response_dict = {'reachable': [], 'dead': []}
        LOG.debug("Current Backlogged hosting devices: %s",
                  self.backlog_hosting_devices.keys())
        for hd_id in self.backlog_hosting_devices.keys():
            hd = self.backlog_hosting_devices[hd_id]['hd']
            if not timeutils.is_older_than(hd['created_at'],
                                           hd['booting_time']):
                LOG.info(_LI("Hosting device: %(hd_id)s @ %(ip)s hasn't "
                             "passed minimum boot time. Skipping it. "),
                         {'hd_id': hd_id, 'ip': hd['management_ip_address']})
                continue
            LOG.info(_LI("Checking hosting device: %(hd_id)s @ %(ip)s for "
                       "reachability."), {'hd_id': hd_id,
                                          'ip': hd['management_ip_address']})
            if _is_pingable(hd['management_ip_address']):
                hd.pop('backlog_insertion_ts', None)
                del self.backlog_hosting_devices[hd_id]
                response_dict['reachable'].append(hd_id)
                LOG.info(_LI("Hosting device: %(hd_id)s @ %(ip)s is now "
                           "reachable. Adding it to response"),
                         {'hd_id': hd_id, 'ip': hd['management_ip_address']})
            else:
                LOG.info(_LI("Hosting device: %(hd_id)s @ %(ip)s still not "
                           "reachable "), {'hd_id': hd_id,
                                           'ip': hd['management_ip_address']})
                if timeutils.is_older_than(
                        hd['backlog_insertion_ts'],
                        cfg.CONF.cfg_agent.hosting_device_dead_timeout):
                    LOG.debug("Hosting device: %(hd_id)s @ %(ip)s hasn't "
                              "been reachable for the last %(time)d seconds. "
                              "Marking it dead.",
                              {'hd_id': hd_id,
                               'ip': hd['management_ip_address'],
                               'time': cfg.CONF.cfg_agent.
                              hosting_device_dead_timeout})
                    response_dict['dead'].append(hd_id)
                    hd.pop('backlog_insertion_ts', None)
                    del self.backlog_hosting_devices[hd_id]
        LOG.debug("Response: %s", response_dict)
        return response_dict
