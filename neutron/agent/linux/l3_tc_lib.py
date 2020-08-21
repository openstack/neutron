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

import re

from neutron_lib import constants
from neutron_lib import exceptions
from oslo_log import log as logging

from neutron.agent.linux import ip_lib
from neutron.agent.linux import tc_lib

LOG = logging.getLogger(__name__)

# NOTE(slaweq): in iproute 4.15 chain value was added to filter output and this
# needs to be included in REGEX
FILTER_ID_REGEX = re.compile(
    r"filter protocol ip u32 (fh|chain \d+ fh) (\w+::\w+) *")
FILTER_STATS_REGEX = re.compile(r"Sent (\w+) bytes (\w+) pkts *")


class FloatingIPTcCommandBase(ip_lib.IPDevice):

    def _execute_tc_cmd(self, cmd, **kwargs):
        cmd = ['tc'] + cmd
        ip_wrapper = ip_lib.IPWrapper(self.namespace)
        return ip_wrapper.netns.execute(cmd, run_as_root=True, **kwargs)

    def _get_qdisc_id_for_filter(self, direction):
        qdiscs = tc_lib.list_tc_qdiscs(self.name, namespace=self.namespace)
        qdisc_type = (tc_lib.TC_QDISC_TYPE_HTB
                      if direction == constants.EGRESS_DIRECTION
                      else tc_lib.TC_QDISC_TYPE_INGRESS)
        for qdisc in (qd for qd in qdiscs if qd['qdisc_type'] == qdisc_type):
            return qdisc['handle']

    def _add_qdisc(self, direction):
        if direction == constants.EGRESS_DIRECTION:
            tc_lib.add_tc_qdisc(
                self.name, 'htb', parent='root', namespace=self.namespace)
        else:
            tc_lib.add_tc_qdisc(
                self.name, 'ingress', namespace=self.namespace)

    def _get_filters(self, qdisc_id):
        cmd = ['-p', '-s', '-d', 'filter', 'show', 'dev', self.name,
               'parent', qdisc_id, 'prio', 1]
        return self._execute_tc_cmd(cmd)

    def _get_filterid_for_ip(self, qdisc_id, ip):
        filterids_for_ip = []
        filters_output = self._get_filters(qdisc_id)
        if not filters_output:
            raise exceptions.FilterIDForIPNotFound(ip=ip)
        filter_lines = filters_output.split('\n')
        for line in filter_lines:
            line = line.strip()
            m = FILTER_ID_REGEX.match(line)
            if m:
                filter_id = m.group(2)
                # It matched, so ip/32 is not here. continue
                continue
            if not line.startswith('match'):
                continue
            parts = line.split(" ")
            if ip + '/32' in parts:
                filterids_for_ip.append(filter_id)
        if len(filterids_for_ip) > 1:
            raise exceptions.MultipleFilterIDForIPFound(ip=ip)
        if len(filterids_for_ip) == 0:
            raise exceptions.FilterIDForIPNotFound(ip=ip)
        return filterids_for_ip[0]

    def _del_filter_by_id(self, qdisc_id, filter_id):
        cmd = ['filter', 'del', 'dev', self.name,
               'parent', qdisc_id,
               'prio', 1, 'handle', filter_id, 'u32']
        self._execute_tc_cmd(cmd)

    def _get_qdisc_filters(self, qdisc_id):
        filterids = []
        filters_output = self._get_filters(qdisc_id)
        if not filters_output:
            return filterids
        filter_lines = filters_output.split('\n')
        for line in filter_lines:
            line = line.strip()
            m = FILTER_ID_REGEX.match(line)
            if m:
                filter_id = m.group(2)
                filterids.append(filter_id)
        return filterids

    def _add_filter(self, qdisc_id, direction, ip, rate, burst):
        rate_value = "%s%s" % (rate, tc_lib.BW_LIMIT_UNIT)
        burst_value = "%s%s" % (
            tc_lib.TcCommand.get_ingress_qdisc_burst_value(rate, burst),
            tc_lib.BURST_UNIT
        )
        protocol = ['protocol', 'ip']
        prio = ['prio', 1]
        _match = 'src' if direction == constants.EGRESS_DIRECTION else 'dst'
        match = ['u32', 'match', 'ip', _match, ip]
        police = ['police', 'rate', rate_value, 'burst', burst_value,
                  'mtu', '64kb', 'drop', 'flowid', ':1']
        args = protocol + prio + match + police
        cmd = ['filter', 'add', 'dev', self.name,
               'parent', qdisc_id] + args
        self._execute_tc_cmd(cmd)

    def _get_or_create_qdisc(self, direction):
        qdisc_id = self._get_qdisc_id_for_filter(direction)
        if not qdisc_id:
            self._add_qdisc(direction)
            qdisc_id = self._get_qdisc_id_for_filter(direction)
            if not qdisc_id:
                raise exceptions.FailedToAddQdiscToDevice(direction=direction,
                                                          device=self.name)
        return qdisc_id


class FloatingIPTcCommand(FloatingIPTcCommandBase):

    def clear_all_filters(self, direction):
        qdisc_id = self._get_qdisc_id_for_filter(direction)
        if not qdisc_id:
            return
        filterids = self._get_qdisc_filters(qdisc_id)
        for filter_id in filterids:
            self._del_filter_by_id(qdisc_id, filter_id)

    def get_filter_id_for_ip(self, direction, ip):
        qdisc_id = self._get_qdisc_id_for_filter(direction)
        if not qdisc_id:
            return
        return self._get_filterid_for_ip(qdisc_id, ip)

    def get_existing_filter_ids(self, direction):
        qdisc_id = self._get_qdisc_id_for_filter(direction)
        if not qdisc_id:
            return
        return self._get_qdisc_filters(qdisc_id)

    def delete_filter_ids(self, direction, filterids):
        qdisc_id = self._get_qdisc_id_for_filter(direction)
        if not qdisc_id:
            return
        for filter_id in filterids:
            self._del_filter_by_id(qdisc_id, filter_id)

    def set_ip_rate_limit(self, direction, ip, rate, burst):
        qdisc_id = self._get_or_create_qdisc(direction)
        try:
            filter_id = self._get_filterid_for_ip(qdisc_id, ip)
            LOG.debug("Filter %(filter)s for IP %(ip)s in %(direction)s "
                      "qdisc already existed, removing.",
                      {'filter': filter_id,
                       'ip': ip,
                       'direction': direction})
            self._del_filter_by_id(qdisc_id, filter_id)
        except exceptions.FilterIDForIPNotFound:
            pass
        LOG.debug("Adding filter for IP %(ip)s in %(direction)s.",
                  {'ip': ip,
                   'direction': direction})
        self._add_filter(qdisc_id, direction, ip, rate, burst)

    def clear_ip_rate_limit(self, direction, ip):
        qdisc_id = self._get_qdisc_id_for_filter(direction)
        if not qdisc_id:
            return
        try:
            filter_id = self._get_filterid_for_ip(qdisc_id, ip)
            self._del_filter_by_id(qdisc_id, filter_id)
        except exceptions.FilterIDForIPNotFound:
            LOG.debug("No filter found for IP %(ip)s in %(direction)s, "
                      "skipping deletion.",
                      {'ip': ip,
                       'direction': direction})
