# Copyright (c) 2013 OpenStack Foundation
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

from neutron_lib.api.definitions import portbindings
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants as n_const
from neutron_lib.plugins import directory
from oslo_db import exception as db_exc
from oslo_log import log
from oslo_utils import uuidutils
import six
from sqlalchemy import or_
from sqlalchemy.orm import exc

from neutron._i18n import _
from neutron.db import api as db_api
from neutron.db.models import securitygroup as sg_models
from neutron.db import models_v2
from neutron.objects import ports as port_obj
from neutron.plugins.ml2 import models
from neutron.services.segments import exceptions as seg_exc

LOG = log.getLogger(__name__)

# limit the number of port OR LIKE statements in one query
MAX_PORTS_PER_QUERY = 500


@db_api.context_manager.writer
def add_port_binding(context, port_id):
    record = models.PortBinding(
        port_id=port_id,
        vif_type=portbindings.VIF_TYPE_UNBOUND)
    context.session.add(record)
    return record


@db_api.context_manager.writer
def set_binding_levels(context, levels):
    if levels:
        for level in levels:
            level.persist_state_to_session(context.session)
        LOG.debug("For port %(port_id)s, host %(host)s, "
                  "set binding levels %(levels)s",
                  {'port_id': levels[0].port_id,
                   'host': levels[0].host,
                   'levels': levels})
    else:
        LOG.debug("Attempted to set empty binding levels")


@db_api.context_manager.reader
def get_binding_levels(context, port_id, host):
    if host:
        result = (context.session.query(models.PortBindingLevel).
                  filter_by(port_id=port_id, host=host).
                  order_by(models.PortBindingLevel.level).
                  all())
        LOG.debug("For port %(port_id)s, host %(host)s, "
                  "got binding levels %(levels)s",
                  {'port_id': port_id,
                   'host': host,
                   'levels': result})
        return result


@db_api.context_manager.writer
def clear_binding_levels(context, port_id, host):
    if host:
        for l in (context.session.query(models.PortBindingLevel).
                  filter_by(port_id=port_id, host=host)):
            context.session.delete(l)
        LOG.debug("For port %(port_id)s, host %(host)s, "
                  "cleared binding levels",
                  {'port_id': port_id,
                   'host': host})


def ensure_distributed_port_binding(context, port_id, host, router_id=None):
    with db_api.context_manager.reader.using(context):
        record = (context.session.query(models.DistributedPortBinding).
                  filter_by(port_id=port_id, host=host).first())
    if record:
        return record

    try:
        with db_api.context_manager.writer.using(context):
            record = models.DistributedPortBinding(
                port_id=port_id,
                host=host,
                router_id=router_id,
                vif_type=portbindings.VIF_TYPE_UNBOUND,
                vnic_type=portbindings.VNIC_NORMAL,
                status=n_const.PORT_STATUS_DOWN)
            context.session.add(record)
            return record
    except db_exc.DBDuplicateEntry:
        LOG.debug("Distributed Port %s already bound", port_id)
        with db_api.context_manager.reader.using(context):
            return (context.session.query(models.DistributedPortBinding).
                    filter_by(port_id=port_id, host=host).one())


def delete_distributed_port_binding_if_stale(context, binding):
    if not binding.router_id and binding.status == n_const.PORT_STATUS_DOWN:
        with db_api.context_manager.writer.using(context):
            LOG.debug("Distributed port: Deleting binding %s", binding)
            context.session.delete(binding)


def get_port(context, port_id):
    """Get port record for update within transaction."""

    with db_api.context_manager.reader.using(context):
        try:
            # Set enable_eagerloads to True, so that lazy load can be
            # proceed later.
            record = (context.session.query(models_v2.Port).
                      enable_eagerloads(True).
                      filter(models_v2.Port.id.startswith(port_id)).
                      one())
            return record
        except exc.NoResultFound:
            return
        except exc.MultipleResultsFound:
            LOG.error("Multiple ports have port_id starting with %s",
                      port_id)
            return


@db_api.context_manager.reader
def get_port_from_device_mac(context, device_mac):
    LOG.debug("get_port_from_device_mac() called for mac %s", device_mac)
    ports = port_obj.Port.get_objects(context, mac_address=device_mac)
    return ports.pop() if ports else None


def get_ports_and_sgs(context, port_ids):
    """Get ports from database with security group info."""

    # break large queries into smaller parts
    if len(port_ids) > MAX_PORTS_PER_QUERY:
        LOG.debug("Number of ports %(pcount)s exceeds the maximum per "
                  "query %(maxp)s. Partitioning queries.",
                  {'pcount': len(port_ids), 'maxp': MAX_PORTS_PER_QUERY})
        return (get_ports_and_sgs(context, port_ids[:MAX_PORTS_PER_QUERY]) +
                get_ports_and_sgs(context, port_ids[MAX_PORTS_PER_QUERY:]))

    LOG.debug("get_ports_and_sgs() called for port_ids %s", port_ids)

    if not port_ids:
        # if port_ids is empty, avoid querying to DB to ask it for nothing
        return []
    ports_to_sg_ids = get_sg_ids_grouped_by_port(context, port_ids)
    return [make_port_dict_with_security_groups(port, sec_groups)
            for port, sec_groups in six.iteritems(ports_to_sg_ids)]


def get_sg_ids_grouped_by_port(context, port_ids):
    sg_ids_grouped_by_port = {}
    sg_binding_port = sg_models.SecurityGroupPortBinding.port_id

    with db_api.context_manager.reader.using(context):
        # partial UUIDs must be individually matched with startswith.
        # full UUIDs may be matched directly in an IN statement
        partial_uuids = set(port_id for port_id in port_ids
                            if not uuidutils.is_uuid_like(port_id))
        full_uuids = set(port_ids) - partial_uuids
        or_criteria = [models_v2.Port.id.startswith(port_id)
                       for port_id in partial_uuids]
        if full_uuids:
            or_criteria.append(models_v2.Port.id.in_(full_uuids))

        query = context.session.query(
            models_v2.Port,
            sg_models.SecurityGroupPortBinding.security_group_id)
        query = query.outerjoin(sg_models.SecurityGroupPortBinding,
                                models_v2.Port.id == sg_binding_port)
        query = query.filter(or_(*or_criteria))

        for port, sg_id in query:
            if port not in sg_ids_grouped_by_port:
                sg_ids_grouped_by_port[port] = []
            if sg_id:
                sg_ids_grouped_by_port[port].append(sg_id)
    return sg_ids_grouped_by_port


def make_port_dict_with_security_groups(port, sec_groups):
    plugin = directory.get_plugin()
    port_dict = plugin._make_port_dict(port)
    port_dict['security_groups'] = sec_groups
    port_dict['security_group_rules'] = []
    port_dict['security_group_source_groups'] = []
    port_dict['fixed_ips'] = [ip['ip_address']
                              for ip in port['fixed_ips']]
    return port_dict


def get_port_binding_host(context, port_id):
    try:
        with db_api.context_manager.reader.using(context):
            query = (context.session.query(models.PortBinding.host).
                     filter(models.PortBinding.port_id.startswith(port_id)))
            query = query.filter(
                models.PortBinding.status == n_const.ACTIVE).one()
    except exc.NoResultFound:
        LOG.debug("No binding found for port %(port_id)s",
                  {'port_id': port_id})
        return
    except exc.MultipleResultsFound:
        LOG.error("Multiple ports have port_id starting with %s",
                  port_id)
        return
    return query.host


@db_api.context_manager.reader
def generate_distributed_port_status(context, port_id):
    # an OR'ed value of status assigned to parent port from the
    # distributedportbinding bucket
    query = context.session.query(models.DistributedPortBinding.status)
    final_status = n_const.PORT_STATUS_BUILD
    for bind in query.filter(models.DistributedPortBinding.port_id == port_id):
        if bind.status == n_const.PORT_STATUS_ACTIVE:
            return bind.status
        elif bind.status == n_const.PORT_STATUS_DOWN:
            final_status = bind.status
    return final_status


def get_distributed_port_binding_by_host(context, port_id, host):
    with db_api.context_manager.reader.using(context):
        binding = (context.session.query(models.DistributedPortBinding).
            filter(models.DistributedPortBinding.port_id.startswith(port_id),
                   models.DistributedPortBinding.host == host).first())
    if not binding:
        LOG.debug("No binding for distributed port %(port_id)s with host "
                  "%(host)s", {'port_id': port_id, 'host': host})
    return binding


def get_distributed_port_bindings(context, port_id):
    with db_api.context_manager.reader.using(context):
        bindings = (context.session.query(models.DistributedPortBinding).
                    filter(models.DistributedPortBinding.port_id.startswith(
                           port_id)).all())
    if not bindings:
        LOG.debug("No bindings for distributed port %s", port_id)
    return bindings


@db_api.context_manager.reader
def partial_port_ids_to_full_ids(context, partial_ids):
    """Takes a list of the start of port IDs and returns full IDs.

    Returns dictionary of partial IDs to full IDs if a single match
    is found.
    """
    result = {}
    to_full_query = (context.session.query(models_v2.Port.id).
                     filter(or_(*[models_v2.Port.id.startswith(p)
                                  for p in partial_ids])))
    candidates = [match[0] for match in to_full_query]
    for partial_id in partial_ids:
        matching = [c for c in candidates if c.startswith(partial_id)]
        if len(matching) == 1:
            result[partial_id] = matching[0]
            continue
        if len(matching) < 1:
            LOG.info("No ports have port_id starting with %s", partial_id)
        elif len(matching) > 1:
            LOG.error("Multiple ports have port_id starting with %s",
                      partial_id)
    return result


@db_api.context_manager.reader
def get_port_db_objects(context, port_ids):
    """Takes a list of port_ids and returns matching port db objects.

    return format is a dictionary keyed by passed in IDs with db objects
    for values or None if the port was not present.
    """
    port_qry = (context.session.query(models_v2.Port).
                filter(models_v2.Port.id.in_(port_ids)))
    result = {p: None for p in port_ids}
    for port in port_qry:
        result[port.id] = port
    return result


@db_api.context_manager.reader
def is_dhcp_active_on_any_subnet(context, subnet_ids):
    if not subnet_ids:
        return False
    return bool(context.session.query(models_v2.Subnet.id).
                enable_eagerloads(False).filter_by(enable_dhcp=True).
                filter(models_v2.Subnet.id.in_(subnet_ids)).count())


def _prevent_segment_delete_with_port_bound(resource, event, trigger,
                                            context, segment,
                                            for_net_delete=False):
    """Raise exception if there are any ports bound with segment_id."""
    if for_net_delete:
        # don't check for network deletes
        return

    with db_api.context_manager.reader.using(context):
        segment_id = segment['id']
        query = context.session.query(models_v2.Port.id)
        query = query.join(
            models.PortBindingLevel,
            models.PortBindingLevel.port_id == models_v2.Port.id)
        query = query.filter(models.PortBindingLevel.segment_id == segment_id)
        port_ids = [p.id for p in query]

    # There are still some ports in the segment, segment should not be deleted
    # TODO(xiaohhui): Should we delete the dhcp port automatically here?
    if port_ids:
        reason = _("The segment is still bound with port(s) "
                   "%s") % ", ".join(port_ids)
        raise seg_exc.SegmentInUse(segment_id=segment_id, reason=reason)


def subscribe():
    registry.subscribe(_prevent_segment_delete_with_port_bound,
                       resources.SEGMENT,
                       events.BEFORE_DELETE)

subscribe()
