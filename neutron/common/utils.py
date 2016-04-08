# Copyright 2011, VMware, Inc.
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
#
# Borrowed from nova code base, more utilities will be added/borrowed as and
# when needed.

"""Utilities and helper functions."""

import collections
import datetime
import decimal
import errno
import functools
import hashlib
import math
import multiprocessing
import os
import random
import signal
import socket
import sys
import tempfile
import time
import uuid

import debtcollector
from eventlet.green import subprocess
import netaddr
from oslo_concurrency import lockutils
from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_log import log as logging
from oslo_utils import excutils
from oslo_utils import importutils
from oslo_utils import reflection
import six
from stevedore import driver

from neutron._i18n import _, _LE
from neutron.common import constants as n_const
from neutron.db import api as db_api

TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
LOG = logging.getLogger(__name__)
SYNCHRONIZED_PREFIX = 'neutron-'
# Unsigned 16 bit MAX.
MAX_UINT16 = 0xffff

synchronized = lockutils.synchronized_with_prefix(SYNCHRONIZED_PREFIX)


class cache_method_results(object):
    """This decorator is intended for object methods only."""

    def __init__(self, func):
        self.func = func
        functools.update_wrapper(self, func)
        self._first_call = True
        self._not_cached = object()

    def _get_from_cache(self, target_self, *args, **kwargs):
        target_self_cls_name = reflection.get_class_name(target_self,
                                                         fully_qualified=False)
        func_name = "%(module)s.%(class)s.%(func_name)s" % {
            'module': target_self.__module__,
            'class': target_self_cls_name,
            'func_name': self.func.__name__,
        }
        key = (func_name,) + args
        if kwargs:
            key += dict2tuple(kwargs)
        try:
            item = target_self._cache.get(key, self._not_cached)
        except TypeError:
            LOG.debug("Method %(func_name)s cannot be cached due to "
                      "unhashable parameters: args: %(args)s, kwargs: "
                      "%(kwargs)s",
                      {'func_name': func_name,
                       'args': args,
                       'kwargs': kwargs})
            return self.func(target_self, *args, **kwargs)

        if item is self._not_cached:
            item = self.func(target_self, *args, **kwargs)
            target_self._cache.set(key, item, None)

        return item

    def __call__(self, target_self, *args, **kwargs):
        target_self_cls_name = reflection.get_class_name(target_self,
                                                         fully_qualified=False)
        if not hasattr(target_self, '_cache'):
            raise NotImplementedError(
                _("Instance of class %(module)s.%(class)s must contain _cache "
                  "attribute") % {
                    'module': target_self.__module__,
                    'class': target_self_cls_name})
        if not target_self._cache:
            if self._first_call:
                LOG.debug("Instance of class %(module)s.%(class)s doesn't "
                          "contain attribute _cache therefore results "
                          "cannot be cached for %(func_name)s.",
                          {'module': target_self.__module__,
                           'class': target_self_cls_name,
                           'func_name': self.func.__name__})
                self._first_call = False
            return self.func(target_self, *args, **kwargs)
        return self._get_from_cache(target_self, *args, **kwargs)

    def __get__(self, obj, objtype):
        return functools.partial(self.__call__, obj)


@debtcollector.removals.remove(message="This will removed in the N cycle.")
def read_cached_file(filename, cache_info, reload_func=None):
    """Read from a file if it has been modified.

    :param cache_info: dictionary to hold opaque cache.
    :param reload_func: optional function to be called with data when
                        file is reloaded due to a modification.

    :returns: data from file

    """
    mtime = os.path.getmtime(filename)
    if not cache_info or mtime != cache_info.get('mtime'):
        LOG.debug("Reloading cached file %s", filename)
        with open(filename) as fap:
            cache_info['data'] = fap.read()
        cache_info['mtime'] = mtime
        if reload_func:
            reload_func(cache_info['data'])
    return cache_info['data']


@debtcollector.removals.remove(message="This will removed in the N cycle.")
def find_config_file(options, config_file):
    """Return the first config file found.

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
                        fix_path(os.path.join('~', '.neutron-venv', 'etc',
                                              'neutron')),
                        fix_path('~'),
                        os.path.join(cfg.CONF.state_path, 'etc'),
                        os.path.join(cfg.CONF.state_path, 'etc', 'neutron'),
                        fix_path(os.path.join('~', '.local',
                                              'etc', 'neutron')),
                        '/usr/etc/neutron',
                        '/usr/local/etc/neutron',
                        '/etc/neutron/',
                        '/etc']

    if 'plugin' in options:
        config_file_dirs = [
            os.path.join(x, 'neutron', 'plugins', options['plugin'])
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


def ensure_dir(dir_path):
    """Ensure a directory with 755 permissions mode."""
    try:
        os.makedirs(dir_path, 0o755)
    except OSError as e:
        # If the directory already existed, don't raise the error.
        if e.errno != errno.EEXIST:
            raise


def _subprocess_setup():
    # Python installs a SIGPIPE handler by default. This is usually not what
    # non-Python subprocesses expect.
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)


def subprocess_popen(args, stdin=None, stdout=None, stderr=None, shell=False,
                     env=None, preexec_fn=_subprocess_setup, close_fds=True):

    return subprocess.Popen(args, shell=shell, stdin=stdin, stdout=stdout,
                            stderr=stderr, preexec_fn=preexec_fn,
                            close_fds=close_fds, env=env)


def parse_mappings(mapping_list, unique_values=True, unique_keys=True):
    """Parse a list of mapping strings into a dictionary.

    :param mapping_list: a list of strings of the form '<key>:<value>'
    :param unique_values: values must be unique if True
    :param unique_keys: keys must be unique if True, else implies that keys
    and values are not unique
    :returns: a dict mapping keys to values or to list of values
    """
    mappings = {}
    for mapping in mapping_list:
        mapping = mapping.strip()
        if not mapping:
            continue
        split_result = mapping.split(':')
        if len(split_result) != 2:
            raise ValueError(_("Invalid mapping: '%s'") % mapping)
        key = split_result[0].strip()
        if not key:
            raise ValueError(_("Missing key in mapping: '%s'") % mapping)
        value = split_result[1].strip()
        if not value:
            raise ValueError(_("Missing value in mapping: '%s'") % mapping)
        if unique_keys:
            if key in mappings:
                raise ValueError(_("Key %(key)s in mapping: '%(mapping)s' not "
                                   "unique") % {'key': key,
                                                'mapping': mapping})
            if unique_values and value in mappings.values():
                raise ValueError(_("Value %(value)s in mapping: '%(mapping)s' "
                                   "not unique") % {'value': value,
                                                    'mapping': mapping})
            mappings[key] = value
        else:
            mappings.setdefault(key, [])
            if value not in mappings[key]:
                mappings[key].append(value)
    return mappings


def get_hostname():
    return socket.gethostname()


def get_first_host_ip(net, ip_version):
    return str(netaddr.IPAddress(net.first + 1, ip_version))


def compare_elements(a, b):
    """Compare elements if a and b have same elements.

    This method doesn't consider ordering
    """
    if a is None:
        a = []
    if b is None:
        b = []
    return set(a) == set(b)


def safe_sort_key(value):
    """Return value hash or build one for dictionaries."""
    if isinstance(value, collections.Mapping):
        return sorted(value.items())
    return value


def dict2str(dic):
    return ','.join("%s=%s" % (key, val)
                    for key, val in sorted(six.iteritems(dic)))


def str2dict(string):
    res_dict = {}
    for keyvalue in string.split(','):
        (key, value) = keyvalue.split('=', 1)
        res_dict[key] = value
    return res_dict


def dict2tuple(d):
    items = list(d.items())
    items.sort()
    return tuple(items)


def diff_list_of_dict(old_list, new_list):
    new_set = set([dict2str(l) for l in new_list])
    old_set = set([dict2str(l) for l in old_list])
    added = new_set - old_set
    removed = old_set - new_set
    return [str2dict(a) for a in added], [str2dict(r) for r in removed]


def is_extension_supported(plugin, ext_alias):
    return ext_alias in getattr(
        plugin, "supported_extension_aliases", [])


def log_opt_values(log):
    cfg.CONF.log_opt_values(log, logging.DEBUG)


def get_random_mac(base_mac):
    mac = [int(base_mac[0], 16), int(base_mac[1], 16),
           int(base_mac[2], 16), random.randint(0x00, 0xff),
           random.randint(0x00, 0xff), random.randint(0x00, 0xff)]
    if base_mac[3] != '00':
        mac[3] = int(base_mac[3], 16)
    return ':'.join(["%02x" % x for x in mac])


def get_random_string(length):
    """Get a random hex string of the specified length.

    based on Cinder library
      cinder/transfer/api.py
    """
    rndstr = ""
    random.seed(datetime.datetime.now().microsecond)
    while len(rndstr) < length:
        base_str = str(random.random()).encode('utf-8')
        rndstr += hashlib.sha224(base_str).hexdigest()

    return rndstr[0:length]


def get_dhcp_agent_device_id(network_id, host):
    # Split host so as to always use only the hostname and
    # not the domain name. This will guarantee consistency
    # whether a local hostname or an fqdn is passed in.
    local_hostname = host.split('.')[0]
    host_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, str(local_hostname))
    return 'dhcp%s-%s' % (host_uuid, network_id)


def cpu_count():
    try:
        return multiprocessing.cpu_count()
    except NotImplementedError:
        return 1


class exception_logger(object):
    """Wrap a function and log raised exception

    :param logger: the logger to log the exception default is LOG.exception

    :returns: origin value if no exception raised; re-raise the exception if
              any occurred

    """
    def __init__(self, logger=None):
        self.logger = logger

    def __call__(self, func):
        if self.logger is None:
            LOG = logging.getLogger(func.__module__)
            self.logger = LOG.exception

        def call(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                with excutils.save_and_reraise_exception():
                    self.logger(e)
        return call


def get_other_dvr_serviced_device_owners():
    """Return device_owner names for ports that should be serviced by DVR

    This doesn't return DEVICE_OWNER_COMPUTE_PREFIX since it is a
    prefix, not a complete device_owner name, so should be handled
    separately (see is_dvr_serviced() below)
    """
    return [n_const.DEVICE_OWNER_LOADBALANCER,
            n_const.DEVICE_OWNER_LOADBALANCERV2,
            n_const.DEVICE_OWNER_DHCP]


def is_dvr_serviced(device_owner):
    """Check if the port need to be serviced by DVR

    Helper function to check the device owners of the
    ports in the compute and service node to make sure
    if they are required for DVR or any service directly or
    indirectly associated with DVR.
    """
    return (device_owner.startswith(n_const.DEVICE_OWNER_COMPUTE_PREFIX) or
            device_owner in get_other_dvr_serviced_device_owners())


@debtcollector.removals.remove(message="This will removed in the N cycle.")
def get_keystone_url(conf):
    if conf.auth_uri:
        auth_uri = conf.auth_uri.rstrip('/')
    else:
        auth_uri = ('%(protocol)s://%(host)s:%(port)s' %
            {'protocol': conf.auth_protocol,
             'host': conf.auth_host,
             'port': conf.auth_port})
    # NOTE(ihrachys): all existing consumers assume version 2.0
    return '%s/v2.0/' % auth_uri


def ip_to_cidr(ip, prefix=None):
    """Convert an ip with no prefix to cidr notation

    :param ip: An ipv4 or ipv6 address.  Convertable to netaddr.IPNetwork.
    :param prefix: Optional prefix.  If None, the default 32 will be used for
        ipv4 and 128 for ipv6.
    """
    net = netaddr.IPNetwork(ip)
    if prefix is not None:
        # Can't pass ip and prefix separately.  Must concatenate strings.
        net = netaddr.IPNetwork(str(net.ip) + '/' + str(prefix))
    return str(net)


def fixed_ip_cidrs(fixed_ips):
    """Create a list of a port's fixed IPs in cidr notation.

    :param fixed_ips: A neutron port's fixed_ips dictionary
    """
    return [ip_to_cidr(fixed_ip['ip_address'], fixed_ip.get('prefixlen'))
            for fixed_ip in fixed_ips]


def is_cidr_host(cidr):
    """Determines if the cidr passed in represents a single host network

    :param cidr: Either an ipv4 or ipv6 cidr.
    :returns: True if the cidr is /32 for ipv4 or /128 for ipv6.
    :raises ValueError: raises if cidr does not contain a '/'.  This disallows
        plain IP addresses specifically to avoid ambiguity.
    """
    if '/' not in str(cidr):
        raise ValueError("cidr doesn't contain a '/'")
    net = netaddr.IPNetwork(cidr)
    if net.version == 4:
        return net.prefixlen == n_const.IPv4_BITS
    return net.prefixlen == n_const.IPv6_BITS


def ip_version_from_int(ip_version_int):
    if ip_version_int == 4:
        return n_const.IPv4
    if ip_version_int == 6:
        return n_const.IPv6
    raise ValueError(_('Illegal IP version number'))


def is_port_trusted(port):
    """Used to determine if port can be trusted not to attack network.

    Trust is currently based on the device_owner field starting with 'network:'
    since we restrict who can use that in the default policy.json file.
    """
    return port['device_owner'].startswith(n_const.DEVICE_OWNER_NETWORK_PREFIX)


class DelayedStringRenderer(object):
    """Takes a callable and its args and calls when __str__ is called

    Useful for when an argument to a logging statement is expensive to
    create. This will prevent the callable from being called if it's
    never converted to a string.
    """

    def __init__(self, function, *args, **kwargs):
        self.function = function
        self.args = args
        self.kwargs = kwargs

    def __str__(self):
        return str(self.function(*self.args, **self.kwargs))


def camelize(s):
    return ''.join(s.replace('_', ' ').title().split())


def round_val(val):
    # we rely on decimal module since it behaves consistently across Python
    # versions (2.x vs. 3.x)
    return int(decimal.Decimal(val).quantize(decimal.Decimal('1'),
                                             rounding=decimal.ROUND_HALF_UP))


def replace_file(file_name, data, file_mode=0o644):
    """Replaces the contents of file_name with data in a safe manner.

    First write to a temp file and then rename. Since POSIX renames are
    atomic, the file is unlikely to be corrupted by competing writes.

    We create the tempfile on the same device to ensure that it can be renamed.
    """

    base_dir = os.path.dirname(os.path.abspath(file_name))
    with tempfile.NamedTemporaryFile('w+',
                                     dir=base_dir,
                                     delete=False) as tmp_file:
        tmp_file.write(data)
    os.chmod(tmp_file.name, file_mode)
    os.rename(tmp_file.name, file_name)


def load_class_by_alias_or_classname(namespace, name):
    """Load class using stevedore alias or the class name
    :param namespace: namespace where the alias is defined
    :param name: alias or class name of the class to be loaded
    :returns class if calls can be loaded
    :raises ImportError if class cannot be loaded
    """

    if not name:
        LOG.error(_LE("Alias or class name is not set"))
        raise ImportError(_("Class not found."))
    try:
        # Try to resolve class by alias
        mgr = driver.DriverManager(namespace, name)
        class_to_load = mgr.driver
    except RuntimeError:
        e1_info = sys.exc_info()
        # Fallback to class name
        try:
            class_to_load = importutils.import_class(name)
        except (ImportError, ValueError):
            LOG.error(_LE("Error loading class by alias"),
                      exc_info=e1_info)
            LOG.error(_LE("Error loading class by class name"),
                      exc_info=True)
            raise ImportError(_("Class not found."))
    return class_to_load


def safe_decode_utf8(s):
    if six.PY3 and isinstance(s, bytes):
        return s.decode('utf-8', 'surrogateescape')
    return s


#TODO(jlibosva): Move this to neutron-lib and reuse in networking-ovs-dpdk
def _create_mask(lsb_mask):
    return (MAX_UINT16 << int(math.floor(math.log(lsb_mask, 2)))) \
           & MAX_UINT16


def _reduce_mask(mask, step=1):
    mask <<= step
    return mask & MAX_UINT16


def _increase_mask(mask, step=1):
    for index in range(step):
        mask >>= 1
        mask |= 0x8000
    return mask


def _hex_format(number):
    return format(number, '#06x')


def port_rule_masking(port_min, port_max):
    # Check port_max >= port_min.
    if port_max < port_min:
        raise ValueError(_("'port_max' is smaller than 'port_min'"))

    # Rules to be added to OVS.
    rules = []

    # Loop from the lower part. Increment port_min.
    bit_right = 1
    mask = MAX_UINT16
    t_port_min = port_min
    while True:
        # Obtain last significative bit.
        bit_min = port_min & bit_right
        # Take care of first bit.
        if bit_right == 1:
            if bit_min > 0:
                rules.append("%s" % (_hex_format(t_port_min)))
            else:
                mask = _create_mask(2)
                rules.append("%s/%s" % (_hex_format(t_port_min & mask),
                                        _hex_format(mask)))
        elif bit_min == 0:
            mask = _create_mask(bit_right)
            t_port_min += bit_right
            # If the temporal variable we are using exceeds the
            # port_max value, exit the loop.
            if t_port_min > port_max:
                break
            rules.append("%s/%s" % (_hex_format(t_port_min & mask),
                                    _hex_format(mask)))

        # If the temporal variable we are using exceeds the
        # port_max value, exit the loop.
        if t_port_min > port_max:
            break
        bit_right <<= 1

    # Loop from the higher part.
    bit_position = int(round(math.log(port_max, 2)))
    bit_left = 1 << bit_position
    mask = MAX_UINT16
    mask = _reduce_mask(mask, bit_position)
    # Find the most significative bit of port_max, higher
    # than the most significative bit of port_min.
    while mask < MAX_UINT16:
        bit_max = port_max & bit_left
        bit_min = port_min & bit_left
        if bit_max > bit_min:
            # Difference found.
            break
        # Rotate bit_left to the right and increase mask.
        bit_left >>= 1
        mask = _increase_mask(mask)

    while bit_left > 1:
        # Obtain next most significative bit.
        bit_left >>= 1
        bit_max = port_max & bit_left
        if bit_left == 1:
            if bit_max == 0:
                rules.append("%s" % (_hex_format(port_max)))
            else:
                mask = _create_mask(2)
                rules.append("%s/%s" % (_hex_format(port_max & mask),
                                        _hex_format(mask)))
        elif bit_max > 0:
            t_port_max = port_max - bit_max
            mask = _create_mask(bit_left)
            rules.append("%s/%s" % (_hex_format(t_port_max),
                                    _hex_format(mask)))

    return rules


def create_object_with_dependency(creator, dep_getter, dep_creator,
                                  dep_id_attr):
    """Creates an object that binds to a dependency while handling races.

    creator is a function that expected to take the result of either
    dep_getter or dep_creator.

    The result of dep_getter and dep_creator must have an attribute of
    dep_id_attr be used to determine if the dependency changed during object
    creation.

    dep_getter should return None if the dependency does not exist

    dep_creator can raise a DBDuplicateEntry to indicate that a concurrent
    create of the dependency occured and the process will restart to get the
    concurrently created one

    This function will return both the created object and the dependency it
    used/created.

    This function protects against all of the cases where the dependency can
    be concurrently removed by catching exceptions and restarting the
    process of creating the dependency if one no longer exists. It will
    give up after neutron.db.api.MAX_RETRIES and raise the exception it
    encounters after that.

    TODO(kevinbenton): currently this does not try to delete the dependency
    it created. This matches the semantics of the HA network logic it is used
    for but it should be modified to cleanup in the future.
    """
    result, dependency, dep_id = None, None, None
    for attempts in range(1, db_api.MAX_RETRIES + 1):
        # we go to max + 1 here so the exception handlers can raise their
        # errors at the end
        try:
            dependency = dep_getter() or dep_creator()
            dep_id = getattr(dependency, dep_id_attr)
        except db_exc.DBDuplicateEntry:
            # dependency was concurrently created.
            with excutils.save_and_reraise_exception() as ctx:
                if attempts < db_api.MAX_RETRIES:
                    # sleep for a random time between 0 and 1 second to
                    # make sure a concurrent worker doesn't retry again
                    # at exactly the same time
                    time.sleep(random.uniform(0, 1))
                    ctx.reraise = False
                    continue
        try:
            result = creator(dependency)
            break
        except Exception:
            with excutils.save_and_reraise_exception() as ctx:
                # check if dependency we tried to use was removed during
                # object creation
                if attempts < db_api.MAX_RETRIES:
                    dependency = dep_getter()
                    if not dependency or dep_id != getattr(dependency,
                                                           dep_id_attr):
                        ctx.reraise = False
    return result, dependency


def transaction_guard(f):
    """Ensures that the context passed in is not in a transaction.

    Various Neutron methods modifying resources have assumptions that they will
    not be called inside of a transaction because they perform operations that
    expect all data to be committed to the database (e.g. ML2 postcommit calls)
    and/or they have side effects on external systems.
    So calling them in a transaction can lead to consistency errors on failures
    since the side effect will not be reverted on a DB rollback.

    If you receive this error, you must alter your code to handle the fact that
    the thing you are calling can have side effects so using transactions to
    undo on failures is not possible.
    """
    @functools.wraps(f)
    def inner(self, context, *args, **kwargs):
        if context.session.is_active:
            raise RuntimeError(_("Method cannot be called within a "
                                 "transaction."))
        return f(self, context, *args, **kwargs)
    return inner
