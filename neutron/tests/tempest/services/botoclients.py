# Copyright 2012 OpenStack Foundation
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

import ConfigParser
import contextlib
from tempest_lib import exceptions as lib_exc
import types
import urlparse

from neutron.tests.tempest import config

import boto
import boto.ec2
import boto.s3.connection

CONF = config.CONF


class BotoClientBase(object):

    ALLOWED_METHODS = set()

    def __init__(self, identity_client):
        self.identity_client = identity_client

        self.ca_cert = CONF.identity.ca_certificates_file
        self.connection_timeout = str(CONF.boto.http_socket_timeout)
        self.num_retries = str(CONF.boto.num_retries)
        self.build_timeout = CONF.boto.build_timeout

        self.connection_data = {}

    def _config_boto_timeout(self, timeout, retries):
        try:
            boto.config.add_section("Boto")
        except ConfigParser.DuplicateSectionError:
            pass
        boto.config.set("Boto", "http_socket_timeout", timeout)
        boto.config.set("Boto", "num_retries", retries)

    def _config_boto_ca_certificates_file(self, ca_cert):
        if ca_cert is None:
            return

        try:
            boto.config.add_section("Boto")
        except ConfigParser.DuplicateSectionError:
            pass
        boto.config.set("Boto", "ca_certificates_file", ca_cert)

    def __getattr__(self, name):
        """Automatically creates methods for the allowed methods set."""
        if name in self.ALLOWED_METHODS:
            def func(self, *args, **kwargs):
                with contextlib.closing(self.get_connection()) as conn:
                    return getattr(conn, name)(*args, **kwargs)

            func.__name__ = name
            setattr(self, name, types.MethodType(func, self, self.__class__))
            setattr(self.__class__, name,
                    types.MethodType(func, None, self.__class__))
            return getattr(self, name)
        else:
            raise AttributeError(name)

    def get_connection(self):
        self._config_boto_timeout(self.connection_timeout, self.num_retries)
        self._config_boto_ca_certificates_file(self.ca_cert)

        ec2_client_args = {'aws_access_key_id': CONF.boto.aws_access,
                           'aws_secret_access_key': CONF.boto.aws_secret}
        if not all(ec2_client_args.values()):
            ec2_client_args = self.get_aws_credentials(self.identity_client)

        self.connection_data.update(ec2_client_args)
        return self.connect_method(**self.connection_data)

    def get_aws_credentials(self, identity_client):
        """
        Obtain existing, or create new AWS credentials
        :param identity_client: identity client with embedded credentials
        :return: EC2 credentials
        """
        ec2_cred_list = identity_client.list_user_ec2_credentials(
            identity_client.user_id)
        for cred in ec2_cred_list:
            if cred['tenant_id'] == identity_client.tenant_id:
                ec2_cred = cred
                break
        else:
            ec2_cred = identity_client.create_user_ec2_credentials(
                identity_client.user_id, identity_client.tenant_id)
        if not all((ec2_cred, ec2_cred['access'], ec2_cred['secret'])):
            raise lib_exc.NotFound("Unable to get access and secret keys")
        else:
            ec2_cred_aws = {}
            ec2_cred_aws['aws_access_key_id'] = ec2_cred['access']
            ec2_cred_aws['aws_secret_access_key'] = ec2_cred['secret']
        return ec2_cred_aws


class APIClientEC2(BotoClientBase):

    def connect_method(self, *args, **kwargs):
        return boto.connect_ec2(*args, **kwargs)

    def __init__(self, identity_client):
        super(APIClientEC2, self).__init__(identity_client)
        insecure_ssl = CONF.identity.disable_ssl_certificate_validation
        purl = urlparse.urlparse(CONF.boto.ec2_url)

        region_name = CONF.compute.region
        if not region_name:
            region_name = CONF.identity.region
        region = boto.ec2.regioninfo.RegionInfo(name=region_name,
                                                endpoint=purl.hostname)
        port = purl.port
        if port is None:
            if purl.scheme is not "https":
                port = 80
            else:
                port = 443
        else:
            port = int(port)
        self.connection_data.update({"is_secure": purl.scheme == "https",
                                     "validate_certs": not insecure_ssl,
                                     "region": region,
                                     "host": purl.hostname,
                                     "port": port,
                                     "path": purl.path})

    ALLOWED_METHODS = set(('create_key_pair', 'get_key_pair',
                           'delete_key_pair', 'import_key_pair',
                           'get_all_key_pairs',
                           'get_all_tags',
                           'create_image', 'get_image',
                           'register_image', 'deregister_image',
                           'get_all_images', 'get_image_attribute',
                           'modify_image_attribute', 'reset_image_attribute',
                           'get_all_kernels',
                           'create_volume', 'delete_volume',
                           'get_all_volume_status', 'get_all_volumes',
                           'get_volume_attribute', 'modify_volume_attribute'
                           'bundle_instance', 'cancel_spot_instance_requests',
                           'confirm_product_instanc',
                           'get_all_instance_status', 'get_all_instances',
                           'get_all_reserved_instances',
                           'get_all_spot_instance_requests',
                           'get_instance_attribute', 'monitor_instance',
                           'monitor_instances', 'unmonitor_instance',
                           'unmonitor_instances',
                           'purchase_reserved_instance_offering',
                           'reboot_instances', 'request_spot_instances',
                           'reset_instance_attribute', 'run_instances',
                           'start_instances', 'stop_instances',
                           'terminate_instances',
                           'attach_network_interface', 'attach_volume',
                           'detach_network_interface', 'detach_volume',
                           'get_console_output',
                           'delete_network_interface', 'create_subnet',
                           'create_network_interface', 'delete_subnet',
                           'get_all_network_interfaces',
                           'allocate_address', 'associate_address',
                           'disassociate_address', 'get_all_addresses',
                           'release_address',
                           'create_snapshot', 'delete_snapshot',
                           'get_all_snapshots', 'get_snapshot_attribute',
                           'modify_snapshot_attribute',
                           'reset_snapshot_attribute', 'trim_snapshots',
                           'get_all_regions', 'get_all_zones',
                           'get_all_security_groups', 'create_security_group',
                           'delete_security_group', 'authorize_security_group',
                           'authorize_security_group_egress',
                           'revoke_security_group',
                           'revoke_security_group_egress'))


class ObjectClientS3(BotoClientBase):

    def connect_method(self, *args, **kwargs):
        return boto.connect_s3(*args, **kwargs)

    def __init__(self, identity_client):
        super(ObjectClientS3, self).__init__(identity_client)
        insecure_ssl = CONF.identity.disable_ssl_certificate_validation
        purl = urlparse.urlparse(CONF.boto.s3_url)
        port = purl.port
        if port is None:
            if purl.scheme is not "https":
                port = 80
            else:
                port = 443
        else:
            port = int(port)
        self.connection_data.update({"is_secure": purl.scheme == "https",
                                     "validate_certs": not insecure_ssl,
                                     "host": purl.hostname,
                                     "port": port,
                                     "calling_format": boto.s3.connection.
                                     OrdinaryCallingFormat()})

    ALLOWED_METHODS = set(('create_bucket', 'delete_bucket', 'generate_url',
                           'get_all_buckets', 'get_bucket', 'delete_key',
                           'lookup'))
