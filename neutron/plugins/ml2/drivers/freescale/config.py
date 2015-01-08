# Copyright (c) 2014 Freescale Semiconductor
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

from neutronclient.v2_0 import client
from oslo_config import cfg

# Freescale CRD Server Configuration used by ML2 Mechanism Driver.
#
# The following configuration is used by Freescale Drivers/Plugin
# like, FWaaS Plugin, VPNaaS Plugin etc.. which connect to Cloud Resource
# Discovery Service (CRD).

# CRD service options required for FSL SDN OS Mech Driver
ml2_fslsdn_opts = [
    cfg.StrOpt('crd_user_name', default='crd',
               help=_("CRD service Username.")),
    cfg.StrOpt('crd_password', default='password',
               secret=True,
               help=_("CRD Service Password.")),
    cfg.StrOpt('crd_tenant_name', default='service',
               help=_("CRD Tenant Name.")),
    cfg.StrOpt('crd_auth_url',
               default='http://127.0.0.1:5000/v2.0/',
               help=_("CRD Auth URL.")),
    cfg.StrOpt('crd_url',
               default='http://127.0.0.1:9797',
               help=_("URL for connecting to CRD service.")),
    cfg.IntOpt('crd_url_timeout',
               default=30,
               help=_("Timeout value for connecting to "
                      "CRD service in seconds.")),
    cfg.StrOpt('crd_region_name',
               default='RegionOne',
               help=_("Region name for connecting to "
                      "CRD Service in admin context.")),
    cfg.BoolOpt('crd_api_insecure',
                default=False,
                help=_("If set, ignore any SSL validation issues.")),
    cfg.StrOpt('crd_auth_strategy',
               default='keystone',
               help=_("Auth strategy for connecting to "
                      "neutron in admin context.")),
    cfg.StrOpt('crd_ca_certificates_file',
               help=_("Location of ca certificates file to use for "
                      "CRD client requests.")),
]

# Register the configuration option for crd service
cfg.CONF.register_opts(ml2_fslsdn_opts, "ml2_fslsdn")

# shortcut
FSLCONF = cfg.CONF.ml2_fslsdn

SERVICE_TYPE = 'crd'


def get_crdclient():
    """Using the CRD configuration, get and return CRD Client instance."""
    crd_client_params = {
        'username': FSLCONF.crd_user_name,
        'tenant_name': FSLCONF.crd_tenant_name,
        'region_name': FSLCONF.crd_region_name,
        'password': FSLCONF.crd_password,
        'auth_url': FSLCONF.crd_auth_url,
        'auth_strategy': FSLCONF.crd_auth_strategy,
        'endpoint_url': FSLCONF.crd_url,
        'timeout': FSLCONF.crd_url_timeout,
        'insecure': FSLCONF.crd_api_insecure,
        'service_type': SERVICE_TYPE,
        'ca_cert': FSLCONF.crd_ca_certificates_file,
    }
    return client.Client(**crd_client_params)
