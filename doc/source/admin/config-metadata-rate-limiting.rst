.. _config-metadata-rate-limiting:

====================================
Metadata Service Query Rate-limiting
====================================

The OpenStack Networking service proxies the requests that VMs send to the
Compute service to obtain their metadata. The Networking service offers cloud
administrators the ability to limit the rate at which VMs query the Compute's
metadata service, in order to protect the OpenStack deployment from DoS or
misbehaved instances.

Metadata requests rate limiting is configured through the following parameters
in the ``metadata_rate_limiting`` section of
``neutron.conf``:

* ``rate_limit_enabled``: enables rate limiting of metadata requests. It is
  a boolean that is set to ``False`` by default.
* ``ip_versions``: list of comma separated strings that specify the metadata
  address versions (4 and/or 6) for which rate limiting must be enabled. The
  default is to configure rate limiting only for the IPv4 address.
* ``base_window_duration``: defines in seconds the duration of the base time
  sliding window in which query requests will be rate limited. The default
  value is 10 seconds.
* ``base_query_rate_limit``: maximum number of requests to be allowed during
  the base time window. The default value is 10 requests.
* ``burst_window_duration``: this parameter can be used to define, in seconds,
  a shorter sliding window of time during which a requests rate higher than the
  base one will be allowed. The default value is 10 seconds.
* ``burst_query_rate_limit``: maximum number of requests to be allowed during
  the burst time window. The default value is 10 requests.

.. note::
   These parameters are used to configure HAProxy servers to perform the rate
   limiting. These servers run inside L3 routers and DHCP agents in the OVS
   backend and the metadata agent in the OVN backend.

.. note::
   At the moment, rate limiting can only be configured either for IPv4 or IPv6
   but not both at the same time, due to a limitation in the open source
   version of HAProxy.

.. note::
   From the point of view of the Networking services, the base and burst
   windows are just two different sliding periods of time during which to
   enforce two different metadata requests rate limits. The Networking service
   doesn't enforce that the burst window should be shorter or that the burst
   rate should be higher. It is recommended, though, that cloud administrators
   use the burst window to allow, for shorter periods of time, a higher
   requests rate than the allowed during the base window, if there is a need to
   do so.

In the following ``neutron.conf`` snippet, the Networking service is configured
to allow VMs to query the IPv4 metadata service address 6 times over a 60
seconds period, while allowing a higher rate of 2 queries during shorter
periods of 10 seconds each:

.. code-block:: console

   [metadata_rate_limiting]
   rate_limit_enabled = True
   ip_versions = 4
   base_window_duration = 60
   base_query_rate_limit = 6
   burst_window_duration = 10
   burst_query_rate_limit = 2
