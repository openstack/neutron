..
      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.


Network IP Availability Extension
=================================

This extension is an information-only API that allows a user or process
to determine the amount of IPs that are consumed across networks and
their subnets' allocation pools. Each network and embedded subnet returns
with values for **used_ips** and **total_ips** making it easy
to determine how much of your network's IP space is consumed.

This API provides the ability for network administrators to periodically
list usage (manual or automated) in order to preemptively add new network
capacity when thresholds are exceeded.

**Important Note:**

This API tracks a network's "consumable" IPs. What's the distinction?
After a network and its subnets are created, consumable IPs
are:

* Consumed in the subnet's allocations (derives used IPs)
* Consumed from the subnet's allocation pools (derives total IPs)

This API tracks consumable IPs so network administrators know when their
subnet's IP pools (and ultimately a network's) IPs are about to run out.
This API does not account reserved IPs such as a subnet's gateway IP or other
reserved or unused IPs of a subnet's cidr that are consumed as a result of
the subnet creation itself.


API Specification
-----------------

Availability for all networks
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

GET /v2.0/network-ip-availabilities ::

    Request to url: v2.0/network-ip-availabilities
      headers: {'content-type': 'application/json', 'X-Auth-Token': 'SOME_AUTH_TOKEN'}

Example response ::

    Response:
      HTTP/1.1 200 OK
      Content-Type: application/json; charset=UTF-8

.. code::

    {
        "network_ip_availabilities": [
            {
                "network_id": "f944c153-3f46-417b-a3c2-487cd9a456b9",
                "network_name": "net1",
                "subnet_ip_availability": [
                    {
                        "cidr": "10.0.0.0/24",
                        "ip_version": 4,
                        "subnet_id": "46b1406a-8373-454c-8eb8-500a09eb77fb",
                        "subnet_name": "",
                        "total_ips": 253,
                        "used_ips": 3
                    }
                ],
                "tenant_id": "test-project",
                "total_ips": 253,
                "used_ips": 3
            },
            {
                "network_id": "47035bae-4f29-4fef-be2e-2941b72528a8",
                "network_name": "net2",
                "subnet_ip_availability": [],
                "tenant_id": "test-project",
                "total_ips": 0,
                "used_ips": 0
            },
            {
                "network_id": "2e3ea0cd-c757-44bf-bb30-42d038687e3f",
                "network_name": "net3",
                "subnet_ip_availability": [
                    {
                        "cidr": "40.0.0.0/24",
                        "ip_version": 4,
                        "subnet_id": "aab6b35c-16b5-489c-a5c7-fec778273495",
                        "subnet_name": "",
                        "total_ips": 253,
                        "used_ips": 2
                    }
                ],
                "tenant_id": "test-project",
                "total_ips": 253,
                "used_ips": 2
            }
        ]
    }

Availability by network ID
~~~~~~~~~~~~~~~~~~~~~~~~~~

GET /v2.0/network-ip-availabilities/{network\_uuid} ::

    Request to url: /v2.0/network-ip-availabilities/aba3b29b-c119-4b45-afbd-88e500acd970
      headers: {'content-type': 'application/json', 'X-Auth-Token': 'SOME_AUTH_TOKEN'}

Example response ::

    Response:
      HTTP/1.1 200 OK
      Content-Type: application/json; charset=UTF-8

.. code::

    {
        "network_ip_availability": {
            "network_id": "f944c153-3f46-417b-a3c2-487cd9a456b9",
            "network_name": "net1",
            "subnet_ip_availability": [
                {
                    "cidr": "10.0.0.0/24",
                    "ip_version": 4,
                    "subnet_name": "",
                    "subnet_id": "46b1406a-8373-454c-8eb8-500a09eb77fb",
                    "total_ips": 253,
                    "used_ips": 3
                }
            ],
            "tenant_id": "test-project",
            "total_ips": 253,
            "used_ips": 3
        }
    }

Supported Query Filters
~~~~~~~~~~~~~~~~~~~~~~~
This API currently supports the following query parameters:

* **network_id**: Returns availability for the network matching the network ID.
  Note: This query (?network_id={network_id_guid})is roughly equivalent to
  *Availability by network ID* section except it returns the plural
  response form as a list rather than as an item.
* **network_name**: Returns availability for network matching
  the provided name
* **tenant_id**: Returns availability for all networks owned by the provided
  project ID.
* **ip_version**: Filters network subnets by those supporting the supplied
  ip version. Values can be either 4 or 6.

Query filters can be combined to further narrow results and what is returned
will match all criteria. When a parameter is specified more
than once, it will return results that match both. Examples: ::

    # Fetch IPv4 availability for a specific project uuid
    GET /v2.0/network-ip-availabilities?ip_version=4&tenant_id=example-project-uuid

    # Fetch multiple networks by their ids
    GET /v2.0/network-ip-availabilities?network_id=uuid_sample_1&network_id=uuid_sample_2
