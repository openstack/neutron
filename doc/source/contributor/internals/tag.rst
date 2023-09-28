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


      Convention for heading levels in Neutron devref:
      =======  Heading 0 (reserved for the title in a document)
      -------  Heading 1
      ~~~~~~~  Heading 2
      +++++++  Heading 3
      '''''''  Heading 4
      (Avoid deeper levels because they do not render well.)


Tags in Neutron Resources
=========================

Tag service plugin allows users to set tags on their resources. Tagging
resources can be used by external systems or any other clients of the Neutron
REST API (and NOT backend drivers).

The following use cases refer to adding tags to networks, but the same
can be applicable to any other Neutron resource:

1) Ability to map different networks in different OpenStack locations
   to one logically same network (for Multi site OpenStack)

2) Ability to map Id's from different management/orchestration systems to
   OpenStack networks in mixed environments, for example for project Kuryr,
   map docker network id to neutron network id

3) Leverage tags by deployment tools

4) allow operators to tag information about provider networks
   (e.g. high-bandwidth, low-latency, etc)

5) new features like get-me-a-network or a similar port scheduler
   could choose a network for a port based on tags

Which Resources
---------------

Tag system uses standardattr mechanism so it's targeting to resources that have
the mechanism. Some resources with standard attribute don't suit fit tag
support usecases (e.g. security_group_rule). If new tag support resource is
added, the resource model should inherit HasStandardAttributes and then it must
implement the property 'api_parent' and 'tag_support'. And also the change
must include a release note for API user.

Current API resources extended by tag extensions:

- floatingips
- networks
- network_segment_ranges
- policies
- ports
- routers
- security_groups
- subnetpools
- subnets
- trunks

Model
-----

Tag is not standalone resource. Tag is always related to existing
resources. The following shows tag model::

    +------------------+        +------------------+
    |     Network      |        |       Tag        |
    +------------------+        +------------------+
    | standard_attr_id +------> | standard_attr_id |
    |                  |        | tag              |
    |                  |        |                  |
    +------------------+        +------------------+

Tag has two columns only and tag column is just string. These tags are
defined per resource. Tag is unique in a resource but it can be
overlapped throughout.

API
---

The following shows basic API for tag. Tag is regarded as a subresource of
resource so API always includes id of resource related to tag.

Add a single tag on a network ::

    PUT /v2.0/networks/{network_id}/tags/{tag}

Returns `201 Created`. If the tag already exists, no error is raised, it
just returns the `201 Created` because the `OpenStack Development Mailing List
<http://lists.openstack.org/pipermail/openstack-dev/2016-February/087638.html>`_
discussion told us that PUT should be no issue updating an existing tag.

Replace set of tags on a network ::

    PUT /v2.0/networks/{network_id}/tags

with request payload ::

    {
        'tags': ['foo', 'bar', 'baz']
    }

Response ::

    {
        'tags': ['foo', 'bar', 'baz']
    }

Check if a tag exists or not on a network ::

    GET /v2.0/networks/{network_id}/tags/{tag}

Remove a single tag on a network ::

    DELETE /v2.0/networks/{network_id}/tags/{tag}

Remove all tags on a network ::

    DELETE /v2.0/networks/{network_id}/tags

PUT and DELETE for collections are the motivation of `extending the API
framework <https://review.opendev.org/#/c/284519/>`_.
