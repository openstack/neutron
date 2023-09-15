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


RPC API Layer
=============

Neutron uses the oslo.messaging library to provide an internal communication
channel between Neutron services.  This communication is typically done via
AMQP, but those details are mostly hidden by the use of oslo.messaging and it
could be some other protocol in the future.

RPC APIs are defined in Neutron in two parts: client side and server side.

Client Side
-----------

Here is an example of an rpc client definition:

::

  import oslo_messaging

  from neutron.common import rpc as n_rpc


  class ClientAPI(object):
      """Client side RPC interface definition.

      API version history:
          1.0 - Initial version
          1.1 - Added my_remote_method_2
      """

      def __init__(self, topic):
          target = oslo_messaging.Target(topic=topic, version='1.0')
          self.client = n_rpc.get_client(target)

      def my_remote_method(self, context, arg1, arg2):
          cctxt = self.client.prepare()
          return cctxt.call(context, 'my_remote_method', arg1=arg1, arg2=arg2)

      def my_remote_method_2(self, context, arg1):
          cctxt = self.client.prepare(version='1.1')
          return cctxt.call(context, 'my_remote_method_2', arg1=arg1)


This class defines the client side interface for an rpc API.  The interface has
2 methods.  The first method existed in version 1.0 of the interface.  The
second method was added in version 1.1.  When the newer method is called, it
specifies that the remote side must implement at least version 1.1 to handle
this request.

Server Side
-----------

The server side of an rpc interface looks like this:

::

  import oslo_messaging


  class ServerAPI(object):

      target = oslo_messaging.Target(version='1.1')

      def my_remote_method(self, context, arg1, arg2):
          return 'foo'

      def my_remote_method_2(self, context, arg1):
          return 'bar'


This class implements the server side of the interface.  The
oslo_messaging.Target() defined says that this class currently implements
version 1.1 of the interface.

.. _rpc_versioning:

Versioning
----------

Note that changes to rpc interfaces must always be done in a backwards
compatible way.  The server side should always be able to handle older clients
(within the same major version series, such as 1.X).

It is possible to bump the major version number and drop some code only needed
for backwards compatibility.  For more information about how to do that, see
https://wiki.openstack.org/wiki/RpcMajorVersionUpdates.

Example Change
~~~~~~~~~~~~~~

As an example minor API change, let's assume we want to add a new parameter to
my_remote_method_2.  First, we add the argument on the server side.  To be
backwards compatible, the new argument must have a default value set so that the
interface will still work even if the argument is not supplied.  Also, the
interface's minor version number must be incremented.  So, the new server side
code would look like this:

::

  import oslo_messaging


  class ServerAPI(object):

      target = oslo_messaging.Target(version='1.2')

      def my_remote_method(self, context, arg1, arg2):
          return 'foo'

      def my_remote_method_2(self, context, arg1, arg2=None):
          if not arg2:
              # Deal with the fact that arg2 was not specified if needed.
          return 'bar'

We can now update the client side to pass the new argument.  The client must
also specify that version '1.2' is required for this method call to be
successful.  The updated client side would look like this:

::

  import oslo_messaging

  from neutron.common import rpc as n_rpc


  class ClientAPI(object):
      """Client side RPC interface definition.

      API version history:
          1.0 - Initial version
          1.1 - Added my_remote_method_2
          1.2 - Added arg2 to my_remote_method_2
      """

      def __init__(self, topic):
          target = oslo_messaging.Target(topic=topic, version='1.0')
          self.client = n_rpc.get_client(target)

      def my_remote_method(self, context, arg1, arg2):
          cctxt = self.client.prepare()
          return cctxt.call(context, 'my_remote_method', arg1=arg1, arg2=arg2)

      def my_remote_method_2(self, context, arg1, arg2):
          cctxt = self.client.prepare(version='1.2')
          return cctxt.call(context, 'my_remote_method_2',
                            arg1=arg1, arg2=arg2)

Neutron RPC APIs
----------------

As discussed before, RPC APIs are defined in two parts: a client side and a
server side.  Several of these pairs exist in the Neutron code base.  The code
base is being updated with documentation on every rpc interface implementation
that indicates where the corresponding server or client code is located.

Example: DHCP
~~~~~~~~~~~~~

The DHCP agent includes a client API, neutron.agent.dhcp.agent.DhcpPluginAPI.
The DHCP agent uses this class to call remote methods back in the Neutron
server.  The server side is defined in
neutron.api.rpc.handlers.dhcp_rpc.DhcpRpcCallback.  It is up to the Neutron
plugin in use to decide whether the DhcpRpcCallback interface should be
exposed.

Similarly, there is an RPC interface defined that allows the Neutron plugin to
remotely invoke methods in the DHCP agent.  The client side is defined in
neutron.api.rpc.agentnotifiers.dhcp_rpc_agent_api.DhcpAgentNotifyAPI.  The
server side of this interface that runs in the DHCP agent is
neutron.agent.dhcp.agent.DhcpAgent.

More Info
---------

For more information, see the oslo.messaging documentation:
https://docs.openstack.org/oslo.messaging/latest/.
