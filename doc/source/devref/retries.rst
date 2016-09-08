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


Retrying Operations
===================

Inside of the neutron.db.api module there is a decorator called
'retry_if_session_inactive'. This should be used to protect any
functions that perform DB operations. This decorator will capture
any deadlock errors, RetryRequests, connection errors, and unique
constraint violations that are thrown by the function it is
protecting.

This decorator will not retry an operation if the function it is
applied to is called within an active session. This is because the
majority of the exceptions it captures put the session into a
partially rolled back state so it is no longer usable. It is important
to ensure there is a decorator outside of the start of the transaction.
The decorators are safe to nest if a function is sometimes called inside
of another transaction.

If a function is being protected that does not take context as an
argument the 'retry_db_errors' decorator function may be used instead.
It retries the same exceptions and has the same anti-nesting behavior
as 'retry_if_session_active', but it does not check if a session is
attached to any context keywords. ('retry_if_session_active' just uses
'retry_db_errors' internally after checking the session)

Idempotency on Failures
-----------------------
The function that is being decorated should always fully cleanup whenever
it encounters an exception so its safe to retry the operation. So if a
function creates a DB object, commits, then creates another, the function
must have a cleanup handler to remove the first DB object in the case that
the second one fails. Assume any DB operation can throw a retriable error.

You may see some retry decorators at the API layers in Neutron; however,
we are trying to eliminate them because each API operation has many
independent steps that makes ensuring idempotency on partial failures
very difficult.

Argument Mutation
-----------------
A decorated function should not mutate any complex arguments which are
passed into it. If it does, it should have an exception handler that reverts
the change so it's safe to retry.

The decorator will automatically create deep copies of sets, lists,
and dicts which are passed through it, but it will leave the other arguments
alone.


Retrying to Handle Race Conditions
----------------------------------
One of the difficulties with detecting race conditions to create a DB record
with a unique constraint is determining where to put the exception handler
because a constraint violation can happen immediately on flush or it may not
happen all of the way until the transaction is being committed on the exit
of the session context manager. So we would end up with code that looks
something like this:

::

  def create_port(context, ip_address, mac_address):
      _ensure_mac_not_in_use(context, mac_address)
      _ensure_ip_not_in_use(context, ip_address)
      try:
          with context.session.begin():
             port_obj = Port(ip=ip_address, mac=mac_address)
             do_expensive_thing(...)
             do_extra_other_thing(...)
             return port_obj
      except DBDuplicateEntry as e:
          # code to parse columns
          if 'mac' in e.columns:
              raise MacInUse(mac_address)
          if 'ip' in e.columns:
              raise IPAddressInUse(ip)

  def _ensure_mac_not_in_use(context, mac):
      if context.session.query(Port).filter_by(mac=mac).count():
          raise MacInUse(mac)

  def _ensure_ip_not_in_use(context, ip):
      if context.session.query(Port).filter_by(ip=ip).count():
          raise IPAddressInUse(ip)


So we end up with an exception handler that has to understand where things
went wrong and convert them into appropriate exceptions for the end-users.
This distracts significantly from the main purpose of create_port.

Since the retry decorator will automatically catch and retry DB duplicate
errors for us, we can allow it to retry on this race condition which will
give the original validation logic to be re-executed and raise the
appropriate error. This keeps validation logic in one place and makes the
code cleaner.

::

  from neutron.db import api as db_api

  @db_api.retry_if_session_inactive()
  def create_port(context, ip_address, mac_address):
      _ensure_mac_not_in_use(context, mac_address)
      _ensure_ip_not_in_use(context, ip_address)
      with context.session.begin():
         port_obj = Port(ip=ip_address, mac=mac_address)
         do_expensive_thing(...)
         do_extra_other_thing(...)
         return port_obj

  def _ensure_mac_not_in_use(context, mac):
      if context.session.query(Port).filter_by(mac=mac).count():
          raise MacInUse(mac)

  def _ensure_ip_not_in_use(context, ip):
      if context.session.query(Port).filter_by(ip=ip).count():
          raise IPAddressInUse(ip)



Nesting
-------
Once the decorator retries an operation the maximum number of times, it
will attach a flag to the exception it raises further up that will prevent
decorators around the calling functions from retrying the error again.
This prevents an exponential increase in the number of retries if they are
layered.

Usage
-----

Here are some usage examples:

::

  from neutron.db import api as db_api

  @db_api.retry_if_session_inactive()
  def create_elephant(context, elephant_details):
      ....

  @db_api.retry_if_session_inactive()
  def atomic_bulk_create_elephants(context, elephants):
      with context.session.begin():
          for elephant in elephants:
              # note that if create_elephant throws a retriable
              # exception, the decorator around it will not retry
              # because the session is active. The decorator around
              # atomic_bulk_create_elephants will be responsible for
              # retrying the entire operation.
              create_elephant(context, elephant)

  # sample usage when session is attached to a var other than 'context'
  @db_api.retry_if_session_inactive(context_var_name='ctx')
  def some_function(ctx):
      ...
