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


Transient DB Failure Injection
==============================

Neutron has a service plugin to inject random delays and Deadlock exceptions
into normal Neutron operations. The service plugin is called 'Loki' and is
located under neutron.services.loki.loki_plugin.

To enable the plugin, just add 'loki' to the list of service_plugins in your
neutron-server neutron.conf file.

The plugin will inject a Deadlock exception on database flushes with a 1/50
probability and a delay of 1 second with a 1/200 probability when SQLAlchemy
objects are loaded into the persistent state from the DB. The goal is to ensure
the code is tolerant of these transient delays/failures that will be experienced
in busy production (and Galera) systems.
