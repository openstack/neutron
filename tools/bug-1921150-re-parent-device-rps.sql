/*
    Licensed under the Apache License, Version 2.0 (the "License"); you may
    not use this file except in compliance with the License. You may obtain
    a copy of the License at

         http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
    License for the specific language governing permissions and limitations
    under the License.
*/

/*
Fix wrongly parented physical NIC resource providers due to bug
https://bugs.launchpad.net/neutron/+bug/1921150

Compatible with MySQL.
*/

USE placement;

SELECT 'Affected device RPs:' as '';

SELECT *
FROM resource_providers
WHERE
  (name LIKE '%:NIC Switch agent:%' OR
   name LIKE '%:Open vSwitch agent:%') AND
  parent_provider_id=root_provider_id;


/*
To find the proper parent we have to use the naming scheme of the RPs which
is <computePR.name>:<agentRP.name>:<deviceRP.name>
The name of the proper parent for deviceRP is name of the deviceRP minus
everything after the second ':'.
*/

UPDATE resource_providers as rp
INNER JOIN resource_providers as parent_rp
ON
  parent_rp.name=SUBSTRING(rp.name, 1, LOCATE(':', rp.name, LOCATE(':', rp.name) + 1) -1)
SET
  rp.parent_provider_id = parent_rp.id
WHERE
  (rp.name LIKE '%:NIC Switch agent:%' OR
   rp.name LIKE '%:Open vSwitch agent:%') AND
  rp.parent_provider_id=rp.root_provider_id;

SELECT CONCAT('Fixed ', ROW_COUNT(), ' RPs') as '';
