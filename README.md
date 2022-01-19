[comment]: # "Auto-generated SOAR connector documentation"
# MSG File Parser

Publisher: Splunk  
Connector Version: 2\.2\.4  
Product Vendor: Phantom  
Product Name: MSG File Parser  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 4\.10\.0\.40961  

This app parses an outlook \.msg file and extracts IOCs into Container and Artifacts

[comment]: # " File: readme.md"
[comment]: # "  Copyright (c) 2019-2022 Splunk Inc."
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""
## outlookmsgfile

This app uses the outlookmsgfile module, which is licensed under the MIT License, Copyright (c) 2018
Joshua Tauberer.

## compoundfiles

This app uses the compoundfiles module, which is licensed under the MIT License, Copyright (c) 2014
Dave Jones.

## compressed_rtf

This app uses the compressed_rtf module, which is licensed under the MIT License, Copyright (c) 2016
Dmitry Alimov.


### Supported Actions  
[extract email](#action-extract-email) - Extract email data from Outlook MSG files  

## action: 'extract email'
Extract email data from Outlook MSG files

Type: **generic**  
Read only: **False**

This action requires the input vault file to be an Outlook MSG file\. This action creates artifacts for the email data \(from, to, cc, date, subject, body\) and the email's attachment\(s\)\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vault\_id** |  required  | Vault ID of the \.msg file | string |  `vault id`  `sha1` 
**container\_id** |  optional  | Add created artifacts to this container | numeric |  `phantom container id` 
**label** |  optional  | Creates a new Container with this label to add created artifacts | string |  `phantom container label` 
**severity** |  optional  | Severity applied to the artifact\(s\) extracted from the \.msg file | string | 
**artifact\_name** |  required  | Name of artifact, default \(Email Artifact\) | string | 
**run\_automation** |  optional  | If true, active playbooks will be triggered when artifacts are created | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.artifact\_name | string | 
action\_result\.parameter\.container\_id | numeric |  `phantom container id` 
action\_result\.parameter\.label | string |  `phantom container label` 
action\_result\.parameter\.vault\_id | string |  `vault id`  `sha1` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.summary\.artifacts\_found | numeric | 
action\_result\.summary\.container\_id | numeric |  `phantom container id` 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 
action\_result\.parameter\.severity | string | 
action\_result\.parameter\.run\_automation | boolean | 