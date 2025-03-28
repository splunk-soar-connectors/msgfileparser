# MSG File Parser

Publisher: Splunk \
Connector Version: 2.2.8 \
Product Vendor: Phantom \
Product Name: MSG File Parser \
Minimum Product Version: 6.1.1

This app parses an outlook .msg file and extracts IOCs into Container and Artifacts

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

Type: **generic** \
Read only: **False**

This action requires the input vault file to be an Outlook MSG file. This action creates artifacts for the email data (from, to, cc, date, subject, body) and the email's attachment(s).

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vault_id** | required | Vault ID of the .msg file | string | `vault id` `sha1` |
**container_id** | optional | Add created artifacts to this container | numeric | `phantom container id` |
**label** | optional | Creates a new Container with this label to add created artifacts | string | `phantom container label` |
**severity** | optional | Severity applied to the artifact(s) extracted from the .msg file | string | |
**artifact_name** | required | Name of artifact, default (Email Artifact) | string | |
**run_automation** | optional | If true, active playbooks will be triggered when artifacts are created | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.artifact_name | string | | Email Artifact |
action_result.parameter.container_id | numeric | `phantom container id` | 193 |
action_result.parameter.label | string | `phantom container label` | events email |
action_result.parameter.vault_id | string | `vault id` `sha1` | 492cafe7223b63c03413a290b8b7cefdfbc9e5d2 f1cba62002865cdcee8ce010abb87510c32c48ca |
action_result.data | string | | |
action_result.summary | string | | |
action_result.summary.artifacts_found | numeric | | 2 8 |
action_result.summary.container_id | numeric | `phantom container id` | 256 193 |
action_result.message | string | | Container id: 256, Artifacts found: 2 Container id: 193, Artifacts found: 8 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |
action_result.parameter.severity | string | | low medium |
action_result.parameter.run_automation | boolean | | True False |

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2025 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
