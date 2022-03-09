# File: msgfileparser_consts.py
#
# Copyright (c) 2019-2022 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
#
#
# Consts for error messages
MSGFILEPARSER_ERR_CODE_UNAVAILABLE = "Error code unavailable"
MSGFILEPARSER_ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or the action parameters."
MSGFILEPARSER_INVALID_INT_ERR = "Please provide a valid {msg} integer value in the '{param}' action parameter"
MSGFILEPARSER_VAULT_INFO_EXTRACTION_ERR = "Failed to get vault info of extracted file"
MSGFILEPARSER_VAULT_INFO_BEFORE_EXTRACTION_ERR = "Could not retrieve vault file"
MSGFILEPARSER_VAULT_ID_NOT_FOUND_ERR = "Vault ID not found"
MSGFILEPARSER_VAULT_METADATA_NOT_FOUND_ERR = "Failed to get vault item metadata"
MSGFILEPARSER_EMAIL_HEADER_MSG_ERR = "Unable to get email headers from message. Error: {0}"
MSGFILEPARSER_EMAIL_HEADER_FILE_ERR = "Unable to fetch the headers information from the provided MSG file"
MSGFILEPARSER_FETCH_DETAILS_FROM_FILE_ERR = "Unable to fetch the fromEmail, toEmail, and message ID information from the provided MSG file"
MSGFILEPARSER_UNABLE_TO_WRITE_FILE_ERR = "Unable to write file to tmp folder for attachment name: {0}. Error: {1}"
MSGFILEPARSER_UNABLE_TO_ADD_FILE_ERR = "Unable to add file to the vault for attachment name: {0}. Error: {1}"
MSGFILEPARSER_PROVIDE_LABEL_ERR = "A label must be specified if no container ID is provided"
MSGFILEPARSER_CONTAINERS_NOT_FOUND_ERR = "Unable to find container: {}"
MSGFILEPARSER_PARSER_MSG_FILE_ERR = "Failed to parse message. Please check if the provided file is valid msg file."
MSGFILEPARSER_PARSER_DECODE_ERR = "Failed to parse message. Error: {}"

# Consts for action names
MSGFILEPARSER_EXTRACT_EMAIL_ACTION = "extract_email"

# Regex statements used for extraction
URI_REGEX = r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+#]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+"
EMAIL_REGEX = r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"
EMAIL_REGEX2 = r'".*"@[A-Z0-9.-]+\.[A-Z]{2,}\b'
