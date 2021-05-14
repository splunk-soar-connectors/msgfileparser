# File: msgfileparser_connector.py
# Copyright (c) 2019-2021 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
from phantom.vault import Vault

import requests
import json
import tempfile
import os
import email
import hashlib
import base64
import quopri
import re
import sys
from bs4 import BeautifulSoup, UnicodeDammit
from ExtractMsg import Message
from requests.structures import CaseInsensitiveDict
from msgfileparser_consts import *


_container_common = {
    "run_automation": False  # Don't run any playbooks, when this artifact is added
}


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class MsgFileParserConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(MsgFileParserConnector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None

    def _handle_py_ver_compat_for_input_str(self, input_str, always_encode=False):
        """
        This method returns the encoded|original string based on the Python version.
        :param input_str: Input string to be processed
        :param always_encode: Used if the string needs to be encoded for python 3
        :return: input_str (Processed input string based on following logic 'input_str - Python 3; encoded input_str - Python 2')
        """

        try:
            if input_str and (self._python_version == 2 or always_encode):
                input_str = UnicodeDammit(input_str).unicode_markup.encode('utf-8')
        except:
            self.debug_print("Error occurred while handling python 2to3 compatibility for the input string")

        return input_str

    def _get_error_message_from_exception(self, e):
        """ This method is used to get appropriate error message from the exception.
        :param e: Exception object
        :return: error message
        """
        error_code = MSGFILEPARSER_ERR_CODE_UNAVAILABLE
        error_msg = MSGFILEPARSER_ERR_MSG_UNAVAILABLE

        try:
            if e.args:
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_msg = str(e)
                elif len(e.args) == 1:
                    error_code = MSGFILEPARSER_ERR_CODE_UNAVAILABLE
                    error_msg = e.args[0]
        except:
            pass

        try:
            error_msg = self._handle_py_ver_compat_for_input_str(error_msg)
        except TypeError:
            error_msg = MSGFILEPARSER_UNICODE_DAMMIT_TYPE_ERR
        except:
            error_msg = MSGFILEPARSER_ERR_MSG_UNAVAILABLE

        return "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)

    def _validate_integer(self, action_result, parameter, key, allow_zero=False):
        if parameter is not None:
            try:
                if not float(parameter).is_integer():
                    return action_result.set_status(phantom.APP_ERROR, MSGFILEPARSER_INVALID_INT_ERR.format(msg="", param=key)), None

                parameter = int(parameter)
            except:
                return action_result.set_status(phantom.APP_ERROR, MSGFILEPARSER_INVALID_INT_ERR.format(msg="", param=key)), None

            if parameter < 0:
                return action_result.set_status(phantom.APP_ERROR, MSGFILEPARSER_INVALID_INT_ERR.format(msg="non-negative", param=key)), None
            if not allow_zero and parameter == 0:
                return action_result.set_status(phantom.APP_ERROR, MSGFILEPARSER_INVALID_INT_ERR.format(msg="non-zero positive", param=key)), None

        return phantom.APP_SUCCESS, parameter

    def _process_empty_response(self, response, action_result):

        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        error_msg = "Status code: {}. Empty response and no information in the header".format(response.status_code)
        return RetVal(action_result.set_status(phantom.APP_ERROR, error_msg), None)

    def _process_html_response(self, response, action_result):

        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code,
                error_text)

        message = message.replace('{', '{{').replace('}', '}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):

        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            error_msg = self._get_error_message_from_exception(e)
            return RetVal(action_result.set_status(phantom.APP_ERROR,
                "Unable to parse JSON response. Error: {0}".format(error_msg)), None)

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):

        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if 'json' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_response(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, headers=None, params=None, data=None, method="get"):

        config = self.get_config()

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        # Create a URL to connect to
        url = self._base_url + endpoint

        try:
            r = request_func(
                            url,
                            # auth=(username, password),  # basic authentication
                            data=data,
                            headers=headers,
                            verify=config.get('verify_server_cert', False),
                            params=params)
        except Exception as e:
            error_msg = self._get_error_message_from_exception(e)
            return RetVal(action_result.set_status( phantom.APP_ERROR,
                "Error Connecting to server. Details: {0}".format(error_msg)), resp_json)

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # NOTE: test connectivity does _NOT_ take any parameters
        # i.e. the param dictionary passed to this handler will be empty.
        # Also typically it does not add any data into an action_result either.
        # The status and progress messages are more important.

        """
        # self.save_progress("Connecting to endpoint")
        # make rest call
        ret_val, response = self._make_rest_call('/endpoint', action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            self.save_progress("Test Connectivity Failed.")
            return action_result.get_status()

        # Return success
        # self.save_progress("Test Connectivity Passed")
        # return action_result.set_status(phantom.APP_SUCCESS)
        """

        # For now return Error with a message, in case of success we don't set the message, but use the summary
        self.save_progress("Test Connectivity Failed")
        return action_result.set_status(phantom.APP_ERROR, "Action not yet implemented")

    def _add_vault_hashes_to_dictionary(self, cef_artifact, vault_id, action_result):

        try:
            url = '{0}rest/container_attachment'.format(self._get_phantom_base_url())
            query_params = {
                    '_filter_vault_document__hash': '"{}"'.format(vault_id),
                    'page_size': 1,
                    'pretty': ''
            }
            r = requests.get(url, params=query_params, verify=False)
            resp_data = r.json()
            vault_info = resp_data['data'][0]
            for k in list(vault_info):
                if k.startswith('_pretty_'):
                    name = k[8:]
                    vault_info[name] = vault_info.pop(k)
        except Exception as e:
            error_msg = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "Failed to get vault info of extracted file. Error: {0}".format(error_msg))

        if (not vault_info):
            return (phantom.APP_ERROR, "Vault ID not found")

        # /rest/container_attachment (with pretty) returns metadata about the file including multiple common hash formats
        try:
            metadata = vault_info.get('metadata')
        except:
            return action_result.set_status(phantom.APP_ERROR, "Failed to get vault item metadata")

        try:
            cef_artifact['fileHashSha256'] = metadata['sha256']
        except:
            pass

        try:
            cef_artifact['fileHashMd5'] = metadata['md5']
        except:
            pass

        try:
            cef_artifact['fileHashSha1'] = metadata['sha1']
        except:
            pass

        return (phantom.APP_SUCCESS)

    def _get_vault_artifact(self, vault_info, file_name, action_result):

        vault_artifact = {'name': 'Vault Artifact'}
        cef = vault_artifact['cef'] = dict()
        cef['vaultId'] = vault_info.get('vault_id')
        cef['fileName'] = file_name

        ret_val = self._add_vault_hashes_to_dictionary(cef, cef['vaultId'], action_result)

        return (ret_val, vault_artifact)

    def _get_email_headers_from_mail(self, mail, charset=None, email_headers=None):

        if mail:
            email_headers = mail.items()

            # TODO: the next 2 ifs can be condensed to use 'or'
            if (charset is None):
                charset = mail.get_content_charset().strip() if mail.get_content_charset() else None

        if (not charset):
            charset = 'utf-8'

        if (not email_headers):
            return {}

        # Convert the header tuple into a dictionary
        headers = CaseInsensitiveDict()
        [headers.update({x[0]: str(x[1])}) for x in email_headers]

        # Decode unicode subject
        utf_regex = re.compile(r'\?utf-8\?')
        for key, hdr in headers.items():
            if utf_regex.search(hdr.lower()):
                chars = 'utf-8'
                headers[key] = self._decode_header(hdr, chars)

        # Handle received seperately
        received_headers = [str(x[1]) for x in email_headers if x[0].lower() == 'received']

        if (received_headers):
            headers['Received'] = received_headers

        # handle the subject string, if required add a new key
        subject = headers.get('Subject')
        if (subject):
            headers['decodedSubject'] = subject

        return headers

    def _decode_header(self, hdr, charset):

        # Decode header unicode
        hdr = hdr.replace('"', '').replace(' ', '')
        decoded_header = ''
        try:
            if '?utf-8?b?' in hdr.lower():
                hdr = hdr.replace('?UTF-8?B?', '').replace('?utf-8?B?', '').replace('?=', '')
                hdr = base64.b64decode(hdr)
            elif '?utf-8?q?' in hdr.lower():
                hdr = hdr.replace('?UTF-8?Q?', '').replace('?utf-8?Q?', '').replace('?=', '')
                hdr = quopri.decodestring(hdr)
            hdr = hdr.decode(charset, "ignore")
            decoded_header = decoded_header + hdr
            return decoded_header
        except Exception as e:
            error_msg = self._get_error_message_from_exception(e)
            decoded_header = 'Unable to decode header: {}'.format(error_msg)
            return decoded_header

    def _create_email_artifact(self, msg, email_artifact, action_result, artifact_name, charset=None):

        try:
            try:
                email_text = msg._getStringStream('__substg1.0_007D').decode('utf-8')
            except:
                email_text = msg._getStringStream('__substg1.0_007D')
            if email_text:
                mail = email.message_from_string(email_text)

                # When '_headers' = [] (empty-list), bool(mail) returns False
                if not mail:
                    self.debug_print("Trying to fetch the headers information by an alternative approach of extraction of additional headers prefix data")
                    first_col_ind = email_text.find(":")
                    first_lf_ind = email_text.find("\n")
                    # Check if there is additional prefix before original headers string, if yes,
                    # extract that additional string in an additional prefix called "Header-Prefix" and
                    # extract the remaining email text for parsing the other headers information
                    if first_col_ind != -1 and '\n' in email_text[:first_col_ind]:
                        self.debug_print("Trying to fetch the headers information by extraction of additional headers prefix data")
                        prefix_header = "Header-Prefix: {}".format(email_text[:first_lf_ind + 1])
                        email_text = "{}{}".format(prefix_header, email_text[first_lf_ind + 1: ])
                        mail = email.message_from_string(email_text)
                    else:
                        try:
                            self.debug_print("Unable to fetch the additional header prefix and other headers details from the email text")
                            self.debug_print("Email-text: {}".format(self._handle_py_ver_compat_for_input_str(email_text)))
                        except:
                            self.debug_print("Error occurred while logging the email text in _create_email_artifact")
                headers = self._get_email_headers_from_mail(mail, charset)
            else:
                headers_data = msg._header
                if not headers_data:
                    return action_result.set_status(phantom.APP_ERROR, "Unable to get email headers from message")
                headers_dict = headers_data.__dict__
                headers = self._get_email_headers_from_mail(None, charset, email_headers=headers_dict.get('_headers'))
        except Exception as e:
            error_msg = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR,
                    "Unable to get email header string from message. Error: {0}".format(error_msg))

        if (not headers):
            return action_result.set_status(phantom.APP_ERROR, "Unable to fetch the headers information from the provided MSG file")

        # Parse email keys first
        cef_artifact = {}
        cef_types = {}

        if (headers.get('From')):
            emails = headers['From']
            if (emails):
                cef_artifact.update({'fromEmail': emails})

        if (headers.get('To')):
            emails = headers['To']
            if (emails):
                cef_artifact.update({'toEmail': emails})

        # if the header did not contain any email addresses then ignore this artifact
        message_id = headers.get('message-id')
        if ((not cef_artifact) and (message_id is None)):
            return action_result.set_status(phantom.APP_ERROR, "Unable to fetch the fromEmail, toEmail, and message ID information from the provided MSG file")

        try:
            cef_artifact['bodyText'] = self._extract_str(msg.body).decode('utf-8', 'replace').replace(u'\u0000', '')
        except:
            cef_artifact['bodyText'] = self._extract_str(msg.body).replace(u'\u0000', '')

        try:
            body_html = msg._getStringStream('__substg1.0_1013')
            if (body_html):
                try:
                    cef_artifact['bodyHtml'] = body_html.decode('utf-8', 'replace').replace(u'\u0000', '')
                except:
                    cef_artifact['bodyHtml'] = body_html.replace(u'\u0000', '')
        except:
            pass

        cef_types.update({'fromEmail': ['email'], 'toEmail': ['email']})

        if (headers):
            # convert from CaseInsensitive to normal dict, so that it is serializable
            cef_artifact['emailHeaders'] = dict(headers)

        email_artifact['name'] = artifact_name
        email_artifact['cef'] = cef_artifact
        email_artifact['cef_types'] = cef_types

        return (phantom.APP_SUCCESS)

    def _create_dict_hash(self, input_dict):

        input_dict_str = None

        if (not input_dict):
            return None

        try:
            input_dict_str = json.dumps(input_dict, sort_keys=True)
        except Exception as e:
            error_msg = self._get_error_message_from_exception(e)
            self.debug_print('Handled exception in _create_dict_hash. Error: {0}'.format(error_msg))
            return None

        return hashlib.md5(input_dict_str.encode('utf-8')).hexdigest()

    def _add_attachments_to_container(self, msg, container_id, artifact_severity, run_auto_flag, action_result):

        # get the attachments

        vault_artifacts = list()

        for i, curr_attach in enumerate(msg.attachments or []):

            if (not curr_attach.data):
                continue

            # get the file name
            file_name = (curr_attach.longFilename or curr_attach.shortFilename or 'attached_file-{0}'.format(i))
            file_name = UnicodeDammit(file_name).unicode_markup.encode('utf-8')
            if hasattr(file_name, 'decode'):
                file_name = file_name.decode('utf-8')

            try:
                if hasattr(Vault, 'get_vault_tmp_dir'):
                    fd, tmp_file_path = tempfile.mkstemp(dir=Vault.get_vault_tmp_dir())
                else:
                    fd, tmp_file_path = tempfile.mkstemp(dir='/opt/phantom/vault/tmp')
                os.write(fd, curr_attach.data)
                os.close(fd)
            except Exception as e:
                error_msg = self._get_error_message_from_exception(e)
                return RetVal(action_result.set_status(phantom.APP_ERROR,
                        "Unable to write file to tmp folder for attachment number: {0}. Error: {1}".format(i, error_msg)))

            try:
                vault_info = Vault.add_attachment(tmp_file_path, container_id=container_id, file_name=file_name)
            except Exception as e:
                error_msg = self._get_error_message_from_exception(e)
                return RetVal(action_result.set_status(phantom.APP_ERROR,
                        "Unable to add file to the vault for attachment number: {0}. Error: {1}".format(i, error_msg)))

            ret_val, vault_artifact = self._get_vault_artifact(vault_info, file_name, action_result)
            if (ret_val and vault_artifact):
                vault_artifact['severity'] = artifact_severity
                if run_auto_flag is False:
                    vault_artifact['run_automation'] = run_auto_flag
                vault_artifacts.append(vault_artifact)

        return (phantom.APP_SUCCESS, vault_artifacts)

    def _extract_str(self, string):

        if not string:
            return ''
        string = UnicodeDammit(string).unicode_markup.encode('utf-8')
        if hasattr(string, 'decode'):
            string = string.decode('utf-8')

        return string

    def _save_artifacts(self, action_result, artifacts, container_id):

        for artifact in artifacts:
            artifact['container_id'] = container_id
        if artifacts:
            status, message, id_list = self.save_artifacts(artifacts)
        else:
            # No IOCS found
            return action_result.set_status(phantom.APP_SUCCESS)
        if phantom.is_fail(status):
            message = message + '. Please validate severity parameter'
            return action_result.set_status(phantom.APP_ERROR, message)
        return phantom.APP_SUCCESS

    def _create_container(self, action_result, email_artifact, label, container_severity, vault_path):

        # create a container
        container = dict()
        # set container severity
        container['severity'] = container_severity

        try:
            container['name'] = email_artifact['cef']['emailHeaders']['Subject']
        except:
            container['name'] = os.path.basename(vault_path)

        # we don't/can't add a raw_email to this container, .msg file does not contain the email
        # in rfc822 format
        container['source_data_identifier'] = self._create_dict_hash(container)

        container['label'] = label

        container.update(_container_common)

        status, message, container_id = self.save_container(container)
        if (phantom.is_fail(status)):
            return RetVal(action_result.set_status(status, message))

        return (phantom.APP_SUCCESS, container_id)

    def _save_to_existing_container(self, action_result, artifacts, container_id):
        return self._save_artifacts(action_result, artifacts, container_id)

    def _handle_extract_email(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        # validate the container id
        ret_val, container_id = self._validate_integer(action_result, param.get('container_id'), "container_id")
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        label = param.get('label')
        if container_id is None and label is None:
            return action_result.set_status(phantom.APP_ERROR, "A label must be specified if no container ID is provided")
        if container_id:
            # Make sure container exists first, provide a better error message than waiting for save_artifacts to fail
            ret_val, message, _ = self.get_container_info(container_id)
            if phantom.is_fail(ret_val):
                return action_result.set_status(phantom.APP_ERROR, "Unable to find container: {}".format(message))

        # get the .msg file from the vault
        vault_id = param['vault_id']
        try:
            url = '{0}rest/container_attachment'.format(self._get_phantom_base_url())
            query_params = {
                    '_filter_vault_document__hash': '"{}"'.format(vault_id),
                    'page_size': 1,
                    'pretty': ''
            }
            r = requests.get(url, params=query_params, verify=False)
            resp_data = r.json()
            vault_info = resp_data['data'][0]
            for k in list(vault_info):
                if k.startswith('_pretty_'):
                    name = k[8:]
                    vault_info[name] = vault_info.pop(k)
            vault_path = vault_info['path']
        except:
            return action_result.set_status(phantom.APP_ERROR, "Failed to get vault info before extracting")

        try:
            msg = Message(vault_path)
        except Exception as e:
            error_msg = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "Failed to parse message. Error: {0}".format(error_msg))

        # the list of artifacts will be stored in this var
        artifacts = list()

        # create the email artifact
        email_artifact = dict()

        ret_val = self._create_email_artifact(msg, email_artifact, action_result, param['artifact_name'])

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Set severity and run_automation flag of artifacts
        severity = param.get('severity', 'medium').lower()
        email_artifact['severity'] = severity

        # Set run_automation flag
        run_auto_flag = param['run_automation']
        # Only set run_automation if it is False. Causes multiple unwanted playbooks runs when set to True
        if run_auto_flag is False:
            email_artifact['run_automation'] = run_auto_flag
        artifacts.append(email_artifact)

        # create a container if required
        if not container_id:

            ret_val, container_id = self._create_container(action_result, email_artifact, label, severity, vault_path)

            if phantom.is_fail(ret_val):
                return action_result.get_status()

        # now work on the attachments
        ret_val, vault_artifacts = self._add_attachments_to_container(msg, container_id, severity, run_auto_flag, action_result)

        if (phantom.is_success(ret_val) and vault_artifacts):
            artifacts.extend(vault_artifacts)

        # now add all the artifacts
        ret_val = self._save_to_existing_container(action_result, artifacts, container_id)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['artifacts_found'] = len(artifacts)
        summary['container_id'] = container_id

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id: {0}".format(self.get_action_identifier()))

        if action_id == MSGFILEPARSER_TEST_CONNECTIVITY_ACTION:
            ret_val = self._handle_test_connectivity(param)

        elif action_id == MSGFILEPARSER_EXTRACT_EMAIL_ACTION:
            ret_val = self._handle_extract_email(param)

        return ret_val

    def initialize(self):

        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()

        # Fetching the Python major version
        try:
            self._python_version = int(sys.version_info[0])
        except:
            return self.set_status(phantom.APP_ERROR, "Error occurred while getting the Phantom server's Python major version")

        """
        # Access values in asset config by the name

        # Required values can be accessed directly
        required_config_name = config['required_config_name']

        # Optional values should use the .get() function
        optional_config_name = config.get('optional_config_name')
        """

        self._base_url = config.get('base_url')

        return phantom.APP_SUCCESS

    def finalize(self):

        # Save the state, this data is saved accross actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == '__main__':

    import pudb
    import argparse

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if (username is not None and password is None):

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if (username and password):
        try:
            print("Accessing the Login page")
            r = requests.get(MSGFILEPARSER_LOGIN_URL, verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = MSGFILEPARSER_LOGIN_URL

            print("Logging into Platform to get the session id")
            r2 = requests.post(MSGFILEPARSER_LOGIN_URL, verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platfrom. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = MsgFileParserConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
