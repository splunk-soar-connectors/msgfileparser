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
import phantom.rules as ph_rules

# Constants imports
from msgfileparser_consts import *

import requests
import json
import tempfile
import os
import hashlib
import base64
import quopri
import outlookmsgfile
import re
from email.header import decode_header
from bs4 import UnicodeDammit, BeautifulSoup
from compoundfiles import CompoundFileReader
from requests.structures import CaseInsensitiveDict


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
                    error_msg = e.args[0]
        except:
            pass

        return "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)

    def _add_vault_hashes_to_dictionary(self, cef_artifact, vault_id, action_result):

        try:
            success, message, vault_info = ph_rules.vault_info(vault_id=vault_id)
            vault_info = list(vault_info)[0]
        except Exception as e:
            error_msg = self._get_error_message_from_exception(e)
            self.debug_print("{}. Error: {}".format(MSGFILEPARSER_VAULT_INFO_EXTRACTION_ERR, error_msg))
            return action_result.set_status(phantom.APP_ERROR, MSGFILEPARSER_VAULT_INFO_EXTRACTION_ERR)

        if not vault_info:
            return (phantom.APP_ERROR, MSGFILEPARSER_VAULT_ID_NOT_FOUND_ERR)

        try:
            metadata = vault_info['metadata']
        except:
            return action_result.set_status(phantom.APP_ERROR, MSGFILEPARSER_VAULT_METADATA_NOT_FOUND_ERR)

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

    def _get_vault_artifact(self, attachment_vault_id, file_name, action_result):

        vault_artifact = {'name': 'Vault Artifact'}
        cef = vault_artifact['cef'] = dict()
        cef['vaultId'] = attachment_vault_id
        cef['fileName'] = file_name

        ret_val = self._add_vault_hashes_to_dictionary(cef, cef['vaultId'], action_result)

        return (ret_val, vault_artifact)

    def _get_email_headers_from_mail(self, mail, charset=None, email_headers=None):

        if mail:
            email_headers = list(mail.items())
            if not email_headers:
                return {}

        if not charset:
            charset = mail.get_content_charset() or 'utf-8'

        # Convert the header tuple into a dictionary
        headers = CaseInsensitiveDict()
        received_headers = []
        for x in email_headers:
            try:
                headers.update({x[0]: x[1].decode(charset)})
                if x[0].lower() == 'received':
                    received_headers.append(x[1].decode(charset))
            except:
                headers.update({x[0]: str(x[1])})
                if x[0].lower() == 'received':
                    received_headers.append(str(x[1]))

        if received_headers:
            headers['Received'] = received_headers

        # Decode unicode subject
        if '?UTF-8?' in headers.get('Subject', ""):
            chars = 'utf-8'
            headers['Subject'] = self._decode_subject(headers.get('Subject', ""), chars)

        # handle the subject string, if required add a new key
        subject = headers.get('Subject')
        if subject:
            if isinstance(subject, str):
                headers['decodedSubject'] = self._decode_uni_string(subject, subject)

        return headers

    def _decode_subject(self, subject, charset):

        # Decode subject unicode
        decoded_subject = ''
        subject = subject.split('?=\r\n\t=')
        for sub in subject:
            if '?UTF-8?B?' in sub:
                sub = sub.replace('?UTF-8?B?', '').replace('?=', '')
                sub = base64.b64decode(sub)
            elif '?UTF-8?Q?' in sub:
                sub = sub.replace('?UTF-8?Q?', '').replace('?=', '')
                sub = quopri.decodestring(sub)
            sub = sub.decode(charset)
            decoded_subject = "{}{}".format(decoded_subject, sub)

        return decoded_subject

    def _decode_uni_string(self, input_str, def_name):

        encoded_strings = re.findall(r'=\?.*\?=', input_str, re.I)

        # return input_str as is, no need to do any conversion
        if not encoded_strings:
            return input_str

        # get the decoded strings
        try:
            decoded_strings = [decode_header(x)[0] for x in encoded_strings]
            decoded_strings = [{'value': x[0], 'encoding': x[1]} for x in decoded_strings]
        except Exception as e:
            error_msg = self._get_error_message_from_exception(e)
            self.debug_print("Decoding: {0}. {1}".format(encoded_strings, error_msg))
            return def_name

        new_str_list = []
        for decoded_string in decoded_strings:

            if not decoded_string:
                # nothing to replace with
                continue

            value = decoded_string.get('value')
            encoding = decoded_string.get('encoding')

            if not encoding or not value:
                # nothing to replace with
                continue

            try:
                value = value.decode(encoding)
                new_str_list.append(value)
            except:
                try:
                    if encoding != 'utf-8':
                        value = str(value, encoding)
                except:
                    pass

                try:
                    if value:
                        new_str_list.append(UnicodeDammit(value).unicode_markup)
                except:
                    pass

        if new_str_list and len(new_str_list) == len(encoded_strings):
            self.debug_print("Creating a new string entirely from the encoded_strings and assigning into input_str")
            input_str = ''.join(new_str_list)

        return input_str

    def _create_email_artifact(self, mail, email_artifact, action_result, artifact_name, charset=None):

        try:
            headers = self._get_email_headers_from_mail(mail)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR,
                    MSGFILEPARSER_EMAIL_HEADER_MSG_ERR.format(self._get_error_message_from_exception(e)))

        if not headers:
            return action_result.set_status(phantom.APP_ERROR, MSGFILEPARSER_EMAIL_HEADER_FILE_ERR)

        # Parse email keys first
        cef_artifact = {}
        cef_types = {}

        if headers.get('From'):
            emails = headers['From']
            if emails:
                cef_artifact.update({'fromEmail': emails})
                cef_types.update({'fromEmail': ['email']})

        if headers.get('To'):
            emails = headers['To']
            if emails:
                cef_artifact.update({'toEmail': emails})
                cef_types.update({'toEmail': ['email']})

        # if the header did not contain any email addresses then ignore this artifact
        message_id = headers.get('message-id')
        if (not cef_artifact) and (message_id is None):
            self.debug_print(MSGFILEPARSER_FETCH_DETAILS_FROM_FILE_ERR)

        if headers:
            # convert from CaseInsensitive to normal dict, so that it is serializable
            cef_artifact['emailHeaders'] = dict(headers)

        email_artifact['name'] = artifact_name
        email_artifact['cef'] = cef_artifact
        email_artifact['cef_types'] = cef_types

        return (phantom.APP_SUCCESS)

    def _create_dict_hash(self, input_dict):

        input_dict_str = None

        if not input_dict:
            return None

        try:
            input_dict_str = json.dumps(input_dict, sort_keys=True)
        except Exception as e:
            self.debug_print('Handled exception in _create_dict_hash', self._get_error_message_from_exception(e))
            return None

        return hashlib.md5(input_dict_str.encode('utf-8')).hexdigest()

    def _add_attachments_to_container(self, mail, container_id, artifact_severity, run_auto_flag, action_result, email_artifact):

        # get the attachments
        vault_artifacts = list()
        if mail.is_multipart():
            ret_val = None
            for part in mail.walk():
                if part.is_multipart():
                    self.debug_print("Multipart skip attachment")
                    continue

                # Process if body
                content_disp = part.get('Content-Disposition')
                content_type = part.get('Content-Type')

                process_as_body = False
                if content_disp is None:
                    process_as_body = True
                elif content_disp.lower().strip() == 'inline':
                    if ('text/html' in content_type) or ('text/plain' in content_type):
                        process_as_body = True
                if process_as_body:
                    body_payload = part.get_payload(decode=True)
                    charset = part.get_content_charset() or 'utf-8'
                    if hasattr(body_payload, 'decode'):
                        body_payload = body_payload.decode(charset)
                    if 'bodyText' not in email_artifact['cef']:
                        email_artifact['cef']['bodyText'] = body_payload
                    continue

                # Process Attachments
                file_name = part.get_filename()
                if not file_name:
                    self.debug_print("Skipping Empty filename")
                    continue
                file_name = self._decode_uni_string(file_name, file_name)

                # Save attachment to temp location
                try:
                    if hasattr(Vault, 'get_vault_tmp_dir'):
                        fd, tmp_file_path = tempfile.mkstemp(dir=Vault.get_vault_tmp_dir())
                    else:
                        fd, tmp_file_path = tempfile.mkstemp(dir='/opt/phantom/vault/tmp')
                    os.close(fd)

                    part_payload = part.get_payload(decode=True)
                    if not part_payload:
                        self.debug_print("Skipping Empty payload")
                        continue
                    with open(tmp_file_path, 'wb') as f:
                        f.write(part_payload)
                except Exception as e:
                    error_msg = self._get_error_message_from_exception(e)
                    self.debug_print(MSGFILEPARSER_UNABLE_TO_WRITE_FILE_ERR.format(file_name, error_msg))
                    continue

                # Save attachment file to the vault
                try:
                    success, message, attachment_vault_id = ph_rules.vault_add(
                        container=container_id,
                        file_location=tmp_file_path,
                        file_name=file_name
                    )

                except Exception as e:
                    error_msg = self._get_error_message_from_exception(e)
                    self.debug_print(MSGFILEPARSER_UNABLE_TO_ADD_FILE_ERR.format(file_name, error_msg))
                    continue

                # Create Vault artifact
                ret_val, vault_artifact = self._get_vault_artifact(attachment_vault_id, file_name, action_result)
                if ret_val and vault_artifact:
                    vault_artifact['severity'] = artifact_severity
                    if run_auto_flag is False:
                        vault_artifact['run_automation'] = run_auto_flag
                    vault_artifacts.append(vault_artifact)
        else:
            self.debug_print('Not multipart')
            body_payload = mail.get_payload(decode=True)
            charset = mail.get_content_charset() or 'utf-8'
            if hasattr(body_payload, 'decode'):
                body_payload = body_payload.decode(charset)
            email_artifact['cef']['bodyText'] = body_payload

        return (phantom.APP_SUCCESS, vault_artifacts)

    def _sanitize_dict(self, obj):
        if isinstance(obj, str):
            return obj.replace('\u0000', '')
        if isinstance(obj, list):
            return [self._sanitize_dict(item) for item in obj]
        if isinstance(obj, dict):
            return {k: self._sanitize_dict(v) for k, v in obj.items()}
        return obj

    def _save_artifacts(self, action_result, artifacts, container_id):

        for artifact in artifacts:
            artifact['container_id'] = container_id
        if artifacts:
            artifacts = self._sanitize_dict(artifacts)
            status, message, id_list = self.save_artifacts(artifacts)
        else:
            # No IOCS found
            return action_result.set_status(phantom.APP_SUCCESS)
        if phantom.is_fail(status):
            message = '{}. Please validate severity parameter'.format(message)
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
            pass
        if not container.get('name'):
            container['name'] = os.path.basename(vault_path)

        # we don't/can't add a raw_email to this container, .msg file does not contain the email
        # in rfc822 format
        container['source_data_identifier'] = self._create_dict_hash(container)
        container['label'] = label

        container.update(_container_common)

        status, message, container_id = self.save_container(container)
        if phantom.is_fail(status):
            return RetVal(action_result.set_status(status, message))

        return (phantom.APP_SUCCESS, container_id)

    def _save_to_existing_container(self, action_result, artifacts, container_id):
        return self._save_artifacts(action_result, artifacts, container_id)

    def _handle_extract_email(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        # validate the container id
        container_id = param.get('container_id')
        ret_val, container_id = self._validate_integer(action_result, container_id, 'container_id')
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        label = param.get('label')
        if container_id is None and label is None:
            return action_result.set_status(phantom.APP_ERROR, MSGFILEPARSER_PROVIDE_LABEL_ERR)
        if container_id:
            # Make sure container exists first, provide a better error message than waiting for save_artifacts to fail
            ret_val, message, _ = self.get_container_info(container_id)
            if phantom.is_fail(ret_val):
                return action_result.set_status(phantom.APP_ERROR, MSGFILEPARSER_CONTAINERS_NOT_FOUND_ERR.format(message))

        # get the .msg file from the vault
        vault_id = param['vault_id']
        try:
            success, message, vault_info = ph_rules.vault_info(vault_id=vault_id)
            vault_info = list(vault_info)[0]
            vault_path = vault_info['path']
        except Exception as e:
            error_msg = self._get_error_message_from_exception(e)
            self.debug_print("{}. Error: {}".format(MSGFILEPARSER_VAULT_INFO_BEFORE_EXTRACTION_ERR, error_msg))
            return action_result.set_status(phantom.APP_ERROR, MSGFILEPARSER_VAULT_INFO_BEFORE_EXTRACTION_ERR)

        try:
            mail = outlookmsgfile.load(vault_path)
        except UnicodeDecodeError as e:
            error_msg = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, MSGFILEPARSER_PARSER_DECODE_ERR.format(error_msg))
        except Exception as e:
            error_msg = self._get_error_message_from_exception(e)
            self.debug_print("{} Error: {}".format(MSGFILEPARSER_PARSER_MSG_FILE_ERR, error_msg))
            return action_result.set_status(phantom.APP_ERROR, MSGFILEPARSER_PARSER_MSG_FILE_ERR)

        # the list of artifacts will be stored in this var
        artifacts = list()

        # create the email artifact
        email_artifact = dict()

        ret_val = self._create_email_artifact(mail, email_artifact, action_result, param['artifact_name'])

        if phantom.is_fail(ret_val):
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
        ret_val, vault_artifacts = self._add_attachments_to_container(mail, container_id, severity, run_auto_flag, action_result, email_artifact)

        if phantom.is_success(ret_val) and vault_artifacts:
            artifacts.extend(vault_artifacts)

        try:
            with CompoundFileReader(vault_path) as doc:
                for entry in doc.root:
                    if '__substg1.0_1013' in entry.name:
                        streamname = entry.name
                        try:
                            with doc.open(doc.root[streamname]) as innerstream:
                                value = innerstream.read()
                                soup = BeautifulSoup(value, 'html.parser')
                                body_html = soup.prettify()
                                if body_html:
                                    email_artifact['cef']['bodyHtml'] = body_html
                                    email_artifact['cef']['bodyText'] = soup.get_text()
                                break
                        except Exception as e:
                            error_msg = self._get_error_message_from_exception(e)
                            self.debug_print("Stream missing for bodyHtml. {}.".format(error_msg))
                            break
        except Exception as e:
            error_msg = self._get_error_message_from_exception(e)
            self.debug_print("Unable to read bodyHtml from file. {}.".format(error_msg))

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

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == MSGFILEPARSER_EXTRACT_EMAIL_ACTION:
            ret_val = self._handle_extract_email(param)

        return ret_val

    def initialize(self):

        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()

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

    if username is not None and password is None:

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if username and password:
        try:
            print("Accessing the Login page")
            r = requests.get("{}login".format(BaseConnector._get_phantom_base_url()), verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken={}'.format(csrftoken)
            headers['Referer'] = "{}login".format(BaseConnector._get_phantom_base_url())

            print("Logging into Platform to get the session id")
            r2 = requests.post("{}login".format(BaseConnector._get_phantom_base_url()), verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platfrom. Error: {}".format(str(e)))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = MsgFileParserConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
