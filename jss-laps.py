#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""This program was created to perform Jamf Pro LAPS Operations including viewing LAPS settings, viewing total current pending password rotations or if a pending password rotation exists for a LAPS user on a specific computer, resetting a specific LAPS user password on a specific computer, and mass resetting a specific LAPS user passwords for a large group of computers (up to all computers).

Copyright (c) 2023 Julie Flanakin, All rights reserved.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS, COPYRIGHT HOLDERS, OR JAMF SOFTWARE BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

* Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

* Neither the name of JAMF, JAMF SOFTWARE, nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
"""

import os
import sys

import base64
import datetime
import getpass
import json
import re
import requests
import textwrap

# Debug 
gUseDebugInput = False
gDebugURL = ""
gDebugUsername = ""
gDebugPassword = ""
gDebugLAPSEnabledUser = ""
gDebugLAPSUserPassword = ""

# Global constants
HTTP_ERRORS = [400, 401, 403, 404, 405, 500, 502, 503, 504]
HTTP_SUCCESS = [200, 201, 202, 204]

        
# Global variables
session = requests.Session()


class JamfProAPI:
    """Formats and performs API calls to Jamf Pro. 
    """
    
    def __init__(self):
        pass

    def get(self, jssURL: str, credentials: str, endpoint: str, operation="") -> dict:
        """Formats and performs an HTTP GET request via the "Requests" library.

        Args:
            jssURL (str): Jamf Pro Server URL
            credentials (str): Bearer Token
            endpoint (str): API Endpoint
            operation (str, optional): API Endpoint operation. Defaults to "".

        Returns:
            dict: Python dictionary containing an HTTP status code and JSON response data.
            
        Example: 
            dict: {'httpStatus': <status code>, 'message': '<json data>'}
        """

        url = jssURL + endpoint + operation
        headers = {
            "accept": "application/json",
            "Authorization": "Bearer " + credentials
            }
        response = session.get(url, headers=headers)
        status = response.status_code
        data = self.format_http_response(status, response)
        return data

    def post_simple(self, jssURL: str, credentials: str, endpoint: str, operation="", payload="") -> dict:
        """Formats and performs an HTTP POST request via the "Requests" library using basic authentication credentials (username/password).

        Args:
            jssURL (str): Jamf Pro Server URL
            credentials (str): Basic Authentication Credentials (username/password)
            endpoint (str): API Endpoint
            operation (str, optional): API Endpoint operation. Defaults to "".
            payload (str, optional): Payload to create a new object in Jamf Pro. The payload is required to be in JSON format. Defaults to "".

        Returns:
            dict: Python dictionary containing an HTTP status code and JSON response data.
            
        Example: 
            dict: {'httpStatus': <status code>, 'message': '<json data>'}
        """
        
        url = jssURL + endpoint + operation
        headers = {
            "accept": "application/json",
            "Authorization": "Basic " + credentials
            }
        response = session.post(url, json=payload, headers=headers)
        status = response.status_code
        data = self.format_http_response(status, response)
        return data
    
    def post(self, jssURL: str, credentials: str, endpoint: str, operation="", payload="") -> dict:
        """Formats and performs an HTTP POST request via the "Requests" library using a bearer token for authentication. Can deliver a payload to create a new object in Jamf Pro.

        Args:
            jssURL (str): Jamf Pro Server URL
            credentials (str): Bearer Token
            endpoint (str): API Endpoint
            operation (str, optional): API Endpoint operation. Defaults to "".
            payload (str, optional): Payload to create a new object in Jamf Pro. The payload is required to be in JSON format. Defaults to "".

        Returns:
            dict: Python dictionary containing an HTTP status code and JSON response data.
            
        Example: 
            dict: {'httpStatus': <status code>, 'message': '<json data>'}
        """

        url = jssURL + endpoint + operation
        headers = {
            "accept": "application/json",
            "Authorization": "Bearer " + credentials
            }
        response = session.post(url, json=payload, headers=headers)
        status = response.status_code
        data = self.format_http_response(status, response)
        return data

    def put(self, jssURL: str, credentials: str, endpoint: str, payload: str, operation="") -> dict:
        """Formats and performs an HTTP PUT request via the "Requests" library using a bearer token for authentication. Delivers a payload to update an object in Jamf Pro.

        Args:
            jssURL (str): Jamf Pro Server URL
            credentials (str): Bearer Token
            endpoint (str): API Endpoint
            payload (str): Payload to update an new object in Jamf Pro. The payload is required to be in JSON format.
            operation (str, optional): API Endpoint operation. Defaults to "".

        Returns:
            dict: Python dictionary containing an HTTP status code and JSON response data.
            
        Example: 
            dict: {'httpStatus': <status code>, 'message': '<json data>'}
        """
        url = jssURL + endpoint + operation
        headers = {
            "accept": "application/json",
            "content-type": "application/json",
            "Authorization": "Bearer " + credentials
            }
        response = session.put(url, json=payload, headers=headers)
        status = response.status_code
        data = self.format_http_response(status, response)
        return data
    
    def patch(self, jssURL: str, credentials: str, endpoint: str, payload: str, operation="") -> dict:
        """Formats and performs an HTTP PATCH request via the "Requests" library using a bearer token for authentication. Delivers a payload to update part of an object in Jamf Pro.

        Args:
            jssURL (str): Jamf Pro Server URL
            credentials (str): Bearer Token
            endpoint (str): API Endpoint
            payload (str): Payload to update an new object in Jamf Pro. The payload is required to be in JSON format.
            operation (str, optional): API Endpoint operation. Defaults to "".

        Returns:
            dict: Python dictionary containing an HTTP status code and JSON response data.
            
        Example: 
            dict: {'httpStatus': <status code>, 'message': '<json data>'}
        """
        url = jssURL + endpoint + operation
        headers = {
            "accept": "application/json",
            "content-type": "application/json",
            "Authorization": "Bearer " + credentials
            }
        response = session.patch(url, json=payload, headers=headers)
        status = response.status_code
        data = self.format_http_response(status, response)
        return data
    
    def delete(self, jssURL: str, credentials: str, endpoint: str, operation="") -> dict:
        """Formats and performs an HTTP DELETE request via the "Requests" library using a bearer token for authentication. 

        Args:
            jssURL (str): Jamf Pro Server URL
            credentials (str): Bearer Token
            endpoint (str): API Endpoint
            operation (str, optional): API Endpoint operation. Defaults to "".

        Returns:
            dict: Python dictionary containing an HTTP status code and JSON response data.
            
        Example: 
            dict: {'httpStatus': <status code>, 'message': '<json data>'}
        """
        url = jssURL + endpoint + operation
        headers = {
            "accept": "application/json",
            "Authorization": "Bearer " + credentials
            }
        response = session.delete(url, headers=headers)
        status = response.status_code
        data = self.format_http_response(status, response)
        return data
    
    def format_http_response(self, http_status: int, response: str) -> dict:
        """Formats the response of any HTTP request into a Python dictionary containing an HTTP status code and json response.
        
        Args:
            http_status (int): HTTP status code
            response (str): JSON data contained in HTTP response.
        
        Returns:
            dict: Python dictionary containing an HTTP status code and JSON response data.

        Examples: 
            * {'httpStatus': <status code>, 'message': '<json data>'}
            
            * {'httpStatus': '200', 'message': 'HTTP 200 (OK). Everything has gone right and you should never see this message.'}
            
            * {'httpStatus': '404', 'message': 'HTTP 404 (Not Found). Please verify that your Jamf Pro URL was entered in correctly.'}
            
        Includes generic response messages for niche response codes that don't come up often enough to write more specific explanations into the script:
        
            * {'httpStatus': '203', 'message': 'This is a generic response message and indicates an unexpected HTTP status code. Everything probably went alright and you should never see this message.'}
            
            * {'httpStatus': '409', 'message': 'This is a generic response message and indicates an unexpected HTTP status code. This indicates something may have gone wrong with an API call.'}
        """

        terminal_size = os.get_terminal_size()
        width = terminal_size.columns
        max_size = 128
        
        d = dict()
        d['httpStatus'] = http_status
        
        if (http_status in HTTP_SUCCESS) and (http_status != 204):
            d['message'] = json.loads(response.text)
            return d
        
        elif http_status in HTTP_ERRORS:
            match http_status:
                case 400:
                    d['message'] = "HTTP 400 (Bad Request). Something in the script has broken and an API call was made incorrectly.Something likely changed in the Jamf Pro API and hasn't been updated in this script."
                case 401:
                    d['message'] = "HTTP 401 (Unauthorized). Either your password was incorrect or your authentication token expired and you need to re-authenticate. Please also verify that your account is enabled and not locked out."
                case 403:
                    d['message'] = "HTTP 403 (Forbidden). Please check the permissions of your Jamf Pro account and make sure you can perform this operation."
                case 404:
                    d['message'] = "HTTP 404 (Not Found). Please verify that your Jamf Pro URL was entered in correctly."
                case 405:
                    d['message'] = "HTTP 405 (Method Not allowed). Something has gone wrong with this script or something changed in the Jamf Pro API and hasn't been updated in this script."
                case 500:
                    d['message'] = "HTTP 500 (Internal Server Error). Either an API call failed to complete due to bad information (specified object does not exist, unable to complete lookup, etc) OR something has gone wrong with your Jamf Pro instance and this action cannot be completed. Please try again."
                case 502:
                    d['message'] = "HTTP 502 (Bad Gateway). A network issue has occured, please try again later."
                case 503:
                    d['message'] = "HTTP 503 (Service Unavailable). A network issue has occured, please try again later."
                case 504:
                    d['message'] = "HTTP 504 (Gateway Timeout). A network issue has occured, please try again later."
                case _:
                    d['message'] = "This is a generic response message and indicates an unexpected HTTP status code. This indicates something may have gone wrong with that an call."
            return d

        elif http_status in HTTP_SUCCESS:
            match http_status:
                case 200:
                    d['message'] = "HTTP 200 (OK). Everything has gone right and you should never see this message."
                case 201:
                    d['message'] = "HTTP 201 (Created). Everything has gone right and you should never see this message."
                case 202:
                    d['message'] = "HTTP 202 (Accepted). Everything has gone right and you should never see this message."
                case 204:
                    d['message'] = "HTTP 204 (No Content) Everything has gone right and you should never see this message."
                case _:
                    d['message'] = "This is a generic response message and indicates an unexpected HTTP status code. Everything probably went alright and you should never see this message."
            return d
        else:
            d['message'] = "This is a generic response message and indicates an unexpected HTTP status code. This indicates something may have gone wrong with an API call or we received an unexpected 2XX response code."
            return d


class Menu_Actions:
    """Creates objects or performs actions based on menu choices.
    """
    
    def __init__(self) -> None:
        pass
    
    def url_validation(self) -> str:
        """Interactive prompt with regex pattern matching to confirm if the URL is in the correct syntax as well confirming if the URL resolves.
    
        Returns:
            str: Jamf Pro URL
        """
        
        print(self.menu_title("Enter Jamf Pro URL"))
        
        if gUseDebugInput:
            url = gDebugURL
            
        else:
            i = 0
            valid_url = False
            
            while not valid_url:
                url = ""
                validate = ""
                response = ""
                
                if i > 2:
                    print(self.format_text("Too many attempts. Please check and verify that you are entering the correct Jamf Pro URL."))
                    input("""Press enter to continue: """)
                    print("Exiting!")
                    sys.exit()
                
                url = input(self.format_text("Please enter your Jamf Pro URL (Example: \"https://jamf.jamfcloud.com\"): "))
                if url == "0":
                    print("Exiting!")
                    sys.exit()
                
                elif url == "":
                    print("URL cannot be empty!")
                    continue
                    
                validate = input(self.format_text("Please re-enter your Jamf Pro URL to validate that it is correct: "))
                if validate == "0":
                    print("Exiting!")
                    sys.exit()
                    
                elif validate == url:
                    print("Validating URL...")
                    
                else:
                    print("URL's did not match. Please try again.")
                    i+=1
                    continue
                
                regex = re.compile(
                        r'^(?:http|ftp)s?://' # http or https
                        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' #domain
                        r'localhost|' #localhost
                        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ip address
                        r'(?::\d+)?' # optional port
                        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
                
                if re.match(regex, url) is not None:
                    try:
                        response = requests.get(url)
                        if response.status_code != 404:
                            valid_url = True
                            
                        else:
                            print(self.format_text("Syntax error. Please enter a valid URL, such as \"https://jamf.jamfcloud.com\"."))
                            i+=1
                            continue
                        
                    except:
                        print(self.format_text("HTTP 404 or other connection-specific error. Please enter a valid URL and make sure your Jamf Pro server can be reached by this computer."))
                        i+=1
                        
                else:
                    print(self.format_text("Syntax error. Please enter a valid URL, such as \"https://jamf.jamfcloud.com\"."))
                    i+=1
                    continue
                
        # If everything is successful, return the URL. 
        return url
    
    def get_simple_auth_creds(self) -> str:
        """Interactive prompt to request username and password, then transform them into base64 encoded credentials to be used for simple authentication to aqcuire a bearer token.
        
        Returns:
            str: base64 encoded credentials
        """
        
        print(self.menu_title("Enter authentication credentials"))
        
        print(self.format_text("Either you have not authenticated to Jamf Pro yet or your authentication token expired and you need to re-authenticate. \nPlease authenticate to Jamf Pro using your username and password (non-SSO accounts only)."))
        
        if gUseDebugInput:
            username = gDebugUsername
            password = gDebugPassword
            
        else:
            username = input(self.format_text("Please enter your username (non-SSO accounts only): "))
            if username == "0":
                print("Exiting!")
                sys.exit()
                
            password = getpass.getpass("Please enter your password: ")
            if password == "0":
                print("Exiting!")
                sys.exit()

        string = username + ":" + password
        credentials = base64.b64encode(bytes(string, 'utf-8')).decode("utf-8")
        username = ""
        password = ""
        return credentials
    
    def auth_attempt(self, url: str) -> str:
        """Attempts to perform an API call to the specified Jamf Pro server using simple credentials to get a bearer token.
        
        Args:
            url (str): Jamf Pro URL
        
        Returns:
            str: Bearer token
        """
        
        endpoint = "/api/v1/auth/"
        operation = "token"
        authenticated = False
        i = 0
        
        while not authenticated:
            plain_credentials = ""
            token = ""
            
            if i > 2:
                print(self.format_text("Too many attempts. Please check and verify that you are entering the correct username or password. If so, please verify that your account is not locked out, disabled, or that it has the correct permissions in Jamf Pro."))
                input("Press enter to continue: ")
                print("Exiting!")
                sys.exit()

            plain_credentials = Menu_Actions().get_simple_auth_creds()
            try:
                response = JamfProAPI().post_simple(url, plain_credentials, endpoint, operation=operation)
                
                if response['httpStatus'] in HTTP_SUCCESS:
                    token = response['message']['token']
                    plain_credentials = ""
                    authenticated = True
                    return token
                
                else:
                    print(self.format_text(response['message']))
                    input("Press enter to continue: ")
                    i+=1
                    continue
                
            except:
                print(self.format_text("The URL you entered passed regex pattern matching and resolves correctly, however when we tried to make an API call it failed with a non-authentication related error. This means that your API call may have gone to the wrong URL and you need to change the password for the account you just used to attempt the API call. If this keeps happening and you know for sure you are entering the correct URL, then either a change was made to the Jamf Pro API that broke this script or something is going wrong with your Jamf Pro server."))
                input("""
Press enter to continue: """)
                print("Exiting!")
                sys.exit()

    def display_user_attributes(self, user_object: dict) -> None:
        """Displays username, account type, and site access.

        Args:
            user_object (dict): json object representing user account details
        """
        
        if user_object is None:
            print(self.broken_script_message)
            input("Press enter to continue")
            print("Exiting!")
            sys.exit()
            
        else:
            account = user_object['account']
            sites = user_object['sites']
            authenticationType = user_object['authenticationType']
            user_access_level = account['accessLevel']
            
            print("Logged in user: " + account['username'])
            
            # Check if the user is an LDAP user or not
            if authenticationType == "LDAP":
                print("User type: LDAP" )
            else:
                print("User type: Standard")
            
            for element in sites:
                if element['name'] != "None":
                    user_site = element['name']

            # Find sites that the user has access to
            if user_access_level == "FullAccess":
                print("Site Access: All Jamf Pro Sites")
            else:
                print("Site Access: " + user_site)

    def invalidate_auth_token(self, url: str, credentials: str) -> str:
        """_summary_

        Args:
            url (str): Jamf Pro URL
            credentials (str): Bearer token

        Returns:
            str: Message detailing if the bearer token has been invalidated or not.
        """
        
        endpoint = "/api/v1/auth/"
        operation = "invalidate-token"
        
        try:
            response = JamfProAPI().post(url, credentials, endpoint, operation=operation)
            
            if response['httpStatus'] in HTTP_SUCCESS:
                message = self.format_text("Auth token has been invalidated successfully!")
                
            else:
                message = self.format_text("Either the token somehow doesn't exist or was already expired/invalidated. Moving on.")
        except:
                message = self.format_text("Something unexpected went wrong when trying to invalidate your authentication token. If this keeps happening then either a change was made to the Jamf Pro API that broke this script or something is going wrong with your Jamf Pro server.")
            
        return message

    def get_jss_user_object(self, url: str, credentials: str) -> dict:
        """Attempts to get authentication details for a Jamf Pro or LDAP user from the specified Jamf Pro server. 

        Args:
            url (str): Jamf Pro URL
            credentials (str): Bearer token

        Returns:
            dict: JSON data containing user information
        """
        
        endpoint = "/api/v1/auth/"
        attempt = False
        
        while not attempt:
            response = ""
            try:
                response = JamfProAPI().get(url, credentials, endpoint)
                
                if response['httpStatus'] in HTTP_SUCCESS:
                    attempt = True
                    user_object = response['message']
                    return user_object
                
                else:
                    print(self.format_text(response['message']))
                    input("Press enter to continue: ")
                    attempt = True
            
            except:
                print(self.broken_script_message)
                input("Press enter to continue")
                print("Exiting!")
                sys.exit()

    def get_laps_settings(self, url: str, credentials: str) -> dict:
        """Attempts to get LAPS settings from the specified Jamf Pro server.

        Args:
            url (str): Jamf Pro server URL
            credentials (str): Bearer token

        Returns:
            dict: LAPS settings in JSON format
        """
        
        print(self.menu_title("Current LAPS Settings"))
        
        endpoint = "/api/v2/local-admin-password/"
        operation = "settings"
        attempt = False

        while not attempt:
            response = ""
            try:
                response = JamfProAPI().get(url, credentials, endpoint, operation=operation)
                
                if response['httpStatus'] in HTTP_SUCCESS:
                    laps_settings = response['message']
                    attempt = True
                    return laps_settings
                
                else:
                    attempt = True
                    print(self.format_text(response['message']))
            
            except:
                print(self.broken_script_message)
                input("Press enter to continue")
                print("Exiting!")
                sys.exit()

    def get_all_pending_laps_rotations(self, url: str, credentials:str) -> int:
        """Gets the number of pending LAPS rotations from Jamf Pro.

        Args:
            url (str): Jamf Pro URL
            credentials (str): Bearer Token

        Returns:
            int: Number of pending password rotations.
        """
        
        print(self.menu_title("Total Pending LAPS Rotations"))
        
        endpoint = "/api/v2/local-admin-password/"
        operation = "pending-rotations"
        
        try:
            response = JamfProAPI().get(url, credentials, endpoint, operation)
        
        except:
            print(self.broken_script_message)
            input("Press enter to continue")
            print("Exiting!")
            sys.exit()
        
        if response['httpStatus'] in HTTP_SUCCESS:
            
            json_data = response['message']
            totalCount = json_data['totalCount']
            pending_rotations = int(totalCount)
            return pending_rotations
        
        else:
            print(self.format_text(response['message']))

    def view_pending_rotations_by_device(self, url: str, credentials: str) -> str:
        """Checks for any pending password rotations for a specific computer.

        Args:
            url (str): Jamf Pro URL
            credentials (str): Bearer Token

        Returns:
            int: Number of pending password rotations.
        """
        
        print(self.menu_title("View Pending Rotations by Device"))
        permission_checker = self.permission_checker(url, credentials)
        
        has_permission = False
        
        if (type(permission_checker) is int) and (permission_checker > 0):
            has_permission = True
        
        elif permission_checker is None:
            has_permission = False
        
        else:
            print("No pending rotations at this time.")
            has_permission = False
        
        if has_permission:
        
            print(self.menu_title("View Pending Rotations by Device"))
        
            endpoint = "/api/v2/local-admin-password/"
            operation = "pending-rotations"
            
            computer_object = self.get_computer_object_interactive(url, credentials)
            if computer_object is not None:
                computer_id = computer_object['id']
                computer_name = computer_object['general']['name']
                computer_site = computer_object['general']['site']["name"]
                management_id = computer_object['general']['managementId']
                
                try:
                    response = JamfProAPI().get(url, credentials, endpoint, operation)
                    
                    if response['httpStatus'] in HTTP_SUCCESS:
                        
                        json_data = response['message']
                        totalCount = json_data['totalCount']
                        
                        if totalCount == "0":
                            pending_rotations = "No pending rotations at this time."
                            print(pending_rotations)
                            
                        else:
                            i = 0
                            pending_management_ids = []
                            while i < totalCount:
                                pending_management_ids.append(json_data['results'][i]['lapsUser']['clientManagementId'])
                                i+=1
                            
                            if management_id in pending_management_ids:
                                j = i - 1
                                pending_user = json_data['results'][j]['lapsUser']['username']
                                raw_created_date = json_data['results'][j]['createdDate']
                                formated_datetime = datetime.datetime.strptime(raw_created_date, "%Y-%m-%dT%H:%M:%S.%fZ")
                                display_txt = """
Computer ID: {0}
Computer Name: {1}
Computer Site {2}
Computer Management ID: {3}

LAPS rotation pending for user: {4}
LAPS Rotation pending since: {5}
""".format(computer_id, computer_name, computer_site, management_id, pending_user, formated_datetime)
                            
                            else:
                                display_txt = """
Computer ID: {0}
Computer Name: {1}
Computer Site {2}
Computer Management ID: {3}

No pending LAPS rotation for this computer at this time.
""".format(computer_id, computer_name, management_id, computer_site)

                    else:
                        print(self.format_text(response['message']))
                        
                except:
                    print(self.broken_script_message)
                    input("Press enter to continue")
                    print("Exiting!")
                    sys.exit()
            
                return display_txt
            else:
                pass
        else:
            pass

    def get_computer_object_interactive(self, url: str, credentials: str) -> dict:
        """Interactive prompt to get a computer ID. Will check if that ID actually exists. If it exists, attempts to retrieve the GENERAL section of the specified computer inventory record. 
        
        User has to know the computer ID of the computer they want to use as Jamf Pro API does not support using computer name in this endpoint at this time.  

        Args:
            url (str): Jamf Pro server URL
            credentials (str): Bearer token

        Returns:
            dict: GENERAL section of the specified computer inventory record in json format
        """
        
        # print(self.menu_title("Choose Computer"))
        
        endpoint = "/api/v1/computers-inventory/"
        computer_exists = False
        
        i = 0
        while not computer_exists:
            computer_id = ""
            computer_obj = ""
            
            if i > 2:
                print(self.format_text("Too many attempts. Please check and verify that you are entering the correct computer ID or have permissions to perform this action."))
                print("Exiting to main menu")
                break
            
            computer_id = input(self.format_text("Please enter the ID (not the computer name or management ID) of the computer you would like to get or update information on: "))
            
            if computer_id == "":
                print("Computer ID cannot be empty. Try again.")
                i+=1
            
            elif computer_id == "0":
                print("Exiting!")
                sys.exit()
            
            else:
                try:
                    operation = computer_id + "?section=GENERAL"
                    
                    response = JamfProAPI().get(url, credentials, endpoint, operation=operation)
                    response_check = response['message']
                    
                    if "totalCount" in response_check:
                        valid_response = False
                        i+=1
                    else:
                        valid_response = True
                    
                    if (response['httpStatus'] in HTTP_SUCCESS) and (valid_response):
                        computer_exists = True
                        computer_obj = response["message"]
                        return computer_obj
                    
                    elif (response['httpStatus'] == 403) and (valid_response):
                        print(self.format_text("You do not have permission to view this piece of information. Please confirm your user account permissions in Jamf Pro."))
                        i+=1
                        continue

                    else:
                        message = "Computer ID " + computer_id + " does not exist or another error is occuring, please try again."
                        print(self.format_text(message))
                        i+=1
                        continue
                except:
                    print(self.broken_script_message)
                    input("Press enter to continue")
                    print("Exiting!")
                    sys.exit()
  
    def get_computer_object(self, url: str, credentials: str, computer_id: str) -> dict:
        """Checks if a computer ID actually exists. If it exists, attempts to retrieve the GENERAL section of the specified computer inventory record. 

        Args:
            url (str): Jamf Pro server URL
            credentials (str): Bearer token

        Returns:
            dict: GENERAL section of the specified computer inventory record in json format
        """
        
        print(self.menu_title("Choose Computer"))
        
        endpoint = "/api/v1/computers-inventory/"
        operation = computer_id + "?section=GENERAL"
        computer_exists = False
        
        i = 0
        while not computer_exists:
            computer_obj = ""
            response = ""
            
            if i > 2:
                print(self.format_text("Too many attempts. Please check and verify that you are entering the correct computer ID or have permissions to perform this action."))
                print("Exiting to main menu")
                break
            
            try:
                response = JamfProAPI().get(url, credentials, endpoint, operation=operation)
                response_check = response['message']
                
                if "totalCount" in response_check:
                    valid_response = False
                    i+=1
                else:
                    valid_response = True
                
                if (response['httpStatus'] in HTTP_SUCCESS) and (valid_response):
                    computer_exists = True
                    computer_obj = response["message"]
                    return computer_obj

                else:
                    message = "Computer ID " + computer_id + " does not exist or another error is occuring, please try again."
                    print(self.format_text(message))
                    i+=1
                    continue
            except:
                print(self.broken_script_message)
                input("Press enter to continue")
                print("Exiting!")
                sys.exit()

    def get_all_computers(self, url: str, credentials: str) -> dict:
        """Gets a json object that contains a total count of all computers and the GENERAL section of each computer inventory record the user has access to.

        Args:
            url (str): Jamf Pro URL
            credentials (str): Bearer token

        Returns:
            dict: JSON object that contains a total count of all computers and the GENERAL section of each computer inventory record the user has access to.
        """
        
        endpoint = "/api/v1/computers-inventory/"
        operation = "?section=GENERAL"
        
        try:
            response = JamfProAPI().get(url, credentials, endpoint, operation=operation)
            
            if response['httpStatus'] in HTTP_SUCCESS:
                all_computers = response['message']
                return all_computers

            else:
                print(self.format_text(response['message']))
                
        except:
            print(self.broken_script_message)
            input("Press enter to continue")
            print("Exiting!")
            sys.exit()

    def get_laps_user_interactive(self, url: str, management_id: str, credentials: str) -> str:
        """Interactive prompt to get a LAPS username. Will check if that username exists on the specified computer. If it exists, returns the username. 

        Args:
            url (str): Jamf Pro server URL
            management_id (str): Management ID corresponding to a specific computer inventory record.
            credentials (str): Bearer token

        Returns:
            str: LAPS username
        """
        
        print(self.menu_title("Choose LAPS enabled user"))
        
        laps_user = input(self.format_text("Please enter the LAPS enabled local admin account username that you would like to perform this operation on: "))
        
        user_exists = self.check_laps_user(url, management_id, credentials, laps_user)
                
        if user_exists:
            return laps_user
        
        else: 
            pass
            
    def check_laps_user(self, url: str, management_id: str, credentials: str, laps_user: str) -> bool:
        """Checks if the specified laps username exists on the specified computer. If it exists, returns a boolean. 

        Args:
            url (str): Jamf Pro server URL
            management_id (str): Management ID corresponding to a specific computer inventory record.
            credentials (str): Bearer token

        Returns:
            str: LAPS username
        """
        
        endpoint = "/api/v2/local-admin-password/"
        operation = management_id + "/accounts"
        user_exists = False
        
        j = 0
        while not user_exists:
            if j > 2:
                print(self.format_text("Please check and verify that you are entering the correct LAPS username or have permissions to perform this action."))
                print("Exiting to main menu.")
                break
            
            all_laps_users = []
            response = ""
            total_count = ""
            username = ""
            
            try:
                response = JamfProAPI().get(url, credentials, endpoint, operation=operation)

                if response['httpStatus'] in HTTP_SUCCESS:
                    total_count = response['message']['totalCount']
                    
                    i = 0
                    while i < total_count:
                        username = response['message']['results'][i]['username']
                        all_laps_users.append(username)
                        i+=1
                        
                else:
                    print(self.format_text(response['message']))
                    input("Press enter to continue: ")
                    j+=1
                    continue
                
            except:
                print(self.broken_script_message)
                input("Press enter to continue")
                print("Exiting!")
                sys.exit()
            
            if laps_user in all_laps_users:
                user_exists = True
            
            else: 
                j+=1

        return user_exists

    def get_laps_password(self, url: str, management_id: str, laps_user: str, credentials: str) -> str:
        """Gets the LAPS password for a specified LAPS enabled local admin on a specific computer.

        Args:
            url (str): Jamf Pro server URL
            management_id (str): Management ID corresponding to a specific computer inventory record.
            credentials (str): Bearer token

        Returns:
            str: LAPS password
        """
            
        endpoint="/api/v2/local-admin-password/"
        operation = management_id + "/account/" + laps_user + "/password"
        attempt = False
        
        user_exists = self.check_laps_user(url, management_id, credentials, laps_user)
        if user_exists:
            while not attempt:
                laps_user_password = ""
                response = ""
                
                try:
                    response = JamfProAPI().get(url, credentials, endpoint, operation=operation)
                    
                    if response['httpStatus'] in HTTP_SUCCESS:
                        laps_user_password = response['message']['password']
                        return laps_user_password
                    
                    else:
                        print(self.format_text(response['message']))
                        input("Press enter to continue: ")
                        continue

                except:
                    print(self.broken_script_message)
                    input("Press enter to continue")
                    print("Exiting!")
                    sys.exit()
        
        else:
            pass

    def view_laps_password(self, url: str, credentials: str) -> None:
        """Displays LAPS password for a specific local admin on a specific computer alongside identifying information for that computer.

        Args:
            url (str): Jamf Pro server URL
            credentials (str): Bearer token
        """
        
        print(self.menu_title("View LAPS user password for a computer"))
        
        permission_checker = self.permission_checker(url, credentials)
        
        has_permission = False
        if permission_checker is not None:
            has_permission = True
        
        if has_permission:
            
            computer_object = self.get_computer_object_interactive(url, credentials)
            
            if computer_object is not None:
                computer_id = computer_object['id']
                computer_name = computer_object['general']['name']
                computer_site = computer_object['general']['site']["name"]
                management_id = computer_object['general']['managementId']
                
                # Gets LAPS enabled admin username and confirms that it exists on the computer name chosen above.
                if gUseDebugInput:
                    laps_user = gDebugLAPSEnabledUser
                    
                else:
                    laps_user = self.get_laps_user_interactive(url, management_id, credentials)

                if laps_user is not None:
                    print(self.menu_title("View LAPS user password for a computer"))
                    
                    # Displays LAPS enabled admin user for the chosen computer, followed by that account's password in plaintext. 
                    laps_user_password = self.get_laps_password(url, management_id, laps_user, credentials)
                    
                    if laps_user_password is not None:
                    
                        display_txt = """
Computer ID: {0}
Computer Name: {1}
Computer Site {2}
Computer Management ID: {3}
LAPS enabled admin username: {4}
LAPS enabled admin password: {5}
""".format(computer_id, computer_name, computer_site, management_id, laps_user, laps_user_password)
                    
                        return display_txt
                
                else:
                    pass
            else:
                pass
        else:
            pass

    def change_laps_password_interactive(self, url: str, credentials: str) -> None:
        
        print(self.menu_title("Update LAPS user password for a computer"))
        
        permission_checker = self.permission_checker(url, credentials)
        
        has_permission = False
        if permission_checker is not None:
            has_permission = True
        
        if has_permission:
            print(self.menu_title("Update LAPS user password for a computer"))
            
            start_over = False
            
            computer_object = self.get_computer_object_interactive(url, credentials)
            
            if computer_object is not None:
                computer_id = computer_object['id']
                computer_name = computer_object['general']['name']
                computer_site = computer_object['general']['site']["name"]
                management_id = computer_object['general']['managementId']
                
                # Gets LAPS enabled admin username and confirms that it exists on the computer name chosen above.
                laps_user = ""
                if gUseDebugInput:
                    laps_user = gDebugLAPSEnabledUser
                    
                else:
                    laps_user = self.get_laps_user_interactive(url, management_id, credentials=credentials)
                
                if laps_user is not None:
                    # Prompt the user for a new password for the LAPS enabled user. 
                    valid_password = False
                    while not valid_password:
                        
                        if start_over:
                            break
                        # print(self.menu_title("Update LAPS user password for a computer"))
                        
                        new_laps_password = ""
                        confirm_new_laps_password = ""
                        
                        old_laps_user_password = self.get_laps_password(url, management_id, laps_user, credentials)
                        
                        password_request_txt = "Please enter the password that you would like to use for the LAPS enabled admin account, \"{0}\", on \"{1}\": ".format(laps_user, computer_name)
                        
                        formatted_password_request_txt = self.format_text(password_request_txt)
                        
                        new_laps_password = getpass.getpass(formatted_password_request_txt)
                        if new_laps_password == "0":
                            print("Exiting!")
                            sys.exit()
                        
                        if new_laps_password != "":
                            confirm_new_laps_password = getpass.getpass(self.format_text("Please re-enter the password to validate that it is what you intended to type: "))
                            print("")
                            
                            if confirm_new_laps_password == "0":
                                print("Exiting!")
                                sys.exit()
                        else:
                            print("New password cannot be empty!\n")
                            continue
                                
                        if new_laps_password == confirm_new_laps_password:
                            user_confirmed_information = False
                            
                            while not user_confirmed_information:
                                confirmation_txt = """
Computer ID: {0}
Computer Name: {1}
Computer Site {2}
Computer Management ID: {3}
LAPS enabled admin username: {4}
OLD LAPS enabled admin password: {5}
NEW LAPS enabled admin password: {6}
""".format(computer_id, computer_name, computer_site, management_id, laps_user, old_laps_user_password, new_laps_password)

                                confirm_information = input(confirmation_txt + "\nDoes this look correct? [Y|N]: ")
                                
                                match confirm_information:
                                    case "y"|"Y":
                                        user_confirmed_information = True
                                        
                                    case "n"|"N":
                                        print("Please re-enter the information and try again. Exiting to main menu.\n")
                                        start_over = True
                                        break
                                    
                                    case "0":
                                        print("Exiting!")
                                        sys.exit()
                                        
                                    case _:
                                        print("Invalid input, please try again.\n")
                                        continue
                                    
                            if user_confirmed_information:
                                valid_password = True
                                
                        else:
                            print("Passwords did not match, please try again.")
                            continue
                    
                    # Update the LAPS enabled admins users' password with the previously acquired password.
                    password_updated = False
                    while not password_updated:
                        if start_over:
                            break
                        endpoint="/api/v2/local-admin-password/"
                        operation = management_id + "/set-password"
                        payload = { "lapsUserPasswordList": [
        {
        "username": laps_user,
        "password": new_laps_password
        }
        ] }
                                
                        try:
                            response = JamfProAPI().put(url, credentials, endpoint, payload, operation=operation)
                            
                            if response['httpStatus'] in HTTP_SUCCESS:
                                password_updated = True
                                print(self.format_text("Jamf Pro reports the API call to update the password as a success! Please allow a few minutes for the change to reflect on the computer. If it takes any longer, please ensure that the computer is turned on and connected to the internet and that the password meets any password policies applied to the computer."))
                                
                            else:
                                print(response)
                                print("\nPassword update not successful. Please try again.")
                                break
                        except:
                            print(self.broken_script_message)
                            break
                else:
                    pass
            else:
                pass
        else:
            pass

    def change_laps_password_iterative(self, url: str, credentials: str) -> None:
        
        print(self.menu_title("Update LAPS user password for all available computers"))
        
        permission_checker = self.permission_checker(url, credentials)
        
        has_permission = False
        if permission_checker is not None:
            has_permission = True
        
        if has_permission:
            print(self.menu_title("Update LAPS user password for all available computers"))
            
            all_computers_object = self.get_all_computers(url, credentials)
            
            if all_computers_object is not None:
                totalCount = all_computers_object['totalCount']
                
                if gUseDebugInput:
                    laps_user = gDebugLAPSEnabledUser
                else:
                    laps_user = input(self.format_text("Please enter the LAPS enabled local admin account name that you would like to change the password for on all available computers: "))
                
                display_sanity = "Are you sure you want to change the password for \"{0}\" on up to {1} computers? This process will make any effected computers share the exact same password for the local admin account \"{0}\" and that could introduce a security vulnrability that Jamf implemented LAPS to avoid causing. [Y|N]: ".format(laps_user, totalCount)
                
                final_plead = "The author of this script, it's contributors, and Jamf Software do not take responsibility for any issues, security vulnrabilities, or security breaches caused by taking this action. Only proceed if you are sure of what you are doing. Proceed? [Y|N]: "
                
                user_agreement_1 = False
                user_agreement_2 = False
                user_choice = False
                undesirable_choice = False
                
                while not user_choice:
                    sanity_check = input(self.format_text(display_sanity))
                    match sanity_check:
                        case "y"|"Y":
                            user_agreement_1 = True
                        
                        case "n"|"N":
                            user_choice = True
                            
                        case "0":
                            print("Exiting without making any changes.")
                            sys.exit()
                            
                        case _:
                            print("Invalid input. Read carefully and try again.")
                                
                    if user_agreement_1:
                        triple_check = input(self.format_text(final_plead))
                        match triple_check:
                            case "y"|"Y":
                                user_agreement_2 = True
                            
                            case "n"|"N":
                                user_choice = True
                                
                            case "0":
                                print("Exiting without making any changes.")
                                sys.exit()
                                
                            case _:
                                print("Invalid input. Read carefully and try again.")
                            
                    if user_agreement_2:
                        user_choice = True
                        undesirable_choice = True
                
                if undesirable_choice:
                    confirm_user_exists_txt = "Confirming that \"{0}\" exists on the target computers. If the user does not exist on a specific computer, the computer will be skipped.".format(laps_user)
                    print(self.format_text(confirm_user_exists_txt))
                    
                    i = 0
                    computers = dict()
                    while i < totalCount:
                        computers[i] = {}
                        computers[i]['managementId'] = all_computers_object['results'][i]['general']['managementId']
                        computers[i]['name'] = all_computers_object['results'][i]['general']['name']
                        i+=1
                    
                    confirmed_computers = dict()
                    for index in computers:
                        check_id = computers[index]['managementId']
                        user_exists = self.check_laps_user(url, check_id, credentials, laps_user)
                        if user_exists:
                            confirmed_computers[index] = computers[index]

                    all_effected_computers = len(confirmed_computers)
                    
                    if all_effected_computers > 0:
                        confirmation_text = "{0} computers will be effected. This is the final chance to abort this action, proceeding will start the process of changing the LAPS password for the {1} account for every single effected computer. Proceed? [Y|N]: ".format(all_effected_computers, laps_user)
                        user_agreement_3 = False
                        user_choice_2 = False
                        while not user_choice_2:
                            final_confirmation = input(self.format_text(confirmation_text))
                            match final_confirmation:
                                case "y"|"Y":
                                    user_agreement_3 = True
                                    user_choice_2 = True
                                
                                case "n"|"N":
                                    user_choice_2 = True
                                    
                                case "0":
                                    print("Exiting without making any changes.")
                                    sys.exit()
                                    
                                case _:
                                    print("Invalid input. Read carefully and try again.")
                                    
                        if user_agreement_3:
                            valid_password = False
                            while not valid_password:
                                new_laps_password = ""
                                confirm_new_laps_password = ""
                                
                                password_request_txt = "Please enter the password that you would like to use for the LAPS enabled admin account, \"{0}\", on all effected computers: ".format(laps_user)
                                
                                new_laps_password = getpass.getpass(self.format_text(password_request_txt))
                                if new_laps_password == "0":
                                    print("Exiting!")
                                    sys.exit()

                                if new_laps_password != "":
                                    confirm_new_laps_password = getpass.getpass(self.format_text("Please re-enter the password to validate that it is what you intended to type: "))
                                    print("")
                                    
                                    if confirm_new_laps_password == "0":
                                        print("Exiting!")
                                        sys.exit()
                                else:
                                    print("New password cannot be empty!\n")
                                    continue
                                
                                if new_laps_password == confirm_new_laps_password:
                                    valid_password = True
                                
                                else:
                                    print("Passwords did not match. Please try again.\n")
                                    continue
                            
                            if valid_password:
                                for index in confirmed_computers:
                                    confirmed_id = confirmed_computers[index]['managementId']
                                    confirmed_name = confirmed_computers[index]['name']
                                    password_updated = False
                                    while not password_updated:
                                        endpoint="/api/v2/local-admin-password/"
                                        operation = confirmed_id + "/set-password"
                                        payload = { "lapsUserPasswordList": [
            {
            "username": laps_user,
            "password": new_laps_password
            }
            ] }
                                                
                                        try:
                                            response = JamfProAPI().put(url, credentials, endpoint, payload, operation=operation)
                                            if response['httpStatus'] in HTTP_SUCCESS:
                                                password_updated = True
                                                formatted_success = "Jamf Pro reports the API call to update the password on {} as a success! Please allow a few minutes for the change to reflect on the computer. If it takes any longer, please ensure that the computer is turned on and connected to the internet and that the password meets any password policies applied to the computer.".format(confirmed_name)
                                                print("\n" + self.format_text(formatted_success))
                                            else:
                                                print(response)
                                                formatted_failure = "Password update on {} not successful Ending this attempt to ensure nothing else goes wrong. Please try again.".format(confirmed_name)
                                                print(self.format_text(formatted_failure))
                                                break
                                        except:
                                            print(self.broken_script_message)
                                            break
                        else:
                            print("Returning to main menu without making any changes.")
                    
                    else:
                        pass
                    
                else:
                        print("Returning to main menu without making any changes.")
            else:
                pass
        else:
            pass
 
    def permission_checker(self, url: str, credentials: str) -> int:
        
        endpoint = "/api/v2/local-admin-password/"
        operation = "pending-rotations"
        
        try:
            response = JamfProAPI().get(url, credentials, endpoint, operation)
        
        except:
            print(self.broken_script_message)
            input("Press enter to continue")
            print("Exiting!")
            sys.exit()
        
        if response['httpStatus'] in HTTP_SUCCESS:
            
            json_data = response['message']
            totalCount = json_data['totalCount']
            pending_rotations = int(totalCount)
            return pending_rotations
        
        else:
            print(self.format_text(response['message']))
 
    def state_checker(self, url: str, credentials: str) -> str:
        """Checks authentication state prior to every operation.

        Args:
            url (string): Jamf Pro URL
            credentials (string): Bearer Token

        Returns:
            string: Either "OK" or a new bearer token
        """
        
        print("Checking state...")
        
        endpoint="/api/v1/auth/"
        
        response = JamfProAPI().get(url, credentials, endpoint)
        status = response['httpStatus']
        if status in HTTP_SUCCESS:
            state = "OK"
            return state
        else:
            state = "Error"
            return state

    def format_text(self, text: str) -> str:
        terminal_size = os.get_terminal_size()
        width = terminal_size.columns
        max_size = 128
        
        if width > max_size:
            formatted_text = textwrap.fill(text, max_size, drop_whitespace=False)
        
        else:
            formatted_text = textwrap.fill(text, width, drop_whitespace=False)
        
        return formatted_text

    def broken_script_message(self) -> str:
        
        message = self.format_text("Something unexpected went wrong. Try that again. If this keeps happening then either a change was made to the Jamf Pro API that broke this script or something is going wrong with your Jamf Pro server.")
        return message

    def menu_title(self, title) -> str:
        
        os.system('cls' if os.name == 'nt' else 'clear')
        
        terminal_size = os.get_terminal_size()
        width = terminal_size.columns
        space_left = width - len(title)
        
        filler_space = int((space_left/2) - 1)
        max_size = 130
        min_size = int(max_size/2)
        max_filler_space = int((max_size - len(title))/2)
        min_filler_space = int((min_size - len(title))/2)
        
        filler_characters = filler_space*"-"
        max_filler_characters = max_filler_space*"-"
        min_filler_characters = min_filler_space*"-"

        quit_text = "\nExit script at any time by entering \"0\".\n"
        
        menu_title = filler_characters + title + filler_characters + quit_text
        
        if len(menu_title) > max_size:
            menu_title = max_filler_characters + title + max_filler_characters + quit_text
        
        elif len(menu_title) < min_size:
            menu_title = min_filler_characters + title + min_filler_characters + quit_text
        
        return menu_title
  

class Menu:
    """Provides a menu of operations this script can perform. This is treated as the main function of this script. Exiting the menu ends the script.
    """
    
    def __init__(self):
        pass

    def main_menu(self):
        """Main menu for the script. Holds the values for a Jamf Pro URL and Bearer Token while the script is running.
        """
        
        # Users will see and agree to the license one way or another.
        print(self.menu_title("License Agreement"))
        
        license_message = "THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS, COPYRIGHT HOLDERS, OR JAMF SOFTWARE BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE."
        
        print(self.format_text(license_message))
        license_agreement = input("\nPress enter to continue or \"0\" to exit the script without agreeing to the license: ")
        if license_agreement == "0":
            print("Exiting!")
            sys.exit()
        
        # Require user to enter their Jamf Pro URL before moving forward. User cannot move forward without a valid URL that resolves without a 404 error.
        jss_url = Menu_Actions().url_validation()
        
        # Require user to authenticate before moving forward. User cannot move forward without successfully authenticating to Jamf Pro with simple credentials and acquiring a bearer token. Future functionality will include logic for API roles/clients feature that recently released. 
        token = Menu_Actions().auth_attempt(jss_url)
        
        # Now that we have a valid URL and valid bearer token, the script presents the main menu.
        choice = False
        while not choice:
            menu_title = "Welcome to your Jamf Pro LAPS interface"
            print(self.menu_title(menu_title))
            
            # State checker confirms that the user has a valid authentication token every time they enter the menu or take a menu action. If not it forces them to create a new one. 
            check_state = Menu_Actions().state_checker(jss_url, token)
            if check_state != "OK":
                token = Menu_Actions().auth_attempt(jss_url)
            
            # Presents the logged in user and site they have access to.
            user_object = Menu_Actions().get_jss_user_object(jss_url, token)
            
            if user_object is not None:
                Menu_Actions().display_user_attributes(user_object)
            
            else:
                print(self.format_text("You somehow have an authentication token but we cannot get your user information from Jamf Pro. The Jamf Pro API may have changed and this script not updated to match it. Whatever is going on I don't like it. Exiting script, please try again."))
                sys.exit()
        
            # Present menu options and ask user to input a number that corresponds to a specific option.
            options = self.menu_options()
            
            match options:
                # 1: View Jamf Pro LAPS Settings
                case "1":
                    check_state = Menu_Actions().state_checker(jss_url, token)
                    if check_state != "OK":
                        token = Menu_Actions().auth_attempt(jss_url)
                    
                    laps_settings = Menu_Actions().get_laps_settings(jss_url, credentials=token)
                    
                    if laps_settings != None:
                        print("MDM LAPS enabled: ", laps_settings['autoDeployEnabled'])
                        print("Password rotation time (in seconds): ", laps_settings['passwordRotationTime'])
                        print("Automatic password rotation enabled: ", laps_settings['autoRotateEnabled'])
                        print("Automatic rotation expiration time (in seconds): ", laps_settings['autoRotateExpirationTime'])
                        
                        # View raw json by uncommenting below: 
                        # print(json.dumps(laps_settings, indent=4))

                    else:
                        pass
                    
                    input("\nPress enter to continue: ")
                
                # 2: View total pending LAPS rotations
                case "2":
                    check_state = Menu_Actions().state_checker(jss_url, token)
                    if check_state != "OK":
                        token = Menu_Actions().auth_attempt(jss_url)
                    
                    pending_rotations = Menu_Actions().get_all_pending_laps_rotations(jss_url, token)
                    
                    if (type(pending_rotations) is int) and (pending_rotations > 0):
                        print("Total pending LAPS rotations:", pending_rotations)
                    
                    elif pending_rotations is None:
                        pass
                    
                    else:
                        print("No pending rotations at this time.")
                    
                    input("\nPress enter to continue: ")
                
                # 3: View pending LAPS rotation for a specific computer
                case "3":
                    check_state = Menu_Actions().state_checker(jss_url, token)
                    if check_state != "OK":
                        token = Menu_Actions().auth_attempt(jss_url)
                    
                    pending_laps_rotations = Menu_Actions().view_pending_rotations_by_device(jss_url, token)
                    
                    if pending_laps_rotations is not None:
                        print(pending_laps_rotations)
                    
                    else:
                        pass
                    
                    input("\nPress enter to continue: ")
                
                # 4: View LAPS enabled local admin user password for a specific computer
                case "4":
                    check_state = Menu_Actions().state_checker(jss_url, token)
                    if check_state != "OK":
                        token = Menu_Actions().auth_attempt(jss_url)
                    
                    password_info = Menu_Actions().view_laps_password(jss_url, token)
                    
                    if password_info is not None:
                        print(password_info)
                    
                    else:
                        pass
                    
                    input("\nPress enter to continue: ")
                
                # 5: Update password for LAPS enabled local admin for a specific computer
                case "5":
                    check_state = Menu_Actions().state_checker(jss_url, token)
                    if check_state != "OK":
                        token = Menu_Actions().auth_attempt(jss_url)
                    
                    Menu_Actions().change_laps_password_interactive(jss_url, token)
                    input("\nPress enter to continue: ")
                
                # 6: Update password for LAPS enabled local admin for all available computers (limited to a single site or potentially all computers in Jamf Pro depending on your user permissions)
                case "6":
                    check_state = Menu_Actions().state_checker(jss_url, token)
                    if check_state != "OK":
                        token = Menu_Actions().auth_attempt(jss_url)
                    
                    Menu_Actions().change_laps_password_iterative(jss_url, token)
                    
                    input("\nPress enter to continue: ")
                
                # 0: Quit
                case "0":
                    print(Menu_Actions().invalidate_auth_token(jss_url, token))
                    print("Exiting!")
                    sys.exit()
                
                # Invalid option    
                case _:
                    print("Invalid option, please enter the number corresponding to the action you would like to take.")
                    input("\nPress enter to continue: ")

    def menu_title(self, title) -> str:
        
        os.system('cls' if os.name == 'nt' else 'clear')
        
        terminal_size = os.get_terminal_size()
        width = terminal_size.columns
        space_left = width - len(title)
        
        filler_space = int((space_left/2) - 1)
        max_size = 130
        min_size = int(max_size/2)
        max_filler_space = int((max_size - len(title))/2)
        min_filler_space = int((min_size - len(title))/2)
        
        filler_characters = filler_space*"-"
        max_filler_characters = max_filler_space*"-"
        min_filler_characters = min_filler_space*"-"

        quit_text = "\nExit script at any time by entering \"0\".\n"
        
        menu_title = filler_characters + title + filler_characters + quit_text
        
        if len(menu_title) > max_size:
            menu_title = max_filler_characters + title + max_filler_characters + quit_text
        
        elif len(menu_title) < min_size:
            menu_title = min_filler_characters + title + min_filler_characters + quit_text
        
        return menu_title

    def menu_options(self) -> str:
        """Presents menu options to the user. Formats the options to fit within their terminal space and not look janky.

        Returns:
            str: Option user would like to take.
        """

        terminal_size = os.get_terminal_size()
        width = terminal_size.columns
        max_size = 128
        
        request = "Please enter the number that corresponds to the action you would like to take to continue:"
        option_0 = "0: Quit"
        option_1 = "1: View Jamf Pro LAPS Settings"
        option_2 = "2: View total pending LAPS rotations"
        option_3 = "3: View pending LAPS rotation for a specific computer"
        option_4 = "4: View LAPS enabled local admin user password for a specific computer"
        option_5 = "5: Update password for LAPS enabled local admin for a specific computer"
        option_6 = "6: Update password for LAPS enabled local admin for all available computers (limited to a single site or potentially all computers in Jamf Pro depending on your user permissions)"
        
        options = [option_1, option_2, option_3, option_4, option_5, option_6, option_0]
        
        if width > max_size:
            print("\n" + textwrap.fill(request, max_size) + "\n")
            
            for text in options:
                formatted_text = textwrap.fill(text, max_size)
                print(formatted_text)
            
            user_input = input("Enter option: ")
        
        else:
            print("\n" + textwrap.fill(request, width) + "\n")
            
            for text in options:
                formatted_text = textwrap.fill(text, width)
                print(formatted_text)
            
            user_input = input("Enter option: ")
        
        return user_input

    def format_text(self, text: str) -> str:
        terminal_size = os.get_terminal_size()
        width = terminal_size.columns
        max_size = 128
        
        if width > max_size:
            formatted_text = textwrap.fill(text, max_size, drop_whitespace=False)
        
        else:
            formatted_text = textwrap.fill(text, width, drop_whitespace=False)
        
        return formatted_text


def main():
    Menu().main_menu()


if __name__ == "__main__":
    main()
