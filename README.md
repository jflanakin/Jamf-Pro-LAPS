# Summary
This program was created to perform Jamf Pro API LAPS Operations. It is a menu based cli/terminal only program with basic permissions checking and as robust error checking & error message handling as a I can include. Will work for MacOS, Windows, or Linux assuming you have Python 3 installed. 

## Current functionality includes:
* Utilize basic authentication credentials (username/password) to acquire a bearer token for future API calls to Jamf Pro.
* User actions limited based on site access (full Jamf Pro or single-site specific).
* Basic permissions checking prior to every action.
* Shows user authentication details from bearer token including username, user type, and site access.
* View LAPS settings for Jamf Pro.
* View total pending LAPS rotations for all computers the current user has access to (limited based on site access).
* View pending LAPS rotation for a specific admin account on a specific computer.
* Update password for LAPS enabled local admin for a specific computer.
* Update password for LAPS enabled local admin for all available computers (limited to a single site or potentially all
computers in Jamf Pro depending on your user permissions)

## Future planned updates:
* Release as an executable file/package alongside source for ease of usability.
* Jamf Pro API Clients/Roles functionality.
* Limiting mass action resets to static or smart groups.
* More advanced permissions checking prior to every action.
* Including functionality for any API actions for LAPS operations that doesn't currently exist in the program.
* More robust error checking and error message handling.

# Requirements: 
* Python 3
* requirements.txt file

# Pre-Requisites: 
Run the following command to install the required libraries in order to run the script from source:
* Windows:
```pip install -r requirements.txt```

* Linux/MacOS: 
```pip3 install -r requirements.txt```

# Running the script:
* Windows:
```python C:\path\to\jss-laps.py```
* Linux/MacOS:
```python3 /path/to/jss-laps.py```

# Known issues: 
* Entering a URL that technically resolves but is not your Jamf Pro server will throw an error and gracefully exit the script. This is due to the "requests" library and how it handles 404's. The error message includes a warning to reset whatever password you used to attempt the authentication with since I cannot stop folks from typing in malicious URL's on accident (nor check for them before proceeding). 
* Users with extremely weird permissions in Jamf Pro may run into some unhandled exceptions, or at least a fair amount of issues using this script. Currently the script only does permissions checking by ensuring that your user account has the ability to view the number pending password rotations and handles any potential 403 errors after that initial check as best it can. Future updates will include functionality to pre-screen permissions based on the details contained in a users' authentication token rather than a simple check and attempting to handle potential 403 errors when they come up.