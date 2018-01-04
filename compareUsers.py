# !/usr/bin/env python

import base64
import requests
import json
import sys
import re
import os
import argparse
import xlsxwriter
import getpass
from ldap3 import Server, Connection, SUBTREE, DEREF_ALWAYS

# In a devtest environment, self-signed certs are regularly used.
# Let's disable the warning when over-riding.
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# Ask the User for his/her AD/LDAP user password
def get_AD_password(ad_user):
    ad_password = getpass.getpass('Enter password for your domain username %s: ' % ad_user)
    return ad_password

# Ask the User for his/her ESM user password
def get_ESM_password(esm_user):
    esm_password = getpass.getpass('Enter password for your ESM username %s: ' % esm_user)
    return esm_password


### ESM API Call Functions ###

# Builds the ESM API URL used in all API Call Functions
def build_url(esm):
    url_base = 'https://' + esm + '/rs/esm/'
    return url_base

#ESM Login
def login(url_base, user, password):
    try:
        user = base64.b64encode(user)
        password = base64.b64encode(password)
        params = {"username": user, "password": password, "locale": "en_US", "os" : "Win32"}
        params_json = json.dumps(params)
        login_headers = {'Content-Type': 'application/json'}
        login_response = requests.post(url_base + 'login', params_json, headers=login_headers, verify=False)
        Cookie = login_response.headers.get('Set-Cookie')
        JWTToken = re.search('(^[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*)', Cookie).group(1)
        Xsrf_Token = login_response.headers.get('Xsrf-Token')
        session_header = {'Cookie' : JWTToken, 'X-Xsrf-Token' : Xsrf_Token, 'Content-Type': 'application/json'}
    except KeyError:
        print 'Invalid credentials'
        sys.exit(1)
    return session_header

#ESM Logout
def logout(url_base, session_header):
    requests.delete(url_base + 'logout', headers=session_header, verify=False)

# Get a list of all ESM Users
def esmUserList(url_base, session_header, password):
    params = {"authPW": {"value": password}}
    params_json = json.dumps(params)
    response = requests.post(url_base + 'userGetUserList', data=params_json, headers=session_header, verify=False)
    data = response.json()
    return data

# Get a list of all ESM Groups, and return the ID of the specified Group
def getGroupID(url_base, session_header, password, groupname):
    params = {"authPW": {"value": password}}
    params_json = json.dumps(params)
    response = requests.post(url_base + 'userGetAccessGroupList?restrictToUsersGroup=false', data=params_json, headers = session_header, verify = False)
    data = response.json()
    for item in data.get('return'):
        if groupname == item.get('name'):
            groupID = item.get('id').get('value')
            return groupID

# Delete the Specified ESM User
def deleteUser(url_base, session_header, password, esmUsers, user):
    userID = getUserID(esmUsers, user)
    params = {
       "id" : userID,
       "authPW": {"value": password}
       }
    params_json = json.dumps(params)
    response = requests.post(url_base + 'userDeleteUser', data=params_json, headers = session_header, verify = False)
    if response.status_code == 200:
        print 'User (%s) was successfully deleted from the SIEM' %user
    else:
        print 'This did not work for user (%s)' %user

# Disable the Specified ESM User
def disableEsmUser(url_base, session_header, password, esmUsers, user):
    params = {}
    user_params = getUserConfig(esmUsers, user)
    user_params['locked'] = "True"
    params = {
       "user" : user_params,
       "authPW": {"value": password}
       }
    params_json = json.dumps(params)
    response = requests.post(url_base + 'userEditUser', data = params_json, headers = session_header, verify = False)
    if response.status_code == 200:
        print 'ESM Account (%s) was successfully disabled' %user
    else:
        print 'This did not work for ESM account (%s)' %user


### LDAP functions ###

# Bind/Connect to LDAP Server
def getLdapClientConnection(ad_server, ad_user, ad_password):
    try:
        server = Server(ad_server, port=389, use_ssl=False)
        connection = Connection(server, auto_bind=True, version=3, authentication="SIMPLE", user=ad_user, password=ad_password)
        return connection
    except:
        print "Failed to establish LDAP connection. Could not bind to AD Server: %s with the specified credentials" % ad_server
        sys.exit(1)

# UnBind/Disconnect from LDAP Server
def closeLdapClientConnection(connection):
    connection.unbind()

# List all of the users in the specified LDAP Group
def listAllUsersinGroup(connection, search_basedn):
    results = []
    search_base = search_basedn
    search_scope = SUBTREE
    search_filter = '(objectClass=group)'
    attributes = [ 'member' ]
    dereference_aliases = DEREF_ALWAYS
    get_operational_attributes = False
    connection.search(search_base, search_filter, search_scope, dereference_aliases, attributes, get_operational_attributes)
    for entry in connection.entries:
        for member in entry.member:
         results.append(member)
    return results

# Return a list of sAMAccountNames of all users in the Specified LDAP Group
def getSamAccountNames(connection, ad_users):
    results = []
    for user in ad_users:
        search_base = user
        search_scope = SUBTREE
        search_filter = '(sAMAccountType=805306368)'
        attributes = [ 'sAMAccountName' ]
        dereference_aliases = DEREF_ALWAYS
        get_operational_attributes = False
        connection.search(search_base, search_filter, search_scope, dereference_aliases, attributes, get_operational_attributes)
        for entry in connection.entries:
            results.append(entry.sAMAccountName[0].lower())
    return results

# Return a list of all disabled Users in the Specified LDAP Group
def listDisabledUsersinGroup(connection, ad_users):
    #  User account Control Values for any type of Disabled aD User
    #  -------------------------------------------------------------
    #  Disabled account, 514
    #  Disabled, Password Not Required, 546
    #  Disabled, Password Doesnt Expire, 66050
    #  Disabled, Password Doesnt Expire & Not Required, 66082
    #  Disabled, Smartcard Required, 262658
    #  Disabled, Smartcard Required, Password Not Required, 262690
    #  Disabled, Smartcard Required, Password Doesnt Expire, 328194
    #  Disabled, Smartcard Required, Password Doesnt Expire & Not Required, 328226

    uac_disabled_codes = [514, 546, 66050, 66082, 262658, 262690, 328194, 328226]
    results = []
    for user in ad_users:
        search_base = user
        search_scope = SUBTREE
        search_filter = '(sAMAccountType=805306368)'
        attributes = [ 'userAccountControl', 'sAMAccountName' ]
        dereference_aliases = DEREF_ALWAYS
        get_operational_attributes = False
        connection.search(search_base, search_filter, search_scope, dereference_aliases, attributes, get_operational_attributes)
        for entry in connection.entries:
            if entry.userAccountControl[0] in uac_disabled_codes:
                results.append(entry.sAMAccountName[0].lower())
    return results

def listUsernamesinGroup(esmUsers, groupID):
    results = []
    data = esmUsers
    for item in data.get('return'):
        for group in item.get('groups'):
            if group.get('value') == groupID:
                pattern = re.search('[a-zA-Z0-9\x2e]+(.*)', item.get('username')).group(1)
                results.append(item.get('username').replace(pattern, '').lower())
    return results


### Helper functions ###

# Returns a list of only the usernames of the ESM Users
def listESMUsers(esmUsers):
    results = []
    for item in esmUsers.get('return'):
        pattern = re.search('[a-zA-Z0-9\x2e]+(.*)', item.get('username')).group(1)
        results.append(item.get('username').replace(pattern, '').lower())
    return results

# Returns the ID of the Specified ESM User
def getUserID(esmUsers, user):
    for item in esmUsers.get('return'):
        if user in item.get('username'):
            user_id = item.get('id').get('value')
            return user_id

# Returns the configuration of the Specified ESM User
def getUserConfig(esmUsers, user):
    for item in esmUsers.get('return'):
        if user in item.get('username'):
            return item

# Returns a list of only users that exist in the ESM
def esmUsersNotinAD(esm_users, ad_users):
    defaultEsm_users = set(['ngcp', 'policy', 'report'])
    dupes = set(esm_users).intersection(ad_users)
    diffs = set(esm_users) - set(dupes)
    diff_users = list(set(diffs) - defaultEsm_users)
    return diff_users

# Returns a list of only users that exist in Active Directory
def adUsersNotinESM(ad_users, esm_users):
    dupes = set(ad_users).intersection(esm_users)
    diffs = set(ad_users) - set(dupes)
    diff_users = list(diffs)
    return diff_users

# Generates the list of AD/LDAP Users, ESM Users, and ESM Group ID for the Specified Group
def build_script_constants(conn, ad_group, url_base, session_header, esm_password, esm_group):
    ad_users_in_group = listAllUsersinGroup(conn, ad_group)
    esmUsers = esmUserList(url_base, session_header, esm_password)
    groupID = getGroupID(url_base, session_header, esm_password, esm_group)
    return ad_users_in_group, esmUsers, groupID


### Workbook Functions ###

# Create Excel Worksheet containing the Specified User List
def createUserWrkbk(base_path, user_type, userlist):
    if not os.path.exists(base_path):
        os.makedirs(base_path)
    if '~' in base_path:
        base_path = os.path.expanduser(file_path)
    file_path = os.path.join(base_path, user_type + ' Users.xlsx')
    if len(userlist) != 0:
        workbook = xlsxwriter.Workbook(file_path)
        worksheet = workbook.add_worksheet()
        format = workbook.add_format({'bold': True, 'align' : 'center'})
        format.set_bg_color('# 90EE90')
        format.set_border(1)
        user_fmt = workbook.add_format({'align' : 'left', 'border' : 1})
        user_fmt.set_text_wrap()
        worksheet.write('A1', user_type+' Users', format)
        worksheet.set_column(0, 0, 25)
        worksheet.freeze_panes(1,0)
        row = 1
        col = 0
        for user in userlist:
            worksheet.write_string(row, col, user, user_fmt)
            row += 1
        workbook.close()
        print "Created Spreadsheet"
    else:
        if user_type == 'ESM Only':
            print "There are no ESM Only Users"
        elif user_type == 'AD Only':
            print "There are no AD Only Users"
        else:
            print "User List is empty"

# Create an Excel Worksheet containing All users:
#   All ESM Users, AD Users, Users that only exist in the ESM Group, and Users that only exist in the AD Group
def createCombinedWrkbk(base_path, esm_users, ad_users, esmonly, adonly):
    if not os.path.exists(base_path):
        os.makedirs(base_path)
    if '~' in base_path:
        base_path = os.path.expanduser(file_path)
    file_path = os.path.join(base_path, 'All Users.xlsx')
    workbook = xlsxwriter.Workbook(file_path)
    worksheet = workbook.add_worksheet()
    format = workbook.add_format({'bold': True, 'align': 'center'})
    format.set_bg_color('# 90EE90')
    format.set_border(1)
    user_fmt = workbook.add_format({'align': 'left', 'border': 1})
    user_fmt.set_text_wrap()
    worksheet.write('A1', 'ESM Users', format)
    worksheet.write('B1', 'AD Users', format)
    worksheet.write('C1', 'ESM Only Users', format)
    workshett.write('D1', 'AD Only Users', format)
    worksheet.set_column(0, 0, 20)
    worksheet.set_column(1, 1, 20)
    worksheet.set_column(2, 2, 20)
    worksheet.set_column(3, 3, 20)
    worksheet.freeze_panes(1, 0)
    if len(esm_users) != 0:
        row = 1
        col = 0
        for user in esm_users:
            worksheet.write_string(row, col, user, user_fmt)
            row += 1
    else:
        print "ESM User List is empty, and was not written to spreadsheet."
    if len(ad_users) != 0:
        row = 1
        col = 1
        for user in ad_users:
            worksheet.write_string(row, col, user, user_fmt)
            row += 1
    else:
        print "AD User List is empty, and was not written to spreadsheet."
    if len(esmonly) != 0:
        row = 1
        col = 2
        for user in esmonly:
            worksheet.write_string(row, col, user, user_fmt)
            row += 1
    else:
        print "List of Users in ESM only is empty, and was not written to spreadsheet."
    if len(adonly) != 0:
        row = 1
        col = 3
        for user in adonly:
            worksheet.write_string(row, col, user, user_fmt)
            row += 1
    else:
        print "List of Users in AD only is empty, and was not written to spreadsheet."
    workbook.close()
    print "Created Spreadsheet"

# Main Function :D
def main():

    parser = argparse.ArgumentParser(description='McAfee ESM and Active Directory Clean up Tool. The main purpose of this tool is to delete Users that exist in ESM but not in Active Directory. A secondary function exists where an ESM account can be disabled, if it is disabled in Active Directory.')

    #  AD parameters
    ad_group = parser.add_argument_group("AD options")
    ad_group.add_argument("-a", "--ad_server", type=str, metavar='AD SERVER',
                          help="Active Directory Server Hostname/ip", required=True)
    ad_group.add_argument("-d", "--ad_user", type=str, metavar='AD USERNAME',
                          help="DOMAIN\\username for authentication", required=True)
    ad_group.add_argument("-n", "--ad_password", type=str, metavar='AD PASSWORD', help="Domain User Password")
    ad_group.add_argument("-b", "--ad_group", type=str, metavar='AD GROUP BASEDN', help="AD Group Search Base DN, in a format similar to CN=Group,OU=Groups,DC=Example,DC=Com",
                          required=True)
    #  ESM Parameters
    esm_group = parser.add_argument_group("SIEM Options")
    esm_group.add_argument("-e", "--esm", type=str, metavar='ESM HOSTNAME', help="ESM Hostname/ip", required=True)
    esm_group.add_argument("-u", "--esm_user", type=str, metavar='ESM User', help='ESM Username for authentication',
                           required=True)
    esm_group.add_argument("-p", '--esm_password', type=str, metavar='ESM Password', help='ESM User Password')
    esm_group.add_argument("-g", "--esm_group", type=str, metavar='ESM GROUP', help="ESM Group Name", required=True)

    # Actions
    action_group = parser.add_mutually_exclusive_group()
    action_group.add_argument("-r", "--delete", action='store_true', help="Delete Users that exist in ESM but not in Active Directory")
    action_group.add_argument("-s", "--disable", action='store_true', help="Disable ESM Accounts that are disabled in Active Directory")

    #  Output parameters
    outputgroup = parser.add_argument_group("Output options")
    outputgroup.add_argument("-o", "--outdir", type=str, metavar='DIRECTORY',
                             help="Directory in which the dump will be saved (default: current)")
    outputgroup.add_argument("--write_ad_users", action='store_true', help="Create a spreadsheet containing only users in the AD Group")
    outputgroup.add_argument("--write_esm_users", action='store_true', help="Create a spreadsheet containing only users in the ESM Group")
    outputgroup.add_argument("--write_esmonly", action='store_true', help="Create a spreadsheet containing only users that exist in the ESM, but not in AD Group")
    outputgroup.add_argument("--write_adonly", action='store_true', help="Create a spreadsheet containing only users that exist in AD, but not in the ESM")
    outputgroup.add_argument("--write_all", action='store_true', help='Create a spreadsheet containing AD Users, ESM Users, and ESM Only Users')

    args = parser.parse_args()

    #Prompt for passwords, if not set
    if not '\\' in args.ad_user:
        print 'Username must include a domain, use: DOMAIN\username'
        sys.exit(1)
    if args.ad_password is None:
        args.ad_password = get_AD_password(args.ad_user)
    if args.esm_password is None:
        args.esm_password = get_ESM_password(args.esm_user)

    # Connect to LDAP Server
    connection = getLdapClientConnection(args.ad_server, args.ad_user, args.ad_password)

    url = build_url(args.esm)

    # Login and Grap ESM Session
    session = login(url, args.esm_user, args.esm_password)

    # Grab the AD/LDAP, ESM Users, ESM Group ID of the Specified Group
    ad_users_in_group, esmUsers, groupID = build_script_constants(connection, args.ad_group, url, session, args.esm_password, args.esm_group)

    # Build the Lists needed for the Delete, Disable Functions, and Excel Spreadsheets
    ad_users = getSamAccountNames(connection, ad_users_in_group)
    esm_users = listUsernamesinGroup(esmUsers, groupID)
    esm_users_notinAD = esmUsersNotinAD(esm_users, ad_users)
    ad_users_notinESM = adUsersNotinESM(ad_users, esm_users)

    # Export Worksheets to specified Directory, or current if not set
    if args.outdir is not None:
        file_path = args.outdir
    else:
        file_path = '.'

    # Delete only those Users that exist in the ESM
    if args.delete:
        for user in esm_users_notinAD:
            deleteUser(url, session, args.esm_password, esmUsers, user)
        createUserWrkbk(file_path, "Deleted ESM", esm_users_notinAD)

    # Disable ESM Users that are also Disabled in AD/LDAP
    if args.disable:
        dupes = set(listESMUsers(esmUsers)).intersection(listDisabledUsersinGroup(connection, ad_users_in_group))
        disabled_esm_users = list(dupes)
        for user in disabled_esm_users:
            disableEsmUser(url, session, args.esm_password, esmUsers, user)
        createUserWrkbk(file_path, 'Disabled ESM', disabled_esm_users)

    # Disconnect from LDAP Server
    closeLdapClientConnection(connection)

    # Disconnect from ESM
    logout(url, session)

    # Create Excel Spreadsheet containing all AD/LDAP users from Specified Group
    if args.write_ad_users:
        createUserWrkbk(file_path, 'Active Directory', ad_users)

    # Create Excel Spreadsheet containing all ESM users from Specified Group
    if args.write_esm_users:
        createUserWrkbk(file_path, 'McAfee ESM', esm_users)

    # Create Excel Spreadsheet containing aonly those Users that exist in the ESM Group
    if args.write_esmonly:
        createUserWrkbk(file_path, 'ESM Only', esm_users_notinAD)
    # Create Excel Spreadsheet containing only those Users that exist in the AD/LDAP Group
    if args.write_adonly:
        createUserWrkbk(file_path, 'AD Only', ad_users_notinESM)
    # Create Excel Spreadsheet containing all User Lists
    if args.write_all:
        createCombinedWrkbk(file_path, esm_users, ad_users, esm_users_notinAD, ad_users_notinESM)

if __name__ == "__main__":
    main()
