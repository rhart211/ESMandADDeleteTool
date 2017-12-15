#!/usr/bin/env python

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
#In a devtest environment, self-signed certs are regularly used.
#Let's disable the warning when over-riding.
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def build_url(esm):
    url_base = 'https://' + esm + '/rs/esm/'
    return url_base

def get_AD_password(ad_user):
    ad_password = getpass.getpass('Enter password for your domain username %s' %user)
    return ad_password

def get_ESM_password(esm_user):
    esm_password = getpass.getpass('Enter password for your ESM username %s: ' %user)
    return esm_password

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

def getLdapClientConnection(ad_server, adUser_dn, ad_password):
    try:
        server = Server(ad_server, port=389, use_ssl=False)
        connection = Connection(server, auto_bind=True, version=3, authentication="SIMPLE", user=adUser_dn, password=ad_password)
        return connection
    except:
        print("Failed to establish LDAP connection.")

def logout(url_base, session_header):
    requests.delete(url_base + 'logout', headers=session_header, verify=False)

def closeLdapClientConnection(connection):
    connection.unbind()

def esmUserList(url_base, session_header, password):
    params = {"authPW": {"value": password}}
    params_json = json.dumps(params)
    response = requests.post(url_base + 'userGetUserList', data=params_json, headers=session_header, verify=False)
    data = response.json()
    return data

def getGroupID(url_base, session_header, password, groupname):
    params = {"authPW": {"value": password}}
    params_json = json.dumps(params)
    response = requests.post(url_base + 'userGetAccessGroupList?restrictToUsersGroup=false', data=params_json, headers = session_header, verify = False)
    data = response.json()
    for item in data.get('return'):
        if groupname == item.get('name'):
            groupID = item.get('id').get('value')
            return groupID

def listUsernamesinGroup(esmUsers, groupID):
    results = []
    data = esmUsers
    for item in data.get('return'):
        for group in item.get('groups'):
            if group.get('value') == groupID:
                pattern = re.search('[a-zA-Z0-9\x2e]+(.*)', item.get('username')).group(1)
                results.append(item.get('username').replace(pattern, '').lower())
    return results

def listESMUsers(esmUsers):
    results = []
    for item in esmUsers.get('return'):
        pattern = re.search('[a-zA-Z0-9\x2e]+(.*)', item.get('username')).group(1
        results.append(item.get('username').replace(pattern, '').lower())
    return results

def getUserID(esmUsers, user):
    for item in esmUsers.get('return'):
        if user in item.get('username'):
            user_id = item.get('id').get('value')
    return user_id

def getUserConfig(esmUsers, user):
    for item in esmUsers.get('return'):
        if user in item.get('username'):
            return item

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

def listDisabledUsersinGroup(connection, ad_users):
    # User account Control Values for any type of Disabled aD User
    # -------------------------------------------------------------
    # Disabled account, 514
    # Disabled, Password Not Required, 546
    # Disabled, Password Doesnt Expire, 66050
    # Disabled, Password Doesnt Expire & Not Required, 66082
    # Disabled, Smartcard Required, 262658
    # Disabled, Smartcard Required, Password Not Required, 262690
    # Disabled, Smartcard Required, Password Doesnt Expire, 328194
    # Disabled, Smartcard Required, Password Doesnt Expire & Not Required, 328226

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

def esmUsersNotinAD(esm_users, ad_users):
    defaultEsm_users = set(['ngcp', 'policy', 'report'])
    dupes = set(esm_users).intersection(ad_users)
    diffs = set(esm_users) - set(dupes)
    diff_users = list(set(diffs) - defaultEsm_users)
    return diff_users

def build_script_constants(conn, ad_group, url_base, session_header, esm_password, esm_group):
    ad_users_in_group = listAllUsersinGroup(conn, ad_group)
    esmUsers = esmUserList(url_base, session_header, esm_password)
    groupID = getGroupID(url_base, session_header, esm_password, esm_group)
    return ad_users_in_group, esmUsers, groupID

def createUserWrkbk(user_type, userlist):
    if len(userlist) != 0:
        workbook = xlsxwriter.Workbook(user_type+'_Users.xlsx')
        worksheet = workbook.add_worksheet()
        format = workbook.add_format({'bold': True, 'align' : 'center'})
        format.set_bg_color('#90EE90')
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
    else:
        if user_type == 'ESM Only':
            print "There are no ESM Only Users"
        else:
            print "User List is empty"

def createCombinedWrkbk(esm_users, ad_users, esmonly):
    workbook = xlsxwriter.Workbook('All_Users.xlsx')
    worksheet = workbook.add_worksheet()
    format = workbook.add_format({'bold': True, 'align': 'center'})
    format.set_bg_color('#90EE90')
    format.set_border(1)
    user_fmt = workbook.add_format({'align': 'left', 'border': 1})
    user_fmt.set_text_wrap()
    worksheet.write('A1', 'ESM Users', format)
    worksheet.write('B1', 'AD Users', format)
    worksheet.write('C1', 'ESM Only Users', format)
    worksheet.set_column(0, 0, 20)
    worksheet.set_column(1, 1, 20)
    worksheet.set_column(2, 2, 20)
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
    workbook.close()
    print "Created Spreadsheet"

def main():
    parser = argparse.ArgumentParser(description='McAfee ESM and Active Directory Clean up Tool. The main purpose of this tool is to delete Users that exist in ESM but not in Active Directory. A secondary function exists where an ESM account can be disabled, if it is disabled in Active Directory.')

    # AD parameters
    ad_group = parser.add_argument_group("AD options")
    ad_group.add_argument("-a", "--ad_server", type=str, metavar='AD SERVER',
                          help="Active Directory Server Hostname/ip", required=True)
    ad_group.add_argument("-d", "--ad_user", type=str, metavar='AD USERNAME',
                          help="DOMAIN\\username for authentication", required=True)
    ad_group.add_argument("-n", "--ad_password", type=str, metavar='AD PASSWORD', help="Domain User Password",
                          required=True)
    ad_group.add_argument("-b", "--ad_group", type=str, metavar='AD GROUP BASEDN', help="AD Group Search Base DN, in a format similar to CN=Group,OU=Groups,DC=Example,DC=Com",
                          required=True)
    # ESM Parameters
    esm_group = parser.add_argument_group("SIEM Options")
    esm_group.add_argument("-e", "--esm", type=str, metavar='ESM HOSTNAME', help="ESM Hostname/ip", required=True)
    esm_group.add_argument("-u", "--esm_user", type=str, metavar='ESM User', help='ESM Username for authentication',
                           required=True)
    esm_group.add_argument("-p", '--esm_password', type=str, metavar='ESM Password', help='ESM User Password',
                           required=True)
    esm_group.add_argument("-g", "--esm_group", type=str, metavar='ESM GROUP', help="ESM Group Name", required=True)

    #Actions
    action_group = parser.add_mutually_exclusive_group()
    action_group.add_argument("-r", "--delete", action='store_true', help="Delete Users that exist in ESM but not in Active Directory")
    action_group.add_argument("-s", "--disable", action='store_true', help="Disable ESM Accounts that are disabled in Active Directory")

    # Output parameters
    outputgroup = parser.add_argument_group("Output options")
    outputgroup.add_argument("-o", "--outdir", type=str, metavar='DIRECTORY',
                             help="Directory in which the dump will be saved (default: current)")
    outputgroup.add_argument("--write_ad_users", action='store_true', help="Create a spreadsheet containing only users in the AD Group")
    outputgroup.add_argument("--write_esm_users", action='store_true', help="Create a spreadsheet containing only users in the ESM Group")
    outputgroup.add_argument("--write_esmonly", action='store_true', help="Create a spreadsheet containing only users that exist in the ESM, but not in AD Group")
    outputgroup.add_argument("--write_all", action='store_true', help='Create a spreadsheet containing AD Users, ESM Users, and ESM Only Users')

    args = parser.parse_args()

    if not '\\' in arg.ad_user:
        print 'Username must include a domain, use: DOMAIN\\username'
        sys.exit(1)
    if args.ad_password is None:
        args.ad_password = get_AD_password(args.ad_user)
    if args.esm_password is None:
        args.esm_password = get_ESM_password(args.esm_user)

    connection = getLdapClientConnection(args.ad_server, args.ad_user, args.ad_password)

    if not connection.bind():
        print "Could not bind to AD Server: %s with the specified credentials" %args.ad_server
        sys.exit(1)

    url = build_url(args.esm)
    session = login(url, args.esm_user, args.esm_password)
    ad_users_in_group, esmUsers, groupID = build_script_constants(connection, args.ad_group, url, session, args.esm_password, args.esm_group)

    ad_users = getSamAccountNames(connection, ad_users_in_group)
    esm_users = listUsernamesinGroup(esmUsers, groupID)
    esm_users_notinAD = esmUsersNotinAD(ad_users, esm_users)

    if args.delete:
        for user in esm_users_notinAD:
            deleteUser(url, session, args.esm_password, esmUsers, user)
        createUserWrkbk("Deleted ESM", esm_users_notinAD)

    if args.disable:
        disabled_esm_users = []
        for user in listDisabledUsersinGroup(connection, ad_users):
            all_esm_users = listESMUsers(esmUsers)
            if user in all_esm_users:
                disableEsmUser(url, session, args.esm_password, esmUsers, user)
                disabled_esm_users.append(user)
        createUserWrkbk('Disabled ESM', disabled_esm_users)

    closeLdapClientConnection(connection)
    logout(url, session)

    if args.write_ad_users:
        createUserWrkbk('Active Direcotry', ad_users)
    if args.write_esm_users:
        createUserWrkbk('McAfee ESM', esm_users)
    if args.write_esmonly:
        createUserWrkbk('ESM Only', esm_users_notinAD)
    if args.write_all:
        createCombinedWrkbk(esm_users, ad_users, esm_users_notinAD)


if __name__ == "__main__":
    main()
