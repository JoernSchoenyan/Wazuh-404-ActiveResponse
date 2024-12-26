#!/usr/bin/python3
# Copyright (C) 2015-2022, Wazuh Inc.
# All rights reserved.

# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

import os, subprocess, sys, json, datetime, sqlite3
from pathlib import PureWindowsPath, PurePosixPath

if os.name == 'nt':
    LOG_FILE = "C:\\Program Files (x86)\\ossec-agent\\active-response\\active-responses.log"
else:
    LOG_FILE = "/var/ossec/logs/active-responses.log"

DB_FILE = '/var/ossec/etc/suspicious_paths.db'

ADD_COMMAND = 0
DELETE_COMMAND = 1
CONTINUE_COMMAND = 2
ABORT_COMMAND = 3

OS_SUCCESS = 0
OS_INVALID = -1

class message:
    def __init__(self):
        self.alert = ""
        self.command = 0

def connect_to_db():
    """Connect to SQLite database or create it if it doesn't exist."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS suspicious_paths (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            path TEXT UNIQUE
        )
    ''')
    conn.commit()
    return conn


def write_debug_file(msg):
    ar_name = sys.argv[0]

    with open(LOG_FILE, mode="a") as log_file:
        ar_name_posix = str(PurePosixPath(PureWindowsPath(ar_name[ar_name.find("active-response"):])))
        log_file.write(str(datetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S')) + " " + ar_name_posix + ": " + msg +"\n")


def setup_and_check_message(argv):

    # get alert from stdin
    input_str = ""
    for line in sys.stdin:
        input_str = line
        break

    write_debug_file(input_str)

    try:
        data = json.loads(input_str)
    except ValueError:
        write_debug_file('Decoding JSON has failed, invalid input format')
        message.command = OS_INVALID
        return message

    message.alert = data

    command = data.get("command")

    if command == "add":
        message.command = ADD_COMMAND
    elif command == "delete":
        message.command = DELETE_COMMAND
    else:
        message.command = OS_INVALID
        write_debug_file('Not valid command: ' + command)

    return message


def send_keys_and_check_message(argv, keys):
    # build and send message with keys
    keys_msg = json.dumps({"version": 1,"origin":{"name": argv[0],"module":"active-response"},"command":"check_keys","parameters":{"keys":keys}})

    write_debug_file(keys_msg)
    print(keys_msg)
    sys.stdout.flush()

    # read the response of previous message
    input_str = ""
    while True:
        line = sys.stdin.readline()
        if line:
            input_str = line
            break

    write_debug_file(input_str)

    try:
        data = json.loads(input_str)
    except ValueError:
        write_debug_file('Decoding JSON has failed, invalid input format')
        return message

    action = data.get("command")

    if "continue" == action:
        ret = CONTINUE_COMMAND
    elif "abort" == action:
        ret = ABORT_COMMAND
    else:
        ret = OS_INVALID
        write_debug_file("Invalid value of 'command'")

    return ret

def block_ip(ip):
    """Block the given IP using iptables."""
    try:
        subprocess.run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        return True
    except subprocess.CalledProcessError as e:
        write_debug_file(f"Failed to block IP {ip}: {e}")
        return False
    
def unblock_ip(ip):
    """Block the given IP using iptables."""
    try:
        subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        return True
    except subprocess.CalledProcessError as e:
        write_debug_file(f"Failed to block IP {ip}: {e}")
        return False


def is_path_suspicious(conn, path):
    """Check if the given path is in the suspicious_paths database."""
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM suspicious_paths WHERE path = ?", (path,))
    return cursor.fetchone() is not None


def main(argv):
    conn = connect_to_db()

    write_debug_file("Started")

    # validate json and get command
    msg = setup_and_check_message(argv)

    if msg.command < 0:
        sys.exit(OS_INVALID)

    if msg.command == ADD_COMMAND:

        """ Start Custom Key
        At this point, it is necessary to select the keys from the alert and add them into the keys array.
        """

        alert = msg.alert["parameters"]["alert"]
        keys = [alert["rule"]["id"]]

        """ End Custom Key """

        action = send_keys_and_check_message(argv, keys)

        # if necessary, abort execution
        if action != CONTINUE_COMMAND:

            if action == ABORT_COMMAND:
                write_debug_file("Aborted")
                sys.exit(OS_SUCCESS)
            else:
                write_debug_file("Invalid command")
                sys.exit(OS_INVALID)

        if is_path_suspicious(conn, msg.alert["parameters"]["alert"]["data"]["url"]):
            block_ip(msg.alert["parameters"]["alert"]["data"]["srcip"])

    elif msg.command == DELETE_COMMAND:
        unblock_ip(msg.alert["parameters"]["alert"]["data"]["srcip"])

    else:
        write_debug_file("Invalid command")

    write_debug_file("Ended")

    sys.exit(OS_SUCCESS)


if __name__ == "__main__":
    main(sys.argv)