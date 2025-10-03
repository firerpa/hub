#!/usr/bin/env python3
import time
import sqlite3
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("-n", "--name", type=str,
                        help="username", required=True)
parser.add_argument("-p", "--password", type=str,
                        help="password", required=True)
parser.add_argument("-c", "--contact", type=str,
                        help="contact", required=True)
parser.add_argument("--admin", dest="admin",
                        action="store_true")
args = parser.parse_args()

db = sqlite3.connect("/user/database.db")

cursor = db.cursor()
meta = (args.name, args.contact, args.password,
        time.time(), 0, args.password,
        int(args.admin))

cursor.execute("INSERT INTO `user` ("
                                        "name,"
                                        "contact,"
                                        "password,"
                                        "reg_time,"
                                        "login_time,"
                                        "token,"
                                        "admin)"
"VALUES (?, ?, ?, ?, ?, ?, ?)", meta)
db.commit()
db.close()