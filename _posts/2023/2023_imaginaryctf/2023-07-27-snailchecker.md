---
title: 2023 ImaginaryCTF - snailchecker
date: 2023-07-23 00:00:00 +0700
categories:
  - Write-ups
tags:
  - 2023_imaginaryCTF
  - Reverse Engineering
---

## Overview

* Points: 100

## Description

> Optimize me, if you dare. Or not. It might run if you try hard enough.

### Attached

[snailchecker.py](https://github.com/encuetee/CTF-writeups/blob/main/2023/2023_imaginaryctf/attached/snailchecker.py)

## Solution

By [allforest01](https://github.com/allforest01)

```python
def josephus(n):
    return 2 * (n - 2 ** (n.bit_length() - 1)) + 1

def enc1(b):
    n = b[0] * 2 ** 24 + b[1] * 2 ** 16 + b[2] * 2 ** 8 + b[3]
    return josephus(n) - 1

def enc2(n):
    return bytes.fromhex(hex(enc1(n[::-1]))[2:].zfill(8))

charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/_{}'
table = dict()
cnt = 0
for i in charset:
    for j in charset:
        for k in charset:
            for l in charset:
                s = (i + j + k + l).encode()
                table[enc2(s)] = s
    cnt += 1
    print(cnt / len(charset) * 100)

flag = b'L\xe8\xc6\xd2f\xde\xd4\xf6j\xd0\xe0\xcad\xe0\xbe\xe6J\xd8\xc4\xde`\xe6\xbe\xda>\xc8\xca\xca^\xde\xde\xc4^\xde\xde\xdez\xe8\xe6\xde'
out = b''
for n in [flag[i:i+4] for i in range(0,len(flag),4)]:
  out += table[n]
print(out)
```

The flag is
```
ictf{josephus_problem_speed_boooooooost}
```