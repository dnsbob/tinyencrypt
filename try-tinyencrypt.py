#!/usr/bin/env python

import tinyencrypt

code=tinyencrypt.tinyencrypt("hello-world","secret")
print(code)
plain=tinyencrypt.tinydecrypt(code,"secret")
print(plain)
