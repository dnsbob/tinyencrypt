#!/usr/bin/env python
'''tinyencrypt-testing.py'''
# minimal encryption in python for low memory micro-controller
# rotation substitution cipher
# rotate among common password characters only
# only encrypt the passwords

# to be python2/3 compatible:
from __future__ import print_function
from __future__ import unicode_literals

import random
import argparse

# all printable ascii chars, plus space, except double quote, tab, backslash
mychars="`aZ0+nM<bY1!oL>cX2@pK;dW3#qJ:eV4$rI'fU5%sH[gT6^tG]hS7&uF{iR8*vE}jQ9(wD-kP,)xC=lO.~yB_mN/ zA"
mylen=len(mychars)
# direction values
ENCRYPT=+1
DECRYPT=-1

def code2indexlist(key):
    # turn key into list of indexes
    keyi=[]
    for k in range(len(key)):
        keyi.append(mychars.index(key[k]))
    return keyi

def cryptchar(inchar,keyoffset,direction):
    try:
        charindex=mychars.index(inchar)
        encind=(charindex+direction*keyoffset)%mylen
        outchar=mychars[encind]
    except ValueError:
        print("invalid character used?")
        outchar="invalid"
    return outchar

def cryptstring(instring,keyi,direction):
    outstring=""
    keylen=len(keyi)
    keyindex=1%keylen   # allow 1 char key (even if not recommended)
    for eachchar in instring:
        keyoffset=keyi[keyindex]
        outletter=cryptchar(eachchar,keyoffset,direction)
        outstring+=outletter
        keyindex = (keyindex+1) % keylen
    return outstring

def tinyencrypt(text,key):
    try:
        keyi = code2indexlist(key)
        textlen=len(text)
        keylen=len(keyi)
        totlen=textlen + keylen
        if totlen > mylen:
            print("error - string too long, limited to",mylen,"character")
            return "invalid"
        eachchar=mychars[totlen]
        keyoffset=keyi[0]
        # use lencode as first char of text to encrypt
        code=cryptchar(eachchar,keyoffset,ENCRYPT)
        keyindex=1%keylen   # allow 1 char key
        code2=cryptstring(text,keyi,ENCRYPT)
        code += code2
        # pad to nearest block size
        blocksize=20
        blocks=int(textlen/blocksize)+1
        padding=blocks*blocksize-textlen
        for x in range(padding):
            code+=mychars[random.randrange(mylen)]
    except ValueError:
        print("invalid character used?")
        code="invalid"
    return code

def tinydecrypt(code,key):
    try:
        keyi = code2indexlist(key)
        codelen=len(code)
        keylen=len(keyi)
        eachchar=code[0]
        keyoffset=keyi[0]
        lencode=cryptchar(eachchar,keyoffset,DECRYPT)
        totlen=mychars.index(lencode)
        encind=mychars.index(code[0])
        textlen=(totlen-keylen+mylen)%mylen
        plain=cryptstring(code[1:textlen+1],keyi,DECRYPT)
    except ValueError:
        print("invalid character used?")
        plain="invalid"
    return plain

def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("key")
    parser.add_argument("text")
    args = parser.parse_args()

    key=args.key
    text=args.text
    print("text=",text)
    print("key=",key)

    code=tinyencrypt(text,key)

    #print("codelen=",len(code)
    print("code=",code)
    plain=tinydecrypt(code,key)
    print("decrypted=",plain)

if __name__ == "__main__":
    main()
