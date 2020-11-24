#!/usr/bin/env python
'''tinyencrypt-testing.py'''
# minimal encryption in python for low memory micro-controller
# rotation substitution cipher
# rotate among common password characters only
# only encrypt the passwords

# to do:
# hide the length of the password with padding
# combine duplicate code


# to be python2/3 compatible:
from __future__ import print_function
from __future__ import unicode_literals

import argparse
parser = argparse.ArgumentParser()
parser.add_argument("key")
parser.add_argument("text")
args = parser.parse_args()

#text="Hello World!"
#key="Secret.1"
#key="abcd" # for testing

key=args.key
text=args.text

'''code to create the character set below'''
lo="abcdefghijklmnopqrstuvwxyz"
up="ZYXWVUTSRQPONMLKJIHGFEDCBA"
num="0123456789"
#sym=",./<>;:'[]{}-=_+!@#$%^&*()`~ "
# rotate to put least likely char in fourth place
# which will become the first char, zero code rotation
sym=",./`<>;:'[]{}-=_+!@#$%^&*()~ "
# no double quote
# no tab, no backslash, no control characters
#for x in ( lo,up,num,sym):
#  print(x,len(x))

a=[]
a.append(sym[3:16])
a.append(lo[0:13])
a.append(lo[13:])
a.append(up[0:13])
a.append(up[13:])
a.append(num + sym[0:3])
#a.append(sym[3:16])
a.append(sym[16:])
#for x in a:
#    print(x,len(x))
#print("".join(a))

for x in range(0,13):
    for y in range(0,7):
        print(a[y][x],end="")
print("")
# end of code to create char set


# planned: lower, upper, numbers, symbols evenly spread
# all printable ascii chars, plus space, except double quote, tab, backslash
#mychars="anZM0<!boYL1>@cpXK2;#dqWJ3:$erVI4'%fsUH5[^gtTG6]&huSF7{*ivRE8}(jwQD9-)kxPC,=`lyOB._~mzNA/+ "
# put least likely char in the zero position
# the code above to create the character set can be replaced with this one line:
mychars="`anZM0+<boYL1!>cpXK2@;dqWJ3#:erVI4$'fsUH5%[gtTG6^]huSF7&{ivRE8*}jwQD9(-kxPC,)=lyOB.~_mzNA/ "
# simplified for testing:
#mychars="abcdefghijklmnopqrstuvwxyzZYXWVUTSRQPONMLKJIHGFEDCBA0123456789,./<>;:'[]{}-=_+!@#$%^&*()`~ "
mylen=len(mychars)
print("mychars=",mychars)
print("mylen=",mylen)

textlen=len(text)
keylen=len(key)
print("text=",text)
print("key=",key)
print("textlen=",textlen)
print("keylen=",keylen)

def code2indexlist(key):
    # turn key in to list of indexes
    keyi=[]
    for k in range(len(key)):
        keyi.append(mychars.index(key[k]))
        #print(k,keyi[k])
    return keyi

def tinyencrypt(text,keyi):
    try:
        textlen=len(text)
        keylen=len(key)
        totlen=textlen + keylen
        lencode=mychars[totlen]
        print("textlen=",textlen,"keylen=",keylen,"total=",totlen,"lencode=", lencode)
        #sprint(textlen, keylen, lencode)
        # use lencode as first char of text to encrypt
        encind=(mychars.index(lencode)+mychars.index(key[0]))%mylen
        r=mychars[encind]
        keyindex=1%keylen   # allow 1 char key
        print("keyindex=",0, "keychar=",key[0], "charindex=",mychars.index(key[0]),"lenchar=",lencode,"charindex=",totlen, "encind=",encind, "encrypted=",r)
        for eachchar in text:
            eachindex=mychars.index(eachchar)
            #print(keyindex, key[keyindex], eachindex, eachchar)
            #r += mychars[(mychars.index(eachchar)+mychars.index(keychar))%mylen]
            encind=(mychars.index(eachchar)+keyi[keyindex])%mylen
            nextr = mychars[encind]
            r += nextr
            #print(keyindex, key[keyindex], eachindex, eachchar, nextr)
            print("keyindex=",keyindex, "keychar=",key[keyindex], "charindex=",keyi[keyindex],"textchar=",eachchar,"charindex=",eachindex,"encind=",encind, "encrypted=",nextr)
            keyindex = (keyindex+1) % keylen
    except ValueError:
        print("invalid character used?")
        r="invalid"
    return r

def mydecrypt(code,keyi):
    try:
        codelen=len(code)
        keylen=len(key)
        lenchar=code[0]
        key0i=mychars.index(lenchar)
        print("codelen=",codelen,"keylen=",keylen,"key0i=",key0i)
        encind=mychars.index(code[0])
        totlen=(encind-keyi[0]+mylen)%mylen
        textlen=(totlen-keylen+mylen)%mylen
        lencode=mychars[totlen]
        print("keyindex=",0, "keychar=",key[0], "charindex=",keyi[0],"encrypted=",lenchar,"charindex=",key0i,"unencind=",totlen, "lencode=",lencode)
        print("keylen=",keylen,"textlen=",textlen)
        r=""
        keyindex=1%keylen   # allow 1 char key
        for eachchar in code[1:]:
            eachindex=mychars.index(eachchar)
            unencind=(mychars.index(eachchar)-keyi[keyindex]+mylen)%mylen
            nextr = mychars[unencind]
            r+=nextr
            print("keyindex=",keyindex, "keychar=",key[keyindex], "charindex=",keyi[keyindex],"codechar=",eachchar,"codeindex=",eachindex,"unencind=",unencind, "unencrypted=",nextr)
            keyindex = (keyindex+1) % keylen
    except ValueError:
        print("invalid character used?")
        r="invalid"
    return r

keyi = code2indexlist(key)
r=tinyencrypt(text,keyi)

print("codelen=",len(r), "code=",r)
u=mydecrypt(r,keyi)
print("decrypted=",u)
