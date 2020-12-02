#!/usr/bin/env python
'''tinyencrypt-testing.py'''
# minimal encryption in python for low memory micro-controller
# rotation substitution cipher
# rotate among common password characters only
# only encrypt the passwords

# to do:
# hide the length of the password with padding


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
'''
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

#a=[]
#a.append(sym[3:16])
#a.append(lo[0:13])
#a.append(lo[13:])
#a.append(up[0:13])
#a.append(up[13:])
#a.append(num + sym[0:3])
##a.append(sym[3:16])
#a.append(sym[16:])

#alternate order
a=[]
a.append(sym[3:16])
a.append(lo[0:13])
a.append(up[0:13])
a.append(num + sym[0:3])
a.append(sym[16:])
a.append(lo[13:])
a.append(up[13:])

#for x in a:
#    print(x,len(x))
#print("".join(a))

for x in range(0,13):
    for y in range(0,7):
        print(a[y][x],end="")
print("")
'''
'''# end of code to create char set'''


# planned: lower, upper, numbers, symbols evenly spread
# all printable ascii chars, plus space, except double quote, tab, backslash
#mychars="anZM0<!boYL1>@cpXK2;#dqWJ3:$erVI4'%fsUH5[^gtTG6]&huSF7{*ivRE8}(jwQD9-)kxPC,=`lyOB._~mzNA/+ "
# put least likely char in the zero position
# the code above to create the character set can be replaced with this one line:
#mychars="`anZM0+<boYL1!>cpXK2@;dqWJ3#:erVI4$'fsUH5%[gtTG6^]huSF7&{ivRE8*}jwQD9(-kxPC,)=lyOB.~_mzNA/ "
# more distributed:
mychars="`aZ0+nM<bY1!oL>cX2@pK;dW3#qJ:eV4$rI'fU5%sH[gT6^tG]hS7&uF{iR8*vE}jQ9(wD-kP,)xC=lO.~yB_mN/ zA"
# simplified for testing:
#mychars="abcdefghijklmnopqrstuvwxyzZYXWVUTSRQPONMLKJIHGFEDCBA0123456789,./<>;:'[]{}-=_+!@#$%^&*()`~ "
mylen=len(mychars)
#print("mychars=",mychars)
#print("mylen=",mylen)

textlen=len(text)
keylen=len(key)
print("text=",text)
print("key=",key)
#print("textlen=",textlen)
#print("keylen=",keylen)

def code2indexlist(key):
    # turn key in to list of indexes
    keyi=[]
    for k in range(len(key)):
        keyi.append(mychars.index(key[k]))
        #print(k,keyi[k])
    return keyi

# direction values
ENCRYPT=+1
DECRYPT=-1

def crypt(inchar,keyoffset,direction):
    try:
        charindex=mychars.index(inchar)
        encind=(charindex+direction*keyoffset)%mylen
        outchar=mychars[encind]
    except ValueError:
        print("invalid character used?")
        outchar="invalid"
    return outchar

def tinyencrypt(text,keyi):
    try:
        textlen=len(text)
        keylen=len(key)
        totlen=textlen + keylen
        eachchar=mychars[totlen]
        keyoffset=keyi[0]
        #print("textlen=",textlen,"keylen=",keylen,"total=",totlen,"lencode=", eachchar)
        # use lencode as first char of text to encrypt
        code=crypt(eachchar,keyoffset,ENCRYPT)
        keyindex=1%keylen   # allow 1 char key
        #print("keyindex=",0, "keychar=",key[0], "charindex=",mychars.index(key[0]),"lenchar=",eachchar,"charindex=",totlen, "encind=",(mychars.index(eachchar)+keyoffset)%mylen, "encrypted=",code)
        for eachchar in text:
            keyoffset=keyi[keyindex]
            codeletter=crypt(eachchar,keyoffset,ENCRYPT)
            code += codeletter
            #print(keyindex, key[keyindex], eachindex, eachchar, codeletter)
            #print("keyindex=",keyindex, "keychar=",key[keyindex], "charindex=",keyoffset,"textchar=",eachchar,"charindex=",mychars.index(eachchar),"encind=",(mychars.index(eachchar)+keyoffset)%mylen, "encrypted=",codeletter)
            keyindex = (keyindex+1) % keylen
    except ValueError:
        print("invalid character used?")
        code="invalid"
    return code

def tinydecrypt(code,keyi):
    try:
        codelen=len(code)
        keylen=len(key)
        #print("codelen=",codelen,"keylen=",keylen,"key0i=",mychars.index(code[0]))
        eachchar=code[0]
        keyoffset=keyi[0]
        lencode=crypt(eachchar,keyoffset,DECRYPT)
        totlen=mychars.index(lencode)
        encind=mychars.index(code[0])
        textlen=(totlen-keylen+mylen)%mylen
        #print("keyindex=",0, "keychar=",key[0], "charindex=",keyi[0],"encrypted=",eachchar,"charindex=",mychars.index(eachchar),"unencind=",totlen, "lencode=",lencode)
        #print("keylen=",keylen,"textlen=",textlen)
        plain=""
        keyindex=1%keylen   # allow 1 char key
        for eachchar in code[1:]:
            keyoffset=keyi[keyindex]
            plainletter=crypt(eachchar,keyoffset,DECRYPT)
            plain+=plainletter
            #print("keyindex=",keyindex, "keychar=",key[keyindex], "charindex=",keyoffset,"codechar=",eachchar,"codeindex=",mychars.index(eachchar),"unencind=",(mychars.index(eachchar)-keyoffset+mylen)%mylen, "unencrypted=",plainletter)
            keyindex = (keyindex+1) % keylen
    except ValueError:
        print("invalid character used?")
        plain="invalid"
    return plain

keyi = code2indexlist(key)
code=tinyencrypt(text,keyi)

#print("codelen=",len(code)
print("code=",code)
plain=tinydecrypt(code,keyi)
print("decrypted=",plain)
