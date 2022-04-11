#!/usr/bin/env python3

import sys, string, struct

def strByByte(_strval):
    strval = bytearray(_strval.encode())
    for s in strval: yield s

def strByDword(_strval):
    strval = bytearray(_strval.encode())
    numDwords = int(len(strval) / 4)
    remainder = len(strval) - (numDwords*4)

    for x in range(numDwords):
        yield struct.unpack_from("<L", strval, 4*x)[0]
    if remainder != 0:
        remainderVals = strval[4*numDwords:]
        remainderVals.extend(bytearray([0]*(4-remainder)))
        yield struct.unpack("<L", remainderVals)[0]

        
def hexlify(v): return '{:x}'.format(v)
def strToHex(strval): return ''.join(list(map(lambda k: '{:02x}'.format(ord(k)), strval)))
def bufToHex(bval): return ''.join(list(map(lambda k: '{:02x}'.format(k), bval)))


    
def doPrototype(proto, _strval):
    strval = bytearray(_strval.encode())
    v = []
    for s in strval: v.append(proto.format(s))
    return ' '.join(v)

def generateSmallStack(strval):
    return '   $smallStack = {' + doPrototype('c645??{:02x}', strval) +'}'

def generateLargeStack(strval):
    return '   $largeStack = {' + doPrototype('c7(45|85)[1-4]{:02x}000000', strval) + '}'

def generateRegister(strval):
    return '   $register = {'+ doPrototype('b?{:02x}000000 6689????', strval) + '}'

def generateDword(_strval):
    strval = bytearray(_strval.encode())
    numDwords = int(len(strval)/4)
    remainder = len(strval) - (numDwords*4)

    values = []
    for x in range(numDwords):
        nextd = struct.unpack_from("<L", strval, 4*x)[0]
        values.append('c7(45|85)[1-4]{:08x}'.format(nextd))
    if remainder > 0:
        if remainder == 3:
            firstv, secondv = struct.unpack("<HB", strval[-remainder:])
            print(firstv, secondv,file=sys.stderr)
            values.append('[0-1]c7(45|85)[1-4]{:04x}'.format(firstv))
            values.append('[0-1]c6(45|85)[1-4]{:02x}'.format(secondv))
        elif remainder == 2:
            firstv = struct.unpack("<H", strval[-remainder:])[0]
            values.append('[0-1]c7(45|85)[1-4]{:04x}'.format(firstv))
        elif remainder == 1:
            values.append('[0-1]c6(45|85)[1-4]{:02x}'.format(strval[-1]))
    
    return '   $dword = {'+(' '.join(values))+ '}'

def generatePushPop(strval):
    return ('   $pushpop = {'+
            doPrototype('6a{:02x}5? ', strval[0]) +
            doPrototype('6a{:02x} 6689????5?', strval[1:-1]) + '}')
            
def generateCallOverString(strval):
    return ('   $callOverString = {e8'+
            bufToHex(struct.pack("<L", len(strval))) +
            strToHex(strval) + '5? }')

def fixName(strval):
    result = []
    valid = string.ascii_letters + string.digits + '_'
    for s in strval:
        result.append('_' if s not in valid else s)
    return ''.join(result)



def generate(strval):
    nl = '\n'
    clauses = []
    clauses.append("rule stackstring_{}".format(fixName(strval)))
    clauses.append("{")
    clauses.append("  strings:")
    
    clauses.append(generateSmallStack(strval)+nl)
    clauses.append(generateLargeStack(strval)+nl)
    clauses.append(generateRegister(strval)+nl)
    clauses.append(generateDword(strval)+nl)
    clauses.append(generatePushPop(strval)+nl)
    clauses.append(generateCallOverString(strval)+nl)
    
    clauses.append("  condition:")
    clauses.append("    any of them")
    clauses.append("}")
    
    print(nl.join(clauses)+nl+nl)
    
for strval in sys.argv[1:]:

    generate(strval)
    
