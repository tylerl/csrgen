import zlib
import base64
import sys
import pprint

def packfile(filename):
    with open(filename,"r") as f:
        content = f.read()
        return base64.b64encode(zlib.compress(content,9))

def chunk(data,width):
    return (data[n:n+width] for n in range(0,len(data),width))

def main(args):
    w = 70
    for arg in args:
        print arg
        out = packfile(arg)
        for d in chunk(out,70):
            print '  ' + d

if __name__ == '__main__':
    main(sys.argv[1:])