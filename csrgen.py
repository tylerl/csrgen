#!/usr/bin/python
from wsgiref import simple_server
import os
import subprocess
import sys
import re
import mimetypes
import cgi
import traceback
import json
import zlib
import base64
import optparse

OPENSSL_PATH="openssl"  #rely on $PATH by default
STATIC_DIR=None

###############################################################
# First our extremely simplistic webapp framework

class Response(object):
    def __init__(self,code,headers,content,status=None):
        if status == None:
            status = {200:'OK',404:'Not Found'}.get(code,'Error')
        self.code = code
        self.headers = headers
        self.status = status
        self.content = content
        if isinstance(self,str):
            self.content = [content]

class Request(object):
    def __init__(self,environ):
        self.environ = environ
        self.path = environ['PATH_INFO']
        self.args = []
        self.code = None  # used for error handlers
        self.exception = None  # used for error handlers
        self.fields = {}
        self.method = environ['REQUEST_METHOD']
        self._out_headers = []
        if self.method == 'POST':
            fs = cgi.FieldStorage(fp=environ['wsgi.input'], environ=environ)
        else:
            fs = cgi.FieldStorage(environ=environ)
        for key in fs:
            self.fields[key] = fs[key].value

class HTTP(Exception):
    def __init__(self,code,message=None):
        Exception.__init__(self,"HTTP %i" % (code))
        self.code = code
        self.message=message


class App(object):
    def __init__(self):
        self.routes = []
        self.handlers={}

    def route(self,name, methods=None):
        def wrapper(fn):
            self.routes.append((name,fn))
            fn._methods = methods
            return fn
        return wrapper

    def handler(self,code):
        def wrapper(fn):
            self.handlers[code]=fn
            return fn
        return wrapper

    def __call__(self,environ,start_response):
        return self.app_handler(environ,start_response)

    def run(self,fn,request):
        try:
            return fn(request)
        except HTTP as e:
            return self.handle_error(request,e.code,e.message)
        except Exception as e:
            request.traceback = traceback.format_exc()
            return self.handle_error(request,500)

    def handle_error(self,request,code,message=None):
        request.code = code
        if code in self.handlers:
            return self.handlers[code](request,message=message)
        headers = [('Content-type', 'text/html')]
        headers.extend(request._out_headers)
        if not message:
            message = "<h1>Error %i</h1><p>Unable to process request" % (code)
        return Response(code, headers,[message])


    def request_handler(self,request):
        methods_allowed = []
        for pattern,fn in self.routes:
            match = re.match(pattern,request.path)
            if match:
                if fn._methods and request.method not in fn._methods:
                    methods_allowed.extend(fn._methods)
                    continue
                request.args = match.groups()
                return self.run(fn,request)
        if methods_allowed:
            request._out_headers.append(('Allow',",".join(methods_allowed)))
            request._methods = methods_allowed
            return self.handle_error(request,405)
        return self.handle_error(request,404)

    def app_handler(self,environ,start_response):
        request = Request(environ)
        response = self.request_handler(request)
        start_response("%i %s" % (response.code,response.status), response.headers)
        return response.content


###############################################################
# Next our actual request handlers

myapp = App()

@myapp.handler(404)
def r_404(request,**args):
    return Response(404,[('Content-type', 'text/html')],
        ["<h1>Not Found</h1><p>Not the page you're looking for</p>"])


@myapp.handler(500)
def r_500(request,message=None,**args):
    if getattr(request,'traceback',None):
        return Response(500,[('content-type','text/plain')],request.traceback)
    if not message:
        message = "<h1>Error</h1><p>An unspecified error occurred</p>"
    return Response(500,[('Content-type', 'text/html')],message)


@myapp.route('/$')
def r_home(request):
    request.args = ['home.html']
    return r_static(request)


@myapp.route('/static/(.*)$',['GET'])
def r_static(request):
    data = None
    path = request.args[0]
    if ".." in path: raise HTTP(404)
    mime, _ = mimetypes.guess_type(path)
    if not mime:
        mime = "application/octet-stream"
    if STATIC_DIR:
        mypath = os.path.join(os.path.dirname(__file__),STATIC_DIR,path)
        if not os.path.isfile(mypath):
            raise HTTP(404)
        with open(mypath,'r') as f:
            data = f.read()
    else:
        try:
            data = static_files[path]
        except KeyError:
            raise HTTP(404)
    return Response(200, [('Content-type', mime)], [data])



@myapp.route("/gen.json",['POST'])
def r_gen(request):
    bits = request.fields.get('bits','2048')
    key = None
    if bits == "own":
        key = request.fields.get('mykey',None)
        if not key:
            raise HTTP(500,"Paste private key into the box")
        bits=2048

    LABELS=["CN","emailAddress","C","ST","L","O","OU"]
    config = OpensslConfig()
    config.bits = bits
    config.subject = [
        (x,request.fields[x]) for x in LABELS if request.fields.get(x,None)]
    altkeys = [k for k,v in request.fields.items() if k.startswith("DNS.") and v]
    config.altnames = [request.fields[k] for k in sorted(altkeys)]

    if not config.subject:
        raise HTTP(500,"No certificate subject provided")
    #print config.serialize()

    openssl = OpensslCmdline(OPENSSL_PATH,config)

    if not key:
        key = openssl.openssl_genkey()
    if not key: raise HTTP(500,"Unable to generate private key.")
    csr = openssl.openssl_gencsr(key)
    if not csr: raise HTTP(500,"Unable to generate CSR.")
    password = request.fields.get('pw',None)
    if password:
        key = openssl.openssl_enckey(key,password)

    return Response(200,[('content-type','application/json')],
        json.dumps({'key':key,'csr':csr})
    )


#######################################################################
## Our Main function

def main():
    global STATIC_DIR
    parser = optparse.OptionParser()
    parser.add_option('-n','--no-browser', dest='nobrowser',
        action='store_true', help='Don\'t start browser')
    parser.add_option('-s','--static', dest='static',
        help='Static dir')

    (options,args) = parser.parse_args()
    if options.static:
        STATIC_DIR = options.static

    server = simple_server.make_server('', 8000, myapp)
    if not options.nobrowser:
        browser_open("http://localhost:8000/")
    server.serve_forever()


def browser_open(url):
    import webbrowser
    mode = 2  # new tab
    webbrowser.open(url,new=mode)


#######################################################################
## OpenSSL Interop

class OpensslCmdline(object):
    """Access openssl via command line. Less portable, better typical deployment."""
    def __init__(self,cmdpath,config):
        self.cmdpath = cmdpath
        self.config = config

    def _run(self,*cmd,**args):
        stdin = args.pop('stdin',None)
        cmd = list(cmd)
        cmd.insert(0,self.cmdpath)
        try:
            if stdin:
                proc = subprocess.Popen(cmd,stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            else:
                proc = subprocess.Popen(cmd,stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE)
            out,err = proc.communicate(stdin)
            return out
        except:
            return None

    def test(self):
        out = self._run("version")
        return out is not None

    def openssl_genkey(self):
        keyout = self._run("genrsa", str(self.config.bits))
        return keyout

    def openssl_enckey(self,key,password):
        return self._run("rsa","-des3","-passout", "pass:%s" % (password),stdin=key)

    def openssl_gencsr(self,privkey):
        key_r,key_w = os.pipe()
        csr_r,csr_w = os.pipe()
        cnf_r,cnf_w = os.pipe()
        child=os.fork()
        if child==0:
            os.close(key_w)
            os.close(cnf_w)
            os.close(csr_r)
            os.dup2(csr_w,1)
            os.execlp(self.cmdpath, "req", "-new", "-key", "/dev/fd/%i"%(key_r,),
                    "-config", "/dev/fd/%i"%(cnf_r,))
            sys.exit(100)
        os.write(cnf_w,self.config.serialize())
        os.write(key_w,privkey)
        os.close(cnf_w)
        os.close(key_w)
        unused_pid, status = os.waitpid(child,0)
        out=None
        if status == 0:
            out = os.read(csr_r,1024000)
        os.close(csr_r)
        return out


class OpensslConfig(object):
    def __init__(self):
        self.bits = 2048
        self.subject = [] # (CN,example.com), (OU,Foobar), etc.
        self.altnames = []

    def serialize(self):
        lines = [
            "[default]",
            "prompt=no",
            "[req]",
            "default_bits = {0}".format(self.bits),
            "attributes = req_attributes",
            "distinguished_name = req_dn",
            "req_extensions = ext",
            "[req_attributes]",
            "[ext]",
            "basicConstraints = CA:FALSE",
            "subjectKeyIdentifier=hash",
            "keyUsage = nonRepudiation, digitalSignature, keyEncipherment",
        ]
        if self.altnames:
            lines.extend([
                "subjectAltName = @alt_names",
                "[alt_names]"
            ])
            dns = 0
            for name in self.altnames:
                lines.append("DNS.{0}=\"{1}\"".format(dns,name))
                dns+=1
        lines.append("[ req_dn ]")
        for k,v in self.subject:
            if v:
                lines.append("{0}=\"{1}\"".format(k,v))
        return "\n".join(lines)

#######################################################################
## static files

class StaticData(object):
    def __init__(self,data):
        name=None
        self.data = {}
        pending = []
        for line in data.splitlines():
            if name and line.startswith(' '):
                pending.append(line.strip())
                continue
            if pending:
                self._add(name,"".join(pending))
                pending=[]
                name=None
            line = line.strip()
            if line:
                name = line
        if pending:
            self._add(name,"".join(pending))
    def _add(self,name,data):
        self.data[name]=zlib.decompress(base64.b64decode(data))
    def __getitem__(self,key):
        return self.data[key]

static_files = StaticData("""
flaticon.eot
  eNrlVM1vG0UU/83uetehJXWNP9p6jbaxawc32cYbe10llSgodd04FZFBkQUCunJsJ5VjR7
  YrpRJIgECCnCokOCCVA4o4wAWknJBAOQASPfWC6AEh99CcK6FKnAhv1uOmddT+A4z05v3m
  fe2bfW+ergFdFWCQwJcEz4gLSHKDcb6w2D/DJziY4PO7l+7gwPKhhgYcdLGKClpokmwUJV
  RRxzVX0yZJCEskaaNDVtzGQBompp7gLz76LN6DjMV8/rXLV/8K/AqoZZLqF+cu5GGBbqGe
  pbPxyqtnrDNfFHfJieuXKmvO+o4/9hOdfyaarzud9b09igSVf9Bbb1yv/fBl6ntA1klfWK
  k6y1JnN026P4nsFRLI99k90gXoHF9Z626o/aS+o83faFUczGGL/Pk/OrzmbKxjAS+S3s2n
  6axVP/tj4zKgLJPs0/VWp7v9zLYX8PxD+rPu3YjuXNqdf/vIuQc41K/F7W9Kt/b5Xk8C2+
  H5ilK5PmxnrwdzULuHpRksxZV4cI5ImJCEy84PYlDUG6T1sgVWo/NFwR/gOD58tB8eawFa
  i7ULyzjfQ49RDjswKTdjvzkGKUqPYFqyIF3YzdGJuWcF48RVN2Ny6DGqEK0eODfk/Zsxdf
  +abCj8Y+35/1i87/gfNaiOVzCCk3iBTmOq9jyz7FwiGQqrmjqWTCTtnJ1Tg4GQZWczyZAa
  UMcSGdtipa3NeHyTb2+Z0ag58/EMZ5LiLV4tepV39HFdH2dXyoVCmUiOmmb01Cm+S1IwnC
  0Ws+GgpHIb3e2zQZf6cAwJes6zVI5QeJTFxpK50LSV4xlpHAcD6nMxLRGjRENhLTjNPBZx
  k2UztiYyDWsJtjV7Mr5ZMieSx0/MUWL6xPtHfTeV4reRZmqytBk3Zt+IsF/+ve+PSLY/rH
  /kJn4immITqZcL5SNJlVKdiH6t3PQdzRbZm83RcuGl1Ovk8kHYb0sRf0Cv9G9yOhblF8Bh
  fC76h9E78wssQcNpgWXE8a7ACtlsC+zBIfwusEryv3lnKyMk8bleHEs0CCMCyyhgWmCFbL
  4S2EOj8UeBVZLfPTgOaw2nu1ppERqaqqVq/VrDIZB3Dbsub5NFlZ6m5c5XAzNEwyH70hwm
  aQpbtFtkmUaGArWa3XyrXa8aljllzBiDTxPMTaatSWsqTVZPyfAJU36p2u6sUpi0OfVU9+
  HXffBte1ypxCQme6rXqxnb3fnc5RNEcj1GiY6JSjL6t3zGKA9juzF/+6SVHp65/wFAieK4
flaticon.svg
  eNqtVdtuG0cMfc9XsFugbzO7w7m3lgN0bQQF7DZA0hR9FFZrS4AsGV7VdvT1PZxZO4HroH
  0oYGMuyyEPeQ6pk7ePN1u6H++mzX63aIzuGpoOy91qud3vxkWz2zdvT9+cfHf2W//xz/fn
  NN1f0/vff774padGte0ftm/bs49n9OHTOzLatO35rw0168Ph9se2fXh40A9W7++u23d3y9
  v1ZphaGLZiiEctnBmjV4dVgxDiGVh20+KV59x1nZg3pyer8Wo6Pbna7w60WS2aq+3ysBn2
  u4bW+7vNUS1X9+px0XjDTbVSV8thpL92m8Okbsc7Nd7Ur7SchnF3WDTOpYZW43xSwTX0qN
  bj5nqNIzsUZFjePl+41DXt6cnNZpo2u2t1vf18u/5naFjUL4g77Fco5A/fP54jiZ8aKh/U
  bnmD2/Hz6MIr0AmZXbIPZD33xjltnZE9uai9z8Qp6BwzdWQyD/Olyq5cPtkrEzoSJ7IZDE
  odfMQT7pJ2NlPwumNTLMSyd8Fp5/jZuQ2xvJC4M5bjpU2smT0xPhqXBtvpLkmsrE2K5L32
  EUdASDhGp6NJpKIXYxqKmQMiPONQ7YKFAd5lOZcH+elBb/HdcaTMOjpLtut0BLJU80rdIA
  5iQlIqISlOZKqlMhwKTht0Av5BFaA0w1QFJ80oa1SgLUGHGWOByFQQlsQyTi8sdUbdjZY4
  OiMP1g5ZwJRRPhSPegM3UerlUS/rgA9WjrVF3LLnOAB97HTIeBm1BUplSiZ1M5RvLFzjpl
  hkmg3w1PjiS3EJg2gSRUUdO0fO6pgz9TYmDVZBWtbAZ5OkJhwmbXOiF5wei/LYWQGGMnrw
  wkY70AIO5/9J1i+3uKiHspe/D8UJAvoqMfg7frMvzCt9kb7VFw4EBaTBOSM97p0H9ckSR6
  QRwWruoH9EtF4zVjwsbaKkT0Rkc5+o2ii2Nop66hTRCiiFQ1wGgwrBhTYdviZkk6TBtHe8
  tQlupHqy9Iz8M7SejAYdjNsU/VdKFaGWji1CjU9CrTq1zzqd+6noNNV24qrTTHNzFPFl9F
  LSnpFmLmAVyO6gHe9QBA8FAAc4jRY1iBcvalYphjTgBRkGUZdiqDJiFqCYoNiyTgESglLS
  1njIABqsq+lFMcKry3gC8MmVjMVR2XPsZRVzUatFkiJhBKxxj5eYo0gr0VoUlkK+ABHaio
  Lhx2TXWwg7opIWrBnRD6aSPPhqGv3rZKQBpFgWiQKv8IglSHugvN4RhOIzegfkam/dBYqA
  2lrzCdmvZ1wFKNzItSvNgSJzNgM7jE8pHIBnFhVhXLooQJyMOIe2TZ62CoxEFGZeexOrnQ
  EVHeRaprSpWip7Z/uy1t4xqfQVItIc+XgJWXQ+1Qz/x2n1X4YVlaGQS7BcFKZ8mKcHuJDR
  jdmTzLYYiRDr2ueoO8Q0oDeGILo0WZIH65a+JFRmRCs/3Fjqb7388J+++RuArevH
flaticon.ttf
  eNrlVM+LG1Uc/7yZySRr6zZN86NtJmW6SZM13UyT2WRSdgvWspvGpsUSZQmKtUN2kt2STZ
  YkhS0oqCjonkTQg1APsniwF4U9FSp7sAU9eRE9SEkP7rkgBU+u3/cy6dYt9B/og+97n+/P
  93k/wQC8iPch43Kp9Mala/eD9wC1Rlbt/Nx8CSZU0k+Trr/2+inz1FeVbYBx/0J9xV7dCs
  R/JP0nkgtNu7e6s0OVoGbJ72u2bjRuf53+AZA18peXHHtR6m3nyPcnibVEBvkh+4t8QdIT
  Syv9NZqMGvueukCrU7cxhw3K95O+f8VeW8VFvEx+wadtrzhf/L52CVAWyfb5aqfX33xh0w
  d4/iH/afC1kfzx6vaFdw6ceYR9kqj+63fVX3bHnYEEtsX5YugWOWxrZwBjaJCE5X9NERYP
  zpC4IWThtrOjGlT1M/L62EXWIP28Oz7CEXzEEzxju+X8T5S+3JhfxNkBBow4bMEgbjoeMx
  hRlJ7A1GRXNDdujjQmdAWTNKqCMSUMGJ0QtQH4qMu7K2Pq7jLZnvKjXXmOGr93fEd1Oser
  GMNxvETahOo9xkyrmEyFI6pXnUglU1bRKqqhYNi0CvlUWA2qE8m8ZbLqxnoisc67K0YsZs
  x8MsMHSfFVrlV8yrvapKZNsqu1crlGIscMI3biBO8lKRQpVCqFSEhSeYwm7tnolvpxGElk
  MUvHEY6Ms/hEqhieNouckZfjUFA9FPcm40Q0HPGGppnHpNFghbzldZlGvEm2MXs8sV41pl
  JHjs4RMW3qg4P+m0rlVrSdzlTXE/rsW1F299+HgahkBSLax4L40ViaTaXPlWsHUipRnYp9
  q9z0HyxU2Nvt8Vr5lfSblPJhJGBJ0UBQqw9XcjIe4wvAfnzp3h9G7yzgYglenHSxjATec7
  FCMZsu9mAffnOxSva/+c1WxsjiF1kcSxhH1MUyyph2sUIx37jYgzDuuFgl+wM00IKNPpZR
  RwdtoNGy+8v1DqEqHDRxXQR0SXWa11s2gZII7IuxSxEOPU0TBh2IjhmSvSWH1iIyyFFchi
  RLKE+FOu1+qdNtOrppZPUZfTQ1wWImZ2bMbI6insFwgebuokeu4Tw5wQILTre3TGVyRvaZ
  6Xtf99Nv2yOsEpOY7HFuOHlL9Pzf5T+IJDLGSQ67J8lob/kfozyuLWr+/Gknt/fP/Q+SLt
  Et
flaticon.woff
  eNor93dzY2BkAAKWHQy8IJqthAEHcHML8QWqmwNkSgGxTNY9kWPuLq5uQLEaIF8eiBUYjB
  jY/IP1jRgYGEHqgHIMYfqzvJ8l5yYWAMW+APnOQNrrgJDyvvTEYqAYC8g+DhD+/5+BOT2n
  Mo2BgckFqEYbiD12zdPamJGamAJkGwDV6AGxGVPxM8MMoCBQLAHkDiBWYf7A+DQjt6QCKP
  YEyBcAYiE2IJGTnwxUx2QBZPKAsQvDktzECpBbQG6WBbvZh8E+LzE3lYGBGSjOANTPOGnq
  9QrfgvxioNtYQsBqGBgstnBt4ai4lZyQkpDA8Eh63vk9j37m7jMqMDZsONAa6rhc4Mt/dh
  +eHvaGGD62DSYM/uu5bzAwQNXbfPjP2CwnzMzB4OnGFnKAiSHEhOkmVC4hdQNjkkACU5Ib
  24QZzDPOMzBw8jP0MED1JiXMOXDg1IGDLw7POHbgwAO+pfuNPIy2GBgYGG4oMjrQyNB0Um
  DCs1mHHnxoeMio/LjxP7vEFwl+Aw2GVknHIoa+Rq7PYHOSGhjUNNJAoRXGwF5x627XRc4D
  CiJHirZauNr/eaNwt57N/GK1VpO2SYFMI0PnTnbBGjPe/ZV/b+rrrcjSbfKq8Vxtfipn4u
  kV/Efev0yZyLYBkSiA4VlxS7ff0O+wg4Bruvm5vAynpBz9I7s1NsrmGxxz8tszbRKXS+LJ
  WC1uli4X94nCFxpaWmraSwR5py94KCfTKMyQvWDG//Qlkn/NLzA1KLJtaZKVODhxno0Tf+
  CqTwFWPQGPTgasinl6ZNuckFTjlwLdFQ99lmbsXNu8IO+JmqDSTPvz0ofdlu/Rtj5mO7/A
  znH1Kg2tWN2JKkk2eSLJs1NTZxpKT05rf33F7MD39mcVzXJvnDmWb2Bw4HutdH/yTmPfz2
  0dZntzJ9rOb9vHViqxdfmKuVn+AWbBX+ZPuSiQK754QZzaRhuJmAwDOfsv1dKLa0qvXzy5
  ia+tW1t8b33tLL0wtcf++x8wCy60sNJfFetpkqUT1+O7fv7UF1V313ZtfhE038YoOPH6lh
  9v76sf3/fgA7NBvRkvMC5q++z9DhuItO/fkskoqnjkwlJvNrMpJ/g8plY1dO10/r6iaLFH
  oPLOlydMqxjOHThlaMGQ/oDpz6tZrQunzfvz82d1fUN0n8ocv0Om/BPZYz6KVJ5Qzp8YbC
  k/0d3nR5dN2D/3tEn3NIrlV/nZPOiLfKK43sbd7+kedznDp8afIn7mb9sS8sUk58WNg9vW
  /kq73BlmkcXn+KFq168LYU2pAr8LqiX7eiYxLa5e+OP+pzlzJyc/fcqlXBW4OO+6vnX87j
  U6PttO/HPjfr5T9/OliEhxs5jsbenr13+Wkd6W8PbPvkDp6BneT/c7Btuyg9JtkgNbD8+L
  BlGdU0dOHDlxZlbUzKwkNjVdBvEZzJXAVMMIzOtM0PT/gDmJk00gIQnITktgnKSTIMfMwD
  KBwRKc/hMSUhiaJs/92abw69CqBcEGUgzu2uzA3AgAUGu/Kw==
home.html
  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
style.css
  eNqVVlmL2zAQfo5/hXAobJbYtTebbFahUFoo9L0vpReyNU7EypKRlU3csv+9Ix+JnaMHy4
  Zo7plvjiSaV+SXN0pY+rQ2eqs4JbuNsLDyRqmW2lCSSOStPG+UaWWDjOVCVpSUTJVBCUZk
  q5ZTip9ASXxf2JX34o311oJxpi3sbcCkWCtKUlBIrfmZAMnLU99jgHPXo5yZtVCUba3GV6
  L3QblhXO8omRd7Ekf4MXMfZp2wm2jq/sL5BEV3gtsNRSbk+CoY50KtKblzwu6jtmY4oK8Y
  SaWWgpPx4+PjgREYxsW2pLWXfuDcutgzqZmlEjJ79BYPvAVWF3RxosudbpNVkGhrdU5JFM
  6c3kBKqGJrp6RHcdVkBpgzcMiuyeSQnivKvCYdgYnjFpfOlEQL+MyrJ6h+cPHsDPZDng9D
  bgTrlI9gP4Q9N11n5FrpsmCpw3EDYr2xlCybzDZ1Q7TEuCn/AfygAX1Qfaq0cnb2+z7oDr
  24/e9DPpvUEWMSuTZQ5xdmahjyInrVBbxrg1Pa5EyuTgGJm5hDq6518aAU/2s32eJLhYlV
  U1KChNS672fzMJs9sOThOBLdcPaQvXPIdgXrtfHdYr5czs47+X7YLfft9KzaJLsqdxW+G1
  Y5CheTkyHsJGcXRvDFe9t2RwqH7ulaxf8gmRWpVj5aLE1KydbIGz9rqSFo60+ussYCMrH3
  JyRzhbY3PuQJcA480AUiVBXgT6beaKi301nWU2meZ1LW9oWs2cIVc+XzuidYv662QQOZrS
  QciS/e69sPSCdrUGCYBU6SihzMpzon2Ae4SN+/J+8+h+TTBgiuwY02JRGI5UeU0Cgo9O1r
  70sqWVl+f3MIL/C/0QQwOpiShnn7xicXuJdVWYZtfk2zZp4h2gE6HI521V4qwOVaucHtfE
  EF94s2UOcPaRbhxe75ClEU+efSy6vScS09RqFQKzLQ+ouHRifL/lGpcdTMuFPt7b1u2J7B
  oB0mu62SC84l1GsyPtmz8bIe8X6pEi358TJGvYGOVtdubog3Ge/JqfHozzu83jhB/XIA7Q
  wrVpd/MLTBkAt3ulsR7jSNGWPI5qIsJKtoIrU78k14kiUgr+7bk4vZRt5S3dFqO635+YGp
  dpey80Wae/Li/Qa4JOVE
""")

#######################################################################
## ifmain

if __name__ == '__main__':
    main()
