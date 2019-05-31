import requests
import json


from certsrv import Certsrv
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

from http.server import HTTPServer
from http.server import BaseHTTPRequestHandler
from pathlib import Path
import time

HOST_NAME = 'XXXXX'
PORT_NUMBER = 8000
PASSWORD = 'XXXX'
USER='XXXX'
USERDN='XXXX'
LDAP_ADDR = 'ldaps://XXXX:636'
LDAP_ADDR = 'XXXXX'
LDAP_BASE = 'DC=XXXXXX,DC=com'
LDAP_BIND = "CN=XXXXXXX,DC=COM"


# User google auth 2 endpoint to get email from user token

def validateToken(token):
        url="https://www.googleapis.com/plus/v1/people/me?fields=emails"
        headers = {"Authorization" : "Bearer "+token}
        r = requests.get(url, headers=headers)
        fields = json.loads(r.text)
        print(fields)
        if 'emails' not in fields.keys():
                return False
        email=''
        for f in fields['emails']:
                if f['type']=='account':
                        email=f['value']
                        break
        return email

# With email, get AD user information
def getUserCN(email):
        from ldap3 import Server, Connection, ALL, NTLM

        server = Server(host=LDAP_ADDR, port=389, use_ssl=False)
        conn = Connection(server,LDAP_BIND, PASSWORD, auto_bind=True)

        search = "(mail="+email+")"
        conn.search(LDAP_BASE,search,attributes = ['dn', 'UserPrincipalName'])
        CN = str(conn.entries[0].entry_get_dn())+"|"+str(conn.entries[0].UserPrincipalName)
        #return DN (used for csr forgery) concatenate to UserPincipalName
        return CN

# Generate csr from ad information
def generateCsr(email, dn):
        # get UPN and dn
        t = dn.split('|')
        # Add stop to dn
        dn = t[0]+',end=end'
        userupn=t[1].encode()

        # browse UPN to generate CSR
        unit = dn.split(',')
        csr_cn_parts = []
        csr_cn_partstmp=[]
        last=''
        for u in unit:
                t = u.split('=')
                (name,value) = (t[0],t[1])
                print((name,value))

                # the x509 lib need to inverse OU orders, don't knwo why
                if name!=last and len(csr_cn_partstmp)>0:
                        for element in reversed(csr_cn_partstmp):
                                csr_cn_parts.append(element)
                        csr_cn_partstmp=[]  
                last=name
                if name=='OU':
                        csr_cn_partstmp.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, value))
                elif name=='DC':
                        csr_cn_partstmp.append(x509.NameAttribute(NameOID.DOMAIN_COMPONENT, value))
                elif name=='CN':
                        csr_cn_partstmp.append(x509.NameAttribute(NameOID.COMMON_NAME, value))
        csr_cn_parts = [x509.NameAttribute(NameOID.EMAIL_ADDRESS, email)]+csr_cn_parts

        # Generate a key
        key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
        )
        bupn=b"\x0C"+bytes([len(userupn)])+userupn

        # generate csr
        custom_oid_user_principal_name = x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2.3")
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name(csr_cn_parts)
                ).add_extension(
                        x509.SubjectAlternativeName([
                                x509.OtherName(custom_oid_user_principal_name,bupn), # ASN.1 encoded string= (bytes) \x0C (UTF 8 String) + len(ASCII) + ASCII en hex
                        ]),critical=False,
                ).sign(key, hashes.SHA256(), default_backend())
        pem_req = csr.public_bytes(serialization.Encoding.PEM)


        # Get the cert from the ADCS server
        pem_req = csr.public_bytes(serialization.Encoding.PEM)

        ca_server = Certsrv("XXXXX", "XXXXXX", PASSWORD,auth_method="ntlm")
        pem_cert = ca_server.get_cert(pem_req, "User_ADFS_Script")

        # Print the key
        pem_key = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
        )
        print(pem_key.decode())
        print(pem_cert.decode())

# Small http server
class Server(BaseHTTPRequestHandler):
    def do_HEAD(self):
        return

    def do_GET(self):
        self.respond()

    def handle_http(self):
        status = 200
        content_type = "application/json"
        response_content = ""
        dn=''
        token = self.headers.get('Authentication')
        if token==None:
                email=False
        else:
                email = validateToken(token)
        if email==False:
                response_content=json.dumps({'error':'authentication error'})
                status=403
        else:
                dn = getUserCN(email)
                response_content=json.dumps({'error':'No Error','DN':dn})
        self.send_response(status)
        self.send_header('Content-type', content_type)
        self.send_header('Access-Control-Allow-Origin','chrome-extension://XXXXXXXXXXXXXXXXXX')
        self.end_headers()
        generateCsr(email,dn)
        return bytes(response_content, "UTF-8")

    def respond(self):
        content = self.handle_http()
        self.wfile.write(content)


#main
if __name__ == '__main__':
    httpd = HTTPServer((HOST_NAME, PORT_NUMBER), Server)
    print(time.asctime(), 'Server UP - %s:%s' % (HOST_NAME, PORT_NUMBER))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    print(time.asctime(), 'Server DOWN - %s:%s' % (HOST_NAME, PORT_NUMBER))