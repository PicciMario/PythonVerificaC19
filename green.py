#pip install Pillow
#pip install opencv-python
#pip install pyzbar
#pip install base45
#pip install cryptography
#pip install cose
#pip install cbor2

from pyzbar.pyzbar import decode
import cv2
import zlib
import base45
from base64 import b64decode, b64encode
import cbor2
import json
from urllib.request import urlopen
import urllib
import OpenSSL.crypto
import sys

from cryptography import x509
from cryptography.utils import int_to_bytes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from cose.messages import CoseMessage
from cose.headers import KID, Algorithm
from cose.keys import CoseKey
from cose.keys.keytype import KtyEC2, KtyRSA
from cose.keys.keyparam import KpKty, KpAlg, EC2KpX, EC2KpY, EC2KpCurve, RSAKpE, RSAKpN
from cose.algorithms import Es256, EdDSA, Ps256
from cose.keys.curves import P256

from cryptography import x509
from cryptography.hazmat.backends import default_backend

import datetime

# Lettura QR Code
filename = "napoleon.jpg"
print(f"\nAnalisi file: {filename}")
img = cv2.imread(filename)
gray_img = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

# Estrazione payload da QR Code
decoded = decode(gray_img)
payload = decoded[0].data[4:]

# Decodifica B45 e decompressione
decoded = base45.b45decode(payload)
decompressed = zlib.decompress(decoded)

# Decodifica messaggio COSE
cose_message = CoseMessage.decode(decompressed)
algorithm = cose_message.get_attr(Algorithm).fullname
kid = cose_message.get_attr(KID)

# Stampa messaggio CBOR in payload COSE
# from Tobias Girstmair (https://gir.st)
# https://gist.github.com/dsoares/dbd784615defd8800e93e4df4c783ce1

sch = urlopen('https://raw.githubusercontent.com/ehn-dcc-development/ehn-dcc-schema/release/1.3.0/DCC.combined-schema.json')
glb_schema = json.load(sch)

def annotate(data, schema, level=0):
    for key, value in data.items():
        description = schema[key].get('title') or schema[key].get('description') or key
        description, _, _ = description.partition(' - ')
        if type(value) is dict:
            print('  '*level, description)
            _, _, sch_ref = schema[key]['$ref'].rpartition('/')
            annotate(value, glb_schema['$defs'][sch_ref]['properties'], level+1)
        elif type(value) is list:
            print('  '*level, description)
            _, _, sch_ref = schema[key]['items']['$ref'].rpartition('/')
            for v in value:
                annotate(v, glb_schema['$defs'][sch_ref]['properties'], level+1)
        else: # value is scalar
            print('  '*level, description, ':', value)

data = cbor2.loads(cose_message.payload)
print("\nDati Green Pass:\n")
annotate(data[-260][1], glb_schema['properties'])

# Recupero chiavi pubbliche
url = 'https://get.dgc.gov.it/v1/dgc/signercertificate/update'
token = ''

certificates = {}
x509_collection = {}

print("\nRecupero lista certificati validi...\n")

while True:
    
    request = urllib.request.Request(url)
    if (token):
        request.add_header('X-RESUME-TOKEN', token)
        
    with urlopen(request) as keyfile:
        
        key = keyfile.read()
        if (not key): break
        token = keyfile.getheader('X-RESUME-TOKEN')
        b64kid = keyfile.getheader('X-KID')
                
        deckey = b64decode(key)
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, deckey)
        x509_collection[b64kid] = x509
        pk_data = x509.get_pubkey()
        
        pub_key = OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_ASN1, pk_data)
        pub = serialization.load_der_public_key(pub_key)
        
        # key types: https://pycose.readthedocs.io/en/latest/cose/keys/keytype.html
        # key parameters: https://pycose.readthedocs.io/en/latest/cose/keys/keyparam.html
        if (isinstance(pub, EllipticCurvePublicKey)):
            # ECDSA SHA256
            # curves: https://pycose.readthedocs.io/en/latest/cose/keys/curves.html
            certificates[b64kid] = CoseKey.from_dict({
                KpKty: KtyEC2,
                KpAlg: Es256,
                EC2KpCurve: P256,
                EC2KpX: pub.public_numbers().x.to_bytes(32, byteorder="big"),
                EC2KpY: pub.public_numbers().y.to_bytes(32, byteorder="big")
            })    
        elif (isinstance(pub, RSAPublicKey)):
            # RSSA-PSS SHA-56 MFG1
            certificates[b64kid] = CoseKey.from_dict({
                KpKty: KtyRSA,
                KpAlg: Ps256, 
                RSAKpE: int_to_bytes(pub.public_numbers().e),
                RSAKpN: int_to_bytes(pub.public_numbers().n)
            })
        else:
              print(f"Tipo chiave sconosciuto {pub.__class__.__name__}).")          


# Trova chiave corretta per certificato
kid = b64encode(cose_message.get_attr(KID)).decode('ASCII')
if (kid not in certificates):
	print(f"ERRORE: il certificato {kid} non è presente nella lista dei certificati accettati.")
	sys.exit(0)
pk_to_use = certificates[kid]

#Stampa attributi chiave trovata
print("\nDati certificato rilascio:\n")
print(f"KID: {kid}")
iss = x509_collection[kid].get_issuer().get_components()
c = [(x.decode('UTF-8'), y.decode('UTF-8')) for (x,y) in iss if x.decode('UTF-8') == "C"]
if(c): print(f"Country: {c[0][1]}")
cn = [(x.decode('UTF-8'), y.decode('UTF-8')) for (x,y) in iss if x.decode('UTF-8') == "CN"]
if(cn): print(f"Common name: {cn[0][1]}")
o = [(x.decode('UTF-8'), y.decode('UTF-8')) for (x,y) in iss if x.decode('UTF-8') == "O"]
if(o): print(f"Organization: {o[0][1]}")   

valid_from = datetime.datetime.strptime(x509_collection[kid].get_notBefore().decode('ASCII'),"%Y%m%d%H%M%SZ")
print(f"Valido da: {valid_from}")
valid_to = datetime.datetime.strptime(x509_collection[kid].get_notAfter().decode('ASCII'),"%Y%m%d%H%M%SZ")
print(f"Valido fino a: {valid_to}")

# Verifica firma
print("\nVerifica Green Pass:\n")
cose_message.key = pk_to_use
if not cose_message.verify_signature():
    print("Firma NON valida")
else:
    print("Firma valida")

# Verifica lista revoca chiavi
valid_url = 'https://get.dgc.gov.it/v1/dgc/signercertificate/status'
valid_list = []
with urlopen(valid_url) as valid_file:
    valid_list = valid_file.read()
    valid_list = json.loads(valid_list.decode('ASCII'))

if (kid not in valid_list):
    print("Certificato revocato")
else:
   	print("Certificato valido")

# Verifica lsta revoca certificati
settings_url = 'https://get.dgc.gov.it/v1/dgc/settings'
revoked_list =[]

with urlopen(settings_url) as settings_file:
    settings = settings_file.read()
    settings = json.loads(settings.decode('UTF-8'))
    
    revoked_data = [x for x in settings if x['name'] == 'black_list_uvci']    
    if (revoked_data): revoked_list = revoked_data[0]['value'].split(';')

gp_id = data[-260][1]['v'][0]['ci']

if (gp_id in revoked_list):
    print("Green Pass revocato")
else:
    print("Green Pass valido")