
from base64 import *
from OpenSSL.crypto import dump_privatekey,load_privatekey, FILETYPE_ASN1,FILETYPE_PEM
from OpenSSL import *
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pyasn1.type import univ
from pyasn1.codec.der.encoder import encode
from Crypto.Util.asn1 import *
from Crypto.Util.number import *

def KPT_encrypt_rsa_field(data, key, iv):
    data = long_to_bytes(data)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(iv, data, None)
    ct = ct[:-4]
    return bytes_to_long(ct)

def gen_wpk_by_swk(raw_key, gcm_key, gcm_iv):
    
    # Read raw key and decode it into Der sequence 
    pkey = crypto.load_privatekey(FILETYPE_PEM, raw_key)
    private_key_der = DerSequence()
    private_key_der.decode(dump_privatekey(FILETYPE_ASN1, pkey))

    # Encrypt the rsa field with AESGCM
    private_key_der[3] = KPT_encrypt_rsa_field(private_key_der[3], gcm_key, gcm_iv)
    private_key_der[4] = KPT_encrypt_rsa_field(private_key_der[4], gcm_key, gcm_iv)
    private_key_der[5] = KPT_encrypt_rsa_field(private_key_der[5], gcm_key, gcm_iv)
    private_key_der[6] = KPT_encrypt_rsa_field(private_key_der[6], gcm_key, gcm_iv)
    private_key_der[7] = KPT_encrypt_rsa_field(private_key_der[7], gcm_key, gcm_iv)
    private_key_der[8] = KPT_encrypt_rsa_field(private_key_der[8], gcm_key, gcm_iv)
    
    wraped_key_der = private_key_der.encode()
    wrap_pkey = load_privatekey(FILETYPE_ASN1, private_key_der.encode())

    ENC_ALGO_DESP = DerSequence()
    enc_algo_idId = univ.ObjectIdentifier('2.16.840.1.101.3.4.1.6')
    enc_algo_id = encode(enc_algo_idId)
    iv = DerOctetString(value=gcm_iv).encode()
    ic = DerInteger(0x01).encode()
    hmac_algo_idId = univ.ObjectIdentifier('1.2.840.113549.2.7')
    hmac_algo_id = encode(hmac_algo_idId)

    ENC_ALGO_DESP.append(enc_algo_id)
    ENC_ALGO_DESP.append(iv)
    ENC_ALGO_DESP.append(ic)
    ENC_ALGO_DESP.append(hmac_algo_id)


    WRAP_DESP = DerSequence()
    wrapping_formatId = univ.ObjectIdentifier('1.2.840.113549.1.5.15')
    wrapping_format = encode(wrapping_formatId)
    encrypt_algo = ENC_ALGO_DESP.encode()

    WRAP_DESP.append(wrapping_format)
    WRAP_DESP.append(encrypt_algo)


    WRAPPED_PRIV_KEY = DerSequence()
    version = DerInteger(0x01).encode()
    algo_idId = univ.ObjectIdentifier('1.2.840.113549.1.1.5')
    algo_id = encode(algo_idId)
    wrapped_key = DerOctetString(value=wraped_key_der).encode()
    WRAPPED_PRIV_KEY.append(version)
    WRAPPED_PRIV_KEY.append(algo_id)
    WRAPPED_PRIV_KEY.append(wrapped_key)

    wpinfo = DerSequence()
    wrap_desp = WRAP_DESP.encode()
    encrypted_data = WRAPPED_PRIV_KEY.encode()
    wpinfo.append(wrap_desp)
    wpinfo.append(encrypted_data)

    wsp = wpinfo.encode()
    wsp = b64encode(wsp)


    fp= open('py_wp_rsa.pem', 'w')
    spilt_wsp= '\n'.join(wsp[i:i+64] for i in range(0, len(wsp), 64))
    data = '-----BEGIN WRAPPED PRIVATE KEY-----\n'+spilt_wsp+'\n'+'-----END WRAPPED PRIVATE KEY-----\n'
    return data





