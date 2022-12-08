import IPython.display
import numpy as np
import pandas as pd
import os
import getpass
import qrcode
import ecies
import eth_keys
import coincurve
import cryptos
import hashlib
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
from coincurve.utils import get_valid_secret
from PIL import Image
from cryptos.py3specials import safe_hexlify, from_string_to_bytes, from_int_to_byte, from_string_to_bytes
from cryptos import serialize,deserialize

AES_KEY_BYTES_LEN = 32

def mk_opreturn(msg, rawtx=None, json=0):
    
    def op_push(data):
        if type(data) == bytes:
            bytedata=data
        else:
            bytedata=data.encode()
        import struct
        if len(data) < 0x4c:
            return from_int_to_byte(len(bytedata)) + bytedata
        elif len(data) < 0xff:
            return from_int_to_byte(76) + struct.pack('<B', len(bytedata)) + bytedata
        elif len(data) < 0xffff:
            return from_int_to_byte(77) + struct.pack('<H', len(bytedata)) + bytedata
        elif len(data) < 0xffffffff:
            return from_int_to_byte(78) + struct.pack('<I', len(bytedata)) + bytedata
        else: raise Exception("Input data error. Rawtx must be hex chars" \
                            + "0xffffffff > len(data) > 0")

    orhex = safe_hexlify(b'\x6a' + op_push(msg))
    orjson = {'script' : orhex, 'value' : 0}
    if rawtx is not None:
        try:
            txo = deserialize(rawtx)
            if not 'outs' in txo.keys(): raise Exception("OP_Return cannot be the sole output!")
            txo['outs'].append(orjson)
            newrawtx = serialize(txo)
            return newrawtx
        except Exception as E:
            print(E)
            print(type(E))
            raise Exception("Raw Tx Error!")
    return orhex if not json else orjson


class Cadena():

  def __init__(self,prvkey,data,utxo_dct,tip):
    self.data=data
    self.doge=cryptos.Doge()
    self.clip=[self.data[i:i+80] for i in range(0,len(self.data),80) ]
    self.og_len=len(self.clip)
    self.state='CONF'
    self.utxo=utxo_dct
    self.head_utxo=self.utxo
    self.txn_ids=[self.utxo['output'].split(':')[0]]
    self.prv=prvkey
    self.addr=self.doge.privtoaddr(self.prv)
    self.tip=tip
    self.index=0

  def make_tx(self):
    tx = self.doge.mktx([self.head_utxo],[ {'value':self.head_utxo['value']-self.tip , 'address': self.addr}])
    doge_inscribed_serial_tx=mk_opreturn( self.clip[self.index] , cryptos.serialize(tx))
    doge_inscribed_tx=cryptos.deserialize(doge_inscribed_serial_tx)
    self.signed_inscribed_tx=self.doge.signall(doge_inscribed_tx,self.prv)
    self.state='READY'
  
  def broadcast(self):
    self.cast=self.doge.pushtx(self.signed_inscribed_tx)
    cast_txid=self.cast['data']['txid']
    self.txn_ids.append(cast_txid)
    self.head_utxo={'output':cast_txid+':0' ,'value':self.head_utxo['value']-self.tip }
    self.index=self.index+1
    self.state='SENT'

  def update(self):
    if self.doge.fetchtx(self.head_utxo['output'].split(':')[0])['confirmations']:
      self.state='CONF'
      if self.index==self.og_len:
        self.state='DONE'

class CadenaMulti():

  def __init__(self,prvkeys,data,utxo_dct,tip):
    self.data=data
    self.doge=cryptos.Doge()
    self.doge.script_magicbyte=22
    self.clip=[self.data[i:i+80] for i in range(0,len(self.data),80) ]
    self.og_len=len(self.clip)
    self.state='CONF'
    self.utxo=utxo_dct
    self.head_utxo=self.utxo
    self.txn_ids=[self.utxo['output'].split(':')[0]]
    self.prvs=prvkeys
    self.pubs=[ self.doge.privtopub(prv) for prv in prvkeys]
    (self.script,self.addr)=self.doge.mk_multsig_address(self.pubs,len(self.pubs))#self.doge.privtoaddr(self.prv)
    self.tip=tip
    self.index=0

  def make_tx(self):
    tx = self.doge.mktx([self.head_utxo],[ {'value':self.head_utxo['value']-self.tip , 'address': self.addr}])
    doge_inscribed_serial_tx=mk_opreturn( self.clip[self.index] , cryptos.serialize(tx))
    doge_inscribed_tx=cryptos.deserialize(doge_inscribed_serial_tx)
    sigs=[ self.doge.multisign(tx=doge_inscribed_tx, i=0, script=self.script, pk=prv) for prv in self.prvs]
    self.signed_inscribed_tx=cryptos.apply_multisignatures(doge_inscribed_tx, 0, self.script,*sigs)#self.doge.signall(doge_inscribed_tx,self.prv)
    self.state='READY'
  
  def broadcast(self):
    self.cast=self.doge.pushtx(self.signed_inscribed_tx)
    cast_txid=self.cast['data']['txid']
    self.txn_ids.append(cast_txid)
    self.head_utxo={'output':cast_txid+':0' ,'value':self.head_utxo['value']-self.tip }
    self.index=self.index+1
    self.state='SENT'

  def update(self):
    if self.doge.fetchtx(self.head_utxo['output'].split(':')[0])['confirmations']:
      self.state='CONF'
      if self.index==self.og_len:
        self.state='DONE'


def get_output_spend_txns(txn_ident):
  import requests
  import json
  r = requests.get(f'https://sochain.com/api/v2/tx/DOGE/{txn_ident}')
  return [out['spent']['txid'] for out in json.loads(r.text)['data']['outputs']]

def get_op_return(txn_ident):
  import requests
  import json
  r = requests.get(f'https://sochain.com/api/v2/tx/DOGE/{txn_ident}')
  outs=json.loads(r.text)['data']['outputs']
  asm=outs[-1]['script_asm']
  hx=outs[-1]['script_hex'][4:]
  if 'OP_RETURN' in asm:
    return (asm[10:] if len(asm[10:])%2==0 else hx),outs[0]['spent']['txid'] if outs[0]['spent'] else None
  else:
    return (None,outs[0]['spent']['txid'] if outs[0]['spent'] else None)
  #return (asm[10:] if 'OP_RETURN' in asm else None),outs[0]['spent']['txid'] if outs[0]['spent'] else None

def get_op_returns(tx_head,prefix=''):
  import time
  time.sleep(0.25)
  op_ret,next_txn=get_op_return(tx_head)
  if (op_ret and next_txn):
    return get_op_returns(next_txn,prefix+op_ret)
  if op_ret==None:
    return prefix
  else:
    return prefix+op_ret

def read_cadenas(txn_ident):
  datalist=[get_op_returns(txn) for txn in get_output_spend_txns(txn_ident)]
  return datalist[0],b''.join([bytes.fromhex(x) for x in datalist[1:] ])

def get_txn_pub(txn_ident):
  import requests
  import json
  r = requests.get(f'https://sochain.com/api/v2/tx/DOGE/{txn_ident}')
  ins=json.loads(r.text)['data']['inputs']
  publica=ins[0]['script_asm'][-128:]
  return publica

def read_image_data(hex_header,image_bytes):
	C={0:1,1:3}[int(hex_header[12:14],16)]
	L=int(hex_header[14:18],16)
	W=int(hex_header[18:22],16)
	B=int(hex_header[22:24],16)
	print(C,L,W,B)
	sparkle_bits=message_2_bit_array(image_bytes,mode=None)
	spark_array=bitarray2imgarr(sparkle_bits,imgshape=(W,L),bit=B,color=C).squeeze()
	return spark_array

def array_dec_from_txn(txn_ident,prvKey_input,index_key):
	hex_header,enc_bytes=read_cadenas(txn_ident)
	N_keys=int(hex_header[24:26])
	Zipkeys=[enc_bytes[i*64:i*64+64] for i in range(N_keys) ]
	Zipdata=enc_bytes[N_keys*64:]
	Txn_pub=eth_keys.keys.PublicKey(bytes.fromhex(get_txn_pub(txn_ident)))
	Shared_key=shared_key(prvKey_input,Txn_pub)
	Ses_key=ecies.aes_decrypt(Shared_key,Zipkeys[index_key])
	Data=ecies.aes_decrypt(Ses_key,Zipdata)
	return hex_header,read_image_data(hex_header,Data)



def only_conf(utxos):
    return [utxo for utxo in utxos
            if doge.fetchtx(utxo['output'].split(':')[0])['confirmations']>0]


def save_privkey(privkey,privkey_filepath,password=None):
    if password==None:
        while True:
                password = getpass.getpass("Input password for encrypting keyfile: ")
                password_2 = getpass.getpass("Repeat password for encrypting keyfile: ")
                if password==password_2:
                    print('\nPasswords match...')
                    break
                else:
                    print('\nPasswords do not match...')
    encrypted_bytes=ecies.aes_encrypt(key=hashlib.sha256(password.encode()).digest(),
                                      plain_text=privkey.to_bytes())
    open(privkey_filepath,'wb').write(encrypted_bytes)
    print(f'Password protected file written to {privkey_filepath} containing {encrypted_bytes.hex()}')
    
def save_pubkey(pubkey,pubkey_filepath):
    open(pubkey_filepath,'wb').write(pubkey.to_bytes())
    print(f'File written to {pubkey_filepath} containing {pubkey.to_bytes().hex()}')
    
def save_addr(addr,addr_filepath):
    open(addr_filepath,'wb').write(addr.encode())
    print(f'Address written to {addr_filepath} containing {addr}')

def make_qr(data,image_path=None):
    qr = qrcode.QRCode(version=1,box_size=5,border=2)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill='black', back_color='white')
    if image_path!=None:
        img.save(image_path)
    return img
    
def gen_save_keys_addr(basename_filepath,password=None,coin='Doge'):
    if os.path.isfile(basename_filepath+'_prv.enc'):
        privkey2save=import_privKey(basename_filepath+'_prv.enc',password)
    else:
        privkey2save = ecies.utils.generate_eth_key()
    pubkey2save = privkey2save.public_key    
    save_privkey(privkey2save,basename_filepath+'_prv.enc',password=password)
    save_pubkey(pubkey2save,basename_filepath+'_pub.bin')
    if coin[0].lower()=='d':
      doge = cryptos.Doge()
    else:
      doge = cryptos.Bitcoin()
    addr2save=doge.pubtoaddr('04'+pubkey2save.to_bytes().hex())
    save_addr(addr2save,basename_filepath+'_addr.bin')
    return make_qr(addr2save,basename_filepath+'_addr.png')



def import_privKey(privkey_filepath,password=None):
    if password==None:
        password = getpass.getpass("Input password for decrypting keyfile: ")
    password=password.encode()
    f=open(privkey_filepath,'rb')
    decrypted_bytes=ecies.aes_decrypt(key=hashlib.sha256(password).digest(),cipher_text=f.read())
    privKey=eth_keys.keys.PrivateKey(decrypted_bytes)
    return privKey

def import_pubKey(pubkey_filepath):
    f=open(pubkey_filepath,'rb')
    privKey=eth_keys.keys.PublicKey(f.read())
    return privKey

def import_addr(addr_filepath):
    return open(addr_filepath,'rb').read().decode()

def grey_imgarr(imgarr):
  return imgarr[:,:,:3].mean(axis=2).astype('uint8')

def message_2_bit_array(message,mode=None):
    '''This function takes in a message as string, bytestring or hextring.
    If hexstring input the set mode='hex' '''
    if type(message)==bytes:
        hex_str=message.hex()
    elif (type(message)==str):
        if mode not in ('hex','hexstring'):
            hex_str=message.encode().hex()
        else:
            hex_str=message
    else:
        print('fix the input and mode')
        return None
    
    num=int('0x'+hex_str,base=16)
    byte_len=(len(hex_str)+1)//2
    bit_len=byte_len*8
    bin_str=bin(num)
    bit_list=[int(bit) for bit in bin_str[2:]]
    bit_list=[0]*(bit_len-len(bit_list))+bit_list
    bit_array=np.array(bit_list,dtype='uint8')
    return bit_array

def bit_array_2_byte_str(bit_array):
    '''Convert bit array to a bytestring'''
    bit_list=[ str(bit) for bit in bit_array]
    bin_str='0b'+(''.join(bit_list))
    num=int(bin_str,base=2)
    return num.to_bytes(len(bit_array)//8,'big')

def bit_array_2_hex_str(bit_array):  
    '''Convert a bit array to a hexstring'''
    return bit_array_2_byte_str(bit_array).hex()

def bit_array_2_str(bit_array,encoding='utf-8'):
    '''Convert a bit array to a string'''
    return bit_array_2_byte_str(bit_array).decode(encoding)

def int2bitarray(x,bit=8):
  return message_2_bit_array(hex(x)[2:],mode='hex')[:bit]

def bitarray2int(b_arr):
  ln=b_arr.shape[0]
  scales=(2**np.arange(7,-1,-1))[:ln]
  return (b_arr*scales).sum()

def imgarr2bitarray(imgarr,bit=8):
  return np.array([ int2bitarray(it,bit) for it in imgarr.reshape(-1)]).reshape(-1)

def bitarray2imgarr(barrs,imgshape=(16,16),bit=2,color=1):
  lns=len(barrs.reshape(-1))
  #Bs=barrs.reshape(*imgshape,bit)
  intlst=[ bitarray2int(barrs.reshape(-1)[i:i+bit]) for i in range(0,lns,bit) ]
  intarr=np.array(intlst).reshape(*imgshape,color).astype('uint8')
  return intarr
 
def bitarray2imgarr_scale(barrs,imgshape=(16,16),bit=2,color=1):
  lns=len(barrs.reshape(-1))
  #Bs=barrs.reshape(*imgshape,bit)
  intlst=[ bitarray2int_scale(barrs.reshape(-1)[i:i+bit]) for i in range(0,lns,bit) ]
  intarr=np.array(intlst).reshape(*imgshape,color).astype('uint8')
  return intarr

class bitimage():

  def __init__(self,imgpath,dims=(16,16),bit=2,color=1):
    from PIL import Image
    self.color=color
    self.bit=bit
    self.dims=list(dims)
    self.img_og=Image.open(imgpath)
    self.img_resize=self.img_og.resize(dims)
    self.grey=grey_imgarr(np.array(self.img_resize))
    self.img_grey=Image.fromarray(self.grey)
    self.bitarray=imgarr2bitarray(self.grey,bit)
    self.bitarray_color=imgarr2bitarray(np.array(self.img_resize)[:,:,:color],bit)
    self.newimg=Image.fromarray(bitarray2imgarr(self.bitarray,imgshape=dims[::-1],bit=bit,color=1).squeeze())
    self.newimg_color=Image.fromarray(bitarray2imgarr(self.bitarray_color,imgshape=dims[::-1],bit=bit,color=3).squeeze())
    self.bytestring=bit_array_2_byte_str(self.bitarray)
    self.bytestring_color=bit_array_2_byte_str(self.bitarray_color)

def shared_key(prvKey,pubKey):
  cc_prvKey=coincurve.PrivateKey(prvKey.to_bytes())
  cc_pubKey= coincurve.PublicKey( pubKey.to_compressed_bytes() )
  return HKDF(cc_pubKey.multiply(cc_prvKey.secret).format(), AES_KEY_BYTES_LEN, b"", SHA256)
