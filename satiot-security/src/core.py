"""P1 research protocol. Single-threaded, in-memory, trusted-endpoint scope."""
from __future__ import annotations
import hashlib, hmac, math, random, secrets, struct, time
from dataclasses import dataclass
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

TAG_LEN=16
VERSION=1
UPLINK=0

# Object fields are validated before encoding or cryptographic state changes.
def uint(value, bits):
    if type(value) is not int or not 0 <= value < 2**bits:
        raise ValueError('MALFORMED_INTEGER')

def did_bytes(did):
    if not isinstance(did, str): raise ValueError('MALFORMED_DID')
    try: data=did.encode('ascii')
    except UnicodeEncodeError: raise ValueError('MALFORMED_DID') from None
    if not 1 <= len(data) <= 255: raise ValueError('MALFORMED_DID')
    return data

def fixed(data, size):
    if not isinstance(data, bytes) or len(data)!=size:
        raise ValueError('MALFORMED_LENGTH')


def hkdf(ikm: bytes, info: bytes, salt: bytes|None=None, length: int=32)->bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)

def mac(key: bytes, data: bytes)->bytes:
    return hmac.new(key,data,hashlib.sha256).digest()[:TAG_LEN]

def join_key(root: bytes, did: str)->bytes:
    return hkdf(root,b"SATIOT|JOIN|"+did.encode())

def session_material(root: bytes, did: str, nd: bytes, ns: bytes, sid: int):
    ks=hkdf(root,b"SATIOT|SESSION|"+did.encode()+sid.to_bytes(8,'big'),salt=nd+ns)
    return {
        'k_up': hkdf(ks,b'SATIOT|UP|'+did.encode()+sid.to_bytes(8,'big')),
        'nonce_prefix': hkdf(ks,b'SATIOT|NONCE|'+did.encode()+sid.to_bytes(8,'big'),length=4),
    }

def nonce(prefix: bytes, seq: int)->bytes:
    return prefix+seq.to_bytes(8,'big')

@dataclass
class JoinInit:
    did:str; epoch:int; nd:bytes; tag:bytes=b''
    def unsigned(self):
        d=did_bytes(self.did); uint(self.epoch,32); fixed(self.nd,16)
        return bytes([VERSION,len(d)])+d+struct.pack('>I',self.epoch)+self.nd
    def wire(self):
        fixed(self.tag,TAG_LEN); return self.unsigned()+self.tag

@dataclass
class JoinAccept:
    did:str; sid:int; nd:bytes; ns:bytes; tag:bytes=b''
    def unsigned(self):
        d=did_bytes(self.did); uint(self.sid,64); fixed(self.nd,16); fixed(self.ns,16)
        return bytes([VERSION,len(d)])+d+struct.pack('>Q',self.sid)+self.nd+self.ns
    def wire(self):
        fixed(self.tag,TAG_LEN); return self.unsigned()+self.tag

@dataclass
class Protected:
    did:str; sid:int; seq:int; mtype:int; ciphertext:bytes; tag:bytes
    def aad(self):
        d=did_bytes(self.did); uint(self.sid,64); uint(self.seq,64); uint(self.mtype,8)
        return bytes([VERSION,len(d)])+d+struct.pack('>QQBB',self.sid,self.seq,UPLINK,self.mtype)
    def wire(self):
        fixed(self.tag,TAG_LEN)
        if not isinstance(self.ciphertext,bytes): raise ValueError('MALFORMED_CIPHERTEXT')
        uint(len(self.ciphertext),16)
        return self.aad()+struct.pack('>H',len(self.ciphertext))+self.ciphertext+self.tag

class ReplayWindow:
    def __init__(self, size:int):
        uint(size,32)
        self.size=size; self.highest=-1; self.seen=set()
    def check(self, seq:int)->bool:
        if self.size<=0:
            return seq>self.highest
        if self.highest>=0 and seq <= self.highest-self.size:
            return False
        return seq not in self.seen
    def commit(self, seq:int):
        if self.size<=0:
            self.highest=max(self.highest,seq); return
        self.seen.add(seq); self.highest=max(self.highest,seq)
        cutoff=self.highest-self.size
        self.seen={s for s in self.seen if s>cutoff}

class EndDevice:
    def __init__(self,did='ED0001',root=None,epoch=1):
        did_bytes(did); uint(epoch,32)
        self.did=did; self.root=secrets.token_bytes(32) if root is None else root; self.epoch=epoch
        fixed(self.root,32)
        self.pending=None; self.sid=None; self.keys=None; self.seq=0
    def join_init(self):
        nd=secrets.token_bytes(16); self.pending=nd
        j=JoinInit(self.did,self.epoch,nd)
        j.tag=mac(join_key(self.root,self.did),j.unsigned()); return j
    def accept(self,ja:JoinAccept):
        ja.wire()
        if ja.did!=self.did: raise ValueError('WRONG_DEVICE')
        if self.pending is None or self.pending!=ja.nd: raise ValueError('STALE_JOIN')
        if not hmac.compare_digest(mac(join_key(self.root,self.did),ja.unsigned()),ja.tag): raise ValueError('INVALID_MAC')
        self.sid=ja.sid; self.keys=session_material(self.root,self.did,ja.nd,ja.ns,ja.sid); self.seq=0; self.pending=None
    def protect(self,payload:bytes,mtype=1):
        if self.sid is None: raise ValueError('NO_SESSION')
        if not isinstance(payload,bytes) or len(payload)>65535: raise ValueError('MALFORMED_PAYLOAD')
        if self.seq>=2**64: raise ValueError('COUNTER_EXHAUSTED')
        uint(self.seq,64); uint(mtype,8)
        seq=self.seq
        hdr=Protected(self.did,self.sid,seq,mtype,b'',b'')
        enc=AESGCM(self.keys['k_up']).encrypt(nonce(self.keys['nonce_prefix'],seq),payload,hdr.aad())
        self.seq+=1
        return Protected(self.did,self.sid,seq,mtype,enc[:-16],enc[-16:])
    def invalidate(self): self.sid=None; self.keys=None; self.seq=0; self.pending=None

class KMS:
    def __init__(self):
        self.db={}; self.revoked=set(); self.issued=set()
    def register(self,ed:EndDevice): self.db[ed.did]=(ed.root,ed.epoch)
    def revoke(self,did:str): self.revoked.add(did)
    def process(self,ji:JoinInit):
        ji.wire()
        if ji.did not in self.db: raise ValueError('UNKNOWN_DEVICE')
        if ji.did in self.revoked: raise ValueError('REVOKED_DEVICE')
        root,epoch=self.db[ji.did]
        if epoch!=ji.epoch: raise ValueError('STALE_EPOCH')
        if not hmac.compare_digest(mac(join_key(root,ji.did),ji.unsigned()),ji.tag): raise ValueError('INVALID_MAC')
        ns=secrets.token_bytes(16)
        for _ in range(16):
            sid=secrets.randbits(64)
            if (ji.did,sid) not in self.issued: break
        else: raise ValueError('SID_EXHAUSTED')
        self.issued.add((ji.did,sid))
        ja=JoinAccept(ji.did,sid,ji.nd,ns)
        ja.tag=mac(join_key(root,ji.did),ja.unsigned())
        return ja, session_material(root,ji.did,ji.nd,ns,sid)

class ApplicationServer:
    def __init__(self,window_size=0): self.sessions={}; self.window_size=window_size
    def install(self,did,sid,keys):
        did_bytes(did); uint(sid,64)
        fixed(keys['k_up'],32); fixed(keys['nonce_prefix'],4)
        existing=self.sessions.get((did,sid))
        if existing is not None:
            if existing[0]!=keys: raise ValueError('CONFLICTING_SESSION')
            return  # Idempotent installation preserves the existing replay window.
        self.sessions[(did,sid)]=(dict(keys),ReplayWindow(self.window_size))
    def retire_device_sessions(self,did,except_sid=None):
        for key in list(self.sessions):
            if key[0]==did and key[1]!=except_sid: self.sessions.pop(key)
    def revoke_session(self,did,sid): self.sessions.pop((did,sid),None)
    def receive(self,m:Protected):
        try: m.wire()
        except (ValueError,TypeError,AttributeError): return False,'MALFORMED',None
        ent=self.sessions.get((m.did,m.sid))
        if ent is None:return False,'UNKNOWN_SESSION',None
        keys,rw=ent
        if not rw.check(m.seq):return False,'REPLAY',None
        try: p=AESGCM(keys['k_up']).decrypt(nonce(keys['nonce_prefix'],m.seq),m.ciphertext+m.tag,m.aad())
        except InvalidTag:return False,'AUTH_FAILURE',None
        rw.commit(m.seq); return True,'ACCEPT',p

class Relay:
    def __init__(self,delay_ms=0,jitter_ms=0,loss=0,seed=1):
        self.delay_ms=delay_ms; self.jitter_ms=jitter_ms; self.loss=loss; self.r=random.Random(seed)
    def latency(self): return max(0,self.delay_ms+self.r.uniform(-self.jitter_ms,self.jitter_ms))
    def deliver(self,obj):
        d=self.latency()
        if d: time.sleep(d/1000)
        if self.r.random()<self.loss:return None
        return obj

class ContactWindowRelay(Relay):
    def __init__(self, available_ms:int, unavailable_ms:int, start_available=True, **kwargs):
        super().__init__(**kwargs)
        if available_ms<0 or unavailable_ms<0: raise ValueError('NEGATIVE_CONTACT')
        self.available_ms=available_ms; self.unavailable_ms=unavailable_ms; self.start_available=start_available
        self.virtual_ms=0.0
    def remaining_contact(self):
        cycle=self.available_ms+self.unavailable_ms
        if self.available_ms<=0: return 0.0
        if self.unavailable_ms<=0: return float('inf')
        phase=self.virtual_ms % cycle
        if self.start_available:
            return max(0.0,self.available_ms-phase) if phase<self.available_ms else 0.0
        return cycle-phase if phase>=self.unavailable_ms else 0.0
    def is_available(self): return self.remaining_contact()>0
    def advance(self,ms:float):
        if ms<0: raise ValueError('NEGATIVE_TIME')
        self.virtual_ms += ms
    def deliver(self,obj):
        remaining=self.remaining_contact()
        if remaining<=0: return None
        duration=self.latency()
        self.virtual_ms += duration
        # A traversal must complete within the same continuous available interval.
        # Completion exactly at its closing boundary is permitted; new starts are not.
        if duration>remaining or self.r.random()<self.loss: return None
        return obj

def establish(ed,kms,app,relay=None,retire_previous=False):
    ji=ed.join_init(); ji2=relay.deliver(ji) if relay else ji
    if ji2 is None:return False,'JOIN_INIT_DROPPED'
    ja,keys=kms.process(ji2); ja2=relay.deliver(ja) if relay else ja
    if ja2 is None:return False,'JOIN_ACCEPT_DROPPED'
    app.install(ed.did,ja.sid,keys); ed.accept(ja2)
    if retire_previous: app.retire_device_sessions(ed.did,except_sid=ja.sid)
    return True,'ACCEPT'

# LoRa PHY time-on-air calculation based on the standard LoRa symbol-time formula.
def lora_airtime_ms(phy_payload_bytes:int,sf:int=7,bw_hz:int=125000,cr:int=1,preamble:int=8,explicit_header:bool=True,crc:bool=True,low_data_rate_opt:bool|None=None):
    if low_data_rate_opt is None:
        low_data_rate_opt = (sf>=11 and bw_hz==125000)
    tsym=(2**sf)/bw_hz
    tpreamble=(preamble+4.25)*tsym
    ih=0 if explicit_header else 1
    crc_i=1 if crc else 0
    de=1 if low_data_rate_opt else 0
    numerator=8*phy_payload_bytes-4*sf+28+16*crc_i-20*ih
    denom=4*(sf-2*de)
    payload_sym=8+max(math.ceil(numerator/denom)*(cr+4),0)
    return (tpreamble+payload_sym*tsym)*1000

def lorawan_packetise(frm_payload_bytes:int,max_frm_payload_bytes:int):
    return math.ceil(frm_payload_bytes/max_frm_payload_bytes) if frm_payload_bytes else 1


def decode_wire(data: bytes, kind: str):
    """Strict decoder for the specified application-security representation.

    Message kind is supplied by the caller/transport. No radio stack is implied.
    """
    try:
        if not isinstance(data,bytes) or len(data)<3 or data[0]!=VERSION:
            raise ValueError('MALFORMED_WIRE')
        n=data[1]; end=2+n
        did=data[2:end].decode('ascii'); did_bytes(did)
        tail=data[end:]
        if kind=='join_init':
            if len(tail)!=36: raise ValueError('MALFORMED_WIRE')
            obj=JoinInit(did,int.from_bytes(tail[:4],'big'),tail[4:20],tail[20:])
        elif kind=='join_accept':
            if len(tail)!=56: raise ValueError('MALFORMED_WIRE')
            obj=JoinAccept(did,int.from_bytes(tail[:8],'big'),tail[8:24],tail[24:40],tail[40:])
        elif kind=='protected':
            if len(tail)<36 or tail[16]!=UPLINK: raise ValueError('MALFORMED_WIRE')
            length=int.from_bytes(tail[18:20],'big')
            if len(tail)!=36+length: raise ValueError('MALFORMED_WIRE')
            obj=Protected(did,int.from_bytes(tail[:8],'big'),int.from_bytes(tail[8:16],'big'),tail[17],tail[20:20+length],tail[20+length:])
        else: raise ValueError('UNKNOWN_KIND')
        if obj.wire()!=data: raise ValueError('MALFORMED_WIRE')
        return obj
    except (UnicodeError,IndexError,TypeError,struct.error):
        raise ValueError('MALFORMED_WIRE') from None
