#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Dash-Electrum - lightweight Dash client
# Copyright (C) 2018 Dash Developers
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import struct
from collections import namedtuple
from enum import IntEnum
from ipaddress import ip_address, IPv6Address
from bls_py import bls

from .util import bh2u, bfh, pack_varint
from .bitcoin import COIN
from .crypto import sha256d
from .i18n import _

from .blspy_wrapper import BasicSchemeMPL, G1Element, G2Element, PrivateKey

def tx_header_to_tx_type(tx_header_bytes):
    tx_header = struct.unpack('<I', tx_header_bytes)[0]
    tx_type = (tx_header >> 16)
    if tx_type and (tx_header & 0x0000ffff) < 3:
        tx_type = 0
    return tx_type


def serialize_ip(ip):
    if ip.version == 4:
        return b'\x00'*10 + b'\xff'*2 + ip.packed
    else:
        return ip.packed


def service_to_ip_port(service):
    '''Convert str service to ipaddress, port tuple'''
    if ']' in service:                  # IPv6
        ip, port = service.split(']')
        ip = ip[1:]                     # remove opening square bracket
        port = port[1:]                 # remove colon before portnum
    else:                               # IPv4
        ip, port = service.split(':')
    return ip_address(ip), int(port)


def str_ip(ip):
    if type(ip) == IPv6Address and ip.ipv4_mapped:
        return str(ip.ipv4_mapped)
    else:
        return str(ip)


def to_compact_size(size):
    if size < 0:
        raise ValueError('Wroing size arg, must be >= 0')
    elif size < 253:
        return bytes([size])
    elif size < 2**16:
        return b'\xfd' + struct.pack('<H', size)
    elif size < 2**32:
        return b'\xfe' + struct.pack('<I', size)
    else:
        return b'\xff' + struct.pack('<Q', size)


def to_varbytes(_bytes):
    return to_compact_size(len(_bytes)) + _bytes


def read_varbytes(vds):
    return vds.read_bytes(vds.read_compact_size())


def read_outpoint(vds):
    return TxOutPoint.read_vds(vds)


def read_uint16_nbo(vds):
    (i,) = struct.unpack_from('>H', vds.input, vds.read_cursor)
    vds.read_cursor += struct.calcsize('>H')
    return i


class DashTxError(Exception):
    """Thrown when there's a problem with Dash serialize/deserialize"""


class ProTxService (namedtuple('ProTxService', 'ip port')):
    '''Class representing Masternode service'''
    def __str__(self):
        if not self.ip:
            return '%s:%s' % (self.ip, self.port)
        ip = ip_address(self.ip)
        if ip.version == 4:
            return '%s:%s' % (self.ip, self.port)
        else:
            return '[%s]:%s' % (self.ip, self.port)

    def _asdict(self):
        return {'ip': self.ip, 'port': self.port}


# https://dash-docs.github.io/en/developer-reference#outpoint
class TxOutPoint(namedtuple('TxOutPoint', 'hash index')):
    '''Class representing tx input outpoint'''
    def __str__(self):
        d = self._asdict()
        return '%s:%s' % (d['hash'], d['index'])

    @property
    def is_null(self):
        return self.hash == b'\x00'*32 and self.index == -1

    @property
    def hash_is_null(self):
        return self.hash == b'\x00'*32

    def serialize(self):
        assert len(self.hash) == 32, \
            f'{len(self.hash)} not 32'
        index = 0xffffffff if self.index == -1 else self.index
        return (
            self.hash +                         # hash
            struct.pack('<I', index)            # index
        )

    @classmethod
    def read_vds(cls, vds):
        o_hash = vds.read_bytes(32)             # hash
        o_index = vds.read_uint32()             # index
        if o_index == 0xffffffff:
            o_index = -1
        return TxOutPoint(o_hash, o_index)

    def _asdict(self):
        return {
            'hash': bh2u(self.hash[::-1]) if self.hash else '',
            'index': self.index,
        }


class CTxIn(namedtuple('CTxIn', 'hash index scriptSig sequence')):
    '''Class representing tx input'''
    def __str__(self):
        return ('CTxIn: %s:%s, scriptSig=%s, sequeence=%s' %
                (bh2u(self.hash[::-1]), self.index,
                 self.scriptSig, self.sequence))

    @classmethod
    def read_vds(cls, vds):
        h = vds.read_bytes(32)                  # hash
        idx = vds.read_uint32()                 # index
        slen = vds.read_compact_size()
        scriptSig = vds.read_bytes(slen)        # scriptSig
        sequence = vds.read_uint32()            # sequence
        return CTxIn(h, idx, scriptSig, sequence)

    def serialize(self):
        assert len(self.hash) == 32, \
            f'{len(self.hash)} not 32'
        return (
            self.hash +                         # hash
            struct.pack('<I', self.index) +     # index
            to_varbytes(self.scriptSig) +       # scriptSig
            struct.pack('<I', self.sequence)    # sequence
        )


class CTxOut(namedtuple('CTxOut', 'value scriptPubKey')):
    '''Class representing tx output'''
    def __str__(self):
        return ('CTxOut: %s:%s, scriptPubKey=%s, sequeence=%s' %
                (bh2u(self.hash[::-1]), self.index,
                 self.scriptPubKey, self.sequence))

    @classmethod
    def read_vds(cls, vds):
        value = vds.read_int64()                # value
        slen = vds.read_compact_size()
        scriptPubKey = vds.read_bytes(slen)     # scriptPubKey
        return CTxOut(value, scriptPubKey)

    def serialize(self):
        return (
            struct.pack('<q', self.value) +     # value
            to_varbytes(self.scriptPubKey)      # scriptPubKey
        )


# https://github.com/dashpay/dips/blob/master/dip-0002-special-transactions.md
class ProTxBase:
    '''Base Class representing DIP2 Special Transactions'''
    def __init__(self, *args, **kwargs):
        if args and not kwargs:
            argsl = list(args)
            for f in self.__slots__:
                setattr(self, f, argsl.pop(0))
        elif kwargs and not args:
            for f in self.__slots__:
                setattr(self, f, kwargs[f])
        else:
            raise ValueError('__init__ works with all args or all kwargs')

    def _asdict(self):
        d = {}
        for f in self.__slots__:
            v = getattr(self, f)
            if isinstance(v, (bytes, bytearray)):
                v = bh2u(v)
            elif isinstance(v, TxOutPoint):
                v = v._asdict()
            d[f] = v
        return d

    @classmethod
    def from_hex_str(cls, tx_type, hex_str):
        if tx_type == STANDARD_TX:
            return b''
        spec_tx_class = SPEC_TX_HANDLERS.get(tx_type)
        if not spec_tx_class:
            return bfh(hex_str)
        from .transaction import BCDataStream
        vds = BCDataStream()
        vds.write(bfh(hex_str))
        read_method = getattr(spec_tx_class, 'read_vds', None)
        if not read_method:
            raise NotImplementedError('%s has no read_vds method' %
                                      spec_tx_class)
        extra_payload = read_method(vds)
        assert isinstance(extra_payload, spec_tx_class)
        return extra_payload

    def to_hex_str(self):
        return bh2u(self.serialize())

    def update_with_tx_data(self, *args, **kwargs):
        '''Update spec tx data based on main tx data inputs/outputs changes'''

    def check_after_tx_prepared(self, *args, **kwargs):
        '''Check spec tx after inputs/outputs is set (can rise error msg)'''

    def update_before_sign(self, *args, **kwargs):
        '''Update spec tx signature when password is accessible'''


class DashProRegTx(ProTxBase):
    '''Class representing DIP3 ProRegTx'''

    __slots__ = ('version type mode collateralOutpoint '
                 'ipAddress port KeyIdOwner PubKeyOperator '
                 'KeyIdVoting operatorReward scriptPayout '
                 'inputsHash payloadSig').split()

    def __init__(self, *args, **kwargs):
        super(DashProRegTx, self).__init__(*args, **kwargs)
        self.payload_sig_msg_part = ''

    def __str__(self):
        return ('ProRegTx Version: %s\n'
                'type: %s, mode: %s\n'
                'collateral: %s\n'
                'ipAddress: %s, port: %s\n'
                'KeyIdOwner: %s\n'
                'PubKeyOperator: %s\n'
                'KeyIdVoting: %s\n'
                'operatorReward: %s\n'
                'scriptPayout: %s\n'
                % (self.version, self.type, self.mode,
                   self.collateralOutpoint,
                   self.ipAddress, self.port,
                   bh2u(self.KeyIdOwner),
                   bh2u(self.PubKeyOperator),
                   bh2u(self.KeyIdVoting),
                   self.operatorReward,
                   bh2u(self.scriptPayout)))

    def serialize(self, full=True):
        assert len(self.KeyIdOwner) == 20, \
            f'{len(self.KeyIdOwner)} not 20'
        assert len(self.PubKeyOperator) == 48, \
            f'{len(self.PubKeyOperator)} not 48'
        assert len(self.KeyIdVoting) == 20, \
            f'{len(self.KeyIdVoting)} not 20'
        assert len(self.inputsHash) == 32, \
            f'{len(self.inputsHash)} not 32'

        if self.version >= 3:
            # ProRegTx v3+ uses netInfo instead of ipAddress/port.
            # Proper netInfo serialization is not implemented here.
            raise ValueError("ProRegTx version >= 3 (netInfo) serialization is not supported yet")

        if self.ipAddress:
            ipAddress = ip_address(self.ipAddress)
            ipAddress = serialize_ip(ipAddress)
            port = self.port
        else:
            ipAddress = b'\x00' * 16
            port = 0

        # ProRegTx payloadSig is CompactSize-prefixed varbytes for all versions.
        payload_sig_bytes = to_varbytes(self.payloadSig) if full else b''

        return (
            struct.pack('<H', self.version) +           # version
            struct.pack('<H', self.type) +              # type
            struct.pack('<H', self.mode) +              # mode
            self.collateralOutpoint.serialize() +       # collateralOutpoint
            ipAddress +                                 # ipAddress (v<3)
            struct.pack('>H', port) +                   # port (v<3, network byte order)
            self.KeyIdOwner +                           # KeyIdOwner
            self.PubKeyOperator +                       # PubKeyOperator
            self.KeyIdVoting +                          # KeyIdVoting
            struct.pack('<H', self.operatorReward) +    # operatorReward
            to_varbytes(self.scriptPayout) +            # scriptPayout
            self.inputsHash +                           # inputsHash
            payload_sig_bytes                           # payloadSig (varbytes)
        )

    @classmethod
    def read_vds(cls, vds):
        version = vds.read_uint16()                     # version
        mn_type = vds.read_uint16()                     # type
        mode = vds.read_uint16()                        # mode
        collateralOutpoint = read_outpoint(vds)         # collateralOutpoint

        if version < 3:
            ip_raw = vds.read_bytes(16)                 # ipAddress (v<3)
            port = read_uint16_nbo(vds)                 # port (v<3)
            ip_obj = ip_address(bytes(ip_raw))
            if ip_obj.ipv4_mapped:
                ipAddress = str(ip_obj.ipv4_mapped)
            else:
                ipAddress = str(ip_obj)
        else:
            # ProRegTx v3+ replaces ipAddress/port and platform fields with netInfo (varbytes).
            # We read it to keep the cursor aligned, but we don't parse it yet.
            _netInfo = read_varbytes(vds)
            ipAddress = ''  # Unknown/unparsed netInfo
            port = 0

        KeyIdOwner = vds.read_bytes(20)                 # KeyIdOwner
        PubKeyOperator = vds.read_bytes(48)             # PubKeyOperator
        KeyIdVoting = vds.read_bytes(20)                # KeyIdVoting
        operatorReward = vds.read_uint16()              # operatorReward
        scriptPayout = read_varbytes(vds)               # scriptPayout
        inputsHash = vds.read_bytes(32)                 # inputsHash

        # ProRegTx payloadSig is CompactSize-prefixed varbytes for all versions.
        payloadSig = read_varbytes(vds)

        return DashProRegTx(
            version, mn_type, mode, collateralOutpoint,
            ipAddress, port, KeyIdOwner, PubKeyOperator,
            KeyIdVoting, operatorReward, scriptPayout,
            inputsHash, payloadSig
        )

    def update_with_tx_data(self, tx):
        if self.collateralOutpoint.hash_is_null:
            found_idx = -1
            for i, o in enumerate(tx.outputs()):
                if o.value == 1000 * COIN:
                    found_idx = i
                    break
            if found_idx >= 0:
                self.collateralOutpoint = TxOutPoint(b'\x00'*32, found_idx)

        outpoints = [TxOutPoint(bfh(i.prevout.txid.hex())[::-1],
                                i.prevout.out_idx)
                     for i in tx.inputs()]
        outpoints_ser = [o.serialize() for o in outpoints]
        self.inputsHash = sha256d(b''.join(outpoints_ser))

    def check_after_tx_prepared(self, tx):
        outpoints = [TxOutPoint(bfh(i.prevout.txid.hex())[::-1],
                                i.prevout.out_idx)
                     for i in tx.inputs()]

        outpoints_str = [str(o) for o in outpoints]
        if str(self.collateralOutpoint) in outpoints_str:
            raise DashTxError('Collateral outpoint used as ProRegTx input.\n'
                              'Please select coins to spend at Coins tab '
                              'of freeze collateral at Addresses tab.')

    def update_before_sign(self, tx, wallet, password):
        if self.payloadSig == b'':
            return
        coins = wallet.get_utxos(domain=None, excluded_addresses=False,
                                 mature_only=True, confirmed_funding_only=True)

        c_hash = bh2u(self.collateralOutpoint.hash[::-1])
        c_index = self.collateralOutpoint.index
        coins = list(filter(lambda x: (x.prevout.txid.hex() == c_hash
                                       and x.prevout.out_idx == c_index),
                            coins))
        if len(coins) == 1:
            coll_address = coins[0].address
            payload_hash = bh2u(sha256d(self.serialize(full=False))[::-1])
            payload_sig_msg = self.payload_sig_msg_part + payload_hash
            self.payloadSig = wallet.sign_message(coll_address,
                                                  payload_sig_msg,
                                                  password)


class DashProUpServTx(ProTxBase):
    '''Class representing DIP3 ProUpServTx'''

    __slots__ = ('version proTxHash ipAddress port '
                 'scriptOperatorPayout inputsHash '
                 'payloadSig mn_type '
                 'platformNodeID platformP2PPort platformHTTPPort'
                 ).split()

    def __str__(self):
        res = (f'ProUpServTx Version: {self.version}\n')
        if getattr(self, 'mn_type', None) is not None:
            res += (f'Masternode type: {self.mn_type}\n')
        res += (
            f'proTxHash: {bh2u(self.proTxHash[::-1])}\n'
            f'ipAddress: {self.ipAddress}, port: {self.port}\n'
        )
        if self.scriptOperatorPayout:
            res += f'scriptOperatorPayout: {bh2u(self.scriptOperatorPayout)}\n'
        if getattr(self, 'mn_type', 0) == 1:
            if getattr(self, 'platformNodeID', b''):
                res += f'platformNodeID: {bh2u(self.platformNodeID)}\n'
            if getattr(self, 'platformP2PPort', None) is not None:
                res += f'platformP2PPort: {self.platformP2PPort}\n'
            if getattr(self, 'platformHTTPPort', None) is not None:
                res += f'platformHTTPPort: {self.platformHTTPPort}\n'
        return res

    def serialize(self, full=True):
        """
        Serialize ProUpServTx extra payload (DIP3 / DIP23).

        Supports both legacy (v1) and current (v2) formats.

        Layout:
          version            (uint16 LE)
          [mn_type]          (uint16 LE)               # only for version >= 2
          proTxHash          (32 bytes, LE)
          ipAddress          (16 bytes, IPv6 mapped, network byte order)
          port               (uint16 BE, "network byte order")
          scriptOperatorPayout (varbytes: CompactSize + script)
          inputsHash         (32 bytes, LE)
          [platformNodeID]   (20 bytes, optional for mn_type == 1)
          [platformP2PPort]  (uint16 BE, optional)
          [platformHTTPPort] (uint16 BE, optional)
          payloadSig:
              - v1: CompactSize + bytes (legacy BLS)
              - v2: raw bytes (90–96), no prefix (basic BLS)
        """
        # --- sanity checks ---
        assert len(self.proTxHash) == 32, f'{len(self.proTxHash)} not 32'
        assert len(self.inputsHash) == 32, f'{len(self.inputsHash)} not 32'

        # Normalize and serialize IP + port
        ip_obj = ip_address(self.ipAddress)
        ip_bytes = serialize_ip(ip_obj)  # always 16 bytes IPv6-mapped
        assert len(ip_bytes) == 16, 'serialized IP must be 16 bytes'
        port_be = struct.pack('>H', self.port)  # network byte order (big-endian)

        # Determine signature serialization
        if full:
            if getattr(self, 'version', 1) < 2:
                # --- Legacy (v1): signature uses CompactSize prefix ---
                payloadSig = to_varbytes(self.payloadSig)
            else:
                # --- v2+: raw signature, no prefix ---
                assert len(self.payloadSig) in (90, 96), \
                    f'Unexpected payloadSig length {len(self.payloadSig)} (expected 90/96)'
                payloadSig = self.payloadSig
        else:
            payloadSig = b''

        # --- Begin writing ---
        serialized = struct.pack('<H', self.version)  # payloadVersion (LE)

        # Add masternode type if present (v2+)
        if getattr(self, 'mn_type', None) is not None:
            serialized += struct.pack('<H', self.mn_type)

        # Common fields
        serialized += (
                self.proTxHash +  # proTxHash
                ip_bytes +  # ipAddress (IPv6 mapped)
                port_be +  # port (BE)
                to_varbytes(self.scriptOperatorPayout or b'') +  # scriptOperatorPayout
                self.inputsHash  # inputsHash
        )

        # --- Optional platform fields (v2 type-1 only) ---
        platformNodeID = getattr(self, 'platformNodeID', b'') or b''
        if platformNodeID:
            # 20-byte NodeID + two BE ports (present only if mn_type == 1)
            assert len(platformNodeID) == 20, 'platformNodeID must be 20 bytes'
            serialized += platformNodeID
            serialized += struct.pack('<H', self.platformP2PPort)  # Discrepancy with documentation. According to the documentation, BE (network byte order), but actually accepts LE.
            serialized += struct.pack('<H', self.platformHTTPPort) # Discrepancy with documentation. According to the documentation, BE (network byte order), but actually accepts LE.

        # --- Append payload signature ---
        serialized += payloadSig

        return serialized

    @classmethod
    def read_vds(cls, vds):
        mn_type = None

        # Defaults for optional platform fields
        platformNodeID = b''
        platformP2PPort = None
        platformHTTPPort = None

        version = vds.read_uint16()  # version
        if version >= 2:
            mn_type = vds.read_uint16()  # TX Type

        proTxHash = vds.read_bytes(32)  # proTxHash
        ipAddress = vds.read_bytes(16)  # ipAddress
        port = read_uint16_nbo(vds)  # port
        scriptOperatorPayout = read_varbytes(vds)  # scriptOperatorPayout
        inputsHash = vds.read_bytes(32)  # inputsHash

        if version >= 2 and mn_type == 1:
            platformNodeID = vds.read_bytes(20)  # 20 bytes
            platformP2PPort = vds.read_uint16()  # 2 bytes LE
            platformHTTPPort = vds.read_uint16()  # 2 bytes LE

        # payloadSig
        if version < 2:
            payloadSig = read_varbytes(vds)
        else:
            remaining = len(vds.input) - vds.read_cursor
            if remaining not in (90, 96):
                raise ValueError(f"Unexpected payloadSig size: {remaining} bytes")
            payloadSig = vds.read_bytes(remaining)

        ipAddress = ip_address(bytes(ipAddress))
        if ipAddress.ipv4_mapped:
            ipAddress = str(ipAddress.ipv4_mapped)
        else:
            ipAddress = str(ipAddress)

        return DashProUpServTx(
            version,
            proTxHash,
            ipAddress,
            port,
            scriptOperatorPayout,
            inputsHash,
            payloadSig,
            mn_type,
            platformNodeID,
            platformP2PPort,
            platformHTTPPort,
        )

    def update_with_tx_data(self, tx):
        outpoints = [TxOutPoint(bfh(i.prevout.txid.hex())[::-1],
                                i.prevout.out_idx)
                     for i in tx.inputs()]
        outpoints_ser = [o.serialize() for o in outpoints]
        self.inputsHash = sha256d(b''.join(outpoints_ser))

    def update_before_sign(self, tx, wallet, password):
        protx_hash = bh2u(self.proTxHash[::-1])  # Get the proTxHash in the required format
        manager = wallet.protx_manager
        bls_privk_bytes = None

        # Find the operator's private key for the given proTxHash
        for mn in manager.mns.values():
            if protx_hash == mn.protx_hash:
                bls_privk_bytes = bfh(mn.bls_privk)  # Convert hex to bytes
                break

        if not bls_privk_bytes:
            raise ValueError("Operator's private key not found for the given proTxHash.")

        # Serialize data without a signature
        serialized_data = self.serialize(full=False)

        if self.version == 1:
            # Version 1: Use legacy BLS scheme
            # Create a private key using the legacy BLS scheme for version 1
            bls_privk = bls.PrivateKey.from_bytes(bls_privk_bytes)

            # Hash the data
            serialized_hash = sha256d(serialized_data)

            # Sign using the legacy BLS scheme
            bls_sig = bls_privk.sign_prehashed(serialized_hash)

            bls_sig_bytes = bls_sig.serialize()

        elif self.version == 2:
            # Version 2: Use the new BLS scheme (BasicSchemeMPL)
            # Create a private key using G2Element for version 2
            bls_privk = PrivateKey.from_bytes(bls_privk_bytes)

            # Hash the data with the key type
            serialized_hash = sha256d(serialized_data)

            # Sign using BasicSchemeMPL
            bls_sig = BasicSchemeMPL.sign(bls_privk, serialized_hash)

            bls_sig_bytes = bls_sig.__bytes__()

        else:
            raise ValueError(f"Unsupported ProUpServTx version: {self.version}")

        self.payloadSig = bls_sig_bytes


class DashProUpRegTx(ProTxBase):
    '''Class representing DIP3 ProUpRegTx'''

    __slots__ = ('version proTxHash mode PubKeyOperator '
                 'KeyIdVoting scriptPayout inputsHash '
                 'payloadSig').split()

    def __str__(self):
        return ('ProUpRegTx Version: %s\n'
                'proTxHash: %s\n'
                'mode: %s\n'
                'PubKeyOperator: %s\n'
                'KeyIdVoting: %s\n'
                'scriptPayout: %s\n'
                % (self.version,
                   bh2u(self.proTxHash[::-1]),
                   self.mode,
                   bh2u(self.PubKeyOperator),
                   bh2u(self.KeyIdVoting),
                   bh2u(self.scriptPayout)))

    def serialize(self, full=True):
        assert len(self.proTxHash) == 32, \
            f'{len(self.proTxHash)} not 32'
        assert len(self.PubKeyOperator) == 48, \
            f'{len(self.PubKeyOperator)} not 48'
        assert len(self.KeyIdVoting) == 20, \
            f'{len(self.KeyIdVoting)} not 20'
        assert len(self.inputsHash) == 32, \
            f'{len(self.inputsHash)} not 32'
        payloadSig = to_varbytes(self.payloadSig) if full else b''
        return (
            struct.pack('<H', self.version) +           # version
            self.proTxHash +                            # proTxHash
            struct.pack('<H', self.mode) +              # mode
            self.PubKeyOperator +                       # PubKeyOperator
            self.KeyIdVoting +                          # KeyIdVoting
            to_varbytes(self.scriptPayout) +            # scriptPayout
            self.inputsHash +                           # inputsHash
            payloadSig                                  # payloadSig
        )

    @classmethod
    def read_vds(cls, vds):
        return DashProUpRegTx(
            vds.read_uint16(),                          # version
            vds.read_bytes(32),                         # proTxHash
            vds.read_uint16(),                          # mode
            vds.read_bytes(48),                         # PubKeyOperator
            vds.read_bytes(20),                         # KeyIdVoting
            read_varbytes(vds),                         # scriptPayout
            vds.read_bytes(32),                         # inputsHash
            read_varbytes(vds)                          # payloadSig
        )

    def update_with_tx_data(self, tx):
        outpoints = [TxOutPoint(bfh(i.prevout.txid.hex())[::-1],
                                i.prevout.out_idx)
                     for i in tx.inputs()]
        outpoints_ser = [o.serialize() for o in outpoints]
        self.inputsHash = sha256d(b''.join(outpoints_ser))

    def update_before_sign(self, tx, wallet, password):
        protx_hash = bh2u(self.proTxHash[::-1])
        owner_addr = None
        for alias, mn in wallet.protx_manager.mns.items():
            if mn.protx_hash == protx_hash:
                owner_addr = mn.owner_addr
        if not owner_addr:
            return
        payload_hash = sha256d(self.serialize(full=False))
        self.payloadSig = wallet.sign_digest(owner_addr, payload_hash,
                                             password)


class RevokeReasons(IntEnum):
    '''DashProUpRevTx revocation reasons'''
    NOT_SPECIFIED = 0
    TERMINATION_OF_SERVICE = 1
    COMPROMISED_KEYS = 2
    CHANGE_OF_KEYS = 3


def revoke_reason_str(reason):
    if reason == RevokeReasons.NOT_SPECIFIED:
        return _('Not Specified')
    elif reason == RevokeReasons.TERMINATION_OF_SERVICE:
        return _('Termination of Service')
    elif reason == RevokeReasons.COMPROMISED_KEYS:
        return _('Compromised Keys')
    elif reason == RevokeReasons.CHANGE_OF_KEYS:
        return _('Change of Keys')
    else:
        return 'Unknown reason'


class DashProUpRevTx(ProTxBase):
    '''Class representing DIP3 ProUpRevTx'''

    __slots__ = ('version proTxHash reason '
                 'inputsHash payloadSig').split()

    def __str__(self):
        return ('ProUpRevTx Version: %s\n'
                'proTxHash: %s\n'
                'reason: %s\n'
                % (self.version,
                   bh2u(self.proTxHash[::-1]),
                   revoke_reason_str(self.reason)))

    def serialize(self, full=True):
        assert len(self.proTxHash) == 32, \
            f'{len(self.proTxHash)} not 32'
        assert len(self.inputsHash) == 32, \
            f'{len(self.inputsHash)} not 32'
        assert len(self.payloadSig) == 96, \
            f'{len(self.payloadSig)} not 96'
        payloadSig = self.payloadSig if full else b''
        return (
            struct.pack('<H', self.version) +           # version
            self.proTxHash +                            # proTxHash
            struct.pack('<H', self.reason) +            # reason
            self.inputsHash +                           # inputsHash
            payloadSig                                  # payloadSig
        )

    @classmethod
    def read_vds(cls, vds):
        return DashProUpRevTx(
            vds.read_uint16(),                          # version
            vds.read_bytes(32),                         # proTxHash
            vds.read_uint16(),                          # reason
            vds.read_bytes(32),                         # inputsHash
            vds.read_bytes(96)                          # payloadSig
        )

    def update_with_tx_data(self, tx):
        outpoints = [TxOutPoint(bfh(i.prevout.txid.hex())[::-1],
                                i.prevout.out_idx)
                     for i in tx.inputs()]
        outpoints_ser = [o.serialize() for o in outpoints]
        self.inputsHash = sha256d(b''.join(outpoints_ser))

    def update_before_sign(self, tx, wallet, password):
        protx_hash = bh2u(self.proTxHash[::-1])
        manager = wallet.protx_manager
        bls_privk_bytes = None
        for mn in manager.mns.values():
            if protx_hash == mn.protx_hash:
                bls_privk_bytes = bfh(mn.bls_privk)
                break
        if not bls_privk_bytes:
            return
        bls_privk = bls.PrivateKey.from_bytes(bls_privk_bytes)
        bls_sig = bls_privk.sign_prehashed(sha256d(self.serialize(full=False)))
        self.payloadSig = bls_sig.serialize()


class DashCbTx(ProTxBase):
    '''Class representing DIP4 coinbase special tx'''

    __slots__ = ('version height merkleRootMNList merkleRootQuorums bestCLHeightDiff bestCLSignature assetLockedAmount').split()

    def __str__(self):
        res = ('CbTx Version: %s\n'
               'height: %s\n'
               'merkleRootMNList: %s\n'
               % (self.version, self.height,
                  bh2u(self.merkleRootMNList[::-1])))
        if self.version > 1:
            res += ('merkleRootQuorums: %s\n' %
                    bh2u(self.merkleRootQuorums[::-1]))
        if self.version > 2:
            res += ('bestCLHeightDiff: %s\n' %
                    self.bestCLHeightDiff)
            res += ('bestCLSignature: %s\n' %
                    bh2u(self.bestCLSignature[::-1]))
            res += ('assetLockedAmount: %s\n' %
                    self.assetLockedAmount)
        return res

    def serialize(self):
        assert len(self.merkleRootMNList) == 32, \
            f'{len(self.merkleRootMNList)} not 32'
        res = (
            struct.pack('<H', self.version) +           # version
            struct.pack('<I', self.height) +            # height
            self.merkleRootMNList                       # merkleRootMNList
        )
        if self.version > 1:
            assert len(self.merkleRootQuorums) == 32, \
                f'{len(self.merkleRootQuorums)} not 32'
            res += self.merkleRootQuorums               # merkleRootMNList
        if self.version > 2:
            res += pack_varint(self.bestCLHeightDiff)   # bestCLHeightDiff
            assert len(self.bestCLSignature) == 96, \
                f'{len(self.bestCLSignature)} not 96'
            res += self.bestCLSignature                 # bestCLSignature
            res += struct.pack('<q', self.assetLockedAmount)  # assetLockedAmount
        return res

    @classmethod
    def read_vds(cls, vds):
        version = vds.read_uint16()
        height = vds.read_uint32()
        merkleRootMNList = vds.read_bytes(32)
        merkleRootQuorums = b''
        bestCLHeightDiff = 0
        bestCLSignature = ""
        assetLockedAmount = 0
        if version > 1:
            merkleRootQuorums = vds.read_bytes(32)
        if version > 2:
            bestCLHeightDiff = vds.read_varint()
            bestCLSignature = vds.read_bytes(96)
            assetLockedAmount = vds.read_uint64()
        return DashCbTx(version, height, merkleRootMNList, merkleRootQuorums,
                        bestCLHeightDiff, bestCLSignature, assetLockedAmount)


class AssetLockTx(ProTxBase):
    '''Class representing AssetLock transaction (type 8)'''

    __slots__ = ('version', 'count', 'creditOutputs')

    def __init__(self, version, count, creditOutputs):
        self.version = version            # version (uint8_t)
        self.count = count                # count (uint8_t)
        self.creditOutputs = creditOutputs  # List of tx outpoint (value, scriptPubKey)

    def __str__(self):
        outputs_str = '\n'.join(
            ['  - Value: {}\n    ScriptPubKey: {}'.format(
                credit_output[0], bh2u(credit_output[1])) for credit_output in self.creditOutputs])
        return ('AssetLockTx\n'
                'Version: {}\n'
                'Count: {}\n'
                'Credit Outputs:\n{}\n'
                .format(
                    self.version,
                    self.count,
                    outputs_str
                ))

    def serialize(self):
        res = b''
        res += struct.pack('<B', self.version)     # version (uint8_t)
        res += struct.pack('<B', self.count)       # count (uint8_t)
        for value, scriptPubKey in self.creditOutputs:
            res += struct.pack('<q', value)        # credit outputs value  (int64)
            res += to_varbytes(scriptPubKey)     # scriptPubKey (as varbytes)
        return res

    @classmethod
    def read_vds(cls, vds):
        version = vds.read_uchar()                   # version (uint8_t)
        count = vds.read_uchar()                     # count (uint8_t)
        creditOutputs = []
        for _ in range(count):
            value = vds.read_int64()                 # credit outputs value (int64)
            scriptPubKey = read_varbytes(vds)        # scriptPubKey as varbytes
            creditOutputs.append((value, scriptPubKey))
        return cls(version, count, creditOutputs)

class AssetUnlockTx(ProTxBase):
    '''Class representing AssetUnlock transaction (type 9)'''

    __slots__ = ('version', 'index', 'fee', 'signHeight', 'quorumHash', 'quorumSig')

    def __init__(self, version, index, fee, signHeight, quorumHash, quorumSig):
        self.version = version              # version (uint8_t)
        self.index = index                  # index (uint64)
        self.fee = fee                      # fee (uint32)
        self.signHeight = signHeight        # sign height (uint32)
        self.quorumHash = quorumHash        # quorumHash (bytes(32))
        self.quorumSig = quorumSig          # quorumSig (bytes(96))

    def __str__(self):
        return ('AssetUnlockTx\n'
                'Version: {}\n'
                'Index: {}\n'
                'Fee: {}\n'
                'Sign Height: {}\n'
                'Quorum Hash: {}\n'
                'Quorum Signature: {}\n'
                .format(
                    self.version,
                    self.index,
                    self.fee,
                    self.signHeight,
                    bh2u(self.quorumHash[::-1]),
                    bh2u(self.quorumSig)
                ))

    def serialize(self):
        res = b''
        res += struct.pack('<B', self.version)     # version (uint8_t)
        res += struct.pack('<Q', self.index)       # index (uint64)
        res += struct.pack('<I', self.fee)         # fee (uint32)
        res += struct.pack('<I', self.signHeight)  # signHeight (uint32)
        res += self.quorumHash                     # quorumHash (32 bytes)
        res += self.quorumSig                      # quorumSig (96 bytes)
        return res

    @classmethod
    def read_vds(cls, vds):
        version = vds.read_uchar()                    # version (uint8_t)
        index = vds.read_uint64()                    # index (uint64)
        fee = vds.read_uint32()                      # fee (uint32)
        signHeight = vds.read_uint32()               # signHeight (uint32)
        quorumHash = vds.read_bytes(32)              # quorumHash (bytes(32))
        quorumSig = vds.read_bytes(96)               # quorumSig (bytes(96))
        return cls(version, index, fee, signHeight, quorumHash, quorumSig)


# Supported Spec Tx types and corresponding handlers mapping
STANDARD_TX = 0
SPEC_PRO_REG_TX = 1
SPEC_PRO_UP_SERV_TX = 2
SPEC_PRO_UP_REG_TX = 3
SPEC_PRO_UP_REV_TX = 4
SPEC_CB_TX = 5
SPEC_ASSETLOCK_TX = 8
SPEC_ASSETUNLOCK_TX = 9


SPEC_TX_HANDLERS = {
    SPEC_PRO_REG_TX: DashProRegTx,
    SPEC_PRO_UP_SERV_TX: DashProUpServTx,
    SPEC_PRO_UP_REG_TX: DashProUpRegTx,
    SPEC_PRO_UP_REV_TX: DashProUpRevTx,
    SPEC_CB_TX: DashCbTx,
    SPEC_ASSETLOCK_TX: AssetLockTx,
    SPEC_ASSETUNLOCK_TX: AssetUnlockTx,
}


# Use DIP2 tx_type to output PrivateSend type in wallet history
class PSTxTypes(IntEnum):
    '''PS Tx types'''
    NEW_DENOMS = 65536
    NEW_COLLATERAL = 65537
    DENOMINATE = 65538
    PAY_COLLATERAL = 65539
    PRIVATESEND = 65540
    PS_MIXING_TXS = 65541
    SPEND_PS_COINS = 65542
    OTHER_PS_COINS = 65543


SPEC_TX_NAMES = {
    STANDARD_TX: 'Standard',
    SPEC_PRO_REG_TX: 'ProRegTx',
    SPEC_PRO_UP_SERV_TX: 'ProUpServTx',
    SPEC_PRO_UP_REG_TX: 'ProUpRegTx',
    SPEC_PRO_UP_REV_TX: 'ProUpRevTx',
    SPEC_CB_TX: 'CbTx',
    SPEC_ASSETLOCK_TX: 'AssetLockTx',
    SPEC_ASSETUNLOCK_TX: 'AssetUnlockTx',

    # as tx_type is uint16, can make PrivateSend types >= 65536
    PSTxTypes.NEW_DENOMS: 'PS New Denoms',
    PSTxTypes.NEW_COLLATERAL: 'PS New Collateral',
    PSTxTypes.DENOMINATE: 'PS Denominate',
    PSTxTypes.PAY_COLLATERAL: 'PS Pay Collateral',
    PSTxTypes.PRIVATESEND: 'PrivateSend',
    PSTxTypes.PS_MIXING_TXS: 'PS Mixing Txs ...',
    PSTxTypes.SPEND_PS_COINS: 'Spend PS Coins',
    PSTxTypes.OTHER_PS_COINS: 'Other PS Coins',
}


def read_extra_payload(vds, tx_type):
    if tx_type:
        extra_payload_size = vds.read_compact_size()
        end = vds.read_cursor + extra_payload_size
        spec_tx_class = SPEC_TX_HANDLERS.get(tx_type)
        if spec_tx_class:
            read_method = getattr(spec_tx_class, 'read_vds', None)
            if not read_method:
                raise NotImplementedError('%s has no read_vds method' %
                                          spec_tx_class)
            extra_payload = read_method(vds)
            assert isinstance(extra_payload, spec_tx_class)
        else:
            raise DashTxError(f'Unkonwn tx type {tx_type}')
        assert vds.read_cursor == end
    else:
        extra_payload = b''
    return extra_payload


def serialize_extra_payload(tx):
    tx_type = tx.tx_type
    if not tx_type:
        raise DashTxError('No special tx type set to serialize')

    extra = tx.extra_payload
    spec_tx_class = SPEC_TX_HANDLERS.get(tx_type)
    if not spec_tx_class:
        assert isinstance(extra, (bytes, bytearray))
        return extra

    if not isinstance(extra, spec_tx_class):
        raise DashTxError('Dash tx_type not conform with extra'
                          ' payload class: %s, %s' % (tx_type, extra))
    return extra.serialize()
