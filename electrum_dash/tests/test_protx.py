import unittest

from electrum_dash.dash_tx import TxOutPoint
from electrum_dash.protx import ProTxMN


def _strip_platform_fields(d: dict) -> dict:
    d = dict(d)
    for k in (
        'platform_node_id',
        'platform_p2p_port',
        'platform_http_port',
        'platform_ed25519_privkey',
        'platform_ed25519_pubkey',
    ):
        d.pop(k, None)
    return d


class ProTxTestCase(unittest.TestCase):

    def test_protxmn(self):
        mn_dict = {
            'alias': 'default',
            'bls_privk': '702ac35f02311c6b3209538c2784c21a'
                         '066d767b53d5a7c69fd677f1949a76a5',
            'collateral': {
                'hash': '0' * 64,
                'index': -1
            },
            'is_operated': True,
            'is_owned': True,
            'mode': 0,
            'op_payout_address': '',
            'op_reward': 0,
            'owner_addr': 'yevc1CQmqyPWJjz1kg9KbnAvov8K3RmaYz',
            'payout_address': 'ygeCXmn4ysXxL1DmUAcmuG5WA6QwNJbr3b',
            'protx_hash': '',
            'pubkey_operator': '012152114d9b7edaa5473c93858f8c11'
                               'fa12b6f8afa37a40ed335407b207f7c8'
                               'caa46092586c369daba06cfda00893ae',
            'service': {
                'ip': '127.0.0.1',
                'port': 9999
            },
            'type': 0,
            'voting_addr': 'yevc1CQmqyPWJjz1kg9KbnAvov8K3RmaYz',
        }

        mn = ProTxMN.from_dict(mn_dict)
        assert mn.alias == 'default'
        assert mn.is_owned is True
        assert mn.is_operated is True
        assert mn.bls_privk == (
            '702ac35f02311c6b3209538c2784c21a'
            '066d767b53d5a7c69fd677f1949a76a5'
        )
        assert mn.type == 0
        assert mn.mode == 0
        assert mn.collateral == TxOutPoint(b'\x00' * 32, -1)
        assert str(mn.service) == '127.0.0.1:9999'
        assert mn.owner_addr == 'yevc1CQmqyPWJjz1kg9KbnAvov8K3RmaYz'
        assert mn.pubkey_operator == (
            '012152114d9b7edaa5473c93858f8c11'
            'fa12b6f8afa37a40ed335407b207f7c8'
            'caa46092586c369daba06cfda00893ae'
        )
        assert mn.voting_addr == 'yevc1CQmqyPWJjz1kg9KbnAvov8K3RmaYz'
        assert mn.op_reward == 0
        assert mn.payout_address == 'ygeCXmn4ysXxL1DmUAcmuG5WA6QwNJbr3b'
        assert mn.op_payout_address == ''
        assert mn.protx_hash == ''

        mn_dict2 = mn.as_dict()
        assert _strip_platform_fields(mn_dict2) == mn_dict

        # Ensure platform fields exist and have sane defaults (backward compatible behavior).
        assert hasattr(mn, 'platform_node_id')
        assert hasattr(mn, 'platform_p2p_port')
        assert hasattr(mn, 'platform_http_port')
        assert hasattr(mn, 'platform_ed25519_privkey')
        assert hasattr(mn, 'platform_ed25519_pubkey')

        assert mn.platform_node_id == ''
        assert isinstance(mn.platform_p2p_port, int)
        assert isinstance(mn.platform_http_port, int)
        assert mn.platform_ed25519_privkey == ''
        assert mn.platform_ed25519_pubkey == ''

    def test_protxmn_evonode_roundtrip(self):
        mn_dict = {
            'alias': 'evonode1',
            'bls_privk': '702ac35f02311c6b3209538c2784c21a'
                         '066d767b53d5a7c69fd677f1949a76a5',
            'collateral': {
                'hash': '0' * 64,
                'index': -1
            },
            'is_operated': True,
            'is_owned': True,
            'mode': 0,
            'op_payout_address': '',
            'op_reward': 0,
            'owner_addr': 'yevc1CQmqyPWJjz1kg9KbnAvov8K3RmaYz',
            'payout_address': 'ygeCXmn4ysXxL1DmUAcmuG5WA6QwNJbr3b',
            'protx_hash': '',
            'pubkey_operator': '012152114d9b7edaa5473c93858f8c11'
                               'fa12b6f8afa37a40ed335407b207f7c8'
                               'caa46092586c369daba06cfda00893ae',
            'service': {
                'ip': '127.0.0.1',
                'port': 9999
            },
            'type': 1,
            'voting_addr': 'yevc1CQmqyPWJjz1kg9KbnAvov8K3RmaYz',
            'platform_node_id': '11' * 20,  # 20 bytes hex (40 chars)
            'platform_p2p_port': 26656,
            'platform_http_port': 443,
            'platform_ed25519_privkey': '',
            'platform_ed25519_pubkey': '',
        }

        mn = ProTxMN.from_dict(mn_dict)
        assert mn.type == 1
        assert mn.platform_node_id == mn_dict['platform_node_id']
        assert mn.platform_p2p_port == mn_dict['platform_p2p_port']
        assert mn.platform_http_port == mn_dict['platform_http_port']
        assert mn.platform_ed25519_privkey == mn_dict['platform_ed25519_privkey']
        assert mn.platform_ed25519_pubkey == mn_dict['platform_ed25519_pubkey']

        mn_dict2 = mn.as_dict()
        assert mn_dict2 == mn_dict