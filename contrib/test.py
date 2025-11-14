import sys
import time
import hashlib
from textwrap import wrap

from electrum_dash.transaction import Transaction


# ---------- Utilities ----------

def txid_from_raw(raw_hex: str) -> str:
    """Compute txid (little-endian hex) directly from raw hex."""
    raw_hex = raw_hex.strip().lower()
    b = bytes.fromhex(raw_hex)
    h = hashlib.sha256(hashlib.sha256(b).digest()).digest()[::-1].hex()
    return h

def hex_preview(h: str, width: int = 64) -> str:
    """Pretty wrap hex string for better readability."""
    return "\n".join(wrap(h, width))

def first_hex_diff(a: str, b: str) -> int:
    """Return the first differing nibble index between two hex strings, or -1 if equal."""
    n = min(len(a), len(b))
    for i in range(n):
        if a[i] != b[i]:
            return i
    if len(a) != len(b):
        return n
    return -1

def mark_hex_mismatch(a: str, b: str, context: int = 32) -> str:
    """Render a short diff context around the first mismatch between two hex strings."""
    i = first_hex_diff(a, b)
    if i < 0:
        return "No difference."
    start = max(0, i - context)
    end   = min(max(len(a), len(b)), i + context)
    seg_a = a[start:end]
    seg_b = b[start:end]
    caret = " " * (i - start) + "^"
    return f"Index (nibble) {i}:\nA: {seg_a}\nB: {seg_b}\n   {caret}"

def safe_deserialize(raw_hex: str):
    """Deserialize a transaction, capturing exceptions and basic timings."""
    t0 = time.time()
    tx = Transaction(raw_hex)
    try:
        tx.deserialize()
        ok = True
        err = None
    except Exception as e:
        ok = False
        err = e
    dt = (time.time() - t0) * 1000.0
    return ok, tx, err, dt

def to_hex_maybe(x) -> str:
    """Return hex string from either bytes or str hex."""
    if isinstance(x, (bytes, bytearray)):
        return x.hex()
    if isinstance(x, str):
        return x
    raise TypeError(f"Unsupported type for hex conversion: {type(x)}")

def round_trip_hex(tx: Transaction) -> str:
    """Serialize back to hex (full tx, not just payload)."""
    out = tx.serialize()
    return to_hex_maybe(out)

def detect_version_type_from_raw(raw_hex: str):
    """Read first 4 bytes as little-endian int32 and split into (base, type)."""
    b = bytes.fromhex(raw_hex[:8])  # first 4 bytes
    n = int.from_bytes(b, "little", signed=True)  # version-with-type
    base = n & 0xFFFF
    tx_type = (n >> 16) & 0xFFFF
    return n, base, tx_type


# ---------- Pretty logger helpers ----------

def log_header(title: str):
    print("\n" + "="*80)
    print(f"🧪 {title}")
    print("="*80)

def log_ok(msg: str):
    print(f"✅ {msg}")

def log_warn(msg: str):
    print(f"⚠️  {msg}")

def log_err(msg: str):
    print(f"❌ {msg}")

def log_info(msg: str):
    print(f"ℹ️  {msg}")


# ---------- Test Runner ----------

def test_one(name: str, raw_hex: str):
    log_header(name)

    # Expected txid from raw
    exp_txid = txid_from_raw(raw_hex)
    log_info(f"Expected txid: {exp_txid}")

    # Show combined version/type from RAW (more reliable than object sometimes)
    try:
        nver, base, ttype = detect_version_type_from_raw(raw_hex)
        log_info(f"nVersionWithType (raw) = 0x{nver:08x}  -> base={base}, type={ttype}")
    except Exception as e:
        log_warn(f"Cannot detect version/type from raw: {e!r}")

    # Deserialize
    ok, tx, err, dt_ms = safe_deserialize(raw_hex)
    if not ok:
        log_err(f"Deserialize failed in {dt_ms:.2f} ms: {err!r}")
        print("Raw (head):")
        print(hex_preview(raw_hex[:256]))
        return
    log_ok(f"Deserialized in {dt_ms:.2f} ms")

    # txid() from object
    try:
        got_txid = tx.txid()
        if got_txid == exp_txid:
            log_ok(f"txid() matches expected: {got_txid}")
        else:
            log_warn("txid() mismatch!\n"
                     f"  expected: {exp_txid}\n"
                     f"       got: {got_txid}\n"
                     "  HINT: check nVersionWithType serialization and extraPayload signature encoding.")
    except Exception as e:
        log_warn(f"tx.txid() raised: {e!r}. Using raw-based txid only.")

    # extraPayload preview (object may store bytes or a formatted string)
    try:
        ep = tx.extra_payload
        if isinstance(ep, (bytes, bytearray)):
            log_info(f"extraPayload bytes: {len(ep)}")
            print("extraPayload (preview):")
            print(hex_preview(ep.hex()[:512]))
        else:
            log_info("extraPayload is a parsed object/string:")
            print(str(ep))
    except Exception as e:
        log_warn(f"Cannot preview extra_payload: {e!r}")

    # Round-trip serialization and compare with raw
    try:
        t0 = time.time()
        rt_hex = round_trip_hex(tx)
        dt2 = (time.time() - t0) * 1000.0
        if rt_hex == raw_hex:
            log_ok(f"Round-trip OK (serialize==raw) in {dt2:.2f} ms")
        else:
            log_warn(f"Round-trip mismatch in {dt2:.2f} ms")
            print(mark_hex_mismatch(raw_hex, rt_hex))
            # Compute txid of reserialized and show
            try:
                rt_txid = txid_from_raw(rt_hex)
                log_info(f"txid(reserialized): {rt_txid}")
            except Exception as e:
                log_warn(f"Cannot compute txid(reserialized): {e!r}")
    except Exception as e:
        log_err(f"Serialization failed: {e!r}")

    print("-"*80)


if __name__ == "__main__":
    # 1) ProRegTx
    raw1 = "03000100018552d77f66e16bee7a62267f54b2e357adb93802948718137abba3d36ac8b3a7000000006a4730440220530f046b044a47f40852514cd0f233601ac3d19b91ab6073ae8ccf9473ee56360220016c8d8572ba3d82bca8a9c2959a5184b0145dde7dc4b713ebad428b012ecbbd012103250bbf397268d69bcf80c750e2bec76a1b1f73492f7e2ce9d830ea5a7c965f56feffffff010adff505000000001976a914d4a82009b30cfa6dbd9e5b6e30e2990ac2318bff88ac00000000fd2a01020001000000ca1dd5c2d7f5beff73f45829cc69fab06a506c8b83109088e6d1e8b5b12da8800100000000000000000000000000ffff6dde3f464e1f95ee38f69bfb5f2dbdaf6c5e2b7eb8b41ea998cd83962d0e4a4d55aac178afe84b38a052e11fe5ab66bda15db460e5e8a664f21932608bd3b467712dd6eeef073fb119a795ee38f69bfb5f2dbdaf6c5e2b7eb8b41ea998cd00001976a914d4a82009b30cfa6dbd9e5b6e30e2990ac2318bff88ac75868428683e631bd8a9813b6e08e1197a1842023b355f3febc58ed19e567133f1d50a7dea6db5fbde482b4e2838cce517a59dac308fa30541204aa6a509a63fc38787e3b36d83ad1801e3f0a989a52e6e9818882d070442672c3bb300e0a54ca69afdd7f86a0b019d771b4e0f4397c149db9691aa4be5a8d80f"
    test_one("ProRegTx", raw1)

    # 2) ProUpServTx
    raw2 = "0300020001a2459ab64c7e57d839d7139b3eca65e86a41dd973f973198673e17a0ec54c574020000006a47304402204a53463aac9e455b921f217d016d4abe511ef68d5f7cef913f0abc0df2ddae6f02206f90984f4aa4c570e092390d3ef62e8053292c5344df078c0eeffe11b4cb45ea012103250bbf397268d69bcf80c750e2bec76a1b1f73492f7e2ce9d830ea5a7c965f56feffffff014c22b707000000001976a914d4a82009b30cfa6dbd9e5b6e30e2990ac2318bff88ac00000000cf020001002d677437e23ac3772cb1f661578586b3f2c25a3d68fb48d9e1f152f9a3eeb03600000000000000000000ffff5d154cb94e1f008c4e81657bad4739c8943e787bb1324de46a4c13426283560dbb5abd4e8454cac985e8067fdd5c2126853e9577fcb32775cbebda308fa305a34c4b8a3e1c8eae6bc82a6ab28742e180b9a996cbf887ea596ef2b5ee0cb6fb3b0ef5dc5e2107179789ba76c3fa1a9d09523d7d5fb16cb08ccfa330d5072ce17dd39b0e49d850ba1e33941d280dab3f76b3d88b97df3cba0afa4a5d6223107d"
    test_one("ProUpServTx", raw2)
