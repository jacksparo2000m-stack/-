#!/usr/bin/env python3
"""Print an APK's identity (package, versionCode, versionName, signer certificate SHA-256)
and optionally enforce expectations. Pure Python 3, no dependencies.

Usage: apk_identity.py APK [--package ID] [--cert SHA256_HEX] [--min-version-code N]
Exit code 1 (with ::error:: lines for GitHub Actions) if any expectation fails."""
import argparse, hashlib, struct, sys, zipfile


def _manifest_attrs(b):
    """Attributes of the <manifest> element from a binary AndroidManifest.xml."""
    off = struct.unpack('<H', b[2:4])[0]
    strs = []
    while off < len(b):
        ctype, _, csize = struct.unpack('<HHI', b[off:off + 8])
        ch = b[off:off + csize]
        if ctype == 0x0001:  # string pool
            n, _, flags, sstart, _ = struct.unpack('<IIIII', ch[8:28])
            for o in struct.unpack('<%dI' % n, ch[28:28 + 4 * n]):
                p = sstart + o
                if flags & 0x100:  # UTF-8
                    p += 1 if ch[p] < 0x80 else 2
                    ln = ch[p]; p += 1
                    if ln & 0x80:
                        ln = ((ln & 0x7F) << 8) | ch[p]; p += 1
                    strs.append(ch[p:p + ln].decode('utf8', 'replace'))
                else:  # UTF-16
                    ln = struct.unpack('<H', ch[p:p + 2])[0]; p += 2
                    if ln & 0x8000:
                        ln = ((ln & 0x7FFF) << 16) | struct.unpack('<H', ch[p:p + 2])[0]; p += 2
                    strs.append(ch[p:p + 2 * ln].decode('utf-16le', 'replace'))
        elif ctype == 0x0102:  # start element
            name_i = struct.unpack('<i', ch[20:24])[0]
            a_off, _, a_cnt = struct.unpack('<HHH', ch[24:30])
            if strs[name_i] == 'manifest':
                attrs = {}
                for i in range(a_cnt):
                    q = 16 + a_off + i * 20
                    _, an, rv, _, _, dt, dat = struct.unpack('<iiiHBBI', ch[q:q + 20])
                    attrs[strs[an]] = strs[rv] if rv >= 0 else (strs[dat] if dt == 3 else dat)
                return attrs
        off += csize
    raise ValueError('no <manifest> element found')


def _seq(b):
    out, q = [], 0
    while q < len(b):
        n = struct.unpack('<I', b[q:q + 4])[0]
        out.append(b[q + 4:q + 4 + n]); q += 4 + n
    return out


def _signer_certs(d):
    """SHA-256 hex of every signer certificate in the APK Signing Block (v2 or v3)."""
    e = d.rfind(b'PK\x05\x06')
    cd = struct.unpack('<I', d[e + 16:e + 20])[0]
    if d[cd - 16:cd] != b'APK Sig Block 42':
        raise ValueError('no APK Signature Scheme v2/v3 block (unsigned or v1-only)')
    size = struct.unpack('<Q', d[cd - 24:cd - 16])[0]
    pairs, p, blk = d[cd - size:cd - 24], 0, {}
    while p < len(pairs):
        n = struct.unpack('<Q', pairs[p:p + 8])[0]
        blk[struct.unpack('<I', pairs[p + 8:p + 12])[0]] = pairs[p + 12:p + 8 + n]
        p += 8 + n
    v = blk.get(0xF05368C0) or blk.get(0x7109871A)
    if v is None:
        raise ValueError('signing block has no v2/v3 signature')
    return {hashlib.sha256(c).hexdigest() for signer in _seq(_seq(v)[0]) for c in _seq(_seq(_seq(signer)[0])[1])}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('apk'); ap.add_argument('--package'); ap.add_argument('--cert'); ap.add_argument('--min-version-code', type=int)
    a = ap.parse_args()
    m = _manifest_attrs(zipfile.ZipFile(a.apk).read('AndroidManifest.xml'))
    certs = _signer_certs(open(a.apk, 'rb').read())
    fmt = lambda h: ':'.join(h[i:i + 2] for i in range(0, 64, 2)).upper()
    print('package      :', m.get('package'))
    print('versionCode  :', m.get('versionCode'), '| versionName:', m.get('versionName'))
    print('signer SHA-256:', ', '.join(fmt(c) for c in sorted(certs)))
    bad = []
    if a.package and m.get('package') != a.package:
        bad.append('package is %s, expected %s' % (m.get('package'), a.package))
    if a.cert and certs != {a.cert.replace(':', '').lower()}:
        bad.append('the APK is NOT signed with the expected key (expected %s)' % fmt(a.cert.replace(':', '').lower()))
    if a.min_version_code is not None and not (isinstance(m.get('versionCode'), int) and m['versionCode'] >= a.min_version_code):
        bad.append('versionCode %s is lower than %d' % (m.get('versionCode'), a.min_version_code))
    for b in bad:
        print('::error::' + b)
    sys.exit(1 if bad else 0)


if __name__ == '__main__':
    main()
