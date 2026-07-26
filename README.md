# macOS 26 APFS FileVault keybags — parser-compatibility notes and the expanded container VEK entry

Byte-level notes on a macOS 26 FileVault APFS keybag, focused on where the two
open-source offline APFS decrypters (libfsapfs, apfs-fuse) can and cannot parse it,
and on one entry — the container keybag's wrapped-VEK entry — whose macOS 26 layout
neither tool currently handles. Written to fill a gap in the public byte-level
record and to give libfsapfs a concrete fix.

> **Scope & intent.** This is interoperability / digital-forensics documentation,
> produced during legitimate offline data-recovery of a disposable macOS virtual
> machine that the author owns and holds the password to. The sample bytes below
> are captured key material (wrapped keys, HMACs, salts) from a throwaway VM that
> is being destroyed and whose login password is the literal string `admin`,
> published here alongside them — so nothing sensitive is disclosed. **No technique
> in this document recovers a volume key from the disk image.** In fact, on the
> guest examined here the password does *not* unlock the volume offline (see
> "Offline unlock is not achieved by this decode").

## Summary

On a macOS 26 FileVault container:

1. **The KEK records' metadata attribute (context tag `[2]`) is 22 bytes**, laid out
   as a 6-byte header + a 16-byte, UUID-shaped value. This layout is **not new** —
   apfs-fuse has modeled it since 2023 as `struct key_info_t { uint32_t flags;
   uint8_t unk_04; uint8_t unk_05; uint8_t uuid[16]; }` and tolerates it. But
   **libfsapfs 20240429 still hard-codes 8 bytes** here and rejects the record
   outright, with the distinguishing error substring:
   ```
   unsupported KEK metadata attribute value data size: 22
   ```

2. **The container keybag's VEK entry (`KB_TAG_VOLUME_KEY`) is much larger** than the
   documented layout — 388 bytes, with long-form DER lengths, a `[4]` field grown to
   16 bytes, a `[5]` field shrunk to 3 bytes, and three tags `[6]`/`[7]`/`[8]`
   carrying 216 bytes of uncharacterized data. **Neither tool fully models this
   entry:** apfs-fuse's `DecodeVEK()` parses the prefix through `[3]` (the 40-byte
   wrapped VEK) and returns success while ignoring `[4]`–`[8]`, stopping at a literal
   `// HW encrypt has more here ... TODO`; libfsapfs rejects this sample earlier, on
   the 22-byte metadata. This entry's byte-level layout is what this document mainly
   contributes.

Separately, and contrary to a common assumption: on the guest examined here the
on-disk records parse cleanly but the **password does not unwrap the KEK offline**
— see "Offline unlock is not achieved by this decode."

## Observed on

- macOS **26.5.2**, build **25F84**, Apple Silicon, running as a guest under Apple
  Virtualization.framework (via Tart).
- **Version-attribution caveat:** these bytes were only observed on macOS 26.5.2.
  Earlier macOS was not tested, and the 22-byte metadata predates macOS 26 (apfs-fuse
  modeled it in 2023), so treat "macOS 26" as "observed on 26.5.2," not "introduced
  in macOS 26."
- Whether the expanded VEK entry is tied to the Virtualization.framework
  key-management path or is also present on physical Macs is **untested**. The
  container keybag itself decrypts with no password (it is AES-XTS under a key
  derived from the container UUID), so the records are fully readable offline.

## Background: the two tools' models of the KEK metadata

The documented KEK record (KEKBLOB) is, in libfsapfs's `Apple File System
(APFS).asciidoc` and Joe Sylve's APFS writeups (jtsylve.blog), a structure of
context-specific *implicit* TLVs (`0x80` = `[0]`, `0xa3` = constructed `[3]`, …).
Read `[n]` as "context tag n":

```
KEKBLOB ::= SEQUENCE {
    version      [0]              hmac  [1]  (32 bytes)   salt  [2]  (8 bytes)
    keyblob      [3] SEQUENCE {
        version     [0]           uuid  [1]  (16 bytes)   metadata [2]  (see below)
        wrapped_key [3] (40 bytes, RFC-3394 wrap of a 32-byte key)
        iterations  [4] (PBKDF2 count)      salt  [5]  (16 bytes, PBKDF2 salt)
    }
}
```

The `metadata[2]` field is where the two tools disagree, and where libfsapfs is stale:

- **libfsapfs 20240429** models it as an 8-byte struct
  (`encryption_method` uint32-LE + `unknown1[2]` + `unknown2[1]` + `unknown3[1]`) and
  requires exactly 8 bytes.
- **apfs-fuse** models it (since 2023, commit `be0f05af`) as the 22-byte
  `key_info_t` above: a 4-byte `flags` (little-endian) + two unknown bytes + a
  16-byte `uuid`, guarded by `info_len <= 0x16`.

The volumes here carry the 22-byte form, so apfs-fuse accepts it and libfsapfs
rejects it. Note the first 4 bytes are `flags` in apfs-fuse's model, not
`encryption_method`; the observed value (73) is not a valid libfsapfs
`encryption_method` (`{0, 2, 16}`), consistent with it being a flags/other field.

## The KEK record (per-user), byte-level

Captured via an instrumented `fsapfsinfo` from a disposable VM with password
`admin`. Annotations are (tag, length, value); all lengths sum exactly. Full hex of
this and two other records is in the appendix.

```
30 81 9f                                              SEQUENCE (159)
   80 01 00                                           [0] version = 0
   81 20  6b1c2ec7801860470d390e0b4db6594c            [1] hmac (32 bytes)
          8674d050a0f7887067382d4d45e830b9
   82 08  07dae24ec205fe57                            [2] salt (8 bytes)
   a3 6e                                              [3] keyblob SEQUENCE (110)
      80 01 00                                        [0] version = 0
      81 10  faa413cdc9f64543ba84b89439c40732         [1] uuid = FAA413CD-C9F6-4543-BA84-B89439C40732
      82 16  49000000 0200                            [2] metadata (22 bytes: 6-byte header + 16-byte value)
             96d725ec34d842ac9764e43f81804f57
      83 28  7cb2aef582de675023e977b6e6ffca85         [3] wrapped_key (40 bytes)
             45f808155e2b7375f83ccf65e9f41b8c
             e712099bfb67599f
      84 03  088950                                   [4] iterations = 0x088950 = 559,440
      85 10  5142af0bf434de029f9f4f1a8538430e         [5] salt (16 bytes)
```

Length checks: outer `3 + 34 + 10 + 112 = 159 = 0x9f`; keyblob
`3 + 18 + 24 + 42 + 5 + 18 = 110 = 0x6e`. Both exact. The outer `30 81 9f` uses a
1-byte long-form length (`0x81`) because 159 exceeds the 127-byte short-form maximum
— this is true of the older 8-byte-metadata record too (its outer content would be
145, still > 127), so long-form at the top level is not new.

**The 16-byte value.** What the bytes establish: a 6-byte header followed by a
16-byte, UUID-shaped value that is byte-identical across all three records observed
in this container (the two KEK records and the VEK entry), while the *leading* 6
bytes differ between record types (`49 00 00 00 02 00` in the KEK records,
`29 00 00 00 01 01` in the VEK entry). That differential fixes the 6/16 boundary.
apfs-fuse names the 16-byte field `uuid`; whether it identifies a key-wrapping
context (relevant to the offline-unlock discussion below) is an **inference**, not
established by the bytes. Sample size is three records in one container.

## The container VEK entry (`KB_TAG_VOLUME_KEY`) — the under-documented part

This entry holds the wrapped volume key. In this macOS 26.5.2 VZ sample it is
**388 bytes**, and neither tool fully models it (annotations truncate opaque bodies
as `…`; full hex in the appendix):

```
30 82 01 80                                           SEQUENCE (384)  <-- 2-byte long-form length
   80 01 00                                           [0] version = 0
   81 20  7324fa3a…bb22                               [1] hmac (32 bytes)
   82 08  ee545736c59b91b5                            [2] salt (8 bytes)
   a3 82 01 4d                                        [3] keyblob SEQUENCE (333)  <-- 2-byte long-form length
      80 01 00                                        [0] version = 0
      81 10  66eb31c4197c43a2b833c52052884e9c         [1] uuid = 66EB31C4-197C-43A2-B833-C52052884E9C (volume UUID)
      82 16  29000000 0101                            [2] metadata (22 bytes)
             96d725ec34d842ac9764e43f81804f57
      83 28  d7ecb1c0…4e3d                            [3] wrapped_vek (40 bytes)
      84 10  8b84c638a62348aa8e5e8d6d87ff3389         [4] 16 bytes  <-- documented layout: <=8-byte iteration count
      85 03  35ad36                                   [5]  3 bytes  <-- documented layout: 16-byte PBKDF2 salt
      86 10  fa4fc6c0…6ddc                            [6] 16 bytes  <-- extra tag (vs documented layout)
      87 10  d3c8b878…1526                            [7] 16 bytes  <-- extra tag (vs documented layout)
      88 81 b8  779182…5b92                           [8] 184 bytes <-- extra tag (1-byte long-form length)
```

Length checks: outer `3 + 34 + 10 + 337 = 384 = 0x0180`; keyblob
`3 + 18 + 24 + 42 + 18 + 5 + 18 + 18 + 187 = 333 = 0x014d`. Both exact.

What is new here versus a documented KEK record:

- **`0x82` (2-byte) long-form lengths** on the outer SEQUENCE and the `[3]` keyblob
  (their contents, 384 and 333, exceed 255), and a **`0x81` (1-byte) long-form
  length** on `[8]` (its 184-byte value exceeds 127). The KEK record only needed the
  top-level `0x81`.
- **`[2]` metadata is 22 bytes** — same as the KEK records, same shared 16-byte
  value, different 6-byte header (`29 00 00 00 01 01`).
- **`[4]` is 16 bytes** — the documented layout uses this slot for a `<=8`-byte
  PBKDF2 iteration count; this entry is password-independent (the VEK is wrapped by
  the KEK, not a password-derived key), and 16 bytes does not fit that field, so its
  meaning here is uncharacterized.
- **`[5]` is 3 bytes** (documented layout: a 16-byte PBKDF2 salt).
- **`[6]`, `[7]`, `[8]`** — not in the documented layout (16 + 16 + 184 = 216 bytes
  of uncharacterized data).

apfs-fuse's `DecodeVEK()` parses the prefix through `[3]` and returns success while
ignoring `[4]`–`[8]` (it stops at `// HW encrypt has more here ... TODO`); libfsapfs
rejects this sample earlier, on the 22-byte KEK metadata. So the `[4]`–`[8]` layout
above is, as far as the prior-art check below found, undocumented in public.

## Impact on the two tools

- **libfsapfs** (`libfsapfs_key_encrypted_key.c`, version 20240429): enforces
  `value_data_size == 8` on `keyblob[2]` and aborts. It parses both the KEK records
  and the container VEK entry through the same
  `libfsapfs_key_encrypted_key_read_data`, so it cannot process this sampled keybag.
  Needs the fixes below.
- **apfs-fuse** (`ApfsLib/KeyMgmt.cpp`, pinned at commit `66b86bd5`): accepts the
  22-byte KEK metadata (`key_info_t`), so it parses the KEK records; but its
  `DecodeVEK()` does not handle the expanded container VEK entry (the `// … TODO`).
  Full compatibility with the entry above is therefore **untested** and would need
  the `[4]`–`[8]` handling added.

## The libfsapfs fixes

To bring libfsapfs 20240429 up to parsing a macOS 26 keybag (verified against a
patched build that reads both record types):

1. **DER long-form length endianness (upstream bug).** libfsapfs reads `0x82`
   long-form lengths with `byte_stream_copy_to_uint16_little_endian`, but DER
   lengths are **big-endian**. On the 388-byte VEK entry, `a3 82 01 4d` is read as
   `0x4d01 = 19713` instead of `333`. Fix: `..._big_endian` (four call sites). This
   first bites at a content length of 256 and misdecodes any `0x82` length whose two
   octets differ (e.g. `01 4d`; a value like `01 01` byte-swaps to itself).
2. **Support `0x81` (1-byte) long-form lengths in the nested wrapped-KEK sub-parser.**
   libfsapfs handles long-form at the top-level record parse (that is how it reads
   `30 81 9f`), but its nested wrapped-KEK-object sub-parser accepts only `0x82`, so
   `[8]`'s `88 81 b8` is rejected there.
3. **Derive the nested wrapped-KEK object header size from the length form**
   (`0x81` → 3, `0x82` → 4) instead of the hard-coded 2, so the sub-object starts on
   its real tag byte.
4. **Accept 22-byte `keyblob[2]`** in addition to 8, and do **not** feed offset 0
   into the legacy `encryption_method` dispatch (the value is a `flags`/other field,
   not a valid method). As a compatibility choice, force method 0: its sizing
   (32-byte key, 40-byte wrap) matches the observed 40-byte `wrapped_key`, so parsing
   proceeds. This is a structural match, not a validated cipher identification — the
   offline unwrap does not succeed (below).
5. **Relax the `[4]`/`[5]` guards** for the container VEK entry: read `[4]` as an
   iteration count only when `<= 8` bytes, and `[5]` as a PBKDF2 salt only when
   exactly 16 bytes; otherwise leave them uninterpreted.
6. **New tags `[6]`/`[7]`/`[8]` need no per-tag handling** — libfsapfs's field switch
   already has a `default: break` that skips unknown tags; they become reachable only
   once #1–#3 let the parser decode their lengths.

apfs-fuse would separately need `DecodeVEK()` extended past its `TODO` for the
`[4]`–`[8]` fields.

## Offline unlock is not achieved by this decode

Parsing the records is not the same as unlocking the volume. On the macOS 26 VZ guest
examined here, the standard software-FileVault unwrap chain

```
KEK  = PBKDF2-HMAC-SHA256(password, salt[16], iterations)   -> 32 bytes
KEK' = RFC3394_unwrap(KEK, wrapped_kek[40])                 -> fails integrity check
```

**fails the RFC-3394 integrity check** (`A6A6A6A6A6A6A6A6`) with the correct login
password. The failing matrix: PBKDF2-HMAC-SHA256 over the password in several
encodings, against the on-disk salt and a few candidate salts, across the observed
and neighbouring iteration counts, with 16- and 32-byte derived-key lengths and
24-/40-byte wrap lengths (~150 combinations), cross-checked with two independent
unwrap implementations (a pure-Python RFC-3394 and libfsapfs's C path). The
personal-recovery-key record fails the same way.

Stated narrowly: **on this guest, the documented software unwrap chain and every
enumerated variant failed** — the KEK could not be derived from on-disk material.
This does **not** prove no derivation exists (an undiscovered KDF or
password-preprocessing step is not excluded), nor the mechanism. The most consistent
*hypothesis* is that the KEK is bound to a wrapping context not present on disk — on
a Virtualization.framework guest, KEK-wrapping is plausibly handled by the
out-of-process virtual Secure Enclave that exists only while the VM runs — with the
16-byte metadata value as a candidate context identifier. This was not traced to the
vSEP image, so it remains a hypothesis. Still, it is a useful correction to the
intuition that "a VM has no Secure Enclave, so its FileVault must be plain
software-wrapped and offline-crackable": at least on this guest, the records parse
but the offline password unwrap does not succeed.

## Prior-art check (2026-07-26)

Searched: the libfsapfs and apfs-fuse issue trackers, PRs, and source; the libfsapfs
APFS asciidoc spec; Joe Sylve's APFS series; Eclectic Light's FileVault corpus;
Elcomsoft / Passware / hashcat; mac_apt / plaso.

- The **22-byte KEK metadata with a 16-byte UUID** is **prior art** — apfs-fuse's
  `key_info_t` (commit `be0f05af`, 2023). It is documented here only because
  libfsapfs still lacks it.
- The **expanded container VEK entry** (`[4]` 16B, `[5]` 3B, new tags `[6]`/`[7]`/
  `[8]`, long-form lengths) is **not** handled by either tool (apfs-fuse's
  `// … TODO`) and returns no hits on web search, GitHub code search, or the issue
  trackers — it appears undocumented in public at the byte level.
- The **libfsapfs DER long-form endianness bug** does not appear to be reported.
- Eclectic Light confirms macOS 26 *changed* FileVault key management, but only
  conceptually — no byte-level format.

## Provenance

- Sample bytes are captured key material from a disposable macOS 26.5.2 (25F84) VZ
  guest that is being retired; its login password is the literal `admin`, published
  alongside, so nothing sensitive is disclosed.
- "DER-validated" / "round-trip" mean: every TLV length was parsed and re-summed to
  its enclosing length exactly, and re-encoding the parsed tag/length/value tree
  reproduces the original bytes. The full hex below lets a reader repeat both checks.

## Appendix — full record hex

All three records are from the same container of the disposable `admin` VM. Each
block is continuous hex (whitespace-free).

Per-user KEK record (162 bytes):

```
30819f80010081206b1c2ec7801860470d390e0b4db6594c8674d050a0f7887067382d4d45e830b9820807dae24ec205fe57a36e8001008110faa413cdc9f64543ba84b89439c40732821649000000020096d725ec34d842ac9764e43f81804f5783287cb2aef582de675023e977b6e6ffca8545f808155e2b7375f83ccf65e9f41b8ce712099bfb67599f840308895085105142af0bf434de029f9f4f1a8538430e
```

Personal-recovery-key KEK record (162 bytes; note the identical 16-byte metadata
value and identical `49000000 0200` header):

```
30819f80010081205ab0a14dbebcdf6bea99bf48e9cdd25efcf63bedd032fce49a00c55c427d85fd82088c69cac5ecf63a99a36e8001008110ebc6c064000011aaaa1100306543ecac821649000000020096d725ec34d842ac9764e43f81804f578328d19275df338b1b76836c09fa1234b9355d4faceee251d7f45492ac33e1fd0defaefd614db143ba6584030a6b258510d83c493c5a1078ddc1e36b3d4d37dfa7
```

Container VEK entry (388 bytes; metadata header `29000000 0101` differs, trailing
16 bytes identical):

```
3082018080010081207324fa3a90b75ae5c555193bacc177007c0969bd851247cfa94824f20fe4bb228208ee545736c59b91b5a382014d800100811066eb31c4197c43a2b833c52052884e9c821629000000010196d725ec34d842ac9764e43f81804f578328d7ecb1c0140b97658889bbcee5f41dee20ebd89e48960d7d3c0028ed1be49c44ce8a1bbf17324e3d84108b84c638a62348aa8e5e8d6d87ff3389850335ad368610fa4fc6c02a69e471c297a3d8ca9f6ddc8710d3c8b878909ba85511e01477685215268881b87791822068558779794b7cd200f07141e2ea17a64c55bea3beb2ee1b91145804f86bbd5819cd335f96d6cdb8b3bf9d7f5e4ae482b7b63dcc1c9a5aa987c9720dc6346d1f247683087b9404ebda9581a52ebb98cccac23113cc6e188b40b9a37f4d3879a63372919e552ae0e544aad6c0370a3cb718de57d7a70f1c67ee32b1dc636d2a94ceddd6944a6539b64c84c577569819bf4a8040f4ae9c4130e1fb57a17740df34704dfba15f7b3f09182229ee562c60a82d295b92
```

*Corrections and additional data points — especially from physical Macs, the version
in which the expanded VEK entry first appeared, and the meaning of the new fields —
are welcome. Open an issue.*
