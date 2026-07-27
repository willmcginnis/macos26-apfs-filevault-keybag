# Offline FileVault on Apple Virtualization.framework (Tart) macOS 26 guests — keybag format, the offline-unlock wall, and recovering your own volume key from guest RAM

Byte-level notes on a macOS 26 FileVault APFS keybag as it appears on an Apple
Virtualization.framework guest, **plus** the two things a reader most often actually
wants to know: **can you unlock such a volume offline, and if so, how.** The short
answers are (1) *not* from the password or recovery key alone, and (2) *yes*, once
you boot the guest one time and read the volume key out of the guest kernel's own
memory. Both are documented below in full, with the failing attempts included.

This write-up serves two audiences:

- **libfsapfs / apfs-fuse maintainers** — the on-disk format and the concrete parser
  fixes (Part 1, the prior-art check, and the appendix).
- **Anyone recovering data from a macOS VM they own** — why the offline password path
  cannot work, and the working RAM-extraction path that can (Parts 2–3).

> **Scope & intent.** This is interoperability / digital-forensics / self-recovery
> documentation, produced during legitimate offline data-recovery of *disposable
> macOS virtual machines that the author owns and holds the password to.* Every
> sample byte below — wrapped keys, HMACs, salts, and one recovered volume key — is
> from a throwaway VM whose login is the literal `admin` / `admin` and which is being
> destroyed, so nothing sensitive is disclosed. The one recovered volume key shown is
> **per-volume, from that disposable VM — it is not a master key and (as the
> universality section shows) does not decrypt any other independently-created
> volume.** Host SIP was never disabled at any point; only *guest* SIP-off (inside a
> VM the author controls) is used, which is a supported operation on a machine you own.

---

## TL;DR — what unlocks offline, and what doesn't

| Approach (VM stopped, `disk.img` as a file on the host) | Result | Why |
|---|---|---|
| **Parse the keybag records** | works | Container keybag is AES-XTS under a key derived from the container UUID — no secret needed. Needs the parser fixes in Part 1. |
| **Password → PBKDF2 → RFC-3394 unwrap of the KEK** | **FAILS** | The KEK is wrapped by a context that is not on disk. On a Virtualization.framework guest that context is the out-of-process **virtual Secure Enclave** (inference). ~150 enumerated variants, two independent implementations, and a second tool (apfs-fuse) all fail the RFC-3394 integrity check. |
| **Personal Recovery Key (PRK) → RFC-3394 unwrap** | **FAILS (structural)** | The recovery record is an ordinary KEK record (Apple's standard recovery crypto-user UUID `EBC6C064-0000-11AA-AA11-00306543ECAC`) carrying the **same 16-byte wrapping-context value** as the password KEK, so the same SEP binding applies. (We did not hold the actual recovery key to test a correct-PRK unwrap directly — this is the structural argument.) |
| **Boot once, read the VEK out of guest kernel RAM, then mount `disk.img` offline forever** | **WORKS** | Bulk FileVault decryption in this guest is *software* AES-XTS (no hardware AES engine services bulk reads), so the unwrapped volume key sits in guest kernel memory while the volume is mounted. Extract it, inject it into a patched libfsapfs, mount the image offline thereafter. |

The rest of this document is the byte-level and mechanism detail behind each row.

## The environment (observed on)

- macOS **26.5.2**, build **25F84**, Apple Silicon, running as a guest under Apple
  Virtualization.framework (via Tart), on a plain `disk.img` (virtio-blk;
  `VZMacOSBootLoader`).
- **Version-attribution caveat.** The keybag bytes were observed on 26.5.2 (and, for
  the universality cross-check, 26.3). Earlier macOS was not tested, and the 22-byte
  KEK metadata predates macOS 26 (apfs-fuse modeled it in 2023), so read "macOS 26" as
  "observed on 26.x," not "introduced in macOS 26."
- Whether the *expanded VEK entry* (Part 1) is tied to the Virtualization.framework
  key-management path or is also present on physical Macs is **untested**.

---

# Part 1 — The on-disk keybag format (for libfsapfs / apfs-fuse maintainers)

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
   the 22-byte metadata. This entry's byte-level layout is the main format
   contribution here.

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
`encryption_method`; the observed value (`73`) is not a valid libfsapfs
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
   offline unwrap does not succeed (Part 2).
5. **Relax the `[4]`/`[5]` guards** for the container VEK entry: read `[4]` as an
   iteration count only when `<= 8` bytes, and `[5]` as a PBKDF2 salt only when
   exactly 16 bytes; otherwise leave them uninterpreted.
6. **New tags `[6]`/`[7]`/`[8]` need no per-tag handling** — libfsapfs's field switch
   already has a `default: break` that skips unknown tags; they become reachable only
   once #1–#3 let the parser decode their lengths.

apfs-fuse would separately need `DecodeVEK()` extended past its `TODO` for the
`[4]`–`[8]` fields.

---

# Part 2 — What unlocks offline, and what doesn't

Parsing the records is not the same as unlocking the volume. This part covers the two
paths that *look* like they should work offline but don't, and then the path that
does.

## Password-only, no boot: FAILS

On the macOS 26 VZ guest examined here, the standard software-FileVault unwrap chain

```
derived = PBKDF2-HMAC-SHA256(password, salt[16], iterations)   -> 32 bytes
KEK     = RFC3394_unwrap(derived, wrapped_kek[40])             -> fails integrity check
```

**fails the RFC-3394 integrity check** (`A6A6A6A6A6A6A6A6`) with the correct login
password — so the chain never reaches the VEK. The failing matrix: PBKDF2-HMAC-SHA256
over the password in several encodings, against the on-disk salt and a few candidate
salts, across the observed and neighbouring iteration counts, with 16- and 32-byte
derived-key lengths and 24-/40-byte wrap lengths (~150 combinations), cross-checked
with two independent unwrap implementations (a pure-Python RFC-3394 and libfsapfs's C
path). A third, independent tool (apfs-fuse) reproduces the same failure (below).

Stated narrowly: **on this guest, the documented software unwrap chain and every
enumerated variant failed** — the KEK could not be derived from on-disk material.
This does **not** prove no derivation exists (an undiscovered KDF or
password-preprocessing step is not excluded); it establishes that the *documented*
offline path does not work here.

**Why (inference).** The most consistent hypothesis for the failure is that the KEK
is bound to a wrapping context that is **not present on disk**. On a
Virtualization.framework guest, macOS 26 gives the VM "full-strength FileVault": the
VM's identity is derived from the host's Secure Enclave, and KEK-wrapping is
plausibly handled by the guest's **out-of-process virtual Secure Enclave (vSEP)**,
which exists only while the VM runs. On-disk corroboration: the Preboot volume
carries an `apticket…im4m` (an Image4 ticket bound to the VM's exact ECID), and the
16-byte metadata value in the keybag records is a candidate wrapping-context
identifier. **This SEP-binding is INFERENCE — it was not traced to the vSEP image**
(that would require reverse-engineering the coprocessor image itself, a separate
target). It is, however, a useful correction to the intuition that "a VM has no
Secure Enclave, so its FileVault must be plain software-wrapped and
offline-crackable": at least on this guest, the records parse but the offline
password unwrap does not succeed, and a *virtual* SEP is present.

## Personal Recovery Key (PRK): also FAILS

The Personal Recovery Key does **not** provide an offline shortcut here either. The
recovery record is structurally an ordinary KEK record — same 162-byte shape, same
22-byte metadata with the same shared 16-byte value — keyed to Apple's **standard
recovery crypto-user UUID `EBC6C064-0000-11AA-AA11-00306543ECAC`** (visible in the
appendix hex). We did **not** hold the actual recovery key, so we did not run a
correct-PRK unwrap directly — but the argument is **structural, and decisive**: both
KEK records carry the **same 16-byte wrapping-context value** (`96d725ec…`), so whatever
binds the password KEK binds the recovery KEK. The recovery path is SEP-bound the same
way. (Candidate PRK derivation/normalization sweeps *without* the real key fail
regardless of SEP binding, so they prove nothing on their own.) Whichever credential
you hold, offline you are unwrapping a KEK whose wrapping context is not on the disk.

## The crypto architecture — why the password path can't work offline but RAM can

There are two independent crypto layers here; do not conflate them.

| Layer | What | Where the key is | Offline? |
|---|---|---|---|
| **A — host disk-image encryption** (`per_io_encrypted` + DiskImages2) | the host decrypts blocks | host process (unwrapped from a host-SEP-derived key) | recoverable with the image passphrase |
| **B — guest FileVault** (these VMs) | the guest decrypts; the host sees only ciphertext | guest kernel RAM (the VEK) | not via the host — you need the VEK |

These Tart VMs are **Layer B on a plain `disk.img`**. The consequence that matters
for recovery: **bulk FileVault decryption runs as software AES-XTS in the guest
kernel.** In this Tart configuration no inline AES *hardware* engine is attached to
the guest — the framework can register an emulated `apple.aes-engine` device, but it
is not in these VMs' device set. (The guest's `AppleS8000AESAccelerator` IOKit driver
is present but idle during bulk reads — its role is unlock-time key wrapping, not bulk
decryption.) So the guest does the XTS itself. And ARMv8-A has no
opaque AES key register: the `AESE`/`AESD` instructions consume round keys **from
memory**, so a software XTS decrypt requires the expanded key schedule to be resident
in guest RAM at decrypt time. **Therefore the unwrapped VEK sits in guest kernel
memory the whole time the volume is mounted** — which is exactly the material the
offline password path cannot reconstruct, but a one-time boot exposes.

(The guest's VEK does *not* transit the host VM-runner process's normal heap: that
process contains no guest-FileVault crypto at all, and the vSEP is a separate,
out-of-process coprocessor. So the extraction target is the *guest's* RAM, not the
host runner's.)

## VEK-from-RAM: the working path (for self-recovery)

If you own the VM and hold its password, this is how to get your data out offline —
permanently, without the 2-concurrent-VM cap and with full xattr fidelity via a Linux
FUSE mount:

1. **Boot the guest once** and log in / unlock so the volume mounts and the VEK is
   live in guest kernel RAM.
2. **Disable *guest* SIP** (inside the VM you own; host SIP stays on) so you can read
   guest kernel memory.
3. **Capture the corecrypto AES-XTS context from guest kernel RAM** (via a
   self-signed kext, KDP + a KDK, or a light dtrace read of the running XTS context —
   see the tooling caveats in Part 3). You are looking for the `ccaes_xts` leaf's key
   schedule, not a hardware register.
4. **Invert the schedule to the raw key** (Part 3) and **concatenate data-key-half ‖
   tweak-key-half** to form the AES-XTS VEK.
5. **Verify the candidate against `disk.img`** with the patched-libfsapfs oracle
   (Part 3) — correct key lists the real filesystem; a 1-byte-flipped tweak yields
   garbage.
6. **Mount the image offline, forever after**, with the injected VEK. No further boot
   or SIP change is needed once the context is captured.

This was carried out and independently re-verified. Against this disposable VM's Data
volume (Volume 5, UUID `66EB31C4-…`), the recovered key decrypts the real filesystem
(307,216 entries; `/private/etc/{hosts,kcpassword,…}` to exact content), and a
1-byte-flipped tweak produces `invalid object type` — a positive-and-negative proof.
The same recovery reproduced on a Linux `fsapfsmount` (below).

## The one-time boot, minimally: keeping the original image pristine

The working path needs exactly one boot to birth the key in RAM, and a normal boot
mounts the Data volume read-write — so it dirties the disk. To keep the *original*
`disk.img` byte-for-byte pristine, do that boot on a **copy**.

On real hardware you would reach for a rescue environment (grml / a custom initramfs)
that extracts only the key and never writes the target. A VZ macOS guest has no such
hook: `VZMacOSBootLoader` boots the macOS on the guest's own disk, with no
custom-kernel / initramfs injection point. The analog is cheaper here, though, because
the guest disk is an APFS file — a **copy-on-write clone of `disk.img`** costs ~22 KiB
of metadata (it shares every block with the source until it diverges):

1. CoW-clone the VM (`tart clone` — an APFS clonefile; ~22 KiB, not a full copy).
2. Boot the **clone**, disable *guest* SIP, unlock, extract the key(s) from the
   clone's RAM, then discard the clone.
3. The original `disk.img` is never booted — confirm it byte-identical by SHA-256
   before and after. Every write the boot makes (SIP-off nvram, logs, mount dirtying)
   lands on the disposable clone.

(macOS recoveryOS — `tart run --recovery` — is the closer spiritual match to "don't
boot the target OS at all," but in practice it exposes no Tart guest-agent shell
channel and does not reliably ship a usable dtrace, so the proven extraction can't be
scripted there. The CoW clone reuses the already-proven full-OS extraction environment
while still leaving the original pristine, so it is the preferred realization of the
"minimal boot" intent.)

---

# Part 3 — Reading the VEK out of guest RAM

## corecrypto arm64 "vng" AES key-schedule layout

`aeskeyfind` finds nothing in these guest-RAM dumps, because it scans for x86-style
AES-128 sequential / InvMixColumns schedules, whereas Apple's arm64 corecrypto
("vng") stores **AES-256 schedules in an identity layout**. Once you know the layout,
the key reads out directly.

For an AES-XTS context, the two key schedules are **contiguous** at fixed offsets, one
16-byte round key per round:

- **Data-key schedule: base `ctx+0x10`.** Round `r` is at `ctx[0x10 + 16*r]`. Fifteen
  round keys (AES-256) occupy 240 bytes, running from `0x10` up to `0x100`.
- **Last-round marker at `ctx+0x100`.** This is the byte offset of the last round key
  within a schedule: `0xE0` (= 14×16) for **AES-256**, `0xA0` (= 10×16) for
  **AES-128**. It is the cheap discriminator for cipher width. (Between the data
  schedule's end at `0x100` and the tweak schedule's start at `0x108` sit 8 bytes of
  marker/count — the 240 round-key bytes + 8 = the `0x108 − 0x10` span.)
- **Tweak-key schedule: base `ctx+0x108`.** Same shape, another 240 bytes.

The round keys are **contiguous** — there is no working state interleaved between
them (an earlier pass mis-described the layout that way; it is a plain contiguous
schedule).

**Encryption vs decryption schedule.** An *encryption* schedule holds the raw key at
round 0, so `ctx[base : base+32]` is the raw 32-byte AES-256 key. A *decryption*
schedule instead stores `InvMixColumns(key)` applied per 4-byte column (the
equivalent-inverse-cipher form), so it must be **inverted** to recover the raw key.
This was byte-verified: an XTS context's `ctx[0x10:0x100]` matched a computed AES-256
schedule, and `dec_ctx = InvMixColumns(enc_ctx)` held per 4-byte column. So the raw
key reads out as:

```
VEK = ctx[dataBase : dataBase+klen]  ‖  ctx[tweakBase : tweakBase+klen]
      (klen = 32 for AES-256; invert first if this is a decryption schedule)
```

**A decoy to filter out.** A zero-*data*-key AES-256-XTS context fires constantly
(an integrity / sealed-volume / self-test op) and an earlier extraction pass
dismissed the real Data key as this "no-op decoy," precisely *because* it also has a
zero data key. The resolution: the Data volume's VEK genuinely has an all-zero
data-cipher half — the entropy lives entirely in the **tweak** key. What
distinguishes the real Data key from a self-test context is therefore the **tweak,
not the data key**. So do not filter on "non-zero data key"; sample many distinct
contexts and **verify every candidate against the disk with the oracle** (below).

## The oracle: patched libfsapfs `FSAPFS_INJECT_VEK`

To test a candidate VEK against the image without any live SEP, patch libfsapfs so an
`FSAPFS_INJECT_VEK=<hex>` environment variable is injected in
`libfsapfs_internal_volume_unlock`, **bypassing** the SEP-bound keybag unwrap and
applying a candidate raw VEK directly. Then:

```
FSAPFS_INJECT_VEK=<hex> fsapfsinfo -o <vol_offset> -f 5 -H <disk.img>
```

A wrong key fails the Fletcher-64 object checksum (`invalid object type`); the correct
key lists the Data volume's file tree. This is the positive/negative test used to
confirm the recovered key. (The unmodified libfsapfs is AES-128-XTS internally; a
64-byte AES-256-XTS VEK needs the width extended in the patch — see the recovered-key
note.)

## The recovered key on this VM

**Disposable-VM caveat first:** the value below is the volume key of *one throwaway VM
that is being destroyed.* It is **per-volume, not a master key**; as Part 5 shows, it
does **not** decrypt any independently-created volume.

On this VM the recovered runtime key is a **64-byte AES-256-XTS** VEK:

```
data-cipher key : 00 00 … 00                                            (32 × 0x00)
tweak key       : 776cbf2b5af564ccbdaa481931a56477e2a719408a424ca1ab1e9fe38e3013ca
```

**The striking observation:** the data-cipher half is **all zero** — the volume's
confidentiality rests entirely on the 32-byte tweak plus the host `disk.img`
boundary, not on a per-volume secret data key. This was verified end-to-end by the
oracle (correct key → 307,216 real entries; flipped tweak → garbage) and re-run
independently.

**The 32-byte on-disk VEK → 64-byte runtime key: the per-volume derivation.** The
on-disk keybag wraps a **32-byte** VEK (the 40-byte RFC-3394 `wrapped_vek` at tag
`[3]`), while the RAM-recovered runtime key is **64 bytes** (AES-256-XTS). A static
read of the macOS 26.4.1 kernel's APFS key path (`_unmanaged_vek_unwrap_from_kek`)
characterizes the mapping as a two-step derivation:

```
unwrapped = RFC3394_unwrap(KEK, wrapped_vek[40])              -> 32 bytes
xts_seed  = HKDF-SHA256(IKM  = unwrapped[32],
                        salt = APFS volume UUID [16 bytes],
                        info = "vekderivedentropy\0" [18 bytes],
                        L    = 32)                             -> 32 bytes
```

The HKDF salt is the volume's own APFS UUID (the same pointer is handed to
`_uuid_to_string` immediately before the derivation). This step runs for the
FileVault Data/group volume; a scratch / non-FileVault volume **skips** it (identity —
the RFC-3394 output is used directly). The 32-byte `xts_seed` is consistent with the
observed runtime key being **`(32 zero bytes) ‖ (32-byte derived value)`**: the
derived value supplies the AES-256 **tweak** half, and the **data** half is the
hardcoded all-zero AES-256 key (matching the systematic zero-data-key result — see
Part 5). This resolves the earlier "why 32 on disk but 64 in RAM?" question in
principle: the on-disk 32-byte VEK is not the runtime key, it is the HKDF *input*.

**Status: characterized from static disassembly (INFERENCE), not yet proven
end-to-end.** The chain above is read from the 26.4.1 kernel, not reproduced
against ground truth here; the end-to-end check — derive `xts_seed` offline from a
volume's on-disk `wrapped_vek` + UUID and confirm it equals that volume's
independently RAM-recovered VEK — is **pending**. Treat the exact byte-level chain
(and the `info` string / `L`) as characterized-not-confirmed until that reproduction
runs.

## Cross-tool confirmation on Linux

Reproduced independently in a throwaway Linux LXD container (since torn down):

- **apfs-fuse** (HEAD `66b86bd`) parses the recent-macOS container + 22-byte KEK
  metadata and mounts the *unencrypted* System volume read-only; on the encrypted Data
  volume with the correct password it fails at the **RFC-3394 KEK-unwrap on both KEK
  entries, never reaching the VEK** — the same SEP-bound signature, now reproduced by
  a second, independent tool. (apfs-fuse is AES-128-XTS only and has no raw-VEK
  injection path.)
- **Payoff:** a patched libfsapfs + the injected recovered VEK produced a **real
  Linux FUSE mount** (`fsapfsmount`); `ls` + file-content reads proved genuine
  decryption. This is the "mount your own image offline forever" path realized on
  Linux.

---

# Part 4 — What we tried and why it failed (the full record)

Included because the dead ends are the useful part for anyone attempting this on
their own VM.

- **Password → PBKDF2 → RFC-3394 KEK unwrap: FAILED.** ~150 enumerated PBKDF2 /
  RFC-3394 variants (encodings, salts, iteration counts, key/wrap lengths) all failed
  the `A6A6…` integrity check with the correct password, cross-checked with two
  independent unwrap implementations (pure-Python RFC-3394 and libfsapfs's C path).
  Reproduced by a **third tool** (apfs-fuse) independently.
- **Personal Recovery Key → offline unwrap: not achievable (structural).** We did not
  hold the actual recovery key, so this was not tested with a correct PRK — but both KEK
  records carry the same 16-byte wrapping-context value, so the recovery KEK is SEP-bound
  exactly like the password KEK; neither credential unwraps offline. (Candidate
  PRK-normalization sweeps without the real key fail regardless.)
- **`tart suspend` save-state: not usable.** Per WWDC23, the save-state is
  hardware-encrypted and host+user bound.
- **`dtrace -A` anonymous boot-time tracing: does NOT work on macOS 26.** Anonymous
  tracing state is not persisted across reboot — after boot the probes report "No
  anonymous tracing state," so you cannot capture the key-schedule expansion at
  unlock-time via anonymous dtrace.
- **Return-time context dump: failed.** Hooking the corecrypto XTS wrapper at RETURN
  (instead of entry) gave `entry == return` with the raw key not in `arg0` — so the
  entry hook, capturing the live `ccxts_ctx`, was the route that worked.
- **The zero-key "decoy" XTS context misled an earlier pass.** A zero-*data*-key
  AES-256-XTS self-test context fires constantly and was mistaken for a no-op,
  causing the real Data key to be dismissed (it, too, has a zero data key). The
  discriminator turned out to be the *tweak*. (See Part 3.)
- **What finally worked: the raw VEK from the corecrypto XTS context in guest RAM.**
  Capture the running AES-XTS context, read the contiguous vng schedules at
  `ctx+0x10` / `ctx+0x108`, invert if it is a decryption schedule, concatenate, and
  verify against `disk.img` with the patched-libfsapfs oracle. Once captured, the
  image mounts offline indefinitely.

---

# Part 5 — Universality: the VEK is not a universal constant, but the KEK path is deterministic

A separate test settled whether the recovered key is anything like an Apple-wide
constant. It is not — but the result has a second half that is more interesting for
the format record.

Method: cloned the pristine upstream `macos-tahoe-base` image (ships FileVault OFF),
enabled FileVault **freshly and independently** on the clone (its own new VEK, macOS
26.3), let it encrypt to 100%, stopped it, and injected the previously-recovered VEK
against its Data volume via the patched oracle.

- **Result: the inject FAILED** (`invalid object type`, identical to the negative
  control). **The recovered VEK does not decrypt an independently-enabled volume —
  the VEK / tweak is NOT a universal Apple constant.** (Where a single recovered VEK
  *had* decrypted several sibling VMs, that was **copy-on-write clone inheritance**:
  they all descended from one base image whose FileVault was enabled once.)
- **The interesting half: the KEK path is deterministic.** Across the two
  *independently created* volumes — different lineages, different ECIDs, macOS
  26.3 vs 26.5.2 — the **volume-keybag KEK records are byte-identical**: same HMAC,
  same admin crypto-user UUID (`faa413cd…`), same PBKDF2 salt (`5142af0b…`), same
  `wrapped_kek`, same 16-byte metadata value (`96d725ec…`). So the **password→KEK
  path is deterministic**, while the **container VEK entry differs** (which is why the
  cross-inject fails). Deterministic KEK, per-enable VEK.
- **From open lead to a characterized method (end-to-end proof pending).** Two
  on-disk facts compose into a route to a *reusable* offline unlock:
  1. the **KEK is deterministic** per (account, password) — byte-identical on-disk KEK
     records across independent volumes — yet is **not** offline-derivable from the
     password (the wrap is SEP-bound); it is obtained **once**, by guest-RAM
     extraction.
  2. the per-volume step from KEK to XTS key uses **only on-disk material**:
     `RFC3394_unwrap(KEK, wrapped_vek)` then `HKDF-SHA256(·, salt = the volume's APFS
     UUID, info = "vekderivedentropy")` (Part 3).

  Together these characterize a **"boot once, then unlock offline forever — across
  volumes"** method: extract the deterministic KEK a single time from one volume's
  boot, then for **any** same-account volume derive its XTS key from that volume's
  on-disk `wrapped_vek` + UUID alone — no further boot, no SEP, no per-volume
  extraction. **This is a characterized method, not yet a demonstrated result:** the
  one-time KEK extraction and the full offline cross-derivation (KEK from volume A →
  mount volume B from B's on-disk bytes, cross-checked against B's independently
  RAM-recovered VEK) have not been run to completion here. One dependency gates the
  *universality* specifically — whether the pre-unwrap `fv_hw_crypt` transform seen in
  the static read is a pure function of on-disk bytes or is itself SEP-bound; if the
  latter, the method narrows to flag-clear volumes. Stated honestly: the mechanism is
  understood end-to-end on paper; the offline end-to-end *demonstration* is the
  remaining work.

**The zero data key is SYSTEMATIC — not a per-volume anomaly.**

A RAM extraction of the independently-enabled volume's live VEK settled it
(oracle-verified: positive decrypt of ~287k real entries + two negative controls).
That volume is **also AES-256-XTS with an all-zero data-cipher key**, and a
**different** tweak. So across two independently created volumes — distinct lineages,
distinct ECIDs, macOS 26.3 vs 26.5.2 — the **data half is all-zero both times while the
tweak differs**: the zero-data-key property is **systematic**, and only the tweak key
carries entropy (per-`fdesetup`-enable).

Security consequence: in this VZ software-FileVault path the XTS **data** cipher runs
under a publicly-known constant (all-zero) key — effectively a fixed, public
permutation — so confidentiality of these Data volumes rests **entirely** on the secret
tweak key plus the host `disk.img` boundary, not on any per-volume secret *data* key.
(n = 2 — a strong systematic inference for the zero data key; the specific tweak is
per-enable and carries no cross-volume value, so no literal tweak is published here.)

---

## Confidence — FACT vs INFERENCE

**FACT:**

- The on-disk keybag byte layout (KEK records, expanded 388-byte VEK entry) and all
  the length checks; the libfsapfs parser bugs (DER big-endian, nested long-form,
  22-byte metadata, `[4]`/`[5]` guards); the container keybag opening with no secret
  (container-UUID-derived key).
- Password offline unwrap fails the RFC-3394 integrity check with the correct password
  (~150-combo sweep, cross-checked with two independent unwrap implementations).
- Bulk FileVault decryption in this guest is software AES-XTS, and the unwrapped VEK
  is resident in guest kernel RAM while the volume is mounted (binary trace + the
  successful extraction).
- The corecrypto vng schedule layout (contiguous 16-byte round keys; data base
  `0x10`, tweak base `0x108`; `0xE0`/`0xA0` last-round marker at `ctx+0x100`;
  enc-schedule holds the raw key, dec-schedule holds `InvMixColumns(key)` per column
  and must be inverted) — byte-verified.
- VEK-from-RAM works: a 64-byte AES-256-XTS key that decrypts the Data volume,
  oracle-verified positive (real filesystem, 307,216 entries) and negative
  (1-byte-flipped tweak → garbage), re-run independently and reproduced as a Linux
  FUSE mount.
- The VEK is not a universal Apple constant (independent FileVault-enable → inject
  fails); the KEK records are byte-identical across independent volumes (deterministic
  password→KEK path).
- Both independently-extracted volumes' VEKs have an all-zero AES-256-XTS **data** key
  (only the tweak differs) — the zero data key is systematic across the two (n = 2).

**INFERENCE:**

- That the guest FileVault KEK-wrapping is specifically SEP / vSEP-transformed.
  Well-supported — every enumerated offline unwrap fails; the Preboot `apticket…im4m`
  binds to the exact ECID; the 16-byte metadata value is a candidate wrapping-context
  id — but **not line-traced to the vSEP image** (that is a separate reversing
  target).
- The relationship between the 32-byte on-disk VEK and the 64-byte runtime key (the
  matching 32-byte non-zero half is suggestive, not confirmed).
- That the PRK path is SEP-bound like the password path — structural (both KEK records
  carry the same 16-byte wrapping-context value), not tested with a correct recovery key.
- That the zero data key is systematic across *all* VZ FileVault volumes (beyond the two
  measured) — strongly supported at n = 2, not proven beyond the sample.
- The per-volume `RFC-3394 → HKDF-SHA256(·, salt = volume UUID, info =
  "vekderivedentropy")` derivation (Part 3) — read from a **static** disassembly of the
  26.4.1 kernel, **not yet reproduced end-to-end** against the two known VEKs. The `info`
  string, the `L = 32` length, and the exact split into (zero data ‖ derived tweak) are
  characterized-not-confirmed.
- That a single extracted KEK yields a *universal* (same-account) offline unlock — a
  method characterized from the on-disk determinism + the HKDF-from-UUID step, but not
  demonstrated end-to-end here, and contingent on the `fv_hw_crypt` transform being a
  pure function of on-disk bytes (if it is SEP-bound, the method narrows to flag-clear
  volumes).

## Prior-art check

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
  guest that is being retired; its login is the literal `admin` / `admin`, published
  alongside, so nothing sensitive is disclosed.
- The one recovered volume key shown is per-volume and from that same disposable VM;
  it is not a master key and does not decrypt any independently-created volume
  (Part 5).
- "DER-validated" / "round-trip" mean: every TLV length was parsed and re-summed to
  its enclosing length exactly, and re-encoding the parsed tag/length/value tree
  reproduces the original bytes. The full hex below lets a reader repeat both checks.
- Host SIP was never disabled; only guest SIP-off (inside owned VMs) was used.
- **Editorial scope — verified-or-omitted.** This write-up asserts only what was
  checked here and deliberately *omits* operational specifics that were not confirmed,
  rather than stating them speculatively. Where a mechanism is understood but its
  end-to-end reproduction has not been run (the HKDF derivation and the universal
  same-account unlock), it is labelled **characterized / proof-pending**, not claimed
  as a result. Less asserted, but each assertion carries its evidence.

## Appendix — full record hex

All three records are from the same container of the disposable `admin` VM. Each
block is continuous hex (whitespace-free).

Per-user KEK record (162 bytes):

```
30819f80010081206b1c2ec7801860470d390e0b4db6594c8674d050a0f7887067382d4d45e830b9820807dae24ec205fe57a36e8001008110faa413cdc9f64543ba84b89439c40732821649000000020096d725ec34d842ac9764e43f81804f5783287cb2aef582de675023e977b6e6ffca8545f808155e2b7375f83ccf65e9f41b8ce712099bfb67599f840308895085105142af0bf434de029f9f4f1a8538430e
```

Personal-recovery-key KEK record (162 bytes; note the identical 16-byte metadata
value, identical `49000000 0200` header, and the standard recovery crypto-user UUID
`EBC6C064-0000-11AA-AA11-00306543ECAC`):

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
