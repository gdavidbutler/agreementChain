#!/usr/bin/env python3
#
# cryptoMule - disk based mule of the multi-seat dispersal payload
# Copyright (C) 2026 G. David Butler <gdb@dbSystems.com>
#
# This file is part of cryptoMule
#
# cryptoMule is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# cryptoMule is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#

"""cryptoMule driver / analyzer (stdlib only).

Plays the OPERATOR: deals drive/config.txt (its full view) plus, per seat, the
priv/<p>_config.txt + priv/<p>_keystate.txt it would receive out-of-band; then
runs the C phase programs and pretty-prints the disk files so the flow can be
analyzed without wire captures.

  drive.py setup N T       # operator config + per-seat deal, blob
  drive.py keychain M      # M+1 MLS contexts; bootstrap books to pub_0
  drive.py rotchain M N T  # walk the identity chain pub_0..pub_M
  drive.py dist [ctx process]  # run ./distribute
  drive.py recv|exch|asm   # run that phase for every recipient seat
  drive.py show FILE       # pretty-print a phase file
  drive.py demo N T        # one dispersal end-to-end, report PASS/FAIL
  drive.py session R N T   # R dispersals: payload + rotation under rotating identity
  drive.py offsets N T     # one identity, signing offsets 0..N: offset run + re-injection floor
  drive.py catchup R N T   # survivor fast-forwards its key over R-1 chain links
  drive.py mixed N T       # payloads ratchet the mask; interleaved rotations do not
  drive.py steps N T       # one step for the whole flow, the single ratchet after it
  drive.py fwdsec N T      # forward secrecy of both phases, bounded by the retention floor
  drive.py tamper N T      # wire tampering detected by the pairwise hmac
  drive.py byz N T         # byzantine dealer: a bad committed part searched past, most leaves salted, a wrong codeword FRAUD
  drive.py parts N T       # the share and the shard are two parts: a rotted shard costs its holder's share nothing
  drive.py limit N T       # the 64k ciphertext cap: refused at distribute, and refused on the wire when dispersed anyway
  drive.py retry N T       # byte-identical re-presentation accepted, re-authoring not (payload and rotation)
  drive.py resend R N T    # a banked distribute re-sent, mask rebuilt off the floor chain
  drive.py chain R N T     # the dispersal chain from the dealt genesis, and its two ways to fall off
  drive.py evidence R N T  # the chain as OUTSIDE evidence: gap, where it starts, how far it validates
  drive.py empty N T       # an empty message is a message: reconstructed at length 0, and its wrong codeword still FRAUD
  drive.py slot N T        # the signing offset partition: a rotation at a payload signing offset, a payload at the rotation's, a payload apex as a rotation
  drive.py hostile N T     # hostile bytes at every ingress, authenticated by a Byzantine sender
  drive.py pools N T       # two apexes under one pub: each pooled by its apex and reported, the one at T delivered
  drive.py signer N T      # the apex commits its signer: a value committed under one key, signed by another, refused
  drive.py twoslot N T     # the apex commits its signing offset: one apex signed at two offsets, admitted at one only

byz needs R-2 >= T (its geom fault is rejected at receive on two leaves, and a
seat must still reach threshold on shares from the rest), so N=5 T=2 rather
than N=4 T=2.

WIRE TAMPER -- between phases an adversary can alter any disk file OUTSIDE priv/
(the disk IS the wire).  Every wire message therefore ends in hmac =
rmd128hmac(mac PSK, [sender][recipient] || file bytes), keyed by a SEPARATELY
DEALT static pairwise mac mesh (in config, never in keystate, never ratcheted:
integrity needs no forward secrecy, and a static key lets a stale seat detect
tampering before catch-up).  Readers gate the hmac FIRST -- a failure is a
wire-tamper verdict, distinct from the sender-fault verdicts, and nothing else
in the message is parsed.  And there is NO broadcast (every message names
one recipient and goes under that pair's keys; nothing assumes a broadcast
medium): rotation and
run messages are directed per recipient like dist/exch, and each recipient
holds its own book (priv/<p>_book.txt) and offset floor (priv/<p>_floor.txt).

THE DISPERSAL CHAIN -- chain_0 is the DEALT genesis (config's `genesis` row, public
and identical at every seat); chain_{k+1} = H(chain_k || msg_k), the message hash, folded by
`./cmchain`.  The ratchet has to key on something, and forward secrecy is only as
good as the parties' AGREEMENT on what that something is -- two seats stepping
on different values stop sharing keys, and nothing reports it.  Agreement is ASSUMED here (who
fixes a dispersal's apex, and when, is the supplier's, like the rest of the
coordination).  What the chain adds is that the trigger cannot be an ARBITRARY
value: each link folds the previous one, so the sequence is pinned end to end from
a base every seat was dealt.

FORWARD SECRECY -- the mask chain advances externally, never at send.  The four
phase programs -- distribute, receive, exchange, assemble -- are LOCAL: each READS
its keystate (the current step of the pairwise mask chain) and NEVER advances it.
A forward-secret key cannot advance at SEND -- a sent message may still have to be
produced again byte for byte until the dispersal's public anchor is fixed outside
these programs, so advancing (and wiping) the key at send would be wrong.  One payload's
whole flow masks under ONE step: distribute and exchange mask under SEPARATE
domains (CM_DOM_DIST / CM_DOM_EXCH), so the step serves both phases.  The advance
is a SINGLE ratchet per payload, taken once the flow is done (`ratchet_all`,
keyed on the payload's chain link), and the next payload's distribute is the
first thing masked under the new step.  The MLS signing-offset high-water
(`offsetgate`, `gate_offset`) is a separate record with a separate moment: it
records the signature at receive, where the signature is known.  These helpers
(plus `catchup`, which fast-forwards a stale chain) are invoked from THIS driver,
never from a phase program.  Each ratchet keys on a PUBLIC ANCHOR -- the dispersal's
chain link; here drive.py fixes it as a stand-in so the round-trip is provable.
In a deployment the link is fixed by whatever host coordinates the parties --
that wiring is out of scope; the cryptography is the point.

THE RETENTION FLOOR -- the same wipe that buys forward secrecy is what makes a
seat that missed a dispersal unanswerable, since the key its dispersal needs is several steps gone.
So the keystate carries TWO things: the current step, which `./ratchet` advances
and wipes, and a floor base (`floor:` + `fpsk_<QQ>`), which it copies through --
born at the first ratchet, holding the key of the dispersal being stepped past.
`./exchange <dispersal> <anchorLog>` walks that base FORWARD over the chain links to
any retained dispersal and re-masks the banked fragment for one wanting seat;
`./assemble <dispersal> <anchorLog>` does the same walk on the receiving side.  One
base covers every dispersal at or after it -- no per-dispersal snapshots.
`./release` moves the floor and destroys what it passes, so forward secrecy is
bounded by the FLOOR rather than by the current step, and that gap is the price
of being able to serve at all.

Why the on-wire fragments are so spare: the crypto primitives were designed *to*
this problem, so each one's natural output is exactly what the protocol needs --
there is almost no framing to carry.  Every length or code point a generic dispersal
protocol would put on the wire is here self-describing, derivable, or
hidden-but-verifiable:

  - huffman embeds the original length      -> no orig_len; the decoder self-terminates
  - a shard is one transport message        -> shard_len IS the message's own length
  - the code points derive from a hidden seed -> no scp/ocp on the wire; the seed rides
                                               inside the masked unit, bound into every
                                               sssMk leaf, so one unmasked unit re-derives
                                               and verifies its seed's code points (one seed
                                               for every leaf is checked at threshold)
  - masks are independent per recipient/sender -> safe to fold the code points' seed into the
                                               masked unit
  - encrypt-before-split                     -> the shard is clear ciphertext (rsecMk-
                                               authenticated); no shard masking, so no
                                               parity-row pad leak
  - apex = H(signer pub || signing offset || orig_hash || roots), signed once
                                            -> the roots ARE the commitment (the shard
                                               length is bound in the rsecMk root, never
                                               carried), the signer pub names whose
                                               it is (never carried: the verifier's book
                                               holds it) and the offset which signing it
                                               is (never carried: the signature yields
                                               it); the one apex is also the mask
                                               domain; the chain folds the message hash
                                               its signed header carries
  - the chain link is derivable              -> no link on the wire: a holder of the
                                               previous link and the message hash recomputes it,
                                               so anchorlog.txt is a CACHE of public
                                               values, never an authority
  - drive/config.txt is the OOB deal         -> R/T/k/m are derived; the one non-secret
                                               dealt field is the genesis

What is left per fragment is irreducible -- process, the signed apex inputs (orig_hash
+ the two Merkle roots), the signature, the recipient's own masked share /
ciphertext shard / Merkle proofs, and the pairwise wire hmac -- nothing whose only
job is to describe another field.  The one addition is the apex message: the
value signed, alone, a hash alone for a rotation and for a payload alike.
Every apex preimage starts with the signer's current pub and the signing
offset it signs at, which no message carries; the sign message carries the
rest of what hashes to it (orig_hash and the roots for a payload, pub_hash
-- the successor pub -- for a rotation), and a reader recomputes the apex
under the pub its book holds as current and the offset the signature yields
(what ./cmapex does for a payload) and requires the apex message to carry it
and the signature to extract to that same pub.  So one value is one kind
under one signer at one offset: a payload's apex or a rotation's, never
both, never verifiable under another of the signer's keys, and never
admitted at two offsets, so every seat's offset floor records the offset
the value fixes.

THE WIRE IS THREE MESSAGES per recipient, each under its own pairwise hmac, and
no two carry the same kind of content (the files render them readably; the
bytes a transport sends are the same fields, not this text):
  - <s>_to_<p>_apex.txt   the apex alone: one hash width, the same to every
                          recipient -- the value signed.
  - <s>_to_<p>_shard.txt  the tag and the shard alone: this recipient's
                          clear ciphertext shard, the one shard-sized part.
  - <s>_to_<p>_sign.txt   the tag and the rest, every field hash-width
                          scaled: process, orig_hash, the two roots, the
                          signature, this recipient's masked
                          [seed][key-share], both Merkle proofs -- the
                          sidecar that proves the apex and the shard.
The TAG is the apex message's file name (`tag: 00_to_01_apex.txt`): the shard
and sign messages are sent under it, so a reader knows which apex message a
part is of before verifying it; the reader holds that message by path already
and compares the tag, never opens what it names.  Nothing binds the three to
each other but the arithmetic: the sign message's
inputs must hash, under the reader's current pub and the offset the signature
yields, to the apex the apex message carries, and the shard verifies under the
sign message's rsecmk_root by the proof carried there, so the parts need not
travel together, and an authentic part paired with another distribution's apex
fails that check, not its hmac.  No length prefix anywhere.  Exchange sends
the same three under the same field names: the sender id and the share's mask
are the only differences, and assemble reads a leg as receive reads a
distribution.  The share and the shard are each an optional payload, sent
where the sender validated it and never without the apex and the signature.
"""

import glob
import os
import sys
import secrets
import shutil
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
OPERCFG = os.path.join(HERE, "drive", "config.txt")


def _mkdirs():
    """create the layout: priv/ (per-seat state), wire/ (directed messages),
    drive/ (the OPERATOR's own files: its full deal, plus driver scratch).
    anchorlog stays in root -- it is the one file that must be read from
    outside."""
    for d in ("priv", "wire", "wire/dist", "wire/exch", "wire/rot", "drive"):
        os.makedirs(os.path.join(HERE, *d.split("/")), exist_ok=True)


def _cfgpath(p):
    return "priv/%02d_config.txt" % p


def _kspath(p):
    return "priv/%02d_keystate.txt" % p


def _pair(a, b):
    return (a, b) if a < b else (b, a)


def _write_operator(f, n, t, mesh, macmesh, genesis):
    """the dealer's full ledger: every unordered pair PSK(a,b) -- the ratcheting
    mask mesh AND the static wire-hmac mac mesh -- plus the genesis, the dispersal
    chain's base.  No scp/ocp: the SSS code points derive from a hidden
    per-distribution seed, never dealt."""
    f.write("N %d\n" % n)
    f.write("T %d\n" % t)
    f.write("genesis %s\n" % genesis.hex())
    for a, b in sorted(mesh):
        f.write("psk %d_%d %s\n" % (a, b, mesh[(a, b)].hex()))
    for a, b in sorted(macmesh):
        f.write("mac %d_%d %s\n" % (a, b, macmesh[(a, b)].hex()))


def _write_projection(f, n, t, p, mesh, macmesh, genesis):
    """seat p's ROW: one line per recipient q, key pre-resolved to PSK(p,q) and
    indexed by the recipient id (self-relative).  This is all seat p is dealt.
    The mac row is the static wire-hmac key: it never enters the keystate and
    never ratchets.  The genesis is the ONE dealt field that is not a secret and
    not a row: every seat gets the SAME value, because a chain whose base
    differs between two seats never joins."""
    f.write("N %d\n" % n)
    f.write("T %d\n" % t)
    f.write("genesis %s\n" % genesis.hex())
    for q in range(n):
        if q == p:
            continue
        f.write("psk %d %s\n" % (q, mesh[_pair(p, q)].hex()))
    for q in range(n):
        if q == p:
            continue
        f.write("mac %d %s\n" % (q, macmesh[_pair(p, q)].hex()))


def cmd_setup(n, t):
    if not (n >= 3 and 2 <= t <= n - 1):     # T > 1: at T = 1 every share is the key
        sys.exit("setup: need N>=3 and 2<=T<=N-1 (got N=%d T=%d)" % (n, t))
    _mkdirs()
    # full pairwise meshes: the ratcheting mask keys (distribution AND exchange)
    # and the static wire-hmac mac keys
    mesh = {(a, b): secrets.token_bytes(64)
            for a in range(n) for b in range(a + 1, n)}
    macmesh = {(a, b): secrets.token_bytes(64)
               for a in range(n) for b in range(a + 1, n)}
    genesis = secrets.token_bytes(16)          # CM_SIGN_HSZ; public, common to all
    # drive/config.txt: the dealer's full view -- every pairwise PSK.  It lives
    # with the driver because the driver IS the operator, and no C program ever
    # reads it: the phase programs take a priv/<p>_config.txt row.
    with open(OPERCFG, "w") as f:
        _write_operator(f, n, t, mesh, macmesh, genesis)
    # deal each seat only its row, then seed its dispersal-0 keystate.
    for p in range(n):
        with open(os.path.join(HERE, _cfgpath(p)), "w") as f:
            _write_projection(f, n, t, p, mesh, macmesh, genesis)
    _seed_all()
    _boot_books()
    write_blob("cryptoMule test blob -- compressible payload. " * 64)
    print("setup: N=%d T=%d (full pairwise mask + mac meshes; genesis %s;"
          " SSS geometry seed-derived per-distribution)" % (n, t, genesis.hex()))


def write_blob(text):
    with open(os.path.join(HERE, "priv", "00_blob.bin"), "wb") as f:
        f.write(text.encode() if isinstance(text, str) else text)


def _seed_all():
    """(re)seed every per-seat keystate at dispersal 0 from its config row."""
    for p in range(_cfg_n()):
        row = {}
        for line in open(os.path.join(HERE, _cfgpath(p))):
            w = line.split()
            if not w:
                continue
            if w[0] == "psk":
                row[int(w[1])] = w[2]            # w[1] = recipient seat id
        with open(os.path.join(HERE, _kspath(p)), "w") as f:
            f.write("process: 0\n")
            for q in sorted(row):
                f.write("psk_%02d: %s\n" % (q, row[q]))   # psk_<recipient>: <hex>


def _cfg_n():
    for line in open(OPERCFG):
        if line.startswith("N "):
            return int(line.split()[1])
    sys.exit("drive/config.txt: no N")


def _mac(a, b):
    """operator-ledger mac(a,b) hex, for the wire messages the driver
    synthesizes itself (the run files) or re-authenticates as a BYZANTINE
    sender (the hostile arm)."""
    for line in open(OPERCFG):
        w = line.split()
        if len(w) == 3 and w[0] == "mac" and w[1] == "%d_%d" % (min(a, b), max(a, b)):
            return w[2]
    sys.exit("drive/config.txt: no mac %d_%d" % (a, b))


def _mac0(p):
    return _mac(0, p)


def _boot_books():
    """bootstrap every recipient's book (priv/<p>_book.txt) to the OOB root
    pub_0.  Needs BOTH the keychain (ctx_00) and the deal (drive/config.txt);
    the scenarios run keychain and setup in either order, so both call here and
    the boot happens when the second half arrives."""
    ctx = os.path.join(HERE, "priv", "00_ctx_00.bin")
    if not (os.path.exists(ctx) and os.path.exists(OPERCFG)):
        return
    pub0 = subprocess.check_output(
        ["./mlspub", "priv/00_ctx_00.bin"], cwd=HERE).decode().strip()
    for p in range(1, _cfg_n()):
        with open(os.path.join(HERE, "priv", "%02d_book.txt" % p), "w") as f:
            f.write("process: 0\ncurrent: %s\n" % pub0)


def cmd_dist(ctx="priv/00_ctx_00.bin", process=0, fault=None, other=None):
    cmd = ["./distribute", "priv/00_config.txt", "priv/00_blob.bin", ctx, ".", str(process)]
    if fault:
        cmd.append(fault)
    if other:                                  # the signer fault's other context
        cmd.append(other)
    r = subprocess.run(cmd, cwd=HERE)
    if r.returncode:
        sys.exit("distribute failed (%d)" % r.returncode)


def _sys(prog, i):
    """run prog (receive/exchange/assemble) as recipient seat i+1 (index i)."""
    return subprocess.run(
        ["./" + prog, _cfgpath(i + 1), str(i), "."], cwd=HERE).returncode


def cmd_phase(prog):
    """run prog for every recipient seat (1..n-1)."""
    return [_sys(prog, i) for i in range(_cfg_n() - 1)]


def rotate_verify(k):
    """rotation k: the initiator sends the signed successor (its apex, the hash
    of the successor pub, and the sign message carrying that pub) to every
    recipient (directed, hmac'd), and EACH recipient verifies its own message
    against its own book.  Returns the count of recipients that installed."""
    subprocess.run(["./rotate", "priv/00_config.txt", "priv/00_ctx_%02d.bin" % k,
                    "priv/00_ctx_%02d.bin" % (k + 1), str(k), "."], cwd=HERE)
    return sum(1 for p in range(1, _cfg_n())
               if subprocess.run(["./rotverify", _cfgpath(p), str(k), str(p - 1), "."],
                                 cwd=HERE).returncode == 0)


def ratchet_all(process, anchor, systems):
    """Advance every seat's mask chain one step on the public anchor -- the
    dispersal's CHAIN LINK (see _chain), so the next step is reachable only by a
    holder of this dispersal's result.  A phase program never does this; the driver
    does it once per payload, AFTER the payload's whole flow (distribute, receive,
    exchange, assemble -- all masked under the one step being stepped past) --
    never at send.  The next payload's distribute is the first thing masked under
    the new step.  In a deployment the link is fixed externally.  See the module
    docstring 'FORWARD SECRECY'."""
    for p in systems:
        subprocess.run(["./ratchet", _cfgpath(p), str(process), anchor], cwd=HERE)


def cmd_demo(n, t):
    cmd_keychain(1)            # ctx_00, ctx_01; book bootstrapped to pub_0
    cmd_setup(n, t)
    _reset_floor()
    print("-- distribute/receive/exchange/assemble at one step | ratchet (pub_0) --")
    npass, total, _, _ = _payload_steps("priv/00_ctx_00.bin", 0, 0, range(n))
    print("RESULT: %d/%d seats reconstructed the blob (one step, no ratchet inside the flow)"
          % (npass, total))
    sys.exit(0 if npass == total else 1)


def cmd_session(processes, n, t):
    """message after message under a rotating identity (payload + rotation)."""
    cmd_keychain(processes)       # ctx_0..ctx_processes + book at pub_0
    cmd_setup(n, t)            # config (stable, operator-dealt once)
    _reset_floor()
    step = 0                  # mask-chain step, advances ONE per payload (single ratchet after the flow)
    link = None               # chain link, folded from the dealt genesis forward
    allok = 0
    for k in range(processes):
        write_blob("cryptoMule process %d payload -- compressible message. " % k * 48)
        print("=== dispersal %d: payload signed by ctx_%d, verified vs book current pub_%d ==="
              % (k, k, k))
        npass, total, step, link = _payload_steps("priv/00_ctx_%02d.bin" % k, k, step,
                                                  range(n), link)
        print("  payload: %d/%d reconstructed (single ratchet after the flow; PSK step now %d)"
              % (npass, total, step))
        rotate_verify(k)                                                    # books advance
        allok += (npass == total)
    print("SESSION: %d/%d dispersals reconstructed under rotating identity, one chain step per payload"
          % (allok, processes))
    # a refused receive REPLACES the record: a distribution for a dispersal the
    # book is not at (books are at R, this says R+1) is refused, and exchange
    # then has nothing to forward -- not the validated unit of dispersal R-1
    cmd_dist("priv/00_ctx_%02d.bin" % processes, processes + 1)
    rcs = cmd_phase("receive")
    stale = (all(r != 0 for r in rcs) and all(_sys("exchange", i) != 0 for i in range(n - 1))
             and not os.path.exists(os.path.join(HERE, "wire", "exch", "01_to_02_apex.txt")))
    print("refused receive leaves nothing to forward: %s" % ("yes" if stale else "NO (BUG)"))
    sys.exit(0 if allok == processes and stale else 1)


def cmd_fwdsec(n, t):
    """forward secrecy of the SINGLE per-payload ratchet, taken after the flow.
    Both phases of a payload mask under ONE step (domains CM_DOM_DIST and
    CM_DOM_EXCH); once the ratchet steps past it, the harvested distribution
    shares AND the exchange legs are unreadable at the current step, and
    re-deriving that step reads them again.  The oracles are the live phase
    programs: `receive` (domain D) and `assemble` (domain X).

    The ratchet also BIRTHS the retention floor holding the step it stepped
    past, so the same legs still read in resend mode (that is the retention
    obligation, and the walk landing on the right step is what proves the
    floor's indexing) until `release` moves the floor past the dispersal:
    forward secrecy starts at the floor, not at the step."""
    cmd_keychain(1)
    cmd_setup(n, t)
    _reset_floor()
    write_blob("forward-secrecy demonstration payload -- compressible. " * 40)
    total = n - 1
    cmd_dist("priv/00_ctx_00.bin", 0)
    n_recv = sum(1 for r in cmd_phase("receive") if r == 0)    # domain D at the step
    _retain(0, n)                                # each holder BANKS what it validated: the resend read below needs it at T = R
    gate_offset(_apex())
    cmd_phase("exchange")
    n_asm = sum(1 for r in cmd_phase("assemble") if r == 0)    # domain X at the step
    print("payload at its step: received %d/%d, assembled %d/%d" % (n_recv, total, n_asm, total))
    anchor = _apex()
    link = _chain(None, _msg())
    # the single ratchet, after the flow: the step -> the next (wipes the current key)
    ratchet_all(0, link, range(n))
    _write_anchorlog([link])
    n_recv_post = sum(1 for r in cmd_phase("receive") if r == 0)
    n_asm_post = sum(1 for r in cmd_phase("assemble") if r == 0)
    print("under the post-ratchet keystate: received %d/%d, assembled %d/%d (expect 0, 0)"
          % (n_recv_post, total, n_asm_post, total))
    # the floor born at the ratchet holds the step the flow masked under
    n_floor = sum(1 for i in range(total)
                  if subprocess.run(["./assemble", _cfgpath(i + 1), str(i), ".", "0", "anchorlog.txt"],
                                    cwd=HERE).returncode == 0)
    print("the same legs off the retention floor (resend mode): %d/%d" % (n_floor, total))
    # release past the dispersal: the base is gone at every seat
    for p in range(1, n):
        subprocess.run(["./release", _cfgpath(p), "1", "anchorlog.txt"], cwd=HERE)
    n_rel = sum(1 for i in range(total)
                if subprocess.run(["./assemble", _cfgpath(i + 1), str(i), ".", "0", "anchorlog.txt"],
                                  cwd=HERE).returncode == 0)
    n_rel += sum(1 for p in range(1, n) if os.path.exists(os.path.join(HERE, "priv", "%02d_assemble.txt" % p)))
    print("after release past dispersal 0, off the floor: %d/%d (expect 0; no record left either)" % (n_rel, total))
    # re-derive the step (re-seed back to step 0) -> readable again
    _seed_all()
    n_re_recv = sum(1 for r in cmd_phase("receive") if r == 0)
    n_re_asm = sum(1 for r in cmd_phase("assemble") if r == 0)
    print("same shares and legs with the step restored: received %d/%d, assembled %d/%d"
          % (n_re_recv, total, n_re_asm, total))
    # a keystate short of any row is refused, at the current step and at the
    # floor: the dealt key in its place would read what the chain stepped past
    ksFull = os.path.join(HERE, _kspath(1))
    ok_short = True
    for prefix, cmd, word in (("psk_", ["./receive", _cfgpath(1), "0", "."], "no keystate"),
                              ("fpsk_", ["./release", _cfgpath(1), "0", "anchorlog.txt"], "no floor")):
        if prefix == "fpsk_":                  # a step births the floor to read
            ratchet_all(0, "00" * 16, [1])
        cleanKs = open(ksFull).read()
        rows = [l.split(":")[0] for l in cleanKs.splitlines() if l.startswith(prefix)]
        if not rows:
            sys.exit("fwdsec: keystate carries no %s rows" % prefix)
        for row in rows:
            open(ksFull, "w").write("".join(l for l in cleanKs.splitlines(True) if not l.startswith(row + ":")))
            e = subprocess.run(cmd, cwd=HERE, capture_output=True).stderr.decode()
            ok_short = ok_short and word in e
        open(ksFull, "w").write(cleanKs)
    print("keystate short of a row: %s" % ("refused" if ok_short else "ACCEPTED (BUG)"))
    ok = (n_recv == total and n_asm == total and n_recv_post == 0 and n_asm_post == 0
          and n_floor == total and n_rel == 0 and n_re_recv == total and n_re_asm == total
          and ok_short)
    print("FORWARD SECRECY (both phases at one step; bounded by the floor): %s"
          % ("demonstrated" if ok else "NOT shown"))
    sys.exit(0 if ok else 1)


def _szinfo():
    """(private-data size, signing-offset count) for the configured MLS context."""
    out = subprocess.check_output(["./cmprsz"], cwd=HERE).split()
    return int(out[0]), int(out[1])


def _apex():
    """the public anchor of the most recent payload distribution: recomputed
    from a recipient's sign message under the pub its book holds as current
    and the offset the signature yields, via ./cmapex (the arithmetic, not
    the apex message's field).  Every arm
    calls this while seat 1's book is at the signing context's pub."""
    return subprocess.check_output(
        ["./cmapex", "wire/dist/00_to_01_sign.txt", "priv/01_book.txt"],
        cwd=HERE).decode().strip()


def _msg():
    """the MESSAGE hash of the most recent payload distribution: the orig_hash
    its signed header carries.  This, not the apex, is what the chain folds:
    the application that gave the message knows it, and nothing of the roots."""
    return _field("wire/dist/00_to_01_sign.txt", "orig_hash")


def _genesis():
    """the dealt chain base (config's genesis row)."""
    for line in open(OPERCFG):
        w = line.split()
        if len(w) == 2 and w[0] == "genesis":
            return w[1]
    sys.exit("drive/config.txt: no genesis")


def _chain(prev, msg, cfg="priv/00_config.txt"):
    """fold one link of the dispersal chain: chain_{k+1} = H(chain_k || msg), msg
    the dispersal's message hash.  prev=None starts from the DEALT genesis of `cfg`.

    The link, not a bare value, is what the mask chain ratchets on, so the
    trigger sequence is pinned from the dealt base forward and a seat that folds
    a different message hash (or a different genesis) is off the chain from there on.
    Agreement on the message itself is ASSUMED -- see cmChain in cm.h.  cfg is a
    parameter because every seat folds with ITS OWN dealt genesis: that is what
    the wrong-genesis arm of `drive.py chain` exercises."""
    return subprocess.check_output(
        ["./cmchain", cfg, prev or "-", msg], cwd=HERE).decode().strip()


def cmd_catchup(processes, n, t):
    """recovery key-half: a survivor present only at dispersal 0 fast-forwards its
    stale keystate over the public anchor sequence to the live dispersal and
    reads it.  The live seats ran every dispersal; the survivor (seat 1) missed
    all but dispersal 0."""
    if processes < 2:
        sys.exit("catchup: need dispersals>=2")
    cmd_keychain(processes)
    cmd_setup(n, t)
    _reset_floor()
    surv = 0                               # survivor = recipient index 0 (seat 1)
    skey = os.path.join(HERE, _kspath(surv + 1))
    stale = os.path.join(HERE, "drive", "stale.txt")
    recipient = os.path.join(HERE, "drive", "recipient.txt")
    alog = os.path.join(HERE, "anchorlog.txt")
    shutil.copyfile(skey, stale)           # the survivor's last-seen keys (step 0)
    target = processes - 1
    links = {}
    link = None
    step = 0
    for k in range(target):                # history payloads: dist-only chain advance
        write_blob("cryptoMule catchup history process %d. " % k * 32)
        cmd_dist("priv/00_ctx_%02d.bin" % k, k)
        links[k] = link = _chain(link, _msg())
        ratchet_all(step, link, range(n))      # one chain step (no phases run here)
        step += 1
        rotate_verify(k)
    # the live payload: one step for its whole flow, the single ratchet after it
    write_blob("cryptoMule catchup LIVE process %d payload. " % target * 40)
    cmd_dist("priv/00_ctx_%02d.bin" % target, target)
    cmd_phase("receive")
    apex_live = _apex()
    gate_offset(apex_live)
    cmd_phase("exchange")
    live = sum(1 for r in cmd_phase("assemble") if r == 0)
    link = _chain(link, _msg())
    ratchet_all(step, link, range(n))
    # anchorlog = every payload's chain link, the live one included; the survivor
    # must reach the live STEP, which the links of dispersals 0 .. target-1 carry it to
    with open(alog, "w") as f:
        for k in range(target):
            f.write("anchor%02d: %s\n" % (k, links[k]))
        f.write("anchor%02d: %s\n" % (target, link))
    # the survivor: stale step 0 -> fast-forward over the public anchors -> the live step
    if subprocess.run(["./catchup", _cfgpath(surv + 1), stale, alog, "0", str(target),
                       recipient], cwd=HERE).returncode:
        sys.exit("catchup failed")
    shutil.copyfile(recipient, skey)            # install the caught-up keystate
    caught = (_sys("assemble", surv) == 0)
    shutil.copyfile(stale, skey)           # control: no fast-forward
    stalen = (_sys("assemble", surv) == 0)
    shutil.copyfile(recipient, skey)            # leave the survivor caught up
    total = n - 1
    print("live seats (present every dispersal):  %d/%d read dispersal %d" % (live, total, target))
    print("survivor caught up over %d anchors: %s read dispersal %d"
          % (target, "DID" if caught else "did NOT", target))
    print("survivor WITHOUT fast-forward:      %s (expect did NOT)"
          % ("DID (BUG)" if stalen else "did NOT"))
    ok = live == total and caught and not stalen
    print("CATCH-UP KEY FAST-FORWARD: %s" % ("demonstrated" if ok else "NOT shown"))
    sys.exit(0 if ok else 1)


def cmd_mixed(n, t):
    """payloads and pure MLS rotations interleave.  A rotation masks nothing, so
    it does NOT ratchet the mask chain and its pub never enters the anchorlog --
    only payloads do.  The book (identity) still advances on every rotation.  A
    recipient rebuilds its mask key from the payload apexes ALONE and reads the live
    payload, proving the interleaved rotations left the mask chain untouched."""
    rots = 2                               # two pure rotations between payloads
    cmd_keychain(rots)                     # ctx_00..ctx_0<rots>; book current pub_0
    cmd_setup(n, t)
    _reset_floor()
    surv = 0                               # survivor = recipient index 0 (seat 1)
    skey = os.path.join(HERE, _kspath(surv + 1))
    stale = os.path.join(HERE, "drive", "stale.txt")
    recipient = os.path.join(HERE, "drive", "recipient.txt")
    alog = os.path.join(HERE, "anchorlog.txt")
    shutil.copyfile(skey, stale)           # the recipient's last-seen keys (step 0)
    links = []
    link = None
    step = 0
    # payload A at identity pub_0: the mask chain advances (one step), link logged
    write_blob("cryptoMule mixed payload A. " * 32)
    cmd_dist("priv/00_ctx_00.bin", 0)
    link = _chain(link, _msg())
    links.append(link)
    ratchet_all(step, link, range(n)); step += 1
    print("  payload  : mask ratcheted, chain link logged")
    # pure rotations: the books advance pub_0 -> pub_<rots>, the mask is UNTOUCHED
    for k in range(rots):
        rotate_verify(k)
        print("  rotation : identity pub_%d -> pub_%d, NOT ratcheted, not logged" % (k, k + 1))
    # payload B: mask chain advances, link logged.  Signed by ctx_01, whose
    # payload signing offset is unspent -- ctx_<rots>'s one payload signing offset is the live
    # payload's, and a signing offset is signed once (B is a dist-only chain step, never
    # received, so its signer is not verified against a book)
    write_blob("cryptoMule mixed payload B. " * 48)
    cmd_dist("priv/00_ctx_01.bin", rots)
    link = _chain(link, _msg())
    links.append(link)
    ratchet_all(step, link, range(n)); step += 1
    print("  payload  : mask ratcheted, chain link logged")
    # live payload at pub_<rots>: one step for its whole flow, the ratchet after it
    write_blob("cryptoMule mixed LIVE payload. " * 40)
    cmd_dist("priv/00_ctx_%02d.bin" % rots, rots)
    cmd_phase("receive")
    apex_live = _apex()
    gate_offset(apex_live)
    cmd_phase("exchange")
    live = sum(1 for r in cmd_phase("assemble") if r == 0)
    live_step = step
    link = _chain(link, _msg())
    ratchet_all(step, link, range(n)); step += 1
    # the anchorlog carries ONLY payload links (A, B, live) -- a rotation folds no
    # apex and mints no link; the links of A and B carry the recipient to the
    # live step
    links.append(link)
    with open(alog, "w") as f:
        for k, a in enumerate(links):
            f.write("anchor%02d: %s\n" % (k, a))
    # recipient: stale step 0 -> fast-forward over the payload anchors ALONE -> the live step
    if subprocess.run(["./catchup", _cfgpath(surv + 1), stale, alog, "0", str(live_step),
                       recipient], cwd=HERE).returncode:
        sys.exit("catchup failed")
    shutil.copyfile(recipient, skey)
    caught = (_sys("assemble", surv) == 0)
    shutil.copyfile(stale, skey)
    stalen = (_sys("assemble", surv) == 0)
    shutil.copyfile(recipient, skey)
    total = n - 1
    print("live (mask ratcheted on payloads only):     %d/%d" % (live, total))
    print("recipient (caught up over %d payload anchors):     %s" % (live_step, "read" if caught else "FAILED"))
    print("recipient without fast-forward:                   %s (expect FAILED)"
          % ("read (BUG)" if stalen else "FAILED"))
    ok = live == total and caught and not stalen
    print("ROTATIONS DO NOT RATCHET THE MASK: %s" % ("demonstrated" if ok else "NOT shown"))
    sys.exit(0 if ok else 1)


def cmd_offsets(n, t):
    """offset run + floor: one identity signs signing offset 0 (rotation) and signing offsets 1..N
    (payloads), sent DIRECTED to every recipient; every recipient's own floor
    accepts the monotone offsets and rejects a re-injection."""
    cmd_keychain(1)            # ctx_00 (= book current pub_0), ctx_01 (successor)
    cmd_setup(n, t)
    _reset_floor()             # fresh high-waters for this identity
    _, nslots = _szinfo()
    npay = nslots - 1
    r = subprocess.run(["./offsetrun", "priv/00_config.txt", "priv/00_ctx_00.bin",
                        "priv/00_ctx_01.bin", str(npay), "."], cwd=HERE)
    if r.returncode:
        sys.exit("offsetrun failed (%d)" % r.returncode)
    accepts = 0
    for s in range(nslots):    # offsets 0..nslots-1 in order: all above every floor
        if all(subprocess.run(["./offsetgate", _cfgpath(p), str(s), str(p - 1), "."],
                              cwd=HERE).returncode == 0 for p in range(1, n)):
            accepts += 1
    print("monotone offset run: %d/%d offsets accepted at all %d recipients"
          % (accepts, nslots, n - 1))
    reinj = subprocess.run(["./offsetgate", _cfgpath(1), "1", "0", "."],
                           cwd=HERE).returncode
    print("re-injection at signing offset 1 under high-water %d: %s"
          % (nslots - 1, "REJECTED" if reinj else "ACCEPTED (BUG)"))
    ok = (accepts == nslots and reinj != 0)
    print("OFFSET FLOOR (re-injection defense): %s"
          % ("demonstrated" if ok else "NOT shown"))
    sys.exit(0 if ok else 1)


SLOT_PAY = 1   # CM_SLOT_PAY: the payload signing offset (signing offset 0 is the rotation's)


def _floor_hw():
    """seat 1's MLS offset-floor high-water, or None if no floor recorded yet."""
    p = os.path.join(HERE, "priv", "01_floor.txt")
    if not os.path.exists(p):
        return None
    for line in open(p):
        if line.startswith("highwater: "):
            return int(line.split(": ", 1)[1])
    return None


def _ks_step(p):
    """seat p's keystate step (the keystate's `process` counter the ratchet steps)."""
    for line in open(os.path.join(HERE, _kspath(p))):
        if line.startswith("process: "):
            return int(line.split(": ", 1)[1])
    return None


def _ks_floor(p):
    """seat p's retention floor -- the oldest dispersal it can still re-derive a
    serving form for.  None until the first ratchet births it."""
    for line in open(os.path.join(HERE, _kspath(p))):
        if line.startswith("floor: "):
            return int(line.split(": ", 1)[1])
    return None


def _gate(p, slot):
    """run seat p's MLS offset floor over wire/run_<slot>_to_<p>.txt and return
    the verdict word offsetgate printed: ACCEPT, RETRY or REJECT."""
    e = subprocess.run(["./offsetgate", _cfgpath(p), str(slot), str(p - 1), "."],
                       cwd=HERE, capture_output=True).stderr.decode()
    for w in ("ACCEPT", "RETRY", "REJECT"):
        if w + ":" in e:
            return w
    return "?"


def _retain(process, n):
    """every recipient keeps its validated receive fragment for this dispersal.
    Ordinary storage -- what a resend needs BEYOND it is the key, which the
    forward-only chain destroys unless the floor holds a base (see exchange.c)."""
    for p in range(1, n):
        src = os.path.join(HERE, "priv", "%02d_recv.txt" % p)
        if os.path.exists(src):
            shutil.copyfile(src, os.path.join(HERE, "priv", "%02d_recv_%02d.txt"
                                              % (p, process)))


def _field(path, name):
    """one named field's text from a phase/wire file, or None."""
    for line in open(os.path.join(HERE, path)):
        if line.startswith(name + ": "):
            return line.split(": ", 1)[1].strip()
    return None


def _write_anchorlog(links):
    """the public chain-link sequence, the input every forward walk shares
    (./catchup, ./release, and the resend modes of exchange and assemble)."""
    with open(os.path.join(HERE, "anchorlog.txt"), "w") as f:
        for k, a in enumerate(links):
            f.write("anchor%02d: %s\n" % (k, a))


def _reset_floor():
    """clear the MLS offset floors so a demo's first gate_offset inits fresh
    high-waters (a stale floor would skew it)."""
    for p in range(1, _cfg_n()):
        f = os.path.join(HERE, "priv", "%02d_floor.txt" % p)
        if os.path.exists(f):
            os.remove(f)


def _distribute_runfile(anchor, slot=SLOT_PAY):
    """synthesize wire/run_<slot>_to_<p>.txt (directed, per recipient) from the
    distribution so offsetgate can advance the MLS offset floor from the
    distribution's OWN signature: anchor = the apex (cmapex), mls_sig = the one
    the dist fragment carries (offsetgate reads the offset from the signature
    structure).  Seat 1's signature serves every seat: the apex commits the
    offset, so every seat that admitted this apex holds it at that one offset
    (`twoslot` gates each seat on its own copy, the case where they differ).  The driver plays the sender, so it appends the pairwise wire
    hmac itself (./cmhmac, keys from the operator ledger)."""
    sig = None
    for line in open(os.path.join(HERE, "wire", "dist", "00_to_01_sign.txt")):
        if line.startswith("mls_sig: "):
            sig = line.split(": ", 1)[1].strip()
            break
    for p in range(1, _cfg_n()):
        path = os.path.join(HERE, "wire", "run_%02d_to_%02d.txt" % (slot, p))
        with open(path, "w") as f:
            f.write("phase: payload\n")
            f.write("slot: %d\n" % slot)
            f.write("anchor: %s\n" % anchor)
            f.write("mls_sig: %s\n" % sig)
        subprocess.run(["./cmhmac", _mac0(p), "0", str(p), path], cwd=HERE, check=True)


def gate_offset(apex):
    """Advance every recipient's MLS signing-offset high-water (offsetgate) from
    the distribution's own signature, at receive -- the signature is known then.

    TWO ANCHORS, TWO JOBS, TWO MOMENTS.  The APEX is what the initiator signed, so
    it is what the offset floor records and compares, and it is recorded here.
    The dispersal's CHAIN LINK is what the mask ratchet steps on (ratchet_all), so
    that the next step is reachable only by a holder of this dispersal's result, and
    that step is taken after the flow."""
    _distribute_runfile(apex)
    for p in range(1, _cfg_n()):
        if subprocess.run(["./offsetgate", _cfgpath(p), str(SLOT_PAY), str(p - 1), "."],
                          cwd=HERE).returncode:
            # receive read the same floor and admitted this signature, so a
            # refusal here is the driver contradicting itself, never a verdict
            sys.exit("offset floor refused at seat %d a payload receive admitted" % p)


def _payload_steps(ctx, process, step, systems, prev=None):
    """one full payload under ONE mask-chain step, the SINGLE ratchet after it:
        distribute(s) receive(s) exchange(s) assemble(s) | RATCHET
    The two phases mask under separate domains (CM_DOM_DIST / CM_DOM_EXCH), so one
    step serves the whole flow; the ratchet is keyed on the payload's chain link
    and the NEXT payload distributes at s+1.  process = the dispersal index (the
    dist-file header); step = the mask-chain step the flow runs under; prev = the
    previous chain link (None = the dealt genesis).  Returns (npass, total,
    step+1, link)."""
    cmd_dist(ctx, process)
    cmd_phase("receive")                          # recipients unmask at s, domain D (local)
    gate_offset(_apex())                          # the offset floor records the signature
    cmd_phase("exchange")                         # senders mask at s, domain X (local)
    rcs = cmd_phase("assemble")                   # recipients unmask at s, domain X (local)
    link = _chain(prev, _msg())
    ratchet_all(step, link, systems)              # the flow is done: s -> s+1
    return sum(1 for r in rcs if r == 0), len(rcs), step + 1, link


def cmd_steps(n, t):
    """The SINGLE per-payload mask-chain ratchet, after the flow -- demonstrated.

    Distribute, receive, exchange and assemble of one payload all mask under ONE
    step, CM_DOM_DIST and CM_DOM_EXCH keeping the two phases' keystreams apart; the
    ratchet is taken once the flow is done, keyed on the payload's chain link, and
    the NEXT payload's distribute is the first thing masked under the new step.
    Two records advance, at two moments:
      - the MLS signing-offset high-water at receive (the signature is known then),
      - the pairwise mask chain after assemble (one step).
    The four phase programs never advance either; the driver does (in a deployment
    the anchor is fixed externally), never at send."""
    cmd_keychain(1)
    cmd_setup(n, t)
    _reset_floor()
    write_blob("cryptoMule step-demo payload -- compressible. " * 40)

    # the flow, PSK step s0 throughout: domain D then domain X
    cmd_dist("priv/00_ctx_00.bin", 0)
    cmd_phase("receive")                         # recipients unmask at s0, domain D (local)
    hw0, s0 = _floor_hw(), _ks_step(1)
    anchor = _apex()
    gate_offset(anchor)                          # the offset record, at receive
    hw1 = _floor_hw()
    cmd_phase("exchange")                        # senders mask at s0, domain X (local)
    asm = cmd_phase("assemble")                  # recipients unmask at s0, domain X (local)
    npass, total = sum(1 for r in asm if r == 0), n - 1
    s_flow = _ks_step(1)                         # unmoved through the flow

    # the single ratchet, after the flow: PSK one step
    ratchet_all(s0, _chain(None, _msg()), range(n))
    s1 = _ks_step(1)
    print("offset floor at receive: %s -> %s ; PSK step through the flow: %d ; ratchet after it: %d -> %d"
          % (hw0, hw1, s_flow, s0, s1))

    ok = (npass == total
          and hw0 is None and hw1 is not None     # offset recorded at receive
          and s_flow == s0                        # no step inside the flow
          and s1 == s0 + 1)                       # mask chain advanced one step after it
    print("reconstruct: %d/%d at the one step" % (npass, total))
    print("SINGLE RATCHET AFTER THE FLOW (one step for both phases; domains split them): %s"
          % ("demonstrated" if ok else "NOT shown"))
    sys.exit(0 if ok else 1)


def _rotgate(p, process):
    """run seat p's rotverify for dispersal and return its verdict word:
    INSTALL, RETRY or REJECT."""
    e = subprocess.run(["./rotverify", _cfgpath(p), str(process), str(p - 1), "."],
                       cwd=HERE, capture_output=True).stderr.decode()
    for w, word in (("RETRY:", "RETRY"), ("REJECT:", "REJECT"), ("ok: installed", "INSTALL")):
        if w in e:
            return word
    return "?"


def cmd_retry(n, t):
    """RETRY vs RE-AUTHORING at the MLS offset floor.

    A monotone-only floor is wrong whenever the same signed bytes are presented
    more than once: the second copy is the same message, and rejecting it rejects
    an honest one.  The floor therefore records the accepted
    APEX beside the high-water and splits the equal-offset case by what was
    signed -- byte-identical is a RETRY, a different apex at the same one-time
    signing offset is leaked key material and a rejected re-authoring.  Nine arms, in
    the order a reader should take them: four at the floor itself (offsetgate),
    two showing receive and assemble READ that floor, one showing the floor is
    a LIVE gate (an older dispersal read in resend mode is below it by
    definition), two giving a re-presented rotation the same split at the book
    (rotverify)."""
    cmd_keychain(2)
    cmd_setup(n, t)
    _reset_floor()
    write_blob("cryptoMule retry demonstration payload. " * 40)
    cmd_dist("priv/00_ctx_00.bin", 0)
    cmd_phase("receive")
    _retain(0, n)                                # banked before the re-authored distribution replaces the live record
    link0 = _chain(None, _msg())         # the honest payload's chain link
    _distribute_runfile(_apex())          # the distribution's own offset-1 signature

    first = _gate(1, SLOT_PAY)            # 1: fresh -- offset above the floor
    hw1 = _floor_hw()
    for p in range(2, n):                 # every other recipient's floor, for 5/6
        _gate(p, SLOT_PAY)
    again = _gate(1, SLOT_PAY)            # 2: the same bytes again -- RETRY
    hw2 = _floor_hw()
    # 3: the SAME identity signs the SAME signing offset over a DIFFERENT apex.  This is
    # not merely a policy violation: MLS signing offsets are one-time, so the two signatures
    # together leak the signing offset's private material.  The floor sees offset == its
    # high-water with an anchor it did not record and refuses.
    subprocess.run(["./offsetrun", "priv/00_config.txt", "priv/00_ctx_00.bin",
                    "priv/00_ctx_01.bin", "1", "."], cwd=HERE,
                   capture_output=True)
    reauth = _gate(1, SLOT_PAY)
    stale = _gate(1, 0)                   # 4: an older offset -- plain re-injection

    # the honest payload runs on to its exchange legs, at the flow's one step
    cmd_phase("exchange")

    print("fresh signature at offset 1        : %s (high-water -> %s)" % (first, hw1))
    print("byte-identical re-presentation     : %s (high-water %s, unmoved)" % (again, hw2))
    print("re-authored: same signing offset, new apex : %s" % reauth)
    print("stale offset 0 under high-water 1  : %s" % stale)
    ok = (first == "ACCEPT" and again == "RETRY" and hw1 == hw2 == 1
          and reauth == "REJECT" and stale == "REJECT")

    # 5: the phase programs READ the floor.  A re-authored DISTRIBUTION -- the
    # same identity signs a second payload apex at the same signing offset -- verifies as
    # the initiator's, and receive refuses it on the floor it never writes.
    write_blob("cryptoMule retry demonstration, re-authored. " * 40)
    cmd_dist("priv/00_ctx_00.bin", 0)
    rcs = cmd_phase("receive")
    ok5 = all(r != 0 for r in rcs) and all(
        _field("priv/%02d_recv.txt" % p, "sig_ok") == "yes"
        and _field("priv/%02d_recv.txt" % p, "offset_ok") == "no" for p in range(1, n))
    print("re-authored distribution at receive: %s"
          % ("REFUSED on the floor at all %d recipients" % (n - 1) if ok5 else "ACCEPTED (BUG)"))
    # 6: a forwarder that vouches for it anyway (its own receive record edited)
    # gets it past nobody: assemble reads the floor at the lock
    rec = os.path.join(HERE, "priv", "01_recv.txt")
    vouched = open(rec).read().replace("offset_ok: no", "offset_ok: yes")
    open(rec, "w").write(vouched)
    if _sys("exchange", 0):
        sys.exit("retry: seat 1 did not forward the vouched unit")
    for i in range(1, n - 1):
        _sys("assemble", i)
    ok6 = all("1" not in _asm(p, "share_senders") + _asm(p, "shard_senders")
              for p in range(2, n))
    print("forwarded anyway                   : %s"
          % ("NO assembler locks on it; the honest legs still lock" if ok6 else "LOCKED (BUG)"))

    # the flow is done: the single ratchet (which births the retention floor,
    # holding the step the flow masked under) and its chain link logged -- what
    # the resend read of arm 6b walks from
    ratchet_all(0, link0, range(n))
    _write_anchorlog([link0])

    # 6b: the floor is a LIVE gate.  Under the multi-payload cadence the
    # high-water moves past an older dispersal's offset (here: signing offset 2 signed and
    # gated, high-water 2), and that dispersal, read back in resend mode, is
    # below the high-water by definition -- the chain walk is its gate, and
    # the honest legs of dispersal 0 still assemble.
    subprocess.run(["./offsetrun", "priv/00_config.txt", "priv/00_ctx_00.bin",
                    "priv/00_ctx_01.bin", "2", "."], cwd=HERE, capture_output=True)
    hw3 = _gate(1, 2)
    old = subprocess.run(["./assemble", _cfgpath(1), "0", ".", "0", "anchorlog.txt"],
                         cwd=HERE).returncode == 0 and _asm_result(1) == "PASS"
    ok6b = hw3 == "ACCEPT" and _floor_hw() == 2 and old
    print("older dispersal read below high-water: %s"
          % ("PASS in resend mode (high-water %s)" % _floor_hw() if ok6b else "REFUSED (BUG)"))

    # 7/8: the same split for a ROTATION.  Once the book has moved past dispersal
    # 0, a copy of the installed rotation presented again is a RETRY; a second successor
    # signed at the same rotation signing offset is a REJECT (leaked signing offset).
    if rotate_verify(0) != n - 1:
        sys.exit("retry: rotation 0 did not install everywhere")
    rrot = _rotgate(1, 0)
    if rotate_verify(1) != n - 1:          # two dispersals on, still the same rotation
        sys.exit("retry: rotation 1 did not install everywhere")
    book = open(os.path.join(HERE, "priv", "01_book.txt")).read()
    rrot2 = _rotgate(1, 0)
    subprocess.run(["./rotate", "priv/00_config.txt", "priv/00_ctx_00.bin",
                    "priv/00_ctx_02.bin", "0", "."], cwd=HERE, capture_output=True)
    rreauth = _rotgate(1, 0)
    ok7 = rrot == "RETRY" and rrot2 == "RETRY" and rreauth == "REJECT" and open(
        os.path.join(HERE, "priv", "01_book.txt")).read() == book
    print("rotation re-presented after install: %s, two dispersals on: %s" % (rrot, rrot2))
    print("rotation re-authored: new successor : %s (book unchanged: %s)"
          % (rreauth, "yes" if ok7 else "NO (BUG)"))

    ok = ok and ok5 and ok6 and ok6b and ok7
    print("RETRY WITHOUT RE-INJECTION (byte-identity at the offset floor,"
          " read by receive/assemble, and at the rotation book): %s"
          % ("demonstrated" if ok else "NOT shown"))
    sys.exit(0 if ok else 1)


def cmd_resend(processes, n, t):
    """RESENDING A BANKED DISTRIBUTE -- and why the floor has to exist.

    A message that did not arrive gets sent again; that is all this is.  The
    sender still has the distribute fragment it banked, and re-masks the SSS value
    for the recipient exactly as it did the first time.  Same program, same
    wire/exch/ path, same bytes.

    What makes it interesting is the KEY, not the message.  The mask chain is
    forward-only and wiped the step that dispersal was masked under, at BOTH ends.
    So sender and receiver each rebuild it by walking the retention floor base
    forward over the public chain links -- one base covering every dispersal at or
    after it, no per-dispersal snapshots.  Then ./release moves the floor and the
    same resend becomes impossible, which is the point of the floor rather than a
    failure of it: forward secrecy is bounded by the floor, and that is the price
    of being able to answer at all.

    READING IT BACK NEEDS A RETAINED PUB, and the demo runs at depth zero on
    purpose.  Identity rotates once per dispersal, so an older leg is signed by a
    retired pub while the book here keeps only `current`.  That is not a missing
    mechanism -- the signer's pub is one more thing retained, to the same depth as
    the fragment, and the rotation chain from the OOB pub_0 is what makes a
    retained pub checkable (`drive.py rotchain`).  HOW FAR BACK IS FAR ENOUGH is
    the consumer's to answer; the mule has no idea, so it keeps nothing and says
    so."""
    if processes < 3:
        sys.exit("resend: need dispersals>=3 (the missed dispersal needs one on each side)")
    cmd_keychain(processes)
    cmd_setup(n, t)
    _reset_floor()
    lag = n - 1                            # the seat whose copy went missing
    miss = 1                               # the dispersal whose leg it lost
    missed = False
    link = None
    links = []
    for k in range(processes):
        write_blob("cryptoMule resend process %d payload. " % k * 40)
        cmd_dist("priv/00_ctx_%02d.bin" % k, k)
        cmd_phase("receive")
        _retain(k, n)                      # each recipient BANKS its validated fragment
        apex = _apex()
        gate_offset(apex)
        cmd_phase("exchange")
        if k == miss:                      # this seat's copies never arrive
            shutil.copyfile(
                os.path.join(HERE, "wire", "exch", "%02d_to_%02d_sign.txt" % (1, lag)),
                os.path.join(HERE, "drive", "orig_exch.txt"))
            for s in range(1, n):
                for part in ("apex", "shard", "sign"):
                    f = os.path.join(HERE, "wire", "exch", "%02d_to_%02d_%s.txt" % (s, lag, part))
                    if os.path.exists(f):
                        os.remove(f)
        cmd_phase("assemble")
        if k == miss:
            missed = _asm_result(lag) != "PASS"
        link = _chain(link, _msg())
        links.append(link)
        ratchet_all(k, link, range(n))     # the flow is done: the step after it
        rotate_verify(k)       # one payload per signing context; the book advances
    _write_anchorlog(links)
    print("after %d dispersals: seat %d keystate at step %s, floor at %s"
          % (processes, lag, _ks_step(lag), _ks_floor(lag)))
    print("seat %d never got dispersal %d's exchange: %s"
          % (lag, miss, "did not assemble it" if missed else "assembled it anyway (BUG)"))

    # the resend: every other seat re-sends the banked dispersal, mask rebuilt
    # from its floor.  Same program, same wire path, no new message kind.
    sent = 0
    for s in range(1, n):
        if s == lag:
            continue
        if subprocess.run(["./exchange", _cfgpath(s), str(s - 1), ".",
                           str(miss), "anchorlog.txt"], cwd=HERE).returncode == 0:
            sent += 1
    same = (open(os.path.join(HERE, "drive", "orig_exch.txt")).read()
            == open(os.path.join(HERE, "wire", "exch", "%02d_to_%02d_sign.txt" % (1, lag))).read())
    read = subprocess.run(["./assemble", _cfgpath(lag), str(lag - 1), ".",
                           str(miss), "anchorlog.txt"], cwd=HERE).returncode == 0
    print("seats that rebuilt dispersal %d's mask from their floor: %d" % (miss, sent))
    print("resent leg vs the leg it repeats: %s"
          % ("byte-identical" if same else "DIFFERENT (BUG)"))
    print("seat %d read dispersal %d from the resent legs: %s"
          % (lag, miss, "PASS" if read
             else "NO -- signed by a retired pub, and this book retains none"))

    # the bound: release past it and the resend cannot be produced at all
    for p in range(1, n):
        subprocess.run(["./release", _cfgpath(p), str(miss + 1), "anchorlog.txt"],
                       cwd=HERE, capture_output=True)
    refused = 0
    for s in range(1, n):
        if s == lag:
            continue
        if subprocess.run(["./exchange", _cfgpath(s), str(s - 1), ".",
                           str(miss), "anchorlog.txt"], cwd=HERE,
                          capture_output=True).returncode != 0:
            refused += 1
    print("after releasing the floor to %d, seats that can still resend %d: %d of %d"
          % (miss + 1, miss, sent - refused, sent))
    ok = missed and sent >= t and same and refused == sent
    print("RESEND OFF THE FLOOR CHAIN (mask rebuilt, bounded by release): %s"
          % ("demonstrated" if ok else "NOT shown"))
    print("  reading it back needs the pub retained to the same depth as the"
          " fragment; how far back is far enough is the consumer's to size.")
    sys.exit(0 if ok else 1)


def cmd_evidence(processes, n, t):
    """THE CHAIN AS OUTSIDE EVIDENCE -- what a seat older than every retention floor recovers on.

    Past the retention floor there is no inside heal: nothing anyone still holds
    reaches back, and a resend refuses.  The public link sequence is what is left,
    and ./chainverify is what makes it usable -- fold from the DEALT genesis over
    whatever fragments have been gathered and compare each link to the log.  Three
    arms, one per answer the returning seat needs:

      complete   every position gathered -> validates 0..R-1
      gap        one position missing    -> reports WHERE it starts, and how far
                                            the chain validated before it
      wrong item an item at the wrong position -> MISMATCH, even though the item
                                            is perfectly authentic elsewhere

    The third arm is the one worth watching: the fragment is genuine and its
    signature is fine.  What the chain decides is not who made it but whether it
    BELONGS here, and it decides that against a log nobody had to authenticate."""
    cmd_keychain(processes)
    cmd_setup(n, t)
    _reset_floor()
    link = None
    links = []
    frag = []
    for k in range(processes):
        write_blob("cryptoMule evidence process %d payload. " % k * 40)
        cmd_dist("priv/00_ctx_%02d.bin" % k, k)
        cmd_phase("receive")
        _retain(k, n)
        # what a gatherer ends up holding: one fragment per dispersal
        frag.append("priv/%02d_recv_%02d.txt" % (1, k))
        apex = _apex()
        gate_offset(apex)
        cmd_phase("exchange")
        cmd_phase("assemble")
        link = _chain(link, _msg())
        links.append(link)
        ratchet_all(k, link, range(n))     # the flow is done: the step after it
        rotate_verify(k)       # one payload per signing context; the book advances
    _write_anchorlog(links)
    print("-- %d dispersals logged; genesis %s --" % (processes, _genesis()))

    def verify(items):
        r = subprocess.run(["./chainverify", "priv/00_config.txt", "anchorlog.txt"]
                           + items, cwd=HERE, capture_output=True)
        return r.returncode, r.stderr.decode().strip().split(": ", 1)[-1]

    rc0, m0 = verify(frag)                                  # complete
    hole = frag[:]
    hole[1] = "-"                                           # nothing for dispersal 1
    rc1, m1 = verify(hole)                                  # gap
    swap = frag[:]
    swap[1] = frag[2]                                       # authentic, wrong place
    rc2, m2 = verify(swap)                                  # wrong item

    print("complete   : rc=%d  %s" % (rc0, m0))
    print("gap        : rc=%d  %s" % (rc1, m1))
    print("wrong item : rc=%d  %s" % (rc2, m2))
    ok = (rc0 == 0 and rc1 == 2 and "GAP at dispersal 1" in m1
          and rc2 == 1 and "MISMATCH at dispersal 1" in m2)
    print("CHAIN AS OUTSIDE EVIDENCE (gap exists / where it starts / how far it"
          " validates): %s" % ("demonstrated" if ok else "NOT shown"))
    sys.exit(0 if ok else 1)


def cmd_chain(processes, n, t):
    """THE DISPERSAL CHAIN: chain_0 = the dealt genesis, chain_{k+1} =
    H(chain_k || msg_k), msg_k the message hash.

    An apex commits ONE dispersal and says nothing about which dispersal it belongs
    to or what came before.  The chain fixes both, and it earns its keep by being
    what the mask ratchet steps on: the key for dispersal k+1 is reachable only from
    dispersal k's result.  Two arms show what that buys, because a chain nobody
    depends on proves nothing --

      fabricated fold  a seat folds a message hash the cohort did not agree on.  Its
                       next step lands elsewhere and it can neither read the
                       cohort nor be read by it.
      wrong genesis    a seat dealt a different base diverges at the FIRST
                       link, from the same message hash.  This is why the genesis is
                       dealt rather than chosen (A11) even though it is public.

    Divergence is undetected at the fold and total at the next message: the dispersal
    whose link the rogue mis-folded completes for everyone (its whole flow ran
    under the step before the fold), the NEXT payload's distribute is the first
    thing masked under the diverged step, and there nothing rejects the rogue, it
    simply stops sharing keys with everyone else."""
    ok = True

    cmd_keychain(processes)
    cmd_setup(n, t)
    _reset_floor()
    print("-- walk: genesis %s --" % _genesis())
    link = None
    for k in range(processes):
        write_blob("cryptoMule chain process %d payload. " % k * 40)
        npass, total, _, link = _payload_steps("priv/00_ctx_%02d.bin" % k, k, k,
                                               range(n), link)
        print("   dispersal %d: link %s  reconstructed %d/%d" % (k, link, npass, total))
        ok = ok and npass == total
        rotate_verify(k)       # one payload per signing context; the book advances

    # arm 1: a fabricated fold at dispersal 0, felt at dispersal 1.  Dispersal 0's
    # whole flow ran under step 0 and everyone read it; the rogue steps on a
    # link nobody agreed, and dispersal 1's distribute is the first thing masked
    # under the step it diverged at
    rog = 1
    cmd_keychain(2)
    cmd_setup(n, t)
    _reset_floor()
    write_blob("cryptoMule chain fabricated-fold process 0. " * 40)
    npass0, total, _, _ = _payload_steps("priv/00_ctx_00.bin", 0, 0,
                                         [p for p in range(n) if p != rog])
    fake0 = _chain(None, secrets.token_bytes(16).hex())   # a message hash nobody agreed
    subprocess.run(["./ratchet", _cfgpath(rog), "0", fake0], cwd=HERE,
                   capture_output=True)
    rotate_verify(0)
    write_blob("cryptoMule chain fabricated-fold process 1. " * 40)
    cmd_dist("priv/00_ctx_01.bin", 1)
    cmd_phase("receive")
    gate_offset(_apex())
    cmd_phase("exchange")
    cmd_phase("assemble")
    verdicts = [_asm_result(p) for p in range(1, n)]
    rogOut = verdicts[rog - 1] != "PASS"
    othersIn = all(v == "PASS" for i, v in enumerate(verdicts) if i != rog - 1)
    print("fabricated fold: dispersal 0 read %d/%d; at dispersal 1 rogue seat %d %s, the other %d %s"
          % (npass0, total, rog, "off the chain" if rogOut else "still reading (BUG)",
             n - 2, "still agree" if othersIn else "broke too (BUG)"))
    ok = ok and npass0 == total and rogOut and othersIn

    # arm 2: a different dealt genesis, diverging at the FIRST link (from the
    # same apex), felt at dispersal 1 the same way
    cmd_keychain(2)
    cmd_setup(n, t)
    _reset_floor()
    rogcfg = os.path.join(HERE, _cfgpath(rog))
    lines = list(open(rogcfg))
    with open(rogcfg, "w") as f:
        for l in lines:
            if l.startswith("genesis "):
                l = "genesis %s\n" % secrets.token_bytes(16).hex()
            f.write(l)
    write_blob("cryptoMule chain wrong-genesis process 0. " * 40)
    npass0, total, _, _ = _payload_steps("priv/00_ctx_00.bin", 0, 0,
                                         [p for p in range(n) if p != rog])
    subprocess.run(["./ratchet", _cfgpath(rog), "0",
                    _chain(None, _msg(), _cfgpath(rog))], cwd=HERE,
                   capture_output=True)
    rotate_verify(0)
    write_blob("cryptoMule chain wrong-genesis process 1. " * 40)
    cmd_dist("priv/00_ctx_01.bin", 1)
    cmd_phase("receive")
    gate_offset(_apex())
    cmd_phase("exchange")
    cmd_phase("assemble")
    verdicts = [_asm_result(p) for p in range(1, n)]
    gOut = verdicts[rog - 1] != "PASS"
    gIn = all(v == "PASS" for i, v in enumerate(verdicts) if i != rog - 1)
    print("wrong genesis  : dispersal 0 read %d/%d; at dispersal 1 seat %d %s at the first link, the other %d %s"
          % (npass0, total, rog, "off the chain" if gOut else "still reading (BUG)",
             n - 2, "still agree" if gIn else "broke too (BUG)"))
    ok = ok and npass0 == total and gOut and gIn

    print("DISPERSAL CHAIN (linkage from a dealt genesis, load-bearing at the"
          " ratchet): %s" % ("demonstrated" if ok else "NOT shown"))
    sys.exit(0 if ok else 1)


def _alter_phase(path):
    """tamper: alter the `phase` line of a wire message, a field no reader
    consumes, so only that message's hmac can refuse it.  Returns the clean
    text to put back."""
    full = os.path.join(HERE, path)
    clean = open(full).read()
    if not clean.startswith("phase: "):
        sys.exit("tamper: no phase in %s" % path)
    open(full, "w").write("phase: x" + clean[len("phase: "):])
    return clean


def _flip_field(path, name):
    """tamper: flip one nibble inside the named hex field, keeping it valid hex
    so parsing still succeeds -- only the hmac can tell."""
    lines = open(os.path.join(HERE, path)).readlines()
    for i, line in enumerate(lines):
        if line.startswith(name + ": "):
            k, v = line.split(": ", 1)
            v = v.rstrip("\n")
            lines[i] = "%s: %s%s\n" % (k, "0" if v[0] != "0" else "1", v[1:])
            break
    else:
        sys.exit("tamper: no field %s in %s" % (name, path))
    open(os.path.join(HERE, path), "w").writelines(lines)


def cmd_tamper(n, t):
    """wire tampering detected by the pairwise hmac.  The adversary can alter
    any file OUTSIDE priv/ between phases; every alteration below keeps the
    field valid hex, so only the hmac (not a parse failure) can catch it.
      1. a tampered dist sign message: receive rejects the unit UNPARSED
         (hmac_ok: no); 1b. a tampered dist shard message: the shard part
         refused unparsed (rsecmk_ok: no, no shard kept), the share kept;
         1c. the hmac field in capitals or changed in its first or last digit,
         and the message hmac'd for the other direction or under the other
         pair's key: refused unparsed;
      2. a tampered exchange fragment: assemble skips that sender and still
         reaches threshold from the untampered rest (censorship recovery);
      3. a tampered rotation: the recipient rejects it, its book unchanged;
      4. each reader's hmac on its own: every one of the nine wire messages a
         reader checks, altered only in `phase`, a field no reader consumes,
         so nothing but that hmac can refuse it."""
    cmd_keychain(1)
    cmd_setup(n, t)
    _reset_floor()
    write_blob("cryptoMule tamper demonstration payload. " * 40)
    cmd_dist("priv/00_ctx_00.bin", 0)
    # 1: flip a nibble of seat 1's dist sign message -> receive must reject
    # the unit via that message's hmac, the apex and shard messages untouched
    # (the clean bytes are kept and put back: the initiator signs its one
    # payload signing offset once, it does not re-sign to recover from the wire)
    clean = open(os.path.join(HERE, "wire", "dist", "00_to_01_sign.txt")).read()
    _flip_field("wire/dist/00_to_01_sign.txt", "share_masked")
    r1 = _sys("receive", 0)
    ok1 = r1 != 0 and "hmac_ok: no" in open(os.path.join(HERE, "priv", "01_recv.txt")).read()
    print("tampered dist sign message: %s" % ("unit REJECTED unparsed (hmac)" if ok1 else "ACCEPTED (BUG)"))
    open(os.path.join(HERE, "wire", "dist", "00_to_01_sign.txt"), "w").write(clean)
    # 1c: forms of the apex message only the hmac can tell from the clean one
    apx = "wire/dist/00_to_01_apex.txt"
    cleanApx = open(os.path.join(HERE, apx)).read()
    bodyApx = "".join(l for l in cleanApx.splitlines(True) if not l.startswith("hmac: "))
    hmApx = cleanApx.splitlines(True)[-1]
    ok1c = True
    hex0 = hmApx[6:-1]
    for name, mac, s, r, field in (
            ("hmac field in capitals", None, 0, 1, hex0.upper()),
            ("hmac field's first digit changed", None, 0, 1, ("0" if hex0[0] != "0" else "1") + hex0[1:]),
            ("hmac field's last digit changed", None, 0, 1, hex0[:-1] + ("0" if hex0[-1] != "0" else "1")),
            ("hmac'd for the other direction", _mac0(1), 1, 0, None),
            ("hmac'd under the other pair's key", _mac(0, 2), 0, 1, None)):
        if mac:
            open(os.path.join(HERE, apx), "w").write(bodyApx)
            subprocess.run(["./cmhmac", mac, str(s), str(r), apx], cwd=HERE, check=True)
        else:
            open(os.path.join(HERE, apx), "w").write(bodyApx + "hmac: " + field + "\n")
        os.remove(os.path.join(HERE, "priv", "01_recv.txt"))   # this read's verdict, no earlier one
        good = _sys("receive", 0) != 0 and _field("priv/01_recv.txt", "hmac_ok") == "no"
        print("%s: %s" % (name, "unit REJECTED unparsed (hmac)" if good else "ACCEPTED (BUG)"))
        ok1c = ok1c and good
    open(os.path.join(HERE, apx), "w").write(cleanApx)
    # 1b: the shard message tampered instead -> the shard part refused
    # unparsed and not kept, the share validated and kept (the adversary
    # blocks and reorders; every intact part is progress)
    clean = open(os.path.join(HERE, "wire", "dist", "00_to_01_shard.txt")).read()
    _flip_field("wire/dist/00_to_01_shard.txt", "shard")
    r1b = _sys("receive", 0)
    rec = open(os.path.join(HERE, "priv", "01_recv.txt")).read()
    ok1b = (r1b != 0 and "hmac_ok: yes" in rec and "sssmk_ok: yes" in rec
            and "rsecmk_ok: no" in rec and "\nshard: " not in rec)
    print("tampered dist shard message: %s" % ("shard part REFUSED unparsed, share kept" if ok1b else "NOT split (BUG)"))
    # the clean fragment delivered after all, the payload runs through to exchange
    open(os.path.join(HERE, "wire", "dist", "00_to_01_shard.txt"), "w").write(clean)
    cmd_phase("receive")
    gate_offset(_apex())
    cmd_phase("exchange")
    # 2: flip a nibble of the sign message sender 2 sent seat 1 -> assemble
    # skips sender 2 entirely (the sign message carries the signed header both
    # parts verify under; its apex and shard messages alone are nothing),
    # still PASSes from the others
    _flip_field("wire/exch/02_to_01_sign.txt", "share_masked")
    ok2 = _sys("assemble", 0) == 0
    senders = _asm(1, "share_senders") + _asm(1, "shard_senders")
    ok2 = ok2 and "2" not in senders
    print("tampered exchange fragment: %s"
          % ("SKIPPED, threshold from the rest (shares %s; shards %s)"
             % (" ".join(_asm(1, "share_senders")), " ".join(_asm(1, "shard_senders")))
             if ok2 else "NOT contained (BUG)"))
    # 4, the readers of the payload: each message altered only in `phase`
    ok4 = True
    for part in ("apex", "sign", "shard"):
        path = "wire/dist/00_to_01_%s.txt" % part
        clean = _alter_phase(path)
        os.remove(os.path.join(HERE, "priv", "01_recv.txt"))   # this read's verdict, no earlier one
        r = _sys("receive", 0)
        if part == "shard":
            good = _field("priv/01_recv.txt", "hmac_ok") == "yes" and _field("priv/01_recv.txt", "rsecmk_ok") == "no"
        else:
            good = r != 0 and _field("priv/01_recv.txt", "hmac_ok") == "no"
        open(os.path.join(HERE, path), "w").write(clean)
        print("receive, %s message's phase altered: %s" % (part, "refused by its hmac" if good else "ACCEPTED (BUG)"))
        ok4 = ok4 and good
    _sys("receive", 0)                         # seat 1's own record, clean again
    _sys("exchange", 1)                        # sender 2's fragment, clean again
    _sys("assemble", 0)                        # and used, so its absence below is the hmac's
    ok4 = ok4 and "2" in _asm(1, "shard_senders") and "2" in _asm(1, "share_senders")
    for part in ("apex", "sign", "shard"):
        path = "wire/exch/02_to_01_%s.txt" % part
        clean = _alter_phase(path)
        _sys("assemble", 0)
        good = "2" not in _asm(1, "shard_senders") and (part == "shard" or "2" not in _asm(1, "share_senders"))
        open(os.path.join(HERE, path), "w").write(clean)
        print("assemble, %s message's phase altered: %s" % (part, "refused by its hmac" if good else "ACCEPTED (BUG)"))
        ok4 = ok4 and good
    ratchet_all(0, _chain(None, _msg()), range(n))   # the payload's flow is done
    # 3: a tampered rotation: recipient 1 must reject, its book unchanged
    subprocess.run(["./rotate", "priv/00_config.txt", "priv/00_ctx_00.bin",
                    "priv/00_ctx_01.bin", "0", "."], cwd=HERE)
    rotApex = os.path.join(HERE, "wire", "rot", "00_rotate_00_to_01_apex.txt")
    cleanRot = open(rotApex).read()
    _flip_field("wire/rot/00_rotate_00_to_01_apex.txt", "apex")
    book0 = open(os.path.join(HERE, "priv", "01_book.txt")).read()
    r3 = subprocess.run(["./rotverify", _cfgpath(1), "0", "0", "."], cwd=HERE).returncode
    ok3 = r3 != 0 and open(os.path.join(HERE, "priv", "01_book.txt")).read() == book0
    print("tampered rotation: %s" % ("REJECTED, book unchanged" if ok3 else "INSTALLED (BUG)"))
    open(rotApex, "w").write(cleanRot)
    # 4, the rotation's reader and the run file's: the verdict names the hmac
    for path, cmd in (("wire/rot/00_rotate_00_to_01_apex.txt", ["./rotverify", _cfgpath(1), "0", "0", "."]),
                      ("wire/rot/00_rotate_00_to_01_sign.txt", ["./rotverify", _cfgpath(1), "0", "0", "."]),
                      ("wire/run_%02d_to_01.txt" % SLOT_PAY, ["./offsetgate", _cfgpath(1), str(SLOT_PAY), "0", "."])):
        clean = _alter_phase(path)
        e = subprocess.run(cmd, cwd=HERE, capture_output=True).stderr.decode()
        good = "hmac (wire tamper)" in e and open(os.path.join(HERE, "priv", "01_book.txt")).read() == book0
        open(os.path.join(HERE, path), "w").write(clean)
        print("%s, phase altered: %s" % (os.path.basename(path), "refused by its hmac" if good else "ACCEPTED (BUG)"))
        ok4 = ok4 and good
    ok = ok1 and ok1b and ok1c and ok2 and ok3 and ok4
    print("WIRE TAMPER DETECTION (pairwise hmac, checked FIRST): %s"
          % ("demonstrated" if ok else "NOT shown"))
    sys.exit(0 if ok else 1)


def _asm_result(p):
    """recipient p's assemble verdict (PASS / FAIL / FRAUD)."""
    for line in open(os.path.join(HERE, "priv", "%02d_assemble.txt" % p)):
        if line.startswith("result: "):
            return line.split(": ", 1)[1].strip()
    return "?"


def _asm(p, name):
    """one field of recipient p's assemble record, split into words."""
    v = _field("priv/%02d_assemble.txt" % p, name)
    return v.split() if v is not None else []


def cmd_byz(n, t):
    """BYZANTINE DEALER, under the rule that most
    byzantine results are environmental.  A dealer that commits one bad part
    (a non-codeword shard, an off-polynomial share) passes every per-unit gate
    where the fault is not local; assemble gathers every held part and
    SEARCHES T-subsets against the signed orig_hash, so every honest receiver
    with T good parts delivers the message, reads the commitment inconsistent
    on the re-encode, and names the bad leaf.  Committed code points that are
    not the seed's derivation is rejected at receive on the mis-bound leaves
    (their holders forward the shard part alone) and the rest deliver.  A
    CONSISTENT codeword of the wrong bytes (the ct fault) is the one thing no
    subset repairs: the search exhausts and the verdict is FRAUD."""
    # per fault: the description, the bad shares and bad shards every
    # assembler must name (leaf 0 is seat 1), the receives that reject.
    # salt corrupts every share but the last T: more T-subsets than R, so
    # the search's K candidate list must grow past R to reach the good pair
    # (a list capped at R would read FRAUD, "every subset tried", for a message
    # that is there).  pad flips a padding byte of data shard k-1 (seat T):
    # the hash passes without reading it, and a re-encode from the winning
    # shards would name nothing (or an honest parity leaf); the re-encode from
    # the canonical ciphertext names seat T
    salted = [str(i + 1) for i in range(n - 1 - t)]
    faults = {
        "shard": ("non-codeword RS shard    -> delivered, commitment inconsistent, bad shard named", [], ["1"], 0),
        "pad":   ("flipped padding byte     -> the hash never reads it: delivered, named by the canonical re-encode", [], [str(t)], 0),
        "share": ("off-polynomial SSS share -> delivered, commitment inconsistent, bad share named", ["1"], [], 0),
        "salt":  ("every share but T off    -> delivered past R candidates, the salted leaves named", salted, [], 0),
        "geom":  ("off-derivation geometry  -> receive rejects the mis-bound leaves; delivered from the rest", [], [], 2),
        "ct":    ("consistent codeword, wrong bytes -> nothing reproduces the signed hash: FRAUD", None, None, 0),
    }
    allok = True
    for fault, (desc, badShares, badShards, rejects) in faults.items():
        cmd_keychain(1)
        cmd_setup(n, t)
        _reset_floor()
        write_blob("cryptoMule byzantine-dealer %s payload. " % fault * 40)
        cmd_dist("priv/00_ctx_00.bin", 0, fault)
        recv = cmd_phase("receive")
        rej = sum(1 for r in recv if r != 0)
        gate_offset(_apex())
        cmd_phase("exchange")
        cmd_phase("assemble")
        ratchet_all(0, _chain(None, _msg()), range(n))
        verdicts = [_asm_result(p) for p in range(1, n)]
        tries = [_asm(p, "tries") for p in range(1, n)]
        commit = [_asm(p, "commitment") for p in range(1, n)]
        if fault == "ct":
            ok = all(v == "FRAUD" for v in verdicts)
        else:
            # the commitment reads inconsistent iff a committed part is off:
            # salt at T = R salts nothing
            expect = ["consistent"] if fault == "salt" and not salted else ["inconsistent"]
            ok = (all(v == "PASS" for v in verdicts)
                  and all(c == expect for c in commit)
                  and rej == rejects
                  and all(open(os.path.join(HERE, "priv", "%02d_recovered.bin" % p), "rb").read()
                          == open(os.path.join(HERE, "priv", "00_blob.bin"), "rb").read()
                          for p in range(1, n))
                  and all(_asm(p, "bad_shares") == badShares and _asm(p, "bad_shards") == badShards
                          for p in range(1, n)))
        allok = allok and ok
        print("  %-6s recv-reject %d/%d  assemble %s  tries %s  -> %s"
              % (fault, rej, n - 1, verdicts, [x[0] if x else "?" for x in tries], "OK" if ok else "MISS"))
        print("         %s" % desc)
    print("BYZANTINE DEALER (a bad part searched past, a wrong codeword FRAUD): %s"
          % ("demonstrated" if allok else "NOT shown"))
    sys.exit(0 if allok else 1)


def cmd_parts(n, t):
    """THE SHARE AND THE SHARD ARE TWO PARTS.  Seat 1's dist shard arrives
    with a byte flipped and re-hmac'd by the dealer's own key (a rotted copy
    is the same bytes), so receive says rsecmk_ok no and the other four yes;
    exchange forwards the share part alone; every assembler reaches T on
    shards without seat 1 and delivers, the commitment consistent, and
    seat 1's own assembly counts its share and not its shard."""
    cmd_keychain(1)
    cmd_setup(n, t)
    _reset_floor()
    write_blob("cryptoMule two-parts payload. " * 40)
    cmd_dist("priv/00_ctx_00.bin", 0)
    _hostile("wire/dist/00_to_01_shard.txt", 0, 1, "shard", HOSTILE["flip"])
    recv = cmd_phase("receive")
    r1 = open(os.path.join(HERE, "priv", "01_recv.txt")).read()
    ok1 = recv[0] != 0 and "rsecmk_ok: no" in r1 and "sssmk_ok: yes" in r1
    gate_offset(_apex())
    cmd_phase("exchange")
    ok2 = not os.path.exists(os.path.join(HERE, "wire", "exch", "01_to_02_shard.txt")) \
        and _field("wire/exch/01_to_02_sign.txt", "share_masked") is not None
    cmd_phase("assemble")
    ratchet_all(0, _chain(None, _msg()), range(n))
    verdicts = [_asm_result(p) for p in range(1, n)]
    ok3 = (all(v == "PASS" for v in verdicts)
           and all(_asm(p, "commitment") == ["consistent"] for p in range(1, n))
           and all("1" not in [x.replace("(held)", "") for x in _asm(p, "shard_senders")] for p in range(1, n))
           and all("1" in [x.replace("(held)", "") for x in _asm(p, "share_senders")] for p in range(1, n)))
    print("receive at seat 1: %s" % ("shard part refused, share part kept" if ok1 else "NOT split (BUG)"))
    print("exchange from seat 1: %s" % ("share forwarded, no shard message" if ok2 else "NOT split (BUG)"))
    print("assemble: %s  shards without 1, shares with 1: %s" % (verdicts, "yes" if ok3 else "NO (BUG)"))
    ok = ok1 and ok2 and ok3
    print("TWO PARTS (a rotted shard costs its holder's share nothing): %s"
          % ("demonstrated" if ok else "NOT shown"))
    sys.exit(0 if ok else 1)


def cmd_limit(n, t):
    """THE CIPHERTEXT CAP (CM_CT_MAX).  A message that compresses past it is
    not dispersed; dispersed anyway (distribute's `big` fault), every
    receiver refuses the shard part on its own wire (rsecmk_ok no, the share
    kept), exchange forwards shares alone, and no assembler reaches T on
    shards -- the same check on both wires."""
    cmd_keychain(1)
    cmd_setup(n, t)
    _reset_floor()
    write_blob(os.urandom(70000))               # incompressible: past 64k however it is packed
    for f in glob.glob(os.path.join(HERE, "wire", "dist", "00_to_01_*.txt")):
        os.remove(f)                             # an earlier arm's leg must not stand in for this one
    r = subprocess.run(["./distribute", "priv/00_config.txt", "priv/00_blob.bin",
                        "priv/00_ctx_00.bin", ".", "0"], cwd=HERE).returncode
    ok1 = r != 0 and not os.path.exists(os.path.join(HERE, "wire", "dist", "00_to_01_shard.txt"))
    print("distribute past the cap: %s" % ("REFUSED, nothing on the wire" if ok1 else "DISPERSED (BUG)"))
    cmd_dist("priv/00_ctx_00.bin", 0, "big")
    recv = cmd_phase("receive")
    recs = [open(os.path.join(HERE, "priv", "%02d_recv.txt" % p)).read() for p in range(1, n)]
    ok2 = all(rc != 0 for rc in recv) and all("rsecmk_ok: no" in x and "sssmk_ok: yes" in x for x in recs)
    print("receive of the oversize dispersal: %s" % ("shard part refused at every seat, share kept" if ok2 else "ADMITTED (BUG)"))
    gate_offset(_apex())
    cmd_phase("exchange")
    cmd_phase("assemble")
    verdicts = [_asm_result(p) for p in range(1, n)]
    held = [_asm(p, "shards_held") for p in range(1, n)]
    ok3 = all(v == "FAIL" for v in verdicts) and all(h == ["0"] for h in held)
    print("assemble: %s shards held %s -> %s" % (verdicts, held, "no shard on any wire" if ok3 else "SHARDS ADMITTED (BUG)"))
    # a Byzantine forwarder vouches for its oversize shard (its own receive
    # record edited): assemble's cap check on its own wire refuses it
    rec = os.path.join(HERE, "priv", "01_recv.txt")
    vouched = open(rec).read().replace("rsecmk_ok: no", "rsecmk_ok: yes")
    open(rec, "w").write(vouched)
    if _sys("exchange", 0):
        sys.exit("limit: seat 1 did not forward the vouched shard")
    for i in range(1, n - 1):
        _sys("assemble", i)
    ok4 = (os.path.exists(os.path.join(HERE, "wire", "exch", "01_to_02_shard.txt"))
           and all("1" not in _asm(p, "shard_senders") and "1" in _asm(p, "share_senders") for p in range(2, n)))
    print("vouched oversize shard on the exchange wire: %s" % ("REFUSED by assemble's own cap check, the share kept" if ok4 else "ADMITTED (BUG)"))
    ok = ok1 and ok2 and ok3 and ok4
    print("THE CIPHERTEXT CAP (the same check on both wires): %s" % ("demonstrated" if ok else "NOT shown"))
    sys.exit(0 if ok else 1)


def cmd_empty(n, t):
    """an EMPTY message is a message.  The huffman encoding of nothing is two
    bytes, so distribute admits a zero-length blob and every recipient
    reconstructs it: assemble's one gate is H(blob) == orig_hash at whatever
    length the stream self-describes, here 0."""
    cmd_keychain(1)
    cmd_setup(n, t)
    _reset_floor()
    write_blob("")
    npass, total, _, _ = _payload_steps("priv/00_ctx_00.bin", 0, 0, range(n))
    lens = [_field("priv/%02d_assemble.txt" % p, "recovered_len") for p in range(1, n)]
    sizes = [os.path.getsize(os.path.join(HERE, "priv", "%02d_recovered.bin" % p))
             for p in range(1, n)]
    ok = npass == total and all(l == "0" for l in lens) and all(sz == 0 for sz in sizes)
    print("empty payload: %d/%d PASS, recovered_len %s, recovered.bin sizes %s"
          % (npass, total, " ".join(lens), " ".join(str(sz) for sz in sizes)))
    # the hash of nothing has no power: a wrong try's broken stream probes 0
    # like the stream of nothing does, so a consistent codeword of the wrong
    # bytes at an empty payload must still read FRAUD everywhere (it read
    # PASS, and a bad share subset could win the search and misname leaves)
    cmd_keychain(1)
    cmd_setup(n, t)
    _reset_floor()
    write_blob("")
    cmd_dist("priv/00_ctx_00.bin", 0, "ct")
    cmd_phase("receive")
    gate_offset(_apex())
    cmd_phase("exchange")
    cmd_phase("assemble")
    ratchet_all(0, _chain(None, _msg()), range(n))
    verdicts = [_asm_result(p) for p in range(1, n)]
    ok2 = all(v == "FRAUD" for v in verdicts)
    print("empty payload, wrong codeword: %s -> %s" % (verdicts, "FRAUD everywhere" if ok2 else "NOT caught (BUG)"))
    ok = ok and ok2
    # the plaintext padding must read as zero at every T: the dealer
    # keystreams the padded ciphertext whole.  Keystreaming the stream alone
    # left the padding as keystream in the assembler's plaintext, and the
    # all-zero test then read an honest empty message as FRAUD at T >= 3
    # (two bytes of stream, T x 1 bytes of plaintext)
    if n >= 4:
        cmd_keychain(1)
        cmd_setup(n, 3)
        _reset_floor()
        write_blob("")
        npass3, total3, _, _ = _payload_steps("priv/00_ctx_00.bin", 0, 0, range(n))
        ok3 = npass3 == total3
        print("empty payload at T=3: %d/%d PASS -> %s" % (npass3, total3, "padding reads as zero" if ok3 else "FRAUD on an honest dealer (BUG)"))
        ok = ok and ok3
    else:
        print("empty payload at T=3: needs N>=4, not run here")
    print("AN EMPTY MESSAGE IS A MESSAGE (and its oracle still decides): %s" % ("demonstrated" if ok else "NOT shown"))
    sys.exit(0 if ok else 1)


def cmd_slot(n, t):
    """THE SIGNING OFFSET PARTITION.  CM_SLOT_ROT is the rotation's signing offset and only the
    rotation's: every verifier gates the signing offset it recovers from the
    signature, so a one-time signing offset cannot be spent once as a rotation and once
    as a payload (two apexes under one signing offset leak it).  And a VALUE is
    a payload's apex or a rotation's, never both: the sign message carries
    the apex's preimage but the signer's pub and the offset (orig_hash and
    the roots, or pub_hash) and the reader recomputes it under its current
    pub and the offset the signature yields.  Four arms:
      1: a rotation signed at a payload signing offset (rotate's `slot` fault) is
         refused by rotverify on the signing offset it recovers, the book unchanged;
         the genuine rotation then installs (the gate is the signing offset, not the
         message);
      2: a payload signed at the rotation signing offset (distribute's `slot` fault) is
         refused by receive at every recipient;
      3: a forwarder that vouches for it anyway (its own receive record edited
         to sig_ok: yes, offset_ok: yes) gets it past nobody -- assemble gates
         the signing offset itself and cannot lock;
      4: that same signature at the rotation's offset over the payload apex, dressed as
         dispersal 1's rotation to seat 1, is refused by rotverify: no
         pub_hash hashes to a payload's apex.  Before pub_hash rode in the
         rotation's sign message the successor pub WAS the apex and these
         bytes, in that wire's format (`apex:` in the sign message),
         installed the payload apex as seat 1's current pub -- the sender
         giving some seats a payload and the rest the same value as a
         rotation, which parted them at the next ratchet."""
    cmd_keychain(1)
    cmd_setup(n, t)
    _reset_floor()
    # 1: ctx_00 signs dispersal 0's rotation at the payload signing offset (its signing offset 1,
    # which no payload of ctx_00 spends in this arm); the genuine rotation
    # then signs the same value at signing offset 0
    subprocess.run(["./rotate", "priv/00_config.txt", "priv/00_ctx_00.bin",
                    "priv/00_ctx_01.bin", "0", ".", "slot"], cwd=HERE)
    book0 = open(os.path.join(HERE, "priv", "01_book.txt")).read()
    r1 = subprocess.run(["./rotverify", _cfgpath(1), "0", "0", "."], cwd=HERE, capture_output=True)
    ok1 = (r1.returncode != 0 and "payload signing offset" in r1.stderr.decode()
           and open(os.path.join(HERE, "priv", "01_book.txt")).read() == book0)
    print("rotation at a payload signing offset: %s" % ("REFUSED on the signing offset, book unchanged" if ok1 else "INSTALLED (BUG)"))
    ok1 = ok1 and rotate_verify(0) == n - 1
    print("genuine rotation at the rotation signing offset: %s" % ("installed" if ok1 else "REFUSED (BUG)"))
    # 2: ctx_01 (now current, dispersal 1) signs a payload apex at signing offset 0
    write_blob("cryptoMule slot demonstration payload. " * 40)
    cmd_dist("priv/00_ctx_01.bin", 1, "slot")
    rcs = cmd_phase("receive")
    ok2 = all(r != 0 for r in rcs) and all(
        _field("priv/%02d_recv.txt" % p, "sig_ok") == "no" for p in range(1, n))
    print("payload at the rotation signing offset: %s"
          % ("REFUSED at all %d recipients" % (n - 1) if ok2 else "ACCEPTED (BUG)"))
    # 3: seat 1 vouches for the refused unit and forwards it; nobody locks
    rec = os.path.join(HERE, "priv", "01_recv.txt")
    vouched = open(rec).read().replace("sig_ok: no", "sig_ok: yes").replace(
        "offset_ok: no", "offset_ok: yes")
    open(rec, "w").write(vouched)
    if _sys("exchange", 0):
        sys.exit("slot: seat 1 did not forward the vouched unit")
    rcs = [_sys("assemble", i) for i in range(1, n - 1)]
    ok3 = all(r != 0 for r in rcs) and all(
        _field("priv/%02d_assemble.txt" % p, "sig_ok") == "no"
        and os.path.exists(os.path.join(HERE, "wire", "exch", "01_to_%02d_apex.txt" % p))
        for p in range(2, n))
    print("forwarded anyway: %s" % ("NO assembler locks on it" if ok3 else "LOCKED (BUG)"))
    # 4: the payload apex as a rotation.  ctx_01's offset-0 signature over the
    # payload apex (arm 2) IS a signature at the rotation's offset; dressed as dispersal
    # 1's rotation to seat 1 (apex message = the payload apex, sign message
    # = the tag, a pub_hash of the sender's choosing, that signature) it must
    # be refused: whatever pub_hash names, its hash is not this apex
    apex = _apex()
    path = os.path.join(HERE, "wire", "rot", "00_rotate_01_to_01_apex.txt")
    with open(path, "w") as f:
        f.write("phase: rotate\n")
        f.write("apex: %s\n" % apex)
    subprocess.run(["./cmhmac", _mac0(1), "0", "1", path], cwd=HERE, check=True)
    path = os.path.join(HERE, "wire", "rot", "00_rotate_01_to_01_sign.txt")
    with open(path, "w") as f:
        f.write("phase: rotate\n")
        f.write("tag: 00_rotate_01_to_01_apex.txt\n")
        f.write("process: 1\n")
        f.write("pub_hash: %s\n" % apex)
        f.write("mls_sig: %s\n" % _field("wire/dist/00_to_01_sign.txt", "mls_sig"))
    subprocess.run(["./cmhmac", _mac0(1), "0", "1", path], cwd=HERE, check=True)
    book1 = open(os.path.join(HERE, "priv", "01_book.txt")).read()
    r4 = subprocess.run(["./rotverify", _cfgpath(1), "1", "0", "."], cwd=HERE, capture_output=True)
    ok4 = (r4.returncode != 0 and "does not hash to the apex" in r4.stderr.decode()
           and open(os.path.join(HERE, "priv", "01_book.txt")).read() == book1)
    print("payload apex dressed as a rotation: %s"
          % ("REFUSED, no pub_hash hashes to it; book unchanged" if ok4 else "INSTALLED (BUG)"))
    ok = ok1 and ok2 and ok3 and ok4
    print("THE SIGNING OFFSET PARTITION (rotation signing offset vs payload signing offsets, gated at every verifier;"
          " a value is one apex or the other): %s" % ("demonstrated" if ok else "NOT shown"))
    sys.exit(0 if ok else 1)


HOSTILE = {                     # one field, rewritten by a sender who holds the mac key
    "missing": None,
    "empty": lambda v: "",
    "nonhex": lambda v: "zz" + v[2:],
    "odd": lambda v: v[:-1],
    "half": lambda v: v[:len(v) // 2],
    "double": lambda v: v + v,
    "huge": lambda v: "ab" * 70000,
    "flip": lambda v: v[:len(v) // 2] + ("0" if v[len(v) // 2] != "0" else "1") + v[len(v) // 2 + 1:],
    "tail": lambda v: v + "x",
}


def _hostile(path, a, b, field, how):
    """rewrite one field of the wire message at path as the Byzantine sender a
    would -- and re-authenticate it with mac(a,b), so the hmac gate PASSES and
    the bytes reach the reader.  Returns the clean text to put back."""
    clean = open(os.path.join(HERE, path)).read()
    out = []
    for line in clean.splitlines():
        if line.startswith("hmac: "):
            continue
        if line.startswith(field + ": "):
            if how is None:
                continue
            line = field + ": " + how(line.split(": ", 1)[1])
        out.append(line)
    open(os.path.join(HERE, path), "w").write("\n".join(out) + "\n")
    subprocess.run(["./cmhmac", _mac(a, b), str(a), str(b), path], cwd=HERE, capture_output=True, check=True)
    return clean


def _fields(path, labels=()):
    """the fields a reader consumes: every field but the hmac (gated first),
    phase, and the labels this reader does not parse (the run file's `slot` and
    the rotation's `process`: the directed path names them, the reader takes
    them from its argument, the field is for the eye)."""
    return [l.split(": ")[0] for l in open(os.path.join(HERE, path)).read().splitlines()
            if ": " in l and l.split(": ")[0] not in ("hmac", "phase") + tuple(labels)]


def cmd_hostile(n, t):
    """HOSTILE BYTES AT EVERY INGRESS, from a sender who holds the key.  The
    wire hmac refuses the network's alterations unparsed (tamper); a BYZANTINE
    SENDER authenticates whatever it likes, so every reader must survive
    every field of every message being missing, empty, non-hex, odd, short,
    overlong, huge or bit-flipped -- no crash, the message refused, and (for
    an exchange fragment) threshold still reached from the honest rest.  The
    driver plays that sender: it rewrites one field and re-hmacs with the
    dealt pairwise key.  Four ingresses: dist -> receive, exch -> assemble,
    rot -> rotverify, run -> offsetgate; dist and exch are three messages
    each (apex, shard, sign) and rot two (apex, sign), every field of every
    one swept."""
    cmd_keychain(1)
    cmd_setup(n, t)
    _reset_floor()
    write_blob("cryptoMule hostile-bytes payload. " * 40)
    cmd_dist("priv/00_ctx_00.bin", 0)
    cmd_phase("receive")
    gate_offset(_apex())
    subprocess.run(["./rotate", "priv/00_config.txt", "priv/00_ctx_00.bin",
                    "priv/00_ctx_01.bin", "0", "."], cwd=HERE, capture_output=True)
    cmd_phase("exchange")
    book = open(os.path.join(HERE, "priv", "01_book.txt")).read()
    floor = open(os.path.join(HERE, "priv", "01_floor.txt")).read()
    recv = open(os.path.join(HERE, "priv", "01_recv.txt")).read()
    cases = crashes = admitted = 0
    bad = []

    def run(argv):
        return subprocess.run(argv, cwd=HERE, capture_output=True).returncode

    # dist -> receive at seat 1 (sender 0), each of the three messages
    # the part the field belongs to refused (a hostile shard message, or the
    # sign message's rsecmk_proof, costs the shard part; share_masked or
    # sssmk_proof the share part; any other field the unit, by whichever
    # verdict catches it), the other part kept
    for part in ("apex", "shard", "sign"):
        path = "wire/dist/00_to_01_%s.txt" % part
        for f in _fields(path):
            if part == "shard" or f == "rsecmk_proof":
                off, on = "rsecmk_ok", "sssmk_ok"
            elif f in ("share_masked", "sssmk_proof"):
                off, on = "sssmk_ok", "rsecmk_ok"
            else:
                off, on = None, None
            for how, m in HOSTILE.items():
                clean = _hostile(path, 0, 1, f, m)
                rc = run(["./receive", _cfgpath(1), "0", "."])
                open(os.path.join(HERE, path), "w").write(clean)
                r = open(os.path.join(HERE, "priv", "01_recv.txt")).read()
                cases += 1
                if rc < 0: crashes += 1; bad.append(("dist", f, how, "CRASH"))
                elif rc == 0: admitted += 1; bad.append(("dist", f, how, "admitted"))
                elif off is not None and off + ": no" not in r:
                    admitted += 1; bad.append(("dist", f, how, "part admitted"))
                elif on is not None and on + ": yes" not in r:
                    bad.append(("dist", f, how, "other part lost"))
    open(os.path.join(HERE, "priv", "01_recv.txt"), "w").write(recv)   # the clean record back
    # exch -> assemble at seat 1 (sender 2), each of the three messages:
    # the part the field belongs to refused (a hostile shard message, or the
    # sign message's rsecmk_proof, costs sender 2's shard part; its share value
    # or sssmk_proof the share part; any other field the whole fragment), and
    # T from the rest
    for part in ("apex", "shard", "sign"):
        path = "wire/exch/02_to_01_%s.txt" % part
        for f in _fields(path):
            if part == "shard" or f == "rsecmk_proof":
                lists = ("shard_senders",)
            elif f in ("share_masked", "sssmk_proof"):
                lists = ("share_senders",)
            else:
                lists = ("share_senders", "shard_senders")
            for how, m in HOSTILE.items():
                clean = _hostile(path, 2, 1, f, m)
                rc = run(["./assemble", _cfgpath(1), "0", "."])
                open(os.path.join(HERE, path), "w").write(clean)
                cases += 1
                if rc < 0: crashes += 1; bad.append(("exch", f, how, "CRASH"))
                elif any("2" in _asm(1, l) for l in lists): admitted += 1; bad.append(("exch", f, how, "admitted"))
                elif rc != 0: bad.append(("exch", f, how, "threshold lost"))
                elif len(lists) == 1 and "2" not in _asm(1, "shard_senders" if lists[0] == "share_senders" else "share_senders"):
                    bad.append(("exch", f, how, "other part lost"))
    # rot -> rotverify at seat 1 (sender 0), the apex and sign messages:
    # refused, book unchanged
    for part in ("apex", "sign"):
        path = "wire/rot/00_rotate_00_to_01_%s.txt" % part
        for f in _fields(path, ("process",)):
            for how, m in HOSTILE.items():
                clean = _hostile(path, 0, 1, f, m)
                rc = run(["./rotverify", _cfgpath(1), "0", "0", "."])
                open(os.path.join(HERE, path), "w").write(clean)
                cases += 1
                if rc < 0: crashes += 1; bad.append(("rot", f, how, "CRASH"))
                elif rc == 0 or open(os.path.join(HERE, "priv", "01_book.txt")).read() != book:
                    admitted += 1; bad.append(("rot", f, how, "admitted"))
    # run -> offsetgate at seat 1 (sender 0): refused, floor unchanged
    for f in _fields("wire/run_01_to_01.txt", ("slot",)):
        for how, m in HOSTILE.items():
            clean = _hostile("wire/run_01_to_01.txt", 0, 1, f, m)
            rc = run(["./offsetgate", _cfgpath(1), "1", "0", "."])
            open(os.path.join(HERE, "wire", "run_01_to_01.txt"), "w").write(clean)
            cases += 1
            if rc < 0: crashes += 1; bad.append(("run", f, how, "CRASH"))
            elif open(os.path.join(HERE, "priv", "01_floor.txt")).read() != floor:
                admitted += 1; bad.append(("run", f, how, "floor moved"))
            elif rc == 0:
                admitted += 1; bad.append(("run", f, how, "admitted"))
    for b in bad:
        print("  %s %s %s: %s" % b)
    ok = crashes == 0 and admitted == 0 and not [b for b in bad if b[3] in ("threshold lost", "other part lost")]
    print("hostile bytes: %d cases, %d crashes, %d admitted" % (cases, crashes, admitted))
    print("HOSTILE BYTES AT EVERY INGRESS (authenticated by a Byzantine sender): %s"
          % ("survived" if ok else "NOT survived"))
    sys.exit(0 if ok else 1)


def cmd_pools(n, t):
    """TWO APEXES, EACH REPORTED.  Every part is tagged with the apex message
    it is of, so an assembler pools parts by apex and reports every pool,
    choosing none.
    The same pub signs two payloads (signing offsets 1 and 2); seat 1's legs carry
    the first apex A, everyone else's the second, B.  Every assembler sees
    two pools: A under threshold, B at T and delivered -- a lowest-index
    sender's apex does not fix what the rest are judged against (a lock on
    the first valid header would read FAIL here at every seat but 1).
    Needs R > T: at T = R the B pool is one leg short."""
    cmd_keychain(1)
    cmd_setup(n, t)
    _reset_floor()
    write_blob("cryptoMule pools payload A. " * 40)
    cmd_dist("priv/00_ctx_00.bin", 0)
    cmd_phase("receive")
    apexA = _apex()
    gate_offset(apexA)
    cmd_phase("exchange")
    write_blob("cryptoMule pools payload B. " * 40)
    cmd_dist("priv/00_ctx_00.bin", 0, "slot2")       # the same pub, the next payload signing offset
    apexB = _apex()
    for i in range(1, n - 1):                        # seats 2..R take B; seat 1 keeps A
        _sys("receive", i)
        _sys("exchange", i)
    rcs = cmd_phase("assemble")
    pools = [_field("priv/%02d_assemble.txt" % p, "pools") for p in range(1, n)]
    apexes = [_field("priv/%02d_assemble.txt" % p, "apex") for p in range(1, n)]
    verdicts = [_asm_result(p) for p in range(1, n)]
    ok = (all(r == 0 for r in rcs) and all(x == "2" for x in pools)
          and all(a == apexB for a in apexes) and apexA != apexB)
    print("two apexes under one pub: pools %s, delivered %s, result %s"
          % (pools, ["B" if a == apexB else "A" if a == apexA else "?" for a in apexes], verdicts))
    print("TWO APEXES, EACH REPORTED (no lock on the first valid header): %s"
          % ("demonstrated" if ok else "NOT shown"))
    sys.exit(0 if ok else 1)


def cmd_signer(n, t):
    """THE APEX COMMITS ITS SIGNER.  Every apex preimage starts with the
    signer's current pub, never carried: a reader recomputes the apex under
    the pub its book holds as current and requires the signature to extract
    to that same pub.  So a value signed under one of the initiator's keys
    does not verify under another, and a seat that holds two of them (its
    current and an installed successor) cannot be shown one value under
    either.  distribute's `signer <otherCtx>` fault computes the apex under
    the other context's pub and signs it with its own.  Two arms:
      1: before the rotation, pub_0 current: ctx_00 signs an apex committed
         under pub_1.  The signature extracts to the current pub (offsetgate
         ACCEPTs it); the recompute under pub_0 does not reach the apex, and
         every receive refuses it, every exchange forwards nothing, every
         assemble pools nothing;
      2: the genuine rotation installed, pub_1 current: ctx_01 signs an apex
         committed under pub_0.  The same: the signature extracts to the
         current pub, the recompute under it does not reach the apex."""
    def recv_all(prog="./receive"):
        return [subprocess.run([prog, _cfgpath(p), str(p - 1), "."], cwd=HERE,
                               capture_output=True) for p in range(1, n)]

    def refused(rs):
        return all(r.returncode != 0 and b"apex=BAD" in r.stderr for r in rs)

    def nothing_pooled():
        xs = [_sys("exchange", i) for i in range(n - 1)]
        rcs = cmd_phase("assemble")
        return (all(x != 0 for x in xs) and all(r != 0 for r in rcs)
                and all(_field("priv/%02d_assemble.txt" % p, "pools") == "0"
                        for p in range(1, n)))

    def sig_current():
        _distribute_runfile(_field("wire/dist/00_to_01_apex.txt", "apex"))
        return _gate(1, SLOT_PAY)

    cmd_keychain(1)
    cmd_setup(n, t)
    _reset_floor()
    write_blob("cryptoMule signer demonstration, apex under pub_1. " * 40)
    cmd_dist("priv/00_ctx_00.bin", 0, "signer", "priv/00_ctx_01.bin")
    ok1 = refused(recv_all())
    pool1 = nothing_pooled()
    gate1 = sig_current()
    print("ctx_00 signs an apex committed under pub_1, pub_0 current: the signature %s"
          " the current pub; receive %s; assemble %s"
          % ("extracts to" if gate1 == "ACCEPT" else "does NOT extract to (BUG)",
             "REFUSED at all %d (apex)" % (n - 1) if ok1 else "ADMITTED (BUG)",
             "pools nothing" if pool1 else "POOLED (BUG)"))
    if rotate_verify(0) != n - 1:
        sys.exit("signer: rotation 0 did not install everywhere")
    write_blob("cryptoMule signer demonstration, apex under pub_0. " * 40)
    cmd_dist("priv/00_ctx_01.bin", 1, "signer", "priv/00_ctx_00.bin")
    ok2 = refused(recv_all())
    pool2 = nothing_pooled()
    gate2 = sig_current()
    print("ctx_01 signs an apex committed under pub_0, pub_1 current: the signature %s"
          " the current pub; receive %s; assemble %s"
          % ("extracts to" if gate2 == "ACCEPT" else "does NOT extract to (BUG)",
             "REFUSED at all %d (apex)" % (n - 1) if ok2 else "ADMITTED (BUG)",
             "pools nothing" if pool2 else "POOLED (BUG)"))
    ok = (ok1 and pool1 and gate1 == "ACCEPT" and ok2 and pool2 and gate2 == "ACCEPT")
    print("THE APEX COMMITS ITS SIGNER (recomputed under the current pub, the"
          " signature extracting to it): %s" % ("demonstrated" if ok else "NOT shown"))
    sys.exit(0 if ok else 1)


def cmd_twoslot(n, t):
    """ONE VALUE IS ONE SIGNING AT ONE OFFSET.  Every apex preimage carries
    the signing offset right after the signer's pub, and no message carries
    it: a reader recomputes the apex under its book's pub and the offset the
    signature yields.  So a value fixes the offset it was signed at, and every
    seat that admits it records that one offset in its offset floor,
    whichever copy reached it.  distribute's `twoslot` fault signs one apex at
    signing offset 1, sent to the first half of the recipients (rounded up),
    and at signing offset 3, sent to the rest.  Three checks:
      1: the copies at offset 3 do not recompute to the apex message at their
         offset, and receive refuses them on the apex; the copies at offset 1
         are admitted;
      2: each admitting seat's offset floor records its OWN copy's signature
         (the driver plays the floor's writer per seat here, not with seat
         1's signature for all): every floor that holds the value holds
         offset 1;
      3: the next payload, at the unspent offset 2, is admitted at every
         seat.
    Were the offset outside the value, both copies would be admitted as the
    one apex, the floors would read 1 and 3, and the payload at offset 2
    would be admitted at some seats and refused at the rest as below their
    floor."""
    def recv_all():
        return [subprocess.run(["./receive", _cfgpath(p), str(p - 1), "."], cwd=HERE,
                               capture_output=True) for p in range(1, n)]

    def admitted():
        return [p for p in range(1, n)
                if _field("priv/%02d_recv.txt" % p, "sig_ok") == "yes"
                and _field("priv/%02d_recv.txt" % p, "offset_ok") == "yes"]

    cmd_keychain(1)
    cmd_setup(n, t)
    _reset_floor()
    write_blob("cryptoMule twoslot demonstration, one apex. " * 40)
    cmd_dist("priv/00_ctx_00.bin", 0, "twoslot")
    rs = recv_all()
    adm = admitted()
    ref = [p for p in range(1, n) if p not in adm]
    first = list(range(1, n // 2 + 1))             # the seats sent offset 1
    floors = {}
    for p in adm:
        path = os.path.join(HERE, "wire", "run_%02d_to_%02d.txt" % (SLOT_PAY, p))
        with open(path, "w") as f:
            f.write("phase: payload\n")
            f.write("slot: %d\n" % SLOT_PAY)
            f.write("anchor: %s\n" % _field("priv/%02d_recv.txt" % p, "apex"))
            f.write("mls_sig: %s\n" % _field("priv/%02d_recv.txt" % p, "mls_sig"))
        subprocess.run(["./cmhmac", _mac0(p), "0", str(p), path], cwd=HERE, check=True)
        if _gate(p, SLOT_PAY) != "ACCEPT":
            sys.exit("twoslot: offset floor refused at seat %d a payload receive admitted" % p)
        floors[p] = int(_field("priv/%02d_floor.txt" % p, "highwater"))
    apexes = set(_field("priv/%02d_recv.txt" % p, "apex") for p in adm)
    ok1 = (adm == first and len(apexes) == 1
           and all(b"apex=BAD" in rs[p - 1].stderr for p in ref))
    ok2 = bool(floors) and set(floors.values()) == {1}
    print("one apex signed at signing offsets 1 (seats %s) and 3 (seats %s):"
          " receive admitted at seats %s under %d apex, refused at seats %s%s"
          % (first, [p for p in range(1, n) if p not in first], adm, len(apexes), ref,
             " (apex)" if ref and ok1 else ""))
    print("offset floors of the seats that admitted it: %s"
          % ", ".join("seat %d at %d" % (p, floors[p]) for p in sorted(floors)))
    write_blob("cryptoMule twoslot demonstration, the next payload. " * 40)
    cmd_dist("priv/00_ctx_00.bin", 0, "slot2")     # the next payload, at the unspent offset 2
    recv_all()
    adm2 = admitted()
    ok3 = adm2 == list(range(1, n))
    print("the next payload at signing offset 2: admitted at seats %s, refused at seats %s"
          % (adm2, [p for p in range(1, n) if p not in adm2]))
    ok = ok1 and ok2 and ok3
    print("ONE VALUE IS ONE SIGNING AT ONE OFFSET (every seat that admits it"
          " records the same offset): %s" % ("demonstrated" if ok else "NOT shown"))
    sys.exit(0 if ok else 1)


def cmd_keychain(m):
    """generate m+1 MLS contexts and bootstrap the books from pub_0 (OOB root)."""
    _mkdirs()
    prsz, _ = _szinfo()
    for k in range(m + 1):
        with open(os.path.join(HERE, "priv", "00_ctx_%02d.bin" % k), "wb") as f:
            f.write(secrets.token_bytes(prsz))
    pub0 = subprocess.check_output(
        ["./mlspub", "priv/00_ctx_00.bin"], cwd=HERE).decode().strip()
    _boot_books()
    print("keychain: %d contexts; OOB root pub_0 = %s" % (m + 1, pub0))


def cmd_rotchain(m, n, t):
    """walk the identity chain: each context signs the next context's pub,
    directed to every recipient; every recipient walks its own book."""
    cmd_keychain(m)
    cmd_setup(n, t)
    for k in range(m):
        if rotate_verify(k) != n - 1:
            sys.exit("rotation %d failed to verify at every recipient" % k)
    print("-- final book of seat 1 (current = pub_%d) --" % m)
    cmd_show("priv/01_book.txt")


def _ishex(s):
    return len(s) >= 2 and len(s) % 2 == 0 and all(c in "0123456789abcdef" for c in s)


def cmd_show(path):
    if not os.path.isabs(path):
        path = os.path.join(HERE, path)
    print("== %s ==" % os.path.relpath(path, HERE))
    with open(path) as f:
        for line in f:
            line = line.rstrip("\n")
            if ": " not in line:
                print(line)
                continue
            k, v = line.split(": ", 1)
            if _ishex(v):
                nb = len(v) // 2
                disp = v if len(v) <= 72 else v[:48] + " ... " + v[-16:]
                print("  %-14s %5dB  %s" % (k, nb, disp))
            else:
                print("  %-14s        %s" % (k, v))


def main(argv):
    if len(argv) < 2:
        sys.exit(__doc__)
    c = argv[1]
    if c == "setup":
        cmd_setup(int(argv[2]), int(argv[3]))
    elif c == "keychain":
        cmd_keychain(int(argv[2]))
    elif c == "dist":
        cmd_dist(*argv[2:4]) if len(argv) > 2 else cmd_dist()
    elif c == "recv":
        cmd_phase("receive")
    elif c == "exch":
        cmd_phase("exchange")
    elif c == "asm":
        cmd_phase("assemble")
    elif c == "demo":
        cmd_demo(int(argv[2]), int(argv[3]))
    elif c == "rotchain":
        cmd_rotchain(int(argv[2]), int(argv[3]), int(argv[4]))
    elif c == "session":
        cmd_session(int(argv[2]), int(argv[3]), int(argv[4]))
    elif c == "fwdsec":
        cmd_fwdsec(int(argv[2]), int(argv[3]))
    elif c == "offsets":
        cmd_offsets(int(argv[2]), int(argv[3]))
    elif c == "catchup":
        cmd_catchup(int(argv[2]), int(argv[3]), int(argv[4]))
    elif c == "mixed":
        cmd_mixed(int(argv[2]), int(argv[3]))
    elif c == "steps":
        cmd_steps(int(argv[2]), int(argv[3]))
    elif c == "tamper":
        cmd_tamper(int(argv[2]), int(argv[3]))
    elif c == "byz":
        cmd_byz(int(argv[2]), int(argv[3]))
    elif c == "parts":
        cmd_parts(int(argv[2]), int(argv[3]))
    elif c == "limit":
        cmd_limit(int(argv[2]), int(argv[3]))
    elif c == "retry":
        cmd_retry(int(argv[2]), int(argv[3]))
    elif c == "resend":
        cmd_resend(int(argv[2]), int(argv[3]), int(argv[4]))
    elif c == "chain":
        cmd_chain(int(argv[2]), int(argv[3]), int(argv[4]))
    elif c == "evidence":
        cmd_evidence(int(argv[2]), int(argv[3]), int(argv[4]))
    elif c == "hostile":
        cmd_hostile(int(argv[2]), int(argv[3]))
    elif c == "pools":
        cmd_pools(int(argv[2]), int(argv[3]))
    elif c == "signer":
        cmd_signer(int(argv[2]), int(argv[3]))
    elif c == "twoslot":
        cmd_twoslot(int(argv[2]), int(argv[3]))
    elif c == "empty":
        cmd_empty(int(argv[2]), int(argv[3]))
    elif c == "slot":
        cmd_slot(int(argv[2]), int(argv[3]))
    elif c == "show":
        cmd_show(argv[2])
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main(sys.argv)
