/*
 * cryptoMule - disk based mule of the multi-seat dispersal payload
 * Copyright (C) 2026 G. David Butler <gdb@dbSystems.com>
 *
 * This file is part of cryptoMule
 *
 * cryptoMule is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * cryptoMule is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/*
 * cm.h - shared definitions for the phase programs (distribute, receive,
 * exchange, assemble).  Files on disk stand in for the wire, so the blob
 * round-trip is provable from disk files instead of wire captures (the files
 * render each message's fields readably, hmac included; they are not the
 * transport's bytes).  The wire is THREE directed messages per recipient, each
 * under its own pairwise hmac and no two alike in content: the apex alone (one
 * hash width, the same to everyone: the value signed), the shard
 * alone (the one shard-sized part), and the sign message (everything else,
 * the dispersal label and every hash-width scaled field: the signed inputs,
 * the signature, the masked value, both proofs).  The shard and sign
 * messages carry a TAG, the apex message's file name, so a reader knows
 * which apex message a part is of before verifying it.  The arithmetic ties
 * them, not travelling together: the sign message's inputs hash to the apex
 * under the signer's pub the reader holds and the offset its signature
 * yields, the shard verifies under its root.
 * The three are one sender's FRAGMENT to one recipient; on the exchange wire
 * a fragment is that sender's LEG.  A recipient keeps the fragment it
 * validated BANKED per dispersal (priv/<p>_recv_<kk>.txt), so it can be sent
 * again byte for byte.  The mule exercises only the value+sidecar
 * cryptography that enables censorship resistance: encrypt, Reed-Solomon
 * shard, Shamir secret-share, Merkle-bind, pairwise mask, and a
 * forward-secret key chain.
 *
 * Pipeline (encrypt-then-disperse):
 *   distribute: blob -> huffman -> compressed, zero-padded to k x shard_len
 *               -> ciphertext = that XOR keystream(K), the thing dispersed
 *               -> rsecMk shards (R = N-1, k=T data, m=R-T parity)
 *               K -> sss shares (R, threshold T) -> sssMk tree
 *               apex = H(signer pub || signing offset || orig_hash ||
 *                        rsecmk_root || sssmk_root)
 *               MLS-signed once by the initiator, under that pub at that offset.
 *   value   = [seed][SSS key-share] masked as one UNIT; sidecar = the clear
 *             RSEC shard.  Each carries its Merkle proof against the signed
 *             roots.  All the SSS code points (scp + R ocps, N distinct points)
 *             DERIVE from the hidden per-distribution seed, and the seed is
 *             bound into every sssMk leaf: a received unit verifies the
 *             code points ITS seed derives, and that every leaf was dealt under
 *             one seed is checked at threshold, where a subset mixes no
 *             seeds and the re-encode names every leaf of another (below-
 *             threshold outsiders still see nothing -- the seed rides only
 *             inside the mask).
 *
 * Dispersal identity and retention (cmChain, cmFloorLoad below):
 *   chain_0 = the dealt genesis; chain_{k+1} = H(chain_k || the dispersal's
 *   message hash, orig_hash).  The chain is the application's: it knows its
 *   message and so that hash, and can fold and check the chain with nothing of
 *   the dispersal.  The mask ratchet steps on the LINK, so the key for dispersal k+1 is
 *   reachable only from dispersal k's result.  Stepping wipes, so the keystate
 *   also holds a floor base the serving side walks FORWARD from to re-derive any
 *   retained dispersal's masks; release moves the floor and destroys what it
 *   passes, which is where forward secrecy actually starts.
 *
 * Dealer consistency (a dealer is only byzantine if receivers can DETECT it;
 * there must be enough information received to do so), and most byzantine
 * results are environmental, not adversarial -- a dealer without ECC memory
 * commits a flipped share or shard now and then:
 *   - per part (receive, and assemble's gather): Merkle proofs vs the signed
 *     roots, code points vs the seed derivation.  The share and the shard are
 *     two parts under two roots and are judged, forwarded and gathered
 *     independently: a rotted shard does not cost its holder's share.
 *   - at threshold (assemble): the signed orig_hash is the oracle.  Parts
 *     are gathered LAZILY -- T shares and T shards, a search, and the next
 *     fragment only after a failed search -- and T-subsets are tried in
 *     whack-a-mole order (the first T, then one swap, then two) until a
 *     reconstruction hashes to orig_hash: shares first, a candidate K being
 *     any subset whose polynomial one more held share agrees with (or the
 *     sole subset when exactly T are held); then, under that K with its
 *     keystream hoisted once, shards against the hash.  A single bad
 *     committed part costs a few tries; the full C(R,T) is never incurred by
 *     an honest dealer, and CM_SEARCH_TRIES bounds a dealer that salts (corrupts) most
 *     of its leaves.  PASS is the message that matches the signed hash;
 *     FRAUD is threshold reached and no subset reproducing it (a consistent
 *     codeword of the wrong bytes included); FAIL is no message and no accusation: no validated header, under
 *     threshold on either part, or the search unfinished at the try budget.
 *   - after PASS, RE-ENCODE BOTH CODES and compare to the signed roots --
 *     the RS code from the CANONICAL ciphertext (the delivered blob
 *     re-encoded, zero-padded, keystreamed under the winning K: the hash
 *     never read the stream's unused bits or the padding), all R shards and
 *     the rsecMk tree vs rsecmk_root; the share polynomial of the winning
 *     subset at ALL R points of its seed and the sssMk tree vs sssmk_root.
 *     Root equality holds iff the committed trees ARE the honest encodings
 *     of the delivered message; a mismatch names the commitment
 *     inconsistent and every held part off the re-encode is listed by leaf.
 *     The mule reports the count; what it means is the host's.
 *   The shard length is not among the judged properties: the rsecMk root
 *   binds it (a leaf hash binds bytes, not a length; a codeword's rows are
 *   one length), so a verifier recomputes the root at the length of the shard
 *   it holds and a leaf committed at another length fails its Merkle check at
 *   receive.
 *
 * Hash roles (each named once at its seam; see the CM_*_H defines below and the
 * plug fills in cm.c).  The mule runs a single concrete hash, but the roles are
 * separated in the source so a lift to a runtime suite changes definitions, not
 * scattered call sites:
 *   sign -- apex + MLS signature + signer pub + orig_hash, ONE width.  mlsExtract
 *           verifies a signed hash of exactly 2^CM_SIGN_H bytes and the apex IS
 *           that signed hash, so the apex hash and MLS share the sign plug.
 *           Every apex preimage starts with the SIGNER'S CURRENT PUB and
 *           the SIGNING OFFSET it signs at: a payload's apex is the
 *           sign-hash of them, orig_hash and the two roots (cmApex), a
 *           rotation's the sign-hash of them and the successor pub its sign
 *           message carries as pub_hash (cmApexRot).  The sign message
 *           carries the rest of the preimage, never the signer pub or the
 *           offset: a reader takes the pub from its book and the offset from
 *           the signature's structure (cmMlsOff), recomputes the apex under
 *           both, and verifies that the signature extracts to the same pub.
 *           So one value is one kind under one signer at one offset: not a
 *           payload to some seats and a rotation to others, not verifiable
 *           under another of the signer's keys, and not signed at two
 *           offsets -- every seat that holds the value holds the offset it
 *           was signed at, whichever copy reached it.
 *   sss  -- Shamir Merkle tree (root + per-recipient proof).  Independent.
 *   rsec -- Reed-Solomon Merkle tree (root + per-recipient proof).  Independent.
 *   kdf  -- keystream + mask + ratchet HKDF.  Off-wire (speed, not bandwidth).
 *   hmac -- pairwise wire-message tamper MAC.  Between phases an adversary can
 *           alter any disk file OUTSIDE priv/ (the disk IS the wire), so every
 *           wire message carries, as its mandatory LAST field, hmac =
 *           CM_HMAC(mac PSK, [sender][recipient] || file bytes).  The mac PSK
 *           is a SEPARATELY DEALT static pairwise mesh: it never enters the
 *           keystate and never ratchets -- integrity needs no forward secrecy,
 *           and a static key lets a stale seat detect tampering before
 *           catch-up.  The id fold blocks cross-edge replay under the
 *           symmetric pairwise key.  A failed hmac is a WIRE-TAMPER verdict,
 *           distinct from the sender-fault verdicts the inner gates produce.
 */

#ifndef CM_H
#define CM_H

#include <stdio.h>
#include "rmd128.h"
#include "rmd160.h"
#include "sss.h"
#include "sssMk.h"
#include "rsec.h"
#include "rsecMk.h"
#include "huf.h"
#include "mls.h"

#define CM_SIGN_H     4              /* sign: 2^4 bytes; apex + MLS + pub + orig_hash */
#define CM_SIGN_HSZ   RMD128_SZ      /* == (1 << CM_SIGN_H) */
#define CM_SSS_H      4              /* sss Merkle tree: 2^4 bytes per tree element */
#define CM_SSS_HSZ    RMD128_SZ      /* == (1 << CM_SSS_H) */
#define CM_RSEC_H     4              /* rsec Merkle tree: 2^4 bytes per tree element */
#define CM_RSEC_HSZ   RMD128_SZ      /* == (1 << CM_RSEC_H) */
#define CM_KDF        rmd160hkdf     /* kdf: keystream + mask + ratchet (off-wire) */
#define CM_KDF_HSZ    RMD160_SZ      /* kdf hash output (chunk/info sizing) */
#define CM_HMAC       rmd128hmac     /* hmac: pairwise wire-message tamper MAC */
#define CM_HMAC_SZ    RMD128_SZ      /* hmac output (the wire "hmac" field) */
#define CM_MLS_S      2              /* 2^2 = 4 signing offsets: 0 the rotation, signing offsets 1..3 a run of payloads */
#define CM_SLOT_ROT   0              /* the rotation's signing offset, and ONLY the rotation's: rotverify refuses a rotation at any other offset, receive/assemble refuse a payload at this one */
#define CM_SLOT_PAY   1              /* payload (application message) signing offset */
#define CM_KEY_LEN    32             /* bulk keystream key K, == SSS share len */
#define CM_SEED_LEN   16             /* hidden per-distribution seed of the code points (128-bit) */
#define CM_MVAL_LEN   (CM_SEED_LEN + CM_KEY_LEN)  /* masked SSS value on the wire AND the sssMk leaf data: [seed][key-share], masked as one unit so the code points stay hidden from anyone who cannot unmask; scp/ocp are DERIVED from the seed, never carried */
#define CM_CT_MAX     65536          /* the padded ciphertext (k x shard_len), the thing dispersed, is at most 64k (the number is the expected transport's, not derived here); distribute refuses a message that compresses past it, and receive and assemble refuse a shard that implies more -- the same check on both wires */
#define CM_SHARD_MAX  CM_CT_MAX      /* a ciphertext shard is one transport message and shard_len is the delivered message's own length, never carried; a shard is at most half the ciphertext (T = 2, the least T), so this only bounds the read buffer */
#define CM_PSK_LEN    64             /* pairwise mask IKM: serves BOTH phases (separated by the mask DOMAIN: CM_DOM_DIST vs CM_DOM_EXCH) */
#define CM_MAXPROC    256            /* GF(2^8) bound on shares/shards; also bounds the seat ids that index the pairwise store */
#define CM_SEARCH_TRIES 65536        /* assemble's one try budget, shares and shards together: a committed bad part is found by search (above), and a dealer that salts most of its leaves would otherwise make every assembler enumerate C(R,T); the default covers every pair of 255 shares twice (the agreed pass and the relaxed pass, 2 x 32385), the shard subsets under each K candidate coming out of the same budget */
#define CM_BLOB_MAX   (1UL << 30)    /* a wrong try's garbage stream self-describes any length (the huffman encoding's own length field); below this the blob buffer grows to the probe, a probe past it is that try failing -- the honest blob is the application's to size */

/* HKDF info domain separators (folded after the apex).  Distribute and exchange
 * mask under SEPARATE domains -- CM_DOM_DIST and CM_DOM_EXCH.  One payload's whole
 * flow -- distribute, receive, exchange, assemble -- masks under ONE chain step,
 * the domain keeping the two phases' keystreams distinct; the SINGLE ratchet per
 * payload is taken once the flow is done, keyed on the payload's chain link, and
 * the NEXT payload's distribute is the first thing masked under the new step.
 * Each (step, domain) pair is used once. */
#define CM_DOM_DIST   'D'            /* distribute mask: IKM = PSK(0,i) */
#define CM_DOM_EXCH   'X'            /* exchange  mask: IKM = PSK(i,j) */
#define CM_DOM_KEY    'K'            /* bulk keystream: IKM = K */
#define CM_DOM_RAT    'R'            /* key ratchet: next = HKDF(prev, h_k||'R') */
#define CM_DOM_GEO    'G'            /* SSS code points = HKDF(seed, 'G'||seg) */

/* dealt secrets + membership.  The OPERATOR'S drive/config.txt holds every field
 * (the full pairwise mesh PSK(a,b)); each seat's priv/<p>_config.txt holds only
 * that seat's ROW -- membership (n, T) and the pairwise PSK(p,q) it is a party
 * to, pre-resolved to the recipient id q.  A recipient holding only its own pairs can
 * unmask only its own distribution share (1 < T), so it stays blind to the
 * payload until exchange: this least-knowledge split is what enforces censorship
 * resistance.  The SSS code points (scp/ocp) are NOT here -- they DERIVE from a
 * hidden per-distribution seed (cmGeometry) that rides inside each masked
 * unit, bound into every leaf of the signed sssmk_root.
 * The store is indexed by the RECIPIENT seat id (self-relative): psk[q] is this
 * seat's key with seat q, used for distribution AND exchange alike.
 * The mac mesh is dealt the same way but is STATIC: it keys only the wire-message
 * tamper hmac, never enters the keystate, and never ratchets. */
typedef struct {
  unsigned int n;                            /* total seats incl. initiator */
  unsigned int t;                            /* reconstruction threshold */
  unsigned char psk[CM_MAXPROC][CM_PSK_LEN]; /* psk[q] = pairwise mask PSK(self,q) */
  unsigned char mac[CM_MAXPROC][CM_PSK_LEN]; /* mac[q] = pairwise wire-hmac PSK(self,q), static */
  unsigned char genesis[CM_SIGN_HSZ];        /* the chain's base; PUBLIC, dealt to all (see cmChain) */
  unsigned char pskHave[CM_MAXPROC];         /* pskHave[q]: this seat holds PSK(self,q) */
  unsigned char macHave[CM_MAXPROC];         /* macHave[q]: this seat holds mac(self,q) */
  unsigned char genesisHave;                 /* the deal carried a genesis row */
} cmCfg;

/* hex: write 2*l lower-case chars (no NUL); decode up to max bytes of that
 * one form, return count, or -1 when the hex runs past max or is not that
 * form (overlong is malformed, never truncated; upper case is not the same
 * bytes) */
void cmHexEnc(const unsigned char *b, unsigned int l, char *o);
int cmHexDec(const char *h, unsigned char *o, unsigned int max);

/* load the dealt config from a "key value" text file, 0 on success; refuses
 * a deal outside N >= 3, 2 <= T <= N - 1, N <= CM_MAXPROC (T > 1 is the
 * censorship-resistance floor: at T = 1 every share is the key) */
int cmCfgLoad(const char *path, cmCfg *c);

/* override the PSK(s) this seat holds with the dispersal's ratcheted mask IKMs
 * from a per-seat keystate ("psk_<QQ>: <hex>", QQ = recipient seat id), setting
 * c->pskHave for each one present; call after cmCfgLoad.  -1 if a key the config
 * deals has no row: the dealt key never stands in for a step. */
int cmKeystateLoad(const char *path, cmCfg *c);

/* as cmKeystateLoad, but read the RETENTION FLOOR base ("floor: <process>" +
 * "fpsk_<QQ>: <hex>") instead of the current step, and report the floor's dispersal
 * in *process.  -1 if the keystate carries no floor.
 *
 * The floor is what makes a forward-only chain SERVABLE.  A wiped step cannot be
 * recomputed, so a seat that has ratcheted past a dispersal can no longer produce
 * that dispersal's masks -- yet a seat that missed it may still ask.  Keeping the
 * base at the oldest dispersal still worth serving, and recomputing FORWARD from it
 * (the catchup loop; exchange's and assemble's resend modes), answers those asks without retaining a snapshot per
 * dispersal and without keeping any step the floor has already passed.  The floor is
 * therefore exactly where forward secrecy starts, and moving it (./release) is what
 * buys the secrecy back -- everything at or after it is derivable, everything
 * before it is gone.  Loads into c->psk: the serving form is derived, used, and
 * dropped, never a second live keystate.
 *
 * THE INDEXING, once.  "floor: F" names a DISPERSAL -- the oldest one still
 * servable -- and the base stored beside it is the mask key of chain step F,
 * dispersal F's one step: its distribute and its exchange both masked under it,
 * the single ratchet after its flow stepping past it.  So walking the base from F
 * to dispersal W applies the chain links of dispersals F .. W-1, and a request for
 * W < F is the released case.  The base must be the key the leg was MASKED under
 * for a re-derived serving form to be BYTE-IDENTICAL to the exchange leg it
 * reproduces -- land the walk one step off and a serve becomes a fresh masking
 * that no retained message can be checked against, which reads as working
 * because both ends agree with each other; the byte-identity check is what
 * tells them apart. */
int cmFloorLoad(const char *path, cmCfg *c, unsigned long *process);

/* derive a seat's keystate path from its config path (the sibling that swaps
 * "_config.txt" -> "_keystate.txt"): priv/<p>_config.txt -> priv/<p>_keystate.txt */
void cmKsPath(const char *cfgPath, char *out);

/* one ratchet step: next = HKDF(prev, h_k || 'R', nextLen).  One-way (HMAC),
 * so a wiped prev cannot be recomputed -- forward secrecy on h_k. */
void cmRatchet(const unsigned char *prev, unsigned int prevLen
              ,const unsigned char *hk, unsigned char *next, unsigned int nextLen);

/* rmd128 hash plugs for the three Merkle/identity consumers */
void cmSssMkPlug(sssMkHsh_t *p);
void cmRsecMkPlug(rsecMkHsh_t *p);
void cmMlsPlug(mlsHsh_t *p);

/* one sign-role hash over a single buffer -> CM_SIGN_HSZ bytes */
void cmHash(const unsigned char *b, unsigned int l, unsigned char *o);

/* chain = sign-hash(prev || msg) -- one link of the dispersal chain; msg is the
 * dispersal's MESSAGE hash, the orig_hash its signed header carries.
 *
 * The ratchet has to key on something, and the mule's forward secrecy is only as
 * good as the parties' AGREEMENT on what that something is: two seats that step
 * on different values stop sharing keys, and nothing reports it.  Agreement itself is ASSUMED
 * here -- who fixes a dispersal's message, and when, is the supplier's, exactly as the
 * rest of the coordination is.  What the chain adds is that the trigger cannot be
 * an ARBITRARY value: each link folds the previous one, so the sequence is pinned
 * end to end from a base every seat was dealt, and a seat that steps on
 * anything else is off the chain from there on.
 *
 * What is folded is the MESSAGE hash, not the apex.  The apex is what is signed
 * and what a dispersal is agreed under; it commits the message hash with the
 * two Merkle roots of ONE dispersal of it, and those roots are the mule's --
 * the application that gave the message, or is handed it, knows the message
 * and its hash and nothing of them.  A chain over apexes could be checked only
 * by a holder of a fragment of every dispersal; a chain over message hashes is
 * checked from the messages alone, which is what makes it usable outside, for
 * storage or recovery.
 *
 * The base is the DEALT genesis (cfg->genesis), a public per-deployment value in
 * the same out-of-band deal as the keys.  Public because it authenticates
 * nothing: the signatures do that.  Dealt because every seat must start the
 * fold from the same place or nothing ever agrees. */
void cmChain(const unsigned char *prev, const unsigned char *msg, unsigned char *o);

/* apex = sign-hash(signerPub || off || orig_hash || rsecmk_root || sssmk_root),
 * signerPub the CM_SIGN_HSZ-byte pub of the context that signs the apex and
 * off the signing offset it signs at, 4 bytes big-endian.  The apex commits
 * the identity that signs it and the offset it is signed at, so a value
 * signed under one of a signer's keys does not verify under another, and a
 * value is one signing at one offset: a verifier recomputes under the pub it
 * holds as current and the offset the signature yields (cmMlsOff), and
 * requires the signature to extract to that same pub.  Neither is carried;
 * the verifier has the pub, and the offset is in the signature.  The
 * ciphertext length is not bound: the shard length is the shard message's
 * own length, the huffman encoding self-describes the plaintext length, and
 * H(blob)==orig_hash is the gate -- so a length never needs to be carried or
 * signed. */
void cmApex(const unsigned char *signerPub, unsigned int off, const unsigned char *origHash
           ,const unsigned char *rsecRoot, const unsigned char *sssRoot, unsigned char *o);

/* a rotation's apex = sign-hash(signerPub || off || succPub): signerPub the
 * current context's pub, the one that signs; off the offset it signs at,
 * encoded as cmApex encodes it (CM_SLOT_ROT for a genuine rotation, and
 * rotverify refuses any other); succPub the successor pub the rotation's
 * sign message carries as pub_hash and the verifier installs. */
void cmApexRot(const unsigned char *signerPub, unsigned int off, const unsigned char *succPub
              ,unsigned char *o);

/* XOR buf in place with the bulk keystream CM_KDF(K, nonce||'K'||seg).
 * nonce is orig_hash (CM_SIGN_HSZ bytes): known before the apex, which depends
 * on the ciphertext via the roots, so the apex cannot key the keystream. */
void cmKeystream(const unsigned char *k, unsigned int kl
                ,const unsigned char *nonce, unsigned char *buf, unsigned int len);

/* derive the SSS code points from the hidden seed: n DISTINCT GF(2^8) points
 * (rejection-sampled from CM_KDF(seed, 'G'||seg)); pts[0] is scp, pts[1..n-1]
 * the R ocps.  Deterministic: dealer and every receiver derive the SAME
 * code points, so distinctness and scp-exclusion hold by construction and any
 * committed deviation surfaces as a Merkle/re-encode mismatch. */
void cmGeometry(const unsigned char *seed, unsigned int n, unsigned char *pts);

/* XOR buf in place with CM_KDF(ikm, apex||dom||idx, len) -- mask, symmetric.
 * dom is the phase domain (CM_DOM_DIST for distribute/receive, CM_DOM_EXCH for
 * exchange/assemble): the domain is what separates the two phases' keystreams. */
void cmMask(const unsigned char *ikm, unsigned int ikml, const unsigned char *apex
           ,unsigned char dom, unsigned char idx, unsigned char *buf, unsigned int len);

/* MLS identity helpers (the rotation/payload signing boundary).
 * sign: load private data, derive the signer pub, sign anchor (CM_SIGN_HSZ) at signing offset;
 *       returns malloc'd sig in *sig (caller frees) + *sigLen, writes signer pub.
 * verify: mlsExtract(anchor, sig) == pub ? (1 ok / 0 bad).  The offset is
 *       cmMlsOff's, read first by every verifier.
 * off: the signing offset a signature yields (mlsEgOf - 1), read from its
 *       structure before anything is verified (1 ok / 0 malformed): the
 *       offset is an input of the apex, so a verifier needs it to recompute
 *       the apex, and every gate on it is arithmetic that comes before the
 *       signature is paid for -- the slot class (CM_SLOT_ROT for a rotation,
 *       any other for a payload: rotverify, receive and assemble each gate
 *       it, which is what keeps one class's one-time offsets out of the
 *       other's) and the offset floor (receive, assemble, offsetgate: below
 *       the high-water, or at it under another anchor, refused).  The
 *       signature then verifies the bytes the offset was read from, so a
 *       verifier admits at that offset or not at all.
 * pub: derive only. */
int cmMlsSign(const char *privPath, unsigned int slot, const unsigned char *anchor
             ,unsigned char **sig, unsigned long *sigLen, unsigned char *pub);
int cmMlsVerify(const unsigned char *pub, const unsigned char *anchor
               ,const unsigned char *sig, unsigned long sigLen);
int cmMlsOff(const unsigned char *sig, unsigned long sigLen, unsigned int *off);
int cmMlsPub(const char *privPath, unsigned char *pub);

/* wire-message tamper MAC (see the hmac role above).  append: read the whole
 * file, hmac [sender][recipient] || bytes, append the "hmac" field (so it is
 * the file's LAST line); 0 on success.  check: require the last line to be a
 * well-formed "hmac" field and the hmac over [sender][recipient] || the bytes
 * before it to match as written; 1 ok, 0 tampered/missing.  Check FIRST: no other field
 * of a wire message is trusted until its hmac passes. */
int cmHmacAppend(const char *path, const unsigned char *key, unsigned int kl
                ,unsigned char s, unsigned char r);
int cmHmacCheck(const char *path, const unsigned char *key, unsigned int kl
               ,unsigned char s, unsigned char r);

/* text field I/O: "name: <hex>\n", "name: <decimal>\n" and "name: <text>\n" */
void cmPutField(FILE *f, const char *name, const unsigned char *b, unsigned int l);
void cmPutU(FILE *f, const char *name, unsigned long v);
/* read named field from path; hex -> out (return bytes or -1); U -> *v (0, or -1
 * when absent or not the canonical digit run cmPutU writes); Str -> out,
 * NUL-terminated, the newline stripped (return its length, or -1 when absent
 * or the line does not end within the reader's bound: overlong is malformed,
 * never truncated).  The one text field is the tag, an apex message's file
 * name, written with fprintf. */
int cmGetField(const char *path, const char *name, unsigned char *out, unsigned int max);
int cmGetU(const char *path, const char *name, unsigned long *v);
int cmGetStr(const char *path, const char *name, char *out, unsigned int max);

#endif /* CM_H */
