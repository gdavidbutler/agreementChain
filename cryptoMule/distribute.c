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
 * cryptoMule distribute - the initiator.
 *
 *   blob -> huffman -> compressed, zero-padded to k x shard_len
 *        -> ciphertext = that XOR keystream(K, orig_hash): the thing dispersed
 *        -> rsecMk shards (R = N-1; k = T data, m = R-T parity)
 *   K    -> sss shares (R, threshold T) -> sssMk tree
 *   apex = H(signer pub || signing offset || orig_hash || rsecmk_root ||
 *            sssmk_root).
 *
 * The apex is signed by the initiator's CURRENT MLS context at the payload signing offset,
 * and its preimage starts with that context's pub and that offset: the apex
 * commits the identity that signs it and which of its one-time signings it
 * is.  The apex is the value signed; the share and shard are
 * bound to it by their Merkle proofs against the signed roots.  The verifier
 * recomputes the apex under book.txt's current pub, the identity the rotation
 * chain installed for this dispersal, and the offset the signature yields,
 * and checks that the signature extracts to that same pub.  Neither is
 * carried: the verifier has the pub, and the offset is in the signature.
 *
 * Writes, per recipient seat p in 1..R, THREE directed messages under
 * <out>/wire/dist/, each ending in the pair's wire hmac (static mac PSK;
 * tamper detection on the disk wire, see cm.h), carrying only what the
 * recipient cannot derive:
 *   00_to_<p>_apex.txt   the apex alone: one hash width, the same to every
 *                        recipient -- the value signed;
 *   00_to_<p>_shard.txt  the recipient's clear ciphertext shard alone: the
 *                        one shard-sized sidecar;
 *   00_to_<p>_sign.txt   the rest, every field hash-width scaled: process,
 *                        the apex inputs but the signer pub and the offset
 *                        (orig_hash + the two roots; the verifier holds the
 *                        pub, the signature yields the offset),
 *                        the signature, the recipient's masked value and both
 *                        Merkle proofs -- the sidecar that proves the apex.
 * The three travel under one TAG: the shard and sign messages carry `tag`,
 * the apex message's file name, so a reader knows which apex message a part
 * is of before verifying it (the sign message's inputs must hash to that
 * apex, and the shard verifies under that sign message's rsecmk_root by its
 * proof there); the parts need not travel together or in order.  The masked value
 * is [seed][key-share] masked as one unit; the SSS code points (scp + R ocps)
 * DERIVES from the hidden seed (cmGeometry), the seed is bound into every
 * sssMk leaf, and a recipient re-derives and verifies its seed's code points
 * from its one unit (dealer consistency; see cm.h).  No lengths are carried:
 * shard_len is the shard message's own length, the huffman encoding
 * self-describes the original length, and R/T/k/m come from config.  Seat 0
 * is the initiator; recipient p holds leaf p-1.
 *
 * The optional [fault] argument is BYZANTINE-DEALER demo scaffolding (the
 * fraud detection the construction exists to force; exercised by drive.py):
 *   shard -- commit a non-codeword: corrupt shard 0 BEFORE the rsecMk tree
 *   pad   -- commit a flipped PADDING byte: pad one byte more than the
 *            stream needs and flip the last byte of the last data shard
 *            BEFORE the tree; the huffman encoding never reads it, so the
 *            hash passes and only the re-encode against the canonical
 *            ciphertext can name the leaf
 *   share -- commit an off-polynomial share: corrupt share 0 BEFORE the sssMk tree
 *   salt  -- commit every share but the last T off the polynomial: more
 *            T-subsets than R, so the search's candidate list must grow to
 *            the try budget to reach the good pair
 *   geom  -- commit non-derived code points: build the sssMk tree with ocp 0/1 swapped
 *   grind -- commit leaf 0 under another seed, ground until its code points
 *            give the same scp and leaf-0 point: it passes receive, and no
 *            subset mixing it with the dealt seed is interpolated
 *   ct    -- commit a CONSISTENT codeword of the wrong bytes: corrupt the
 *            ciphertext BEFORE the RS encode, so every subset decodes to it
 *   big   -- disperse past CM_CT_MAX (the cap is skipped here): every
 *            receiver refuses the shard part on its own wire
 * Every per-unit gate still passes where the fraud is not local; detection is
 * receive's code points check or assemble's search: shard, share, geom and
 * grind deliver the message from the good parts and name the commitment
 * inconsistent, ct exhausts the search (nothing reproduces the signed hash)
 * and is the FRAUD verdict.
 *   slot  -- sign the apex at CM_SLOT_ROT, the rotation's one-time signing offset
 *   slot2 -- sign the apex at the payload signing offset after CM_SLOT_PAY: a second
 *            payload under the same pub (`drive.py pools`), two apexes that
 *            both verify
 * Not a threshold fraud: receive and assemble gate the signing offset, so the
 * unit is refused at every recipient.
 *   twoslot -- sign the one apex at CM_SLOT_PAY, sent to the first half of
 *            the recipients (rounded up), and at CM_SLOT_PAY + 2, sent to
 *            the rest (`drive.py twoslot`):
 *            one value signed at two offsets.  The apex commits the offset
 *            it was computed at, so the copy at the other offset does not
 *            recompute to it and those recipients refuse the unit at the
 *            apex.
 *   signer <otherCtxPriv> -- compute the apex under the pub of <otherCtxPriv>
 *            and sign it with <currentCtxPriv> (`drive.py signer`): the
 *            signature extracts to the signer's pub, the apex commits another,
 *            and every recipient refuses the unit at the apex recompute.
 *   stream <streamFile> -- disperse the bytes of <streamFile> in place of
 *            the blob's huffman encoding, a stream of another encoder's
 *            choosing (`drive.py byz`).  One that decodes to the blob
 *            passes the hash, and where the canonical stream does not fit
 *            the committed k x shard_len the commitment is inconsistent with
 *            no leaf named; one whose length field names more than
 *            CM_BLOB_MAX fails every try at the probe: FRAUD.
 *
 * usage: distribute <config> <blob> <currentCtxPriv> <outDir> <dispersal> [fault]
 */

#include <stdlib.h>
#include <string.h>
#include "cm.h"

int
main(
  int argc
 ,char *argv[]
){
  cmCfg *cfg;
  sssMkHsh_t sPlug;
  rsecMkHsh_t rPlug;
  FILE *bf;
  FILE *of;
  unsigned char *blob;
  unsigned char *comp;
  unsigned char *ctPad;
  unsigned char *parity;
  unsigned char *shareBuf;
  unsigned char *ivBuf;
  unsigned char *ip;
  unsigned char **ivp;
  const unsigned char **sShare;
  unsigned char **dptr;
  unsigned char **pptr;
  const unsigned char **shardPtr;
  unsigned char *sssw;
  unsigned char *rsecw;
  unsigned char *sproof;
  unsigned char *rproof;
  unsigned char *sig;
  unsigned char *sig2;                /* the twoslot fault: the same apex at a second offset */
  unsigned char *p;
  unsigned char *leafBuf;             /* r sssMk leaves: [seed][share_i] */
  const unsigned char **leafPtr;
  unsigned char orig_hash[CM_SIGN_HSZ];
  unsigned char sssRoot[CM_SSS_HSZ];
  unsigned char rsecRoot[CM_RSEC_HSZ];
  unsigned char apex[CM_SIGN_HSZ];
  unsigned char signerPub[CM_SIGN_HSZ];
  unsigned char apexPub[CM_SIGN_HSZ];  /* the pub the apex commits: the signer's (the signer fault: another's) */
  unsigned char seed[CM_SEED_LEN];    /* hidden seed of the code points for this distribution */
  unsigned char pool[CM_MAXPROC];     /* derived: pool[0] = scp, pool[1..] = ocps */
  unsigned char scp;
  unsigned char *ocp;
  char *pubCtx;                       /* the context whose pub the apex commits: the signer's (the signer fault: another's) */
  char path[1024];
  char apexName[64];                  /* the apex message's file name: the parts' tag */
  unsigned long origLen;
  long ol;
  unsigned long clen;
  unsigned long cap;
  unsigned long sgsz;
  unsigned int process;
  unsigned int r;            /* recipients = N - 1 */
  unsigned int k;            /* RS data shards = T */
  unsigned int m;            /* RS parity shards = R - T */
  unsigned int t;
  unsigned int shardLen;
  unsigned int pfsS;
  unsigned int pfsR;
  unsigned int off;                   /* the signing offset: the apex commits it */
  unsigned int i;
  unsigned int j;
  int fltShard;
  int fltPad;
  int fltShare;
  int fltSalt;
  int fltGeom;
  int fltGrind;
  int fltSlot;
  int fltCt;
  int fltBig;
  int fltStream;
  int rc;

  cfg = 0; bf = of = 0;
  blob = comp = ctPad = parity = shareBuf = ivBuf = ip = leafBuf = 0;
  ivp = dptr = pptr = 0; sShare = shardPtr = leafPtr = 0;
  sssw = rsecw = sproof = rproof = sig = sig2 = 0;
  t = r = 0;
  fltShard = fltPad = fltShare = fltSalt = fltGeom = fltGrind = fltSlot = fltCt = fltBig = fltStream = 0;
  rc = 1;

  if (argc != 6 && argc != 7
   && !(argc == 8 && (!strcmp(argv[6], "signer") || !strcmp(argv[6], "stream")))) {
    fprintf(stderr, "usage: %s <config> <blob> <currentCtxPriv> <outDir> <dispersal> [shard|pad|share|salt|geom|grind|slot|slot2|twoslot|ct|big|stream <streamFile>|signer <otherCtxPriv>]\n", argv[0]);
    return (1);
  }
  process = (unsigned int)atoi(argv[5]);
  if (argc == 7) {                    /* byzantine-dealer demo fault */
    if (!strcmp(argv[6], "shard")) fltShard = 1;
    else if (!strcmp(argv[6], "pad")) fltPad = 1;
    else if (!strcmp(argv[6], "share")) fltShare = 1;
    else if (!strcmp(argv[6], "salt")) fltSalt = 1;
    else if (!strcmp(argv[6], "geom")) fltGeom = 1;
    else if (!strcmp(argv[6], "grind")) fltGrind = 1;
    else if (!strcmp(argv[6], "slot")) fltSlot = 1;
    else if (!strcmp(argv[6], "slot2")) fltSlot = 2;
    else if (!strcmp(argv[6], "twoslot")) fltSlot = 3;
    else if (!strcmp(argv[6], "ct")) fltCt = 1;
    else if (!strcmp(argv[6], "big")) fltBig = 1;
    else {
      fprintf(stderr, "%s: unknown fault %s\n", argv[0], argv[6]);
      return (1);
    }
  }
  pubCtx = argv[3];
  if (argc == 8) {                    /* a fault with its file */
    if (!strcmp(argv[6], "signer"))
      pubCtx = argv[7];
    else
      fltStream = 1;
  }

  if (!(cfg = malloc(sizeof (*cfg))) || cmCfgLoad(argv[1], cfg)) {
    fprintf(stderr, "%s: bad config %s\n", argv[0], argv[1]);
    goto done;
  }
  cmKsPath(argv[1], path);                          /* dispersal's ratcheted mask IKMs */
  if (cmKeystateLoad(path, cfg)) {
    fprintf(stderr, "%s: no keystate %s\n", argv[0], path);
    goto done;
  }
  t = cfg->t;
  r = cfg->n - 1;
  k = t;
  m = r - t;
  /* N >= 3 and 2 <= T <= R are cmCfgLoad's (T = R: no parity, the smallest
   * configuration) */
  /* per-distribution SSS code points: a hidden random seed; the N distinct GF
   * points (scp + R ocp) DERIVE from it, so any recipient re-derives and
   * verifies all the dealt code points from the seed in its own unit */
  arc4random_buf(seed, CM_SEED_LEN);
  cmGeometry(seed, cfg->n, pool);
  scp = pool[0];
  ocp = pool + 1;

  /* read the blob, hash it (orig_hash is the keystream nonce and apex input) */
  if (!(bf = fopen(argv[2], "rb"))) {
    fprintf(stderr, "%s: cannot open blob %s\n", argv[0], argv[2]);
    goto done;
  }
  if (fseek(bf, 0, SEEK_END) || (ol = ftell(bf)) < 0) {
    fprintf(stderr, "%s: cannot size blob %s\n", argv[0], argv[2]);
    goto done;
  }
  origLen = (unsigned long)ol;
  /* the blob is bounded by what an assembler will decode (CM_BLOB_MAX, the
   * application's to size); past it nothing is read or dispersed, and within
   * it the length fits the hash's and the huffman encoding's unsigned int */
  if (origLen > CM_BLOB_MAX) {
    fprintf(stderr, "%s: blob %lu bytes past CM_BLOB_MAX %lu: not dispersed\n"
           ,argv[0], origLen, (unsigned long)CM_BLOB_MAX);
    goto done;
  }
  rewind(bf);
  /* an empty blob is a message: nothing to read, hashed and encoded at length
   * 0 (the huffman encoding of nothing is two bytes) */
  if (origLen && (!(blob = malloc(origLen))
   || fread(blob, 1, origLen, bf) != origLen)) {
    fprintf(stderr, "%s: cannot read blob\n", argv[0]);
    goto done;
  }
  fclose(bf); bf = 0;
  cmHash(blob, (unsigned int)origLen, orig_hash);

  /* huffman compress (self-describing length); retry if the guess is short */
  cap = origLen + 1024;
  if (!(comp = malloc(cap)))
    goto done;
  clen = hufEncode(comp, (hufLen)cap, blob, (hufLen)origLen);
  if (clen > cap) {
    free(comp);
    if (!(comp = malloc(clen)))
      goto done;
    clen = hufEncode(comp, (hufLen)clen, blob, (hufLen)origLen);
  }
  if (fltStream) {                    /* another encoder's stream in place of the canonical one */
    FILE *sf;
    long sl;

    if (!(sf = fopen(argv[7], "rb")) || fseek(sf, 0, SEEK_END) || (sl = ftell(sf)) <= 0
     || (clen = (unsigned long)sl) > cap || fseek(sf, 0, SEEK_SET)
     || fread(comp, 1, clen, sf) != clen) {
      fprintf(stderr, "%s: cannot read a stream of 1 to %lu bytes from %s\n", argv[0], cap, argv[7]);
      if (sf)
        fclose(sf);
      goto done;
    }
    fclose(sf);
  }

  /* dealt randomness: K (= first KEY_LEN of ivBuf) and the SSS pad values */
  if (!(ivBuf = malloc((unsigned long)t * CM_KEY_LEN)))
    goto done;
  arc4random_buf(ivBuf, t * CM_KEY_LEN);

  /* SSS split K into R shares at threshold T */
  if (!(ip = malloc(t)) || !(ivp = malloc((unsigned long)t * sizeof (*ivp)))
   || !(shareBuf = malloc((unsigned long)r * CM_KEY_LEN))
   || !(sShare = malloc((unsigned long)r * sizeof (*sShare))))
    goto done;
  ip[0] = scp;
  for (j = 1; j < t; ) {            /* internal points, distinct, != scp */
    unsigned char q;
    unsigned int e;
    int dup;

    arc4random_buf(&q, 1);
    for (dup = 0, e = 0; e < j; ++e)
      if (ip[e] == q) { dup = 1; break; }
    if (!dup)
      ip[j++] = q;
  }
  for (j = 0; j < t; ++j)
    ivp[j] = ivBuf + (unsigned long)j * CM_KEY_LEN;
  for (i = 0; i < r; ++i)
    sShare[i] = shareBuf + (unsigned long)i * CM_KEY_LEN;
  sss(ip, ocp, ivp, (unsigned char *const *)sShare, t, r, CM_KEY_LEN);
  if (fltShare)                       /* commit an off-polynomial share 0 */
    shareBuf[0] ^= 0x01;
  if (fltSalt)                        /* commit every share but the last T off the polynomial */
    for (i = 0; i + t < r; ++i)
      shareBuf[(unsigned long)i * CM_KEY_LEN] ^= 0x01;

  /* sssMk tree over the R leaves [seed][share_i] -> sssRoot.  The leaf binds
   * the seed, so the signed root commits the derivable code points. */
  cmSssMkPlug(&sPlug);
  pfsS = sssMkPfSz(CM_SSS_H, r);
  if (!(leafBuf = malloc((unsigned long)r * CM_MVAL_LEN))
   || !(leafPtr = malloc((unsigned long)r * sizeof (*leafPtr))))
    goto done;
  for (i = 0; i < r; ++i) {
    memcpy(leafBuf + (unsigned long)i * CM_MVAL_LEN, seed, CM_SEED_LEN);
    memcpy(leafBuf + (unsigned long)i * CM_MVAL_LEN + CM_SEED_LEN
          ,sShare[i], CM_KEY_LEN);
    leafPtr[i] = leafBuf + (unsigned long)i * CM_MVAL_LEN;
  }
  if (fltGrind) {                     /* leaf 0 under a seed of the same scp and leaf-0 point */
    unsigned char g[CM_SEED_LEN];
    unsigned char st[CM_KDF_HSZ];       /* cmGeometry's first block: scp, then the first byte unlike it */
    unsigned char info[2];

    info[0] = CM_DOM_GEO;
    info[1] = 0;
    for (;;) {
      arc4random_buf(g, CM_SEED_LEN);
      CM_KDF(g, CM_SEED_LEN, info, sizeof (info), st, sizeof (st));
      for (j = 1; j < sizeof (st) && st[j] == st[0]; ++j)
        ;
      if (st[0] == scp && j < sizeof (st) && st[j] == ocp[0])
        break;
    }
    memcpy(leafBuf, g, CM_SEED_LEN);
  }
  if (fltGeom) {                      /* commit non-derived code points */
    unsigned char x;

    x = ocp[0]; ocp[0] = ocp[1]; ocp[1] = x;
  }
  if (!(sssw = malloc(sssMkWaSz(CM_SSS_H, r))) || !(sproof = malloc(pfsS)))
    goto done;
  if (!(p = sssMkHash(&sPlug, scp, ocp, leafPtr, CM_MVAL_LEN, r, sssw)))
    goto done;
  memcpy(sssRoot, p, CM_SSS_HSZ);

  /* RS shard the ciphertext: k data shards of shardLen, m parity shards */
  shardLen = (unsigned int)((clen + k - 1) / k);
  if (fltPad)                         /* one byte of padding at least, to flip */
    shardLen = (unsigned int)((clen + 1 + k - 1) / k);
  if ((unsigned long)k * shardLen > CM_CT_MAX && !fltBig) {
    fprintf(stderr, "%s: compressed message %lu bytes pads to %lu, past CM_CT_MAX %lu: not dispersed\n"
           ,argv[0], clen, (unsigned long)k * shardLen, (unsigned long)CM_CT_MAX);
    goto done;
  }
  if (!(ctPad = malloc((unsigned long)k * shardLen))
   || !(dptr = malloc((unsigned long)k * sizeof (*dptr)))
   || !(shardPtr = malloc((unsigned long)r * sizeof (*shardPtr))))
    goto done;
  if (m                               /* T = R: no parity shards (m = 0), nothing to allocate */
   && (!(parity = malloc((unsigned long)m * shardLen))
    || !(pptr = malloc((unsigned long)m * sizeof (*pptr)))))
    goto done;
  /* the thing dispersed: the stream zero-padded to k x shardLen, then the
   * whole of it XOR keystream(K, orig_hash) -- the padding is under the
   * keystream too, so an assembler's XOR over the same length reads it back
   * as zero (the stream self-terminates; the empty message's plaintext is
   * all zero) */
  memcpy(ctPad, comp, clen);
  memset(ctPad + clen, 0, (unsigned long)k * shardLen - clen);
  cmKeystream(ivBuf, CM_KEY_LEN, orig_hash, ctPad, (unsigned int)(k * shardLen));
  for (j = 0; j < k; ++j)
    dptr[j] = ctPad + (unsigned long)j * shardLen;
  for (j = 0; j < m; ++j)
    pptr[j] = parity + (unsigned long)j * shardLen;
  if (fltCt)                          /* commit a consistent codeword of the wrong bytes */
    ctPad[0] ^= 0x01;
  if (rsecEncode((const unsigned char *const *)dptr, pptr, shardLen, k, m))
    goto done;
  for (j = 0; j < k; ++j)
    shardPtr[j] = dptr[j];
  for (j = 0; j < m; ++j)
    shardPtr[k + j] = pptr[j];
  if (fltShard)                       /* commit a non-codeword shard 0 */
    ctPad[0] ^= 0x01;
  if (fltPad)                         /* commit a flipped padding byte: the last of data shard k-1 */
    ctPad[(unsigned long)k * shardLen - 1] ^= 0x01;

  /* rsecMk tree over the R shards -> rsecRoot */
  cmRsecMkPlug(&rPlug);
  pfsR = rsecMkPfSz(CM_RSEC_H, r);
  if (!(rsecw = malloc(rsecMkWaSz(CM_RSEC_H, r))) || !(rproof = malloc(pfsR)))
    goto done;
  if (!(p = rsecMkHash(&rPlug, shardPtr, shardLen, r, rsecw)))
    goto done;
  memcpy(rsecRoot, p, CM_RSEC_HSZ);

  /* the signer's pub and the offset it signs at first: the apex commits
   * both.  Then the apex over them and the two roots, signed with the
   * CURRENT context at that offset, the payload signing offset (signing
   * offset 0 of this context is its rotation's, and every payload verifier
   * refuses a signature there).  The verifier roots trust in the
   * rotation-managed current pub, not signerPub here, and takes the offset
   * from the signature. */
  if (cmMlsPub(pubCtx, apexPub)) {
    fprintf(stderr, "%s: cannot derive the signer pub from %s\n", argv[0], pubCtx);
    goto done;
  }
  off = fltSlot == 1 ? CM_SLOT_ROT : fltSlot == 2 ? CM_SLOT_PAY + 1 : CM_SLOT_PAY;
  cmApex(apexPub, off, orig_hash, rsecRoot, sssRoot, apex);
  if (cmMlsSign(argv[3], off, apex, &sig, &sgsz, signerPub)) {
    fprintf(stderr, "%s: cannot sign apex with current context %s\n", argv[0], argv[3]);
    goto done;
  }
  if (fltSlot == 3                    /* the same apex at a second offset, for the second half of the recipients */
   && cmMlsSign(argv[3], CM_SLOT_PAY + 2, apex, &sig2, &sgsz, signerPub)) {
    fprintf(stderr, "%s: cannot sign apex with current context %s\n", argv[0], argv[3]);
    goto done;
  }

  /* per-recipient distribution: the apex message (identical across the R but
   * for its hmac), the shard message, the sign message */
  for (i = 0; i < r; ++i) {
    unsigned char masked[CM_MVAL_LEN];   /* [seed][share], masked as one unit */

    if (!sssMkProof(&sPlug, r, i, sssw, sproof))
      goto done;
    if (!rsecMkProof(&rPlug, r, i, rsecw, rproof))
      goto done;
    /* the unit IS the leaf data: the hidden seed (the derivation of every code point)
     * plus this recipient's share */
    memcpy(masked, leafPtr[i], CM_MVAL_LEN);
    /* recipient leaf i is seat i+1; the initiator masks with PSK(0,i+1) under the
     * CM_DOM_DIST domain at the payload's step (exchange masks under the same step,
     * domain CM_DOM_EXCH; the step advances after the flow) */
    cmMask(cfg->psk[i + 1], CM_PSK_LEN, apex, CM_DOM_DIST, (unsigned char)i, masked, CM_MVAL_LEN);

    /* each message ends in its own wire-tamper MAC, the mandatory LAST field:
     * static pairwise mac(0,i+1) over [sender][recipient] || the file */
    sprintf(apexName, "00_to_%02u_apex.txt", i + 1);  /* seat p = leaf i + 1 */
    sprintf(path, "%s/wire/dist/%s", argv[4], apexName);
    if (!(of = fopen(path, "w")))
      goto done;
    fprintf(of, "phase: distribute\n");
    cmPutField(of, "apex", apex, CM_SIGN_HSZ);
    fclose(of); of = 0;
    if (cmHmacAppend(path, cfg->mac[i + 1], CM_PSK_LEN, 0, i + 1)) {
      fprintf(stderr, "%s: cannot hmac %s\n", argv[0], path);
      goto done;
    }
    sprintf(path, "%s/wire/dist/00_to_%02u_shard.txt", argv[4], i + 1);
    if (!(of = fopen(path, "w")))
      goto done;
    fprintf(of, "phase: distribute\n");
    fprintf(of, "tag: %s\n", apexName);                 /* the tag: which apex message this part is of */
    cmPutField(of, "shard", shardPtr[i], shardLen);
    fclose(of); of = 0;
    if (cmHmacAppend(path, cfg->mac[i + 1], CM_PSK_LEN, 0, i + 1)) {
      fprintf(stderr, "%s: cannot hmac %s\n", argv[0], path);
      goto done;
    }
    sprintf(path, "%s/wire/dist/00_to_%02u_sign.txt", argv[4], i + 1);
    if (!(of = fopen(path, "w")))
      goto done;
    fprintf(of, "phase: distribute\n");
    fprintf(of, "tag: %s\n", apexName);                 /* the tag */
    cmPutU(of, "process", process);
    cmPutField(of, "orig_hash", orig_hash, CM_SIGN_HSZ);
    cmPutField(of, "sssmk_root", sssRoot, CM_SSS_HSZ);
    cmPutField(of, "rsecmk_root", rsecRoot, CM_RSEC_HSZ);
    cmPutField(of, "mls_sig", sig2 && i >= (r + 1) / 2 ? sig2 : sig, (unsigned int)sgsz);
    cmPutField(of, "share_masked", masked, CM_MVAL_LEN);
    cmPutField(of, "sssmk_proof", sproof, pfsS);
    cmPutField(of, "rsecmk_proof", rproof, pfsR);
    fclose(of); of = 0;
    if (cmHmacAppend(path, cfg->mac[i + 1], CM_PSK_LEN, 0, i + 1)) {
      fprintf(stderr, "%s: cannot hmac %s\n", argv[0], path);
      goto done;
    }
  }

  fprintf(stderr, "%s: N=%u T=%u R=%u k=%u m=%u orig=%lu ct=%lu shard=%u\n"
         ,argv[0], cfg->n, t, r, k, m, origLen, clen, shardLen);
  rc = 0;

 done:
  if (of) fclose(of);
  if (bf) fclose(bf);
  memset(seed, 0, sizeof (seed));
  if (ivBuf) { memset(ivBuf, 0, (unsigned long)t * CM_KEY_LEN); free(ivBuf); }
  if (shareBuf) { memset(shareBuf, 0, (unsigned long)r * CM_KEY_LEN); free(shareBuf); }
  if (leafBuf) { memset(leafBuf, 0, (unsigned long)r * CM_MVAL_LEN); free(leafBuf); }
  if (sssw) free(sssw);
  if (rsecw) free(rsecw);
  if (cfg) memset(cfg, 0, sizeof (*cfg));  /* the dealt key mesh */
  free(cfg); free(blob); free(comp); free(ctPad); free(parity);
  free(ip); free(ivp); free(sShare); free(dptr); free(pptr); free(shardPtr);
  free(leafPtr); free(sproof); free(rproof); free(sig); free(sig2);
  return (rc);
}
