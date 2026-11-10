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
 * cryptoMule receive - a non-initiator seat i accepting its distribution.
 *
 * Trust anchor is the book's current pub -- the identity the rotation chain
 * installed for this dispersal (NOT a fragment-carried pubroot).  Everything else
 * comes from the (untrusted) three dist messages -- 00_to_<p>_apex.txt (the
 * apex alone), _shard.txt (the clear shard alone), _sign.txt (the signed
 * header, the masked value, both proofs) -- and is checked against it:
 *   - FIRST the pairwise wire hmac of each message (static mac PSK, sender 0):
 *     a failure is a WIRE-TAMPER verdict and nothing of that message is
 *     parsed -- on the apex or sign message the whole unit is refused (both
 *     parts verify under the header the sign message carries), on the shard
 *     message the shard part alone (rsecmk_ok no, the shard not kept), the
 *     share part judged on its own, exactly as assemble reads its wire: the
 *     adversary blocks and reorders, and every intact part is progress.  A
 *     part's own fields (the masked value and sssmk_proof; the shard and
 *     rsecmk_proof) malformed cost that part the same way; the unit's
 *     fields malformed refuse the unit.  Every part carries as its TAG the
 *     file name of the apex message it is of (the tag names the message the
 *     reader already holds by path; it is compared, never opened): a sign
 *     message tagged with another is not this apex's sidecar and the unit is
 *     refused; a shard message tagged with another is not this apex's shard
 *     and the shard part is refused.  A sign
 *     message that carries
 *     rsecmk_proof announces a shard and the shard message is then required,
 *     hmac-whole; one that omits it announces none: what to expect is
 *     learned from the sign message validated, never from a path;
 *   - require the sign message's dispersal label to be this seat's book's;
 *   - recompute apex = H(current pub || signing offset || orig_hash ||
 *     rsecmk_root || sssmk_root), the pub the book names as current (a
 *     verifier's one candidate signer), the offset the signature's structure
 *     yields (cmMlsOff; a signature that yields none refuses the unit) and
 *     the rest from the sign message, and require it to BE the apex the apex
 *     message carries: a sign message that does not hash to the apex under
 *     that pub at that offset is not its sidecar, whichever key signed it at
 *     whichever offset.  The equality is arithmetic over the bytes received
 *     and the book, and needs no signature, so it comes first;
 *   - read the signing-offset floor (priv/<p>_floor.txt, the record offsetgate
 *     keeps for this pub; read here, never written) and refuse a signature the
 *     floor has passed -- offset below the high-water (re-injection) or at it
 *     under a different apex (re-authored: a one-time signing offset spent twice);
 *     at the high-water under the same apex it is the same message again, admitted.
 *     The offset is the structure's, the one the apex was recomputed at, so
 *     this too is arithmetic before the signature: a refused copy is never
 *     verified (sig_ok: unchecked);
 *   - verify the MLS signature over THAT apex recovers the SAME current pub
 *     at a PAYLOAD signing offset (the recovered signing offset is not CM_SLOT_ROT, the
 *     rotation's one-time signing offset; a payload signed there is refused).  Both
 *     must hold: the apex commits the identity that signs it and the offset
 *     it is signed at, so a value signed under one of the initiator's keys
 *     does not verify under another, and a value signed at two offsets is
 *     admitted at one of them only -- the offset the floor records is the
 *     value's, whichever copy arrived;
 *   - unmask the [seed][key-share] unit with PSK(init,i), DERIVE the whole
 *     SSS code points from the seed (cmGeometry), and verify the unit's sssMk
 *     proof -- under the derived scp and this leaf's derived ocp -- against
 *     sssmk_root.  The leaf binds the seed, so committed code points that are
 *     not the derivation of the dealt seed fails HERE (dealer consistency,
 *     per-unit half; assemble's re-encode is the threshold half);
 *   - verify the clear shard's rsecMk proof against rsecmk_root, the shard
 *     first refused when it implies a ciphertext past CM_CT_MAX (k x its
 *     length; the same cap assemble applies on its wire).  The record keeps
 *     the bytes it read either way; exchange forwards on the verdict.
 *
 * Persists priv/<p>_recv.txt (seat p = index i + 1): the five verdicts plus the
 * cleartext share, clear shard, proofs, signature, roots, the dispersal label
 * this seat matched to its book and the apex it matched under the book's
 * pub (exchange re-sends that apex and masks under it, a banked dispersal
 * after the book has moved included), all of which exchange/assemble carry
 * on.
 *
 * usage: receive <config> <index> <baseDir>
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
  mlsCtx_t v;
  mlsHsh_t mPlug;
  sssMkHsh_t sPlug;
  rsecMkHsh_t rPlug;
  FILE *of;
  unsigned char *sig;
  unsigned char *sssvf;
  unsigned char *rsecvf;
  unsigned char *sproof;
  unsigned char *rproof;
  unsigned char *shard;
  unsigned char *p;
  unsigned char share[CM_MVAL_LEN];   /* [seed][key-share] after unmasking */
  unsigned char orig_hash[CM_SIGN_HSZ];
  unsigned char sssRoot[CM_SSS_HSZ];
  unsigned char rsecRoot[CM_RSEC_HSZ];
  unsigned char apex[CM_SIGN_HSZ];
  unsigned char carried[CM_SIGN_HSZ];  /* the apex the apex message carries */
  unsigned char pubroot[CM_SIGN_HSZ];
  unsigned char floorPub[CM_SIGN_HSZ];
  unsigned char floorAnc[CM_SIGN_HSZ];
  unsigned char pool[CM_MAXPROC];     /* code points derived from the unit's seed */
  unsigned char scp;
  unsigned char ocpv;                 /* this recipient's derived output point */
  char apexPath[1024];
  char shardPath[1024];
  char signPath[1024];
  char bpath[1024];
  char fpath[1024];
  char kpath[1024];
  char spath[1024];
  char apexName[64];                  /* the apex message's file name: the tag a part must carry */
  char tag[64];                       /* a part's own tag: which apex message it is of */
  unsigned long sgsz;
  unsigned long hw;
  unsigned long plProcess;            /* the payload's dispersal label, kept in the record for exchange to forward */
  unsigned int idx;
  unsigned int r;
  unsigned int n;
  unsigned int shardLen;
  unsigned int pfsS;
  unsigned int pfsR;
  unsigned int off;
  int sl;
  int hmacOk;
  int shardWire;                      /* the shard message's hmac held: the shard part may be read */
  int shareOk;                        /* the share part's fields are well formed */
  int shardOk;                        /* the shard part's fields are well formed */
  int sigOk;
  int offOk;
  int sssOk;
  int rsecOk;
  int rc;

  cfg = 0; of = 0;
  sig = sssvf = rsecvf = sproof = rproof = shard = 0;
  hmacOk = sigOk = offOk = sssOk = rsecOk = 0;
  rc = 1;

  if (argc != 4) {
    fprintf(stderr, "usage: %s <config> <index> <baseDir>\n", argv[0]);
    return (1);
  }
  idx = (unsigned int)atoi(argv[2]);

  if (!(cfg = malloc(sizeof (*cfg))) || cmCfgLoad(argv[1], cfg)) {
    fprintf(stderr, "%s: bad config %s\n", argv[0], argv[1]);
    goto done;
  }
  n = cfg->n;
  if (idx >= n - 1) {
    fprintf(stderr, "%s: index %u out of range (R=%u)\n", argv[0], idx, n - 1);
    goto done;
  }
  sprintf(bpath, "%s/priv/%02u_book.txt", argv[3], idx + 1);
  sprintf(fpath, "%s/priv/%02u_floor.txt", argv[3], idx + 1);
  cmKsPath(argv[1], kpath);
  sprintf(apexName, "00_to_%02u_apex.txt", idx + 1);
  sprintf(apexPath, "%s/wire/dist/%s", argv[3], apexName);
  sprintf(shardPath, "%s/wire/dist/00_to_%02u_shard.txt", argv[3], idx + 1);
  sprintf(signPath, "%s/wire/dist/00_to_%02u_sign.txt", argv[3], idx + 1);
  sprintf(spath, "%s/priv/%02u_recv.txt", argv[3], idx + 1);
  if (cmKeystateLoad(kpath, cfg)) {            /* dispersal's ratcheted PSK IKM */
    fprintf(stderr, "%s: no keystate %s\n", argv[0], kpath);
    goto done;
  }

  /* wire-tamper gate FIRST: the pairwise hmac (static mac(self,0)) must cover
   * each of the three messages before any field is trusted.  A failure is a
   * distinct verdict -- the wire was tampered, not the sender at fault. */
  if (!cmHmacCheck(apexPath, cfg->mac[0], CM_PSK_LEN, 0, idx + 1)) {
    fprintf(stderr, "%s: seat %u  hmac=BAD on apex (wire tamper)\n", argv[0], idx + 1);
    goto refuse;
  }
  if (!cmHmacCheck(signPath, cfg->mac[0], CM_PSK_LEN, 0, idx + 1)) {
    fprintf(stderr, "%s: seat %u  hmac=BAD on sign (wire tamper)\n", argv[0], idx + 1);
    goto refuse;
  }
  hmacOk = 1;
  shardWire = cmHmacCheck(shardPath, cfg->mac[0], CM_PSK_LEN, 0, idx + 1);

  /* r derives from config; shard_len is the shard message's own length */
  r = n - 1;

  pfsS = sssMkPfSz(CM_SSS_H, r);
  pfsR = rsecMkPfSz(CM_RSEC_H, r);
  cmMlsPlug(&mPlug);
  v.h = &mPlug;
  v.s = CM_MLS_S;
  v.r = 0;
  sgsz = mlsSgSz(&v);

  /* the apex message and the signed header (process, orig_hash, the two
   * roots, the signature): a malformed field refuses the unit.  A part's own
   * fields are read with the part, below, and cost that part alone. */
  if (!(sig = malloc(sgsz)) || !(sproof = malloc(pfsS))
   || !(rproof = malloc(pfsR)) || !(shard = malloc(CM_SHARD_MAX)))
    goto done;
  if (cmGetField(apexPath, "apex", carried, CM_SIGN_HSZ) != CM_SIGN_HSZ) goto badfile;
  if (cmGetStr(signPath, "tag", tag, sizeof (tag)) < 0) goto badfile;
  if (strcmp(tag, apexName)) {                           /* the sign message is of another apex message */
    fprintf(stderr, "%s: seat %u  the sign message is not this apex message's\n", argv[0], idx + 1);
    goto refuse;
  }
  if (cmGetU(signPath, "process", &plProcess)) goto badfile;
  if (cmGetField(signPath, "orig_hash", orig_hash, CM_SIGN_HSZ) != CM_SIGN_HSZ) goto badfile;
  if (cmGetField(signPath, "sssmk_root", sssRoot, CM_SSS_HSZ) != CM_SSS_HSZ) goto badfile;
  if (cmGetField(signPath, "rsecmk_root", rsecRoot, CM_RSEC_HSZ) != CM_RSEC_HSZ) goto badfile;
  if (cmGetField(signPath, "mls_sig", sig, (unsigned int)sgsz) != (int)sgsz) goto badfile;
  /* the dispersal label: the book's (assemble requires the same of every
   * exchange fragment) */
  {
    unsigned long bkProcess;

    if (cmGetU(bpath, "process", &bkProcess))
      goto badfile;
    if (plProcess != bkProcess) {
      fprintf(stderr, "%s: book at dispersal %lu, payload for dispersal %lu\n"
             ,argv[0], bkProcess, plProcess);
      goto refuse;
    }
  }
  if (cmGetField(bpath, "current", pubroot, CM_SIGN_HSZ) != CM_SIGN_HSZ) goto badfile;

  /* recompute the apex under the rotation-managed current pub (this
   * seat's book) -- the identity the rotation chain installed -- and the
   * offset the signature yields, from the sign message's inputs; it must be
   * the apex the apex message carries, else the sign message is not its
   * sidecar; then verify the signature over it extracts to that same pub at
   * a payload signing offset (CM_SLOT_ROT is the rotation's alone) */
  if (!cmMlsOff(sig, sgsz, &off)) {
    fprintf(stderr, "%s: seat %u  apex=BAD (the signature yields no signing offset)\n", argv[0], idx + 1);
    goto refuse;
  }
  cmApex(pubroot, off, orig_hash, rsecRoot, sssRoot, apex);
  if (memcmp(carried, apex, CM_SIGN_HSZ)) {
    fprintf(stderr, "%s: seat %u  apex=BAD (sign message does not hash to the apex)\n", argv[0], idx + 1);
    goto refuse;
  }

  /* the signing-offset floor for this pub (offsetgate's record; no floor, or
   * a floor for another pub, admits), at the offset the signature's
   * structure yields: refuse a re-injected or re-authored signature, admit
   * the same one again.  Arithmetic over the bytes received and this seat's
   * record, so it comes before the signature is paid for; the offset it
   * reads is the one the apex just recomputed at, and the signature then
   * verifies at that same offset */
  offOk = 1;
  if (cmGetField(fpath, "pub", floorPub, CM_SIGN_HSZ) == CM_SIGN_HSZ
   && !memcmp(floorPub, pubroot, CM_SIGN_HSZ)
   && !cmGetU(fpath, "highwater", &hw)
   && cmGetField(fpath, "anchor", floorAnc, CM_SIGN_HSZ) == CM_SIGN_HSZ)
    offOk = off > hw || (off == hw && !memcmp(floorAnc, apex, CM_SIGN_HSZ));
  sigOk = offOk && off != CM_SLOT_ROT && cmMlsVerify(pubroot, apex, sig, sgsz);

  /* the share part: its own fields (a malformed one costs the part, never
   * the unit; assemble reads its wire the same way), then unmask the value,
   * DERIVE the hidden code points from its seed, and authenticate the whole
   * unit (leaf = [seed][share]) under the derived points.  the distribution
   * came from the initiator (seat 0), so its key is PSK(self,0) at the
   * payload's step (the chain advances after the whole flow, never in a
   * phase program). */
  cmSssMkPlug(&sPlug);
  if (!(sssvf = malloc(sssMkVfSz(CM_SSS_H))))
    goto done;
  if ((shareOk = cmGetField(signPath, "share_masked", share, CM_MVAL_LEN) == CM_MVAL_LEN
              && cmGetField(signPath, "sssmk_proof", sproof, pfsS) == (int)pfsS)) {
    cmMask(cfg->psk[0], CM_PSK_LEN, apex, CM_DOM_DIST, (unsigned char)idx, share, CM_MVAL_LEN);
    cmGeometry(share, n, pool);
    scp = pool[0];
    ocpv = pool[1 + idx];
    if ((p = sssMkExtract(&sPlug, scp, ocpv, share, CM_MVAL_LEN
                         ,idx, r, sproof, sssvf)) != 0)
      sssOk = !memcmp(p, sssRoot, CM_SSS_HSZ);
  }

  /* the shard part: expected when the sign message carries rsecmk_proof,
   * then required of the shard message, hmac-whole and well formed (absent,
   * tampered or malformed is not kept), then the clear shard within the cap,
   * then under the root at its own length */
  cmRsecMkPlug(&rPlug);
  if (!(rsecvf = malloc(rsecMkVfSz(CM_RSEC_H))))
    goto done;
  shardLen = 0;
  shardOk = cmGetField(signPath, "rsecmk_proof", rproof, pfsR) == (int)pfsR;
  if (shardOk && !shardWire)
    fprintf(stderr, "%s: seat %u  shard announced, its message absent or tampered: the shard part refused, the share judged\n", argv[0], idx + 1);
  if ((shardOk = shardOk && shardWire
              && cmGetStr(shardPath, "tag", tag, sizeof (tag)) >= 0
              && !strcmp(tag, apexName)                      /* this apex message's shard, by its tag */
              && (sl = cmGetField(shardPath, "shard", shard, CM_SHARD_MAX)) > 0)) {
    shardLen = (unsigned int)sl;
    if ((unsigned long)cfg->t * shardLen > CM_CT_MAX)
      fprintf(stderr, "%s: seat %u  shard %u x T=%u is past CM_CT_MAX %lu: refused\n"
             ,argv[0], idx + 1, shardLen, cfg->t, (unsigned long)CM_CT_MAX);
    else if ((p = rsecMkExtract(&rPlug, shard, shardLen, idx, r, rproof, rsecvf)) != 0)
      rsecOk = !memcmp(p, rsecRoot, CM_RSEC_HSZ);
  }

  /* persist this seat's internal state */
  if (!(of = fopen(spath, "w")))
    goto done;
  fprintf(of, "phase: receive\n");
  cmPutU(of, "system", idx + 1);
  cmPutU(of, "process", plProcess);
  fprintf(of, "hmac_ok: yes\n");
  fprintf(of, "sig_ok: %s\n", sigOk ? "yes" : offOk ? "no" : "unchecked");
  fprintf(of, "offset_ok: %s\n", offOk ? "yes" : "no");
  fprintf(of, "sssmk_ok: %s\n", sssOk ? "yes" : "no");
  fprintf(of, "rsecmk_ok: %s\n", rsecOk ? "yes" : "no");
  cmPutField(of, "orig_hash", orig_hash, CM_SIGN_HSZ);
  cmPutField(of, "sssmk_root", sssRoot, CM_SSS_HSZ);
  cmPutField(of, "rsecmk_root", rsecRoot, CM_RSEC_HSZ);
  cmPutField(of, "mls_sig", sig, (unsigned int)sgsz);
  cmPutField(of, "apex", apex, CM_SIGN_HSZ);
  if (shareOk) {
    cmPutField(of, "share_clear", share, CM_MVAL_LEN);
    cmPutField(of, "sssmk_proof", sproof, pfsS);
  }
  if (shardOk) {
    cmPutField(of, "shard", shard, shardLen);
    cmPutField(of, "rsecmk_proof", rproof, pfsR);
  }
  fclose(of); of = 0;

  fprintf(stderr, "%s: seat %u  sig=%s offset=%s sss=%s rsec=%s\n", argv[0], idx + 1
         ,sigOk ? "ok" : offOk ? "BAD" : "unchecked", offOk ? "ok" : "BAD", sssOk ? "ok" : "BAD", rsecOk ? "ok" : "BAD");
  rc = (sigOk && offOk && sssOk && rsecOk) ? 0 : 1;
  goto done;

 badfile:
  fprintf(stderr, "%s: malformed/missing field in %s/wire/dist/00_to_%02u_{apex,shard,sign}.txt or %s\n"
         ,argv[0], argv[3], idx + 1, bpath);
 refuse:
  /* a refusal REPLACES the record: whatever this seat validated for an
   * earlier dispersal must not be what exchange forwards for this one */
  if ((of = fopen(spath, "w"))) {
    fprintf(of, "phase: receive\n");
    cmPutU(of, "system", idx + 1);
    fprintf(of, "hmac_ok: %s\n", hmacOk ? "yes" : "no");
    fprintf(of, "sig_ok: no\noffset_ok: no\nsssmk_ok: no\nrsecmk_ok: no\n");
    fclose(of); of = 0;
  }
 done:
  if (of) fclose(of);
  memset(share, 0, sizeof (share));
  if (cfg) memset(cfg, 0, sizeof (*cfg));  /* the dealt key mesh */
  free(cfg); free(sig); free(sssvf); free(rsecvf);
  free(sproof); free(rproof); free(shard);
  return (rc);
}
