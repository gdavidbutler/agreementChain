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
 * cryptoMule exchange - seat i re-sends its held fragment, pairwise.
 *
 * Continuation of the initiator's distribution: NO new signature.  The apex,
 * the initiator's MLS signature and the payload's dispersal label ride
 * unchanged (the label as receive matched it to this seat's book, so
 * assemble can make the same match on its own wire; the apex as receive
 * matched it under the book's pub, which commits the signer's identity and
 * signing offset and is not recomputed here: a banked dispersal is re-sent
 * after the book has moved past its signer); each fragment still
 * self-authenticates via its Merkle proof against the signed apex.  What
 * changes is the mask on the key-share: distribution masked with PSK(init,i);
 * exchange uses the pairwise key with the recipient -- PSK(sender,j), keyed by the
 * sender's own leaf -- so recipient j derives the one mask to read this sender's
 * share, while the lurker (no pairwise key) cannot.  Distribute and exchange are
 * separated by the mask DOMAIN (CM_DOM_EXCH vs CM_DOM_DIST) and by nothing else:
 * the keystate this program loads is the SAME step distribute masked under (the
 * single per-payload ratchet is taken after the whole flow, and the next
 * payload's distribute is the first thing masked under the new step).  The
 * clear ciphertext shard rides as the sidecar.
 *
 * A seat forwards only what it validated in receive, and the share and the
 * shard are validated as two PARTS: a holder whose own copy of one part has
 * rotted (receive's sssmk_ok or rsecmk_ok at no, the other verdicts at yes)
 * still forwards the other.  The apex and sign messages go whenever the
 * signature validated (hmac, sig and offset at yes), a part or none: the
 * sign message carries the signed header, and a recipient the initiator
 * never reached must still get the message hash it signed, parts or no
 * parts.  The shard message goes only on rsecmk_ok
 * and the re-masked value rides in the sign message only on sssmk_ok -- a
 * part the holder did not validate is omitted, never zeroed.  A per-recipient
 * masked share is produced (one pairwise mask each) and written to each of
 * the N-2 recipients as the same three DIRECTED messages distribute sends --
 * <i>_to_<j>_apex.txt (the apex alone, unchanged), _shard.txt (the clear
 * shard alone), _sign.txt (the initiator's signed header, the re-masked value
 * and both proofs), the shard and sign messages tagged with the apex
 * message's name -- field for field under distribute's names, each ending
 * in that pair's wire hmac.  The sender id (the path and the hmac fold) and
 * the share's mask (the pairwise key, the EXCH domain, the sender's leaf) are
 * the only differences, and assemble reads a leg as receive reads a
 * distribution.  There is no broadcast; each PAIR is owed exactly two
 * properties: confidentiality and integrity under that pair's keys.
 *
 * <index> is the 0-based recipient (its Merkle/SSS leaf); seat id = index+1.
 *
 * RESENDING A BANKED DISTRIBUTE.  Given <dispersal> <anchorLog> this forwards the
 * fragment banked for THAT dispersal (priv/<p>_recv_<kk>.txt) instead of the live
 * one, with the SSS value masked off the RETENTION FLOOR chain -- load the floor
 * base and walk it forward (the same walk ./catchup runs on a stale chain, and
 * ./assemble runs on the receiving side).  It is NOT a second kind of message and
 * has no carrier of its own: same program, same wire/exch/ path, and the bytes it
 * produces are identical to the leg it replaces.  A resend is a resend.
 *
 * The forward walk is what makes it possible at all: the mask chain is
 * forward-only and wiped the step that dispersal was masked under, so without a
 * base kept at the floor there is nothing left to re-mask with.  Below the floor
 * the answer is no, and that refusal is ./release's doing.
 *
 * usage: exchange <config> <index> <baseDir> [<dispersal> <anchorLog>]
 */

#include <stdlib.h>
#include <string.h>
#include "cm.h"

static int
okField(
  const char *path
 ,const char *name
){
  FILE *f;
  char line[256];
  unsigned int nl;
  int ok;

  if (!(f = fopen(path, "r")))
    return (0);
  ok = 0;
  nl = strlen(name);
  while (fgets(line, sizeof (line), f))
    if (!strncmp(line, name, nl) && line[nl] == ':') {
      ok = (strstr(line, "yes") != 0);
      break;
    }
  fclose(f);
  return (ok);
}

int
main(
  int argc
 ,char *argv[]
){
  cmCfg *cfg;
  mlsCtx_t v;
  mlsHsh_t mPlug;
  FILE *of;
  unsigned char *sig;
  unsigned char *sproof;
  unsigned char *rproof;
  unsigned char *shard;
  unsigned char share[CM_MVAL_LEN];   /* [seed][share]: opaque, just re-masked */
  unsigned char masked[CM_MVAL_LEN];
  unsigned char nxt[CM_PSK_LEN];      /* resend: the floor walked forward */
  unsigned char anchor[CM_SIGN_HSZ];
  unsigned char orig_hash[CM_SIGN_HSZ];
  unsigned char sssRoot[CM_SSS_HSZ];
  unsigned char rsecRoot[CM_RSEC_HSZ];
  unsigned char apex[CM_SIGN_HSZ];
  char spath[1024];
  char kpath[1024];
  char opath[1024];
  char apexName[64];                  /* the apex message's file name: the parts' tag */
  char name[sizeof ("anchor") + 3 * sizeof (unsigned long)];
  unsigned long sgsz;
  unsigned long want;                 /* the dispersal sent: the current step, or the banked one */
  unsigned long proc;                 /* the dispersal label receive matched to the book, forwarded as received */
  unsigned long floorProc;
  int sl;
  unsigned int idx;
  unsigned int r;
  unsigned int n;
  unsigned int shardLen;
  unsigned int pfsS;
  unsigned int pfsR;
  unsigned int j;
  int sOk;                            /* the share part validated at receive */
  int rOk;                            /* the shard part validated at receive */
  int rc;

  cfg = 0; of = 0;
  sig = sproof = rproof = shard = 0;
  rc = 1;

  if (argc != 4 && argc != 6) {
    fprintf(stderr, "usage: %s <config> <index> <baseDir> [<dispersal> <anchorLog>]\n"
           ,argv[0]);
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
  cmKsPath(argv[1], kpath);
  if (argc == 4) {
    sprintf(spath, "%s/priv/%02u_recv.txt", argv[3], idx + 1);
    if (cmKeystateLoad(kpath, cfg)            /* dispersal's ratcheted pairwise IKMs */
     || cmGetU(kpath, "process", &want)) {
      fprintf(stderr, "%s: no keystate %s\n", argv[0], kpath);
      goto done;
    }
  } else {
    /* resend: the banked fragment, masked off the floor chain walked forward */
    want = strtoul(argv[4], 0, 10);
    sprintf(spath, "%s/priv/%02u_recv_%02lu.txt", argv[3], idx + 1, want);
    if (cmFloorLoad(kpath, cfg, &floorProc)) {
      fprintf(stderr, "%s: no floor in %s (nothing retained)\n", argv[0], kpath);
      goto done;
    }
    if (want < floorProc) {
      fprintf(stderr, "%s: cannot resend dispersal %lu: below the retention floor"
                      " %lu (released -- the base is gone)\n"
             ,argv[0], want, floorProc);
      goto done;
    }
    for (; floorProc < want; ++floorProc) {
      unsigned int q;

      sprintf(name, "anchor%02lu", floorProc);
      if (cmGetField(argv[5], name, anchor, CM_SIGN_HSZ) != CM_SIGN_HSZ) {
        fprintf(stderr, "%s: no %s in %s\n", argv[0], name, argv[5]);
        goto done;
      }
      for (q = 0; q < n; ++q)
        if (cfg->pskHave[q]) {
          cmRatchet(cfg->psk[q], CM_PSK_LEN, anchor, nxt, CM_PSK_LEN);
          memcpy(cfg->psk[q], nxt, CM_PSK_LEN);
        }
    }
    memset(nxt, 0, sizeof (nxt));
  }

  sOk = okField(spath, "sssmk_ok");
  rOk = okField(spath, "rsecmk_ok");
  if (!(okField(spath, "hmac_ok") && okField(spath, "sig_ok") && okField(spath, "offset_ok"))) {
    fprintf(stderr, "%s: seat %u did not validate; nothing to forward\n", argv[0], idx);
    for (j = 0; j + 1 < n; ++j)       /* and no earlier dispersal's legs stand in: on the disk-as-wire the file is the message */
      if (j != idx) {
        sprintf(opath, "%s/wire/exch/%02u_to_%02u_apex.txt", argv[3], idx + 1, j + 1);
        remove(opath);
        sprintf(opath, "%s/wire/exch/%02u_to_%02u_shard.txt", argv[3], idx + 1, j + 1);
        remove(opath);
        sprintf(opath, "%s/wire/exch/%02u_to_%02u_sign.txt", argv[3], idx + 1, j + 1);
        remove(opath);
      }
    goto done;
  }

  /* r derives from config; shard_len is the shard message's own length */
  r = n - 1;
  pfsS = sssMkPfSz(CM_SSS_H, r);
  pfsR = rsecMkPfSz(CM_RSEC_H, r);
  cmMlsPlug(&mPlug);
  v.h = &mPlug;
  v.s = CM_MLS_S;
  v.r = 0;
  sgsz = mlsSgSz(&v);

  if (!(sig = malloc(sgsz)) || !(sproof = malloc(pfsS))
   || !(rproof = malloc(pfsR)) || !(shard = malloc(CM_SHARD_MAX)))
    goto done;
  if (cmGetU(spath, "process", &proc)) goto badfile;
  if (cmGetField(spath, "orig_hash", orig_hash, CM_SIGN_HSZ) != CM_SIGN_HSZ) goto badfile;
  if (cmGetField(spath, "sssmk_root", sssRoot, CM_SSS_HSZ) != CM_SSS_HSZ) goto badfile;
  if (cmGetField(spath, "rsecmk_root", rsecRoot, CM_RSEC_HSZ) != CM_RSEC_HSZ) goto badfile;
  if (cmGetField(spath, "mls_sig", sig, (unsigned int)sgsz) != (int)sgsz) goto badfile;
  if (cmGetField(spath, "apex", apex, CM_SIGN_HSZ) != CM_SIGN_HSZ) goto badfile;   /* the apex receive matched (the mask domain) */
  if (sOk && cmGetField(spath, "share_clear", share, CM_MVAL_LEN) != CM_MVAL_LEN) goto badfile;
  if (sOk && cmGetField(spath, "sssmk_proof", sproof, pfsS) != (int)pfsS) goto badfile;
  shardLen = 0;
  if (rOk) {
    if ((sl = cmGetField(spath, "shard", shard, CM_SHARD_MAX)) <= 0) goto badfile;
    shardLen = (unsigned int)sl;
  }
  if (rOk && cmGetField(spath, "rsecmk_proof", rproof, pfsR) != (int)pfsR) goto badfile;

  /* each exch fragment is self-authenticating: it carries the initiator's
   * signed header (orig_hash + roots -> apex under the initiator's pub, which
   * the recipient's book holds, and the offset mls_sig yields, and mls_sig), so any
   * recipient -- even one the initiator never sent a distribution to -- can
   * validate it independently and count it toward threshold. */
  for (j = 0; j < r; ++j) {
    if (j == idx)                 /* exclude self; initiator is not in 0..R-1 */
      continue;
    /* recipient leaf j is seat j+1; mask with the pairwise PSK(self,j+1), keyed by
     * this sender's own leaf so the recipient derives the one mask to read our share.
     * the keystate is the step distribute masked under (the chain advances after the
     * flow, never in a phase program); the CM_DOM_EXCH domain is what separates the
     * exchange mask from the distribute mask. */
    if (sOk) {
      memcpy(masked, share, CM_MVAL_LEN);
      cmMask(cfg->psk[j + 1], CM_PSK_LEN, apex, CM_DOM_EXCH, (unsigned char)idx, masked, CM_MVAL_LEN);
    }
    /* each message ends in its own wire-tamper MAC, the mandatory LAST field:
     * static pairwise mac(self,j+1) */
    sprintf(apexName, "%02u_to_%02u_apex.txt", idx + 1, j + 1);
    sprintf(opath, "%s/wire/exch/%s", argv[3], apexName);
    if (!(of = fopen(opath, "w")))
      goto done;
    fprintf(of, "phase: exchange\n");
    cmPutField(of, "apex", apex, CM_SIGN_HSZ);
    fclose(of); of = 0;
    if (cmHmacAppend(opath, cfg->mac[j + 1], CM_PSK_LEN, idx + 1, j + 1)) {
      fprintf(stderr, "%s: cannot hmac %s\n", argv[0], opath);
      goto done;
    }
    sprintf(opath, "%s/wire/exch/%02u_to_%02u_shard.txt", argv[3], idx + 1, j + 1);
    if (!rOk)                         /* not sent: on the disk-as-wire, not there */
      remove(opath);
    else {                            /* the shard part, only when validated */
      if (!(of = fopen(opath, "w")))
        goto done;
      fprintf(of, "phase: exchange\n");
      fprintf(of, "tag: %s\n", apexName);               /* the tag */
      cmPutField(of, "shard", shard, shardLen);
      fclose(of); of = 0;
      if (cmHmacAppend(opath, cfg->mac[j + 1], CM_PSK_LEN, idx + 1, j + 1)) {
        fprintf(stderr, "%s: cannot hmac %s\n", argv[0], opath);
        goto done;
      }
    }
    sprintf(opath, "%s/wire/exch/%02u_to_%02u_sign.txt", argv[3], idx + 1, j + 1);
    if (!(of = fopen(opath, "w")))
      goto done;
    fprintf(of, "phase: exchange\n");
    fprintf(of, "tag: %s\n", apexName);                 /* the tag */
    cmPutU(of, "process", proc);
    cmPutField(of, "orig_hash", orig_hash, CM_SIGN_HSZ);
    cmPutField(of, "sssmk_root", sssRoot, CM_SSS_HSZ);
    cmPutField(of, "rsecmk_root", rsecRoot, CM_RSEC_HSZ);
    cmPutField(of, "mls_sig", sig, (unsigned int)sgsz);
    if (sOk) {                        /* the share part, only when validated */
      cmPutField(of, "share_masked", masked, CM_MVAL_LEN);
      cmPutField(of, "sssmk_proof", sproof, pfsS);
    }
    if (rOk)
      cmPutField(of, "rsecmk_proof", rproof, pfsR);
    fclose(of); of = 0;
    if (cmHmacAppend(opath, cfg->mac[j + 1], CM_PSK_LEN, idx + 1, j + 1)) {
      fprintf(stderr, "%s: cannot hmac %s\n", argv[0], opath);
      goto done;
    }
  }

  if (argc == 4)
    fprintf(stderr, "%s: seat %u sent dispersal %lu to %u recipients, pairwise (%s%s%s)\n"
           ,argv[0], idx + 1, want, r - 1, sOk ? "masked share" : "", rOk ? (sOk ? ", clear shard" : "clear shard") : ""
           ,sOk || rOk ? "" : "the signed header alone");
  else
    fprintf(stderr, "%s: seat %u RESENT banked dispersal %lu to %u recipients"
                    " (mask off the floor chain)\n", argv[0], idx + 1, want, r - 1);
  rc = 0;
  goto done;

 badfile:
  fprintf(stderr, "%s: malformed/missing field in %s\n", argv[0], spath);
 done:
  if (of) fclose(of);
  memset(share, 0, sizeof (share));
  if (cfg) memset(cfg, 0, sizeof (*cfg));  /* the dealt key mesh */
  free(cfg); free(sig); free(sproof); free(rproof); free(shard);
  return (rc);
}
