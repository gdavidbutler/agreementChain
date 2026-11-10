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
 * cryptoMule offsetgate - a recipient's per-initiator signing-offset FLOOR,
 * the re-injection defense.  Gate the directed run message's pairwise wire
 * hmac FIRST (static mac(self,0); a failure is a wire-tamper verdict and
 * nothing is parsed), verify the run signature against the recipient's book
 * current pub, read its offset via mlsEgOf, and decide against the high-water
 * already recorded for that identity.  A signature from an identity other than
 * the floor's (pub mismatch) resets the high-water -- a fresh root's offsets
 * restart at 0, admitted by threshold elsewhere.
 *
 * THREE OUTCOMES AT THE HIGH-WATER, not two.  A monotone-only floor would be
 * wrong whenever the same signed bytes are presented more than once: the
 * second copy is the same message, and rejecting it rejects an honest one.
 * So the floor records the ACCEPTED APEX (its `anchor` field) beside the high-water and
 * splits the equal case by what was signed:
 *   offset >  high-water                 ACCEPT, raise the high-water
 *   offset == high-water, same anchor    RETRY -- accepted, floor unchanged
 *   offset == high-water, other anchor   REJECT: a re-authored duplicate
 *   offset <  high-water                 REJECT: re-injection
 * The equal-and-different case is not merely a policy violation, it is a
 * DETECTED KEY COMPROMISE: MLS signing offsets are one-time, so two distinct apexes at
 * one offset leak the signing offset's private material.  Re-presentation must therefore
 * be byte-identical to the first authored form, and this gate is what makes a
 * re-authored one detectably distinct rather than silently admitted.
 *
 * The anchor is what the floor compares because the anchor IS the authored
 * value (for a payload it is the apex, which commits the whole distribution
 * and the offset it is signed at, so every seat that admits one apex records
 * one offset for it);
 * comparing the signature bytes would decide the same question at 2^s times
 * the storage.
 *
 * Book, floor, and run message are per seat (there is no broadcast; see
 * offsetrun.c): priv/<p>_book.txt, priv/<p>_floor.txt, wire/run_<slot>_to_<p>.txt.
 *
 * usage: offsetgate <config> <offset> <index> <baseDir>
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
  mlsHsh_t plug;
  unsigned char current[CM_SIGN_HSZ];
  unsigned char floorPub[CM_SIGN_HSZ];
  unsigned char floorAnc[CM_SIGN_HSZ];
  unsigned char anchor[CM_SIGN_HSZ];
  unsigned char *sig;
  FILE *of;
  char bpath[1024];
  char rpath[1024];
  char fpath[1024];
  unsigned long sgsz;
  unsigned long hw;
  unsigned int slot;
  unsigned int idx;
  unsigned int off;
  int haveFloor;
  int rc;

  cfg = 0;
  sig = 0;
  hw = 0;
  rc = 1;
  if (argc != 5) {
    fprintf(stderr, "usage: %s <config> <offset> <index> <baseDir>\n", argv[0]);
    return (1);
  }
  slot = (unsigned int)atoi(argv[2]);
  idx = (unsigned int)atoi(argv[3]);

  if (!(cfg = malloc(sizeof (*cfg))) || cmCfgLoad(argv[1], cfg)) {
    fprintf(stderr, "%s: bad config %s\n", argv[0], argv[1]);
    goto done;
  }
  if (idx >= cfg->n - 1) {
    fprintf(stderr, "%s: index %u out of range (R=%u)\n", argv[0], idx, cfg->n - 1);
    goto done;
  }
  sprintf(bpath, "%s/priv/%02u_book.txt", argv[4], idx + 1);
  sprintf(rpath, "%s/wire/run_%02u_to_%02u.txt", argv[4], slot, idx + 1);
  sprintf(fpath, "%s/priv/%02u_floor.txt", argv[4], idx + 1);

  /* wire-tamper gate FIRST: nothing in the message is trusted until the
   * pairwise hmac passes */
  if (!cmHmacCheck(rpath, cfg->mac[0], CM_PSK_LEN, 0, idx + 1)) {
    fprintf(stderr, "%s: seat %u signing offset %u REJECT: hmac (wire tamper)\n"
           ,argv[0], idx + 1, slot);
    goto done;
  }

  if (cmGetField(bpath, "current", current, CM_SIGN_HSZ) != CM_SIGN_HSZ) {
    fprintf(stderr, "%s: no book current at %s\n", argv[0], bpath);
    goto done;
  }
  if (cmGetField(rpath, "anchor", anchor, CM_SIGN_HSZ) != CM_SIGN_HSZ) {
    fprintf(stderr, "%s: no anchor at %s\n", argv[0], rpath);
    goto done;
  }

  cmMlsPlug(&plug);
  v.h = &plug;
  v.s = CM_MLS_S;
  v.r = 0;
  sgsz = mlsSgSz(&v);
  if (!(sig = malloc(sgsz)))
    goto done;
  if (cmGetField(rpath, "mls_sig", sig, (unsigned int)sgsz) != (int)sgsz) {
    fprintf(stderr, "%s: malformed signature at %s\n", argv[0], rpath);
    goto done;
  }

  /* the floor first, at the offset the signature's structure yields: the
   * refusals are arithmetic over the bytes received and this seat's record,
   * so a refused copy is never verified; what is admitted (RETRY or ACCEPT)
   * is admitted only past the signature, over the bytes that offset came
   * from */
  if (!cmMlsOff(sig, sgsz, &off)) {
    fprintf(stderr, "%s: seat %u signing offset %u REJECT: the signature yields no signing offset\n"
           ,argv[0], idx + 1, slot);
    goto done;
  }
  haveFloor = cmGetField(fpath, "pub", floorPub, CM_SIGN_HSZ) == CM_SIGN_HSZ
           && cmGetU(fpath, "highwater", &hw) == 0
           && cmGetField(fpath, "anchor", floorAnc, CM_SIGN_HSZ) == CM_SIGN_HSZ
           && !memcmp(floorPub, current, CM_SIGN_HSZ);

  if (haveFloor && off < hw) {
    fprintf(stderr, "%s: seat %u signing offset %u REJECT: offset %u < high-water %lu (re-injection; signature not checked)\n"
           ,argv[0], idx + 1, slot, off, hw);
    goto done;
  }
  /* the RETRY / re-authoring split: identical bytes are the same message
   * again, a different apex at one one-time signing offset is leaked key material */
  if (haveFloor && off == hw && memcmp(floorAnc, anchor, CM_SIGN_HSZ)) {
    fprintf(stderr, "%s: seat %u signing offset %u REJECT: offset %u re-authored"
                    " (different apex at one signing offset; signature not checked)\n"
           ,argv[0], idx + 1, slot, off);
    goto done;
  }
  if (!cmMlsVerify(current, anchor, sig, sgsz)) {
    fprintf(stderr, "%s: seat %u signing offset %u REJECT: signature does not verify vs book current\n"
           ,argv[0], idx + 1, slot);
    goto done;
  }
  if (haveFloor && off == hw) {
    fprintf(stderr, "%s: seat %u signing offset %u RETRY: offset %u byte-identical"
                    " re-presentation (high-water %lu unchanged)\n"
           ,argv[0], idx + 1, slot, off, hw);
    rc = 0;
    goto done;
  }

  if (!(of = fopen(fpath, "w")))
    goto done;
  cmPutField(of, "pub", current, CM_SIGN_HSZ);
  cmPutU(of, "highwater", off);
  cmPutField(of, "anchor", anchor, CM_SIGN_HSZ);
  fclose(of);

  fprintf(stderr, "%s: seat %u signing offset %u ACCEPT: offset %u (high-water %s -> %u)\n"
         ,argv[0], idx + 1, slot, off, haveFloor ? "raised" : "init", off);
  rc = 0;
 done:
  if (cfg) memset(cfg, 0, sizeof (*cfg));  /* the dealt key mesh */
  free(cfg);
  free(sig);
  return (rc);
}
