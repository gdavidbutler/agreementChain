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
 * cryptoMule rotate - the rotation launch.
 *
 * The initiator's CURRENT context signs its NEXT context's public key with
 * CM_SLOT_ROT -- the one signing offset of a context that is the rotation's and no
 * payload's (rotverify refuses a rotation at any other offset; receive and
 * assemble refuse a payload at this one).  The anchor is the rotation's
 * apex, the sign-hash of the signer's current pub, the offset it signs at
 * and the successor pub (cmApexRot), as a payload's apex is the sign-hash of
 * the signer's pub, the offset, its orig_hash and roots: the apex message
 * carries a hash alone either way, and the sign message carries the rest of
 * what hashes to it (here pub_hash, the successor pub), never the signer pub,
 * which the verifier holds as its current, nor the offset, which the
 * signature yields.  A value is therefore one kind under one signer at one
 * offset: never a payload to some seats and a rotation to others, never
 * verifiable under another of the signer's keys.  A verifier recomputes the
 * apex under its current pub and the signature's offset, requires the
 * signature to extract to that same pub, and installs pub_hash.  This is the identity-rotation launch at the data layer (just
 * the signed successor).
 *
 * There is no broadcast (each PAIR is owed exactly two properties,
 * confidentiality and integrity under that pair's keys): the one signed rotation is sent to each recipient p as the
 * same two DIRECTED messages a payload's apex and signature take, each
 * ending in that pair's wire hmac (static mac(0,p)):
 *   wire/rot/00_rotate_<process>_to_<p>_apex.txt  the apex alone, a hash
 *          width -- the apex message is the same message for a rotation and
 *          for a payload;
 *   wire/rot/00_rotate_<process>_to_<p>_sign.txt  the tag (the apex
 *          message's file name), the dispersal label, pub_hash (the successor
 *          pub, which must hash to the apex under the signer's pub and the
 *          offset) and the
 *          signature; its FORMAT,
 *          no roots and no proofs, says no payload rides with it.
 *
 * The optional [slot] argument is demo scaffolding (`drive.py slot`): sign at
 * CM_SLOT_PAY, the payload signing offset (the apex computed at it, as every
 * signer computes the apex at the offset it signs at), so rotverify's
 * signing offset gate has something to refuse.
 *
 * usage: rotate <config> <privCurrent> <privNext> <dispersal> <baseDir> [slot]
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
  unsigned char pubNext[CM_SIGN_HSZ];
  unsigned char apex[CM_SIGN_HSZ];
  unsigned char pubSigner[CM_SIGN_HSZ];
  unsigned char *sig;
  unsigned long sigLen;
  FILE *of;
  char path[1024];
  char apexName[64];                  /* the apex message's file name: the sign message's tag */
  unsigned int process;
  unsigned int p;
  int fltSlot;
  int rc;

  cfg = 0;
  sig = 0;
  fltSlot = 0;
  rc = 1;
  if (argc != 6 && argc != 7) {
    fprintf(stderr, "usage: %s <config> <privCurrent> <privNext> <dispersal> <baseDir> [slot]\n", argv[0]);
    return (1);
  }
  process = (unsigned int)atoi(argv[4]);
  if (argc == 7) {
    if (!strcmp(argv[6], "slot")) fltSlot = 1;
    else {
      fprintf(stderr, "%s: unknown fault %s\n", argv[0], argv[6]);
      return (1);
    }
  }

  if (!(cfg = malloc(sizeof (*cfg))) || cmCfgLoad(argv[1], cfg)) {
    fprintf(stderr, "%s: bad config %s\n", argv[0], argv[1]);
    goto done;
  }
  if (cmMlsPub(argv[2], pubSigner)) {     /* the signer's pub first: the apex commits it */
    fprintf(stderr, "%s: cannot derive the signer pub from %s\n", argv[0], argv[2]);
    goto done;
  }
  if (cmMlsPub(argv[3], pubNext)) {       /* successor pub: the rest of the apex's preimage */
    fprintf(stderr, "%s: cannot derive successor pub from %s\n", argv[0], argv[3]);
    goto done;
  }
  cmApexRot(pubSigner, fltSlot ? CM_SLOT_PAY : CM_SLOT_ROT, pubNext, apex);  /* the rotation's apex, the anchor */
  if (cmMlsSign(argv[2], fltSlot ? CM_SLOT_PAY : CM_SLOT_ROT, apex, &sig, &sigLen, pubSigner)) {
    fprintf(stderr, "%s: cannot sign with %s\n", argv[0], argv[2]);
    goto done;
  }

  for (p = 1; p < cfg->n; ++p) {          /* two directed messages per recipient */
    sprintf(apexName, "00_rotate_%02u_to_%02u_apex.txt", process, p);
    sprintf(path, "%s/wire/rot/%s", argv[5], apexName);
    if (!(of = fopen(path, "w")))
      goto done;
    fprintf(of, "phase: rotate\n");
    cmPutField(of, "apex", apex, CM_SIGN_HSZ);          /* the value signed */
    fclose(of);
    if (cmHmacAppend(path, cfg->mac[p], CM_PSK_LEN, 0, p)) {
      fprintf(stderr, "%s: cannot hmac %s\n", argv[0], path);
      goto done;
    }
    sprintf(path, "%s/wire/rot/00_rotate_%02u_to_%02u_sign.txt", argv[5], process, p);
    if (!(of = fopen(path, "w")))
      goto done;
    fprintf(of, "phase: rotate\n");
    fprintf(of, "tag: %s\n", apexName);                 /* the tag */
    cmPutU(of, "process", process);
    cmPutField(of, "pub_hash", pubNext, CM_SIGN_HSZ);   /* the successor pub: hashes to the apex under the signer's pub and offset */
    cmPutField(of, "mls_sig", sig, (unsigned int)sigLen);
    fclose(of);
    if (cmHmacAppend(path, cfg->mac[p], CM_PSK_LEN, 0, p)) {
      fprintf(stderr, "%s: cannot hmac %s\n", argv[0], path);
      goto done;
    }
  }

  fprintf(stderr, "%s: dispersal %u signs the hash of its pub and the successor pub with signing offset %d (the %s), sent to %u recipients\n"
         ,argv[0], process, fltSlot ? CM_SLOT_PAY : CM_SLOT_ROT, fltSlot ? "payload's" : "rotation's", cfg->n - 1);
  rc = 0;
 done:
  if (cfg) memset(cfg, 0, sizeof (*cfg));  /* the dealt key mesh */
  free(cfg);
  free(sig);
  return (rc);
}
