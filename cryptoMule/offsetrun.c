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
 * cryptoMule offsetrun - one identity signs a RUN of values at successive
 * signing offsets: offset 0 the rotation (over the rotation's apex, the hash of
 * the signer's pub, offset 0 and the successor pub, the value rotate signs: the same
 * context's signing offset 0 must not sign two values),
 * signing offsets 1..N the payload apexes.  This isolates the MLS signing-offset sequence so the
 * re-injection floor (offsetgate) can be exercised with a single identity used
 * many times (the s>1 cadence, vs one signing per context).  The signing offset 1..
 * values are stand-ins: offsetgate reads the offset from the signature
 * structure, not from what was signed.
 *
 * There is no broadcast (each PAIR is owed exactly two properties,
 * confidentiality and integrity under that pair's keys): each signing offset's signed run is sent to each recipient p as a
 * DIRECTED message wire/run_<slot>_to_<p>.txt ending in that pair's wire hmac.
 *
 * usage: offsetrun <config> <ctxCurrent> <ctxNext> <nPayload> <baseDir>
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
  unsigned char pubSigner[CM_SIGN_HSZ];
  unsigned char anchor[CM_SIGN_HSZ];
  unsigned char *sig;
  FILE *of;
  char path[1024];
  unsigned long sigLen;
  unsigned int nPay;
  unsigned int slots;
  unsigned int j;
  unsigned int p;
  int rc;

  cfg = 0;
  sig = 0;
  rc = 1;
  if (argc != 6) {
    fprintf(stderr, "usage: %s <config> <ctxCurrent> <ctxNext> <nPayload> <baseDir>\n", argv[0]);
    return (1);
  }
  nPay = (unsigned int)atoi(argv[4]);
  slots = 1U << CM_MLS_S;
  if (nPay + 1 > slots) {
    fprintf(stderr, "%s: nPayload %u + rotation exceeds %u signing offsets (2^%d)\n"
           ,argv[0], nPay, slots, CM_MLS_S);
    return (1);
  }

  if (!(cfg = malloc(sizeof (*cfg))) || cmCfgLoad(argv[1], cfg)) {
    fprintf(stderr, "%s: bad config %s\n", argv[0], argv[1]);
    goto done;
  }
  if (cmMlsPub(argv[2], pubSigner)) {      /* signing offset 0's apex commits the signer's pub */
    fprintf(stderr, "%s: cannot derive the signer pub from %s\n", argv[0], argv[2]);
    goto done;
  }
  if (cmMlsPub(argv[3], pubNext)) {        /* and the successor pub */
    fprintf(stderr, "%s: cannot derive successor pub from %s\n", argv[0], argv[3]);
    goto done;
  }

  for (j = 0; j <= nPay; ++j) {
    if (!j)
      cmApexRot(pubSigner, CM_SLOT_ROT, pubNext, anchor);  /* the rotation's apex, as rotate signs it */
    else {
      unsigned char lbl[32];
      int ln;

      ln = sprintf((char *)lbl, "offsetrun payload %u", j);
      cmHash(lbl, (unsigned int)ln, anchor);
    }
    if (cmMlsSign(argv[2], j, anchor, &sig, &sigLen, pubSigner)) {
      fprintf(stderr, "%s: cannot sign at signing offset %u with %s\n", argv[0], j, argv[2]);
      goto done;
    }
    for (p = 1; p < cfg->n; ++p) {         /* one directed message per recipient */
      sprintf(path, "%s/wire/run_%02u_to_%02u.txt", argv[5], j, p);
      if (!(of = fopen(path, "w")))
        goto done;
      fprintf(of, "phase: %s\n", j ? "payload" : "rotation");
      cmPutU(of, "slot", j);
      cmPutField(of, "anchor", anchor, CM_SIGN_HSZ);
      cmPutField(of, "mls_sig", sig, (unsigned int)sigLen);
      fclose(of);
      if (cmHmacAppend(path, cfg->mac[p], CM_PSK_LEN, 0, p)) {
        fprintf(stderr, "%s: cannot hmac %s\n", argv[0], path);
        goto done;
      }
    }
    free(sig);
    sig = 0;
  }

  fprintf(stderr, "%s: signed at signing offset 0 (rotation) + 1..%u (payload) under one identity, sent to %u recipients each\n"
         ,argv[0], nPay, cfg->n - 1);
  rc = 0;
 done:
  if (cfg) memset(cfg, 0, sizeof (*cfg));  /* the dealt key mesh */
  free(cfg);
  free(sig);
  return (rc);
}
