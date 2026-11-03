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
 * cryptoMule cmapex - recompute and print a fragment's apex (the value
 * signed) from its SIGN message and the signer's pub:
 * H(signer pub || signing offset || orig_hash || rsecmk_root || sssmk_root),
 * the signed inputs from the sign message, the offset from the structure of
 * the signature it carries, and the pub from a book's `current` (the pub a
 * verifier holds; the sign message never carries it) -- the apex the
 * fragment's apex message must carry.  The driver takes the apex this way,
 * by the arithmetic rather than off the apex message, and hands it to the
 * offset floor.
 *
 * usage: cmapex <signMessage> <book>
 */

#include <stdlib.h>
#include "cm.h"

int
main(
  int argc
 ,char *argv[]
){
  unsigned char pub[CM_SIGN_HSZ];
  unsigned char orig_hash[CM_SIGN_HSZ];
  unsigned char sssRoot[CM_SSS_HSZ];
  unsigned char rsecRoot[CM_RSEC_HSZ];
  unsigned char apex[CM_SIGN_HSZ];
  unsigned char *sig;
  char hex[2 * CM_SIGN_HSZ + 1];
  mlsCtx_t v;
  mlsHsh_t plug;
  unsigned long sgsz;
  unsigned int off;
  int rc;

  if (argc != 3) {
    fprintf(stderr, "usage: %s <signMessage> <book>\n", argv[0]);
    return (1);
  }
  if (cmGetField(argv[2], "current", pub, CM_SIGN_HSZ) != CM_SIGN_HSZ) {
    fprintf(stderr, "%s: no current pub in %s\n", argv[0], argv[2]);
    return (1);
  }
  cmMlsPlug(&plug);
  v.h = &plug;
  v.s = CM_MLS_S;
  v.r = 0;
  sgsz = mlsSgSz(&v);
  if (!(sig = malloc(sgsz)))
    return (1);
  rc = 1;
  if (cmGetField(argv[1], "orig_hash", orig_hash, CM_SIGN_HSZ) != CM_SIGN_HSZ
   || cmGetField(argv[1], "sssmk_root", sssRoot, CM_SSS_HSZ) != CM_SSS_HSZ
   || cmGetField(argv[1], "rsecmk_root", rsecRoot, CM_RSEC_HSZ) != CM_RSEC_HSZ
   || cmGetField(argv[1], "mls_sig", sig, (unsigned int)sgsz) != (int)sgsz
   || !cmMlsOff(sig, sgsz, &off)) {
    fprintf(stderr, "%s: malformed fragment %s\n", argv[0], argv[1]);
    goto done;
  }
  cmApex(pub, off, orig_hash, rsecRoot, sssRoot, apex);
  cmHexEnc(apex, CM_SIGN_HSZ, hex);
  hex[2 * CM_SIGN_HSZ] = 0;
  printf("%s\n", hex);
  rc = 0;
 done:
  free(sig);
  return (rc);
}
