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
 * cryptoMule chainverify - the EVIDENCE half of recovery, to catchup's key half.
 *
 * A seat whose keys are older than the retention floor cannot be healed from INSIDE:
 * nothing anyone still holds reaches back that far, and a resend refuses below
 * the floor by design.  What such a seat recovers on instead is the public link
 * sequence, and this program is what turns that sequence plus a pile of gathered
 * fragments into the three answers it needs:
 *
 *   a gap EXISTS          some position has nothing gathered for it
 *   where it STARTS       the first such position
 *   how far it VALIDATES  the last position whose item provably belongs there
 *
 * WHY THE LOG IS PUBLIC AND UNAUTHENTICATED, since this is the program that shows
 * it: an instrument that only helps someone already outside must be readable from
 * outside, and it is CHECKED here rather than trusted.  Fold forward from the
 * DEALT genesis over the gathered message hashes and compare each link to the
 * log.  Tampering the log makes good items fail to validate -- denial, never
 * forgery -- and authenticity stays where it always was, on the initiator's
 * signature over each apex.
 *
 * ORDER, NOT AUTHORSHIP, and keeping them apart is what makes each legible.  What
 * is folded is the item's MESSAGE hash, its orig_hash, and nothing of the
 * dispersal: a gatherer holding only the message computes it, and one holding a
 * fragment reads it from the fragment, which is what this program is handed.
 * The signature, over the apex that commits that hash, is checked where the
 * fragment is CONSUMED (receive, assemble).  The chain answers "does this item belong at this
 * position", and it answers that for a forged item and for a misplaced authentic
 * one alike: an item that does not fold to the logged link is wrong here whoever
 * signed it.
 *
 * A "-" in place of a fragment path is a position with nothing gathered.  The
 * fold cannot pass it -- the next link needs that message hash -- so verification stops
 * and reports it.  That is the gap boundary being located, not a failure.
 *
 * exit 0  every position validated, nothing missing
 *      1  an item does not belong at its position (or the inputs are unusable)
 *      2  a gap: validated up to it, nothing gathered for it
 *
 * usage: chainverify <config> <anchorLog> <frag0|-> [<frag1|-> ..]
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
  unsigned char link[CM_SIGN_HSZ];
  unsigned char next[CM_SIGN_HSZ];
  unsigned char logged[CM_SIGN_HSZ];
  unsigned char orig_hash[CM_SIGN_HSZ];
  char hex[2 * CM_SIGN_HSZ + 1];
  char name[sizeof ("anchor") + 3 * sizeof (unsigned int)];
  unsigned int cnt;
  unsigned int i;
  int through;                        /* last position validated; -1 = none */
  int rc;

  cfg = 0;
  through = -1;
  rc = 1;
  if (argc < 4) {
    fprintf(stderr, "usage: %s <config> <anchorLog> <frag0|-> [<frag1|-> ..]\n"
           ,argv[0]);
    return (1);
  }
  cnt = (unsigned int)(argc - 3);

  if (!(cfg = malloc(sizeof (*cfg))) || cmCfgLoad(argv[1], cfg)) {
    fprintf(stderr, "%s: bad config %s\n", argv[0], argv[1]);
    goto done;
  }
  if (!cfg->genesisHave) {            /* the whole fold bottoms out here */
    fprintf(stderr, "%s: no genesis dealt in %s\n", argv[0], argv[1]);
    goto done;
  }
  memcpy(link, cfg->genesis, CM_SIGN_HSZ);

  for (i = 0; i < cnt; ++i) {
    const char *frag;

    frag = argv[3 + i];
    if (frag[0] == '-' && !frag[1]) { /* nothing gathered: the gap boundary */
      fprintf(stderr, "%s: GAP at dispersal %u (validated through %d)\n"
             ,argv[0], i, through);
      rc = 2;
      goto done;
    }
    if (cmGetField(frag, "orig_hash", orig_hash, CM_SIGN_HSZ) != CM_SIGN_HSZ) {
      fprintf(stderr, "%s: malformed fragment %s at dispersal %u\n"
             ,argv[0], frag, i);
      goto done;
    }
    cmChain(link, orig_hash, next);

    sprintf(name, "anchor%02u", i);
    if (cmGetField(argv[2], name, logged, CM_SIGN_HSZ) != CM_SIGN_HSZ) {
      fprintf(stderr, "%s: no %s in %s (log ends before dispersal %u)\n"
             ,argv[0], name, argv[2], i);
      rc = 2;
      goto done;
    }
    if (memcmp(next, logged, CM_SIGN_HSZ)) {
      fprintf(stderr, "%s: MISMATCH at dispersal %u: %s does not belong there"
                      " (validated through %d)\n", argv[0], i, frag, through);
      goto done;
    }
    memcpy(link, next, CM_SIGN_HSZ);
    through = (int)i;
  }

  cmHexEnc(link, CM_SIGN_HSZ, hex);
  hex[2 * CM_SIGN_HSZ] = 0;
  fprintf(stderr, "%s: validated dispersals 0..%d from the dealt genesis; link %s\n"
         ,argv[0], through, hex);
  rc = 0;
 done:
  if (cfg) memset(cfg, 0, sizeof (*cfg));  /* the dealt key mesh */
  free(cfg);
  return (rc);
}
