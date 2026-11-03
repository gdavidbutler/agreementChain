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
 * cryptoMule catchup - the recovery KEY half.  A seat that holds a stale
 * mask keystate (dispersal j) steps it forward through the PUBLIC anchor
 * sequence to the live dispersal k, after which it can unmask dispersal-k shares.  The
 * public anchor of each dispersal is that dispersal's ratchet trigger h_r, its CHAIN
 * LINK (cmChain: the previous link folded with the payload's message hash); only payload
 * dispersals step the chain, a rotation mints no link.  Walking from j to k
 * applies the links of dispersals j .. k-1, landing on dispersal k's one key.
 * The delivery half (obtaining the dispersal-k shares) is protocol, not modeled
 * here.
 *
 * usage: catchup <config> <staleKeystate> <anchorLog> <fromProcess> <toProcess> <outKeystate>
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
  unsigned char anchor[CM_SIGN_HSZ];
  unsigned char nxt[CM_PSK_LEN];
  FILE *of;
  char name[sizeof ("anchor") + 3 * sizeof (unsigned long)];
  unsigned long from;
  unsigned long to;
  unsigned long rr;
  unsigned int i;
  int rc;

  cfg = 0;
  rc = 1;
  if (argc != 7) {
    fprintf(stderr, "usage: %s <config> <staleKeystate> <anchorLog>"
                    " <fromProcess> <toProcess> <outKeystate>\n", argv[0]);
    return (1);
  }
  from = strtoul(argv[4], 0, 10);
  to = strtoul(argv[5], 0, 10);

  if (!(cfg = malloc(sizeof (*cfg))) || cmCfgLoad(argv[1], cfg)) {
    fprintf(stderr, "%s: bad config %s\n", argv[0], argv[1]);
    goto done;
  }
  if (cmKeystateLoad(argv[2], cfg)) {         /* stale PSK_j(q) into cfg */
    fprintf(stderr, "%s: no stale keystate %s\n", argv[0], argv[2]);
    goto done;
  }

  for (rr = from; rr < to; ++rr) {            /* step over the public anchors */
    sprintf(name, "anchor%02lu", rr);
    if (cmGetField(argv[3], name, anchor, CM_SIGN_HSZ) != CM_SIGN_HSZ) {
      fprintf(stderr, "%s: no %s in %s\n", argv[0], name, argv[3]);
      goto done;
    }
    for (i = 0; i < cfg->n; ++i)
      if (cfg->pskHave[i]) {                  /* only the pair(s) this seat holds */
        cmRatchet(cfg->psk[i], CM_PSK_LEN, anchor, nxt, CM_PSK_LEN);
        memcpy(cfg->psk[i], nxt, CM_PSK_LEN);
      }
  }

  if (!(of = fopen(argv[6], "w")))
    goto done;
  cmPutU(of, "process", to);
  for (i = 0; i < cfg->n; ++i)
    if (cfg->pskHave[i]) {
      sprintf(name, "psk_%02u", i);           /* recipient seat id i */
      cmPutField(of, name, cfg->psk[i], CM_PSK_LEN);
    }
  fclose(of);

  memset(nxt, 0, sizeof (nxt));
  fprintf(stderr, "%s: stepped keystate %lu -> %lu over %lu public anchors\n"
         ,argv[0], from, to, to - from);
  rc = 0;
 done:
  if (cfg) {
    memset(cfg->psk, 0, sizeof (cfg->psk));
    if (cfg) memset(cfg, 0, sizeof (*cfg));  /* the dealt key mesh */
    free(cfg);
  }
  return (rc);
}
