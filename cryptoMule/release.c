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
 * cryptoMule release - move the RETENTION FLOOR forward, destroying what it
 * passes.
 *
 * The floor is the oldest dispersal this seat can still serve (see ratchet.c and
 * cmFloorLoad).  Releasing a dispersal means two things at once and they must be
 * the same act: the seat stops being obliged to serve it, and it stops being
 * ABLE to.  This program does that by recomputing the floor base forward over the
 * public anchor sequence -- the same one-way step ./catchup and ./ratchet use --
 * and overwriting the base with the result.  HKDF/HMAC is one-way, so once the
 * base has stepped past a dispersal, no reader (including this seat) can derive
 * that dispersal's masks again.
 *
 * Forward secrecy is therefore BOUNDED BY THE FLOOR, not by the current step, and
 * that is the price of serving at all: everything from the floor forward is
 * derivable by whoever holds the base.  Keeping the retention span short is what
 * keeps the price small; keeping a per-dispersal snapshot instead would be strictly
 * worse (more to hold, and nothing to destroy on release).
 *
 * The current step (process: / psk_<QQ>) is untouched -- it is ahead of the floor
 * and ./ratchet owns it.
 *
 * usage: release <config> <newFloor> <anchorLog>
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
  cmCfg *flo;
  unsigned char anchor[CM_SIGN_HSZ];
  unsigned char nxt[CM_PSK_LEN];
  FILE *of;
  char kpath[1024];
  char name[sizeof ("anchor") + 3 * sizeof (unsigned long)];
  unsigned long process;
  unsigned long floorProc;
  unsigned long newFloor;
  unsigned long rr;
  unsigned int q;
  int rc;

  cfg = flo = 0;
  rc = 1;
  if (argc != 4) {
    fprintf(stderr, "usage: %s <config> <newFloor> <anchorLog>\n", argv[0]);
    return (1);
  }
  newFloor = strtoul(argv[2], 0, 10);
  cmKsPath(argv[1], kpath);

  if (!(cfg = malloc(sizeof (*cfg))) || cmCfgLoad(argv[1], cfg)
   || !(flo = malloc(sizeof (*flo))) || cmCfgLoad(argv[1], flo)) {
    fprintf(stderr, "%s: bad config %s\n", argv[0], argv[1]);
    goto done;
  }
  if (cmKeystateLoad(kpath, cfg) || cmGetU(kpath, "process", &process)) {
    fprintf(stderr, "%s: no keystate %s\n", argv[0], kpath);
    goto done;
  }
  if (cmFloorLoad(kpath, flo, &floorProc)) {
    fprintf(stderr, "%s: no floor in %s (nothing retained yet)\n", argv[0], kpath);
    goto done;
  }
  if (newFloor < floorProc) {
    fprintf(stderr, "%s: floor is forward-only (%lu -> %lu refused)\n"
           ,argv[0], floorProc, newFloor);
    goto done;
  }
  if (newFloor > process) {         /* dispersal F's key is step F */
    fprintf(stderr, "%s: floor %lu would pass the current step %lu\n"
           ,argv[0], newFloor, process);
    goto done;
  }

  /* the base is dispersal floorProc's key; the links of dispersals
   * floorProc .. newFloor-1 carry it to dispersal newFloor's (see cmFloorLoad) */
  for (rr = floorProc; rr < newFloor; ++rr) {
    sprintf(name, "anchor%02lu", rr);
    if (cmGetField(argv[3], name, anchor, CM_SIGN_HSZ) != CM_SIGN_HSZ) {
      fprintf(stderr, "%s: no %s in %s\n", argv[0], name, argv[3]);
      goto done;
    }
    for (q = 0; q < flo->n; ++q)
      if (flo->pskHave[q]) {
        cmRatchet(flo->psk[q], CM_PSK_LEN, anchor, nxt, CM_PSK_LEN);
        memcpy(flo->psk[q], nxt, CM_PSK_LEN);
      }
  }

  if (!(of = fopen(kpath, "w")))              /* overwrite: the old base is gone */
    goto done;
  cmPutU(of, "process", process);
  cmPutU(of, "floor", newFloor);
  for (q = 0; q < cfg->n; ++q)                /* the current step, untouched */
    if (cfg->pskHave[q]) {
      sprintf(name, "psk_%02u", q);
      cmPutField(of, name, cfg->psk[q], CM_PSK_LEN);
    }
  for (q = 0; q < flo->n; ++q)
    if (flo->pskHave[q]) {
      sprintf(name, "fpsk_%02u", q);
      cmPutField(of, name, flo->psk[q], CM_PSK_LEN);
    }
  fclose(of);

  memset(nxt, 0, sizeof (nxt));
  fprintf(stderr, "%s: floor dispersal %lu -> %lu over %lu public anchor(s);"
                  " dispersals below %lu are unservable and unreadable\n"
         ,argv[0], floorProc, newFloor, newFloor - floorProc, newFloor);
  rc = 0;
 done:
  if (cfg) memset(cfg, 0, sizeof (*cfg));  /* the dealt key mesh */
  free(cfg);
  if (flo) { memset(flo->psk, 0, sizeof (flo->psk)); free(flo); }
  return (rc);
}
