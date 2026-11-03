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
 * cryptoMule ratchet - step the mask key chain at a dispersal boundary.
 *
 * The public anchor sets the step.  When dispersal k's flow is done -- distribute,
 * receive, exchange and assemble all masked under PSK_k -- every pairwise mask
 * IKM this seat holds steps on the same public trigger h_k = the dispersal's
 * chain link:
 *     PSK_{k+1}(q)= HKDF(PSK_k(q), h_k || 'R', 64)
 * and the previous keystate is overwritten (wipe-on-complete); dispersal k+1's
 * distribute is the first thing masked under PSK_{k+1}.  HKDF/HMAC is one-way,
 * so a wiped PSK_k cannot be recomputed: dispersal k's harvested masked shares and
 * exchange legs become unreadable at the current step -- forward secrecy, bounded
 * by the floor below.  (The config still holds the dispersal-0 seed on disk; that
 * is the mule's inspectability tradeoff, not the chain's property.)
 *
 * h_k is the dispersal's public anchor, supplied as <anchorHex>: the chain value the
 * dispersal fixed (./cmchain folds the dealt genesis and the dispersal's message hash into
 * it).  The ratchet keys on whatever the dispersal fixed -- it is
 * dispersal-type-agnostic.
 *
 * THE FLOOR SURVIVES THE STEP.  Wiping the current step is what buys forward
 * secrecy, but a seat that missed dispersal k may still ask for it, and there is
 * then nothing left to answer with.  So the keystate carries two things: the
 * CURRENT step (psk_<QQ>), which this program advances and wipes, and the
 * RETENTION FLOOR base (floor: + fpsk_<QQ>), which it copies through untouched.
 * a resend recomputes forward from the floor to any dispersal at or after it; only
 * ./release moves the floor, and what the floor passes is unrecoverable.  The
 * first ratchet BIRTHS the floor -- at the dispersal it is stepping past, holding
 * the key that dispersal masked under, the one this step wipes from the current
 * (see cmFloorLoad on the indexing).  Before the first ratchet the current step
 * IS that dispersal's key, so there is nothing a floor would add.
 *
 * usage: ratchet <config> <dispersal> <anchorHex>
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
  unsigned char hk[CM_SIGN_HSZ];
  unsigned char nxt[CM_PSK_LEN];
  FILE *of;
  char kpath[1024];
  unsigned long floorProc;
  unsigned int process;
  unsigned int q;
  int born;
  int rc;

  cfg = flo = 0;
  rc = 1;
  if (argc != 4) {
    fprintf(stderr, "usage: %s <config> <dispersal> <anchorHex>\n", argv[0]);
    return (1);
  }
  process = (unsigned int)atoi(argv[2]);
  cmKsPath(argv[1], kpath);                   /* this seat's keystate */

  if (!(cfg = malloc(sizeof (*cfg))) || cmCfgLoad(argv[1], cfg)) {
    fprintf(stderr, "%s: bad config %s\n", argv[0], argv[1]);
    goto done;
  }
  if (cmKeystateLoad(kpath, cfg)) {           /* current PSK_k(q) and pskHave */
    fprintf(stderr, "%s: no keystate %s\n", argv[0], kpath);
    goto done;
  }
  if (cmHexDec(argv[3], hk, CM_SIGN_HSZ) != CM_SIGN_HSZ) {  /* h_k = the dispersal's public anchor */
    fprintf(stderr, "%s: bad anchor hex %s\n", argv[0], argv[3]);
    goto done;
  }

  /* the floor base, carried through unchanged -- or born here if the keystate has
   * none.  flo is zeroed rather than loaded from the config, so a floor row exists
   * only where the birth below writes one: a config row is a DEALT key, never a
   * floor base (the first birth copies the CURRENT key, which at dispersal 0 is
   * the dealt one by value). */
  if (!(flo = malloc(sizeof (*flo))))
    goto done;
  memset(flo, 0, sizeof (*flo));
  flo->n = cfg->n;
  if ((born = cmFloorLoad(kpath, flo, &floorProc) != 0))
    floorProc = process;

  if (!(of = fopen(kpath, "w")))              /* overwrite: wipe the old dispersal */
    goto done;
  cmPutU(of, "process", process + 1);
  cmPutU(of, "floor", floorProc);
  for (q = 0; q < cfg->n; ++q)                /* ratchet only the pair(s) held */
    if (cfg->pskHave[q]) {
      char name[16];

      if (born) {                             /* the floor's birth: the key being stepped past */
        memcpy(flo->psk[q], cfg->psk[q], CM_PSK_LEN);
        flo->pskHave[q] = 1;
      }
      cmRatchet(cfg->psk[q], CM_PSK_LEN, hk, nxt, CM_PSK_LEN);
      sprintf(name, "psk_%02u", q);           /* recipient seat id q */
      cmPutField(of, name, nxt, CM_PSK_LEN);
    }
  for (q = 0; q < flo->n; ++q)
    if (flo->pskHave[q]) {
      char name[16];

      sprintf(name, "fpsk_%02u", q);
      cmPutField(of, name, flo->psk[q], CM_PSK_LEN);
    }
  fclose(of);

  memset(nxt, 0, sizeof (nxt));
  memset(cfg->psk, 0, sizeof (cfg->psk));
  memset(flo->psk, 0, sizeof (flo->psk));
  fprintf(stderr, "%s: dispersal %u -> %u, keyed on h_k = public anchor"
                  " (old keys wiped; floor %s dispersal %lu)\n"
         ,argv[0], process, process + 1, born ? "born at" : "stays at", floorProc);
  rc = 0;
 done:
  if (cfg) memset(cfg, 0, sizeof (*cfg));  /* the dealt key mesh */
  free(cfg);
  free(flo);
  return (rc);
}
