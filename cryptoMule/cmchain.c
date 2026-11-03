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
 * cryptoMule cmchain - fold one link of the dispersal chain and print it.
 *
 *   chain_0     = the dealt genesis (config's "genesis" row)
 *   chain_{k+1} = H(chain_k || msg_k), msg_k the dispersal's message hash
 *
 * The mask ratchet keys on the LINK, not on a bare value, so the sequence of
 * ratchet triggers is pinned end to end from a base every seat was dealt.  It
 * proves nothing on its own -- it is public, and anyone holding the previous link
 * and the message hash recomputes it, the application that holds the message
 * among them.  What it does is deny the ratchet an ARBITRARY trigger: a seat
 * that folds a different message hash, or starts from a different genesis, lands
 * on a different key and can neither read the others nor be read by them.
 * Divergence is undetected at the fold and total at the next message.
 *
 * AGREEMENT ON THE MESSAGE IS ASSUMED, not established here (see cmChain in cm.h).
 *
 * <prevHex> may be "-" to start from the dealt genesis.
 *
 * usage: cmchain <config> <prevHex|-> <msgHashHex>
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
  unsigned char prev[CM_SIGN_HSZ];
  unsigned char msg[CM_SIGN_HSZ];
  unsigned char out[CM_SIGN_HSZ];
  char hx[2 * CM_SIGN_HSZ + 1];
  int rc;

  cfg = 0;
  rc = 1;
  if (argc != 4) {
    fprintf(stderr, "usage: %s <config> <prevHex|-> <msgHashHex>\n", argv[0]);
    return (1);
  }

  if (!(cfg = malloc(sizeof (*cfg))) || cmCfgLoad(argv[1], cfg)) {
    fprintf(stderr, "%s: bad config %s\n", argv[0], argv[1]);
    goto done;
  }
  if (argv[2][0] == '-' && !argv[2][1]) {
    if (!cfg->genesisHave) {
      fprintf(stderr, "%s: no genesis dealt in %s\n", argv[0], argv[1]);
      goto done;
    }
    memcpy(prev, cfg->genesis, CM_SIGN_HSZ);
  } else if (cmHexDec(argv[2], prev, CM_SIGN_HSZ) != CM_SIGN_HSZ) {
    fprintf(stderr, "%s: bad previous link hex %s\n", argv[0], argv[2]);
    goto done;
  }
  if (cmHexDec(argv[3], msg, CM_SIGN_HSZ) != CM_SIGN_HSZ) {
    fprintf(stderr, "%s: bad message hash hex %s\n", argv[0], argv[3]);
    goto done;
  }

  cmChain(prev, msg, out);
  cmHexEnc(out, CM_SIGN_HSZ, hx);
  hx[2 * CM_SIGN_HSZ] = 0;
  printf("%s\n", hx);
  rc = 0;
 done:
  if (cfg) memset(cfg, 0, sizeof (*cfg));  /* the dealt key mesh */
  free(cfg);
  return (rc);
}
