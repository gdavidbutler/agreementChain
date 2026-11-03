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
 * cryptoMule cmhmac - driver-side wire hmac append.  The OPERATOR stand-in
 * (drive.py) synthesizes wire messages (the run files) and must end them with
 * the same pairwise wire hmac the phase programs append; its keys come from
 * the operator ledger (drive/config.txt "mac a_b").  This is demo scaffolding: in a
 * deployment every wire message is produced by a sender that hmacs it itself.
 *
 * usage: cmhmac <macKeyHex> <sender> <recipient> <file>
 */

#include <stdlib.h>
#include "cm.h"

int
main(
  int argc
 ,char *argv[]
){
  unsigned char key[CM_PSK_LEN];

  if (argc != 5) {
    fprintf(stderr, "usage: %s <macKeyHex> <sender> <recipient> <file>\n", argv[0]);
    return (1);
  }
  if (cmHexDec(argv[1], key, CM_PSK_LEN) != CM_PSK_LEN) {
    fprintf(stderr, "%s: bad key hex\n", argv[0]);
    return (1);
  }
  if (cmHmacAppend(argv[4], key, CM_PSK_LEN
                  ,(unsigned char)atoi(argv[2]), (unsigned char)atoi(argv[3]))) {
    fprintf(stderr, "%s: cannot hmac %s\n", argv[0], argv[4]);
    return (1);
  }
  return (0);
}
