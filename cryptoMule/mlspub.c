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
 * cryptoMule mlspub - print the MLS public root (identity) of a private-data
 * file.  Used to establish the out-of-band bootstrap pub (pub_0) that roots
 * the rotation chain.
 *
 * usage: mlspub <privateData>
 */

#include "cm.h"

int
main(
  int argc
 ,char *argv[]
){
  unsigned char pub[CM_SIGN_HSZ];
  char hex[2 * CM_SIGN_HSZ + 1];

  if (argc != 2) {
    fprintf(stderr, "usage: %s <privateData>\n", argv[0]);
    return (1);
  }
  if (cmMlsPub(argv[1], pub)) {
    fprintf(stderr, "%s: cannot derive pub from %s\n", argv[0], argv[1]);
    return (1);
  }
  cmHexEnc(pub, CM_SIGN_HSZ, hex);
  hex[2 * CM_SIGN_HSZ] = 0;
  printf("%s\n", hex);
  return (0);
}
