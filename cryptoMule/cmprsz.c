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
 * cryptoMule cmprsz - print the MLS private-data size and the per-context
 * signing-offset count (2^CM_MLS_S) for the configured context.  The driver
 * uses these to size the context key files instead of hardcoding a length
 * that would silently break when CM_MLS_S grows.
 *
 * usage: cmprsz
 */

#include "cm.h"

int
main(
  void
){
  mlsCtx_t v;
  mlsHsh_t plug;

  cmMlsPlug(&plug);
  v.h = &plug;
  v.s = CM_MLS_S;
  v.r = 0;
  printf("%lu %u\n", (unsigned long)mlsPrSz(&v), 1U << CM_MLS_S);
  return (0);
}
