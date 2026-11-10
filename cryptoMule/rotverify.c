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
 * cryptoMule rotverify - a recipient verifies a rotation and advances its book.
 *
 * A verifier holds a book (the dispersal it is at, and the current pub) rooted
 * at the out-of-band pub_0 -- per seat: priv/<p>_book.txt.  For dispersal k
 * it reads ITS directed rotation
 * -- the apex message (the rotation's apex alone, the sign-hash of the
 * signer's pub, the signing offset and the successor pub) and the sign message (the tag, the
 * dispersal label, pub_hash and the signature, no roots and no proofs: a
 * format that announces no payload), as a payload's apex
 * and signature arrive (there is no broadcast; see rotate.c) -- gates each
 * message's pairwise wire hmac FIRST (static mac(self,0); a failure is a
 * wire-tamper verdict and nothing is parsed), requires the sign message's
 * tag to name this apex message and the apex recomputed under its CURRENT
 * pub and the offset the signature yields from pub_hash (cmApexRot) to be
 * the apex the apex message carries (a
 * payload's apex is the hash of the signer's pub, the offset, its orig_hash and roots,
 * so no pub_hash reaches it: the same value cannot be a payload to one
 * seat and a rotation to another; and a rotation apex committed under
 * another of the signer's keys does not recompute here), verifies the
 * signature against that same CURRENT pub (mlsExtract of the sig over the
 * apex must recover current) AT THE ROTATION'S SIGNING OFFSET
 * (the recovered signing offset must be CM_SLOT_ROT: a rotation signed at a
 * payload signing offset is refused, so a signer cannot spend a one-time payload signing offset
 * twice by putting a rotation on it), then installs pub_hash as
 * the new current for dispersal k+1.  Walking this chain from pub_0
 * authenticates the whole identity sequence; a payload in dispersal k then
 * verifies against this same current pub.
 *
 * A rotation for dispersal k arriving AFTER the book moved past k gets the
 * RETRY / re-authoring split the offset floor gives payloads (offsetgate.c):
 * the install record priv/<p>_install_<k>.txt (the record of the attempt that
 * moved the book; nothing rewrites it afterwards) holds the pub that signed the
 * installed rotation and the successor it installed, so a copy presented again has its apex
 * recomputed under that signer and its signature's offset and its signature
 * verified against it, and
 * then either it carries the SAME successor
 * -- a RETRY, the same message presented again, book unchanged -- or a DIFFERENT one
 * -- REJECT: two successors signed at one one-time signing offset is leaked key
 * material, not a policy breach.
 *
 * book:  process: k   /   current: <pub hex>
 *
 * usage: rotverify <config> <dispersal> <index> <baseDir>
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
  mlsCtx_t v;
  mlsHsh_t plug;
  unsigned char current[CM_SIGN_HSZ];
  unsigned char apex[CM_SIGN_HSZ];    /* the apex message's value: the signed hash of the signer's pub, the offset and the successor */
  unsigned char succ[CM_SIGN_HSZ];    /* the sign message's pub_hash: the successor pub */
  unsigned char recomputed[CM_SIGN_HSZ];
  unsigned char prior[CM_SIGN_HSZ];   /* the successor already installed for this dispersal */
  unsigned char *sig;
  FILE *of;
  char bpath[1024];
  char apexPath[1024];
  char signPath[1024];
  char ipath[1024];
  char apexName[64];                  /* the apex message's file name: the tag the sign message must carry */
  char tag[64];
  unsigned long bookProcess;
  unsigned long sgsz;
  unsigned int process;
  unsigned int idx;
  unsigned int off;
  int installed;                      /* the book already moved past this dispersal */
  int ok;
  int rc;

  cfg = 0;
  sig = 0;
  ok = 0;
  installed = 0;
  rc = 1;
  if (argc != 5) {
    fprintf(stderr, "usage: %s <config> <dispersal> <index> <baseDir>\n", argv[0]);
    return (1);
  }
  process = (unsigned int)atoi(argv[2]);
  idx = (unsigned int)atoi(argv[3]);

  if (!(cfg = malloc(sizeof (*cfg))) || cmCfgLoad(argv[1], cfg)) {
    fprintf(stderr, "%s: bad config %s\n", argv[0], argv[1]);
    goto done;
  }
  if (idx >= cfg->n - 1) {
    fprintf(stderr, "%s: index %u out of range (R=%u)\n", argv[0], idx, cfg->n - 1);
    goto done;
  }
  sprintf(bpath, "%s/priv/%02u_book.txt", argv[4], idx + 1);
  sprintf(apexName, "00_rotate_%02u_to_%02u_apex.txt", process, idx + 1);
  sprintf(apexPath, "%s/wire/rot/%s", argv[4], apexName);
  sprintf(signPath, "%s/wire/rot/00_rotate_%02u_to_%02u_sign.txt", argv[4], process, idx + 1);
  sprintf(ipath, "%s/priv/%02u_install_%02u.txt", argv[4], idx + 1, process);

  /* wire-tamper gate FIRST: nothing in either message is trusted until its
   * pairwise hmac passes; the apex needs its signature, so one failing
   * refuses the rotation */
  if (!cmHmacCheck(apexPath, cfg->mac[0], CM_PSK_LEN, 0, idx + 1)
   || !cmHmacCheck(signPath, cfg->mac[0], CM_PSK_LEN, 0, idx + 1)) {
    fprintf(stderr, "%s: seat %u dispersal %u REJECT: hmac (wire tamper)\n"
           ,argv[0], idx + 1, process);
    goto done;
  }

  if (cmGetU(bpath, "process", &bookProcess)) {
    fprintf(stderr, "%s: no book at %s\n", argv[0], bpath);
    goto done;
  }
  if (cmGetField(bpath, "current", current, CM_SIGN_HSZ) != CM_SIGN_HSZ
   || cmGetField(apexPath, "apex", apex, CM_SIGN_HSZ) != CM_SIGN_HSZ) {
    fprintf(stderr, "%s: malformed book or rotation\n", argv[0]);
    goto done;
  }
  if (bookProcess > process) {
    FILE *rf;
    char line[256];

    /* already installed: a copy presented again verifies against the pub that signed
     * the installed rotation.  The record must be the attempt that moved the
     * book (sig_ok: yes): a failed attempt writes one too, but only while the
     * book is still AT the dispersal, so a record found past it is the installer's */
    installed = 0;
    if ((rf = fopen(ipath, "r"))) {
      while (fgets(line, sizeof (line), rf))
        if (!strcmp(line, "sig_ok: yes\n"))
          installed = 1;
      fclose(rf);
    }
    if (!installed
     || cmGetField(ipath, "installed_new_current", prior, CM_SIGN_HSZ) != CM_SIGN_HSZ
     || cmGetField(ipath, "verified_against_current", current, CM_SIGN_HSZ) != CM_SIGN_HSZ) {
      fprintf(stderr, "%s: book at dispersal %lu, asked %u, no install record for it\n"
             ,argv[0], bookProcess, process);
      goto done;
    }
  } else if (bookProcess != process) {
    fprintf(stderr, "%s: book at dispersal %lu, asked %u\n", argv[0], bookProcess, process);
    goto done;
  }

  cmMlsPlug(&plug);
  v.h = &plug;
  v.s = CM_MLS_S;
  v.r = 0;
  sgsz = mlsSgSz(&v);
  if (!(sig = malloc(sgsz)))
    goto done;
  if (cmGetField(signPath, "mls_sig", sig, (unsigned int)sgsz) != (int)sgsz) {
    fprintf(stderr, "%s: malformed signature\n", argv[0]);
    goto done;
  }
  if (cmGetStr(signPath, "tag", tag, sizeof (tag)) < 0 || strcmp(tag, apexName)) {
    fprintf(stderr, "%s: seat %u dispersal %u REJECT: the sign message is not this apex message's\n"
           ,argv[0], idx + 1, process);
    goto done;
  }
  /* the sign message's pub_hash must hash to the apex under the pub this
   * book holds as current (or, past install, the pub the install record says signed
   * it) and the offset the signature yields: a payload's apex is the hash
   * of the signer's pub, the offset, its orig_hash and roots, so a value
   * signed as a payload is no successor pub's hash, whatever pub_hash a sign
   * message names, a rotation apex committed under another key of the
   * signer's does not recompute under this one, and one committed at
   * another offset does not recompute at this signature's */
  if (cmGetField(signPath, "pub_hash", succ, CM_SIGN_HSZ) != CM_SIGN_HSZ) {
    fprintf(stderr, "%s: malformed successor pub\n", argv[0]);
    goto done;
  }
  if (!cmMlsOff(sig, sgsz, &off)) {
    fprintf(stderr, "%s: seat %u dispersal %u REJECT: the signature yields no signing offset\n"
           ,argv[0], idx + 1, process);
    goto done;
  }
  cmApexRot(current, off, succ, recomputed);
  if (memcmp(recomputed, apex, CM_SIGN_HSZ)) {
    fprintf(stderr, "%s: seat %u dispersal %u REJECT: the sign message does not hash to the apex"
                    " (pub_hash under the current pub at the signature's offset is not this apex's preimage)\n", argv[0], idx + 1, process);
    goto done;
  }

  ok = off == CM_SLOT_ROT && cmMlsVerify(current, apex, sig, sgsz);   /* the offset class first: arithmetic */

  if (installed) {                /* the RETRY / re-authoring split */
    if (!ok)
      fprintf(stderr, "%s: seat %u dispersal %u REJECT: re-presented rotation does not verify"
                      " vs the pub that installed it at the rotation signing offset\n", argv[0], idx + 1, process);
    else if (memcmp(prior, succ, CM_SIGN_HSZ))
      fprintf(stderr, "%s: seat %u dispersal %u REJECT: re-authored (a second"
                      " successor at the rotation signing offset -- key compromise)\n"
             ,argv[0], idx + 1, process);
    else {
      fprintf(stderr, "%s: seat %u dispersal %u RETRY: byte-identical re-presentation"
                      " of the installed rotation (book unchanged)\n"
             ,argv[0], idx + 1, process);
      rc = 0;
    }
    goto done;
  }

  if (ok) {                       /* COMPLETE: install successor as new current */
    if (!(of = fopen(bpath, "w")))
      goto done;
    cmPutU(of, "process", process + 1);
    cmPutField(of, "current", succ, CM_SIGN_HSZ);
    fclose(of);
  }
  if ((of = fopen(ipath, "w"))) {
    fprintf(of, "phase: install\n");
    cmPutU(of, "system", idx + 1);
    cmPutU(of, "process", process);
    fprintf(of, "sig_ok: %s\n", ok ? "yes" : "no");
    cmPutField(of, "verified_against_current", current, CM_SIGN_HSZ);
    cmPutField(of, "installed_new_current", succ, CM_SIGN_HSZ);
    fclose(of);
  }

  fprintf(stderr, "%s: seat %u dispersal %u  %s\n", argv[0], idx + 1, process
         ,ok ? "ok: installed successor as new current"
             : off != CM_SLOT_ROT ? "BAD: signed at a payload signing offset, not the rotation's (signature not checked); book unchanged"
             : "BAD: signature does not verify vs current; book unchanged");
  rc = ok ? 0 : 1;
 done:
  if (cfg) memset(cfg, 0, sizeof (*cfg));  /* the dealt key mesh */
  free(cfg);
  free(sig);
  return (rc);
}
