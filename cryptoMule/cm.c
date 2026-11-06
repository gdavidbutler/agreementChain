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
 * cryptoMule - shared mechanics for the phase programs.
 * See cm.h for the pipeline and layering rationale.
 */

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include "cm.h"

void
cmHexEnc(
  const unsigned char *b
 ,unsigned int l
 ,char *o
){
  const char *hx;
  unsigned int i;

  hx = "0123456789abcdef";
  for (i = 0; i < l; ++i) {
    o[2 * i] = hx[b[i] >> 4];
    o[2 * i + 1] = hx[b[i] & 0xf];
  }
}

int
cmHexDec(
  const char *h
 ,unsigned char *o
 ,unsigned int max
){
  unsigned int n;

  for (n = 0; n < max; ++n) {
    unsigned char v;
    char c;

    c = h[2 * n];
    if (c >= '0' && c <= '9') v = c - '0';
    else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
    else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
    else break;
    o[n] = v << 4;
    c = h[2 * n + 1];
    if (c >= '0' && c <= '9') v = c - '0';
    else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
    else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
    else break;
    o[n] |= v;
  }
  /* the hex run must end the field (the line's newline, or the NUL of a
   * token): a run longer than the reader's bound, a non-hex tail, or a
   * dangling nibble is malformed, never "the first n bytes of it" -- every
   * reader tests for an exact count, and a tail silently dropped here would
   * pass that test */
  if (h[2 * n] != '\n' && h[2 * n] != '\0')
    return (-1);
  return ((int)n);
}

int
cmCfgLoad(
  const char *path
 ,cmCfg *c
){
  FILE *f;
  char key[16];
  int rc;

  if (!(f = fopen(path, "r")))
    return (-1);
  rc = -1;
  memset(c, 0, sizeof (*c));
  while (fscanf(f, "%15s", key) == 1) {
    if (!strcmp(key, "N")) {
      if (fscanf(f, "%u", &c->n) != 1) goto done;
    } else if (!strcmp(key, "T")) {
      if (fscanf(f, "%u", &c->t) != 1) goto done;
    } else if (!strcmp(key, "psk")) {
      unsigned int q;                        /* recipient seat id (this seat's row) */
      char hx[2 * CM_PSK_LEN + 1];
      if (fscanf(f, "%u", &q) != 1 || q >= CM_MAXPROC) goto done;
      if (fscanf(f, "%128s", hx) != 1
       || cmHexDec(hx, c->psk[q], CM_PSK_LEN) != CM_PSK_LEN) goto done;
      c->pskHave[q] = 1;
    } else if (!strcmp(key, "mac")) {        /* static pairwise wire-hmac PSK */
      unsigned int q;
      char hx[2 * CM_PSK_LEN + 1];
      if (fscanf(f, "%u", &q) != 1 || q >= CM_MAXPROC) goto done;
      if (fscanf(f, "%128s", hx) != 1
       || cmHexDec(hx, c->mac[q], CM_PSK_LEN) != CM_PSK_LEN) goto done;
      c->macHave[q] = 1;
    } else if (!strcmp(key, "genesis")) {    /* public chain base, dealt to all */
      char hx[2 * CM_SIGN_HSZ + 1];
      if (fscanf(f, "%32s", hx) != 1
       || cmHexDec(hx, c->genesis, CM_SIGN_HSZ) != CM_SIGN_HSZ) goto done;
      c->genesisHave = 1;
    } else
      goto done;
  }
  /* the deal's bounds, one home for every program: N >= 3 (the initiator
   * and two others), T > 1 (SSS drives censorship
   * resistance, and at T = 1 there is none), T <= R, N within GF(2^8) */
  if (c->n < 3 || c->t < 2 || c->t > c->n - 1 || c->n > CM_MAXPROC)
    goto done;
  rc = 0;
 done:
  fclose(f);
  return (rc);
}

int
cmKeystateLoad(
  const char *path
 ,cmCfg *c
){
  unsigned int q;
  char name[16];

  for (q = 0; q < c->n; ++q) {               /* load only the pair(s) present */
    sprintf(name, "psk_%02u", q);            /* recipient seat id q (self-relative) */
    if (cmGetField(path, name, c->psk[q], CM_PSK_LEN) == CM_PSK_LEN)
      c->pskHave[q] = 1;
    else if (c->pskHave[q])                  /* never the dealt row in its place */
      return (-1);
  }
  return (0);
}

int
cmFloorLoad(
  const char *path
 ,cmCfg *c
 ,unsigned long *process
){
  unsigned int q;
  unsigned int got;
  char name[16];

  if (cmGetU(path, "floor", process))
    return (-1);
  for (got = 0, q = 0; q < c->n; ++q) {      /* load only the pair(s) present */
    sprintf(name, "fpsk_%02u", q);
    if (cmGetField(path, name, c->psk[q], CM_PSK_LEN) == CM_PSK_LEN) {
      c->pskHave[q] = 1;
      ++got;
    } else if (c->pskHave[q])                /* never the dealt row in its place */
      return (-1);
  }
  return (got ? 0 : -1);
}

void
cmKsPath(
  const char *cfgPath
 ,char *out
){
  char *p;

  strcpy(out, cfgPath);
  if ((p = strstr(out, "_config.txt")))
    strcpy(p, "_keystate.txt");
}

void
cmRatchet(
  const unsigned char *prev
 ,unsigned int prevLen
 ,const unsigned char *hk
 ,unsigned char *next
 ,unsigned int nextLen
){
  unsigned char info[CM_SIGN_HSZ + 1];

  memcpy(info, hk, CM_SIGN_HSZ);
  info[CM_SIGN_HSZ] = CM_DOM_RAT;
  CM_KDF(prev, prevLen, info, sizeof (info), next, nextLen);
}

static void *
cmRmd128Alloc(
  void
){
  return (malloc(rmd128tsize()));
}

void
cmSssMkPlug(
  sssMkHsh_t *p
){
  p->a = cmRmd128Alloc;
  p->i = (void (*)(void *))rmd128init;
  p->u = (void (*)(void *, const unsigned char *, unsigned int))rmd128update;
  p->f = (void (*)(void *, unsigned char *))rmd128final;
  p->d = free;
  p->h = CM_SSS_H;
}

void
cmRsecMkPlug(
  rsecMkHsh_t *p
){
  p->a = cmRmd128Alloc;
  p->i = (void (*)(void *))rmd128init;
  p->u = (void (*)(void *, const unsigned char *, unsigned int))rmd128update;
  p->f = (void (*)(void *, unsigned char *))rmd128final;
  p->d = free;
  p->h = CM_RSEC_H;
}

void
cmMlsPlug(
  mlsHsh_t *p
){
  p->a = cmRmd128Alloc;
  p->i = (void (*)(void *))rmd128init;
  p->u = (void (*)(void *, const unsigned char *, unsigned int))rmd128update;
  p->f = (void (*)(void *, unsigned char *))rmd128final;
  p->d = free;
  p->h = CM_SIGN_H;
}

void
cmHash(
  const unsigned char *b
 ,unsigned int l
 ,unsigned char *o
){
  mlsHsh_t p;
  void *c;

  cmMlsPlug(&p);
  if (!(c = p.a()))
    return;
  p.i(c);
  p.u(c, b, l);
  p.f(c, o);
  p.d(c);
}

void
cmChain(
  const unsigned char *prev
 ,const unsigned char *msg
 ,unsigned char *o
){
  mlsHsh_t p;
  void *c;

  cmMlsPlug(&p);
  if (!(c = p.a()))
    return;
  p.i(c);
  p.u(c, prev, CM_SIGN_HSZ);
  p.u(c, msg, CM_SIGN_HSZ);
  p.f(c, o);
  p.d(c);
}

void
cmApex(
  const unsigned char *signerPub
 ,unsigned int off
 ,const unsigned char *origHash
 ,const unsigned char *rsecRoot
 ,const unsigned char *sssRoot
 ,unsigned char *o
){
  mlsHsh_t p;
  void *c;
  unsigned char ob[4];

  cmMlsPlug(&p);
  if (!(c = p.a()))
    return;
  ob[0] = off >> 24;                   /* the signing offset, 4 bytes big-endian */
  ob[1] = off >> 16;
  ob[2] = off >> 8;
  ob[3] = off;
  p.i(c);
  p.u(c, signerPub, CM_SIGN_HSZ);
  p.u(c, ob, sizeof (ob));
  p.u(c, origHash, CM_SIGN_HSZ);
  p.u(c, rsecRoot, CM_RSEC_HSZ);
  p.u(c, sssRoot, CM_SSS_HSZ);
  p.f(c, o);
  p.d(c);
}

void
cmApexRot(
  const unsigned char *signerPub
 ,unsigned int off
 ,const unsigned char *succPub
 ,unsigned char *o
){
  mlsHsh_t p;
  void *c;
  unsigned char ob[4];

  cmMlsPlug(&p);
  if (!(c = p.a()))
    return;
  ob[0] = off >> 24;                   /* the signing offset, 4 bytes big-endian */
  ob[1] = off >> 16;
  ob[2] = off >> 8;
  ob[3] = off;
  p.i(c);
  p.u(c, signerPub, CM_SIGN_HSZ);
  p.u(c, ob, sizeof (ob));
  p.u(c, succPub, CM_SIGN_HSZ);
  p.f(c, o);
  p.d(c);
}

void
cmKeystream(
  const unsigned char *k
 ,unsigned int kl
 ,const unsigned char *nonce
 ,unsigned char *buf
 ,unsigned int len
){
  unsigned char info[CM_SIGN_HSZ + 1 + 4];
  unsigned char ks[255 * CM_KDF_HSZ];
  unsigned int seg;
  unsigned int off;
  unsigned int chunk;

  memcpy(info, nonce, CM_SIGN_HSZ);
  info[CM_SIGN_HSZ] = CM_DOM_KEY;
  chunk = 0;
  for (seg = 0, off = 0; off < len; ++seg, off += chunk) {
    unsigned int j;

    chunk = len - off;
    if (chunk > sizeof (ks))
      chunk = sizeof (ks);
    info[CM_SIGN_HSZ + 1] = (unsigned char)(seg >> 24);
    info[CM_SIGN_HSZ + 2] = (unsigned char)(seg >> 16);
    info[CM_SIGN_HSZ + 3] = (unsigned char)(seg >> 8);
    info[CM_SIGN_HSZ + 4] = (unsigned char)seg;
    CM_KDF(k, kl, info, sizeof (info), ks, chunk);
    for (j = 0; j < chunk; ++j)
      buf[off + j] ^= ks[j];
  }
}

void
cmGeometry(
  const unsigned char *seed
 ,unsigned int n
 ,unsigned char *pts
){
  unsigned char info[2];
  unsigned char st[255 * CM_KDF_HSZ];
  unsigned int got;
  unsigned int seg;

  info[0] = CM_DOM_GEO;
  for (got = 0, seg = 0; got < n; ++seg) {
    unsigned int i;

    info[1] = (unsigned char)seg;
    CM_KDF(seed, CM_SEED_LEN, info, sizeof (info), st, sizeof (st));
    for (i = 0; i < sizeof (st) && got < n; ++i) {
      unsigned int e;
      int dup;

      for (dup = 0, e = 0; e < got; ++e)
        if (pts[e] == st[i]) { dup = 1; break; }
      if (!dup)
        pts[got++] = st[i];
    }
  }
}

void
cmMask(
  const unsigned char *ikm
 ,unsigned int ikml
 ,const unsigned char *apex
 ,unsigned char dom
 ,unsigned char idx
 ,unsigned char *buf
 ,unsigned int len
){
  unsigned char info[CM_SIGN_HSZ + 1 + 1];
  unsigned char m[255 * CM_KDF_HSZ];
  unsigned int j;

  memcpy(info, apex, CM_SIGN_HSZ);
  info[CM_SIGN_HSZ] = dom;
  info[CM_SIGN_HSZ + 1] = idx;
  CM_KDF(ikm, ikml, info, sizeof (info), m, len);
  for (j = 0; j < len; ++j)
    buf[j] ^= m[j];
}

int
cmHmacAppend(
  const char *path
 ,const unsigned char *key
 ,unsigned int kl
 ,unsigned char s
 ,unsigned char r
){
  FILE *f;
  unsigned char *b;
  unsigned char h[CM_HMAC_SZ];
  unsigned long len;
  long lt;
  int rc;

  if (!(f = fopen(path, "rb")))
    return (-1);
  b = 0;
  rc = -1;
  if (fseek(f, 0, SEEK_END) || (lt = ftell(f)) < 0
   || (unsigned long)lt > UINT_MAX - 2 - (6 + 2 * CM_HMAC_SZ + 1))
    goto done;                                /* not a file, or past what its reader takes, sealed */
  len = (unsigned long)lt;
  rewind(f);
  if (!len || !(b = malloc(len + 2)) || fread(b + 2, 1, len, f) != len)
    goto done;
  fclose(f);
  b[0] = s;
  b[1] = r;
  CM_HMAC(key, kl, b, (unsigned int)(len + 2), h);
  if (!(f = fopen(path, "a")))
    goto done;
  cmPutField(f, "hmac", h, CM_HMAC_SZ);
  rc = 0;
 done:
  if (f) fclose(f);
  free(b);
  return (rc);
}

int
cmHmacCheck(
  const char *path
 ,const unsigned char *key
 ,unsigned int kl
 ,unsigned char s
 ,unsigned char r
){
  FILE *f;
  unsigned char *b;
  unsigned char h[CM_HMAC_SZ];
  char hx[2 * CM_HMAC_SZ];
  unsigned long len;
  unsigned long tag;    /* offset of the trailing "hmac: ..." line */
  unsigned long tl;
  unsigned int i;
  unsigned int d;
  long lt;
  int ok;

  if (!(f = fopen(path, "rb")))
    return (0);
  b = 0;
  ok = 0;
  /* a length the hmac can cover whole, from a seekable file: anything else
   * (a FIFO where a file should be, a length past what one hmac takes) is
   * refused before a byte is trusted, never hashed in part */
  if (fseek(f, 0, SEEK_END) || (lt = ftell(f)) < 0 || (unsigned long)lt > UINT_MAX - 2)
    goto done;
  len = (unsigned long)lt;
  rewind(f);
  tl = 6 + 2 * CM_HMAC_SZ + 1;                /* "hmac: " + hex + '\n' */
  if (len <= tl || !(b = malloc(len + 2)) || fread(b + 2, 1, len, f) != len)
    goto done;
  tag = len - tl;                             /* the hmac field must be LAST */
  if (b[2 + tag - 1] != '\n' || memcmp(b + 2 + tag, "hmac: ", 6)
   || b[2 + len - 1] != '\n')
    goto done;
  b[0] = s;                                   /* fold the edge: no cross-edge replay */
  b[1] = r;
  CM_HMAC(key, kl, b, (unsigned int)(tag + 2), h);
  /* the field as written, whole: it has one form, so an altered copy of a
   * message cannot pass, and no early exit says how much of it matched */
  cmHexEnc(h, CM_HMAC_SZ, hx);
  for (d = 0, i = 0; i < sizeof (hx); ++i)
    d |= hx[i] ^ b[2 + tag + 6 + i];
  ok = !d;
 done:
  fclose(f);
  free(b);
  return (ok);
}

int
cmMlsSign(
  const char *privPath
 ,unsigned int slot
 ,const unsigned char *anchor
 ,unsigned char **sigOut
 ,unsigned long *sigLenOut
 ,unsigned char *pub
){
  mlsCtx_t v;
  mlsHsh_t plug;
  FILE *f;
  unsigned char *work;
  unsigned char *sig;
  unsigned char *p;
  unsigned long prsz;
  unsigned long wasz;
  unsigned long sgsz;
  unsigned long got;
  int rc;

  cmMlsPlug(&plug);
  v.h = &plug;
  v.s = CM_MLS_S;
  v.r = 0;
  work = sig = 0;
  rc = -1;
  prsz = mlsPrSz(&v);
  wasz = mlsWaSz(&v);
  sgsz = mlsSgSz(&v);
  if (!prsz || !wasz || !sgsz)
    return (-1);
  if (!(v.r = malloc(prsz)) || !(work = malloc(wasz)) || !(sig = malloc(sgsz)))
    goto done;
  if (!(f = fopen(privPath, "rb")))
    goto done;
  for (got = 0; got < prsz; ) {
    size_t n;

    if (!(n = fread(v.r + got, 1, prsz - got, f)))
      break;
    got += n;
  }
  fclose(f);
  if (got != prsz)
    goto done;
  if (!(p = mlsHash(&v, work)))         /* derive signer pub */
    goto done;
  memcpy(pub, p, CM_SIGN_HSZ);
  if (!mlsSign(&v, work, anchor, sig, slot))  /* reuse work: pub already copied */
    goto done;
  *sigOut = sig;
  sig = 0;
  *sigLenOut = sgsz;
  rc = 0;
 done:
  if (v.r) { memset(v.r, 0, prsz); free(v.r); }
  free(work);
  free(sig);
  return (rc);
}

int
cmMlsVerify(
  const unsigned char *pub
 ,const unsigned char *anchor
 ,const unsigned char *sig
 ,unsigned long sigLen
 ,unsigned int *off
){
  mlsHsh_t plug;
  unsigned char *work;
  unsigned char *p;
  unsigned int ewsz;
  unsigned int o;
  int ok;

  cmMlsPlug(&plug);
  if (mlsEgSz(CM_SIGN_H, sig, (unsigned int)sigLen) != sigLen
   || !(ewsz = mlsEwSz(CM_SIGN_H, sig, (unsigned int)sigLen))
   || !(work = malloc(ewsz)))
    return (0);
  ok = (p = mlsExtract(&plug, work, anchor, sig)) != 0 && !memcmp(p, pub, CM_SIGN_HSZ);
  free(work);
  if (!ok)
    return (0);
  if (!(o = mlsEgOf(CM_SIGN_H, sig, (unsigned int)sigLen)))  /* 0 == error sentinel */
    return (0);
  *off = o - 1;
  return (1);
}

int
cmMlsOff(
  const unsigned char *sig
 ,unsigned long sigLen
 ,unsigned int *off
){
  unsigned int o;

  if (mlsEgSz(CM_SIGN_H, sig, sigLen) != sigLen
   || !(o = mlsEgOf(CM_SIGN_H, sig, sigLen)))  /* 0 == error sentinel */
    return (0);
  *off = o - 1;
  return (1);
}

int
cmMlsPub(
  const char *privPath
 ,unsigned char *pub
){
  mlsCtx_t v;
  mlsHsh_t plug;
  FILE *f;
  unsigned char *work;
  unsigned char *p;
  unsigned long prsz;
  unsigned long wasz;
  unsigned long got;
  int rc;

  cmMlsPlug(&plug);
  v.h = &plug;
  v.s = CM_MLS_S;
  v.r = 0;
  work = 0;
  rc = -1;
  prsz = mlsPrSz(&v);
  wasz = mlsWaSz(&v);
  if (!prsz || !wasz)
    return (-1);
  if (!(v.r = malloc(prsz)) || !(work = malloc(wasz)))
    goto done;
  if (!(f = fopen(privPath, "rb")))
    goto done;
  for (got = 0; got < prsz; ) {
    size_t n;

    if (!(n = fread(v.r + got, 1, prsz - got, f)))
      break;
    got += n;
  }
  fclose(f);
  if (got != prsz)
    goto done;
  if (!(p = mlsHash(&v, work)))
    goto done;
  memcpy(pub, p, CM_SIGN_HSZ);
  rc = 0;
 done:
  if (v.r) { memset(v.r, 0, prsz); free(v.r); }
  free(work);
  return (rc);
}

void
cmPutField(
  FILE *f
 ,const char *name
 ,const unsigned char *b
 ,unsigned int l
){
  unsigned int i;

  fprintf(f, "%s: ", name);
  for (i = 0; i < l; ++i)
    fprintf(f, "%02x", b[i]);
  fputc('\n', f);
}

void
cmPutU(
  FILE *f
 ,const char *name
 ,unsigned long v
){
  fprintf(f, "%s: %lu\n", name, v);
}

int
cmGetField(
  const char *path
 ,const char *name
 ,unsigned char *out
 ,unsigned int max
){
  FILE *f;
  char *line;
  unsigned int nl;
  unsigned int cap;
  int rc;

  cap = 1U << 18; /* 256 KB: holds large shard/signature hex lines */
  if (!(line = malloc(cap)))
    return (-1);
  if (!(f = fopen(path, "r"))) {
    free(line);
    return (-1);
  }
  rc = -1;
  nl = strlen(name);
  while (fgets(line, (int)cap, f))
    if (!strncmp(line, name, nl) && line[nl] == ':' && line[nl + 1] == ' ') {
      rc = cmHexDec(line + nl + 2, out, max);
      break;
    }
  fclose(f);
  free(line);
  return (rc);
}

int
cmGetU(
  const char *path
 ,const char *name
 ,unsigned long *v
){
  FILE *f;
  char line[256];
  unsigned int nl;
  int rc;

  if (!(f = fopen(path, "r")))
    return (-1);
  rc = -1;
  nl = strlen(name);
  while (fgets(line, sizeof (line), f))
    if (!strncmp(line, name, nl) && line[nl] == ':' && line[nl + 1] == ' ') {
      char *e;

      /* exactly what cmPutU writes -- a canonical digit run to the end of the
       * line, in range: strtoul alone reads "" or "zz" as 0, a sign, a blank
       * or a leading zero as a number, and an overflow as ULONG_MAX; a run
       * longer than the line buffer is malformed, never a truncation */
      if (line[nl + 2] >= '0' && line[nl + 2] <= '9') {
        errno = 0;
        *v = strtoul(line + nl + 2, &e, 10);
        if (*e == '\n' && !errno && (line[nl + 2] != '0' || e == line + nl + 3))
          rc = 0;
      }
      break;
    }
  fclose(f);
  return (rc);
}

int
cmGetStr(
  const char *path
 ,const char *name
 ,char *out
 ,unsigned int max
){
  FILE *f;
  char line[256];
  unsigned int nl;
  int rc;

  if (!(f = fopen(path, "r")))
    return (-1);
  rc = -1;
  nl = strlen(name);
  while (fgets(line, sizeof (line), f))
    if (!strncmp(line, name, nl) && line[nl] == ':' && line[nl + 1] == ' ') {
      char *v;
      unsigned int l;

      /* the text runs to the end of the line, within the line buffer and the
       * caller's: a line longer than either is malformed, never a truncation */
      v = line + nl + 2;
      l = strlen(v);
      if (l && v[l - 1] == '\n' && l <= max) {
        v[--l] = 0;
        strcpy(out, v);
        rc = l;
      }
      break;
    }
  fclose(f);
  return (rc);
}
