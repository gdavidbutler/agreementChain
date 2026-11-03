/*
 * agreementChain - a chain of agreements
 * Copyright (C) 2026 G. David Butler <gdb@dbSystems.com>
 *
 * This file is part of agreementChain
 *
 * agreementChain is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * agreementChain is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/*
 * rsecFrmTest [seed [rounds]] - rsecFrm against what its header says,
 * standing alone.
 *
 *   the wire     one message at a time, every datagram against the one
 *                the header's wire format derives by hand, its parity
 *                from rsecEncode, its MACs from the callbacks; and each
 *                delivers once
 *   the streams  seeded runs from two senders' egresses to three
 *                destinations, unperturbed, with a small table, and with
 *                loss, duplication, reordering and corruption: each
 *                destination's datagrams deliver exactly its messages;
 *                every delivery anywhere is a message the test sent,
 *                byte for byte, or a loss notice of one, and the
 *                counters agree with what was delivered
 *   the header   by hand, on a clock the test owns and across its wrap:
 *                shard pacing, the pace from Sent, the packed sum, a
 *                packing that skips another address and goes on, an
 *                exact fit, one tag at an address in flight once, a
 *                datagram held until Sent, an idle egress, a full table
 *                refused once, refusals, m cut at 256 - k; a decode, a
 *                loss, the least recently fed evicted, and under
 *                tagOwner the sender's holding the most, a padding
 *                mismatch, a duplicate, the dedup horizon, dgramMax + 1,
 *                a mixed-sender datagram, the size functions
 *
 * The keyed tiers' callbacks judge what they are handed: the fragment
 * MAC covers its header, address and k, m and si with it; the datagram
 * MAC re-derives the fragments' offsets from the bytes and refuses a
 * datagram whose offsets the framer got wrong.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include "halfsiphash.h"
#include "rsec.h"
#include "rsecFrm.h"

static unsigned int Checks;
static unsigned int Fails;
static unsigned long Rng = 1;
static unsigned char GateKey[HALFSIPHASH_KEY_SZ];
static unsigned char AuthKey[256][HALFSIPHASH_KEY_SZ];
static unsigned char FrgKey[256][HALFSIPHASH_KEY_SZ];
static const unsigned char Dsts[][5] = {
  {4, 'd', 's', 't', '0'}
 ,{4, 'd', 's', 't', '1'}
 ,{4, 'd', 's', 't', '2'}
};
static struct rsecFrmIgrCtrs Reach;   /* the streams' counters, summed */

#define MAC  HALFSIPHASH_HSH_SZ
#define DLEN (sizeof (Dsts[0]))
#define NDST (sizeof (Dsts) / sizeof (Dsts[0]))

static void
check(
  int ok
 ,const char *fmt
 ,...
){
  va_list ap;

  ++Checks;
  if (ok)
    return;
  ++Fails;
  printf("FAIL: ");
  va_start(ap, fmt);
  vprintf(fmt, ap);
  va_end(ap);
  printf("\n");
}

/* xorshift32 */
static unsigned int
rnd(
  unsigned int n
){
  Rng ^= (Rng << 13) & 0xffffffffUL;
  Rng ^= Rng >> 17;
  Rng ^= (Rng << 5) & 0xffffffffUL;
  return (n ? Rng % n : 0);
}

struct cfg {
  const char *name;
  unsigned int dgramMax;
  unsigned int tagSize;
  unsigned int frgHmacSize;
  unsigned int dtgHmacSize;
  unsigned int dtgHashSize;
};

/* ac.c's tiers first: the gate and the datagram AUTH, a 7-byte tag */
static struct cfg Cfgs[] = {
  {"gate+auth", 508, 7, 0, MAC, MAC}
 ,{"none", 508, 4, 0, 0, 0}
 ,{"frg", 508, 4, MAC, 0, 0}
 ,{"all", 508, 5, MAC, MAC, MAC}
 ,{"small", 48, 3, 0, MAC, MAC}
};

/* the keyed tiers: the gate keys on its ctx, the others on the sender,
 * the tag's first byte, under their ctx's configuration */
static void
gateSign(
  void *k
 ,const unsigned char *adr
 ,unsigned char *dst
 ,const unsigned char *src
 ,unsigned int len
){
  (void)adr;
  halfsiphash(src, len, k, dst);
}

static int
gateVrfy(
  void *k
 ,const unsigned char *adr
 ,const unsigned char *mac
 ,const unsigned char *src
 ,unsigned int len
){
  unsigned char h[MAC];

  (void)adr;
  halfsiphash(src, len, k, h);
  return (!memcmp(h, mac, MAC));
}

/* the fragments' tag offsets from the bytes alone, as the wire defines
 * them: the datagram MAC's check on the framer's frgOff */
static unsigned int
offsets(
  const struct cfg *c
 ,const unsigned char *src
 ,unsigned int len
 ,unsigned int *off
 ,unsigned int cap
){
  unsigned int n;
  unsigned int sp;

  for (n = 0, sp = 0; n < cap && sp + c->tagSize + 5 + c->frgHmacSize <= len;) {
    unsigned int vo;
    unsigned int sz;
    unsigned int end;

    if (src[sp + c->tagSize] + 1 + src[sp + c->tagSize + 1] > 256)
      break;
    vo = sp + c->tagSize + 4;
    if (src[vo] & 0x80) {
      if (vo + 2 > len)
        break;
      sz = (((src[vo] & 0x7f) << 7) | (src[vo + 1] & 0x7f)) + 1;
      end = vo + 2 + sz + c->frgHmacSize;
    } else
      end = vo + 1 + src[vo] + c->frgHmacSize;
    if (end > len)
      break;
    off[n++] = sp;
    sp = end;
  }
  return (n);
}

static void
authSign(
  void *v
 ,const unsigned char *adr
 ,unsigned char *dst
 ,const unsigned char *src
 ,unsigned int len
 ,const unsigned int *frgOff
 ,unsigned int frgCnt
){
  unsigned int off[128];
  unsigned int n;

  (void)adr;
  if ((n = offsets(v, src, len, off, sizeof (off) / sizeof (off[0]))) != frgCnt
   || memcmp(off, frgOff, n * sizeof (off[0]))) {
    memset(dst, 0, MAC);
    return;
  }
  halfsiphash(src, len, AuthKey[src[0]], dst);
}

static int
authVrfy(
  void *v
 ,const unsigned char *adr
 ,const unsigned char *mac
 ,const unsigned char *src
 ,unsigned int len
 ,const unsigned int *frgOff
 ,unsigned int frgCnt
){
  unsigned char h[MAC];
  unsigned int off[128];
  unsigned int n;
  unsigned int i;

  (void)adr;
  if (!len
   || (n = offsets(v, src, len, off, sizeof (off) / sizeof (off[0]))) != frgCnt
   || memcmp(off, frgOff, n * sizeof (off[0])))
    return (0);
  halfsiphash(src, len, AuthKey[src[0]], h);
  if (memcmp(h, mac, MAC))
    return (0);
  for (i = 1; i < frgCnt; ++i)
    if (src[frgOff[i]] != src[0])
      return (0);
  return (1);
}

/* over [addrlen][addr][tag][k-1][m][si] and the fragment */
static void
frgMac(
  const struct cfg *c
 ,const unsigned char *hdr
 ,const unsigned char *src
 ,unsigned int len
 ,unsigned char *h
){
  unsigned char b[1024];
  unsigned int hl;

  hl = 1 + hdr[0] + c->tagSize + 3;
  if (hl + len > sizeof (b)) {
    memset(h, 0, MAC);
    return;
  }
  memcpy(b, hdr, hl);
  memcpy(b + hl, src, len);
  halfsiphash(b, hl + len, FrgKey[hdr[1 + hdr[0]]], h);
}

static void
frgSign(
  void *v
 ,const unsigned char *hdr
 ,unsigned char *dst
 ,const unsigned char *src
 ,unsigned int len
){
  frgMac(v, hdr, src, len, dst);
}

static int
frgVrfy(
  void *v
 ,const unsigned char *hdr
 ,const unsigned char *mac
 ,const unsigned char *src
 ,unsigned int len
){
  unsigned char h[MAC];

  frgMac(v, hdr, src, len, h);
  return (!memcmp(h, mac, MAC));
}

/* datagrams or deliveries: [addrlen][addr][...] */
struct item {
  unsigned char *b;
  unsigned int l;
};

struct list {
  struct item *i;
  unsigned int n;
  unsigned int cap;
};

static void
take(
  struct list *t
 ,unsigned char *b
 ,unsigned int l
){
  if (t->n == t->cap) {
    struct item *g;

    if (!(g = realloc(t->i, (t->cap ? 2 * t->cap : 64) * sizeof (*t->i)))) {
      fprintf(stderr, "out of memory at line %d\n", __LINE__);
      exit(2);
    }
    t->i = g;
    t->cap = t->cap ? 2 * t->cap : 64;
  }
  t->i[t->n].b = b;
  t->i[t->n++].l = l;
}

static void
add(
  struct list *t
 ,const unsigned char *b
 ,unsigned int l
){
  unsigned char *c;

  if (!(c = malloc(l ? l : 1))) {
    fprintf(stderr, "out of memory at line %d\n", __LINE__);
    exit(2);
  }
  memcpy(c, b, l);
  take(t, c, l);
}

static void
drop(
  struct list *t
){
  unsigned int i;

  for (i = 0; i < t->n; ++i)
    free(t->i[i].b);
  free(t->i);
  t->i = 0;
  t->n = t->cap = 0;
}

static void
setEgr(
  struct rsecFrmEgr *x
 ,struct cfg *c
 ,unsigned int tableSize
){
  memset(x, 0, sizeof (*x));
  x->realloc = realloc;
  x->free = free;
  x->dtgHashCtx = GateKey;
  x->dtgHashSign = gateSign;
  x->dtgHmacCtx = c;
  x->dtgHmacSign = authSign;
  x->frgHmacCtx = c;
  x->frgHmacSign = frgSign;
  x->dgramMax = c->dgramMax;
  x->tagSize = c->tagSize;
  x->tableSize = tableSize;
  x->frgHmacSize = c->frgHmacSize;
  x->dtgHmacSize = c->dtgHmacSize;
  x->dtgHashSize = c->dtgHashSize;
}

static void
setIgr(
  struct rsecFrmIgr *x
 ,struct cfg *c
 ,unsigned int tableSize
){
  memset(x, 0, sizeof (*x));
  x->realloc = realloc;
  x->free = free;
  x->dtgHashCtx = GateKey;
  x->dtgHashVrfy = gateVrfy;
  x->dtgHmacCtx = c;
  x->dtgHmacVrfy = authVrfy;
  x->frgHmacCtx = c;
  x->frgHmacVrfy = frgVrfy;
  x->dgramMax = c->dgramMax;
  x->tagSize = c->tagSize;
  x->tableSize = tableSize;
  x->frgHmacSize = c->frgHmacSize;
  x->dtgHmacSize = c->dtgHmacSize;
  x->dtgHashSize = c->dtgHashSize;
}

/* a message: [Dsts[d]][tag][m][delay_us][payload], the tag [sender][seq
 * hi][seq lo] and zeros */
static unsigned int
mkMsg(
  unsigned char *b
 ,const struct cfg *c
 ,unsigned int d
 ,unsigned int sender
 ,unsigned int seq
 ,unsigned int m
 ,unsigned long delay
 ,unsigned int len
){
  unsigned int p;
  unsigned int i;

  memcpy(b, Dsts[d], DLEN);
  p = DLEN;
  memset(b + p, 0, c->tagSize);
  b[p] = sender;
  b[p + 1] = seq >> 8;
  b[p + 2] = seq;
  p += c->tagSize;
  b[p++] = m;
  b[p++] = delay >> 24;
  b[p++] = delay >> 16;
  b[p++] = delay >> 8;
  b[p++] = delay;
  for (i = 0; i < len; ++i)
    b[p++] = rnd(256);
  return (p);
}

/* drain one datagram on the test's clock; 0 when none is scheduled */
static int
drainOne(
  struct rsecFrmEgr *x
 ,unsigned long *now
 ,struct list *out
){
  const unsigned char *d;
  unsigned long due;
  unsigned int l;

  if (!rsecFrmEgrDue(x, &due))
    return (0);
  if (due - *now < ~0UL / 2)
    *now = due;
  if (!(l = rsecFrmEgrGet(x, *now, &d))) {
    check(0, "a datagram due at its Due time");
    return (0);
  }
  add(out, d, l);
  rsecFrmEgrSent(x, *now);
  return (1);
}

static void
newIgr(
  struct cfg *c
 ,unsigned int tableSize
 ,const struct list *in
 ,struct list *out
 ,struct rsecFrmIgrCtrs *ctrs
){
  struct rsecFrmIgr y;
  unsigned int i;

  setIgr(&y, c, tableSize);
  if (!rsecFrmIgrInit(&y)) {
    fprintf(stderr, "init failed\n");
    exit(2);
  }
  for (i = 0; i < in->n; ++i) {
    unsigned char *d;
    unsigned int l;

    check(rsecFrmIgrPut(&y, in->i[i].b, in->i[i].b + 1 + in->i[i].b[0], in->i[i].l - 1 - in->i[i].b[0]) == 1
       , "%s: Put with nothing left to Get", c->name);
    while ((d = rsecFrmIgrGet(&y, &l)))
      take(out, d, l);
  }
  *ctrs = y.c;
  rsecFrmIgrFini(&y);
}

/* what a round sent: each message's tag, its payload, its k and its m
 * as the framer takes it */
struct corpus {
  unsigned char *pay[16];
  unsigned int len[16];
  unsigned int dst[16];
  unsigned int snd[16];
  unsigned int seq[16];
  unsigned int k[16];
  unsigned int m[16];
  unsigned int n;
};

/*
 * A stream through the ingress, judged on what it must be whatever the
 * stream: every delivery a message the corpus holds under its tag, byte
 * for byte, its rm the message's m and its um no more, or a loss notice
 * of one, rm 0 and um under its k; the counters the deliveries; with
 * every message's train whole (all), every message delivered.
 */
static void
selfCheck(
  struct cfg *c
 ,unsigned int r
 ,const char *what
 ,unsigned int tableSize
 ,const struct list *s
 ,const struct corpus *cp
 ,int all
){
  struct list b;
  struct rsecFrmIgrCtrs bc;
  unsigned char seen[16];
  unsigned int p;
  unsigned int nm;
  unsigned int nl;
  unsigned int i;
  unsigned int j;
  int ok;

  memset(&b, 0, sizeof (b));
  memset(seen, 0, sizeof (seen));
  newIgr(c, tableSize, s, &b, &bc);
  p = DLEN + c->tagSize;
  for (ok = 1, nm = nl = 0, i = 0; ok && i < b.n; ++i) {
    const unsigned char *d;
    unsigned int rm;
    unsigned int um;

    d = b.i[i].b;
    for (j = 0; j < NDST && memcmp(d, Dsts[j], DLEN); ++j)
      ;
    if (j == NDST || b.i[i].l < p + 2) {
      ok = 0;
      break;
    }
    rm = d[p];
    um = d[p + 1];
    for (j = 0; j < cp->n; ++j) {
      if (cp->snd[j] != d[DLEN] || cp->seq[j] >> 8 != d[DLEN + 1] || (cp->seq[j] & 0xff) != d[DLEN + 2])
        continue;
      if (!rm && um && b.i[i].l == p + 2 && um < cp->k[j])
        break;                          /* a loss notice of it */
      if (rm == cp->m[j] && um <= rm && b.i[i].l == p + 2 + cp->len[j]
       && !memcmp(d + p + 2, cp->pay[j], cp->len[j]))
        break;                          /* it */
    }
    if (j == cp->n)
      ok = 0;
    else if (!rm && um && b.i[i].l == p + 2)
      ++nl;
    else {
      ++nm;
      seen[j] = 1;
    }
  }
  check(ok, "%s round %u %s: delivery %u of %u is no message sent nor a loss of one", c->name, r, what, i, b.n);
  check(nm == bc.msg && nl == bc.evict && bc.dcd <= bc.msg
     , "%s round %u %s: counters msg %u evict %u dcd %u, delivered %u messages %u losses"
     , c->name, r, what, bc.msg, bc.evict, bc.dcd, nm, nl);
  if (all) {
    for (j = 0; j < cp->n && seen[j]; ++j)
      ;
    check(j == cp->n, "%s round %u %s: message %u of %u never delivered", c->name, r, what, j, cp->n);
  }
  Reach.frg += bc.frg;
  Reach.hash += bc.hash;
  Reach.dhmac += bc.dhmac;
  Reach.hmac += bc.hmac;
  Reach.dup += bc.dup;
  Reach.late += bc.late;
  Reach.msg += bc.msg;
  Reach.dcd += bc.dcd;
  Reach.evict += bc.evict;
  drop(&b);
}

/* percents a datagram: lost, duplicated, swapped with the one before, a
 * byte flipped; with none lost or flipped every train is whole */
static const struct perturb {
  const char *name;
  unsigned int loss;
  unsigned int dup;
  unsigned int swap;
  unsigned int bad;
} Perturbs[] = {
  {"loss 10", 10, 0, 0, 0}
 ,{"dup 30 swap 20", 0, 30, 20, 0}
 ,{"loss 30", 30, 0, 0, 0}
 ,{"loss 5 dup 10 swap 20 bad 10", 5, 10, 20, 10}
};

int
main(
  int argc
 ,char *argv[]
){
  unsigned int rounds;
  unsigned int ci;
  unsigned int r;
  unsigned int i;

  Rng = argc > 1 ? strtoul(argv[1], 0, 0) : 20261015UL;
  if (!(Rng &= 0xffffffffUL))
    Rng = 1;
  rounds = argc > 2 ? strtoul(argv[2], 0, 0) : 50;
  printf("rsecFrmTest seed %lu rounds %u\n", Rng, rounds);
  for (i = 0; i < sizeof (GateKey); ++i)
    GateKey[i] = rnd(256);
  for (r = 0; r < 256; ++r)
    for (i = 0; i < HALFSIPHASH_KEY_SZ; ++i) {
      AuthKey[r][i] = rnd(256);
      FrgKey[r][i] = rnd(256);
    }

  for (ci = 0; ci < sizeof (Cfgs) / sizeof (Cfgs[0]); ++ci) {
    static const unsigned int ms[] = {0, 2, 200};
    struct cfg *c;
    struct rsecFrmEgr x;
    struct rsecFrmIgr y;
    unsigned char *b;
    unsigned char *w;
    unsigned int lens[7];
    unsigned int shard;
    unsigned int mx;
    unsigned int li;
    unsigned int mi;
    unsigned int seq;

    c = &Cfgs[ci];
    shard = rsecFrmShard(c->dgramMax, c->tagSize, c->frgHmacSize, c->dtgHmacSize, c->dtgHashSize);
    mx = rsecFrmMax(c->dgramMax, c->tagSize, c->frgHmacSize, c->dtgHmacSize, c->dtgHashSize, 0);
    if (!(b = malloc(DLEN + c->tagSize + 5 + mx)) || !(w = malloc((unsigned long)256 * (1 + 255 + c->dgramMax)))) {
      fprintf(stderr, "out of memory at line %d\n", __LINE__);
      exit(2);
    }

    /* one message at a time, no delay: every datagram the one the
     * header's wire format derives, and each delivers once */
    lens[0] = 0;
    lens[1] = 1;
    lens[2] = shard - 1;
    lens[3] = shard;
    lens[4] = shard + 1;
    lens[5] = 5 * shard + 2;
    lens[6] = mx;
    setEgr(&x, c, 4);
    setIgr(&y, c, 16);
    if (!rsecFrmEgrInit(&x) || !rsecFrmIgrInit(&y)) {
      fprintf(stderr, "init failed\n");
      exit(2);
    }
    seq = 0;
    for (li = 0; li < sizeof (lens) / sizeof (lens[0]); ++li)
      for (mi = 0; mi < sizeof (ms) / sizeof (ms[0]); ++mi) {
        const unsigned char *dp[256];
        unsigned char *pp[256];
        struct list nw;
        struct list dl;
        unsigned long now;
        unsigned int frgOff[1];
        unsigned int stride;
        unsigned int hl;
        unsigned int ml;
        unsigned int k;
        unsigned int km;
        unsigned int mm;
        unsigned int sz;
        unsigned int pad;
        unsigned int p;
        int same;

        memset(&nw, 0, sizeof (nw));
        memset(&dl, 0, sizeof (dl));
        ml = mkMsg(b, c, 0, 1, ++seq, ms[mi], 0, lens[li]);
        k = lens[li] ? (lens[li] + shard - 1) / shard : 1;
        km = k + ms[mi] > 256 ? 256 : k + ms[mi];
        mm = km - k;
        now = 0;
        check(rsecFrmEgrPut(&x, b, ml, now) == 1, "%s: Put len %u m %u", c->name, lens[li], ms[mi]);
        while (drainOne(&x, &now, &nw));
        check(nw.n == km, "%s: len %u m %u: %u datagrams, k + m is %u", c->name, lens[li], ms[mi], nw.n, km);
        /* the wire by hand: [Dst][tag][k-1][m][si][pad][shard_len_vlq]
         * [shard][frgHmac], then the datagram AUTH and the GATE, shard
         * i of k data shards zero-padded and m parity shards */
        p = DLEN + c->tagSize;
        sz = lens[li] ? (lens[li] + k - 1) / k : 0;
        pad = k * sz - lens[li];
        hl = p + 4 + (sz < 128 ? 1 : 2);
        stride = hl + sz + c->frgHmacSize + c->dtgHmacSize + c->dtgHashSize;
        memset(w, 0, (unsigned long)km * stride);
        for (i = 0; i < km; ++i) {
          unsigned char *q;

          q = w + (unsigned long)i * stride;
          memcpy(q, b, p);
          q[p] = k - 1;
          q[p + 1] = mm;
          q[p + 2] = i;
          q[p + 3] = pad;
          if (sz < 128)
            q[p + 4] = sz;
          else {
            q[p + 4] = 0x80 | ((sz - 1) >> 7);
            q[p + 5] = (sz - 1) & 0x7f;
          }
          if (i < k) {
            if (i * sz < lens[li])
              memcpy(q + hl, b + p + 5 + i * sz, lens[li] - i * sz < sz ? lens[li] - i * sz : sz);
            dp[i] = q + hl;
          } else
            pp[i - k] = q + hl;
        }
        if (mm && sz)
          rsecEncode(dp, pp, sz, k, mm);
        frgOff[0] = 0;
        for (same = 1, i = 0; i < km; ++i) {
          unsigned char *q;
          unsigned int fl;

          q = w + (unsigned long)i * stride;
          fl = hl + sz - DLEN;
          if (c->frgHmacSize)
            frgMac(c, q, q + DLEN, fl, q + hl + sz);
          fl += c->frgHmacSize;
          if (c->dtgHmacSize)
            authSign(c, q, q + DLEN + fl, q + DLEN, fl, frgOff, 1);
          fl += c->dtgHmacSize;
          if (c->dtgHashSize)
            gateSign(GateKey, q, q + DLEN + fl, q + DLEN, fl);
          if (i >= nw.n || nw.i[i].l != stride || memcmp(nw.i[i].b, q, stride))
            same = 0;
        }
        check(same, "%s: len %u m %u: every datagram the wire format's, byte for byte", c->name, lens[li], ms[mi]);
        for (i = 0; i < nw.n; ++i) {
          unsigned char *d;
          unsigned int l;

          rsecFrmIgrPut(&y, nw.i[i].b, nw.i[i].b + 1 + nw.i[i].b[0], nw.i[i].l - 1 - nw.i[i].b[0]);
          while ((d = rsecFrmIgrGet(&y, &l)))
            take(&dl, d, l);
        }
        check(dl.n == 1 && dl.i[0].l == p + 2 + lens[li]
           && !memcmp(dl.i[0].b, b, p)
           && dl.i[0].b[p] == mm && !dl.i[0].b[p + 1]
           && !memcmp(dl.i[0].b + p + 2, b + p + 5, lens[li])
           , "%s: len %u m %u: delivered once, rm %u um 0", c->name, lens[li], ms[mi], mm);
        drop(&nw);
        drop(&dl);
      }
    rsecFrmEgrFini(&x);
    rsecFrmIgrFini(&y);
    free(w);

    /*
     * The rounds: each of two senders' egresses Puts a seeded run of
     * messages to three destinations, draining as it goes, and the two
     * streams interleave.  Unperturbed with distinct tags, each
     * destination's datagrams delivered at its own ingress are exactly
     * its messages; then the stream and its perturbations against the
     * reference.
     */
    for (r = 0; r < rounds; ++r) {
      struct rsecFrmEgr xs[2];
      struct corpus cp;
      struct list st[2];
      struct list s;
      unsigned long now[2];
      unsigned int sent[2];
      unsigned int lastSeq[2];
      unsigned int lastLen[2];
      unsigned int lastIdx[2];
      unsigned int nMsg;
      unsigned int j;
      int distinct;

      memset(st, 0, sizeof (st));
      memset(&s, 0, sizeof (s));
      for (j = 0; j < 2; ++j) {
        setEgr(&xs[j], c, 1 + rnd(4));
        if (!rsecFrmEgrInit(&xs[j])) {
          fprintf(stderr, "init failed\n");
          exit(2);
        }
        now[j] = 0;
        sent[j] = 0;
        lastSeq[j] = 0;
        lastLen[j] = 0;
        lastIdx[j] = 0;
      }
      nMsg = 2 + rnd(sizeof (cp.pay) / sizeof (cp.pay[0]) - 1);
      cp.n = nMsg;
      seq = 0;
      distinct = 1;
      for (i = 0; i < nMsg; ++i) {
        unsigned long delay;
        unsigned int len;
        unsigned int m;
        unsigned int q;
        unsigned int d;
        unsigned int ml;
        int rc;

        j = rnd(2);
        switch (rnd(8)) {
        case 0: len = 0; break;
        case 1: len = 1 + rnd(3); break;
        case 2: len = shard - 1 + rnd(3); break;
        case 3: len = 2 * shard + rnd(shard); break;
        case 4: len = rnd(mx / 8 + 1); break;
        default: len = rnd(4 * shard); break;
        }
        if (len > mx)
          len = mx;
        m = rnd(10) ? rnd(4) : 200 + rnd(56);
        delay = rnd(3) ? 0 : rnd(2000);
        d = rnd(NDST);
        q = ++seq;
        /* a re-send under the last tag: the same length, or within k;
         * at the same length the same bytes, as a re-send is */
        rc = 0;
        if (lastSeq[j] && !rnd(6)) {
          rc = 1;
          q = lastSeq[j];
          len = rnd(2) ? lastLen[j] : lastLen[j] + rnd(3);
          if (len > mx)
            len = mx;
          distinct = 0;
        }
        lastSeq[j] = q;
        lastLen[j] = len;
        ml = mkMsg(b, c, d, j, q, m, delay, len);
        if (rc && len == cp.len[lastIdx[j]])
          memcpy(b + DLEN + c->tagSize + 5, cp.pay[lastIdx[j]], len);
        lastIdx[j] = i;
        cp.len[i] = len;
        cp.dst[i] = d;
        cp.snd[i] = j;
        cp.seq[i] = q;
        cp.k[i] = len ? (len + shard - 1) / shard : 1;
        cp.m[i] = cp.k[i] + m > 256 ? 256 - cp.k[i] : m;
        if (!(cp.pay[i] = malloc(len ? len : 1))) {
          fprintf(stderr, "out of memory at line %d\n", __LINE__);
          exit(2);
        }
        memcpy(cp.pay[i], b + DLEN + c->tagSize + 5, len);
        while (!(rc = rsecFrmEgrPut(&xs[j], b, ml, now[j])))
          if (!drainOne(&xs[j], &now[j], &st[j]))
            break;
        /* 2: its tag still in the table, the re-send not taken */
        check(rc == 1 || (rc == 2 && q == lastSeq[j] && q != seq), "%s round %u: Put len %u m %u", c->name, r, len, m);
        if (rc == 1)
          ++sent[j];
        for (q = rnd(4); q; --q)
          drainOne(&xs[j], &now[j], &st[j]);
      }
      for (j = 0; j < 2; ++j) {
        while (drainOne(&xs[j], &now[j], &st[j]));
        check(xs[j].c.msg == sent[j], "%s round %u: sender %u: %u messages Sent, %u Put", c->name, r, j, xs[j].c.msg, sent[j]);
        rsecFrmEgrFini(&xs[j]);
      }
      /* interleave, each stream in its own order */
      for (i = j = 0; i < st[0].n || j < st[1].n;)
        if (j >= st[1].n || (i < st[0].n && rnd(2))) {
          take(&s, st[0].i[i].b, st[0].i[i].l);
          ++i;
        } else {
          take(&s, st[1].i[j].b, st[1].i[j].l);
          ++j;
        }
      free(st[0].i);
      free(st[1].i);

      if (distinct) {
        unsigned int got;
        unsigned int d;

        for (got = 0, d = 0; d < NDST; ++d) {
          struct list sd;
          struct list dd;
          struct rsecFrmIgrCtrs dc;
          unsigned int want;
          unsigned int at;

          memset(&sd, 0, sizeof (sd));
          memset(&dd, 0, sizeof (dd));
          for (i = 0; i < s.n; ++i)
            if (!memcmp(s.i[i].b, Dsts[d], DLEN))
              take(&sd, s.i[i].b, s.i[i].l);
          newIgr(c, 64, &sd, &dd, &dc);
          for (want = 0, i = 0; i < nMsg; ++i)
            want += cp.dst[i] == d;
          check(dd.n == want && !dc.dcd && !dc.evict && !dc.dup && !dc.hash && !dc.dhmac && !dc.hmac
             , "%s round %u: destination %u: %u of %u messages, clean", c->name, r, d, dd.n, want);
          for (at = 0; at < dd.n; ++at) {
            const unsigned char *t;

            t = dd.i[at].b + DLEN;
            for (i = 0; i < nMsg; ++i)
              if (cp.snd[i] == t[0] && cp.seq[i] >> 8 == t[1] && (cp.seq[i] & 0xff) == t[2])
                break;
            check(i < nMsg && cp.dst[i] == d && dd.i[at].l == DLEN + c->tagSize + 2 + cp.len[i]
               && !memcmp(dd.i[at].b + DLEN + c->tagSize + 2, cp.pay[i], cp.len[i])
               , "%s round %u: destination %u delivered its own message", c->name, r, d);
          }
          got += dd.n;
          free(sd.i);
          drop(&dd);
        }
        check(got == nMsg, "%s round %u: %u of %u messages, each at its destination", c->name, r, got, nMsg);
      }
      selfCheck(c, r, "table 64", 64, &s, &cp, distinct);
      selfCheck(c, r, "table 2", 2, &s, &cp, 0);
      for (j = 0; j < sizeof (Perturbs) / sizeof (Perturbs[0]); ++j) {
        const struct perturb *pt;
        struct list p;

        pt = &Perturbs[j];
        memset(&p, 0, sizeof (p));
        for (i = 0; i < s.n; ++i) {
          if (rnd(100) < pt->loss)
            continue;
          add(&p, s.i[i].b, s.i[i].l);
          /* a flip with no keyed tier is a message the test never sent */
          if (rnd(100) < pt->bad && (c->frgHmacSize || c->dtgHmacSize || c->dtgHashSize)) {
            unsigned int w;

            w = 1 + p.i[p.n - 1].b[0];
            if (p.i[p.n - 1].l > w + c->dtgHashSize) {
              unsigned char *q;
              unsigned int ql;

              q = p.i[p.n - 1].b + w;
              ql = p.i[p.n - 1].l - w - c->dtgHashSize;
              q[rnd(ql)] ^= 1 + rnd(255);
              /* half re-gated: the gate passes, the tiers inside judge */
              if (c->dtgHashSize && rnd(2))
                halfsiphash(q, ql, GateKey, q + ql);
            }
          }
          if (rnd(100) < pt->dup)
            add(&p, s.i[i].b, s.i[i].l);
          if (p.n > 1 && rnd(100) < pt->swap) {
            struct item t;

            t = p.i[p.n - 1];
            p.i[p.n - 1] = p.i[p.n - 2];
            p.i[p.n - 2] = t;
          }
        }
        if (!pt->loss && !pt->bad)
          selfCheck(c, r, pt->name, 64, &p, &cp, distinct);
        else
          selfCheck(c, r, pt->name, 1 + rnd(8), &p, &cp, 0);
        drop(&p);
      }
      for (i = 0; i < nMsg; ++i)
        free(cp.pay[i]);
      drop(&s);
    }
    free(b);
  }

  /* the header, by hand, on the "none" tiers */
  {
    static const unsigned long t0s[] = {0, ~0UL - 1500};
    struct cfg *c;
    struct rsecFrmEgr x;
    struct rsecFrmIgr y;
    struct rsecFrmIgrCtrs yc;
    struct list s;
    struct list d;
    const unsigned char *g;
    const unsigned char *g2;
    unsigned char *b;
    unsigned char *m;
    unsigned long due;
    unsigned long now;
    unsigned long t0;
    unsigned int shard;
    unsigned int ml;
    unsigned int l;
    unsigned int l2;
    unsigned int p;
    unsigned int ti;

    c = &Cfgs[1];
    shard = rsecFrmShard(c->dgramMax, c->tagSize, c->frgHmacSize, c->dtgHmacSize, c->dtgHashSize);
    if (!(b = malloc(DLEN + c->tagSize + 5 + 256 * shard + 1))) {
      fprintf(stderr, "out of memory at line %d\n", __LINE__);
      exit(2);
    }
    memset(&s, 0, sizeof (s));
    memset(&d, 0, sizeof (d));
    p = DLEN + c->tagSize;   /* a datagram's first fragment: [k-1][m][si] at p */

    /* pacing, from 0 and across the clock's wrap: k 3, m 1, 1000us;
     * shard i due at (i + 1) x 1000, and no sooner than the last Sent
     * plus its delay; the pace runs from the Sent, not the Get */
    for (ti = 0; ti < sizeof (t0s) / sizeof (t0s[0]); ++ti) {
      t0 = t0s[ti];
      setEgr(&x, c, 4);
      rsecFrmEgrInit(&x);
      ml = mkMsg(b, c, 0, 0, 1, 1, 1000, 3 * shard);
      check(rsecFrmEgrPut(&x, b, ml, t0) == 1, "pacing %u: Put", ti);
      check(rsecFrmEgrDue(&x, &due) && due == t0 + 1000, "pacing %u: first due + 1000, got + %lu", ti, due - t0);
      check(!rsecFrmEgrGet(&x, t0 + 999, &g), "pacing %u: nothing at + 999", ti);
      check(rsecFrmEgrGet(&x, t0 + 1000, &g) && g[p + 2] == 0, "pacing %u: shard 0 at + 1000", ti);
      rsecFrmEgrSent(&x, t0 + 1000);
      check(rsecFrmEgrDue(&x, &due) && due == t0 + 2000, "pacing %u: second due + 2000, got + %lu", ti, due - t0);
      check(rsecFrmEgrGet(&x, t0 + 2000, &g) && g[p + 2] == 1, "pacing %u: shard 1 at + 2000", ti);
      rsecFrmEgrSent(&x, t0 + 2500);
      check(rsecFrmEgrDue(&x, &due) && due == t0 + 3500, "pacing %u: third due from the Sent, + 2500 + 1000, got + %lu", ti, due - t0);
      check(!rsecFrmEgrGet(&x, t0 + 3499, &g), "pacing %u: nothing at + 3499", ti);
      check(rsecFrmEgrGet(&x, t0 + 3500, &g) && g[p + 2] == 2, "pacing %u: shard 2 at + 3500", ti);
      rsecFrmEgrSent(&x, t0 + 3500);
      check(rsecFrmEgrDue(&x, &due) && due == t0 + 4500, "pacing %u: parity due + 4500, got + %lu", ti, due - t0);
      check(rsecFrmEgrGet(&x, t0 + 4500, &g) && g[p + 2] == 3, "pacing %u: shard 3, the parity", ti);
      /* held: the same datagram until Sent, due at once */
      check(rsecFrmEgrGet(&x, t0 + 9000, &g2) && g2 == g, "held %u: Get again, the same datagram", ti);
      check(rsecFrmEgrDue(&x, &due) && due == t0 + 4500, "held %u: due when got, got + %lu", ti, due - t0);
      check(x.c.frg == 3 && !x.c.msg, "held %u: nothing counted until Sent, frg %u msg %u", ti, x.c.frg, x.c.msg);
      rsecFrmEgrSent(&x, t0 + 4500);
      check(!rsecFrmEgrDue(&x, &due), "pacing %u: nothing left", ti);
      check(x.c.msg == 1 && x.c.frg == 4, "pacing %u: msg 1 frg 4, got %u %u", ti, x.c.msg, x.c.frg);
      check(x.c.wait == 4500, "pacing %u: the longest wait, Put to its last shard Sent, 4500us, got %lu", ti, x.c.wait);
      /* idle past half the clock beyond the pace's end: the pace is
       * long spent, never read as a time still ahead */
      now = t0 + 4500 + 1000 + ~0UL / 2 + 100;
      ml = mkMsg(b, c, 0, 0, 2, 0, 0, 10);
      rsecFrmEgrPut(&x, b, ml, now);
      check(rsecFrmEgrDue(&x, &due) && due == now && rsecFrmEgrGet(&x, now, &g)
         , "idle %u: after half the clock, due at once", ti);
      rsecFrmEgrSent(&x, now);
      rsecFrmEgrFini(&x);
    }

    /* packing: at 100 only the shard due then; at 300 the two due then
     * ride one datagram, and the next waits their delays' sum, 600 */
    setEgr(&x, c, 4);
    rsecFrmEgrInit(&x);
    ml = mkMsg(b, c, 0, 0, 1, 0, 100, 10);
    rsecFrmEgrPut(&x, b, ml, 0);
    ml = mkMsg(b, c, 0, 0, 2, 0, 300, 10);
    rsecFrmEgrPut(&x, b, ml, 0);
    ml = mkMsg(b, c, 0, 0, 3, 0, 300, 10);
    rsecFrmEgrPut(&x, b, ml, 0);
    check(rsecFrmEgrDue(&x, &due) && due == 100, "packing: due 100, got %lu", due);
    l = rsecFrmEgrGet(&x, 100, &g);
    check(l == DLEN + c->tagSize + 5 + 10, "packing: at 100 the one shard due, %u bytes", l);
    rsecFrmEgrSent(&x, 100);
    check(rsecFrmEgrDue(&x, &due) && due == 300, "packing: then due 300, got %lu", due);
    l = rsecFrmEgrGet(&x, 300, &g);
    check(l == DLEN + 2 * (c->tagSize + 5 + 10), "packing: two fragments in one datagram, %u bytes", l);
    rsecFrmEgrSent(&x, 300);
    check(!rsecFrmEgrDue(&x, &due) && x.c.msg == 3 && x.c.frg == 3, "packing: all three messages Sent");
    ml = mkMsg(b, c, 0, 0, 4, 0, 0, 10);
    rsecFrmEgrPut(&x, b, ml, 300);
    check(rsecFrmEgrDue(&x, &due) && due == 900, "packing: next waits the sum, due 900, got %lu", due);
    rsecFrmEgrFini(&x);

    /* packing by address: A and C to destination 0, B between them to
     * 1, all due: A and C ride together past B, and B alone to its own */
    setEgr(&x, c, 4);
    rsecFrmEgrInit(&x);
    ml = mkMsg(b, c, 0, 0, 1, 0, 0, 10);
    rsecFrmEgrPut(&x, b, ml, 0);
    ml = mkMsg(b, c, 1, 0, 2, 0, 0, 10);
    rsecFrmEgrPut(&x, b, ml, 0);
    ml = mkMsg(b, c, 0, 0, 3, 0, 0, 10);
    rsecFrmEgrPut(&x, b, ml, 0);
    l = rsecFrmEgrGet(&x, 0, &g);
    check(l == DLEN + 2 * (c->tagSize + 5 + 10) && !memcmp(g, Dsts[0], DLEN)
       && g[DLEN + 2] == 1 && g[DLEN + c->tagSize + 5 + 10 + 2] == 3
       , "address: A and C to destination 0, past B");
    rsecFrmEgrSent(&x, 0);
    l = rsecFrmEgrGet(&x, 0, &g);
    check(l == DLEN + c->tagSize + 5 + 10 && !memcmp(g, Dsts[1], DLEN) && g[DLEN + 2] == 2
       , "address: B alone to destination 1");
    rsecFrmEgrSent(&x, 0);
    rsecFrmEgrFini(&x);

    /* an exact fit: fragments of 210 and 298 bytes fill 508; one byte
     * more and they do not */
    for (ti = 0; ti < 2; ++ti) {
      setEgr(&x, c, 4);
      rsecFrmEgrInit(&x);
      ml = mkMsg(b, c, 0, 0, 1, 0, 0, 200);
      rsecFrmEgrPut(&x, b, ml, 0);
      ml = mkMsg(b, c, 0, 0, 2, 0, 0, 288 + ti);
      rsecFrmEgrPut(&x, b, ml, 0);
      l = rsecFrmEgrGet(&x, 0, &g);
      rsecFrmEgrSent(&x, 0);
      check(ti ? l == DLEN + c->tagSize + 6 + 200 : l == DLEN + c->dgramMax
         , "fit: %s, %u bytes", ti ? "one byte over, apart" : "exactly, together", l);
      rsecFrmEgrFini(&x);
    }

    /* one tag at an address in flight once */
    setEgr(&x, c, 4);
    rsecFrmEgrInit(&x);
    ml = mkMsg(b, c, 0, 0, 1, 0, 0, 10);
    check(rsecFrmEgrPut(&x, b, ml, 0) == 1 && rsecFrmEgrPut(&x, b, ml, 0) == 2 && x.c.again == 1
       , "one tag: a second Put while the first is in the table is not taken");
    ml = mkMsg(b, c, 1, 0, 1, 0, 0, 10);
    check(rsecFrmEgrPut(&x, b, ml, 0) == 1, "one tag: the same tag to another address is taken");
    l = rsecFrmEgrGet(&x, 0, &g);
    rsecFrmEgrSent(&x, 0);
    l2 = rsecFrmEgrGet(&x, 0, &g);
    rsecFrmEgrSent(&x, 0);
    check(l == DLEN + c->tagSize + 5 + 10 && l == l2 && x.c.frg == 2 && x.c.msg == 2
       , "one tag: one datagram each address");
    ml = mkMsg(b, c, 0, 0, 1, 0, 0, 10);
    check(rsecFrmEgrPut(&x, b, ml, 0) == 1 && x.c.again == 1, "one tag: taken again once the first is Sent");
    rsecFrmEgrFini(&x);

    /* a full table: refused, counted once a run of refusals */
    setEgr(&x, c, 2);
    rsecFrmEgrInit(&x);
    ml = mkMsg(b, c, 0, 0, 1, 0, 0, 10);
    rsecFrmEgrPut(&x, b, ml, 0);
    ml = mkMsg(b, c, 0, 0, 2, 0, 0, 10);
    rsecFrmEgrPut(&x, b, ml, 0);
    ml = mkMsg(b, c, 0, 0, 3, 0, 0, 10);
    check(rsecFrmEgrPut(&x, b, ml, 0) == 0 && rsecFrmEgrPut(&x, b, ml, 0) == 0 && x.c.full == 1
       , "full: refused twice, counted once, full %u", x.c.full);
    check(rsecFrmEgrGet(&x, 0, &g) == DLEN + 2 * (c->tagSize + 5 + 10), "full: the two packed");
    check(rsecFrmEgrPut(&x, b, ml, 0) == 0, "full: a slot frees at Sent, not at Get");
    rsecFrmEgrSent(&x, 0);
    check(rsecFrmEgrPut(&x, b, ml, 0) == 1 && x.c.full == 1, "full: taken after the Sent");
    ml = mkMsg(b, c, 0, 0, 4, 0, 0, 10);
    check(rsecFrmEgrPut(&x, b, ml, 0) == 1, "full: the second slot the Sent freed");
    ml = mkMsg(b, c, 0, 0, 5, 0, 0, 10);
    check(rsecFrmEgrPut(&x, b, ml, 0) == 0 && x.c.full == 2, "full: the next run counted, full %u", x.c.full);
    rsecFrmEgrFini(&x);

    /* refusals, and m cut to 256 - k */
    setEgr(&x, c, 2);
    rsecFrmEgrInit(&x);
    check(rsecFrmEgrPut(&x, b, 0, 0) == -1, "refused: empty");
    check(rsecFrmEgrPut(&x, b, p + 4, 0) == -1, "refused: short of m and the delay");
    ml = mkMsg(b, c, 0, 0, 1, 0, 0, 256 * shard + 1);
    check(rsecFrmEgrPut(&x, b, ml, 0) == -1, "refused: past rsecFrmMax");
    ml = mkMsg(b, c, 0, 0, 1, 20, 0, 250 * shard);
    check(rsecFrmEgrPut(&x, b, ml, 0) == 1, "m cut: Put k 250 m 20");
    for (i = 0; rsecFrmEgrGet(&x, 0, &g); ++i) {
      if (!i)
        check(g[p + 1] == 6, "m cut: m 6 on the wire, got %u", g[p + 1]);
      rsecFrmEgrSent(&x, 0);
    }
    check(i == 256, "m cut: 256 shards, got %u", i);
    rsecFrmEgrFini(&x);
    setEgr(&x, c, 2);
    x.dgramMax = c->tagSize + 6;
    check(!rsecFrmEgrInit(&x), "Init refuses a datagram no shard fits");
    setEgr(&x, c, 0);
    check(!rsecFrmEgrInit(&x), "Init refuses a table of 0");

    /* a decode: k 4 m 2, data shards 1 and 2 lost; pad 3 */
    setEgr(&x, c, 4);
    rsecFrmEgrInit(&x);
    ml = mkMsg(b, c, 0, 0, 1, 2, 0, 4 * shard - 3);
    rsecFrmEgrPut(&x, b, ml, 0);
    now = 0;
    while (drainOne(&x, &now, &s));
    rsecFrmEgrFini(&x);
    free(s.i[1].b);
    free(s.i[2].b);
    s.i[1] = s.i[3];
    s.i[2] = s.i[4];
    s.i[3] = s.i[5];
    s.n = 4;
    setIgr(&y, c, 4);
    rsecFrmIgrInit(&y);
    for (i = 0; i < s.n; ++i) {
      rsecFrmIgrPut(&y, s.i[i].b, s.i[i].b + DLEN, s.i[i].l - DLEN);
      while ((m = rsecFrmIgrGet(&y, &l)))
        take(&d, m, l);
    }
    check(d.n == 1 && d.i[0].l == p + 2 + 4 * shard - 3 && d.i[0].b[p] == 2 && d.i[0].b[p + 1] == 2
       && !memcmp(d.i[0].b + p + 2, b + p + 5, 4 * shard - 3) && y.c.dcd == 1
       , "decode: two data shards lost, delivered, rm 2 um 2");
    rsecFrmIgrFini(&y);
    drop(&d);

    /* a loss: a table of 1, two of four shards, then another tag */
    setIgr(&y, c, 1);
    rsecFrmIgrInit(&y);
    rsecFrmIgrPut(&y, s.i[0].b, s.i[0].b + DLEN, s.i[0].l - DLEN);
    check(!rsecFrmIgrGet(&y, &l), "loss: one shard, nothing yet");
    rsecFrmIgrPut(&y, s.i[1].b, s.i[1].b + DLEN, s.i[1].l - DLEN);
    drop(&s);
    setEgr(&x, c, 4);
    rsecFrmEgrInit(&x);
    ml = mkMsg(b, c, 0, 0, 2, 0, 0, 10);
    rsecFrmEgrPut(&x, b, ml, 0);
    now = 0;
    drainOne(&x, &now, &s);
    rsecFrmEgrFini(&x);
    check(rsecFrmIgrPut(&y, s.i[0].b, s.i[0].b + DLEN, s.i[0].l - DLEN) == 1, "loss: Put");
    {
      unsigned char *m1;
      unsigned int l1;

      m1 = rsecFrmIgrGet(&y, &l1);
      check(!rsecFrmIgrPut(&y, s.i[0].b, s.i[0].b + DLEN, s.i[0].l - DLEN), "loss: Put refused with one left to Get");
      m = rsecFrmIgrGet(&y, &l);
      check(m1 && l1 == p + 2 && m1[DLEN + 2] == 1 && m1[p] == 0 && m1[p + 1] == 2 && y.c.evict == 1
         , "loss: the evicted entry first, rm 0 um 2");
      check(m && l == p + 2 + 10 && m[DLEN + 2] == 2 && !rsecFrmIgrGet(&y, &l)
         , "loss: then the new tag's message");
      free(m1);
      free(m);
    }
    rsecFrmIgrFini(&y);
    drop(&s);

    /* the least recently fed evicted: a table of 2, A and B of k 3 one
     * shard each, then A fed again; a new tag C evicts B, not A, and
     * delivers.  A padding mismatch: E of k 2, shard 497, pad 1, one
     * shard, then a shard of E' under its tag, one byte longer -- the
     * same k and shard, pad 0 -- evicts E and assembles E'.
     * A duplicate: F of k 2, its first shard twice, one delivery */
    {
      static const struct {
        unsigned int seq;
        unsigned int len;
      } ms[] = {{1, 0}, {2, 0}, {3, 10}, {5, 1}, {5, 2}, {7, 0}};
      struct list sm[sizeof (ms) / sizeof (ms[0])];
      unsigned char *pe;
      unsigned char *m1;
      unsigned char *m2;
      unsigned int l1;

      if (!(pe = malloc(2 * shard))) {
        fprintf(stderr, "out of memory at line %d\n", __LINE__);
        exit(2);
      }
      for (i = 0; i < sizeof (ms) / sizeof (ms[0]); ++i) {
        unsigned int len;

        len = ms[i].len == 1 ? 2 * shard - 3 : ms[i].len == 2 ? 2 * shard - 2 : ms[i].len ? ms[i].len
            : ms[i].seq == 7 ? 2 * shard : 3 * shard;
        memset(&sm[i], 0, sizeof (sm[i]));
        setEgr(&x, c, 4);
        rsecFrmEgrInit(&x);
        ml = mkMsg(b, c, 0, 0, ms[i].seq, 0, 0, len);
        if (ms[i].len == 2)
          memcpy(pe, b + p + 5, len);
        rsecFrmEgrPut(&x, b, ml, 0);
        now = 0;
        while (drainOne(&x, &now, &sm[i]));
        rsecFrmEgrFini(&x);
      }
      setIgr(&y, c, 2);
      rsecFrmIgrInit(&y);
      rsecFrmIgrPut(&y, sm[0].i[0].b, sm[0].i[0].b + DLEN, sm[0].i[0].l - DLEN);
      rsecFrmIgrPut(&y, sm[1].i[0].b, sm[1].i[0].b + DLEN, sm[1].i[0].l - DLEN);
      rsecFrmIgrPut(&y, sm[0].i[1].b, sm[0].i[1].b + DLEN, sm[0].i[1].l - DLEN);
      check(!rsecFrmIgrGet(&y, &l), "lru: three shards, nothing yet");
      rsecFrmIgrPut(&y, sm[2].i[0].b, sm[2].i[0].b + DLEN, sm[2].i[0].l - DLEN);
      m1 = rsecFrmIgrGet(&y, &l1);
      m2 = rsecFrmIgrGet(&y, &l);
      check(m1 && l1 == p + 2 && m1[DLEN + 2] == 2 && !m1[p] && m1[p + 1] == 1 && y.c.evict == 1
         , "lru: B evicted, the least recently fed, rm 0 um 1");
      check(m2 && l == p + 2 + 10 && m2[DLEN + 2] == 3, "lru: then C delivered");
      free(m1);
      free(m2);
      rsecFrmIgrFini(&y);
      /* the sender holding the most: a table of 3 under tagOwner, A of
       * sender 0 and B and C of sender 1, one shard each of k 3; sender
       * 1's new tags D and E evict B and C, its own, never A, the least
       * recently fed, and A then delivers */
      {
        struct list so[5];
        unsigned int ev[2];
        unsigned int ne;

        for (i = 0; i < 5; ++i) {
          memset(&so[i], 0, sizeof (so[i]));
          setEgr(&x, c, 4);
          rsecFrmEgrInit(&x);
          ml = mkMsg(b, c, 0, i ? 1 : 0, 11 + i, 0, 0, 3 * shard);
          rsecFrmEgrPut(&x, b, ml, 0);
          now = 0;
          while (drainOne(&x, &now, &so[i]));
          rsecFrmEgrFini(&x);
        }
        setIgr(&y, c, 3);
        y.tagOwner = 1;
        rsecFrmIgrInit(&y);
        ne = ev[0] = ev[1] = 0;
        for (i = 0; i < 5; ++i) {
          rsecFrmIgrPut(&y, so[i].i[0].b, so[i].i[0].b + DLEN, so[i].i[0].l - DLEN);
          while ((m1 = rsecFrmIgrGet(&y, &l1))) {
            if (ne < 2 && l1 == p + 2 && !m1[p])
              ev[ne] = m1[DLEN + 2];
            ++ne;
            free(m1);
          }
        }
        check(ne == 2 && ev[0] == 12 && ev[1] == 13 && y.c.evict == 2
           , "owner: sender 1's new tags evict its own, B then C");
        rsecFrmIgrPut(&y, so[0].i[1].b, so[0].i[1].b + DLEN, so[0].i[1].l - DLEN);
        rsecFrmIgrPut(&y, so[0].i[2].b, so[0].i[2].b + DLEN, so[0].i[2].l - DLEN);
        m1 = rsecFrmIgrGet(&y, &l1);
        check(m1 && l1 == p + 2 + 3 * shard && m1[DLEN + 2] == 11 && !rsecFrmIgrGet(&y, &l)
           , "owner: then A, sender 0's, delivered");
        free(m1);
        rsecFrmIgrFini(&y);
        /* a delivered entry before one in flight: a table of 3 under
         * tagOwner, all sender 1's: A of k 3 one shard, fed first, then
         * B and C of k 1, delivered; a new tag D evicts B, no loss, and
         * A's last two shards then deliver A */
        {
          struct list sd[4];

          for (i = 0; i < 4; ++i) {
            memset(&sd[i], 0, sizeof (sd[i]));
            setEgr(&x, c, 4);
            rsecFrmEgrInit(&x);
            ml = mkMsg(b, c, 0, 1, 21 + i, 0, 0, i ? 10 : 3 * shard);
            rsecFrmEgrPut(&x, b, ml, 0);
            now = 0;
            while (drainOne(&x, &now, &sd[i]));
            rsecFrmEgrFini(&x);
          }
          setIgr(&y, c, 3);
          y.tagOwner = 1;
          rsecFrmIgrInit(&y);
          ne = 0;
          for (i = 0; i < 4; ++i) {
            rsecFrmIgrPut(&y, sd[i].i[0].b, sd[i].i[0].b + DLEN, sd[i].i[0].l - DLEN);
            while ((m1 = rsecFrmIgrGet(&y, &l1))) {
              ++ne;
              free(m1);
            }
          }
          check(ne == 3 && !y.c.evict, "delivered first: B, C and D delivered, nothing lost");
          rsecFrmIgrPut(&y, sd[0].i[1].b, sd[0].i[1].b + DLEN, sd[0].i[1].l - DLEN);
          rsecFrmIgrPut(&y, sd[0].i[2].b, sd[0].i[2].b + DLEN, sd[0].i[2].l - DLEN);
          m1 = rsecFrmIgrGet(&y, &l1);
          check(m1 && l1 == p + 2 + 3 * shard && m1[DLEN + 2] == 21 && !rsecFrmIgrGet(&y, &l)
             , "delivered first: then A, in flight, delivered");
          free(m1);
          for (i = 0; i < 4; ++i)
            drop(&sd[i]);
        }
        rsecFrmIgrFini(&y);
        for (i = 0; i < 5; ++i)
          drop(&so[i]);
      }
      setIgr(&y, c, 4);
      rsecFrmIgrInit(&y);
      rsecFrmIgrPut(&y, sm[3].i[0].b, sm[3].i[0].b + DLEN, sm[3].i[0].l - DLEN);
      rsecFrmIgrPut(&y, sm[4].i[0].b, sm[4].i[0].b + DLEN, sm[4].i[0].l - DLEN);
      m1 = rsecFrmIgrGet(&y, &l1);
      check(m1 && l1 == p + 2 && m1[DLEN + 2] == 5 && !m1[p] && m1[p + 1] == 1 && !rsecFrmIgrGet(&y, &l)
         , "mismatch: a pad of 0 under E's tag evicts E, rm 0 um 1");
      free(m1);
      rsecFrmIgrPut(&y, sm[4].i[1].b, sm[4].i[1].b + DLEN, sm[4].i[1].l - DLEN);
      m1 = rsecFrmIgrGet(&y, &l1);
      check(m1 && l1 == p + 2 + 2 * shard - 2 && !memcmp(m1 + p + 2, pe, 2 * shard - 2)
         , "mismatch: E' assembled, its own length");
      free(m1);
      rsecFrmIgrFini(&y);
      setIgr(&y, c, 4);
      rsecFrmIgrInit(&y);
      rsecFrmIgrPut(&y, sm[5].i[0].b, sm[5].i[0].b + DLEN, sm[5].i[0].l - DLEN);
      rsecFrmIgrPut(&y, sm[5].i[0].b, sm[5].i[0].b + DLEN, sm[5].i[0].l - DLEN);
      rsecFrmIgrPut(&y, sm[5].i[1].b, sm[5].i[1].b + DLEN, sm[5].i[1].l - DLEN);
      m1 = rsecFrmIgrGet(&y, &l1);
      check(m1 && !rsecFrmIgrGet(&y, &l) && y.c.dup == 1 && y.c.msg == 1, "dup: a shard twice, one delivery, dup 1");
      free(m1);
      rsecFrmIgrFini(&y);
      for (i = 0; i < sizeof (ms) / sizeof (ms[0]); ++i)
        drop(&sm[i]);
      free(pe);
    }

    /*
     * Hostile fragments under the keyless tiers, each in a buffer of
     * exactly its length: a shard index at k + m; k + m past 256; a
     * padding past k x shard ahead of a good fragment in one datagram;
     * a 2-byte VLQ cut at the end.  None is taken, and the good one and
     * a good shard after them deliver once.  An m mismatch under one
     * tag evicts.  Under the gate, a datagram short of a fragment is
     * dropped uncounted.
     */
    {
      unsigned char *h;
      unsigned char *m1;
      unsigned int hl;
      unsigned int l1;

      setIgr(&y, c, 4);
      rsecFrmIgrInit(&y);
      /* [tag 4][k-1][m][si][pad][vlq][data] */
      hl = 4 + 5 + 64;
      if (!(h = malloc(2 * hl))) {
        fprintf(stderr, "out of memory at line %d\n", __LINE__);
        exit(2);
      }
      memset(h, 0, 2 * hl);
      h[0] = 0; h[2] = 20;                  /* tag: sender 0, seq 20 */
      h[4] = 0; h[5] = 0; h[6] = 1; h[7] = 0; h[8] = 64;   /* k 1, m 0, si 1 */
      rsecFrmIgrPut(&y, Dsts[0], h, hl);
      check(!rsecFrmIgrGet(&y, &l1) && y.c.frg == 1 && !y.c.msg, "hostile: a shard index at k + m, not taken");
      h[4] = 200; h[5] = 100; h[6] = 0;     /* k 201, m 100 */
      rsecFrmIgrPut(&y, Dsts[0], h, hl);
      check(!rsecFrmIgrGet(&y, &l1) && y.c.frg == 2 && !y.c.msg, "hostile: k + m past 256, not taken");
      {
        struct rsecFrmIgr y1;
        unsigned char *g1;

        /* nor kept: in a table of 1, the next good message evicts
         * nothing */
        setIgr(&y1, c, 1);
        rsecFrmIgrInit(&y1);
        rsecFrmIgrPut(&y1, Dsts[0], h, hl);
        if (!(g1 = malloc(hl))) {
          fprintf(stderr, "out of memory at line %d\n", __LINE__);
          exit(2);
        }
        memset(g1, 0, hl);
        g1[2] = 23;
        g1[8] = 64;
        rsecFrmIgrPut(&y1, Dsts[0], g1, hl);
        m1 = rsecFrmIgrGet(&y1, &l1);
        check(m1 && l1 == p + 2 + 64 && !rsecFrmIgrGet(&y1, &l) && !y1.c.evict && y1.c.msg == 1
           , "hostile: k + m past 256 held nowhere, the next message evicts nothing");
        free(m1);
        free(g1);
        rsecFrmIgrFini(&y1);
      }
      h[4] = 0; h[5] = 0; h[6] = 0; h[7] = 65;   /* pad 65 > 1 x 64, then a good fragment */
      memcpy(h + hl, h, hl);
      h[hl + 2] = 21;
      h[hl + 7] = 0;
      h[hl + 9] = 'g';
      rsecFrmIgrPut(&y, Dsts[0], h, 2 * hl);
      m1 = rsecFrmIgrGet(&y, &l1);
      check(m1 && l1 == p + 2 + 64 && m1[DLEN + 2] == 21 && m1[p + 2] == 'g' && !rsecFrmIgrGet(&y, &l)
         && y.c.frg == 4 && y.c.msg == 1, "hostile: a padding past k x shard skipped, the good fragment behind it taken");
      free(m1);
      free(h);
      if (!(h = malloc(4 + 5))) {
        fprintf(stderr, "out of memory at line %d\n", __LINE__);
        exit(2);
      }
      memset(h, 0, 4 + 5);
      h[2] = 22;
      h[8] = 0x81;                          /* a 2-byte VLQ, its second byte past the end */
      rsecFrmIgrPut(&y, Dsts[0], h, 4 + 5);
      check(!rsecFrmIgrGet(&y, &l1) && y.c.frg == 5 && y.c.msg == 1, "hostile: a VLQ cut at the end, not taken");
      free(h);
      rsecFrmIgrFini(&y);
      /* an m mismatch: G k 2 m 0 one shard, then G' under its tag with
       * m 2, a parity shard: G evicted, nothing written past it */
      {
        struct list sg;
        struct list sg2;

        memset(&sg, 0, sizeof (sg));
        memset(&sg2, 0, sizeof (sg2));
        setEgr(&x, c, 4);
        rsecFrmEgrInit(&x);
        ml = mkMsg(b, c, 0, 0, 30, 0, 0, 2 * shard);
        rsecFrmEgrPut(&x, b, ml, 0);
        now = 0;
        while (drainOne(&x, &now, &sg));
        rsecFrmEgrFini(&x);
        setEgr(&x, c, 4);
        rsecFrmEgrInit(&x);
        ml = mkMsg(b, c, 0, 0, 30, 2, 0, 2 * shard);
        rsecFrmEgrPut(&x, b, ml, 0);
        now = 0;
        while (drainOne(&x, &now, &sg2));
        rsecFrmEgrFini(&x);
        setIgr(&y, c, 4);
        rsecFrmIgrInit(&y);
        rsecFrmIgrPut(&y, sg.i[0].b, sg.i[0].b + DLEN, sg.i[0].l - DLEN);
        rsecFrmIgrPut(&y, sg2.i[2].b, sg2.i[2].b + DLEN, sg2.i[2].l - DLEN);
        m1 = rsecFrmIgrGet(&y, &l1);
        check(m1 && l1 == p + 2 && !m1[p] && m1[p + 1] == 1 && y.c.evict == 1 && !rsecFrmIgrGet(&y, &l)
           , "mismatch: an m of 2 under G's tag evicts G, rm 0 um 1");
        free(m1);
        rsecFrmIgrFini(&y);
        drop(&sg);
        drop(&sg2);
      }
      /* under the gate: short of one fragment, dropped uncounted */
      {
        struct cfg *cg;

        cg = &Cfgs[4];
        setIgr(&y, cg, 4);
        rsecFrmIgrInit(&y);
        if (!(h = malloc(3))) {
          fprintf(stderr, "out of memory at line %d\n", __LINE__);
          exit(2);
        }
        memset(h, 0, 3);
        rsecFrmIgrPut(&y, Dsts[0], h, 3);
        check(!rsecFrmIgrGet(&y, &l1) && !y.c.frg && !y.c.hash && !y.c.dhmac, "hostile: a datagram short of a fragment, dropped uncounted");
        free(h);
        rsecFrmIgrFini(&y);
      }
    }

    /* the size functions, against their own arithmetic by hand: the
     * overhead is the tag, the three MACs and 6 */
    check(rsecFrmShard(508, 7, 0, 20, 4) == 471 && rsecFrmShard(508, 4, 0, 0, 0) == 498
       && rsecFrmMax(508, 4, 0, 0, 0, 6) == 124500 && !rsecFrmShard(10, 4, 0, 0, 0)
       && rsecFrmShard(16394, 4, 0, 0, 0) == 16384 && !rsecFrmShard(16395, 4, 0, 0, 0)
       && !rsecFrmMax(10, 4, 0, 0, 0, 0)
       , "size: shard and max by hand");

    /* the dedup horizon: k 1 m 2, each shard twice: s0 delivers, s0 s1
     * late, s1 again past k + m starts afresh and delivers by decode,
     * s2 s2 late */
    setEgr(&x, c, 4);
    rsecFrmEgrInit(&x);
    ml = mkMsg(b, c, 0, 0, 1, 2, 0, 10);
    rsecFrmEgrPut(&x, b, ml, 0);
    now = 0;
    while (drainOne(&x, &now, &s));
    rsecFrmEgrFini(&x);
    setIgr(&y, c, 4);
    rsecFrmIgrInit(&y);
    for (i = 0; i < 6; ++i) {
      rsecFrmIgrPut(&y, s.i[i / 2].b, s.i[i / 2].b + DLEN, s.i[i / 2].l - DLEN);
      while ((m = rsecFrmIgrGet(&y, &l)))
        take(&d, m, l);
    }
    check(d.n == 2 && y.c.msg == 2 && y.c.dcd == 1 && y.c.late == 4 && !y.c.dup
       , "dedup: delivered twice, late 4, got %u msg %u dcd %u late %u dup %u", d.n, y.c.msg, y.c.dcd, y.c.late, y.c.dup);
    for (i = 0; i < d.n; ++i)
      check(d.i[i].l == p + 2 + 10 && !memcmp(d.i[i].b + p + 2, b + p + 5, 10), "dedup: delivery %u the message", i);
    rsecFrmIgrFini(&y);
    drop(&d);
    drop(&s);

    /* past dgramMax: a good datagram with more fragments behind it,
     * dropped whole and uncounted at dgramMax + 1; at dgramMax each
     * copy, k 1 m 0, is a re-send past its train, delivered again */
    {
      unsigned char *big;
      unsigned int bl;

      setEgr(&x, c, 4);
      rsecFrmEgrInit(&x);
      ml = mkMsg(b, c, 0, 0, 9, 0, 0, 10);
      rsecFrmEgrPut(&x, b, ml, 0);
      l = rsecFrmEgrGet(&x, 0, &g) - DLEN;
      if (!(big = malloc(c->dgramMax + l))) {
        fprintf(stderr, "out of memory at line %d\n", __LINE__);
        exit(2);
      }
      for (bl = 0; bl <= c->dgramMax; bl += l)
        memcpy(big + bl, g + DLEN, l);
      rsecFrmEgrSent(&x, 0);
      rsecFrmEgrFini(&x);
      setIgr(&y, c, 4);
      rsecFrmIgrInit(&y);
      check(rsecFrmIgrPut(&y, Dsts[0], big, c->dgramMax + 1) == 1 && !rsecFrmIgrGet(&y, &l2) && !y.c.frg
         , "oversize: dgramMax + 1 bytes, dropped uncounted");
      check(rsecFrmIgrPut(&y, Dsts[0], big, c->dgramMax) == 1, "oversize: at dgramMax, taken");
      for (i = 0; (m = rsecFrmIgrGet(&y, &l2)); ++i)
        free(m);
      /* the cut copy's header is parsed, its end refused */
      check(i == c->dgramMax / l && i == y.c.msg
         && y.c.frg == i + (c->dgramMax % l >= c->tagSize + 5)
         , "oversize: at dgramMax the same bytes parse, %u copies, %u delivered, frg %u", c->dgramMax / l, i, y.c.frg);
      rsecFrmIgrFini(&y);
      free(big);
    }

    /* a mixed-sender datagram: refused at the AUTH, in both */
    c = &Cfgs[0];
    setEgr(&x, c, 4);
    rsecFrmEgrInit(&x);
    ml = mkMsg(b, c, 0, 0, 1, 0, 0, 10);
    rsecFrmEgrPut(&x, b, ml, 0);
    ml = mkMsg(b, c, 0, 1, 2, 0, 0, 10);
    rsecFrmEgrPut(&x, b, ml, 0);
    now = 0;
    drainOne(&x, &now, &s);
    rsecFrmEgrFini(&x);
    check(s.n == 1 && s.i[0].l == DLEN + 2 * (c->tagSize + 5 + 10) + 2 * MAC, "mixed: two senders packed in one datagram");
    newIgr(c, 4, &s, &d, &yc);
    check(!d.n && yc.dhmac == 1, "mixed: refused at the AUTH, dhmac %u", yc.dhmac);
    drop(&d);
    drop(&s);
    free(b);
  }

  /* what the streams reached: every counter, or they judged nothing
   * there */
  printf("reach: frg %u hash %u dhmac %u hmac %u dup %u late %u msg %u dcd %u evict %u\n"
    , Reach.frg, Reach.hash, Reach.dhmac, Reach.hmac, Reach.dup, Reach.late, Reach.msg, Reach.dcd, Reach.evict);
  check(Reach.frg && Reach.hash && Reach.dhmac && Reach.hmac && Reach.dup
     && Reach.late && Reach.msg && Reach.dcd && Reach.evict, "the streams reached every counter");
  printf("%u checks, %u failed\n", Checks, Fails);
  return (Fails ? 1 : 0);
}
