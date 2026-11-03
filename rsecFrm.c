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

#include <string.h>
#include "rsec.h"
#include "rsecFrm.h"

/* a after b on a clock that wraps; a schedule and a pace each stay
 * under a quarter of its range, so every pair compared is within half */
#define AFTER(a, b) ((b) - (a) > ~0UL / 2)
#define QUARTER (~0UL / 4)

/*
 * A fragment's fixed overhead: [k-1][m][si][pad], a VLQ of at most 2,
 * and the tag and the three MACs.  A minimal fragment, a 1-byte VLQ and
 * no shard, is one less.
 */
unsigned int
rsecFrmShard(
  unsigned int dgramMax
 ,unsigned int tagSize
 ,unsigned int frgHmacSize
 ,unsigned int dtgHmacSize
 ,unsigned int dtgHashSize
){
  unsigned int overhead;

  overhead = tagSize + frgHmacSize + dtgHmacSize + dtgHashSize + 6;
  if (dgramMax <= overhead
   || dgramMax - overhead > 16384)
    return (0);
  return (dgramMax - overhead);
}

unsigned int
rsecFrmMax(
  unsigned int dgramMax
 ,unsigned int tagSize
 ,unsigned int frgHmacSize
 ,unsigned int dtgHmacSize
 ,unsigned int dtgHashSize
 ,unsigned char m
){
  unsigned int s;

  if (!(s = rsecFrmShard(dgramMax, tagSize, frgHmacSize, dtgHmacSize, dtgHashSize)))
    return (0);
  return ((256 - m) * s);
}

/*
 * Egress.  A slot holds a message's k + m shards, each a fragment ready
 * but for the datagram trailers, stride bytes apart:
 *   [addrlen][addr][tag][k-1][m][si][pad][shard_len_vlq][shard_data][frgHmac]
 * One schedule, sorted by due time, interleaves every slot's shards.
 */
struct egrEnt {
  unsigned char *work;  /* 0: a free slot */
  unsigned long delay;  /* microseconds a shard */
  unsigned long putAt;  /* when it was taken */
  unsigned int stride;
  unsigned int km;
  unsigned int sent;    /* shards packed so far */
};

struct egrShd {
  unsigned long ts;     /* due */
  unsigned int ent;
  unsigned int shard;
};

struct egr {
  struct egrEnt *tab;
  struct egrShd *shd;
  unsigned char *pack;  /* [addrlen][addr][wire], 1 + 255 + dgramMax */
  unsigned char *seen;  /* a slot already in the pack */
  unsigned int *frgOff; /* the pack's fragment tag offsets, one a slot at most */
  unsigned long shdCnt;
  unsigned long shdCap;
  unsigned long lastSent;
  unsigned long lastPackD;  /* the delays packed into the last datagram Sent */
  unsigned long packAt;     /* when the datagram in hand was got */
  unsigned long packD;      /* and its packed delays */
  unsigned int maxShard;
  unsigned int packLen;     /* the datagram in hand, 0 none */
  unsigned int packFrg;     /* and its fragments */
  unsigned char hasSent;
  unsigned char refused;    /* the last Put was refused for room */
};

int
rsecFrmEgrInit(
  struct rsecFrmEgr *x
){
  struct egr *e;
  unsigned int i;

  if (!x->realloc || !x->free || !x->tableSize
   || (x->dtgHashSize && !x->dtgHashSign)
   || (x->dtgHmacSize && !x->dtgHmacSign)
   || (x->frgHmacSize && !x->frgHmacSign))
    return (0);
  if (!(e = x->realloc(0, sizeof (*e))))
    return (0);
  memset(e, 0, sizeof (*e));
  if (!(e->maxShard = rsecFrmShard(x->dgramMax, x->tagSize, x->frgHmacSize, x->dtgHmacSize, x->dtgHashSize))
   || !(e->tab = x->realloc(0, x->tableSize * sizeof (*e->tab)))
   || !(e->pack = x->realloc(0, 1 + 255 + x->dgramMax))
   || !(e->seen = x->realloc(0, x->tableSize))
   || !(e->frgOff = x->realloc(0, x->tableSize * sizeof (*e->frgOff)))) {
    x->free(e->frgOff);
    x->free(e->seen);
    x->free(e->pack);
    x->free(e->tab);
    x->free(e);
    return (0);
  }
  for (i = 0; i < x->tableSize; ++i)
    e->tab[i].work = 0;
  x->opaque = e;
  return (1);
}

void
rsecFrmEgrFini(
  struct rsecFrmEgr *x
){
  struct egr *e;
  unsigned int i;

  if (!(e = x->opaque))
    return;
  for (i = 0; i < x->tableSize; ++i)
    x->free(e->tab[i].work);
  x->free(e->shd);
  x->free(e->frgOff);
  x->free(e->seen);
  x->free(e->pack);
  x->free(e->tab);
  x->free(e);
  x->opaque = 0;
}

int
rsecFrmEgrPut(
  struct rsecFrmEgr *x
 ,const unsigned char *b
 ,unsigned int l
 ,unsigned long now
){
  const unsigned char *dp[256];
  unsigned char *pp[256];
  unsigned char vlq[2];
  struct egr *e;
  unsigned char *work;
  unsigned long delay;
  unsigned long ts;
  unsigned int prefix;
  unsigned int payLen;
  unsigned int slot;
  unsigned int k;
  unsigned int km;
  unsigned int sz;
  unsigned int pad;
  unsigned int vlqLen;
  unsigned int gap;
  unsigned int stride;
  unsigned int i;
  unsigned int m;

  e = x->opaque;
  if (l < 1)
    return (-1);
  prefix = 1 + b[0] + x->tagSize;
  if (l < prefix + 5)
    return (-1);
  m = b[prefix];
  delay = (unsigned long)b[prefix + 1] << 24
        | (unsigned long)b[prefix + 2] << 16
        | (unsigned long)b[prefix + 3] << 8
        | b[prefix + 4];
  payLen = l - (prefix + 5);
  /* in bytes: the ceiling below can wrap within maxShard of UINT_MAX */
  if (payLen > 256 * e->maxShard)
    return (-1);
  /* the same address and tag still in the table: that message is still
   * going, and a second train under its tag would feed the one
   * reassembly at the ingress */
  for (i = 0; i < x->tableSize; ++i)
    if (e->tab[i].work && !memcmp(e->tab[i].work, b, prefix)) {
      ++x->c.again;
      return (2);
    }
  for (slot = 0; slot < x->tableSize && e->tab[slot].work; ++slot);
  if (slot == x->tableSize) {
    if (!e->refused) {
      e->refused = 1;
      ++x->c.full;
    }
    return (0);
  }
  e->refused = 0;
  k = payLen ? (payLen + e->maxShard - 1) / e->maxShard : 1;
  if ((km = k + m) > 256) {
    m = 256 - k;
    km = 256;
  }
  if (delay && km > QUARTER / delay)
    return (-1);
  /* the pace is elapsed time: an idle egress never reads a stale send */
  if (e->hasSent && now - e->lastSent >= e->lastPackD)
    e->hasSent = 0;
  /* the message's own shard size, tighter than maxShard */
  sz = payLen ? (payLen + k - 1) / k : 0;
  pad = k * sz - payLen;
  if (sz < 128) {
    vlq[0] = sz;
    vlqLen = 1;
  } else {
    vlq[0] = 0x80 | ((sz - 1) >> 7);
    vlq[1] = (sz - 1) & 0x7f;
    vlqLen = 2;
  }
  gap = prefix + 4 + vlqLen;
  stride = gap + sz + x->frgHmacSize;
  if (e->shdCnt + km > e->shdCap) {
    struct egrShd *t;

    if (!(t = x->realloc(e->shd, (e->shdCnt + km) * sizeof (*e->shd))))
      return (-1);
    e->shd = t;
    e->shdCap = e->shdCnt + km;
  }
  if (!(work = x->realloc(0, (unsigned long)km * stride)))
    return (-1);
  memcpy(work, b, prefix);
  work[prefix] = k - 1;
  work[prefix + 1] = m;
  work[prefix + 2] = 0;
  work[prefix + 3] = pad;
  memcpy(work + prefix + 4, vlq, vlqLen);
  for (i = 0; i < km; ++i) {
    unsigned char *s;

    s = work + (unsigned long)i * stride;
    if (i)
      memcpy(s, work, gap);
    s[prefix + 2] = i;
    if (i < k) {
      unsigned int off;
      unsigned int len;

      off = i * sz;
      if ((len = payLen - off) > sz)
        len = sz;
      if (len)
        memcpy(s + gap, b + prefix + 5 + off, len);
      if (len < sz)
        memset(s + gap + len, 0, sz - len);
      dp[i] = s + gap;
    } else
      pp[i - k] = s + gap;
  }
  if (m && sz && rsecEncode(dp, pp, sz, k, m)) {
    x->free(work);
    return (-1);
  }
  if (x->frgHmacSize)
    for (i = 0; i < km; ++i) {
      unsigned char *s;

      s = work + (unsigned long)i * stride;
      x->frgHmacSign(x->frgHmacCtx, s, s + gap + sz, s + 1 + b[0], gap + sz - (1 + b[0]));
    }
  e->tab[slot].work = work;
  e->tab[slot].delay = delay;
  e->tab[slot].stride = stride;
  e->tab[slot].km = km;
  e->tab[slot].sent = 0;
  e->tab[slot].putAt = now;
  /* shard i due at now + (i + 1) x delay, after any already due then */
  for (ts = now, i = 0; i < km; ++i) {
    unsigned long lo;
    unsigned long hi;

    ts += delay;
    lo = 0;
    hi = e->shdCnt;
    while (lo < hi) {
      unsigned long mid;

      mid = lo + (hi - lo) / 2;
      if (AFTER(e->shd[mid].ts, ts))
        hi = mid;
      else
        lo = mid + 1;
    }
    if (lo < e->shdCnt)
      memmove(e->shd + lo + 1, e->shd + lo, (e->shdCnt - lo) * sizeof (*e->shd));
    e->shd[lo].ts = ts;
    e->shd[lo].ent = slot;
    e->shd[lo].shard = i;
    ++e->shdCnt;
  }
  return (1);
}

int
rsecFrmEgrDue(
  struct rsecFrmEgr *x
 ,unsigned long *due
){
  struct egr *e;
  unsigned long t;

  e = x->opaque;
  if (e->packLen) {
    *due = e->packAt;
    return (1);
  }
  if (!e->shdCnt)
    return (0);
  t = e->shd[0].ts;
  if (e->hasSent && AFTER(e->lastSent + e->lastPackD, t))
    t = e->lastSent + e->lastPackD;
  *due = t;
  return (1);
}

/*
 * The pack: the head shard, then every shard due at now to the same
 * address from a slot not yet in it, while there is room for both
 * trailers -- a slot is a tag at an address, so no two fragments of a
 * datagram share a tag.  The wait after it is the SUM of the packed
 * shards' delays: a delay is a slice of wire time, and packing lets
 * shards ride early, never for free.
 */
unsigned int
rsecFrmEgrGet(
  struct rsecFrmEgr *x
 ,unsigned long now
 ,const unsigned char **dgram
){
  struct egr *e;
  unsigned long due;
  unsigned long si;
  unsigned int wp;
  unsigned int pos;
  unsigned int ei;

  e = x->opaque;
  if (e->packLen)
    goto held;
  if (e->hasSent && now - e->lastSent >= e->lastPackD)
    e->hasSent = 0;
  if (!rsecFrmEgrDue(x, &due) || AFTER(due, now))
    return (0);
  ei = e->shd[0].ent;
  wp = 1 + e->tab[ei].work[0];
  memcpy(e->pack, e->tab[ei].work, wp);
  memset(e->seen, 0, x->tableSize);
  e->frgOff[0] = 0;
  memcpy(e->pack + wp, e->tab[ei].work + (unsigned long)e->shd[0].shard * e->tab[ei].stride + wp, e->tab[ei].stride - wp);
  pos = e->tab[ei].stride;
  e->seen[ei] = 1;
  e->packD = e->tab[ei].delay;
  e->packFrg = 1;
  ++e->tab[ei].sent;
  if (--e->shdCnt)
    memmove(e->shd, e->shd + 1, e->shdCnt * sizeof (*e->shd));
  for (si = 0; si < e->shdCnt && !AFTER(e->shd[si].ts, now);) {
    unsigned int ej;
    unsigned int wj;
    unsigned int fl;

    ej = e->shd[si].ent;
    wj = 1 + e->tab[ej].work[0];
    fl = e->tab[ej].stride - wj;
    if (wj == wp
     && !memcmp(e->tab[ej].work, e->pack, wp)
     && !e->seen[ej]
     && pos + fl + x->dtgHmacSize + x->dtgHashSize <= wp + x->dgramMax) {
      e->frgOff[e->packFrg++] = pos - wp;
      memcpy(e->pack + pos, e->tab[ej].work + (unsigned long)e->shd[si].shard * e->tab[ej].stride + wj, fl);
      pos += fl;
      e->seen[ej] = 1;
      if ((e->packD += e->tab[ej].delay) > QUARTER)
        e->packD = QUARTER;
      ++e->tab[ej].sent;
      if (si < --e->shdCnt)
        memmove(e->shd + si, e->shd + si + 1, (e->shdCnt - si) * sizeof (*e->shd));
    } else
      ++si;
  }
  if (x->dtgHmacSize)
    x->dtgHmacSign(x->dtgHmacCtx, e->pack, e->pack + pos, e->pack + wp, pos - wp, e->frgOff, e->packFrg);
  pos += x->dtgHmacSize;
  if (x->dtgHashSize)
    x->dtgHashSign(x->dtgHashCtx, e->pack, e->pack + pos, e->pack + wp, pos - wp);
  pos += x->dtgHashSize;
  e->packLen = pos;
  e->packAt = now;
held:
  *dgram = e->pack;
  return (e->packLen);
}

void
rsecFrmEgrSent(
  struct rsecFrmEgr *x
 ,unsigned long now
){
  struct egr *e;
  unsigned int i;

  e = x->opaque;
  if (!e->packLen)
    return;
  x->c.frg += e->packFrg;
  for (i = 0; i < x->tableSize; ++i)
    if (e->seen[i] && e->tab[i].work && e->tab[i].sent >= e->tab[i].km) {
      ++x->c.msg;
      if (now - e->tab[i].putAt > x->c.wait)
        x->c.wait = now - e->tab[i].putAt;
      x->free(e->tab[i].work);
      e->tab[i].work = 0;
    }
  e->lastSent = now;
  e->lastPackD = e->packD;
  e->hasSent = 1;
  e->packLen = 0;
}

/*
 * Ingress.  A reassembly: blob is the message being assembled, data
 * shards in place behind its [addrlen][addr][tag][rm][um] prefix, and 0
 * once it is delivered; the parity shards and the tag ride in mem.
 */
struct igrEnt {
  unsigned char *blob;
  unsigned char *parity;   /* m x shardSize, in mem */
  unsigned char *tag;      /* tagSize, in mem after the parity */
  unsigned int k;
  unsigned int m;
  unsigned int shardSize;
  unsigned int padding;
  unsigned int received;
  unsigned int age;
  unsigned int prefix;     /* 1 + addrlen + tagSize + 2 */
  unsigned char present[256];
  unsigned char mem[1];
};

struct igrDlv {
  unsigned char *b;
  unsigned int l;
};

struct igr {
  struct igrEnt **tab;     /* sorted by tag, used of them */
  struct igrDlv *dlv;      /* what the last Put left, two a fragment at most */
  unsigned char *hdr;      /* [addrlen][addr][tag][k-1][m][si] for frgHmacVrfy */
  unsigned int *frgOff;
  unsigned int used;
  unsigned int age;        /* fragments parsed, halved with every entry's */
  unsigned int held[256];  /* tagOwner: the entries by sender */
  unsigned int dlvCnt;
  unsigned int dlvNext;
};

int
rsecFrmIgrInit(
  struct rsecFrmIgr *x
){
  struct igr *g;
  unsigned int maxFrg;

  if (!x->realloc || !x->free || !x->tableSize || x->tagOwner > x->tagSize
   || (x->dtgHashSize && !x->dtgHashVrfy)
   || (x->dtgHmacSize && !x->dtgHmacVrfy)
   || (x->frgHmacSize && !x->frgHmacVrfy))
    return (0);
  if (!(g = x->realloc(0, sizeof (*g))))
    return (0);
  memset(g, 0, sizeof (*g));
  /* a minimal fragment: [tag][k-1][m][si][pad][1-byte VLQ][frgHmac] */
  maxFrg = x->dgramMax / (x->tagSize + 5 + x->frgHmacSize) + 1;
  if (!(g->tab = x->realloc(0, x->tableSize * sizeof (*g->tab)))
   || !(g->dlv = x->realloc(0, 2 * maxFrg * sizeof (*g->dlv)))
   || !(g->hdr = x->realloc(0, 1 + 255 + x->tagSize + 3))
   || !(g->frgOff = x->realloc(0, maxFrg * sizeof (*g->frgOff)))) {
    x->free(g->frgOff);
    x->free(g->hdr);
    x->free(g->dlv);
    x->free(g->tab);
    x->free(g);
    return (0);
  }
  x->opaque = g;
  return (1);
}

void
rsecFrmIgrFini(
  struct rsecFrmIgr *x
){
  struct igr *g;
  unsigned int i;

  if (!(g = x->opaque))
    return;
  for (i = g->dlvNext; i < g->dlvCnt; ++i)
    x->free(g->dlv[i].b);
  for (i = 0; i < g->used; ++i) {
    x->free(g->tab[i]->blob);
    x->free(g->tab[i]);
  }
  x->free(g->frgOff);
  x->free(g->hdr);
  x->free(g->dlv);
  x->free(g->tab);
  x->free(g);
  x->opaque = 0;
}

int
rsecFrmIgrPut(
  struct rsecFrmIgr *x
 ,const unsigned char *adr
 ,const unsigned char *buf
 ,unsigned int n
){
  struct igr *g;
  struct igrEnt *ent;
  unsigned int tagSize;
  unsigned int frgHmacSize;
  unsigned int wp;
  unsigned int pos;
  unsigned int slot;
  unsigned int i;
  int full;

  g = x->opaque;
  if (g->dlvNext < g->dlvCnt)
    return (0);
  g->dlvCnt = g->dlvNext = 0;
  tagSize = x->tagSize;
  frgHmacSize = x->frgHmacSize;
  wp = 1 + adr[0];
  /* past the wire's size or short of one fragment: not of this wire */
  if (n > x->dgramMax
   || n < tagSize + 5 + frgHmacSize + x->dtgHmacSize + x->dtgHashSize)
    return (1);

  /* the GATE, outermost, before any other work */
  if (x->dtgHashSize) {
    if (!x->dtgHashVrfy(x->dtgHashCtx, adr, buf + n - x->dtgHashSize, buf, n - x->dtgHashSize)) {
      ++x->c.hash;
      return (1);
    }
    n -= x->dtgHashSize;
  }

  /* the AUTH: the fragments' tag offsets from their framing, then the
   * MAC; a failure, a bad MAC or a mixed-sender datagram, drops it */
  if (x->dtgHmacSize) {
    unsigned int fend;
    unsigned int sp;
    unsigned int frgCnt;

    fend = n - x->dtgHmacSize;
    for (sp = 0, frgCnt = 0; sp + tagSize + 5 + frgHmacSize <= fend;) {
      unsigned int vo;
      unsigned int ssz;
      unsigned int svlq;
      unsigned int send;

      if (buf[sp + tagSize] + 1 + buf[sp + tagSize + 1] > 256)
        break;
      vo = sp + tagSize + 4;
      if (buf[vo] & 0x80) {
        if (vo + 2 > fend)
          break;
        ssz = (((buf[vo] & 0x7f) << 7) | (buf[vo + 1] & 0x7f)) + 1;
        svlq = 2;
      } else {
        ssz = buf[vo];
        svlq = 1;
      }
      if ((send = sp + tagSize + 4 + svlq + ssz + frgHmacSize) > fend)
        break;
      g->frgOff[frgCnt++] = sp;
      sp = send;
    }
    if (!x->dtgHmacVrfy(x->dtgHmacCtx, adr, buf + fend, buf, fend, g->frgOff, frgCnt)) {
      ++x->c.dhmac;
      return (1);
    }
    n = fend;
  }

  for (pos = 0; pos + tagSize + 5 + frgHmacSize <= n;) {
    unsigned int k;
    unsigned int m;
    unsigned int si;
    unsigned int padding;
    unsigned int sz;
    unsigned int vlqLen;
    unsigned int hl;
    unsigned int fragEnd;
    unsigned int vo;
    unsigned int dataPresent;
    int found;

    ++x->c.frg;
    k = buf[pos + tagSize] + 1;
    m = buf[pos + tagSize + 1];
    si = buf[pos + tagSize + 2];
    if (k + m > 256 || si >= k + m)
      break;
    padding = buf[pos + tagSize + 3];
    vo = pos + tagSize + 4;
    if (buf[vo] & 0x80) {
      if (vo + 2 > n)
        break;
      sz = (((buf[vo] & 0x7f) << 7) | (buf[vo + 1] & 0x7f)) + 1;
      vlqLen = 2;
    } else {
      sz = buf[vo];
      vlqLen = 1;
    }
    hl = tagSize + 4 + vlqLen;
    if ((fragEnd = pos + hl + sz + frgHmacSize) > n)
      break;
    if (padding > k * sz) {
      pos = fragEnd;
      continue;
    }
    if (frgHmacSize) {
      memcpy(g->hdr, adr, wp);
      memcpy(g->hdr + wp, buf + pos, tagSize + 3);
      if (!x->frgHmacVrfy(x->frgHmacCtx, g->hdr, buf + pos + hl + sz, buf + pos, hl + sz)) {
        ++x->c.hmac;
        pos = fragEnd;
        continue;
      }
    }
    /* halved with every entry's before it can wrap */
    if (++g->age >= ~0U / 2) {
      for (i = 0; i < g->used; ++i)
        g->tab[i]->age >>= 1;
      g->age >>= 1;
    }
    {
      unsigned int lo;
      unsigned int hi;

      lo = 0;
      hi = g->used;
      found = 0;
      while (lo < hi) {
        unsigned int mid;
        int c;

        mid = lo + (hi - lo) / 2;
        if ((c = memcmp(buf + pos, g->tab[mid]->tag, tagSize)) < 0)
          hi = mid;
        else if (c > 0)
          lo = mid + 1;
        else {
          found = 1;
          lo = mid;
          break;
        }
      }
      slot = lo;
    }

    /* a mismatch evicts: padding counts, since it sets the delivered
     * length, and two same-tag payloads fewer than k bytes apart agree
     * on k, m and shard size */
    if (found
     && (g->tab[slot]->k != k || g->tab[slot]->m != m
      || g->tab[slot]->shardSize != sz || g->tab[slot]->padding != padding)) {
      i = slot;
      found = 0;
      full = 0;
      goto evict;
    }

    /* a delivered entry whose train is spent, k + m arrivals: the next
     * fragment under its tag can only be a re-send, a new reassembly */
    if (found && !g->tab[slot]->blob
     && g->tab[slot]->received >= g->tab[slot]->k + g->tab[slot]->m) {
      if (x->tagOwner)
        --g->held[g->tab[slot]->tag[x->tagOwner - 1]];
      x->free(g->tab[slot]);
      if (slot < --g->used)
        memmove(g->tab + slot, g->tab + slot + 1, (g->used - slot) * sizeof (*g->tab));
      found = 0;
    }

    /* a new tag on a full table evicts the least recently fed, of the
     * sender holding the most where the tag names its sender: one
     * delivered first, which costs nothing, then one in flight, a loss */
    if (!found && g->used >= x->tableSize) {
      unsigned int lru;
      unsigned int own;

      own = 0;
      if (x->tagOwner) {
        own = buf[pos + x->tagOwner - 1];
        for (i = 0; i < 256; ++i)
          if (g->held[i] > g->held[own])
            own = i;
      }
      for (lru = g->used, i = 0; i < g->used; ++i)
        if ((!x->tagOwner || g->tab[i]->tag[x->tagOwner - 1] == own) && !g->tab[i]->blob
         && (lru == g->used || g->tab[i]->age < g->tab[lru]->age))
          lru = i;
      if (lru == g->used)
        for (i = 0; i < g->used; ++i)
          if ((!x->tagOwner || g->tab[i]->tag[x->tagOwner - 1] == own)
           && (lru == g->used || g->tab[i]->age < g->tab[lru]->age))
            lru = i;
      if ((i = lru) < slot)
        --slot;
      full = 1;
      goto evict;
    }
evicted:

    if (!found) {
      if (!(ent = x->realloc(0, sizeof (*ent) + (unsigned long)m * sz + tagSize)))
        break;
      ent->parity = ent->mem;
      ent->tag = ent->mem + (unsigned long)m * sz;
      ent->k = k;
      ent->m = m;
      ent->shardSize = sz;
      ent->padding = padding;
      ent->received = 0;
      ent->age = g->age;
      ent->prefix = wp + tagSize + 2;
      memcpy(ent->tag, buf + pos, tagSize);
      memset(ent->present, 0, sizeof (ent->present));
      if (!(ent->blob = x->realloc(0, ent->prefix + (unsigned long)k * sz))) {
        x->free(ent);
        break;
      }
      memcpy(ent->blob, adr, wp);
      memcpy(ent->blob + wp, buf + pos, tagSize);
      ent->blob[wp + tagSize] = 0;
      ent->blob[wp + tagSize + 1] = 0;
      if (slot < g->used)
        memmove(g->tab + slot + 1, g->tab + slot, (g->used - slot) * sizeof (*g->tab));
      g->tab[slot] = ent;
      ++g->used;
      if (x->tagOwner)
        ++g->held[ent->tag[x->tagOwner - 1]];
    }
    ent = g->tab[slot];

    /* delivered: a straggler, counted against the train */
    if (!ent->blob) {
      ++x->c.late;
      ++ent->received;
      pos = fragEnd;
      continue;
    }
    if (ent->present[si]) {
      ++x->c.dup;
      pos = fragEnd;
      continue;
    }
    if (si < k)
      memcpy(ent->blob + ent->prefix + (unsigned long)si * sz, buf + pos + hl, sz);
    else
      memcpy(ent->parity + (unsigned long)(si - k) * sz, buf + pos + hl, sz);
    ent->present[si] = 1;
    ++ent->received;
    ent->age = g->age;
    pos = fragEnd;
    if (ent->received < k)
      continue;

    for (dataPresent = 0, i = 0; i < k; ++i)
      if (ent->present[i])
        ++dataPresent;
    if (dataPresent < k) {
      const unsigned char *rp[256];
      unsigned char *op[256];
      unsigned char idx[256];
      unsigned char *ws;
      unsigned char *cp;
      unsigned int ri;

      if (!(ws = x->realloc(0, RS_WORK_SIZE(k) + (unsigned long)dataPresent * sz)))
        goto drop;
      /* the data shards present are copied out: the output is the blob */
      cp = ws + RS_WORK_SIZE(k);
      for (ri = 0, i = 0; i < k; ++i)
        if (ent->present[i]) {
          memcpy(cp + (unsigned long)ri * sz, ent->blob + ent->prefix + (unsigned long)i * sz, sz);
          rp[ri] = cp + (unsigned long)ri * sz;
          idx[ri++] = i;
        }
      for (i = k; i < k + ent->m && ri < k; ++i)
        if (ent->present[i]) {
          rp[ri] = ent->parity + (unsigned long)(i - k) * sz;
          idx[ri++] = i;
        }
      for (i = 0; i < k; ++i)
        op[i] = ent->blob + ent->prefix + (unsigned long)i * sz;
      if (rsecDecode(rp, idx, op, sz, k, ent->m, ws)) {
        x->free(ws);
        goto drop;
      }
      x->free(ws);
      ++x->c.dcd;
    }
    ent->blob[ent->prefix - 2] = ent->m;
    ent->blob[ent->prefix - 1] = k - dataPresent;
    g->dlv[g->dlvCnt].b = ent->blob;
    g->dlv[g->dlvCnt++].l = ent->prefix + k * sz - ent->padding;
    ++x->c.msg;
    ent->blob = 0;
    continue;

drop:
    if (x->tagOwner)
      --g->held[ent->tag[x->tagOwner - 1]];
    x->free(ent->blob);
    x->free(ent);
    if (slot < --g->used)
      memmove(g->tab + slot, g->tab + slot + 1, (g->used - slot) * sizeof (*g->tab));
    continue;

    /* the entry at i evicted, a loss when not yet delivered; slot is
     * the new entry's place once it is gone */
evict:
    ent = g->tab[i];
    if (ent->blob) {
      ++x->c.evict;
      if (full)
        ++x->c.evictFull;
      ent->blob[ent->prefix - 2] = 0;
      ent->blob[ent->prefix - 1] = ent->received;
      g->dlv[g->dlvCnt].b = ent->blob;
      g->dlv[g->dlvCnt++].l = ent->prefix;
    }
    if (x->tagOwner)
      --g->held[ent->tag[x->tagOwner - 1]];
    x->free(ent);
    if (i < --g->used)
      memmove(g->tab + i, g->tab + i + 1, (g->used - i) * sizeof (*g->tab));
    goto evicted;
  }
  return (1);
}

unsigned char *
rsecFrmIgrGet(
  struct rsecFrmIgr *x
 ,unsigned int *l
){
  struct igr *g;

  g = x->opaque;
  if (g->dlvNext >= g->dlvCnt)
    return (0);
  *l = g->dlv[g->dlvNext].l;
  return (g->dlv[g->dlvNext++].b);
}
