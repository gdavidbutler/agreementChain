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

#ifndef RSECFRM_H
#define RSECFRM_H

/*
 * rsecFrm - messages over datagrams, each message k data shards and m
 * Reed-Solomon parity shards, any k of which deliver it.  Driven by its
 * caller: no thread, no socket, no clock.  The caller's event loop owns
 * the descriptors and the time; the framer turns bytes into bytes.
 *
 * Egress and ingress are independent contexts, each owned by one
 * thread.  The caller fills the configuration fields, zeroes opaque and
 * the counters (calloc), and calls Init; Fini releases what Init and
 * the traffic allocated.  The counters are plain fields, read directly.
 *
 * Time is the caller's monotonic clock in microseconds, an unsigned
 * long that may wrap: times are compared by their difference.  A
 * message's schedule and a datagram's pace each stay under a quarter of
 * the range (17 minutes at 32 bits), so a caller that calls Get at
 * least that often while something is scheduled keeps every comparison
 * within half.
 *
 * The wire-format sizes (dgramMax, tagSize, dtgHashSize) must match
 * between a sender's egress and the receiver's ingress.  tableSize is
 * per direction.
 *
 * Wire format, one datagram:
 *   [frag1][frag2]...[fragN][dtgHash(dtgHashSize)]
 * One fragment:
 *   [tag][k-1][m][si][pad][shard_len_vlq(1-2)][shard_data]
 *   k-1  data shards less one, so k in 1..256 fits a byte
 *   m    parity shards, 0..255, k + m <= 256
 *   si   the shard's index, 0-based
 *   pad  bytes appended to the last data shard, k * ceil(L / k) - L,
 *        in [0, k - 1]
 * k and the shard's length are the message length's alone, its first
 * shard_len_vlq byte aside, and ingress refuses any other: k is 1 for an
 * empty message and else ceil(L / rsecFrmShard), so what an entry and a
 * decode cost is the length of a message, never a fragment's choice.
 *   shard_len_vlq  byte0 & 0x80 == 0: byte0 (0..127); else
 *        (((byte0 & 0x7f) << 7) | (byte1 & 0x7f)) + 1 (1..16384), the
 *        1-byte form always taken below 128
 * dtgHash covers [frag1]..[fragN].
 *
 * Fragments of one TAG never share a datagram: one loss would take two
 * shards of one train.  Fragments of different tags to one address do,
 * as many as fit.
 *
 * An address is [addrlen(1)][addr(addrlen)], the transport's own frame,
 * never on the wire and under no MAC.
 *
 * One keyed tier, enabled by its size > 0, the GATE: dtgHash, one cheap
 * keyed MAC a datagram, verified before any other work, so a flood
 * without the key costs one verify.  It says only that a holder of the
 * key framed these bytes, once, and a copy of them passes.  Whether a
 * message is authentic, and whether a copy of it is worth anything, is
 * for the end that knows what it holds, so a message's own proof is
 * that caller's, inside its payload: the fragments here are carried on
 * the gate's word alone, and a delivery may be noise.
 * On ingress adr is the kernel's source address: whoever sent the
 * datagram chose it, so a verify must not select a key by it.  A verify
 * that selects its key by the tag's sender byte names that byte in
 * tagOwner, and a fragment claiming any other sender than the
 * datagram's first is refused here.
 */

/* Shard bytes a datagram carries (0 if dgramMax is too small or the
 * shard would pass 16384) */
unsigned int
rsecFrmShard(
  unsigned int /* dgramMax */
 ,unsigned int /* tagSize */
 ,unsigned int /* dtgHashSize */
);

/* Payload bytes a message can carry at m parity shards (0 as above) */
unsigned int
rsecFrmMax(
  unsigned int /* dgramMax */
 ,unsigned int /* tagSize */
 ,unsigned int /* dtgHashSize */
 ,unsigned char /* m */
);

struct rsecFrmEgrCtrs {
  unsigned long wait; /* the longest a message took, its Put to its last
                       * shard Sent, microseconds */
  unsigned int msg;   /* messages whose every shard was Sent */
  unsigned int frg;   /* fragments Sent */
  unsigned int full;  /* Puts refused for a full table, a run of refusals
                       * once: the caller holds one message and Puts it
                       * again */
  unsigned int again; /* Puts not taken: a message to the same address
                       * under the same tag still in the table */
};

struct rsecFrmEgr {
  void *(*realloc)(void *, unsigned long);
  void (*free)(void *);
  void *dtgHashCtx;
  /* adr: the destination; src/len: every fragment's bytes */
  void (*dtgHashSign)(void *dtgHashCtx, const unsigned char *adr, unsigned char *dst, const unsigned char *src, unsigned int len);
  void *opaque;       /* private: Init sets it, Fini clears it */
  unsigned int dgramMax;
  unsigned int tagSize;
  unsigned int tableSize;  /* messages in flight: a message holds its
                            * slot until its last shard is Sent */
  unsigned int dtgHashSize;
  struct rsecFrmEgrCtrs c;
};

/* 1, or 0 on a callback or the table size missing, a configuration no
 * shard fits, or no memory */
int
rsecFrmEgrInit(
  struct rsecFrmEgr *
);

void
rsecFrmEgrFini(
  struct rsecFrmEgr *
);

/*
 * Take a message: [addrlen][addr][tag][m(1)][delay_us(4)][payload].
 * delay_us, big endian, paces the message's shards: shard i is due at
 * now + (i + 1) x delay_us.  The message is copied; the caller keeps
 * its bytes.  m is cut to 256 - k where k + m would pass 256.
 * A tag is unique among the messages in flight: a message to the same
 * address under the same tag as one still in the table is that one,
 * still going -- a second train under its tag would feed the one
 * reassembly at the ingress, two messages delivered as one.
 * Returns 1 taken; 2 the same address and tag still in the table, not
 * taken; 0 the table is full, nothing taken -- hold it and Put it again
 * after a Sent; -1 refused and dropped: malformed or past rsecFrmMax at
 * m = 0, before the table is looked at; or, a place free, a schedule
 * past a quarter of the clock, or no memory.
 */
int
rsecFrmEgrPut(
  struct rsecFrmEgr *
 ,const unsigned char *  /* the message */
 ,unsigned int           /* its length */
 ,unsigned long          /* now */
);

/*
 * 0 nothing to send; else 1 and the time the next datagram may leave:
 * the later of its first shard's due time and the last Sent plus the
 * sum of the delays packed into that datagram, capped at a quarter of
 * the clock.  A datagram got and not yet Sent is due at once: the
 * caller waits for its socket to take it, not for the clock.
 */
int
rsecFrmEgrDue(
  struct rsecFrmEgr *
 ,unsigned long *        /* out: when */
);

/*
 * The datagram due at now, [addrlen][addr][wire], and its length; 0
 * when none is.  It packs every fragment due at now to the same
 * address, from distinct slots, that fits.  The same datagram comes
 * back from every Get until rsecFrmEgrSent: a send that would block
 * (EAGAIN, or ENOBUFS where a kernel pushes back so) leaves it here, to
 * Get again when the socket can take it.
 */
unsigned int
rsecFrmEgrGet(
  struct rsecFrmEgr *
 ,unsigned long          /* now */
 ,const unsigned char ** /* out: the datagram */
);

/* The datagram from Get left at now: it is released, its pace starts,
 * and a message whose last shard it carried frees its slot.  A send
 * that failed for any reason but the socket's push back is the
 * network's loss: Sent all the same */
void
rsecFrmEgrSent(
  struct rsecFrmEgr *
 ,unsigned long          /* now */
);

struct rsecFrmIgrCtrs {
  unsigned int frg;   /* fragments parsed */
  unsigned int hash;  /* datagram GATE failures, a fragment claiming another
                       * sender among them */
  unsigned int shape; /* fragments of a geometry no egress derives, or past msgMax */
  unsigned int dup;   /* duplicate fragments */
  unsigned int late;  /* fragments after their message was delivered */
  unsigned int refused;    /* fragments the caller refused from their tag (tagOk) */
  unsigned int refusedMsg; /* of those, first fragments: a message each */
  unsigned int msg;   /* messages delivered */
  unsigned int dcd;   /* of those, by Reed-Solomon decode */
  unsigned int evict; /* incomplete messages evicted: a loss each */
  unsigned int evictFull; /* of those, by a new tag on a full table */
};

struct rsecFrmIgr {
  void *(*realloc)(void *, unsigned long);
  void (*free)(void *);
  void *dtgHashCtx;
  /* adr: the kernel's source; mac: the dtgHash on the wire; src/len:
   * every fragment's bytes; non-zero accepts */
  int (*dtgHashVrfy)(void *dtgHashCtx, const unsigned char *adr, const unsigned char *mac, const unsigned char *src, unsigned int len);
  void *tagOkCtx;
  /* 0 or: a fragment past the gate and its geometry, of no train in flight
   * here, its tag and its index in the train; 0 refuses it before any entry
   * or decode, the caller's say that its message would move nothing */
  int (*tagOk)(void *tagOkCtx, const unsigned char *tag, unsigned int si);
  void *opaque;       /* private: Init sets it, Fini clears it */
  unsigned int dgramMax;
  unsigned int tagSize;
  /* 0, or the longest message a sender may frame: a fragment implying more
   * is refused before any entry */
  unsigned int msgMax;
  /*
   * Reassemblies in flight.  A new tag on a full table evicts the one
   * least recently fed, a delivered one first, which costs nothing,
   * then one in flight; a fragment whose k, m, shard size or padding
   * differ from its tag's entry evicts that entry.  An evicted entry
   * not yet delivered is a loss.  A delivered entry stays to eat its
   * train's stragglers until k + m of its fragments have arrived; the
   * next fragment under its tag starts a new reassembly, so a re-send
   * under the same tag is delivered again.  No clock enters.
   */
  unsigned int tableSize;
  /*
   * 0, or 1 + the offset of the tag byte that names the fragment's
   * sender, the byte the gate selects its key by: every fragment of a
   * datagram must name the first's, and a new tag on a full table
   * evicts the entry least recently fed of the sender holding the most
   * entries, its own where it ties for the most, a delivered one first
   * as above.  A sender that opens reassemblies faster than it
   * completes them takes the table from nobody but itself.
   */
  unsigned int tagOwner;
  unsigned int dtgHashSize;
  struct rsecFrmIgrCtrs c;
};

/* 1, or 0 on a callback or the table size missing, tagOwner past the
 * tag, or no memory */
int
rsecFrmIgrInit(
  struct rsecFrmIgr *
);

void
rsecFrmIgrFini(
  struct rsecFrmIgr *
);

/*
 * Take a datagram from adr.  What it completes and what it evicts wait
 * for Get, in the order they happened.  A datagram longer than dgramMax
 * or shorter than one fragment is not of this wire: dropped, uncounted;
 * receive into dgramMax + 1 bytes, so one cut at dgramMax is seen as
 * longer.
 * Returns 1; 0 when what the last Put left has not all been got --
 * nothing is taken.
 */
int
rsecFrmIgrPut(
  struct rsecFrmIgr *
 ,const unsigned char *  /* adr: [addrlen][addr], the kernel's source */
 ,const unsigned char *  /* the datagram */
 ,unsigned int           /* its length */
);

/*
 * The next of what the last Put left, the caller's to release with the
 * context's free; 0 when none is left.
 *   a message  [addrlen][addr][tag][rm][um][payload]: rm the sender's
 *              m, um the parity shards the decode used
 *   a loss     [addrlen][addr][tag][0][received]: rm 0 with um above 0,
 *              no payload, the fragments the evicted entry held
 * (rm 0 um 0 is a message: m 0, every data shard arrived.)  addr is the
 * source of the entry's first fragment.
 */
unsigned char *
rsecFrmIgrGet(
  struct rsecFrmIgr *
 ,unsigned int *         /* out: its length */
);

#endif /* RSECFRM_H */
