/*
 * agreementChain - one seat of a chain of agreements
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

#ifndef AC_H
#define AC_H

/*
 * One seat.  N seats run a chain of BKR94 Agreement[Q] instances over
 * an asynchronous network of which up to t may be Byzantine, N > 3t, so
 * that every correct seat that folds a position delivers the same
 * messages in the same order.  The design is the head comment of ac.c
 * and the reasons are the README's; this file is what a caller needs.
 * A seat's two reports are both in message hashes, as the messages
 * flow: the chain's, once a position, at the fold -- the chain hash
 * before, every member's hash, the chain hash after -- and the
 * messages', once a member, at that member's end here -- the chain hash
 * before, the member's hash, the message or why there is none.  Beside
 * them, released: the retention let a position's record go, and a seat
 * still behind it is partitioned.  Everything else is recovery and
 * physics.
 *
 * The caller owns the wire, the clock and the threads, as it does for
 * bracha87Fig1.h and bkr94acs.h: it feeds every datagram that arrives
 * (acInput), sends the datagrams the seat hands it (the send callback),
 * and calls the pass on its own clock (acWork), which returns how long
 * until the seat next has something due.  The seat has no socket, no
 * poll, no clock and no randomness of its own.  The time is the
 * caller's microseconds, an unsigned long that may wrap, the same clock
 * to acGo, acInput and acWork; the caller calls acWork at least every
 * tick, and at least every quarter of the clock's range.  Identity on
 * the wire is the in-tag sender the datagram's authentication tier
 * verified under the dealt pairwise secret, never where a datagram came
 * from: a datagram carries a destination seat, the caller maps seats to
 * addresses, and no datagram is handed to the caller for the seat
 * itself, which feeds its own messages back locally.
 *
 * The caller gives the seat its PHYSICS and its CONFIGURATION, and the
 * seat derives the rest (acDerive).  The physics is what the network
 * does at the 99th percentile: the bandwidth a seat may send, the
 * steady loss, the longest burst of loss and the delay.  Beside it, the
 * abandon: the sweeps an instance runs before it stops, how long the
 * deployment holds its memory.  From them: the parity shards every
 * message leaves with, the pacing of its shards, the tick -- the retry
 * cadence, one feedback cycle at the declared physics -- and the
 * patience, in sweeps, a seat waits for all n before it goes on at n -
 * t, two and the sweeps the declared loss and burst retry.  The
 * configuration is the deal's: the membership and this seat, the hash
 * suites, the signing context's size, the datagram and the retention.
 * From them: the threshold, the sizes, the longest message a seat may
 * propose, which the wire bounds and the caller cannot know, and the
 * longest record a position can leave; the agreements' round ceiling is
 * the byte's.  A position launches when the one in hand has folded and
 * this seat has a reason to: its caller has a message to propose
 * (acAvailable), or a rotation of its that the last subset left out is
 * presented again, or another seat's rows for it have arrived.  This
 * seat then proposes a rotation the last subset left out, again; else a
 * payload a subset left out, where its caller, asked first (propose),
 * gives the same bytes; else the rotation its signing context is due,
 * switching first to the installed successor where the context is
 * spent; else what its caller gives when asked, its message or, with
 * none, its noop: an idle chain sends nothing.  Nothing here queues a
 * proposal: the position's chain report says what became of the
 * caller's message, and the caller decides there what to propose next,
 * the same bytes again if it likes.  A noop left out is let go; a
 * payload left out is kept, and presented again, the same value under
 * the same signature and no slot spent, only where the caller, asked,
 * gives the same bytes.
 *
 * A position's name is the chain.  The link that closes a position is
 * the name of the next: every row of a position carries it in its tag,
 * so a seat routes a row to the position's machines by the link it
 * minted itself, holds a row whose name it has not minted yet until it
 * does, and keys the records it keeps by the same name.  Every fold
 * mints a link, over the subset and every member's hash as the chain's
 * report carries it, so no two positions share a name.  Three windows.
 * A position's machines -- its agreement, its value broadcasts, its
 * exchange legs -- run until each reaches the deployment's abandon: a
 * seat whose rows land in them participates.  A position folded here
 * whose machines have all abandoned leaves a RECORD -- the subset,
 * every member's agreed value, the book at the launch, this seat's unit
 * of each member, its own distribution -- in the retention, a ring of
 * the declared bytes, the newest record overwriting the oldest, the
 * only forgetting.  A row naming a recorded position is evidence, and
 * what deals with it is RECOVER: where no recover leg of this seat's
 * runs toward the row's sender there, this seat starts one, a
 * bracha87Fig1 point to point (n = 2, t = 0), for every member whose
 * unit it holds, its own among them, carrying beside the member's
 * agreed value this seat's unit of the member and the position's
 * description, the subset and every member's agreed value; each runs to
 * the abandon, the record stays, and a row naming it after that starts
 * them again.  The returner folds on T descriptions alike from distinct
 * seats (DISCOVER), assembles from the units beside them, mints the
 * next name and launches the next, so it walks forward a position a
 * round trip until the machines of a position still running at the
 * others carry it; a position it folded is never agreed again.  A
 * member still under threshold here when its position leaves for the
 * retention keeps its assembly with the record: a part of it landing
 * later is received all the same and placed there, and nothing is sent
 * for it: the member's report says under threshold only when the
 * retention lets the record go.
 * A seat behind the oldest record is beyond what the seats can do for
 * it: partitioned until the operator intervenes, who reads where it is
 * from the chain the reports publish, since a name this seat has
 * neither minted nor kept is one it cannot place.
 *
 * The deal is the operator's and arrives through the caller.  A seat
 * mints its signing identity at acInit and publishes the public key
 * alone (acPub); the caller deals every other seat's row entry (acDeal)
 * -- the pairwise secret, which the datagram tiers and the mask key are
 * sliced from, and that seat's public key -- then the go (acGo) with
 * the chain's genesis, the dealt base every seat folds from.  Every
 * seat of a deployment is dealt the same physics and configuration but
 * self; a secret is one per unordered pair; the genesis is one for all.
 * Nothing here touches disk.
 *
 * The callbacks: random runs inside acInit and acGo too (the coin, at
 * an agreement's turn, inside acInput and acWork), the rest inside
 * acInput and acWork; a callback must not call acInput, acWork, acDeal,
 * acGo or acFree on the seat (acAvailable, acEnd and acQuiet it may),
 * and returns without waiting, since the seat has no thread but the
 * caller's: propose answers from what the caller holds then, and a
 * message not yet in hand is none; every pointer a report or a send
 * carries is borrowed for the call.  The chain's reports come once per
 * position, in position order, none skipped; the messages' come in the
 * order the verdicts fall, one per member other than this seat, whose
 * own messages the caller has from what it proposed, and a member's can
 * come before or after its position's chain report; the subset's order,
 * ascending seat, is the order a caller delivers in.  Nothing here
 * aborts: a refused argument is a -1 return and no state change, a
 * refused allocation at acInit a 0.  Everything a seat allocates it
 * allocates with malloc and releases at acFree, its secrets and the
 * caller's messages it holds wiped.
 */

struct ac;                              /* one seat */

#define AC_SEATS    256                 /* seats are bytes on the wire: a table by seat is this
                                         * wide, and what grows as n^2 is allocated by n */
#define AC_HASH_MAX 64                  /* the widest hash a suite may make */
#define AC_PSK      136                 /* a dealt pairwise secret: the datagram authentication
                                         * key (64), the datagram gate key (8), the mask key (64) */

/*
 * A hash suite the caller plugs.  init, update and final take the
 * suite's context as void *, so a suite whose functions take their own
 * context type is plugged through casts to these types; alloc returns a
 * context of tsize bytes from malloc, which the seat frees; hmac is
 * (key, keyLen, data, dataLen, out) and hkdf (ikm, ikmLen, info,
 * infoLen, out, outLen).  The sign role (the agreed value, the
 * signatures and keys, both Merkle trees, and a payload's message hash,
 * the hash of its bytes alone, which the reports carry) needs a
 * power-of-two width, h its exponent, h at least 1; the kdf role (the
 * keystream, the masks, the key walk, the datagram authentication) any
 * width.  Neither may exceed AC_HASH_MAX.  The seat calls the sign
 * role's alloc, tsize, init, update and final and the kdf role's hmac
 * and hkdf; the rest are the caller's.
 */
struct acHash {
  const char *name;                     /* the caller's, for its prints */
  void *(*alloc)(void);                 /* a context of tsize bytes, malloc'd */
  unsigned int (*tsize)(void);
  void (*init)(void *);
  void (*update)(void *, const unsigned char *, unsigned int);
  void (*final)(void *, unsigned char *);
  void (*hmac)(const unsigned char *, unsigned int, const unsigned char *, unsigned int, unsigned char *);
  void (*hkdf)(const unsigned char *, unsigned int, const unsigned char *, unsigned int, unsigned char *, unsigned int);
  unsigned int size;
  unsigned char h;
};


/*
 * The parameters.  The caller sets the physics and the configuration,
 * the same at every seat but self, a zero taking the default where one
 * is named and standing for none where the physics admits none;
 * acDerive, which acInit runs on its copy, fills everything marked
 * derived from them, whatever the caller left there, and refuses a set
 * that makes no seat.  It may be run on a copy the caller reads its own
 * loop's sizes from, and a derived struct given to acInit derives the
 * same.  shardDelayUs is derived, and placed with the retention for its
 * alignment.
 */
struct acPar {
  const struct acHash *sign;         /* the sign role: the value, the
                                      * signatures and keys, both Merkle trees */
  const struct acHash *kdf;          /* the kdf role: keystream, masks,
                                      * the key walk, the datagram MAC */
  unsigned long retention;              /* the records kept for the seats that return,
                                         * bytes, at least recMax, which the widest
                                         * memberships exceed at the default; 0 for 16 MiB */
  long          shardDelayUs;           /* derived: -1, the inter-shard pacing is per message,
                                         * one datagram's wire time at bwLimit, in microseconds */
  /* the physics, at the 99th percentile */
  unsigned int  bwLimit;                /* bits/s this seat sends, IP and UDP headers
                                         * counted; required: UDP has no back pressure */
  unsigned int  lossPct;                /* the steady loss, percent, under 100,
                                         * the parity is sized for; 0 for none */
  unsigned int  delayMs;                /* the one-way delay, ms, of the slowest answer: the longest
                                         * path's, or the slowest honest host's pass where that is
                                         * longer; 0 for none */
  unsigned int  burstMs;                /* the longest burst of loss, ms, every sweep in
                                         * it a retry the patience waits out; 0 for none */
  /* the tolerance */
  unsigned int  abandon;                /* the sweeps an instance runs before it stops, how
                                         * long this deployment holds its memory: its
                                         * abandon, paid out of t in liveness, never
                                         * safety; required, past the patience, and at
                                         * t > 0 at least one agreement with a member
                                         * gone, 1 + 7 patiences at the least and under
                                         * load more: twice the longest one a rehearsal
                                         * with a seat stopped counts (subsetMost) */
  /* the configuration */
  unsigned int  n;                      /* seats, 3..AC_SEATS */
  unsigned int  t;                      /* seats that may be Byzantine, n > 3t */
  unsigned int  self;                   /* this seat, 0..n-1 */
  unsigned int  dgramMax;               /* the datagram, bytes; 0 for 1232,
                                         * IPv6's least MTU less its headers */
  unsigned int  mlsS;                   /* 2^mlsS one-time signings a context,
                                         * the first its rotation, 1..8; 0 for 2 */
  /* derived from here on */
  unsigned int  T;                      /* the secret-sharing threshold, above t and above 1 */
  unsigned int  hashSz;                 /* the sign role's width, 1 << signH */
  unsigned int  msgMax;                 /* the longest message a proposal admits: one whose
                                         * ciphertext, T shards, fits the wire's message bound */
  unsigned int  recMax;                 /* the longest record a position can leave in
                                         * the retention: every member a payload at the
                                         * wire's bound, and the book at the launch */
  unsigned int  tickMs;                 /* the retry cadence: one feedback cycle at the
                                         * declared physics, derived at 50 at least */
  unsigned int  patience;               /* sweeps a seat waits for all n before going on at n - t:
                                         * two, and the sweeps the declared loss and burst retry */
  unsigned int  rounds;                 /* 3 x the phases an agreement may run: the byte, 255 */
  unsigned int  kdfSz;
  unsigned int  kdfMax;                 /* one HKDF call's ceiling, 255 * kdfSz */
  unsigned int  hmacSz;                 /* datagram AUTH: the kdf hash's HMAC */
  unsigned int  sigLen;                 /* mlsSgSz at signH, mlsS */
  unsigned int  pfSz;                   /* a Merkle proof at R leaves */
  unsigned int  unitFixed;              /* a payload's sign part: the header, the
                                         * signature, the masked value, both proofs */
  unsigned int  shardMax;               /* the longest shard any admitted message
                                         * can make: a unit past it is refused */
  unsigned int  partMax;                /* the longest message any seat makes: a
                                         * sign part or a data part at that shard */
  unsigned int  shard;                  /* the framer's shard at the tag's size */
  int           parity;                 /* -1: the parity shards a message leaves
                                         * with are per message, from lossPct */
  unsigned char signH;                  /* the sign role's exponent: hashSz is 1 << signH */
};

/* what a member of a position is */
#define AC_PAYLOAD  0
/* what a held sign part says its hash is, by its shape: a payload's
 * apex (0), the hash of a rotation's key, slot and successor, the hash
 * of a key and slot.  The value the ACS agrees is the hash alone; this
 * is read from the sign part a seat validated for it, never from the
 * value, and the value commits it with the key and slot that signed it */
#define AC_ROTATION   1
#define AC_NOOP  2
/* the gates a unit can fail at, in the order they run */
#define AC_UNIT_OK    0
#define AC_UNIT_LEN   1
#define AC_UNIT_SIG   2
#define AC_UNIT_SSS   3
#define AC_UNIT_RSEC  4
#define AC_UNIT_MEM   5  /* this seat's memory refused the judgment: the
                          * part is not held and its sender re-sends it */

/*
 * What a seat has of a member's message: the message, or why none.
 * Every correct seat that reports a verdict at threshold for a member
 * reports the same outcome: AC_PASS, the same bytes at each, or no
 * message, AC_EXHAUSTED, AC_INCONSISTENT or AC_BUDGET.  Which of those
 * three is which parts reached the seat, so correct seats may report
 * different ones, and an application acts on the outcome alone.  No
 * message is the member's own fault: a commitment that is the encoding
 * of a message within msgMax, each part checked against it on arrival,
 * gives AC_PASS at every correct seat at threshold.  AC_UNDER, and
 * AC_NONE in a report, are this seat's alone: it fell outside what its
 * deployment declared, its retention or its memory, and the library
 * gives it the message no more; its chain report still carries the
 * member's agreed hash, which bytes taken from any other seat must
 * reproduce.
 */
#define AC_NONE      0  /* not yet: under threshold, or the search still has pool to try */
#define AC_PASS      1  /* the message that matches the signed hash,
                         * under a commitment that is its encoding */
#define AC_EXHAUSTED 2  /* at threshold, every subset tried: no subset reproduces the hash */
#define AC_UNDER     3  /* under threshold when the retention let the position's record go */
#define AC_BUDGET    4  /* at threshold, the try budget spent: not shown either way */
#define AC_INCONSISTENT 5  /* a subset reproduces the hash under a
                            * commitment that is not its encoding */


/* the chain's report, at the fold of a position; the tables by seat
 * hold zero for a seat outside the subset; a bitmap is (n + 7) / 8
 * bytes, bit j of seat j at byte j / 8, 1 << (j % 8).  The chain hash
 * after the position is the sign hash of the one before it, the subset
 * bitmap and every member's hash in seat order, so a reader of the
 * reports folds the chain for itself, and the link commits who the
 * members were, two of whom may say the same bytes; it is the name
 * every row of the next position carries.  A caller finds which of its
 * messages landed by its own member: in the subset as AC_PAYLOAD, its
 * hash is the sign role's hash of the bytes the caller gave, which the
 * caller matches by hashing what it gave; outside the subset, or a
 * noop, no message of its landed at the position, and it may give the
 * same bytes again */
struct acChain {
  const unsigned char *prev;            /* the chain hash before the position: its name */
  const unsigned char *next;            /* and after it: the next position's name */
  const unsigned char *subset;          /* bitmap by seat */
  const unsigned char *hash;            /* N x HashSz by seat: a payload's message hash, the sign
                                         * role's hash of its bytes; a rotation's or noop's value */
  const unsigned char *successor;       /* N x HashSz by seat: a rotation member's successor
                                         * key, installed in the book at this fold */
  const unsigned char *kind;            /* N by seat: AC_PAYLOAD, AC_ROTATION, AC_NOOP */
  const unsigned char *ending;          /* N by seat: 1 where the member's value carries the end its
                                         * caller asked for (acEnd) */
  const unsigned char *promoted;        /* N by seat: the member switched
                                         * to its successor at this fold */
  const unsigned char *round;           /* N by seat, every seat: the round the seat's agreement
                                         * decided at here, a phase's third round: 3 is a first
                                         * phase that decided, and every three past it is a
                                         * phase it ran undecided here, on the coin or a phase
                                         * behind a seat that decided first; 0
                                         * where it had not decided here by the report: an
                                         * agreement the round ceiling stopped, or one that had
                                         * not decided when the position folded here on DISCOVER */
  const unsigned char *entered;         /* N by seat, every seat: 1 where this seat
                                         * entered its agreement on the seat's value, held
                                         * by then; 0 where its patience ran out first */
  unsigned int position;                /* this seat's count of the positions it launched, 1.. */
  unsigned int members;
  unsigned int launchTick;
  unsigned int subsetTick;
  unsigned int tick;
  unsigned char ceiling;                /* this seat's agreement stopped at the round ceiling */
  unsigned char end;                    /* more than t members carry the end: the chain's last link,
                                         * next its final hash */
};

/* the messages' report, once per member other than this seat, at that
 * member's end here: a payload's message at AC_PASS; under an
 * inconsistent commitment no seat's, since which seats reproduce the
 * hash is which leaves reach them; a rotation's or noop's AC_PASS with
 * no message, its hash the value; AC_NONE only where this seat's memory
 * still refused the search when the retention let the position's record
 * go */
struct acMessage {
  const unsigned char *prev;            /* the chain hash before the position */
  const unsigned char *hash;            /* the member's hash, as the chain's report carries
                                         * it; 0 while no sign part of the member is held */
  const unsigned char *msg;             /* the message, len bytes, at AC_PASS; else 0 */
  const unsigned char *heldShares;      /* bitmaps by recipient seat: the
                                         * parts in the pool at the report */
  const unsigned char *heldShards;
  const unsigned char *badShares;       /* of those, off the dealer's
                                         * commitment, at AC_INCONSISTENT */
  const unsigned char *badShards;
  unsigned int position;
  unsigned int len;
  unsigned int tick;
  unsigned int tries;                   /* the search's */
  unsigned char member;
  unsigned char kind;
  unsigned char verdict;                /* AC_NONE .. AC_INCONSISTENT */
};

struct acCb {
  void *ctx;
  void (*chain)(void *, const struct acChain *);
  void (*message)(void *, const struct acMessage *);
  /* retention let the position's record go: a seat behind it is
   * partitioned */
  void (*released)(void *, unsigned int position, unsigned int tick);
  /* a datagram to seat dest, len bytes, borrowed for the call: 1 taken,
   * or the network's loss; 0 not taken, the socket's push back, and it
   * stays due.  Which refusal is which is the caller's: an interface
   * answers ENOBUFS both while its queue is full and for as long as it
   * is down */
  int (*send)(void *, unsigned char dest, const unsigned char *dgram, unsigned int len);
  void (*random)(void *, unsigned char *, unsigned int);  /* the caller's randomness:
                                                           * keys, seeds, the coin */
  /* this seat's input to the position launching, asked where its
   * signing context leaves it a payload slot: the caller's message
   * written to msg, at most max bytes (msgMax), its length returned at
   * once; 0 for none, the noop.  A message within max always fits the
   * ciphertext; a length past max is the caller's error, the noop
   * proposed in its place (proposeLong).  The same bytes as its payload
   * a subset left out present that one again, and where one is kept it
   * is asked ahead of a rotation or switch, which then takes the
   * position in place of another answer */
  unsigned int (*propose)(void *, unsigned char *msg, unsigned int max);
  void (*trace)(void *, const char *);  /* one line per transition, or 0 */
};


/* the said counters' indices.  The first, why the framer took a
 * message: a first send, a reply to one seat, a sweep's re-send */
#define AC_SAID_FIRST 0
#define AC_SAID_REPLY 1
#define AC_SAID_SWEEP 2
/* the second, its class, the one its tag carries: the agreements' rows,
 * a message's distribute, an exchange leg, a recover leg */
#define AC_CLS_ACS    0
#define AC_CLS_DIST   1
#define AC_CLS_LEG    2
#define AC_CLS_RCV    3
/* the third, its kind, the broadcast's: an initial, an echo, a ready, a
 * message beside an initial */
#define AC_KIND_INITIAL 0
#define AC_KIND_ECHO    1
#define AC_KIND_READY   2
#define AC_KIND_BESIDE  3

/*
 * What this seat counts of one other seat: identity on the wire is the
 * in-tag sender the datagram tier verified, so what a row costs or
 * breaks is that sender's, and what a verified signature says is the
 * signer's.  The three windows, per seat, are the tick its rows last
 * landed in each: placed in a live machine, naming a record, held under
 * a name not yet minted here; the newest of the three is where that
 * seat is, as this seat last saw it, and nothing else here says.  Read
 * one seat at a time (acSeatCounters).
 */
struct acSeatCounters {
  unsigned int liveTick;              /* the tick of its last row placed in a live machine here */
  unsigned int recordTick;            /* of its last row naming a record
                                       * here: behind the live window */
  unsigned int heldTick;              /* of its last row held under a
                                       * name not minted here yet: ahead */
  unsigned int live;                  /* its rows placed in live machines */
  unsigned int recorded;              /* its rows naming a record */
  unsigned int held;                  /* its rows held under a name not yet minted */
  unsigned int heldFull;              /* its rows not held: the window's count of the shape held */
  unsigned int swept;                 /* the sweeps' rows to it: re-sends of what
                                       * it had not said it holds, and the turns a
                                       * sweep step fired, returned the same way */
  unsigned int sweptTurn;             /* of those, an agreement's INITIAL on its pass's completing
                                       * step: a turn that step fired, or a re-send; the rest are
                                       * re-sends */
  unsigned int sweptHeld;             /* its re-sends a sweep held: its least round trip had not
                                       * passed since its sweep was last due */
  unsigned int resent;                /* its re-sends of what is held already: an INITIAL fed, a
                                       * part held, a row held ahead; it has not heard HOLDING */
  unsigned int replied;               /* the replies said to it: an echo or ready to it alone,
                                       * on an arrival of its that asked for one */
  unsigned int rtts;                  /* round trips timed: this seat's value broadcast's INITIAL,
                                       * first said to it, to its echo back, the unit, its checks
                                       * and both queues between (rttLeast, rttMost, rttSum) */
  unsigned int lates;                 /* its values accepted here after n - t agreements had
                                       * decided 1: patience waited on them, or ran out first */
  unsigned int lateMost;              /* the most sweeps of this seat's one of them came after
                                       * the (n - t)th decision of 1 (lateMostUs): the patience
                                       * that would have waited for every one */
  unsigned int zeros;                 /* its agreements this seat entered 0 in: patience ran out */
  unsigned int noInstance;            /* its leg rows with no instance here */
  unsigned int stopped;               /* its rows to an ACS seat the ceiling stopped */
  unsigned int loss;                  /* loss notifications of its messages:
                                       * the framer evicted a train */
  unsigned int malformed;             /* its rows refused from the tag */
  unsigned int notInitiator;          /* its INITIAL or BESIDE of an
                                       * instance it does not initiate */
  unsigned int initOther;             /* its INITIAL under another value than the sign part held */
  unsigned int partOther;             /* its sign part not under the value it must have, or a second
                                       * with none held to judge by, refused unchecked */
  unsigned int rcvRefused;            /* its recover legs' descriptions refused */
  unsigned int unitBad[6];            /* its parts refused, by the gate (AC_UNIT_*);
                                       * none at AC_UNIT_MEM, this seat's own */
  unsigned int shardOther;            /* its second, different shard ahead
                                       * of the sign part: the first kept */
  /* the signer's, from a verified signature, whoever carried it */
  unsigned int secondApex;            /* its verified sign part under another value */
  unsigned int signReplaced;          /* its sign part under the held (initial,
                                       * v) replaced one under another apex */
  unsigned int slotReused;            /* its one-time slot signed twice: leaked, refused */
  unsigned int offsetReplay;          /* its old signature re-dealt at a later position */
  /* the link, both ways, in message bytes at the framers: what this
   * seat gave its egress framer for it, what its ingress framer
   * completed from it, and the most of each in one tick of this seat's,
   * which against the tick and the declared bandwidth is the link's
   * load as this seat saw it */
  unsigned long sentBytes;
  unsigned long recvBytes;
  unsigned long sentTickMost;
  unsigned long recvTickMost;
  unsigned long rttMost;              /* the round trips, microseconds: the longest */
  unsigned long rttSum;               /* and their sum */
  unsigned long rttLeast;             /* and the shortest: the earliest its word has come back */
  unsigned long lateMostUs;           /* the latest value, microseconds after the (n - t)th 1 */
};

struct acCounters {
  unsigned long overUs;               /* the longest a tick started past its due,
                                       * microseconds: a pass in hand, or the
                                       * caller's cadence */
  unsigned long retainedBytes;        /* the retention: bytes of records held now, */
  unsigned long retainedMost;         /* the most at once, its high water, */
  unsigned long saidBytes[3][4][4];   /* bytes the framer took, by why (AC_SAID_*),
                                       * class (AC_CLS_*) and kind (AC_KIND_*) */
  unsigned long saidUs[3][4][4];      /* and their wire time at the declared bandwidth,
                                       * microseconds, shards and parity */
  unsigned long dgBytes;              /* datagrams sent: their bytes, IP and UDP headers counted */
  unsigned int said[3][4][4];         /* and those messages */
  unsigned int dgSent;                /* datagrams sent */
  unsigned int launchHeld;            /* the launch's checks the last position's assembly held */
  unsigned int igrEvict;              /* the ingress framer's incomplete messages evicted, */
  unsigned int igrEvictFull;          /* of those, by a new tag on a full table */
  unsigned int sweepYoung;            /* positions a pass passed over:
                                       * launched under a tick before */
  unsigned int dgFrg;                 /* the fragments they carried */
  unsigned int sweepAge[4];           /* a sweep's re-sends, by its position's age since its
                                       * launch here: under a tick, under 2, under 4, more */
  unsigned int retained;              /* records held now, */
  unsigned int released;              /* and records the head overwrote: let go */
  unsigned int future;                /* a row naming a position this seat has not
                                       * minted the name of: held until it does */
  unsigned int aheadMem;              /* such a row not held: this seat's memory
                                       * refused it; its sender's sweep brings it
                                       * again */
  unsigned int rowMem;                /* a row whose kept position or leg this seat's
                                       * memory refused: not taken; its sender's
                                       * sweep brings it again */
  unsigned int ownMem;                /* a step of this seat's own its memory refused --
                                       * a launch, a leg, a record -- nothing of it
                                       * spent: the seat's next call takes it again,
                                       * and counts again */
  unsigned int aheadDup;              /* such a row of a message held already, by its
                                       * tag: its annotations taken, the rest dropped */
  unsigned int aheadFull;             /* a row not held: its sender already has the
                                       * live window's count and one more of rows of
                                       * that shape held here under other names, so what is
                                       * held is bounded by the shape of a position
                                       * and the window, never by what a sender
                                       * says; its sweep brings it again */
  unsigned int recorded;              /* rows naming a position retained here: its
                                       * legs' rows fed to its machines, started
                                       * again from the record where they are not
                                       * running */
  unsigned int recovered;             /* positions folded here on T legs'
                                       * descriptions alike, from distinct seats,
                                       * before this seat's agreement there
                                       * completed: this seat behind the others,
                                       * most of all behind their live windows */
  unsigned int placed;                /* unit parts under a recorded name, of a
                                       * member that left the live window under
                                       * threshold here: taken to the position's
                                       * assembly the record keeps, whose gates
                                       * judge them as a live one's do */
  unsigned int placedAfter;           /* the most ticks after its position left
                                       * the live window here that such a part
                                       * landed, on this seat's clock */
  unsigned int kept;                  /* positions whose assembly a record kept */
  unsigned int keptMembers;           /* members under threshold, or with their
                                       * last pass owed, at their position's
                                       * end here: kept */
  unsigned int keptPassed;            /* of them, reported with the message */
  unsigned int keptUnder;             /* reported under threshold, the record let
                                       * go */
  unsigned int keptNow;               /* still kept, unreported, as read */
  unsigned int repeated;              /* this seat's value broadcasts started as a
                                       * bracha87Fig1 alone, its agreement
                                       * let go or at the ceiling with the
                                       * position unfolded */
  unsigned int heldRepeated;          /* and at a launch held: the last position
                                       * folded, a member short here, left the
                                       * live window with its machines gone */
  unsigned int recoverStarts;         /* recover legs started toward a seat: a
                                       * row of its naming a position in the
                                       * retention, no recover leg of this
                                       * seat's running toward it there */
  unsigned int endRefused;            /* rows refused past the chain's end, its
                                       * last link gone from the live window:
                                       * no recover leg starts, no row is held */
  unsigned long recvTickMost;         /* the most message bytes completed here
                                       * from every seat in one tick: against the
                                       * tick and the declared bandwidth, whether
                                       * this seat's ingress was held to the
                                       * declaration */
  unsigned long egrWaitUs;            /* the longest a message waited in the
                                       * egress framer, its Put to its last
                                       * shard sent, microseconds: against the
                                       * tick, whether a re-send could leave
                                       * before the first had */
  unsigned int rcvRefused;            /* recover descriptions refused: malformed, a
                                       * subset or a member's value other than this
                                       * seat's own, or a second one from a seat */
  unsigned int slotReused;            /* a verified sign part at a signer's slot
                                       * already agreed here under another value: the
                                       * one-time slot leaked, the signer Byzantine;
                                       * refused at or past the last position whose
                                       * subset took the signer */
  unsigned int offsetReplay;          /* a verified sign part at a slot below the
                                       * signer's high water, at or past the last
                                       * position whose subset took the signer: an old
                                       * signature re-dealt, refused */
  unsigned int replayed;              /* rows held ahead taken at their launch */
  unsigned int replayMost;            /* the most of them taken in one acInput or acWork */
  unsigned int launchOnRows;          /* positions launched here on another seat's
                                       * rows for them, no word from the caller and
                                       * no rotation to present again: its input was
                                       * what the caller gave when asked, its noop,
                                       * or the rotation or switch its context was due.
                                       * A seat that proposes at every fold costs
                                       * every other seat a position of
                                       * agreements for it */
  unsigned int routedUnit;            /* a unit of an instance not live here */
  unsigned int inAcs;                 /* class 0 rows fed */
  unsigned int inDist;                /* class 1 INITIAL, ECHO, READY fed */
  unsigned int inLeg;                 /* class 2 INITIAL, ECHO, READY fed */
  unsigned int inDunit;               /* class 1 BESIDE: a part of X's unit to this seat */
  unsigned int inXunit;               /* class 2 BESIDE: a part of S's exchange unit of X */
  unsigned int dupDunit;              /* a part already held: X has not yet recorded
                                       * this seat's echo */
  unsigned int dupXunit;
  unsigned int shardAhead;            /* a shard landed ahead of its sign part: stashed */
  unsigned int shardOther;            /* a second, different shard ahead of the sign
                                       * part: the first kept */
  unsigned int dupInitial;            /* an INITIAL already fed to its instance */
  unsigned int initOther;             /* an INITIAL under another value than the
                                       * held sign part's apex: fed, the part not
                                       * fed beside it */
  unsigned int partOther;             /* a sign part whose value, under either of the
                                       * signer's roots, is not the agreed one, else
                                       * the (initial, v) held, or any second one with
                                       * none held: refused before its signature is
                                       * checked, its sender's */
  unsigned int unitSent;
  unsigned int unitBad[6];            /* units refused, by the gate (AC_UNIT_*) */
  unsigned int secondApex;            /* a verified sign part under another value:
                                       * than the agreed one; than the (initial, v)
                                       * held, a part held or not; or, with no v
                                       * held yet, than the one held, which is kept;
                                       * and a second rotation of a context whose
                                       * successor the book has installed */
  unsigned int signReplaced;          /* a verified sign part under the held (initial, v)
                                       * replaced one held under another apex: a
                                       * two-faced dealer */
  unsigned int asmAlloc;              /* an assembly this seat could not allocate for:
                                       * owed, and taken again at every tick, past
                                       * its position's end with its record */
  unsigned int noInstance;            /* a leg row with no instance here: before
                                       * this seat's SUBSET, or a leg it never
                                       * launched; BPR re-serves it */
  unsigned int stopped;               /* a row to an ACS seat the ceiling stopped */
  unsigned int notInitiator;          /* INITIAL or BESIDE from a seat that is not
                                       * the instance's initiator */
  unsigned int malformed;             /* length, index, class/payload mismatch */
  unsigned int loss;                  /* ingress loss notifications: the framer
                                       * evicted an incomplete train; BPR
                                       * re-serves it */
  unsigned int lossUnit;              /* of those, units */
  unsigned int qDrop;                 /* the hand-back queue could not grow: this
                                       * seat's memory */
  unsigned int replyEcho;             /* replies said, an echo to one seat, */
  unsigned int replyReady;            /* or a ready */
  unsigned int frmRefused;            /* a message the egress framer refused */
  unsigned int igrBusy;               /* a datagram the ingress framer refused,
                                       * its last deliveries not all taken */
  unsigned int igrGate;               /* datagrams the ingress framer's gate refused:
                                       * not keyed by a dealt secret */
  unsigned int igrAuth;               /* datagrams its authentication tier refused:
                                       * not from the sender the tag names */
  unsigned int sendRefused;           /* sends the caller refused: the datagram
                                       * stays due, the pass ends there, and the
                                       * next pass offers it again */
  unsigned int passLong;              /* passes that ended past the tick they
                                       * were due in: what the pass carried past
                                       * one step's feedback cycle, the live
                                       * positions' rows and the messages'
                                       * shards, or the caller's cadence; the
                                       * next tick starts when the pass ends */
  unsigned int subsetMost;            /* the most sweeps an agreement here ran to its
                                       * SUBSET: the longest the deployment's load has
                                       * made one, the abandon's floor as measured; the
                                       * abandon at twice the longest with a seat stopped */
  unsigned int noSubset;              /* agreements here abandoned at the round
                                       * ceiling with no subset, their SUBSET's or a
                                       * DISCOVER's: undecided past the phases; short
                                       * of the ceiling an agreement runs until its
                                       * subset */
  unsigned int liveMost;              /* the most positions in the live window here at
                                       * once, each its agreement's machines, legs and
                                       * units; the oldest leaves once folded with every
                                       * machine at the abandon, so one unfolded holds
                                       * every younger one: the memory the abandon costs,
                                       * beside the retention and the records' machines
                                       * a returning seat starts again */
  unsigned int parityUsed;            /* parity shards the ingress decodes used,
                                       * in all: the steady loss as met */
  unsigned int parityMost;            /* the most one message's decode used */
  unsigned int parityLast;            /* decodes that used every parity shard
                                       * the message left with: one more loss
                                       * was an eviction */
  unsigned int unitMax;               /* this seat's largest own unit, bytes */
  unsigned int again;                 /* payloads a subset left out presented again on
                                       * the caller's same bytes, no slot spent */
  unsigned int proposeLong;           /* lengths the caller gave past msgMax, the
                                       * caller's error: the noop proposed instead */
};


/*
 * A seat, from the caller's parameters and callbacks, both copied: the
 * sizes derived (acDerive), the signing identity minted, the tables and
 * retention allocated.  Every callback but trace is required.  0 where
 * the parameters make no seat or an allocation failed, and nothing is
 * kept.
 */
struct ac *acInit(const struct acPar *, const struct acCb *);

/*
 * What the construction fixes from the physics and the configuration
 * given: the threshold, the sizes, the longest message a proposal
 * admits, the longest record a position leaves, the parity and the
 * pacing (each per message, from the loss and the bandwidth), the tick,
 * the patience, the round ceiling.  0, or -1 where the parameters make
 * no seat: a self outside 0..n-1, a suite not as struct acHash states
 * it, or a retention below one record among the reasons.
 */
int acDerive(struct acPar *);

/* this seat's public key, hashSz bytes: minted at acInit, the caller
 * publishes it */
const unsigned char *acPub(const struct ac *);

/*
 * One other seat's row entry: the pairwise secret, AC_PSK bytes, and
 * that seat's public key, hashSz bytes, both copied, so the caller may
 * wipe its own.  0, or -1 for a seat outside 0..n-1, self, one already
 * dealt, or any after the go.
 */
int acDeal(struct ac *, unsigned char seat, const unsigned char *psk, const unsigned char *pub);

/*
 * The go: every other seat dealt, the chain's genesis, hashSz bytes,
 * copied, and the caller's clock.  The framers are keyed and position 1
 * launches, every seat's rotation.  0, or -1 with a seat undealt, a go
 * already made, the framers refused -- memory alone, and the seat left
 * as the call found it, to go again -- or the seat failed at the launch
 * (acFailed).
 */
int acGo(struct ac *, const unsigned char *genesis, unsigned long nowUs);

/*
 * The caller has a message to propose.  With no position in hand here,
 * one launches at the next pass, or in the pass in hand from a
 * callback, and, where the signing context leaves it a payload slot or
 * a payload a subset left out is kept, its proposal is asked of the
 * caller (propose); 0.  With one in hand, or before the go, whose
 * position 1 is every seat's rotation, nothing is done and nothing is
 * kept; 1: the chain report of the one in hand is where the caller
 * learns what became of its proposal and decides what to propose next.
 * -1 for a null seat, or one ended -- its caller's acEnd, or the
 * chain's last link folded here -- quiet or failed.
 */
int acAvailable(struct ac *);

/*
 * A datagram from the wire, len bytes as the transport delivered them,
 * received into dgramMax + 1 bytes so a longer one shows, and the
 * clock.  What it completes is read and the work that leaves is done;
 * what that says waits in the framer for acWork to send.  0, or -1 for
 * a null seat or datagram, one not started, or one that failed before
 * the call.
 */
int acInput(struct ac *, const unsigned char *dgram, unsigned int len, unsigned long nowUs);

/*
 * The pass: the datagrams due to the caller's send until the caller
 * refuses one, the held message to the framer, the tick when due, the
 * work.  Returns the microseconds until the seat next has something due
 * -- a datagram the framer paces, or the tick, which is due only while
 * no pass is in hand (a pass that outlasts the tick waits on the
 * framer's pacing, and the next tick starts when it ends) -- 0 when
 * something is due now or a send was refused, which the caller, who
 * refused it, knows and waits for its socket on, and -1 when nothing is
 * due: a seat quiet, told so or its end run over, with nothing left in
 * its framer, one not started, or one that failed (acFailed).
 */
long acWork(struct ac *, unsigned long nowUs);

/*
 * The caller's end of the chain, a state of this seat, not a message:
 * nothing more is asked of the caller (acAvailable refuses, a payload a
 * subset left out is let go), every value this seat signs from here
 * carries the end, a byte in its preimage and its shape, and the call
 * is its reason to launch, so an idle chain folds on to the end.  A
 * value signed before the call is presented again as it was.  The chain
 * ends at the first fold whose subset holds more than t members
 * carrying it (acChain's end): t faulty seats cannot reach the count,
 * so a correct seat's caller asked, and every correct seat that folds
 * that position reads the same subset and the same sign parts, so the
 * chain ends there at every one of them, one final hash, or at none.
 * Once every correct seat's caller has called, and each one value it
 * signed before has landed in a subset or been let go, every subset
 * holds at least n - 2t correct members carrying it, more than t, and
 * the chain ends.  Nothing launches after the last link.  The seat then
 * runs its end: once that link has left the live window, every member
 * of it reported here, its record carries a seat behind for one abandon
 * more, then nothing new starts, and once every record's machines are
 * let go the seat is quiet of its own accord: acWork returns -1 once
 * the framer is empty.  A member whose message this seat cannot yet
 * have holds the end as it holds a launch: slow, never stopped.  The
 * last link, the final hash, is a next chain's genesis where more than
 * t seats report it alike, a correct seat's; that chain is dealt
 * afresh, since no seat's identity outlives its process and the framer
 * authenticates a datagram by its pair secret alone: under the old
 * secrets what this chain put on the wire, replayed or from a seat
 * still in it, would be a seat's word in the next.  The caller's stop
 * (acQuiet) is local: nothing more is said -- no pass, no re-send, no
 * launch -- and what the framer holds goes at its pace; to the other
 * seats it is a silence, one of t.  Either may be called from a
 * callback.
 */
void acEnd(struct ac *);
void acQuiet(struct ac *);

/* non-zero once the seat has stopped on a parameter its derivation
 * validated, refused by a library beneath it whose only refusal is a
 * parameter: no deployment reaches that, short of a fault in this tree.
 * Memory refused never stops a seat (rowMem, ownMem, asmAlloc).  acWork
 * returns -1 and acInput refuses from then on */
int acFailed(const struct ac *);

/* this seat's tick count: a tick starts a pass of the retry over every
 * live position, and every count here is in ticks */
unsigned int acTicks(const struct ac *);

/* the seat's counters, copied: the application's instrument */
void acCounters(const struct ac *, struct acCounters *);

/* what this seat counts of one other seat, copied; 0, or -1 for a null
 * seat, a seat outside 0..n-1 or this seat itself, which counts nothing
 * of its own */
int acSeatCounters(const struct ac *, unsigned char seat, struct acSeatCounters *);

/* the parameters as derived: what the seat runs by */
const struct acPar *acPar(const struct ac *);

/* release a seat, or nothing for a null one: the secrets wiped,
 * everything freed */
void acFree(struct ac *);

#endif /* AC_H */
