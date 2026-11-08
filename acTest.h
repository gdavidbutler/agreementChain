/*
 * agreementChain - the harness's interface to a seat
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

#ifndef ACTEST_H
#define ACTEST_H

/*
 * The harness's interface to a seat: the hooks a test attacks a seat
 * through, the knobs that stand in for a derivation, and the framers'
 * counters, defined with AC_TEST and in no deployment; and the names
 * they speak in, the wire's tag, its parts, the dealer's fault classes,
 * the parameters by name and the sizes both count by, which ac.c reads
 * here in every build and no deployment's caller needs.  ac.h is the
 * seat; this is what a test needs beside it.
 */

#include "ac.h"
#include "rsecFrm.h"

/*
 * The wire's tag, the bytes that name a message, which the head comment
 * of ac.c states (THE WIRE) and the test hooks see: Bracha's (p, k) tag
 * raised to the chain, [byte][ba][round][initiator][sender][name].
 * The byte: the kind in bits 0-1, the BA value or a part in 2-3, the
 * class (AC_CLS_*, ac.h) in 4-5, a READY's two annotations in 6-7.  The
 * name is the position's name, the chain hash before it, hashSz bytes.
 * On a recover leg, class 3, the round byte names its returner.
 */
#define AC_TAG_BA     1
#define AC_TAG_ROUND  2
#define AC_TAG_INIT   3
#define AC_TAG_SENDER 4
#define AC_TAG_NAME 5
#define AC_TAG_SIZE(hashSz) (5 + (hashSz))
#define AC_TAG_BYTE(cls, kind, value) (((cls) << 4) | ((value) << 2) | (kind))
#define AC_TAG_KIND(b)   ((b) & 3)
#define AC_TAG_VALUE(b)  (((b) >> 2) & 3)
#define AC_TAG_CLASS(b)  (((b) >> 4) & 3)
#define AC_TAG_ANN(b)    ((b) >> 6)
#define AC_TAG_ANN_SHIFT 6
/* the sidecars beside an INITIAL, bits 2-3 of a BESIDE's tag byte: the
 * sign and the data, on classes 1 and 2 */
#define AC_PART_SIGN   0
#define AC_PART_DATA   1
#define AC_PART_DESC   2                /* class 3 alone: the link's
                                         * description beside a recover leg */

/* the fault classes a test build's dealer can commit (fault) */
#define AC_FAULT_SHARD   1
#define AC_FAULT_SHARE   2
#define AC_FAULT_GEOM    3
#define AC_FAULT_CT      4
#define AC_FAULT_SALT    5
#define AC_FAULT_PAD     6
#define AC_FAULT_TWOFACE 7
#define AC_FAULT_SPLIT   8
#define AC_FAULT_BOTH    9          /* a shard of one leaf and a share of another */
#define AC_FAULT_TWOSLOT 10         /* one apex signed at two slots */
#define AC_FAULT_REUSE   11         /* the second payload signed at the first's slot */
#define AC_FAULT_BELOW   12         /* the third payload signed at the first's slot, below the second's */
/* the three signing faults, dealt to seat 0 alone */
#define AC_FAULT_SIGNING(f) ((f) == AC_FAULT_TWOFACE || (f) == AC_FAULT_SPLIT || (f) == AC_FAULT_TWOSLOT)
/* the two spent-slot faults: every unit the dealer deals is good, one
 * payload is signed at a slot its subsets already took */
#define AC_FAULT_SPENT(f) ((f) == AC_FAULT_REUSE || (f) == AC_FAULT_BELOW)

/* the parameters by name, S the struct acPar in hand, as ac.c and the
 * harness both read them */
#define N            (S->n)
#define MaxByz       (S->t)
#define Threshold    (S->T)
#define Shard        (S->shard)
#define TickMs       (S->tickMs)
#define Patience     (S->patience)
#define Rounds       (S->rounds)
#define Abandon      (S->abandon)
#define Retention    (S->retention)
#define RecMax       (S->recMax)
#define MlsS         (S->mlsS)
#define DgramMax     (S->dgramMax)
#define BwLimit      (S->bwLimit)
#define ParityShards (S->parity)
#define ShardDelayUs (S->shardDelayUs)
#define HashSz       (S->hashSz)
#define SignH        (S->signH)
#define KdfSz        (S->kdfSz)
#define KdfMax       (S->kdfMax)
#define HmacSz       (S->hmacSz)
#define SigLen       (S->sigLen)
#define PfSz         (S->pfSz)
#define MsgMax       (S->msgMax)
#define UnitFixed    (S->unitFixed)
#define ShardMax     (S->shardMax)
#define PartMax      (S->partMax)
#define Sign         (S->sign)
#define Kdf          (S->kdf)
/* a bitmap's bytes, a bit a seat */
#define BITS(n)      (((n) + 7) / 8)
/* IPv4 and UDP: the wire carries them beside every datagram */
#define IPUDP_HDR    28
/* a signing context's first payload slot, after its rotation's */
#define SLOT_PAY     1

/*
 * The hooks and the knobs.  The two message filters see each message as
 * it leaves and as it arrives: the ingress filter answers non-zero to
 * let it pass; the egress filter is told the position the message is
 * of, by the seat's count, 0 for a record's re-send past the live
 * window, and answers the payload length to send, which may be 0, or -1
 * to drop it, and may rewrite the tag and the payload's bytes, which
 * are then authenticated as the seat's own word -- a Byzantine seat
 * says what it likes under its own key, while what it feeds itself never
 * crosses the hook; badMac, every message of this seat's under a proof
 * that fails; a dealer's fault and a laggard's hold act
 * inside the seat.  A knob set stands where the derivation would: the
 * parity (-1 derives it per message), the inter-shard pacing (-1
 * derives it), the tick, the patience and the round ceiling (0 derives
 * each).
 */
struct acTest {
  void *ctx;
  int (*egress)(void *, unsigned int inst, unsigned char dest, unsigned char *tag, unsigned char *payload, unsigned int len);
  int (*ingress)(void *, const unsigned char *tag, const unsigned char *payload, unsigned int len);
  long shardDelayUs;
  int parity;
  unsigned int tickMs;
  unsigned int patience;
  unsigned int rounds;
  unsigned int fault;
  unsigned int badMac;
  unsigned int lag;
  unsigned int refuse;                  /* 1 + the member whose search this seat's memory refuses
                                         * until its position's end keeps it, or 0 */
  unsigned int refuseAt;                /* where: 0 the search's buffers, 1 the pool's */
  int tagAudit;                         /* -l: the framer refuses nothing, and each
                                         * arrival is held to what it would have refused */
  int tagPredict;                       /* this arrival would have been */
  int tagMoved;                         /* and it drew a reply here */
  unsigned int tagPred;                 /* -l: arrivals it would have refused */
  unsigned int tagBad;                  /* of those, ones proved or replied to here */
  unsigned int dealtAt;                 /* -f 11, 12: the instance it was dealt at */
  unsigned int dealt;                   /* -f 7, 8, 10, 11, 12: the fault's second
                                         * signature was made and dealt */
};

/* acDerive, the knobs standing where they are set */
int acTestDerive(struct acPar *, const struct acTest *);

/* acInit, the knobs standing where they are set, and the hooks kept by
 * pointer for the seat's life, or 0 for none */
struct ac *acTestInit(const struct acPar *, const struct acCb *, struct acTest *);

/* the parity shards and the inter-shard pacing a message of payLen
 * bytes leaves with, from derived parameters, the knobs standing where
 * they were set: the shards it expects to lose to the steady loss, and
 * one datagram's wire time at the bandwidth, in microseconds */
void acTestPace(const struct acPar *, unsigned int payLen, unsigned int *m, unsigned long *d);

/* the framers' counters, copied into those not null */
void acTestCounters(const struct ac *, struct rsecFrmEgrCtrs *, struct rsecFrmIgrCtrs *);

/* the records whose machines run now */
unsigned int acTestKept(const struct ac *);

/* whether a signer's high water is set here and, when it is, its
 * context, signing offset, position and apex (hashSz bytes) */
int acTestHw(const struct ac *, unsigned int seat, unsigned int *gen, unsigned int *off, unsigned int *pos, unsigned char *apex);

#endif /* ACTEST_H */
