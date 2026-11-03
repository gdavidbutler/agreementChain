/*
 * agreementChain - the harness
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
 * test/ac.c - the harness: N seats, as threads of one process, each
 * binding one seat of the library (ac.h) over its own UDP socket on the
 * loopback, with the operator in main, who deals the pairwise secrets
 * and the addresses, launches the seats, collects their reports and
 * judges them against each other, every datagram reconciled.  The
 * harness attacks its own seats: the declared network at each seat's
 * send, the cuts, the split and the censor through the library's test
 * hooks on the messages (AC_TEST), the dealer's faults and the
 * laggard's hold inside the seat under the same build.  The library's
 * head comment is the design; this file is what is tested.
 *
 * Build:
 *   make check
 *
 * Usage:
 *   ./acTest -W bps [options] N t
 *
 *   The declared network, applied at each seat's sendto (loss and delay
 *   default 0):
 *     -W bits_per_s  the bandwidth a seat sends, bits/sec on the wire, IP
 *                    and UDP headers counted: required.  UDP has no back
 *                    pressure, so every seat paces its datagrams to it
 *                    (acTestPace's d); a send past it is the network's to
 *                    drop
 *     -D drop        packet drop percent 0..99; with parity to use, the
 *                    judge expects some decode to have used it
 *     -L delayms     max random send delay (ms), uniform 0..delayms
 *     -B burstms     mean burst duration (ms), Gilbert-Elliott loss:
 *                    the declared loss shaped into bursts that take
 *                    whole trains, which BPR pays for across ticks and
 *                    the parity has no margin for; declared to the
 *                    seats as the longest, twice the mean, which the
 *                    patience waits out; the judge expects some train
 *                    evicted or some parity used
 *     -K burstdrop   drop percent while in burst state (default 90)
 *
 *   Protocol options.  Five are knobs the test build sets where a
 *   seat derives (acTest.h: -m, -d, -r, -g and -P); a deployment has
 *   none of them:
 *     -m parity      parity shards per message; derived: the shards the
 *                    message expects to lose to steady loss, round(k *
 *                    D / (100 - D)) (acTestPace)
 *     -d shardus     inter-shard pacing delay in microseconds; derived:
 *                    one datagram's wire time under -W
 *     -p port        base UDP port (default 42000)
 *     -r tickms      the retry cadence: BPR has no RTT of its own, so
 *                    the tick is where the physics is declared.
 *                    Derived: one feedback cycle, a broadcast's
 *                    INITIAL with the sign part beside it to the N - 1
 *                    others at the declared bandwidth, the ECHO back
 *                    from each, and twice the declared delay, floored
 *                    at 50; a pass that carries more than the tick
 *                    runs past it, and the next tick starts when it
 *                    ends
 *     -g patience    patience, in sweeps; derived: 2, one partial sweep
 *                    and one tick, the feedback cycle, and the sweeps
 *                    the declared loss (-D) and burst (-B) retry; the
 *                    abandon, -A, sits above it, and at t > 0 at 1 + 7
 *                    of it
 *     -P phases      phases of three rounds an agreement may run, 1..85;
 *                    derived: 85, the byte.  The coin is each seat's own, so a
 *                    BA whose inputs a scheduler split (the readies of
 *                    one value withheld from k seats past patience)
 *                    ends a phase only when more than (N + t) / 2 of
 *                    the N - t honest coins agree, 2t / sqrt(N - t)
 *                    standard deviations: 1/4 a phase at 4 1, 1/16 at
 *                    7 2, 1/37 at 26 5, 1/15 at 41 5.  The ceiling is
 *                    paid in seats: at 2t / sqrt(N - t) <= 1.5 with
 *                    N + t odd (the coins are a whole count, so an even
 *                    N + t needs one more), N above about 1.8 t^2 + t,
 *                    a split BA outlasts 85 phases under 1e-5 against a
 *                    scheduler that sees every coin
 *     -c ticks       the tick cap, a guard only (default 128 x
 *                    instances)
 *     -n instances   the messages a seat proposes (default 1); at its
 *                    n-th fold each seat calls the end (acEnd), and the
 *                    chain ends at the first link more than t members
 *                    carry it into
 *     -e step        seat i calls the end at its (n + i x step)-th fold
 *                    instead, proposing a message for every position
 *                    before it: every seat calls at a different link
 *     -E k           seats 0..k-1 alone call the end: at most t of them,
 *                    no end comes, and the harness stops each seat at
 *                    the positions its reports are kept for
 *     -s signings    2^s slots a signing context (default 2: a rotation
 *                    and three payloads)
 *     -i             seat N-1 is idle: it proposes nothing, so every
 *                    position after its rotation launches there on the
 *                    others' rows for it, its noop -- the hash of its
 *                    key alone signed at the next payload slot -- its
 *                    input, a rotation of its a subset left out
 *                    presented again excepted; the judge expects some
 *                    position launched that way there, no more than
 *                    the positions after its first, and none at the
 *                    seats that propose when nothing is lost
 *     -z lagticks    seat N-1 is a laggard: the INITIAL of each new
 *                    proposal of its own is held back this many ticks, so
 *                    the subset closes without it and it proposes the
 *                    same blob again in the next instance, presented
 *                    again and not held, an even one excepted, which it
 *                    lets go, giving the next; the judge expects every
 *                    payload agreed to be the bytes its seat gave when
 *                    asked, and the laggard to deliver, present again
 *                    and let go some; past patience,
 *                    the judge expects some chain report to show it
 *                    entered 0 for seat N-1
 *     -w slowness    seats 0 .. -v's count less one are processors
 *                    this many times slower than the host's: after the
 *                    seat's own work the thread sleeps slowness - 1
 *                    times the processor time it took, so its passes,
 *                    and its every answer, take that much longer, an
 *                    Atom beside a Xeon; nothing is judged of it
 *     -v seats       the slow seats of -w (default 1)
 *     -x cutticks    seat N-1's ingress is cut for this many ticks from
 *                    the go, and its egress too unless -X says
 *                    otherwise: the others fold without it, and on its
 *                    return the rows their ACS seats and legs kept
 *                    re-sending carry it through each position still
 *                    in their live windows, and for the positions behind
 *                    them it DISCOVERs the subset on T descriptions
 *                    alike beside their legs, which their machines for
 *                    each, started again from its record by its own
 *                    rows naming it, carry it, units and all, a
 *                    position a round trip; its two reports then
 *                    equal theirs, and where it folded a link more than
 *                    the abandon and two ticks after the first other
 *                    seat did, the judge expects some seat's
 *                    machines started again from a record and some
 *                    position DISCOVERed at it
 *                    (the lossless reconciliation is off: what the cut
 *                    dropped the framers never counted; the cut must
 *                    outlast the window's filling, and while a seat is
 *                    silent the others fold a position about every
 *                    fourteen ticks at 4 1, spending patience on it at
 *                    every round, so ninety ticks leave three records
 *                    behind a window of four; at -D 10, a patience of
 *                    4, about every thirty, and the two after the
 *                    first up to seventy-six while the exchange toward
 *                    the cut seat fills the wire, so it takes three
 *                    hundred and twenty); cut past the retention
 *                    it is beyond recovery and ends at the cap; cut at
 *                    or past the cap it is DEAD for the run,
 *                    which the judge expects: the others complete every
 *                    position without it, each at the rounds run plus
 *                    one, times patience, in ticks, their sweeps
 *                    re-sending it everything they owe until the live
 *                    window lets each position go
 *     -X egressticks seat N-1's egress alone is cut for this many ticks
 *                    from the go: with -x shorter, the seat heals on
 *                    ingress first and can say nothing; the others' ACS
 *                    seats re-send to it throughout, and it completes a
 *                    position on them alone; the exchange units it
 *                    assembles from come by the others' legs, re-sent
 *                    from their fold until it says it holds them
 *     -U legticks    seat N-1's ingress of the exchange alone is cut
 *                    for this many ticks from the go: every class 2 row
 *                    dropped unread, the agreement's rows and the dealt
 *                    units delivered, its egress open.  The seat reaches
 *                    SUBSET holding what it was dealt, and what it was
 *                    not dealt reaches it only once the others' legs do
 *     -V             with -U, the dealt units' data parts are cut too:
 *                    the sign parts arrive, so the seat folds, and a
 *                    payload member's own shard lands past the cut,
 *                    after its position has left the live window, a
 *                    newer copy of its record due
 *     -O at:m        seat N-1's memory refuses its search of member m's
 *                    message, at = s at the search's buffers or p at
 *                    the pool's, until the position's end keeps m with
 *                    the record: the search owed past the end, the
 *                    next launch held on it, and m's message reported
 *                    here as at every other seat
 *     -S k:m         seats 0..k-1 receive no READY of seat N-1's value
 *                    for m ticks from the go, longer than patience, and
 *                    that value's BA rows do not cross between seats
 *                    0..k-1 and the rest for those ticks: the
 *                    scheduler's split of one BA's inputs, k zeros
 *                    against N - k ones, each group's sample its own
 *                    until the rows cross into a tie, which the coins
 *                    alone decide: 2:6 at 4 1 stops every seat at the
 *                    ceiling in every run at -P 1, in three runs of
 *                    eight at -P 2 (the 2-2 coin tie, 6 of 16), and in
 *                    none at the default; the judge expects some seat's
 *                    decision in some agreement past round 3, the first
 *                    phase in doubt
 *     -C             seat 0 sends seat N-1 no (initial, v) of its own
 *                    and no unit, ever, and runs as a correct seat
 *                    otherwise.  Seat N-1 is carried to the accept by
 *                    the others' readies and holds seat 0's unit only
 *                    from their legs, which re-send it until it says it
 *                    holds it: with -U it holds it when the cut heals
 *     -y tick        the cut (-x, -X, -U) begins at this tick instead
 *                    of the go, and runs its length from there
 *     -T links       the Internet's directed links over time, N <= 10:
 *                    phases split by '/', each ms=pairs, the ms since
 *                    each seat's own go the phase begins at and the
 *                    links it carries, a digit pair ab the link from
 *                    seat a to seat b, '*' every link, none a dark
 *                    network: a seat's message to a seat its link to
 *                    does not carry is dropped at its egress, unseen
 *                    by the seat, and -D, -L and -B apply to what is
 *                    carried.  Seats are never told: each sends from
 *                    its machines and keeps what arrives, and the
 *                    judge reads only the reports.  The stop prints
 *                    one seat at a time what it put in each phase,
 *                    by kind and destination, carried, dropped and
 *                    from a record, and what it got, by kind and
 *                    sender.  0=/5000=01 is a
 *                    network dark for five seconds, then seat 0 heard
 *                    by seat 1 alone
 *     -G bytes       seat N-1's socket receive buffer, below the
 *                    system's default: a smaller host's (FreeBSD gives a
 *                    UDP socket 42080), whose kernel drops what arrives
 *                    past it while the seat is not reading
 *     -Q positions   seat N-1 is frozen, at its first pass at or after
 *                    the tick -y names, until every other seat
 *                    has folded this many positions past the ones it had
 *                    folded, or the whole chain:
 *                    its thread calls nothing of the seat and reads
 *                    nothing of its socket, as a process stopped by a
 *                    signal is, its ticks and its sweeps standing still
 *                    and its socket's queue filling and then losing; on
 *                    its return it reads what the kernel kept and
 *                    carries on.  The thaw is an event the harness sees
 *                    in the others' reports, never a time, so with more
 *                    positions than the live window the others are past
 *                    it at the thaw whatever the host, and the judge
 *                    expects machines started again from a record, as
 *                    for a cut; a chain too short for that is the arm not
 *                    run, and the judge says so; frozen past the
 *                    retention it is partitioned, as a cut is; the
 *                    others all ending short of the thaw, it ends
 *                    frozen, as capped
 *     -Y             the cut is every seat's, not seat N-1's alone:
 *                    the network dark for its length, every seat's
 *                    machines at every live position waiting it out
 *     -Z from:len    every seat but N-1 proposes nothing from this tick
 *                    for this many ticks, and proposes again after: the
 *                    chain idles at a folded head.  With -i and a cut
 *                    of seat N-1 inside the pause (-y, -x) outlasting
 *                    the others' live windows, seat N-1 sits at that
 *                    head with nothing pending and its broadcast owed
 *                    to nobody, and misses the next position whole: on
 *                    its return the others' live rows, under names it
 *                    has not minted, are its one reason to launch it,
 *                    and its rows there start the others' machines
 *                    again from their records; the judge expects
 *                    machines started again from a record
 *     -A sweeps      the sweeps an instance runs before it stops,
 *                    how long the deployment holds its memory: its
 *                    abandon, paid out of t, at t > 0 at least one
 *                    agreement with a member gone, 1 + 7 patiences at
 *                    the least.  A deployment measures its own (the
 *                    README); the default here is a stand-in, twice
 *                    that least, which a loaded run can outlast, as
 *                    the longest agreement printed beside it shows
 *     -M bytes       a seat's retention (default 16 MiB): the records
 *                    of the positions behind its live window, the
 *                    newest over the oldest, at least the longest a
 *                    position can leave (recMax, printed); declared,
 *                    the judge expects some record let go
 *     -u bytes       each seat's blob (default 200; 0 is a message)
 *     -F bytes       the datagram (default 508, IPv4 fragment-free)
 *     -H hash        the sign role: rmd128 (default), sha256, sha3256
 *                    or sha3512
 *     -k hash        the kdf and wire-MAC role: rmd160 (default),
 *                    rmd128, sha256, sha3256 or sha3512
 *     -f fault       seat N-1 commits a fault in every payload it deals
 *                    and otherwise runs as a correct seat: 1 a shard
 *                    flipped before the tree (a non-codeword), 2 a
 *                    share flipped before the tree (off the
 *                    polynomial), 3 the sssMk tree built under points 0
 *                    and 1 swapped (a non-derived geometry: refused at
 *                    receive at the two mis-bound leaves, whose seats do
 *                    not echo the dealer's initial; where the rest still
 *                    accept it, 7 2, the others' readies carry those two
 *                    seats to the same accept and the legs bring them
 *                    the header and the parts; at 4 1 the dealer's
 *                    payload falls out of every subset); 1, 2, 3, 5, 6
 *                    and 9 reproduce the hash where T good parts are in
 *                    hand and the commitment, inconsistent, gives no
 *                    message anywhere; 4 a ciphertext byte
 *                    flipped before both codes (a consistent codeword
 *                    of the wrong bytes: no subset reproduces the
 *                    signed hash, no message anywhere); 5 every share
 *                    but the last T flipped before the tree, one at
 *                    T = R (salted: the good subset is the last in
 *                    whack-a-mole order, past more K candidates than R,
 *                    searched past where R > T; at thirteen seats the
 *                    candidates outrun the try budget, and a seat that
 *                    spends it reports no message, budget spent); 6 a padding byte of
 *                    the last data shard flipped after the parity and
 *                    before the tree (the hash sees the message and
 *                    nothing of the padding, so every subset reproduces
 *                    it, and only a re-encode from the message's own
 *                    canonical stream names the leaf); 7 two-faced: in place of its
 *                    rotation at instance 1 it deals a payload, and
 *                    signs that payload's apex at slot 0 too, dealing
 *                    it to seat 0 in a rotation's shape, the apex where
 *                    the successor key rides (a rotation's value is
 *                    the hash of the signing key and the key it
 *                    carries, so the carried apex recomputes to
 *                    another value, under which that part's signature
 *                    does not extract, and seat 0 refuses it;
 *                    the others' readies carry seat 0 to the accept and
 *                    the legs bring it the message; every seat folds
 *                    the apex as the payload it is; the dealer's slot
 *                    0 is spent and it never rotates, so -n stays
 *                    below 2^s, its switch); 8 split: its rotation
 *                    folded everywhere, it signs its second payload's
 *                    apex, hashed under its current key, a second time
 *                    with the installed successor and deals that copy
 *                    to seat 0 in the payload's shape (the value
 *                    commits the key: under the current key the
 *                    signature extracts to the successor, under the
 *                    successor the recomputed value is another, so
 *                    seat 0 refuses it and is carried to the accept and
 *                    the message as under 7, and every seat's fold
 *                    promotes nobody; needs -s 2 and -n 3, below the
 *                    switch, which would sign the spent slot again);
 *                    9 a shard of leaf 0 and a share of leaf 1 flipped
 *                    before the trees: under loss a seat may hold T good
 *                    shares beside the bad one while its T shards still
 *                    include the bad one, and the message must come
 *                    when the pool fills, by the end's relaxed pass over
 *                    every subset.
 *                    Instance 1 is every seat's rotation: -n 2 is the
 *                    first run that deals a fault 1..6 or 9, 7 is dealt at
 *                    instance 1, 8 at instance 3
 *     -b mask        seat N-1 (N-2 under -2) is a Byzantine row sender,
 *                    its tags, and under bits 8..32 its exchange parts,
 *                    rewritten at its egress before the framer
 *                    authenticates them as its own word, and it runs
 *                    as a correct seat otherwise; its own view stays
 *                    honest, since what it feeds itself never crosses
 *                    the hook.  Bit 1: it says HOLDING of nothing, its
 *                    ECHO and READY bare of every annotation, so every
 *                    other seat re-sends it what it is owed at every
 *                    tick for the live window, which its row of the
 *                    table counts, beside the honest rows' counts: a
 *                    reading, not judged, since any seat's row counts
 *                    the sweeps' rows to it and a judge of the ratio
 *                    would be one of the honest seats' timing.  Bit 2:
 *                    its agreement rows leave under random names, a
 *                    fresh one at every re-send, so each is a new
 *                    message to its own egress framer too, held at
 *                    every other seat under names never minted, the
 *                    live window of each shape and one more and the
 *                    rest not held;
 *                    the judge expects both counts in its row once the
 *                    chain is longer than two (-n
 *                    above 2).  Bit 4: its own value broadcast's
 *                    INITIAL leaves under the genesis, position 1's
 *                    name: while position 1 is live at the others an
 *                    INITIAL under another value, once it is a record
 *                    a row naming a record it has folded past, since
 *                    its agreement rows show it at live positions, so
 *                    it costs each seat one start of position 1's
 *                    machines from its record; the judge expects both
 *                    counts in its row once the chain has run past the
 *                    live window, and its value
 *                    in no subset after the first, since nobody holds
 *                    its INITIAL.  Whatever
 *                    it sends, every seat reports the same chain, and
 *                    every fault counted is counted to it: the honest
 *                    seats' rows of faults stay at zero.  Bits 8, 16
 *                    and 32 are hostile bytes from an authenticated
 *                    sender, cryptoMule's hostile arm at the exchange: one
 *                    byte of every exchange sign part it forwards
 *                    flipped (8), one byte of every exchange data part
 *                    (16), every exchange unit's part a byte short (32);
 *                    the judge expects some part so sent refused at a
 *                    gate, every refusal counted to it, no honest seat's part
 *                    refused, and every message delivered from the
 *                    other legs.  Bit 64: one byte of the description
 *                    beside every recover leg it initiates flipped, a lie about
 *                    the subset or a member's value; the judge expects
 *                    some refused, every refusal counted to it, and
 *                    every seat the same chain
 *     -2             the Byzantine seat of -b is N-2, not N-1, so that
 *                    seat N-1's cut (-x) and it make two faulty seats:
 *                    needs t >= 2
 *     -a             seat N-2 is the dealer's accomplice: with -f 5 at
 *                    7 2 its leaf is one of the T good ones, and it
 *                    sends its exchange parts, on its legs and its
 *                    recover legs, to seat 0 alone, so seat 0 alone
 *                    holds a subset that reproduces the signed hash;
 *                    the judge expects the dealer's message at no
 *                    correct seat.  Needs -f 1..6 or 9 and t >= 2,
 *                    and neither -b nor -C: the dealer and its
 *                    accomplice are the two faulty seats
 *     -t             the state trace: one line per transition of one
 *                    seat, stamped with its tick
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "rmd128.h"
#include "rmd160.h"
#include "sha256.h"
#include "sha3256.h"
#include "sha3512.h"
#include "huf.h"
#include "bracha87Fig1.h"
#include "halfsiphash.h"
#include "acTest.h"

#define USEC(ts)      ((unsigned long)(ts).tv_sec * 1000000UL + (ts).tv_nsec / 1000)
#define WAIT_MAX      1000
#define BIT_TST(mask, p) ((mask)[(p) >> 3] & (1 << ((p) & 7)))
/* the operator's deal, main's: the pair (i, k) of N x N */
#define MESH(i, k)    (mesh + ((i) * N + (k)) * AC_PSK)

/*------------------------------------------------------------------------*/
/*  Globals (set in main before any pthread_create, or by the judge once  */
/*  the seats have reported; the seats' folds, ends and freeze marks      */
/*  under FoldMu, and each seat's own Link* row)                          */
/*------------------------------------------------------------------------*/

static unsigned int        BasePort     = 42000;
static unsigned int        TickCap;
static unsigned int        BlobLen      = 200;
static unsigned int        Count        = 1;    /* -n: instances, one message a seat each */
static unsigned int        Step;                /* -e: seat i calls acEnd at its (Count
                                                 * + i * Step)-th fold, proposing a
                                                 * message for every position before it */
static unsigned int        Callers = AC_SEATS;      /* -E: seats 0..Callers-1 alone call acEnd */
static unsigned int        Slots;               /* the positions a seat's reports are kept for: the
                                                 * last call's, then room for the end */
static unsigned int        StopAt;              /* -E: no end to wait for: a seat's end is reported
                                                 * at this many folds, the harness's stop */
#define QUOTA(i)           (Count + (i) * Step) /* seat i's messages, and the
                                                 * fold it calls acEnd at */
static unsigned int        Lag;                 /* -z: seat N-1 holds each new proposal's
                                                 * INITIAL this many ticks */
static unsigned int        Slow;                /* -w: seats 0..SlowSeats-1
                                                 * this many times slower */
static unsigned int        SlowSeats    = 1;    /* -v */
static unsigned int        SplitK;              /* -S k:m: seats 0..k-1 receive no READY of
                                                 * seat N-1's value for m ticks from the go:
                                                 * they enter 0 on its BA, the rest 1 */
static unsigned int        SplitM;
static int                 Censor;              /* -C: seat 0 sends seat N-1 no (initial, v)
                                                 * of its own and no unit */
static int                 Idle;                /* -i: seat N-1 proposes nothing */
static unsigned int        Byz;                 /* -b: seat BzSeat rewrites its tags at its
                                                 * egress: bit 1 no annotations, 2 random names
                                                 * on its agreement rows, 4 its own INITIAL
                                                 * under the genesis; and its exchange parts: 8
                                                 * a sign part byte, 16 a data part byte, 32 a
                                                 * byte short, 64 a description byte */
static unsigned int        BzSeat;              /* the Byzantine seat: N-1, or N-2 under -2 */
static int                 Accomplice;          /* -a: seat N-2, the dealer's accomplice, sends its
                                                 * exchange parts to seat 0 alone */
static int                 RetainSet;           /* -M: the retention declared,
                                                 * one the arm means to wrap */
static int                 Partitioned;         /* -x past the others' retention: seat
                                                 * N-1 is beyond recovery, read from
                                                 * the reports, and expected capped */
static unsigned int        Cut;                 /* -x: seat N-1's ingress is cut for this
                                                 * many ticks from the go, and its egress
                                                 * unless -X says otherwise */
static unsigned int        CutEgr = ~0u;        /* -X: seat N-1's egress is cut for this
                                                 * many ticks from the go */
static unsigned int        CutUnit;             /* -U: seat N-1's ingress of the exchange is
                                                 * cut for this many ticks: every class 2
                                                 * row; the agreement's rows and the dealt
                                                 * units arrive */
static int                 CutData;             /* -V: with -U, the dealt units' data parts too */
static unsigned int        Refuse;              /* -O: 1 + the member seat N-1's
                                                 * memory refuses the search of */
static unsigned int        RefuseAt;            /* -O: 0 the search's buffers, 1 the pool's */
static unsigned int        CutFrom;             /* -y: the tick the cut begins at */
static unsigned int        NLinks;              /* -T: the phases */
static unsigned long       LinkAt[32];          /* -T: each phase's ms since the go */
static unsigned char       LinkOk[32][100];     /* -T: [phase][a * 10 + b]
                                                 * the link a to b carries */
/* -T: one seat's wire by phase, each seat's thread writing its own row:
 * what it put to its egress, carried or dropped, and what it got from
 * its ingress, [seat][phase][other seat][class * 4 + kind]; the
 * positions its rows named and the rows it got named, by its own count,
 * the lowest and the highest, and the rows it got under a name it had
 * not minted; the positions it folded */
static unsigned int        LinkPut[10][32][10][16];
static unsigned int        LinkRec[10][32][10][16];  /* of the carried, a record's recover leg */
static unsigned int        LinkOld[10][32];     /* rows got naming one behind it */
static unsigned int        LinkCut[10][32][10][16];
static unsigned int        LinkGot[10][32][10][16];
static unsigned int        LinkPos[10][32][4];
static unsigned int        LinkAhead[10][32];
static unsigned int        LinkFold[10][32];
static unsigned int        RcvBuf;              /* -G: seat N-1's socket receive
                                                 * buffer, bytes, below the default */
static unsigned int        Freeze;              /* -Q: seat N-1 frozen from -y until the others
                                                 * have folded this many positions past it */
static pthread_mutex_t     FoldMu = PTHREAD_MUTEX_INITIALIZER;
static unsigned int        Folded[AC_SEATS];      /* -Q: each seat's positions folded, FoldMu */
static int                 Ended[AC_SEATS];      /* -Q: each seat's end reported, FoldMu */
static unsigned int        ApiLate;             /* a deal taken after the go, or acAvailable not -1
                                                 * at the chain's last link, any seat: FoldMu */
struct hwAt {
  unsigned int  gen;
  unsigned int  off;
  unsigned char seen;                 /* a seat has folded the position */
  unsigned char set;
  unsigned char apex[AC_HASH_MAX];
};
static struct hwAt        *HwAt;                /* [position][signer] the first seat's high water at
                                                 * its fold of the position, FoldMu */
static unsigned long      *FoldMs;              /* the harness's clock at each seat's fold
                                                 * of each link, seat by link: what decides
                                                 * whether seat N-1 folded one past the
                                                 * others' abandon, never a seat's */
static unsigned int        FrozeAt;             /* -Q: the frozen seat's
                                                 * positions folded at its freeze */
static unsigned long       RejoinMs;            /* -Q: from the thaw until it was within
                                                 * one position of every other seat */
static int                 Rejoined;
static int                 Thawed;              /* -Q: the freeze came and ended */
static int                 CutAll;              /* -Y: the cut is every seat's: the network dark */
static unsigned int        PauseFrom;           /* -Z from:len: every seat but N-1 proposes nothing
                                                 * from this tick for this many ticks */
static unsigned int        PauseLen;
static int                 Dead;                /* -x and -X at or past the cap: seat N-1 is
                                                 * dead for the run, and the judge expects it
                                                 * capped with nothing launched */
/* the declared network, applied at each seat's sendto */
static unsigned int        DropPct;             /* -D: steady loss */
static unsigned int        DelayMs;             /* -L: a datagram's delay, uniform 0..DelayMs */
static unsigned int        BurstLen;            /* -B: Gilbert-Elliott, the mean burst in ms */
static unsigned int        BurstDrop    = 90;   /* -K: loss in a burst */
static int                 Trace;

static void *
rmd128Alloc(
  void
){
  return (malloc(rmd128tsize()));
}

static void *
rmd160Alloc(
  void
){
  return (malloc(rmd160tsize()));
}

static void *
sha256Alloc(
  void
){
  return (malloc(sha256tsize()));
}

static void *
sha3256Alloc(
  void
){
  return (malloc(sha3256tsize()));
}

static void *
sha3512Alloc(
  void
){
  return (malloc(sha3512tsize()));
}

static const struct acHash Suites[] = {
  { "rmd128", rmd128Alloc, rmd128tsize, (void (*)(void *))rmd128init
  , (void (*)(void *, const unsigned char *, unsigned int))rmd128update
  , (void (*)(void *, unsigned char *))rmd128final, rmd128hmac, rmd128hkdf, RMD128_SZ, 4 },
  { "rmd160", rmd160Alloc, rmd160tsize, (void (*)(void *))rmd160init
  , (void (*)(void *, const unsigned char *, unsigned int))rmd160update
  , (void (*)(void *, unsigned char *))rmd160final, rmd160hmac, rmd160hkdf, RMD160_SZ, 0 },
  { "sha256", sha256Alloc, sha256tsize, (void (*)(void *))sha256init
  , (void (*)(void *, const unsigned char *, unsigned int))sha256update
  , (void (*)(void *, unsigned char *))sha256final, sha256hmac, sha256hkdf, SHA256_SZ, 5 },
  { "sha3256", sha3256Alloc, sha3256tsize, (void (*)(void *))sha3256init
  , (void (*)(void *, const unsigned char *, unsigned int))sha3256update
  , (void (*)(void *, unsigned char *))sha3256final, sha3256hmac, sha3256hkdf, SHA3256_SZ, 5 },
  { "sha3512", sha3512Alloc, sha3512tsize, (void (*)(void *))sha3512init
  , (void (*)(void *, const unsigned char *, unsigned int))sha3512update
  , (void (*)(void *, unsigned char *))sha3512final, sha3512hmac, sha3512hkdf, SHA3512_SZ, 6 },
};


static struct acPar P;                  /* the harness's deal: what main
                                         * fills and every seat copies */
static struct acTest Knobs;             /* the knobs (-m, -d, -r, -g,
                                         * -P) every seat's hooks carry */
static int Fault;

/* one sign-role hash over a buffer, the judge's */
static void
hHash(
  const unsigned char *b
 ,unsigned int l
 ,unsigned char *o
){
  const struct acPar *S;
  void *x;

  S = &P;
  if (!(x = Sign->alloc())) {
    memset(o, 0, HashSz);
    return;
  }
  Sign->init(x);
  Sign->update(x, b, l);
  Sign->final(x, o);
  free(x);
}

/* seat x's blob: a compressible text, distinct per seat and, by its
 * first four letters, per ordinal, that the operator hands x and an
 * assembler regenerates to check its recovery */
static void
blobFill(
  unsigned int x
 ,unsigned int inst
 ,unsigned char *b
){
  unsigned int k;
  unsigned int o;

  for (o = inst, k = 0; k < BlobLen; ++k)
    if (k < 4) {
      b[k] = 'A' + o % 26;
      o /= 26;
    } else
      b[k] = 'A' + (x * 31 + inst * 13 + k * 7 + (k >> 5)) % 26;
}

static const char *
verdictName(
  unsigned char v
){
  switch (v) {
  case AC_PASS:      return ("message");
  case AC_EXHAUSTED: return ("no message, exhausted");
  case AC_UNDER:     return ("no message, under threshold");
  case AC_BUDGET:    return ("no message, budget spent");
  case AC_INCONSISTENT: return ("no message, the commitment inconsistent");
  default:                return ("none yet");
  }
}


/*
 * The operator's deal to one seat (the roster): for every other seat
 * its id, its address, the pair secret and its MLS public key.  Wiped
 * on release, whichever side releases it.
 */
struct rosterEntry {
  struct sockaddr_in addr;
  unsigned char      psk[AC_PSK];
  unsigned char      pub[AC_HASH_MAX];
  unsigned char      id;
};

struct roster {
  unsigned int       cnt;             /* N - 1 entries; 0 is the go */
  unsigned char      genesis[AC_HASH_MAX]; /* the chain's dealt base: public, dealt
                                            * so every seat folds from one place */
  struct rosterEntry e[1];
};

static void
rosterDealloc(
  void *v
){
  struct roster *r;

  r = v;
  if (r) {
    memset(r, 0, sizeof (*r) + (unsigned long)r->cnt * sizeof (r->e[0]));
    free(r);
  }
}

/* what a seat reports of one instance */
struct instRes {
  unsigned long puts;
  unsigned long gets;
  unsigned int  launchTick;
  unsigned int  subsetTick;
  unsigned int  foldTick;
  unsigned int  endTick;              /* retention let its record go; 0:
                                       * still retained at the report */
  unsigned int  cnt;                  /* the subset's size */
  unsigned int  legCnt;
  unsigned int  rot;
  unsigned int  noop;
  unsigned int  promo;
  unsigned int  ending;               /* members carrying the end */
  unsigned char launched;
  unsigned char end;                  /* the chain's last link */
  unsigned char complete;             /* SUBSET was output */
  unsigned char stepped;
  unsigned char subset[BITS(AC_SEATS)];
  unsigned char link[AC_HASH_MAX];
};


/*
 * The seat's own count of its wire, beside the framers': what sendto
 * took and recvfrom gave, what was still in the socket at the stop,
 * what the declared network dropped, and what the kernel refused at the
 * send.  The two framer refusals and -L's drop are defects.
 */
struct wire {
  unsigned int sent;
  unsigned int recv;
  unsigned int unread;
  unsigned int stressed;
  unsigned int refused;
  unsigned int noBufs;                /* sends the kernel pushed back, ENOBUFS: tried again */
  unsigned int dqDrop;                /* -L could not hold a datagram */
  unsigned int cut;                   /* -x, -X, -U, -S: messages dropped at the cut */
  unsigned int cutUnit;               /* of those, unit parts */
  unsigned int censored;              /* -C: INITIALs with their units the dealer withheld */
  unsigned int faultDealt;            /* -f 7, -f 8, -f 10, -f 11: the
                                       * second signature was made and dealt */
  unsigned int byz;                   /* -b: tags rewritten at the egress */
  unsigned int withheld;              /* -a: exchange parts withheld at the egress */
  unsigned int agreed;                /* this seat's blobs agreed */
  unsigned int notGiven;              /* this seat's payloads agreed whose bytes are not the
                                       * ones it gave when asked: a queue in the seat */
  unsigned int hwEarly;               /* at a fold, a signer's high water set with the
                                       * signer in no subset this seat folded */
  unsigned int hwMissing;             /* not set with the signer in one */
  unsigned int hwPos;                 /* set at another position than the last fold
                                       * with the signer in its subset */
  unsigned int hwMoved;               /* a non-member's high water moved since the last fold */
  unsigned int hwSplit;               /* unlike another seat's at its fold of the position */
  unsigned int hwStale;               /* a member that left its signer's high water where
                                       * it was: folded at or below it */
  unsigned int skipped;               /* -z: blobs a subset left out let go, the next given */
};

/* a datagram held to its -L deadline */
struct dq {
  struct dq    *next;
  unsigned long due;
  unsigned int  len;
  unsigned char b[1];                 /* [addrlen][addr][wire] */
};

/*
 * A seat's word up to the operator, by kind, the kind read first: 0 the
 * chain's report of an instance, at its fold -- the chain hash before
 * it, the subset, every member's hash and the chain hash after it; 2
 * the messages' report of one member of an instance, at that member's
 * end here -- the chain hash before the instance, the member's hash,
 * the message or why none, the message in the tail; 3 the seat's end,
 * every instance's record and the counters; 1 the counters at the stop.
 * One allocation each, the channel's free its dealloc.
 */
struct resHdr {
  unsigned int  inst;                  /* the instance, 1..; 0 for the seat's */
  unsigned int  tick;
  unsigned char self;
  unsigned char kind;
  unsigned char member;                /* kind 2: X */
};

struct memberResult {
  struct resHdr hdr;
  unsigned int  msgLen;
  unsigned int  shares;                /* the parts in the pool at the report */
  unsigned int  shards;
  unsigned int  tries;
  unsigned int  name;                  /* the harness: the blob's name, from the
                                        * context and slot the signature says */
  unsigned char verdict;               /* VERDICT_* */
  unsigned char mkind;                 /* 0 a payload, AC_ROTATION, AC_NOOP */
  unsigned char known;                 /* the member's hash is held: a
                                        * sign part under its agreed value */
  unsigned char prev[AC_HASH_MAX];     /* the chain hash before the instance */
  unsigned char value[AC_HASH_MAX];    /* the agreed hash */
  unsigned char hash[AC_HASH_MAX];     /* a payload's message hash, from the signed header */
  unsigned char heldShares[BITS(AC_SEATS)];      /* the leaves in the pool at the report */
  unsigned char heldShards[BITS(AC_SEATS)];
  unsigned char badShares[BITS(AC_SEATS)];       /* of those, off the re-encode */
  unsigned char badShards[BITS(AC_SEATS)];
  unsigned char msg[1];                /* the message, msgLen bytes */
};

struct processResult {
  struct resHdr hdr;
  struct rsecFrmEgrCtrs ec;            /* kind 1: the framers' counters at the stop */
  struct rsecFrmIgrCtrs ic;
  struct wire   w;                     /* kind 1: the seat's own count of its wire */
  unsigned int  launched;              /* kind 3: the positions folded */
  unsigned int  endPos;                /* kind 3: the position the chain
                                        * ended at here, 0 for none */
  unsigned int  unitLen;               /* this seat's largest own unit, bytes */
  unsigned int  cnt;                   /* kind 0: the subset's size */
  unsigned int  rot;
  unsigned int  noop;
  unsigned int  promo;
  struct acCounters c;                   /* kinds 1 and 3 */
  struct acSeatCounters sc[AC_SEATS];      /* kinds 1 and 3: what this seat
                                            * counts of each other seat */
  unsigned char capped;
  unsigned char exited;                /* kind 3: the seat stopped on its own, its end run */
  unsigned char end;                   /* kind 0: the chain's last link */
  unsigned char ceiling;               /* kind 0: the ACS seat stopped at the round ceiling */
  unsigned char complete;              /* kind 0: SUBSET was output */
  unsigned char stepped;               /* kind 0: folded, the link below */
  unsigned char head[AC_HASH_MAX];     /* kind 3: the chain's head */
  unsigned char prev[AC_HASH_MAX];     /* kind 0: the chain hash before the instance */
  unsigned char link[AC_HASH_MAX];     /* and after it */
  /* kind 3: Slots records; behind them kind 0's tables by X (RP_*): X's
   * hash (a payload's message hash; a rotation's or noop's value), its
   * kind (0 a payload, AC_ROTATION, AC_NOOP), whether it was promoted
   * to its successor at this fold (the book's move), the subset's
   * bitmap, the bitmap of the X whose hash is held, what this seat
   * entered in each X's agreement, the round it decided at, and whether
   * its value carries the end */
  struct instRes ir[1];
};
#define RP_SZ             (sizeof (struct processResult) + (Slots - 1) * sizeof (struct instRes) \
                           + N * (HashSz + 5) + 2 * BITS(N))
#define RP_HASH(rp, x)    ((unsigned char *)((rp)->ir + Slots) + (x) * HashSz)
#define RP_MKIND(rp)      ((unsigned char *)((rp)->ir + Slots) + N * HashSz)
#define RP_PROMOTED(rp)   (RP_MKIND(rp) + N)
#define RP_SUBSET(rp)     (RP_PROMOTED(rp) + N)
#define RP_KNOWN(rp)      (RP_SUBSET(rp) + BITS(N))
#define RP_ENTERED(rp)    (RP_KNOWN(rp) + BITS(N))
#define RP_ROUND(rp)      (RP_ENTERED(rp) + N)
#define RP_ENDING(rp)     (RP_ROUND(rp) + N)

/*
 * The operator's link, one socketpair a seat: a record is a pointer,
 * the thing it points to passing with it, or a one-byte word.  These
 * wait: the bootstrap, the stop and main, never the seat's loop.
 */
static int
opSend(
  int fd
 ,const void *b
 ,unsigned int l
){
  for (;;) {
    struct timespec ts;

    if (send(fd, b, l, 0) >= 0)
      return (1);
    if (errno != EAGAIN && errno != ENOBUFS && errno != EINTR)
      return (0);
    ts.tv_sec = 0;
    ts.tv_nsec = 1000000L;
    nanosleep(&ts, 0);
  }
}

static unsigned int
opRecv(
  int fd
 ,void *b
 ,unsigned int l
){
  struct pollfd pf;
  long n;

  pf.fd = fd;
  pf.events = POLLIN;
  for (;;) {
    if ((n = recv(fd, b, l, 0)) >= 0)
      return (n);
    if (errno != EAGAIN && errno != EINTR)
      return (0);
    poll(&pf, 1, -1);
  }
}

/*
 * The harness: one thread a seat, binding one seat of the library and
 * owning what the library does not -- the socket, the operator's link,
 * the clock, the declared network applied at its send, and the knobs,
 * which act through the library's test hooks on the messages and at the
 * wire on the datagrams.  The seat's reports become the operator's
 * records.
 */
struct hseat {
  struct ac  *seat;
  struct dq          *dq;             /* -L: datagrams held to their delay, by deadline */
  unsigned char      *ibuf;           /* a datagram received: DgramMax + 1, so a longer one shows */
  struct sockaddr_in *addr;           /* [seat], from the roster */
  unsigned long      *geEnd;          /* -B: a destination's burst ends */
  unsigned long      *geLast;         /* and when its good state was last read */
  unsigned long      *lastMem;        /* [seat] the last position folded here with it a member */
  struct hwAt        *hwPrev;         /* [seat] its high water at the last fold here */
  unsigned char      *geBad;
  struct instRes     *res;            /* [position], Slots */
  struct acCb         cb;
  struct acTest       test;
  struct wire         w;
  unsigned long       bwLast;         /* -W: the bucket's last refill */
  unsigned long       bwTokens;
  unsigned long       cpuMark;        /* -w: the thread's processor time at the last look */
  unsigned long       slowDebt;       /* -w: the sleep owed, us */
  unsigned int        self;
  unsigned int        proposed;       /* blobs agreed or let go: the next one's ordinal, less one */
  unsigned int        given;          /* the ordinal last given when asked, 0 for none */
  unsigned int        chains;         /* chain reports out, positions 1..Slots */
  unsigned int        endPos;         /* the position the chain ended at here, 0 for none yet */
  unsigned int        top;            /* the highest position folded here, past Slots too */
  int                 stuck;          /* quiet on its own with a report
                                       * still owed: capped, never hung */
  unsigned int        members;        /* member reports out of those positions */
  unsigned int        due;            /* member reports those positions owe */
  int                 fd;             /* the wire: one bound UDP socket, both directions */
  int                 op;             /* the operator's link: this seat's end */
  int                 sendBlocked;    /* the socket would not take a datagram: POLLOUT */
  int                 noBufs;         /* the kernel had no buffer for it: again in a ms */
  int                 ended;          /* the seat's end is reported */
  int                 resumed;        /* -Z: the pause ended and the
                                       * seat said again it has a blob */
  int                 thawed;         /* -Q: the freeze is over */
  int                 frozeOut;       /* -Q: the others ended while it was frozen */
  unsigned long       thawUs;         /* -Q: when */
  unsigned long       goUs;           /* -T: the go */
  struct sockaddr_in  listen;         /* this seat's address, from the operator */
  unsigned char       genesis[AC_HASH_MAX]; /* position 1's name: -b names a record by it */
};

/* -T: the phase in force at this seat, by its own clock from its go,
 * NLinks before the first; and the position a name names here, by this
 * seat's count, 0 for one it has not minted */
static unsigned int
linkAt(
  const struct hseat *h
 ,const unsigned char *name
 ,unsigned int *pos
){
  const struct acPar *S;
  struct timespec now;
  unsigned long ms;
  unsigned int ph;
  unsigned int k;

  S = &P;
  clock_gettime(CLOCK_MONOTONIC, &now);
  ms = (USEC(now) - h->goUs) / 1000;
  *pos = 0;
  if (!memcmp(name, h->genesis, HashSz))
    *pos = 1;
  else
    for (k = 0; k < Slots && h->res[k].stepped; ++k)
      if (!memcmp(name, h->res[k].link, HashSz)) {
        *pos = k + 2;
        break;
      }
  if (ms < LinkAt[0])
    return (NLinks);
  for (ph = 0; ph + 1 < NLinks && LinkAt[ph + 1] <= ms; ++ph)
    ;
  return (ph);
}

/* the seat's word that it has a blob to propose, at every chain report:
 * none past the count, none while -Z's pause lasts (said again after
 * it), and -i's seat has none */
static void
hAvail(
  struct hseat *h
){
  const struct acPar *S;

  S = &P;
  if (h->proposed >= QUOTA(h->self) || (Idle && h->self == N - 1))
    return;
  if (PauseLen && h->self != N - 1 && acTicks(h->seat) >= PauseFrom && acTicks(h->seat) - PauseFrom < PauseLen)
    return;
  acAvailable(h->seat);
}

/* the seat's blob, asked for the position launching: the next one not
 * yet agreed, the same bytes again where a subset left it out, except
 * that -z's laggard lets an even one go and gives the next instead, the
 * caller's choice, so a seat that presented what it kept in place of
 * what it was given shows in its chain report */
static unsigned int
hPropose(
  void *ctx
 ,unsigned char *msg
 ,unsigned int max
){
  const struct acPar *S;
  struct hseat *h;

  h = ctx;
  S = &P;
  if (h->proposed >= QUOTA(h->self) || (Idle && h->self == N - 1) || BlobLen > max
   || (PauseLen && h->self != N - 1 && acTicks(h->seat) >= PauseFrom && acTicks(h->seat) - PauseFrom < PauseLen)) {
    h->given = 0;
    return (0);
  }
  if (Lag && h->self == N - 1 && h->given == h->proposed + 1 && !(h->given & 1) && h->proposed + 1 < QUOTA(h->self)) {
    ++h->proposed;
    ++h->w.skipped;
  }
  h->given = h->proposed + 1;
  blobFill(h->self, h->given, msg);
  return (BlobLen);
}

/* the seat's end: its chain ended here and the seat stopped on its own,
 * every member of every position reported; or, under -E, where no end
 * comes, StopAt positions folded and every member of those reported,
 * the harness's stop */
static void
hEnd(
  struct hseat *h
 ,int exited
){
  const struct acPar *S;
  struct processResult *rp;
  struct acCounters c;
  unsigned int j;

  S = &P;
  if (h->ended || h->members < h->due || (exited ? !h->endPos : !StopAt || h->chains < StopAt))
    return;
  h->ended = 1;
  pthread_mutex_lock(&FoldMu);
  Ended[h->self] = 1;
  pthread_mutex_unlock(&FoldMu);
  acCounters(h->seat, &c);
  if (!(rp = calloc(1, RP_SZ)))
    return;
  rp->hdr.self = h->self;
  rp->hdr.kind = 3;
  rp->hdr.tick = acTicks(h->seat);
  rp->launched = h->top;
  rp->endPos = h->endPos;
  rp->exited = exited != 0;
  rp->unitLen = c.unitMax;
  rp->c = c;
  for (j = 0; j < N; ++j)
    acSeatCounters(h->seat, j, &rp->sc[j]);
  memcpy(rp->head, h->chains ? h->res[h->chains - 1].link : h->genesis, HashSz);
  memcpy(rp->ir, h->res, Slots * sizeof (*h->res));
  if (!opSend(h->op, &rp, sizeof (rp)))
    free(rp);
}

static void
hChain(
  void *ctx
 ,const struct acChain *rc
){
  struct hseat *h;
  const struct acPar *S;
  struct processResult *rp;
  struct instRes *r;
  unsigned int j;

  h = ctx;
  S = &P;
  if (rc->position > h->top)
    h->top = rc->position;
  /* the last link: nothing more launches here, whether or not this
   * seat's caller has called the end */
  if (rc->end && acAvailable(h->seat) != -1) {
    pthread_mutex_lock(&FoldMu);
    ++ApiLate;
    pthread_mutex_unlock(&FoldMu);
  }
  /* a signer's high water is raised on SUBSET inclusion and nowhere
   * else: at each fold it is set for exactly the signers some fold here
   * has had in its subset, at the last such position; a non-member's
   * has not moved since the last fold; and every seat's is the same at
   * its fold of the same position */
  for (j = 0; j < N; ++j) {
    struct hwAt now;
    struct hwAt *a;
    unsigned int pos;

    memset(&now, 0, sizeof (now));
    if (BIT_TST(rc->subset, j))
      h->lastMem[j] = rc->position;
    now.set = acTestHw(h->seat, j, &now.gen, &now.off, &pos, now.apex);
    if (now.set && !h->lastMem[j])
      ++h->w.hwEarly;
    else if (!now.set && h->lastMem[j])
      ++h->w.hwMissing;
    else if (now.set && pos != h->lastMem[j])
      ++h->w.hwPos;
    a = &h->hwPrev[j];
    if (!BIT_TST(rc->subset, j)
     && (now.set != a->set || now.gen != a->gen || now.off != a->off || memcmp(now.apex, a->apex, HashSz)))
      ++h->w.hwMoved;
    if (BIT_TST(rc->subset, j) && a->set
     && !(now.gen > a->gen || (now.gen == a->gen && now.off > a->off)))
      ++h->w.hwStale;
    *a = now;
    if (rc->position > Slots)
      continue;
    pthread_mutex_lock(&FoldMu);
    a = &HwAt[(rc->position - 1) * N + j];
    if (!a->seen) {
      *a = now;
      a->seen = 1;
    } else if (now.set != a->set || now.gen != a->gen || now.off != a->off || memcmp(now.apex, a->apex, HashSz))
      ++h->w.hwSplit;
    pthread_mutex_unlock(&FoldMu);
  }
  /* this seat's blob, a payload member, is agreed, and it is the one
   * this seat gave when asked */
  if (BIT_TST(rc->subset, h->self) && rc->kind[h->self] == AC_PAYLOAD) {
    unsigned char *b;
    unsigned char g[AC_HASH_MAX];

    memset(g, 0, sizeof (g));
    if (h->given && (b = malloc(BlobLen ? BlobLen : 1))) {
      blobFill(h->self, h->given, b);
      hHash(b, BlobLen, g);
      free(b);
    }
    if (!h->given || memcmp(g, rc->hash + h->self * HashSz, HashSz))
      ++h->w.notGiven;
    ++h->w.agreed;
    ++h->proposed;
  }
  if (rc->end)
    h->endPos = rc->position;
  if (rc->position > Slots)
    return;
  r = &h->res[rc->position - 1];
  r->launched = r->complete = r->stepped = 1;
  r->end = rc->end;
  for (j = 0; j < N; ++j)
    r->ending += BIT_TST(rc->subset, j) && rc->ending[j];
  r->cnt = rc->members;
  r->launchTick = rc->launchTick;
  r->subsetTick = rc->subsetTick;
  r->foldTick = rc->tick;
  memcpy(r->subset, rc->subset, BITS(N));
  memcpy(r->link, rc->next, HashSz);
  ++h->chains;
  if (NLinks) {
    unsigned int ph;
    unsigned int pos;

    if ((ph = linkAt(h, rc->prev, &pos)) < NLinks)
      ++LinkFold[h->self][ph];
  }
  pthread_mutex_lock(&FoldMu);
  Folded[h->self] = h->chains;
  {
    struct timespec now;

    clock_gettime(CLOCK_MONOTONIC, &now);
    FoldMs[h->self * Slots + rc->position - 1] = (unsigned long)now.tv_sec * 1000 + now.tv_nsec / 1000000;
  }
  pthread_mutex_unlock(&FoldMu);
  /* the caller's end, at its own count: from here every value this seat
   * signs carries it, and the chain ends at the first link more than t
   * members carry it into */
  if (rc->position == QUOTA(h->self) && h->self < Callers)
    acEnd(h->seat);
  if (!(rp = calloc(1, RP_SZ)))
    return;
  rp->hdr.self = h->self;
  rp->hdr.kind = 0;
  rp->hdr.inst = rc->position;
  rp->hdr.tick = rc->tick;
  rp->complete = rp->stepped = 1;
  rp->end = rc->end;
  rp->ceiling = rc->ceiling;
  rp->cnt = rc->members;
  memcpy(RP_SUBSET(rp), rc->subset, BITS(N));
  memcpy(RP_PROMOTED(rp), rc->promoted, N);
  memcpy(RP_ENTERED(rp), rc->entered, N);
  memcpy(RP_ROUND(rp), rc->round, N);
  memcpy(RP_ENDING(rp), rc->ending, N);
  memcpy(rp->prev, rc->prev, HashSz);
  memcpy(rp->link, rc->next, HashSz);
  for (j = 0; j < N; ++j) {
    if (!BIT_TST(rc->subset, j))
      continue;
    if (j != h->self)
      ++h->due;
    RP_MKIND(rp)[j] = rc->kind[j];
    memcpy(RP_HASH(rp, j), rc->hash + j * HashSz, HashSz);
    RP_KNOWN(rp)[j >> 3] |= 1 << (j & 7);
    r->rot += rc->kind[j] == AC_ROTATION;
    r->noop += rc->kind[j] == AC_NOOP;
    r->promo += rc->promoted[j] != 0;
  }
  rp->rot = r->rot;
  rp->noop = r->noop;
  rp->promo = r->promo;
  if (!opSend(h->op, &rp, sizeof (rp)))
    free(rp);
  hAvail(h);
  hEnd(h, 0);
}

static void
hMessage(
  void *ctx
 ,const struct acMessage *rm
){
  struct hseat *h;
  const struct acPar *S;
  struct memberResult *mr;
  unsigned int q;

  h = ctx;
  S = &P;
  if (rm->position > Slots)
    return;
  ++h->members;
  if (!(mr = calloc(1, sizeof (*mr) + rm->len)))
    return;
  mr->hdr.self = h->self;
  mr->hdr.kind = 2;
  mr->hdr.inst = rm->position;
  mr->hdr.tick = rm->tick;
  mr->hdr.member = rm->member;
  memcpy(mr->prev, rm->prev, HashSz);
  if (rm->hash) {
    mr->known = 1;
    mr->mkind = rm->kind;
    memcpy(mr->hash, rm->hash, HashSz);
    memcpy(mr->value, rm->hash, HashSz);
  }
  mr->verdict = rm->verdict;
  mr->tries = rm->tries;
  memcpy(mr->heldShares, rm->heldShares, BITS(N));
  memcpy(mr->heldShards, rm->heldShards, BITS(N));
  memcpy(mr->badShares, rm->badShares, BITS(N));
  memcpy(mr->badShards, rm->badShards, BITS(N));
  for (q = 0; q < N; ++q) {
    mr->shares += BIT_TST(rm->heldShares, q) != 0;
    mr->shards += BIT_TST(rm->heldShards, q) != 0;
  }
  mr->msgLen = rm->len;
  if (rm->len)
    memcpy(mr->msg, rm->msg, rm->len);
  if (!opSend(h->op, &mr, sizeof (mr)))
    free(mr);
  hEnd(h, 0);
}

static void
hReleased(
  void *ctx
 ,unsigned int position
 ,unsigned int tick
){
  struct hseat *h;

  h = ctx;
  if (position <= Slots)
    h->res[position - 1].endTick = tick;
}

static void
hRandom(
  void *ctx
 ,unsigned char *b
 ,unsigned int l
){
  (void)ctx;
  arc4random_buf(b, l);
}

static void
hTrace(
  void *ctx
 ,const char *line
){
  char out[64 + 16 * AC_SEATS + 2];

  (void)ctx;
  sprintf(out, "%s\n", line);
  fputs(out, stdout);                 /* one write, so the threads' lines do not interleave */
}

/* the harness's adversary at the seat's egress: the cut (-x, -X, -Y,
 * -y) and the censor (-C), on the message, before the framer; and the
 * Byzantine row sender (-b), who rewrites the tag the framer then
 * authenticates as this seat's word */
static int
hEgress(
  void *ctx
 ,unsigned int inst
 ,unsigned char dest
 ,unsigned char *tag
 ,unsigned char *payload
 ,unsigned int len
){
  struct hseat *h;
  const struct acPar *S;
  unsigned int ticks;

  h = ctx;
  S = &P;
  ticks = acTicks(h->seat);
  /* -T: the link to dest, as the phase in force carries it; what the
   * seat put, carried or dropped, counted by the phase */
  if (NLinks && dest < N) {
    unsigned int ph;
    unsigned int pos;

    ph = linkAt(h, tag + AC_TAG_NAME, &pos);
    if (ph < NLinks) {
      if (pos && (!LinkPos[h->self][ph][0] || pos < LinkPos[h->self][ph][0]))
        LinkPos[h->self][ph][0] = pos;
      if (pos > LinkPos[h->self][ph][1])
        LinkPos[h->self][ph][1] = pos;
    }
    if (ph == NLinks || !LinkOk[ph][h->self * 10 + dest]) {
      if (ph < NLinks)
        ++LinkCut[h->self][ph][dest][AC_TAG_CLASS(tag[0]) * 4 + AC_TAG_KIND(tag[0])];
      ++h->w.cut;
      if (AC_TAG_KIND(tag[0]) == BRACHA87_BESIDE)
        ++h->w.cutUnit;
      return (-1);
    }
    ++LinkPut[h->self][ph][dest][AC_TAG_CLASS(tag[0]) * 4 + AC_TAG_KIND(tag[0])];
    if (!inst)
      ++LinkRec[h->self][ph][dest][AC_TAG_CLASS(tag[0]) * 4 + AC_TAG_KIND(tag[0])];
  }
  if (Byz && h->self == BzSeat) {
    /* bit 1: no annotation on an ECHO or a READY -- bit 6 of an ECHO,
     * bits 6-7 of a READY and, outside class 0 where bit 2 is the BA
     * value, its HOLDING in bit 2: this seat holds nothing, has
     * accepted nothing, has heard nothing */
    if ((Byz & 1) && AC_TAG_KIND(tag[0]) == BRACHA87_ECHO) {
      tag[0] &= 0xbf;
      ++h->w.byz;
    }
    if ((Byz & 1) && AC_TAG_KIND(tag[0]) == BRACHA87_READY) {
      tag[0] &= AC_TAG_CLASS(tag[0]) ? 0x3b : 0x3f;
      ++h->w.byz;
    }
    /* bit 2: an agreement row under a name nobody minted, a fresh one
     * at every re-send */
    if ((Byz & 2) && AC_TAG_CLASS(tag[0]) == AC_CLS_ACS) {
      arc4random_buf(tag + AC_TAG_NAME, HashSz);
      ++h->w.byz;
    }
    /* bit 4: its own value broadcast's INITIAL under position 1's name */
    if ((Byz & 4) && AC_TAG_CLASS(tag[0]) == AC_CLS_DIST && AC_TAG_KIND(tag[0]) == BRACHA87_INITIAL
     && tag[AC_TAG_BA] == h->self) {
      memcpy(tag + AC_TAG_NAME, h->genesis, HashSz);
      ++h->w.byz;
    }
    /* bits 8, 16, 32: hostile bytes in the exchange parts it forwards,
     * on its legs and its recover legs, under its own key: a byte of
     * the sign part, of the data part, or a unit's part a byte short;
     * 64: a byte of the description beside its recover legs */
    if ((Byz & 120) && AC_TAG_CLASS(tag[0]) >= AC_CLS_LEG && AC_TAG_KIND(tag[0]) == BRACHA87_BESIDE && len) {
      if ((Byz & 8) && AC_TAG_VALUE(tag[0]) == AC_PART_SIGN) {
        payload[arc4random_uniform(len)] ^= 1;
        ++h->w.byz;
      }
      if ((Byz & 16) && AC_TAG_VALUE(tag[0]) == AC_PART_DATA) {
        payload[arc4random_uniform(len)] ^= 1;
        ++h->w.byz;
      }
      if ((Byz & 32) && AC_TAG_VALUE(tag[0]) != AC_PART_DESC && len > 1) {
        --len;
        ++h->w.byz;
      }
      if ((Byz & 64) && AC_TAG_VALUE(tag[0]) == AC_PART_DESC) {
        payload[arc4random_uniform(len)] ^= 1;
        ++h->w.byz;
      }
    }
  }
  /* -a: the dealer's accomplice holds a leaf of the dealer's and sends
   * its exchange parts, on its legs and its recover legs, to seat 0
   * alone: a recipient forwards or withholds its parts */
  if (Accomplice && h->self == N - 2 && dest && AC_TAG_CLASS(tag[0]) >= AC_CLS_LEG
   && AC_TAG_KIND(tag[0]) == BRACHA87_BESIDE && AC_TAG_VALUE(tag[0]) != AC_PART_DESC) {
    ++h->w.withheld;
    return (-1);
  }
  if (CutEgr && (CutAll || h->self == N - 1) && ticks >= CutFrom && ticks - CutFrom < CutEgr) {
    ++h->w.cut;
    if (AC_TAG_KIND(tag[0]) == BRACHA87_BESIDE)
      ++h->w.cutUnit;
    return (-1);
  }
  if (Censor && h->self == 0 && dest == N - 1 && AC_TAG_CLASS(tag[0]) == AC_CLS_DIST
   && (AC_TAG_KIND(tag[0]) == BRACHA87_INITIAL || AC_TAG_KIND(tag[0]) == BRACHA87_BESIDE)) {
    /* -C: the dealer sends seat N-1 no (initial, v) of its own and no
     * unit, ever; the others' readies carry N-1 to the accept and their
     * legs alone bring it the unit */
    if (AC_TAG_KIND(tag[0]) == BRACHA87_INITIAL)
      ++h->w.censored;
    return (-1);
  }
  return (len);
}

/* the harness's adversary at the seat's ingress: the cuts (-x, -U, -Y,
 * -y) and the scheduler's split (-S), on the message, after the framer */
static int
hIngress(
  void *ctx
 ,const unsigned char *tag
 ,const unsigned char *payload
 ,unsigned int len
){
  struct hseat *h;
  const struct acPar *S;
  unsigned int ticks;
  unsigned int kind;
  unsigned int cls;

  (void)payload;
  (void)len;
  h = ctx;
  S = &P;
  ticks = acTicks(h->seat);
  kind = AC_TAG_KIND(tag[0]);
  cls = AC_TAG_CLASS(tag[0]);
  /* -T: what the seat got, by the phase */
  if (NLinks && tag[AC_TAG_SENDER] < N) {
    unsigned int ph;
    unsigned int pos;

    if ((ph = linkAt(h, tag + AC_TAG_NAME, &pos)) < NLinks) {
      ++LinkGot[h->self][ph][tag[AC_TAG_SENDER]][cls * 4 + kind];
      if (!pos)
        ++LinkAhead[h->self][ph];
      else {
        if (pos < h->chains)
          ++LinkOld[h->self][ph];
        if (!LinkPos[h->self][ph][2] || pos < LinkPos[h->self][ph][2])
          LinkPos[h->self][ph][2] = pos;
        if (pos > LinkPos[h->self][ph][3])
          LinkPos[h->self][ph][3] = pos;
      }
    }
  }
  /* -x: the cut seat's ingress is dropped unread */
  if (Cut && (CutAll || h->self == N - 1) && ticks >= CutFrom && ticks - CutFrom < Cut) {
    ++h->w.cut;
    if (kind == BRACHA87_BESIDE)
      ++h->w.cutUnit;
    return (0);
  }
  /* -U: the cut seat's ingress of the exchange is dropped unread; the
   * agreement's rows and the dealt units are delivered, so the seat
   * reaches SUBSET holding what it was dealt and no more */
  if (CutUnit && (CutAll || h->self == N - 1) && ticks >= CutFrom && ticks - CutFrom < CutUnit
   && (cls == AC_CLS_LEG
    || (CutData && cls == AC_CLS_DIST && kind == BRACHA87_BESIDE && AC_TAG_VALUE(tag[0]) == AC_PART_DATA))) {
    ++h->w.cut;
    if (kind == BRACHA87_BESIDE)
      ++h->w.cutUnit;
    return (0);
  }
  /* -S: the scheduler withholds the readies of seat N-1's value from
   * seats 0..k-1 past patience, so their BA for it enters 0 while the
   * others' enters 1, and holds the readies of that BA's broadcasts
   * initiated in the other group, so each group accepts its own first
   * and the sample that turns the round keeps its majority: the split,
   * which the coins alone decide */
  if (SplitM && ticks < SplitM && tag[AC_TAG_BA] == N - 1 && kind == BRACHA87_READY
   && ((cls == AC_CLS_DIST && h->self < SplitK)
    || (cls == AC_CLS_ACS && (h->self < SplitK) != (tag[AC_TAG_INIT] < SplitK)))) {
    ++h->w.cut;
    return (0);
  }
  return (1);
}

/*
 * The seat's datagram to the wire, judged once by the declared network
 * -- a burst or the steady loss, then the bucket -- before -L or the
 * send.  A send the socket would not take, or the kernel had no buffer
 * for, is not taken: the seat keeps it due and this loop waits for the
 * socket; any other refusal is the kernel's loss, taken all the same.
 */
static int
hSend(
  void *ctx
 ,unsigned char dest
 ,const unsigned char *dg
 ,unsigned int dgl
){
  struct hseat *h;
  const struct acPar *S;
  struct timespec now;
  unsigned long us;
  int lose;

  h = ctx;
  S = &P;
  if (h->sendBlocked || h->noBufs)
    return (0);
  clock_gettime(CLOCK_MONOTONIC, &now);
  us = USEC(now);
  lose = 0;
  if (BurstLen && dest < N) {
    if (h->geBad[dest] && us - h->geEnd[dest] <= ~0UL / 2) {
      h->geBad[dest] = 0;
      h->geLast[dest] = us;
    }
    if (!h->geBad[dest] && DropPct && DropPct < BurstDrop) {
      unsigned long el;
      unsigned long good;

      el = (us - h->geLast[dest]) / 1000;
      h->geLast[dest] += el * 1000;       /* the part of a ms not yet read stays */
      if ((good = (unsigned long)BurstLen * (BurstDrop - DropPct) / DropPct) > 0xfffffffeUL)
        good = 0xfffffffeUL;
      if (el > good)
        el = good;
      if (good && el && arc4random_uniform(good) < el) {
        h->geBad[dest] = 1;
        h->geEnd[dest] = us + 1000UL * (1 + arc4random_uniform(2 * BurstLen));
      }
    }
    lose = h->geBad[dest] && BurstDrop && arc4random_uniform(100) < BurstDrop;
  } else if (!BurstLen && DropPct && arc4random_uniform(100) < DropPct)
    lose = 1;
  if (!lose) {
    unsigned long ms;
    unsigned long fill;
    unsigned long cost;

    /* refilled by the ms, the part of one not yet earned kept */
    if ((ms = (us - h->bwLast) / 1000)) {
      fill = BwLimit * ms / 1000;
      if ((h->bwTokens += fill) > BwLimit)
        h->bwTokens = BwLimit;
      h->bwLast += ms * 1000;
    }
    cost = 8UL * (IPUDP_HDR + dgl);
    if (h->bwTokens >= cost)
      h->bwTokens -= cost;
    else
      lose = 1;
  }
  if (lose) {
    ++h->w.stressed;
    return (1);
  }
  if (DelayMs) {
    struct dq *q;
    struct dq **qp;

    if ((q = malloc(sizeof (*q) + 1 + sizeof (struct sockaddr_in) + dgl))) {
      q->due = us + 1000UL * arc4random_uniform(DelayMs + 1);
      q->len = 1 + sizeof (struct sockaddr_in) + dgl;
      q->b[0] = sizeof (struct sockaddr_in);
      memcpy(q->b + 1, &h->addr[dest], sizeof (struct sockaddr_in));
      memcpy(q->b + 1 + sizeof (struct sockaddr_in), dg, dgl);
      /* by deadline, after any due no later */
      for (qp = &h->dq; *qp && q->due - (*qp)->due <= ~0UL / 2; qp = &(*qp)->next)
        ;
      q->next = *qp;
      *qp = q;
    } else
      ++h->w.dqDrop;
    return (1);
  }
  if (sendto(h->fd, dg, dgl, 0, (struct sockaddr *)&h->addr[dest], sizeof (h->addr[dest])) < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      h->sendBlocked = 1;
      return (0);
    }
    if (errno == ENOBUFS) {
      ++h->w.noBufs;
      h->noBufs = 1;
      return (0);
    }
    ++h->w.refused;
  } else
    ++h->w.sent;
  return (1);
}

/*
 * The seat's thread.  The bootstrap, the operator/seat rendezvous: the
 * seat is made, the wire is bound, its public key goes up, the roster
 * comes down and deals it, ready goes up and the go comes down, so
 * every socket is bound before any seat sends; a seat that fails here
 * says so with a null record, which is what releases the operator's
 * barrier.  Then the loop: -L's held datagrams that are due, the seat's
 * pass, the operator's word, a datagram from the socket to the seat,
 * else the wait.  The stop is the operator's two words.
 */
static void *
processT(
  void *v
){
  struct hseat *h;
  const struct acPar *S;
  struct acPar p;
  struct timespec now;
  struct timespec slept;
  struct pollfd pf[2];
  struct sockaddr_storage from;
  unsigned char word[sizeof (void *)];
  unsigned char *kp;
  struct roster *ros;
  struct processResult *rp;
  unsigned char genesis[AC_HASH_MAX];
  unsigned long us;
  socklen_t fl;
  long waitUs;
  long waitMs;
  long n;
  unsigned int e;
  unsigned int wl;
  int booted;

  h = v;
  S = &P;
  booted = 0;
  kp = 0;
  ros = 0;
  h->cb.ctx = h;
  h->cb.chain = hChain;
  h->cb.message = hMessage;
  h->cb.released = hReleased;
  h->cb.send = hSend;
  h->cb.random = hRandom;
  h->cb.propose = hPropose;
  h->cb.trace = Trace ? hTrace : 0;
  h->test = Knobs;
  h->test.ctx = h;
  h->test.egress = hEgress;
  h->test.ingress = hIngress;
  h->test.fault = h->self == N - 1 ? Fault : 0;
  h->test.lag = h->self == N - 1 ? Lag : 0;
  h->test.refuse = h->self == N - 1 ? Refuse : 0;
  h->test.refuseAt = RefuseAt;
  p = P;                                /* the deal is shared; self is this thread's */
  p.self = h->self;
  if (!(h->seat = acTestInit(&p, &h->cb, &h->test)))
    goto bootFail;
  /* the wire: one bound socket for both directions, its receive buffer
   * the kernel's default, or seat N-1's the smaller one -G declares (a
   * bind conflict is a configuration error and fails loudly) */
  if ((h->fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    perror("socket");
    goto bootFail;
  }
  if (RcvBuf && h->self == N - 1) {
    int rb;

    rb = RcvBuf;
    if (setsockopt(h->fd, SOL_SOCKET, SO_RCVBUF, &rb, sizeof (rb))) {
      perror("setsockopt");
      goto bootFail;
    }
  }
  if (bind(h->fd, (struct sockaddr *)&h->listen, sizeof (h->listen))) {
    fprintf(stderr, "seat %u: bind(%u): %s\n", h->self,
            (unsigned int)ntohs(h->listen.sin_port), strerror(errno));
    goto bootFail;
  }
  /* up: the public key */
  if (!(kp = malloc(HashSz)))
    goto bootFail;
  memcpy(kp, acPub(h->seat), HashSz);
  if (!opSend(h->op, &kp, sizeof (kp)))
    goto bootFail;
  kp = 0;
  /* down: the roster */
  if (opRecv(h->op, &ros, sizeof (ros)) != sizeof (ros) || !ros)
    goto bootFail;
  if (ros->cnt != N - 1)
    goto bootFail;
  memcpy(genesis, ros->genesis, HashSz);
  memcpy(h->genesis, genesis, HashSz);
  h->addr[h->self] = h->listen;
  for (e = 0; e < ros->cnt; ++e) {
    if (ros->e[e].id >= N || ros->e[e].id == h->self
     || acDeal(h->seat, ros->e[e].id, ros->e[e].psk, ros->e[e].pub))
      goto bootFail;
    h->addr[ros->e[e].id] = ros->e[e].addr;
  }
  rosterDealloc(ros);
  ros = 0;
  /* up: ready; down: go */
  if (!(kp = malloc(1)))
    goto bootFail;
  *kp = 1;
  if (!opSend(h->op, &kp, sizeof (kp)))
    goto bootFail;
  kp = 0;
  if (opRecv(h->op, &ros, sizeof (ros)) != sizeof (ros) || !ros)
    goto bootFail;
  rosterDealloc(ros);
  ros = 0;
  if (fcntl(h->fd, F_SETFL, fcntl(h->fd, F_GETFL) | O_NONBLOCK) < 0
   || fcntl(h->op, F_SETFL, fcntl(h->op, F_GETFL) | O_NONBLOCK) < 0)
    goto bootFail;
  clock_gettime(CLOCK_MONOTONIC, &now);
  us = USEC(now);
  for (e = 0; e < N; ++e)
    h->geLast[e] = us;
  h->bwLast = us;
  h->bwTokens = BwLimit;
  h->goUs = us;
  clock_gettime(CLOCK_THREAD_CPUTIME_ID, &now);
  h->cpuMark = USEC(now);
  if (acGo(h->seat, genesis, us))
    goto bootFail;
  booted = 1;
  {
    unsigned char z[AC_PSK + AC_HASH_MAX];

    /* a deal after the go is refused */
    memset(z, 0, sizeof (z));
    if (acDeal(h->seat, (h->self + 1) % N, z, z + AC_PSK) != -1) {
      pthread_mutex_lock(&FoldMu);
      ++ApiLate;
      pthread_mutex_unlock(&FoldMu);
    }
  }
  goto loop;

bootFail:
  fprintf(stderr, "seat %u: bootstrap failed\n", h->self);
  rosterDealloc(ros);
  free(kp);
  kp = 0;
  opSend(h->op, &kp, sizeof (kp));
  goto exit;

  /*
   * -L's held datagrams that are due, to the socket; a send the socket
   * would not take leaves the datagram where it is, POLLOUT to wait on.
   */
flush:
  while (!h->sendBlocked && !h->noBufs && h->dq && us - h->dq->due <= ~0UL / 2) {
    struct dq *q;
    struct sockaddr_in to;

    q = h->dq;
    memcpy(&to, q->b + 1, sizeof (to));
    if (sendto(h->fd, q->b + 1 + q->b[0], q->len - 1 - q->b[0], 0, (struct sockaddr *)&to, sizeof (to)) < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        h->sendBlocked = 1;
        break;
      }
      if (errno == ENOBUFS) {
        ++h->w.noBufs;
        h->noBufs = 1;
        break;
      }
      ++h->w.refused;
    } else
      ++h->w.sent;
    h->dq = q->next;
    free(q);
  }
  if (booted == 1)
    goto flushDone;
  goto flushDone2;

loop:
  for (;;) {
    /* -w: the seat's work since the last look, slowed */
    if (Slow > 1 && h->self < SlowSeats) {
      clock_gettime(CLOCK_THREAD_CPUTIME_ID, &now);
      h->slowDebt += (Slow - 1) * (USEC(now) - h->cpuMark);
      if (h->slowDebt >= 1000) {
        slept.tv_sec = h->slowDebt / 1000000;
        slept.tv_nsec = h->slowDebt % 1000000 * 1000;
        nanosleep(&slept, 0);
        h->slowDebt = 0;
      }
      clock_gettime(CLOCK_THREAD_CPUTIME_ID, &now);
      h->cpuMark = USEC(now);
    }
    clock_gettime(CLOCK_MONOTONIC, &now);
    us = USEC(now);
    h->noBufs = 0;
    goto flush;
flushDone:
    /* -Q: frozen, as a stopped process, from its -y tick on: nothing of
     * the seat runs and the socket's queue fills, the others going on
     * without it */
    if (Freeze && h->self == N - 1 && !h->thawed && acTicks(h->seat) >= CutFrom) {
      struct timespec fz;
      unsigned int want;
      unsigned int least;

      pthread_mutex_lock(&FoldMu);
      FrozeAt = h->chains;
      pthread_mutex_unlock(&FoldMu);
      want = h->chains + Freeze < Count ? h->chains + Freeze : Count;
      fz.tv_sec = 0;
      fz.tv_nsec = 100000000L;
      /* until the others have folded past it, or have all ended short
       * of that: then it ends frozen, as capped, nothing of the seat
       * run and nothing of its socket read */
      for (;;) {
        nanosleep(&fz, 0);
        pthread_mutex_lock(&FoldMu);
        for (least = ~0u, e = 0; e < N - 1; ++e)
          if (Folded[e] < least)
            least = Folded[e];
        for (e = 0; e < N - 1 && Ended[e]; ++e)
          ;
        pthread_mutex_unlock(&FoldMu);
        if (least >= want)
          break;
        if (e == N - 1) {
          h->thawed = h->frozeOut = 1;
          waitUs = 0;
          goto capCheck;
        }
      }
      pthread_mutex_lock(&FoldMu);
      Thawed = 1;
      pthread_mutex_unlock(&FoldMu);
      h->thawed = 1;
      clock_gettime(CLOCK_MONOTONIC, &now);
      h->thawUs = USEC(now);
      continue;
    }
    /* -Q: back within one position of every other seat, how long after
     * the thaw: the returning seat's whole walk */
    if (Freeze && h->self == N - 1 && h->thawed && !h->frozeOut && !Rejoined) {
      unsigned int most;

      pthread_mutex_lock(&FoldMu);
      for (most = 0, e = 0; e < N - 1; ++e)
        if (Folded[e] > most)
          most = Folded[e];
      pthread_mutex_unlock(&FoldMu);
      if (h->chains + 1 >= most) {
        pthread_mutex_lock(&FoldMu);
        RejoinMs = (us - h->thawUs) / 1000;
        Rejoined = 1;
        pthread_mutex_unlock(&FoldMu);
      }
    }
    waitUs = acWork(h->seat, us);
    /* the seat stopped on its own: its chain's end run */
    if (waitUs < 0 && !h->ended && !acFailed(h->seat)) {
      hEnd(h, 1);
      h->stuck = !h->ended;             /* a quiet seat ticks no more: its cap would never come */
    }
    /* -Z: the pause over, the word the reports could not say is said */
    if (PauseLen && !h->resumed && acTicks(h->seat) >= PauseFrom + PauseLen) {
      h->resumed = 1;
      hAvail(h);
    }
    /* the operator's word: the stop */
    if (recv(h->op, word, sizeof (word), 0) == 1 && word[0] == 'Q')
      goto stopping;
    fl = sizeof (from);
    if ((n = recvfrom(h->fd, h->ibuf, DgramMax + 1, 0, (struct sockaddr *)&from, &fl)) >= 0) {
      ++h->w.recv;
      acInput(h->seat, h->ibuf, n, us);
      continue;
    }
    /* the cap: a guard; the seat's end record goes as capped */
capCheck:
    if (((TickCap && acTicks(h->seat) >= TickCap) || h->frozeOut || h->stuck) && !h->ended) {
      struct acCounters c;

      h->ended = 1;
      pthread_mutex_lock(&FoldMu);
      Ended[h->self] = 1;
      pthread_mutex_unlock(&FoldMu);
      acCounters(h->seat, &c);
      if ((rp = calloc(1, RP_SZ))) {
        rp->hdr.self = h->self;
        rp->hdr.kind = 3;
        rp->hdr.tick = acTicks(h->seat);
        rp->capped = 1;
        rp->launched = h->top;
        rp->unitLen = c.unitMax;
        rp->c = c;
        for (e = 0; e < N; ++e)
          acSeatCounters(h->seat, e, &rp->sc[e]);
        rp->endPos = h->endPos;
        memcpy(rp->head, h->chains ? h->res[h->chains - 1].link : h->genesis, HashSz);
        memcpy(rp->ir, h->res, Slots * sizeof (*h->res));
        if (!opSend(h->op, &rp, sizeof (rp)))
          free(rp);
      }
    }
    /* the wait: the seat's next due, -L's next deadline, POLLOUT while
     * the socket refuses */
    waitMs = waitUs < 0 ? WAIT_MAX : (waitUs + 999) / 1000;
    if (waitMs > WAIT_MAX)
      waitMs = WAIT_MAX;
    if (h->dq && !h->sendBlocked && !h->noBufs) {
      n = h->dq->due - us > ~0UL / 2 ? 0 : (h->dq->due - us + 999) / 1000;
      if (n < waitMs)
        waitMs = n;
    }
    if (h->noBufs && waitMs > 1)
      waitMs = 1;
    pf[0].fd = h->fd;
    pf[0].events = h->sendBlocked ? POLLIN | POLLOUT : POLLIN;
    pf[1].fd = h->op;
    pf[1].events = POLLIN;
    if (poll(pf, 2, waitMs) > 0 && pf[0].revents & POLLOUT)
      h->sendBlocked = 0;
  }

  /*
   * The stop, two words.  At the operator's quiet (Q) the seat stops
   * talking -- one whose chain ended is quiet of its own accord
   * already, and one under -E or capped is told -- what its egress
   * framer still holds goes at its pace, and -L's held datagrams with
   * it; then Q goes back.  At the operator's drain (D) what is still in
   * the socket is counted, in flight at the stop, and the counters go
   * up.  So every datagram any seat sent was received, is still in a
   * socket, or is the kernel's loss.
   */
stopping:
  acQuiet(h->seat);
  booted = 2;
  for (;;) {
    clock_gettime(CLOCK_MONOTONIC, &now);
    us = USEC(now);
    h->noBufs = 0;
    goto flush;
flushDone2:
    waitUs = acWork(h->seat, us);
    if (waitUs < 0 && !h->dq)
      break;
    waitMs = h->noBufs ? 1 : waitUs < 0 ? WAIT_MAX : (waitUs + 999) / 1000;
    if (waitMs > WAIT_MAX)
      waitMs = WAIT_MAX;
    if (h->dq && !h->sendBlocked && !h->noBufs) {
      n = h->dq->due - us > ~0UL / 2 ? 0 : (h->dq->due - us + 999) / 1000;
      if (n < waitMs)
        waitMs = n;
    }
    pf[0].fd = h->fd;
    pf[0].events = POLLOUT;
    if (poll(pf, h->sendBlocked ? 1 : 0, waitMs) > 0)
      h->sendBlocked = 0;
  }
  opSend(h->op, "Q", 1);
  while ((wl = opRecv(h->op, word, sizeof (word))) && !(wl == 1 && word[0] == 'D'))
    ;
  while (recv(h->fd, h->ibuf, DgramMax + 1, 0) >= 0)
    ++h->w.unread;
  if ((rp = calloc(1, RP_SZ))) {
    rp->hdr.self = h->self;
    rp->hdr.kind = 1;
    acCounters(h->seat, &rp->c);
    for (e = 0; e < N; ++e)
      acSeatCounters(h->seat, e, &rp->sc[e]);
    acTestCounters(h->seat, &rp->ec, &rp->ic);
    rp->w = h->w;
    rp->w.faultDealt = h->test.dealt;
    if (!opSend(h->op, &rp, sizeof (rp)))
      free(rp);
  }

exit:
  (void)booted;
  acFree(h->seat);
  while (h->dq) {
    struct dq *q;

    q = h->dq;
    h->dq = q->next;
    free(q);
  }
  free(h->ibuf);
  free(h->res);
  free(h->hwPrev);
  free(h->addr);
  if (h->fd >= 0)
    close(h->fd);
  close(h->op);
  free(h);
  return (0);
}

static int
launchProcess(
  int op
 ,unsigned int self
 ,const struct sockaddr_in *listen
){
  const struct acPar *S;
  struct hseat *h;
  pthread_t pt;

  S = &P;
  if (!(h = calloc(1, sizeof (*h))))
    return (1);
  if (!(h->ibuf = malloc(DgramMax + 1))
   || !(h->res = calloc(Slots, sizeof (*h->res)))
   || !(h->hwPrev = calloc(N, sizeof (*h->hwPrev)))
   || !(h->addr = calloc(N, sizeof (*h->addr) + 3 * sizeof (unsigned long) + 1))) {
    free(h->ibuf);
    free(h->res);
    free(h->hwPrev);
    free(h->addr);
    free(h);
    return (1);
  }
  h->geEnd = (unsigned long *)(h->addr + N);
  h->geLast = h->geEnd + N;
  h->lastMem = h->geLast + N;
  h->geBad = (unsigned char *)(h->lastMem + N);
  h->op = op;
  h->fd = -1;
  h->self = self;
  h->listen = *listen;
  if (pthread_create(&pt, 0, processT, h)) {
    free(h->ibuf);
    free(h->res);
    free(h->hwPrev);
    free(h->addr);
    free(h);
    return (1);
  }
  pthread_detach(pt);
  return (0);
}

/*------------------------------------------------------------------------*/
/*  main: the operator.  Parse args, deal the mesh and the identities,    */
/*  wire N seats, collect N results, verify agreement and assembly,       */
/*  reconcile the counters, cascade shutdown.                             */
/*------------------------------------------------------------------------*/

int
main(
  int argc
 ,char **argv
){
  int opFd[AC_SEATS];                  /* each seat's link, the operator's end */
  unsigned char quiet[AC_SEATS];       /* the seat said Q */
  struct acPar *S;                     /* the deal's parameters, P */
  unsigned char *mesh;                 /* the deal: N x N pairs (MESH) */
  unsigned char genesis[AC_HASH_MAX];
  struct sockaddr_in listen[AC_SEATS];
  unsigned char *blob[AC_SEATS];
  unsigned char *pub[AC_SEATS];
  unsigned int i;
  unsigned int k;
  int opt;
  int exitCode;
  int behind;
  int abandonOwn;                      /* no -A: the harness declares its own */
  int reboot;                          /* -R: a second chain once this one ends */
  int rebooted;                        /* this is the second chain */
  int wasDead;                         /* -R: seat N-1 was dead for the first */
  unsigned char next[AC_HASH_MAX];     /* -R: the next chain's genesis, the final hash */

  mesh = 0;
  S = &P;
  Sign = &Suites[0];
  Kdf = &Suites[1];
  Abandon = 0;                          /* the harness's own declaration, after the patience */
  MlsS = 2;
  DgramMax = 508;
  Knobs.parity = -1;
  Knobs.shardDelayUs = -1;
  reboot = rebooted = wasDead = 0;
  memset(next, 0, sizeof (next));
  while ((opt = getopt(argc, argv, "D:L:B:K:W:m:d:p:r:g:c:u:f:F:H:k:n:s:z:w:v:x:X:U:S:y:T:Z:A:M:P:b:Q:G:O:e:E:2aCRYitV")) != -1) {
    switch (opt) {
    case 'D':
      DropPct = atoi(optarg);
      break;
    case 'L':
      DelayMs = atoi(optarg);
      break;
    case 'B':
      BurstLen = atoi(optarg);
      break;
    case 'K':
      BurstDrop = atoi(optarg);
      break;
    case 'W':
      BwLimit = atoi(optarg);
      break;
    case 'm':
      Knobs.parity = atoi(optarg);
      break;
    case 'd':
      Knobs.shardDelayUs = atoi(optarg);
      break;
    case 'p':
      BasePort = atoi(optarg);
      break;
    case 'r':
      Knobs.tickMs = atoi(optarg);
      if (!Knobs.tickMs) {
        fprintf(stderr, "-r needs a tick > 0: the tick is the retry cadence\n");
        return (1);
      }
      break;
    case 'g':
      Knobs.patience = atoi(optarg);
      break;
    case 'c':
      TickCap = atoi(optarg);
      break;
    case 'u':
      BlobLen = atoi(optarg);
      /* 0 is a message: the huffman stream of nothing is not nothing */
      break;
    case 'f':
      Fault = atoi(optarg);
      if (Fault < AC_FAULT_SHARD || Fault > AC_FAULT_REUSE) {
        fprintf(stderr, "-f needs 1 (shard), 2 (share), 3 (geometry), 4 (ciphertext), 5 (salted shares), 6 (padding), 7 (two-faced), 8 (split), 9 (a shard and a share), 10 (one apex at two slots) or 11 (the second payload at the first's slot)\n");
        return (1);
      }
      break;
    case 'F':
      DgramMax = atoi(optarg);
      if (!DgramMax) {
        fprintf(stderr, "-F needs a datagram size\n");
        return (1);
      }
      break;
    case 'H':
    case 'k':
      for (i = 0; i < sizeof (Suites) / sizeof (Suites[0])
       && strcmp(Suites[i].name, optarg); ++i)
        ;
      if (i == sizeof (Suites) / sizeof (Suites[0])
       || (opt == 'H' && !Suites[i].h)) {
        fprintf(stderr, "-%c %s: not a %shash here\n", opt, optarg,
                opt == 'H' ? "power-of-two " : "");
        return (1);
      }
      if (opt == 'H')
        Sign = &Suites[i];
      else
        Kdf = &Suites[i];
      break;
    case 'n':
      Count = atoi(optarg);
      break;
    case 's':
      MlsS = atoi(optarg);
      break;
    case 'z':
      Lag = atoi(optarg);
      break;
    case 'w':
      Slow = atoi(optarg);
      break;
    case 'v':
      SlowSeats = atoi(optarg);
      break;
    case 'x':
      Cut = atoi(optarg);
      break;
    case 'X':
      CutEgr = atoi(optarg);
      break;
    case 'U':
      CutUnit = atoi(optarg);
      break;
    case 'V':
      CutData = 1;
      break;
    case 'e':
      Step = atoi(optarg);
      break;
    case 'E':
      Callers = atoi(optarg);
      break;
    case 'O':
      if ((optarg[0] != 's' && optarg[0] != 'p') || optarg[1] != ':')
        goto usage;
      RefuseAt = optarg[0] == 'p';
      Refuse = atoi(optarg + 2) + 1;
      break;
    case 'y':
      CutFrom = atoi(optarg);
      break;
    case 'T':
      {
        char *c;

        /* ms=pairs/ms=pairs...: each phase's start and its links */
        for (c = optarg, NLinks = 0; *c; ++NLinks) {
          if (NLinks == sizeof (LinkAt) / sizeof (LinkAt[0]))
            goto usage;
          LinkAt[NLinks] = strtoul(c, &c, 10);
          if (*c++ != '=' || (NLinks && LinkAt[NLinks] < LinkAt[NLinks - 1]))
            goto usage;
          memset(LinkOk[NLinks], 0, sizeof (LinkOk[0]));
          if (*c == '*') {
            memset(LinkOk[NLinks], 1, sizeof (LinkOk[0]));
            ++c;
          } else
            for (; c[0] >= '0' && c[0] <= '9' && c[1] >= '0' && c[1] <= '9'; c += 2)
              LinkOk[NLinks][(c[0] - '0') * 10 + c[1] - '0'] = 1;
          if (*c == '/')
            ++c;
          else if (*c)
            goto usage;
        }
      }
      break;
    case 'Q':
      Freeze = atoi(optarg);
      break;
    case 'G':
      RcvBuf = atoi(optarg);
      break;
    case 'Y':
      CutAll = 1;
      break;
    case 'Z':
      if (sscanf(optarg, "%u:%u", &PauseFrom, &PauseLen) != 2 || !PauseLen) {
        fprintf(stderr, "-Z needs from:len, len above 0\n");
        return (1);
      }
      break;
    case 'C':
      Censor = 1;
      break;
    case 'S':
      if (sscanf(optarg, "%u:%u", &SplitK, &SplitM) != 2 || !SplitK || !SplitM) {
        fprintf(stderr, "-S needs k:m, both above 0\n");
        return (1);
      }
      break;
    case 'A':
      Abandon = atoi(optarg);
      break;
    case 'M':
      Retention = strtoul(optarg, 0, 10);
      RetainSet = 1;
      break;
    case 'i':
      Idle = 1;
      break;
    case 'b':
      Byz = atoi(optarg);
      if (!Byz || Byz > 127) {
        fprintf(stderr, "-b needs a mask 1..127: 1 no annotations, 2 random names on the agreement rows, 4 the own INITIAL under the genesis, 8 a sign part byte, 16 a data part byte, 32 a unit's part a byte short, 64 a description byte\n");
        return (1);
      }
      break;
    case '2':
      BzSeat = 2;                       /* N - 2, once N is known */
      break;
    case 'a':
      Accomplice = 1;
      break;
    case 'R':
      reboot = 1;
      break;
    case 'P':
      if (atoi(optarg) < 1 || atoi(optarg) > 85) {
        fprintf(stderr, "-P phases is 1..85\n");
        return (1);
      }
      Knobs.rounds = 3 * atoi(optarg);
      break;
    case 't':
      Trace = 1;
      break;
    default:
      goto usage;
    }
  }

  if (argc - optind < 2)
    goto usage;
  if (!BwLimit) {
    fprintf(stderr, "-W is required: UDP has no back pressure, so every seat paces to the declared bandwidth\n");
    goto usage;
  }
  if (BurstLen && (!DropPct || DropPct >= BurstDrop)) {
    fprintf(stderr, "-B needs 0 < -D < -K: the steady loss -D is shaped into bursts that drop -K\n");
    goto usage;
  }
  N = atoi(argv[optind++]);
  MaxByz = atoi(argv[optind++]);
  if (N < 3 || N > AC_SEATS || N <= 3 * MaxByz || (NLinks && N > 10)) {
    fprintf(stderr, "need 3 <= N <= %u and N > 3t (got N=%u t=%u)\n",
      AC_SEATS, N, MaxByz);
    return (1);
  }
  if (Count < 1) {
    fprintf(stderr, "-n needs at least 1 instance\n");
    return (1);
  }
  /* the positions a seat's reports are kept for: the last seat's call,
   * then room for the end, at most one value of each seat's signed
   * before its call and one that carries it, twice over */
  Slots = QUOTA(N - 1) + 2 * N + 2;
  if (Callers < N)
    StopAt = Slots;
  if (!(FoldMs = calloc(AC_SEATS * Slots, sizeof (*FoldMs)))
   || !(HwAt = calloc(N * Slots, sizeof (*HwAt)))) {
    fprintf(stderr, "no memory\n");
    return (1);
  }
  if (MlsS < 1 || MlsS > 8) {
    fprintf(stderr, "-s needs 1..8: a context signs its rotation and at least one payload\n");
    return (1);
  }
  if (AC_FAULT_SIGNING(Fault) && Count >= 1u << MlsS) {
    /* -f 7: the dealer spends slot 0 on its apex and never rotates, so
     * it must not reach its switch; -f 8: it spends a slot of the
     * successor, which the switch would sign at again */
    fprintf(stderr, "-f %d needs -n below %u, the dealer's switch\n", Fault, 1u << MlsS);
    return (1);
  }
  if (Fault == AC_FAULT_SPLIT && (MlsS < 2 || Count < 3)) {
    fprintf(stderr, "-f 8 needs -s 2 or more and -n 3 or more: the dealer's second payload, its rotation folded everywhere\n");
    return (1);
  }
  Threshold = MaxByz > 1 ? MaxByz + 1 : 2;      /* T > t and T > 1 */
  if (AC_FAULT_SIGNING(Fault) && N - 1 == Threshold) {
    /* seat 0's own leaf is refused and the legs carry R - 1: at T = R
     * it is under threshold by arithmetic, which is not the arm */
    fprintf(stderr, "-f %d needs R > T (N - 1 > %u): seat 0 assembles from the legs alone\n", Fault, Threshold);
    return (1);
  }
  if (Censor && Fault) {
    fprintf(stderr, "-C with -f makes seats 0 and N-1 both faulty\n");
    return (1);
  }
  if (BzSeat && (!Byz || MaxByz < 2)) {
    fprintf(stderr, "-2 needs -b and t >= 2: two faulty seats\n");
    return (1);
  }
  BzSeat = BzSeat ? N - 2 : N - 1;
  if (Accomplice && (!Fault || AC_FAULT_SIGNING(Fault) || Fault == AC_FAULT_REUSE || MaxByz < 2 || Byz || Censor)) {
    fprintf(stderr, "-a needs a dealer's fault of -f 1..6 or 9 and t >= 2, and neither -b nor -C: the dealer and its accomplice are the two faulty seats\n");
    return (1);
  }
  if (Refuse && (Refuse >= N || Fault || (Byz && BzSeat == N - 1))) {
    fprintf(stderr, "-O names a member other than seat N-1, 0..N-2, and seat N-1 is a correct seat: neither -f nor -b at it\n");
    return (1);
  }
  if (Byz && (Censor || Fault)) {
    fprintf(stderr, "-b with -C makes seats 0 and N-1 both faulty; with -f the dealer's expectations are another arm's\n");
    return (1);
  }
  if (Byz && BzSeat == N - 1 && (Idle || Lag || Cut || CutEgr != ~0u || CutUnit || SplitM)) {
    fprintf(stderr, "-b with -i, -z, -x, -X, -U or -S acts on seat N-1 twice: one arm at a time, or -2\n");
    return (1);
  }
  if (CutData && !CutUnit) {
    fprintf(stderr, "-V cuts the dealt data parts beside -U's exchange: it needs -U\n");
    return (1);
  }
  if (reboot && (Callers < N || Freeze || NLinks)) {
    fprintf(stderr, "-R reboots from the end: not with -E, where no end comes, nor -Q or -T, whose marks are one chain's\n");
    return (1);
  }
  if (CutEgr == ~0u)
    CutEgr = Cut;

  for (i = 0; i < AC_SEATS; ++i) {
    pub[i] = 0;
    blob[i] = 0;
    opFd[i] = -1;
    quiet[i] = 0;
  }

  /* The sizes the construction fixes at this membership derive as every
   * seat derives them, the knobs standing where they are set; the
   * harness's own bounds beside: the blob within the message a proposal
   * admits.  -B declares the longest burst it makes, twice its mean. */
  P.lossPct = DropPct;
  P.delayMs = DelayMs;
  P.burstMs = 2 * BurstLen;
  if ((abandonOwn = !Abandon))
    Abandon = 1u << 30;                 /* the patience first */
  if (acTestDerive(S, &Knobs)) {
    fprintf(stderr, "no seat from these parameters: %s/%s, N=%u t=%u, -s %u, -F %u, -M %lu (a retention below one record, or an abandon below 1 + 7 patiences at t > 0, among the reasons)\n",
            Sign->name, Kdf->name, N, MaxByz, MlsS, DgramMax, Retention);
    return (1);
  }
  if (BlobLen > MsgMax) {
    fprintf(stderr, "-u %u: the message a proposal admits at T=%u is %u\n", BlobLen, Threshold, MsgMax);
    return (1);
  }
  /* the harness's abandon, where -A does not declare one: twice the
   * least the seat takes, one agreement with a member gone -- the
   * launch's tick, the first phase of the agreements that decide 1,
   * three rounds each waiting its patience, step 2's patience and the
   * first phase of those that decide 0 -- the patience already holding
   * the retries the declared loss makes */
  if (abandonOwn)
    Abandon = 2 * (1 + 7 * Patience);
  /* a guard only: the longest arm ends under a quarter of it, its end
   * run an abandon past its last link */
  if (!TickCap)
    TickCap = 128 * (StopAt ? StopAt : QUOTA(N - 1) + 1) + 4 * Abandon;
  Dead = Cut && !CutAll && Cut >= TickCap && CutEgr >= TickCap;
  /* again at the tick and the abandon the seats will derive */
  if (acTestDerive(S, &Knobs)) {
    fprintf(stderr, "no seat at an abandon of %u sweeps at a patience of %u\n", Abandon, Patience);
    return (1);
  }
  /* the derivation's refusals as ac.h states them, a sample of each
   * kind, one breach on a copy that otherwise derives */
  {
    struct acPar q;
    struct acHash hs;
    struct acHash hk;
    unsigned int bad;

    q = P;
    bad = !!acTestDerive(&q, &Knobs);
    q = P;
    q.self = N;
    bad |= !acTestDerive(&q, &Knobs) << 1;
    q = P;
    hs = *P.sign;
    hs.size = 1U << (hs.h - 1);
    q.sign = &hs;
    bad |= !acTestDerive(&q, &Knobs) << 2;
    hs = *P.sign;
    hs.h = 8 * sizeof (hs.size);
    q.sign = &hs;
    bad |= !acTestDerive(&q, &Knobs) << 3;
    hs = *P.sign;
    hs.final = 0;
    q.sign = &hs;
    bad |= !acTestDerive(&q, &Knobs) << 4;
    q = P;
    hk = *P.kdf;
    hk.size = 0;
    q.kdf = &hk;
    bad |= !acTestDerive(&q, &Knobs) << 5;
    hk = *P.kdf;
    hk.hkdf = 0;
    q.kdf = &hk;
    bad |= !acTestDerive(&q, &Knobs) << 6;
    printf("parameters refused: a self past n - 1, a sign width not 1 << h, an h past the width's, a sign role without final, a kdf of no width, a kdf role without hkdf: %s\n",
           bad ? "FAIL" : "ok");
    if (bad) {
      fprintf(stderr, "the derivation's refusals: 0x%x\n", bad);
      return (1);
    }
  }

  /* the chain's genesis: public, dealt */
  arc4random_buf(genesis, HashSz);

  /* The operator's deal: one secret per unordered pair, sliced for the
   * framer's two tiers and the mask, and each seat's address.  The
   * identities are the seats' own -- the operator sees public keys only
   * -- so the deal is scattered as rosters once every seat has
   * published one.  Nothing touches disk; the operator's copy of the
   * mesh is wiped once the rosters are out. */
deal:
  if (!(mesh = calloc((unsigned long)N * N, AC_PSK))) {
    fprintf(stderr, "mesh allocation failed\n");
    return (1);
  }
  for (i = 0; i < N; ++i)
    for (k = i + 1; k < N; ++k) {
      arc4random_buf(MESH(i, k), AC_PSK);
      memcpy(MESH(k, i), MESH(i, k), AC_PSK);
    }
  for (i = 0; i < N; ++i) {
    memset(&listen[i], 0, sizeof (listen[i]));
    listen[i].sin_family = AF_INET;
    listen[i].sin_port = htons(BasePort + i);
    listen[i].sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  }

  exitCode = 0;

  /* The seats start, each with its end of a socketpair to the operator;
   * each binds its wire, mints its identity and publishes its public
   * key.  The N reads are the barrier: no roster goes down until every
   * key is in. */
  for (i = 0; i < N; ++i) {
    int sv[2];

    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv)) {
      perror("socketpair");
      exitCode = 1;
      goto shutdown;
    }
    opFd[i] = sv[0];
    if (launchProcess(sv[1], i, &listen[i])) {
      close(sv[1]);
      fprintf(stderr, "launchProcess failed for seat %u\n", i);
      exitCode = 1;
      goto shutdown;
    }
  }
  for (i = 0; i < N; ++i)
    if (opRecv(opFd[i], &pub[i], sizeof (pub[i])) != sizeof (pub[i]) || !pub[i]) {
      fprintf(stderr, "seat %u failed before publishing its key\n", i);
      exitCode = 1;
      goto shutdown;
    }
  /* The rosters, one per seat: its row of the mesh and every other
   * seat's address and key. */
  for (i = 0; i < N; ++i) {
    struct roster *rs;
    unsigned int e;

    if (!(rs = malloc(sizeof (*rs) + N * sizeof (rs->e[0])))) {
      fprintf(stderr, "roster allocation failed for seat %u\n", i);
      exitCode = 1;
      goto shutdown;
    }
    rs->cnt = N - 1;
    memcpy(rs->genesis, genesis, HashSz);
    for (e = 0, k = 0; k < N; ++k) {
      if (k == i)
        continue;
      rs->e[e].id = k;
      rs->e[e].addr = listen[k];
      memcpy(rs->e[e].psk, MESH(i, k), AC_PSK);
      memcpy(rs->e[e].pub, pub[k], HashSz);
      ++e;
    }
    if (!opSend(opFd[i], &rs, sizeof (rs))) {
      rosterDealloc(rs);
      fprintf(stderr, "seat %u refused its roster\n", i);
      exitCode = 1;
      goto shutdown;
    }
  }
  memset(mesh, 0, (unsigned long)N * N * AC_PSK);
  /* Every seat reports ready once its socket is bound and its framers
   * are up, then all get the go: every socket is bound before any seat
   * sends (a datagram to a port not yet bound is the kernel's loss, and
   * the reconciliation below counts every datagram). */
  for (i = 0; i < N; ++i) {
    unsigned char *tok;

    tok = 0;
    if (opRecv(opFd[i], &tok, sizeof (tok)) != sizeof (tok) || !tok) {
      fprintf(stderr, "seat %u failed before raising its framers\n", i);
      exitCode = 1;
      goto shutdown;
    }
    free(tok);
  }
  /* the go: an empty roster, the Store's own item kind */
  for (i = 0; i < N; ++i) {
    struct roster *rs;

    if (!(rs = malloc(sizeof (*rs)))) {
      exitCode = 1;
      goto shutdown;
    }
    rs->cnt = 0;
    if (!opSend(opFd[i], &rs, sizeof (rs))) {
      rosterDealloc(rs);
      fprintf(stderr, "seat %u refused the go\n", i);
      exitCode = 1;
      goto shutdown;
    }
  }

  {
    struct processResult *got[AC_SEATS];        /* kind 3: the seat's end */
    struct processResult *ctr[AC_SEATS];        /* kind 1: the counters at stop */
    struct processResult **sub;                 /* kind 0: [seat][instance] */
    struct memberResult **msg;                  /* kind 2: [seat][instance][member] */
    struct acCounters tot;
    struct acSeatCounters attr[AC_SEATS];       /* what every seat counted of each seat, summed */
    unsigned int dupIn[AC_SEATS];               /* each seat's re-sends received
                                                 * of what it held already */
    struct wire wtot;                           /* the harness's own, from the kind-1 records */
    unsigned char *expected;
    unsigned char h[AC_HASH_MAX];
    unsigned int sigAt0;                        /* seat 0's signature refusals: -f 7's */
    unsigned int otherAt0;                      /* and its parts refused unchecked */
    unsigned int lagZero;                       /* chain reports that entered 0 for seat N-1: the
                                                 * laggard's, or the dead seat's */
    unsigned int roundMost;                     /* the latest round any agreement
                                                 * decided at, any seat */
    unsigned int idleRows;                      /* -i: positions seat N-1
                                                 * launched on the others' rows */
    unsigned int otherRows;                     /* and the other seats */
    unsigned int byzIn;                         /* -b: positions the -b seat is in
                                                 * the subset of, after the first */
    unsigned int recoveredLast;                 /* positions seat N-1 DISCOVERed */
    unsigned int frozeAt;                       /* -Q: FrozeAt, RejoinMs,
                                                 * Rejoined read under FoldMu */
    unsigned long rejoinMs;
    int rejoined;
    int thawed;
    unsigned int byzDup;                        /* -b: the re-sends that reached the -b seat */
    unsigned int collected;
    unsigned int capped;
    unsigned int missing;
    unsigned int noEnd;
    unsigned int last;                  /* the positions judged: to the end, or -E's stop */
    int endOk;                          /* the chain's end, as the reports say it */
    int faulty;                         /* the seat is one of the run's faulty seats */
    unsigned int faultyCapped;          /* faulty seats capped: no end owed */
    unsigned int egrMsg;
    unsigned int igrMsg;
    unsigned int egrFrg;
    unsigned int igrFrg;
    unsigned int wSent;
    unsigned int wRecv;
    unsigned int wUnread;
    unsigned int wStressed;
    unsigned int wRefused;
    unsigned int wNoBufs;
    unsigned int dropped;
    unsigned int unitMax;
    unsigned int dealerIn;
    int allAgree;
    int allLinked;
    int allFolded;                              /* every link the fold of its report:
                                                 * the head, the subset, the hashes */
    unsigned char fold[AC_HASH_MAX + BITS(AC_SEATS) + AC_SEATS * AC_HASH_MAX];
    unsigned int foldLen;
    int allMessages;
    int allUniform;                             /* every member's message the same
                                                 * at every correct seat, or at none */
    unsigned int accompliceHit;                 /* -a: the dealer's payloads
                                                 * seat 0 found inconsistent */
    unsigned int budgetHit;                     /* -f: the dealer's payloads
                                                 * whose search spent its budget */
    unsigned int triesMost;                     /* the most tries an honest dealer's message took */
    int lossless;

    memset(got, 0, sizeof (got));
    memset(ctr, 0, sizeof (ctr));
    memset(&tot, 0, sizeof (tot));
    memset(attr, 0, sizeof (attr));
    memset(dupIn, 0, sizeof (dupIn));
    memset(&wtot, 0, sizeof (wtot));
    sigAt0 = otherAt0 = 0;
    lagZero = 0;
    roundMost = 0;
    idleRows = otherRows = 0;
    byzIn = byzDup = 0;
    recoveredLast = 0;
    sub = 0;
    msg = 0;
    expected = 0;
    if (!(sub = calloc((unsigned long)N * Slots, sizeof (*sub)))
     || !(msg = calloc((unsigned long)N * Slots * N, sizeof (*msg)))
     || !(expected = malloc(BlobLen ? BlobLen : 1))) {
      fprintf(stderr, "report table allocation failed\n");
      exitCode = 1;
    }
    /* the seats' words, until every seat's end: the chain's and the
     * messages' reports by seat, instance and member as they flow */
    collected = 0;
    for (k = 0; collected < N;) {
      struct pollfd pf[AC_SEATS];
      unsigned char rec[sizeof (void *)];
      void *rp;
      struct resHdr *hd;
      unsigned int rl;

      for (i = 0; i < N; ++i) {
        pf[i].fd = opFd[i];
        pf[i].events = POLLIN;
        pf[i].revents = 0;
      }
      if (poll(pf, N, -1) < 0) {
        if (errno == EINTR)
          continue;
        break;
      }
      /* one record a pass, the seats in turn */
      for (i = 0; i < N && !pf[(k + i) % N].revents; ++i)
        ;
      if (i == N)
        continue;
      i = (k + i) % N;
      k = i + 1;
      rl = opRecv(opFd[i], rec, sizeof (rec));
      if (!rl) {
        /* its link closed without its word: the seat has ended */
        close(opFd[i]);
        opFd[i] = -1;
        quiet[i] = 1;
        if (!got[i])
          ++collected;
        continue;
      }
      if (rl == 1 && rec[0] == 'Q')
        quiet[i] = 1;                   /* a seat that left early: quiet already */
      if (rl != sizeof (rec))
        continue;
      memcpy(&rp, rec, sizeof (rp));
      if (!rp)
        continue;
      hd = rp;
      if (hd->self < N)
        switch (hd->kind) {
        case 3:
          if (!got[hd->self]) {
            got[hd->self] = rp;
            ++collected;
            rp = 0;
          }
          break;
        case 1:
          if (!ctr[hd->self]) {
            ctr[hd->self] = rp;         /* a seat that left early: parked */
            rp = 0;
          }
          break;
        case 0:
          if (sub && hd->inst >= 1 && hd->inst <= Slots && !sub[hd->self * Slots + hd->inst - 1]) {
            sub[hd->self * Slots + hd->inst - 1] = rp;
            rp = 0;
          }
          break;
        case 2:
          if (msg && hd->inst >= 1 && hd->inst <= Slots && hd->member < N
           && !msg[(hd->self * Slots + hd->inst - 1) * N + hd->member]) {
            msg[(hd->self * Slots + hd->inst - 1) * N + hd->member] = rp;
            rp = 0;
          }
          break;
        default:
          break;
        }
      free(rp);
    }

    {
      unsigned int m1;
      unsigned int mu;
      unsigned long d1;
      unsigned long du;

      acTestPace(S, HashSz, &m1, &d1);
      acTestPace(S, PartMax, &mu, &du);
      printf("\n--- ac results (N=%u t=%u T=%u D=%u L=%u B=%u W=%u"
             " m=%u/%u d=%lu/%lu blob=%u sign=%s kdf=%s sig=%u signpart=%u shard<=%u dgram=%u"
             " r=%u patience=%u rounds=%u abandon=%u retention=%lu record<=%u"
            ,N, MaxByz, Threshold
            ,DropPct
            ,DelayMs
            ,BurstLen
            ,BwLimit
            ,m1, mu, d1, du, BlobLen, Sign->name, Kdf->name, SigLen, UnitFixed, ShardMax, DgramMax
            ,TickMs, Patience, Rounds, Abandon, Retention, RecMax);
    }
    if (Byz)
      printf(" byzantine=%u mask=%u", BzSeat, Byz);
    if (Fault)
      printf(" dealer=%u %s", N - 1,
             Fault == AC_FAULT_SHARD ? "shard-fault" : Fault == AC_FAULT_SHARE ? "share-fault"
             : Fault == AC_FAULT_GEOM ? "geometry-fault" : Fault == AC_FAULT_CT ? "ciphertext-fault"
             : Fault == AC_FAULT_SALT ? "salted-shares" : Fault == AC_FAULT_PAD ? "padding-fault"
             : Fault == AC_FAULT_TWOFACE ? "two-faced" : Fault == AC_FAULT_SPLIT ? "split"
             : Fault == AC_FAULT_TWOSLOT ? "two-slot" : Fault == AC_FAULT_REUSE ? "reused-slot" : "shard-and-share-fault");
    printf(") ---\n");
    lossless = !DropPct && !BurstLen && !Freeze
            && ParityShards <= 0 && !Cut && !CutEgr && !CutUnit && !SplitM && !NLinks;
    printf("instances %u, %u signings a context\n", Count, 1u << MlsS);
    allAgree = allLinked = allFolded = allMessages = allUniform = 1;
    accompliceHit = 0;
    budgetHit = 0;
    triesMost = 0;
    capped = 0;
    missing = 0;
    noEnd = 0;
    unitMax = 0;
    dealerIn = 0;
    endOk = 1;
    faultyCapped = 0;
    /* the positions judged: -E's stop, else the most any seat that
     * stopped on its own folded, its end */
    for (last = StopAt, i = 0; !StopAt && i < N; ++i)
      if (got[i] && !got[i]->capped && got[i]->launched > last)
        last = got[i]->launched;
    for (i = 0; !last && i < N; ++i)    /* every seat capped: the longest chain any holds */
      if (got[i] && got[i]->launched > last)
        last = got[i]->launched;
    if (!last)
      last = Count;
    if (last > Slots)                   /* the reports kept; a seat past them fails its end below */
      last = Slots;
    for (i = 0; i < N; ++i) {
      if (!got[i]) {
        printf("seat %u: did not end\n", i);
        ++missing;
        ++noEnd;
        allAgree = allLinked = allMessages = 0;
        continue;
      }
      if (got[i]->unitLen > unitMax)
        unitMax = got[i]->unitLen;
      /* a faulty seat owes no end: one the others' answers to its own
       * lies keep busy past the cap is its cost, not the run's */
      faulty = (Byz && i == BzSeat) || (Fault && i == N - 1) || (Accomplice && i == N - 2) || (Censor && !i);
      if (got[i]->capped && !faulty)
        ++capped;
      else if (got[i]->capped)
        ++faultyCapped;
      printf("seat %u: launched %u of %u, %s at tick %u, head %02x%02x..%s\n", i,
             got[i]->launched, last, got[i]->capped ? "capped" : got[i]->exited ? "ended" : "stopped",
             got[i]->hdr.tick, got[i]->head[0], got[i]->head[1],
             Dead && i == N - 1 ? " (dead: cut past the cap)" : got[i]->capped && faulty ? " (faulty: no end owed)" : "");
    }
    /* the third window, read as an operator would, from the reports: a
     * cut seat capped at a position the every other seat has let the
     * record of go is beyond recovery, partitioned until the operator
     * intervenes, and is expected capped */
    if (((Cut && !CutAll && !Dead) || Freeze) && got[N - 1] && got[N - 1]->capped && got[N - 1]->launched < last && got[N - 1]->launched < Slots) {
      unsigned int at;

      at = got[N - 1]->launched;        /* the position it is at, 0-based */
      Partitioned = 1;
      for (i = 0; i < N - 1; ++i)
        if (!got[i] || !got[i]->ir[at].endTick)
          Partitioned = 0;
      if (Partitioned)
        printf("seat %u is at position %u, whose record every other seat has let go: partitioned, beyond the retention (expected capped)\n",
               N - 1, at + 1);
    }
    /*
     * An instance at a time: its timing from the seats' ends, then each
     * seat's two reports as that seat gave them -- the chain's at the
     * fold, the messages' at each member's end -- and the test: every
     * seat's chain report says the same subset, the same hash for every
     * member and the same link; every member's message at every other
     * seat hashes to its reported hash, the same hash the chain report
     * carried, and is the blob the operator dealt that member -- the
     * dealer's under -f no message, its commitment inconsistent, or,
     * the ciphertext fault, the search exhausted; a rotation or a noop
     * member reported as that.
     */
    for (k = 0; k < last; ++k) {
      const struct instRes *base;
      const struct processResult *sbase;
      unsigned long puts;
      unsigned long gets;
      unsigned int lo[4];
      unsigned int hi[4];
      unsigned int ok;
      unsigned int j;

      base = 0;
      sbase = 0;
      puts = gets = 0;
      ok = 0;
      for (j = 0; j < 4; ++j) {
        lo[j] = ~0u;
        hi[j] = 0;
      }
      for (i = 0; i < N; ++i) {
        const struct instRes *ir;
        unsigned int v[4];

        if (!got[i])
          continue;
        ir = &got[i]->ir[k];
        if (!ir->launched || !ir->complete)
          continue;
        ++ok;
        puts += ir->puts;
        gets += ir->gets;
        v[0] = ir->launchTick;
        v[1] = ir->subsetTick;
        v[2] = ir->foldTick;
        v[3] = ir->endTick;
        for (j = 0; j < 4; ++j) {
          if (v[j] < lo[j])
            lo[j] = v[j];
          if (v[j] > hi[j])
            hi[j] = v[j];
        }
        if (!base)
          base = ir;
      }
      printf("instance %u: %u of %u seats complete", k + 1, ok, N);
      if (base) {
        printf("; rotations %u, noops %u, promoted %u", base->rot, base->noop, base->promo);
        printf("; launch %u-%u SUBSET %u-%u fold %u-%u let go %u-%u; puts %lu gets %lu",
               lo[0], hi[0], lo[1], hi[1], lo[2], hi[2], lo[3], hi[3], puts, gets);
      }
      printf("\n");
      for (i = 0; i < N; ++i) {
        const struct processResult *sp;

        sp = sub ? sub[i * Slots + k] : 0;
        if (!sp && Dead && i == N - 1) {
          printf("  seat %u: dead\n", i);
          continue;
        }
        if (!sp && Partitioned && i == N - 1) {
          printf("  seat %u: partitioned\n", i);
          continue;
        }
        if (!sp) {
          printf("  seat %u: no chain report\n", i);
          ++missing;
          allAgree = allLinked = allMessages = 0;
          continue;
        }
        if (!sp->complete) {
          printf("  seat %u: no subset%s, reported at tick %u\n", i,
                 sp->ceiling ? ", the ACS seat stopped at the round ceiling" : "", sp->hdr.tick);
          allAgree = allLinked = allMessages = 0;
          continue;
        }
        /* the first report, the chain's: the chain hash before, the
         * subset's hashes in seat order, the chain hash after */
        printf("  seat %u: subset (%u/%u), %s at tick %u\n        %02x%02x..", i, sp->cnt, N,
               sp->stepped ? "folded" : "not folded", sp->hdr.tick, sp->prev[0], sp->prev[1]);
        for (j = 0; j < N; ++j) {
          if (!BIT_TST(RP_SUBSET(sp), j))
            continue;
          if (!BIT_TST(RP_KNOWN(sp), j)) {
            printf(":%u=unknown", j);
            allAgree = 0;
          } else if (RP_MKIND(sp)[j] == AC_ROTATION)
            printf(":%u=rotation%s:%02x%02x..", j, RP_ENDING(sp)[j] ? "+end" : "", RP_HASH(sp, j)[0], RP_HASH(sp, j)[1]);
          else if (RP_MKIND(sp)[j] == AC_NOOP)
            printf(":%u=noop%s", j, RP_ENDING(sp)[j] ? "+end" : "");
          else
            printf(":%u=%02x%02x..", j, RP_HASH(sp, j)[0], RP_HASH(sp, j)[1]);
        }
        printf(":%02x%02x..%s\n", sp->link[0], sp->link[1], sp->end ? " the end" : "");
        {
          unsigned int e;

          /* the end: at the first fold whose subset holds more than t
           * members carrying it, and no position after it */
          /* a correct member carries the end only once its seat has
           * called it, at its (n + j x step)-th fold, and only under
           * -E's callers */
          for (e = 0, j = 0; j < N; ++j) {
            e += BIT_TST(RP_SUBSET(sp), j) && RP_ENDING(sp)[j];
            if (BIT_TST(RP_SUBSET(sp), j) && RP_ENDING(sp)[j]
             && !((Byz && j == BzSeat) || (Fault && j == N - 1) || (Accomplice && j == N - 2) || (Censor && !j))
             && (j >= Callers || k + 1 <= QUOTA(j)))
              endOk = 0;
          }
          if (sp->end != (e > MaxByz) || (got[i] && got[i]->endPos && (sp->end ? k + 1 != got[i]->endPos : k + 1 >= got[i]->endPos)))
            endOk = 0;
        }
        {
          unsigned int z;

          /* the seats whose value this seat had not accepted when its
           * patience ran out, or whose agreement it had not entered by
           * the report */
          for (z = 0, j = 0; j < N; ++j)
            if (!RP_ENTERED(sp)[j])
              printf("%s %u", z++ ? "" : "        entered 0 for seats", j);
          if (z)
            printf("\n");
          if (!RP_ENTERED(sp)[N - 1])
            ++lagZero;
          /* the round each seat's agreement decided at here: a phase is
           * three rounds, and a decision past the first phase is a
           * phase in doubt */
          printf("        decided at round");
          for (j = 0; j < N; ++j) {
            printf(" %u", RP_ROUND(sp)[j]);
            if (RP_ROUND(sp)[j] > roundMost)
              roundMost = RP_ROUND(sp)[j];
          }
          printf("\n");
        }
        if (k && i != BzSeat && BIT_TST(RP_SUBSET(sp), BzSeat))
          ++byzIn;                      /* -b: in the subset at an honest seat, after the first */
        if (!sbase)
          sbase = sp;
        else {
          /* the book's move is agreed too: the same members promoted,
           * between seats that folded (an unfolded report promotes
           * nobody) */
          if (sp->cnt != sbase->cnt || memcmp(RP_SUBSET(sp), RP_SUBSET(sbase), BITS(N))
           || memcmp(sp->prev, sbase->prev, HashSz)
           || (sp->stepped && sbase->stepped && memcmp(RP_PROMOTED(sp), RP_PROMOTED(sbase), N)))
            allAgree = 0;
          for (j = 0; j < N; ++j)
            if (BIT_TST(RP_SUBSET(sp), j)
             && (RP_MKIND(sp)[j] != RP_MKIND(sbase)[j] || RP_ENDING(sp)[j] != RP_ENDING(sbase)[j]
              || memcmp(RP_HASH(sp, j), RP_HASH(sbase, j), HashSz)))
              allAgree = 0;
        }
        if (!sp->stepped || (sp != sbase && memcmp(sp->link, sbase->link, HashSz)))
          allLinked = 0;
        /* a reader of the reports folds the link for itself: the head,
         * the subset, and each member's hash in seat order, so the link
         * commits who the members were as well as what they said */
        if (sp->stepped) {
          const struct processResult *pp;

          /* the head: the dealt genesis at position 1, the link before
           * at every later one */
          pp = k ? sub[i * Slots + k - 1] : 0;
          if (k ? !pp || memcmp(sp->prev, pp->link, HashSz) : memcmp(sp->prev, genesis, HashSz))
            allFolded = 0;
          memcpy(fold, sp->prev, HashSz);
          memcpy(fold + HashSz, RP_SUBSET(sp), BITS(N));
          foldLen = HashSz + BITS(N);
          for (j = 0; j < N; ++j)
            if (BIT_TST(RP_SUBSET(sp), j)) {
              memcpy(fold + foldLen, RP_HASH(sp, j), HashSz);
              foldLen += HashSz;
            }
          hHash(fold, foldLen, h);
          if (memcmp(h, sp->link, HashSz))
            allFolded = 0;
        }
        /* the second reports, the messages': the chain hash before the
         * instance, the member's hash, the message or why none */
        printf("        messages:");
        for (j = 0; j < N; ++j) {
          const struct memberResult *mp;
          unsigned char want;
          unsigned int q;

          if (!BIT_TST(RP_SUBSET(sp), j) || j == i)
            continue;
          mp = msg ? msg[(i * Slots + k) * N + j] : 0;
          /* the dealer's: no message, the commitment inconsistent,
           * where there is a part to spare (R > T) -- at T = R one bad
           * part is in every subset and the search exhausts -- or, the
           * ciphertext fault, the search exhausted; under -a a seat the
           * accomplice withheld from holds no T good parts and
           * exhausts, and so does seat 0, or the accomplice, whose last
           * pass came before the parts that make T good; its rotation
           * is a rotation.  Where the commitment's parts are dealt bad,
           * the try budget spent is the dealer's too: no message, shown
           * nothing either way, where enough bad shares make a K for
           * nearly every subset (-f 5 at thirteen seats) */
          want = AC_PASS;
          if (Fault && j == N - 1 && !RP_MKIND(sp)[j]) {
            ++dealerIn;
            if (Fault == AC_FAULT_CT
             || (Fault != AC_FAULT_PAD && Fault != AC_FAULT_REUSE && !AC_FAULT_SIGNING(Fault) && N - 1 == Threshold))
              want = AC_EXHAUSTED;
            else if (Fault != AC_FAULT_REUSE && !AC_FAULT_SIGNING(Fault))
              want = AC_INCONSISTENT;
          }
          if (!mp) {
            printf(" %u=no report", j);
            allMessages = 0;
            continue;
          }
          printf(" %02x%02x..:%u=", mp->prev[0], mp->prev[1], j);
          if (mp->known && !mp->mkind)
            printf("%02x%02x..", mp->hash[0], mp->hash[1]);
          else if (!mp->known)
            printf("unknown");
          if (Accomplice && !i && j == N - 1 && mp->verdict == AC_INCONSISTENT)
            ++accompliceHit;
          if (want != AC_PASS && mp->verdict == AC_BUDGET)
            ++budgetHit;
          ok = (mp->verdict == want || (Accomplice && want == AC_INCONSISTENT && mp->verdict == AC_EXHAUSTED)
             || (want != AC_PASS && mp->verdict == AC_BUDGET))
            && !memcmp(mp->prev, sp->prev, HashSz)
            && mp->known == 1 && mp->mkind == RP_MKIND(sp)[j];
          if (mp->mkind) {
            /* a rotation or a noop: its value, the hash the chain
             * report carries for it */
            if (memcmp(mp->value, RP_HASH(sp, j), HashSz))
              ok = 0;
            printf("%s%s", mp->mkind == AC_ROTATION ? "rotation" : "noop", ok ? "" : " WRONG");
          } else if (mp->verdict == AC_PASS) {
            /* the message hashes to its reported hash, the same hash
             * the chain report carried, and is the blob dealt to j */
            hHash(mp->msg, mp->msgLen, h);
            if (memcmp(h, mp->hash, HashSz) || memcmp(h, RP_HASH(sp, j), HashSz))
              ok = 0;
            if (expected) {
              /* one of the blobs j proposed: the k-th, by its hash */
              for (q = 1; q <= QUOTA(j); ++q) {
                blobFill(j, q, expected);
                hHash(expected, BlobLen, h);
                if (!memcmp(h, mp->hash, HashSz))
                  break;
              }
              if (q > QUOTA(j) || mp->msgLen != BlobLen || memcmp(mp->msg, expected, BlobLen))
                ok = 0;
            }
            /* a consistent commitment: no held leaf is off it */
            for (q = 0; q < N - 1; ++q)
              if (BIT_TST(mp->badShares, q) || BIT_TST(mp->badShards, q))
                ok = 0;
            if (!(Fault && j == N - 1) && mp->tries > triesMost)
              triesMost = mp->tries;
            printf("=%u bytes%s", mp->msgLen, ok ? "" : " WRONG");
          } else {
            /* the leaves named are the fault's and no other: shard 0
             * for -f 1, share 0 for -f 2, shares 0..R-T-1 for -f 5,
             * data shard T-1 for -f 6, none for the rest and for every
             * honest member; each named iff held at the report */
            for (q = 0; q < N - 1; ++q) {
              int share;
              int shard;
              int badShare;
              int badShard;

              share = BIT_TST(mp->badShares, q) != 0;
              shard = BIT_TST(mp->badShards, q) != 0;
              badShard = Fault && j == N - 1
                      && ((Fault == AC_FAULT_SHARD && q == 0) || (Fault == AC_FAULT_BOTH && q == 0)
                       || (Fault == AC_FAULT_PAD && q == Threshold - 1));
              badShare = Fault && j == N - 1
                      && ((Fault == AC_FAULT_SHARE && q == 0) || (Fault == AC_FAULT_BOTH && q == 1)
                       || (Fault == AC_FAULT_SALT && q < N - 1 - Threshold));
              if (mp->verdict == AC_INCONSISTENT
               && (shard != (badShard && BIT_TST(mp->heldShards, q) != 0)
                || share != (badShare && BIT_TST(mp->heldShares, q) != 0)))
                ok = 0;
            }
            printf("=%s %u/%u shares %u/%u shards %u tries%s", verdictName(mp->verdict),
                   mp->shares, Threshold, mp->shards, Threshold, mp->tries, ok ? "" : " WRONG");
            for (q = 0; q < N - 1; ++q)
              if (BIT_TST(mp->badShares, q))
                printf(" bad-share-leaf-%u", q);
            for (q = 0; q < N - 1; ++q)
              if (BIT_TST(mp->badShards, q))
                printf(" bad-shard-leaf-%u", q);
          }
          if (!ok)
            allMessages = 0;
        }
        printf("\n");
      }
      /* each member's message the same bytes at every correct seat that
       * reported it, or a message at none: the dealer of -f, its
       * accomplice of -a, the seat of -b and the censor of -C are the
       * faulty seats */
      if (msg)
        for (j = 0; j < N; ++j) {
          const struct memberResult *mp;
          const struct memberResult *m0;
          unsigned int pass;
          unsigned int none;
          int differ;

          for (m0 = 0, pass = none = 0, differ = 0, i = 0; i < N; ++i) {
            if (i == j || (Fault && i == N - 1) || (Accomplice && i == N - 2) || (Byz && i == BzSeat)
             || (Censor && !i) || !(mp = msg[(i * Slots + k) * N + j]) || mp->mkind)
              continue;
            if (mp->verdict != AC_PASS)
              ++none;
            else {
              if (!m0)
                m0 = mp;
              else if (mp->msgLen != m0->msgLen || memcmp(mp->msg, m0->msg, mp->msgLen))
                differ = 1;
              ++pass;
            }
          }
          if ((pass && none) || differ) {
            printf("  member %u: a message at %u correct seats%s and none at %u: NOT UNIFORM\n",
                   j, pass, differ ? ", not the same bytes," : "", none);
            allUniform = 0;
          }
        }
    }
    /* the chain's end: every seat that stopped on its own reports it at
     * one position, that link its head, one final hash at all; under
     * -E, with t seats or fewer calling it, no seat reports one */
    {
      const struct processResult *e0;

      for (e0 = 0, i = 0; i < N; ++i) {
        if (!got[i] || got[i]->capped)
          continue;
        if (StopAt ? got[i]->endPos != 0 : !got[i]->exited || got[i]->endPos != got[i]->launched)
          endOk = 0;
        else if (!StopAt && !e0)
          e0 = got[i];
        else if (!StopAt && (got[i]->endPos != e0->endPos || memcmp(got[i]->head, e0->head, HashSz)))
          endOk = 0;
      }
      if (StopAt)
        printf("seats 0..%u alone call the end: no link carries it from more than t members, and no seat reports one: %s\n",
               Callers - 1, endOk ? "ok" : "FAIL");
      else
        printf("the chain's end: every seat that ended stopped on its own at one position, %u, the first whose subset holds more than t members carrying it, one final hash %02x%02x..: %s\n",
               e0 ? e0->endPos : 0, e0 ? e0->head[0] : 0, e0 ? e0->head[1] : 0, endOk && e0 ? "ok" : "FAIL");
      if (!endOk || (!StopAt && !e0))
        exitCode = 1;
      pthread_mutex_lock(&FoldMu);
      k = ApiLate;
      pthread_mutex_unlock(&FoldMu);
      printf("a deal after the go refused at every seat, and nothing to propose for at the chain's last link: %s\n",
             k ? "FAIL" : "ok");
      if (k)
        exitCode = 1;
      /* -R: the operator's next genesis is a final hash more than t
       * seats report alike, so a correct seat's: here the first ended
       * seat's, counted across every seat's report */
      if (reboot && e0) {
        unsigned int alike;

        for (alike = 0, i = 0; i < N; ++i)
          alike += got[i] && got[i]->exited && got[i]->endPos && !memcmp(got[i]->head, e0->head, HashSz);
        memcpy(next, e0->head, HashSz);
        printf("the next chain's genesis: the final hash %02x%02x.., reported alike by %u seats, more than t: %s\n",
               next[0], next[1], alike, alike > MaxByz ? "ok" : "FAIL");
        if (alike <= MaxByz)
          exitCode = 1;
      } else if (reboot)
        exitCode = 1;
      /* a second chain: every seat's position 1 headed by the first's
       * final hash, and seat N-1 a member of its subsets */
      if (rebooted) {
        unsigned int in;
        unsigned int from;

        for (from = 0, i = 0; i < N; ++i)
          from += sub && sub[i * Slots] && !memcmp(sub[i * Slots]->prev, next, HashSz);
        for (in = 0, k = 0; k < last; ++k)
          in += sub && sub[k] && sub[k]->complete && BIT_TST(RP_SUBSET(sub[k]), N - 1);
        printf("the chain from the last one's final hash %02x%02x..: position 1 headed by it at %u of %u seats; seat %u%s a member of %u of seat 0's %u subsets: %s\n",
               next[0], next[1], from, N, N - 1, wasDead ? ", dead in the last," : "", in, last, from == N && in ? "ok" : "FAIL");
        if (from != N || !in)
          exitCode = 1;
      }
    }
    printf("every seat reports the same subset, the same hash for every member and the same link at every instance: %s\n",
           allAgree && allLinked ? "ok" : "FAIL");
    printf("every link the fold of its report, the head, the subset and the members' hashes, and every head the link before, the genesis at position 1: %s\n", allFolded ? "ok" : "FAIL");
    if (!allFolded)
      exitCode = 1;
    printf("every member's message the same bytes at every correct seat, or at none: %s\n", allUniform ? "ok" : "FAIL");
    if (!allUniform)
      exitCode = 1;
    /* -a: seat 0 held T good parts, the accomplice's among them, and
     * reproduced the hash at least once, else the arm did not run */
    if (Accomplice) {
      printf("the dealer's payloads seat 0 reproduced and found inconsistent: %u%s\n", accompliceHit,
             accompliceHit ? "" : ": the arm did not run, FAIL");
      if (!accompliceHit)
        exitCode = 1;
    }
    /* an honest dealer's pool is one polynomial and one message: the
     * search finds it in about a try a part, whatever the pool's size
     * and however its parts arrived, all at once to a seat cut from
     * them among them */
    printf("the most tries an honest dealer's message took: %u (at most 4N = %u): %s\n",
           triesMost, 4 * N, triesMost <= 4 * N ? "ok" : "FAIL");
    if (triesMost > 4 * N)
      exitCode = 1;
    printf("every member's message at every other seat hashes to its reported hash and is its blob%s: %s\n",
           !Fault ? "" : Fault == AC_FAULT_CT ? " (the dealer's: no message, the search exhausted)"
           : Fault == AC_FAULT_TWOFACE ? " (the dealer's: its apex in a rotation's shape refused at seat 0, the message from the legs)"
           : Fault == AC_FAULT_SPLIT ? " (the dealer's: its apex signed by its successor refused at seat 0, the message from the legs)"
           : Fault == AC_FAULT_TWOSLOT ? " (the dealer's: its apex signed at a second slot refused at seat 0, the message from the legs)"
           : Fault == AC_FAULT_REUSE ? " (the dealer's: the payload at its first payload's slot in no subset)"
           : N - 1 == Threshold && Fault != AC_FAULT_PAD ? " (the dealer's: no message, one bad part is in every subset at T = R)"
           : " (the dealer's: no message, its commitment inconsistent)", allMessages ? "ok" : "FAIL");
    if (budgetHit)
      printf("the dealer's payloads whose search spent its try budget, no message: %u\n", budgetHit);
    if (Fault && !dealerIn) {
      /* a geometry dealer is refused at receive where its leaves are
       * mis-bound and can fall out; any other dealer's units verify
       * everywhere, and a subset without its payload is the test not
       * run */
      printf("the dealer %u's payload is in no seat's subset%s\n", N - 1,
             Fault == AC_FAULT_GEOM ? ": its fault was refused at receive"
             : AC_FAULT_SIGNING(Fault) ? ": FAIL, one seat's refusal cannot keep it out" : ": FAIL, its units verify everywhere");
      if (Fault != AC_FAULT_GEOM)
        exitCode = 1;
    }
    printf("Ending: %u of %u seats ended with every instance folded and reported, %u capped%s, %u faulty capped (no end owed), %u reports missing\n",
           N - capped - faultyCapped - noEnd, N, capped, Dead ? " (the dead seat, expected)" : Partitioned ? " (the partitioned seat, expected)" : "",
           faultyCapped, missing);
    if (!allAgree || !allMessages || !allLinked || capped != (Dead || Partitioned ? 1u : 0u) || missing)
      exitCode = 1;

    /* Let what the last report's tick put on the wire land before the
     * counters are read: ten ticks for the framer pipelines, plus the
     * declared delay (-L, twice) and the longest shard train (-d) a
     * framer may still be pacing.  A wait sized from the declared
     * physics, so the reconciliation below can be exact; no seat waits
     * on it. */
    {
      struct timespec ts;
      unsigned long ms;
      unsigned int m;
      unsigned long d;

      acTestPace(S, PartMax, &m, &d);
      ms = (unsigned long)TickMs * 10 + 2UL * DelayMs
         + ((PartMax + Shard - 1) / Shard + m + 1) * d / 1000;
      ts.tv_sec = ms / 1000;
      ts.tv_nsec = (long)(ms % 1000) * 1000000L;
      nanosleep(&ts, 0);
    }
    /* The stop, two words: Q, and every seat stops talking, sends what
     * its framer still has and says Q back; then D, and every seat
     * counts what is still in its socket and sends its counters. */
    {
    unsigned char rec[sizeof (void *)];
    struct processResult *rp;
    unsigned int rl;

    for (i = 0; i < N; ++i)
      if (!quiet[i] && opFd[i] >= 0)
        opSend(opFd[i], "Q", 1);
    for (;;) {
      for (collected = 0, i = 0; i < N; ++i)
        collected += quiet[i] ? 1 : 0;
      if (collected == N)
        break;
      {
        struct pollfd pf[AC_SEATS];

        for (i = 0; i < N; ++i) {
          pf[i].fd = opFd[i];
          pf[i].events = POLLIN;
          pf[i].revents = 0;
        }
        if (poll(pf, N, -1) < 0 && errno != EINTR)
          break;
        for (i = 0; i < N && !pf[i].revents; ++i)
          ;
        if (i == N)
          continue;
        if (!(rl = opRecv(opFd[i], rec, sizeof (rec)))) {
          close(opFd[i]);               /* the seat has ended */
          opFd[i] = -1;
          quiet[i] = 1;
          continue;
        }
      }
      if (rl == 1 && rec[0] == 'Q')
        quiet[i] = 1;
      else if (rl == sizeof (rec)) {
        memcpy(&rp, rec, sizeof (rp));
        free(rp);                       /* a report after the end: the operator's no more */
      }
    }
    for (i = 0; i < N; ++i)
      if (opFd[i] >= 0)
        opSend(opFd[i], "D", 1);
    for (;;) {
      for (collected = 0, i = 0; i < N; ++i)
        collected += ctr[i] || opFd[i] < 0 ? 1 : 0;
      if (collected == N)
        break;
      {
        struct pollfd pf[AC_SEATS];

        for (i = 0; i < N; ++i) {
          pf[i].fd = opFd[i];
          pf[i].events = POLLIN;
          pf[i].revents = 0;
        }
        if (poll(pf, N, -1) < 0 && errno != EINTR)
          break;
        for (i = 0; i < N && !pf[i].revents; ++i)
          ;
        if (i == N)
          continue;
        if (!(rl = opRecv(opFd[i], rec, sizeof (rec)))) {
          close(opFd[i]);               /* the seat has ended */
          opFd[i] = -1;
          quiet[i] = 1;
          continue;
        }
      }
      if (rl != sizeof (rec))
        continue;
      memcpy(&rp, rec, sizeof (rp));
      if (rp && rp->hdr.self < N && rp->hdr.kind == 1 && !ctr[rp->hdr.self])
        ctr[rp->hdr.self] = rp;
      else
        free(rp);
    }
    }
    /* The class counters, one cut per seat at the stop (the report's
     * copy is an earlier cut; a seat that never answered the stop
     * leaves its report's). */
    for (i = 0; i < N; ++i) {
      const struct acCounters *c;
      unsigned int j;

      if (!ctr[i] && !got[i])
        continue;
      c = ctr[i] ? &ctr[i]->c : &got[i]->c;
      if (!i) {
        sigAt0 = c->unitBad[AC_UNIT_SIG];
        otherAt0 = c->partOther;
      }
      if (i == BzSeat)
        byzDup = c->dupInitial + c->dupDunit + c->dupXunit;
      tot.inAcs += c->inAcs;
      tot.inDist += c->inDist;
      tot.inLeg += c->inLeg;
      tot.inDunit += c->inDunit;
      tot.inXunit += c->inXunit;
      tot.dupDunit += c->dupDunit;
      tot.dupXunit += c->dupXunit;
      tot.shardAhead += c->shardAhead;
      tot.shardOther += c->shardOther;
      tot.dupInitial += c->dupInitial;
      tot.initOther += c->initOther;
      tot.unitSent += c->unitSent;
      for (j = 0; j < sizeof (tot.unitBad) / sizeof (tot.unitBad[0]); ++j)
        tot.unitBad[j] += c->unitBad[j];
      tot.secondApex += c->secondApex;
      tot.partOther += c->partOther;
      tot.signReplaced += c->signReplaced;
      tot.asmAlloc += c->asmAlloc;
      tot.noInstance += c->noInstance;
      tot.future += c->future;
      tot.aheadFull += c->aheadFull;
      tot.aheadDup += c->aheadDup;
      tot.replayed += c->replayed;
      tot.rowMem += c->rowMem;
      tot.ownMem += c->ownMem;
      tot.sweepAge[0] += c->sweepAge[0];
      if (c->replayMost > tot.replayMost)
        tot.replayMost = c->replayMost;
      tot.recorded += c->recorded;
      tot.recoverStarts += c->recoverStarts;
      tot.repeated += c->repeated;
      tot.heldRepeated += c->heldRepeated;
      tot.recovered += c->recovered;
      tot.placed += c->placed;
      tot.kept += c->kept;
      tot.keptMembers += c->keptMembers;
      tot.keptPassed += c->keptPassed;
      tot.keptUnder += c->keptUnder;
      tot.keptNow += c->keptNow;
      if (c->placedAfter > tot.placedAfter)
        tot.placedAfter = c->placedAfter;
      tot.rcvRefused += c->rcvRefused;
      tot.slotReused += c->slotReused;
      tot.offsetReplay += c->offsetReplay;
      tot.launchOnRows += c->launchOnRows;
      if (i == N - 1) {
        recoveredLast = c->recovered;
        idleRows = c->launchOnRows;
      } else
        otherRows += c->launchOnRows;
      tot.routedUnit += c->routedUnit;
      tot.stopped += c->stopped;
      tot.notInitiator += c->notInitiator;
      tot.malformed += c->malformed;
      tot.loss += c->loss;
      tot.lossUnit += c->lossUnit;
      tot.qDrop += c->qDrop;
      tot.replyEcho += c->replyEcho;
      tot.replyReady += c->replyReady;
      tot.aheadMem += c->aheadMem;
      tot.sendRefused += c->sendRefused;
      tot.passLong += c->passLong;
      tot.noSubset += c->noSubset;
      if (c->subsetMost > tot.subsetMost)
        tot.subsetMost = c->subsetMost;
      tot.parityUsed += c->parityUsed;
      tot.parityLast += c->parityLast;
      if (c->parityMost > tot.parityMost)
        tot.parityMost = c->parityMost;
      if (c->overUs > tot.overUs)
        tot.overUs = c->overUs;
      tot.retained += c->retained;
      tot.retainedBytes += c->retainedBytes;
      if (c->retainedMost > tot.retainedMost)
        tot.retainedMost = c->retainedMost;
      tot.released += c->released;
      /* what seat i counted of each other seat, by the sender the tier
       * verified or the signer: summed, the window ticks the newest */
      for (j = 0; j < N; ++j) {
        const struct acSeatCounters *a;
        unsigned int q;

        a = ctr[i] ? &ctr[i]->sc[j] : &got[i]->sc[j];
        if (a->liveTick > attr[j].liveTick)
          attr[j].liveTick = a->liveTick;
        if (a->recordTick > attr[j].recordTick)
          attr[j].recordTick = a->recordTick;
        if (a->heldTick > attr[j].heldTick)
          attr[j].heldTick = a->heldTick;
        if (a->rttLeast > attr[j].rttLeast)
          attr[j].rttLeast = a->rttLeast;
        if (a->rttMost > attr[j].rttMost)
          attr[j].rttMost = a->rttMost;
        attr[j].rtts += a->rtts;
        attr[j].sweptHeld += a->sweptHeld;
        attr[j].live += a->live;
        attr[j].recorded += a->recorded;
        attr[j].held += a->held;
        attr[j].heldFull += a->heldFull;
        attr[j].swept += a->swept;
        attr[j].resent += a->resent;
        dupIn[i] += a->resent;
        attr[j].replied += a->replied;
        attr[j].noInstance += a->noInstance;
        attr[j].stopped += a->stopped;
        attr[j].loss += a->loss;
        attr[j].malformed += a->malformed;
        attr[j].notInitiator += a->notInitiator;
        attr[j].initOther += a->initOther;
        attr[j].partOther += a->partOther;
        attr[j].rcvRefused += a->rcvRefused;
        for (q = 0; q < sizeof (a->unitBad) / sizeof (a->unitBad[0]); ++q)
          attr[j].unitBad[q] += a->unitBad[q];
        attr[j].secondApex += a->secondApex;
        attr[j].signReplaced += a->signReplaced;
        attr[j].slotReused += a->slotReused;
        attr[j].offsetReplay += a->offsetReplay;
      }
      if (ctr[i]) {
        wtot.cut += ctr[i]->w.cut;
        wtot.cutUnit += ctr[i]->w.cutUnit;
        wtot.censored += ctr[i]->w.censored;
        wtot.faultDealt += ctr[i]->w.faultDealt;
        wtot.byz += ctr[i]->w.byz;
        wtot.withheld += ctr[i]->w.withheld;
        wtot.notGiven += ctr[i]->w.notGiven;
        wtot.hwEarly += ctr[i]->w.hwEarly;
        wtot.hwMissing += ctr[i]->w.hwMissing;
        wtot.hwPos += ctr[i]->w.hwPos;
        wtot.hwMoved += ctr[i]->w.hwMoved;
        wtot.hwSplit += ctr[i]->w.hwSplit;
        wtot.hwStale += ctr[i]->w.hwStale;
      }
    }
    printf("per seat at the stop, the longest agreement in sweeps / the most positions live:");
    for (i = 0; i < N; ++i) {
      const struct acCounters *c;

      if (!ctr[i] && !got[i])
        continue;
      c = ctr[i] ? &ctr[i]->c : &got[i]->c;
      printf(" %u: %u/%u", i, c->subsetMost, c->liveMost);
    }
    printf("\n");
    printf("\n--- ingress by class ---\n");
    printf("acs %u  dist %u  leg %u  dunit parts %u (dup %u)  xunit parts %u (dup %u)"
           "  parts sent %u  unit %u bytes  shard ahead of its sign %u (another %u)\n",
           tot.inAcs, tot.inDist, tot.inLeg, tot.inDunit, tot.dupDunit,
           tot.inXunit, tot.dupXunit, tot.unitSent, unitMax, tot.shardAhead, tot.shardOther);
    printf("INITIAL already fed %u  INITIAL under another value than the held unit's %u  replies said: echo %u ready %u\n",
           tot.dupInitial, tot.initOther, tot.replyEcho, tot.replyReady);
    printf("leg rows with no instance here %u  rows to a stopped ACS seat %u"
           "  rows held under a name not yet minted %u (re-sent %u, not held, the window full of the sender's %u, read at the launch %u, at most %u in one call)  positions launched on another seat's rows %u\n",
           tot.noInstance, tot.stopped, tot.future, tot.aheadDup, tot.aheadFull, tot.replayed, tot.replayMost, tot.launchOnRows);
    pthread_mutex_lock(&FoldMu);
    frozeAt = FrozeAt;
    rejoinMs = RejoinMs;
    rejoined = Rejoined;
    thawed = Thawed;
    pthread_mutex_unlock(&FoldMu);
    if (Freeze && rejoined)
      printf("seat %u, frozen at %u positions folded, was within one position of every other seat %lu ms after its thaw\n",
             N - 1, frozeAt, rejoinMs);
    printf("own value broadcasts started alone, a bracha87Fig1, the agreement let go or at the ceiling with the position unfolded: %u; at a launch held, the folded position's machines gone: %u\n", tot.repeated, tot.heldRepeated);
    printf("retention: rows naming a retained position %u  recover legs started %u  records held at the stop %u (%lu bytes; the most at once at one seat %lu)  let go %u\n",
           tot.recorded, tot.recoverStarts, tot.retained, tot.retainedBytes, tot.retainedMost, tot.released);
    printf("recovery: recover descriptions refused %u  positions folded on T of them alike %u, %u of them at seat %u\n"
           "kept past the live window: positions %u, members %u, of them reported with the message %u, under threshold %u, unreported %u;"
           " parts placed %u, at most %u ticks after their position left the window\n",
           tot.rcvRefused, tot.recovered, recoveredLast, N - 1,
           tot.kept, tot.keptMembers, tot.keptPassed, tot.keptUnder, tot.keptNow, tot.placed, tot.placedAfter);
    printf("attribution, by the sender the datagram tier verified or the signer, summed over the seats, the window ticks the newest:\n");
    for (i = 0; i < N; ++i)
      printf("  seat %u: rows live %u recorded %u held %u (full %u) re-sent %u  swept to it %u (held %u)  in held already %u  replied to it %u  round trips %u (least at most %lu ms, most %lu ms)  no instance %u stopped %u lost %u"
             "  malformed %u notInitiator %u initOther %u parts refused %u (unchecked %u)  signer faults %u"
             "  last live t=%u record t=%u held t=%u\n",
             i, attr[i].live, attr[i].recorded, attr[i].held, attr[i].heldFull, attr[i].resent, attr[i].swept, attr[i].sweptHeld, dupIn[i],
             attr[i].replied, attr[i].rtts, attr[i].rttLeast / 1000, attr[i].rttMost / 1000, attr[i].noInstance, attr[i].stopped, attr[i].loss, attr[i].malformed, attr[i].notInitiator, attr[i].initOther,
             attr[i].unitBad[AC_UNIT_LEN] + attr[i].unitBad[AC_UNIT_SIG] + attr[i].unitBad[AC_UNIT_SSS] + attr[i].unitBad[AC_UNIT_RSEC],
             attr[i].partOther,
             attr[i].secondApex + attr[i].signReplaced + attr[i].slotReused + attr[i].offsetReplay,
             attr[i].liveTick, attr[i].recordTick, attr[i].heldTick);
    printf("unit refused: len %u sig %u sss %u rsec %u mem %u  unchecked %u  secondApex %u  sign part replaced %u  slot leaked %u  offset replayed %u  assembly unallocated %u\n",
           tot.unitBad[AC_UNIT_LEN], tot.unitBad[AC_UNIT_SIG],
           tot.unitBad[AC_UNIT_SSS], tot.unitBad[AC_UNIT_RSEC], tot.unitBad[AC_UNIT_MEM], tot.partOther, tot.secondApex, tot.signReplaced,
           tot.slotReused, tot.offsetReplay, tot.asmAlloc);
    printf("malformed %u  notInitiator %u  loss %u (units %u)  qDrop %u  held rows refused by memory %u  rows refused by memory %u  own steps waiting on memory %u  cut %u (units %u)  censored %u  proposals past the bound %u\n",
           tot.malformed, tot.notInitiator, tot.loss, tot.lossUnit, tot.qDrop, tot.aheadMem, tot.rowMem, tot.ownMem,
           wtot.cut, wtot.cutUnit, wtot.censored, tot.proposeLong);
    printf("physics: parity shards the decodes used %u (the most one message used %u, decodes with none to spare %u)"
           "  sends refused %u  passes past their tick %u  a tick late by at most %lu ms  decided at round %u at the latest"
           "  the longest agreement %u sweeps of the abandon's %u, agreements abandoned without a subset %u\n",
           tot.parityUsed, tot.parityMost, tot.parityLast, tot.sendRefused, tot.passLong, tot.overUs / 1000, roundMost,
           tot.subsetMost, P.abandon, tot.noSubset);
    /* the tick is at least the earliest evidence: what a position said
     * is not swept again until a tick has passed since its launch, loss
     * or none, whatever the round trips */
    printf("rows re-sent under a tick from their position's launch: %u: %s\n",
           tot.sweepAge[0], tot.sweepAge[0] ? "FAIL" : "ok");
    if (tot.sweepAge[0])
      exitCode = 1;
    {
      unsigned int mu;
      unsigned long du;

      /* the instruments are the integration's: the framer's decode
       * reaches the parity counters, the ACS seat's entry reaches the
       * chain report.  Under a declared loss, with parity to use, some
       * decode used it; with a laggard held past patience or a dead
       * seat, some report entered 0 for it.  What the agreement does
       * past patience is its own library's test. */
      acTestPace(S, PartMax, &mu, &du);
      if (DropPct && mu && !BurstLen && !tot.parityUsed) {
        printf("loss declared and no decode used parity: the detector is blind, FAIL\n");
        exitCode = 1;
      }
      /* in bursts the loss takes whole trains, which the parity has no
       * margin for and BPR pays for across ticks: an eviction's loss
       * notification, or a decode's parity, reached the counters */
      if (BurstLen && !tot.loss && !tot.parityUsed) {
        printf("loss declared in bursts and no train was evicted and no decode used parity: the detector is blind, FAIL\n");
        exitCode = 1;
      }
      if ((Lag > Patience || Dead) && !lagZero) {
        printf("seat %u held past patience and no report entered 0 for it: the detector is blind, FAIL\n", N - 1);
        exitCode = 1;
      }
      /* a payload agreed that its seat did not give when asked is a
       * proposal the seat queued; the laggard, held past patience on
       * every new proposal, delivers only by presenting again what a
       * subset left out, on the same bytes given, and lets every other
       * one go, the next given in its place */
      if (wtot.notGiven) {
        printf("%u payloads agreed that their seat did not give when asked: a queue, FAIL\n", wtot.notGiven);
        exitCode = 1;
      }
      if (wtot.hwEarly || wtot.hwMissing || wtot.hwPos || wtot.hwMoved || wtot.hwSplit || wtot.hwStale) {
        printf("signer high water off SUBSET inclusion at a fold: set with no membership %u, unset with one %u,"
               " at another position %u, moved for a non-member %u, unlike another seat's %u,"
               " a member at or below it %u, FAIL\n",
               wtot.hwEarly, wtot.hwMissing, wtot.hwPos, wtot.hwMoved, wtot.hwSplit, wtot.hwStale);
        exitCode = 1;
      }
      if (Lag > Patience && Count >= 8 && ctr[N - 1]
       && (!ctr[N - 1]->w.agreed || !ctr[N - 1]->c.again || !ctr[N - 1]->w.skipped)) {
        printf("seat %u held past patience: %u blobs agreed, %u presented again, %u let go; each should be some: FAIL\n",
               N - 1, ctr[N - 1]->w.agreed, ctr[N - 1]->c.again, ctr[N - 1]->w.skipped);
        exitCode = 1;
      }
      /* the split, held past patience, keeps one agreement's first
       * phase from deciding (the head comment: at -P 1 every run stops
       * at the ceiling), so some seat's decision in it fell past round
       * 3 */
      if (SplitK && SplitM > Patience && roundMost <= 3) {
        printf("a split agreement and every decision at round 3: the detector is blind, FAIL\n");
        exitCode = 1;
      }
      /* the idle seat proposes nothing, so its positions after the
       * first launch on the others' rows, but for one presenting again
       * a rotation a subset left out, and the counter says so: some,
       * and never more than the positions after the first; the others
       * say they have a blob inside their chain callback, ahead of the
       * same pass's launch, so with nothing lost none of theirs does */
      if (Idle && Count > 1 && (!idleRows || idleRows > Count - 1)) {
        printf("seat %u proposed nothing and launched %u positions on the others' rows of %u after its first: FAIL\n",
               N - 1, idleRows, Count - 1);
        exitCode = 1;
      }
      /* under -E the seats that never call propose nothing past their
       * count and launch on the callers' rows */
      if (lossless && otherRows && !StopAt) {
        printf("%u positions launched on another seat's rows at seats that propose at every fold: FAIL\n", otherRows);
        exitCode = 1;
      }
      /* the harness's ground truth, never a seat's: seat N-1 folded a
       * link more than the abandon, and two ticks, after the first
       * other seat folded it, so it folded on what the ring held */
      behind = 0;
      for (k = 0; k < Count; ++k) {
        unsigned long first;

        for (first = 0, i = 0; i < N - 1; ++i)
          if (FoldMs[i * Slots + k] && (!first || FoldMs[i * Slots + k] < first))
            first = FoldMs[i * Slots + k];
        if (first && FoldMs[(N - 1) * Slots + k] > first + (unsigned long)(Abandon + 2) * TickMs)
          behind = 1;
      }
      /* a freeze thaws when the others have folded its positions past
       * the ones it had, or the whole chain: a chain that ended before
       * they were past the live window is the arm not run, no verdict */
      if (Freeze && !Partitioned && !thawed) {
        printf("seat %u was never frozen or never thawed: the arm did not run, FAIL\n", N - 1);
        exitCode = 1;
      }
      if (Freeze && !Partitioned && thawed && !behind) {
        printf("seat %u was frozen at %u positions folded, and folded no link of the chain of %u past the others' abandon: the arm did not run, FAIL\n",
               N - 1, frozeAt, Count);
        exitCode = 1;
      }
      if (((Cut && !CutAll && !Dead && !Partitioned) || (Freeze && !Partitioned)) && behind && !tot.recoverStarts) {
        printf("seat %u cut with the chain past the live window and no recover leg started from a record: the detector is blind, FAIL\n", N - 1);
        exitCode = 1;
      }
      /* the attribution reached the counters: the cut seat's rows named
       * records, which started the others' recover legs.  Nothing is
       * asserted of the other seats: under unbounded latency any of
       * them may lag another by the live window, and up to t of them
       * may do anything.  Under a dealt fault every part refused at a
       * gate is the dealer's: the gates are cryptoMule's, and no honest
       * part fails one */
      /* and its positions the others had let go of the machines of it
       * DISCOVERed, T descriptions alike beside the recover legs their
       * records sent it: the recovery reached its counter */
      if (((Cut && !CutAll && !Dead && !Partitioned) || (Freeze && !Partitioned)) && behind
       && !recoveredLast) {
        printf("seat %u was cut or frozen past the live window and DISCOVERed no position: FAIL\n", N - 1);
        exitCode = 1;
      }
      if (((Cut && !CutAll && !Dead && !Partitioned) || (Freeze && !Partitioned)) && behind
       && !attr[N - 1].recorded) {
        printf("seat %u was cut or frozen past the live window and the counters attribute it no row naming a record: FAIL\n",
               N - 1);
        exitCode = 1;
      }
      for (i = 0; i < N - 1; ++i)
        if (Fault && attr[i].unitBad[AC_UNIT_LEN] + attr[i].unitBad[AC_UNIT_SIG] + attr[i].unitBad[AC_UNIT_SSS] + attr[i].unitBad[AC_UNIT_RSEC]) {
          printf("seat %u dealt no fault and %u of its parts were refused: FAIL\n", i,
                 attr[i].unitBad[AC_UNIT_LEN] + attr[i].unitBad[AC_UNIT_SIG] + attr[i].unitBad[AC_UNIT_SSS] + attr[i].unitBad[AC_UNIT_RSEC]);
          exitCode = 1;
        }
      /* the Byzantine row sender: what it sends costs what the head
       * comment says and moves nothing.  Saying HOLDING of nothing, it
       * is re-sent what it is owed at every tick, which its row counts;
       * its agreement rows under random names are held at the others,
       * the live window of each shape and one more, the rest not held,
       * which the chain shows once it has run past the window and one;
       * its own INITIAL under the genesis is, while position 1 is live,
       * an INITIAL under another value, and once position 1 is a
       * record, a row naming a record it has folded past, which its row
       * counts and which is owed nothing, its agreement rows having
       * shown it at live positions; and nobody holding its INITIAL its
       * value is in no subset after the first at any honest seat.  The
       * sweeps' rows to it under bit 1, its subsets and the re-sends it
       * saw are readings, not judged: every seat's row counts the
       * sweeps' rows to it, so a judge of them would be one of the
       * honest seats' timing, and its INITIAL is its own and may be
       * late like any seat's.  Every count is in its row of the table,
       * summed over the seats that counted it */
      if (Byz && !wtot.byz) {
        printf("seat %u rewrote no tag or part: the arm did not fire, FAIL\n", BzSeat);
        exitCode = 1;
      }
      if (Accomplice) {
        printf("seat %u, the dealer's accomplice, withheld %u exchange parts from every seat but 0%s\n",
               N - 2, wtot.withheld, wtot.withheld ? "" : ": the arm did not fire, FAIL");
        if (!wtot.withheld)
          exitCode = 1;
      }
      if (Byz)
        printf("seat %u rewrote %u tags and parts; %u re-sends reached it, %u sweeps' rows were sent it; in %u subsets of %u after the first at the honest seats; %u of its parts refused\n",
               BzSeat, wtot.byz, byzDup, attr[BzSeat].swept, byzIn, (N - 1) * (Count - 1),
               attr[BzSeat].unitBad[AC_UNIT_LEN] + attr[BzSeat].unitBad[AC_UNIT_SIG] + attr[BzSeat].unitBad[AC_UNIT_SSS] + attr[BzSeat].unitBad[AC_UNIT_RSEC]);
      if ((Byz & 2) && Count > 2 && (!attr[BzSeat].held || !attr[BzSeat].heldFull)) {
        printf("seat %u named its agreement rows at random and the counters attribute it %u rows held and %u not held: FAIL\n",
               BzSeat, attr[BzSeat].held, attr[BzSeat].heldFull);
        exitCode = 1;
      }
      if ((Byz & 4) && tot.retainedMost && (!attr[BzSeat].initOther || !attr[BzSeat].recorded || byzIn)) {
        printf("seat %u named position 1 in its INITIAL and the counters attribute it %u under another value, %u naming a record, in %u subsets after the first: FAIL\n",
               BzSeat, attr[BzSeat].initOther, attr[BzSeat].recorded, byzIn);
        exitCode = 1;
      }
      /* hostile bytes under its own key: every part so sent refused at
       * a gate and counted to it, and no honest seat's part refused */
      if ((Byz & 56) && !(attr[BzSeat].unitBad[AC_UNIT_LEN] + attr[BzSeat].unitBad[AC_UNIT_SIG]
                          + attr[BzSeat].unitBad[AC_UNIT_SSS] + attr[BzSeat].unitBad[AC_UNIT_RSEC])) {
        printf("seat %u sent hostile parts and none was refused: the gates are blind, FAIL\n", BzSeat);
        exitCode = 1;
      }
      if ((Byz & 64) && !attr[BzSeat].rcvRefused) {
        printf("seat %u sent hostile descriptions and none was refused: the check is blind, FAIL\n", BzSeat);
        exitCode = 1;
      }
      for (i = 0; i < N; ++i)
        if (Byz && i != BzSeat && attr[i].unitBad[AC_UNIT_LEN] + attr[i].unitBad[AC_UNIT_SIG] + attr[i].unitBad[AC_UNIT_SSS] + attr[i].unitBad[AC_UNIT_RSEC]) {
          printf("seat %u is honest and %u of its parts were refused: FAIL\n", i,
                 attr[i].unitBad[AC_UNIT_LEN] + attr[i].unitBad[AC_UNIT_SIG] + attr[i].unitBad[AC_UNIT_SSS] + attr[i].unitBad[AC_UNIT_RSEC]);
          exitCode = 1;
        }
      /* a partitioned seat's rows name a position nobody can place:
       * held, and records were let go */
      if (Partitioned && (!(attr[N - 1].held || attr[N - 1].heldFull) || !tot.released)) {
        printf("seat %u is partitioned and its rows were not held under an unplaceable name, or nothing was let go: FAIL\n", N - 1);
        exitCode = 1;
      }
      /* positions left the live window: records were held */
      if (behind && !tot.retainedMost) {
        printf("the chain ran past the live window and no record was held: FAIL\n");
        exitCode = 1;
      }
      /* a declared retention is one the arm means to wrap: records were
       * let go */
      if (RetainSet && !tot.released) {
        printf("a retention of %lu bytes was declared and no record was let go: the arm did not run, FAIL\n", Retention);
        exitCode = 1;
      }
    }
    /* what a correct run leaves at zero: the faults, by the row of the
     * seat they are counted to, every honest seat's row at zero, and
     * the Byzantine seat's too but for the one its bits predict, an
     * INITIAL under another value from bit 4; a frame refused from its
     * length names no seat and stays in the seat-wide count */
    {
      unsigned int faults;
      unsigned int named;

      faults = 0;
      named = 0;
      for (i = 0; i < N; ++i) {
        named += attr[i].malformed;
        faults += attr[i].malformed + attr[i].notInitiator + attr[i].secondApex
                + attr[i].signReplaced + attr[i].offsetReplay;
        /* -f 11: the dealer's leaked slot, refused, is its own */
        if (Fault != AC_FAULT_REUSE || i != N - 1)
          faults += attr[i].slotReused;
        /* a signing fault's copy refused at seat 0 on its value is the
         * dealer's, as one refused at its signature gate is; so is a
         * sign part -b 8 flipped in its offset or hashes, refused on
         * its value before its signature is read */
        if ((!AC_FAULT_SIGNING(Fault) || i != N - 1) && (!(Byz & 8) || i != BzSeat))
          faults += attr[i].partOther;
        if (!(Byz & 64) || i != BzSeat)
          faults += attr[i].rcvRefused;
        if (!(Byz & 4) || i != BzSeat)
          faults += attr[i].initOther;
      }
      if (faults || tot.malformed - named || tot.qDrop || tot.aheadMem || (tot.asmAlloc && !Refuse) || tot.proposeLong
       || (!Byz && (tot.notInitiator || (Fault != AC_FAULT_REUSE && tot.slotReused) || tot.offsetReplay || tot.secondApex || tot.signReplaced || tot.initOther))) {
        printf("a counter a correct run leaves at zero is not (the faults by seat, malformed, qDrop, held rows refused by memory,"
               " assembly unallocated, proposals past the bound): FAIL\n");
        exitCode = 1;
      }
    }
    /* -f 7: seat 0's signature refusals are the dealt fraud; any other
     * seat's are a defect */
    for (i = 1; i < sizeof (tot.unitBad) / sizeof (tot.unitBad[0]); ++i)
      if (tot.unitBad[i] && !(Fault == AC_FAULT_GEOM && i == AC_UNIT_SSS)
       && !(AC_FAULT_SIGNING(Fault) && i == AC_UNIT_SIG && tot.unitBad[i] == sigAt0)
       && !((Byz & 56) && i != AC_UNIT_MEM && tot.unitBad[i] == attr[BzSeat].unitBad[i])) {
        printf("unit refused at gate %u, %u times, not the arm's fault: FAIL\n", i, tot.unitBad[i]);
        exitCode = 1;
      }
    if (Fault == AC_FAULT_GEOM && !tot.unitBad[AC_UNIT_SSS]) {
      printf("a non-derived geometry dealt and the sssMk gate never fired: the detector is blind\n");
      exitCode = 1;
    }
    /* -O: the refusal reached a position's end, and every member it
     * kept there was reported with its message (the uniformity above
     * says the same bytes as the others) */
    if (Refuse && (!tot.asmAlloc || !tot.keptMembers || tot.keptPassed != tot.keptMembers || tot.keptNow)) {
      printf("the refused search %s: FAIL\n",
             !tot.asmAlloc ? "was never refused: the arm did not run"
             : !tot.keptMembers ? "kept no member past its position's end"
             : "left a member it kept without its message");
      exitCode = 1;
    }
    if (Fault == AC_FAULT_REUSE && (!wtot.faultDealt || !tot.slotReused)) {
      /* the dealer's first payload left out leaves its slot unagreed,
       * and a second value there is no leak any seat can see */
      printf("the payload at the first payload's slot %s: the arm did not run\n",
             !wtot.faultDealt ? "was never signed" : "reached no seat's gate with that slot agreed");
      exitCode = 1;
    }
    if (AC_FAULT_SIGNING(Fault) && !wtot.faultDealt) {
      /* the dealer was left out before the payload that carries the
       * fault: the arm did not run, which is not a verdict on the gate */
      printf("the fault was never dealt: the dealer's payload at slot %u came too late for -n %u; the arm did not run\n",
             Fault == AC_FAULT_SPLIT ? SLOT_PAY + 1 : SLOT_PAY, Count);
      exitCode = 1;
    } else if (AC_FAULT_SIGNING(Fault) && !sigAt0 && !otherAt0) {
      printf("%s and seat 0 refused it at neither its signature gate nor its value: the detector is blind\n",
             Fault == AC_FAULT_TWOFACE ? "a payload's apex dealt in a rotation's shape"
             : Fault == AC_FAULT_TWOSLOT ? "a payload's apex signed at a second slot"
             : "a payload's apex signed by the dealer's successor");
      exitCode = 1;
    }

    /* -T: one seat at a time, what it put and got in each phase: the
     * kinds by class -- the agreement's rows I/E/R, the value
     * broadcasts' I/E/R/B, the legs' I/E/R/B, the recover legs' I/E/R/B
     * -- to each other seat, carried or dropped at its egress, and from
     * each other seat */
    if (NLinks) {
      unsigned int sx;
      unsigned int ph;
      unsigned int o;

      printf("\n--- one seat's wire by phase (-T): put to its egress, carried | dropped, and got from its ingress;"
             " acs I/E/R  dist I/E/R/B  leg I/E/R/B  rcv I/E/R/B ---\n");
      for (sx = 0; sx < N; ++sx)
        for (ph = 0; ph < NLinks; ++ph) {
          const unsigned int *pp;

          pp = LinkPos[sx][ph];
          printf("seat %u phase %u at %lu ms: folded %u; its rows named %u..%u, rows got named %u..%u,"
                 " %u behind its newest fold, %u under a name not minted here\n",
                 sx, ph + 1, LinkAt[ph], LinkFold[sx][ph], pp[0], pp[1], pp[2], pp[3], LinkOld[sx][ph], LinkAhead[sx][ph]);
          for (o = 0; o < N; ++o) {
            const unsigned int *a;
            const unsigned int *b;
            const unsigned int *c;

            if (o == sx)
              continue;
            a = LinkPut[sx][ph][o];
            b = LinkCut[sx][ph][o];
            c = LinkGot[sx][ph][o];
            printf("  to %u: %u/%u/%u %u/%u/%u/%u %u/%u/%u/%u %u/%u/%u/%u | %u/%u/%u %u/%u/%u/%u %u/%u/%u/%u %u/%u/%u/%u"
                   "   from %u: %u/%u/%u %u/%u/%u/%u %u/%u/%u/%u %u/%u/%u/%u\n", o,
                   a[0], a[1], a[2], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11], a[12], a[13], a[14], a[15],
                   b[0], b[1], b[2], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15], o,
                   c[0], c[1], c[2], c[4], c[5], c[6], c[7], c[8], c[9], c[10], c[11], c[12], c[13], c[14], c[15]);
            a = LinkRec[sx][ph][o];
            for (c = a; c < a + 16 && !*c; ++c)
              ;
            if (c < a + 16)
              printf("    of the carried, from a record: %u/%u/%u/%u\n", a[12], a[13], a[14], a[15]);
          }
        }
    }

    {
      int rb;
      int pfd;
      socklen_t rl;

      /* a seat's receive buffer, this kernel's default */
      rb = 0;
      if ((pfd = socket(AF_INET, SOCK_DGRAM, 0)) >= 0) {
        rl = sizeof (rb);
        getsockopt(pfd, SOL_SOCKET, SO_RCVBUF, &rb, &rl);
        close(pfd);
      }
      printf("\n--- rsecFrm counters (tag %u, shard %u, hmac %u, gate %u; a seat's receive buffer %d bytes) ---\n",
             AC_TAG_SIZE(HashSz), Shard, HmacSz, (unsigned int)HALFSIPHASH_HSH_SZ, rb);
    }
    printf("seat     egrMsg  egrFrg  egrFull egrAgn  egrWaitMs igrFrg  igrGate igrAuth igrDup "
           "igrLate igrMsg  igrDcd  igrEvict\n");
    egrMsg = 0;
    igrMsg = 0;
    egrFrg = 0;
    igrFrg = 0;
    wSent = wRecv = wUnread = wStressed = wRefused = wNoBufs = 0;
    for (i = 0; i < N; ++i) {
      struct rsecFrmEgrCtrs ec;
      struct rsecFrmIgrCtrs ic;

      if (!ctr[i]) {
        printf("%-5u no counters: the seat did not answer the stop\n", i);
        exitCode = 1;
        continue;
      }
      ec = ctr[i]->ec;
      ic = ctr[i]->ic;
      egrMsg += ec.msg;
      igrMsg += ic.msg;
      egrFrg += ec.frg;
      igrFrg += ic.frg;
      wSent += ctr[i]->w.sent;
      wRecv += ctr[i]->w.recv;
      wUnread += ctr[i]->w.unread;
      wStressed += ctr[i]->w.stressed;
      wRefused += ctr[i]->w.refused;
      wNoBufs += ctr[i]->w.noBufs;
      if (ctr[i]->c.frmRefused || ctr[i]->c.igrBusy || ctr[i]->w.dqDrop) {
        printf("seat %u: the loop lost what it held (egress framer %u, ingress framer %u, -L %u)\n",
               i, ctr[i]->c.frmRefused, ctr[i]->c.igrBusy, ctr[i]->w.dqDrop);
        exitCode = 1;
      }
      printf("%-5u %-7u %-7u %-7u %-7u %-9lu %-7u %-7u %-7u %-6u %-7u %-7u %-7u %-u\n"
            ,i
            ,ec.msg, ec.frg, ec.full, ec.again, ec.wait / 1000
            ,ic.frg, ic.hash, ic.dhmac, ic.dup, ic.late
            ,ic.msg, ic.dcd, ic.evict);
      if (ic.hash || ic.dhmac) {
        printf("seat %u: the framer refused datagrams (gate %u, auth %u)\n",
               i, ic.hash, ic.dhmac);
        exitCode = 1;
      }
    }
    /* The wire, from the seats' own counts at the stop: every datagram
     * a seat's sendto took was received, is still unread in a socket --
     * in flight, so the counters are a cut, not a reconciliation -- or
     * is the kernel's loss, a full receive buffer on the way.  The
     * declared network's drops are before the sendto, and a send the
     * kernel refused is its loss too.  A loss in the kernel is fair
     * loss to BPR like any other, never a failure; a run that sees one
     * sends harder than its physics carries, which the counts say.
     * With nothing in flight and nothing lost the counts must reconcile
     * exactly. */
    dropped = wSent >= wRecv + wUnread ? wSent - wRecv - wUnread : 0;
    printf("datagrams sent %u, received %u, unread at the stop %u, lost in the kernel %u;"
           " dropped by the declared network %u, refused at the send %u; the kernel pushed back %u\n",
           wSent, wRecv, wUnread, dropped, wStressed, wRefused, wNoBufs);
    if (wSent < wRecv + wUnread) {
      printf("more datagrams received than sent: MISMATCH\n");
      exitCode = 1;
    }
    printf("fragments sent %u, received %u\n", egrFrg, igrFrg);
    if (lossless && !wUnread && !dropped && !wRefused && !wStressed && egrFrg != igrFrg) {
      printf("nothing in flight, nothing lost, and the fragment counts differ: MISMATCH\n");
      exitCode = 1;
    }
    if ((Censor && !wtot.censored) || ((Cut || CutEgr || CutUnit || SplitM || NLinks) && !wtot.cut)) {
      printf("the declared cut or censor dropped nothing: the arm did not fire, FAIL\n");
      exitCode = 1;
    }
    printf("egress messages %u, ingress messages %u", egrMsg, igrMsg);
    if (wUnread)
      printf(" (a cut: %u datagrams in flight)", wUnread);
    else if (dropped || wRefused)
      printf(" (the kernel lost %u datagrams: not reconciled)", dropped + wRefused);
    else if (lossless && wStressed)
      printf(" (the bandwidth dropped %u datagrams, a send past -W: not reconciled)", wStressed);
    else if (lossless) {
      unsigned int over;
      unsigned int overUnit;

      /* Lossless: every egress message delivered once or notified lost
       * (the framer's LRU can still evict a slow multi-shard train
       * under the single-shard churn; the notification is the receipt,
       * and BPR re-serves it), and every unit sent received or so
       * notified -- the framer's counts and the classes' agree.  An
       * evicted train's late shards open a second partial entry the LRU
       * can evict again, so one message can be notified twice: the
       * identity is exact without evictions and, with them,
       * over-notified by at most their count. */
      over = igrMsg + tot.loss - egrMsg;
      overUnit = tot.inDunit + tot.inXunit + (tot.lossUnit + tot.routedUnit) - tot.unitSent;
      printf(" (lossless, m=0: %s with %u notified lost; unit parts %u sent, %u received"
             " + %u notified or of an instance not live there: %s)",
             egrMsg == igrMsg + tot.loss ? "reconciled"
             : igrMsg + tot.loss > egrMsg && over <= tot.loss
               ? "reconciled net of a twice-notified train" : "MISMATCH",
             tot.loss, tot.unitSent, tot.inDunit + tot.inXunit, (tot.lossUnit + tot.routedUnit),
             tot.unitSent == tot.inDunit + tot.inXunit + (tot.lossUnit + tot.routedUnit) ? "ok"
             : tot.inDunit + tot.inXunit + (tot.lossUnit + tot.routedUnit) > tot.unitSent
               && overUnit <= (tot.lossUnit + tot.routedUnit) ? "ok net of it" : "MISMATCH");
      if (igrMsg + tot.loss < egrMsg || over > tot.loss
       || tot.inDunit + tot.inXunit + (tot.lossUnit + tot.routedUnit) < tot.unitSent
       || overUnit > (tot.lossUnit + tot.routedUnit))
        exitCode = 1;
    }
    printf("\n");

    for (i = 0; i < N; ++i) {
      free(got[i]);
      free(ctr[i]);
    }
    if (sub)
      for (i = 0; i < N * Slots; ++i)
        free(sub[i]);
    if (msg)
      for (i = 0; i < N * Slots * N; ++i) {
        if (msg[i] && msg[i]->msgLen)
          memset(msg[i]->msg, 0, msg[i]->msgLen);
        free(msg[i]);
      }
    free(sub);
    free(msg);
    free(expected);
  }

  /* -R: the reboot.  The chain has ended at every seat that could end
   * it; the operator deals the next one afresh, as it dealt this one:
   * every seat a new process minting a new identity, since no key
   * outlives its process, new pair secrets, so nothing this chain put
   * on the wire, replayed or from a seat still running in it,
   * authenticates in the next, and the genesis the final hash.  The
   * seat dead here is back; the next chain's seats bind the ports past
   * this one's. */
  if (reboot && !exitCode) {
    printf("the reboot: a fresh deal, every seat back, the genesis the final hash\n\n");
    reboot = 0;
    rebooted = 1;
    wasDead = Dead;
    memcpy(genesis, next, HashSz);
    free(mesh);
    mesh = 0;
    for (i = 0; i < N; ++i) {
      free(blob[i]);
      blob[i] = 0;
      free(pub[i]);
      pub[i] = 0;
      if (opFd[i] >= 0)
        close(opFd[i]);
      opFd[i] = -1;
      quiet[i] = 0;
    }
    Cut = CutEgr = CutUnit = CutFrom = 0;
    CutData = CutAll = Dead = Partitioned = 0;
    memset(Folded, 0, sizeof (Folded));
    memset(Ended, 0, sizeof (Ended));
    ApiLate = 0;
    memset(HwAt, 0, N * Slots * sizeof (*HwAt));
    memset(FoldMs, 0, AC_SEATS * Slots * sizeof (*FoldMs));
    BasePort += N;
    goto deal;
  }

shutdown:
  if (mesh)
    memset(mesh, 0, (unsigned long)N * N * AC_PSK);
  free(mesh);
  for (i = 0; i < N; ++i) {
    free(blob[i]);
    free(pub[i]);
    if (opFd[i] >= 0)
      close(opFd[i]);
  }
  return (exitCode);

usage:
  fprintf(stderr,
    "usage: acTest -W bps [-D drop] [-L delayms] [-B burstms] [-K burstdrop]\n"
    "            [-m parity] [-d shardus] [-p baseport]\n"
    "          [-r tickms] [-g patience] [-c ticks]\n"
    "            [-u blobbytes] [-F dgram] [-H sign] [-k kdf]\n"
    "            [-n instances] [-e step] [-E k] [-s signings] [-z lagticks] [-w slowness] [-v seats] [-x cutticks] [-X egressticks] [-U legticks] [-V] [-O at:m] [-C] [-S k:m] [-y cutstart] [-Y] [-Z from:len]\n"
    "            [-T ms=pairs/...] [-Q positions] [-G bytes]\n");
  fprintf(stderr,
    "            [-A sweeps] [-M bytes] [-P phases] [-i] [-b mask] [-2] [-f fault] [-a] [-R] [-t] N t\n");
  fprintf(stderr,
    "  N   seats (3-%d)\n"
    "  -W  bits/s a seat sends, required: UDP has no back pressure, the seats pace to it\n"
    "  t   max byzantine (N > 3t); the SSS threshold T is above t and above 1\n",
    AC_SEATS);
  fprintf(stderr,
    "  -D  percent of datagrams lost at each send; -L each one delayed 0..ms, uniform\n"
    "  -B  -D shaped into bursts of this mean in ms; -K the loss in a burst (default 90)\n"
    "  -m  parity shards a message leaves with, in place of the derived; -d the inter-shard pacing in us, likewise\n"
    "  -p  the first seat's UDP port (default 42000): seat i binds it + i, and under -R the next chain the N past those\n"
    "  -r  the tick in ms in place of the derived\n");
  fprintf(stderr,
    "  -g  patience in sweeps in place of the derived 2 and the sweeps -D and -B retry; the abandon, -A, sits above it, at t > 0 at 1 + 7 of it\n"
    "  -c  the tick cap, a guard only (default 128 x the last call's position, and four abandons)\n");
  fprintf(stderr,
    "  -n  seat i calls the end at its n-th fold, proposing a message for every position before it but the rotations\n"
    "      its signing context is due, position 1 among them (default 1: no message, the rotation and the end)\n"
    "  -e  seat i calls the end at its (n + i x step)-th fold, proposing a message for every position before it\n"
    "  -E  seats 0..k-1 alone call the end: no end comes, and the harness stops the seats\n");
  fprintf(stderr,
    "  -R  once the chain ends, a second from its final hash under a fresh deal, every seat back, on the ports past the first's\n"
    "  -u  each seat's blob in bytes (default 200)\n"
    "  -s  2^s one-time signings a signing context, the first its rotation (1..8, default 2)\n"
    "  -P  phases an agreement may run, 1..85, in place of the byte's 85\n"
    "  -F  datagram bytes (default 508); -H sign hash; -k kdf hash\n");
  fprintf(stderr,
    "  -T  the directed links over time: ms=pairs phases split by '/', ab the link a to b, '*' all\n"
    "  -x  seat N-1's ingress, and its egress unless -X, is cut for this many ticks from the go\n"
    "  -X  seat N-1's egress alone is cut for this many ticks from the go\n"
    "  -U  seat N-1's ingress of the exchange alone is cut for this many ticks from the go\n"
    "  -V  with -U, the dealt units' data parts are cut too: the sign parts arrive\n");
  fprintf(stderr,
    "  -O  at:m, seat N-1's memory refuses member m's search, s the search's buffers or p the pool's, until kept\n"
    "  -C  seat 0 sends seat N-1 no (initial, v) of its own and no unit, ever\n");
  fprintf(stderr,
    "  -w  seats 0..-v less one are this many times slower: each sleeps that less one times its processor time\n"
    "  -z  seat N-1 holds each new proposal's INITIAL this many ticks: the laggard\n");
  fprintf(stderr,
    "  -S  k:m, seats 0..k-1 receive no READY of seat N-1's value for m ticks: one BA's inputs split\n"
    "  -y  the cut begins at this tick, not the go; -Y the cut is every seat's: the network dark\n"
    "  -Q  seat N-1 frozen from the tick -y names until the others fold this many positions past it: a stopped process\n"
    "  -G  seat N-1's socket receive buffer in bytes, below the system's default: a smaller host's\n");
  fprintf(stderr,
    "  -Z  from:len, every seat but N-1 proposes nothing from this tick for this many ticks: the chain idles\n"
    "  -A  the sweeps an instance runs before it stops: its abandon, paid out of t (default 2 x (1 + 7 patience))\n");
  fprintf(stderr,
    "  -M  a seat's retention in bytes: the records behind the live window, the newest over the oldest (default 16 MiB)\n");
  fprintf(stderr,
    "  -i  seat N-1 proposes nothing: its positions launch on the others' rows, its noop its input\n"
    "  -b  seat N-1 rewrites its tags: 1 no annotations, 2 random names on its agreement rows, 4 its INITIAL under the genesis;\n"
    "      and its exchange parts: 8 a sign part byte, 16 a data part byte, 32 a unit's part a byte short,\n"
    "      64 a description byte; -2 the seat is N-2 (t >= 2)\n");
  fprintf(stderr,
    "  -f  seat N-1's fault: 1 a shard, 2 a share, 3 the geometry, 4 the ciphertext,\n"
    "      5 every share but the last T, 6 a padding byte, 7 two-faced, 8 split (-n below 2^s),\n"
    "      9 a shard of one leaf and a share of another, 10 one apex at two slots,\n"
    "      11 the second payload at the first's slot\n"
    "  -a  with -f 1..6 or 9 and t >= 2, not -b or -C: seat N-2, the dealer's accomplice,\n"
    "      sends its exchange parts to seat 0 alone\n"
    "  -t  the state trace, one line per transition\n");
  return (1);
}
