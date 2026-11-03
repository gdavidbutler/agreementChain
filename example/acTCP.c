/*
 * agreementChain - an operator and its seats, over TCP
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
 * example/acTCP.c - acUDP.c with the seats' datagrams carried over TCP
 * connections, for a network that carries no datagrams.  The operator,
 * the deal, the configuration's format, the link, the reports and the
 * seat's loop are acUDP.c's, and its head comment says them; this one
 * says the transport and the datagram's length, the two things that
 * differ.  The library is the same: it hands its send callback datagrams
 * of the same form, authenticated as there, only longer, and takes the
 * same at acInput.  TCP adds nothing it relies on.
 *
 * A seat keeps at most one connection with each other seat, whichever
 * of the two dialed it, and sends and receives on it alike.  Each
 * datagram goes on it as a frame, a 2-byte big-endian length and the
 * datagram.  A frame whose length is 0 or past the datagram the seats
 * were dealt closes the connection, since a stream cannot find its next
 * frame after it; a datagram the library refuses does not, the framing
 * being intact.
 *
 * Nothing about a connection names the seat at its other end but what
 * that seat proves: an address proves nothing, and a datagram replayed
 * proves nothing either, since the network may replay any.  So each end
 * sends a hello, its seat number and a fresh nonce, and on the other's
 * hello a proof: the HMAC, under a key derived from the pair's dealt
 * secret, of the prover, the verifier, whether the prover dialed, and
 * the two nonces, the prover's first.  The other's proof checked, the
 * connection is bound to that seat; a dialer also refuses a hello from
 * any seat but the one it dialed.  A replayed proof answers a nonce of
 * another connection, so a replay binds nothing.  Nor does a stranger
 * that opens a connection to each of two seats and passes each one's
 * hello and proof to the other: both of its connections were dialed by
 * it, so each seat proves as the one dialed, and each expects a proof
 * from a dialer.  To be bound it must be where a seat dials, at the
 * address dealt for the other: on the network between them, which may
 * carry or drop what each sends, as any network may.  The prover leads,
 * so no proof verifies back at the seat that made it.  On each stream
 * the hello goes first and the proof before any datagram, and a seat
 * sends datagrams only once bound, which is after its own proof went:
 * so a seat never reads a datagram on a connection it has not bound.
 * The key is the hash's HKDF of the whole secret under a label of its
 * own, so it shares nothing with the slices the library keys its
 * datagrams by.
 *
 * Two seats that dial each other at once may both bind: each keeps the
 * one the lower-numbered seat dialed and closes the other, which both
 * can tell without a word.  A connection bound beside one bound more
 * than a tick before takes its place: crossing dials bind within a
 * round trip of each other, and a seat dials only when it has no
 * connection of its own dialing in hand, so a later one says the older
 * is gone at the other end, though this end has not heard.  A
 * connection not bound within HS_TICKS ticks of its making is closed,
 * whoever made it, so a dial to an address that never answers gives way
 * to the next, and a stranger holds a place only that long; and past N
 * unbound ones accepted, the oldest is closed for the newest.
 *
 * The library stops its egress at the first datagram its send callback
 * refuses, for every seat at once, so a refusal says the whole seat's
 * socket is full; here no connection may stop the others.  A datagram
 * that cannot go now is the network's loss, counted by why, and the
 * seat's sweeps re-send it as they re-send any datagram lost: to a seat
 * with no connection bound, which this seat then dials if it is not
 * dialing it already, once a tick at most, each dial the next address
 * its list gives; or behind a connection that still holds the rest of an
 * earlier frame, or that the system says is not writable.  A connection
 * is writable while its unsent bytes are under LOWAT_BYTES, or under
 * half of it as Linux counts (TCP_NOTSENT_LOWAT, where the system has
 * it), so what the seat chose to send waits in the seat, not in a kernel
 * queue ahead of what it chooses next.  TCP's retransmission makes a live
 * connection lossless, but not a broken one: what either kernel held
 * when it broke is gone, and the sweeps re-send that too, so a
 * connection lossless while it lasts is still a network that only
 * eventually delivers.  A connection that dies with no word at either end
 * is found when TCP gives up on it, and the seat counts its datagrams
 * lost until then.  Within a connection one lost segment holds every
 * datagram behind it, every position's alike, which datagrams never do
 * to each other: the delay is the declared delay's to cover.  At its end
 * a seat closes its side for writing, reads what still comes for a tick,
 * and closes, so the frames it handed the kernel last are not discarded
 * by a close with unread bytes.
 *
 * The configuration is acUDP.c's: bind is what seat S listens on, reach
 * where the other seats dial it, each address in its turn, exec the
 * command that starts it, which runs ./acTCP -l at the seat's end.
 *
 * Usage:
 *   ./acTCP [-W bits_per_s] [-L delay_ms] [-D loss_pct] [-B burst_ms] -A abandon_sweeps [-p baseport] [-e messages] N t
 *   ./acTCP [-W bits_per_s] [-L delay_ms] [-D loss_pct] [-B burst_ms] -A abandon_sweeps [-e messages] -o config N t
 *   ./acTCP -l
 *
 * The options are acUDP.c's.  -D declares the loss TCP leaves, its
 * breaks, and is 0 where the connections hold.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include "rmd128.h"
#include "rmd160.h"
#include "ac.h"

static void *rmd128Alloc(void) { return (malloc(rmd128tsize())); }
static void *rmd160Alloc(void) { return (malloc(rmd160tsize())); }

static const struct acHash Sign = {
  "rmd128", rmd128Alloc, rmd128tsize, (void (*)(void *))rmd128init
, (void (*)(void *, const unsigned char *, unsigned int))rmd128update
, (void (*)(void *, unsigned char *))rmd128final, rmd128hmac, rmd128hkdf, RMD128_SZ, 4 };
static const struct acHash Kdf = {
  "rmd160", rmd160Alloc, rmd160tsize, (void (*)(void *))rmd160init
, (void (*)(void *, const unsigned char *, unsigned int))rmd160update
, (void (*)(void *, unsigned char *))rmd160final, rmd160hmac, rmd160hkdf, RMD160_SZ, 0 };

#define USEC(ts) ((unsigned long)(ts).tv_sec * 1000000UL + (ts).tv_nsec / 1000)
/* a call this long is said when it returns; the counters are looked at
 * this often */
#define LONG_MS 200
#define LOOK_MS 30000
/* the datagram every seat is dealt.  A stream fragments none, so a
 * frame need not fit a path's packet, and the framer caps a shard at
 * 16384 bytes: at 4096 the 51 bytes of tag, HMAC, gate and framing every
 * datagram carries are about 1% of it, under a third of their share of
 * acUDP's 1232, and a frame is about three full Ethernet segments */
#define DGRAM_MAX 4096

/* where a seat's reports go: standard output, or standard error where
 * standard input and output are its link (-l), each report one write */
static FILE *Out;
static char OutBuf[1 << 16];

/* the operator's parameters down the link, ten 4-byte big-endian words:
 * n, t, bwLimit, lossPct, delayMs, dgramMax, abandon, mlsS, messages,
 * burstMs.  An address list on the link is its text, a 2-byte
 * big-endian length and the bytes, which the seat reading it resolves:
 * never a socket structure, whose layout is each system's own */
#define DEAL_WORDS 10
#define LIST_MAX   65535
/* a seat's entry on the link: [id][secret][key][list length], the list
 * after */
#define ENTRY_LEN(hashSz) (1 + AC_PSK + (hashSz) + 2)
#define PUT32(p, v) ((p)[0] = ((v) >> 24) & 0xff, (p)[1] = ((v) >> 16) & 0xff, (p)[2] = ((v) >> 8) & 0xff, (p)[3] = (v) & 0xff)
#define GET32(p)    (((unsigned long)(p)[0] << 24) | ((unsigned long)(p)[1] << 16) | ((unsigned long)(p)[2] << 8) | (p)[3])
#define PUT16(p, v) ((p)[0] = ((v) >> 8) & 0xff, (p)[1] = (v) & 0xff)
#define GET16(p)    (((unsigned int)(p)[0] << 8) | (p)[1])

/* the handshake: a hello is [seat][nonce], a proof the HMAC of
 * [prover][verifier][prover's nonce][verifier's nonce], under the pair's
 * key, the HKDF of its dealt secret under HK_LABEL */
#define NONCE      16
#define HELLO_LEN  (1 + NONCE)
#define PROOF_TEXT (3 + 2 * NONCE)
#define HK_LABEL   "acTCP handshake"
#define HK_LEN     RMD160_SZ          /* Kdf's */
/* the unsent bytes past which a connection is not writable: about two
 * frames, or one where Linux counts half */
#define LOWAT_BYTES 8192
/* the ticks a connection has to bind: a dial's connect, the hellos and
 * the proofs are three round trips, and a tick is at least one */
#define HS_TICKS     4

/* a connection: dialing, hello sent, proof sent, bound */
#define C_DIAL  0
#define C_HELLO 1
#define C_PROOF 2
#define C_BOUND 3
struct conn {
  unsigned char      *in;             /* a frame as it arrives, 2 + dgramMax */
  unsigned char      *out;            /* the frame the socket took part of, 2 + dgramMax */
  unsigned long       born;           /* when it was made: its deadline to bind,
                                       * and the oldest unbound */
  unsigned long       bound;          /* when it was bound */
  int                 fd;             /* -1 once closed */
  unsigned int        peer;           /* the seat at its other end: the one dialed,
                                       * or a hello's; N until then */
  unsigned int        inLen;
  unsigned int        outOff;         /* out[outOff..outLen) still to go */
  unsigned int        outLen;
  unsigned char       dialed;         /* this seat dialed it */
  unsigned char       state;
  unsigned char       nonce[NONCE];   /* this seat's */
  unsigned char       peerNonce[NONCE];
};

/* an address a seat is dialed at */
struct to {
  struct sockaddr_storage sa;
  socklen_t           len;
};

/* one seat: the library's seat and what this process owns around it */
struct seat {
  struct ac          *ac;
  struct to          *to;             /* every address dealt: seat k's at
                                       * to[at[k]] .. to[at[k + 1] - 1] */
  unsigned int       *at;             /* [seat + 1] */
  struct conn        *c;              /* the connections, nc of them */
  int                *lfd;            /* the listening sockets, nl of them */
  struct pollfd      *pf;             /* the listening sockets, then each connection */
  unsigned char      *hk;             /* [seat] x HK_LEN: the handshake keys */
  unsigned long      *dialUs;         /* [seat]: when this seat last dialed it */
  unsigned int       *dialNext;       /* [seat]: the address its next dial tries */
  unsigned long       us;             /* the loop's clock, for the send callback */
  unsigned int        nc;
  unsigned int        nl;
  unsigned int        self;
  unsigned int        n;
  unsigned int        hashSz;
  unsigned int        dgramMax;
  unsigned int        tickMs;
  unsigned int        messages;       /* messages left to propose */
  unsigned int        sent;           /* messages agreed */
  unsigned int        folded;         /* chain reports */
  unsigned int        lostNone;       /* datagrams lost for want of a bound connection */
  unsigned int        lostFull;       /* behind a connection holding an earlier frame's rest
                                       * or its unsent bytes at their bound */
  unsigned int        lostOther;      /* for any other reason, the connection closed by it */
  unsigned int        dials;          /* connections this seat dialed */
  unsigned int        dialFails;      /* dials that never connected */
  unsigned int        accepts;        /* connections it accepted */
  unsigned int        binds;          /* connections bound */
  unsigned int        refused;        /* closed at the handshake: a hello or proof refused */
  unsigned int        late;           /* closed not bound by its deadline */
  unsigned int        dups;           /* bound beside another to the same seat, one closed */
  unsigned int        closes;         /* connections closed, every reason */
  int                 up;             /* the link up: ready, then how the seat ended */
};

static void
hex(
  const unsigned char *b
 ,unsigned int l
){
  while (l--)
    fprintf(Out, "%02x", *b++);
}

/* the seat's message, asked for the position launching: the next one
 * not yet agreed, the same bytes again where a subset left it out */
static unsigned int
propose(
  void *ctx
 ,unsigned char *msg
 ,unsigned int max
){
  struct seat *s;
  char text[64];
  unsigned int len;

  s = ctx;
  if (!s->messages)
    return (0);
  sprintf(text, "seat %u says hello, message %u", s->self, s->sent + 1);
  if ((len = strlen(text)) > max)
    return (0);
  memcpy(msg, text, len);
  return (len);
}

static void
chain(
  void *ctx
 ,const struct acChain *c
){
  struct seat *s;
  unsigned int j;

  s = ctx;
  fprintf(Out, "seat %u chain %u: ", s->self, c->position);
  hex(c->prev, s->hashSz);
  for (j = 0; j < s->n; ++j) {
    if (!(c->subset[j >> 3] & (1 << (j & 7))))
      continue;
    fprintf(Out, ":%u=", j);
    if (c->kind[j] == AC_ROTATION)
      fprintf(Out, "rotation ");
    else if (c->kind[j] == AC_NOOP)
      fprintf(Out, "noop ");
    hex(c->hash + j * s->hashSz, s->hashSz);
  }
  fprintf(Out, ":");
  hex(c->next, s->hashSz);
  fprintf(Out, "%s\n", c->end ? " the end" : "");
  fflush(Out);
  ++s->folded;
  /* this seat's message, a payload member, is agreed: the next is the
   * one it says it has */
  if ((c->subset[s->self >> 3] & (1 << (s->self & 7))) && c->kind[s->self] == AC_PAYLOAD) {
    --s->messages;
    ++s->sent;
  }
  /* its last message agreed, the seat calls the end, at whatever link
   * that is here: every value it signs from now carries it, and the
   * chain ends at the first link more than t members carry it into, the
   * same link at every seat; the seat stops on its own after it */
  if (!s->messages)
    acEnd(s->ac);
  else
    acAvailable(s->ac);
}

static void
message(
  void *ctx
 ,const struct acMessage *m
){
  struct seat *s;

  s = ctx;
  if (m->kind != AC_PAYLOAD)
    return;
  fprintf(Out, "seat %u message %u member %u: ", s->self, m->position, m->member);
  hex(m->prev, s->hashSz);
  fprintf(Out, ":");
  if (m->hash)
    hex(m->hash, s->hashSz);
  fprintf(Out, ": ");
  if (m->verdict == AC_PASS)
    fwrite(m->msg, 1, m->len, Out);
  else
    fprintf(Out, "(no message: verdict %u)", m->verdict);
  fprintf(Out, "\n");
  fflush(Out);
}

static void
released(
  void *ctx
 ,unsigned int position
 ,unsigned int tick
){
  (void)ctx;
  (void)position;
  (void)tick;
}

/* a connection closed, the seat's count of them kept */
#define CLOSE(s, c) (close((c)->fd), (c)->fd = -1, ++(s)->closes)

/* a socket as a connection is kept: no wait to coalesce frames, its
 * unsent bytes bounded, and never blocking; 0 if it cannot be */
static int
tune(
  int fd
){
  int v;

  v = 1;
  if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &v, sizeof (v)))
    return (0);
#ifdef TCP_NOTSENT_LOWAT
  v = LOWAT_BYTES;
  if (setsockopt(fd, IPPROTO_TCP, TCP_NOTSENT_LOWAT, &v, sizeof (v)))
    return (0);
#endif
  return (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) >= 0);
}

/* a connection on socket fd, appended, its nonce fresh; 0 if this
 * seat's memory refused it */
static struct conn *
connNew(
  struct seat *s
 ,int fd
){
  struct conn *c;
  void *v;

  if (!(v = realloc(s->c, (s->nc + 1) * sizeof (*s->c))))
    return (0);
  s->c = v;
  c = s->c + s->nc;
  memset(c, 0, sizeof (*c));
  if (!(c->in = malloc(2 * (2 + s->dgramMax))))
    return (0);
  c->out = c->in + 2 + s->dgramMax;
  c->fd = fd;
  c->peer = s->n;
  c->born = s->us;
  arc4random_buf(c->nonce, NONCE);
  ++s->nc;
  return (c);
}

/* a frame on a connection: 1 taken, whole or its rest held to go when
 * the socket can; 0 not taken, the rest of an earlier one still held or
 * the socket not writable, its unsent bytes at their bound; -1 the
 * connection closed by it.  The system is asked first, since a write
 * may take past the bound where the bound says only when to poll */
static int
put(
  struct seat *s
 ,struct conn *c
 ,const unsigned char *b
 ,unsigned int l
){
  struct pollfd w;
  long f;
  long n;

  w.fd = c->fd;
  w.events = POLLOUT;
  if (c->outOff < c->outLen || poll(&w, 1, 0) != 1)
    return (0);
  PUT16(c->out, l);
  memcpy(c->out + 2, b, l);
  f = 2 + l;
  if ((n = write(c->fd, c->out, f)) == f)
    return (1);
  if (n > 0) {
    c->outOff = n;
    c->outLen = f;
    return (1);
  }
  if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
    return (0);
  CLOSE(s, c);
  return (-1);
}

/* a datagram to a seat: a frame on the connection bound to it, or the
 * network's loss, counted by why.  No connection refusal is a refusal
 * here, since the library would hold every seat's datagrams behind it:
 * the seat's sweeps re-send what was lost, as across any loss.  With no
 * connection bound to the seat and none this seat is dialing to it, it
 * dials, at most once a tick, each dial the next address dealt for it;
 * a connection accepted from a seat stops no dial until it binds, since
 * until then it is only a claim */
static int
send1(
  void *ctx
 ,unsigned char dest
 ,const unsigned char *dgram
 ,unsigned int len
){
  struct seat *s;
  struct conn *c;
  struct to *a;
  unsigned int i;
  int any;
  int fd;

  s = ctx;
  for (any = 0, c = 0, i = 0; i < s->nc; ++i)
    if (s->c[i].fd >= 0 && s->c[i].peer == dest) {
      if (s->c[i].dialed)
        any = 1;
      if (s->c[i].state == C_BOUND)
        c = s->c + i;
    }
  if (c) {
    switch (put(s, c, dgram, len)) {
    case 1:  break;
    case 0:  ++s->lostFull; break;
    default: ++s->lostOther; break;
    }
    return (1);
  }
  ++s->lostNone;
  if (any || (s->dialUs[dest] && s->us - s->dialUs[dest] < s->tickMs * 1000UL))
    return (1);
  s->dialUs[dest] = s->us ? s->us : 1;
  a = s->to + s->at[dest] + s->dialNext[dest]++ % (s->at[dest + 1] - s->at[dest]);
  ++s->dials;
  if ((fd = socket(a->sa.ss_family, SOCK_STREAM, IPPROTO_TCP)) < 0) {
    ++s->dialFails;
    return (1);
  }
  if (!tune(fd)
   || (connect(fd, (struct sockaddr *)&a->sa, a->len) && errno != EINPROGRESS)
   || !(c = connNew(s, fd))) {
    close(fd);
    ++s->dialFails;
    return (1);
  }
  c->peer = dest;
  c->dialed = 1;
  c->state = C_DIAL;
  return (1);
}

static void
random1(
  void *ctx
 ,unsigned char *b
 ,unsigned int l
){
  (void)ctx;
  arc4random_buf(b, l);
}

/* read exactly l bytes from the link; 0 on its end */
static int
readAll(
  int fd
 ,void *b
 ,unsigned int l
){
  long n;

  while (l) {
    if ((n = read(fd, b, l)) <= 0)
      return (0);
    b = (unsigned char *)b + n;
    l -= n;
  }
  return (1);
}

/* write exactly l bytes to the link, waiting where a link made
 * non-blocking will not take them yet; 0 on its end */
static int
writeAll(
  int fd
 ,const void *b
 ,unsigned int l
){
  struct pollfd pf;
  long n;

  while (l) {
    if ((n = write(fd, b, l)) < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
      pf.fd = fd;
      pf.events = POLLOUT;
      poll(&pf, 1, 1000);
      continue;
    }
    if (n <= 0)
      return (0);
    b = (const unsigned char *)b + n;
    l -= n;
  }
  return (1);
}

/* bytes of key material zeroed through a volatile pointer, a store the
 * compiler may not drop as dead */
static void
wipe(
  void *p
 ,unsigned long l
){
  volatile unsigned char *z;

  for (z = p; l--; )
    *z++ = 0;
}

/*
 * One seat, in its own process: the operator's parameters, this seat's
 * number and what it binds down the link, the identity up, the row
 * down, every list resolved here and every listening socket bound, the
 * go, then the loop: until the seat stops on its own, its chain's end
 * run over and the framer empty, then how it went up the link.  The
 * link is one descriptor each way: a pipe pair on this host, the
 * command's channel across the network.
 */
static int
seatMain(
  int up
 ,int down
){
  static const unsigned char hkLabel[] = HK_LABEL;
  struct seat s;
  struct acPar par;
  struct acCb cb;
  struct timespec now;
  struct timespec t0;                 /* the go, and the CPU this process had used by then */
  clock_t c0;
  clock_t c1;                         /* the CPU at a call's start: a
                                       * long call's own against its wall */
  unsigned long workMost;             /* the longest acWork and acInput calls, microseconds */
  unsigned long inputMost;
  unsigned long look;                 /* ms since the go of the next look at the counters */
  unsigned char deal[4 * DEAL_WORDS];
  unsigned char genesis[AC_HASH_MAX];
  unsigned char e[ENTRY_LEN(AC_HASH_MAX)];
  unsigned char hs[PROOF_TEXT];       /* a proof's text, or a hello */
  unsigned char mac[HK_LEN];
  char **list;                        /* [seat]: this seat's what it binds,
                                       * every other's where it is dialed */
  void *v;
  unsigned long us;
  long wait;
  long n;
  unsigned int messages;
  unsigned int nTo;
  unsigned int np;
  unsigned int i;
  unsigned int k;
  int moved;                          /* the pass's sockets made progress */
  unsigned char go;
  unsigned char d;
  unsigned char id;
  unsigned char rc;

  rc = 1;
  list = 0;
  memset(&s, 0, sizeof (s));
  s.up = up;
  /* down: the parameters and this seat's number */
  if (!readAll(down, deal, sizeof (deal)) || !readAll(down, &id, 1))
    goto done;
  memset(&par, 0, sizeof (par));
  par.sign = &Sign;
  par.kdf = &Kdf;
  par.n = GET32(deal);
  par.t = GET32(deal + 4);
  par.bwLimit = GET32(deal + 8);
  par.lossPct = GET32(deal + 12);
  par.delayMs = GET32(deal + 16);
  par.dgramMax = GET32(deal + 20);
  par.abandon = GET32(deal + 24);
  par.mlsS = GET32(deal + 28);
  messages = GET32(deal + 32);
  par.burstMs = GET32(deal + 36);
  par.self = id;
  s.self = id;
  s.n = par.n;
  s.messages = messages;
  cb.ctx = &s;
  cb.chain = chain;
  cb.message = message;
  cb.released = released;
  cb.send = send1;
  cb.random = random1;
  cb.propose = propose;
  cb.trace = 0;
  if (!(s.ac = acInit(&par, &cb))
   || !(list = calloc(s.n, sizeof (*list)))
   || !(s.at = calloc(s.n + 1, sizeof (*s.at)))
   || !(s.hk = calloc(s.n, HK_LEN))
   || !(s.dialUs = calloc(s.n, sizeof (*s.dialUs)))
   || !(s.dialNext = calloc(s.n, sizeof (*s.dialNext))))
    goto done;
  s.hashSz = acPar(s.ac)->hashSz;
  s.dgramMax = acPar(s.ac)->dgramMax;
  s.tickMs = acPar(s.ac)->tickMs;
  /* down: what this seat binds; up: the public key */
  if (!readAll(down, e, 2) || !(list[s.self] = malloc(GET16(e) + 1)) || !readAll(down, list[s.self], GET16(e)))
    goto done;
  list[s.self][GET16(e)] = 0;
  if (!writeAll(up, acPub(s.ac), s.hashSz))
    goto done;
  /* down: every other seat's entry and where this seat dials it, then
   * the genesis; the pair's handshake key derived from its secret on
   * the way to the library */
  for (k = 1; k < s.n; ++k) {
    unsigned int x;
    unsigned int l;

    if (!readAll(down, e, ENTRY_LEN(s.hashSz)) || (x = e[0]) >= s.n || x == s.self || list[x]
     || acDeal(s.ac, x, e + 1, e + 1 + AC_PSK))
      goto done;
    Kdf.hkdf(e + 1, AC_PSK, hkLabel, sizeof (hkLabel) - 1, s.hk + x * HK_LEN, HK_LEN);
    l = GET16(e + 1 + AC_PSK + s.hashSz);
    if (!(list[x] = malloc(l + 1)) || !readAll(down, list[x], l))
      goto done;
    list[x][l] = 0;
  }
  wipe(e, sizeof (e));
  if (!readAll(down, genesis, s.hashSz))
    goto done;
  /* every list, resolved here: this seat's own a listening socket at
   * each address; every other seat's the addresses it is dialed at,
   * every one a name resolves to; a family this host has no sockets for
   * passed over */
  for (nTo = 0, k = 0; k < s.n; ++k) {
    char *p0;
    char *p1;

    s.at[k] = nTo;
    for (p0 = list[k]; p0; p0 = p1) {
      struct addrinfo hint;
      struct addrinfo *ai;
      struct addrinfo *a;
      char *h;
      char *pt;

      if ((p1 = strchr(p0, ',')))
        *p1++ = 0;
      if (!(pt = strrchr(p0, ':')) || !pt[1]) {
        fprintf(stderr, "seat %u: %s: not host:port\n", s.self, p0);
        goto done;
      }
      *pt++ = 0;
      h = p0;
      if (*h == '[' && pt - 2 > h && pt[-2] == ']') {
        ++h;
        pt[-2] = 0;
      }
      memset(&hint, 0, sizeof (hint));
      hint.ai_family = AF_UNSPEC;
      hint.ai_socktype = SOCK_STREAM;
      hint.ai_protocol = IPPROTO_TCP;
      if (k == s.self)
        hint.ai_flags = AI_PASSIVE;
      if (getaddrinfo(*h ? h : 0, pt, &hint, &ai) || !ai) {
        fprintf(stderr, "seat %u: %s:%s: no address\n", s.self, h, pt);
        goto done;
      }
      for (a = ai; a; a = a->ai_next) {
        int fd;
        int one;

        if (a->ai_family != AF_INET && a->ai_family != AF_INET6)
          continue;
        if (k == s.self) {
          one = 1;
          if (!(v = realloc(s.lfd, (s.nl + 1) * sizeof (*s.lfd)))) {
            freeaddrinfo(ai);
            goto done;
          }
          s.lfd = v;
          if ((fd = socket(a->ai_family, a->ai_socktype, a->ai_protocol)) < 0
           && (errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT))
            continue;
          if (fd >= 0)
            s.lfd[s.nl++] = fd;         /* closed at the end, bound or not */
          if (fd < 0
           || setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof (one))
           || (a->ai_family == AF_INET6 && setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof (one)))
           || bind(fd, a->ai_addr, a->ai_addrlen)
           || listen(fd, s.n)
           || fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) < 0) {
            fprintf(stderr, "seat %u: %s:%s: %s\n", s.self, h, pt, strerror(errno));
            freeaddrinfo(ai);
            goto done;
          }
          continue;
        }
        if (!(v = realloc(s.to, (nTo + 1) * sizeof (*s.to)))) {
          freeaddrinfo(ai);
          goto done;
        }
        s.to = v;
        memcpy(&s.to[nTo].sa, a->ai_addr, a->ai_addrlen);
        s.to[nTo++].len = a->ai_addrlen;
      }
      freeaddrinfo(ai);
    }
  }
  s.at[s.n] = nTo;
  if (!s.nl) {
    fprintf(stderr, "seat %u: binds nothing this host has sockets for\n", s.self);
    goto done;
  }
  for (k = 0; k < s.n; ++k)
    if (k != s.self && s.at[k] == s.at[k + 1]) {
      fprintf(stderr, "seat %u: no address it has sockets for reaches seat %u\n", s.self, k);
      goto done;
    }
  /* up: ready; down: the go, once every seat listens */
  if (!writeAll(up, "r", 1) || !readAll(down, &go, 1))
    goto done;
  clock_gettime(CLOCK_MONOTONIC, &now);
  t0 = now;
  c0 = clock();
  workMost = inputMost = 0;
  look = LOOK_MS;
  if (acGo(s.ac, genesis, USEC(now)))
    goto done;
  if (!s.messages)
    acEnd(s.ac);                        /* nothing to propose: the end from the go */
  for (;;) {
    clock_gettime(CLOCK_MONOTONIC, &now);
    s.us = us = USEC(now);
    c1 = clock();
    wait = acWork(s.ac, us);
    clock_gettime(CLOCK_MONOTONIC, &now);
    if (USEC(now) - us > workMost)
      workMost = USEC(now) - us;
    /* the instrument, as it runs, as acUDP.c's */
    if (USEC(now) - us > LONG_MS * 1000UL) {
      fprintf(Out, "seat %u at %lu ms: acWork %lu ms, %lu ms of it CPU\n", s.self,
              (unsigned long)(now.tv_sec - t0.tv_sec) * 1000 + (now.tv_nsec - t0.tv_nsec) / 1000000,
              (USEC(now) - us) / 1000, (unsigned long)(clock() - c1) * 1000 / CLOCKS_PER_SEC);
      fflush(Out);
    }
    if ((unsigned long)(now.tv_sec - t0.tv_sec) * 1000 + (now.tv_nsec - t0.tv_nsec) / 1000000 >= look) {
      struct acCounters c;

      acCounters(s.ac, &c);
      fprintf(Out, "seat %u at %lu ms: folded %u, ticks %u, CPU %lu ms; held %u, not held %u, naming a record %u,"
              " recover legs started %u, own value broadcasts alone %u; DISCOVERed %u, kept now %u, parts placed %u; lost %u, passes past their tick %u;"
              " connections bound %u, closed %u\n",
              s.self, look, s.folded, acTicks(s.ac), (unsigned long)(clock() - c0) * 1000 / CLOCKS_PER_SEC,
              c.future, c.aheadFull, c.recorded, c.recoverStarts, c.repeated, c.recovered, c.keptNow, c.placed, c.loss, c.passLong,
              s.binds, s.closes);
      fflush(Out);
      look += LOOK_MS;
    }
    if (wait < 0)
      break;                            /* the end run over, or failed, and nothing left to send */
    /* a connection not bound by its deadline closed; the poll set: the
     * listening sockets, then every open connection, the closed ones let
     * go; a connection dialing or holding a frame's rest also waits to
     * write */
    for (i = 0; i < s.nc; ++i)
      if (s.c[i].fd >= 0 && s.c[i].state != C_BOUND && s.us - s.c[i].born > HS_TICKS * s.tickMs * 1000UL) {
        CLOSE(&s, s.c + i);
        ++s.late;
      }
    for (i = k = 0; i < s.nc; ++i)
      if (s.c[i].fd >= 0)
        s.c[k++] = s.c[i];
      else
        free(s.c[i].in);
    s.nc = k;
    if (!(v = realloc(s.pf, (s.nl + s.nc) * sizeof (*s.pf))))
      goto done;
    s.pf = v;
    for (i = 0; i < s.nl; ++i) {
      s.pf[i].fd = s.lfd[i];
      s.pf[i].events = POLLIN;
    }
    for (i = 0; i < s.nc; ++i) {
      s.pf[s.nl + i].fd = s.c[i].fd;
      s.pf[s.nl + i].events = POLLIN | (s.c[i].state == C_DIAL || s.c[i].outOff < s.c[i].outLen ? POLLOUT : 0);
    }
    np = s.nl + s.nc;
    /* nothing ready: the wait, the seat's next due, then its pass */
    if (poll(s.pf, np, 0) <= 0) {
      poll(s.pf, np, wait > 1000000L ? 1000 : (wait + 999) / 1000);
      continue;
    }
    /* a connection accepted gets this seat's hello at once; past N
     * unbound ones accepted, the oldest is closed for it.  An accept
     * that fails for want of descriptors leaves its socket readable, so
     * it is let out of the wait below, or the loop would spin on it */
    moved = 0;
    for (i = 0; i < s.nl; ++i) {
      int fd;

      if (!(s.pf[i].revents & POLLIN))
        continue;
      while ((fd = accept(s.lfd[i], 0, 0)) >= 0) {
        struct conn *c;
        struct conn *old;
        unsigned int un;

        if (!tune(fd)) {
          close(fd);
          continue;
        }
        for (old = 0, un = 0, k = 0; k < s.nc; ++k)
          if (s.c[k].fd >= 0 && !s.c[k].dialed && s.c[k].state != C_BOUND) {
            ++un;
            if (!old || s.c[k].born < old->born)
              old = s.c + k;
          }
        if (un >= s.n)
          CLOSE(&s, old);
        if (!(c = connNew(&s, fd))) {
          close(fd);
          continue;
        }
        ++s.accepts;
        moved = 1;
        hs[0] = s.self;
        memcpy(hs + 1, c->nonce, NONCE);
        if (put(&s, c, hs, HELLO_LEN) == 1)
          c->state = C_HELLO;
        else if (c->fd >= 0)
          CLOSE(&s, c);
      }
      if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR && errno != ECONNABORTED)
        s.pf[i].events = 0;
    }
    /* each connection in the poll set: a dial done, a frame's rest
     * written, and what came read, frame by frame */
    for (i = 0; i < np - s.nl; ++i) {
      struct conn *c;
      int re;

      c = s.c + i;
      if (!(re = s.pf[s.nl + i].revents) || c->fd < 0)
        continue;
      if (c->state == C_DIAL) {
        socklen_t el;
        int err;

        if (!(re & (POLLOUT | POLLERR | POLLHUP)))
          continue;
        moved = 1;
        el = sizeof (err);
        if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, &err, &el) || err) {
          CLOSE(&s, c);
          ++s.dialFails;
          continue;
        }
        hs[0] = s.self;
        memcpy(hs + 1, c->nonce, NONCE);
        if (put(&s, c, hs, HELLO_LEN) != 1) {
          if (c->fd >= 0)
            CLOSE(&s, c);
          continue;
        }
        c->state = C_HELLO;
      }
      if (c->outOff < c->outLen && re & POLLOUT) {
        moved = 1;
        if ((n = write(c->fd, c->out + c->outOff, c->outLen - c->outOff)) > 0) {
          if ((c->outOff += n) == c->outLen)
            c->outOff = c->outLen = 0;
        } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
          CLOSE(&s, c);
          continue;
        }
      }
      if (!(re & (POLLIN | POLLERR | POLLHUP)))
        continue;
      moved = 1;
      if ((n = read(c->fd, c->in + c->inLen, 2 + s.dgramMax - c->inLen)) <= 0) {
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
          continue;
        CLOSE(&s, c);
        continue;
      }
      c->inLen += n;
      while (c->fd >= 0 && c->inLen >= 2) {
        unsigned int fl;

        if (!(fl = GET16(c->in)) || fl > s.dgramMax) {
          CLOSE(&s, c);
          break;
        }
        if (c->inLen < 2 + fl)
          break;
        switch (c->state) {
        case C_HELLO:
          /* the other's hello: a seat but this one, the one dialed if
           * this seat dialed; then this seat's proof */
          if (fl != HELLO_LEN || c->in[2] >= s.n || c->in[2] == s.self || (c->dialed && c->in[2] != c->peer))
            goto refuse;
          c->peer = c->in[2];
          memcpy(c->peerNonce, c->in + 3, NONCE);
          hs[0] = s.self;
          hs[1] = c->peer;
          hs[2] = c->dialed;
          memcpy(hs + 3, c->nonce, NONCE);
          memcpy(hs + 3 + NONCE, c->peerNonce, NONCE);
          Kdf.hmac(s.hk + c->peer * HK_LEN, HK_LEN, hs, sizeof (hs), mac);
          if (put(&s, c, mac, HK_LEN) != 1) {
            if (c->fd >= 0)
              CLOSE(&s, c);
            break;
          }
          c->state = C_PROOF;
          break;
        case C_PROOF:
          /* the other's proof, over this connection's nonces and its
           * role, the one this seat's is not: bound.  Beside another
           * bound to the same seat, the newer is kept where the older
           * was bound more than a tick before, or both were dialed
           * alike; else the one the lower-numbered seat dialed */
          if (fl != HK_LEN)
            goto refuse;
          hs[0] = c->peer;
          hs[1] = s.self;
          hs[2] = !c->dialed;
          memcpy(hs + 3, c->peerNonce, NONCE);
          memcpy(hs + 3 + NONCE, c->nonce, NONCE);
          Kdf.hmac(s.hk + c->peer * HK_LEN, HK_LEN, hs, sizeof (hs), mac);
          for (d = 0, k = 0; k < HK_LEN; ++k)
            d |= mac[k] ^ c->in[2 + k];
          if (d)
            goto refuse;
          c->state = C_BOUND;
          c->bound = s.us;
          ++s.binds;
          for (k = 0; k < s.nc; ++k)
            if (s.c + k != c && s.c[k].fd >= 0 && s.c[k].peer == c->peer && s.c[k].state == C_BOUND) {
              ++s.dups;
              if (s.us - s.c[k].bound <= s.tickMs * 1000UL
               && s.c[k].dialed != c->dialed && c->dialed != (s.self < c->peer))
                CLOSE(&s, c);
              else
                CLOSE(&s, s.c + k);
              break;
            }
          break;
        default:
          clock_gettime(CLOCK_MONOTONIC, &now);
          us = USEC(now);
          s.us = us;
          c1 = clock();
          acInput(s.ac, c->in + 2, fl, us);
          c = s.c + i;                    /* the send callback may have grown the table */
          clock_gettime(CLOCK_MONOTONIC, &now);
          if (USEC(now) - us > inputMost)
            inputMost = USEC(now) - us;
          if (USEC(now) - us > LONG_MS * 1000UL) {
            fprintf(Out, "seat %u at %lu ms: acInput %lu ms, %lu ms of it CPU\n", s.self,
                    (unsigned long)(now.tv_sec - t0.tv_sec) * 1000 + (now.tv_nsec - t0.tv_nsec) / 1000000,
                    (USEC(now) - us) / 1000, (unsigned long)(clock() - c1) * 1000 / CLOCKS_PER_SEC);
            fflush(Out);
          }
          break;
        }
        if (c->fd < 0)
          break;
        memmove(c->in, c->in + 2 + fl, c->inLen - 2 - fl);
        c->inLen -= 2 + fl;
        continue;
refuse:
        ++s.refused;
        CLOSE(&s, c);
        break;
      }
    }
    /* ready but nothing moved: the wait, as above */
    if (!moved)
      poll(s.pf, np, wait > 1000000L ? 1000 : (wait + 999) / 1000);
  }
  /* what the connections still hold of a frame, a tick at most to go */
  if (!(v = realloc(s.pf, (s.nl + s.nc) * sizeof (*s.pf))))
    goto done;
  s.pf = v;
  for (us = s.us + s.tickMs * 1000UL;;) {
    for (np = 0, i = 0; i < s.nc; ++i)
      if (s.c[i].fd >= 0 && s.c[i].outOff < s.c[i].outLen) {
        s.pf[np].fd = s.c[i].fd;
        s.pf[np++].events = POLLOUT;
      }
    clock_gettime(CLOCK_MONOTONIC, &now);
    if (!np || USEC(now) >= us || poll(s.pf, np, (us - USEC(now) + 999) / 1000) <= 0)
      break;
    for (np = 0, i = 0; i < s.nc; ++i)
      if (s.c[i].fd >= 0 && s.c[i].outOff < s.c[i].outLen && s.pf[np++].revents) {
        if ((n = write(s.c[i].fd, s.c[i].out + s.c[i].outOff, s.c[i].outLen - s.c[i].outOff)) > 0) {
          if ((s.c[i].outOff += n) == s.c[i].outLen)
            s.c[i].outOff = s.c[i].outLen = 0;
        } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
          CLOSE(&s, s.c + i);
      }
  }
  /* this side closed for writing, what still comes read and let go for
   * a tick, so no close finds unread bytes and discards what it sent */
  for (i = 0; i < s.nc; ++i)
    if (s.c[i].fd >= 0)
      shutdown(s.c[i].fd, SHUT_WR);
  clock_gettime(CLOCK_MONOTONIC, &now);
  for (us = USEC(now) + s.tickMs * 1000UL;;) {
    for (np = 0, i = 0; i < s.nc; ++i)
      if (s.c[i].fd >= 0) {
        s.pf[np].fd = s.c[i].fd;
        s.pf[np++].events = POLLIN;
      }
    clock_gettime(CLOCK_MONOTONIC, &now);
    if (!np || USEC(now) >= us || poll(s.pf, np, (us - USEC(now) + 999) / 1000) <= 0)
      break;
    for (np = 0, i = 0; i < s.nc; ++i)
      if (s.c[i].fd >= 0 && s.pf[np++].revents
       && (n = read(s.c[i].fd, s.c[i].in, 2 + s.dgramMax)) <= 0
       && (!n || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)))
        CLOSE(&s, s.c + i);
  }
  rc = acFailed(s.ac) ? 1 : 0;
  {
    struct acCounters c;

    /* the instrument: the tick and how late it ran, the passes past it,
     * the patience the physics derived, the abandon declared and the
     * longest agreement against it, those abandoned without a subset,
     * the most positions live at once, the losses the framer met and
     * the parity it used, the rows held under names not minted and not
     * held, the records named and the machines started again from them,
     * the retention, the parts refused */
    acCounters(s.ac, &c);
    fprintf(Out, "seat %u counters: ticks %u of %u ms, late by at most %lu ms, %u passes past their tick, patience %u, abandon %u,"
           " the longest agreement %u sweeps, agreements abandoned without a subset %u, at most %u positions live;"
           " lost %u, decodes with no parity to spare %u, refused at the gate %u, at the tier %u;"
           " held %u, not held %u, naming a record %u, recover legs started %u, retained %u, let go %u;",
           s.self, acTicks(s.ac), acPar(s.ac)->tickMs, c.overUs / 1000, c.passLong,
           acPar(s.ac)->patience, acPar(s.ac)->abandon, c.subsetMost, c.noSubset, c.liveMost,
           c.loss, c.parityLast, c.igrGate, c.igrAuth,
           c.future, c.aheadFull, c.recorded, c.recoverStarts, c.retained, c.released);
    fprintf(Out, " own value broadcasts alone %u; DISCOVERed %u; kept past the window %u positions, %u members, %u passed, %u under, %u now,"
           " %u parts placed, at most %u ticks after their position left the window;"
           " parts refused %u; refused by this seat's memory %u; its own steps waiting on its memory %u;"
           " datagrams lost here for want of a connection %u, behind a full one %u, otherwise %u\n",
           c.repeated, c.recovered, c.kept, c.keptMembers, c.keptPassed, c.keptUnder, c.keptNow, c.placed, c.placedAfter,
           c.unitBad[AC_UNIT_LEN] + c.unitBad[AC_UNIT_SIG] + c.unitBad[AC_UNIT_SSS] + c.unitBad[AC_UNIT_RSEC],
           c.aheadMem + c.rowMem + c.qDrop + c.asmAlloc + c.unitBad[AC_UNIT_MEM], c.ownMem,
           s.lostNone, s.lostFull, s.lostOther);
    /* the connections: dialed, accepted, bound, refused, closed */
    fprintf(Out, "seat %u connections: dialed %u, of them never connected %u; accepted %u; bound %u, beside another %u;"
            " refused at the handshake %u, not bound in time %u; closed %u\n",
            s.self, s.dials, s.dialFails, s.accepts, s.binds, s.dups, s.refused, s.late, s.closes);
    /* the seat's own thread: its CPU against the wall since the go */
    clock_gettime(CLOCK_MONOTONIC, &now);
    fprintf(Out, "seat %u thread: %lu ms of CPU in %lu ms since the go; the longest acWork %lu ms, acInput %lu ms; rows held ahead replayed %u, at most %u in one call\n", s.self,
            (unsigned long)(clock() - c0) * 1000 / CLOCKS_PER_SEC,
            (unsigned long)(now.tv_sec - t0.tv_sec) * 1000 + (now.tv_nsec - t0.tv_nsec) / 1000000,
            workMost / 1000, inputMost / 1000, c.replayed, c.replayMost);
    /* the ingress's most from every seat at once, and the egress's
     * longest wait */
    fprintf(Out, "seat %u ingress: most %lu bit/s in a tick, declared %u bit/s a seat's send; egress: a message waited at most %lu ms, the tick %u ms\n",
            s.self, c.recvTickMost * 8000UL / acPar(s.ac)->tickMs, acPar(s.ac)->bwLimit,
            c.egrWaitUs / 1000, acPar(s.ac)->tickMs);
    fprintf(Out, "seat %u datagrams: %u sent carrying %u fragments, %lu bytes as the library counts them, as UDP datagrams, %lu ms at the declared bandwidth; launch checks the assembly held %u; positions a pass passed over %u; ingress evicted %u, %u of them by a full table\n",
            s.self, c.dgSent, c.dgFrg, c.dgBytes, c.dgBytes * 8000 / acPar(s.ac)->bwLimit, c.launchHeld, c.sweepYoung, c.igrEvict, c.igrEvictFull);
    /* what the framer took, by why, class and kind: messages, bytes */
    fprintf(Out, "seat %u said:", s.self);
    for (k = 0; k < 3 * 4 * 4; ++k)
      if (c.said[k >> 4][k >> 2 & 3][k & 3])
        fprintf(Out, " %s %s %s %u %lu %lu;", (k >> 4) == AC_SAID_SWEEP ? "sweep" : (k >> 4) == AC_SAID_REPLY ? "reply" : "first",
                (k >> 2 & 3) == AC_CLS_ACS ? "ACS" : (k >> 2 & 3) == AC_CLS_DIST ? "DIST" : (k >> 2 & 3) == AC_CLS_LEG ? "LEG" : "RCV",
                (k & 3) == AC_KIND_INITIAL ? "INITIAL" : (k & 3) == AC_KIND_ECHO ? "ECHO" : (k & 3) == AC_KIND_READY ? "READY" : "BESIDE",
                c.said[k >> 4][k >> 2 & 3][k & 3], c.saidBytes[k >> 4][k >> 2 & 3][k & 3], c.saidUs[k >> 4][k >> 2 & 3][k & 3] / 1000);
    fprintf(Out, " re-sends by their position's age in ticks: under 1 %u, 1-2 %u, 2-4 %u, 4 or more %u\n",
            c.sweepAge[0], c.sweepAge[1], c.sweepAge[2], c.sweepAge[3]);
    /* the links: message bytes each way and the most in one tick, as
     * bits a second at the tick, against the declared bandwidth */
    for (k = 0; k < s.n; ++k) {
      struct acSeatCounters sc;

      if (acSeatCounters(s.ac, k, &sc))
        continue;
      fprintf(Out, "seat %u link %u: sent %lu bytes, most %lu bit/s in a tick, re-sends to it %u (turns or re-sends %u), held %u, replies to it %u;"
              " received %lu bytes, most %lu bit/s in a tick, of what was held already %u;"
              " round trip least %lu ms, most %lu ms, mean %lu ms of %u; its values after n - t ones %u, at most %u sweeps, %lu ms;"
              " entered 0 %u\n",
              s.self, k, sc.sentBytes, sc.sentTickMost * 8000UL / acPar(s.ac)->tickMs, sc.swept, sc.sweptTurn, sc.sweptHeld, sc.replied,
              sc.recvBytes, sc.recvTickMost * 8000UL / acPar(s.ac)->tickMs, sc.resent,
              sc.rttLeast / 1000, sc.rttMost / 1000, sc.rtts ? sc.rttSum / sc.rtts / 1000 : 0, sc.rtts,
              sc.lates, sc.lateMost, sc.lateMostUs / 1000, sc.zeros);
    }
    fflush(Out);
  }
done:
  /* up: the end, and how it went */
  wipe(e, sizeof (e));
  writeAll(up, &rc, 1);
  acFree(s.ac);
  for (i = 0; i < s.nc; ++i) {
    if (s.c[i].fd >= 0)
      close(s.c[i].fd);
    free(s.c[i].in);
  }
  free(s.c);
  for (i = 0; i < s.nl; ++i)
    close(s.lfd[i]);
  free(s.lfd);
  free(s.pf);
  if (s.hk)
    wipe(s.hk, s.n * HK_LEN);
  free(s.hk);
  free(s.dialUs);
  free(s.dialNext);
  free(s.to);
  free(s.at);
  if (list)
    for (k = 0; k < s.n; ++k)
      free(list[k]);
  free(list);
  return (rc);
}

int
main(
  int argc
 ,char **argv
){
  struct acPar par;
  unsigned char *mesh;                /* the deal: a secret per ordered pair,
                                       * (i, k) at (i * n + k) * AC_PSK */
  char **bindL;                       /* [seat]: what it binds */
  char **reachL;                      /* [from * n + to]: where seat from sends to reach seat to */
  char *cfg;                          /* -o: the configuration's text, the lists pointing into it;
                                       * on this host, the lists themselves */
  char **execL;                       /* [seat]: the command that starts it, or 0 to fork it here */
  const char *cfgName;
  unsigned char genesis[AC_HASH_MAX];
  unsigned char deal[4 * DEAL_WORDS];
  unsigned char *pubs;
  int *up;
  int *down;
  pid_t *pid;
  unsigned int n;
  unsigned int t;
  unsigned int port;
  unsigned int messages;
  unsigned int i;
  unsigned int k;
  int opt;
  int rc;

  /* descriptors 0, 1 and 2 open, so no pipe made here is one of them */
  while ((opt = open("/dev/null", O_RDWR)) >= 0 && opt < 3)
    ;
  if (opt >= 3)
    close(opt);
  /* a link that ends is read as its end, never as a signal that ends
   * the process before it can say so */
  signal(SIGPIPE, SIG_IGN);
  memset(&par, 0, sizeof (par));
  par.sign = &Sign;
  par.kdf = &Kdf;
  par.bwLimit = 2500000;
  par.dgramMax = DGRAM_MAX;
  port = 42000;
  messages = 2;
  cfgName = 0;
  Out = stdout;
  while ((opt = getopt(argc, argv, "W:L:D:B:A:p:e:o:l")) != -1)
    switch (opt) {
    case 'W': par.bwLimit = atoi(optarg); break;
    case 'L': par.delayMs = atoi(optarg); break;
    case 'D': par.lossPct = atoi(optarg); break;
    case 'B': par.burstMs = atoi(optarg); break;
    case 'A': par.abandon = atoi(optarg); break;
    case 'p': port = atoi(optarg); break;
    case 'e': messages = atoi(optarg); break;
    case 'o': cfgName = optarg; break;
    case 'l':
      /* a seat the operator started: its link standard input and
       * output, everything comes down it */
      if (argc != 2)
        goto usage;
      Out = stderr;
      setvbuf(stderr, OutBuf, _IOFBF, sizeof (OutBuf));
      return (seatMain(1, 0));
    default:  goto usage;
    }
  setvbuf(stdout, OutBuf, _IOFBF, sizeof (OutBuf));
  if (argc - optind != 2)
    goto usage;
  n = atoi(argv[optind]);
  t = atoi(argv[optind + 1]);
  par.n = n;
  par.t = t;
  /* the bandwidth -W's, the loss -D's, the delay -L's, the burst -B's,
   * the datagram DGRAM_MAX's, the configuration at its defaults; the
   * rest derives here for the operator and again, the same, in every
   * seat.  The abandon is -A's, measured, never derived */
  if (!par.abandon) {
    fprintf(stderr, "-A is required: twice the longest agreement, in sweeps, of a rehearsal with one seat stopped\n");
    goto usage;
  }
  if (acDerive(&par)) {
    fprintf(stderr, "no seat from N=%u t=%u at an abandon of %u sweeps\n", n, t, par.abandon);
    return (1);
  }
  rc = 1;
  mesh = 0;
  bindL = reachL = execL = 0;
  cfg = 0;
  pubs = 0;
  up = down = 0;
  pid = 0;
  if (!(mesh = calloc((unsigned long)n * n, AC_PSK))
   || !(bindL = calloc(n, sizeof (*bindL)))
   || !(reachL = calloc((unsigned long)n * n, sizeof (*reachL)))
   || !(execL = calloc(n, sizeof (*execL)))
   || !(pubs = malloc(n * par.hashSz))
   || !(up = malloc(2 * n * sizeof (*up)))
   || !(pid = malloc(n * sizeof (*pid)))) {
    fprintf(stderr, "allocation failed\n");
    goto done;
  }
  down = up + n;
  for (i = 0; i < n; ++i) {
    pid[i] = 0;
    up[i] = down[i] = -1;
  }
  if (!cfgName) {
    /* on this host: seat i binds the loopback at the base port plus i,
     * where every other seat reaches it */
    if (!port || port + n > 65536) {
      fprintf(stderr, "-p %u: the ports of %u seats run past 65535\n", port, n);
      goto done;
    }
    if (!(cfg = malloc(n * sizeof ("127.0.0.1:65535"))))
      goto done;
    for (i = 0; i < n; ++i) {
      bindL[i] = cfg + i * sizeof ("127.0.0.1:65535");
      sprintf(bindL[i], "127.0.0.1:%u", port + i);
      for (k = 0; k < n; ++k)
        reachL[k * n + i] = bindL[i];
    }
  } else {
    FILE *f;
    char *line;
    char *nl;
    unsigned long len;
    unsigned int ln;
    void *v;

    /* the configuration: read whole, each list a string in place */
    if (!(f = fopen(cfgName, "r"))) {
      perror(cfgName);
      goto done;
    }
    /* a short read is the end, or an error the stream then says */
    for (len = 0; (v = realloc(cfg, len + 4096 + 1));) {
      cfg = v;
      len += k = fread(cfg + len, 1, 4096, f);
      if (k < 4096)
        break;
    }
    if (ferror(f)) {
      perror(cfgName);
      fclose(f);
      goto done;
    }
    fclose(f);
    if (!v) {
      fprintf(stderr, "allocation failed\n");
      goto done;
    }
    cfg[len] = 0;
    for (ln = 1, line = cfg; line; line = nl, ++ln) {
      char *tok[6];
      char *c;
      unsigned long sx;
      unsigned int nt;

      if ((nl = strchr(line, '\n')))
        *nl++ = 0;
      for (c = line; *c == ' ' || *c == '\t'; ++c)
        ;
      if (!strncmp(c, "exec", 4) && (c[4] == ' ' || c[4] == '\t')) {
        char *z;

        /* the command, the rest of the line, to the shell as it is */
        for (c += 4; *c == ' ' || *c == '\t'; ++c)
          ;
        if (*c < '0' || *c > '9' || (sx = strtoul(c, &c, 10)) >= n || (*c != ' ' && *c != '\t'))
          goto badLine;
        while (*c == ' ' || *c == '\t')
          ++c;
        for (z = c + strlen(c); z > c && (z[-1] == ' ' || z[-1] == '\t' || z[-1] == '\r'); )
          *--z = 0;
        if (!*c)
          goto badLine;
        execL[sx] = c;
        continue;
      }
      if ((c = strchr(line, '#')))
        *c = 0;
      for (nt = 0, c = line; nt < sizeof (tok) / sizeof (tok[0]);) {
        while (*c == ' ' || *c == '\t' || *c == '\r')
          *c++ = 0;
        if (!*c)
          break;
        tok[nt++] = c;
        while (*c && *c != ' ' && *c != '\t' && *c != '\r')
          ++c;
      }
      if (!nt)
        continue;
      if (nt < 3)
        goto badLine;
      sx = strtoul(tok[1], &c, 10);
      if (*c || *tok[1] < '0' || *tok[1] > '9' || sx >= n || strlen(tok[2]) > LIST_MAX)
        goto badLine;
      if (!strcmp(tok[0], "bind") && nt == 3)
        bindL[sx] = tok[2];
      else if (!strcmp(tok[0], "reach") && nt == 3) {
        for (k = 0; k < n; ++k)
          if (k != sx)
            reachL[k * n + sx] = tok[2];
      } else if (!strcmp(tok[0], "reach") && nt == 5 && !strcmp(tok[3], "from")) {
        char *fp;
        char *fn;
        unsigned long fx;

        for (fp = tok[4]; fp; fp = fn) {
          if ((fn = strchr(fp, ',')))
            *fn++ = 0;
          fx = strtoul(fp, &c, 10);
          if (*c || *fp < '0' || *fp > '9' || fx >= n || fx == sx)
            goto badLine;
          reachL[fx * n + sx] = tok[2];
        }
      } else
        goto badLine;
      continue;
badLine:
      fprintf(stderr, "%s: line %u: not bind S list, reach S list, reach S list from F,... or exec S command\n", cfgName, ln);
      goto done;
    }
    for (i = 0; i < n; ++i) {
      if (!bindL[i]) {
        fprintf(stderr, "%s: seat %u binds nothing\n", cfgName, i);
        goto done;
      }
      for (k = 0; k < n; ++k)
        if (k != i && !reachL[k * n + i]) {
          fprintf(stderr, "%s: seat %u does not reach seat %u\n", cfgName, k, i);
          goto done;
        }
    }
  }
  /* the parameters every seat is dealt: the same but self */
  PUT32(deal, par.n);
  PUT32(deal + 4, par.t);
  PUT32(deal + 8, par.bwLimit);
  PUT32(deal + 12, par.lossPct);
  PUT32(deal + 16, par.delayMs);
  PUT32(deal + 20, par.dgramMax);
  PUT32(deal + 24, par.abandon);
  PUT32(deal + 28, par.mlsS);
  PUT32(deal + 32, messages);
  PUT32(deal + 36, par.burstMs);
  /* every seat a process on two pipes: forked here, or the command its
   * exec line names run with the pipes its standard input and output --
   * ssh to the seat's host, say, which keeps the deal private and the
   * seat the one the operator started */
  for (i = 0; i < n; ++i) {
    int u[2];
    int d[2];

    if (pipe(u) || pipe(d)) {
      perror("pipe");
      goto done;
    }
    if ((pid[i] = fork()) < 0) {
      perror("fork");
      goto done;
    }
    if (!pid[i]) {
      /* the seat holds its own link alone */
      close(u[0]);
      close(d[1]);
      for (k = 0; k < i; ++k) {
        close(up[k]);
        close(down[k]);
      }
      if (!execL[i])
        exit(seatMain(u[1], d[0]));
      if (dup2(d[0], 0) < 0 || dup2(u[1], 1) < 0) {
        perror("dup2");
        _exit(127);
      }
      close(u[1]);
      close(d[0]);
      signal(SIGPIPE, SIG_DFL);
      execl("/bin/sh", "sh", "-c", execL[i], (char *)0);
      perror("/bin/sh");
      _exit(127);
    }
    close(u[1]);
    close(d[0]);
    up[i] = u[0];
    down[i] = d[1];
  }
  /* the deal: one secret per unordered pair, the genesis, made once the
   * seats are, so a seat forked here holds no row but its own */
  for (i = 0; i < n; ++i)
    for (k = i + 1; k < n; ++k) {
      arc4random_buf(mesh + (i * n + k) * AC_PSK, AC_PSK);
      memcpy(mesh + (k * n + i) * AC_PSK, mesh + (i * n + k) * AC_PSK, AC_PSK);
    }
  arc4random_buf(genesis, par.hashSz);
  /* down: the parameters, the seat's number and what it binds; up:
   * every key before any row goes down */
  for (i = 0; i < n; ++i) {
    unsigned char l[2];
    unsigned char id;

    id = i;
    PUT16(l, strlen(bindL[i]));
    if (!writeAll(down[i], deal, sizeof (deal)) || !writeAll(down[i], &id, 1)
     || !writeAll(down[i], l, 2) || !writeAll(down[i], bindL[i], strlen(bindL[i])))
      goto linkLost;
  }
  for (i = 0; i < n; ++i)
    if (!readAll(up[i], pubs + i * par.hashSz, par.hashSz)) {
      fprintf(stderr, "seat %u gave no key\n", i);
      goto done;
    }
  for (i = 0; i < n; ++i) {
    for (k = 0; k < n; ++k) {
      unsigned char e[ENTRY_LEN(AC_HASH_MAX)];
      const char *r;
      int bad;

      if (k == i)
        continue;
      r = reachL[i * n + k];
      e[0] = k;
      memcpy(e + 1, mesh + (i * n + k) * AC_PSK, AC_PSK);
      memcpy(e + 1 + AC_PSK, pubs + k * par.hashSz, par.hashSz);
      PUT16(e + 1 + AC_PSK + par.hashSz, strlen(r));
      bad = !writeAll(down[i], e, ENTRY_LEN(par.hashSz)) || !writeAll(down[i], r, strlen(r));
      wipe(e, sizeof (e));
      if (bad)
        goto linkLost;
    }
    if (!writeAll(down[i], genesis, par.hashSz))
      goto linkLost;
  }
  wipe(mesh, (unsigned long)n * n * AC_PSK);
  /* every socket bound before any seat sends */
  for (i = 0; i < n; ++i) {
    unsigned char r;

    if (!readAll(up[i], &r, 1) || r != 'r') {
      fprintf(stderr, "operator: seat %u failed before its go\n", i);
      goto done;
    }
  }
  for (i = 0; i < n; ++i)
    if (!writeAll(down[i], "g", 1))
      goto linkLost;
  /* the operator says nothing more: each seat calls the end once its
   * messages are agreed, and stops on its own once the chain has ended
   * and its end run is over, the same final hash at every seat.  How
   * each went comes up its link, which then closes; a seat whose link
   * ends first is gone, which the operator sees and the seats do not:
   * they carry on without it, as they would without a seat that is only
   * slow */
  rc = 0;
  for (i = 0; i < n; ++i) {
    unsigned char r;

    r = 0;
    if (!readAll(up[i], &r, 1) || r) {
      fprintf(stderr, "operator: seat %u %s\n", i, r ? "failed" : "left before its end");
      rc = 1;
    }
    if (pid[i] > 0) {
      pid_t w;
      int st;

      while ((w = waitpid(pid[i], &st, 0)) < 0 && errno == EINTR)
        ;
      if (w != pid[i] || !WIFEXITED(st) || WEXITSTATUS(st))
        rc = 1;
    }
  }
  goto done;
linkLost:
  fprintf(stderr, "operator: seat %u's link failed\n", i);
done:
  if (mesh)
    wipe(mesh, (unsigned long)n * n * AC_PSK);
  free(mesh);
  free(bindL);
  free(reachL);
  free(execL);
  free(cfg);
  free(pubs);
  if (down)                           /* set once every link is marked unopened */
    for (i = 0; i < n; ++i) {
      if (up[i] >= 0)
        close(up[i]);
      if (down[i] >= 0)
        close(down[i]);
    }
  free(up);
  free(pid);
  return (rc);

usage:
  fprintf(stderr, "usage: acTCP [-W bits_per_s] [-L delay_ms] [-D loss_pct] [-B burst_ms] -A abandon_sweeps [-p baseport] [-e messages] N t\n"
                  "       acTCP [-W bits_per_s] [-L delay_ms] [-D loss_pct] [-B burst_ms] -A abandon_sweeps [-e messages] -o config N t\n"
                  "       acTCP -l\n");
  return (1);
}
