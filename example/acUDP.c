/*
 * agreementChain - an operator and its seats
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
 * example/acUDP.c - an operator and N seats, each a process binding one
 * seat of the library (ac.h) over its own UDP sockets, and the two
 * reports as each seat gives them.
 *
 * The operator deals: one pairwise secret per unordered pair, the
 * network, and the chain's genesis.  Each seat mints its own signing
 * identity and publishes the public key alone, up its link to the
 * operator; the operator sends every seat its row -- the other seats'
 * secrets, keys and addresses -- down the link, then the go.  No secret
 * is on disk, on a command line, or on a network in the clear.  Each
 * seat proposes a few messages of its own, saying it has one at every
 * fold while any are left, giving it when asked and moving to the next
 * only once a fold's subset holds it, and once its last is agreed it
 * calls the end (acEnd), at whatever link that is at this seat: every
 * value it signs from then carries the end, and the chain ends at the
 * first link more than t members carry it into, the same link and the
 * same final hash at every seat.  Each seat then runs its end, carrying
 * a seat behind to the same end, and stops on its own; how it went goes
 * up the link, and the operator, which says nothing after the go, waits
 * for every seat's.  Its reports are lines on its standard output, or
 * its standard error where it was started by a command (-l, below), and
 * every thirty seconds and at its end lines of the counters an
 * application reads to see whether the physics it declared fits the
 * network and the hosts it has:
 *
 *   seat S chain P: previousChainHash:member=hash:...:nextChainHash[ the end]
 *   seat S message P member M: previousChainHash:hash: the message
 *   seat S at MS ms: folded P, ticks, CPU, the rows held ...
 *   seat S counters: the ticks, how late, the losses, the rows held ...
 *
 * One deal, every seat a process on a pipe pair, its link.  By default
 * the operator forks the seats on this host, each on a loopback port.
 * Across a network the network is the operator's configuration (-o):
 * with address translation everywhere, the address a seat listens on is
 * seldom the one another seat reaches it at, and two seats may reach a
 * third at different addresses from where each sits.  So the
 * configuration names what each seat binds and, for every pair, where
 * the one sends to reach the other, each a comma-separated list of
 * host:port, a host a name or an address, an IPv6 one in brackets, and
 * the command that starts each seat elsewhere, ssh to its host, say,
 * run with the pipe pair its standard input and output.  The command is
 * to make the link a secure channel, as ssh does: then the deal, every
 * pairwise secret among it, crosses no network in the clear, and the
 * seat at the other end is the one the operator started; the operator
 * reads the link as bytes and cannot tell.  A seat started so (-l)
 * reports on its standard error, which the command may keep where the
 * seat runs.  A seat with no command is forked on the operator's host.
 * The deal carries the lists as text, and each seat resolves them where
 * it runs, since a name may resolve differently there.  A seat binds
 * every address its list names and reads them all; it sends from one
 * unbound socket per address family to every address dealt for the seat
 * it sends to, every address a name resolves to among them, since it
 * cannot tell which reaches it, and the receiver takes a second copy as
 * the re-send it is; each copy is the declared bandwidth's again, so a
 * list names only the addresses that may reach its seat.  An address of
 * a family the host has no sockets for is passed over.  Which socket a
 * datagram arrives on, and from where, is nothing to a seat: the sender
 * is in the tag, proven by the message's authentication.  The
 * operator's parameters -- the membership, the bandwidth, the delay,
 * the messages -- go down the link first, so a seat is started with
 * nothing.
 *
 * The configuration, a line each, a # beginning a comment to the line's
 * end but in an exec line, whose rest is the shell's:
 *
 *   bind S host:port[,host:port...]
 *   reach S host:port[,host:port...] [from F[,F...]]
 *   exec S command
 *
 * bind is what seat S listens on, an empty host every interface.  reach
 * is where the other seats send to reach S: every other seat, or the
 * ones the from list names.  exec is the command that starts seat S,
 * the rest of the line to the shell; it runs ./acUDP -l at the seat's end.
 * A later line takes the place of an earlier one for what it names.
 * Seats are numbered from 0 to N - 1.  Every seat binds, and every seat
 * reaches every other, or the operator refuses the configuration.
 *
 * Four seats on one host, each reached its own way, seat 3 started
 * through the shell and the rest forked here, ./acUDP -o four.cfg -A 100
 * 4 1.  It shows the format, every kind of line and form of address; it
 * shows no network, every address being the host's own:
 *
 *   bind 0 127.0.0.1:43600
 *   bind 1 [::1]:43601
 *   bind 2 :43602
 *   bind 3 127.0.0.1:43603,[::1]:43613
 *   reach 0 127.0.0.1:43600
 *   reach 1 [::1]:43601
 *   reach 2 localhost:43602
 *   reach 2 127.0.0.1:43602 from 0,1
 *   reach 3 [::1]:43613 from 0
 *   reach 3 127.0.0.1:43603,[::1]:43613 from 1,2
 *   exec 3 ./acUDP -l 2> seat3.out
 *
 * The seat's loop is what any application's would be: sockets, a poll,
 * the clock; what arrives goes to acInput, the seat's pass is acWork,
 * and the datagrams the seat hands its send callback go to the
 * addresses the seat number names.
 *
 * Usage:
 *   ./acUDP [-W bits_per_s] [-L delay_ms] [-D loss_pct] [-B burst_ms] -A abandon_sweeps [-p baseport] [-e messages] N t
 *   ./acUDP [-W bits_per_s] [-L delay_ms] [-D loss_pct] [-B burst_ms] -A abandon_sweeps [-e messages] -o config N t
 *   ./acUDP -l
 *
 * -A is the abandon every seat is dealt, in sweeps, required: how long
 * the deployment holds an instance's memory before it stops, past which
 * a seat behind is carried by recovery.  Nothing declared says how long
 * an agreement with a member gone runs under the deployment's load, so
 * its floor is measured: rehearse with one seat stopped and declare at
 * least twice the longest agreement the seats' counters show; at t > 0 one shorter than
 * the least such agreement can be, 1 + 7 patiences, makes no seat.  -L
 * is the one-way delay every seat is dealt, in milliseconds (default
 * 0): the tick is one feedback cycle only with the slowest answer
 * declared, and a host answers at the end of its pass, so it is the
 * longest path's delay or the slowest honest host's pass, whichever is
 * longer -- seconds where a slow host is among the seats, on a LAN as
 * on a WAN.  -D is the steady loss every seat is dealt, in percent
 * under 100 (default 0): the parity is sized for it and the patience
 * waits out the retries it leaves.  -B is the longest burst of loss
 * every seat is dealt, in milliseconds (default 0): every sweep in it a
 * retry, so the patience waits it out.  -e is the messages each seat
 * proposes (default 2).  The harness (test/ac.c) declares -L and -D as
 * the example does and also makes the delay and the loss, shaped into
 * bursts where there are any; its -B is their mean, and it declares
 * twice that as the longest; its -e is the end's step, and its -n the
 * positions before the end.
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
/* the datagram every seat is dealt: IPv6's least MTU, 1280 bytes, less
 * its 40-byte header and UDP's 8.  Every IPv6 link carries it whole and
 * no IPv6 router fragments, and since links and tunnels are built to
 * carry IPv6, nearly every IPv4 path carries it too; DNS moved its
 * default to it for the same reasons.  IPv4 itself promises a path no
 * more than 68 bytes and a host no more than 576, so on a path that
 * cannot carry it a datagram is fragmented or dropped, and a fragment
 * lost loses its datagram */
#define DGRAM_MAX 1232

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

/* an address a datagram to a seat goes to, and the socket it leaves by */
struct to {
  struct sockaddr_storage sa;
  socklen_t           len;
  int                 fd;
};

/* one seat: the library's seat and what this process owns around it */
struct seat {
  struct ac          *ac;
  struct to          *to;             /* every address dealt: seat k's at
                                       * to[at[k]] .. to[at[k + 1] - 1] */
  unsigned int       *at;             /* [seat + 1] */
  struct pollfd      *pf;             /* the link down, the IPv4 and IPv6
                                       * sending sockets, then each bound one */
  unsigned int        nf;             /* pf's count */
  unsigned int        self;
  unsigned int        n;
  unsigned int        hashSz;
  unsigned int        messages;       /* messages left to propose */
  unsigned int        sent;           /* messages agreed */
  unsigned int        folded;         /* chain reports */
  unsigned int        lostBuf;        /* sends the kernel refused for want of buffer: lost */
  unsigned int        lostDown;       /* for want of carrier, route or host: lost */
  unsigned int        lostOther;      /* for any other reason: lost */
  int                 up;             /* the link up: ready, then how the seat ended */
  int                 blocked;        /* the sending sockets that would not take a datagram:
                                       * 1 the IPv4 one, 2 the IPv6 one */
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

/* a datagram to a seat: every address dealt for it, from the sending
 * socket of each one's family.  A copy the socket will not take now is
 * not taken, and when no copy was the loop waits for the socket; every
 * other refusal -- no buffer, no carrier, no route, the host down -- is
 * the network's loss, counted by its kind: a seat cannot tell its own
 * link from one further on, a switch losing power from a cable pulled
 * between two, so it treats them alike, and its sweeps re-send what was
 * lost once the network carries again, as they do across a break
 * downstream.  An interface without carrier can answer no buffer for as
 * long as it is down, which held as back pressure would stall the seat
 * on one datagram and spin its loop */
static int
send1(
  void *ctx
 ,unsigned char dest
 ,const unsigned char *dgram
 ,unsigned int len
){
  struct seat *s;
  struct to *a;
  unsigned int held;
  int took;

  s = ctx;
  for (held = took = 0, a = s->to + s->at[dest]; a < s->to + s->at[dest + 1]; ++a) {
    if (sendto(a->fd, dgram, len, 0, (struct sockaddr *)&a->sa, a->len) >= 0) {
      took = 1;
      continue;
    }
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      s->blocked |= a->fd == s->pf[2].fd ? 2 : 1;
      ++held;
      continue;
    }
    took = 1;
    if (errno == ENOBUFS)
      ++s->lostBuf;
    else if (errno == ENETDOWN || errno == ENETUNREACH || errno == EHOSTDOWN || errno == EHOSTUNREACH
          || errno == EADDRNOTAVAIL)
      ++s->lostDown;
    else
      ++s->lostOther;
  }
  if (took)
    s->lostBuf += held;               /* a copy pushed back beside one taken:
                                       * the datagram is not due again */
  return (took);
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
 * down, every list resolved here and every address bound, the go, then
 * the loop: until the seat stops on its own, its chain's end run over
 * and the framer empty, then how it went up the link.  The link is one
 * descriptor each way: a pipe pair on this host, the command's channel
 * across the network.
 */
static int
seatMain(
  int up
 ,int down
){
  struct seat s;
  struct acPar par;
  struct acCb cb;
  struct timespec now;
  struct timespec t0;                 /* the go, and the CPU this process had used by then */
  clock_t c0;
  clock_t c1;                         /* the CPU at a call's start: a
                                       * long call's own against its wall */
  unsigned long workMost;              /* the longest acWork and acInput calls, microseconds: */
  unsigned long inputMost;             /* no socket is read inside one */
  unsigned long look;                 /* ms since the go of the next look at the counters */
  unsigned char deal[4 * DEAL_WORDS];
  unsigned char genesis[AC_HASH_MAX];
  unsigned char e[ENTRY_LEN(AC_HASH_MAX)];
  unsigned char *ibuf;
  char **list;                        /* [seat]: this seat's what it binds,
                                       * every other's where it is reached */
  unsigned long us;
  long wait;
  long n;
  unsigned int messages;
  unsigned int nTo;
  unsigned int k;
  unsigned char go;
  unsigned char id;
  unsigned char rc;

  rc = 1;
  ibuf = 0;
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
   || !(s.pf = malloc(3 * sizeof (*s.pf))))
    goto done;
  s.nf = 3;
  s.pf[0].fd = s.pf[1].fd = s.pf[2].fd = -1;
  if (!(ibuf = malloc(acPar(s.ac)->dgramMax + 1)))
    goto done;
  s.hashSz = acPar(s.ac)->hashSz;
  /* down: what this seat binds; up: the public key */
  if (!readAll(down, e, 2) || !(list[s.self] = malloc(GET16(e) + 1)) || !readAll(down, list[s.self], GET16(e)))
    goto done;
  list[s.self][GET16(e)] = 0;
  if (!writeAll(up, acPub(s.ac), s.hashSz))
    goto done;
  /* down: every other seat's entry and where this seat reaches it, then
   * the genesis */
  for (k = 1; k < s.n; ++k) {
    unsigned int x;
    unsigned int l;

    if (!readAll(down, e, ENTRY_LEN(s.hashSz)) || (x = e[0]) >= s.n || x == s.self || list[x]
     || acDeal(s.ac, x, e + 1, e + 1 + AC_PSK))
      goto done;
    l = GET16(e + 1 + AC_PSK + s.hashSz);
    if (!(list[x] = malloc(l + 1)) || !readAll(down, list[x], l))
      goto done;
    list[x][l] = 0;
  }
  if (!readAll(down, genesis, s.hashSz))
    goto done;
  /* every list, resolved here: this seat's own bound, each address a
   * socket the loop reads; every other seat's the addresses a datagram
   * to it goes to, every one a name resolves to, from this seat's one
   * sending socket of that address's family; a family this host has no
   * sockets for passed over */
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
      void *v;

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
      hint.ai_socktype = SOCK_DGRAM;
      hint.ai_protocol = IPPROTO_UDP;
      if (k == s.self)
        hint.ai_flags = AI_PASSIVE;
      if (getaddrinfo(*h ? h : 0, pt, &hint, &ai) || !ai) {
        fprintf(stderr, "seat %u: %s:%s: no address\n", s.self, h, pt);
        goto done;
      }
      for (a = ai; a; a = a->ai_next) {
        unsigned int fi;
        int fd;
        int one;

        if (a->ai_family != AF_INET && a->ai_family != AF_INET6)
          continue;
        if (k == s.self) {
          one = 1;
          if (!(v = realloc(s.pf, (s.nf + 1) * sizeof (*s.pf)))) {
            freeaddrinfo(ai);
            goto done;
          }
          s.pf = v;
          if ((fd = socket(a->ai_family, a->ai_socktype, a->ai_protocol)) < 0
           && (errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT))
            continue;
          if (fd >= 0)
            s.pf[s.nf++].fd = fd;       /* closed at the end, bound or not */
          if (fd < 0
           || (a->ai_family == AF_INET6 && setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof (one)))
           || bind(fd, a->ai_addr, a->ai_addrlen)
           || fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) < 0) {
            fprintf(stderr, "seat %u: %s:%s: %s\n", s.self, h, pt, strerror(errno));
            freeaddrinfo(ai);
            goto done;
          }
          continue;
        }
        /* the sending socket of the family, made at its first address */
        fi = a->ai_family == AF_INET6 ? 2 : 1;
        if (s.pf[fi].fd < 0) {
          if ((s.pf[fi].fd = socket(a->ai_family, SOCK_DGRAM, IPPROTO_UDP)) < 0
           && (errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT))
            continue;
          if (s.pf[fi].fd < 0
           || fcntl(s.pf[fi].fd, F_SETFL, fcntl(s.pf[fi].fd, F_GETFL) | O_NONBLOCK) < 0) {
            freeaddrinfo(ai);
            goto done;
          }
        }
        if (!(v = realloc(s.to, (nTo + 1) * sizeof (*s.to)))) {
          freeaddrinfo(ai);
          goto done;
        }
        s.to = v;
        memcpy(&s.to[nTo].sa, a->ai_addr, a->ai_addrlen);
        s.to[nTo].len = a->ai_addrlen;
        s.to[nTo++].fd = s.pf[fi].fd;
      }
      freeaddrinfo(ai);
    }
  }
  s.at[s.n] = nTo;
  wipe(e, sizeof (e));
  if (s.nf == 3) {
    fprintf(stderr, "seat %u: binds nothing this host has sockets for\n", s.self);
    goto done;
  }
  for (k = 0; k < s.n; ++k)
    if (k != s.self && s.at[k] == s.at[k + 1]) {
      fprintf(stderr, "seat %u: no address it has sockets for reaches seat %u\n", s.self, k);
      goto done;
    }
  /* up: ready; down: the go, once every socket is bound */
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
    int got;

    clock_gettime(CLOCK_MONOTONIC, &now);
    us = USEC(now);
    s.blocked = 0;
    c1 = clock();
    wait = acWork(s.ac, us);
    clock_gettime(CLOCK_MONOTONIC, &now);
    if (USEC(now) - us > workMost)
      workMost = USEC(now) - us;
    /* the instrument, as it runs: a call long enough to fill a socket's
     * default buffer at the declared ingress, its CPU against its wall,
     * a stop of the process being all wall; and every LOOK_MS a look at
     * the counters, so what moved is laid against when */
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
              " recover legs started %u, own value broadcasts alone %u; DISCOVERed %u, kept now %u, parts placed %u; lost %u, passes past their tick %u\n",
              s.self, look, s.folded, acTicks(s.ac), (unsigned long)(clock() - c0) * 1000 / CLOCKS_PER_SEC,
              c.future, c.aheadFull, c.recorded, c.recoverStarts, c.repeated, c.recovered, c.keptNow, c.placed, c.loss, c.passLong);
      fflush(Out);
      look += LOOK_MS;
    }
    if (wait < 0)
      break;                            /* the end run over, or failed, and nothing left to send */
    for (got = 0, k = 3; k < s.nf; ++k)
      if ((n = recvfrom(s.pf[k].fd, ibuf, acPar(s.ac)->dgramMax + 1, 0, 0, 0)) >= 0) {
        clock_gettime(CLOCK_MONOTONIC, &now);
        us = USEC(now);
        c1 = clock();
        acInput(s.ac, ibuf, n, us);
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (USEC(now) - us > inputMost)
          inputMost = USEC(now) - us;
        if (USEC(now) - us > LONG_MS * 1000UL) {
          fprintf(Out, "seat %u at %lu ms: acInput %lu ms, %lu ms of it CPU\n", s.self,
                  (unsigned long)(now.tv_sec - t0.tv_sec) * 1000 + (now.tv_nsec - t0.tv_nsec) / 1000000,
                  (USEC(now) - us) / 1000, (unsigned long)(clock() - c1) * 1000 / CLOCKS_PER_SEC);
          fflush(Out);
        }
        got = 1;
      }
    if (got)
      continue;
    /* the wait: the seat's next due, or, a sending socket having
     * refused a datagram, until it is writable, no longer than a tick */
    s.pf[0].fd = -1;                    /* poll ignores a negative one */
    s.pf[0].events = 0;
    s.pf[1].events = s.blocked & 1 ? POLLOUT : 0;
    s.pf[2].events = s.blocked & 2 ? POLLOUT : 0;
    for (k = 3; k < s.nf; ++k)
      s.pf[k].events = POLLIN;
    poll(s.pf, s.nf, s.blocked ? acPar(s.ac)->tickMs : wait > 1000000L ? 1000 : (wait + 999) / 1000);
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
           " lost %u, decodes with no parity to spare %u, refused at the gate %u, by a message's HMAC %u, held already and refused unread %u, HMACs run %u;"
           " held %u, not held %u, naming a record %u, recover legs started %u, retained %u, let go %u;",
           s.self, acTicks(s.ac), acPar(s.ac)->tickMs, c.overUs / 1000, c.passLong,
           acPar(s.ac)->patience, acPar(s.ac)->abandon, c.subsetMost, c.noSubset, c.liveMost,
           c.loss, c.parityLast, c.igrGate, c.igrAuth, c.copy, c.authRun,
           c.future, c.aheadFull, c.recorded, c.recoverStarts, c.retained, c.released);
    fprintf(Out, " own value broadcasts alone %u; descriptions alone %u; parts with no machine %u; DISCOVERed %u; kept past the window %u positions, %u members, %u passed, %u under, %u now,"
           " %u parts placed, at most %u ticks after their position left the window;"
           " parts refused %u; refused by this seat's memory %u; its own steps waiting on its memory %u;"
           " sends lost here for want of buffer %u, of carrier, route or host %u, otherwise %u\n",
           c.repeated, c.descAlone, c.latePast, c.recovered, c.kept, c.keptMembers, c.keptPassed, c.keptUnder, c.keptNow, c.placed, c.placedAfter,
           c.unitBad[AC_UNIT_LEN] + c.unitBad[AC_UNIT_SIG] + c.unitBad[AC_UNIT_SSS] + c.unitBad[AC_UNIT_RSEC],
           c.aheadMem + c.rowMem + c.qDrop + c.asmAlloc + c.unitBad[AC_UNIT_MEM], c.ownMem,
           s.lostBuf, s.lostDown, s.lostOther);
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
    fprintf(Out, "seat %u datagrams: %u sent carrying %u fragments, %lu bytes with IP and UDP headers, %lu ms at the declared bandwidth; launch checks the assembly held %u; positions a pass passed over %u; ingress evicted %u, %u of them by a full table\n",
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
  if (s.pf)
    for (k = 1; k < s.nf; ++k)
      if (s.pf[k].fd >= 0)
        close(s.pf[k].fd);
  free(s.pf);
  free(s.to);
  free(s.at);
  if (list)
    for (k = 0; k < s.n; ++k)
      free(list[k]);
  free(list);
  free(ibuf);
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
    fprintf(stderr, "-A is required: at least twice the longest agreement, in sweeps, of a rehearsal with one seat stopped\n");
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
  fprintf(stderr, "usage: acUDP [-W bits_per_s] [-L delay_ms] [-D loss_pct] [-B burst_ms] -A abandon_sweeps [-p baseport] [-e messages] N t\n"
                  "       acUDP [-W bits_per_s] [-L delay_ms] [-D loss_pct] [-B burst_ms] -A abandon_sweeps [-e messages] -o config N t\n"
                  "       acUDP -l\n");
  return (1);
}
