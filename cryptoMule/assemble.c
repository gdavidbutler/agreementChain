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
 * cryptoMule assemble - a seat reconstructs the blob at threshold.
 *
 * Threshold is T shares AND T shards IN HAND under ONE apex, gathered as two
 * PARTS.  Every part on the wire carries as its TAG the file name of the
 * apex message it is of (the shard and sign messages' `tag` field; the
 * message the reader already holds by path, compared, never opened), so a
 * part is known to be of an apex message before it is verified, and there
 * is no first choice of apex to make: parts are POOLED BY APEX (the value
 * that message carries, which the sign message's header must recompute
 * to), each pool is
 * verified under its own signed header and roots, and each pool that reaches
 * T is searched on its own.  This seat need NOT have received its own
 * distribution: the unit it holds from receive, when it holds one, joins
 * the pool of the apex receive matched it to, counted when present, never
 * depended on.  Each exchange fragment -- the sender's three directed
 * messages, <s>_to_<p>_apex.txt (the apex alone), _shard.txt (the tag and
 * the clear shard), _sign.txt (the tag, the initiator's signed header, the
 * re-masked value, both proofs) -- is validated independently, exactly as
 * receive validates a distribution: FIRST the pairwise wire hmac of each
 * message (static mac PSK; a failure on the apex or sign message means the
 * wire was tampered and the fragment is skipped, nothing of it parsed; on
 * the shard message it costs the shard part alone), then the sign message's
 * tag must name the apex message, its dispersal label must be this seat's
 * book's (live) or the dispersal asked for (resend), as receive requires of a
 * distribution, its header must recompute to the apex under book.txt's
 * current pub and the offset its signature yields (apex = H(current pub ||
 * signing offset || orig_hash || rsecmk_root || sssmk_root), the pub the
 * book names being a verifier's one candidate signer, the offset read from
 * the signature's structure); -- assembling the LIVE dispersal -- the
 * signing-offset floor is read exactly as receive reads it, at that offset
 * and before the signature (offset below the high-water or at it under
 * another apex: refused; the floor is read, never written; an older
 * dispersal read in resend mode is below the high-water by definition, and
 * there the chain walk is the gate); then the initiator's MLS signature must
 * recover that same current pub at a payload signing offset (not
 * CM_SLOT_ROT, the rotation's; this is the path a seat that never ran
 * receive takes, so it gates the signing offset itself).  The exchange wire is
 * the distribution wire -- the same three messages under the same field
 * names, the sender id and the share's mask the only differences -- and
 * this is the same reader.  Then each PART on its own, into its apex's
 * pool: the share part is the [seed][key-share] unit unmasked with the
 * pairwise PSK(self,sender) at the payload's one step (domain CM_DOM_EXCH),
 * the code points DERIVED from its seed, the unit authenticated (sssMk, under
 * the derived points) against the signed sssmk_root; the shard part is the
 * clear shard, tagged with this apex message, authenticated (rsecMk) against the
 * signed rsecmk_root.  A fragment whose sign message omits the share (its
 * holder's copy rotted, exchange forwards what it validated) contributes
 * the shard; one whose sign message omits rsecmk_proof announces no shard,
 * and one that carries it is required to have its shard message, hmac-whole,
 * tagged with this apex message, within the cap and under the root, else contributes
 * the share alone: what to expect of a fragment is learned from the sign
 * message validated, never from a path.  The held unit takes the same path
 * from its receive record: its gate is receive's verdicts (there is no wire
 * hmac inside priv/), the share on sssmk_ok and the shard on rsecmk_ok, and
 * its share is already clear.  r/t/k/m derive from config; shard_len is the
 * shard message's own length, learned per pool from the first shard that
 * verifies under its signed root -- never from a field a sender alone vouches
 * for.
 *
 * Parts are gathered lazily from T up to R, and each pool's reconstruction
 * is a SEARCH with its signed orig_hash as the oracle (most byzantine
 * results are environmental: a dealer without ECC memory commits a flipped
 * share or shard now and then, and one bad committed part must not cost the
 * message when T good ones are in hand):
 *
 *   T-subsets of the held shares, in whack-a-mole order (the first T, then
 *   every single swap of one of those for one of the rest, then pairs, ...):
 *     T key-shares -> sss -> K, a CANDIDATE first when one more held share
 *     agrees with the polynomial (two distinct polynomials agree on at most
 *     T-1 points, so a corrupted share agrees with nothing), or when exactly
 *     T are held; agreement ORDERS, it does not decide: once every part is
 *     gathered a relaxed pass tries every subset agreement rejected (a good
 *     pair whose only outside share is the bad one), the hash deciding; a K
 *     already tried is skipped.
 *     keystream(K, orig_hash) hoisted once, then T-subsets of the held
 *     shards in the same order:
 *       T shards -> rsec -> ciphertext -> XOR keystream -> huffman-expand
 *       -> blob; PASS iff H(blob) == orig_hash.
 *
 * The honest dealer's first T of each part reproduce the hash at the first
 * try, one bad committed part costs a few tries, and the full C(R,T) is
 * never incurred by an honest dealer; CM_SEARCH_TRIES (shares and shards
 * together, per pool) bounds a dealer that salts most of its leaves -- the K
 * candidate list grows to that budget, since every candidate cost a try --
 * and a probe past CM_BLOB_MAX is a wrong try's garbage stream, never an
 * allocation.  The hash has no power over nothing: when the signed hash is
 * the empty message's, a try reads it only when its whole plaintext is
 * zero -- the two-byte stream of nothing and the zero padding, both under
 * the dealer's keystream -- since hufDecode reports a broken stream and the
 * stream of nothing alike.  Shares go first because interpolating a 32-byte
 * share is free and agreement settles K before any shard is decoded: the
 * search is nested, never the product of two enumerations.
 *
 * The gather stops at the first pool that PASSes (lazy: the honest path
 * reads T fragments); every pool seen is reported with its own outcome:
 *   PASS  -- a reconstruction matches its signed hash (the original length
 *            is self-described by the huffman encoding, so it is not carried)
 *   FRAUD -- threshold reached on both parts and every subset tried, none
 *            reproducing it: the dealer signed a hash its committed
 *            encodings cannot produce, a consistent codeword of the wrong
 *            bytes included
 *   FAIL  -- under threshold on either part, or the search unfinished at the
 *            try budget (search: budget): a report says what it knows
 * and the record's `result:` is the pool that PASSed, else the first pool
 * seen, else FAIL with no pool at all (no initiator-signed fragment).
 * Which of two apexes is the one is not decided here: each is reported.
 *
 * Dealer consistency after PASS (a dealer is only
 * byzantine if receivers can detect it, and the parts in hand ARE enough
 * information to do so).  RE-ENCODE BOTH CODES and compare against the
 * SIGNED commitment -- the RS code from the CANONICAL ciphertext, not the
 * winning shards: the hash saw the message and nothing of the stream's
 * unused bits or the padding, so a flipped byte there rides through a PASS
 * and would make the winning subset the yardstick for the rest.  The
 * canonical ciphertext is derivable: huffman is deterministic, so the
 * delivered blob re-encodes to the dealer's stream, zero-padded and under
 * the winning K's keystream:
 *   - RS: re-encode all R shards from it, rebuild the rsecMk tree, compare
 *     rsecmk_root, and name every held shard that is not its canonical one;
 *   - SSS: re-evaluate the share polynomial at ALL R derived points, rebuild
 *     the sssMk tree, compare sssmk_root.
 * Root equality is a property of the signed commitment, so every honest
 * receiver that PASSes reads the same `commitment:` -- and every held part
 * that disagrees with the re-encode is named by leaf (bad_shares, bad_shards):
 * the mule reports the count; what it means is the host's.  The rsecMk root
 * binds the shard length, so every shard that
 * verifies under the pool's root is the one committed length (a codeword's
 * rows are one length): shard_len is the first verified shard's, and a leaf
 * committed at another length never verifies at its receiver.
 *
 * Writes priv/<p>_assemble.txt (verdict) and priv/<p>_recovered.bin (the blob),
 * seat p = index i + 1; both are removed first, so a run that ends without
 * a verdict leaves none.
 *
 * ONE GATHER, TWO KEY SOURCES.  With no trailing arguments this assembles the LIVE
 * dispersal at the current keystate.  Given <dispersal> <anchorLog> it assembles an
 * OLDER one, deriving that dispersal's mask key by recomputing FORWARD from
 * the retention floor (the same walk ./exchange runs when it resends, and
 * ./catchup runs on a stale chain).  THAT IS THE ONLY DIFFERENCE.  The gather is
 * the same wire/exch/ path and the validation is the same validation, because a
 * resent leg is not a second kind of message -- it is this message again,
 * and the only thing standing in the way of reading it is that the mask
 * chain wiped the step it was masked under.  If the floor has already passed that
 * dispersal the derivation is unavailable; that bound is ./release's doing and is
 * the accepted price of forward secrecy.
 *
 * usage: assemble <config> <index> <baseDir> [<dispersal> <anchorLog>]
 */

#include <stdlib.h>
#include <string.h>
#include "cm.h"

/* a T-subset of h parts in whack-a-mole order: the first T, then every single
 * swap of one of those for one of the rest, then every pair of swaps, ... --
 * a bad part among the first T is whacked out within 1 + T x (h - T) tries
 * wherever it sits, and every receiver holding the same parts tries the same
 * subsets in the same order.  Two instances run nested (shares outside,
 * shards inside), which is why the state is a struct and not the enclosing
 * frame.  sel receives the subset; 0 once every subset has been produced. */
struct comb {
  unsigned int *sel;                  /* t: the subset, indices into 0..h-1 */
  unsigned int *a;                    /* d: positions among the first t swapped out, ascending */
  unsigned int *b;                    /* d: positions among the rest swapped in, ascending */
  unsigned int h;
  unsigned int t;
  unsigned int d;                     /* the current swap distance */
  int begun;
};

static int
combNext(
  struct comb *c
){
  unsigned int i;
  unsigned int j;

  if (!c->begun) {
    c->begun = 1;
    c->d = 0;
    goto fill;
  }
  for (i = c->d; i-- > 0;)            /* next d-subset of the rest */
    if (c->b[i] < c->h - c->d + i) {
      ++c->b[i];
      for (j = i + 1; j < c->d; ++j)
        c->b[j] = c->b[j - 1] + 1;
      goto fill;
    }
  for (i = c->d; i-- > 0;)            /* next d-subset of the first t, the rest from its start */
    if (c->a[i] < c->t - c->d + i) {
      ++c->a[i];
      for (j = i + 1; j < c->d; ++j)
        c->a[j] = c->a[j - 1] + 1;
      for (j = 0; j < c->d; ++j)
        c->b[j] = c->t + j;
      goto fill;
    }
  if (++c->d > c->t || c->d > c->h - c->t)
    return (0);
  for (j = 0; j < c->d; ++j) {
    c->a[j] = j;
    c->b[j] = c->t + j;
  }
fill:
  for (i = 0; i < c->t; ++i)
    c->sel[i] = i;
  for (i = 0; i < c->d; ++i)
    c->sel[c->a[i]] = c->b[i];
  return (1);
}

/* the parts held under one apex, and that pool's search: one per apex seen,
 * at most one per leaf.  The pool is the unit of verification (its own
 * signed header and roots) and of the search (its own budget). */
struct pool {
  unsigned char *shareBuf;            /* held shares, clear: cs x CM_KEY_LEN */
  unsigned char *shareSeed;           /* each held share's seed: cs x CM_SEED_LEN */
  unsigned char *sharePt;             /* each held share's derived output point */
  unsigned char *shareScp;            /* each held share's derived secret point */
  unsigned char *shareLeaf;           /* each held share's leaf */
  unsigned char *shardBuf;            /* held shards: cd x shardLen */
  unsigned char *shardLeaf;           /* each held shard's leaf (= RS shard index) */
  unsigned char *triedK;              /* the K candidates, in the order found */
  unsigned int *kSel;                 /* each candidate's share subset */
  unsigned int *kSearched;            /* the shard pool size each candidate was searched against */
  unsigned int shardLen;
  unsigned int cs;                    /* shares held */
  unsigned int cd;                    /* shards held */
  unsigned int nK;
  unsigned int kCap;                  /* the candidate list's capacity: r, grown to the budget */
  unsigned int csOld;                 /* the share pool the last search saw */
  unsigned int tries;
  int added;                          /* a part joined since the last search */
  int relaxed;                        /* every part gathered: agreement no longer excludes a subset */
  int pass;
  int fraud;
  int budget;
  unsigned char apex[CM_SIGN_HSZ];
  unsigned char orig[CM_SIGN_HSZ];
  unsigned char sr[CM_SSS_HSZ];
  unsigned char rr[CM_RSEC_HSZ];
  char shareSenders[4096];
  char shardSenders[4096];
};

int
main(
  int argc
 ,char *argv[]
){
  cmCfg *cfg;
  mlsCtx_t v;
  mlsHsh_t mPlug;
  sssMkHsh_t sPlug;
  rsecMkHsh_t rPlug;
  struct comb sc;                     /* shares: the outer search */
  struct comb dc;                     /* shards: the inner search, per K */
  struct pool *pools;                 /* one per apex seen */
  struct pool *P;                     /* the pool being gathered into, searched or reported */
  FILE *of;
  unsigned char *sig;
  unsigned char *sssvf;
  unsigned char *rsecvf;
  unsigned char *sproof;
  unsigned char *rproof;
  unsigned char **shareptr;           /* the subset under trial */
  unsigned char *ptSel;
  unsigned char *outPts;              /* the held shares outside the subset: agreement */
  unsigned char **outPtr;
  unsigned char *outBuf;
  unsigned char **shardptr;
  unsigned char *xidx;
  unsigned char **dptr;
  unsigned char *dbuf;                /* the decoded ciphertext */
  unsigned char *ptbuf;               /* the ciphertext XOR the hoisted keystream */
  unsigned char *ks;                  /* keystream(K, orig_hash), once per K */
  unsigned char *rswork;
  unsigned char *blob;
  unsigned char *p;
  unsigned char *reShare;             /* re-encode: all R shares re-evaluated */
  unsigned char **reSharePtr;
  unsigned char *reLeaf;              /* re-encode: all R sssMk leaves [seed][share] */
  const unsigned char **reLeafPtr;
  unsigned char *reParity;            /* re-encode: m re-derived RS parity shards */
  const unsigned char **reShardPtr;   /* re-encode: all R RS shards (data + parity) */
  unsigned char *sssw;
  unsigned char *rsecw;
  unsigned char *shardprobe;          /* measures shard_len = the shard's own length */
  unsigned char *canon;               /* after PASS: the delivered blob's canonical stream */
  const char *spent;                  /* the search the try budget ran out in: share or shard subsets */
  unsigned char *ovArr[1];
  unsigned int *ssel;
  unsigned int *sa;
  unsigned int *sb;
  unsigned int *dsel;
  unsigned int *da;
  unsigned int *db;
  unsigned char kkey[CM_KEY_LEN];
  unsigned char unit[CM_MVAL_LEN];    /* [seed][key-share] after unmasking */
  unsigned char pool[CM_MAXPROC];     /* code points derived from a seed */
  unsigned char carried[CM_SIGN_HSZ];  /* the apex an apex message carries */
  unsigned char pubroot[CM_SIGN_HSZ];
  unsigned char floorPub[CM_SIGN_HSZ];
  unsigned char floorAnc[CM_SIGN_HSZ];
  unsigned char recvHash[CM_SIGN_HSZ];
  unsigned char probe;                /* hufDecode length-probe target (never written) */
  unsigned char scp;
  unsigned char step[CM_PSK_LEN];     /* resend mode: the floor recomputed forward */
  char bpath[1024];
  char fpath[1024];
  char kpath[1024];
  char apexPath[1024];
  char shardPath[1024];
  char signPath[1024];
  char spath[1024];                   /* this seat's own receive record, if held */
  char opath[1024];
  char apexName[64];                  /* a leg's apex message file name: the tag its parts must carry */
  char tag[64];                       /* a part's own tag */
  char usedShares[4096];
  char usedShards[4096];
  char badShares[4096];
  char badShards[4096];
  unsigned long sgsz;
  unsigned long hw;
  unsigned long want;                 /* resend mode: the older dispersal being read */
  unsigned long expProc;              /* the dispersal label every fragment must carry: the book's (live) or want (resend) */
  unsigned long plProc;
  unsigned long floorProc;
  hufLen declen;
  hufLen blobCap;
  unsigned int idx;
  unsigned int r;
  unsigned int t;
  unsigned int k;
  unsigned int m;
  unsigned int n;
  unsigned int scratchLen;            /* the shard length the shard-sized scratch is sized for */
  unsigned int pfsS;
  unsigned int pfsR;
  unsigned int nPools;
  unsigned int gi;                    /* the next leaf to gather */
  unsigned int i;
  unsigned int j;
  unsigned int q;
  unsigned int off;
  int sl;
  int held;                           /* gathering the own unit, not a wire message */
  int haveFloor;
  int sigOk;                          /* an initiator-signed fragment was seen */
  int inconsistent;
  int rc;

  cfg = 0; of = 0;
  pools = P = 0;
  sig = sssvf = rsecvf = sproof = rproof = 0;
  shareptr = outPtr = shardptr = dptr = 0;
  ptSel = outPts = outBuf = xidx = dbuf = ptbuf = ks = rswork = blob = shardprobe = canon = 0;
  spent = 0;
  reShare = reLeaf = reParity = sssw = rsecw = 0;
  reSharePtr = 0; reLeafPtr = reShardPtr = 0;
  ssel = sa = sb = dsel = da = db = 0;
  sigOk = inconsistent = 0;
  declen = blobCap = 0;
  memset(recvHash, 0, sizeof (recvHash));
  usedShares[0] = usedShards[0] = badShares[0] = badShards[0] = 0;
  r = t = k = m = nPools = scratchLen = 0;
  rc = 1;

  if (argc != 4 && argc != 6) {
    fprintf(stderr, "usage: %s <config> <index> <baseDir> [<dispersal> <anchorLog>]\n", argv[0]);
    return (1);
  }
  idx = (unsigned int)atoi(argv[2]);

  if (!(cfg = malloc(sizeof (*cfg))) || cmCfgLoad(argv[1], cfg)) {
    fprintf(stderr, "%s: bad config %s\n", argv[0], argv[1]);
    goto done;
  }
  n = cfg->n;
  if (idx >= n - 1) {
    fprintf(stderr, "%s: index %u out of range (R=%u)\n", argv[0], idx, n - 1);
    goto done;
  }
  sprintf(bpath, "%s/priv/%02u_book.txt", argv[3], idx + 1);
  sprintf(fpath, "%s/priv/%02u_floor.txt", argv[3], idx + 1);
  cmKsPath(argv[1], kpath);
  /* this run's outputs, and no earlier run's: a run that ends without a
   * verdict leaves none, never the previous dispersal's */
  sprintf(opath, "%s/priv/%02u_assemble.txt", argv[3], idx + 1);
  remove(opath);
  sprintf(opath, "%s/priv/%02u_recovered.bin", argv[3], idx + 1);
  remove(opath);
  if (argc == 4) {
    sprintf(spath, "%s/priv/%02u_recv.txt", argv[3], idx + 1);
    if (cmKeystateLoad(kpath, cfg)) {          /* dispersal's ratcheted pairwise IKMs */
      fprintf(stderr, "%s: no keystate %s\n", argv[0], kpath);
      goto done;
    }
  } else {
    /* the wanted dispersal is behind the current step and its keys are gone from
     * it, so rebuild them from the floor base forward */
    want = strtoul(argv[4], 0, 10);
    sprintf(spath, "%s/priv/%02u_recv_%02lu.txt", argv[3], idx + 1, want);
    if (cmFloorLoad(kpath, cfg, &floorProc)) {
      fprintf(stderr, "%s: no floor in %s (nothing retained)\n", argv[0], kpath);
      goto done;
    }
    if (want < floorProc) {
      fprintf(stderr, "%s: dispersal %lu is below the retention floor %lu"
                      " (released -- unrecoverable)\n", argv[0], want, floorProc);
      goto done;
    }
    /* the base is dispersal floorProc's key; the links of dispersals
     * floorProc .. want-1 carry it to dispersal want's (see cmFloorLoad) */
    for (; floorProc < want; ++floorProc) {
      unsigned char anch[CM_SIGN_HSZ];
      char nm[sizeof ("anchor") + 3 * sizeof (unsigned long)];

      sprintf(nm, "anchor%02lu", floorProc);
      if (cmGetField(argv[5], nm, anch, CM_SIGN_HSZ) != CM_SIGN_HSZ) {
        fprintf(stderr, "%s: no %s in %s\n", argv[0], nm, argv[5]);
        goto done;
      }
      for (q = 0; q < n; ++q)
        if (cfg->pskHave[q]) {
          cmRatchet(cfg->psk[q], CM_PSK_LEN, anch, step, CM_PSK_LEN);
          memcpy(cfg->psk[q], step, CM_PSK_LEN);
        }
    }
    memset(step, 0, sizeof (step));
  }

  /* r/t/k/m derive from config; everything else comes from the exchange
   * messages.  The trust anchor (current pub) comes from the rotation book. */
  r = n - 1;
  t = cfg->t;
  k = t;
  m = r - t;
  pfsS = sssMkPfSz(CM_SSS_H, r);
  pfsR = rsecMkPfSz(CM_RSEC_H, r);
  cmMlsPlug(&mPlug);
  cmSssMkPlug(&sPlug);
  cmRsecMkPlug(&rPlug);
  v.h = &mPlug;
  v.s = CM_MLS_S;
  v.r = 0;
  sgsz = mlsSgSz(&v);
  if (cmGetField(bpath, "current", pubroot, CM_SIGN_HSZ) != CM_SIGN_HSZ) {
    fprintf(stderr, "%s: no book current at %s\n", argv[0], bpath);
    goto done;
  }
  /* the dispersal label: receive matches the distribution's against its book,
   * and the same match is made here on every exchange fragment -- the book's
   * dispersal live, the dispersal asked for in resend mode (the book has moved) */
  if (argc == 4) {
    if (cmGetU(bpath, "process", &expProc)) {
      fprintf(stderr, "%s: no book dispersal at %s\n", argv[0], bpath);
      goto done;
    }
  } else
    expProc = want;
  /* the signing-offset floor for this pub (offsetgate's record): no floor, or
   * a floor for another pub, admits.  Live mode only: an older dispersal is
   * asked for by its number and is below the high-water by definition. */
  haveFloor = argc == 4
           && cmGetField(fpath, "pub", floorPub, CM_SIGN_HSZ) == CM_SIGN_HSZ
           && !memcmp(floorPub, pubroot, CM_SIGN_HSZ)
           && !cmGetU(fpath, "highwater", &hw)
           && cmGetField(fpath, "anchor", floorAnc, CM_SIGN_HSZ) == CM_SIGN_HSZ;

  /* config-sized scratch: the gather's, the search's and the re-encode's;
   * the shard-sized scratch follows each pool's first verified shard; blob
   * is sized by each try's self-described length; a pool's own arrays are
   * made when its apex is first seen */
  if (!(sig = malloc(sgsz)) || !(sproof = malloc(pfsS)) || !(rproof = malloc(pfsR))
   || !(sssvf = malloc(sssMkVfSz(CM_SSS_H))) || !(rsecvf = malloc(rsecMkVfSz(CM_RSEC_H)))
   || !(shardprobe = malloc(CM_SHARD_MAX))
   || !(pools = calloc(r, sizeof (*pools)))
   || !(shareptr = malloc((unsigned long)t * sizeof (*shareptr)))
   || !(ptSel = malloc(t))
   || !(outPts = malloc(r))
   || !(outPtr = malloc((unsigned long)r * sizeof (*outPtr)))
   || !(outBuf = malloc((unsigned long)r * CM_KEY_LEN))
   || !(shardptr = malloc((unsigned long)t * sizeof (*shardptr)))
   || !(xidx = malloc(t))
   || !(dptr = malloc((unsigned long)k * sizeof (*dptr)))
   || !(rswork = malloc(RS_WORK_SIZE(k)))
   || !(ssel = malloc((unsigned long)t * sizeof (*ssel)))
   || !(sa = malloc((unsigned long)t * sizeof (*sa)))
   || !(sb = malloc((unsigned long)t * sizeof (*sb)))
   || !(dsel = malloc((unsigned long)t * sizeof (*dsel)))
   || !(da = malloc((unsigned long)t * sizeof (*da)))
   || !(db = malloc((unsigned long)t * sizeof (*db)))
   || !(reShare = malloc((unsigned long)r * CM_KEY_LEN))
   || !(reSharePtr = malloc((unsigned long)r * sizeof (*reSharePtr)))
   || !(reLeaf = malloc((unsigned long)r * CM_MVAL_LEN))
   || !(reLeafPtr = malloc((unsigned long)r * sizeof (*reLeafPtr)))
   || !(reShardPtr = malloc((unsigned long)r * sizeof (*reShardPtr)))
   || !(sssw = malloc(sssMkWaSz(CM_SSS_H, r)))
   || !(rsecw = malloc(rsecMkWaSz(CM_RSEC_H, r))))
    goto done;

  /* Gather, LAZILY, into pools by apex.  Parts are read leaf by leaf; a
   * pool with T shares and T shards in hand is searched as soon as a part
   * joins it, and only a failed search reads the next leaf: the honest path
   * reads T fragments and PASSes at the first try, a bad committed part
   * costs the fragments the search needs.  Each exchange fragment is
   * validated like receive does, gate for gate in receive's order -- the
   * hmacs, the apex message, the sign message's tag and signed header, the
   * dispersal label, the apex recomputed under the book's pub and the
   * signature's offset and required to
   * be the apex message's, the offset floor (live), the initiator's
   * signature extracting to that pub at a payload signing offset -- then
   * the share and the shard each under its own proof into the apex's pool.
   * Leaf idx is this seat's own unit: gathered from its receive record by
   * the same path, gated by receive's verdicts in place of a wire hmac (and
   * receive already matched it to its apex), share already clear. */
  gi = 0;
 gather:
  while (gi < r) {
    unsigned char ocpv;
    unsigned char scpv;
    unsigned char geo[CM_MAXPROC];      /* code points derived from this unit's seed */
    unsigned char oh[CM_SIGN_HSZ];
    unsigned char sr[CM_SSS_HSZ];
    unsigned char rr[CM_RSEC_HSZ];
    unsigned char ap[CM_SIGN_HSZ];
    int sOk;                            /* the share part may be gathered */
    int rOk;                            /* the shard part may be gathered */

    i = gi++;
    if ((held = i == idx)) {
      FILE *rf;
      char line[256];
      unsigned int ok;

      if (!(rf = fopen(spath, "r")))
        continue;                                      /* not held: censored, or not yet */
      for (ok = 0; fgets(line, sizeof (line), rf); ) {
        if (!strcmp(line, "hmac_ok: yes\n")) ok |= 1;
        if (!strcmp(line, "sig_ok: yes\n")) ok |= 2;
        if (!strcmp(line, "offset_ok: yes\n")) ok |= 4;
        if (!strcmp(line, "sssmk_ok: yes\n")) ok |= 8;
        if (!strcmp(line, "rsecmk_ok: yes\n")) ok |= 16;
      }
      fclose(rf);
      if ((ok & 7) != 7)
        continue;                                      /* receive did not validate it */
      sOk = (ok & 8) != 0;
      rOk = (ok & 16) != 0;
      strcpy(shardPath, spath);                        /* the record holds the shard and the sign */
      strcpy(signPath, spath);
    } else {
      sprintf(apexName, "%02u_to_%02u_apex.txt", i + 1, idx + 1);
      sprintf(apexPath, "%s/wire/exch/%s", argv[3], apexName);
      sprintf(shardPath, "%s/wire/exch/%02u_to_%02u_shard.txt", argv[3], i + 1, idx + 1);
      sprintf(signPath, "%s/wire/exch/%02u_to_%02u_sign.txt", argv[3], i + 1, idx + 1);
      if (!cmHmacCheck(apexPath, cfg->mac[i + 1], CM_PSK_LEN, i + 1, idx + 1)
       || !cmHmacCheck(signPath, cfg->mac[i + 1], CM_PSK_LEN, i + 1, idx + 1))
        continue;                                      /* wire-tampered: skip unparsed */
      sOk = 1;
      rOk = cmHmacCheck(shardPath, cfg->mac[i + 1], CM_PSK_LEN, i + 1, idx + 1);  /* absent or tampered: the shard part alone */
      if (cmGetField(apexPath, "apex", carried, CM_SIGN_HSZ) != CM_SIGN_HSZ
       || cmGetStr(signPath, "tag", tag, sizeof (tag)) < 0
       || strcmp(tag, apexName))                       /* the sign message is of another apex message */
        continue;
    }
    if (!(sOk || rOk))
      continue;
    if (cmGetU(signPath, "process", &plProc)           /* the signed header */
     || cmGetField(signPath, "orig_hash", oh, CM_SIGN_HSZ) != CM_SIGN_HSZ
     || cmGetField(signPath, "sssmk_root", sr, CM_SSS_HSZ) != CM_SSS_HSZ
     || cmGetField(signPath, "rsecmk_root", rr, CM_RSEC_HSZ) != CM_RSEC_HSZ
     || cmGetField(signPath, "mls_sig", sig, (unsigned int)sgsz) != (int)sgsz)
      continue;                                        /* malformed: skip, as receive refuses */
    if (plProc != expProc)                             /* the dispersal label: the book's, or the one asked for */
      continue;
    if (!cmMlsOff(sig, sgsz, &off))                    /* the offset the signature yields: the apex commits it */
      continue;
    cmApex(pubroot, off, oh, rr, sr, ap);              /* under the book's pub, the one candidate signer */
    if (!held && memcmp(carried, ap, CM_SIGN_HSZ))     /* the sign message hashes to its apex message's value */
      continue;
    if (haveFloor                                      /* not passed by the floor, as receive reads it, */
     && (off < hw                                      /* at the offset the apex was recomputed at: re-injected, or */
      || (off == hw && memcmp(floorAnc, ap, CM_SIGN_HSZ))))  /* re-authored -- before the signature is paid for */
      continue;
    if (off == CM_SLOT_ROT                             /* at a payload signing offset */
     || !cmMlsVerify(pubroot, ap, sig, sgsz))          /* initiator-authentic */
      continue;
    sigOk = 1;

    /* the pool of this apex, made at its first fragment: its header is that
     * fragment's, and every later fragment of the apex recomputed to the
     * same bytes, so the header is the apex's and not the sender's */
    for (q = 0; q < nPools && memcmp(pools[q].apex, ap, CM_SIGN_HSZ); ++q)
      ;
    P = pools + q;
    if (q == nPools) {
      ++nPools;
      memcpy(P->apex, ap, CM_SIGN_HSZ);
      memcpy(P->orig, oh, CM_SIGN_HSZ);
      memcpy(P->sr, sr, CM_SSS_HSZ);
      memcpy(P->rr, rr, CM_RSEC_HSZ);
      P->kCap = r;
      if (!(P->shareBuf = malloc((unsigned long)r * CM_KEY_LEN))
       || !(P->shareSeed = malloc((unsigned long)r * CM_SEED_LEN))
       || !(P->sharePt = malloc(r)) || !(P->shareScp = malloc(r)) || !(P->shareLeaf = malloc(r))
       || !(P->shardLeaf = malloc(r))
       || !(P->triedK = malloc((unsigned long)r * CM_KEY_LEN))
       || !(P->kSel = malloc((unsigned long)r * t * sizeof (*P->kSel)))
       || !(P->kSearched = malloc((unsigned long)r * sizeof (*P->kSearched))))
        goto done;
    }

    /* the share part: unmask the value, recover the hidden code points,
     * authenticate the unit.  sender leaf i is seat i+1; its exchange mask
     * is the pairwise PSK(self,i+1) under the CM_DOM_EXCH domain at the
     * payload's one step (the same step distribute masked under).  the held
     * unit was unmasked at receive. */
    if (sOk
     && cmGetField(signPath, held ? "share_clear" : "share_masked", unit, CM_MVAL_LEN) == CM_MVAL_LEN
     && cmGetField(signPath, "sssmk_proof", sproof, pfsS) == (int)pfsS) {
      if (!held)
        cmMask(cfg->psk[i + 1], CM_PSK_LEN, ap, CM_DOM_EXCH, (unsigned char)i, unit, CM_MVAL_LEN);
      cmGeometry(unit, n, geo);         /* derive the code points from the unit's seed */
      scpv = geo[0];
      ocpv = geo[1 + i];
      if ((p = sssMkExtract(&sPlug, scpv, ocpv, unit, CM_MVAL_LEN, i, r, sproof, sssvf))
       && !memcmp(p, P->sr, CM_SSS_HSZ)) {
        memcpy(P->shareBuf + (unsigned long)P->cs * CM_KEY_LEN, unit + CM_SEED_LEN, CM_KEY_LEN);
        memcpy(P->shareSeed + (unsigned long)P->cs * CM_SEED_LEN, unit, CM_SEED_LEN);
        P->sharePt[P->cs] = ocpv;
        P->shareScp[P->cs] = scpv;
        P->shareLeaf[P->cs] = (unsigned char)i;
        sprintf(P->shareSenders + strlen(P->shareSenders), held ? "%u(held) " : "%u ", i + 1);
        ++P->cs;
        P->added = 1;
      }
    }

    /* the shard part: expected when the validated sign message carries
     * rsecmk_proof, then required of the shard message, hmac-whole, tagged
     * with this apex message, within the cap (k x its length is the
     * ciphertext, the same check receive makes), then the clear shard under
     * the signed root.
     * shard_len is the shard's own length, taken from the pool's first shard
     * that verifies; the root binds the length, so every shard that verifies
     * after it is this length too */
    if (cmGetField(signPath, "rsecmk_proof", rproof, pfsR) == (int)pfsR
     && rOk
     && (held || (cmGetStr(shardPath, "tag", tag, sizeof (tag)) >= 0
               && !strcmp(tag, apexName)))             /* this apex message's shard, by its tag */
     && (sl = cmGetField(shardPath, "shard", shardprobe, CM_SHARD_MAX)) > 0
     && (unsigned long)k * sl <= CM_CT_MAX
     && (p = rsecMkExtract(&rPlug, shardprobe, (unsigned int)sl, i, r, rproof, rsecvf))
     && !memcmp(p, P->rr, CM_RSEC_HSZ)) {
      if (!P->cd) {
        P->shardLen = (unsigned int)sl;
        if (!(P->shardBuf = malloc((unsigned long)r * P->shardLen)))
          goto done;
      }
      if ((unsigned int)sl == P->shardLen) {
        memcpy(P->shardBuf + (unsigned long)P->cd * P->shardLen, shardprobe, P->shardLen);
        P->shardLeaf[P->cd] = (unsigned char)i;
        sprintf(P->shardSenders + strlen(P->shardSenders), held ? "%u(held) " : "%u ", i + 1);
        ++P->cd;
        P->added = 1;
      }
    }
    if (P->added && !P->budget && P->cs >= t && P->cd >= t)   /* a spent budget is spent: no search again */
      goto search;
  }
  /* every leaf read: a pool at threshold was searched when its last part
   * joined, so one searched with everything gets its relaxed pass; one
   * searched relaxed is exhausted; the rest are under threshold */
  for (q = 0; q < nPools; ++q) {
    P = pools + q;
    if (P->pass || P->fraud || P->budget || P->cs < t || P->cd < t)
      continue;
    if (!P->relaxed) {
      P->relaxed = 1;                 /* the last pass: every subset, agreement or not, the hash deciding */
      P->csOld = 0;
      goto search;
    }
    P->fraud = 1;
    fprintf(stderr, "%s: FRAUD -- no subset of the held parts reproduces the signed hash (every subset tried, %u tries)\n"
           ,argv[0], P->tries);
  }
  goto report;

  /* The search over pool P in hand -- shares outside, a K candidate per
   * agreed polynomial; shards inside, the signed hash the oracle; one try
   * budget over both, per pool.  Only subsets that touch a part gathered
   * since the last search are new: a subset whose every index is below the
   * pool size then is one already tried. */
 search:
  P->added = 0;
  if (P->shardLen > scratchLen) {     /* the shard-sized scratch, at the largest shard length seen */
    unsigned char *g;

    scratchLen = P->shardLen;
    if (!(g = realloc(dbuf, (unsigned long)k * scratchLen))) goto done;
    dbuf = g;
    if (!(g = realloc(ptbuf, (unsigned long)k * scratchLen))) goto done;
    ptbuf = g;
    if (!(g = realloc(ks, (unsigned long)k * scratchLen))) goto done;
    ks = g;
    if (m) {
      if (!(g = realloc(reParity, (unsigned long)m * scratchLen))) goto done;
      reParity = g;
    }
  }
  for (j = 0; j < k; ++j)
    dptr[j] = dbuf + (unsigned long)j * P->shardLen;
  sc.sel = ssel; sc.a = sa; sc.b = sb; sc.h = P->cs; sc.t = t; sc.begun = 0;
  while (combNext(&sc)) {
    unsigned int no;                    /* held shares outside the subset, same code points */
    unsigned int agree;

    for (j = 0; j < t && ssel[j] < P->csOld; ++j)
      ;
    if (j == t)
      continue;                         /* tried against an earlier pool */
    if (++P->tries > CM_SEARCH_TRIES) {
      spent = "share";
      goto budget;
    }
    /* one seed across the subset: the seed the points derive from */
    for (j = 0; j < t; ++j) {
      shareptr[j] = P->shareBuf + (unsigned long)ssel[j] * CM_KEY_LEN;
      ptSel[j] = P->sharePt[ssel[j]];
    }
    for (j = 1; j < t && !memcmp(P->shareSeed + (unsigned long)ssel[j] * CM_SEED_LEN
                                ,P->shareSeed + (unsigned long)ssel[0] * CM_SEED_LEN, CM_SEED_LEN); ++j)
      ;
    if (j < t)
      continue;
    scp = P->shareScp[ssel[0]];
    ovArr[0] = kkey;
    sss(ptSel, &scp, shareptr, ovArr, t, 1, CM_KEY_LEN);
    /* a candidate when one more held share lies on the polynomial -- agreement
     * ORDERS the candidates (a good subset beside one bad share is rejected
     * here when that share is its only outside); once every part is gathered
     * the relaxed pass tries the rest, the hash deciding */
    if (P->cs > t && !P->relaxed) {
      for (no = q = 0; q < P->cs; ++q) {
        for (j = 0; j < t && ssel[j] != q; ++j)
          ;
        if (j < t || memcmp(P->shareSeed + (unsigned long)q * CM_SEED_LEN
                           ,P->shareSeed + (unsigned long)ssel[0] * CM_SEED_LEN, CM_SEED_LEN))
          continue;
        outPts[no] = P->sharePt[q];
        outPtr[no] = outBuf + (unsigned long)q * CM_KEY_LEN;
        ++no;
      }
      if (no) {                         /* no held share of its code points outside: a candidate as the sole subset is */
        sss(ptSel, outPts, shareptr, outPtr, t, no, CM_KEY_LEN);
        for (agree = q = 0; q < no; ++q)
          if (!memcmp(outPtr[q], P->shareBuf + (outPtr[q] - outBuf), CM_KEY_LEN))
            ++agree;
        if (!agree)
          continue;
      }
    }
    for (q = 0; q < P->nK && memcmp(P->triedK + (unsigned long)q * CM_KEY_LEN, kkey, CM_KEY_LEN); ++q)
      ;
    if (q < P->nK)
      continue;                         /* this K is a candidate already */
    if (P->nK == P->kCap) {             /* grow: every candidate cost a try, so the budget bounds the list */
      unsigned char *gk;
      unsigned int *gs;
      unsigned int *gd;

      if (!(gk = realloc(P->triedK, (unsigned long)P->kCap * 2 * CM_KEY_LEN)))
        goto done;
      P->triedK = gk;
      if (!(gs = realloc(P->kSel, (unsigned long)P->kCap * 2 * t * sizeof (*P->kSel))))
        goto done;
      P->kSel = gs;
      if (!(gd = realloc(P->kSearched, (unsigned long)P->kCap * 2 * sizeof (*P->kSearched))))
        goto done;
      P->kSearched = gd;
      P->kCap *= 2;
    }
    memcpy(P->triedK + (unsigned long)P->nK * CM_KEY_LEN, kkey, CM_KEY_LEN);
    memcpy(P->kSel + (unsigned long)P->nK * t, ssel, (unsigned long)t * sizeof (*ssel));
    P->kSearched[P->nK] = 0;
    ++P->nK;
  }
  P->csOld = P->cs;
  for (q = 0; q < P->nK; ++q) {
    if (P->kSearched[q] == P->cd)
      continue;                         /* no shard gathered since this K was searched under */
    memset(ks, 0, (unsigned long)k * P->shardLen);
    cmKeystream(P->triedK + (unsigned long)q * CM_KEY_LEN, CM_KEY_LEN, P->orig, ks, k * P->shardLen);
    dc.sel = dsel; dc.a = da; dc.b = db; dc.h = P->cd; dc.t = t; dc.begun = 0;
    while (combNext(&dc)) {
      for (j = 0; j < t && dsel[j] < P->kSearched[q]; ++j)
        ;
      if (j == t)
        continue;                       /* tried under this K against an earlier pool */
      if (++P->tries > CM_SEARCH_TRIES) {
        spent = "shard";
        goto budget;
      }
      for (j = 0; j < t; ++j) {
        shardptr[j] = P->shardBuf + (unsigned long)dsel[j] * P->shardLen;
        xidx[j] = P->shardLeaf[dsel[j]];
      }
      if (rsecDecode((const unsigned char *const *)shardptr, xidx, dptr, P->shardLen, k, m, rswork))
        continue;
      for (j = 0; j < k * P->shardLen; ++j)
        ptbuf[j] = dbuf[j] ^ ks[j];
      /* the stream embeds the original length: probe it (olen 0 writes
       * nothing), size the buffer, decode.  A probe of 0 is either the stream
       * of nothing (an empty message IS a message) or a broken stream, and
       * the hash of nothing cannot tell them apart: a try reads the empty
       * message only when its whole plaintext is zero -- the two-byte stream
       * of nothing and the zero padding, the dealer having keystreamed the
       * padded ciphertext whole -- so a wrong try's garbage is this try
       * failing, as it is at any other length.  A probe past CM_BLOB_MAX is
       * this try failing; a buffer this box cannot give is the program. */
      declen = hufDecode(&probe, 0, ptbuf, (hufLen)(k * P->shardLen));
      if (!declen) {
        for (j = 0; j < k * P->shardLen && !ptbuf[j]; ++j)
          ;
        if (j < k * P->shardLen)
          continue;
      }
      if (declen > CM_BLOB_MAX)
        continue;
      if (declen > blobCap) {
        if (!(p = realloc(blob, declen)))
          goto done;
        blob = p;
        blobCap = declen;
      }
      if (declen)                       /* the same stream: the count the probe read */
        hufDecode(blob, declen, ptbuf, (hufLen)(k * P->shardLen));
      cmHash(blob, declen, recvHash);
      if (!memcmp(recvHash, P->orig, CM_SIGN_HSZ)) {
        memcpy(kkey, P->triedK + (unsigned long)q * CM_KEY_LEN, CM_KEY_LEN);
        memcpy(ssel, P->kSel + (unsigned long)q * t, (unsigned long)t * sizeof (*ssel));
        for (j = 0; j < t; ++j) {
          shareptr[j] = P->shareBuf + (unsigned long)ssel[j] * CM_KEY_LEN;
          ptSel[j] = P->sharePt[ssel[j]];
        }
        goto found;
      }
    }
    P->kSearched[q] = P->cd;
  }
  goto gather;                          /* nothing in this pool yet: one more fragment */

 budget:
  P->budget = 1;
  fprintf(stderr, "%s: FAIL -- the search is unfinished at the try budget (%u tries, in the %s subsets)\n"
         ,argv[0], P->tries, spent);
  goto gather;

 found:
  P->pass = 1;
  for (j = 0; j < t; ++j) {
    sprintf(usedShares + strlen(usedShares), "%u ", P->shareLeaf[ssel[j]] + 1);
    sprintf(usedShards + strlen(usedShards), "%u ", P->shardLeaf[dsel[j]] + 1);
  }

  /* DEALER CONSISTENCY after PASS: re-encode both codes and compare to the
   * SIGNED commitment; every held part off the re-encode is named by leaf.
   * The RS side starts from the CANONICAL ciphertext -- the delivered blob
   * re-encoded (huffman is deterministic), zero-padded to k x shard_len,
   * under the winning K's keystream -- not from the winning shards: the
   * hash never read the stream's unused bits or the padding, so a flip
   * there survives a PASS, and against the canonical bytes it is named at
   * its leaf instead of being the yardstick the rest are judged by.  A
   * canonical stream that does not fit the committed shard length means
   * the dealer dispersed a stream of another encoder's choosing: the
   * commitment is inconsistent outright, and no shard is named, since the
   * canonical ciphertext cannot be laid out in it. */
  {                                     /* the canonical ciphertext into dbuf */
    unsigned long cap;
    unsigned long clen;

    cap = (unsigned long)declen + 1024;
    if (!(canon = malloc(cap)))
      goto done;
    clen = hufEncode(canon, (hufLen)cap, blob, declen);
    if (clen > cap) {
      free(canon);
      if (!(canon = malloc(clen)))
        goto done;
      if (hufEncode(canon, (hufLen)clen, blob, declen) != clen)
        goto done;
    }
    if (clen > (unsigned long)k * P->shardLen) {
      inconsistent = 1;
      goto reSss;
    }
    memcpy(dbuf, canon, clen);
    memset(dbuf + clen, 0, (unsigned long)k * P->shardLen - clen);
    cmKeystream(kkey, CM_KEY_LEN, P->orig, dbuf, k * P->shardLen);
  }
  {                                     /* RS: re-encode all R shards */
    for (i = 0; i < m; ++i)
      reShardPtr[k + i] = reParity + (unsigned long)i * P->shardLen;
    if (rsecEncode((const unsigned char *const *)dptr
                  ,(unsigned char *const *)(reShardPtr + k), P->shardLen, k, m))
      goto done;
    for (i = 0; i < k; ++i)
      reShardPtr[i] = dptr[i];
    if (!(p = rsecMkHash(&rPlug, reShardPtr, P->shardLen, r, rsecw))
     || memcmp(p, P->rr, CM_RSEC_HSZ))
      inconsistent = 1;
    for (q = 0; q < P->cd; ++q)
      if (memcmp(P->shardBuf + (unsigned long)q * P->shardLen, reShardPtr[P->shardLeaf[q]], P->shardLen))
        sprintf(badShards + strlen(badShards), "%u ", P->shardLeaf[q] + 1);
  }
 reSss:
  {                                     /* SSS: re-evaluate at all R points of the winning seed */
    cmGeometry(P->shareSeed + (unsigned long)ssel[0] * CM_SEED_LEN, n, pool);
    for (i = 0; i < r; ++i)
      reSharePtr[i] = reShare + (unsigned long)i * CM_KEY_LEN;
    sss(ptSel, pool + 1, shareptr, reSharePtr, t, r, CM_KEY_LEN);
    for (i = 0; i < r; ++i) {
      memcpy(reLeaf + (unsigned long)i * CM_MVAL_LEN, P->shareSeed + (unsigned long)ssel[0] * CM_SEED_LEN, CM_SEED_LEN);
      memcpy(reLeaf + (unsigned long)i * CM_MVAL_LEN + CM_SEED_LEN
            ,reShare + (unsigned long)i * CM_KEY_LEN, CM_KEY_LEN);
      reLeafPtr[i] = reLeaf + (unsigned long)i * CM_MVAL_LEN;
    }
    if (!(p = sssMkHash(&sPlug, pool[0], pool + 1, reLeafPtr, CM_MVAL_LEN, r, sssw))
     || memcmp(p, P->sr, CM_SSS_HSZ))
      inconsistent = 1;
    for (q = 0; q < P->cs; ++q)
      if (memcmp(P->shareSeed + (unsigned long)q * CM_SEED_LEN, P->shareSeed + (unsigned long)ssel[0] * CM_SEED_LEN, CM_SEED_LEN)
       || memcmp(P->shareBuf + (unsigned long)q * CM_KEY_LEN, reShare + (unsigned long)P->shareLeaf[q] * CM_KEY_LEN, CM_KEY_LEN))
        sprintf(badShares + strlen(badShares), "%u ", P->shareLeaf[q] + 1);
  }
  if (inconsistent)
    fprintf(stderr, "%s: commitment INCONSISTENT -- re-encode does not match the signed roots (bad shares: %s; bad shards: %s)\n"
           ,argv[0], badShares, badShards);

 report:
  /* the pool reported in full: the one that PASSed, else the first seen;
   * every pool seen gets its own line */
  for (q = 0; q < nPools && !pools[q].pass; ++q)
    ;
  P = q < nPools ? pools + q : nPools ? pools : 0;
  sprintf(opath, "%s/priv/%02u_assemble.txt", argv[3], idx + 1);
  if (!(of = fopen(opath, "w")))
    goto done;
  fprintf(of, "phase: assemble\n");
  cmPutU(of, "system", idx + 1);
  fprintf(of, "sig_ok: %s\n", sigOk ? "yes" : "no");
  cmPutU(of, "pools", nPools);
  for (q = 0; q < nPools; ++q) {
    char hex[2 * CM_SIGN_HSZ + 1];

    cmHexEnc(pools[q].apex, CM_SIGN_HSZ, hex);
    hex[2 * CM_SIGN_HSZ] = 0;
    fprintf(of, "pool: %s shares=%u shards=%u tries=%u result=%s%s\n", hex
           ,pools[q].cs, pools[q].cd, pools[q].tries
           ,pools[q].pass ? "PASS" : pools[q].fraud ? "FRAUD" : "FAIL"
           ,pools[q].budget ? " search=budget" : pools[q].fraud ? " search=exhausted" : "");
  }
  if (P)
    cmPutField(of, "apex", P->apex, CM_SIGN_HSZ);
  cmPutU(of, "shares_held", P ? P->cs : 0);
  cmPutU(of, "shards_held", P ? P->cd : 0);
  cmPutU(of, "threshold", t);
  fprintf(of, "share_senders: %s\n", P ? P->shareSenders : "");
  fprintf(of, "shard_senders: %s\n", P ? P->shardSenders : "");
  cmPutU(of, "tries", P ? P->tries : 0);
  if (P && (P->fraud || P->budget))
    fprintf(of, "search: %s\n", P->budget ? "budget" : "exhausted");
  if (P && P->pass) {
    fprintf(of, "used_shares: %s\n", usedShares);
    fprintf(of, "used_shards: %s\n", usedShards);
    fprintf(of, "commitment: %s\n", inconsistent ? "inconsistent" : "consistent");
    fprintf(of, "bad_shares: %s\n", badShares);
    fprintf(of, "bad_shards: %s\n", badShards);
  }
  cmPutU(of, "recovered_len", P && P->pass ? declen : 0);
  if (P && P->pass)
    cmPutField(of, "recovered_hash", recvHash, CM_SIGN_HSZ);
  if (P)                              /* the signed message hash: only under a validated header is it anyone's */
    cmPutField(of, "orig_hash", P->orig, CM_SIGN_HSZ);
  fprintf(of, "result: %s\n", P ? (P->pass ? "PASS" : P->fraud ? "FRAUD" : "FAIL") : "FAIL");
  fclose(of); of = 0;

  if (P && P->pass) {
    sprintf(opath, "%s/priv/%02u_recovered.bin", argv[3], idx + 1);
    if ((of = fopen(opath, "wb"))) {
      if (declen)
        fwrite(blob, 1, declen, of);
      fclose(of); of = 0;
    }
  }

  if (!sigOk)
    fprintf(stderr, "%s: no initiator-signed exchange fragment to assemble from\n", argv[0]);
  fprintf(stderr, "%s: seat %u  sig=%s pools=%u shares=%u/%u shards=%u/%u tries=%u  result=%s%s\n", argv[0]
         ,idx + 1, sigOk ? "ok" : "BAD", nPools, P ? P->cs : 0, t, P ? P->cd : 0, t, P ? P->tries : 0
         ,P ? (P->pass ? "PASS" : P->fraud ? "FRAUD" : "FAIL") : "FAIL"
         ,inconsistent ? " (commitment inconsistent)" : "");
  rc = P && P->pass ? 0 : 1;

 done:
  if (of) fclose(of);
  memset(kkey, 0, sizeof (kkey));
  memset(unit, 0, sizeof (unit));
  if (outBuf) memset(outBuf, 0, (unsigned long)r * CM_KEY_LEN);
  if (ks) memset(ks, 0, (unsigned long)k * scratchLen);
  if (reShare) memset(reShare, 0, (unsigned long)r * CM_KEY_LEN);
  if (reLeaf) memset(reLeaf, 0, (unsigned long)r * CM_MVAL_LEN);
  if (ptbuf) memset(ptbuf, 0, (unsigned long)k * scratchLen);   /* the compressed plaintext */
  if (blob) memset(blob, 0, blobCap);                            /* the plaintext */
  memset(pool, 0, sizeof (pool));                                 /* the dealt code points */
  for (q = 0; q < nPools; ++q) {
    P = pools + q;
    if (P->shareBuf) memset(P->shareBuf, 0, (unsigned long)r * CM_KEY_LEN);
    if (P->shareSeed) memset(P->shareSeed, 0, (unsigned long)r * CM_SEED_LEN);
    if (P->triedK) memset(P->triedK, 0, (unsigned long)P->kCap * CM_KEY_LEN);
    free(P->shareBuf); free(P->shareSeed); free(P->sharePt); free(P->shareScp); free(P->shareLeaf);
    free(P->shardBuf); free(P->shardLeaf);
    free(P->triedK); free(P->kSel); free(P->kSearched);
  }
  free(pools);
  if (cfg) memset(cfg, 0, sizeof (*cfg));  /* the dealt key mesh */
  free(cfg); free(sig); free(sssvf); free(rsecvf);
  free(sproof); free(rproof); free(shardprobe); free(canon);
  free(shareptr); free(ptSel); free(outPts); free(outPtr); free(outBuf);
  free(shardptr); free(xidx); free(dptr); free(dbuf); free(ptbuf); free(ks); free(rswork); free(blob);
  free(ssel); free(sa); free(sb); free(dsel); free(da); free(db);
  free(reShare); free(reSharePtr); free(reLeaf); free(reLeafPtr);
  free(reParity); free(reShardPtr); free(sssw); free(rsecw);
  return (rc);
}
