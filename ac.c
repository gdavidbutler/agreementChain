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
 * ac.c - a chain of dispersals over BKR94 Agreement[Q]: one seat,
 * driven by its caller over UDP.  N seats run instance after instance;
 * in each, every seat is the initiator of its own distribution and a
 * recipient of every other's, they agree on a subset of the
 * distributions and assemble every member's payload, and the chain's
 * head folded with the subset and every member's hash -- a payload's
 * message hash, a rotation's or a noop's value -- is the next head.
 *
 * THE CHAIN, from one seat.  A position is one Agreement[Q], and its
 * NAME is the chain hash before it, the link the fold of the position
 * before it minted: position 1's is the dealt genesis.  Every row of a
 * position carries the name in its tag, which is Bracha's tag raised
 * one level: within one agreement "all messages sent in the kth round
 * by process p will be tagged with (p, k)", since asynchrony keeps
 * several broadcasts alive at once [Bracha87 Section 3], and a chain
 * keeps several agreements alive at once the same way, so the tag is
 * (name, ba, q, k).  A seat routes a row to the position whose name it
 * minted itself; a row whose name it has not minted yet it holds until
 * it does, as Bracha stores a later round's message till that round;
 * and the records it keeps are keyed by the same name.  Nothing here
 * numbers a position on the wire: a number is a counter with a wrap,
 * and the chain runs for no bounded length.  The name is public, the
 * chain the reports publish, and carries no secret.  The seat launches
 * position 1 at the go, every seat's rotation, and the next position
 * when the one in hand has folded here and there is a reason to: its
 * caller has a message to propose (acAvailable), or a rotation of its
 * the last subset left out is presented again, or another seat's rows
 * under the name the fold just minted are held here, or a row under a
 * name this seat has not minted has arrived since its last launch, a
 * position past its head existing at that sender.  Where its signing
 * context leaves the position a payload slot, this seat's input is
 * asked of the caller then (propose): its message, or, with none, its
 * noop.  Nothing here queues a proposal: the position's chain report
 * says what became of it, and the caller decides there what to propose
 * next, the same bytes again if it likes.  A position is every seat's
 * agreement on every seat's input [BKR94 Agreement[Q]], so one seat's
 * message launches the position at every seat, and an idle chain sends
 * nothing.  It launches under the mask keys as that fold left them; a
 * position's machines -- its ACS seat, its value broadcasts, its legs,
 * their re-sends -- run on under its own mask step, overlapping what
 * follows, each to its abandon count, the deployment's abandon: under
 * unbounded latency any count is one the network can outlast, so the
 * count is the deployment's reading of its physics, paid out of t in
 * liveness, never safety: the papers' agreement properties count what
 * correct seats sent and need no bound on their later silence.  Each
 * re-sends what it owes to the seats not recorded as having it, which
 * is BPR, retry in the face of silence at the tick, the most that can
 * be done about silence, and the ACS seat's own value broadcast among
 * that is the seat's presence at the position.  Those machines are the
 * LIVE WINDOW.  A position folded here whose machines have all
 * abandoned leaves a RECORD -- its subset, every member's agreed value,
 * the book at its launch, this seat's unit of each member, its own
 * distribution -- in the RETENTION, the declared bytes, the retention
 * parameter, the newest record overwriting the oldest, so nothing here
 * decides when to evict.  The two cut the seats into three windows:
 * participating, its rows routed to live machines; returning, its rows
 * naming a recorded position, which RECOVER carries a position a round
 * trip; behind the oldest record, partitioned for good, until the
 * operator intervenes.  A seat that folded a position never agrees it
 * again; one that has not keeps its agreement there running until it
 * has the subset, and where the others' machines there are gone,
 * recovery gives it the subset it missed.  The harness's arm (-C, -U):
 * a dealer that sends one seat nothing of its own, with the exchange
 * toward that seat dark, leaves that seat holding every other unit,
 * owing nothing and saying nothing, and the unit it was never dealt
 * comes by the others' legs alone, whenever the exchange returns.
 * Every communication is a Figure 1 of the library's: nothing is
 * invented and nothing is asked.  A seat that does not fold an instance
 * launches nothing after it.
 * RECOVERY is the exchange carried to one seat.  A row naming a
 * position this seat retains is evidence, and the question is the one a
 * live row asks: does this seat have a machine to deal with it?  A
 * recover leg's row is fed to its machine, the initiator's INITIAL
 * opening one here, at a position folded here or not.  Any other row is
 * its sender's, nothing where its own word says it is owed nothing here (a
 * later position named, or HOLDING on the legs run toward it): else, where
 * no recover leg of this seat's runs toward that
 * seat at the position, this seat starts them, for every member X whose
 * unit it holds under X's agreed value, its own among them, one
 * bracha87Fig1 point to point, n = 2 and t = 0, this seat initiating
 * and the sender, the returner, the other process: v = X's agreed
 * value, and beside it this seat's unit of X -- the exchange unit
 * re-masked for the returner, or its own distribution's unit to it --
 * and the position's DESCRIPTION, its subset and every member's agreed
 * value.  No recover leg of X's value goes to X, which dealt it.  It is
 * BPR's like any leg: re-sent to the returner until its HOLDING, the
 * unit and the description held, or its abandon count, after which the
 * next row naming the position, HOLDING unheard, starts it again, the same v and the same
 * bytes beside it; what an abandoned machine received goes with it, and
 * the record stays.  The seat holding the record never runs the
 * agreement again: recovery has no consensus to reach.  A part of a
 * member's distribution to this seat landing after the record was
 * written goes into the ring too, a newer copy of the record at the
 * head, the first keeping the position's place in the ring's order.
 * The head overwriting that first record at the retention's tail is
 * this seat's abandon of the position, and the only forgetting.  A row
 * is a row "received at previous steps" [Bracha87 Section 2.1] whenever
 * it lands.  COMPLETE: the seat's own agreement, on the others' rows;
 * or, whichever comes first, and where the others' agreements are gone
 * the only way, DISCOVER: T descriptions alike, from distinct seats,
 * beside their recover legs or alone [the chain's own count, since the library agrees
 * values and never what rides beside one: at most t seats are faulty
 * and T > t, so one of the T is a correct seat's, and a correct seat
 * describes only what its agreement decided, the same at every correct
 * seat; the count is of the in-tag senders the dealt tier verified, a
 * description being no Figure 1 value].  The seat folds, mints the next
 * name, launches the next and reads what it held under that name.
 * Nothing is launched on silence, and nothing is let go on it.  A seat
 * behind the oldest record is beyond the retention: partitioned until
 * the operator intervenes.
 *
 * THE FIGURE, in Bracha's form: one seat, rows of in / condition / out.
 * Every out is on this seat's own state or on one received row.  No row
 * waits on a named seat or reads absence.
 *
 *   The chain seat (by seat p).  n seats, t faulty, n > 3t.
 *   Positions named by the chain: the genesis, then each fold's link;
 *   L live positions, those whose machines run here; a retention of M
 *   bytes of records.
 *   State: C, the chain's head here, the name of the next position.
 *          Per live position, by name: the ACS seat; a leg (X, p) per
 *          member X whose unit p holds, each recording its holders;
 *          a recipient of s's recover leg of X, opened by its INITIAL.
 *          Per record, the positions that left the live window, the
 *          newest over the oldest, by name: the subset, every member's
 *          agreed value, the book at the launch, the units p held of
 *          the members, p's own distribution; and p's recover legs
 *          toward the seats whose rows named it, and the recipients of
 *          the recover legs toward p.
 *          Rows held under names p has not minted, by sender and
 *          shape, L + 1 names of each.
 *          Per seat s: the high water of its signing offset; what s's
 *          rows cost or broke here, and the tick
 *          its rows last landed in each window (acSeatCounters):
 *          each a count under a name, the in-tag sender or the signer,
 *          never a finding about the seat.
 *
 *   in                      condition                        out
 *   -------------------------------------------------------------------------
 *   go                      --                               launch ACS(genesis) with
 *                                                            proposal: (initial, v)
 *                                                            and the unit to all
 *   available; row under    the newest position folded       launch ACS(C) with the
 *   C from s; a row under a here                             proposal: the caller's
 *   name not minted here,                                    message asked, or the noop
 *   arrived since the last
 *   launch
 *   ACS(a) SUBSET           --                               COMPLETE(a)
 *   ACS(a) ABANDON          a unfolded here                  p's value broadcast
 *                                                            alone, a Figure 1, till
 *                                                            a folds here
 *   S's recover leg's       a live here, no subset, T        COMPLETE(a) on that
 *   description under a     held alike from distinct S       description: DISCOVER
 *   row under a from s      a live here                      feed its machine
 *   recover row under a     a recorded here                  feed its machine; an
 *   from s                                                   INITIAL opens one
 *   other row under a       a recorded here                  no recover leg of p's
 *   from s                                                   toward s running: start
 *                                                            them; a unit part of a
 *                                                            member a's record keeps:
 *                                                            placed there; holding
 *                                                            nothing for s: its
 *                                                            description alone
 *   row under a from s      a neither live nor recorded      hold, L + 1 names of the
 *                                                            shape per s, till a is
 *                                                            minted here
 *   sweep                   --                               every machine's re-sends
 *                                                            to its non-holders; count
 *
 *   COMPLETE(a): fold a from the sign parts held under the agreed
 *   values: C := H(C || subset || every member's hash); launch a leg (X, p) for
 *   every member X whose unit is held under the value accepted here:
 *   (initial, apex) and the unit to all, to X the INITIAL alone;
 *   assemble at T; report; if the caller has said it has a message, or
 *   a rotation left out is presented again, or a row under C is held, or a row under a name not minted here arrived
 *   since the last launch, launch ACS(C) under the keys as this fold
 *   left them, and read the rows held under C.  The oldest live
 *   position, folded with every machine abandoned, leaves the live
 *   window: the last pass, the reports, its record goes to the
 *   retention with the assembly of a member still under threshold
 *   or whose last pass this seat's memory refused, and the current step moves over the link it minted; a record the
 *   head overwrites steps the floor over its link, and reports a member
 *   it kept.
 *
 * The thresholds are the papers' and cryptoMule's: the subset is the
 * library's n - t; assembly is T, and so is DISCOVER, T descriptions
 * alike.  Nothing else counts anything but sweeps, and every machine's
 * count is the deployment's abandon.  A seat that folded has its legs
 * launched once to all and re-sent to the non-holders [Lemma 4 under
 * loss], each retired by HOLDING, the directed seat's own word, or by
 * its count; its ACS seat re-sends on to the seats not recorded as
 * having its rows the same way.  A seat behind keeps its ACS seat: the
 * others' re-sends carry it to the same COMPLETE [Lemma 3, and the
 * agreement property of the BA]; where the others' machines are gone,
 * its rows start the others' recover legs toward it from their records,
 * and DISCOVER is its only COMPLETE.  A Byzantine seat can send any row
 * under any name: a seat that never says HOLDING costs every other seat
 * one re-send a tick of what it is owed, for the abandon; a row under a
 * name not yet minted costs a held row, L + 1 names of each shape per
 * sender, which the figure holds anyway; one row under C, a class 0 row
 * with no payload will do, launches the next position here once the
 * newest has folded, whether or not its sender proposes there: a
 * position of N agreements with what this seat's caller gives when
 * asked as its input, its noop where it has nothing, a payload slot of
 * this seat's signing context spent on it, so a new context minted
 * every 2^s such positions -- which is exactly what any seat's message
 * costs every other seat, and a seat may propose at every fold
 * (launchOnRows counts them); a row naming a record this seat holds
 * starts this seat's recover legs toward its sender, point to point,
 * one a member, re-sent to that seat alone for the abandon, and its
 * next row after that starts them again: an abandon of re-sends to
 * itself a row, and no other seat pays; and a description of its own
 * costs a held hash, one per seat a position, and moves nothing short
 * of T alike, which t seats cannot make.  It moves no value, no subset
 * and no key.  The harness's arm (-b): one seat says HOLDING of
 * nothing, names its agreement rows at random and its own broadcast
 * after a record, and the cost is read in that seat's row of the table,
 * the sweeps' rows to it among them.
 * A seat returning from behind the live window pays its own way: it
 * proposes at every position it recovers, each complete elsewhere -- a
 * slot of its context a position, its noop or what its caller gives
 * when asked, or a proposal presented again, a rotation or the caller's
 * same bytes -- and sends the N - 1 units of it to seats that fold
 * nothing on them, a position a round trip for the length of its gap.
 * Outside the figure: more than t seats silent at once, and a seat
 * behind the oldest record, both the operator's.
 *
 * THE ROTATION AND THE SIGNING BUDGET.  A signing context has 2^s
 * one-time slots: slot 0 signs its successor's public key and nothing
 * else, the rest sign payloads, one an instance.  A seat makes one
 * proposal an instance, in this order: a rotation the last subset left
 * out, presented again, the same value under the same signature, slot 0
 * being one-time (a noop left out is let go instead, since agreeing it
 * would buy nothing, and a payload left out is kept, presented again
 * only where the caller, asked, gives the same bytes); else, its
 * context spent, the SWITCH to the successor its agreed rotation
 * installed; else, its context's rotation not yet made, the ROTATION --
 * a successor context is generated and the hash of the seat's key, slot
 * 0 and the successor's is the value of the seat's distribute Fig 1,
 * one sign sidecar beside it [successor key][signature at slot 0], the
 * same bytes to every seat, with no blob, no shards, no masks and no
 * data sidecar;
 * else the caller asked (propose): the same bytes as the payload kept,
 * that payload presented again at its slot; nothing, the NOOP -- the
 * hash of its key and that slot is the value, one sign sidecar beside
 * it [signature at the next payload slot], the signature alone: the
 * slot is spent, so the context's clock keeps its instance cadence;
 * else a payload at the next slot, the value its apex, two sidecars
 * beside it.  So instance 1 is every seat's rotation, and a context of
 * 2^s slots lasts 2^s instances.  EVERY VALUE COMMITS ITS SIGNER AND
 * ITS SLOT [cryptoMule README, Message attribution]: the preimage
 * starts with the signing context's key and the slot the signature
 * yields, then what the sidecar carries -- for a payload orig_hash and
 * the two roots, for a rotation the successor key, for a noop nothing,
 * and for a rotation or a noop carrying the caller's end the end's byte
 * last -- so one value is one signing at one slot, whoever carries it.
 * A sign sidecar is parsed by its SHAPE, never by a mode: exactly
 * SigLen is a noop; exactly HashSz + SigLen a rotation, the successor
 * key; either one byte longer, the end's byte last, the same carrying
 * the end; exactly a payload's fixed part a payload, the signed header;
 * anything else refused, and a shape at the other kind's slot refused,
 * 0 being the rotation's and no other's.  A rotation's successor is
 * installed from the held sidecar, never read off the value.  A
 * rotation or a noop rides as a payload does -- its Fig 1, its ACCEPT
 * as Q(X), its legs at SUBSET, where any holder forwards the same bytes
 * -- and is assembled at ONE verified sidecar, or at none.  Every seat
 * keeps a BOOK: X's key, dealt, and the successor X's agreed rotation
 * installed.  An instance takes both as its ROOTS at its launch, and a
 * signature of X in it must extract to one of them; under the
 * successor, X has switched.  The book moves only at the FOLD, the
 * agreement, so at the same instance at every seat: a member signed
 * under its successor is PROMOTED, a rotation member's successor
 * INSTALLED, a noop member moves nothing.  The link is over the subset
 * and every member's hash as the chain's report carries it, the subset
 * since two members may say the same bytes, a payload's message hash, a
 * rotation's or a noop's value: every fold mints one, since the link is
 * the next position's name, and the mask keys step on every link;
 * identity advances on rotations, in the book.
 * The value the ACS agrees is a hash alone, the same shape for a
 * payload's apex, the hash of a rotation's key, slot and successor and
 * the hash of a key and slot: what a hash IS, the sign part a seat
 * validated for it says, by its format, never the value or a tag.
 * Accepting a value is holding that sign part (the beside flag) or
 * being carried to the accept by the others' readies, so at the fold,
 * once a sign part under every member's value has landed, by the dealer
 * or by a leg, each member's kind, the context that signed it and, for
 * a payload, the message hash in its signed header are here, and the
 * fold reads them from the held sign parts.
 *
 * THE SHAPE, from one seat.  Each seat's proposal is the value it
 * broadcasts inside Agreement[Q], and Q(j) is the seat's accept of j's.
 *
 *   distribute   the ACS seat's value broadcast of X, round 0 of (X, X):
 *                v = X's apex, the hash of X's key, slot and successor
 *                or the hash of X's key and slot, a hash alone, and X's
 *                unit to this seat as the message beside X's
 *                (initial, v), in
 *                sidecars: the SIGN part -- for a payload the signed
 *                header, the signature, the masked [seed][share] and
 *                both proofs, one fixed size; for a rotation
 *                [key][signature], for a noop [signature], shorter --
 *                and, for a payload only, the DATA part -- the clear
 *                shard alone, the one shard-sized message.  The three
 *                messages arrive in any order and are stashed.  That
 *                something rides beside is declared to the library at
 *                Init, for the ACS seat's value broadcasts and for
 *                every leg, since it cannot be inferred from arrival.
 *                The library holds the first (initial, v) from X
 *                whenever it lands; the seat holds the sign part of X
 *                that passes receive's gates under that v -- the first
 *                to pass while no v is held yet, a part under the v
 *                replacing one held under another apex, a part not
 *                under the v refused -- and the shard that verifies
 *                under its root, in either order (a shard ahead of its
 *                sign is stashed unjudged), and feeds BESIDE once it
 *                holds what the sign part's format announced.  A shard
 *                that fails its root is refused, the sign kept for the
 *                re-send.  Once X's value is agreed here a unit of X is
 *                taken only under the agreed value.  X's accept here is
 *                Q(X) = 1, inside the library.  The gate is step 1's
 *                initial enabling alone: a seat does not echo X's
 *                (initial, v) without validating the unit beside it,
 *                and the figure's other two ways in, enough echoes or
 *                readies from the others, run as printed.  So a seat X
 *                never dealt to, or dealt a unit that fails its gates,
 *                is carried to the same accept by the others (Lemma 3,
 *                Theorem 1 as printed), holds X's value and no unit,
 *                initiates no leg for X, and takes X's signed header
 *                and X's parts from the exchange.
 *   agreement    one bkr94acs seat an instance, values of HashSz
 *                bytes, beside 1 (a value's (initial, v) waits for its
 *                unit; nothing rides beside a BA broadcast), 85 phases
 *                of three rounds, the byte, the patience the tick
 *                derives (acDerive), and no abandon count: it runs
 *                until its subset is had, the round ceiling its one
 *                exit before that, and this seat lets it go at the
 *                deployment's abandon once it has the subset.  Let go
 *                with the position unfolded, its own value broadcast
 *                runs on alone, a Figure 1 of the same (initial, v)
 *                under the same tag with the same unit beside it,
 *                started again at its count while the position is
 *                unfolded here.
 *                The coin is the caller's randomness (acCb.random),
 *                local to the seat.  SUBSET
 *                comes with every member's value accepted here.
 *                A pass: for every live instance, bkr94acsSweep until it
 *                returns 0, and one BRACHA87_SWEEP to each of its legs
 *                and recover legs, and to those of every record.
 *                A tick starts a pass; one that falls due inside a pass
 *                starts the next when this one ends, so the seat's tick
 *                count is its pass count.  A position launched under a
 *                tick before is passed over: the tick is one feedback
 *                cycle, so nothing it said can have drawn its answer.
 *   exchange     at SUBSET: for every member X and every S != X one
 *                standalone leg Fig 1 (X, S), initiator S, all started
 *                at that instant, with the deployment's abandon for its
 *                count: a leg re-sends to the seats not recorded as
 *                HOLDING until then.
 *                This seat initiates (X, self) only holding X's unit
 *                under the value this seat accepted for X: v = that
 *                value's apex, and the unit re-masked for each recipient
 *                in the EXCH domain beside its INITIAL, the same
 *                sidecars, gated at the recipient as the distribute unit
 *                is.  HOLDING on a leg means the unit held.  X gets the
 *                INITIAL alone, since it dealt the unit and holds it,
 *                and feeds its own BESIDE under its own apex.  An
 *                exchange unit is verified and held whenever it lands,
 *                SUBSET or not; a row under a name this seat has not
 *                minted is one received at a previous step: held, and
 *                read as an arrival when the position launches, one a
 *                call, as acInput takes one datagram, so the caller
 *                reads its socket between them.
 *   assemble     X from the parts held under the agreed hash, once this
 *                seat's ACS is COMPLETE with X in the subset, and not
 *                before: parts can land first, from faster seats' legs,
 *                and nothing acts on them until then.  A rotation or a
 *                noop is whole in any one sign part held under its
 *                value.  A payload's pool is a share from every held
 *                sign part and a shard from every held shard, the own
 *                unit's among them, in arrival order; at T of each it
 *                is SEARCHED and, after PASS, re-encoded, as
 *                cryptoMule's assemble does [cryptoMule assemble.c],
 *                the search run at every arrival.  The commitment is
 *                reported consistent or
 *                not, with every leaf held by then named off the
 *                re-encode, and an inconsistent one is no seat's
 *                message: which seats reproduce the hash is which
 *                leaves reach them, so none delivers it.  No message is
 *                reported too, each its own word: every subset tried
 *                at threshold (exhausted: no subset reproduces the
 *                hash); the try budget spent at threshold (shown
 *                nothing either way); or under threshold when the
 *                retention lets the position's record go, the search's
 *                last pass over what is held.  A member under
 *                threshold when the position leaves the live window
 *                keeps its assembly with the record, which places a
 *                part of it still landing, a message received all the
 *                same [Bracha87 Section 3: "including those received at
 *                previous steps"]; nothing is sent for it.  Reaching
 *                threshold there with no message found, it waits an
 *                abandon past its last new part, then has that same
 *                last pass.  A last pass
 *                this seat's memory refuses is kept the same way, the
 *                pass taken again at every tick, and only where the
 *                memory refuses it still when the retention lets the
 *                record go is the member reported with no verdict.  Self holds
 *                its own message by construction.
 *   the fold     once SUBSET is held, every member's value is the ACS's
 *                for it, and the sign part held under it says the
 *                member's kind and context and, for a payload, the
 *                message hash.  The chain's head, the subset and every
 *                member's hash in subset order -- a payload's message hash, a
 *                rotation's or a noop's value, the report's hash column
 *                -- hash into one link, the new head, which is the next
 *                position's name, and every pair's mask key for the
 *                positions after it is HKDF(key, link || 'R').  As in
 *                cryptoMule [cryptoMule README, Forward secrecy], the
 *                chain folds message hashes, never apexes, and one
 *                instance's whole flow runs under one mask step.  The
 *                seat holds TWO keys per pair, as cryptoMule's
 *                keystate holds its current step and its retention
 *                floor: the CURRENT
 *                STEP, the oldest live position's, from which any live
 *                position's is walked forward over the links of the
 *                positions before it, and the FLOOR, the oldest
 *                record's, from which a record's is walked over the
 *                records before it when its machines run; each walked at
 *                first use and held with its position until it is let
 *                go.  When a position leaves the live window
 *                the current step moves over the link it minted; when
 *                its record leaves the retention the floor does, and
 *                the masks under the key before that step cannot be
 *                made here again.
 *   the reports  two kinds, both in MESSAGE hashes, as the messages
 *                flow.  The chain's, once an instance, at the fold,
 *                which is ACS COMPLETE: the chain hash before the
 *                instance, every member's hash -- a payload's message
 *                hash, a rotation's or a noop's value -- and the chain
 *                hash after it.  The messages', once a member, at that
 *                member's verdict here -- the message at its PASS,
 *                judged over every leaf held by then, or why none --
 *                or, no verdict yet, when the retention lets the
 *                position's record go, the search's last pass over
 *                what is held: the
 *                chain hash before the instance, the member's hash, and
 *                the message or why none -- never held for the others,
 *                since some come only by recovery.
 *   the end      the live window: a position folded here leaves it once
 *                every machine of it has reached its count, and what its
 *                legs carried goes to the retention as its record, which
 *                the newest record overwrites in its turn.  Nothing of a
 *                position is let go on account of what the other seats
 *                say or do not say: the counts, the deployment's, and
 *                then memory alone, by age alone, the retention's.
 *                Memory refused stops nothing: a row is refused and its
 *                sender's sweep brings it again (rowMem); a step of this
 *                seat's own -- a launch, a leg, a record -- spends
 *                nothing and waits for the seat's next call (ownMem),
 *                and a search for the next tick (asmAlloc).
 *                Before it leaves, every member without a verdict gets
 *                the search's last pass and its report, but one under
 *                threshold, whose assembly goes with the record until
 *                the retention lets it go.
 *   behind       an ACS seat not yet complete while the others folded
 *                is behind, and the seat cannot tell by how much.
 *                Receiving noise, it does nothing new: the same seat
 *                re-sends what it owes, its own value broadcast among
 *                it, under the same tags, on the figure's own cadence,
 *                until its count; and the others' ACS seats there, live
 *                until theirs, re-send what it has not acknowledged,
 *                which carries it to the same
 *                subset [Lemma 3; the BA's agreement].  Its agreement
 *                there runs until it has the subset, never abandoned
 *                before it and never started again: a fresh one would
 *                say again under the same tags what it may have said
 *                otherwise before.  Nothing is launched after an
 *                unfolded instance.
 *   returning    a seat behind the others' live windows has their
 *                machines gone for its position; its own machines
 *                there re-send at every tick, and each of its rows
 *                lands at a seat holding the position's record as
 *                evidence there, which starts that seat's recover legs
 *                toward it where none runs: point to point, one a
 *                member whose unit that seat holds, each INITIAL, unit
 *                and description re-sent to it alone until its HOLDING
 *                or the abandon, and started again by its next row
 *                naming the record.  The agreements are never started
 *                again and nothing re-runs an agreement: the returning
 *                seat's own agreement there may never complete, and it
 *                does not need to.  It DISCOVERs the subset from T
 *                seats' descriptions alike, one of them a
 *                correct seat's, holds a sign part under every member's
 *                value and the units to assemble from, folds, mints the
 *                next name, launches the next on its caller's word, a
 *                rotation presented again, or the rows it holds under
 *                that name, and so walks a
 *                position a round trip; its own legs there, launched
 *                late, land at seats that let the position go as rows
 *                naming a record, which hold nothing for them, so they
 *                re-send to those seats for their count.  The others,
 *                meanwhile, wait their patience on it at every round,
 *                since it is silent at their positions, and that slows
 *                the frontier to about the returning seat's pace: it is
 *                what lets the seat behind catch up at all, and no
 *                evidence a seat has may skip it, a seat coming back
 *                looking like one merely slow.
 *                What closes the gap is the returning seat's side: a
 *                position it DISCOVERs waits no patience at all, and
 *                at positions whose machines still run at the others,
 *                their re-sends take over.  A seat whose head
 *                position folded with every holder recorded, nothing
 *                pending, and the position after it gone from the
 *                others' windows before any row of it arrived says
 *                nothing of its own; the others' live rows, under
 *                names it has not minted, are its reason to launch the
 *                next position, whose rows then start the others'
 *                recover legs toward it from their records.  A member
 *                still under threshold when its position leaves this
 *                seat's window has its record place what still lands
 *                until the retention lets the record go, and only then
 *                does the report say under threshold.
 *                Participating, returning, partitioned:
 *                the three windows, and the third is the operator's to
 *                see, from the chain the reports publish, since a row
 *                under a name a seat has neither minted nor kept is one
 *                it cannot place.  The three windows are nothing else.
 *
 * THE CRYPTOGRAPHY is cryptoMule's construction [cryptoMule cm.h, the
 * head comment; the why, cryptoMule README], made natively over the
 * sibling primitives (rsec/rsecMk, sss/sssMk, mls, huf, the hash repos'
 * HMAC and HKDF) with the caller's hash suites (acHash).  Here:
 *   distribute  the apex is the v of X's value broadcast, not a message
 *               of its own, and the unit to j is two messages: the sign
 *               part -- the signed header, the signature, [seed][share_j]
 *               masked under PSK(X, j) in the DIST domain and both
 *               Merkle proofs -- and the data part, the clear shard_j.
 *               A rotation's one message: [successor key][signature over
 *               H(key || slot || successor key)]; a noop's: [signature
 *               over H(key || slot)]; carrying the end, either with the
 *               end's byte after it and last in the preimage.
 *   receive     the sign part, gate by gate (AC_UNIT_*): its length, by
 *               shape, which says the kind (LEN); the value recomputed
 *               under each of X's keys in the book in turn and the
 *               signature extracting it to that same key, at the kind's
 *               slot (SIG); for a payload, unmasked, the share's leaf
 *               under the code points its seed derives against
 *               sssmk_root (SSS).  The data part, once the sign part is
 *               held: the shard against rsecmk_root at its own length
 *               (RSEC).  The order and the reasons are cryptoMule's
 *               [cryptoMule receive.c], ahead of them one of this
 *               file's: a sign part whose value, recomputed, cannot be
 *               the one it must be is refused unchecked.  A part that
 *               fails a gate is counted by the gate and not held.  A
 *               verified sign part not under the (initial, v) the
 *               instance holds is refused, a part held or not; one
 *               under it replaces a part held under another apex; with
 *               no v held yet the first stays.  A unit held is what the
 *               sign part's format announced, and nothing is acted on
 *               until this seat's ACS is COMPLETE with X in the subset.
 *   exchange    the held unit forwarded: the same header, signature,
 *               shard and proofs, [seed][share] re-masked under
 *               PSK(S, j) in the EXCH domain; verified at j by the same
 *               gates, the leaf now S's.
 *
 * THE WIRE.  Neither library sends anything of its own: the seat's only
 * wire actions are the INITIAL, ECHO, READY and BESIDE of a Fig 1
 * instance.  The RSEC tag is this file's, 5 bytes and a hash (21 at
 * rmd128, 37 at sha256) at every hash:
 *
 *   [byte][ba][round][initiator][sender][name]
 *
 *   byte bits 0-1  INITIAL / ECHO / READY / BESIDE (BRACHA87_*)
 *   byte bits 2-3  class 0: the BA value, BKR94ACS_V0..D1; classes 1
 *                  to 3: bit 2 on a READY, the sender holds the
 *                  initiator's (initial, v) and what rode beside it
 *                  (BRACHA87_ANN_HOLDING); on a BESIDE the part: 0 the
 *                  sign, 1 the data, and on class 3 alone 2 the
 *                  description; 0 otherwise
 *   byte bits 4-5  the class: 0 an ACS row (ba, q, k >= 1), 1 the ACS
 *                  value broadcast of X (round 0 of (X, X)), 2 the leg
 *                  (X, S), 3 the recover leg (X, S) to the returner R
 *   byte bits 6-7  the annotations the instance frames
 *                  (BRACHA87_ANN_*): on a READY, bit 6 the sender has
 *                  accepted, bit 7 the sender holds the recipient's
 *                  accept; on an ECHO, bit 6 the sender holds the
 *                  initiator's (initial, v) and what rode beside it,
 *                  bit 7 0; 0 on INITIAL and BESIDE.  A class 0 READY
 *                  has no room for HOLDING; its ECHO carries it
 *   ba             the agreement: ba / X
 *   round          k, 1..3 x phases / 0 / 0 / R
 *   initiator      q / X / S / S
 *   sender         from: the sender byte the message's HMAC is verified
 *                  under, never the source address
 *   name           the position's name: the chain hash before it, the
 *                  sign role's width
 *   payload        none on a class 0 row; v (HashSz) on INITIAL, ECHO
 *                  and READY of classes 1 to 3; on BESIDE one part of
 *                  the unit, from X on class 1, from S on classes 2 and
 *                  3, or on class 3 the position's description: the
 *                  subset's bitmap, then every member's agreed value in
 *                  seat order
 *
 * The BA value is in the tag, not a payload: the value is part of the
 * message's identity, so a BPR re-send is the same bytes under the same
 * tag and the framer complements one reassembly.  A READY's two bits
 * are in the tag too, so a re-send whose bits moved is a new message to
 * the framer, delivered whole, not a late fragment of the old one.  The
 * name is under the message's MAC because the mac mesh is static, and it
 * is the sender's word, unsigned: a lie in it misroutes the liar's own
 * row into a machine where the figure counts that sender once.  It is
 * the chain hash and not a number because a number is a counter with a
 * wrap and the chain has no bounded length, and not a byte of one
 * because a byte names a position only within a window of its period
 * and needs that window to place it.  cryptoMule carries no link, a
 * holder of the previous link recomputing it from the fold [cryptoMule
 * README, The wire at its minimum]; here several positions are live at
 * once and a seat must route a row before it can recompute anything, so
 * the link rides, public as the chain the reports publish.  Refused
 * from the tag alone, ahead of any Input and counted: bits 6-7 set on
 * INITIAL or BESIDE, or bit 7 on ECHO, or bit 2 on an INITIAL or ECHO
 * of classes 1 to 3; class 0 needs round 1..3 x phases, initiator and
 * sender below n, no payload, and its INITIAL from the initiator; class
 * 1 needs round 0, initiator == ba, INITIAL and BESIDE from X only;
 * class 2 needs round 0, initiator != ba, INITIAL and BESIDE from S
 * only, and a unit's part not to its dealer; class 3 needs S and R
 * distinct and below n, the row between them and this seat one of them,
 * ba != R, INITIAL and BESIDE from S only, and a description of a
 * bitmap and up to N values.  A recover leg's two processes are S, 0,
 * and R, 1: n = 2, t = 0.
 *
 * The transport: the caller's UDP socket, one a seat, and the RSEC
 * framer (rsecFrm.h) driven by the seat's pass, with its halfsiphash
 * DoS gate on each datagram, and past it cryptoMule's authenticated
 * channel on each message [cryptoMule README, An authenticated channel]:
 * the kdf hash's HMAC under the pairwise secret of the in-tag sender,
 * over the tag and the payload, run only where the machine the tag names
 * would record what it carries.  Both are keyed by slices of one dealt
 * pairwise secret whose third slice is the mask key.  UDP has no back pressure: the deployment states the bandwidth a
 * seat sends, the bwLimit parameter, and the framer paces every
 * message's shards to it.  The caller owns the wire, and a datagram the
 * kernel drops is loss like any other.  The operator deals the secrets
 * and the addresses through the caller (acDeal); each seat mints its
 * own MLS context and publishes only its public key (acPub).  Nothing
 * is ever on disk.
 *
 * Decomposition: one seat, driven by its caller's loop -- acInput for
 * each datagram that arrives, acWork for the pass -- with its own
 * framers, ACS seat, n distribute instances and its legs, its own row
 * of the mesh, MLS context, blob and retention; self is a recipient
 * like any other, by a local hand-back.  Nothing the seat says is sent
 * where it fires: a step's send is marked owed on its instance, a sweep
 * pass is a cursor over the instances, and the pass holds one message,
 * and one report, at a time.  The held message goes to the framer
 * first, so no flood of arrivals keeps the seat from talking; while the
 * framer's table is full the seat reads, so it hears through whatever
 * it has to say.  What is waiting for the wire is state on the
 * instances, the framer's table and the one sweep step in hand, bounded
 * by them; only the hand-backs to self are queued.  The END is the
 * caller's word to the chain, not to the seat: from acEnd on, every
 * value the seat signs carries it, and the chain ends at the first fold
 * whose subset holds more than t members carrying it, the same position
 * and final hash at every correct seat that folds it; nothing launches
 * after it, and the seat runs its end -- the last link to its count and
 * every member of it reported, then its record carrying a seat behind
 * for an abandon -- and goes quiet of its own accord.  acQuiet is the
 * caller's local stop: nothing more said, the framer drained at its
 * pace, a silence to the others.
 */

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include "huf.h"
#include "sss.h"
#include "sssMk.h"
#include "rsec.h"
#include "rsecMk.h"
#include "mls.h"
#include "bracha87Fig1.h"
#include "bkr94acs.h"
#include "halfsiphash.h"
#include "rsecFrm.h"
#include "ac.h"
#include "acTest.h"

/* ac.h names the said counters' kinds for callers that never read the
 * agreement library's header: they are its kinds, or this fails to
 * compile */
typedef char acKindsAreBracha87[AC_KIND_INITIAL == BRACHA87_INITIAL && AC_KIND_ECHO == BRACHA87_ECHO
                              && AC_KIND_READY == BRACHA87_READY && AC_KIND_BESIDE == BRACHA87_BESIDE ? 1 : -1];

#define DEF_PHASES    85         /* the byte's all: the coin is each seat's
                                  * own, so a split BA ends a phase only when
                                  * the honest coins agree by chance, and the
                                  * ceiling is paid in seats, never in phases */
#define MSG_MAX       65536      /* a wire message: within what 256 RSEC
                                  * shards of a ~500-byte datagram carry
                                  * (acDerive refuses a dgramMax that cannot) */

/*
 * The construction's constants, with the hash roles chosen at run time
 * (-H, -k): the SIGN role (the apex, the MLS signature and public key,
 * orig_hash, both Merkle trees) needs a power-of-two width, which MLS
 * and the Merkle plugs address by its exponent; the KDF role
 * (keystream, mask, geometry) and the wire MAC do not.  The mask
 * domains keep a payload's distribute and exchange keystreams apart on
 * one key step.
 */
#define VALMATCH(v, d) (!memcmp((v), (d)->apex, HashSz))
#define KEY_LEN    32                    /* keystream key K == share length */
#define SEED_LEN   16                    /* the hidden geometry seed */
#define MVAL_LEN   (SEED_LEN + KEY_LEN)  /* [seed][share], masked as one */
#define DOM_DIST   'D'
#define DOM_EXCH   'X'
#define DOM_KEY    'K'
#define DOM_GEO    'G'
#define DOM_RAT    'R'
#define END_MARK   'E'                   /* a value carrying the end: its byte,
                                          * last in its preimage and its shape */
#define KDF_MAX    (255 * AC_HASH_MAX)   /* one HKDF call's ceiling, at the
                                          * widest suite; KdfMax is the run's */

/*
 * The dealt pairwise secret, one per unordered pair, carved into three
 * slices no third seat holds: the message HMAC key, the DoS gate key,
 * and the mask IKM both phases key on.
 */
#define PSK_HMAC_SIZE 64
#define PSK_HASH_SIZE HALFSIPHASH_KEY_SZ
#define PSK_MASK_SIZE 64
#define PSK_HMAC_OFF  0
#define PSK_HASH_OFF  PSK_HMAC_SIZE
#define PSK_MASK_OFF  (PSK_HMAC_SIZE + PSK_HASH_SIZE)
#define PSK_SIZE      (PSK_MASK_OFF + PSK_MASK_SIZE)
typedef char acPskSized[PSK_SIZE == AC_PSK ? 1 : -1];  /* the header's number is this one */

#define GATE_SIZE  HALFSIPHASH_HSH_SZ    /* datagram GATE: halfsiphash */
#define PROOF_MAX  (8 * AC_HASH_MAX)     /* a proof at R <= 255 leaves: 8 levels;
                                          * acDerive checks the size functions against it */

/* the BRACHA87_ANN_* bits a tag byte carries, by class and kind: a
 * READY's two in bits 6-7 and, outside class 0, HOLDING in bit 2; an
 * ECHO's HOLDING in bit 6 */
#define AC_TAG_TO_ANN(b) (AC_TAG_KIND(b) == BRACHA87_READY \
  ? (AC_TAG_ANN(b) | (AC_TAG_CLASS(b) && (AC_TAG_VALUE(b) & 1) ? BRACHA87_ANN_HOLDING : 0)) \
  : AC_TAG_KIND(b) == BRACHA87_ECHO && (AC_TAG_ANN(b) & 1) ? BRACHA87_ANN_HOLDING : 0)
#define HOLDS(st) (((st) & (BRACHA87_F1_INITIAL | BRACHA87_F1_BESIDE)) == (BRACHA87_F1_INITIAL | BRACHA87_F1_BESIDE))

/* recipient j's leaf in X's distribution: the n-1 others in order */
#define LEAF(x, j) ((j) < (x) ? (j) : (j) - 1)
/* the exchange unit of X held at that leaf, in the N x (N - 1) table */
#define EXCH(in, x, leaf) ((in)->exch[(x) * (N - 1) + (leaf)])
/* the leg (x, s) in the N x N of them; then this seat's recover leg of
 * x to the returner r, and s's recover leg of x to this seat, N x N
 * each */
#define LEG(in, x, s)  ((in)->leg[(x) * N + (s)])
#define ROUT(in, x, r) ((in)->leg[N * N + (x) * N + (r)])
#define RIN(in, x, s)  ((in)->leg[2 * N * N + (x) * N + (s)])
/* a seat's process in a recover leg initiated by i: i is 0, the
 * returner 1 */
#define FIDX(seat, i)  ((seat) == (i) ? 0 : 1)

/* the search's one try budget per member, shares and shards together,
 * cryptoMule's (CM_SEARCH_TRIES, cm.h) */
#define SEARCH_TRIES  65536

/* what this seat has fed a standalone instance */
#define FED_INITIAL 0x01
#define FED_BESIDE  0x02

#define TABLE_SIZE 256           /* in-flight messages a framer paces, both
                                  * directions */

#define GET32(p)   (((unsigned long)(p)[0] << 24) | ((unsigned long)(p)[1] << 16) | ((unsigned long)(p)[2] << 8) | (p)[3])
#define PUT32(p, v) ((p)[0] = ((v) >> 24) & 0xff, (p)[1] = ((v) >> 16) & 0xff, (p)[2] = ((v) >> 8) & 0xff, (p)[3] = (v) & 0xff)
#define GET16(p)    (((unsigned int)(p)[0] << 8) | (p)[1])
#define PUT16(p, v) ((p)[0] = ((v) >> 8) & 0xff, (p)[1] = (v) & 0xff)

/* the tag: the byte, the four bytes of Bracha's tag -- the agreement,
 * the round, the initiator, the sender -- and the position's name, the
 * chain hash before it (acTest.h) */
#define TagSz       (AC_TAG_SIZE(HashSz))

/*
 * A record in the retention: what a position's machines start again
 * from, on a row naming it, for the seats that return: a re-send is the
 * same bytes [cryptoMule README, Forward secrecy].  Its length first (a
 * length of 0 is the retention wrapping to its start), its name and the
 * link it minted, the subset, the value this seat accepted for each
 * agreement, the book at the launch -- every member's contexts before
 * it, its key and the successor installed -- which verifies a part
 * landing for the position then, then a member for every member whose
 * sign part this seat held: the seat, its kind, 1 where it was signed
 * under the member's successor, the shard length, 0 where the shard was
 * not held, five hashes (the value, the message hash, both roots, the
 * successor), the signature, then for a payload the clear
 * [seed][share], both proofs and the shard -- for this seat's own,
 * every recipient's leaf, proofs and shard.  A sign part alone is a
 * share for a returning seat's search, as it is for the live one's.
 * A part of a member's distribution to this seat landing after the
 * record was written goes into the ring too: a newer copy of the
 * record, with it, at the head.  The first stays the position's place
 * in the ring's order, which the key floor steps in, and its
 * overwriting is the position's let-go; a copy's is its bytes alone.
 */
#define REC_LEN     0
#define REC_NUM     4                    /* this seat's count of the
                                          * position, the released report's */
#define REC_NAME  8
#define REC_LINK    (8 + HashSz)
#define REC_MEMB    (8 + 2 * HashSz)     /* two bytes: up to every seat */
#define REC_SUBSET  (10 + 2 * HashSz)    /* BITS(N) */
#define REC_HASVAL  (REC_SUBSET + BITS(N))
#define REC_VALS    (REC_HASVAL + BITS(N))
#define REC_GEN     (REC_VALS + N * HashSz)  /* N x 4: the book at the launch,
                                              * every member's contexts before it, */
#define REC_ROOT    (REC_GEN + 4 * N)        /* N x HashSz: its key, */
#define REC_ROOTN   (REC_ROOT + N * HashSz)  /* N x HashSz: its successor, */
#define REC_HASN    (REC_ROOTN + N * HashSz) /* BITS(N): where one was installed: what
                                              * verifies a part landing for the
                                              * position when its machines start again */
#define REC_COPY    (REC_HASN + BITS(N))     /* 0 the position's place in the
                                              * ring's order, 1 a newer copy */
#define REC_HDR     (REC_COPY + 1)
/* the description of a position: its subset's bitmap, then every
 * member's agreed value in seat order; at most this long */
#define DESC_MAX    (BITS(N) + N * HashSz)
#define RM_SEAT     0
#define RM_KIND     1                     /* the kind, RM_END beside it */
#define RM_NEXT     2
#define RM_SHLEN    3
#define RM_APEX     7
#define RM_HDR      (7 + 5 * HashSz)     /* then the signature */
#define RM_END      0x80                  /* RM_KIND's bit: the value carries the end */
#define RM_LEAVES   ((N - 1) * (MVAL_LEN + 2 * PfSz))
/* a member's length past its header and signature */
#define RM_BODY(kind, own, shardLen) ((kind) ? 0 : (own) \
  ? RM_LEAVES + (N - 1) * (shardLen) : MVAL_LEN + 2 * PfSz + (shardLen))

/* the chain ended here, its last link gone from the live window an
 * abandon ago: nothing new starts */
#define END_SHUT(V)  ((V)->lastLink && (V)->lastGone && (V)->ticks - (V)->lastGone >= Abandon)
#define MlsPlug      (V->mlsPlug)
#define SssPlug      (V->sssPlug)
#define RsecPlug     (V->rsecPlug)


static const char *
kindName(
  unsigned char kind
){
  switch (kind) {
  case BRACHA87_INITIAL: return ("INITIAL");
  case BRACHA87_ECHO:    return ("ECHO");
  case BRACHA87_READY:   return ("READY");
  case BRACHA87_BESIDE:  return ("BESIDE");
  default:               return ("???");
  }
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


/*------------------------------------------------------------------------*/
/*  The primitives, plugged.                                              */
/*------------------------------------------------------------------------*/

/* one sign-role hash over up to four buffers: 0, or -1 with o untouched
 * where the suite's context could not be allocated, this seat's memory */
static int
hashBuf(
  const struct acPar *S
 ,const unsigned char *a
 ,unsigned int al
 ,const unsigned char *b
 ,unsigned int bl
 ,const unsigned char *c
 ,unsigned int cl
 ,const unsigned char *d
 ,unsigned int dl
 ,unsigned char *o
){
  void *h;

  if (!(h = malloc(Sign->tsize())))
    return (-1);
  Sign->init(h);
  if (al)
    Sign->update(h, a, al);
  if (bl)
    Sign->update(h, b, bl);
  if (cl)
    Sign->update(h, c, cl);
  if (dl)
    Sign->update(h, d, dl);
  Sign->final(h, o);
  free(h);
  return (0);
}

static const unsigned char EndMark[1] = { END_MARK };

/* a value's hash [cryptoMule cmApex, cmApexRot]: the signer's key, the
 * signing offset four bytes big-endian, then up to three buffers.  The
 * value commits the offset as it commits the key, so one value is one
 * signing at one offset, whoever carries it */
static int
apexBuf(
  const struct acPar *S
 ,const unsigned char *k
 ,unsigned int off
 ,const unsigned char *b
 ,unsigned int bl
 ,const unsigned char *c
 ,unsigned int cl
 ,const unsigned char *d
 ,unsigned int dl
 ,unsigned char *o
){
  void *h;
  unsigned char ob[4];

  if (!(h = malloc(Sign->tsize())))
    return (-1);
  ob[0] = off >> 24;
  ob[1] = off >> 16;
  ob[2] = off >> 8;
  ob[3] = off;
  Sign->init(h);
  Sign->update(h, k, HashSz);
  Sign->update(h, ob, sizeof (ob));
  if (bl)
    Sign->update(h, b, bl);
  if (cl)
    Sign->update(h, c, cl);
  if (dl)
    Sign->update(h, d, dl);
  Sign->final(h, o);
  free(h);
  return (0);
}

/*
 * The trees: an AVL tree (Adelson-Velsky and Landis), balanced and
 * iterative over parent pointers, drawn from memDta's avl and made for
 * this seat's keys.  A node lies inside the entry it orders, a held row
 * or a record's index entry, so a tree allocates nothing of its own;
 * its key is a first byte, as the tree reads it, then the tree's length
 * of the entry's own bytes, then an arrival number.  A lookup and an
 * update are logarithmic in what is held whatever the keys, so no
 * sender's choice of names lengthens one past that and the L + 1 names
 * a shape holds.
 */
struct tnod {
  struct tnod *left;
  struct tnod *right;
  struct tnod *parent;
  const unsigned char *key;           /* the key's bytes after the first */
  void *own;                          /* the entry the node lies in */
  unsigned long seq;                  /* the key's last part: an arrival number, or 0 */
  unsigned char k0;                   /* the key's first byte, as the tree reads it */
  signed char bal;                    /* the left subtree's height less the right's */
};

struct tree {
  struct tnod *root;
  unsigned long len;                  /* the key's bytes after the first */
};

static int
tCmp(
  const struct tree *t
 ,const struct tnod *a
 ,const struct tnod *b
){
  int c;

  if (a->k0 != b->k0)
    return (a->k0 < b->k0 ? -1 : 1);
  if ((c = memcmp(a->key, b->key, t->len)))
    return (c);
  return (a->seq < b->seq ? -1 : a->seq > b->seq);
}

/*
 * Right rotation:
 *       y            x
 *      / \          / \
 *     x   C  ->    A   y
 *    / \              / \
 *   A   B            B   C
 */
static void
tRotR(
  struct tree *t
 ,struct tnod *y
){
  struct tnod *x;
  struct tnod *p;

  x = y->left;
  p = y->parent;
  y->left = x->right;
  if (x->right)
    x->right->parent = y;
  x->right = y;
  y->parent = x;
  x->parent = p;
  if (!p)
    t->root = x;
  else if (p->left == y)
    p->left = x;
  else
    p->right = x;
}

/*
 * Left rotation:
 *     x              y
 *    / \            / \
 *   A   y    ->    x   C
 *      / \        / \
 *     B   C      A   B
 */
static void
tRotL(
  struct tree *t
 ,struct tnod *x
){
  struct tnod *y;
  struct tnod *p;

  y = x->right;
  p = x->parent;
  x->right = y->left;
  if (y->left)
    y->left->parent = x;
  y->left = x;
  x->parent = y;
  y->parent = p;
  if (!p)
    t->root = y;
  else if (p->left == x)
    p->left = y;
  else
    p->right = y;
}

/* a node in, its key unique in the tree */
static void
tIns(
  struct tree *t
 ,struct tnod *new
){
  struct tnod *n;
  struct tnod *p;
  int c;

  c = 0;
  p = 0;
  for (n = t->root; n; n = c < 0 ? n->left : n->right) {
    c = tCmp(t, new, n);
    p = n;
  }
  new->left = new->right = 0;
  new->parent = p;
  new->bal = 0;
  if (!p) {
    t->root = new;
    return;
  }
  if (c < 0)
    p->left = new;
  else
    p->right = new;
  /* rebalance from the new node toward the root */
  n = new;
  while (p) {
    if (p->left == n)
      ++p->bal;
    else
      --p->bal;
    if (!p->bal)
      break;                            /* the subtree's height is unchanged */
    if (p->bal == 1 || p->bal == -1) {
      n = p;                            /* taller: on up */
      p = p->parent;
      continue;
    }
    if (p->bal == 2) {
      if (n->bal == -1) {               /* left-right */
        struct tnod *x;
        struct tnod *y;

        x = n;
        y = n->right;
        tRotL(t, x);
        tRotR(t, p);
        p->bal = y->bal == 1 ? -1 : 0;
        x->bal = y->bal == -1 ? 1 : 0;
        y->bal = 0;
      } else {                          /* left-left */
        tRotR(t, p);
        p->bal = n->bal = 0;
      }
    } else {
      if (n->bal == 1) {                /* right-left */
        struct tnod *x;
        struct tnod *y;

        x = n;
        y = n->left;
        tRotR(t, x);
        tRotL(t, p);
        p->bal = y->bal == -1 ? 1 : 0;
        x->bal = y->bal == 1 ? -1 : 0;
        y->bal = 0;
      } else {                          /* right-right */
        tRotL(t, p);
        p->bal = n->bal = 0;
      }
    }
    break;
  }
}

/* a node out: one with two children has its in-order successor, which
 * has no left child, relinked into its place -- the node lies in its
 * entry, so there is no item to swap -- and the rebalance starts where
 * the successor was taken from */
static void
tDel(
  struct tree *t
 ,struct tnod *n
){
  struct tnod *p;
  struct tnod *r;
  struct tnod *s;
  int fromLeft;

  fromLeft = 0;
  if (n->left && n->right) {
    for (s = n->right; s->left; s = s->left)
      ;
    if (s->parent == n) {
      p = s;                            /* n's right subtree loses its root */
      fromLeft = 0;
    } else {
      p = s->parent;
      fromLeft = 1;
      p->left = s->right;
      if (s->right)
        s->right->parent = p;
      s->right = n->right;
      n->right->parent = s;
    }
    s->left = n->left;
    n->left->parent = s;
    s->parent = n->parent;
    if (!n->parent)
      t->root = s;
    else if (n->parent->left == n)
      n->parent->left = s;
    else
      n->parent->right = s;
    s->bal = n->bal;
  } else {
    r = n->left ? n->left : n->right;
    p = n->parent;
    if (r)
      r->parent = p;
    if (!p)
      t->root = r;
    else if ((fromLeft = p->left == n))
      p->left = r;
    else
      p->right = r;
  }
  /* rebalance from p toward the root */
  while (p) {
    if (fromLeft)
      --p->bal;
    else
      ++p->bal;
    if (p->bal == 1 || p->bal == -1)
      break;                            /* the height is unchanged */
    if (!p->bal) {
      n = p;                            /* shorter: on up */
      if ((p = p->parent))
        fromLeft = p->left == n;
      continue;
    }
    if (!fromLeft) {                    /* the right shortened: the left two taller */
      n = p->left;
      if (n->bal == -1) {               /* left-right */
        struct tnod *y;

        y = n->right;
        tRotL(t, n);
        tRotR(t, p);
        p->bal = y->bal == 1 ? -1 : 0;
        n->bal = y->bal == -1 ? 1 : 0;
        n = y;
        n->bal = 0;
      } else {                          /* left-left */
        tRotR(t, p);
        if (!n->bal) {
          p->bal = 1;
          n->bal = -1;
          break;                        /* the height is unchanged */
        }
        p->bal = n->bal = 0;
      }
    } else {
      n = p->right;
      if (n->bal == 1) {                /* right-left */
        struct tnod *y;

        y = n->left;
        tRotR(t, n);
        tRotL(t, p);
        p->bal = y->bal == -1 ? 1 : 0;
        n->bal = y->bal == 1 ? -1 : 0;
        n = y;
        n->bal = 0;
      } else {                          /* right-right */
        tRotL(t, p);
        if (!n->bal) {
          p->bal = -1;
          n->bal = 1;
          break;
        }
        p->bal = n->bal = 0;
      }
    }
    if ((p = n->parent))
      fromLeft = p->left == n;
  }
}

/* the least node at or after the key, or 0 */
static struct tnod *
tLow(
  const struct tree *t
 ,const struct tnod *key
){
  struct tnod *n;
  struct tnod *m;

  for (m = 0, n = t->root; n;)
    if (tCmp(t, key, n) <= 0) {
      m = n;
      n = n->left;
    } else
      n = n->right;
  return (m);
}

/* the node after n in key order, or 0 */
static struct tnod *
tNext(
  struct tnod *n
){
  struct tnod *p;

  if (n->right) {
    for (n = n->right; n->left; n = n->left)
      ;
    return (n);
  }
  for (p = n->parent; p && n == p->right; p = p->parent)
    n = p;
  return (p);
}

/* XOR buf in place with HKDF(k, nonce || 'K' || seg), one call per
 * chunk */
static void
keystream(
  const struct acPar *S
 ,const unsigned char *k
 ,const unsigned char *nonce
 ,unsigned char *buf
 ,unsigned int len
){
  unsigned char info[AC_HASH_MAX + 1 + 4];
  unsigned char ks[KDF_MAX];
  unsigned int seg;
  unsigned int off;
  unsigned int chunk;
  unsigned int j;

  memcpy(info, nonce, HashSz);
  info[HashSz] = DOM_KEY;
  for (seg = 0, off = 0; off < len; ++seg, off += chunk) {
    chunk = len - off;
    if (chunk > KdfMax)
      chunk = KdfMax;
    info[HashSz + 1] = seg >> 24;
    info[HashSz + 2] = seg >> 16;
    info[HashSz + 3] = seg >> 8;
    info[HashSz + 4] = seg;
    Kdf->hkdf(k, KEY_LEN, info, HashSz + 1 + 4, ks, chunk);
    for (j = 0; j < chunk; ++j)
      buf[off + j] ^= ks[j];
  }
  memset(ks, 0, sizeof (ks));
}

/* the SSS code points from the hidden seed, cryptoMule's cmGeometry
 * (cm.h): pts[0] the secret point, pts[1..n-1] the R output points */
static void
geometry(
  const struct acPar *S
 ,const unsigned char *seed
 ,unsigned int n
 ,unsigned char *pts
){
  unsigned char info[2];
  unsigned char st[KDF_MAX];
  unsigned int got;
  unsigned int seg;

  memset(pts, 0, n);
  info[0] = DOM_GEO;
  for (got = 0, seg = 0; got < n; ++seg) {
    unsigned int i;

    info[1] = seg;
    Kdf->hkdf(seed, SEED_LEN, info, sizeof (info), st, KdfMax);
    for (i = 0; i < KdfMax && got < n; ++i) {
      unsigned int e;

      for (e = 0; e < got && pts[e] != st[i]; ++e)
        ;
      if (e == got)
        pts[got++] = st[i];
    }
  }
  memset(st, 0, sizeof (st));
}

/* XOR buf in place with HKDF(ikm, apex || dom || idx): the pairwise
 * mask */
static void
mask(
  const struct acPar *S
 ,const unsigned char *ikm
 ,const unsigned char *apex
 ,unsigned char dom
 ,unsigned char idx
 ,unsigned char *buf
 ,unsigned int len
){
  unsigned char info[AC_HASH_MAX + 1 + 1];
  unsigned char m[MVAL_LEN];
  unsigned int j;

  memcpy(info, apex, HashSz);
  info[HashSz] = dom;
  info[HashSz + 1] = idx;
  Kdf->hkdf(ikm, PSK_MASK_SIZE, info, HashSz + 1 + 1, m, len);
  for (j = 0; j < len; ++j)
    buf[j] ^= m[j];
  memset(m, 0, sizeof (m));
}

/*
 * A T-subset of h parts in whack-a-mole order [cryptoMule assemble.c]:
 * a bad part among the first T is whacked out within 1 + T x (h - T)
 * tries wherever it sits.  Two instances run nested (shares outside,
 * shards inside), which is why the state is a struct and not the
 * enclosing frame.  sel receives the subset; 0 once every subset has
 * been produced.
 */
struct comb {
  unsigned int *sel;                  /* T: the subset, indices into 0..h-1 */
  unsigned int *a;                    /* d: positions among the first T swapped out, ascending */
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
  for (i = c->d; i-- > 0;)            /* next d-subset of the first T, the rest from its start */
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

/*------------------------------------------------------------------------*/
/*  The seat's state.                                                     */
/*------------------------------------------------------------------------*/

/* a hand-back: this seat's own INITIAL, ECHO or READY to itself */
struct msg {
  unsigned int  inst;                 /* the position, this seat's own number */
  unsigned char byte;                 /* the tag byte: class, kind, value, a READY's bits */
  unsigned char process;
  unsigned char round;
  unsigned char initiator;
  unsigned char v[AC_HASH_MAX];       /* at round 0: the hash */
};

/* this seat's own distribution, as distribute leaves it */
struct own {
  unsigned char *sig;                 /* SigLen */
  unsigned char *shards;              /* R * shardLen: data, then parity */
  unsigned char *sig0;                /* -f 7: the apex signed again, at slot 0 */
  unsigned char *sig1;                /* -f 8: the apex signed again, under the
                                       * successor; -f 10: at the next slot */
  unsigned int   shardLen;            /* 0: a rotation or a noop */
  unsigned int   off;                 /* the slot it was signed at */
  unsigned int   ref;                 /* the instances presenting it, and the seat
                                       * while it is not agreed */
  int            underNext;           /* signed by the context this seat switched
                                       * to, not yet promoted to at the others */
  unsigned char  kind;                /* 0 a payload, AC_ROTATION, AC_NOOP */
  unsigned char  end;                 /* a rotation or noop carrying the end */
  unsigned char  apex[AC_HASH_MAX];   /* the value: signed, agreed */
  unsigned char  succ[AC_HASH_MAX];   /* a rotation's successor key: the value's
                                       * preimage after the key and slot */
  unsigned char  origHash[AC_HASH_MAX];
  unsigned char  sssRoot[AC_HASH_MAX];
  unsigned char  rsecRoot[AC_HASH_MAX];
  unsigned char  tab[1];              /* the R leaves, clear [seed][share_i], then
                                       * their sss proofs, then their rsec proofs,
                                       * sized by the run (OWN_*) */
};
#define OWN_SZ          (sizeof (struct own) + (N - 1) * (MVAL_LEN + 2 * PfSz))
#define OWN_LEAF(o, i)  ((o)->tab + (i) * MVAL_LEN)
#define OWN_SSSPF(o, i) ((o)->tab + (N - 1) * MVAL_LEN + (i) * PfSz)
#define OWN_RSECPF(o, i) ((o)->tab + (N - 1) * (MVAL_LEN + PfSz) + (i) * PfSz)

/* a row received at a previous step [Bracha87 Section 3]: one under a
 * name neither live nor recorded here, held to count when this seat
 * mints the name; the name is in its tag.  It lies in two trees: by its
 * name and its arrival, for the launch that mints the name, and by its
 * shape and its name, for one sender's rows of a shape under other
 * names; a seat behind holds tens of thousands, and a walk over all of
 * them at every arrival is what a slow host cannot pay */
struct ahead {
  struct tnod    byName;              /* the name, then the arrival */
  struct tnod    byShape;             /* the shape -- the tag byte's naming bits, a BESIDE's part
                                       * among them, and its four bytes -- then the name */
  unsigned char *b;
  unsigned int   len;
  unsigned char  part;                /* a unit part: the reconciliation's */
};
/* the tag of a held row, and its name */
#define AHEAD_TAG(a)    ((a)->b + 1 + (a)->b[0])
#define AHEAD_NAME(a) (AHEAD_TAG(a) + AC_TAG_NAME)
/* a record by its name: where it lies in the retention, and the
 * position's assembly where a member left the live window under
 * threshold, or its machines rebuilt from the record for recover legs */
struct recIx {
  struct tnod    byName;
  struct inst   *kept;
  unsigned long  off;                 /* the newest copy */
  unsigned long  anchor;              /* the first: the position's place in the ring's order */
  unsigned char  done[1];             /* BITS(N): the seats whose own word says they are owed
                                       * nothing here (recHeard); then BITS(N): those whose
                                       * recover legs here were answered; then BITS(N): those
                                       * this record holds nothing to carry to, its
                                       * description alone owed them (DESC_OWED) */
};

/* a standalone Fig 1 instance and what this seat fed it, live until the
 * position leaves the live window, a recover leg until its record's
 * machines are let go */
struct gate {
  struct bracha87Fig1 *f;
  unsigned char fed;                  /* FED_INITIAL, FED_BESIDE */
  unsigned char owed;                 /* OWED(kind): taken, not yet said */
  unsigned char v[AC_HASH_MAX];       /* the v fed from the INITIAL */
};

/* X's distribute instance here, and X's unit to this seat as held: the
 * sign part first, verified alone, the shard under its root; held is
 * what the kind needs */
struct dist {
  unsigned char *sig;                 /* SigLen; the exchange unit carries it on */
  unsigned char *shard;               /* shardLen */
  unsigned char *stash;               /* a shard landed ahead of its sign part, unjudged */
  unsigned int   shardLen;
  unsigned int   stashLen;
  unsigned int   off;                 /* the signing offset the signature was made at */
  unsigned char  apex[AC_HASH_MAX];   /* the value, recomputed from what the part carries */
  unsigned char  succ[AC_HASH_MAX];   /* a rotation's successor key: the value's
                                       * preimage after the key and slot */
  unsigned char  origHash[AC_HASH_MAX];
  unsigned char  sssRoot[AC_HASH_MAX];
  unsigned char  rsecRoot[AC_HASH_MAX];
  unsigned char  unit[MVAL_LEN];      /* clear [seed][share_self] */
  unsigned char  sssProof[PROOF_MAX];
  unsigned char  rsecProof[PROOF_MAX];
  unsigned char  scp;
  unsigned char  ocp;
  unsigned char  underNext;           /* signed under X's successor: X has switched */
  unsigned char  kind;                /* 0 a payload, AC_ROTATION, AC_NOOP */
  unsigned char  end;                 /* a rotation or noop carrying the end */
  unsigned char  sign;                /* the sign part held */
  unsigned char  held;                /* and the shard under its root, for a payload */
  unsigned char  fedBeside;           /* the unit fed beside X's (initial, v) */
  unsigned char  accepted;            /* X's value accepted: Q(X) = 1 here */
};

/*
 * S's exchange unit of X, by S's leaf in X's distribution.  Its signed
 * header rides with it: an exchange unit can land before this seat has
 * accepted X's, and the apex it verified under is what assembly matches
 * against, so each held unit carries its own, laid out ahead of the
 * shard: [apex][what hashes to it][shard] -- a payload's orig_hash,
 * sssmk_root and rsecmk_root, the header from the sign part, or a
 * rotation's successor key, or nothing for a noop, three hash widths
 * every way -- the shard grown on when the data part verifies.
 */
struct exch {
  unsigned char *buf;                 /* 4 * HashSz + shardLen, held */
  unsigned char *stash;               /* a shard landed ahead of its sign part, unjudged */
  unsigned int   shardLen;
  unsigned int   stashLen;
  unsigned int   off;
  unsigned char  unit[MVAL_LEN];      /* clear [seed][share_S] */
  unsigned char  rsecProof[PROOF_MAX];/* from the sign part, for the shard's gate */
  unsigned char  scp;
  unsigned char  ocp;
  unsigned char  underNext;           /* signed under X's successor: X has switched */
  unsigned char  kind;                /* 0 a payload, AC_ROTATION, AC_NOOP */
  unsigned char  end;                 /* a rotation or noop carrying the end */
  unsigned char  sign;                /* the sign part held */
  unsigned char  held;                /* and the shard under its root, for a payload */
};
#define EX_APEX(e)  ((e)->buf)
/* VALMATCH for an exchange unit, whose apex is in its buffer */
#define VALMATCHX(v, e) (!memcmp((v), EX_APEX(e), HashSz))
#define EX_ORIG(e)  ((e)->buf + HashSz)
#define EX_SUCC(e)  ((e)->buf + HashSz)  /* a rotation's successor key,
                                          * where a payload's header starts */
#define EX_SSS(e)   ((e)->buf + 2 * HashSz)
#define EX_RSEC(e)  ((e)->buf + 3 * HashSz)
#define EX_SHARD(e) ((e)->buf + 4 * HashSz)

/*
 * The search over X's parts in hand, carried across arrivals: the pool
 * in arrival order, the K candidates found and the shard pool each was
 * searched against, so an arrival tries only the subsets that touch it.
 * The arrays are one block, carved, allocated when X first has a part
 * to search.
 */
struct search {
  unsigned char *triedK;              /* kcap x KEY_LEN: the K candidates, in the
                                       * order found; one block with the two below,
                                       * grown as found: every candidate cost a try,
                                       * so the try budget bounds them, never a list */
  unsigned char *kSel;                /* kcap x T: each candidate's share subset, pool indices */
  unsigned char *kSearched;           /* kcap: the shard pool size each
                                       * candidate was searched against */
  unsigned char *shareLeaf;           /* R: the share pool, leaves in
                                       * arrival order; one block with */
  unsigned char *shardLeaf;           /* R: the shard pool */
  unsigned int   cs;                  /* shares in the pool */
  unsigned int   cd;                  /* shards */
  unsigned int   csOld;               /* the share pool the last search saw */
  unsigned int   nK;
  unsigned int   nKold;               /* the candidates before the pass at T + 1
                                       * shares: it keeps its own only by a PASS */
  unsigned int   kcap;
  unsigned int   tries;
  unsigned int   partAt;              /* the tick the pool last grew */
  unsigned char  relaxed;             /* the pass without agreement: at T + 1 shares
                                       * over the new subsets, its candidates kept
                                       * only by a PASS; at the end over every subset */
  unsigned char  owed;                /* a search this seat's memory refused: tried again */
  unsigned char  final;               /* the position leaving the live window, or the retention
                                       * letting the record go: the last pass over what is held */
  unsigned char  kept;                /* under threshold at the position's end, or its
                                       * last pass owed: the record places its parts */
  unsigned char  reported;            /* X's second report is out */
  unsigned char  inconsistent;        /* the hash reproduced: a re-encode off a signed root */
  unsigned char  badShares[BITS(AC_SEATS)];       /* then held leaves off the re-encode */
  unsigned char  badShards[BITS(AC_SEATS)];
};

/*
 * One instance at one seat, a position of the live window: its ACS
 * seat, its n distribute instances and its legs, this seat's own
 * distribution in it, what it holds of the others', and what its
 * instances owe.  Its mask key per pair is walked from the seat's floor
 * at first use (keyWalk) and held here (kc) until the position is let
 * go.  Its tables lie over one block allocated at its launch, or a
 * record's machines' at the row naming the record, freed with it when
 * it is let go (instFree).
 */
struct inst {
  struct bkr94acs *a;                 /* the ACS seat, live until the
                                       * position leaves the live window */
  unsigned short  *oAcs;              /* [ba][q][k], k 0..Rounds: OWED, and the values */
  unsigned char   *rAcs;              /* [to], RACS_ROW each: a reply the library returned
                                       * on an arrival from to, owed it alone, a bit at
                                       * 2 (k N^2 + ba N + q) + kind - ECHO, the round
                                       * outermost, so the rounds in hand lead the row;
                                       * then
                                       * (RAVAL) [ba][q][k] the values replied, the
                                       * ECHO's in bits 0-1, the READY's in 2-3 */
  unsigned char   *blob;              /* this seat's message of this instance, MsgMax */
  unsigned int     blobLen;
  struct gate     *leg;               /* [X][S], N x N, f 0 until SUBSET; then the
                                       * recover legs, ROUT and RIN, N x N each */
  struct exch     *exch;              /* [X][leaf], N x (N - 1) */
  struct dist     *dist;              /* [X], N */
  struct search   *srch;              /* [X]: the search over X's parts in hand */
  unsigned char  **msg;               /* [X]: X's message, assembled, until the report */
  unsigned int    *msgLen;
  struct own      *own;               /* this seat's proposal */
  /* every table below lies over tab, the position's one block
   * (instCarve): pointers, structs, ints, bytes */
  unsigned char   *tab;
  /* the book as it stood at the launch: every signature of X in this
   * instance extracts to ROOT(X), or to ROOTNEXT(X) where one is
   * installed, and gen[X] counts X's contexts before it */
  unsigned int    *gen;
  unsigned int    *rDueG;             /* [to]: the replies owed it, of the legs */
  unsigned int    *rDueA;             /* and of the ACS instances */
  unsigned char   *root;              /* X x HashSz */
  unsigned char   *rootNext;
  /* X's value as this seat holds it, accepted here by the ACS seat:
   * what the fold, assembly and the reports read */
  unsigned char   *val;               /* X x HashSz */
  unsigned char   *dHash;             /* S x HashSz: the hash of the
                                       * description S's recover legs carried */
  unsigned char   *kc;                /* j x PSK_MASK_SIZE: the position's mask key with j,
                                       * walked once (keyWalk) and wiped with the position */
  unsigned char   *hasNext;
  unsigned char   *hasVal;
  unsigned char   *verdict;
  unsigned char   *promoted;          /* X was promoted at this fold */
  unsigned char   *isRot;             /* X was assembled as a rotation */
  unsigned char   *isNoop;            /* X was assembled as a noop */
  unsigned char   *asmDue;            /* a part of X landed, or SUBSET,
                                       * or the position's end: try */
  unsigned char   *entered;           /* this seat entered X's agreement on X's value */
  unsigned char   *round;             /* the round X's agreement decided at here */
  unsigned char   *dHeld;             /* S's recover legs' description held, its hash in dHash */
  unsigned char   *kcOk;              /* j's key is in kc */
  unsigned char   *acc;               /* 1: j's value accepted here; 2:
                                       * its agreement entered 0 here */
  unsigned char   *subset;            /* BITS(N) */
  unsigned char   *rLeg;              /* [to], RLEG_ROW each: a reply owed it of a leg,
                                       * a bit at 2 ix + kind - ECHO, ix among the 3N^2 */
  unsigned char   *rCopy;             /* copyBudget's, made on the first */
  unsigned int     rcvMem;            /* a recover leg its memory refused: no one's word covers it */
  unsigned int    *rCopyAt;
  unsigned long    puts;              /* messages of this instance Put */
  unsigned long    gets;              /* rows and units of it taken */
  unsigned long    nmtUs;             /* when its (n - t)th agreement decided 1 here */
  unsigned long    launchUs;          /* when it launched here */
  unsigned int     num;               /* 1.. : this seat's launch count, the
                                       * position's number in reports and records */
  unsigned int     aOwed;             /* ACS instances owing */
  unsigned int     gOwed;             /* standalone instances owing */
  unsigned int     aScan;
  unsigned int     gScan;
  unsigned int     subsetCnt;
  unsigned int     launchTick;
  unsigned int     subsetTick;
  unsigned int     ones;              /* its agreements decided 1 here */
  unsigned int     nmtTick;           /* the tick the (n - t)th of them did */
  unsigned int     foldTick;
  unsigned int     legCnt;            /* standalone instances made, recover legs among them */
  unsigned int     legGone;           /* and at their abandon count */
  int              haveSubset;
  int              subsetDue;
  int              acsAbandoned;      /* its agreement let go, its subset had, or at the ceiling */
  int              ceiling;           /* abandoned at the round ceiling */
  int              acsSubset;         /* its ACS seat returned SUBSET: here or after a DISCOVER */
  int              ownDue;            /* launched, its value broadcast waits
                                       * for the talk with no pass in hand */
  int              recovered;         /* the subset from T descriptions alike */
  int              stepped;           /* folded: the book moved, the link minted */
  int              last;              /* the chain's last link: more than t members carry the end */
  int              again;             /* this seat's proposal is presented again: a rotation,
                                       * or a payload the caller gave the same bytes of */
  int              ending;            /* leaving the live window: the last pass and the
                                       * reports first */
  struct recIx    *rx;                /* left the live window, its assembly kept: its record */
  int              gone;              /* and the retention let the record go: the last pass */
  int              loaded;            /* this seat's units of the members taken from the record */
  int              recDue;            /* a part of this seat's distribution placed past
                                       * the position's end, its member reported or not:
                                       * the record's copy due */
  unsigned int     endTick;           /* the tick it left the live window */
  unsigned int     lagUntil;          /* -z: the tick its INITIAL is held to */
  unsigned int     rot;               /* members that are rotations */
  unsigned int     noop;              /* members that are noops */
  unsigned int     promo;             /* members signed under their successor */
  int              switched;          /* this seat switched at this launch */
  int              asked;             /* the caller asked at this launch: once, its message
                                       * kept while the launch waits on this seat's memory */
  unsigned char    link[AC_HASH_MAX];       /* the link it minted: the next position's name */
  unsigned char    launched;                /* this seat's value broadcast made (step 0) */
  unsigned char    reported0;               /* the chain's report of this instance is out */
  unsigned char    prev[AC_HASH_MAX];       /* the chain hash at its launch: its name */
};
/* a seat's row of reply bits: over the ACS instances, over the legs */
#define RACS_ROW    BITS(2 * N * N * (Rounds + 1))
#define RLEG_ROW    BITS(6 * N * N)
#define RAVAL(in)   ((in)->rAcs + N * RACS_ROW)
/* the block the tables by X lay over: N pointers, 4N ints, 4N hashes, N
 * mask keys, 12N bytes, the subset's bitmap and the legs' reply bits */
#define INST_TAB_SZ (N * sizeof (unsigned char *) + N * sizeof (struct dist) \
                     + 3 * N * N * sizeof (struct gate) + N * (N - 1) * sizeof (struct exch) \
                     + N * sizeof (struct search) + 4 * N * sizeof (unsigned int) \
                     + 4 * N * HashSz + N * PSK_MASK_SIZE + 12 * N + BITS(N) + N * RLEG_ROW)
#define ROOT(in, x)     ((in)->root + (x) * HashSz)
#define ROOTNEXT(in, x) ((in)->rootNext + (x) * HashSz)
#define VAL(in, x)      ((in)->val + (x) * HashSz)

/* one holder of a proposal lets go; the last frees it */
static void
ownDrop(
  const struct acPar *S
 ,struct own *o
){
  if (!o || --o->ref)
    return;
  memset(o->tab, 0, (N - 1) * MVAL_LEN);  /* the leaves: the shares */
  free(o->sig);
  free(o->sig0);
  free(o->sig1);
  free(o->shards);
  free(o);
}

/* a position's tables laid over its one block, by alignment: the
 * pointer arrays, the structs (each holds a pointer, so its size is a
 * multiple of one), the ints, the bytes */
static void
instCarve(
  const struct acPar *S
 ,struct inst *in
 ,unsigned char *tab
){
  in->tab = tab;
  in->msg = (unsigned char **)tab;
  in->dist = (struct dist *)(in->msg + N);
  in->leg = (struct gate *)(in->dist + N);
  in->exch = (struct exch *)(in->leg + 3 * N * N);
  in->srch = (struct search *)(in->exch + N * (N - 1));
  in->msgLen = (unsigned int *)(in->srch + N);
  in->gen = in->msgLen + N;
  in->rDueG = in->gen + N;
  in->rDueA = in->rDueG + N;
  in->root = (unsigned char *)(in->rDueA + N);
  in->rootNext = in->root + N * HashSz;
  in->val = in->rootNext + N * HashSz;
  in->dHash = in->val + N * HashSz;
  in->kc = in->dHash + N * HashSz;
  in->hasNext = in->kc + N * PSK_MASK_SIZE;
  in->hasVal = in->hasNext + N;
  in->verdict = in->hasVal + N;
  in->promoted = in->verdict + N;
  in->isRot = in->promoted + N;
  in->isNoop = in->isRot + N;
  in->asmDue = in->isNoop + N;
  in->entered = in->asmDue + N;
  in->round = in->entered + N;
  in->dHeld = in->round + N;
  in->kcOk = in->dHeld + N;
  in->acc = in->kcOk + N;
  in->subset = in->acc + N;
  in->rLeg = in->subset + BITS(N);
}

/*
 * A position let go: what it allocated is freed, the secrets among it
 * wiped -- the units, the K candidates, a message not yet reported, and
 * the mask keys in its tables.
 */
static void
instFree(
  const struct acPar *S
 ,struct inst *in
){
  unsigned int i;
  unsigned int j;

  if (!in)
    return;
  ownDrop(S, in->own);
  for (i = 0; i < N; ++i) {
    memset(in->dist[i].unit, 0, MVAL_LEN);
    free(in->dist[i].sig);
    free(in->dist[i].shard);
    free(in->dist[i].stash);
    for (j = 0; j < N - 1; ++j) {
      memset(EXCH(in, i, j).unit, 0, MVAL_LEN);
      free(EXCH(in, i, j).buf);
      free(EXCH(in, i, j).stash);
    }
    for (j = 0; j < N; ++j) {
      free(LEG(in, i, j).f);
      free(ROUT(in, i, j).f);
      free(RIN(in, i, j).f);
    }
    if (in->srch[i].triedK)             /* the K candidates */
      memset(in->srch[i].triedK, 0, in->srch[i].kcap * KEY_LEN);
    free(in->srch[i].triedK);
    free(in->srch[i].shareLeaf);
    if (in->msg[i]) {                   /* a message not yet reported */
      memset(in->msg[i], 0, in->msgLen[i]);
      free(in->msg[i]);
    }
  }
  memset(in->tab, 0, INST_TAB_SZ);
  free(in->tab);
  free(in->a);
  free(in->oAcs);
  free(in->rAcs);
  free(in->rCopy);
  free(in->rCopyAt);
  if (in->blob && in->blobLen)
    memset(in->blob, 0, in->blobLen);
  free(in->blob);
  free(in);
}

#ifdef AC_TEST
#define TESTFAULT(V) ((V)->test ? (V)->test->fault : 0)
/* the harness's memory refusing X's search at one allocation, until the
 * position's end keeps X */
#define TESTREFUSE(V, x, s, at) ((V)->test && (V)->test->refuse == (x) + 1 && (V)->test->refuseAt == (at) && !(s)->kept)
#else
#define TESTFAULT(V) 0
#define TESTREFUSE(V, x, s, at) 0
#endif

/* what seat() is entered on */
#define EV_GO    0
#define EV_INPUT 1
#define EV_WORK  2

struct ac {
  struct pskTab            *egrTab;   /* the framers' gate */
  struct pskTab            *igrTab;
  unsigned char            *obuf;     /* the held message, for the egress framer */
  unsigned char            *ubuf;     /* one part of a unit, PartMax, or a description, DESC_MAX */
  unsigned char            *pbuf;     /* the proposal's huffman stream, the ciphertext
                                       * bound: a message past it is refused at the ask */
  void                     *hLink;    /* the fold's link hash: the suite's context, made once */
  struct inst              *launching; /* a launch this seat's memory held: no number, no
                                       * slot spent, taken again at the next call */
  struct msg               *q;        /* the hand-back queue, grows */
  unsigned long            *rttUs;    /* by seat: when this seat's value broadcast's INITIAL
                                       * was first said to it, at instance rttNum */
  unsigned int             *rttNum;
  unsigned char            *rttOpen;  /* its echo of that one not yet in */
  unsigned int             *rowTick;  /* by seat, 1 + the tick its row was last taken
                                       * as word of a name past the rows held; then, by seat,
                                       * the newest position its proven rows have named
                                       * (NAMED): it has folded every one before that; then,
                                       * by seat, 1 + the tick a description alone was last
                                       * owed it (DESC_AT) */
  struct recIx            **descTo;   /* by seat: the record whose description alone it is owed */
  unsigned long            *swUs;     /* by seat: when its sweep was last due */
  unsigned long            *tickNow;  /* by seat, two each: the message bytes sent it and
                                       * completed from it this tick so far */
  unsigned char            *swDue;    /* its sweep due this pass: its least round trip
                                       * has passed since swUs */
  unsigned int              qCap;
  unsigned int              putAt;    /* the held message's why, class and kind: saidBytes */
  unsigned int              qHead;
  unsigned int              qTail;
  unsigned int              fl;       /* the talk's stop: the seat whose replies it serves,
                                       * this seat's own its own word */
  unsigned int              flIdle;   /* the stops passed with nothing since the last turn */
  unsigned int              self;
  unsigned int              ticks;    /* this seat's tick count, the trace's stamp */
  struct inst             **live;     /* the links whose machines run here, oldest first */
  struct inst             **kept;     /* the assemblies records keep, members under
                                       * threshold at their position's end,
                                       * and a record's machines rebuilt for recover legs */
  unsigned int              nKept;
  unsigned int              keptCap;
  /*
   * The retention: the declared bytes holding the records of the
   * positions that left the live window, consecutive from the tail, the
   * oldest, to the head, where the next is written; the newest
   * overwrites the oldest, and the second window ends at the tail.  A
   * record is what this seat's machines for the position start again
   * from, on a row naming it, and run on until the tail passes it.
   */
  unsigned char            *rec;
  unsigned long             recHead;  /* where the next record goes */
  unsigned long             recTail;  /* the oldest record */
  unsigned int              recCount;
  unsigned int              nLive;
  unsigned int              liveCap;
  unsigned int              launched; /* instances launched here */
  unsigned int              folded;   /* instances folded here */
  unsigned int              nAhead;   /* rows held ahead */
  struct tree               ahName;   /* the rows held ahead, by name and arrival */
  struct tree               ahShape;  /* and by shape and name */
  struct tree               recName;  /* the records, by name */
  unsigned long             ahSeq;    /* the arrivals held, numbered */
  mlsCtx_t                  mls;      /* the signing context; the private data is
                                       * owned, wiped at the switch and at exit */
  mlsCtx_t                  mlsNext;  /* its successor, once the rotation is made */
  struct own               *pend;     /* this seat's rotation, until it is agreed:
                                       * excluded, it is presented again */
  struct own               *cache;    /* this seat's payload a subset left out: presented
                                       * again where the caller gives the same bytes */
  unsigned int              slot;     /* the next payload slot of the signing context */
  unsigned int              gen;      /* contexts this seat has spent */
  int                       avail;    /* the caller has a message to propose, with no
                                       * position in hand: the next pass launches one */
  int                       rotated;  /* the signing context's rotation is made */
  unsigned char             cur[AC_HASH_MAX]; /* the signing context's key: every value
                                               * this seat signs is hashed under it first */
  /* the book: pub[X] is X's key, pubNext[X] the successor X's agreed
   * rotation installed, promoted[X] the contexts X has left */
  unsigned char            *pubNext;  /* X x HashSz (PUBNEXT) */
  unsigned char            *hasNext;
  unsigned int             *promoted;
  /*
   * Per seat, what gates its signatures.  The high water is the signing
   * offset, context and slot, of the newest value of X's a SUBSET took,
   * with that value and the last position whose SUBSET took X: it is
   * raised at a fold and nowhere else.  An arriving part is judged
   * against it and moves none of it: at it under the same value is a
   * re-send or a proposal presented again; at or past that position, at
   * it under another value is the one-time slot leaked and below it is
   * an old signature re-dealt, and each is refused.
   */
  unsigned int             *hwGen;
  unsigned int             *hwOff;
  unsigned int             *hwPos;
  unsigned char            *hwApex;   /* X x HashSz (HWAPEX) */
  unsigned char            *hwSet;
  struct acCounters           c;
  struct acSeatCounters    *sc;       /* [X]: what this seat counts of X, by the in-tag
                                       * sender or the signer (SEATC) */
  struct rsecFrmEgr         egr;      /* the framers, this seat's alone */
  struct rsecFrmIgr         igr;
  unsigned char            *psk;      /* X x PSK_SIZE (PSKROW): this row of the mesh */
  unsigned char            *pub;      /* X x HashSz (PUB): the dealt public keys */
  /*
   * The chain and the keys.  chain is the dealt genesis folded, at
   * every fold, with the subset and the members' hashes into the next
   * link, which is the next position's name.  One position's whole flow
   * masks under one key per pair, the DIST and EXCH domains keeping its
   * two keystreams apart, and that key is the dealt one stepped by
   * HKDF(key, link || 'R') over the link of every position before it.
   * Two keys are held per pair, as cryptoMule's keystate holds its
   * current step and its retention floor [cryptoMule README, Forward
   * secrecy]: curIkm, the oldest live position's, from which every live
   * position's is walked forward over the links the live window holds
   * (keyWalk), and floorIkm, the oldest record's, from which a record's
   * is walked over the links of the records before it when its machines
   * run; each walked at first use and held with its position (kc).
   * When a position leaves the live window the current step moves over
   * the link it minted, and when its record leaves the retention the
   * floor does and the position's held keys are wiped, and the masks
   * under the key before that step cannot be made here again: what a
   * seat holds per position is derivable from the floor, and goes with
   * it.
   */
  unsigned char             chain[AC_HASH_MAX];
  unsigned char            *curIkm;   /* X x PSK_MASK_SIZE (CURIKM) */
  unsigned char            *floorIkm; /* X x PSK_MASK_SIZE (FLOORIKM) */
  unsigned char            *tab;      /* the block the tables above lay over (make carves it) */
  struct acPar              p;        /* the run's parameters, S in every seat-side function */
  mlsHsh_t                  mlsPlug;  /* the sign suite as the signature and
                                       * the two Merkle libraries plug it */
  sssMkHsh_t                sssPlug;
  rsecMkHsh_t               rsecPlug;
  const struct acCb        *cb;       /* the application: cbs, copied at acInit */
  struct acCb               cbs;
#ifdef AC_TEST
  struct acTest            *test;     /* the harness's hooks, or 0 */
#endif
  /*
   * The seat's frame across the caller's calls: the message held for
   * the egress framer, the send in hand, the sweep pass and its step,
   * what a launch left.
   */
  struct bkr94acsAct       *acts;
  struct bkr94acsAct       *sActs;    /* the pass's step, ACS */
  struct inst              *heldI;    /* the held message's instance */
  struct inst              *eI;       /* the send in hand's, and the pass's */
  struct gate              *eG;       /* the send in hand: its instance */
  struct gate              *sG;       /* the pass's step, standalone */
  unsigned char            *rwa;      /* the rotation's work area */
  unsigned char            *rtab;     /* the reports' tables by seat: two of
                                       * N x HashSz, N kinds, four bitmaps */
  unsigned long             lastTickUs;
  unsigned long             recvNow;  /* message bytes completed from every seat this tick
                                       * so far */
  unsigned long             egrEndUs; /* when what the framer was given has all left, at its pace */
  unsigned long             talkUs;   /* how far the talk runs ahead of
                                       * the wire: the tick's own send */
  unsigned int              outMax;
  unsigned int              held;     /* the held message's length, in obuf */
  unsigned int              eCls;     /* the send in hand: class, */
  unsigned int              eX;       /* process, */
  unsigned int              eS;       /* initiator, */
  unsigned int              eR;       /* a recover leg's returner, 0 otherwise, */
  unsigned int              eK;       /* round, */
  unsigned int              eKind;    /* kind, */
  unsigned int              eVal;     /* BA value, */
  unsigned int              eJ;       /* the recipient reached, */
  unsigned int              eU;       /* and which part of its unit is next:
                                       * 0 none, 1 the sign, 2 the data */
  unsigned int              eTo;      /* a reply's one recipient */
  unsigned int              swPhase;  /* where the pass is */
  unsigned int              sN;       /* the step's actions */
  unsigned int              sA;
  unsigned int              sI;
  unsigned int              sIx;      /* the pass: which live instance */
  unsigned int              sCls;
  unsigned int              sX;
  unsigned int              sS;
  unsigned int              sR;
  int                       heldUnit; /* the message held is a unit */
  int                       eActive;
  int                       eRecip;   /* the send in hand goes to sRecip only */
  int                       eERecip;  /* or, an ECHO re-send, to sERecip only */
  int                       eSweep;   /* it is a re-send */
  int                       eOne;     /* it is a reply, to eTo alone */
  int                       flGo;     /* the stop took its turn: a message of it left */
  int                       eGate;    /* it is a standalone instance's: a leg, or this seat's
                                       * value broadcast alone */
  int                       eHeardOk; /* it goes to the seats not in eHeard */
  int                       sMore;
  int                       sRecipOk;
  int                       sERecipOk; /* the step's ECHO re-send, to sERecip only */
  int                       talkWork; /* a step's own actions left work, or the pass ended */
  int                       aheadDue; /* a launch: rows held ahead may be its */
  int                       aheadMore; /* this call took one; the next takes the next */
  int                       aheadNew; /* a row under a name neither live nor recorded
                                       * here arrived since the last launch: a position
                                       * past this seat's head at its sender, or a name
                                       * it cannot place */
  int                       ended;    /* the caller's end: every value this
                                       * seat signs from here carries it */
  unsigned int              lastLink; /* the position the chain ended at here, 0 for none yet */
  unsigned int              lastGone; /* the tick that link left the live window, its record the
                                       * retention's: an abandon from it, rows naming a record
                                       * start recover legs, then nothing new starts */
  int                       quiet;    /* the caller's stop: nothing more is
                                       * said, what the framer holds goes */
  int                       failed;   /* a parameter derive validated,
                                       * refused: it goes no further */
  int                       went;     /* acGo given: the seat runs, its first launch made or due */
  int                       launchDue; /* a launch begun and not yet made: its memory refused */
  unsigned char             sOut[BRACHA87_FIG1_OUT];
  unsigned char             sRecip[BITS(AC_SEATS)];
  unsigned char             sERecip[BITS(AC_SEATS)];
  unsigned char             eHeard[BITS(AC_SEATS)];
};
/* the reports' tables over rtab */
#define RT_HASH(V)  ((V)->rtab)
#define RT_SUCC(V)  ((V)->rtab + (V)->p.n * (V)->p.hashSz)
#define RT_KIND(V)  ((V)->rtab + 2 * (V)->p.n * (V)->p.hashSz)
#define RT_BITS(V, k) (RT_KIND(V) + (V)->p.n + (k) * BITS((V)->p.n))
#define RT_END(V)   (RT_BITS(V, 4))
#define RT_SZ(V)    (2 * (V)->p.n * (V)->p.hashSz + 2 * (V)->p.n + 4 * BITS((V)->p.n))
/* the block: 4N ints, then the bytes; the live window's pointers are
 * their own allocation, grown at a launch */
#define CTX_TAB_SZ (4 * N * sizeof (unsigned int) + N * (3 * HashSz + PSK_SIZE + 2 * PSK_MASK_SIZE + 2))
#define PUB(V, x)      ((V)->pub + (x) * HashSz)
#define PUBNEXT(V, x)  ((V)->pubNext + (x) * HashSz)
#define HWAPEX(V, x)   ((V)->hwApex + (x) * HashSz)
#define PSKROW(V, x)   ((V)->psk + (x) * PSK_SIZE)
#define CURIKM(V, x)   ((V)->curIkm + (x) * PSK_MASK_SIZE)
#define FLOORIKM(V, x) ((V)->floorIkm + (x) * PSK_MASK_SIZE)
/* what this seat counts of seat x: never of itself, whose rows are
 * hand-backs */
#define SEATC(V, x)    ((V)->sc[(x)])

/* the coin: the caller's randomness, local to the seat, unpredictable
 * to the scheduler */
static unsigned char
coinFn(
  void *ctx
){
  const struct ac *V;
  unsigned char b;

  V = ctx;
  V->cb->random(V->cb->ctx, &b, 1);
  return (b & 1);
}

/*
 * The state trace: one line per transition of one seat, stamped with
 * its tick, to the application's trace callback, so a run reads as N
 * timelines.
 */
static void
trace(
  const struct ac *V
 ,unsigned int inst
 ,const char *fmt
 ,...
){
  char line[64 + 16 * AC_SEATS];       /* the formats are this file's;
                                        * the subset line is the longest */
  va_list ap;
  int n;

  if (!V->cb->trace)
    return;
  n = sprintf(line, "t=%u p=%u i=%u ", V->ticks, V->self, inst);
  va_start(ap, fmt);
  vsprintf(line + n, fmt, ap);
  va_end(ap);
  V->cb->trace(V->cb->ctx, line);
}

/*
 * The framers' gate: each framer's context holds the gate slice of the
 * seat's row of the mesh, one per other seat.  Egress keys on the
 * destination, found by its address; ingress keys on the in-tag sender
 * byte, the framer's tagOwner, and the framer refuses a fragment
 * claiming another -- the kernel's source address is never consulted.
 */
struct pskTab {
  const struct acPar *p;              /* the seat's parameters */
  unsigned int        self;
  unsigned char       psk[1];         /* N x PSK_HASH_SIZE */
};
#define PSKTAB_SZ (sizeof (struct pskTab) + N * PSK_HASH_SIZE)

/* the seat a framer address names: one byte, the seat; N for none */
static unsigned int
addrToIdx(
  const struct pskTab *tab
 ,const unsigned char *adr
){
  const struct acPar *S;

  S = tab->p;
  if (adr[0] != 1 || adr[1] >= N)
    return (N);
  return (adr[1]);
}

static void
gateSignCb(
  void *ctx
 ,const unsigned char *adr
 ,unsigned char *dst
 ,const unsigned char *src
 ,unsigned int len
){
  struct pskTab *tab;
  const struct acPar *S;
  unsigned int id;

  tab = ctx;
  S = tab->p;
  if ((id = addrToIdx(tab, adr)) >= N || id == tab->self) {
    memset(dst, 0, GATE_SIZE);
    return;
  }
  halfsiphash(src, len, tab->psk + id * PSK_HASH_SIZE, dst);
}

static int
gateVrfyCb(
  void *ctx
 ,const unsigned char *adr
 ,const unsigned char *mac
 ,const unsigned char *src
 ,unsigned int len
){
  struct pskTab *tab;
  const struct acPar *S;
  unsigned char computed[GATE_SIZE];
  unsigned int sender;
  unsigned int i;
  unsigned char diff;

  (void)adr;
  tab = ctx;
  S = tab->p;
  if (len < TagSz)
    return (0);
  sender = src[AC_TAG_SENDER];
  if (sender >= N || sender == tab->self)
    return (0);
  halfsiphash(src, len, tab->psk + sender * PSK_HASH_SIZE, computed);
  for (diff = 0, i = 0; i < GATE_SIZE; ++i)
    diff |= mac[i] ^ computed[i];
  return (!diff);
}

/*
 * A message's HMAC, under the slice of the pair's secret: over its tag
 * and its payload, whatever the framer's fields between them, which are
 * the framer's and differ from one end to the other.  The hash takes one
 * run of bytes, so the tag slides over them for the call.
 */
static void
msgMac(
  struct ac *V
 ,unsigned int peer
 ,unsigned char *tag
 ,unsigned int gap
 ,unsigned int len
 ,unsigned char *out
){
  const struct acPar *S;
  unsigned char between[5];

  S = &V->p;
  memcpy(between, tag + TagSz, gap);
  memmove(tag + gap, tag, TagSz);
  Kdf->hmac(PSKROW(V, peer) + PSK_HMAC_OFF, PSK_HMAC_SIZE, tag + gap, TagSz + len, out);
  memmove(tag, tag + gap, TagSz);
  memcpy(tag + TagSz, between, gap);
}

/* the newest position seat s has named in a proven row, this seat's count */
#define NAMED(V, s) ((V)->rowTick[S->n + (s)])
/* a row of seat s, no part, at a record that holds nothing to carry it,
 * naming the position s is at, and no description alone owed it this tick */
#define DESC_AT(V, s) ((V)->rowTick[2 * S->n + (s)])
#define DESC_OWED(V, rx, s, kind, num) ((kind) != BRACHA87_BESIDE && (num) >= NAMED(V, s) \
  && ((rx)->done[2 * BITS(N) + ((s) >> 3)] >> ((s) & 7) & 1) && DESC_AT(V, s) != (V)->ticks + 1)
/* where a row landed: what the sender's word says of where it is, once it
 * is its word */
#define WIN_NONE    0
#define WIN_LIVE    1
#define WIN_RECORD  2
#define WIN_HELD    3

/*
 * The proof, paid only where a message is about to move something: a
 * delivered [tag][rm][um][payload][hmac], len the payload.  A failed
 * proof is a counted discard, as a failed gate is: it says nothing of the
 * seat named, what crossed a Byzantine network being no one's word, and it
 * changes nothing for what comes next under that name.
 */
static int
msgAuth(
  struct ac *V
 ,unsigned char *tag
 ,unsigned int len
 ,unsigned int win
 ,unsigned int num
){
  const struct acPar *S;
  const unsigned char *mac;
  unsigned char computed[AC_HASH_MAX];
  unsigned int from;
  unsigned int i;
  unsigned char diff;

  S = &V->p;
  from = tag[AC_TAG_SENDER];
  ++V->c.authRun;
  msgMac(V, from, tag, 2, len, computed);
  mac = tag + TagSz + 2 + len;
  for (diff = 0, i = 0; i < HmacSz; ++i)
    diff |= mac[i] ^ computed[i];
  if (diff) {
    ++V->c.igrAuth;
    ++SEATC(V, from).authBad;
    return (0);
  }
  if (win != WIN_HELD && num > NAMED(V, from))
    NAMED(V, from) = num;
  switch (win) {
  case WIN_LIVE:
    ++SEATC(V, from).live;
    SEATC(V, from).liveTick = V->ticks;
    break;
  case WIN_RECORD:
    ++SEATC(V, from).recorded;
    SEATC(V, from).recordTick = V->ticks;
    break;
  case WIN_HELD:
    SEATC(V, from).heldTick = V->ticks;
    break;
  default:
    break;
  }
  return (1);
}

/*
 * A copy's one reply a tick: what the row has solicited of this seat
 * this tick toward its sender, a bit, 2 ix + kind - ECHO among the legs
 * and, past them, the instances.  A reply is for a sender that has not
 * heard, and a sender's sweep says so once a tick; what is presented
 * beyond that has no one behind it, whoever sends it.  Made when a
 * position first sees a copy that would be answered, cleared seat by seat
 * as a tick first uses it.  This seat's memory refusing it is a reply
 * lost, the sender's next re-send asking again.
 */
static int
copyBudget(
  struct ac *V
 ,struct inst *I
 ,unsigned int to
 ,unsigned int bit
){
  const struct acPar *S;
  unsigned char *row;
  unsigned int rowSz;

  S = &V->p;
  rowSz = RLEG_ROW + (I->rx ? 0 : RACS_ROW);  /* a record's machines are legs alone */
  if (!I->rCopy) {
    if (!(I->rCopy = calloc(N, rowSz)))
      return (0);
    if (!(I->rCopyAt = calloc(N, sizeof (*I->rCopyAt)))) {
      free(I->rCopy);
      I->rCopy = 0;
      return (0);
    }
  }
  row = I->rCopy + to * rowSz;
  if (I->rCopyAt[to] != V->ticks + 1) {
    memset(row, 0, rowSz);
    I->rCopyAt[to] = V->ticks + 1;
  }
  if (row[bit >> 3] & (1 << (bit & 7)))
    return (0);
  row[bit >> 3] |= 1 << (bit & 7);
#ifdef AC_TEST
  if (V->test)
    V->test->tagMoved = 1;
#endif
  return (1);
}

/*
 * m and d for one message from the declared physics: m the shards this
 * message expects to lose to STEADY loss -- proactive, paid on every
 * transmission, so only where a loss is expected; burst loss is BPR's
 * obligation across ticks and gets no margin -- and d one datagram's
 * wire time at the declared bandwidth, its IP and UDP headers with it,
 * rounded up so a declared cap always paces.  -m / -d override.  Called
 * for every egress message, and wherever a wait is sized from the
 * physics.
 */
static void
pace(
  const struct acPar *S
 ,unsigned int payLen
 ,unsigned int *m
 ,unsigned long *d
){
  unsigned int k;

  payLen += HmacSz;
  if (!(k = (payLen + Shard - 1) / Shard))
    k = 1;
  if (ParityShards >= 0)
    *m = ParityShards;
  else if (S->lossPct >= 100)
    *m = 256 - k;
  else {
    unsigned int loss;

    loss = S->lossPct;
    *m = (k * loss + (100 - loss) / 2) / (100 - loss);
  }
  if (k + *m > 256)
    *m = 256 - k;
  if (ShardDelayUs >= 0)
    *d = ShardDelayUs;
  else {
    unsigned long bits;

    bits = (unsigned long)(IPUDP_HDR + DgramMax - Shard + (payLen + k - 1) / k) * 8 * 1000000;
    *d = bits / BwLimit;
    if (bits % BwLimit)
      ++*d;
  }
}

/*
 * One message to one recipient: self is a local hand-back onto the
 * queue (never a BESIDE: self feeds its own BESIDE where it needs one),
 * every other the message held in the seat's buffer, its length in
 * hold, for the pass to Put to the egress framer.  The position is
 * named by its name, the chain hash before it; inst is this seat's own
 * count of it, which the hand-back routes by.  The wire boundary,
 * called from every send.
 */
static void
emit(
  struct ac *ctx
 ,unsigned int inst
 ,const unsigned char *name
 ,unsigned int dest
 ,unsigned char byte
 ,unsigned char ba
 ,unsigned char round
 ,unsigned char initiator
 ,const unsigned char *payload
 ,unsigned int payLen
 ,unsigned int *hold
){
  const struct acPar *S;
  unsigned char *p;
  unsigned int addrLen;
  unsigned int m;
  unsigned long d;

  S = &ctx->p;
  if (dest == ctx->self) {
    struct msg *qm;

    if (ctx->qTail >= ctx->qCap) {
      struct msg *grown;
      unsigned int c;

      /* doubled, unless the count wraps */
      if ((c = 2 * ctx->qCap) <= ctx->qCap
       || !(grown = realloc(ctx->q, c * sizeof (*ctx->q)))) {
        ++ctx->c.qDrop;
        return;
      }
      ctx->q = grown;
      ctx->qCap = c;
    }
    qm = &ctx->q[ctx->qTail++];
    qm->inst = inst;
    qm->byte = byte;
    qm->process = ba;
    qm->round = round;
    qm->initiator = initiator;
    if (payLen >= HashSz)
      memcpy(qm->v, payload, HashSz);
    return;
  }
  ctx->putAt = (ctx->eSweep ? AC_SAID_SWEEP : ctx->eOne ? AC_SAID_REPLY : AC_SAID_FIRST) * 16 + AC_TAG_CLASS(byte) * 4 + AC_TAG_KIND(byte);
  pace(S, payLen, &m, &d);
  addrLen = 1;                        /* the framer's address: the destination seat */
  p = ctx->obuf;
  *p++ = addrLen;
  *p++ = dest;
  *p++ = byte;
  *p++ = ba;
  *p++ = round;
  *p++ = initiator;
  *p++ = ctx->self;
  memcpy(p, name, HashSz);
  p += HashSz;
  *p++ = m;
  *p++ = (d >> 24) & 0xff;
  *p++ = (d >> 16) & 0xff;
  *p++ = (d >> 8) & 0xff;
  *p++ = d & 0xff;
  if (payLen)
    memcpy(p, payload, payLen);
#ifdef AC_TEST
  /* the harness's seat may rewrite the tag and the payload's copy, or
   * shorten it, before they are authenticated as this seat's own */
  if (ctx->test && ctx->test->egress) {
    int nl;

    if ((nl = ctx->test->egress(ctx->test->ctx, ctx->eActive && ctx->eI && ctx->eI->rx ? 0 : inst, dest, ctx->obuf + 2, p, payLen)) < 0)
      return;
    payLen = nl;
  }
#endif
  msgMac(ctx, dest, ctx->obuf + 2, 5, payLen, p + payLen);
#ifdef AC_TEST
  if (ctx->test && ctx->test->badMac)
    p[payLen] ^= 1;
#endif
  *hold = 1 + addrLen + TagSz + 5 + payLen + HmacSz;
}

/*
 * What a part is laid out from: this seat's own distribution of a
 * position (own set: every recipient's leaf, proofs and shard) or its
 * held unit of X (one leaf's), read from the live position or from a
 * record; sig0 and sig1 are the test build's two-faced signatures, to
 * seat 0 alone, 0 otherwise.
 */
struct part {
  const unsigned char *sig;
  const unsigned char *sig0;
  const unsigned char *sig1;
  const unsigned char *apex;
  const unsigned char *succ;
  const unsigned char *origHash;
  const unsigned char *sssRoot;
  const unsigned char *rsecRoot;
  const unsigned char *leaf;          /* own: R x MVAL_LEN; else the one clear [seed][share] */
  const unsigned char *sssPf;         /* own: R x PfSz; else one */
  const unsigned char *rsecPf;
  const unsigned char *shard;         /* own: R x shardLen; else one */
  unsigned int shardLen;
  unsigned char kind;
  unsigned char end;
  unsigned char own;
};

/*
 * Lay out one part of a unit for recipient j into b, and return its
 * length: for the sign part the signed header (orig_hash, both roots --
 * the apex recomputes from it), the signature, the masked [seed][share]
 * and the proofs, and for the data part the shard alone.  u->own: this
 * seat's own distribution's unit to j (the leaf j's, masked under
 * PSK(self, j) in the DIST domain with the recipient's leaf as the
 * index).  Otherwise this seat's exchange unit of X to j (its held
 * leaf, re-masked under PSK(self, j) in the EXCH domain with the
 * SENDER's leaf as the index).  The same header, signature, shard and
 * proofs ride in both; only the mask tells them apart, and the two
 * domains are what keep one key step from serving both keystreams.  For
 * a rotation the sign part is its successor key and the signature, for
 * a noop the signature alone, and neither has a data part.  The crypto
 * boundary, called beside every INITIAL this seat sends, a live leg's
 * or one a record's machines started again.
 */
static unsigned int
unitPut(
  const struct acPar *S
 ,const struct part *u
 ,unsigned int self
 ,unsigned int x
 ,unsigned int j
 ,const unsigned char *ikm   /* this position's mask key with j */
 ,unsigned int part
 ,unsigned char *b
){
  unsigned char *p;
  unsigned int leaf;

  p = b;
  if (part == AC_PART_DATA) {
    if (u->own) {
      leaf = LEAF(x, j);
      memcpy(p, u->shard + leaf * u->shardLen, u->shardLen);
    } else
      memcpy(p, u->shard, u->shardLen);
    return (u->shardLen);
  }
  /* a rotation: its successor key and the signature; a noop: the
   * signature alone; either carrying the end, the end's byte after */
  if (u->kind) {
    if (u->kind == AC_ROTATION) {
      memcpy(p, u->succ, HashSz);
      p += HashSz;
    }
    memcpy(p, u->sig, SigLen);
    p += SigLen;
    if (u->end)
      *p++ = END_MARK;
    return (p - b);
  }
  if (u->own && u->sig0 && j == 0) {
    /* -f 7: to seat 0, the apex in a rotation's shape -- the apex where
     * the successor key rides, and the slot 0 signature over the apex */
    memcpy(p, u->apex, HashSz);
    p += HashSz;
    memcpy(p, u->sig0, SigLen);
    p += SigLen;
    return (p - b);
  }
  memcpy(p, u->origHash, HashSz);
  p += HashSz;
  memcpy(p, u->sssRoot, HashSz);
  p += HashSz;
  memcpy(p, u->rsecRoot, HashSz);
  p += HashSz;
  /* -f 8: seat 0's copy signed by the successor */
  memcpy(p, u->own && u->sig1 && j == 0 ? u->sig1 : u->sig, SigLen);
  p += SigLen;
  if (u->own) {
    leaf = LEAF(x, j);
    memcpy(p, u->leaf + leaf * MVAL_LEN, MVAL_LEN);
    mask(S, ikm, u->apex, DOM_DIST, leaf, p, MVAL_LEN);
    p += MVAL_LEN;
    memcpy(p, u->sssPf + leaf * PfSz, PfSz);
    p += PfSz;
    memcpy(p, u->rsecPf + leaf * PfSz, PfSz);
    p += PfSz;
  } else {
    leaf = LEAF(x, self);
    memcpy(p, u->leaf, MVAL_LEN);
    mask(S, ikm, u->apex, DOM_EXCH, leaf, p, MVAL_LEN);
    p += MVAL_LEN;
    memcpy(p, u->sssPf, PfSz);
    p += PfSz;
    memcpy(p, u->rsecPf, PfSz);
    p += PfSz;
  }
  return (p - b);
}

/*
 * A sign part's shape, by its length: a noop's signature, a rotation's
 * successor key and signature, each with the end's byte after it where
 * the value carries the end, or a payload's fixed part.  The value it
 * recomputes under key k at offset o: the key and offset, then what the
 * shape carries, the end's byte last where it carries one.
 */
#define SHAPE_OK(l)  ((l) == SigLen || (l) == SigLen + 1 || (l) == HashSz + SigLen \
                      || (l) == HashSz + SigLen + 1 || (l) == UnitFixed)
#define SHAPE_END(l) ((l) == SigLen + 1 || (l) == HashSz + SigLen + 1)
#define SHAPE_SIG(l) ((l) == UnitFixed ? 3 * HashSz : (l) >= HashSz + SigLen ? HashSz : 0)
#define SHAPE_APEX(k, o, p, l, a) ((l) == UnitFixed \
  ? apexBuf(S, (k), (o), (p), HashSz, (p) + 2 * HashSz, HashSz, (p) + HashSz, HashSz, (a)) \
  : (l) >= HashSz + SigLen \
  ? apexBuf(S, (k), (o), (p), HashSz, EndMark, SHAPE_END(l), 0, 0, (a)) \
  : apexBuf(S, (k), (o), EndMark, SHAPE_END(l), 0, 0, 0, 0, (a)))

/*
 * The receive gates over the sign part of one unit of X's distribution
 * for leaf 'leaf' (the recipient's on a distribute unit, the sender's
 * on an exchange unit), masked under ikm in domain dom.  Returns
 * AC_UNIT_OK with d filled -- the signature stays in u, where the shape
 * puts it, and the caller copies it -- or the gate that refused it,
 * AC_UNIT_MEM where this seat's memory refused the judgment.  The gates
 * are the head comment's (THE CRYPTOGRAPHY, receive); here the value is
 * recomputed under each of X's two roots in the book in turn, where
 * cryptoMule's book holds one, and which root signed it is what the
 * value says, not what the part says.  The slot it was made at must be
 * the kind's: 0 the rotation's, any other a payload's or a noop's.  The
 * shard's gate runs where the shard is in hand (unitIn).  The crypto
 * boundary, called for every sign part that lands and is neither a
 * duplicate nor refused for its value unchecked.
 */
static unsigned int
unitCheck(
  const struct ac *V
 ,const unsigned char *root         /* X's key at the instance */
 ,const unsigned char *rootNext     /* X's installed successor there, or 0 */
 ,unsigned int leaf
 ,unsigned char dom
 ,const unsigned char *ikm
 ,const unsigned char *u
 ,unsigned int ul
 ,struct dist *d
){
  const struct acPar *S;
  const unsigned char *sig;
  const unsigned char *mval;
  const unsigned char *sssProof;
  const unsigned char *rsecProof;
  unsigned char pts[256];
  unsigned char *wa;
  unsigned char *vf;
  const unsigned char *p;
  const unsigned char *cand;          /* the root the value is tried under */
  unsigned int ew;
  unsigned int r;

  S = &V->p;
  r = N - 1;
  mval = sssProof = rsecProof = 0;
  d->shard = 0;
  d->shardLen = 0;
  if (!SHAPE_OK(ul) || (SHAPE_END(ul) && u[ul - 1] != END_MARK))
    return (AC_UNIT_LEN);
  d->end = SHAPE_END(ul);
  if (ul == SigLen || ul == SigLen + 1) {
    /* [signature]: a noop, over the hash of the signing key and slot,
     * and the end's byte where it carries the end */
    memset(d->origHash, 0, HashSz);
    memset(d->sssRoot, 0, HashSz);
    memset(d->rsecRoot, 0, HashSz);
    memset(d->succ, 0, HashSz);
    d->kind = AC_NOOP;
    sig = u;
  } else if (ul == HashSz + SigLen || ul == HashSz + SigLen + 1) {
    /* [successor key][signature]: a rotation, over the hash of the
     * signing key, the slot and the successor, and the end's byte where
     * it carries the end */
    memset(d->origHash, 0, HashSz);
    memset(d->sssRoot, 0, HashSz);
    memset(d->rsecRoot, 0, HashSz);
    memcpy(d->succ, u, HashSz);
    d->kind = AC_ROTATION;
    sig = u + HashSz;
  } else {
    /* the payload's sign part: the signed header, the signature, the
     * masked [seed][share], both proofs */
    memset(d->succ, 0, HashSz);
    memcpy(d->origHash, u, HashSz);
    memcpy(d->sssRoot, u + HashSz, HashSz);
    memcpy(d->rsecRoot, u + 2 * HashSz, HashSz);
    d->kind = 0;
    sig = u + 3 * HashSz;
    mval = sig + SigLen;
    sssProof = mval + MVAL_LEN;
    rsecProof = sssProof + PfSz;
  }
  if (mlsEgSz(SignH, sig, SigLen) != SigLen
   || !(ew = mlsEwSz(SignH, sig, SigLen)))
    return (AC_UNIT_SIG);
  if (!(wa = malloc(ew)))
    return (AC_UNIT_MEM);
  /* the offset first, from the signature's structure: the value is
   * recomputed at it, so the value commits the slot that signed it */
  if (!(ew = mlsEgOf(SignH, sig, SigLen))) {
    free(wa);
    return (AC_UNIT_SIG);
  }
  d->off = ew - 1;
  /* slot 0 is the rotation's and no payload's or noop's */
  if ((d->kind == AC_ROTATION) != !d->off) {
    free(wa);
    return (AC_UNIT_SIG);
  }
  /* the value, under each of X's two roots in turn: the root first in
   * the preimage, the offset after it, then what the part carries; the
   * signature must extract that value to the same root, so the value
   * commits the context that signed it */
  cand = root;
  d->underNext = 0;
  for (;;) {
    if (d->kind == AC_NOOP
        ? apexBuf(S, cand, d->off, EndMark, d->end, 0, 0, 0, 0, d->apex)
        : d->kind == AC_ROTATION
        ? apexBuf(S, cand, d->off, d->succ, HashSz, EndMark, d->end, 0, 0, d->apex)
        : apexBuf(S, cand, d->off, d->origHash, HashSz, d->rsecRoot, HashSz, d->sssRoot, HashSz,
                  d->apex)) {
      free(wa);
      return (AC_UNIT_MEM);
    }
    /* the extractors' arguments are this seat's and well formed, so a 0
     * is the hash allocator's refusal: this seat's memory, no judgment */
    if (!(p = mlsExtract(&MlsPlug, wa, d->apex, sig))) {
      free(wa);
      return (AC_UNIT_MEM);
    }
    if (!memcmp(p, cand, HashSz))
      break;
    if (d->underNext || !rootNext) {
      free(wa);
      return (AC_UNIT_SIG);
    }
    cand = rootNext;
    d->underNext = 1;
  }
  free(wa);
  if (!mval) {
    memset(d->unit, 0, MVAL_LEN);
    memset(d->sssProof, 0, PfSz);       /* no proofs: the record copies them all the same */
    memset(d->rsecProof, 0, PfSz);
    d->scp = d->ocp = 0;
    return (AC_UNIT_OK);
  }
  memcpy(d->unit, mval, MVAL_LEN);
  mask(S, ikm, d->apex, dom, leaf, d->unit, MVAL_LEN);
  geometry(S, d->unit, N, pts);
  d->scp = pts[0];
  d->ocp = pts[1 + leaf];
  memset(pts, 0, sizeof (pts));
  if (!(vf = malloc(sssMkVfSz(SignH))))
    return (AC_UNIT_MEM);
  if (!(p = sssMkExtract(&SssPlug, d->scp, d->ocp, d->unit, MVAL_LEN, leaf, r,
                         sssProof, vf))) {
    free(vf);
    return (AC_UNIT_MEM);
  }
  if (memcmp(p, d->sssRoot, HashSz)) {
    free(vf);
    return (AC_UNIT_SSS);
  }
  free(vf);
  memcpy(d->sssProof, sssProof, PfSz);
  memcpy(d->rsecProof, rsecProof, PfSz);
  return (AC_UNIT_OK);
}

/*------------------------------------------------------------------------*/
/*  The seat.                                                             */
/*------------------------------------------------------------------------*/

/* a part of X's own broadcast under a record: its unit, of a member the
 * position agreed, that this seat lacks, however late.  The record takes it, so
 * this seat can carry it to a seat that comes to need it */
#define LATE_UNIT(k, x) ((k)->hasVal[x] && BKR94ACS_BIT_TST((k)->subset, x) && !(k)->dist[x].held)

/*
 * Whether a fragment's message would move nothing here, from its tag alone,
 * ahead of the framer's entry and decode: the same question as the arrival's
 * below, about the same state, the seat's own, which only proven words move,
 * so it can refuse and it can tell nothing to anyone.  Where the answer needs
 * the bytes, a reply is owed, or the tag would not pass the arrival's gates,
 * the fragment goes on and the arrival judges it: an (initial, v), which is
 * another value's to differ; a part of a unit not whole under the agreed value,
 * since a name is not an identity; a row its machine would reply to and has
 * not this tick (copyBudget, spent only where it is said); a row held ahead; a
 * row a record with nothing to carry answers with its description (DESC_OWED).
 */
#define TAG_PASS     0
#define TAG_ROW      1                  /* a machine here holds it */
#define TAG_STOPPED  2                  /* its machine is at its abandon */
#define TAG_RECORD   3                  /* under a record, nothing owed its sender */
#define TAG_END      4                  /* past the chain's end */
#define TAG_UNIT     5                  /* a part of a unit whole under the agreed value */

static unsigned int
tagDecide(
  struct ac *V
 ,const unsigned char *tag
){
  const struct acPar *S;
  struct inst *I;
  struct gate *g;
  const struct bracha87Fig1 *rowF;
  const unsigned char *name;
  struct recIx *rx;
  struct tnod kn;
  struct tnod *tn;
  unsigned int from;
  unsigned int kind;
  unsigned int value;
  unsigned int cls;
  unsigned int ann;
  unsigned int x;
  unsigned int s;
  unsigned int round;
  unsigned int idx;
  unsigned int bit;
  unsigned int wi;
  int uDist;

  S = &V->p;
  from = tag[AC_TAG_SENDER];
  kind = AC_TAG_KIND(tag[0]);
  value = AC_TAG_VALUE(tag[0]);
  cls = AC_TAG_CLASS(tag[0]);
  ann = AC_TAG_TO_ANN(tag[0]);
  x = tag[AC_TAG_BA];
  s = tag[AC_TAG_INIT];
  round = tag[AC_TAG_ROUND];
  name = tag + AC_TAG_NAME;
  if (from >= N || from == V->self || x >= N || kind == BRACHA87_INITIAL
   || (AC_TAG_ANN(tag[0]) && kind != BRACHA87_READY && kind != BRACHA87_ECHO)
   || (kind == BRACHA87_ECHO && (AC_TAG_ANN(tag[0]) & 2))
   || (value && kind != BRACHA87_READY && kind != BRACHA87_BESIDE && cls != AC_CLS_ACS))
    return (TAG_PASS);
  switch (cls) {
  case AC_CLS_ACS:
    if (round < 1 || round > Rounds || s >= N || kind == BRACHA87_BESIDE)
      return (TAG_PASS);
    break;
  case AC_CLS_DIST:
    if (round || s != x || (value & 2) || (kind == BRACHA87_BESIDE && from != x))
      return (TAG_PASS);
    break;
  case AC_CLS_LEG:
    if (round || s == x || s >= N
     || (kind == BRACHA87_BESIDE ? value > AC_PART_DATA || from != s || x == V->self : (value & 2)))
      return (TAG_PASS);
    break;
  case AC_CLS_RCV:
    if (round >= N || s >= N || s == round || (from != s && from != round)
     || (V->self != s && V->self != round) || x == round
     || (kind == BRACHA87_BESIDE ? value > AC_PART_DESC || from != s : (value & 2)))
      return (TAG_PASS);
    break;
  default:
    return (TAG_PASS);
  }
  for (wi = 0; wi < V->nLive && memcmp(V->live[wi]->prev, name, HashSz); ++wi)
    ;
  if (wi < V->nLive)
    I = V->live[wi];
  else {
    kn.k0 = name[0];
    kn.key = name + 1;
    kn.seq = 0;
    rx = 0;
    if ((tn = tLow(&V->recName, &kn)) && !tCmp(&V->recName, &kn, tn))
      rx = tn->own;
    if (END_SHUT(V) && (!rx || !rx->kept))
      return (TAG_END);
    if (!rx)
      return (TAG_PASS);
    I = rx->kept;
    if (cls == AC_CLS_RCV) {
      if (!I)
        return (TAG_RECORD);
    } else if ((GET32(V->rec + rx->off + REC_NUM) < NAMED(V, from)
             || (rx->done[from >> 3] >> (from & 7) & 1))
            && !(kind == BRACHA87_BESIDE && I
              && ((I->srch[x].kept && !I->srch[x].reported) || (cls == AC_CLS_DIST && LATE_UNIT(I, x)))))
      return (DESC_OWED(V, rx, from, kind, GET32(V->rec + rx->off + REC_NUM)) ? TAG_PASS : TAG_RECORD);
    if (!I || !I->loaded || cls != AC_CLS_RCV)
      return (TAG_PASS);
  }
  idx = from;
  g = 0;
  switch (cls) {
  case AC_CLS_ACS:
    if (I->acsAbandoned || !I->a)
      return (TAG_PASS);
    rowF = bkr94acsInstance(I->a, x, s, round);
    bit = 8 * RLEG_ROW + 2 * (round * N * N + x * N + s);
    break;
  case AC_CLS_DIST:
    if (I->acsAbandoned || !I->a)
      return (TAG_PASS);
    rowF = bkr94acsInstance(I->a, x, x, 0);
    bit = 8 * RLEG_ROW + 2 * (x * N + x);
    break;
  default:
    if (cls == AC_CLS_RCV) {
      g = s == V->self ? &ROUT(I, x, round) : &RIN(I, x, s);
      idx = FIDX(from, s);
    } else
      g = &LEG(I, x, s);
    rowF = g->f;
    bit = 2 * (g - I->leg);
    break;
  }
  if (kind == BRACHA87_BESIDE) {
    /* whole under the agreed value, anything more under this tag is the
     * same bytes or refused: all that is left is the reply of dupPart */
    if (value == AC_PART_DESC || !I->hasVal[x])
      return (TAG_PASS);
    uDist = cls == AC_CLS_DIST || (cls == AC_CLS_RCV && x == s);
    if (uDist
        ? !I->dist[x].held || !VALMATCH(VAL(I, x), &I->dist[x])
        : !EXCH(I, x, LEAF(x, s)).held || !VALMATCHX(VAL(I, x), &EXCH(I, x, LEAF(x, s))))
      return (TAG_PASS);
    if (cls == AC_CLS_DIST
        ? !I->dist[x].fedBeside
        : !g->f || !(g->fed & FED_INITIAL))
      return (TAG_UNIT);
    if (cls != AC_CLS_DIST && !(g->fed & FED_BESIDE))
      return (TAG_PASS);
    goto budget;
  }
  if (!rowF || !bracha87Fig1Duplicate(rowF, kind, idx, ann))
    return (TAG_PASS);
  if (bracha87Fig1State(rowF) & BRACHA87_F1_ABANDONED)
    return (TAG_STOPPED);
  if (kind == BRACHA87_ECHO || (ann & BRACHA87_ANN_RECEIVED))
    return (TAG_ROW);
  bit += kind == BRACHA87_READY;
budget:
  /* what is spent is said in this tick, so nothing is owed a copy */
  if (!I->rCopy || I->rCopyAt[from] != V->ticks + 1
   || !(I->rCopy[from * (RLEG_ROW + (I->rx ? 0 : RACS_ROW)) + (bit >> 3)] & (1 << (bit & 7))))
    return (TAG_PASS);
  return (kind == BRACHA87_BESIDE ? TAG_UNIT : TAG_ROW);
}

/* the framer's question, counted as the arrival counts it, once a message */
static int
tagOkCb(
  void *ctx
 ,const unsigned char *tag
 ,unsigned int si
){
  struct ac *V;
  unsigned int from;
  unsigned int rc;

  V = ctx;
#ifdef AC_TEST
  if (V->test && V->test->tagAudit)
    return (1);
#endif
  if (!(rc = tagDecide(V, tag)))
    return (1);
  if (si)
    return (0);
  from = tag[AC_TAG_SENDER];
  if (AC_TAG_KIND(tag[0]) == BRACHA87_BESIDE && (rc == TAG_RECORD || rc == TAG_END))
    ++V->c.routedUnit;
  switch (rc) {
  case TAG_END:
    ++V->c.endRefused;
    break;
  case TAG_STOPPED:
    ++V->c.copy;
    break;
  case TAG_RECORD:
    ++V->c.recorded;
    ++V->c.copy;
    ++SEATC(V, from).resent;
    break;
  case TAG_UNIT:
    if (AC_TAG_CLASS(tag[0]) == AC_CLS_DIST) {
      ++V->c.inDunit;
      ++V->c.dupDunit;
    } else {
      ++V->c.inXunit;
      ++V->c.dupXunit;
    }
    ++V->c.copy;
    ++SEATC(V, from).resent;
    break;
  default:
    ++V->c.copy;
    ++SEATC(V, from).resent;
    break;
  }
  return (0);
}

/* where the regions return to */
#define SITE_ARRIVAL   0
#define SITE_HANDBACK  1
#define SITE_SWEEP     2
#define SITE_BESIDE    3
#define SITE_LAUNCH    4
#define SITE_DISPATCH  5
#define SITE_OWN       6
#define SITE_RCV       7

/* where the pass is */
#define SW_IDLE  0
#define SW_ACS   1
#define SW_F1    2

/* what an instance has taken and not yet said: the kind's bit, and for
 * an ACS row the value it goes out under, two bits a kind */
#define OWED(kind)       (1 << (kind))
#define OWED_VAL(kind)   (4 + 2 * (kind))
#define OWED_KINDS       7

/*
 * One seat's run, entered by the caller's calls: EV_GO at the go, the
 * launch of position 1; EV_INPUT with a datagram, which the ingress
 * framer takes and whose completed messages are read as arrivals;
 * EV_WORK, the pass: what the egress framer has due to the caller's
 * send, the held message to the framer, the tick when due, and the work
 * the events left.  The seat's frame across calls is in V; what follows
 * is one call's.
 */
/*
 * Seat j's own word that nothing more is owed it from this seat at this
 * record's position: HOLDING on a recover leg of every member this seat
 * can carry it now, the unit and the description, and none its memory
 * refused.  Nothing else says so: a recover leg of j's own says it folded
 * the position, and a seat held at its launch gate, a member short, runs
 * those too; an exchange leg's HOLDING is of a unit, with no description
 * beside it, and a seat that missed the agreement holds those too.
 */
static int
recHeard(
  struct ac *V
 ,struct inst *I
 ,unsigned int j
){
  const struct acPar *S;
  unsigned int run;
  unsigned int i;

  S = &V->p;
  if (I->rcvMem)
    return (0);
  for (run = 0, i = 0; i < N; ++i) {
    if (!BKR94ACS_BIT_TST(I->subset, i) || i == j || !I->dist[i].held || !I->hasVal[i]
     || !VALMATCH(VAL(I, i), &I->dist[i]))
      continue;
    if (!ROUT(I, i, j).f || !bracha87Fig1Holder(ROUT(I, i, j).f, FIDX(j, V->self)))
      return (0);
    ++run;
  }
  return (run != 0);
}

/* the arrival's proof, once, at the first thing it would move */
#define AUTHED() (evAuth || (evAuth = msgAuth(V, evTag, evLen, evWin, evNum)))

static void
seat(
  struct ac *V
 ,unsigned int ev
 ,const unsigned char *dgram
 ,unsigned int dlen
 ,unsigned long nowUs
){
  const struct acPar *S;
  unsigned char f1out[BRACHA87_FIG1_OUT];
  unsigned char dh[AC_HASH_MAX];      /* a recover leg's description's hash */
  const unsigned char *dg;
  unsigned long us;                   /* now, the framers' clock */
  unsigned long pw;                   /* a message's wire time */
  unsigned int putSite;
  unsigned int dgl;
  unsigned int rpN;                   /* rows held ahead replayed in this call */
  int lMem;                           /* this call's memory refused a step of the seat's own:
                                       * none is taken again in it */
  int pr;
  unsigned char adr[2];
  unsigned int i;
  unsigned int j;
  /* the event in hand: an arrival or a hand-back */
  unsigned int evCls;
  unsigned int evKind;
  unsigned int evX;
  unsigned int evS;
  unsigned int evFrom;
  unsigned int evRound;
  unsigned int evValue;
  unsigned int evAnnot;               /* a READY's BRACHA87_ANN_* bits */
  unsigned int evIdx;                 /* the sender as the figure indexes it: the seat */
  const unsigned char *evPl;
  unsigned int evLen;
  unsigned int dispatchSite;
  struct gate *g;                     /* the instance whose actions runF1 runs */
  unsigned int fCls;
  unsigned int fX;
  unsigned int fS;
  unsigned int nout;
  unsigned int f1site;
  unsigned long recLen;               /* recRoom: the record's length, room at the head for it */
  unsigned long recNeed;
  unsigned int recMemb;
  unsigned int recSite;
  /* the ACS actions runAcs runs */
  unsigned int nacts;
  unsigned int rpIx;                  /* replyAdd: the reply, the leg's index among the 3N^2
                                       * or the ACS instance's, (ba N + q)(Rounds + 1) + k, */
  unsigned int rpTo;
  unsigned int rpSite;                /* and where it returns to */
  const struct bracha87Fig1 *rpF;     /* answerNext: the instance whose
                                       * ready senders are owed its ready */
  struct inst *lI;                    /* the launch's gate: the last position folded, */
  unsigned int lw;                    /* its index among the live and kept, */
  unsigned int lj;                    /* and a member of its subset */
  unsigned int rb;                    /* its bit in its seat's row */
  unsigned char rpGate;
  unsigned char rpKind;
  unsigned char rpVal;
  unsigned int acsSite;
  /* the regions' own cursors: a region is entered from inside loops */
  unsigned int ra;
  unsigned int rj;
  const struct bkr94acsAct *aList;
  unsigned int aCnt;
  const struct bracha87Fig1 *inst0;   /* X's value broadcast, after a class 1 row */
  const unsigned char *cv0;
  unsigned char evValue8;             /* the BA value, as the seat takes it */
  unsigned char *evTag;               /* the arrival's tag, its proof behind its payload */
  const struct bracha87Fig1 *rowF;    /* the row's machine, 0 none yet */
  unsigned int rowBit;                /* its first bit in copyBudget */
  unsigned int rowSite;               /* where rowGate returns to */
  unsigned int evWin;                 /* WIN_*: where the arrival landed */
  unsigned int evNum;                 /* and the position it named there, 0 none */
  struct inst *evKept;                /* the kept assembly a part of it would go to */
  unsigned int rcvMade;               /* recover legs a row made, or memory refused */
  int evAuth;                         /* the event is this seat's own or its proof is done */
  unsigned int launchStep;            /* step 0, then the hand-back of its two messages */
  unsigned int ownSite;               /* where the own broadcast returns to */
  unsigned int askSite;               /* where the ask returns to: 0 not asked, 1 the kept
                                       * payload's, 2 the payload slot's */
  unsigned char *blob;                /* the arrival in hand: the dispatch leaves the
                                       * drain's block and comes back to free it */
  unsigned int blobLen;
  struct inst *I;                     /* the instance of the region now running */
  const unsigned char *rpub;
  unsigned int wi;
  const unsigned char *evName;      /* the row's name: the chain hash before its position */
  /* the key walk's: the position and seat asked for, where it returns
   * to, its cursor over the live window, and the key it derives */
  struct inst *kI;
  unsigned int kJ;
  unsigned int kSite;
  int kKeep;                          /* the walk reached kI over stepped links: its key holds */
  unsigned int kw;
  unsigned long ko;
  unsigned char kIkm[PSK_MASK_SIZE];
  unsigned char kNk[PSK_MASK_SIZE];
  unsigned char kInfo[AC_HASH_MAX + 1];
  unsigned int sx;
  /* the trees' cursors: a key, a node, a held row, a record, and the
   * bytes of a key a held row's shape starts */
  struct tnod kn;
  struct tnod *tn;
  struct ahead *ah;
  struct recIx *rx;
  struct inst *keptI;                 /* a position leaving the window, its kept assembly's */
  unsigned char *keptTab;
  unsigned char kb[AC_TAG_NAME - 1 + AC_HASH_MAX];

  S = &V->p;
  I = 0;
  evName = 0;
  blob = 0;
  aList = 0;
  blobLen = 0;
  dg = 0;
  evPl = 0;
  evLen = 0;
  evCls = evKind = evX = evS = evFrom = evRound = evIdx = 0;
  dispatchSite = 0;
  g = 0;
  kI = 0;
  rx = 0;
  rpN = 0;
  lMem = 0;
  V->aheadMore = 0;
  us = nowUs;
  if (V->failed)
    return;
  switch (ev) {
  case EV_GO:    goto launch;
  case EV_INPUT: goto input;
  default:       goto pass;
  }


  /*
   * Launch the next instance: at the go, and then when the newest has
   * folded, every member of its subset has its verdict here, and a
   * message is left.  Its number counts this seat's launches; its name
   * is the link before it, and its keys are walked at use (keyWalk).
   * The live window grows to hold it; the oldest leaves at its end,
   * below.  Nothing of it is spent until its proposal is made: a launch
   * this seat's memory refuses waits outside the window, its number not
   * taken, and the seat's next call takes it again (launchMem).
   */
launch:
  V->launchDue = 1;
  if (V->nLive == V->liveCap) {
    struct inst **grown;

    if (!(grown = realloc(V->live, (V->liveCap ? 2 * V->liveCap : 8) * sizeof (*grown))))
      goto launchMem;
    V->live = grown;
    V->liveCap = V->liveCap ? 2 * V->liveCap : 8;
  }
  if ((I = V->launching))
    goto launchAgain;
  if (!(I = calloc(1, sizeof (*I))))
    goto launchMem;
  if (!(I->blob = malloc(MsgMax))
   || !(I->a = calloc(1, bkr94acsSz(N - 1, HashSz - 1, Rounds)))
   || !(I->oAcs = calloc(N * N * (Rounds + 1), sizeof (*I->oAcs)))
   || !(I->rAcs = calloc(N * RACS_ROW + N * N * (Rounds + 1), 1))
   || !(I->tab = calloc(1, INST_TAB_SZ))) {
    free(I->blob);
    free(I->a);
    free(I->oAcs);
    free(I->rAcs);
    free(I);
    goto launchMem;
  }
  instCarve(S, I, I->tab);
  I->num = V->launched + 1;
  /* nothing of this seat's to propose: another seat's rows for the
   * position launched it, and its input is what the caller gives when
   * asked, its noop, or the rotation or switch its context is due */
  if (I->num > 1 && !V->pend && !V->avail && !V->ended)
    ++V->c.launchOnRows;
  V->aheadNew = 0;
  V->avail = 0;
  V->launching = I;
launchAgain:

  /*
   * The proposal, one an instance.  A rotation that was not agreed --
   * this seat was left out of the subset -- is presented again, the
   * same value under the same signature.  Else, the signing context
   * spent, its payload slots all signed, the seat SWITCHES to the
   * successor its agreed rotation installed at every seat.  Else, the
   * signing context's rotation not yet made, the ROTATION: a successor
   * context is generated and the hash of this context's key and the
   * successor's is the value, signed at slot 0.  Else the caller is
   * asked (propose): the same bytes as the payload a subset left out,
   * that payload presented again, else its message, a payload, at the
   * next slot, or, with none, the NOOP there.
   */
  if (V->pend) {
    I->own = V->pend;
    ++I->own->ref;
    I->again = 1;
    trace(V, I->num, "the rotation left out is presented again");
    goto proposed;
  }
  /* a payload a subset left out, kept: the caller is asked first, ahead
   * of the switch, since it is signed under the context in hand, and
   * the same bytes, by their hash, present it again, the same value
   * under the same signature, no slot spent; anything else lets it go,
   * its slot spent, and what the caller gave goes on below */
  askSite = 0;
  if (V->cache) {
    askSite = 1;
    goto ask;
askedKept:
    if (I->blobLen) {
      unsigned char oh[AC_HASH_MAX];

      if (hashBuf(S, I->blob, I->blobLen, 0, 0, 0, 0, 0, 0, oh))
        goto launchMem;
      if (!memcmp(oh, V->cache->origHash, HashSz)) {
        I->own = V->cache;
        ++I->own->ref;
        I->again = 1;
        ++V->c.again;
        trace(V, I->num, "the payload left out is presented again, the caller's same bytes (slot %u)", I->own->off);
        goto proposed;
      }
    }
    ownDrop(S, V->cache);
    V->cache = 0;
  }
  if (!(I->own = calloc(1, OWN_SZ)))
    goto launchMem;
  I->own->ref = 1;
  if (V->rotated && V->slot >> MlsS) {
    memset(V->mls.r, 0, mlsPrSz(&V->mls));
    free(V->mls.r);
    V->mls = V->mlsNext;
    V->mlsNext.r = 0;
    memcpy(V->cur, PUBNEXT(V, V->self), HashSz);
    ++V->gen;
    V->slot = SLOT_PAY;
    V->rotated = 0;
    I->switched = 1;
    trace(V, I->num, "switched to the successor %02x%02x..",
          PUBNEXT(V, V->self)[0], PUBNEXT(V, V->self)[1]);
  }
  /* the successor is made, and the rotation's value signed, before the
   * seat holds it as made: a launch this seat's memory refuses here
   * makes it anew */
  if (!V->rotated) {
    if (!(V->mlsNext.r = malloc(mlsPrSz(&V->mlsNext)))
     || !(V->rwa = malloc(mlsWaSz(&V->mlsNext))))
      goto rotMem;
    V->cb->random(V->cb->ctx, V->mlsNext.r, mlsPrSz(&V->mlsNext));
    if (!(rpub = mlsHash(&V->mlsNext, V->rwa)))
      goto rotMem;
    memcpy(I->own->succ, rpub, HashSz);
    I->own->end = V->ended != 0;
    if (apexBuf(S, V->cur, 0, I->own->succ, HashSz, EndMark, I->own->end, 0, 0, I->own->apex))
      goto rotMem;
    if (TESTFAULT(V) == AC_FAULT_TWOFACE && !V->gen) {
      /* -f 7: the successor made and never proposed; slot 0 is spent
       * below, on the payload's apex */
      memset(V->rwa, 0, mlsWaSz(&V->mlsNext));
      free(V->rwa);
      V->rwa = 0;
      V->rotated = 1;
      trace(V, I->num, "two-faced: the successor made, slot 0 kept for the payload's apex");
    } else {
      if (!(I->own->sig = malloc(SigLen))
       || !mlsSign(&V->mls, V->rwa, I->own->apex, I->own->sig, 0))
        goto rotMem;
      memset(V->rwa, 0, mlsWaSz(&V->mlsNext));
      free(V->rwa);
      V->rwa = 0;
      V->rotated = 1;
      I->own->kind = AC_ROTATION;
      I->own->underNext = I->switched;
      if (I->blobLen) {                 /* the caller's answer, the rotation in its place */
        memset(I->blob, 0, I->blobLen);
        I->blobLen = 0;
      }
      trace(V, I->num, "rotation%s: the successor %02x%02x.., the value %02x%02x.. signed at slot 0",
            I->own->end ? ", carrying the end" : "", I->own->succ[0], I->own->succ[1], I->own->apex[0], I->own->apex[1]);
      goto proposed;
    }
  }
  if (!askSite) {
    askSite = 2;
    goto ask;
  }
askedSlot:
  /* the caller's end called since it gave a message -- inside propose,
   * or a launch its memory refused taken again -- and its message is
   * let go: nothing this seat signs from the call is unmarked */
  if (V->ended && I->blobLen) {
    memset(I->blob, 0, I->blobLen);
    I->blobLen = 0;
  }
#ifdef AC_TEST
  if (TESTFAULT(V) == AC_FAULT_REUSE && !V->gen && V->slot == SLOT_PAY + 1 && !V->test->dealt) {
    I->own->off = SLOT_PAY;
    ++V->test->dealt;
    trace(V, I->num, "reuse: the payload signed at slot %u again", SLOT_PAY);
  } else
#endif
  I->own->off = V->slot;
  if (!I->blobLen) {
    I->own->kind = AC_NOOP;
    I->own->end = V->ended != 0;
    if (apexBuf(S, V->cur, I->own->off, EndMark, I->own->end, 0, 0, 0, 0, I->own->apex)
     || !(I->own->sig = malloc(SigLen))
     || !(V->rwa = malloc(mlsWaSz(&V->mls)))
     || !mlsSign(&V->mls, V->rwa, I->own->apex, I->own->sig, I->own->off))
      goto signMem;
    memset(V->rwa, 0, mlsWaSz(&V->mls));
    free(V->rwa);
    V->rwa = 0;
    /* the slot spent, its signature made */
    if (I->own->off == V->slot)
      ++V->slot;
    trace(V, I->num, "noop%s: the hash of the key and slot%s signed at slot %u",
          I->own->end ? ", carrying the end" : "", I->own->end ? " and the end's byte" : "", I->own->off);
    goto proposed;
  }

  /*
   * Distribute.  The blob is hashed, huffman compressed and encrypted
   * under a fresh K by the keystream nonced on orig_hash; the
   * ciphertext is RS-sharded (k = T, m = R - T) under an rsecMk tree; K
   * is Shamir-split at R points the hidden seed derives, under an sssMk
   * tree whose leaves bind the seed; the apex commits the hash and both
   * roots and is MLS-signed once at the payload slot.  The clear
   * leaves, proofs and shards are kept; unitPut masks per send.  Seat
   * N-1 under -f commits its fraud before the tree is built over it, so
   * every unit still verifies where the construction says it does.
   */
  {
    struct own *o;
    unsigned char seed[SEED_LEN];
    unsigned char pts[256];
    unsigned char ip[AC_SEATS];
    unsigned char *ivp[AC_SEATS];
    unsigned char *sharePtr[AC_SEATS];
    const unsigned char *leafPtr[AC_SEATS];
    const unsigned char *dptr[AC_SEATS];
    unsigned char *pptr[AC_SEATS];
    const unsigned char *shardPtr[AC_SEATS];
    unsigned char *comp;
    unsigned char *ivBuf;
    unsigned char *shareBuf;
    unsigned char *sssw;
    unsigned char *rsecw;
    unsigned char *wa;
    const unsigned char *p;
    unsigned int cap;
    unsigned int clen;
    unsigned int rr;
    unsigned int kk;
    unsigned int m;
    int fault;
    int failed;

    o = I->own;
    fault = TESTFAULT(V);
    rr = N - 1;
    kk = Threshold;
    m = rr - kk;
    failed = 0;
    comp = ivBuf = shareBuf = sssw = rsecw = wa = 0;
    V->cb->random(V->cb->ctx, seed, SEED_LEN);
    geometry(S, seed, N, pts);
    if (hashBuf(S, I->blob, I->blobLen, 0, 0, 0, 0, 0, 0, o->origHash))
      goto distFail;
    cap = I->blobLen + 1024;
    if (!(comp = malloc(cap)))
      goto distFail;
    if (!(clen = hufEncode(comp, cap, I->blob, I->blobLen)))
      goto distFail;
    if (clen > cap) {
      free(comp);
      cap = clen;
      if (!(comp = malloc(cap)))
        goto distFail;
      if (!(clen = hufEncode(comp, cap, I->blob, I->blobLen)))
        goto distFail;
    }
    /* dealt randomness: K, then the t pad values Shamir needs */
    if (!(ivBuf = malloc(kk * KEY_LEN)))
      goto distFail;
    V->cb->random(V->cb->ctx, ivBuf, kk * KEY_LEN);
    ip[0] = pts[0];
    for (j = 1; j < kk; ) {
      unsigned char q;
      unsigned int e;

      V->cb->random(V->cb->ctx, &q, 1);
      for (e = 0; e < j && ip[e] != q; ++e)
        ;
      if (e == j)
        ip[j++] = q;
    }
    for (j = 0; j < kk; ++j)
      ivp[j] = ivBuf + j * KEY_LEN;
    if (!(shareBuf = malloc(rr * KEY_LEN)))
      goto distFail;
    for (i = 0; i < rr; ++i)
      sharePtr[i] = shareBuf + i * KEY_LEN;
    sss(ip, pts + 1, ivp, sharePtr, kk, rr, KEY_LEN);
    for (i = 0; i < rr; ++i) {
      memcpy(OWN_LEAF(o, i), seed, SEED_LEN);
      memcpy(OWN_LEAF(o, i) + SEED_LEN, sharePtr[i], KEY_LEN);
      leafPtr[i] = OWN_LEAF(o, i);
    }
    /* -f 2: a share off the polynomial, committed the same way; -f 5
     * every share but the last T, so the good subset comes last, each
     * in its own byte: flips in one byte cancel at K where two leaves'
     * coefficients at 0 are equal, one subset in 256, and that subset
     * reproduces the hash */
    if (fault == AC_FAULT_SHARE)
      OWN_LEAF(o, 0)[SEED_LEN] ^= 0x01;
    /* -f 9: a share of leaf 1 and a shard of leaf 0 (below), so that a
     * seat holding T good shares beside the bad one may hold no good T
     * shards yet, the case the end's relaxed pass must cover */
    if (fault == AC_FAULT_BOTH)
      OWN_LEAF(o, 1)[SEED_LEN] ^= 0x01;
    if (fault == AC_FAULT_SALT)
      for (i = 0; i < (rr > kk ? rr - kk : 1); ++i)
        OWN_LEAF(o, i)[SEED_LEN + i % KEY_LEN] ^= 0x01;
    /* -f 3: the tree committed under a geometry the seed does not
     * derive: leaves 0 and 1 bound to each other's points */
    if (fault == AC_FAULT_GEOM) {
      unsigned char x;

      x = pts[1];
      pts[1] = pts[2];
      pts[2] = x;
    }
    if (!(sssw = malloc(sssMkWaSz(SignH, rr)))
     || !(p = sssMkHash(&SssPlug, pts[0], pts + 1, leafPtr, MVAL_LEN, rr, sssw)))
      goto distFail;
    memcpy(o->sssRoot, p, HashSz);
    for (i = 0; i < rr; ++i)
      if (!sssMkProof(&SssPlug, rr, i, sssw, OWN_SSSPF(o, i)))
        goto distFail;
    o->shardLen = (clen + kk - 1) / kk;
    if (fault == AC_FAULT_PAD)             /* -f 6: at least one padding byte */
      o->shardLen = clen / kk + 1;
    if (o->shardLen > ShardMax
     || !(o->shards = malloc(rr * o->shardLen)))
      goto distFail;
    memcpy(o->shards, comp, clen);
    memset(o->shards + clen, 0, kk * o->shardLen - clen);
    /* the keystream over the whole padded ciphertext, the thing
     * dispersed: an assembler's XOR over the same length then reads the
     * padding back as zero, which the empty message's test needs */
    keystream(S, ivBuf, o->origHash, o->shards, kk * o->shardLen);
    /* -f 4: a consistent codeword of the wrong bytes.  Both codes are
     * built over the flipped ciphertext, so every part verifies and
     * re-encodes consistent, and no T-subset reproduces the signed
     * hash. */
    if (fault == AC_FAULT_CT)
      o->shards[0] ^= 0x01;
    for (j = 0; j < kk; ++j)
      dptr[j] = o->shards + j * o->shardLen;
    for (j = 0; j < m; ++j)
      pptr[j] = o->shards + (kk + j) * o->shardLen;
    if (rsecEncode(dptr, pptr, o->shardLen, kk, m))
      goto distFail;
    for (i = 0; i < rr; ++i)
      shardPtr[i] = o->shards + i * o->shardLen;
    /* -f 1: a non-codeword.  The tree is built over the flipped shard,
     * so its proof verifies everywhere and only the re-encode at
     * threshold can tell. */
    if (fault == AC_FAULT_SHARD || fault == AC_FAULT_BOTH)
      o->shards[0] ^= 0x01;
    /* -f 6: the last byte of data shard k-1, padding, flipped after the
     * parity and before the tree: every subset reproduces the message */
    if (fault == AC_FAULT_PAD)
      o->shards[kk * o->shardLen - 1] ^= 0x01;
    if (!(rsecw = malloc(rsecMkWaSz(SignH, rr))))
      goto distFail;
    if (!(p = rsecMkHash(&RsecPlug, shardPtr, o->shardLen, rr, rsecw)))
      goto distFail;
    memcpy(o->rsecRoot, p, HashSz);
    for (i = 0; i < rr; ++i)
      if (!rsecMkProof(&RsecPlug, rr, i, rsecw, OWN_RSECPF(o, i)))
        goto distFail;
    if (apexBuf(S, V->cur, o->off, o->origHash, HashSz, o->rsecRoot, HashSz, o->sssRoot, HashSz,
                o->apex)
     || !(o->sig = malloc(SigLen))
     || !(wa = malloc(mlsWaSz(&V->mls)))
     || !mlsSign(&V->mls, wa, o->apex, o->sig, o->off))
      goto distFail;
    /* -f 7: the apex signed again at slot 0, the rotation's, for seat 0
     * (unitPut deals it there in a rotation's shape) */
    if (fault == AC_FAULT_TWOFACE && !V->gen && o->off == SLOT_PAY
     && (!(o->sig0 = malloc(SigLen)) || !mlsSign(&V->mls, wa, o->apex, o->sig0, 0)))
      goto distFail;
    /* -f 8: the apex, hashed under the current key, signed again by the
     * installed successor at its first payload slot, for seat 0
     * (unitPut deals it there in the payload's shape) */
    if (fault == AC_FAULT_SPLIT && !V->gen && V->mlsNext.r && o->off == SLOT_PAY + 1
     && (!(o->sig1 = malloc(SigLen)) || !mlsSign(&V->mlsNext, wa, o->apex, o->sig1, SLOT_PAY)))
      goto distFail;
    /* the same apex signed again at the next slot, spent here so this
     * seat never signs another value there */
    if (fault == AC_FAULT_TWOSLOT && !V->gen && o->off == SLOT_PAY
     && (!(o->sig1 = malloc(SigLen)) || !mlsSign(&V->mls, wa, o->apex, o->sig1, o->off + 1)))
      goto distFail;
#ifdef AC_TEST
    if (o->sig0 || o->sig1)
      ++V->test->dealt;
#endif
    trace(V, I->num, "distributed apex %02x%02x.. at slot %u, unit %u bytes%s",
          o->apex[0], o->apex[1], o->off, UnitFixed + o->shardLen,
          fault == AC_FAULT_SHARD ? " (a shard flipped)" : fault == AC_FAULT_SHARE ? " (a share flipped)"
          : fault == AC_FAULT_GEOM ? " (points 0 and 1 swapped)"
          : fault == AC_FAULT_CT ? " (a ciphertext byte flipped)"
          : fault == AC_FAULT_SALT ? " (every share but the last T flipped)"
          : fault == AC_FAULT_PAD ? " (a padding byte flipped)"
          : fault == AC_FAULT_BOTH ? " (a shard and a share flipped, two leaves)"
          : o->sig0 ? " (the apex signed at slot 0 too, to seat 0 in a rotation's shape)"
          : o->sig1 && fault == AC_FAULT_TWOSLOT ? " (the apex signed at the next slot too, to seat 0)"
          : o->sig1 ? " (the apex signed under the successor too, to seat 0)" : "");
    goto distFree;

  distFail:
    failed = 1;

  distFree:
    /* the dealt randomness, the shares, the plaintext and both work
     * areas are wiped whichever way this was reached */
    memset(seed, 0, sizeof (seed));
    memset(pts, 0, sizeof (pts));       /* the dealt geometry */
    if (comp)
      memset(comp, 0, cap);
    if (ivBuf)
      memset(ivBuf, 0, kk * KEY_LEN);
    if (shareBuf)
      memset(shareBuf, 0, rr * KEY_LEN);
    if (sssw)
      memset(sssw, 0, sssMkWaSz(SignH, rr));
    if (wa)
      memset(wa, 0, mlsWaSz(&V->mls));
    free(comp);
    free(ivBuf);
    free(shareBuf);
    free(sssw);
    free(rsecw);
    free(wa);
    if (failed)
      goto launchMem;
    /* the slot spent, its signature made, and the next under the
     * two-slot fault, spent on the same apex */
    if (o->off == V->slot)
      V->slot += 1 + (fault == AC_FAULT_TWOSLOT && o->sig1);
  }
  goto proposed;

  /*
   * A launch this seat's memory refused: nothing of it is spent -- no
   * number, no slot, no successor made; a switch to the successor
   * already installed stands, as the launch would have made it -- and
   * what it made is let go, the work area wiped; the caller was asked
   * at most once, and its message stays with the waiting instance.  The
   * seat's next call takes it again; the rest of this one goes on
   * without it.
   */
rotMem:
  if (V->mlsNext.r) {
    memset(V->mlsNext.r, 0, mlsPrSz(&V->mlsNext));
    free(V->mlsNext.r);
    V->mlsNext.r = 0;
  }
signMem:
  if (V->rwa) {
    memset(V->rwa, 0, mlsWaSz(&V->mls));
    free(V->rwa);
    V->rwa = 0;
  }
launchMem:
  ++V->c.ownMem;
  if ((I = V->launching) && I->own) {
    ownDrop(S, I->own);
    I->own = 0;
  }
  lMem = 1;
  goto work;

  /* the ask: the caller's message, asked once a launch, into the blob:
   * refused, as at the caller's word of none, where its huffman stream
   * would not fit the ciphertext bound, T shards of the wire's message.
   * The encoder in the tree writes its input raw behind a length and a
   * flag whenever coding would not make it shorter, so a message within
   * MsgMax is never more than six bytes longer as a stream, and the
   * 1024 bytes of room hold it: only a length past MsgMax, the caller's
   * error, is refused.  huf.h states no such bound, so the stream is
   * made once here to know, and again at distribute, the same bytes,
   * and no message asked fails there.  None, at the payload slot: the
   * NOOP, which spends a slot all the same, so the context's clock
   * keeps its instance cadence */
ask:
  /* past the caller's end nothing is asked: what it gives is a noop,
   * and a payload a subset left out goes */
  if (!I->asked && !V->ended) {
    I->asked = 1;
    if ((I->blobLen = V->cb->propose(V->cb->ctx, I->blob, MsgMax))
     && (I->blobLen > MsgMax
      || !(j = hufEncode(V->pbuf, ShardMax * Threshold, I->blob, I->blobLen))
      || j > ShardMax * Threshold)) {
      ++V->c.proposeLong;
      memset(I->blob, 0, MsgMax);
      I->blobLen = 0;
    }
  }
  if (askSite == 1)
    goto askedKept;
  goto askedSlot;

  /* the proposal made, the launch is spent: its number and its place in
   * the live window.  A pass in hand past the live instances, at a
   * record's machines: the launch moves every record's place up one,
   * and the pass stays on the record it is at, whose legs it is
   * sweeping */
proposed:
  V->launching = 0;
  V->launchDue = 0;
  ++V->launched;
  if (V->swPhase != SW_IDLE && V->sIx >= V->nLive)
    ++V->sIx;
  V->live[V->nLive++] = I;
  if (V->nLive > V->c.liveMost)
    V->c.liveMost = V->nLive;
  V->aheadDue = 1;
  I->launchTick = V->ticks;
  I->launchUs = us;
  memcpy(I->prev, V->chain, HashSz);
  for (i = 0; i < N; ++i) {
    memcpy(ROOT(I, i), PUB(V, i), HashSz);
    memcpy(ROOTNEXT(I, i), PUBNEXT(V, i), HashSz);
  }
  memcpy(I->hasNext, V->hasNext, N);
  memcpy(I->gen, V->promoted, N * sizeof (*I->gen));
  trace(V, I->num, "launched");
  /* this seat holds its own proposal's header by construction, and is
   * the one presenting a rotation until it is agreed */
  if (I->own->kind == AC_ROTATION && V->pend != I->own) {
    V->pend = I->own;
    ++I->own->ref;
  }
  memcpy(I->dist[V->self].apex, I->own->apex, HashSz);
  memcpy(I->dist[V->self].origHash, I->own->origHash, HashSz);
  memcpy(I->dist[V->self].sssRoot, I->own->sssRoot, HashSz);
  memcpy(I->dist[V->self].rsecRoot, I->own->rsecRoot, HashSz);
  I->dist[V->self].shardLen = I->own->shardLen;
  I->dist[V->self].off = I->own->off;
  I->dist[V->self].underNext = I->own->underNext;
  I->dist[V->self].kind = I->own->kind;
  I->dist[V->self].end = I->own->end;
  I->dist[V->self].sign = I->dist[V->self].held = 1;
  I->verdict[V->self] = AC_PASS;

  /*
   * The ACS seat, on the seat's clock until the deployment's abandon,
   * its count of sweeps, or the library's round ceiling short of it,
   * its state held until then, since a seat that forgot it could
   * neither finish the agreement nor, by Lemma 1, run it again.  It
   * re-sends what it owes to the seats not recorded as having it, and
   * its own value broadcast among that is its presence to them.
   * Step 0 of this seat's value broadcast -- (initial, hash) and the
   * unit beside it owed to every other seat, both fed straight back to
   * self -- once no pass is in hand, unless -z holds it: the laggard's
   * new proposal leaves late, too late for this instance's subset; one
   * presented again leaves with no pass in hand.
   */
  /* no abandon count: the agreement runs until its subset is had, its
   * own or DISCOVERed, and this seat lets it go after that (below), as
   * the ABAP README has a caller that gives no count do.  Before the
   * subset nothing is forgotten, so nothing is said twice under a tag */
  memset(I->a, 0, bkr94acsSz(N - 1, HashSz - 1, Rounds));
  if (bkr94acsInit(I->a, N - 1, MaxByz, HashSz - 1, V->self, Rounds, Patience, 0,
                   coinFn, V, 1))
    goto exit;
  memset(I->oAcs, 0, N * N * (Rounds + 1) * sizeof (*I->oAcs));
  if (UnitFixed + I->own->shardLen > V->c.unitMax)
    V->c.unitMax = UnitFixed + I->own->shardLen;
#ifdef AC_TEST
  if (V->test && V->test->lag && !I->again) {
    I->lagUntil = V->ticks + V->test->lag;
    goto work;
  }
#endif
  I->ownDue = 1;
  goto work;

  /*
   * This seat's value broadcast: step 0, then the hand-back of its
   * (initial, v) and its unit to itself.  Entered from the talk with no
   * pass in hand, or when -z releases it.
   */
ownBroadcast:
  I->dist[V->self].fedBeside = 1;
  I->launched = 1;
  launchStep = 0;
  nacts = bkr94acsBroadcast(I->a, I->own->apex, V->acts);
  acsSite = SITE_LAUNCH;
ownLaunch:
  aList = V->acts;
  aCnt = nacts;
  goto runAcs;
runAcsLaunchDone:
  if (launchStep == 0) {
    ++launchStep;
    nacts = bkr94acsInput(I->a, BRACHA87_INITIAL, V->self, V->self, 0, V->self, I->own->apex, 0, V->acts);
    goto ownLaunch;
  }
  if (launchStep == 1) {
    ++launchStep;
    nacts = bkr94acsInput(I->a, BRACHA87_BESIDE, V->self, V->self, 0, V->self, 0, 0, V->acts);
    goto ownLaunch;
  }
  switch (ownSite) {
  case 0:  goto ownBroadcastTalkDone;
  default: goto ownBroadcastLagDone;
  }
  /*
   * The pass, EV_WORK: what the egress framer has due goes to the
   * caller's send, until the caller refuses one, which then stays due
   * and the caller, who refused it, knows to wait for its socket; the
   * held message to the framer, which a full table keeps held and a tag
   * still going there takes as said (a re-send, the same bytes); the
   * tick, when due and no pass is in hand, starts a sweep pass; then
   * the work.  The caller calls at least every tick.
   */
pass:
  while ((dgl = rsecFrmEgrGet(&V->egr, us, &dg))) {
    if (!V->cb->send(V->cb->ctx, dg[1], dg + 1 + dg[0], dgl - 1 - dg[0])) {
      ++V->c.sendRefused;
      break;
    }
    rsecFrmEgrSent(&V->egr, us);
    ++V->c.dgSent;
    V->c.dgBytes += IPUDP_HDR + dgl - 1 - dg[0];
  }
  if (V->held) {
    putSite = 0;
    goto heldPut;
  }
heldPutPassDone:
  if (V->quiet)
    return;
  if (V->swPhase == SW_IDLE && us - V->lastTickUs >= (unsigned long)TickMs * 1000) {
    if (us - V->lastTickUs - (unsigned long)TickMs * 1000 > V->c.overUs)
      V->c.overUs = us - V->lastTickUs - (unsigned long)TickMs * 1000;
    V->lastTickUs = us;
    ++V->ticks;
    /* the tick's load, each link's and the ingress's */
    for (i = 0; i < N; ++i) {
      if (i == V->self)
        continue;
      if (V->tickNow[2 * i] > SEATC(V, i).sentTickMost)
        SEATC(V, i).sentTickMost = V->tickNow[2 * i];
      if (V->tickNow[2 * i + 1] > SEATC(V, i).recvTickMost)
        SEATC(V, i).recvTickMost = V->tickNow[2 * i + 1];
      V->tickNow[2 * i] = V->tickNow[2 * i + 1] = 0;
    }
    if (V->recvNow > V->c.recvTickMost)
      V->c.recvTickMost = V->recvNow;
    V->recvNow = 0;
    /* each link's sweep: due once the least round trip it has witnessed
     * has passed since it was last due; a link with none witnessed is
     * swept at every tick */
    for (i = 0; i < N; ++i)
      if ((V->swDue[i] = !SEATC(V, i).rtts || us - V->swUs[i] >= SEATC(V, i).rttLeast))
        V->swUs[i] = us;
    /* a search this seat's memory refused is owed, and taken again at
     * every tick until its memory serves it */
    for (wi = 0; wi < V->nLive + V->nKept; ++wi) {
      I = wi < V->nLive ? V->live[wi] : V->kept[wi - V->nLive];
      for (i = 0; i < N; ++i)
        if (I->srch[i].owed && !I->verdict[i] && !I->srch[i].reported)
          I->asmDue[i] = 1;
    }
    for (wi = 0; wi < V->nLive; ++wi)
      if (V->live[wi]->lagUntil && V->ticks >= V->live[wi]->lagUntil) {
        V->live[wi]->lagUntil = 0;
        I = V->live[wi];
        ownSite = 1;
        goto ownBroadcast;
ownBroadcastLagDone:
        ;
      }
    /* a pass: every live instance in turn, oldest first, then the
     * machines records run; a position launched under a tick before is
     * passed over, nothing it said yet due again */
    if (V->nLive + V->nKept) {
      V->swPhase = SW_ACS;
      V->sIx = 0;
      V->sMore = V->nLive && !V->live[0]->acsAbandoned && us - V->live[0]->launchUs >= (unsigned long)TickMs * 1000;
      V->sN = V->sA = 0;
    }
  }
  goto work;

  /*
   * A datagram, EV_INPUT: to the ingress framer, which counts it
   * delivered where it completes a message; every message it completed
   * is read as an arrival, then the work the arrivals left.
   */
input:
  adr[0] = 1;
  adr[1] = 0;
  if (!rsecFrmIgrPut(&V->igr, adr, dgram, dlen))
    ++V->c.igrBusy;
drain:
#ifdef AC_TEST
  /* what the framer's question would have refused moved nothing here */
  if (V->test && V->test->tagPredict) {
    if (evAuth || V->test->tagMoved)
      ++V->test->tagBad;
    V->test->tagPredict = 0;
  }
#endif
  if ((blob = rsecFrmIgrGet(&V->igr, &blobLen))) {
    evAuth = 0;
    /* the link's load: a message the framer completed, by its in-tag
     * sender, ahead of every gate */
    if (blobLen >= 1u + blob[0] + TagSz && blob[1 + blob[0] + AC_TAG_SENDER] < N
     && blob[1 + blob[0] + AC_TAG_SENDER] != V->self) {
      SEATC(V, blob[1 + blob[0] + AC_TAG_SENDER]).recvBytes += blobLen;
      V->tickNow[2 * blob[1 + blob[0] + AC_TAG_SENDER] + 1] += blobLen;
      V->recvNow += blobLen;
    }
    goto arrival;
  }
  goto work;

    {
      unsigned char *mb;
      unsigned char *tg;
      unsigned int ml;
      unsigned int al;
      unsigned char byte;

    arrival:
      mb = blob;
      ml = blobLen;
      byte = 0;
      evFrom = N;                       /* no sender yet: a frame refused
                                         * from its length is nobody's */
      evWin = WIN_NONE;
      evNum = 0;
      evKept = 0;
      /* ingress: [addrlen][addr][tag][rm][um][payload][hmac] */
      if (ml < 1 || ml < 1u + mb[0] + TagSz + 2u)
        goto malformed;
      al = mb[0];
      tg = mb + 1 + al;
      evTag = tg;
      evPl = tg + TagSz + 2;
      evLen = ml - (1u + al + TagSz + 2u);
      byte = tg[0];
      evKind = AC_TAG_KIND(byte);
      evValue = AC_TAG_VALUE(byte);
      evValue8 = evValue;
      evCls = AC_TAG_CLASS(byte);
      evAnnot = AC_TAG_TO_ANN(byte);
#ifdef AC_TEST
      /* the harness's adversary at the wire: the cuts and the split */
      if (V->test && V->test->ingress && !V->test->ingress(V->test->ctx, tg, evPl, evLen < HmacSz ? 0 : evLen - HmacSz)) {
        free(blob);
        goto drain;
      }
#endif
      /* the loss notification: rm = 0 with um set, no payload */
      if (!evLen && !tg[TagSz] && tg[TagSz + 1]) {
        ++V->c.loss;
        if (evKind == BRACHA87_BESIDE)
          ++V->c.lossUnit;
        if (tg[AC_TAG_SENDER] < N && tg[AC_TAG_SENDER] != V->self)
          ++SEATC(V, tg[AC_TAG_SENDER]).loss;
        free(blob);
        goto drain;
      }
      if (evLen < HmacSz)
        goto malformed;
      evLen -= HmacSz;
#ifdef AC_TEST
      if (V->test && V->test->tagAudit && !evAuth && tagDecide(V, tg)) {
        ++V->test->tagPred;
        V->test->tagPredict = 1;
        V->test->tagMoved = 0;
      }
#endif
      /* the decode's parity: the steady loss as this message met it */
      if (tg[TagSz + 1]) {
        V->c.parityUsed += tg[TagSz + 1];
        if (tg[TagSz + 1] > V->c.parityMost)
          V->c.parityMost = tg[TagSz + 1];
        if (tg[TagSz + 1] == tg[TagSz])
          ++V->c.parityLast;
      }
      /*
       * From here the message is assumed good, a sender's word as it
       * claims, and read for what it would do, since a copy of a message
       * and the message are the same bytes and nothing in them can say
       * which: what the HMAC proves is who wrote it, and that says nothing
       * of whether this seat needs it.  Only the machine it names knows
       * that [SRC84: the argument that put BPR at the endpoint], and asking
       * costs a lookup.  What would move nothing is refused unread, its
       * proof never paid, and a copy costs the same from the network or
       * from a seat that holds the key, so the two need no telling apart.
       * Everything that would move something proves itself first (AUTHED),
       * and nothing of where a seat is is taken on less than that.  So
       * identity is the in-tag sender, proved there, never the source
       * address; a count of what is refused is of the name on it, proved or
       * not.
       */
      evFrom = tg[AC_TAG_SENDER];
      evX = tg[AC_TAG_BA];
      evS = tg[AC_TAG_INIT];
      evRound = tg[AC_TAG_ROUND];
      evName = tg + AC_TAG_NAME;
      if (evFrom >= N || evFrom == V->self || evX >= N
       || (AC_TAG_ANN(byte) && evKind != BRACHA87_READY && evKind != BRACHA87_ECHO)
       || (evKind == BRACHA87_ECHO && (AC_TAG_ANN(byte) & 2)))
        goto malformed;
      /* the tag's gates, before the row is routed: a row held ahead has
       * passed them */
      switch (evCls) {
      case AC_CLS_ACS:
        if (evRound < 1 || evRound > Rounds || evS >= N || evLen
         || evKind == BRACHA87_BESIDE)
          goto malformed;
        if (evKind == BRACHA87_INITIAL && evFrom != evS)
          goto notInitiator;
        break;
      case AC_CLS_DIST:
        /* bits 2-3: HOLDING in bit 2 on a READY, the part in bit 2 on a
         * BESIDE, else none */
        if (evRound || evS != evX || (evValue & 2)
         || (evValue && evKind != BRACHA87_READY && evKind != BRACHA87_BESIDE)
         || (evKind != BRACHA87_BESIDE && evLen != HashSz))
          goto malformed;
        if ((evKind == BRACHA87_INITIAL || evKind == BRACHA87_BESIDE) && evFrom != evX)
          goto notInitiator;
        break;
      case AC_CLS_LEG:
        /* bits 2-3: HOLDING in bit 2 on a READY, the part on a BESIDE,
         * else none */
        if (evRound || evS == evX || evS >= N
         || (evKind == BRACHA87_BESIDE ? evValue > AC_PART_DATA : (evValue & 2))
         || (evValue && evKind != BRACHA87_READY && evKind != BRACHA87_BESIDE)
         || (evKind != BRACHA87_BESIDE && evLen != HashSz)
         || (evKind == BRACHA87_BESIDE && evX == V->self))  /* this seat dealt its own
                                                             * unit: no leg carries it back */
          goto malformed;
        if ((evKind == BRACHA87_INITIAL || evKind == BRACHA87_BESIDE) && evFrom != evS)
          goto notInitiator;
        break;
      case AC_CLS_RCV:
        /* the recover leg (X, S) to the returner R, the round byte: S
         * and R distinct, the row between them, this seat one of them;
         * bits 2-3 as on class 2, the description the third part; a
         * description is a bitmap and up to every seat's value; no leg
         * of R's own value goes to R */
        if (evRound >= N || evS >= N || evS == evRound
         || (evFrom != evS && evFrom != evRound) || (V->self != evS && V->self != evRound)
         || evX == evRound
         || (evKind == BRACHA87_BESIDE ? evValue > AC_PART_DESC : (evValue & 2))
         || (evValue && evKind != BRACHA87_READY && evKind != BRACHA87_BESIDE)
         || (evKind != BRACHA87_BESIDE && evLen != HashSz)
         || (evKind == BRACHA87_BESIDE && evValue == AC_PART_DESC && (evLen < BITS(N) || evLen > DESC_MAX)))
          goto malformed;
        if ((evKind == BRACHA87_INITIAL || evKind == BRACHA87_BESIDE) && evFrom != evS)
          goto notInitiator;
        break;
      default:
        goto malformed;
      }
      /* the position, by its name: the chain hash before it, which this
       * seat minted at the fold before it [Bracha87 Section 3: all
       * messages of a broadcast tagged (p, k), raised to the chain] */
      for (wi = 0; wi < V->nLive && memcmp(V->live[wi]->prev, evName, HashSz); ++wi)
        ;
      if (wi == V->nLive) {
        unsigned long o;
        unsigned char part;
        unsigned char nm;               /* the tag byte's naming bits */
        unsigned char an;               /* and its annotation bits */

        /* not live here.  A row naming a record this seat holds is
         * evidence for that position's machines (below); a name this
         * seat cannot place moves nothing: a seat ahead of this one and
         * one behind its oldest record both send such names */
        part = evKind == BRACHA87_BESIDE;
        if (part)
          ++V->c.routedUnit;
        evWin = WIN_HELD;
        kn.k0 = evName[0];
        kn.key = evName + 1;
        kn.seq = 0;
        rx = 0;
        if ((tn = tLow(&V->recName, &kn)) && !tCmp(&V->recName, &kn, tn))
          rx = tn->own;
        /* the chain ended here, its last link gone from the live window
         * an abandon ago: nothing new starts -- no recover leg,
         * whatever a row names, and no row held for a position no seat
         * launches -- so no seat keeps another alive; a record's
         * machines already running go on to their count.  Until then a
         * row naming the last link's record, as any record's, starts
         * recover legs: what carries a seat behind to the end */
        if (END_SHUT(V) && (!rx || !rx->kept)) {
          ++V->c.endRefused;
          free(blob);
          goto drain;
        }
        if (rx) {
          struct inst *k;
          struct dist *d;
          const unsigned char *r;
          const unsigned char *mp;
          unsigned char *kt;
          unsigned int m;
          unsigned int x;
          unsigned int shl;
          int past;                     /* its sender's word: nothing owed it here */

          o = rx->off;
          r = V->rec + o;
          ++V->c.recorded;
          evWin = WIN_RECORD;
          evNum = GET32(r + REC_NUM);
          /* a row under a position this seat retains is evidence, and
           * what deals with it is a recover leg, whose state is the
           * record's, rebuilt from it -- the subset, every member's
           * agreed value, this seat's unit of each, the book at the
           * launch.  A recover leg's row is fed to its machine, the
           * initiator's INITIAL opening one here.  Any other row is its
           * sender's, and where no recover leg of this seat's runs
           * toward it the set starts.  The agreement and its legs are
           * not run again: recovery has no consensus to reach.
           *
           * The machines are gone, so the question a live machine answers
           * for a copy goes to what is retained: is anything owed?  Not
           * to a seat whose own proven word says it has gone past: a
           * correct seat names a position only after its launch gate, so
           * only with a verdict on every member of the one before, and it
           * lacks nothing of any position before the one it last named.
           * Nor to a seat that said HOLDING on a recover leg of all this
           * seat holds (done), until it holds more; and to a seat this
           * record holds nothing to carry to, its description alone (below),
           * once a tick, read from the record, its machines not rebuilt
           * again.  What
           * it sends under the record,
           * then, this seat's or the network's copy of its old word, moves
           * nothing and is refused unread, whatever it costs to have
           * retained.  So no copy, however old, buys a proof, a machine or
           * a send from a record but toward the one position a seat is
           * still at.  A part of a member whose assembly this seat keeps
           * is that assembly's, whoever carries it */
          k = rx->kept;
          past = evNum < NAMED(V, evFrom) || (rx->done[evFrom >> 3] >> (evFrom & 7) & 1);
          if (evCls == AC_CLS_RCV
              ? !k && (evS == V->self || evKind != BRACHA87_INITIAL
                    || (rx->done[BITS(N) + (evFrom >> 3)] >> (evFrom & 7) & 1))
              : past && !(evKind == BRACHA87_BESIDE && k
                       && ((k->srch[evX].kept && !k->srch[evX].reported)
                        || (evCls == AC_CLS_DIST && LATE_UNIT(k, evX))))) {
            ++V->c.copy;
            ++SEATC(V, evFrom).resent;
            if (evCls != AC_CLS_RCV && DESC_OWED(V, rx, evFrom, evKind, evNum) && !END_SHUT(V) && AUTHED()) {
              DESC_AT(V, evFrom) = V->ticks + 1;
              V->descTo[evFrom] = rx;
            }
            free(blob);
            goto drain;
          }
          /* a recover leg's INITIAL under a value other than the one recorded
           * is discarded on the record, before a proof or a kept instance */
          if (evCls == AC_CLS_RCV && evKind == BRACHA87_INITIAL && !k
           && (!(V->rec[rx->off + REC_HASVAL + (evX >> 3)] & (1 << (evX & 7)))
            || memcmp(evPl, V->rec + rx->off + REC_VALS + evX * HashSz, HashSz))) {
            ++V->c.initOther;
            ++SEATC(V, evFrom).initOther;
            free(blob);
            goto drain;
          }
          if ((!k || !k->loaded) && !AUTHED()) {
            free(blob);
            goto drain;
          }
          if (!(k = rx->kept)) {
            if (V->nKept == V->keptCap) {
              struct inst **grown;

              if (!(grown = realloc(V->kept, (V->keptCap ? 2 * V->keptCap : 8) * sizeof (*grown))))
                goto rowMem;
              V->kept = grown;
              V->keptCap = V->keptCap ? 2 * V->keptCap : 8;
            }
            kt = 0;
            if (!(k = calloc(1, sizeof (*k))) || !(kt = calloc(1, INST_TAB_SZ))) {
              free(k);
              goto rowMem;
            }
            instCarve(S, k, kt);
            k->num = GET32(r + REC_NUM);
            memcpy(k->prev, r + REC_NAME, HashSz);
            memcpy(k->link, r + REC_LINK, HashSz);
            memcpy(k->subset, r + REC_SUBSET, BITS(N));
            for (i = 0; i < N; ++i) {
              if (BKR94ACS_BIT_TST(k->subset, i))
                ++k->subsetCnt;
              if (r[REC_HASVAL + (i >> 3)] & (1 << (i & 7))) {
                memcpy(VAL(k, i), r + REC_VALS + i * HashSz, HashSz);
                k->hasVal[i] = 1;
              }
              k->gen[i] = GET32(r + REC_GEN + 4 * i);
              memcpy(ROOT(k, i), r + REC_ROOT + i * HashSz, HashSz);
              memcpy(ROOTNEXT(k, i), r + REC_ROOTN + i * HashSz, HashSz);
              k->hasNext[i] = (r[REC_HASN + (i >> 3)] >> (i & 7)) & 1;
              k->verdict[i] = AC_PASS;      /* reported at its fold here: nothing assembles again */
              k->srch[i].reported = 1;
            }
            k->haveSubset = k->stepped = 1;
            k->reported0 = 1;
            k->endTick = V->ticks;
            k->rx = rx;
            rx->kept = k;
            V->kept[V->nKept++] = k;
          }
          if (!k->loaded) {
            /* this seat's unit of each member, where the position's end
             * let it go */
            for (mp = r + REC_HDR, m = 0; m < GET16(r + REC_MEMB); ++m) {
              x = mp[RM_SEAT];
              shl = GET32(mp + RM_SHLEN);
              d = &k->dist[x];
              if (x == V->self) {
                /* its own proposal's header, as the launch held it: a
                 * leg of it carries no unit back, so its BESIDE is this
                 * seat's own word under its own apex */
                memcpy(d->apex, mp + RM_APEX, HashSz);
                memcpy(d->origHash, mp + RM_APEX + HashSz, HashSz);
                memcpy(d->sssRoot, mp + RM_APEX + 2 * HashSz, HashSz);
                memcpy(d->rsecRoot, mp + RM_APEX + 3 * HashSz, HashSz);
                d->kind = mp[RM_KIND] & (RM_END - 1);
                d->end = (mp[RM_KIND] & RM_END) != 0;
                d->underNext = mp[RM_NEXT];
                d->shardLen = shl;
                d->sign = d->held = 1;
              } else if (!d->sig) {
                if (!(d->sig = malloc(SigLen)) || (!mp[RM_KIND] && shl && !(d->shard = malloc(shl)))) {
                  /* the members loaded so far stay; the next row loads
                   * the rest */
                  free(d->sig);
                  d->sig = 0;
                  goto rowMem;
                }
                memcpy(d->apex, mp + RM_APEX, HashSz);
                memcpy(d->origHash, mp + RM_APEX + HashSz, HashSz);
                memcpy(d->sssRoot, mp + RM_APEX + 2 * HashSz, HashSz);
                memcpy(d->rsecRoot, mp + RM_APEX + 3 * HashSz, HashSz);
                memcpy(d->succ, mp + RM_APEX + 4 * HashSz, HashSz);
                memcpy(d->sig, mp + RM_HDR, SigLen);
                if (!mp[RM_KIND]) {
                  memcpy(d->unit, mp + RM_HDR + SigLen, MVAL_LEN);
                  memcpy(d->sssProof, mp + RM_HDR + SigLen + MVAL_LEN, PfSz);
                  memcpy(d->rsecProof, mp + RM_HDR + SigLen + MVAL_LEN + PfSz, PfSz);
                  if (shl)
                    memcpy(d->shard, mp + RM_HDR + SigLen + MVAL_LEN + 2 * PfSz, shl);
                }
                d->kind = mp[RM_KIND] & (RM_END - 1);
                d->end = (mp[RM_KIND] & RM_END) != 0;
                d->underNext = mp[RM_NEXT];
                d->shardLen = shl;
                d->sign = 1;
                d->held = d->kind || shl;
              }
              mp += RM_HDR + SigLen + RM_BODY(mp[RM_KIND], x == V->self, shl);
            }
            k->loaded = 1;
          }
          I = k;
          /* past the end's abandon a record's machines run on to their
           * count and none starts again, whatever a row names */
          if (evCls != AC_CLS_RCV && !END_SHUT(V) && !past) {
            for (i = 0; i < N; ++i)
              if (ROUT(I, i, evFrom).f && !(bracha87Fig1State(ROUT(I, i, evFrom).f) & BRACHA87_F1_ABANDONED))
                break;
            if (i == N) {
              /* the legs at their count were heard: nothing is owed it */
              if (recHeard(V, I, evFrom)) {
                rx->done[evFrom >> 3] |= 1 << (evFrom & 7);
                ++V->c.copy;
                ++SEATC(V, evFrom).resent;
              } else {
                if (!AUTHED()) {
                  free(blob);
                  goto drain;
                }
                goto rcvLaunch;
              }
            }
          }
          /* back from rcvLaunch the block's own locals are gone: I and
           * the row's ev* carry on */
rcvLaunched:
          /* a recover leg's row to its machine; a part of a unit of a
           * member whose assembly the record keeps, to that assembly
           * [Bracha87 Section 2.1: "including those received at
           * previous steps"]; a part of the unit of an agreed member this
           * seat lacks, however late; where it is of this seat's own unit,
           * which the record written at the position's end lacks, a newer
           * copy of the record at the head takes it; the rest is noise here */
          if (evCls == AC_CLS_RCV
           || (evKind == BRACHA87_BESIDE && evCls != AC_CLS_ACS && I->srch[evX].kept && !I->srch[evX].reported)
           || (evKind == BRACHA87_BESIDE && evCls == AC_CLS_DIST && LATE_UNIT(I, evX))) {
            if (evKind == BRACHA87_BESIDE) {
              --V->c.routedUnit;
              evKept = I->srch[evX].kept && !I->srch[evX].reported ? I : 0;
            }
            dispatchSite = SITE_ARRIVAL;
            goto dispatch;
          }
          free(blob);
          goto drain;
          /* what a row would have this seat build, a kept position or
           * its legs, this seat's memory refused: the row is not taken,
           * and its sender's sweep brings it again.  A seat stops for
           * no row */
rowMem:
          ++V->c.rowMem;
          free(blob);
          goto drain;
        }
        /* a name neither live nor recorded here -- not minted yet, let
         * go past the retention, or no position's: a row received at a
         * previous step, held to count when the name is minted
         * [Bracha87 Section 3: stored by p till round k], and the
         * lossless reconciliation carries a part as routed until then.
         * One message of a type per sender a position, as the figure
         * holds: a row whose tag names a held row's name, class, kind,
         * agreement, round, initiator and sender is that message again,
         * whatever it carries -- the first is kept, with its value and
         * payload, and the annotations the later one carries are taken,
         * since the library records nothing of a duplicate but those
         * and they only ever set.  A sender's rows of one shape under
         * other names are its positions ahead of this seat, and it
         * sends for its live window of them, which this seat's own says
         * nothing of: a seat held at one position has a window of one
         * while its senders' run on.  A position stays live about an
         * abandon, so that many names are held and the rest are its
         * sweep's to bring again.  So what is held is bounded by the
         * shape of a position and the abandon, never by what a sender
         * chooses to say.  A BESIDE's part is in the
         * tag's bits 2-3 and stays in the name; a READY's HOLDING
         * there, outside class 0, is an annotation; class 0's BA value
         * there is the first's */
        nm = evKind == BRACHA87_BESIDE ? 0x3f : 0x33;
        an = 0xc0 | (evCls && evKind == BRACHA87_READY ? 0x04 : 0);
        /* the sender's rows of this shape, in name order, from the
         * least name: this name among them is this message again */
        memcpy(kb, tg + 1, AC_TAG_NAME - 1);
        memset(kb + AC_TAG_NAME - 1, 0, HashSz);
        kn.k0 = byte & nm;
        kn.key = kb;
        kn.seq = 0;
        for (sx = 0, tn = tLow(&V->ahShape, &kn); tn && tn->k0 == kn.k0 && !memcmp(tn->key, kb, AC_TAG_NAME - 1);) {
          ah = tn->own;
          if (!memcmp(AHEAD_NAME(ah), evName, HashSz)) {
            if (byte & an & ~AHEAD_TAG(ah)[0]) {
              if (!AUTHED()) {
                free(blob);
                goto drain;
              }
              AHEAD_TAG(ah)[0] |= byte & an;  /* outside the naming bits: the keys stand */
            } else
              ++V->c.copy;
            ++V->c.aheadDup;
            ++SEATC(V, evFrom).resent;
            free(blob);
            goto drain;
          }
          ++sx;
          tn = tNext(tn);
        }
        if (sx > Abandon) {
          /* the abandon's count and one more: what a sender's live
           * window sends, and the position past it a seat behind may
           * walk into */
          ++V->c.aheadFull;             /* the part stays counted as routed */
          ++SEATC(V, evFrom).heldFull;
          /* nothing is held of it, so it can only say a sender is further
           * on: its word on that, one a tick */
          if (V->rowTick[evFrom] != V->ticks + 1 && AUTHED()) {
            V->rowTick[evFrom] = V->ticks + 1;
            V->aheadNew = 1;
          }
          free(blob);
          goto drain;
        }
        if (!AUTHED()) {
          free(blob);
          goto drain;
        }
        if (!(ah = malloc(sizeof (*ah)))) {
          ++V->c.aheadMem;              /* this seat's memory: its sender re-sends it */
          V->aheadNew = 1;
          free(blob);
          goto drain;
        }
        ah->b = blob;
        ah->len = ml;
        ah->part = part;
        ah->byName.k0 = evName[0];
        ah->byName.key = AHEAD_NAME(ah) + 1;
        ah->byName.seq = ++V->ahSeq;
        ah->byName.own = ah;
        ah->byShape.k0 = byte & nm;
        ah->byShape.key = AHEAD_TAG(ah) + 1;
        ah->byShape.seq = 0;
        ah->byShape.own = ah;
        tIns(&V->ahName, &ah->byName);
        tIns(&V->ahShape, &ah->byShape);
        ++V->nAhead;
        ++V->c.future;
        ++SEATC(V, evFrom).held;
        V->aheadNew = 1;
        goto drain;
      }
      I = V->live[wi];
      ++I->gets;
      evWin = WIN_LIVE;
      evNum = I->num;
      if (evAuth) {
        ++SEATC(V, evFrom).live;
        SEATC(V, evFrom).liveTick = V->ticks;
        if (evNum > NAMED(V, evFrom))
          NAMED(V, evFrom) = evNum;
      }
      dispatchSite = SITE_ARRIVAL;
      goto dispatch;
arrivalDone:
      /* a part proved for a kept assembly, whatever its gates then said, and
       * where it is of this seat's own unit, which the record may lack, the
       * record is due anew: its copy takes only what is held */
      if (evKept && evAuth) {
        if (evCls == AC_CLS_DIST || (evCls == AC_CLS_RCV && evX == evS))
          evKept->recDue = 1;
        ++V->c.placed;
        if (V->ticks - evKept->endTick > V->c.placedAfter)
          V->c.placedAfter = V->ticks - evKept->endTick;
      }
      free(blob);
      goto drain;

    notInitiator:
      ++V->c.notInitiator;
      ++SEATC(V, evFrom).notInitiator;
      free(blob);
      goto drain;

    malformed:
      ++V->c.malformed;
      if (evFrom < N && evFrom != V->self)
        ++SEATC(V, evFrom).malformed;
      trace(V, 0, "malformed: byte=%02x class %u %s X=%u round=%u S=%u from=%u (%u bytes)",
            byte, evCls, kindName(evKind), evX, evRound, evS, evFrom, evLen);
      free(blob);
      goto drain;
    }

    /*
     * RECOVER: a row of seat evFrom's names the position I this seat
     * retains, and no recover leg of this seat's runs toward it there.
     * For every member X of the subset whose unit this seat holds under
     * X's agreed value, its own among them, one bracha87Fig1 point to
     * point, n = 2 and t = 0, this seat its initiator and evFrom the
     * other process: v = X's agreed value, and beside it this seat's
     * unit of X -- the exchange unit re-masked for evFrom, or for its
     * own value the distribution's unit to evFrom -- and the position's
     * description, the subset and every member's agreed value.  It is
     * the exchange carried to one seat, with what the agreement decided
     * beside it; X's own value goes to no recover leg to X, which dealt
     * it.  A leg at its abandon count is made anew, a send the talk had
     * begun of it being that machine's; the same v and the same bytes
     * beside it, so the fresh one says what the first did.  Back to the
     * row.
     */
  rcvLaunch:
    rcvMade = 0;
    for (i = 0; i < N; ++i) {
      if (!BKR94ACS_BIT_TST(I->subset, i) || i == evFrom || !I->dist[i].held || !I->hasVal[i]
       || !VALMATCH(VAL(I, i), &I->dist[i]))
        continue;
      g = &ROUT(I, i, evFrom);
      if (g->f) {
        if (V->eActive && V->eGate && V->eI == I && V->eG == g)
          V->eActive = 0;
        if (g->owed)
          --I->gOwed;
        free(g->f);
        memset(g, 0, sizeof (*g));
        --I->legCnt;
        --I->legGone;
      }
      if (!(g->f = calloc(1, bracha87Fig1Sz(1, HashSz - 1, 1)))
       || bracha87Fig1Init(g->f, 1, 0, HashSz - 1, 1, 0, 0, Abandon, 1)
       || bracha87Fig1Initiator(g->f, VAL(I, i))) {
        /* this seat's memory: no leg toward it for this member, the
         * returner's next row asking again */
        free(g->f);
        g->f = 0;
        ++V->c.rowMem;
        ++rcvMade;
        I->rcvMem = 1;
        continue;
      }
      ++rcvMade;
      ++I->legCnt;
      ++V->c.recoverStarts;
      trace(V, I->num, "a row of %u names this retained position: recover leg (X=%u) toward it", evFrom, i);
      memcpy(g->v, VAL(I, i), HashSz);
      g->fed = FED_INITIAL | FED_BESIDE;
      g->owed = OWED(BRACHA87_INITIAL);
      ++I->gOwed;
      fX = i;
      fS = V->self;
      bracha87Fig1Input(g->f, BRACHA87_INITIAL, 0, VAL(I, i), 0, f1out);
      nout = bracha87Fig1Input(g->f, BRACHA87_BESIDE, 0, 0, 0, f1out);
      f1site = SITE_RCV;
      goto runF1;
rcvLegDone:
      ;
    }
    /* this record holds nothing to carry it: so it stays, until it holds
     * something, for what a copy of this row would ask next, and no leg
     * runs, for a seat with no unit of X has no word on X.  It folded the
     * position all the same, and a seat with no subset counts descriptions
     * from distinct seats, so its description is owed alone.  No HOLDING
     * can answer what no leg carries, so what that seat says next from
     * the position it is at asks again */
    if (!rcvMade && I->rx) {
      I->rx->done[evFrom >> 3] |= 1 << (evFrom & 7);
      I->rx->done[2 * BITS(N) + (evFrom >> 3)] |= 1 << (evFrom & 7);
      DESC_AT(V, evFrom) = V->ticks + 1;
      V->descTo[evFrom] = I->rx;
    }
    goto rcvLaunched;

  work:
    for (;;) {
      if (V->qHead < V->qTail) {
        struct msg *m;

        m = &V->q[V->qHead++];
        for (wi = 0; wi < V->nLive + V->nKept
                     && (wi < V->nLive ? V->live[wi] : V->kept[wi - V->nLive])->num != m->inst; ++wi)
          ;
        if (wi == V->nLive + V->nKept)
          continue;
        I = wi < V->nLive ? V->live[wi] : V->kept[wi - V->nLive];
        evCls = AC_TAG_CLASS(m->byte);
        evKind = AC_TAG_KIND(m->byte);
        evValue = AC_TAG_VALUE(m->byte);
        evValue8 = evValue;
        evAnnot = AC_TAG_TO_ANN(m->byte);
        evX = m->process;
        evRound = m->round;
        evS = m->initiator;
        evFrom = V->self;
        evPl = m->v;
        evLen = HashSz;
        evAuth = 1;
        dispatchSite = SITE_HANDBACK;
        goto dispatch;
handbackDone:
        continue;
      }
      V->qHead = V->qTail = 0;
      /* the rows held ahead of a launch, those naming a live position
       * now: read as arrivals, each through the same gates, one a call
       * as acInput takes one datagram, so the caller reads its socket
       * between them and acWork says the next is due now */
      if (V->aheadDue && rpN)
        V->aheadMore = 1;
      else if (V->aheadDue) {
        /* the first held under a live name, in its arrival order */
        for (ah = 0, sx = 0; !ah && V->nAhead && sx < V->nLive; ++sx) {
          kn.k0 = V->live[sx]->prev[0];
          kn.key = V->live[sx]->prev + 1;
          kn.seq = 0;
          if ((tn = tLow(&V->ahName, &kn)) && tn->k0 == kn.k0 && !memcmp(tn->key, kn.key, HashSz - 1))
            ah = tn->own;
        }
        if (ah) {
          tDel(&V->ahName, &ah->byName);
          tDel(&V->ahShape, &ah->byShape);
          blob = ah->b;
          blobLen = ah->len;
          if (ah->part)
            --V->c.routedUnit;
          free(ah);
          --V->nAhead;
          ++V->c.replayed;
          if (++rpN > V->c.replayMost)
            V->c.replayMost = rpN;
          evAuth = 1;                   /* proved when it was held */
          goto arrival;
        }
        V->aheadDue = 0;
      }
      for (wi = 0; wi < V->nLive + V->nKept
                   && !(wi < V->nLive ? V->live[wi] : V->kept[wi - V->nLive])->subsetDue; ++wi)
        ;
      if (!lMem && wi < V->nLive + V->nKept) {
        I = wi < V->nLive ? V->live[wi] : V->kept[wi - V->nLive];
        /*
         * Exchange, at SUBSET: for every member X and every S != X one
         * leg (X, S), live until its abandon count.  This seat
         * initiates (X, self) only holding X's unit under the value
         * this seat accepted for X: v = its apex, the unit re-masked
         * per recipient beside the INITIAL (X alone gets the INITIAL:
         * it dealt the unit), self fed straight back.  A unit or a
         * value landing after SUBSET runs this again, so a leg starts
         * when its condition is met, whenever that is.  A record's
         * assembly launches none: a link the retention holds is
         * recovered, never exchanged again.
         */
        I->subsetDue = 0;
        if (I->rx)
          continue;
        for (i = 0; i < N; ++i) {
          if (!BKR94ACS_BIT_TST(I->subset, i))
            continue;
          for (j = 0; j < N; ++j) {
            struct gate *gg;

            if (j == i)
              continue;
            gg = &LEG(I, i, j);
            if (gg->f)
              continue;
            if (j == V->self
             && (i == V->self || !I->dist[i].held || !I->hasVal[i]
              || !VALMATCH(VAL(I, i), &I->dist[i])))
              continue;
            if (!(gg->f = calloc(1, bracha87Fig1Sz(N - 1, HashSz - 1, MaxByz + 1)))) {
              /* this seat's memory refused it: the legs made stand, and
               * the rest wait for the seat's next call */
              I->subsetDue = 1;
              ++V->c.ownMem;
              lMem = 1;
              goto legsMem;
            }
            if (bracha87Fig1Init(gg->f, N - 1, MaxByz, HashSz - 1, MaxByz + 1, j, V->self, Abandon, 1))
              goto exit;
            ++I->legCnt;
            if (j != V->self)
              continue;
            if (bracha87Fig1Initiator(gg->f, VAL(I, i)))
              goto exit;
            memcpy(gg->v, VAL(I, i), HashSz);
            gg->fed = FED_INITIAL | FED_BESIDE;
            trace(V, I->num, "leg (X=%u S=%u) launched", i, j);
            gg->owed = OWED(BRACHA87_INITIAL);
            ++I->gOwed;
            g = gg;
            fX = i;
            fS = j;
            bracha87Fig1Input(g->f, BRACHA87_INITIAL, V->self, VAL(I, i), 0, f1out);
            nout = bracha87Fig1Input(g->f, BRACHA87_BESIDE, V->self, 0, 0, f1out);
            f1site = SITE_LAUNCH;
            goto runF1;
launchLegDone:
            ;
          }
        }
        continue;
      }
      break;
    }

legsMem:
    for (wi = 0; wi < V->nLive + V->nKept; ++wi) {
    I = wi < V->nLive ? V->live[wi] : V->kept[wi - V->nLive];

    /*
     * Assemble: a part of X landed, or SUBSET, and only once this
     * seat's ACS is COMPLETE with X in the subset: nothing acts on a
     * value before the agreement on it.  What the agreed hash is, the
     * sign part held under it says: a rotation or a noop is public and
     * whole in any one, and is X's word at that.  A payload's pool is
     * every part held under that apex -- a share from each held sign
     * part, a shard from each held shard, the own unit's at this seat's
     * leaf -- in arrival order, and at T shares and T shards it is
     * SEARCHED and, after PASS, RE-ENCODED as cryptoMule's assemble
     * does [cryptoMule assemble.c], with two departures.  An arrival
     * tries only the subsets that touch it, where cryptoMule reads one
     * more part only after a failed search.  And at T + 1 shares, the
     * one count where a good subset's only outside share may be the bad
     * one, the relaxed pass follows the agreed one over the same new
     * subsets, so T good parts beside one bad give the message at that
     * arrival; above T + 1 it runs once over every subset, with every
     * part held or at the position's end -- a relaxed pass at every
     * arrival would make each wrong K a standing candidate against
     * every new shard subset, the product of two enumerations the
     * budget then pays for.  An inconsistent commitment withholds the
     * message, its leaves off the re-encode named beside it.  No
     * message is a report too, each its own word: every subset tried at
     * threshold, or the try budget spent, which has shown nothing
     * either way, or under threshold when the retention lets the
     * position's record go.  A last pass this seat's memory refuses is
     * owed: the assembly goes with the record as one under threshold
     * does, the pass taken again at every tick, and is reported with no
     * verdict only where the memory still refuses it when the retention
     * lets the record go.
     */
    for (i = 0; i < N; ++i) {
      struct dist *d;
      struct exch *e;
      struct search *s;
      struct comb sc;                   /* shares: the outer search */
      struct comb dc;                   /* shards: the inner, per K */
      const unsigned char *agreed;
      const unsigned char *origHash;
      const unsigned char *sssRoot;
      const unsigned char *rsecRoot;
      unsigned char *shareU[AC_SEATS];             /* the share pool: each [seed][share] */
      const unsigned char *shardP[AC_SEATS];       /* the shard pool */
      unsigned char *sharePtr[AC_SEATS];           /* the subset under trial */
      const unsigned char *shardPtr[AC_SEATS];
      unsigned char *outPtr[AC_SEATS];             /* the held shares outside
                                                    * the subset: agreement */
      unsigned char *dptr[AC_SEATS];
      const unsigned char *rePtr[AC_SEATS];
      unsigned char *pptr[AC_SEATS];
      unsigned char *reSharePtr[AC_SEATS];
      const unsigned char *leafPtr[AC_SEATS];
      unsigned int ssel[AC_SEATS];
      unsigned int sa[AC_SEATS];
      unsigned int sb[AC_SEATS];
      unsigned int dsel[AC_SEATS];
      unsigned int da[AC_SEATS];
      unsigned int db[AC_SEATS];
      unsigned char sharePt[AC_SEATS];             /* each pool share's derived output point */
      unsigned char shareScp[AC_SEATS];
      unsigned char ptSel[AC_SEATS];
      unsigned char outPts[AC_SEATS];
      unsigned char xidx[AC_SEATS];
      unsigned char pool[256];
      unsigned char kkey[KEY_LEN];
      unsigned char *kptr[1];
      unsigned char h[AC_HASH_MAX];
      unsigned char probe;
      unsigned char *outBuf;            /* R x KEY_LEN */
      unsigned char *dbuf;              /* the decoded ciphertext, k x shardLen */
      unsigned char *ptbuf;             /* the ciphertext XOR the hoisted keystream */
      unsigned char *ks;
      unsigned char *parity;
      unsigned char *reShare;
      unsigned char *reLeaf;
      unsigned char *rswork;
      unsigned char *sssw;
      unsigned char *rsecw;
      unsigned char *recovered;
      unsigned char *grown;
      const unsigned char *p;
      unsigned int recCap;
      unsigned int x;
      unsigned int rr;
      unsigned int kk;
      unsigned int m;
      unsigned int q;
      unsigned int no;
      unsigned int agree;
      int whole;                        /* every held share outside the subset on its polynomial */
      unsigned int leaf;
      unsigned int shardLen;
      unsigned int declen;
      unsigned char scp;
      unsigned char kind;
      unsigned char verdict;
      int added;
      int reOk;                         /* after PASS: rePtr holds the canonical codeword */

      x = i;
      if (!I->asmDue[x])
        continue;
      I->asmDue[x] = 0;
      if (x == V->self)
        continue;
      s = &I->srch[x];
      /* a verdict ends the search */
      if (I->verdict[x])
        continue;
      /* X in this seat's subset, its value the ACS's: parts can land
       * first, from faster seats' legs, and nothing acts on them until
       * this seat's COMPLETE */
      if (!I->haveSubset || !BKR94ACS_BIT_TST(I->subset, x) || !I->hasVal[x])
        continue;
      agreed = VAL(I, x);
      d = &I->dist[x];
      rr = N - 1;
      kk = Threshold;
      m = rr - kk;
      /* what the hash is, from the first sign part held under it: a
       * rotation or a noop is whole there */
      kind = 0;
      for (leaf = 0; leaf < rr; ++leaf) {
        if (leaf == LEAF(x, V->self)) {
          if (!d->sign || memcmp(d->apex, agreed, HashSz))
            continue;
          kind = d->kind;
        } else {
          e = &EXCH(I, x, leaf);
          if (!e->sign || memcmp(EX_APEX(e), agreed, HashSz))
            continue;
          kind = e->kind;
        }
        break;
      }
      if (leaf < rr && kind) {
        if (kind == AC_ROTATION)
          I->isRot[x] = 1;
        else
          I->isNoop[x] = 1;
        I->verdict[x] = AC_PASS;
        trace(V, I->num, "%u's %s, at one sign part", x,
              kind == AC_ROTATION ? "rotation" : "noop");
        continue;
      }
      if (!s->triedK) {
        s->kcap = rr;
        if (TESTREFUSE(V, x, s, 1)
         || !(s->shareLeaf = malloc(2 * rr))
         || !(s->triedK = malloc(s->kcap * (KEY_LEN + kk + 1)))) {
          free(s->shareLeaf);
          s->shareLeaf = 0;
          ++V->c.asmAlloc;              /* this seat's memory, not the
                                         * member's: owed, tried again */
          s->owed = 1;
          continue;
        }
        s->shardLeaf = s->shareLeaf + rr;
        s->cs = s->cd = 0;
        s->kSel = s->triedK + s->kcap * KEY_LEN;
        s->kSearched = s->kSel + s->kcap * kk;
      }
      /* the pool grows by the parts held under the agreed apex since
       * the last search, in arrival order */
      added = 0;
      for (leaf = 0; leaf < rr; ++leaf) {
        const unsigned char *ap;
        int haveShare;
        int haveShard;

        if (leaf == LEAF(x, V->self)) {
          ap = d->apex;
          haveShare = d->sign;
          haveShard = d->held;
        } else {
          e = &EXCH(I, x, leaf);
          ap = EX_APEX(e);
          haveShare = e->sign;
          haveShard = e->held;
        }
        if (!haveShare || memcmp(ap, agreed, HashSz))
          continue;
        for (q = 0; q < s->cs && s->shareLeaf[q] != leaf; ++q)
          ;
        if (q == s->cs) {
          s->shareLeaf[s->cs++] = leaf;
          added = 1;
        }
        if (!haveShard)
          continue;
        for (q = 0; q < s->cd && s->shardLeaf[q] != leaf; ++q)
          ;
        if (q == s->cd) {
          s->shardLeaf[s->cd++] = leaf;
          added = 1;
        }
      }
      if (added)
        s->partAt = V->ticks;
      if (I->verdict[x] != AC_PASS) {
        if (s->cs < kk || s->cd < kk) {
          s->owed = 0;                  /* no search is owed under threshold */
          /* under threshold: the next part tries again.  The position
           * leaving the live window ends nothing here: a part still in
           * flight is received all the same, and the record places it.
           * The retention letting the record go is the end: nothing
           * more lands */
          if (s->final && I->gone) {
            I->verdict[x] = AC_UNDER;
            trace(V, I->num, "the record let go with %u under threshold: %u shares, %u shards", x, s->cs, s->cd);
          } else if (s->final) {
            /* kept already where its last pass was owed: the pass, had,
             * found it under threshold, and the record places the rest */
            if (!s->kept)
              trace(V, I->num, "leaving the live window with %u under threshold: %u shares, %u shards; its record places the rest",
                    x, s->cs, s->cd);
            s->kept = 1;
            s->final = 0;
          }
          continue;
        }
        if (!added && !s->final && !s->owed)
          continue;                     /* nothing new to try */
      }
      /* the pool by pool index: each share's unit and derived points,
       * each shard; the header from the first share's holder (every
       * sign part under one apex carries the one header), the shard
       * length from the first shard (the rsecMk root binds it) */
      origHash = sssRoot = rsecRoot = 0;
      shardLen = 0;
      for (q = 0; q < s->cs; ++q) {
        leaf = s->shareLeaf[q];
        if (leaf == LEAF(x, V->self)) {
          shareU[q] = d->unit;
          sharePt[q] = d->ocp;
          shareScp[q] = d->scp;
          if (!q) {
            origHash = d->origHash;
            sssRoot = d->sssRoot;
            rsecRoot = d->rsecRoot;
          }
        } else {
          e = &EXCH(I, x, leaf);
          shareU[q] = e->unit;
          sharePt[q] = e->ocp;
          shareScp[q] = e->scp;
          if (!q) {
            origHash = EX_ORIG(e);
            sssRoot = EX_SSS(e);
            rsecRoot = EX_RSEC(e);
          }
        }
      }
      for (q = 0; q < s->cd; ++q) {
        leaf = s->shardLeaf[q];
        if (leaf == LEAF(x, V->self)) {
          shardP[q] = d->shard;
          if (!q)
            shardLen = d->shardLen;
        } else {
          e = &EXCH(I, x, leaf);
          shardP[q] = EX_SHARD(e);
          if (!q)
            shardLen = e->shardLen;
        }
      }
      recovered = 0;
      recCap = 0;
      outBuf = malloc(rr * KEY_LEN);
      dbuf = malloc(kk * shardLen);
      ptbuf = malloc(kk * shardLen);
      ks = malloc(kk * shardLen);
      parity = malloc((m ? m : 1) * shardLen);
      reShare = malloc(rr * KEY_LEN);
      reLeaf = malloc(rr * MVAL_LEN);
      rswork = malloc(RS_WORK_SIZE(kk));
      sssw = malloc(sssMkWaSz(SignH, rr));
      rsecw = malloc(rsecMkWaSz(SignH, rr));
      if (TESTREFUSE(V, x, s, 0) || !outBuf || !dbuf || !ptbuf || !ks || !parity || !reShare || !reLeaf
       || !rswork || !sssw || !rsecw) {
        ++V->c.asmAlloc;                /* this seat's memory, not the
                                         * member's: owed, tried again */
        s->owed = 1;
        goto asmFree;
      }
      s->owed = 0;
      for (j = 0; j < kk; ++j)
        dptr[j] = dbuf + j * shardLen;
      kptr[0] = kkey;

      /* the search over the pool in hand [cryptoMule assemble.c].  Only
       * subsets that touch a part gathered since the last search are
       * new: a subset whose every index is below the pool size then is
       * one already tried */
    search:
      sc.sel = ssel; sc.a = sa; sc.b = sb; sc.h = s->cs; sc.t = kk; sc.begun = 0;
      while (combNext(&sc)) {
        whole = 0;
        for (j = 0; j < kk && ssel[j] < s->csOld; ++j)
          ;
        if (j == kk)
          continue;                     /* tried against an earlier pool */
        if (++s->tries > SEARCH_TRIES)
          goto budget;
        /* one seed across the subset: the geometry the points derive
         * from */
        for (j = 1; j < kk && !memcmp(shareU[ssel[j]], shareU[ssel[0]], SEED_LEN); ++j)
          ;
        if (j < kk)
          continue;
        for (j = 0; j < kk; ++j) {
          sharePtr[j] = shareU[ssel[j]] + SEED_LEN;
          ptSel[j] = sharePt[ssel[j]];
        }
        scp = shareScp[ssel[0]];
        sss(ptSel, &scp, sharePtr, kptr, kk, 1, KEY_LEN);
        /* a candidate when one more held share lies on the polynomial,
         * as cryptoMule orders them.  Every held share outside lying on
         * it is the whole pool one polynomial: every other subset gives
         * this K again, so the shares are done with and the shards are
         * next -- an honest dealer's pool is that, and enumerating it,
         * C(R, T) subsets of one K, would spend the budget before a
         * shard was tried */
        if (s->cs > kk && !s->relaxed) {
          for (no = q = 0; q < s->cs; ++q) {
            for (j = 0; j < kk && ssel[j] != q; ++j)
              ;
            if (j < kk || memcmp(shareU[q], shareU[ssel[0]], SEED_LEN))
              continue;
            outPts[no] = sharePt[q];
            outPtr[no] = outBuf + q * KEY_LEN;
            ++no;
          }
          if (no) {                     /* none of its geometry outside: a
                                         * candidate as the sole subset is */
            sss(ptSel, outPts, sharePtr, outPtr, kk, no, KEY_LEN);
            for (agree = q = 0; q < no; ++q)
              if (!memcmp(outPtr[q], shareU[(outPtr[q] - outBuf) / KEY_LEN] + SEED_LEN, KEY_LEN))
                ++agree;
            if (!agree)
              continue;
            whole = agree == no && no == s->cs - kk;
          }
        }
        for (q = 0; q < s->nK && memcmp(s->triedK + q * KEY_LEN, kkey, KEY_LEN); ++q)
          ;
        if (q < s->nK) {
          if (whole)
            break;
          continue;                     /* this K is a candidate already */
        }
        if (s->nK == s->kcap) {         /* the list grows: the budget ends this, never the list */
          unsigned char *grownK;
          unsigned int cap2;

          cap2 = 2 * s->kcap;
          if (!(grownK = malloc(cap2 * (KEY_LEN + kk + 1)))) {
            ++V->c.asmAlloc;            /* this seat's memory: owed, tried again */
            s->owed = 1;
            goto asmFree;
          }
          memcpy(grownK, s->triedK, s->nK * KEY_LEN);
          memcpy(grownK + cap2 * KEY_LEN, s->kSel, s->nK * kk);
          memcpy(grownK + cap2 * (KEY_LEN + kk), s->kSearched, s->nK);
          memset(s->triedK, 0, s->nK * KEY_LEN);
          free(s->triedK);
          s->triedK = grownK;
          s->kSel = grownK + cap2 * KEY_LEN;
          s->kSearched = s->kSel + cap2 * kk;
          s->kcap = cap2;
        }
        memcpy(s->triedK + s->nK * KEY_LEN, kkey, KEY_LEN);
        for (j = 0; j < kk; ++j)
          s->kSel[s->nK * kk + j] = ssel[j];
        s->kSearched[s->nK] = 0;
        ++s->nK;
        if (whole)
          break;
      }
      for (q = 0; q < s->nK; ++q) {
        if (s->kSearched[q] == s->cd)
          continue;                     /* no shard gathered since this K was searched under */
        memset(ks, 0, kk * shardLen);
        keystream(S, s->triedK + q * KEY_LEN, origHash, ks, kk * shardLen);
        dc.sel = dsel; dc.a = da; dc.b = db; dc.h = s->cd; dc.t = kk; dc.begun = 0;
        while (combNext(&dc)) {
          for (j = 0; j < kk && dsel[j] < s->kSearched[q]; ++j)
            ;
          if (j == kk)
            continue;                   /* tried under this K against an earlier pool */
          if (++s->tries > SEARCH_TRIES)
            goto budget;
          for (j = 0; j < kk; ++j) {
            shardPtr[j] = shardP[dsel[j]];
            xidx[j] = s->shardLeaf[dsel[j]];
          }
          if (rsecDecode(shardPtr, xidx, dptr, shardLen, kk, m, rswork))
            continue;
          for (j = 0; j < kk * shardLen; ++j)
            ptbuf[j] = dbuf[j] ^ ks[j];
          /* the stream embeds the original length: probe it, size the
           * buffer, decode.  hufDecode answers 0 for an error and for
           * an EMPTY message alike (huf.h), and the hash of nothing is
           * the oracle's own blind spot, so the plaintext tells them
           * apart; a wrong try's garbage stream self-describes any
           * length, so a probe past what the message admits is that try
           * failing */
          declen = hufDecode(&probe, 0, ptbuf, kk * shardLen);
          if (!declen && (kk * shardLen < 2 || ptbuf[0] || ptbuf[1]))
            continue;                   /* a probe of 0 is the empty message only as the
                                         * two-byte stream of nothing, 00 00 (huf.h); the
                                         * padding behind it is the re-encode's to judge */
          if (declen > MsgMax)
            continue;
          if (declen > recCap) {
            if (!(grown = realloc(recovered, declen))) {
              ++V->c.asmAlloc;          /* this seat's memory: the subset is owed, not spent */
              s->owed = 1;
              goto asmFree;
            }
            recovered = grown;
            recCap = declen;
          }
          if (declen && hufDecode(recovered, declen, ptbuf, kk * shardLen) != declen)
            continue;
          if (hashBuf(S, recovered, declen, 0, 0, 0, 0, 0, 0, h)) {
            ++V->c.asmAlloc;            /* this seat's memory: the subset is owed, not spent */
            s->owed = 1;
            goto asmFree;
          }
          if (!memcmp(h, origHash, HashSz)) {
            memcpy(kkey, s->triedK + q * KEY_LEN, KEY_LEN);
            for (j = 0; j < kk; ++j)
              ssel[j] = s->kSel[q * kk + j];
            goto found;
          }
        }
        s->kSearched[q] = s->cd;
      }
      /* nothing from the agreed pass: the relaxed pass at T + 1 shares
       * now, over the same new subsets, and over every subset once at
       * the end (Assemble, above).  The candidates the T + 1 pass adds
       * stand only by a PASS: finding nothing, it retires them, and the
       * pass at the end tries them again.  Else the next part tries
       * again.  An allocation failure inside a relaxed pass leaves it
       * set, and the retry resumes it */
      if (!s->relaxed && ((s->cs == rr && s->cd == rr) || s->final)) {
        s->relaxed = 1;                 /* the end: every subset, retired candidates among them */
        s->csOld = 0;
        goto search;
      }
      if (!s->relaxed && s->cs == kk + 1) {
        s->relaxed = 1;
        s->nKold = s->nK;
        goto search;
      }
      if (s->relaxed && ((s->cs == rr && s->cd == rr) || s->final))
        goto exhausted;
      if (s->relaxed && s->nK > s->nKold) {
        memset(s->triedK + s->nKold * KEY_LEN, 0, (s->nK - s->nKold) * KEY_LEN);
        s->nK = s->nKold;
      }
      s->relaxed = 0;
      s->csOld = s->cs;
      goto asmFree;

    foundMem:
      /* this seat's memory refused a root's hash, which is no judgment
       * of the commitment: the message is let go and the search owed,
       * and it finds the same subset again, its K kept and its shards
       * not marked searched */
      ++V->c.asmAlloc;
      s->owed = 1;
      s->inconsistent = 0;
      if (I->msg[x]) {
        memset(I->msg[x], 0, I->msgLen[x]);
        free(I->msg[x]);
        I->msg[x] = 0;
      }
      I->msgLen[x] = 0;
      goto asmFree;

    exhausted:
      verdict = AC_EXHAUSTED;
      trace(V, I->num, "no subset of %u shares and %u shards reproduces %u's signed hash: every subset tried, %u tries",
            s->cs, s->cd, x, s->tries);
      goto asmDone;

    budget:
      /* the budget spent has shown nothing either way: a report says
       * what it knows, and this is not exhaustion */
      verdict = AC_BUDGET;
      trace(V, I->num, "the try budget spent on %u's %u shares and %u shards: %u tries, no subset shown",
            x, s->cs, s->cd, s->tries);
      goto asmDone;

    found:
      verdict = AC_PASS;
      I->msg[x] = recovered;            /* the message, kept for the report */
      I->msgLen[x] = declen;
      recovered = 0;
      recCap = 0;
      /* DEALER CONSISTENCY after PASS [cryptoMule assemble.c]: both
       * codes re-encoded against the SIGNED commitment, the RS side
       * from the message's own stream, and every held leaf off it named */
      for (j = 0; j < kk; ++j) {
        sharePtr[j] = shareU[ssel[j]] + SEED_LEN;
        ptSel[j] = sharePt[ssel[j]];
      }
      memset(dbuf, 0, kk * shardLen);
      if (!(q = hufEncode(dbuf, kk * shardLen, I->msgLen[x] ? I->msg[x] : &probe, I->msgLen[x]))
       || q > kk * shardLen)
        s->inconsistent = 1;            /* the committed stream is not
                                         * the message's at this length */
      else {
        keystream(S, kkey, origHash, dbuf, kk * shardLen);
        for (j = 0; j < kk; ++j)
          rePtr[j] = dptr[j];
        for (j = 0; j < m; ++j)
          rePtr[kk + j] = pptr[j] = parity + j * shardLen;
      }
      reOk = 0;
      if (!s->inconsistent && !rsecEncode(rePtr, pptr, shardLen, kk, m)) {
        if (!(p = rsecMkHash(&RsecPlug, rePtr, shardLen, rr, rsecw)))
          goto foundMem;
        if (memcmp(p, rsecRoot, HashSz))
          s->inconsistent = 1;
        reOk = 1;                       /* rePtr is the canonical codeword */
      }
      geometry(S, shareU[ssel[0]], N, pool);
      for (j = 0; j < rr; ++j)
        reSharePtr[j] = reShare + j * KEY_LEN;
      sss(ptSel, pool + 1, sharePtr, reSharePtr, kk, rr, KEY_LEN);
      for (j = 0; j < rr; ++j) {
        memcpy(reLeaf + j * MVAL_LEN, shareU[ssel[0]], SEED_LEN);
        memcpy(reLeaf + j * MVAL_LEN + SEED_LEN, reSharePtr[j], KEY_LEN);
        leafPtr[j] = reLeaf + j * MVAL_LEN;
      }
      if (!(p = sssMkHash(&SssPlug, pool[0], pool + 1, leafPtr, MVAL_LEN, rr, sssw)))
        goto foundMem;
      if (memcmp(p, sssRoot, HashSz))
        s->inconsistent = 1;
      trace(V, I->num, "%u's message, %u bytes, at %u tries from %u shares and %u shards; commitment %s",
            x, declen, s->tries, s->cs, s->cd, s->inconsistent ? "INCONSISTENT" : "consistent");

      /* every leaf held, named against the canonical codes: a held
       * shard off the codeword, a held share off the polynomial or of
       * another seed */
      memset(s->badShares, 0, sizeof (s->badShares));
      memset(s->badShards, 0, sizeof (s->badShards));
      if (reOk)
        for (q = 0; q < s->cd; ++q)
          if (memcmp(shardP[q], rePtr[s->shardLeaf[q]], shardLen))
            s->badShards[s->shardLeaf[q] >> 3] |= 1 << (s->shardLeaf[q] & 7);
      for (q = 0; q < s->cs; ++q)
        if (memcmp(shareU[q], shareU[ssel[0]], SEED_LEN)
         || memcmp(shareU[q] + SEED_LEN, reShare + s->shareLeaf[q] * KEY_LEN, KEY_LEN))
          s->badShares[s->shareLeaf[q] >> 3] |= 1 << (s->shareLeaf[q] & 7);
      /* an inconsistent commitment's message is no seat's: which seats
       * reproduce the hash is which leaves reach them, and the leaves
       * one forwards are its own to give or withhold */
      if (s->inconsistent)
        verdict = AC_INCONSISTENT;

    asmDone:
      I->verdict[x] = verdict;
      memset(s->triedK, 0, s->kcap * KEY_LEN);   /* the K candidates, the real one among them */

    asmFree:
      memset(kkey, 0, sizeof (kkey));
      memset(pool, 0, sizeof (pool));
      if (outBuf)
        memset(outBuf, 0, rr * KEY_LEN);
      if (reShare)
        memset(reShare, 0, rr * KEY_LEN);
      if (reLeaf)
        memset(reLeaf, 0, rr * MVAL_LEN);
      if (sssw)
        memset(sssw, 0, sssMkWaSz(SignH, rr));
      if (ptbuf)
        memset(ptbuf, 0, kk * shardLen);  /* the compressed plaintext */
      if (ks)
        memset(ks, 0, kk * shardLen);     /* the keystream */
      if (dbuf)
        memset(dbuf, 0, kk * shardLen);   /* the ciphertext, or the canonical stream unkeyed */
      if (recovered && recCap)
        memset(recovered, 0, recCap);     /* a wrong try's bytes */
      free(outBuf);
      free(dbuf);
      free(ptbuf);
      free(ks);
      free(parity);
      free(reShare);
      free(reLeaf);
      free(rswork);
      free(sssw);
      free(rsecw);
      free(recovered);
    }

    /*
     * The fold, once SUBSET is held: every member's value is the ACS's,
     * and the sign part held under it says the member's kind and
     * context and, for a payload, carries the message hash.  The
     * chain's head, the subset and the members' hashes in subset order
     * hash into the link, the new head, and the positions after this
     * one mask under every pair's key stepped by HKDF(key, link ||
     * 'R'), which the walk from the floor applies at use (keyWalk):
     * nothing is stepped here but the chain.
     */
    if (I->haveSubset && !I->stepped) {
      const unsigned char *fMsg[AC_SEATS];       /* the member's message hash */
      const unsigned char *fSucc[AC_SEATS];      /* a rotation member's successor key */
      unsigned char fRot[AC_SEATS];        /* the member's proposal is a rotation */
      unsigned char fNoop[AC_SEATS];       /* or a noop */
      unsigned char fEnd[AC_SEATS];        /* either carrying the end */
      unsigned char fNext[AC_SEATS];       /* and is signed under its successor */
      unsigned int fOff[AC_SEATS];         /* at this signing offset */

      /* every member's agreed value is a hash; the sign part held under
       * it says what it is, the context that signed it and what the
       * hash is of: a payload's message hash in its signed header, a
       * rotation's successor key */
      memset(fMsg, 0, sizeof (fMsg));
      memset(fSucc, 0, sizeof (fSucc));
      memset(fRot, 0, sizeof (fRot));
      memset(fNoop, 0, sizeof (fNoop));
      memset(fEnd, 0, sizeof (fEnd));
      memset(fNext, 0, sizeof (fNext));
      for (i = 0; i < N; ++i) {
        const unsigned char *ap;
        unsigned int leaf;

        if (!BKR94ACS_BIT_TST(I->subset, i) || i == V->self)
          continue;
        if (!I->hasVal[i])
          break;
        ap = VAL(I, i);
        if (I->dist[i].sign && VALMATCH(ap, &I->dist[i])) {
          fRot[i] = I->dist[i].kind == AC_ROTATION;
          fNoop[i] = I->dist[i].kind == AC_NOOP;
          fEnd[i] = I->dist[i].end;
          fNext[i] = I->dist[i].underNext;
          fOff[i] = I->dist[i].off;
          if (!I->dist[i].kind)
            fMsg[i] = I->dist[i].origHash;
          else if (fRot[i])
            fSucc[i] = I->dist[i].succ;
          continue;
        }
        for (leaf = 0; leaf < N - 1; ++leaf)
          if (EXCH(I, i, leaf).sign && VALMATCHX(ap, &EXCH(I, i, leaf)))
            break;
        if (leaf == N - 1)
          break;
        fRot[i] = EXCH(I, i, leaf).kind == AC_ROTATION;
        fNoop[i] = EXCH(I, i, leaf).kind == AC_NOOP;
        fEnd[i] = EXCH(I, i, leaf).end;
        fNext[i] = EXCH(I, i, leaf).underNext;
        fOff[i] = EXCH(I, i, leaf).off;
        if (!EXCH(I, i, leaf).kind)
          fMsg[i] = EX_ORIG(&EXCH(I, i, leaf));
        else if (fRot[i])
          fSucc[i] = EX_SUCC(&EXCH(I, i, leaf));
      }
      if (i == N) {
        void *h;

        /*
         * The book moves here, at the agreement, so at the same
         * instance at every seat.  A member signed under its successor
         * has switched: it is PROMOTED, the successor its key and a new
         * record begun.  A member whose proposal is a rotation has its
         * successor, from the held sign part, INSTALLED beside its key.
         * This seat's own rotation, a member, is agreed and let go;
         * left out, it is kept to be presented again.
         */
        for (i = 0; i < N; ++i) {
          if (!BKR94ACS_BIT_TST(I->subset, i))
            continue;
          if (i == V->self) {
            fRot[i] = I->own->kind == AC_ROTATION;
            fNoop[i] = I->own->kind == AC_NOOP;
            fEnd[i] = I->own->end;
            fNext[i] = I->own->underNext;
            fOff[i] = I->own->off;
            fSucc[i] = I->own->succ;
          }
          /* the signer's offset high water is raised here, on SUBSET
           * inclusion, and nowhere else [cryptoMule offsetgate.c, at
           * receive].  Above it raises it; at or below it, the member's
           * part passed the arrival gate against this same high water,
           * so it is the value presented again.  Either way the
           * position it was last confirmed at is this one. */
          {
            unsigned int gen;

            gen = I->gen[i] + fNext[i];
            if (!V->hwSet[i] || gen > V->hwGen[i] || (gen == V->hwGen[i] && fOff[i] > V->hwOff[i])) {
              V->hwSet[i] = 1;
              V->hwGen[i] = gen;
              V->hwOff[i] = fOff[i];
              memcpy(HWAPEX(V, i), i == V->self ? I->own->apex : VAL(I, i), HashSz);
            }
            V->hwPos[i] = I->num;
          }
          if (i == V->self && V->pend == I->own) {
            ownDrop(S, V->pend);
            V->pend = 0;
          }
          if (fNext[i]) {
            memcpy(PUB(V, i), ROOTNEXT(I, i), HashSz);
            V->hasNext[i] = 0;
            ++V->promoted[i];
            ++I->promo;
            I->promoted[i] = 1;
            trace(V, I->num, "promoted %u to its successor %02x%02x..", i,
                  PUB(V, i)[0], PUB(V, i)[1]);
          }
          if (fRot[i]) {
            memcpy(PUBNEXT(V, i), fSucc[i], HashSz);
            V->hasNext[i] = 1;
            ++I->rot;
          }
          if (fNoop[i])
            ++I->noop;
        }
        /* a payload, agreed, is let go; left out, it is kept, and
         * presented again only where the caller, asked, gives the same
         * bytes: what follows it is the caller's, at this chain report.
         * A noop left out is let go: its agreement would install
         * nothing and fold nothing, a position launched for it alone
         * costing every seat N agreements for nothing; the slot it
         * spent stays spent */
        if (I->own->kind == AC_PAYLOAD) {
          if (BKR94ACS_BIT_TST(I->subset, V->self)) {
            if (V->cache == I->own) {
              ownDrop(S, V->cache);
              V->cache = 0;
            }
          } else if (V->cache != I->own) {
            ownDrop(S, V->cache);
            V->cache = I->own;
            ++V->cache->ref;
            trace(V, I->num, "the payload left out is kept: the caller's same bytes present it again");
          }
        } else if (I->own->kind == AC_NOOP && !BKR94ACS_BIT_TST(I->subset, V->self))
          trace(V, I->num, "the noop left out is let go");
        /*
         * The link: the head, the subset, and every member's hash as
         * the chain's report carries it, in subset order -- the subset,
         * since two members may say the same bytes and the link commits
         * who said them; a payload's MESSAGE hash, which the
         * application that gave the message, and the one it is
         * delivered to, can compute, where the apex is what is signed
         * and agreed and its signed header carries the message hash it
         * commits; a rotation's or a noop's value.  Every fold mints a
         * link, since the link is the next position's name and no two
         * positions may share one; the book is where identity advances,
         * and the mask keys step on every link.
         */
        h = V->hLink;
        Sign->init(h);
        Sign->update(h, V->chain, HashSz);
        Sign->update(h, I->subset, BITS(N));
        for (i = 0; i < N; ++i) {
          if (!BKR94ACS_BIT_TST(I->subset, i))
            continue;
          if (i == V->self)
            Sign->update(h, I->own->kind ? I->own->apex : I->own->origHash, HashSz);
          else
            Sign->update(h, fRot[i] || fNoop[i] ? VAL(I, i) : fMsg[i], HashSz);
        }
        Sign->final(h, V->chain);
        trace(V, I->num, "folded: link %02x%02x.., the next position's name, the positions after it mask one step on",
              V->chain[0], V->chain[1]);
        memcpy(I->link, V->chain, HashSz);
        I->stepped = 1;
        I->foldTick = V->ticks;
        ++V->folded;
        /*
         * The end: the first fold whose subset holds more than t
         * members carrying it, counted in this one subset.  t faulty
         * seats cannot reach the count, so a correct seat's caller
         * asked for it; and every correct seat that folds this position
         * reads the same subset and the same sign parts, so the chain
         * ends here at every one of them, or at none.  Nothing launches
         * after it; the link just minted is the final hash
         */
        for (j = 0, i = 0; i < N; ++i)
          j += BKR94ACS_BIT_TST(I->subset, i) && fEnd[i];
        if (j > MaxByz) {
          I->last = 1;
          V->lastLink = I->num;
          trace(V, I->num, "the chain's end: %u members carry it, more than t; the final hash %02x%02x..",
                j, V->chain[0], V->chain[1]);
        }
      }
    }

    /*
     * The reports, as the messages flow.  The chain's, once, at the
     * fold, which is ACS COMPLETE: the chain hash before this instance,
     * the subset, every member's hash -- a payload's message hash from
     * the sign part held under its agreed value, a rotation's or a
     * noop's the value itself -- and the chain hash after it.  The
     * messages', one per member, at that member's verdict here -- the
     * message at its PASS, judged over every leaf held by then, or why
     * none -- or, where this seat's memory refused the search, with
     * none at the position's end; never held for the others, since some
     * come only by recovery.  Each is a call to the caller's chain or
     * message, made as it is built.
     */
    /* an unfolded position reports nothing, a subset held or not: it is
     * reported when it is folded here.  Unfolded it stays live until it
     * is, or retention takes it */
    if (!I->reported0 && I->stepped) {
      struct acChain rc;

      memset(RT_HASH(V), 0, RT_SZ(V));
      rc.prev = I->prev;
      rc.next = I->link;
      rc.subset = I->subset;
      rc.hash = RT_HASH(V);
      rc.successor = RT_SUCC(V);
      rc.kind = RT_KIND(V);
      rc.ending = RT_END(V);
      rc.end = I->last;
      rc.promoted = I->promoted;
      rc.entered = I->entered;
      rc.round = I->round;
      rc.position = I->num;
      rc.members = I->subsetCnt;
      rc.launchTick = I->launchTick;
      rc.subsetTick = I->subsetTick;
      rc.tick = V->ticks;
      rc.ceiling = I->ceiling;
      for (j = 0; j < N; ++j) {
        const unsigned char *ap;
        const unsigned char *mh;
        const unsigned char *sc;
        unsigned int leaf;
        unsigned char mk;

        if (!BKR94ACS_BIT_TST(I->subset, j))
          continue;
        /* the fold held a sign part under every member's value */
        sc = 0;
        if (j == V->self) {
          mk = I->own->kind;
          mh = mk ? I->own->apex : I->own->origHash;
          sc = I->own->succ;
          RT_END(V)[j] = I->own->end;
        } else {
          ap = VAL(I, j);
          if (I->dist[j].sign && VALMATCH(ap, &I->dist[j])) {
            mk = I->dist[j].kind;
            mh = mk ? ap : I->dist[j].origHash;
            sc = I->dist[j].succ;
            RT_END(V)[j] = I->dist[j].end;
          } else {
            for (leaf = 0; leaf < N - 1 && !(EXCH(I, j, leaf).sign && VALMATCHX(ap, &EXCH(I, j, leaf))); ++leaf)
              ;
            mk = EXCH(I, j, leaf).kind;
            mh = mk ? ap : EX_ORIG(&EXCH(I, j, leaf));
            sc = EX_SUCC(&EXCH(I, j, leaf));
            RT_END(V)[j] = EXCH(I, j, leaf).end;
          }
        }
        RT_KIND(V)[j] = mk;
        memcpy(RT_HASH(V) + j * HashSz, mh, HashSz);
        if (mk == AC_ROTATION)
          memcpy(RT_SUCC(V) + j * HashSz, sc, HashSz);
      }
      I->reported0 = 1;
      trace(V, I->num, "report: the chain's, the subset's hashes and the link");
      V->cb->chain(V->cb->ctx, &rc);
    }
    if (I->haveSubset)
      for (i = 0; i < N; ++i) {
        struct acMessage rm;
        struct search *s;
        const unsigned char *ap;
        unsigned int leaf;
        unsigned int k;

        s = &I->srch[i];
        /* at X's verdict; at the record let go with none, where this
         * seat's memory still refuses the search: owed, and reported so */
        if (!BKR94ACS_BIT_TST(I->subset, i) || i == V->self || s->reported
         || !(I->verdict[i] || (I->gone && s->owed)))
          continue;
        memset(RT_BITS(V, 0), 0, 4 * BITS(N));
        rm.prev = I->prev;
        rm.hash = 0;
        rm.kind = 0;
        if (I->hasVal[i]) {
          ap = VAL(I, i);
          if (I->dist[i].sign && VALMATCH(ap, &I->dist[i])) {
            rm.kind = I->dist[i].kind;
            rm.hash = rm.kind ? ap : I->dist[i].origHash;
          } else {
            for (leaf = 0; leaf < N - 1; ++leaf)
              if (EXCH(I, i, leaf).sign && VALMATCHX(ap, &EXCH(I, i, leaf)))
                break;
            if (leaf < N - 1) {
              rm.kind = EXCH(I, i, leaf).kind;
              rm.hash = rm.kind ? ap : EX_ORIG(&EXCH(I, i, leaf));
            }
          }
        }
        rm.msg = I->verdict[i] == AC_PASS ? I->msg[i] : 0;
        rm.len = I->verdict[i] == AC_PASS ? I->msgLen[i] : 0;
        rm.heldShares = RT_BITS(V, 0);
        rm.heldShards = RT_BITS(V, 1);
        rm.badShares = RT_BITS(V, 2);
        rm.badShards = RT_BITS(V, 3);
        /* the leaves by the seat each was dealt to */
        for (k = 0; k < s->cs; ++k) {
          leaf = s->shareLeaf[k] < i ? s->shareLeaf[k] : s->shareLeaf[k] + 1;
          RT_BITS(V, 0)[leaf >> 3] |= 1 << (leaf & 7);
          if (BKR94ACS_BIT_TST(s->badShares, s->shareLeaf[k]))
            RT_BITS(V, 2)[leaf >> 3] |= 1 << (leaf & 7);
        }
        for (k = 0; k < s->cd; ++k) {
          leaf = s->shardLeaf[k] < i ? s->shardLeaf[k] : s->shardLeaf[k] + 1;
          RT_BITS(V, 1)[leaf >> 3] |= 1 << (leaf & 7);
          if (BKR94ACS_BIT_TST(s->badShards, s->shardLeaf[k]))
            RT_BITS(V, 3)[leaf >> 3] |= 1 << (leaf & 7);
        }
        rm.position = I->num;
        rm.tick = V->ticks;
        rm.tries = s->tries;
        rm.member = i;
        rm.verdict = I->verdict[i];
        s->reported = 1;
        /* of the members a record kept: one marked and still live, its
         * position's leaving refused by this seat's memory, is not one */
        if (s->kept && wi >= V->nLive && I->verdict[i] == AC_PASS)
          ++V->c.keptPassed;
        else if (s->kept && wi >= V->nLive && I->verdict[i] == AC_UNDER)
          ++V->c.keptUnder;
        trace(V, I->num, "report: %u's %s", i, verdictName(I->verdict[i]));
        V->cb->message(V->cb->ctx, &rm);
        if (I->msg[i]) {
          memset(I->msg[i], 0, I->msgLen[i]);
          free(I->msg[i]);
          I->msg[i] = 0;
          I->msgLen[i] = 0;
        }
      }
    }

    /* a record whose instance placed a part of this seat's distribution
     * the record lacks, or a shard it lacks: a newer copy
     * of the record with it, at the head, so the ring alone holds what
     * a recover sends.  The member entries are in seat order; the copy
     * takes the assembly's where it holds more, the record's elsewhere */
    for (wi = 0; wi < V->nKept; ++wi) {
      I = V->kept[wi];
      if (!I->recDue)
        continue;
      I->recDue = 0;
      if (!I->rx)
        continue;
      recMemb = 0;
      {
        const unsigned char *o;
        const unsigned char *mp;
        unsigned int m;
        unsigned int osz;

        o = V->rec + I->rx->off;
        recLen = GET32(o + REC_LEN);
        for (mp = o + REC_HDR, m = GET16(o + REC_MEMB), i = 0; i < N; ++i) {
          osz = m && mp[RM_SEAT] == i ? RM_HDR + SigLen + RM_BODY(mp[RM_KIND], i == V->self, GET32(mp + RM_SHLEN)) : 0;
          if (i != V->self && BKR94ACS_BIT_TST(I->subset, i) && I->dist[i].sign && I->hasVal[i]
           && VALMATCH(VAL(I, i), &I->dist[i])
           && (!osz || (!I->dist[i].kind && I->dist[i].held && I->dist[i].shardLen && !GET32(mp + RM_SHLEN)))) {
            recLen += RM_HDR + SigLen + RM_BODY(I->dist[i].kind, 0, I->dist[i].held ? I->dist[i].shardLen : 0) - osz;
            ++recMemb;
          }
          if (osz) {
            mp += osz;
            --m;
          }
        }
      }
      if (!recMemb)
        continue;
      /* a copy whose room would let its own first go saves nothing: the
       * position would be forgotten with the part.  The room is walked
       * as recRoom makes it, nothing moved; reaching the first, the
       * part stays in the kept assembly alone and the record as it is,
       * so a seat held on this position keeps it until its members end */
      {
        unsigned long h;
        unsigned long t;
        unsigned long need;
        unsigned int c;
        int own;

        for (h = V->recHead, t = V->recTail, c = V->recCount, own = 0; !own; h = 0) {
          need = h + recLen <= Retention ? recLen : Retention - h;
          while (c && t >= h && t < h + need) {
            if (t == I->rx->anchor) {
              own = 1;
              break;
            }
            if (!--c) {
              h = 0;
              break;
            }
            t += GET32(V->rec + t + REC_LEN);
            if (t > Retention - REC_HDR || !GET32(V->rec + t + REC_LEN))
              t = 0;
          }
          if (own || h + recLen <= Retention)
            break;
        }
        if (own) {
          ++V->c.recCopyNoRoom;
          V->c.recUnits += recMemb;
          trace(V, I->num, "a part of its distribution past its record: no copy, its room would let the record go");
          continue;
        }
      }
      recSite = 1;
      goto recRoom;
recCopyRoomDone:
      /* its first let go making the room: the position forgotten */
      if (!I->rx) {
        V->c.recUnits += recMemb;
        continue;
      }
      {
        const unsigned char *o;
        const unsigned char *mp;
        const struct dist *d;
        unsigned char *w;
        unsigned char *wp;
        unsigned int m;
        unsigned int nm;
        unsigned int osz;

        o = V->rec + I->rx->off;
        w = V->rec + V->recHead;
        memcpy(w, o, REC_HDR);
        PUT32(w + REC_LEN, recLen);
        w[REC_COPY] = 1;
        for (wp = w + REC_HDR, nm = 0, mp = o + REC_HDR, m = GET16(o + REC_MEMB), i = 0; i < N; ++i) {
          d = &I->dist[i];
          osz = m && mp[RM_SEAT] == i ? RM_HDR + SigLen + RM_BODY(mp[RM_KIND], i == V->self, GET32(mp + RM_SHLEN)) : 0;
          if (i != V->self && BKR94ACS_BIT_TST(I->subset, i) && I->dist[i].sign && I->hasVal[i]
           && VALMATCH(VAL(I, i), &I->dist[i])
           && (!osz || (!I->dist[i].kind && I->dist[i].held && I->dist[i].shardLen && !GET32(mp + RM_SHLEN)))) {
            wp[RM_SEAT] = i;
            wp[RM_KIND] = d->kind | (d->end ? RM_END : 0);
            wp[RM_NEXT] = d->underNext;
            PUT32(wp + RM_SHLEN, d->held ? d->shardLen : 0);
            memcpy(wp + RM_APEX, d->apex, HashSz);
            memcpy(wp + RM_APEX + HashSz, d->origHash, HashSz);
            memcpy(wp + RM_APEX + 2 * HashSz, d->sssRoot, HashSz);
            memcpy(wp + RM_APEX + 3 * HashSz, d->rsecRoot, HashSz);
            memcpy(wp + RM_APEX + 4 * HashSz, d->succ, HashSz);
            wp += RM_HDR;
            memcpy(wp, d->sig, SigLen);
            wp += SigLen;
            if (!d->kind) {
              memcpy(wp, d->unit, MVAL_LEN);
              wp += MVAL_LEN;
              memcpy(wp, d->sssProof, PfSz);
              wp += PfSz;
              memcpy(wp, d->rsecProof, PfSz);
              wp += PfSz;
              if (d->held) {
                memcpy(wp, d->shard, d->shardLen);
                wp += d->shardLen;
              }
            }
            ++nm;
          } else if (osz) {
            memcpy(wp, mp, osz);
            wp += osz;
            ++nm;
          }
          if (osz) {
            mp += osz;
            --m;
          }
        }
        PUT16(w + REC_MEMB, nm);
        trace(V, I->num, "a part of its distribution past its record: a newer copy at the head, %lu bytes", recLen);
        tDel(&V->recName, &I->rx->byName);
        I->rx->off = V->recHead;
        I->rx->byName.key = w + REC_NAME + 1;
        tIns(&V->recName, &I->rx->byName);
        V->recHead += recLen;
        ++V->recCount;
        ++V->c.recCopy;
        V->c.recUnits += recMemb;
        V->c.retained = V->recCount;
        if ((V->c.retainedBytes += recLen) > V->c.retainedMost)
          V->c.retainedMost = V->c.retainedBytes;
      }
    }

    /* a link's machines a record holds, every member reported and every
     * recover leg at its abandon count: let go, the record stays, and a
     * row naming it starts recover legs again; the record let go, every
     * member reported: let go, its legs wherever they are */
    for (wi = 0; wi < V->nKept;) {
      I = V->kept[wi];
      /* a member its record's assembly holds at threshold with no verdict,
       * and an abandon past the last part that added anything: the last
       * pass the position leaving would have given it, for a seat whose
       * launch waits on its report, and a part no faulty dealer dealt never
       * comes.  A copy of a part adds nothing, so none holds this off */
      for (i = 0; i < N; ++i)
        if (I->srch[i].kept && !I->srch[i].final && !I->srch[i].owed && !I->verdict[i]
         && I->srch[i].cs >= Threshold && I->srch[i].cd >= Threshold
         && V->ticks - I->srch[i].partAt >= Abandon) {
          I->srch[i].final = 1;
          I->asmDue[i] = 1;
          trace(V, I->num, "an abandon past %u's last part, at threshold: the search's last pass over what is held", i);
        }
      for (i = 0; i < N; ++i)
        if (BKR94ACS_BIT_TST(I->subset, i) && i != V->self && !I->srch[i].reported)
          break;
      if (i < N || (!I->gone && I->legGone < I->legCnt) || V->swPhase != SW_IDLE
       || (V->eActive && V->eI == I) || (V->held && V->heldI == I)) {
        ++wi;
        continue;
      }
      if (I->rx) {
        I->rx->kept = 0;
        /* what its machines heard goes with the record: j's word that it
         * is owed nothing; and that j's recover legs were answered, so
         * what comes under them again opens nothing here, where a lost
         * answer costs j its re-sends as toward a seat gone */
        for (j = 0; j < N; ++j) {
          if (j == V->self)
            continue;
          if (recHeard(V, I, j))
            I->rx->done[j >> 3] |= 1 << (j & 7);
          for (i = 0; i < N && !RIN(I, i, j).f; ++i)
            ;
          if (i < N)
            I->rx->done[BITS(N) + (j >> 3)] |= 1 << (j & 7);
        }
      }
      trace(V, I->num, "its record's machines let go: every member reported%s", I->gone ? ", the record let go" : I->legCnt ? ", every recover leg at its count" : "");
      instFree(S, I);
      V->kept[wi] = V->kept[--V->nKept];
    }

    /*
     * The next instance, once the newest has folded here and there is a
     * reason to launch it: this seat has a proposal to make -- a
     * rotation the last subset left out, presented again, the caller's
     * word that it has a message, or its end, called -- or another
     * seat's rows for a position past this one are held, under the name
     * the fold just minted or under one this seat has not minted yet,
     * held or not, which is that seat's word that the position after
     * this one exists [Bracha87 Section 3: a message of a later round,
     * stored till that round]; this seat's input to it is then what its
     * caller gives when asked, its noop where it has nothing.  A row
     * under a name not yet minted is a reason once, at its arrival: a
     * seat re-sending the same rows, one gone past the retention among
     * them, launches nothing more, where a seat ahead sends rows under
     * new names as it goes.  A position is every seat's agreement on
     * every seat's input, and an idle chain sends nothing; nothing
     * launches after the chain's last link.  The oldest leaves the live
     * window between passes, once every member there without a verdict
     * has had the search's last pass over what is held and every
     * member's report is out but those under threshold or with that
     * pass owed, and nothing in hand names it: its record goes to the
     * retention, with the assembly of such a member, the current step
     * moves over the link it minted, and it is let go.  Nothing else
     * lets a position go.
     */
    /* the oldest link leaves once it has folded here and every machine
     * of it has abandoned: its record to the ring */
    if (V->nLive && V->live[0]->stepped && V->live[0]->acsAbandoned
     && V->live[0]->legGone == V->live[0]->legCnt) {
      struct inst *in;

      in = V->live[0];
      if (!in->ending) {
        in->ending = 1;
        for (i = 0; i < N; ++i)
          if (in->haveSubset && BKR94ACS_BIT_TST(in->subset, i) && i != V->self && !in->verdict[i]) {
            in->srch[i].final = 1;
            in->asmDue[i] = 1;
          }
        trace(V, in->num, "every machine abandoned: the search's last pass over what is held");
      } else if (!lMem && V->swPhase == SW_IDLE && !(V->eActive && V->eI == in) && !(V->held && V->heldI == in)) {
        for (i = 0; i < N; ++i)
          if (in->haveSubset && BKR94ACS_BIT_TST(in->subset, i) && i != V->self && !in->srch[i].reported
           && !in->srch[i].kept) {
            /* the last pass this seat's memory refused: owed, and the
             * assembly goes with the record, the pass taken again at
             * every tick; its report waits on it, and the launch with
             * it */
            if (!in->srch[i].owed || in->verdict[i])
              break;
            in->srch[i].kept = 1;
            trace(V, in->num, "leaving the live window with %u's last pass owed, this seat's memory; its record keeps the assembly", i);
          }
        if (i == N) {
          unsigned long len;
          unsigned char *r;
          unsigned char *mp;
          unsigned int memb;

          /* the record's length: the header, which carries the subset
           * and every value this seat accepted, and a member for every
           * unit held under the agreed value of the subset's members.
           * The agreements' own rows are not kept: what they decided is
           * the subset, which this seat's legs describe, and a position
           * is never agreed again.  An ECHO is re-sent under the value
           * this seat accepted; where this seat echoed another value --
           * a two-faced dealer's, accepted on the others' readies --
           * the ECHO is not re-sent, since a re-send is the same bytes */
          len = REC_HDR;
          memb = 0;
          for (i = 0; i < N; ++i) {
            if (!in->haveSubset || !BKR94ACS_BIT_TST(in->subset, i))
              continue;
            if (i == V->self) {
              if (!in->own)
                continue;
              len += RM_HDR + SigLen + RM_BODY(in->own->kind, 1, in->own->shardLen);
            } else {
              if (!in->dist[i].sign || !in->hasVal[i] || !VALMATCH(VAL(in, i), &in->dist[i]))
                continue;
              len += RM_HDR + SigLen + RM_BODY(in->dist[i].kind, 0, in->dist[i].held ? in->dist[i].shardLen : 0);
            }
            ++memb;
          }
          /* its entry in the tree by name, for the rows that name it,
           * and with a member kept the kept assembly's place (below),
           * before anything moves: a record no row could find is one
           * whose machines could never start again, so this seat's
           * memory refusing either leaves the position in the window,
           * nothing changed, for the next call to try again, as a held
           * row refused is one its sender's sweep brings again */
          for (i = 0; i < N; ++i)
            if (in->haveSubset && BKR94ACS_BIT_TST(in->subset, i) && i != V->self && in->srch[i].kept
             && !in->srch[i].reported)
              break;
          rx = 0;
          keptI = 0;
          keptTab = 0;
          if (i < N && V->nKept == V->keptCap) {
            struct inst **grown;

            if (!(grown = realloc(V->kept, (V->keptCap ? 2 * V->keptCap : 8) * sizeof (*grown)))) {
              ++V->c.ownMem;
              lMem = 1;
              goto leaveMem;
            }
            V->kept = grown;
            V->keptCap = V->keptCap ? 2 * V->keptCap : 8;
          }
          if (!(rx = calloc(1, sizeof (*rx) + 3 * BITS(N)))
           || (i < N && (!(keptI = malloc(sizeof (*keptI))) || !(keptTab = calloc(1, INST_TAB_SZ))))) {
            free(rx);
            free(keptI);
            rx = 0;
            keptI = 0;
            ++V->c.ownMem;
            lMem = 1;
            goto leaveMem;
          }
          trace(V, in->num, "leaves the live window: its record to the retention, %lu bytes, %u units", len, memb);
          /* room at the head, the oldest records in the way let go
           * (recRoom); back here this block's own locals are gone */
          recLen = len;
          recMemb = memb;
          recSite = 0;
          goto recRoom;
recRoomDone:
          in = V->live[0];
          len = recLen;
          memb = recMemb;
          r = V->rec + V->recHead;
          PUT32(r + REC_LEN, len);
          PUT32(r + REC_NUM, in->num);
          memcpy(r + REC_NAME, in->prev, HashSz);
          memcpy(r + REC_LINK, in->link, HashSz);
          PUT16(r + REC_MEMB, memb);
          memcpy(r + REC_SUBSET, in->subset, BITS(N));
          memset(r + REC_HASN, 0, BITS(N));
          r[REC_COPY] = 0;
          for (i = 0; i < N; ++i) {
            PUT32(r + REC_GEN + 4 * i, in->gen[i]);
            memcpy(r + REC_ROOT + i * HashSz, ROOT(in, i), HashSz);
            memcpy(r + REC_ROOTN + i * HashSz, ROOTNEXT(in, i), HashSz);
            if (in->hasNext[i])
              r[REC_HASN + (i >> 3)] |= 1 << (i & 7);
          }
          memset(r + REC_HASVAL, 0, BITS(N));
          for (i = 0; i < N; ++i) {
            /* the value this seat accepted for each agreement, which
             * its round 0 rows carry: its own is its proposal's */
            if (i == V->self ? !in->own : !in->hasVal[i])
              continue;
            r[REC_HASVAL + (i >> 3)] |= 1 << (i & 7);
            memcpy(r + REC_VALS + i * HashSz, i == V->self ? in->own->apex : VAL(in, i), HashSz);
          }
          mp = r + REC_HDR;
          for (i = 0; i < N; ++i) {
            const struct own *o;
            const struct dist *d;

            if (!in->haveSubset || !BKR94ACS_BIT_TST(in->subset, i))
              continue;
            o = 0;
            d = 0;
            if (i == V->self) {
              if (!(o = in->own))
                continue;
            } else if (!(d = &in->dist[i])->sign || !in->hasVal[i] || !VALMATCH(VAL(in, i), d))
              continue;
            mp[RM_SEAT] = i;
            mp[RM_KIND] = (o ? o->kind : d->kind) | ((o ? o->end : d->end) ? RM_END : 0);
            mp[RM_NEXT] = o ? o->underNext : d->underNext;
            PUT32(mp + RM_SHLEN, o ? o->shardLen : d->held ? d->shardLen : 0);
            memcpy(mp + RM_APEX, o ? o->apex : d->apex, HashSz);
            memcpy(mp + RM_APEX + HashSz, o ? o->origHash : d->origHash, HashSz);
            memcpy(mp + RM_APEX + 2 * HashSz, o ? o->sssRoot : d->sssRoot, HashSz);
            memcpy(mp + RM_APEX + 3 * HashSz, o ? o->rsecRoot : d->rsecRoot, HashSz);
            memcpy(mp + RM_APEX + 4 * HashSz, o ? o->succ : d->succ, HashSz);
            mp += RM_HDR;
            memcpy(mp, o ? o->sig : d->sig, SigLen);
            mp += SigLen;
            if (o ? o->kind : d->kind)
              continue;                   /* a rotation or a noop: whole at its signature */
            if (o) {
              memcpy(mp, o->tab, RM_LEAVES);
              mp += RM_LEAVES;
              memcpy(mp, o->shards, (N - 1) * o->shardLen);
              mp += (N - 1) * o->shardLen;
            } else {
              memcpy(mp, d->unit, MVAL_LEN);
              mp += MVAL_LEN;
              memcpy(mp, d->sssProof, PfSz);
              mp += PfSz;
              memcpy(mp, d->rsecProof, PfSz);
              mp += PfSz;
              if (d->held) {
                memcpy(mp, d->shard, d->shardLen);
                mp += d->shardLen;
              }
            }
          }
          rx->off = rx->anchor = V->recHead;
          rx->kept = 0;
          rx->byName.k0 = r[REC_NAME];
          rx->byName.key = r + REC_NAME + 1;
          rx->byName.seq = 0;
          rx->byName.own = rx;
          tIns(&V->recName, &rx->byName);
          if (!V->recCount)
            V->recTail = V->recHead;
          V->recHead += len;
          ++V->recCount;
          V->c.retained = V->recCount;
          if ((V->c.retainedBytes += len) > V->c.retainedMost)
            V->c.retainedMost = V->c.retainedBytes;
          /* the current step moves over the link the position minted:
           * the live window's walk starts past it */
          memcpy(kInfo, in->link, HashSz);
          kInfo[HashSz] = DOM_RAT;
          for (i = 0; i < N; ++i) {
            Kdf->hkdf(CURIKM(V, i), PSK_MASK_SIZE, kInfo, HashSz + 1, kNk, PSK_MASK_SIZE);
            memcpy(CURIKM(V, i), kNk, PSK_MASK_SIZE);
          }
          memset(kNk, 0, sizeof (kNk));
          /* a member under threshold, or with its last pass owed: the
           * position's assembly goes with its record, which places the
           * parts still landing [Bracha87 Section 3], in a table of its
           * own, and the position is let go.  Its machines stop here:
           * the ACS seat and the legs are the live window's */
          if (keptI) {
            struct inst *k;
            unsigned char *kt;

            k = keptI;
            kt = keptTab;
            keptI = 0;
            *k = *in;
            k->a = 0;
            k->oAcs = 0;
            k->rAcs = 0;
            k->rCopy = 0;
            k->rCopyAt = 0;
            k->blob = 0;
            in->own = 0;                   /* its own proposal goes with it: its
                                            * value broadcast alone at a launch held */
            for (i = 0; i < 3 * N * N; ++i) {
              free(k->leg[i].f);
              k->leg[i].f = 0;
              k->leg[i].owed = 0;
              k->leg[i].fed = 0;             /* what the live machine was
                                              * fed: a fresh one is fed anew */
            }
            k->gOwed = k->aOwed = 0;
            /* and what they were to reply */
            memset(k->rDueG, 0, 2 * N * sizeof (*k->rDueG));
            memset(k->rLeg, 0, N * RLEG_ROW);
            k->ownDue = 0;
            k->legCnt = k->legGone = 0;
            /* only the members kept: the rest is let go here, as the
             * position's end would have let it go */
            for (i = 0; i < N; ++i) {
              if (k->srch[i].kept && !k->srch[i].reported)
                continue;
              memset(k->dist[i].unit, 0, MVAL_LEN);
              free(k->dist[i].sig);
              free(k->dist[i].shard);
              free(k->dist[i].stash);
              k->dist[i].sig = k->dist[i].shard = k->dist[i].stash = 0;
              k->dist[i].sign = k->dist[i].held = 0;
              for (j = 0; j < N - 1; ++j) {
                memset(EXCH(k, i, j).unit, 0, MVAL_LEN);
                free(EXCH(k, i, j).buf);
                free(EXCH(k, i, j).stash);
                EXCH(k, i, j).buf = EXCH(k, i, j).stash = 0;
                EXCH(k, i, j).sign = EXCH(k, i, j).held = 0;
              }
              if (k->srch[i].triedK)
                memset(k->srch[i].triedK, 0, k->srch[i].kcap * KEY_LEN);
              free(k->srch[i].triedK);
              free(k->srch[i].shareLeaf);
              k->srch[i].triedK = k->srch[i].shareLeaf = 0;
            }
            k->rx = rx;
            k->endTick = V->ticks;
            rx->kept = k;
            V->kept[V->nKept++] = k;
            ++V->c.kept;
            for (i = 0; i < N; ++i)
              if (k->srch[i].kept && !k->srch[i].reported)
                ++V->c.keptMembers;
            instCarve(S, in, kt);
            trace(V, k->num, "its assembly kept with its record: members under threshold or owed a pass");
          }
          instFree(S, in);
          memmove(&V->live[0], &V->live[1], (V->nLive - 1) * sizeof (V->live[0]));
          --V->nLive;
        }
      }
    }
leaveMem:
    /* an agreement with its subset had, its own SUBSET or one
     * DISCOVERed, is let go at the abandon count, the sweeps of memory
     * the deployment holds it for: after that it records and sends
     * nothing, as at a library abandon.  Before its subset it is never
     * let go: a seat alone from the deal on, or cut off, keeps
     * re-sending the same rows under the same tag, and a seat that has
     * folded past the position sees that name as a past link and starts
     * its recover legs toward this one, which give it the subset it
     * missed */
    for (wi = 0; wi < V->nLive; ++wi) {
      I = V->live[wi];
      if (I->haveSubset && !I->acsAbandoned && bkr94acsSweeps(I->a) >= Abandon) {
        I->acsAbandoned = 1;
        trace(V, I->num, "ACS seat let go at its count, the subset %s", I->acsSubset ? "its own" : "DISCOVERed");
      }
    }
    /* a position unfolded here an abandon on -- the fold still lacks a
     * member's sign part, or the subset -- may be silence to every other
     * seat: an agreement let go or stopped at the round ceiling says
     * nothing, as the ABAP README says of an abandon, and one still running
     * has no re-send left once every seat has heard its words.  This seat
     * still has the position to fold and its own value to say there, the
     * row that starts the others' recover legs toward it where their
     * machines are gone: it starts a bracha87Fig1 alone for its own value
     * broadcast, the same (initial, v) under the same tag with the same
     * unit beside it, an initiator's every message being of its one v, at
     * that count; at that count, the link still unfolded, it starts one
     * again.  A subset had before its own broadcast went leaves that value
     * for no member, and it is still this seat's to say.  The agreement is
     * not tried again, subset or none, since one started again could say
     * something else under the same tag: what the fold lacks comes by
     * recovery, a member's sign part, or a subset DISCOVERed from seats
     * that folded the position */
    for (wi = 0; wi < V->nLive; ++wi) {
      I = V->live[wi];
      if (!I->stepped && !I->ownDue && (I->launched || I->haveSubset)
       && (I->acsAbandoned || bkr94acsSweeps(I->a) >= Abandon)
       && (!LEG(I, V->self, V->self).f
        || (bracha87Fig1State(LEG(I, V->self, V->self).f) & BRACHA87_F1_ABANDONED)))
        break;
    }
    if (wi < V->nLive && !V->quiet && !lMem) {
ownAlone:
      g = &LEG(I, V->self, V->self);
      if (g->f) {
        if (V->eActive && V->eGate && V->eI == I && V->eG == g)
          V->eActive = 0;
        if (g->owed)
          --I->gOwed;
        free(g->f);
        memset(g, 0, sizeof (*g));
        --I->legCnt;
        --I->legGone;
      }
      if (!(g->f = calloc(1, bracha87Fig1Sz(N - 1, HashSz - 1, MaxByz + 1)))) {
        /* this seat's memory refused it: the next call tries again */
        ++V->c.ownMem;
        lMem = 1;
        goto launchNone;
      }
      if (bracha87Fig1Init(g->f, N - 1, MaxByz, HashSz - 1, MaxByz + 1, V->self, V->self, Abandon, 1)
       || bracha87Fig1Initiator(g->f, I->own->apex))
        goto exit;
      ++I->legCnt;
      memcpy(g->v, I->own->apex, HashSz);
      g->fed = FED_INITIAL | FED_BESIDE;
      g->owed = OWED(BRACHA87_INITIAL);
      ++I->gOwed;
      if (I->stepped) {
        ++V->c.heldRepeated;
        trace(V, I->num, "a launch held, a member short here and the position's machines gone: its own value broadcast alone, a bracha87Fig1");
      } else {
        ++V->c.repeated;
        trace(V, I->num, "an abandon on, the position unfolded: its own value broadcast alone, a bracha87Fig1");
      }
      fX = fS = V->self;
      bracha87Fig1Input(g->f, BRACHA87_INITIAL, V->self, I->own->apex, 0, f1out);
      nout = bracha87Fig1Input(g->f, BRACHA87_BESIDE, V->self, 0, 0, f1out);
      f1site = SITE_OWN;
      goto runF1;
ownAloneDone:
      goto work;
    }
    /* a launch begun and refused by this seat's memory is taken again,
     * once a call; none after the chain's last link */
    if (V->launchDue && !V->quiet && !V->lastLink) {
      if (lMem)
        goto launchNone;
      goto launch;
    }
    /* the end run: the chain ended at the last link folded, and nothing
     * launches.  Once that link's machines are at their count and every
     * member of it is reported or kept here, it leaves the live window
     * and its record is the retention's; for an abandon from then a row
     * naming a record starts recover legs, so a seat behind is carried
     * to the end, and once that abandon is out and every record's
     * machines are let go the seat is quiet: what the framer holds
     * goes, and acWork returns none once it has.  A member short here
     * holds it as it holds a launch: a seat that cannot have the
     * message is slow, not stopped */
    if (V->lastLink && !V->nLive && !V->lastGone) {
      V->lastGone = V->ticks ? V->ticks : 1;
      trace(V, V->lastLink, "the last link gone from the live window: its record carries a seat behind for an abandon");
    }
    if (!V->quiet && END_SHUT(V) && !V->nKept) {
      V->quiet = 1;
      trace(V, V->lastLink, "the end run over: nothing live, nothing kept; quiet");
    }
    if (!V->quiet && V->folded == V->launched) {
      /* the last position folded has every member's message here first:
       * assembled, or its verdict otherwise */
      for (lI = 0, lw = 0; V->folded && lw < V->nLive + V->nKept; ++lw)
        if ((lI = lw < V->nLive ? V->live[lw] : V->kept[lw - V->nLive])->num == V->folded)
          break;
      if (lw < V->nLive + V->nKept && lI) {
        /* a member short of parts first: one whose search this seat's
         * memory owes lacks nothing another seat can send */
        for (lj = 0; lj < N; ++lj)
          if (lj != V->self && BKR94ACS_BIT_TST(lI->subset, lj) && !lI->verdict[lj] && !lI->srch[lj].owed)
            break;
        if (lj == N)
          for (lj = 0; lj < N && (lj == V->self || !BKR94ACS_BIT_TST(lI->subset, lj) || lI->verdict[lj]
                               || lI->srch[lj].reported); ++lj)
            ;
        if (lj < N) {
          ++V->c.launchHeld;
          /* left the live window, its machines gone, it says nothing
           * under its name, and only a row of this seat's naming a
           * position another seat retains starts that seat's recover
           * legs toward it, which carry the parts the member lacks
           * here: its own value broadcast alone, as at a position
           * unfolded an abandon on, and again at its abandon count */
          if (!lMem && !lI->srch[lj].owed && lw >= V->nLive && lI->rx && lI->own
           && (!LEG(lI, V->self, V->self).f
            || (bracha87Fig1State(LEG(lI, V->self, V->self).f) & BRACHA87_F1_ABANDONED))) {
            I = lI;
            goto ownAlone;
          }
          goto launchNone;
        }
      }
      if (V->lastLink)
        goto launchNone;
      /* past the caller's end its call is the reason: every position it
       * launches carries the end, until the chain ends */
      if (!V->pend && !V->avail && !V->aheadNew && !V->ended) {
        kn.k0 = V->chain[0];
        kn.key = V->chain + 1;
        kn.seq = 0;
        if (!(tn = tLow(&V->ahName, &kn)) || tn->k0 != kn.k0 || memcmp(tn->key, kn.key, HashSz - 1))
          goto launchNone;
      }
      goto launch;
    }
launchNone:

    /*
     * The talk, while nothing is held and the seat is not quiet.  In
     * order: the send in hand, to its next recipient; then the next
     * stop with a turn to take: another seat's, a reply owed it; this
     * seat's own, a reply to itself, an instance that owes a send it
     * has taken -- the oldest live instance first -- legs before ACS;
     * the pass's next re-send, or its next step -- for every live
     * instance in turn, its ACS seat's sweep, a step at a time until it
     * returns 0, then one sweep to each of its legs, and for every kept
     * assembly the sweeps to its legs; and, no pass in hand, the value
     * broadcast of a link launched, the oldest first.  A step's ACCEPT,
     * DECIDED, SUBSET and ABANDON run when it is taken.  Every message
     * leaves through the loop's one Put.  An ACS send at round 0 is X's
     * value broadcast: it goes out as class 1, v from the instance and
     * the unit beside its INITIAL.
     */
    while (!V->held && !V->quiet) {
      const unsigned char *cv;
      const struct bracha87Fig1 *inst;
      unsigned char ann;
      int heardOk;

      if (V->eActive && V->eI->gone) {
        V->eActive = 0;                   /* its record let go mid-send:
                                           * the position is abandoned here */
        continue;
      }
      if (V->eActive) {
        /* the instance the send is of: an ACS row's, the value
         * broadcast's (class 1 is ACS round 0), or the leg's */
        inst = V->eGate ? V->eG->f : bkr94acsInstance(V->eI->a, V->eX, V->eS, V->eK);
        if (!inst)
          V->eJ = N;
        /* an INITIAL goes to the seats not recorded as holding it when
         * its send begins: one recorded since still gets it; a first
         * INITIAL to every other seat */
        if (!V->eJ && !V->eU && inst) {
          heardOk = V->eKind == BRACHA87_INITIAL;
          if ((V->eHeardOk = heardOk)) {
            memset(V->eHeard, 0, BITS(N));
            for (rj = 0; rj < N; ++rj)
              if (V->eCls == AC_CLS_RCV ? (rj == V->eS || rj == V->eR) && bracha87Fig1Holder(inst, FIDX(rj, V->eS))
                                        : bracha87Fig1Holder(inst, rj))
                V->eHeard[rj >> 3] |= 1 << (rj & 7);
          }
        }
        cv = 0;
        if (V->eCls != AC_CLS_ACS && inst) {
          if (!(cv = V->eCls >= AC_CLS_LEG && V->eKind == BRACHA87_INITIAL ? V->eG->v
                   : bracha87Fig1Value(inst, V->eKind == BRACHA87_INITIAL ? BRACHA87_INITIAL_ALL
                                           : V->eKind == BRACHA87_ECHO ? BRACHA87_ECHO_ALL : BRACHA87_READY_ALL)))
            V->eJ = N;
        }
        while (V->eJ < N && !V->held) {
          rj = V->eJ;
          /* the unit, beside the INITIAL that just left for this seat:
           * its sign part, then, for a payload, its data part */
          if (V->eU) {
            struct part pu;

            /* a recover leg's description, the third part: the
             * position's subset and every member's agreed value, the
             * same bytes from every seat that folded it */
            if (V->eU == 3) {
              unsigned int dl;
              unsigned int m;

              memcpy(V->ubuf, V->eI->subset, BITS(N));
              for (dl = BITS(N), m = 0; m < N; ++m)
                if (BKR94ACS_BIT_TST(V->eI->subset, m)) {
                  memcpy(V->ubuf + dl, m == V->self && V->eI->own ? V->eI->own->apex : VAL(V->eI, m), HashSz);
                  dl += HashSz;
                }
              emit(V, V->eI->num, V->eI->prev, rj, AC_TAG_BYTE(AC_CLS_RCV, BRACHA87_BESIDE, AC_PART_DESC),
                   V->eX, V->eR, V->eS, V->ubuf, dl, &V->held);
              V->eU = 0;
              ++V->eJ;
              continue;
            }
            if (V->eU == 1) {
              /* the sign part masks under this position's key with rj */
              kI = V->eI;
              kJ = rj;
              kSite = 0;
              goto keyWalk;
keyWalkTalkDone:
              ;
            }
            /* the part's source: this seat's own distribution, or its
             * held unit of X */
            pu.sig0 = pu.sig1 = 0;
            if ((pu.own = V->eX == V->self) && V->eI->rx && !V->eI->own) {
              const unsigned char *rp;
              const unsigned char *mp;
              unsigned int m;

              /* a recover leg of this seat's own value: its own member
               * entry in the record, every recipient's leaf, proofs and
               * shard, found at each send, since a newer copy moves the
               * record */
              rp = V->rec + V->eI->rx->off;
              for (mp = rp + REC_HDR, m = GET16(rp + REC_MEMB); m > 1 && mp[RM_SEAT] != V->self; --m)
                mp += RM_HDR + SigLen + RM_BODY(mp[RM_KIND], 0, GET32(mp + RM_SHLEN));
              pu.sig = mp + RM_HDR;
              pu.apex = mp + RM_APEX;
              pu.origHash = mp + RM_APEX + HashSz;
              pu.sssRoot = mp + RM_APEX + 2 * HashSz;
              pu.rsecRoot = mp + RM_APEX + 3 * HashSz;
              pu.succ = mp + RM_APEX + 4 * HashSz;
              pu.leaf = mp + RM_HDR + SigLen;
              pu.sssPf = pu.leaf + (N - 1) * MVAL_LEN;
              pu.rsecPf = pu.sssPf + (N - 1) * PfSz;
              pu.shard = pu.leaf + RM_LEAVES;
              pu.shardLen = GET32(mp + RM_SHLEN);
              pu.kind = mp[RM_KIND] & (RM_END - 1);
              pu.end = (mp[RM_KIND] & RM_END) != 0;
            } else if (pu.own) {
              const struct own *o;

              o = V->eI->own;
              pu.sig = o->sig;
              pu.sig0 = o->sig0;
              pu.sig1 = o->sig1;
              pu.apex = o->apex;
              pu.succ = o->succ;
              pu.origHash = o->origHash;
              pu.sssRoot = o->sssRoot;
              pu.rsecRoot = o->rsecRoot;
              pu.leaf = OWN_LEAF(o, 0);
              pu.sssPf = OWN_SSSPF(o, 0);
              pu.rsecPf = OWN_RSECPF(o, 0);
              pu.shard = o->shards;
              pu.shardLen = o->shardLen;
              pu.kind = o->kind;
              pu.end = o->end;
            } else {
              const struct dist *d;

              d = &V->eI->dist[V->eX];
              pu.sig = d->sig;
              pu.apex = d->apex;
              pu.succ = d->succ;
              pu.origHash = d->origHash;
              pu.sssRoot = d->sssRoot;
              pu.rsecRoot = d->rsecRoot;
              pu.leaf = d->unit;
              pu.sssPf = d->sssProof;
              pu.rsecPf = d->rsecProof;
              pu.shard = d->shard;
              pu.shardLen = d->shardLen;
              pu.kind = d->kind;
              pu.end = d->end;
            }
            emit(V, V->eI->num, V->eI->prev, rj, AC_TAG_BYTE(V->eCls, BRACHA87_BESIDE, V->eU == 1 ? AC_PART_SIGN : AC_PART_DATA), V->eX, V->eR, V->eS,
                 V->ubuf, unitPut(S, &pu, V->self, V->eX, rj, kIkm, V->eU == 1 ? AC_PART_SIGN : AC_PART_DATA, V->ubuf), &V->held);
            memset(kIkm, 0, sizeof (kIkm));
            V->heldUnit = V->held != 0;
            /* the data part follows a payload's sign part, none rides
             * beside a rotation or a noop; on a recover leg the
             * description follows */
            if (V->eU == 1 && !pu.kind)
              V->eU = 2;
            else if (V->eCls == AC_CLS_RCV)
              V->eU = 3;
            else {
              V->eU = 0;
              ++V->eJ;
            }
            continue;
          }
          /* an INITIAL to the seats not recorded as holding it; a READY
           * re-sent to the seats its instance still owes; an ECHO
           * re-sent to each bracha87Fig1EchoRecipient; a first INITIAL
           * of a value broadcast or a leg to every other seat, self
           * having been fed where it launched; a reply to its one seat */
          if ((V->eCls == AC_CLS_RCV && rj != V->eS && rj != V->eR)
           || (V->eOne && rj != V->eTo)
           || (V->eHeardOk && BRACHA87_BIT_TST(V->eHeard, rj))
           || (V->eRecip && !BRACHA87_BIT_TST(V->sRecip, rj))
           || (V->eERecip && !BRACHA87_BIT_TST(V->sERecip, rj))
           || (rj == V->self && V->eCls != AC_CLS_ACS && V->eKind == BRACHA87_INITIAL)) {
            ++V->eJ;
            continue;
          }
          /* the sweep's re-send to rj held while its sweep is not due:
           * rj's word on what was sent at its last could not be here
           * yet; an agreement's INITIAL may be its round's first, and
           * goes */
          if (V->eSweep && rj != V->self && !V->swDue[rj]
           && (V->eCls != AC_CLS_ACS || V->eKind != BRACHA87_INITIAL)) {
            ++SEATC(V, rj).sweptHeld;
            ++V->eJ;
            continue;
          }
          /* the sweep's row to rj: what rj has not said it holds, or a
           * turn the step fired, which the library returns the same way */
          if (V->eSweep && rj != V->self) {
            ++SEATC(V, rj).swept;
            if (V->swPhase == SW_ACS && !V->sMore && V->eCls == AC_CLS_ACS && V->eKind == BRACHA87_INITIAL)
              ++SEATC(V, rj).sweptTurn;
            else
              ++V->c.sweepAge[us - V->eI->launchUs < (unsigned long)TickMs * 1000 ? 0
                            : us - V->eI->launchUs < 2UL * TickMs * 1000 ? 1
                            : us - V->eI->launchUs < 4UL * TickMs * 1000 ? 2 : 3];
          }
          /* the first INITIAL of this seat's value broadcast to rj: its
           * round trip starts */
          if (V->eCls == AC_CLS_DIST && !V->eGate && V->eKind == BRACHA87_INITIAL && V->eX == V->self
           && rj != V->self && V->rttNum[rj] != V->eI->num) {
            V->rttNum[rj] = V->eI->num;
            V->rttUs[rj] = us;
            V->rttOpen[rj] = 1;
          }
          if (V->eOne) {
            if (rj != V->self)
              ++SEATC(V, rj).replied;
            if (V->eKind == BRACHA87_ECHO)
              ++V->c.replyEcho;
            else
              ++V->c.replyReady;
          }
          if (V->eCls != AC_CLS_ACS && V->eKind == BRACHA87_INITIAL) {
            /* the unit follows the INITIAL, except to the dealer of a
             * leg: X dealt this seat's unit and holds it, so X gets the
             * INITIAL alone and supplies its own unit */
            if (V->eCls == AC_CLS_LEG && rj == V->eX)
              ++V->eJ;
            else
              V->eU = 1;
            emit(V, V->eI->num, V->eI->prev, rj, AC_TAG_BYTE(V->eCls, BRACHA87_INITIAL, 0), V->eX, V->eR, V->eS, cv, HashSz, &V->held);
            continue;
          }
          ++V->eJ;
          /* every ECHO and READY says whether this seat holds the
           * initiator's INITIAL and what rode beside it; a READY says
           * the rest.  The tag's bits per class and kind: AC_TAG_TO_ANN */
          ann = 0;
          if (V->eKind != BRACHA87_INITIAL && HOLDS(bracha87Fig1State(inst)))
            ann |= V->eKind == BRACHA87_READY ? (V->eCls == AC_CLS_ACS ? 0 : 1 << 2) : 1 << AC_TAG_ANN_SHIFT;
          if (V->eKind == BRACHA87_READY) {
            if (bracha87Fig1State(inst) & BRACHA87_F1_ACCEPTED)
              ann |= BRACHA87_ANN_ACCEPTED << AC_TAG_ANN_SHIFT;
            if (BRACHA87_BIT_TST(bracha87Fig1Received(inst), V->eCls == AC_CLS_RCV ? FIDX(rj, V->eS) : rj))
              ann |= BRACHA87_ANN_RECEIVED << AC_TAG_ANN_SHIFT;
          }
          if (V->eCls == AC_CLS_ACS)
            emit(V, V->eI->num, V->eI->prev, rj, AC_TAG_BYTE(AC_CLS_ACS, V->eKind, V->eVal) | ann, V->eX, V->eK, V->eS, 0, 0, &V->held);
          else
            emit(V, V->eI->num, V->eI->prev, rj, AC_TAG_BYTE(V->eCls, V->eKind, 0) | ann, V->eX, V->eR, V->eS, cv, HashSz, &V->held);
        }
        if (V->held) {
          V->heldI = V->eI;
          V->flGo = 1;
        }
        if (V->eJ >= N)
          V->eActive = 0;
        continue;
      }
      V->eJ = V->eU = 0;
      V->eRecip = V->eERecip = V->eSweep = V->eOne = 0;
      /*
       * BPR leaves the order of a bounded egress to its caller.  Here
       * it is an elevator over the seats, a stop each: at another
       * seat's stop a reply owed it, at this seat's own its replies to
       * itself and then its own word.  At a stop with a turn to take
       * the car takes one -- a reply, or one send to its recipients --
       * and moves on; a stop with none it passes, so a talk with one
       * stop busy serves that stop alone, and the talk is done when
       * every stop is passed.  A reply is one message for one arrival,
       * at its sender's rate (bracha87Fig1.h), a copy's at most one a tick
       * a row (copyBudget): a seat that sends faster
       * than this one can answer fills its own stop and no other, and
       * this seat's own word, its pass and so its clock among it, waits
       * at most one turn at each other stop.  No count and no clock: a
       * seat answered late is answered all the same, which the
       * asynchronous model allows, and a delay costs only latency.  Of
       * another seat's stop, the oldest instance owing it first, a
       * leg's before an ACS instance's; of a machine still running
       * here, since a record's leg at its count, or an ACS seat that
       * stopped, is silence.
       */
      if (V->flGo) {
        V->flGo = V->flIdle = 0;
        if (++V->fl == N)
          V->fl = 0;
      }
      /* the description alone a record owes this stop, read from the
       * record: under the first member that is not this stop, no leg of
       * that member behind it, and at most one a tick (DESC_OWED) */
      if (V->descTo[V->fl]) {
        const unsigned char *rp;
        unsigned int dl;
        unsigned int m;

        rp = V->rec + V->descTo[V->fl]->off;
        V->descTo[V->fl] = 0;
        V->eX = N;
        memcpy(V->ubuf, rp + REC_SUBSET, BITS(N));
        for (dl = BITS(N), m = 0; m < N; ++m)
          if (BKR94ACS_BIT_TST(rp + REC_SUBSET, m)) {
            memcpy(V->ubuf + dl, rp + REC_VALS + m * HashSz, HashSz);
            dl += HashSz;
            if (V->eX == N && m != V->fl)
              V->eX = m;
          }
        V->eOne = 1;
        ++V->c.descAlone;
        trace(V, GET32(rp + REC_NUM), "a row of %u names this record, which holds nothing to carry it: its description alone", V->fl);
        emit(V, 0, rp + REC_NAME, V->fl, AC_TAG_BYTE(AC_CLS_RCV, BRACHA87_BESIDE, AC_PART_DESC),
             V->eX, V->fl, V->self, V->ubuf, dl, &V->held);
        if (V->held) {
          V->heldI = 0;
          V->flGo = 1;
        }
        continue;
      }
      for (wi = 0; wi < V->nLive + V->nKept; ++wi) {
        unsigned char *rr;

        V->eI = wi < V->nLive ? V->live[wi] : V->kept[wi - V->nLive];
        if (V->eI->gone)
          continue;
        while (V->eI->rDueG[V->fl]) {
          rr = V->eI->rLeg + V->fl * RLEG_ROW;
          for (sx = 0; !(rr[sx >> 3] & (1 << (sx & 7)));)
            sx += !(sx & 7) && !rr[sx >> 3] ? 8 : 1;
          rr[sx >> 3] &= ~(1 << (sx & 7));
          --V->eI->rDueG[V->fl];
          V->eG = &V->eI->leg[sx >> 1];
          if (!V->eG->f || (bracha87Fig1State(V->eG->f) & BRACHA87_F1_ABANDONED))
            continue;
          V->eKind = BRACHA87_ECHO + (sx & 1);
          V->eTo = V->fl;
          V->eOne = 1;
          sx >>= 1;
          goto legNamed;
        }
        if (!V->eI->rDueA[V->fl])
          continue;
        if (wi >= V->nLive || V->eI->acsAbandoned) {
          memset(V->eI->rAcs + V->fl * RACS_ROW, 0, RACS_ROW);
          V->eI->rDueA[V->fl] = 0;
          continue;
        }
        /* the row read from its first round, a byte at a time past the
         * empty ones: the rounds in hand come first, and a scan reaches
         * far only for a stop owed nothing nearer */
        rr = V->eI->rAcs + V->fl * RACS_ROW;
        for (sx = 0; !(rr[sx >> 3] & (1 << (sx & 7)));)
          sx += !(sx & 7) && !rr[sx >> 3] ? 8 : 1;
        rr[sx >> 3] &= ~(1 << (sx & 7));
        --V->eI->rDueA[V->fl];
        V->eKind = BRACHA87_ECHO + (sx & 1);
        sx = sx / 2 % (N * N) * (Rounds + 1) + sx / 2 / (N * N);
        V->eVal = (RAVAL(V->eI)[sx] >> 2 * (V->eKind - BRACHA87_ECHO)) & 3;
        V->eTo = V->fl;
        V->eOne = 1;
        goto acsNamed;
      }
      if (V->fl == V->self)
        goto ownStop;
nextStop:
      if (++V->fl == N)
        V->fl = 0;
      if (++V->flIdle < N)
        continue;
      V->flIdle = 0;
      break;
ownStop:
      /* this seat's own word, in its order: what moves the links in
       * hand first, what an instance owes, whose ECHO and READY carry
       * the word that retires another seat's re-send toward this one;
       * then the pass, this seat's re-sends.  Last, and only with no
       * pass in hand, new business: a launched link's value broadcast,
       * which starts an instance at every other seat, each owing its
       * ECHO and READY and re-sending them until answered.  An instance
       * that owes: the oldest first */
      for (sx = 0; sx < V->nLive + V->nKept; ++sx) {
        V->eI = sx < V->nLive ? V->live[sx] : V->kept[sx - V->nLive];
        if ((V->eI->gOwed || V->eI->aOwed) && !V->eI->gone)
          break;
      }
      if (sx < V->nLive + V->nKept && V->eI->gOwed) {
        /* its next leg that owes, among the N x N legs and the recover
         * legs: of this seat's to a returner, of another's to this seat */
        for (;;) {
          V->eG = &V->eI->leg[V->eI->gScan];
          if (V->eG->owed)
            break;
          if (++V->eI->gScan == 3 * N * N)
            V->eI->gScan = 0;
        }
        sx = V->eI->gScan;
legNamed:
        V->eX = sx % (N * N) / N;
        V->eS = sx % N;
        V->eR = 0;
        V->eCls = V->eX == V->eS ? AC_CLS_DIST : AC_CLS_LEG;
        if (sx >= N * N) {
          V->eCls = AC_CLS_RCV;
          if (sx < 2 * N * N) {
            V->eR = V->eS;
            V->eS = V->self;
          } else
            V->eR = V->self;
        }
        V->eGate = 1;
        if (V->eOne) {
          V->eActive = 1;
          continue;
        }
        for (V->eKind = BRACHA87_INITIAL; !(V->eG->owed & OWED(V->eKind)); ++V->eKind)
          ;
        V->eG->owed &= ~OWED(V->eKind);
        V->eActive = 1;
        if (!V->eG->owed)
          --V->eI->gOwed;
        continue;
      }
      if (sx < V->nLive) {
        /* its next ACS instance that owes */
        while (!V->eI->oAcs[V->eI->aScan])
          if (++V->eI->aScan == N * N * (Rounds + 1))
            V->eI->aScan = 0;
        sx = V->eI->aScan;
acsNamed:
        V->eX = sx / (N * (Rounds + 1));
        V->eS = sx / (Rounds + 1) % N;
        V->eK = sx % (Rounds + 1);
        V->eCls = V->eK ? AC_CLS_ACS : AC_CLS_DIST;
        V->eR = 0;
        V->eGate = 0;
        if (V->eOne) {
          V->eActive = 1;
          continue;
        }
        for (V->eKind = BRACHA87_INITIAL; !(V->eI->oAcs[V->eI->aScan] & OWED(V->eKind)); ++V->eKind)
          ;
        V->eVal = (V->eI->oAcs[V->eI->aScan] >> OWED_VAL(V->eKind)) & 3;
        V->eI->oAcs[V->eI->aScan] &= ~OWED(V->eKind);
        if (!(V->eI->oAcs[V->eI->aScan] & OWED_KINDS)) {
          V->eI->oAcs[V->eI->aScan] = 0;
          --V->eI->aOwed;
        }
        V->eActive = 1;
        continue;
      }
      if (V->swPhase == SW_ACS) {
        V->eI = V->sIx < V->nLive ? V->live[V->sIx] : V->kept[V->sIx - V->nLive];
        if (V->sA < V->sN) {
          /* the step's next send */
          if (V->sActs[V->sA].act <= BKR94ACS_SEND_READY) {
            V->eX = V->sActs[V->sA].ba;
            V->eS = V->sActs[V->sA].q;
            V->eK = V->sActs[V->sA].k;
            V->eCls = V->eK ? AC_CLS_ACS : AC_CLS_DIST;
            V->eR = 0;
            V->eGate = 0;
            V->eKind = V->sActs[V->sA].act == BKR94ACS_SEND_INITIAL ? BRACHA87_INITIAL
                  : V->sActs[V->sA].act == BKR94ACS_SEND_ECHO ? BRACHA87_ECHO : BRACHA87_READY;
            V->eVal = V->sActs[V->sA].value;
            V->eRecip = V->eKind == BRACHA87_READY && V->sRecipOk;
            V->eERecip = V->eKind == BRACHA87_ECHO && V->sERecipOk;
            V->eSweep = 1;
            V->eActive = 1;
          }
          ++V->sA;
          continue;
        }
        if (!V->sMore) {
          V->swPhase = SW_F1;
          V->sI = 0;
          if (V->sIx < V->nLive && us - V->live[V->sIx]->launchUs < (unsigned long)TickMs * 1000) {
            V->sI = 3 * N * N;
            ++V->c.sweepYoung;
          }
          V->sN = V->sA = 0;
          continue;
        }
        V->sMore = bkr94acsSweep(V->eI->a, V->sActs, &V->sN);
        V->sA = 0;
        /* who the step's READY and ECHO re-sends go to, read before the
         * next Input */
        V->sRecipOk = V->sERecipOk = 0;
        for (sx = 0; sx < V->sN; ++sx) {
          if (V->sActs[sx].act != BKR94ACS_SEND_READY && V->sActs[sx].act != BKR94ACS_SEND_ECHO)
            continue;
          if (!(inst = bkr94acsInstance(V->eI->a, V->sActs[sx].ba, V->sActs[sx].q, V->sActs[sx].k)))
            continue;
          if (V->sActs[sx].act == BKR94ACS_SEND_READY && !V->sRecipOk) {
            memset(V->sRecip, 0, BITS(N));
            for (rj = 0; rj < N; ++rj)
              if (bracha87Fig1Recipient(inst, rj))
                V->sRecip[rj >> 3] |= 1 << (rj & 7);
            V->sRecipOk = 1;
          }
          if (V->sActs[sx].act == BKR94ACS_SEND_ECHO && !V->sERecipOk) {
            memset(V->sERecip, 0, BITS(N));
            for (rj = 0; rj < N; ++rj)
              if (bracha87Fig1EchoRecipient(inst, rj))
                V->sERecip[rj >> 3] |= 1 << (rj & 7);
            V->sERecipOk = 1;
          }
        }
        I = V->eI;
        aList = V->sActs;
        aCnt = V->sN;
        acsSite = SITE_SWEEP;
        goto runAcs;
runAcsSweepDone:
        V->talkWork = 1;
        continue;
      }
      if (V->swPhase == SW_F1) {
        V->eI = V->sIx < V->nLive ? V->live[V->sIx] : V->kept[V->sIx - V->nLive];
        if (V->sA < V->sN) {
          if (V->sOut[V->sA] != BRACHA87_ACCEPT) {
            V->eG = V->sG;
            V->eCls = V->sCls;
            V->eGate = 1;
            V->eX = V->sX;
            V->eS = V->sS;
            V->eR = V->sR;
            V->eKind = V->sOut[V->sA] == BRACHA87_INITIAL_ALL ? BRACHA87_INITIAL
                  : V->sOut[V->sA] == BRACHA87_ECHO_ALL ? BRACHA87_ECHO : BRACHA87_READY;
            V->eRecip = V->eKind == BRACHA87_READY && V->sRecipOk;
            V->eERecip = V->eKind == BRACHA87_ECHO && V->sERecipOk;
            V->eSweep = 1;
            V->eActive = 1;
          }
          ++V->sA;
          continue;
        }
        if (V->sI >= 3 * N * N) {
          /* this instance's pass is done: the next live one's, or the
           * pass's end */
          V->sN = V->sA = 0;
          if (++V->sIx < V->nLive + V->nKept) {
            V->swPhase = SW_ACS;
            V->sMore = V->sIx < V->nLive && !V->live[V->sIx]->acsAbandoned
                    && us - V->live[V->sIx]->launchUs >= (unsigned long)TickMs * 1000;
          } else {
            /* the pass's end is work: the position's end waits for it,
             * and a pass over stopped seats takes no step that would
             * bring the work back on its own */
            V->swPhase = SW_IDLE;
            V->talkWork = 1;
            if (us - V->lastTickUs >= (unsigned long)TickMs * 1000)
              ++V->c.passLong;
          }
          continue;
        }
        V->sG = &V->eI->leg[V->sI];
        V->sX = V->sI % (N * N) / N;
        V->sS = V->sI % N;
        V->sR = 0;
        V->sCls = V->sX == V->sS ? AC_CLS_DIST : AC_CLS_LEG;
        if (V->sI >= N * N) {
          V->sCls = AC_CLS_RCV;
          if (V->sI < 2 * N * N) {
            V->sR = V->sS;
            V->sS = V->self;
          } else
            V->sR = V->self;
        }
        ++V->sI;
        V->sN = V->sA = 0;
        if (!V->sG->f || V->eI->gone)
          continue;
        I = V->eI;
        g = V->sG;
        fX = V->sX;
        fS = V->sS;
        if ((nout = bracha87Fig1Input(g->f, BRACHA87_SWEEP, 0, 0, 0, f1out)) == 1 && f1out[0] == BRACHA87_ABANDON) {
          /* a record's leg at its abandon count re-sends nothing more;
           * a row naming the record starts it again */
          ++I->legGone;
          trace(V, I->num, "leg (X=%u S=%u) abandoned at its count", fX, fS);
          nout = 0;
        }
        V->sN = nout;
        memcpy(V->sOut, f1out, sizeof (V->sOut));
        V->sRecipOk = V->sERecipOk = 0;
        for (sx = 0; sx < V->sN; ++sx) {
          /* by seat; a recover leg's two processes are its initiator
           * and its returner */
          if (V->sOut[sx] == BRACHA87_READY_ALL) {
            memset(V->sRecip, 0, BITS(N));
            for (rj = 0; rj < N; ++rj)
              if (V->sCls == AC_CLS_RCV ? (rj == V->sS || rj == V->sR) && bracha87Fig1Recipient(g->f, FIDX(rj, V->sS))
                                        : bracha87Fig1Recipient(g->f, rj))
                V->sRecip[rj >> 3] |= 1 << (rj & 7);
            V->sRecipOk = 1;
          }
          if (V->sOut[sx] == BRACHA87_ECHO_ALL) {
            memset(V->sERecip, 0, BITS(N));
            for (rj = 0; rj < N; ++rj)
              if (V->sCls == AC_CLS_RCV ? (rj == V->sS || rj == V->sR) && bracha87Fig1EchoRecipient(g->f, FIDX(rj, V->sS))
                                        : bracha87Fig1EchoRecipient(g->f, rj))
                V->sERecip[rj >> 3] |= 1 << (rj & 7);
            V->sERecipOk = 1;
          }
        }
        f1site = SITE_SWEEP;
        goto runF1;
runF1SweepDone:
        V->talkWork = 1;
        continue;
      }
      /* no pass in hand: the value broadcast of a link launched, the
       * oldest first */
      for (sx = 0; sx < V->nLive && !V->live[sx]->ownDue; ++sx)
        ;
      if (sx == V->nLive)
        goto nextStop;
      I = V->live[sx];
      I->ownDue = 0;
      ownSite = 0;
      goto ownBroadcast;
ownBroadcastTalkDone:
      V->talkWork = 1;
    }
    /* what the talk left: its hand-backs, a step's own actions, and the
     * pass's end */
    if (V->qHead < V->qTail || V->talkWork) {
      V->talkWork = 0;
      goto work;
    }
  /* the message the talk left held, to the framer now, so the next pass
   * finds its datagrams due */
  if (V->held) {
    putSite = 1;
    goto heldPut;
  }
  return;

  /*
   * The held message to the framer, which a full table keeps held and a
   * tag still going there takes as said (a re-send, the same bytes).  A
   * message taken ends the framer's sending its wire time later, its
   * shards and parity each at its pace.  From the talk, the talk again
   * while the framer has less than the tick's own send ahead of it --
   * the tick less the delays there and back -- so the wire is still
   * busy when the caller next calls, and what is said leaves within one
   * step of being said: a pass ends on the wire, and a reply waits
   * behind no more than the tick budgets and the turns ahead of it at
   * its stop.  The talk waits on the framer, never on how often the
   * caller calls.
   */
heldPut:
  if ((pr = rsecFrmEgrPut(&V->egr, V->obuf, V->held, us))) {
    if (pr < 0)
      ++V->c.frmRefused;
    else if (pr == 1) {
      if (V->obuf[1] < N && V->obuf[1] != V->self) {
        SEATC(V, V->obuf[1]).sentBytes += V->held;
        V->tickNow[2 * V->obuf[1]] += V->held;
      }
      V->c.saidBytes[V->putAt >> 4][V->putAt >> 2 & 3][V->putAt & 3] += V->held;
      ++V->c.said[V->putAt >> 4][V->putAt >> 2 & 3][V->putAt & 3];
      if (V->heldI)
        ++V->heldI->puts;
      if (V->heldUnit)
        ++V->c.unitSent;
      if (!(pw = (V->held - 7 - TagSz + Shard - 1) / Shard))
        pw = 1;
      pw = (pw + V->obuf[2 + TagSz]) * GET32(V->obuf + 3 + TagSz);
      if (V->egrEndUs - us > ~0UL / 2)
        V->egrEndUs = us;
      V->egrEndUs += pw;
      V->c.saidUs[V->putAt >> 4][V->putAt >> 2 & 3][V->putAt & 3] += pw;
    }
    V->held = 0;
    V->heldUnit = 0;
  }
  if (!putSite)
    goto heldPutPassDone;
  if (!V->held && !V->quiet && (V->egrEndUs - us > ~0UL / 2 || V->egrEndUs - us < V->talkUs))
    goto work;
  return;

  /*
   * Dispatch the event in hand to its instance: a class 0 row to the
   * ACS seat; a class 1 row -- X's value broadcast -- to the ACS seat
   * too, its (initial, v) and the rest fed as they land and the unit
   * fed as BESIDE only once it passed receive's gates and its apex is
   * the v the library holds; a class 2 row to its leg through the
   * seat's own gate, the same way.  Hand-backs come here too, past the
   * wire refusals.
   */
dispatch:
  evIdx = evFrom;
  switch (evCls) {
  case AC_CLS_ACS:
    if (I->acsAbandoned) {
      ++V->c.stopped;
      if (evFrom != V->self)
        ++SEATC(V, evFrom).stopped;
      goto dispatchReturn;
    }
    /* of this seat's own broadcast not begun, the library makes nothing */
    if (!(rowF = bkr94acsInstance(I->a, evX, evS, evRound)) && !evAuth && evS == V->self)
      goto dispatchReturn;
    rowBit = 8 * RLEG_ROW + 2 * (evRound * N * N + evX * N + evS);
    rowSite = 0;
    goto rowGate;
rowGateAcs:
    ++V->c.inAcs;
    nacts = bkr94acsInput(I->a, evKind, evX, evS, evRound, evFrom, &evValue8, evAnnot, V->acts);
    aList = V->acts;
    aCnt = nacts;
    acsSite = SITE_DISPATCH;
    goto runAcs;
runAcsDispatchDone:
    goto dispatchReturn;
  case AC_CLS_DIST:
    fCls = AC_CLS_DIST;
    fX = fS = evX;
    g = 0;
    /* the others' echoes and readies of this seat's value broadcast,
     * its agreement gone: to the bracha87Fig1 alone it runs for it */
    if (evX == V->self && I->acsAbandoned && I->a && LEG(I, V->self, V->self).f && evKind != BRACHA87_BESIDE) {
      g = &LEG(I, V->self, V->self);
      rowF = g->f;
      rowBit = 2 * (g - I->leg);
      rowSite = 1;
      goto rowGate;
rowGateAlone:
      ++V->c.inDist;
      nout = bracha87Fig1Input(g->f, evKind, evIdx, evPl, evAnnot, f1out);
      f1site = SITE_DISPATCH;
      goto runF1;
    }
    if (evKind == BRACHA87_BESIDE)
      goto unitIn;
    if (I->acsAbandoned) {
      if (!I->stepped) {
        ++V->c.stopped;
        if (evFrom != V->self)
          ++SEATC(V, evFrom).stopped;
      }
      goto dispatchReturn;
    }
    if (!(rowF = bkr94acsInstance(I->a, evX, evX, 0)) && !evAuth && evX == V->self)
      goto dispatchReturn;
    rowBit = 8 * RLEG_ROW + 2 * (evX * N + evX);
    rowSite = 2;
    goto rowGate;
rowGateDist:
    ++V->c.inDist;
    if (evAuth && evKind == BRACHA87_INITIAL && I->dist[evX].sign && !VALMATCH(evPl, &I->dist[evX])) {
      ++V->c.initOther;
      if (evFrom != V->self)
        ++SEATC(V, evFrom).initOther;
      trace(V, I->num, "INITIAL of %u under another value than the held unit's", evX);
    }
    /* evFrom's echo of this seat's value broadcast: the round trip ends */
    if (evKind == BRACHA87_ECHO && evX == V->self && evFrom != V->self && V->rttOpen[evFrom]
     && V->rttNum[evFrom] == I->num) {
      V->rttOpen[evFrom] = 0;
      ++SEATC(V, evFrom).rtts;
      SEATC(V, evFrom).rttSum += us - V->rttUs[evFrom];
      if (SEATC(V, evFrom).rtts == 1 || us - V->rttUs[evFrom] < SEATC(V, evFrom).rttLeast)
        SEATC(V, evFrom).rttLeast = us - V->rttUs[evFrom];
      if (us - V->rttUs[evFrom] > SEATC(V, evFrom).rttMost)
        SEATC(V, evFrom).rttMost = us - V->rttUs[evFrom];
    }
    nacts = bkr94acsInput(I->a, evKind, evX, evX, 0, evFrom, evPl, evAnnot, V->acts);
    /* evX's value accepted here: how late, in this seat's sweeps past
     * the (n - t)th 1, whether patience still waited on it or not */
    if (evAuth && !(I->acc[evX] & 1) && bkr94acsValue(I->a, evX)) {
      I->acc[evX] |= 1;
      if (evX != V->self && I->ones >= N - MaxByz) {
        ++SEATC(V, evX).lates;
        if (V->ticks - I->nmtTick > SEATC(V, evX).lateMost)
          SEATC(V, evX).lateMost = V->ticks - I->nmtTick;
        if (us - I->nmtUs > SEATC(V, evX).lateMostUs)
          SEATC(V, evX).lateMostUs = us - I->nmtUs;
      }
    }
    aList = V->acts;
    aCnt = nacts;
    acsSite = SITE_DISPATCH;
    goto runAcs;
  default:
    /* a recover leg: this seat's to the returner, or the initiator's to
     * this seat, its two processes indexed initiator 0, returner 1 */
    if (evCls == AC_CLS_RCV) {
      g = evS == V->self ? &ROUT(I, evX, evRound) : &RIN(I, evX, evS);
      evIdx = FIDX(evFrom, evS);
    } else
      g = &LEG(I, evX, evS);
    fCls = evCls;
    fX = evX;
    fS = evS;
    /* a record's recover leg carries the member's agreed value or
     * nothing: a correct seat's leg carries it, and a fresh instance
     * must not echo another value than the first did [Bracha87 Lemma 1] */
    if (I->rx && evKind != BRACHA87_BESIDE && (!I->hasVal[evX] || memcmp(evPl, VAL(I, evX), HashSz))) {
      ++V->c.initOther;
      if (evFrom != V->self)
        ++SEATC(V, evFrom).initOther;
      goto dispatchReturn;
    }
    if (evKind == BRACHA87_BESIDE && evValue == AC_PART_DESC)
      goto descIn;
    if (evKind == BRACHA87_BESIDE)
      goto unitIn;
    /* a recover leg of S's at its abandon count, and S's INITIAL again:
     * a leg running here for it is started as at the first, where this
     * seat still waits on its position or lacks what the leg carries: at
     * a live position until it has folded and its agreement is let go,
     * for then every leg's count is what lets it leave, and a copy of an
     * INITIAL, which no seat can tell from a re-send, would hold it live
     * for good; then for a member whose assembly its record keeps.  An
     * exchange leg's abandon is final, as every instance's is */
    if (evCls == AC_CLS_RCV && evS != V->self && g->f && evKind == BRACHA87_INITIAL && evFrom == evS
     && (bracha87Fig1State(g->f) & BRACHA87_F1_ABANDONED)
     && (I->rx ? I->srch[evX].kept && !I->srch[evX].reported : !I->stepped || !I->acsAbandoned)) {
      if (!AUTHED())
        goto dispatchReturn;
      if (V->eActive && V->eGate && V->eI == I && V->eG == g)
        V->eActive = 0;
      if (g->owed)
        --I->gOwed;
      free(g->f);
      memset(g, 0, sizeof (*g));
      --I->legCnt;
      --I->legGone;
    }
    if (evS != V->self && !g->f) {
      /* the initiator's INITIAL opens the leg here as its recipient:
       * ahead of this seat's own SUBSET, the leg is S's broadcast of
       * X's value all the same, and a recover leg is opened at a link
       * folded here as at one not, so its HOLDING retires it.  Any
       * other row ahead of it has nowhere to go */
      if (evKind != BRACHA87_INITIAL || evFrom != evS) {
        ++V->c.noInstance;
        if (evFrom != V->self)
          ++SEATC(V, evFrom).noInstance;
        goto dispatchReturn;
      }
      if (!AUTHED())
        goto dispatchReturn;
      if (evCls == AC_CLS_RCV
          ? !(g->f = calloc(1, bracha87Fig1Sz(1, HashSz - 1, 1)))
            || bracha87Fig1Init(g->f, 1, 0, HashSz - 1, 1, 0, 1, Abandon, 1)
          : !(g->f = calloc(1, bracha87Fig1Sz(N - 1, HashSz - 1, MaxByz + 1)))
            || bracha87Fig1Init(g->f, N - 1, MaxByz, HashSz - 1, MaxByz + 1, evS, V->self, Abandon, 1)) {
        /* this seat's memory: the INITIAL is not taken, S's sweep
         * bringing it again */
        free(g->f);
        g->f = 0;
        ++V->c.rowMem;
        goto dispatchReturn;
      }
      ++I->legCnt;
      trace(V, I->num, "leg (X=%u S=%u) opened here", evX, evS);
    }
    break;
  }
  /* a unit is verified and held whether or not its leg exists here yet:
   * assembly reads it either way.  A row has nowhere to go without a
   * live instance. */
  if (!g->f) {
    ++V->c.noInstance;
    if (evFrom != V->self)
      ++SEATC(V, evFrom).noInstance;
    goto dispatchReturn;
  }
  rowF = g->f;
  rowBit = 2 * (g - I->leg);
  rowSite = 3;
  goto rowGate;
rowGateLeg:
  ++V->c.inLeg;
  switch (evKind) {
  case BRACHA87_INITIAL:
    {
      const unsigned char *hv;        /* the held sign part's apex */
      int whole;                      /* and the shard with it */

      if (evX == V->self) {
        /* the dealer: S's unit of this seat's proposal is what this
         * seat dealt S, so what rides beside is known here and S sends
         * the INITIAL alone; BESIDE is this seat's own word, under its
         * own apex */
        hv = I->dist[V->self].apex;
        whole = 1;
      } else if (evX == evS) {
        /* a recover leg of S's own value: S's distribution's unit to
         * this seat */
        hv = I->dist[evX].sign ? I->dist[evX].apex : 0;
        whole = I->dist[evX].held;
      } else {
        hv = EXCH(I, evX, LEAF(evX, evS)).sign ? EX_APEX(&EXCH(I, evX, LEAF(evX, evS))) : 0;
        whole = EXCH(I, evX, LEAF(evX, evS)).held;
      }
      /* HOLDING on a recover leg is the unit and the description S's
       * recover legs carry: the description held too */
      if (evCls == AC_CLS_RCV && !I->dHeld[evS])
        whole = 0;
      if (g->fed & FED_INITIAL) {
        /* a re-send: S has not heard this seat's HOLDING.  The library
         * records nothing of it and replies its echo to S; and what
         * rode beside it, whole here since the first was fed alone -- a
         * recover leg's description held off another of S's legs -- is
         * fed now, the one thing here a re-send moves */
        if (whole && !(g->fed & FED_BESIDE) && hv && !memcmp(hv, g->v, HashSz) && !AUTHED())
          goto dispatchReturn;
        nout = bracha87Fig1Input(g->f, BRACHA87_INITIAL, evIdx, evPl, 0, f1out);
        if (whole && !(g->fed & FED_BESIDE) && hv && !memcmp(hv, g->v, HashSz)) {
          g->fed |= FED_BESIDE;
          nout = bracha87Fig1Input(g->f, BRACHA87_BESIDE, evIdx, 0, 0, f1out);
        }
        f1site = SITE_DISPATCH;
        goto runF1;
      }
      if (hv && memcmp(hv, evPl, HashSz)) {
        /* fed all the same: the instance keeps the first (initial, v)
         * and what is validated is validated against it; the held part
         * is then not S's unit of this value, and S's part under it
         * replaces it when it lands */
        ++V->c.initOther;
        if (evFrom != V->self)
          ++SEATC(V, evFrom).initOther;
        trace(V, I->num, "INITIAL of leg X=%u S=%u under another value than the held sign part's", evX, evS);
        whole = 0;
      }
      memcpy(g->v, evPl, HashSz);
      g->fed |= FED_INITIAL;
      nout = bracha87Fig1Input(g->f, BRACHA87_INITIAL, evIdx, evPl, 0, f1out);
      if (whole) {
        g->fed |= FED_BESIDE;
        nout = bracha87Fig1Input(g->f, BRACHA87_BESIDE, evIdx, 0, 0, f1out);
        trace(V, I->num, "leg X=%u S=%u: INITIAL fed, and the held unit beside it", evX, evS);
      }
      f1site = SITE_DISPATCH;
      goto runF1;
    }
  default:
    nout = bracha87Fig1Input(g->f, evKind, evIdx, evPl, evAnnot, f1out);
    f1site = SITE_DISPATCH;
    goto runF1;
  }

  /*
   * A row at the machine it names, rowF, and what that machine would do
   * with it.  Nothing, if it holds the row, and it says so from the tag
   * alone: the first (initial, v) stands, and a sender of echo or ready
   * is counted once, so that a copy differs from anything else its
   * sender could say under this tag only where it would record nothing
   * anyway.  Refused unread, then, but for one thing: it may be its
   * sender's word that it has not heard, whose reply is owed.  So a copy
   * that would be replied to passes on to the machine, unproved, which
   * records nothing and returns the reply, once a tick a row (copyBudget):
   * the reply is this seat's own word, already its sender's to hear, so
   * there is nothing to prove and a copy can only make it say that again.
   * An (initial, v) under another value is no copy of what is held: a
   * counted discard.  Anything else moves the machine and proves itself first.
   */
rowGate:
  if (!evAuth && rowF && bracha87Fig1Duplicate(rowF, evKind, evIdx, evAnnot)) {
    /* a machine at its abandon runs nothing, and has no reply to give */
    if (bracha87Fig1State(rowF) & BRACHA87_F1_ABANDONED) {
      ++V->c.copy;
      goto dispatchReturn;
    }
    cv0 = evKind == BRACHA87_INITIAL ? bracha87Fig1Value(rowF, BRACHA87_INITIAL_ALL) : 0;
    if (cv0 && memcmp(cv0, evCls == AC_CLS_ACS ? &evValue8 : evPl, evCls == AC_CLS_ACS ? 1 : HashSz)) {
      ++V->c.initOther;
      ++SEATC(V, evFrom).initOther;
      goto dispatchReturn;
    }
    ++V->c.copy;
    ++SEATC(V, evFrom).resent;
    if (evKind == BRACHA87_INITIAL)
      ++V->c.dupInitial;
    if (evKind == BRACHA87_ECHO || (evKind == BRACHA87_READY && (evAnnot & BRACHA87_ANN_RECEIVED))
     || !copyBudget(V, I, evFrom, rowBit + (evKind == BRACHA87_READY)))
      goto dispatchReturn;
  } else if (!AUTHED())
    goto dispatchReturn;
  switch (rowSite) {
  case 0:  goto rowGateAcs;
  case 1:  goto rowGateAlone;
  case 2:  goto rowGateDist;
  default: goto rowGateLeg;
  }

  /*
   * After the ACS seat took a class 1 row, or a unit of X was held: the
   * unit is fed beside X's (initial, v) once both are here under one
   * value, and X's accept, Q(X) = 1 inside the library, is noted.
   */
distAfter:
  if (!I->dist[evX].fedBeside && I->dist[evX].held && !I->acsAbandoned && I->a
   && (inst0 = bkr94acsInstance(I->a, evX, evX, 0))
   && (cv0 = bracha87Fig1Value(inst0, BRACHA87_INITIAL_ALL))
   && VALMATCH(cv0, &I->dist[evX])) {
    I->dist[evX].fedBeside = 1;
    trace(V, I->num, "dist X=%u: the held unit fed beside the INITIAL", evX);
    nacts = bkr94acsInput(I->a, BRACHA87_BESIDE, evX, evX, 0, evX, 0, 0, V->acts);
    aList = V->acts;
    aCnt = nacts;
    acsSite = SITE_BESIDE;
    goto runAcs;
runAcsBesideDone:
    ;
  }
  if (!I->dist[evX].accepted && I->a && (cv0 = bkr94acsValue(I->a, evX))) {
    I->dist[evX].accepted = 1;
    memcpy(VAL(I, evX), cv0, HashSz);
    I->hasVal[evX] = 1;
    if (I->haveSubset)
      I->subsetDue = 1;               /* the leg (X, self)'s other condition, met after SUBSET */
    trace(V, I->num, "accepted %u's value %02x%02x..", evX, cv0[0], cv0[1]);
  }
  goto dispatchReturn;

  /*
   * A part of a unit lands: of X's own to this seat (class 1) or of S's
   * exchange unit of X (class 2).  The sign part: the value from what
   * it carries -- the signed header, the successor key, nothing --
   * first, ahead of the proof and the gates: a part of the held apex is
   * a duplicate (its sender has not yet recorded this seat's echo or
   * ready), neither proved nor re-verified; a second apex not under the
   * value it must have -- the agreed one, else the (initial, v) held --
   * under either of X's roots, or any with a part held and no (initial,
   * v), is a counted discard, before the proof and the gates; the rest
   * proves itself, runs every gate and is then held against
   * the (initial, v) the instance holds: not under it, refused, a part
   * held or not; under it, it replaces a part held under another apex;
   * with no v held yet, refused and the first held sign part kept.  The
   * data part: gated under the held sign part's root by the proof it
   * carried, or stashed unjudged until that part lands; none belongs
   * beside a rotation or a noop.  Held, what the kind needs, the unit
   * is fed beside the INITIAL this seat fed under the same v.
   */
unitIn:
  {
    struct dist tmp;
    unsigned char apex[AC_HASH_MAX];
    struct dist *d;
    struct exch *e;
    unsigned int leaf;
    unsigned int rc;
    unsigned int og;
    int stray;
    unsigned int po;                  /* the part's signing offset, from its signature */
    unsigned int whichRoot;           /* the root its value matched, 2 where none was tried */
    int replay;                       /* a slot below the signer's high water, or at it under
                                       * another value, at or past the position that set it */
    int book;                         /* a second rotation of a context
                                       * whose successor is installed */
    int uDist;                        /* the unit's form: X's own to this
                                       * seat, else S's exchange unit */
    const unsigned char *heldApex;    /* the apex of the sign part held here */
    const unsigned char *pl;
    const unsigned char *sh;          /* the shard to gate, and its length */
    unsigned char *shOwn;             /* the shard where this seat owns it: the stash's */
    const unsigned char *sigp;        /* the signature, where the shape puts it */
    unsigned int shl;
    unsigned char **stash;
    unsigned int *stashLen;
    unsigned char *vf;
    const unsigned char *p;
    char fromS[16];                   /* " from S" on an exchange unit */

    pl = evPl;
    shOwn = 0;
    d = &I->dist[evX];
    e = 0;
    /* the unit's form: X's own to this seat, at this seat's leaf in the
     * DIST domain -- on X's value broadcast, or on X's recover leg of
     * its own value -- or S's exchange unit of X, at S's leaf in the
     * EXCH domain */
    uDist = fCls == AC_CLS_DIST || (fCls == AC_CLS_RCV && evX == evS);
    if (fCls == AC_CLS_DIST) {
      ++V->c.inDunit;
      fromS[0] = 0;
    } else {
      ++V->c.inXunit;
      sprintf(fromS, " from %u", evS);
    }
    if (uDist) {
      leaf = LEAF(evX, V->self);
      heldApex = d->sign ? d->apex : 0;
      stash = &d->stash;
      stashLen = &d->stashLen;
    } else {
      leaf = LEAF(evX, evS);
      e = &EXCH(I, evX, leaf);
      heldApex = e->sign ? EX_APEX(e) : 0;
      stash = &e->stash;
      stashLen = &e->stashLen;
    }
    if (evValue == AC_PART_DATA) {
      if (evLen < 1 || evLen > ShardMax
       || (heldApex && (uDist ? d->kind : e->kind))) {
        ++V->c.unitBad[AC_UNIT_LEN];
        ++SEATC(V, evFrom).unitBad[AC_UNIT_LEN];
        trace(V, I->num, "shard of %u%s refused: %s", evX, fromS,
              evLen < 1 || evLen > ShardMax ? "length" : "none rides beside a rotation or a noop");
        goto dispatchReturn;
      }
      if (!heldApex) {
        /* ahead of its sign part: the first is stashed, judged when the
         * sign part lands; a second is not kept */
        if (*stash) {
          if (*stashLen == evLen && !memcmp(*stash, pl, evLen)) {
            if (fCls == AC_CLS_DIST)
              ++V->c.dupDunit;
            else
              ++V->c.dupXunit;
            ++V->c.copy;
            ++SEATC(V, evFrom).resent;
          } else {
            ++V->c.shardOther;
            ++SEATC(V, evFrom).shardOther;
          }
          goto dispatchReturn;
        }
        if (!AUTHED())
          goto dispatchReturn;
        if (!(*stash = malloc(evLen))) {
          ++V->c.unitBad[AC_UNIT_MEM];
          goto dispatchReturn;
        }
        memcpy(*stash, pl, evLen);
        *stashLen = evLen;
        ++V->c.shardAhead;
        trace(V, I->num, "shard of %u%s held ahead of its sign part", evX, fromS);
        goto dispatchReturn;
      }
      if (uDist ? d->held && d->shardLen == evLen && !memcmp(d->shard, pl, evLen)
                           : e->held && e->shardLen == evLen && !memcmp(EX_SHARD(e), pl, evLen))
        goto dupPart;
      if (!AUTHED())
        goto dispatchReturn;
      sh = pl;
      shl = evLen;
      goto shardGate;
    }
    rc = AC_UNIT_OK;
    if (!SHAPE_OK(evLen) || (SHAPE_END(evLen) && pl[evLen - 1] != END_MARK))
      rc = AC_UNIT_LEN;
    else if (mlsEgSz(SignH, pl + SHAPE_SIG(evLen), SigLen) != SigLen
          || !(po = mlsEgOf(SignH, pl + SHAPE_SIG(evLen), SigLen)))
      rc = AC_UNIT_SIG;
    else {
      --po;
      /* a part of the held apex: the value from what the shape carries
       * -- nothing for a noop, the successor key for a rotation, the
       * signed header for a payload -- under the root the held part was
       * signed under */
      if (heldApex) {
        const unsigned char *hk;

        hk = (uDist ? d->underNext : e->underNext) ? ROOTNEXT(I, evX) : ROOT(I, evX);
        if (SHAPE_APEX(hk, po, pl, evLen, apex))
          rc = AC_UNIT_MEM;
        else if (!memcmp(heldApex, apex, HashSz))
          goto dupPart;
      }
      whichRoot = 2;
      /* a part the gates below would refuse for its value alone is
       * refused before its signature is checked: its value, under
       * either of X's roots, not the one it must be -- the value
       * accepted for X here, else the (initial, v) held -- or any part
       * at all with one held and no (initial, v) to judge them by.
       * It costs this seat a hash, not a signature */
      if (!rc) {
        const unsigned char *want;
        const unsigned char *tgt;
        const unsigned char *hk;
        unsigned int ri;

        if (fCls == AC_CLS_DIST)
          want = I->a && (inst0 = bkr94acsInstance(I->a, evX, evX, 0)) ? bracha87Fig1Value(inst0, BRACHA87_INITIAL_ALL) : 0;
        else
          want = g->f && (g->fed & FED_INITIAL) ? g->v : 0;
        tgt = I->hasVal[evX] ? VAL(I, evX) : want;
        for (ri = 0; tgt && ri < 2 && (hk = !ri ? ROOT(I, evX) : I->hasNext[evX] ? ROOTNEXT(I, evX) : 0); ++ri)
          if (SHAPE_APEX(hk, po, pl, evLen, apex)) {
            rc = AC_UNIT_MEM;
            break;
          } else if (!memcmp(apex, tgt, HashSz)) {
            tgt = 0;
            whichRoot = ri;
          }
        if (!rc && (tgt || (heldApex && !want))) {
          ++V->c.partOther;
          ++SEATC(V, evFrom).partOther;
          trace(V, I->num, "%s of %u%s refused unchecked: %s", fCls == AC_CLS_DIST ? "unit" : "exchange unit",
                evX, fromS, tgt ? "not under the value it must have" : "a second apex with no (initial, v) held");
          goto dispatchReturn;
        }
      }
      /* the signer's high water (below) refuses from the offset, which the
       * signature's structure gives unverified, and at the slot it stands at
       * from the value, a hash, so where it refuses under each root the part
       * could be under -- the one its value matched just above, where this
       * seat holds a value to match -- its signature, code points and proofs
       * are not paid to come to the same refusal, however often it comes */
      if (!rc && V->hwSet[evX] && I->num >= V->hwPos[evX]) {
        const unsigned char *hk;
        unsigned int gen;
        unsigned int ri;
        int other;

        other = 0;
        for (ri = whichRoot == 2 ? 0 : whichRoot;
             ri < (whichRoot == 2 ? 2 : whichRoot + 1)
             && (hk = !ri ? ROOT(I, evX) : I->hasNext[evX] ? ROOTNEXT(I, evX) : 0); ++ri) {
          gen = I->gen[evX] + ri;
          if (gen > V->hwGen[evX] || (gen == V->hwGen[evX] && po > V->hwOff[evX]))
            break;
          if (gen == V->hwGen[evX] && po == V->hwOff[evX]) {
            if (SHAPE_APEX(hk, po, pl, evLen, apex)) {
              rc = AC_UNIT_MEM;
              break;
            }
            if (!memcmp(HWAPEX(V, evX), apex, HashSz))
              break;
            other = 1;
          }
        }
        if (!rc && (ri == (whichRoot == 2 ? 2 : whichRoot + 1) || !hk)) {
          if (other) {
            ++V->c.slotReused;
            ++SEATC(V, evX).slotReused;
          } else {
            ++V->c.offsetReplay;
            ++SEATC(V, evX).offsetReplay;
          }
          trace(V, I->num, "%s of %u%s refused unchecked: at or below the signer's high water",
                fCls == AC_CLS_DIST ? "unit" : "exchange unit", evX, fromS);
          goto dispatchReturn;
        }
      }
      if (!rc) {
        if (!AUTHED())
          goto dispatchReturn;
        kI = I;
        kJ = evFrom;
        kSite = 1;
        goto keyWalk;
keyWalkUnitDone:
        rc = unitCheck(V, ROOT(I, evX), I->hasNext[evX] ? ROOTNEXT(I, evX) : 0, leaf,
                       uDist ? DOM_DIST : DOM_EXCH, kIkm, pl, evLen, &tmp);
        memset(kIkm, 0, sizeof (kIkm));
      }
    }
    /* the signer's offset high water, read here and never raised here:
     * it moves only at a fold, on SUBSET inclusion.  A position's tag
     * names the link before it, so this seat judges a position's parts
     * only once it has folded every position before it, and the high
     * water read here is the same function of the chain at every
     * correct seat.  A verified part above it, or with none set, is not
     * judged by it; the same value at it is the same signing again;
     * another value at it, or anything below it, is refused at or past
     * the position that last confirmed it, where at an older position it
     * is that position's part arriving late.  Most of that was refused
     * above, unverified; here is what hung on which root signed it */
    replay = 0;
    if (!rc && V->hwSet[evX]) {
      unsigned int gen;

      gen = I->gen[evX] + tmp.underNext;
      if (gen == V->hwGen[evX] && tmp.off == V->hwOff[evX]) {
        if (memcmp(HWAPEX(V, evX), tmp.apex, HashSz)) {
          ++V->c.slotReused;
          ++SEATC(V, evX).slotReused;
          trace(V, I->num, "%u's slot %u of context %u signed another value", evX, tmp.off, gen);
          replay = I->num >= V->hwPos[evX];
        }
      } else if ((gen < V->hwGen[evX] || (gen == V->hwGen[evX] && tmp.off < V->hwOff[evX]))
              && I->num >= V->hwPos[evX]) {
        ++V->c.offsetReplay;
        ++SEATC(V, evX).offsetReplay;
        replay = 1;
      }
    }
    /* once this seat has accepted X's value, a unit is of X only under
     * it; before that, the first verified sign part is held -- and a
     * second verified one under the (initial, v) the instance holds
     * replaces a held one under another apex: the caller validates what
     * rode beside against the v the instance holds (bracha87Fig1.h), so
     * the part under that v is the unit, and a first-held rule would
     * let a faulty X lock this seat out with one stray sign part.  With
     * no v held yet, or neither under it, the first stays and the
     * second is refused, since nothing can be judged.  A second
     * rotation of a context whose successor the book has installed is
     * refused from the book, which moved at an agreement */
    og = 0;
    book = 0;
    if (!rc && !replay && I->hasVal[evX] && !VALMATCH(VAL(I, evX), &tmp))
      og = 1;
    if (!rc && !replay && !og && tmp.kind == AC_ROTATION && !tmp.underNext && I->hasNext[evX]
     && memcmp(ROOTNEXT(I, evX), tmp.succ, HashSz))
      book = 1;
    stray = 0;
    if (!rc && !replay && !og && !book) {
      const unsigned char *want;

      if (fCls == AC_CLS_DIST)
        want = I->a && (inst0 = bkr94acsInstance(I->a, evX, evX, 0)) ? bracha87Fig1Value(inst0, BRACHA87_INITIAL_ALL) : 0;
      else
        want = g->f && (g->fed & FED_INITIAL) ? g->v : 0;
      if (want && memcmp(want, tmp.apex, HashSz))
        stray = 1;                      /* not the (initial, v) held: refused, a part held or not */
      else if (want && heldApex && memcmp(want, heldApex, HashSz)) {
        ++V->c.signReplaced;
        ++SEATC(V, evX).signReplaced;
        trace(V, I->num, "sign part of %u%s under the held (initial, v) replaces one under another apex", evX, fromS);
        if (uDist) {
          memset(d->unit, 0, MVAL_LEN);
          free(d->sig);
          free(d->shard);
          free(d->stash);
          d->sig = d->shard = d->stash = 0;
          d->stashLen = 0;
          d->sign = d->held = 0;
        } else {
          memset(e->unit, 0, MVAL_LEN);
          free(e->buf);
          free(e->stash);
          e->buf = e->stash = 0;
          e->stashLen = 0;
          e->sign = e->held = 0;
        }
        heldApex = 0;
      }
    }
    if (rc || replay || og || book || stray || heldApex) {
      if (replay)
        ++V->c.hwLate;
      if (rc) {
        ++V->c.unitBad[rc];
        if (rc != AC_UNIT_MEM)          /* this seat's memory: no name's count */
          ++SEATC(V, evFrom).unitBad[rc];
      } else if (!replay) {
        ++V->c.secondApex;
        /* a verified part of X not under the (initial, v) held: on a leg,
         * exchange or recover, counted under the carrier, whose INITIAL it
         * disagrees with; else under the signer */
        if (stray && (fCls == AC_CLS_LEG || fCls == AC_CLS_RCV))
          ++SEATC(V, evFrom).initOther;
        else
          ++SEATC(V, evX).secondApex;
      }
      trace(V, I->num, "%s of %u%s refused: %s", fCls == AC_CLS_DIST ? "unit" : "exchange unit",
            evX, fromS,
            rc == AC_UNIT_LEN ? "length" : rc == AC_UNIT_SIG ? "signature" : rc == AC_UNIT_SSS ? "sssMk leaf"
            : rc == AC_UNIT_MEM ? "this seat's memory, not judged"
            : replay ? "a slot at or below the signer's high water" : og ? "not the accepted value"
            : book ? "a second rotation of a context with a successor installed"
            : stray ? "not the (initial, v) held" : "a second apex");
      memset(tmp.unit, 0, MVAL_LEN);
      goto dispatchReturn;
    }
    if (uDist) {
      if (!(d->sig = malloc(SigLen))) {
        ++V->c.unitBad[AC_UNIT_MEM];
        memset(tmp.unit, 0, MVAL_LEN);
        goto dispatchReturn;
      }
      sigp = pl + SHAPE_SIG(evLen);
      memcpy(d->sig, sigp, SigLen);
      d->off = tmp.off;
      memcpy(d->apex, tmp.apex, HashSz);
      memcpy(d->succ, tmp.succ, HashSz);
      memcpy(d->origHash, tmp.origHash, HashSz);
      memcpy(d->sssRoot, tmp.sssRoot, HashSz);
      memcpy(d->rsecRoot, tmp.rsecRoot, HashSz);
      memcpy(d->unit, tmp.unit, MVAL_LEN);
      memcpy(d->sssProof, tmp.sssProof, PfSz);
      memcpy(d->rsecProof, tmp.rsecProof, PfSz);
      d->scp = tmp.scp;
      d->ocp = tmp.ocp;
      d->underNext = tmp.underNext;
      d->kind = tmp.kind;
      d->end = tmp.end;
      d->sign = 1;
    } else {
      if (!(e->buf = malloc(4 * HashSz))) {
        ++V->c.unitBad[AC_UNIT_MEM];
        memset(tmp.unit, 0, MVAL_LEN);
        goto dispatchReturn;
      }
      memcpy(EX_APEX(e), tmp.apex, HashSz);
      if (tmp.kind == AC_ROTATION) {
        memcpy(EX_SUCC(e), tmp.succ, HashSz);
        memset(EX_SSS(e), 0, 2 * HashSz);
      } else {
        memcpy(EX_ORIG(e), tmp.origHash, HashSz);
        memcpy(EX_SSS(e), tmp.sssRoot, HashSz);
        memcpy(EX_RSEC(e), tmp.rsecRoot, HashSz);
      }
      e->off = tmp.off;
      memcpy(e->unit, tmp.unit, MVAL_LEN);
      memcpy(e->rsecProof, tmp.rsecProof, PfSz);
      e->scp = tmp.scp;
      e->ocp = tmp.ocp;
      e->underNext = tmp.underNext;
      e->kind = tmp.kind;
      e->end = tmp.end;
      e->sign = 1;
    }
    memset(tmp.unit, 0, MVAL_LEN);
    if (tmp.kind) {
      /* whole at the sign part; a shard stashed ahead of it belongs to
       * nothing */
      if (*stash) {
        ++V->c.unitBad[AC_UNIT_LEN];
        ++SEATC(V, evFrom).unitBad[AC_UNIT_LEN];
        trace(V, I->num, "shard of %u%s refused: none rides beside a rotation or a noop", evX, fromS);
        free(*stash);
        *stash = 0;
        *stashLen = 0;
      }
      if (uDist)
        d->held = 1;
      else
        e->held = 1;
      goto unitHeld;
    }
    trace(V, I->num, "sign part of %u%s held (offset %u)%s", evX, fromS, tmp.off,
          *stash ? ", the stashed shard to its gate" : "");
    if (!*stash)
      goto dispatchReturn;
    sh = shOwn = *stash;
    shl = *stashLen;
    *stash = 0;
    *stashLen = 0;

    /* the shard under the held sign part's root, by the proof it
     * carried, at the shard's own length */
  shardGate:
    if (!(vf = malloc(rsecMkVfSz(SignH)))
     || !(p = rsecMkExtract(&RsecPlug, sh, shl, leaf, N - 1,
                            uDist ? d->rsecProof : e->rsecProof, vf))) {
      /* this seat's memory, not the sender's: the work area, or the
       * hash allocator in the extractor, whose arguments are this
       * seat's and well formed, the shard's length checked on arrival;
       * not held, so its sender's sweep brings it again */
      free(vf);
      ++V->c.unitBad[AC_UNIT_MEM];
      trace(V, I->num, "shard of %u%s refused: this seat's memory, not judged", evX, fromS);
      free(shOwn);
      goto dispatchReturn;
    }
    if (memcmp(p, uDist ? d->rsecRoot : EX_RSEC(e), HashSz))
      p = 0;
    free(vf);
    if (!p) {
      ++V->c.unitBad[AC_UNIT_RSEC];
      ++SEATC(V, evFrom).unitBad[AC_UNIT_RSEC];
      trace(V, I->num, "shard of %u%s refused: rsecMk leaf", evX, fromS);
      free(shOwn);
      goto dispatchReturn;
    }
    if (uDist) {
      if (!shOwn) {
        if (!(shOwn = malloc(shl))) {
          ++V->c.unitBad[AC_UNIT_MEM];
          goto dispatchReturn;
        }
        memcpy(shOwn, sh, shl);
      }
      free(d->shard);
      d->shard = shOwn;
      d->shardLen = shl;
      d->held = 1;
    } else {
      unsigned char *grown;

      if (!(grown = realloc(e->buf, 4 * HashSz + shl))) {
        ++V->c.unitBad[AC_UNIT_MEM];
        free(shOwn);
        goto dispatchReturn;
      }
      e->buf = grown;
      memcpy(EX_SHARD(e), sh, shl);
      e->shardLen = shl;
      e->held = 1;
      free(shOwn);
    }

    /* the unit is whole here */
  unitHeld:
    I->asmDue[evX] = 1;
    /* under a record, its member reported or not: the record takes it, however
     * late, since no one can say which seat's later failures make it the one a
     * returner needs; a recover leg will carry it, and each seat's word that it
     * was owed nothing is of less than this seat now holds */
    if (uDist && I->rx) {
      I->recDue = 1;
      ++V->c.lateUnit;
      if (fCls == AC_CLS_DIST)
        ++V->c.lateDist;
      for (i = 0; i < BITS(N) && !I->rx->done[i]; ++i)
        ;
      if (i < BITS(N))
        ++V->c.lateWord;
      memset(I->rx->done, 0, BITS(N));
      memset(I->rx->done + 2 * BITS(N), 0, BITS(N));
    }
    /* X's unit landing after SUBSET is the leg (X, self)'s condition
     * met then: the exchange's launch runs again, for what it now holds
     * [Bracha87 Section 3: "including those received at previous
     * steps"] */
    if (uDist && I->haveSubset)
      I->subsetDue = 1;
    if (uDist)
      trace(V, I->num, "unit of %u held (offset %u)", evX, d->off);
    else
      trace(V, I->num, "exchange unit of %u from %u held (offset %u)", evX, evS, e->off);
    if (fCls == AC_CLS_DIST)
      goto distAfter;
    /* the leg's BESIDE, once the unit is whole under its v and, on a
     * recover leg, S's description is held */
    if (g->f && (g->fed & FED_INITIAL) && !(g->fed & FED_BESIDE) && (fCls != AC_CLS_RCV || I->dHeld[evS])
     && !memcmp(g->v, uDist ? d->apex : EX_APEX(e), HashSz)) {
      g->fed |= FED_BESIDE;
      nout = bracha87Fig1Input(g->f, BRACHA87_BESIDE, evIdx, 0, 0, f1out);
      f1site = SITE_DISPATCH;
      goto runF1;
    }
    goto dispatchReturn;

    /* a re-send of a part held: its sender has not heard this seat's
     * HOLDING.  With the unit whole and fed, fed as BESIDE again where
     * it was fed before: the library records nothing of it and replies
     * its echo, a copy's reply as a row's (copyBudget) */
  dupPart:
    ++V->c.copy;
    ++SEATC(V, evFrom).resent;
    if (fCls == AC_CLS_DIST) {
      ++V->c.dupDunit;
      if (I->a && d->held && I->dist[evX].fedBeside && !I->acsAbandoned
       && copyBudget(V, I, evFrom, 8 * RLEG_ROW + 2 * (evX * N + evX))) {
        nacts = bkr94acsInput(I->a, BRACHA87_BESIDE, evX, evX, 0, evFrom, 0, 0, V->acts);
        aList = V->acts;
        aCnt = nacts;
        acsSite = SITE_DISPATCH;
        goto runAcs;
      }
    } else {
      ++V->c.dupXunit;
      /* fed again, or fed now where the leg became whole since its
       * INITIAL was fed alone */
      if ((uDist ? d->held : e->held) && g->f && (g->fed & FED_INITIAL)
       && ((g->fed & FED_BESIDE)
        || ((fCls != AC_CLS_RCV || I->dHeld[evS]) && !memcmp(g->v, uDist ? d->apex : EX_APEX(e), HashSz)))) {
        if ((g->fed & FED_BESIDE) ? !copyBudget(V, I, evFrom, 2 * (g - I->leg)) : !AUTHED())
          goto dispatchReturn;
        g->fed |= FED_BESIDE;
        nout = bracha87Fig1Input(g->f, BRACHA87_BESIDE, evIdx, 0, 0, f1out);
        f1site = SITE_DISPATCH;
        goto runF1;
      }
    }
  }
  goto dispatchReturn;

  /*
   * A recover leg's description lands, the third part beside S's unit:
   * S's word on what the position decided, the subset's bitmap and
   * every member's agreed value in seat order, the same bytes beside
   * every recover leg S initiates.  It passes when it is whole -- no
   * seat past n, at least n - t members, a value each -- and agrees
   * with what this seat holds itself: its subset where it has one, and
   * every member's value where it accepted one [Bracha87 Theorem 1: a
   * correct seat's value is accepted alike or not at all], from its
   * agreement, whose value broadcasts answer whether or not it reached
   * its subset (bkr94acs.h).  One description per S is held, by its
   * hash, so whatever comes after it from S moves nothing and is taken
   * for a re-send unread.  At a position this seat has
   * no subset of, T of them held alike from distinct seats are
   * DISCOVER: the description is the subset its agreement would reach,
   * and the subset and the values are taken as SUBSET gives them.
   * Agreed is not true, so the count: at most t seats are faulty and T
   * > t, so one of the T is a correct seat's, and a correct seat
   * describes only what its agreement decided, the same at every
   * correct seat; the description rides beside a recover leg and is no
   * Figure 1 value, so the count is of distinct senders, the in-tag
   * sender its proof verified (the ABAP README on trust).
   * HOLDING on a recover leg is its unit and this description held, so
   * a returner says it only once it has both, and S re-sends both until
   * it does.  S holding no unit to carry says it alone, with no leg here
   * (g->f 0), and it counts the same: S folded the position.
   */
descIn:
  {
    const unsigned char *pl;
    const unsigned char *own;
    unsigned int m;
    unsigned int c;

    /* a re-send: S has not heard this seat's HOLDING, and where the leg
     * is fed the library replies its echo to S, a copy's reply as a row's
     * (copyBudget); where it is not, it may be whole now */
    if (I->dHeld[evS]) {
      ++V->c.copy;
      ++SEATC(V, evFrom).resent;
      if (g->f && (g->fed & FED_BESIDE)) {
        if (!copyBudget(V, I, evFrom, 2 * (g - I->leg)))
          goto dispatchReturn;
        nout = bracha87Fig1Input(g->f, BRACHA87_BESIDE, evIdx, 0, 0, f1out);
        f1site = SITE_DISPATCH;
        goto runF1;
      }
      goto descBeside;
    }
    if ((N & 7) && evPl[BITS(N) - 1] >> (N & 7))
      goto descRefused;
    for (m = c = 0; m < N; ++m)
      if (BKR94ACS_BIT_TST(evPl, m))
        ++c;
    if (c < N - MaxByz || evLen != BITS(N) + c * HashSz)
      goto descRefused;
    if (I->haveSubset && memcmp(evPl, I->subset, BITS(N)))
      goto descRefused;
    for (pl = evPl + BITS(N), m = 0; m < N; ++m) {
      if (!BKR94ACS_BIT_TST(evPl, m))
        continue;
      own = I->hasVal[m] ? VAL(I, m) : m == V->self ? I->own->apex : bkr94acsValue(I->a, m);
      if (own && memcmp(own, pl, HashSz))
        goto descRefused;
      pl += HashSz;
    }
    if (!AUTHED())
      goto dispatchReturn;
    if (hashBuf(S, evPl, evLen, 0, 0, 0, 0, 0, 0, dh))
      goto dispatchReturn;              /* this seat's memory: not judged, S re-sends it */
    memcpy(I->dHash + evS * HashSz, dh, HashSz);
    I->dHeld[evS] = 1;
    trace(V, I->num, "description of %u held, %u members, %02x%02x..", evS, c, dh[0], dh[1]);
    if (!I->haveSubset) {
      for (m = c = 0; m < N; ++m)
        if (I->dHeld[m] && !memcmp(I->dHash + m * HashSz, dh, HashSz))
          ++c;
      if (c >= Threshold) {
        memcpy(I->subset, evPl, BITS(N));
        for (I->subsetCnt = 0, pl = evPl + BITS(N), m = 0; m < N; ++m) {
          if (!BKR94ACS_BIT_TST(I->subset, m))
            continue;
          ++I->subsetCnt;
          memcpy(VAL(I, m), pl, HashSz);
          I->hasVal[m] = 1;
          I->asmDue[m] = 1;
          pl += HashSz;
        }
        I->haveSubset = 1;
        I->subsetDue = 1;
        I->subsetTick = V->ticks;
        I->recovered = 1;
        ++V->c.recovered;
        trace(V, I->num, "DISCOVER: SUBSET (%u/%u) from %u seats' descriptions alike", I->subsetCnt, N, c);
      }
    }
    /* this leg's BESIDE, its unit whole under its v and the description
     * now held */
  descBeside:
    if (g->f && (g->fed & FED_INITIAL) && !(g->fed & FED_BESIDE)
     && (evX == evS ? I->dist[evX].held && VALMATCH(g->v, &I->dist[evX])
                    : EXCH(I, evX, LEAF(evX, evS)).held && VALMATCHX(g->v, &EXCH(I, evX, LEAF(evX, evS))))) {
      if (!AUTHED())
        goto dispatchReturn;
      g->fed |= FED_BESIDE;
      nout = bracha87Fig1Input(g->f, BRACHA87_BESIDE, evIdx, 0, 0, f1out);
      f1site = SITE_DISPATCH;
      goto runF1;
    }
  }
  goto dispatchReturn;

descRefused:
  ++V->c.rcvRefused;
  ++SEATC(V, evS).rcvRefused;
  trace(V, I->num, "description of %u refused", evS);
  goto dispatchReturn;

dispatchReturn:
  switch (dispatchSite) {
  case SITE_ARRIVAL: goto arrivalDone;
  default: goto handbackDone;
  }

  /*
   * Run the actions of the leg g (X = fX, initiator fS): ACCEPT is
   * noted; a step's ECHO or READY is marked owed for the talk to say;
   * a reply is owed to the arrival's sender, self where the event was
   * this seat's own.
   */
runF1:
  for (ra = 0; ra < nout; ++ra) {
    unsigned char act;

    act = f1out[ra];
    if (act == BRACHA87_ACCEPT) {
      trace(V, I->num, "leg (X=%u S=%u) accepted", fX, fS);
      continue;
    }
    if (act == BRACHA87_ECHO_REPLY || act == BRACHA87_READY_REPLY) {
      rpIx = g - I->leg;
      rpGate = 1;
      rpKind = act == BRACHA87_ECHO_REPLY ? BRACHA87_ECHO : BRACHA87_READY;
      rpVal = 0;
      rpTo = f1site == SITE_DISPATCH ? evFrom : V->self;
      rpSite = 1;
      goto replyAdd;
runF1Replied:
      continue;
    }
    if (act == BRACHA87_READY_ANSWER) {
      rpIx = g - I->leg;
      rpGate = 1;
      rpKind = BRACHA87_READY;
      rpVal = 0;
      rpF = g->f;
      rpSite = 3;
      rpTo = 0;
      goto answerNext;
runF1Answered:
      continue;
    }
    /* a step's send is owed; a sweep step's re-sends are the pass's */
    if (f1site == SITE_SWEEP)
      continue;
    if (!g->owed)
      ++I->gOwed;
    g->owed |= OWED(act == BRACHA87_ECHO_ALL ? BRACHA87_ECHO : BRACHA87_READY);
  }
  switch (f1site) {
  case SITE_LAUNCH:   goto launchLegDone;
  case SITE_RCV:      goto rcvLegDone;
  case SITE_SWEEP:    goto runF1SweepDone;
  case SITE_OWN:      goto ownAloneDone;
  default:            goto dispatchReturn;
  }

  /*
   * Run the ACS seat's actions: DECIDED is noted; SUBSET makes the legs
   * due; ABANDON, the round ceiling, is noted; a step's INITIAL, ECHO
   * or READY is marked owed, under its BA value (none at round 0), for
   * the talk to say; a reply is owed to the arrival's sender: the from
   * the seat was fed.
   */
runAcs:
  for (ra = 0; ra < aCnt; ++ra) {
    const struct bkr94acsAct *act;
    unsigned int oi;

    act = &aList[ra];
    switch (act->act) {
    case BKR94ACS_DECIDED:
      I->round[act->ba] = act->k;
      /* the (n - t)th 1: from here this seat waits its patience on the
       * values not yet accepted */
      if (act->value && ++I->ones == N - MaxByz) {
        I->nmtTick = V->ticks;
        I->nmtUs = us;
      }
      trace(V, I->num, "BA[%u] decided %u at round %u%s", act->ba, act->value, act->k,
            act->ba == V->self && !act->value ? " (own message excluded)" : "");
      continue;
    case BKR94ACS_SUBSET:
      /* the agreement here ran to its SUBSET: its length, whether or
       * not a DISCOVER came first */
      if (!I->acsSubset) {
        I->acsSubset = 1;
        if (bkr94acsSweeps(I->a) > V->c.subsetMost)
          V->c.subsetMost = bkr94acsSweeps(I->a);
      }
      if (I->haveSubset) {
        trace(V, I->num, "SUBSET at sweep %u, after a DISCOVER", bkr94acsSweeps(I->a));
        continue;                       /* DISCOVER came first: the same subset */
      }
      memcpy(I->subset, bkr94acsSubSet(I->a), BITS(N));
      for (I->subsetCnt = 0, rj = 0; rj < N; ++rj) {
        const unsigned char *ap;

        if (BKR94ACS_BIT_TST(I->subset, rj))
          ++I->subsetCnt;
        /* every value accepted here, the members' among them: the
         * instance's from here on */
        if ((ap = bkr94acsValue(I->a, rj))) {
          memcpy(VAL(I, rj), ap, HashSz);
          I->hasVal[rj] = 1;
        }
      }
      I->haveSubset = 1;
      I->subsetDue = 1;
      /* a value broadcast still waiting is for no member: it goes again
       * at the next launch */
      I->ownDue = 0;
      I->subsetTick = V->ticks;
      for (rj = 0; rj < N; ++rj)        /* the members' parts held so far: now acted on */
        if (BKR94ACS_BIT_TST(I->subset, rj))
          I->asmDue[rj] = 1;
      if (V->cb->trace) {
        char line[16 * AC_SEATS];
        int n;

        n = 0;
        for (rj = 0; rj < N; ++rj)
          if (BKR94ACS_BIT_TST(I->subset, rj))
            n += sprintf(line + n, " %u", rj);
        trace(V, I->num, "SUBSET (%u/%u) at sweep %u:%s", I->subsetCnt, N, bkr94acsSweeps(I->a), line);
      }
      continue;
    case BKR94ACS_ABANDON:
      /* given no count, the library abandons only at the round ceiling,
       * an agreement undecided past it */
      I->acsAbandoned = 1;
      I->ceiling = 1;
      if (!I->haveSubset)
        ++V->c.noSubset;
      trace(V, I->num, "ACS seat abandoned at the round ceiling%s",
            I->acsSubset ? "" : I->haveSubset ? " without its SUBSET, the subset DISCOVERed" : " without a subset");
      continue;
    case BKR94ACS_REPLY_ECHO:
    case BKR94ACS_REPLY_READY:
      rpIx = (act->ba * N + act->q) * (Rounds + 1) + act->k;
      rpGate = 0;
      rpKind = act->act == BKR94ACS_REPLY_ECHO ? BRACHA87_ECHO : BRACHA87_READY;
      rpVal = act->value;
      rpTo = acsSite == SITE_LAUNCH ? V->self : acsSite == SITE_BESIDE ? evX : evFrom;
      rpSite = 0;
      goto replyAdd;
runAcsReplied:
      continue;
    case BKR94ACS_ANSWER_READY:
      rpIx = (act->ba * N + act->q) * (Rounds + 1) + act->k;
      rpGate = 0;
      rpKind = BRACHA87_READY;
      rpVal = act->value;
      rpF = bkr94acsInstance(I->a, act->ba, act->q, act->k);
      rpSite = 2;
      rpTo = 0;
      goto answerNext;
runAcsAnswered:
      continue;
    default:
      break;
    }
    /* this seat's entry in a member's agreement: 1 on its value, 0 past
     * patience; a re-send says the same */
    if (act->act == BKR94ACS_SEND_INITIAL && act->k == 1 && act->value == BKR94ACS_V1)
      I->entered[act->ba] = 1;
    /* patience ran out on a member: the first 0 entered, its re-sends
     * aside */
    if (act->act == BKR94ACS_SEND_INITIAL && act->k == 1 && act->value == BKR94ACS_V0 && act->ba != V->self
     && !(I->acc[act->ba] & 2)) {
      I->acc[act->ba] |= 2;
      ++SEATC(V, act->ba).zeros;
    }
    oi = (act->ba * N + act->q) * (Rounds + 1) + act->k;
    /* a step's send is owed, under its value; a sweep step's re-sends
     * are the pass's */
    if (acsSite == SITE_SWEEP)
      continue;
    if (!I->oAcs[oi])
      ++I->aOwed;
    I->oAcs[oi] = (I->oAcs[oi] & ~(3 << OWED_VAL(act->act))) | OWED(act->act)
             | (act->value << OWED_VAL(act->act));
  }
  switch (acsSite) {
  case SITE_SWEEP:    goto runAcsSweepDone;
  case SITE_LAUNCH:   goto runAcsLaunchDone;
  case SITE_BESIDE:   goto runAcsBesideDone;
  default:            if (evCls == AC_CLS_DIST) goto distAfter; else goto runAcsDispatchDone;
  }

  /*
   * A reply owed: a bit in the row of the seat it is owed to, so the
   * same row owed to the same seat already is owed once, and all one
   * seat can be owed is bounded by the rows it can name, however fast
   * it sends.  A record's machines have no ACS seat to reply from.
   */
replyAdd:
  if (rpGate) {
    rb = 2 * rpIx + rpKind - BRACHA87_ECHO;
    if (!(I->rLeg[rpTo * RLEG_ROW + (rb >> 3)] & (1 << (rb & 7)))) {
      I->rLeg[rpTo * RLEG_ROW + (rb >> 3)] |= 1 << (rb & 7);
      ++I->rDueG[rpTo];
    }
  } else if (I->rAcs) {
    RAVAL(I)[rpIx] = (RAVAL(I)[rpIx] & ~(3 << 2 * (rpKind - BRACHA87_ECHO))) | rpVal << 2 * (rpKind - BRACHA87_ECHO);
    rb = 2 * (rpIx % (Rounds + 1) * N * N + rpIx / (Rounds + 1)) + rpKind - BRACHA87_ECHO;
    if (!(I->rAcs[rpTo * RACS_ROW + (rb >> 3)] & (1 << (rb & 7)))) {
      I->rAcs[rpTo * RACS_ROW + (rb >> 3)] |= 1 << (rb & 7);
      ++I->rDueA[rpTo];
    }
  }
  switch (rpSite) {
  case 0:  goto runAcsReplied;
  case 1:  goto runF1Replied;
  default: ++rpTo; goto answerNext;
  }

  /*
   * The answer at an accept: its ready owed to each seat whose ready
   * the instance holds, this seat's own by hand-back.
   */
answerNext:
  while (rpTo < N && !bracha87Fig1ReadySender(rpF, rpTo))
    ++rpTo;
  if (rpTo < N)
    goto replyAdd;
  switch (rpSite) {
  case 2:  goto runAcsAnswered;
  default: goto runF1Answered;
  }

  /*
   * Room at the retention's head for a record of recLen bytes: where
   * the retention ends it wraps, and the oldest records in the way are
   * let go, the floor stepping over each link they minted and the masks
   * under the key before each step unrecoverable here from then on --
   * the second window ends at the tail.  A copy in the way gives up its
   * bytes alone: its position's place in the order was its first.
   */
recRoom:
  for (;;) {
    recNeed = V->recHead + recLen <= Retention ? recLen : Retention - V->recHead;
    while (V->recCount && V->recTail >= V->recHead && V->recTail < V->recHead + recNeed) {
      unsigned long tl;
      unsigned char *r;

      r = V->rec + V->recTail;
      tl = GET32(r + REC_LEN);
      if (!r[REC_COPY]) {
        memcpy(kInfo, r + REC_LINK, HashSz);
        kInfo[HashSz] = DOM_RAT;
        for (i = 0; i < N; ++i) {
          Kdf->hkdf(FLOORIKM(V, i), PSK_MASK_SIZE, kInfo, HashSz + 1, kNk, PSK_MASK_SIZE);
          memcpy(FLOORIKM(V, i), kNk, PSK_MASK_SIZE);
        }
        memset(kNk, 0, sizeof (kNk));
        trace(V, GET32(r + REC_NUM), "let go: the retention's tail");
        V->cb->released(V->cb->ctx, GET32(r + REC_NUM), V->ticks);
        kn.k0 = r[REC_NAME];        /* out of the tree by name, while the name is there */
        kn.key = r + REC_NAME + 1;
        kn.seq = 0;
        if ((tn = tLow(&V->recName, &kn)) && !tCmp(&V->recName, &kn, tn)) {
          struct inst *k;
          unsigned int dt;

          for (dt = 0; dt < N; ++dt)
            if (V->descTo[dt] == tn->own)
              V->descTo[dt] = 0;
          tDel(&V->recName, tn);    /* by its node: rx may be another record's */
          /* its kept assembly: nothing more lands, the last pass over
           * what is held and the reports */
          if ((k = ((struct recIx *)tn->own)->kept)) {
            k->rx = 0;
            k->gone = 1;
            memset(k->kc, 0, N * PSK_MASK_SIZE);  /* the floor steps over its key */
            memset(k->kcOk, 0, N);
            for (i = 0; i < N; ++i)
              if (k->srch[i].kept && !k->srch[i].reported) {
                k->srch[i].final = 1;
                k->asmDue[i] = 1;
              }
          }
          free(tn->own);
        }
        ++V->c.released;
      }
      memset(r, 0, tl);           /* the shares among it */
      V->c.retainedBytes -= tl;
      if (!--V->recCount) {
        V->recTail = V->recHead = 0;
        V->c.retained = 0;
        break;
      }
      V->c.retained = V->recCount;
      V->recTail += tl;
      if (V->recTail > Retention - REC_HDR || !GET32(V->rec + V->recTail + REC_LEN))
        V->recTail = 0;
    }
    if (V->recHead + recLen <= Retention)
      break;
    if (Retention - V->recHead >= REC_HDR)
      PUT32(V->rec + V->recHead + REC_LEN, 0);   /* the retention wraps here */
    V->recHead = 0;
  }
  switch (recSite) {
  case 0:   goto recRoomDone;
  default:  goto recCopyRoomDone;
  }

  /*
   * The mask key of the position kI with seat kJ, into kIkm.  A live
   * one's: the current step, the oldest live position's key, walked
   * forward by HKDF(key, link || 'R') over the link of every older live
   * position that has folded, in the window's order.  One whose
   * assembly a record keeps: the floor, over the records before it.
   * Either walk gives the dealt key stepped over every link before the
   * position, so once it reached the position over links all minted it
   * is the position's for good: held in the position's kc, wiped when
   * the position or its record is let go, and the walk not run again.
   * The user wipes kIkm.
   */
keyWalk:
  if (kI->kcOk[kJ]) {
    memcpy(kIkm, kI->kc + kJ * PSK_MASK_SIZE, PSK_MASK_SIZE);
    goto keyWalked;
  }
  kKeep = 0;
  if (kI->rx) {
    /* machines or an assembly its record keeps: the floor, walked over
     * the links of the records before its first, copies passed over */
    memcpy(kIkm, FLOORIKM(V, kJ), PSK_MASK_SIZE);
    for (ko = V->recTail, kw = 0; kw < V->recCount; ++kw) {
      if (ko > Retention - REC_HDR || !GET32(V->rec + ko + REC_LEN))
        ko = 0;
      if (ko == kI->rx->anchor) {
        kKeep = 1;
        break;
      }
      if (!V->rec[ko + REC_COPY]) {
        memcpy(kInfo, V->rec + ko + REC_LINK, HashSz);
        kInfo[HashSz] = DOM_RAT;
        Kdf->hkdf(kIkm, PSK_MASK_SIZE, kInfo, HashSz + 1, kNk, PSK_MASK_SIZE);
        memcpy(kIkm, kNk, PSK_MASK_SIZE);
      }
      ko += GET32(V->rec + ko + REC_LEN);
    }
  } else {
    memcpy(kIkm, CURIKM(V, kJ), PSK_MASK_SIZE);
    for (kKeep = 1, kw = 0; kw < V->nLive && V->live[kw] != kI; ++kw)
      if (V->live[kw]->stepped) {
        memcpy(kInfo, V->live[kw]->link, HashSz);
        kInfo[HashSz] = DOM_RAT;
        Kdf->hkdf(kIkm, PSK_MASK_SIZE, kInfo, HashSz + 1, kNk, PSK_MASK_SIZE);
        memcpy(kIkm, kNk, PSK_MASK_SIZE);
      } else
        kKeep = 0;
    if (kw == V->nLive)
      kKeep = 0;
  }
  memset(kNk, 0, sizeof (kNk));
  /* every link before the position stepped: its key with kJ is that
   * walk from here on, held until the position is let go */
  if (kKeep) {
    memcpy(kI->kc + kJ * PSK_MASK_SIZE, kIkm, PSK_MASK_SIZE);
    kI->kcOk[kJ] = 1;
  }
keyWalked:
  switch (kSite) {
  case 0:  goto keyWalkTalkDone;
  default: goto keyWalkUnitDone;
  }

  /*
   * A library whose only refusal is a parameter, refusing one derive
   * validated: the agreement library's at an instance's start.  No
   * deployment reaches it, short of a fault in this tree.  The seat
   * goes no further, and says so by going quiet; the caller sees acWork
   * return none and frees it.  Memory refused is never this: a row is
   * refused and its sender's sweep brings it again (rowMem), a step of
   * this seat's own waits for its next call (ownMem), and so does one a
   * library refused that may have been the library's memory, a
   * signature or a coding through the suite's allocator.
   */
exit:
  V->failed = 1;
  trace(V, 0, "a parameter refused: the seat stops");
}

/*
 * What the construction fixes from the physics and the configuration
 * the caller gave: the threshold, the signature and proof sizes, the
 * unit and shard bounds, the longest message a proposal admits, the
 * framer's shard, the tick, the patience and the round ceiling.  The
 * public acDerive derives every one of them; the test build's
 * acTestDerive lets a knob stand where one is set, and both run this.
 * 0, or -1 with the reason on nothing: the caller's parameters do not
 * make a seat.
 */
void acFree(struct ac *);

static int
derive(
  struct acPar *S
){
  mlsHsh_t pl;
  mlsCtx_t v;

  /* a zero takes the default: the datagram 1232 bytes (IPv6's least
   * MTU less its headers), 16 MiB of retention, 4 signings a context */
  if (!DgramMax)
    DgramMax = 1232;
  if (!Retention)
    Retention = 16UL << 20;
  if (!MlsS)
    MlsS = 2;
  /* the round ceiling is the byte's: 85 phases of three rounds, 1..255.
   * The coin is each seat's own, so an agreement whose inputs a
   * scheduler split ends a phase only when the honest coins agree by
   * chance, which is good enough for the byte once 2t / sqrt(n - t) is
   * 1.5 or under with n + t odd (the count is whole: an even n + t
   * needs one coin more), n above about 1.8 t^2 + t; the ceiling is
   * paid in seats, never in phases, and the chain report's round is
   * where a deployment reads whether its (n, t) sit there */
  if (!Rounds)
    Rounds = 3 * DEF_PHASES;
  /* the configuration and the suites as ac.h states them: the sign role
   * a power-of-two width, h its exponent, the kdf role any width,
   * neither past AC_HASH_MAX, each with the functions this seat calls */
  if (N < 3 || N > AC_SEATS || N <= 3 * MaxByz || S->self >= N || !BwLimit || S->lossPct >= 100
   || MlsS > 8 || Rounds > 255
   || !Sign || !Sign->alloc || !Sign->tsize || !Sign->init || !Sign->update || !Sign->final
   || !Sign->h || Sign->h >= 8 * sizeof (Sign->size) || Sign->size != 1U << Sign->h || Sign->size > AC_HASH_MAX
   || !Kdf || !Kdf->hmac || !Kdf->hkdf || !Kdf->size || Kdf->size > AC_HASH_MAX)
    return (-1);
  Threshold = MaxByz > 1 ? MaxByz + 1 : 2;      /* T > t and T > 1 */
  HashSz = Sign->size;
  SignH = Sign->h;
  KdfSz = Kdf->size;
  KdfMax = 255 * KdfSz;
  HmacSz = KdfSz;
  pl.a = Sign->alloc;
  pl.i = Sign->init;
  pl.u = Sign->update;
  pl.f = Sign->final;
  pl.d = free;
  pl.h = SignH;
  v.h = &pl;
  v.r = 0;
  v.s = MlsS;
  if (!(SigLen = mlsSgSz(&v)) || !mlsPrSz(&v) || !mlsWaSz(&v))
    return (-1);
  PfSz = sssMkPfSz(SignH, N - 1);
  if (!PfSz || PfSz != rsecMkPfSz(SignH, N - 1) || PfSz > PROOF_MAX)
    return (-1);
  /* the longest message a proposal admits, which the wire bounds and
   * the caller cannot know: a unit is two messages, the sign part and
   * one shard, each at most MSG_MAX; the padded ciphertext, k x the
   * shard, is at most one message, so a shard is at most MSG_MAX / T, a
   * distribute past it refuses and a shard implying more is refused at
   * ingress; the message is the one whose ciphertext at distribute's
   * huffman cap (the message plus 1024) is exactly that.  The longest
   * message any seat makes is that data part or the sign part */
  UnitFixed = 3 * HashSz + SigLen + MVAL_LEN + 2 * PfSz;
  if (UnitFixed > MSG_MAX)
    return (-1);
  ShardMax = MSG_MAX / Threshold;
  PartMax = UnitFixed > ShardMax ? UnitFixed : ShardMax;
  if (ShardMax * Threshold <= 1024)
    return (-1);
  MsgMax = ShardMax * Threshold - 1024;
  /* the longest record a position can leave: a row entry for every
   * value broadcast, a payload at the wire's bound from every member
   * and this seat's own to every recipient; the retention holds at
   * least one, so a record always fits, and a retention of the default
   * refuses the widest memberships at the widest suite */
  RecMax = REC_HDR
         + (N - 1) * (RM_HDR + SigLen + MVAL_LEN + 2 * PfSz + ShardMax)
         + RM_HDR + SigLen + RM_LEAVES + (N - 1) * ShardMax;
  if (Retention < RecMax)
    return (-1);
  if (!(Shard = rsecFrmShard(DgramMax, TagSz, GATE_SIZE))
   || rsecFrmMax(DgramMax, TagSz, GATE_SIZE, 0) < MSG_MAX + HmacSz)
    return (-1);
  if (!TickMs) {
    unsigned int m;
    unsigned int mVal;
    unsigned long d;
    unsigned long dVal;
    unsigned long unit;
    unsigned long burst;
    unsigned long reply;
    unsigned long tick;

    /* One feedback cycle at the declared physics: what this seat says
     * in one step and what comes back.  The step is one broadcast's
     * INITIAL with the sign part beside it (a payload's signed header,
     * signature, masked share and proofs; a rotation's and a noop's are
     * shorter), each datagram its shards and its parity, to the N - 1
     * other seats at the declared bandwidth; then the delay there, the
     * ECHO of its v from each, and the delay back.  The tick is a
     * clock, never a budget: a pass carries what the sweep owes, every
     * instance of every live position, the legs a SUBSET starts at once
     * and a payload's shards among it, paced at the bandwidth, and one
     * that carries more than the tick runs past it, and the next tick
     * starts when it ends (passLong counts them), which is how the tick
     * follows the load without a declaration of it.  Patience and the
     * abandon, counted in sweeps, stretch with it.  A tick past what
     * TickMs holds is the longest it holds. */
    pace(S, UnitFixed, &m, &d);
    unit = ((UnitFixed + HmacSz + Shard - 1) / Shard + m) * d;
    pace(S, HashSz, &mVal, &dVal);
    burst = (unsigned long)(N - 1) * (unit + (1 + mVal) * dVal) / 1000;
    reply = (unsigned long)(N - 1) * (1 + mVal) * dVal / 1000;
    tick = burst + reply + 2 * S->delayMs;
    TickMs = tick > (unsigned int)-1 ? (unsigned int)-1 : tick;
    if (TickMs < 50)
      TickMs = 50;
  }
  /* the patience, in sweeps, a seat waits for all n before it goes on
   * at n - t, so as not to spend the Byzantine budget against an honest
   * laggard: an honest seat's row of a round arrives here within one
   * feedback cycle of this seat's own while that seat's pass fits its
   * tick -- its round turned at most a delay after this seat's, its
   * send is paced within its pass, and the row crosses in a delay --
   * which is the tick above; and the sweep that first counts the round
   * may come at once, the round having started inside a pass.  One
   * partial sweep and one tick.  A seat whose pass runs past its tick
   * is late by what the pass carries, and this seat's own passes,
   * stretched by its own load, are the only measure it has of that.  A
   * row lost past its parity is BPR's: re-sent in the sender's next
   * pass, and the parity counters say how often the declared loss was
   * met.  A sweep that re-sends is a sweep that made no progress, so to
   * those two the sweeps the declared loss retries: the steady loss's,
   * a wait reading about three rows of every other seat's broadcast,
   * 3(n - 1) of a datagram each, a row lost only with all m + 1 of its
   * datagrams (pace's parity), so at loss^(m + 1) a send, and re-sent a
   * sweep later, so the sweeps until every row has arrived 99 times in
   * 100, by the union bound, rows x (loss^(m + 1))^(r + 1) <= 1/100, in
   * hundredths; and the burst's, every sweep in it a retry */
  if (!Patience) {
    unsigned long x;
    unsigned long d;
    unsigned int m;
    unsigned int j;

    Patience = 2;
    if (S->lossPct) {
      pace(S, 1, &m, &d);
      for (x = 3UL * (N - 1) * 100 * 100; ; ++Patience) {
        for (j = 0; j <= m && x > 100; ++j)
          x = (x * S->lossPct + 99) / 100;
        if (x <= 100)
          break;
      }
    }
    Patience += (S->burstMs + TickMs - 1) / TickMs;
  }
  /* the abandon, the deployment's: the sweeps an instance runs before
   * it stops, how long the deployment holds its memory, past the
   * patience [bkr94acs.h] -- and where t allows a member gone, at least
   * one agreement with it gone, every patience running out in full: the
   * launch's tick, the first phase of the agreements that decide 1,
   * three rounds each waiting its patience, step 2's patience, and the
   * first phase of those that decide 0, whose SUBSET the pass that
   * reaches the abandon still returns.  An abandon inside that stops
   * every position at its agreement whenever one seat is silent */
  if (Abandon < (S->t ? 1 + 7 * Patience : Patience + 1))
    return (-1);
  return (0);
}

int
acDerive(
  struct acPar *S
){
  if (!S)
    return (-1);
  ParityShards = -1;
  ShardDelayUs = -1;
  TickMs = Patience = Rounds = 0;
  return (derive(S));
}

#ifdef AC_TEST
int
acTestDerive(
  struct acPar *S
 ,const struct acTest *t
){
  if (!S || !t)
    return (-1);
  ParityShards = t->parity;
  ShardDelayUs = t->shardDelayUs;
  TickMs = t->tickMs;
  Patience = t->patience;
  Rounds = t->rounds;
  return (derive(S));
}

void
acTestPace(
  const struct acPar *S
 ,unsigned int payLen
 ,unsigned int *m
 ,unsigned long *d
){
  pace(S, payLen, m, d);
}
#endif

/*
 * A seat, its parameters derived: the plugs from the sign suite, the
 * signing identity minted, its public key the caller's to publish
 * (acPub), the tables and the retention allocated.  The seat, or 0 with
 * it freed where an allocation failed.
 */
static struct ac *
make(
  struct ac *V
){
  const struct acPar *S;
  unsigned char *wa;
  const unsigned char *pubp;

  S = &V->p;
  MlsPlug.a = SssPlug.a = RsecPlug.a = Sign->alloc;
  MlsPlug.i = SssPlug.i = RsecPlug.i = Sign->init;
  MlsPlug.u = SssPlug.u = RsecPlug.u = Sign->update;
  MlsPlug.f = SssPlug.f = RsecPlug.f = Sign->final;
  MlsPlug.d = SssPlug.d = RsecPlug.d = free;
  MlsPlug.h = SssPlug.h = RsecPlug.h = SignH;
  V->qCap = 64 * N;
  if (!(V->ubuf = malloc(PartMax > DESC_MAX ? PartMax : DESC_MAX))
   || !(V->pbuf = malloc(ShardMax * Threshold))
   || !(V->hLink = malloc(Sign->tsize()))
   || !(V->q = malloc(V->qCap * sizeof (*V->q)))
   || !(V->rec = malloc(Retention))
   || !(V->tab = calloc(1, CTX_TAB_SZ))
   || !(V->sc = calloc(N, sizeof (*V->sc)))
   || !(V->rttUs = calloc(N, sizeof (*V->rttUs)))
   || !(V->tickNow = calloc(2 * N, sizeof (*V->tickNow)))
   || !(V->rttNum = calloc(N, sizeof (*V->rttNum)))
   || !(V->rttOpen = calloc(N, 1))
   || !(V->swUs = calloc(N, sizeof (*V->swUs)))
   || !(V->swDue = calloc(N, 1))
   || !(V->rtab = malloc(RT_SZ(V)))
   || !(V->rowTick = calloc(3 * N, sizeof (*V->rowTick)))
   || !(V->descTo = calloc(N, sizeof (*V->descTo)))
   || !(V->obuf = malloc(1 + 1 + TagSz + 5 + MSG_MAX + HmacSz))
   || !(V->egrTab = calloc(1, PSKTAB_SZ))
   || !(V->igrTab = calloc(1, PSKTAB_SZ)))
    goto fail;
  /* the tables by seat carved from the block, by alignment: ints, then
   * bytes */
  V->promoted = (unsigned int *)V->tab;
  V->hwGen = V->promoted + N;
  V->hwOff = V->hwGen + N;
  V->hwPos = V->hwOff + N;
  V->pub = (unsigned char *)(V->hwPos + N);
  V->pubNext = V->pub + N * HashSz;
  V->hwApex = V->pubNext + N * HashSz;
  V->psk = V->hwApex + N * HashSz;
  V->curIkm = V->psk + N * PSK_SIZE;
  V->floorIkm = V->curIkm + N * PSK_MASK_SIZE;
  V->hasNext = V->floorIkm + N * PSK_MASK_SIZE;
  V->hwSet = V->hasNext + N;
  /* the identity: minted here, the private data never leaving the seat */
  V->mls.h = &V->mlsPlug;
  V->mls.s = MlsS;
  V->mls.r = 0;
  V->mlsNext = V->mls;
  V->slot = SLOT_PAY;
  if (!(V->mls.r = malloc(mlsPrSz(&V->mls)))
   || !(wa = malloc(mlsWaSz(&V->mls))))
    goto fail;
  V->cb->random(V->cb->ctx, V->mls.r, mlsPrSz(&V->mls));
  if (!(pubp = mlsHash(&V->mls, wa))) {
    free(wa);
    goto fail;
  }
  memcpy(PUB(V, V->self), pubp, HashSz);
  memcpy(V->cur, pubp, HashSz);
  memset(wa, 0, mlsWaSz(&V->mls));
  free(wa);
  /* the actions one ACS call can return, read from a seat made with the
   * run's n and rounds; every link's seat is made at its launch */
  {
    struct bkr94acs *a;

    if (!(a = calloc(1, bkr94acsSz(N - 1, HashSz - 1, Rounds)))
     || bkr94acsInit(a, N - 1, MaxByz, HashSz - 1, V->self, Rounds, Patience, 0, coinFn, V, 1)
     || !(V->outMax = bkr94acsOut(a))) {
      free(a);
      goto fail;
    }
    free(a);
  }
  if (!(V->acts = malloc(V->outMax * sizeof (*V->acts)))
   || !(V->sActs = malloc(V->outMax * sizeof (*V->sActs))))
    goto fail;
  /* the trees' keys after their first byte: a name's rest; a shape's
   * four bytes and the name */
  V->ahName.len = V->recName.len = HashSz - 1;
  V->ahShape.len = AC_TAG_NAME - 1 + HashSz;
  V->swPhase = SW_IDLE;
  V->talkUs = (unsigned long)(TickMs > 2 * S->delayMs ? TickMs - 2 * S->delayMs : TickMs) * 1000;
  return (V);

fail:
  acFree(V);
  return (0);
}

/*
 * A seat, from the caller's parameters and callbacks: the parameters
 * copied and derived (acDerive), then made (make).  0 where the
 * parameters make no seat or an allocation failed, and nothing is kept.
 */
struct ac *
acInit(
  const struct acPar *par
 ,const struct acCb *cb
){
  struct ac *V;

  if (!par || !cb || !cb->chain || !cb->message || !cb->released || !cb->send || !cb->random || !cb->propose
   || !(V = calloc(1, sizeof (*V))))
    return (0);
  V->p = *par;
  V->cbs = *cb;
  V->cb = &V->cbs;
  V->self = par->self;
  if (acDerive(&V->p)) {
    acFree(V);
    return (0);
  }
  return (make(V));
}

#ifdef AC_TEST
/* acInit, the harness's knobs standing where they are set, and its
 * hooks kept by pointer for the seat's life */
struct ac *
acTestInit(
  const struct acPar *par
 ,const struct acCb *cb
 ,struct acTest *t
){
  struct ac *V;

  if (!par || !cb || !t || !cb->chain || !cb->message || !cb->released || !cb->send || !cb->random || !cb->propose
   || !(V = calloc(1, sizeof (*V))))
    return (0);
  V->p = *par;
  V->cbs = *cb;
  V->cb = &V->cbs;
  V->self = par->self;
  V->test = t;
  if (acTestDerive(&V->p, t)) {
    acFree(V);
    return (0);
  }
  return (make(V));
}
#endif

/* this seat's public key, the sign role's width: minted at acInit, the
 * caller publishes it */
const unsigned char *
acPub(
  const struct ac *V
){
  return (V ? V->cur : 0);
}

/*
 * One other seat's row entry, the operator's deal through the caller:
 * the pairwise secret, PSK_SIZE bytes, whose slices key the message HMAC,
 * the datagram gate and the mask, and that seat's public key; both copied, so the
 * caller may wipe its own.  0, or -1 for a seat outside 0..n-1, self,
 * one already dealt, or any after the go.
 */
int
acDeal(
  struct ac *V
 ,unsigned char seat
 ,const unsigned char *psk
 ,const unsigned char *pub
){
  const struct acPar *S;

  if (!V || !psk || !pub)
    return (-1);
  S = &V->p;
  if (V->went || seat >= N || seat == V->self || V->hasNext[seat] & 2)
    return (-1);
  memcpy(PSKROW(V, seat), psk, PSK_SIZE);
  memcpy(CURIKM(V, seat), psk + PSK_MASK_OFF, PSK_MASK_SIZE);
  memcpy(FLOORIKM(V, seat), psk + PSK_MASK_OFF, PSK_MASK_SIZE);
  memcpy(PUB(V, seat), pub, HashSz);
  V->hasNext[seat] |= 2;                /* dealt; the book's bit is 1 */
  return (0);
}

/*
 * The go: every other seat dealt, the chain's genesis -- the dealt base
 * every seat folds from, HashSz bytes -- and the caller's clock in
 * microseconds, which acInput and acWork then carry.  The framers are
 * keyed from the rows and position 1 launches.  0, or -1 with a seat
 * undealt, a go already made, the framers refused (memory, the seat as
 * the call found it), or the seat failed at the launch.
 */
int
acGo(
  struct ac *V
 ,const unsigned char *genesis
 ,unsigned long nowUs
){
  const struct acPar *S;
  unsigned int e;

  if (!V || !genesis || V->went)
    return (-1);
  S = &V->p;
  for (e = 0; e < N; ++e)
    if (e != V->self && !(V->hasNext[e] & 2))
      return (-1);
  V->egrTab->self = V->igrTab->self = V->self;
  V->egrTab->p = V->igrTab->p = &V->p;
  V->egr.realloc = V->igr.realloc = realloc;
  V->egr.free = V->igr.free = free;
  V->egr.dgramMax = V->igr.dgramMax = DgramMax;
  V->egr.tagSize = V->igr.tagSize = TagSz;
  V->egr.tableSize = V->igr.tableSize = TABLE_SIZE;
  /* the ingress table shared among the senders the gate proved, so a
   * seat that opens messages it never finishes evicts its own */
  V->igr.tagOwner = 1 + AC_TAG_SENDER;
  V->egr.dtgHashSize = V->igr.dtgHashSize = GATE_SIZE;
  V->egr.dtgHashCtx = V->egrTab;
  V->egr.dtgHashSign = gateSignCb;
  V->igr.dtgHashCtx = V->igrTab;
  V->igr.tagOkCtx = V;
  V->igr.tagOk = tagOkCb;
  V->igr.dtgHashVrfy = gateVrfyCb;
  V->igr.msgMax = PartMax + HmacSz;
  /* the framers first: a refusal, memory alone, leaves the seat as the
   * call found it, to go again */
  if (!rsecFrmEgrInit(&V->egr))
    return (-1);
  if (!rsecFrmIgrInit(&V->igr)) {
    rsecFrmEgrFini(&V->egr);
    return (-1);
  }
  for (e = 0; e < N; ++e) {
    V->hasNext[e] = 0;
    memcpy(V->egrTab->psk + e * PSK_HASH_SIZE, PSKROW(V, e) + PSK_HASH_OFF, PSK_HASH_SIZE);
    memcpy(V->igrTab->psk + e * PSK_HASH_SIZE, PSKROW(V, e) + PSK_HASH_OFF, PSK_HASH_SIZE);
  }
  memcpy(V->chain, genesis, HashSz);
  V->lastTickUs = nowUs;
  V->went = 1;
  seat(V, EV_GO, 0, 0, nowUs);
  return (V->failed ? -1 : 0);
}

/*
 * A datagram from the wire, the bytes the transport delivered, and the
 * clock: identity is the in-tag sender a message's HMAC verifies, never
 * where it came from.  What it completes is read, and the work
 * that leaves is done.  0, or -1 for a null seat or datagram, one not
 * started, or one that failed before the call.
 */
int
acInput(
  struct ac *V
 ,const unsigned char *dgram
 ,unsigned int len
 ,unsigned long nowUs
){
  if (!V || !dgram || !V->went || V->failed)
    return (-1);
  seat(V, EV_INPUT, dgram, len, nowUs);
  return (0);
}

/* non-zero once the seat has stopped on a parameter derive validated,
 * refused by a library beneath: no deployment reaches it */
int
acFailed(
  const struct ac *V
){
  return (V ? V->failed : 1);
}

/*
 * The pass: the datagrams due to the caller's send, the held message to
 * the framer, the tick when due, the work.  Returns the microseconds
 * until the seat next has something due -- a datagram the framer paces,
 * or the tick, when no pass is in hand -- 0 when a send was refused or
 * something is due now, and -1 when nothing is: a quiet seat with
 * nothing left in its framer, or one that failed.  The caller calls at
 * least every tick.
 */
long
acWork(
  struct ac *V
 ,unsigned long nowUs
){
  const struct acPar *S;
  unsigned long due;
  unsigned long w;

  if (!V || !V->went)
    return (-1);
  S = &V->p;
  seat(V, EV_WORK, 0, 0, nowUs);
  if (V->failed)
    return (-1);
  if (V->aheadMore)
    return (0);
  /* the tick is due only when no pass is in hand: a tick that falls
   * inside a pass starts the next when this one ends, and a pass that
   * waits on the framer's pacing is due when its datagrams are */
  w = (unsigned long)TickMs * 1000;
  if (!V->quiet && V->swPhase == SW_IDLE) {
    due = V->lastTickUs + w;
    w = due - nowUs > ~0UL / 2 ? 0 : due - nowUs;
  } else
    w = ~0UL;
  if (rsecFrmEgrDue(&V->egr, &due)) {
    due = due - nowUs > ~0UL / 2 ? 0 : due - nowUs;
    if (due < w)
      w = due;
  }
  if (w == ~0UL)
    return (-1);
  return (w > (unsigned long)(~0UL >> 1) ? (long)(~0UL >> 1) : (long)w);
}

/*
 * The caller's end of the chain: a state of this seat, which every
 * value it signs from here carries, and its reason to launch until the
 * chain ends (the fold's count, the end run).  May be called from a
 * callback.
 */
void
acEnd(
  struct ac *V
){
  if (V)
    V->ended = 1;
}

/*
 * The caller's stop: nothing more is said -- no pass, no re-send, no
 * launch -- and what the framer holds goes at its pace; acWork returns
 * none once it has.  May be called from a callback.
 */
void
acQuiet(
  struct ac *V
){
  if (V)
    V->quiet = 1;
}

/* this seat's tick count: its pass count, the clock every count here is
 * in */
unsigned int
acTicks(
  const struct ac *V
){
  return (V ? V->ticks : 0);
}

/*
 * The caller has a message to propose: with no position in hand here,
 * one launches in the work, at the pass in hand from a callback or at
 * the next pass otherwise, and its input is asked of the caller
 * (propose) where the signing context leaves it a payload slot.  With
 * one in hand nothing is done and nothing is kept: its chain report is
 * where the caller learns what became of its proposal and decides what
 * to propose next.
 */
int
acAvailable(
  struct ac *V
){
  if (!V || V->ended || V->lastLink || V->quiet || V->failed)
    return (-1);
  if (!V->went || V->launchDue || V->folded != V->launched)
    return (1);
  V->avail = 1;
  return (0);
}

/* the seat's counters, copied, the refusals of the ingress framer's gate
 * and of a message's HMAC among them */
void
acCounters(
  const struct ac *V
 ,struct acCounters *c
){
  const struct acPar *S;
  unsigned int i;
  unsigned int j;

  if (!V || !c)
    return;
  S = &V->p;
  *c = V->c;
  for (c->keptNow = 0, i = 0; i < V->nKept; ++i)
    for (j = 0; j < S->n; ++j)
      if (V->kept[i]->srch[j].kept && !V->kept[i]->srch[j].reported)
        ++c->keptNow;
  c->egrWaitUs = V->egr.c.wait;
  c->dgFrg = V->egr.c.frg;
  c->igrEvict = V->igr.c.evict;
  c->igrEvictFull = V->igr.c.evictFull;
  c->igrGate = V->igr.c.hash;
  c->igrShape = V->igr.c.shape;
  c->ticks = V->ticks;
}

/* what this seat counts of one other seat, by the in-tag sender or the
 * signer, copied: never of itself */
int
acSeatCounters(
  const struct ac *V
 ,unsigned char seat
 ,struct acSeatCounters *c
){
  const struct acPar *S;

  if (!V || !c)
    return (-1);
  S = &V->p;
  if (seat >= N || seat == V->self)
    return (-1);
  *c = SEATC(V, seat);
  return (0);
}

/* the parameters as derived: what the seat runs by */
const struct acPar *
acPar(
  const struct ac *V
){
  return (V ? &V->p : 0);
}

#ifdef AC_TEST
/* the framers' counters, copied */
void
acTestCounters(
  const struct ac *V
 ,struct rsecFrmEgrCtrs *ec
 ,struct rsecFrmIgrCtrs *ic
){
  if (!V)
    return;
  if (ec)
    *ec = V->egr.c;
  if (ic)
    *ic = V->igr.c;
}

int
acTestHw(
  const struct ac *V
 ,unsigned int seat
 ,unsigned int *gen
 ,unsigned int *off
 ,unsigned int *pos
 ,unsigned char *apex
){
  const struct acPar *S;

  if (!V || seat >= V->p.n || !V->hwSet[seat])
    return (0);
  S = &V->p;
  *gen = V->hwGen[seat];
  *off = V->hwOff[seat];
  *pos = V->hwPos[seat];
  memcpy(apex, HWAPEX(V, seat), HashSz);
  return (1);
}
#endif

/*
 * Release a seat: the secrets wiped -- the private data, the mesh row,
 * the floor, every share held -- and everything freed.
 */
void
acFree(
  struct ac *V
){
  const struct acPar *S;
  unsigned int i;

  if (!V)
    return;
  S = &V->p;
  free(V->acts);
  free(V->sActs);
  if (V->mls.r) {
    memset(V->mls.r, 0, mlsPrSz(&V->mls));
    free(V->mls.r);
  }
  if (V->mlsNext.r) {
    memset(V->mlsNext.r, 0, mlsPrSz(&V->mlsNext));
    free(V->mlsNext.r);
  }
  if (V->rwa)
    memset(V->rwa, 0, mlsWaSz(&V->mls));   /* the tree over the private data */
  free(V->rwa);
  if (V->psk)
    memset(V->psk, 0, N * PSK_SIZE);
  if (V->curIkm)
    memset(V->curIkm, 0, N * PSK_MASK_SIZE);
  if (V->floorIkm)
    memset(V->floorIkm, 0, N * PSK_MASK_SIZE);
  if (V->rec)
    memset(V->rec, 0, Retention);       /* the records: the shares among them */
  free(V->rec);
  ownDrop(S, V->pend);
  ownDrop(S, V->cache);
  for (i = 0; i < V->nLive; ++i)
    instFree(S, V->live[i]);
  instFree(S, V->launching);
  free(V->live);
  for (i = 0; i < V->nKept; ++i)
    instFree(S, V->kept[i]);
  free(V->kept);
  /* the held rows and the records, each tree taken apart from its
   * leaves up; the shape tree's nodes lie in the rows */
  {
    struct tree *t;
    struct tnod *n;
    struct tnod *p;

    for (t = &V->ahName; t; t = t == &V->ahName ? &V->recName : 0)
      for (n = t->root; n;) {
        if (n->left)
          n = n->left;
        else if (n->right)
          n = n->right;
        else {
          if ((p = n->parent)) {
            if (p->left == n)
              p->left = 0;
            else
              p->right = 0;
          }
          if (t == &V->ahName) {
            struct ahead *a;

            a = n->own;
            free(a->b);
            free(a);
          } else
            free(n->own);
          n = p;
        }
      }
  }
  free(V->q);
  free(V->ubuf);
  if (V->pbuf)
    memset(V->pbuf, 0, ShardMax * Threshold);
  free(V->pbuf);
  free(V->hLink);
  free(V->rtab);
  rsecFrmEgrFini(&V->egr);
  rsecFrmIgrFini(&V->igr);
  if (V->egrTab)
    memset(V->egrTab, 0, PSKTAB_SZ);
  if (V->igrTab)
    memset(V->igrTab, 0, PSKTAB_SZ);
  free(V->egrTab);
  free(V->igrTab);
  free(V->rowTick);
  free(V->descTo);
  free(V->obuf);
  free(V->tab);
  free(V->sc);
  free(V->rttUs);
  free(V->tickNow);
  free(V->rttNum);
  free(V->rttOpen);
  free(V->swUs);
  free(V->swDue);
  free(V);
}

