# cryptoMule

Generated with Claude Code (https://claude.ai/code)

## What this is

[asynchronousByzantineAgreementProtocols](https://github.com/gdavidbutler/asynchronousByzantineAgreementProtocols) agrees on messages among n seats, up to t of them Byzantine. Its papers assume that each message comes from the seat that wrote it, and it leaves that to its caller. cryptoMule meets it two ways, one for each way a message travels:

- **An authenticated channel.** A message handed straight from one seat to another comes from the seat it names, unaltered. There the seat that hands it over is the seat that wrote it.
- **Message attribution.** A message another seat carries is still the word of the seat that wrote it. The papers have no such message. cryptoMule makes them, because a recipient the initiator never reached is served by the others, and through other hands only the writer's signature, and what the signed value commits to, name the writer.

cryptoMule is a set of deterministic recipes that meet it. It builds them from the primitive repositories: [rmd128](https://github.com/gdavidbutler/rmd128) and [rmd160](https://github.com/gdavidbutler/rmd160) for hashes, HMAC and HKDF; [canonicalHuffman](https://github.com/gdavidbutler/canonicalHuffman) to compress; [ReedSolomonErasureCoding](https://github.com/gdavidbutler/ReedSolomonErasureCoding) for the shards and [ShamirSecretSharing](https://github.com/gdavidbutler/ShamirSecretSharing) for the key's shares, each with its Merkle tree; and [MerkleLamportSignature](https://github.com/gdavidbutler/MerkleLamportSignature) to sign. It then goes two steps further, each against a stronger adversary than the assumption names:

- **Forward secrecy**, against the network.
- **Censorship resistance**, against seats.

The parent tree, [agreementChain](../README.md), implements these recipes natively in its `ac.c`. This directory is where they were settled, at a scale where every message is a file you can read.

The words are the agreement library's and the primitives', except dispersal, which is cryptoMule's own. Where the code still uses an older word, that word is given in parentheses. Identifiers, wire fields, file names and the arm and fault names you type keep the older words.

- **seat** (system): a participant. The initiator is seat 0 and the recipients are seats 1 to N - 1.
- **dispersal** (process): one initiator dispersing one message, numbered from 0. The rotation of the initiator's signing key that follows dispersal k carries the number k.
- **N**: the agreement's n, the number of seats, the initiator included.
- **T**: the Shamir threshold, which is not the agreement's t.
- **apex**: the hash the initiator signs. It commits to the initiator's signing key, the signing offset, the message hash and the Merkle roots of the dispersal's two codes.
- **part**: one recipient's share or shard. **pool**: the parts an assembler holds under one apex.
- **book**: a seat's record of the initiator's current public key (pub: the signing hash of `MerkleLamportSignature`, MLS).
- **keystate**: a seat's current pairwise mask keys and its retention floor.
- **code points** (geometry: `cmGeometry`, the `geom` fault): sssMk's secret and output code points.
- **signing offset** (slot: `CM_SLOT_ROT`, `CM_SLOT_PAY`, the `slot` arm and faults): which of an MLS context's one-time signings is used.

Each phase is its own program. In order:

1. `distribute` compresses the message, encrypts it, splits it into shards and the key into shares, signs the apex, and writes three messages to each recipient.
2. `receive` validates what one recipient was sent.
3. `exchange` forwards what that recipient validated to every other recipient.
4. `assemble` rebuilds the message from the parts at threshold.

These four only read a seat's keys. The helpers advance them: `ratchet` and `release` move the mask keys, `catchup` brings a stale seat's keys forward, and `offsetgate` records the signing offsets a seat has accepted. `rotate` and `rotverify` change the initiator's signing key, and `chainverify` checks gathered message hashes against the dispersal chain. [`drive.py`](drive.py) plays the operator. It deals the secrets out of band, runs the programs and prints every file they write. The head comment of [`cm.h`](cm.h) lays out the construction and the role of each hash, the head comment of each program says what it does, and `drive.py`'s docstring lists the arms, each a run that shows one property. This file says why.

## The adversary

The agreement library's papers already make the network and the faulty seats one adversary. Bracha's adversary scheduler "tries to prevent agreement by selectively routing messages to processes". Ben-Or's schedule "takes care for the message system" and "determines what the faulty processes do". The security analysis here gives that adversary cryptographic powers: the network, colluding with up to t seats.

- **The network** reads every message, can alter or replace any byte, and can withhold or replay any message.
- **A colluding seat** holds everything it was dealt: its pairwise keys and, if it is the initiator, its signing key. Under those keys it authenticates and signs whatever it likes. As the initiator it can sign two values, encode a message inconsistently, or give some recipients nothing. As a recipient it can forward or withhold its parts, alter them under its own keys, and pass what it learns to the network.

The initiator is also the dealer of the shares and shards. A dealer without ECC memory flips a share or a shard now and then, and from outside that looks exactly like a Byzantine initiator. So every recipe is judged on what an honest recipient can decide from what it was dealt, what it received and what was signed. None of them depends on a part the recipient might never get.

## An authenticated channel

Every message ends in an HMAC under a key the operator dealt to that pair of seats, with the sender and recipient folded in. Each pair has its own key, so a message from one seat cannot be passed off as from another. The fold stops a message from one seat to another being replayed in the other direction under the key the two share. The key mesh is static and separate from the mask keys. Integrity needs no forward secrecy, and a static key lets a seat with stale mask keys still detect tampering. A reader checks the HMAC before it parses anything, and a failure is a wire-tamper verdict. That verdict is kept apart from the verdicts that blame a sender, so altering a message can never make an honest initiator look Byzantine. A message the network moves unaltered to another path between the same two seats, or presents with a part from another dispersal, passes the HMAC, so those verdicts do not by themselves prove a sender at fault.

The HMAC stops the network. It cannot stop a colluding seat, which holds valid keys and can authenticate anything. So every reader treats the bytes after the HMAC check as hostile and refuses whatever field does not parse to its exact form. See `cmHmacAppend` and `cmHmacCheck` in `cm.h`, and the arms `tamper` and `hostile`.

### A copy of a message

The network can present any authentic message it recorded, to the seat it was meant for, any number of times. The copy passes the HMAC, and it must: a seat that sends a message again sends the same bytes, so nothing in a message can say it is a copy. Over a transport with no handshake, the seats share no state a message could be fresh against but what their agreement fixes. Moving the keys forward with the chain does not help, because the most recent messages always pass.

Read through, a copy costs what the first read cost. At `demo 4 2`'s payload that is 580 rmd128 and 520 rmd160 compressions for a recipient's three messages: 173 of the rmd128 for the HMACs, 385 for the signature, 22 for the apex and the proofs, and all of the rmd160 for the code points and mask. The signature, the code points and the mask stay the same at any payload; the shard's HMAC and hash grow with it. A rotation's two messages cost 525 rmd128 compressions, a run message 519. Multiply by what the network chooses to send. A cheap keyed gate ahead of the HMAC sheds bytes no key holder wrote, but a copy passes a gate too.

So the check belongs before all of that, and it cannot live here. Only the seat knows what it holds and what a copy is worth to it, so which copies to refuse is the implementation's. cryptoMule's programs are each one pass over files and refuse nothing before the HMAC. What cryptoMule can say is what keeps a refusal safe:

- **The HMAC cannot say what a copy is worth.** A refusal must not lose what the implementation still has to do on that copy. So the work copies cause is bounded by a budget per record, renewed on the implementation's own schedule, never by the number of copies presented.
- **Before the HMAC, only refuse.** A reader may read anything there. It may refuse, and it may mark the record it hit, but those bytes never admit a message, change what is held, or blame a sender. A forger who names something held gets its own bytes dropped.
- **A name is not an identity.** Refusing on a name alone drops a different value under that name unread, which loses the split below between the same bytes presented again and another apex at a recorded offset. The check has to bind the bytes, unless the reader keeps one value per sender under that name and would record nothing of another. An HMAC field binds the one unit it covers, so the same message packed differently has another HMAC, and a check on the message compares the bytes held. A short gate is not enough, because an honest collision repeats on every send. Nor are signature bytes alone, which do not bind what was signed: a colluding seat can put an honest signature with its own apex. To skip a verification, recompute the apex and find that apex and those signature bytes among pairs verified together.
- **A record lives exactly as long as it is true.** It says these bytes are held, or were refused against named state. When the bytes are let go or the state moves, the record goes, or it refuses the very message that would replace them. Keep records per pair, so a colluding seat evicts only its own. Past a record, a copy pays at least an HMAC and can pay the whole read: the same bytes at the high-water signing offset are accepted again, and that floor is read after the signature.
- **A refused message displaces nothing admitted.** `receive` here replaces its one record on a refusal, so that a stale verdict is not forwarded, and a single altered copy costs that seat its verdict until the message is read again. An implementation must not copy that.

A colluding seat can still make new authentic messages. Each can cost a reader a full read, and more where assembly must search past bad parts, and no check on copies changes that.

A message that fails its HMAC is counted and discarded, and it costs one HMAC. Refusing it leaves nothing to check the next one against, so a copy of it costs that again. The failure is never a verdict on the seat named: a colluding seat can send such a message and so can the network, and it says nothing of which, as above. Nor may it change what comes next under that name. A reader cannot tell a good message from a bad one without the HMAC, so refusing under a name for a failed HMAC would hand that name's silence to anyone who can reach the HMAC. The same goes for every check behind the HMAC: a failure there is counted and discarded too.

## Message attribution

The initiator signs the apex once, with a Merkle-Lamport signature at one of its context's one-time signing offsets. That one signature travels with the apex through distribution and exchange. A recipient that never heard from the initiator can still attribute what another recipient forwards. The HMAC names who handed a message over; the signature names who wrote it.

Every apex starts with the signer's current pub and the signing offset it is signed at. Neither is carried. A reader takes the pub from its book and the offset from the signature, recomputes the apex under both, and requires the signature to extract to that same pub, and both checks must pass. A value is then one kind of message under one key at one offset. It cannot be a dispersal to some seats and a rotation to others, it cannot be presented as signed under another of the initiator's keys, and it cannot be presented as signed at another offset. A rotation's apex is the hash of the signer's pub, the offset and the successor's pub, so no rotation shares an apex with a dispersal. Signing offset 0 of a context is the rotation's and no dispersal's, and every verifier checks the offset the signature yields.

An offset is one-time: two values signed at one offset expose the private data behind it. Each seat records the highest offset it has accepted from the initiator, with the apex it accepted there. The same bytes presented again are the same message and are accepted. Another apex at a recorded offset is refused as a leaked offset. That record has to be a function of the value: seats that accept the same apex must record the same offset, or the next signature is accepted at one and refused at another. That is why the apex commits the offset. One value is one signing at one offset, so whatever seat forwards it, what the value fixes is fixed everywhere it is agreed. An initiator that signs one apex at two offsets reaches no seat with the second copy, because the apex was computed at one offset and the copy at the other does not recompute to it. Rotations change the key in each seat's book, and the book is rooted at the first pub, dealt out of band.

That record, `priv/<p>_floor.txt`, is one of two unrelated things the code calls a floor; the other is the retention floor below. See `cmApex`, `cmApexRot`, `cmMlsOff` and `cmMlsVerify` in `cm.h`, `rotate.c`, `rotverify.c` and `offsetgate.c`, and the arms `signer`, `twoslot`, `slot`, `retry`, `offsets` and `rotchain`.

## Forward secrecy

The network records every masked share it sees. A seat that later becomes one of the t colluding seats gives the network every key it then holds. Forward secrecy is what keeps those keys from opening the recorded past.

The pairwise mask keys step forward once per dispersal, after the dispersal completes, and the old keys are wiped. The four phase programs only read the keys, because a message already sent may still have to be produced again byte for byte. Distribution and exchange are kept apart by two mask domains under the one step.

The ratchet steps on the dispersal chain. Each link is the hash of the previous link and the dispersal's message hash, starting from a genesis dealt to every seat. Two seats that step on different values stop sharing keys without either seeing why, so the chain makes sure the step cannot be an arbitrary value. The sequence is pinned from a base every seat was dealt, and a seat that steps on anything else falls off it. The chain folds the message hash, not the apex, because the application knows its message's hash and can check the chain from its messages alone. The apex also commits to the dispersal's Merkle roots, which only cryptoMule knows. A rotation masks nothing and adds no link.

Each keystate also keeps a retention floor: one base, the key of the oldest dispersal the seat will still produce. The seat walks it forward to re-derive any later dispersal's masks, so a banked distribution can be sent again. The re-sent message is byte-identical to the one it repeats, because it is the same message. One base is better than a key kept per dispersal: it holds less and destroys more. Forward secrecy therefore starts at the retention floor, and `release` moves the floor forward and destroys what it passes. How far back a deployment keeps the floor is its own choice.

The dispersal chain is published in `anchorlog.txt`, without an HMAC. A seat whose keys are older than every retention floor cannot be healed from inside, because nothing any seat retains reaches back that far. It recovers on the public links, so they must be readable from outside. Anyone can verify them by folding from the genesis over the message hashes they hold. Tampering with the log makes good items fail to verify, which is denial, never forgery.

See `ratchet.c`, `release.c`, `catchup.c`, `chainverify.c`, and `cmChain` and `cmFloorLoad` in `cm.h`. The arms are `steps`, `fwdsec`, `resend`, `chain`, `catchup` and `evidence`.

## Censorship resistance

Censorship resistance is the Shamir threshold. The message is encrypted under a fresh key K, and K is split into shares with threshold T. No seat holding fewer than T shares can read the message, so an initiator cannot deliver to some recipients and not others. The deal is refused at T = 1, where every share is the key. A deployment sets T above its t, so the t colluding seats together hold fewer than T shares. The smallest configuration is N = 3, T = 2.

Before exchange, no coalition below T can read, because keys are isolated. Each seat holds only its own row of the pairwise mask keys, so a recipient can unmask only its own share. A recipient the initiator never reached still assembles from the other recipients' exchange messages. All it needs from the initiator is the pub its book already holds.

The mask keys are pairwise in both phases, with no group key. A group key would put every seat on one shared step, and a seat that missed one dispersal would be cut out of every exchange after it. Pairwise keys keep that loss to one pair. They cost one key derivation per recipient and no extra bytes on the wire, because every message names one recipient anyway, and nothing assumes a broadcast medium.

## Dealer consistency

A Byzantine initiator signs its own fraud, so every per-message check passes. The question is whether its encodings match what it signed, and honest recipients must be able to tell from what they received.

- **Code points from a seed.** The Shamir secret and output code points derive from a seed that travels only inside the mask. The seed is bound into every Merkle leaf. A seat below threshold learns nothing about the code points, one received share can be checked against its own seed's points, and malformed points cannot be represented at all.
- **Two parts, judged apart.** The share and the shard are checked, forwarded and gathered on their own proofs. A rotted shard does not cost its holder's share.
- **A search to the signed hash.** An assembler holding T of each part searches T-subsets against the signed message hash, and reads one more part only after a search fails. Shares that agree with an extra held share are tried first. The shard search runs under each candidate key, never as the product of two searches. With an honest initiator, the first T of each part reproduce the signed hash. A try budget bounds an initiator that corrupts most of its parts.
- **A re-encode after PASS.** The assembler rebuilds the canonical ciphertext from the delivered message, re-encodes both codes, and compares them to the signed roots. It names every held part that differs.

There are three verdicts:

- **PASS:** the delivered message hashes to the signed hash.
- **FRAUD:** both parts reached threshold and no subset reproduces that hash.
- **FAIL:** no message and no accusation. This includes a budget spent before the search finished.

An empty message is a message: the huffman encoding of nothing is two bytes. A broken encoding also decodes to nothing, so a try delivers the empty message only when its whole plaintext is zero.

Two things are deliberately left out. A hash of K or of the ciphertext in the signed header would cost wire bytes and buy nothing the search does not. The hash of K would also give a seat below threshold a way to test guesses of K. A self-check by the initiator is left out too, because a check run in the same faulty memory proves nothing; the recipients' search is the check. `receive` cannot do more on its own. Whether a share is consistent is a relation among T + 1 shares, and per-share commitments would need discrete-log assumptions that a quantum computer breaks.

See `distribute.c`, `receive.c`, `exchange.c` and `assemble.c`, and the arms `demo`, `parts`, `byz`, `pools` and `empty`.

## The wire at its minimum

Each recipient gets three messages, each ending in the pair's HMAC:

- the apex alone, the same message to every recipient
- the shard alone, the one large part
- a sign message with everything else: the signed header, the signature, the masked share and both Merkle proofs

The split keeps the small messages separate from the large one. The shard and sign messages carry a tag naming the apex message they belong to. A reader compares the tag to the name of the apex message it holds and never opens what the tag names.

Nothing that can be derived is carried:

- the shard length, which is the shard message's own length, bound by the signed root
- the message length, which the huffman encoding describes
- the ciphertext length
- R (N - 1, the recipients) and the codes' shape, from the deal
- the code points, from the seed
- the chain link, from the fold
- the signer's pub, which the reader's book holds
- the signing offset, which the signature yields

The ciphertext is capped at 64k (`CM_CT_MAX`). The cap is checked from the shard in hand, at `receive` and at `assemble`, so no length is carried for it.

The ciphertext shard travels in the clear. It is already ciphertext, because the message is encrypted before it is split, and masking a shard after the Reed-Solomon encode would leak the keystream through the parity rows. See the field list in `drive.py`'s docstring and the arm `limit`.

## What it never does

cryptoMule detects and refuses at one seat, from the bytes that seat received. It never decides among artifacts that each verify: which of two signed apexes stands, which successor is the initiator's, or which seat is faulty. Those are the agreement's. When two valid apexes arrive, `assemble` pools and reports each one.

## Why a disk, and why a reference design

Files on disk stand in for the wire. A round trip can then be proven without a transport, and the network adversary is anyone who changes a file outside `priv/` between phases. Each file shows its message's fields readably, HMAC included, and none of them is the bytes a transport sends.

What carries over to an implementation is the construction: the order in which the primitives are called and what each check requires. The code does not carry over. The text-field format, the separate `main`s, the keys read from files, `drive.py`'s orchestration and the concrete parameters are all scaffolding. No implementation links cryptoMule or includes `cm.h`. Each calls the primitives itself, in the order these programs show.

## Try it

```
make
python3 drive.py demo 4 2
python3 drive.py
make reset
make clean
```

`make` builds the programs against the repositories the [`Makefile`](Makefile) names, `rmd128`, `rmd160`, `ShamirSecretSharing`, `ReedSolomonErasureCoding`, `canonicalHuffman` and `MerkleLamportSignature`, each cloned beside agreementChain, as its README lists; an object of theirs not yet built it builds from that repository's source. The driver needs python3. `demo 4 2` deals four seats at threshold two and runs one dispersal through, and each of the three recipients reports PASS. `python3 drive.py` with no arguments prints the docstring, which is the usage and every arm. `make reset` clears the run state (`anchorlog.txt`, `priv/`, `wire/`, `drive/`), and `make clean` does that and removes the programs.

## License

cryptoMule is GPLv3, a program and not a library ([`../COPYING`](../COPYING)); see the head of each file.
