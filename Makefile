CFLAGS = -I. -Os -g
# the sibling repositories, each cloned beside this one; an object of
# theirs not yet built is made from its source by make's built-in rule
ABAP = ../asynchronousByzantineAgreementProtocols
RSEC = ../ReedSolomonErasureCoding
SSS = ../ShamirSecretSharing
MLS = ../MerkleLamportSignature
HUF = ../canonicalHuffman
RMD128 = ../rmd128
RMD160 = ../rmd160
SHA256 = ../sha256
SHA3 = ../sha3
# the library binds the agreement and the primitives its recipes call
LIBINC = -I$(ABAP) -I$(RSEC) -I$(SSS) -I$(MLS) -I$(HUF)
SEATOBJ = rsecFrm.o halfsiphash.o $(ABAP)/bkr94acs.o $(ABAP)/bracha87Fig1.o $(RSEC)/rsec.o $(RSEC)/rsecMk.o $(SSS)/sss.o $(SSS)/sssMk.o $(MLS)/mls.o $(HUF)/huf.o
# a caller deals it the hash suites: the example two, the harness five
EXINC = -I$(RMD128) -I$(RMD160)
EXOBJ = $(RMD128)/rmd128.o $(RMD160)/rmd160.o
TESTINC = $(EXINC) -I$(SHA256) -I$(SHA3)
TESTOBJ = $(EXOBJ) $(SHA256)/sha256.o $(SHA3)/sha3256.o $(SHA3)/sha3512.o

all: ac.o acUDP acTCP

clean:
	rm -f ac.o acTest.o rsecFrm.o halfsiphash.o

clobber: clean
	rm -f acUDP acTCP acTest rsecFrmTest

# the library: one seat
ac.o: ac.c ac.h acTest.h rsecFrm.h halfsiphash.h $(ABAP)/bracha87Fig1.h $(ABAP)/bkr94acs.h
	$(CC) $(CFLAGS) $(LIBINC) -c ac.c

# the examples: an operator launching N seats as processes, over UDP and over TCP
acUDP: example/acUDP.c ac.h ac.o $(SEATOBJ) $(EXOBJ)
	$(CC) $(CFLAGS) $(EXINC) -o acUDP example/acUDP.c ac.o $(SEATOBJ) $(EXOBJ)

acTCP: example/acTCP.c ac.h halfsiphash.h ac.o $(SEATOBJ) $(EXOBJ)
	$(CC) $(CFLAGS) $(EXINC) -o acTCP example/acTCP.c ac.o $(SEATOBJ) $(EXOBJ)

rsecFrm.o: rsecFrm.c rsecFrm.h $(RSEC)/rsec.h
	$(CC) $(CFLAGS) -I$(RSEC) -c rsecFrm.c

halfsiphash.o: halfsiphash.c halfsiphash.h
	$(CC) $(CFLAGS) -c halfsiphash.c

rsecFrmTest: test/rsecFrmTest.c rsecFrm.h rsecFrm.o halfsiphash.h halfsiphash.o $(RSEC)/rsec.h $(RSEC)/rsec.o
	$(CC) $(CFLAGS) -I$(RSEC) -o rsecFrmTest test/rsecFrmTest.c rsecFrm.o halfsiphash.o $(RSEC)/rsec.o

# the library with its test hooks, and the harness bound to it
acTest.o: ac.c ac.h acTest.h rsecFrm.h halfsiphash.h $(ABAP)/bracha87Fig1.h $(ABAP)/bkr94acs.h
	$(CC) $(CFLAGS) $(LIBINC) -DAC_TEST -c -o acTest.o ac.c

acTest: test/ac.c ac.h acTest.h acTest.o $(SEATOBJ) $(TESTOBJ)
	$(CC) $(CFLAGS) $(LIBINC) $(TESTINC) -DAC_TEST -o acTest test/ac.c acTest.o $(SEATOBJ) $(TESTOBJ) -lpthread

check: rsecFrmTest acTest
# the datagram framer's own test
	./rsecFrmTest
# four seats, t = 1: every seat's rotation, then the end
	./acTest -W 2500000 4 1
# ten positions and the end: seven messages a seat, the rotations its signing context is due between them
	./acTest -W 2500000 -n 10 4 1
# the smallest signing context: a rotation every other slot, switching contexts
	./acTest -W 2500000 -n 6 -s 1 4 1
# no loss at a tick longer than every round trip
	./acTest -W 2500000 -r 950 -n 10 4 1
# the laggard: its proposals held back past patience, presented again or let go
	./acTest -W 2500000 -z 22 -n 10 4 1
# the laggard across switches of signing context
	./acTest -W 2500000 -z 22 -s 1 -n 12 4 1
# a seat that proposes nothing, its positions launched on the others' rows
	./acTest -W 2500000 -i -n 6 4 1
# a seat cut off and carried back by the live machines' re-sends
	./acTest -W 2500000 -x 40 -n 2 -A 1200 4 1
# a seat with nothing to say, moved only by the others' rows under names it has not minted
	./acTest -W 2500000 -r 950 -i -n 8 -A 22 -Z 0:8 -y 4 -x 60 4 1
# a retention small enough to wrap under loss, at -F 508 so its parts
# span shards enough to carry parity
	./acTest -W 2500000 -D 10 -n 30 -A 45 -M 250000 -F 508 4 1
# loss in bursts, at -F 508 so a burst leaves trains part arrived
	./acTest -W 2500000 -D 5 -B 200 -F 508 -n 10 4 1
# the whole network dark from the go
	./acTest -W 2500000 -Y -x 12 4 1
# the whole network dark from the first tick after the go
	./acTest -W 2500000 -Y -y 1 -x 12 -n 10 4 1
# the whole network dark past the abandon: agreements outlast their count
	./acTest -W 2500000 -Y -y 0 -x 100 -A 22 -n 3 4 1
# one seat dark past the abandon while the others go on
	./acTest -W 2500000 -y 0 -x 100 -A 22 -n 6 4 1
# a dealer that sends one seat nothing of its own, the exchange toward that seat dark
	./acTest -W 2500000 -C -U 40 -n 2 -A 1200 4 1
# one seat's exchange dark past the abandon: what it was not dealt comes by the others' legs
	./acTest -W 2500000 -U 200 -n 3 -A 64 4 1
# a Byzantine row sender saying HOLDING of nothing
	./acTest -W 2500000 -b 1 -A 74 -n 10 4 1
# a seat's agreement rows under random names: held at the others to the abandon's count of a shape, the rest not
	./acTest -W 2500000 -b 2 -n 10 4 1
# a Byzantine seat's own INITIAL under position 1's name: an initial of another value than the one held, refused
	./acTest -W 2500000 -b 4 -n 4 4 1
# the sign parts it forwards a byte off: refused at the signature
	./acTest -W 2500000 -b 8 -n 4 4 1
# the data parts it forwards a byte off: refused at the rsecMk leaf
	./acTest -W 2500000 -b 16 -n 4 4 1
# the parts it forwards a byte short: refused at the length
	./acTest -W 2500000 -b 32 -n 4 4 1
# its description a byte off, beside its recover legs to a returner, the one seat that asks for one: refused
	./acTest -W 2857142 -b 64 -2 -x 60 -n 4 -A 22 7 2
# a unit landing under a seat's word that it was owed nothing: the word lapses, and that unit brings the returner to threshold
	./acTest -W 2500000 -u 60000 -n 3 -A 60 -o 480 6 1
# a payload signed at its first payload's slot, the dealer in the subsets of the first two by the hold:
# refused unverified where its value is held, past a signature at seat 0, sent no value of it
	./acTest -W 2500000 -f 11 -6 2 -n 6 4 1
# and a recording of it: each copy refused unproved, and a part again from its offset and a hash where its value is held
	./acTest -W 2500000 -f 11 -J 4 -6 2 -n 6 4 1
# its third payload at its first payload's slot, below the second's, the dealer in the subsets of the first three by the hold:
# refused the same way
	./acTest -W 2500000 -f 12 -6 3 -n 6 4 1
# a salted dealer whose accomplice forwards its part to one seat alone: one outcome at every seat
	./acTest -W 2857142 -f 5 -a -n 4 7 2
# a dealer whose shares are bad but the last T, at thirteen seats, where its search's try budget may be spent:
# seats 0..t-1 hold their own INITIALs to their folds of positions 1 and 2, so the dealer is in those subsets
	./acTest -W 2500000 -f 5 -6 2 -n 2 13 4
# a dealer's shard not a codeword: its proof verifies, only the re-encode at threshold tells, no message
	./acTest -W 2500000 -f 1 -n 6 4 1
# a dealer's share a bit off: no message, its commitment inconsistent
	./acTest -W 2500000 -f 2 -n 6 4 1
# a dealer's leaves bound to each other's points: its units refused at receive, at the sssMk leaf
	./acTest -W 2500000 -f 3 -n 6 4 1
# a dealer's padding byte flipped after the parity: the re-encode differs, no message
	./acTest -W 2500000 -f 6 -n 6 4 1
# a dealer's shard of one leaf and share of another: T good shares need not be T good shards, no message
	./acTest -W 2500000 -f 9 -n 6 4 1
# a two-faced dealer: its apex in a rotation's shape refused at seat 0, the message from the legs
	./acTest -W 2500000 -f 7 -n 3 4 1
# a split dealer: its apex signed by its successor refused at seat 0, the message from the legs
	./acTest -W 2500000 -f 8 -n 3 4 1
# a dealer signing one apex at two slots: the second refused at seat 0, the message from the legs
	./acTest -W 2500000 -f 10 -n 3 4 1
# the end called by t seats alone: no end
	./acTest -W 2500000 -E 1 -n 2 4 1
# the end called at a different link by every seat: one end, one final hash
	./acTest -W 2500000 -e 1 -n 2 4 1
# a seat cut across the ending link, recovering it
	./acTest -W 2500000 -y 24 -x 40 -n 2 4 1
# a seat dead for a whole chain, back in the next, dealt afresh from its final hash
	./acTest -W 2500000 -x 999 -c 300 -n 2 -R 4 1
# the network's copies of every datagram: refused unread, an HMAC for what was said and none for the copies
	./acTest -W 2500000 -J 4 -n 4 4 1
# the network's recording of older traffic played back, under names live and retained: no HMAC and no recover leg for it
	./acTest -W 2500000 -I 2 -n 12 -A 22 4 1
# the same on a chain idling at a folded head, where nothing names past it and only a seat's own HOLDING says it is owed nothing
	./acTest -W 2500000 -I 2 -i -Z 40:300 -n 8 -A 22 4 1
# a returner under a recording of recover legs' INITIALs, which no tag refuses: the copies hold no position past its fold and let-go, so it ends
	./acTest -W 2500000 -I 64 -h -x 120 -n 8 -A 22 4 1
# a faulty dealer's consistent wrong bytes reach a seat at threshold under its record, and the rest are never dealt: an abandon on, its last pass, and it launches
	./acTest -W 2500000 -f 4 -N 60 -n 3 -A 22 4 1
# a seat with every word on its own broadcasts heard and nothing to fold on owes no re-send: it says its value again at its abandon, and the others' recover legs carry it
	./acTest -W 2500000 -3 60 -n 14 -A 22 4 1
# a seat that folded with no unit to carry is a returner's second description: it says it alone, with no leg, whenever that seat asks
	./acTest -W 2500000 -4 100 -n 12 -A 22 4 1
# a dealer past a position, still re-sending its unit, reaches a seat whose machines of it are gone: the record takes it, and only that brings a seat a member short to T
	./acTest -W 2500000 -5 -n 3 -A 60 -u 60000 6 1
# a seat holding the gate's key whose every proof fails: each a counted discard
	./acTest -W 2500000 -b 128 -n 4 4 1
# a seat that hears no agreement holds every unit and still lacks the description: it is carried
	./acTest -W 2500000 -q 90 -n 6 -A 22 4 1
# a member reaches two seats and misses a third, stops while they go on, and returns: its unit, late, in that seat's record
	./acTest -W 2500000 -r 950 -A 22 -n 10 -j -T '0=0102031012132021233132/3000=010210122021/60000=*' 4 1
# what the framer would refuse from a tag, asked and not obeyed: nothing of it moves a seat
	./acTest -W 2500000 -l -I 2 -n 12 -A 22 4 1
	./acTest -W 2500000 -l -q 90 -n 6 -A 22 4 1

# the long arms, each waiting out patience and abandons many times over on
# the loopback, then ones that pin defects fixed here
check_abandon: acTest
# a seat cut past the others' machines, carried back by their recover legs and DISCOVER
	./acTest -W 2500000 -r 950 -x 90 -n 4 -A 64 4 1
# a seat healed on ingress first, completing on the others' re-sends alone
	./acTest -W 2500000 -r 950 -x 80 -X 100 -n 2 -A 64 4 1
# a seat frozen as a stopped process, with a small host's socket buffer
	./acTest -W 2500000 -r 950 -y 0 -Q 5 -G 42080 -A 22 -n 16 4 1
# the frozen seat at seven seats
	./acTest -W 2857142 -r 3530 -y 0 -Q 6 -G 42080 -n 18 7 1
# a seat recovering across the retention's wrap, at -F 508 as above
	./acTest -W 2500000 -D 10 -x 320 -n 30 -A 152 -M 250000 -F 508 4 1
# a seat cut past the retention itself: partitioned, read from the reports
	./acTest -W 2500000 -r 950 -x 250 -n 18 -A 22 -M 234743 -u 2000 -c 400 4 1
# a seat dead for the whole run at seven seats
	./acTest -W 1428571 -r 2000 -x 999 -A 16 -c 100 -n 2 7 1
# directed links at three seats, t = 0: dark, one-way links, dark again, a pair both ways, then every link
	./acTest -W 2500000 -r 428 -A 281 -n 6 -T '0=/10000=01/20000=0212/30000=/40000=0110/50000=0221/60000=*' 3 0
# directed links at four seats: dark, one-way links, dark again, a pair both ways, then every link
	./acTest -W 2500000 -r 950 -A 127 -n 6 -T '0=/10000=01/20000=0123/30000=/40000=0110/50000=01100221/60000=*' 4 1
# three seats that hear each other, the fourth dark, then hearing and not heard, then heard
	./acTest -W 2500000 -r 950 -A 22 -n 10 -T '0=010210122021/90000=010210122021031323/130000=*' 4 1
# a seat cut past the others' machines over a longer chain
	./acTest -W 2500000 -r 950 -x 90 -n 10 -A 43 4 1
# a member's own shard landing after its position left the live window, at a one-record retention
	./acTest -W 2500000 -u 60000 -U 200 -V -n 6 -A 64 -M 214410 4 1
# this seat's memory refusing a member's search, the member kept with the record
	./acTest -W 2500000 -O s:2 -n 6 4 1
# the memory refused at the search's pool, the shard landing late
	./acTest -W 2500000 -u 60000 -U 200 -V -O p:2 -n 6 -A 64 4 1
# and at the longer datagram, the senders done sooner: the last link's rows held ahead carry it
	./acTest -W 2500000 -u 60000 -U 200 -V -O p:2 -n 6 -A 64 -F 4096 4 1
# the end at a seat whose memory refused a member of the last link
	./acTest -W 2500000 -e 1 -O s:2 -n 2 4 1
