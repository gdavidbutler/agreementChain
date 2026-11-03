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

all: ac.o ac

clean:
	rm -f ac.o acTest.o rsecFrm.o halfsiphash.o

clobber: clean
	rm -f ac acTest rsecFrmTest

# the library: one seat
ac.o: ac.c ac.h acTest.h rsecFrm.h halfsiphash.h $(ABAP)/bracha87Fig1.h $(ABAP)/bkr94acs.h
	$(CC) $(CFLAGS) $(LIBINC) -c ac.c

# the example: an operator launching N seats as processes
ac: example/ac.c ac.h ac.o $(SEATOBJ) $(EXOBJ)
	$(CC) $(CFLAGS) $(EXINC) -o ac example/ac.c ac.o $(SEATOBJ) $(EXOBJ)

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
# a seat cut past the others' machines, carried back by their recover legs and DISCOVER
	./acTest -W 2500000 -r 950 -x 90 -n 4 -A 64 4 1
# a seat healed on ingress first, completing on the others' re-sends alone
	./acTest -W 2500000 -r 950 -x 80 -X 100 -n 2 -A 64 4 1
# a seat with nothing to say, moved only by the others' rows under names it has not minted
	./acTest -W 2500000 -r 950 -i -n 8 -A 22 -Z 0:8 -y 4 -x 60 4 1
# a seat frozen as a stopped process, with a small host's socket buffer
	./acTest -W 2500000 -r 950 -y 0 -Q 5 -G 42080 -A 22 -n 16 4 1
# the frozen seat at seven seats
	./acTest -W 2857142 -r 3530 -y 0 -Q 6 -G 42080 -n 18 7 1
# a retention small enough to wrap under loss
	./acTest -W 2500000 -D 10 -n 30 -A 45 -M 250000 4 1
# a seat recovering across the retention's wrap
	./acTest -W 2500000 -D 10 -x 320 -n 30 -A 152 -M 250000 4 1
# a seat cut past the retention itself: partitioned, read from the reports
	./acTest -W 2500000 -r 950 -x 250 -n 18 -A 22 -M 234743 -u 2000 -c 400 4 1
# loss in bursts
	./acTest -W 2500000 -D 5 -B 200 -n 10 4 1
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
# a seat dead for the whole run at seven seats
	./acTest -W 1428571 -r 2000 -x 999 -A 16 -c 100 -n 2 7 1
# directed links at three seats, t = 0: dark, one-way links, dark again, a pair both ways, then every link
	./acTest -W 2500000 -r 428 -A 281 -n 6 -T '0=/10000=01/20000=0212/30000=/40000=0110/50000=0221/60000=*' 3 0
# directed links at four seats: dark, one-way links, dark again, a pair both ways, then every link
	./acTest -W 2500000 -r 950 -A 127 -n 6 -T '0=/10000=01/20000=0123/30000=/40000=0110/50000=01100221/60000=*' 4 1
# three seats that hear each other, the fourth dark, then hearing and not heard, then heard
	./acTest -W 2500000 -r 950 -A 22 -n 10 -T '0=010210122021/90000=010210122021031323/130000=*' 4 1
# a Byzantine row sender saying HOLDING of nothing
	./acTest -W 2500000 -b 1 -A 74 -n 10 4 1
# a payload signed at its first payload's slot
	./acTest -W 2500000 -f 11 -n 6 4 1
# a salted dealer whose accomplice forwards its part to one seat alone: one outcome at every seat
	./acTest -W 2857142 -f 5 -a -n 4 7 2
# a dealer whose shares are bad but the last T, at thirteen seats, where its search's try budget may be spent
	./acTest -W 2500000 -f 5 -n 2 13 4
# the end called by t seats alone: no end
	./acTest -W 2500000 -E 1 -n 2 4 1
# the end called at a different link by every seat: one end, one final hash
	./acTest -W 2500000 -e 1 -n 2 4 1
# a seat cut across the ending link, recovering it
	./acTest -W 2500000 -y 24 -x 40 -n 2 4 1
# a seat dead for a whole chain, back in the next, dealt afresh from its final hash
	./acTest -W 2500000 -x 999 -c 300 -n 2 -R 4 1
