CFLAGS=-std=c89 -pedantic -Wall -Wextra -I. \
 -I../../rmd128 -I../../rmd160 -I../../ShamirSecretSharing \
 -I../../ReedSolomonErasureCoding -I../../canonicalHuffman \
 -I../../MerkleLamportSignature -Os -g

OBJS=../../rmd128/rmd128.o ../../rmd160/rmd160.o \
 ../../ShamirSecretSharing/sss.o ../../ShamirSecretSharing/sssMk.o \
 ../../ReedSolomonErasureCoding/rsec.o ../../ReedSolomonErasureCoding/rsecMk.o \
 ../../canonicalHuffman/huf.o ../../MerkleLamportSignature/mls.o

PROGS=distribute receive exchange assemble mlspub rotate rotverify ratchet \
 release offsetrun offsetgate cmprsz catchup cmapex cmhmac cmchain chainverify

all: $(PROGS)

distribute: distribute.c cm.o $(OBJS)
	$(CC) $(CFLAGS) -o distribute distribute.c cm.o $(OBJS)

receive: receive.c cm.o $(OBJS)
	$(CC) $(CFLAGS) -o receive receive.c cm.o $(OBJS)

exchange: exchange.c cm.o $(OBJS)
	$(CC) $(CFLAGS) -o exchange exchange.c cm.o $(OBJS)

assemble: assemble.c cm.o $(OBJS)
	$(CC) $(CFLAGS) -o assemble assemble.c cm.o $(OBJS)

release: release.c cm.o $(OBJS)
	$(CC) $(CFLAGS) -o release release.c cm.o $(OBJS)

cmchain: cmchain.c cm.o $(OBJS)
	$(CC) $(CFLAGS) -o cmchain cmchain.c cm.o $(OBJS)

chainverify: chainverify.c cm.o $(OBJS)
	$(CC) $(CFLAGS) -o chainverify chainverify.c cm.o $(OBJS)

mlspub: mlspub.c cm.o $(OBJS)
	$(CC) $(CFLAGS) -o mlspub mlspub.c cm.o $(OBJS)

rotate: rotate.c cm.o $(OBJS)
	$(CC) $(CFLAGS) -o rotate rotate.c cm.o $(OBJS)

rotverify: rotverify.c cm.o $(OBJS)
	$(CC) $(CFLAGS) -o rotverify rotverify.c cm.o $(OBJS)

ratchet: ratchet.c cm.o $(OBJS)
	$(CC) $(CFLAGS) -o ratchet ratchet.c cm.o $(OBJS)

offsetrun: offsetrun.c cm.o $(OBJS)
	$(CC) $(CFLAGS) -o offsetrun offsetrun.c cm.o $(OBJS)

offsetgate: offsetgate.c cm.o $(OBJS)
	$(CC) $(CFLAGS) -o offsetgate offsetgate.c cm.o $(OBJS)

cmprsz: cmprsz.c cm.o $(OBJS)
	$(CC) $(CFLAGS) -o cmprsz cmprsz.c cm.o $(OBJS)

catchup: catchup.c cm.o $(OBJS)
	$(CC) $(CFLAGS) -o catchup catchup.c cm.o $(OBJS)

cmapex: cmapex.c cm.o $(OBJS)
	$(CC) $(CFLAGS) -o cmapex cmapex.c cm.o $(OBJS)

cmhmac: cmhmac.c cm.o $(OBJS)
	$(CC) $(CFLAGS) -o cmhmac cmhmac.c cm.o $(OBJS)

cm.o: cm.c cm.h
	$(CC) $(CFLAGS) -c cm.c

reset:
	rm -f anchorlog.txt
	rm -rf priv wire drive

clean: reset
	rm -rf cm.o $(PROGS)
