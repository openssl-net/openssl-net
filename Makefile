.PHONY : all build test clean

SUBDIRS = \
	ManagedOpenSsl \
	cli \
	sandbox \
	test

.PHONY : $(SUBDIRS)

all : build test

build : 
	echo build

test : 
	echo test

clean :
	echo clean

cli : ManagedOpenSsl

sandbox : ManagedOpenSsl

test : ManagedOpenSsl

$(SUBDIRS):
	$(MAKE) -C $@
