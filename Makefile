.PHONY : all build test clean

export TOP = $(CURDIR)
export D_OUT = $(TOP)/bin/Debug

export CSC = gmcs
export CSFLAGS = -debug -warn:2 -warnaserror

D_NUNIT = $(TOP)/nunit-2.5.1
export D_NUNIT_LIB = $(D_NUNIT)/framework

export LIBPATH = $(D_OUT),$(D_NUNIT_LIB)

export MONO = mono
NUNIT_EXE = $(D_NUNIT)/nunit-console.exe
export NUNIT = $(MONO) $(NUNIT_EXE) -nologo -noshadow

MAKE_DIR = $(MAKE) -C 

LIB_DIR = ManagedOpenSsl
TEST_DIR = test/UnitTests

all: build

lib: 
	$(MAKE_DIR) $(LIB_DIR)

build: lib build_test 

build_test:
	$(MAKE_DIR) $(TEST_DIR)

test: lib build_test 
	$(MAKE_DIR) $(TEST_DIR) test

clean: clean_lib clean_test

clean_lib:
	$(MAKE_DIR) $(LIB_DIR) clean

clean_test:
	$(MAKE_DIR) $(TEST_DIR) clean

install:
	echo install

pkg:
	echo pkg

dist:
	echo disto

publish:
	echo publish

release:
	echo release
