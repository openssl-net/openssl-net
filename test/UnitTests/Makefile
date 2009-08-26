TGT_NAME = UnitTests
TGT_TYPE = library 
OUT = $(D_OUT)/$(TGT_NAME).dll
TOP_MAKEFILE = $(TOP)/Makefile
MAKEFILE = Makefile

DEPS = $(TOP_MAKEFILE) $(MAKEFILE)

all: build
build: $(OUT)

NUNIT_FLAGS = -nologo -noshadow

uname_S := $(shell sh -c 'uname -s 2>/dev/null || echo not')

ifeq ($(uname_S),Darwin)
NUNIT = nunit-console2 $(NUNIT_FLAGS)
endif
ifeq ($(uname_S),Linux)
NUNIT = LD_LIBRARY_PATH=$(D_OUT) nunit-console $(NUNIT_FLAGS)
endif

SRCS = \
	Properties/AssemblyInfo.cs \
	BaseTest.cs \
	CryptoKeyTest.cs \
	X509CertificateTest.cs

REFS = \
	-r:ManagedOpenSsl.dll \
	-pkg:mono-nunit

$(OUT) : $(SRCS) $(DEPS)
	$(CSC) $(CSFLAGS) -t:$(TGT_TYPE) -lib:$(LIBPATH) $(REFS) -out:$@ $(SRCS)

test: $(OUT)
	( cd $(D_OUT) && $(NUNIT) $(OUT) );

clean:
	rm -f $(D_OUT)/$(TGT_NAME).*
	rm -f $(D_OUT)/TestResult.xml

