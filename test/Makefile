TGT_NAME = UnitTests
TGT_TYPE = library 
OUT = $(D_OUT)/$(TGT_NAME).dll
TOP_MAKEFILE = $(TOP)/Makefile
MAKEFILE = Makefile

DEPS = $(TOP_MAKEFILE) $(MAKEFILE)

all: build
build: $(OUT)

NUNIT_FLAGS = -nologo -noshadow -labels

uname_S := $(shell sh -c 'uname -s 2>/dev/null || echo not')

ifeq ($(uname_S),Darwin)
NUNIT = nunit-console2 $(NUNIT_FLAGS)
NUNIT_PKG = -pkg:mono-nunit
export PKG_CONFIG_PATH = /Library/Frameworks/Mono.framework/Libraries/pkgconfig/
endif
ifeq ($(uname_S),Linux)
NUNIT = LD_LIBRARY_PATH=. nunit-console $(NUNIT_FLAGS)
NUNIT_PKG = -pkg:nunit
endif

SRCS = \
	Properties/AssemblyInfo.cs \
	TestBase.cs \
	TestAES.cs \
	TestCryptoKey.cs \
	TestX509Certificate.cs \
	SourceForgeBugs.cs

REFS = \
	-r:ManagedOpenSsl.dll \
	$(NUNIT_PKG)

$(OUT) : $(SRCS) $(DEPS)
	$(CSC) $(CSFLAGS) -t:$(TGT_TYPE) -lib:$(LIBPATH) $(REFS) -out:$@ $(SRCS)

test: $(OUT)
	( cd $(D_OUT) && $(NUNIT) $(TGT_NAME).dll );

clean:
	rm -f $(D_OUT)/$(TGT_NAME).*
	rm -f $(D_OUT)/TestResult.xml

