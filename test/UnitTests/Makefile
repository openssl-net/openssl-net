TGT_NAME = UnitTests
TGT_TYPE = library 
OUT = $(D_OUT)/$(TGT_NAME).dll
TOP_MAKEFILE = $(TOP)/Makefile
MAKEFILE = Makefile

DEPS = $(TOP_MAKEFILE) $(MAKEFILE)

all: build
build: $(OUT)

SRCS = \
	Properties/AssemblyInfo.cs \
	X509CertificateTest.cs

REFS = \
	-r:ManagedOpenSsl.dll \
	-r:nunit.framework.dll

$(OUT) : $(SRCS) $(DEPS)
	$(CSC) $(CSFLAGS) -t:$(TGT_TYPE) -lib:$(LIBPATH) $(REFS) -out:$@ $(SRCS)

test: $(OUT)
	( cd $(D_OUT) && $(NUNIT) $(OUT) );

clean:
	rm -f $(D_OUT)/$(TGT_NAME).*
	rm -f $(D_OUT)/TestResult.xml

