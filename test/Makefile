TGT_NAME = test
TGT_TYPE = exe
OUT = $(D_OUT)/$(TGT_NAME).exe

MAKE_DIR = $(MAKE) -C 

all: build unit
build: $(OUT)

SRCS = \
	Properties/AssemblyInfo.cs \
	Program.cs \
	TestAES.cs \
	TestDH.cs \
	TestDSA.cs \
	TestHMAC.cs \
	TestRandom.cs \
	TestRSA.cs \
	TestServer.cs \
	TestSHA.cs \
	TestSHA1.cs \
	TestSHA256.cs \
	TestSHA512.cs \
	TestX509.cs

REFS = \
	-r:ManagedOpenSsl.dll

$(OUT) : $(SRCS) $(DEPS)
	$(CSC) $(CSFLAGS) -t:$(TGT_TYPE) -lib:$(LIBPATH) $(REFS) -out:$@ $(SRCS)

unit:
	$(MAKE_DIR) UnitTests

test: unit
	$(MAKE_DIR) UnitTests test

clean: clean_unit
	rm -f $(D_OUT)/$(TGT_NAME).*

clean_unit:
	$(MAKE_DIR) UnitTests clean
	