TGT_NAME = openssl+
TGT_TYPE = exe 
OUT = $(D_OUT)/$(TGT_NAME).exe

all: build
build: $(OUT)

SRCS = \
	Properties/AssemblyInfo.cs \
	CmdCipher.cs \
	CmdDH.cs \
	CmdDigest.cs \
	CmdGenDH.cs \
	CmdGenRSA.cs \
	CmdRSA.cs \
	CmdVersion.cs \
	OptionParser.cs \
	Program.cs

REFS = \
	-r:ManagedOpenSsl.dll

$(OUT) : $(SRCS) $(DEPS)
	$(CSC) $(CSFLAGS) -t:$(TGT_TYPE) -lib:$(LIBPATH) $(REFS) -out:$@ $(SRCS)

clean:
	rm -f $(D_OUT)/$(TGT_NAME).*
