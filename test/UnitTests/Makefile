D_BIN = ../../bin/Debug
D_OBJ = obj

SRCS = \
	Properties/AssemblyInfo.cs \
	X509CertificateTest.cs

REFS = \
	-r:ManagedOpenSsl.dll \
	-r:nunit.framework.dll

$(D_BIN)/UnitTests.dll : $(SRCS)
	gmcs -debug -t:library -lib:$(D_BIN) $(REFS) -out:$(D_BIN)/UnitTests.dll $(SRCS)
