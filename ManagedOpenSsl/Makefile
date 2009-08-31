TGT_NAME = ManagedOpenSsl
TGT_TYPE = library 
OUT = $(D_OUT)/$(TGT_NAME).dll
TOP_MAKEFILE = $(TOP)/Makefile
MAKEFILE = Makefile
OUT_CFG = $(D_OUT)/$(TGT_NAME).dll.config
OUT_DOC = $(D_OUT)/$(TGT_NAME).XML
APP_CFG = App.config

uname_S := $(shell sh -c 'uname -s 2>/dev/null || echo not')
uname_M := $(shell sh -c 'uname -m 2>/dev/null || echo not')

ifeq ($(uname_S),Darwin)
D_OSX = $(TOP)/native/osx
SRC_LIBCRYPTO = $(D_OSX)/libcrypto.0.9.8.dylib
SRC_LIBSSL = $(D_OSX)/libssl.0.9.8.dylib
LIBCRYPTO = $(D_OUT)/libcrypto.dylib
LIBSSL = $(D_OUT)/libssl.dylib
endif
ifeq ($(uname_S),Linux)
D_LINUX = $(TOP)/native/linux/$(uname_M)
SRC_LIBCRYPTO = $(D_LINUX)/libcrypto.so.0.9.8
SRC_LIBSSL = $(D_LINUX)/libssl.so.0.9.8
LIBCRYPTO = $(D_OUT)/libcrypto.so
LIBSSL = $(D_OUT)/libssl.so
endif

DEPS = $(TOP_MAKEFILE) $(MAKEFILE) 

.PHONY: all 
all: build

.PHONY: build
build: $(OUT)

SRCS = \
	Properties/AssemblyInfo.cs \
	\
	Core/Asn1DateTime.cs \
	Core/Asn1Integer.cs \
	Core/Asn1String.cs \
	Core/Base.cs \
	Core/BigNum.cs \
	Core/BIO.cs \
	Core/Crypto.cs \
	Core/MemoryTracker.cs \
	Core/Native.cs \
	Core/OpenSslException.cs \
	Core/Password.cs \
	Core/Random.cs \
	Core/Stack.cs \
	Core/Version.cs \
	\
	Crypto/Cipher.cs \
	Crypto/CryptoKey.cs \
	Crypto/DH.cs \
	Crypto/DSA.cs \
	Crypto/HMAC.cs \
	Crypto/MessageDigest.cs \
	Crypto/RSA.cs \
	\
	X509/Configuration.cs \
	X509/Identity.cs \
	X509/PKCS7.cs \
	X509/PKCS12.cs \
	X509/X509Certificate.cs \
	X509/X509CertificateAuthority.cs \
	X509/X509CertificateInfo.cs \
	X509/X509Chain.cs \
	X509/X509Extension.cs \
	X509/X509Name.cs \
	X509/X509Object.cs \
	X509/X509Request.cs \
	X509/X509Store.cs \
	X509/X509StoreContext.cs \
	\
	Enums.cs \
	Ssl.cs \
	SslCipher.cs \
	SslContext.cs \
	SslMethod.cs \
	SslStream.cs \
	SslStreamBase.cs \
	SslStreamClient.cs \
	SslStreamServer.cs \
	VerifyResult.cs

REFS = 

$(OUT) : $(SRCS) $(DEPS) $(OUT_CFG) $(LIBCRYPTO) $(LIBSSL)
	$(CSC) $(CSFLAGS) -t:$(TGT_TYPE) -lib:$(LIBPATH) $(REFS) -out:$(OUT) -doc:$(OUT_DOC) $(SRCS)

$(OUT_CFG) : $(APP_CFG)
	cp $(APP_CFG) $(OUT_CFG)

$(LIBCRYPTO) : $(SRC_LIBCRYPTO)
	ln -s $(SRC_LIBCRYPTO) $(LIBCRYPTO) 

$(LIBSSL) : $(SRC_LIBSSL)
	ln -s $(SRC_LIBSSL) $(LIBSSL) 

.PHONY: clean
clean:
	rm -f $(D_OUT)/$(TGT_NAME).*
	rm -f $(LIBCRYPTO)
	rm -f $(LIBSSL)

