## OpenSSL.NET - README

### Description

A managed OpenSSL wrapper written in C# for the 2.0 .NET Framework that exposes both the Crypto API and the SSL API.

This a must for .NET developers that need crypto but don't want to use Microsoft's SSPI.

This wrapper is based on version 1.0.0d of libeay32.dll and ssleay32.dll.

### Wrapper Example

The following is a partial example to show the general pattern of wrapping
onto the C API.

Take DSA and the following C prototypes:

```
DSA *  DSA_new(void);
void   DSA_free(DSA *dsa);
int    DSA_size(const DSA *dsa);
int    DSA_generate_key(DSA *dsa);
int    DSA_sign(int dummy, const unsigned char *dgst, int len,
                unsigned char *sigret, unsigned int *siglen, DSA *dsa);
int    DSA_verify(int dummy, const unsigned char *dgst, int len,
                const unsigned char *sigbuf, int siglen, DSA *dsa);
```

Which gets wrapped as something akin to:

```
public class DSA : IDisposable
{
    // calls DSA_new()
    public DSA();

    // calls DSA_free() as needed
    ~DSA();

    // calls DSA_free() as needed
    public void Dispose();

    // returns DSA_size()
    public int Size { get; }

    // calls DSA_generate_key()
    public void GenerateKeys();

    // calls DSA_sign()
    public byte[] Sign(byte[] msg);

    // returns DSA_verify()
    public bool Verify(byte[] msg, byte[] sig);
}
```

### License

The OpenSSL libraries are distributed under the terms of the [OpenSSL License & SSLeay License](LICENSE); this library and related code are released under the BSD license, see [COPYING](COPYING) for more details.

### Team

This library is the product of many contributors, both directly, and indirectly, thanks to the great effort of the OpenSSL team. Thanks to all those that have contributed to this project - whether code, testing, support or anything else.

**Maintainer:**
 * Adam Caudill <adam@adamcaudill.com>
 * Frank Laub (2007-2014)

For security issues, please contact the maintainer directly prior to opening a public ticket. Security issues will receive prompt attention and be handled as quickly as possible.
