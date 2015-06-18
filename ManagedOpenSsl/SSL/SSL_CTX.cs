// Copyright © Microsoft Open Technologies, Inc.
// All Rights Reserved       


using System;
using System.Runtime.InteropServices;
using OpenSSL.Core;

namespace OpenSSL.SSL
{
    [StructLayout(LayoutKind.Explicit)]
    internal struct SSL_CTX
    {
        [FieldOffset(0)]
        public IntPtr method; //SSL_METHOD
        [FieldOffset(4)]
        public IntPtr cipher_list;  // STACK_OF(SSL_CIPHER)
        [FieldOffset(8)]
        public IntPtr cipher_list_by_id; // STACK_OF(SSL_CIPHER)
        [FieldOffset(12)]
        public IntPtr cert_store; //X509_STORE
        [FieldOffset(16)]
        public IntPtr sessions; //lhash_st of SSL_SESSION
        [FieldOffset(20)]
        public int session_cache_size;
        [FieldOffset(24)]
        public IntPtr session_cache_head; //ssl_session_st
        [FieldOffset(28)]
        public IntPtr session_cache_tail; // ssl_session_st
        [FieldOffset(32)]
        public int session_cache_mode;
        [FieldOffset(36)]
        public int session_timeout;
        [FieldOffset(40)]
        public IntPtr new_session_cb; // int (*new_session_cb)(SSL*, SSL_SESSION*)
        [FieldOffset(44)]
        public IntPtr remove_session_cb; // void (*remove_session_cb)(SSL*,SSL_SESSION*)
        [FieldOffset(48)]
        public IntPtr get_session_cb; // SSL_SESSION*(*get_session_cb)(SSL*, uchar* data, int len, int* copy)
        #region stats
        [FieldOffset(52)]
        public int stats_sess_connect;	/* SSL new conn - started */
        [FieldOffset(56)]
        public int stats_sess_connect_renegotiate;/* SSL reneg - requested */
        [FieldOffset(60)]
        public int stats_sess_connect_good;	/* SSL new conne/reneg - finished */
        [FieldOffset(64)]
        public int stats_sess_accept;	/* SSL new accept - started */
        [FieldOffset(68)]
        public int stats_sess_accept_renegotiate;/* SSL reneg - requested */
        [FieldOffset(72)]
        public int stats_sess_accept_good;	/* SSL accept/reneg - finished */
        [FieldOffset(76)]
        public int stats_sess_miss;		/* session lookup misses  */
        [FieldOffset(80)]
        public int stats_sess_timeout;	/* reuse attempt on timeouted session */
        [FieldOffset(84)]
        public int stats_sess_cache_full;	/* session removed due to full cache */
        [FieldOffset(88)]
        public int stats_sess_hit;		/* session reuse actually done */
        [FieldOffset(92)]
        public int stats_sess_cb_hit;	/* session-id that was not in the cache was passed back via the callback.  This
					         * indicates that the application is supplying session-id's from other processes - spooky :-) */
        #endregion
        [FieldOffset(96)]
        public int references;
        [FieldOffset(100)]
        public IntPtr app_verify_callback; //int (*app_verify_callback)(X509_STORE_CTX *, void *)
        [FieldOffset(104)]
        public IntPtr app_verify_arg;
        [FieldOffset(108)]
        public IntPtr default_passwd_callback; //pem_password_cb
        [FieldOffset(112)]
        public IntPtr default_passwd_callback_userdata;
        [FieldOffset(116)]
        public IntPtr client_cert_cb; //int (*client_cert_cb)(SSL *ssl, X509 **x509, EVP_PKEY **pkey)
        [FieldOffset(120)]
        public IntPtr app_gen_cookie_cb; //int (*app_gen_cookie_cb)(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len);
        [FieldOffset(124)]
        public IntPtr app_verify_cookie_cb; //int (*app_verify_cookie_cb)(SSL *ssl, unsigned char *cookie, unsigned int cookie_len); 
        #region CRYPTO_EX_DATA ex_data;
        [FieldOffset(128)]
        public IntPtr ex_data_sk;
        [FieldOffset(132)]
        public int ex_data_dummy;
        #endregion
        [FieldOffset(136)]
        public IntPtr rsa_md5; //EVP_MD
        [FieldOffset(140)]
        public IntPtr md5; //EVP_MD
        [FieldOffset(144)]
        public IntPtr sha1; //EVP_MD
        [FieldOffset(148)]
        public IntPtr extra_certs; //STACK_OF(X509)
        [FieldOffset(152)]
        public IntPtr comp_methods; //STACK_OF(SSL_COMP)
        [FieldOffset(156)]
        public IntPtr info_callback; //void (*info_callback)(const SSL *ssl,int type,int val)
        [FieldOffset(160)]
        public IntPtr client_CA; //STACK_OF(X509_NAME)
        [FieldOffset(164)]
        public uint options;
        [FieldOffset(168)]
        public uint mode;
        [FieldOffset(172)]
        public int max_cert_list;
        [FieldOffset(176)]
        public IntPtr cert; //cert_st
        [FieldOffset(180)]
        public int read_ahead;
        [FieldOffset(184)]
        public IntPtr msg_callback; //void (*msg_callback)(int write_p, int version, int content_type, const void *buf, size_t len, SSL *ssl, void *arg);
        [FieldOffset(188)]
        public IntPtr msg_callback_arg;
        [FieldOffset(192)]
        public int verify_mode;
        [FieldOffset(196)]
        public uint sid_ctx_length;
        [FieldOffset(200)]
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = Native.SSL_MAX_SID_CTX_LENGTH)]
        public byte[] sid_ctx;
        [FieldOffset(200 + Native.SSL_MAX_SID_CTX_LENGTH)]
        public IntPtr default_verify_callback; //int (*default_verify_callback)(int ok,X509_STORE_CTX *ctx)
        [FieldOffset(204 + Native.SSL_MAX_SID_CTX_LENGTH)]
        public IntPtr generate_session_id; //typedef int (*GEN_SESSION_CB)(const SSL *ssl, unsigned char *id,unsigned int *id_len);
        #region X509_VERIFY_PARAM
        [FieldOffset(208 + Native.SSL_MAX_SID_CTX_LENGTH)]
        public IntPtr param; //X509_VERIFY_PARAM *param;
        /*[FieldOffset(208 + Native.SSL_MAX_SID_CTX_LENGTH)]
        public IntPtr x509_verify_param_name;
        [FieldOffset(212 + Native.SSL_MAX_SID_CTX_LENGTH)]
        public long x509_verify_param_check_time;
        [FieldOffset(220)]
        public int x509_verify_param_inh_flags;
        [FieldOffset(224)]
        public int x509_verify_param_flags;
        [FieldOffset(228)]
        public int x509_verify_param_purpose;
        [FieldOffset(232)]
        public int x509_verify_param_trust;
        [FieldOffset(236)]
        public int x509_verify_param_depth;
        [FieldOffset(240)]
        public IntPtr x509_verify_param_policies;*/

        #endregion
#if __UNUSED__
	            int purpose;		/* Purpose setting */
	            int trust;		/* Trust setting */
#endif
        [FieldOffset(212 + Native.SSL_MAX_SID_CTX_LENGTH)]
        public int quiet_shutdown;
        /* Maximum amount of data to send in one fragment.
         * actual record size can be more than this due to
         * padding and MAC overheads.
         */
        [FieldOffset(216 + Native.SSL_MAX_SID_CTX_LENGTH)]
        UInt32 max_send_fragment;
#if (! OPENSSL_ENGINE)
        // Engine to pass requests for client certs to
        [FieldOffset(220 + Native.SSL_MAX_SID_CTX_LENGTH)]
        public IntPtr client_cert_engine;
#endif
#if (! OPENSSL_NO_TLSEXT)
        [FieldOffset(224 + Native.SSL_MAX_SID_CTX_LENGTH)]
        public IntPtr tlsext_servername_callback; //int (*tlsext_servername_callback)(SSL*, int *, void *)
        [FieldOffset(228)]
        public IntPtr tlsext_servername_arg;

        [FieldOffset(232 + Native.SSL_MAX_SID_CTX_LENGTH)]
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] tlsext_tick_key_name;

        [FieldOffset(248 + Native.SSL_MAX_SID_CTX_LENGTH)]
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] tlsext_tick_hmac_key;

        [FieldOffset(264 + Native.SSL_MAX_SID_CTX_LENGTH)]
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] tlsext_tick_aes_key;

        [FieldOffset(280 + Native.SSL_MAX_SID_CTX_LENGTH)]
        public IntPtr tlsext_ticket_key_cb; //int (*tlsext_ticket_key_cb)(SSL *ssl,unsigned char *name, unsigned char *iv,EVP_CIPHER_CTX *ectx,HMAC_CTX *hctx, int enc);

        [FieldOffset(284 + Native.SSL_MAX_SID_CTX_LENGTH)]
        public IntPtr tlsext_status_cb; //int (*tlsext_status_cb)(SSL *ssl, void *arg);
        [FieldOffset(288 + Native.SSL_MAX_SID_CTX_LENGTH)]
        public IntPtr tlsext_status_arg;
        [FieldOffset(292 + Native.SSL_MAX_SID_CTX_LENGTH)]
        public IntPtr tlsext_opaque_prf_input_callback; //int (*tlsext_opaque_prf_input_callback)(SSL *, void *peerinput, size_t len, void *arg);
        [FieldOffset(296 + Native.SSL_MAX_SID_CTX_LENGTH)]
        public IntPtr tlsext_opaque_prf_input_callback_arg; //void *tlsext_opaque_prf_input_callback_arg;
#endif

#if (! OPENSSL_NO_PSK)
        [FieldOffset(300 + Native.SSL_MAX_SID_CTX_LENGTH)]
        [MarshalAs(UnmanagedType.LPTStr)]
        public string psk_identity_hint;

        [FieldOffset(304 + Native.SSL_MAX_SID_CTX_LENGTH)]
        public IntPtr psk_client_callback;
        // unsigned int (*psk_client_callback)(SSL *ssl, const char *hint, char *identity,
        //                                      unsigned int max_identity_len, unsigned char *psk,
        //                                      unsigned int max_psk_len);
        [FieldOffset(308 + Native.SSL_MAX_SID_CTX_LENGTH)]
        public IntPtr psk_server_callback;
        //unsigned int (*psk_server_callback)(SSL *ssl, const char *identity, 
        //                                      unsigned char *psk, unsigned int max_psk_len);
#endif

#if (! OPENSSL_NO_BUF_FREELISTS)
        //#define SSL_MAX_BUF_FREELIST_LEN_DEFAULT //32
        [FieldOffset(312 + Native.SSL_MAX_SID_CTX_LENGTH)]
        UInt32 freelist_max_len;
        [FieldOffset(316 + Native.SSL_MAX_SID_CTX_LENGTH)]
        public IntPtr wbuf_freelist;
        [FieldOffset(320 + Native.SSL_MAX_SID_CTX_LENGTH)]
        public IntPtr rbuf_freelist;
#endif
        #region SRP_CTX
#if (! OPENSSL_NO_SRP)
        /* param for all the callbacks */
        [FieldOffset(324 + Native.SSL_MAX_SID_CTX_LENGTH)]
        public IntPtr SRP_cb_arg;//void *SRP_cb_arg;

        /* set client Hello login callback */
        [FieldOffset(328 + Native.SSL_MAX_SID_CTX_LENGTH)]
        public IntPtr TLS_ext_srp_username_callback;//int (*TLS_ext_srp_username_callback)(SSL *, int *, void *);

        /* set SRP N/g param callback for verification */
        [FieldOffset(332 + Native.SSL_MAX_SID_CTX_LENGTH)]
        public IntPtr SRP_verify_param_callback;//int (*SRP_verify_param_callback)(SSL *, void *);

        /* set SRP client passwd callback */
        [FieldOffset(336 + Native.SSL_MAX_SID_CTX_LENGTH)]
        public IntPtr SRP_give_srp_client_pwd_callback;//char *(*SRP_give_srp_client_pwd_callback)(SSL *, void *);

        [FieldOffset(340 + Native.SSL_MAX_SID_CTX_LENGTH)]
        [MarshalAs(UnmanagedType.LPTStr)]
        public string login;//char *login;

        [FieldOffset(344 + Native.SSL_MAX_SID_CTX_LENGTH)]
        public IntPtr N;

        [FieldOffset(348 + Native.SSL_MAX_SID_CTX_LENGTH)]
        public IntPtr g;

        [FieldOffset(352 + Native.SSL_MAX_SID_CTX_LENGTH)]
        public IntPtr s;

        [FieldOffset(356 + Native.SSL_MAX_SID_CTX_LENGTH)]
        public IntPtr B;

        [FieldOffset(360 + Native.SSL_MAX_SID_CTX_LENGTH)]
        public IntPtr A;//BIGNUM *N,*g,*s,*B,*A; Use BigNumber instead of intptr?

        [FieldOffset(364 + Native.SSL_MAX_SID_CTX_LENGTH)]
        public IntPtr a;

        [FieldOffset(368 + Native.SSL_MAX_SID_CTX_LENGTH)]
        public IntPtr b;

        [FieldOffset(372 + Native.SSL_MAX_SID_CTX_LENGTH)]
        public IntPtr v;//BIGNUM *a,*b,*v;

        [FieldOffset(376 + Native.SSL_MAX_SID_CTX_LENGTH)]
        [MarshalAs(UnmanagedType.LPTStr)]
        public string info;//char *info;

        [FieldOffset(380 + Native.SSL_MAX_SID_CTX_LENGTH)]
        int strength;

        [FieldOffset(384 + Native.SSL_MAX_SID_CTX_LENGTH)]
        public ulong srp_mask;//unsigned long srp_Mask;
#endif
        #endregion
#if (! OPENSSL_NO_TLSEXT)

#if (! OPENSSL_NO_NEXTPROTONEG)
        /* Next protocol negotiation information */
        /* (for experimental NPN extension). */

        /* For a server, this contains a callback function by which the set of
         * advertised protocols can be provided. */
        [FieldOffset(388 + Native.SSL_MAX_SID_CTX_LENGTH)]
        public IntPtr next_protos_advertised_cb;//int (*next_protos_advertised_cb)(SSL *s, const unsigned char **buf,

        [FieldOffset(392 + Native.SSL_MAX_SID_CTX_LENGTH)]//unsigned int *len, void *arg);
        public IntPtr next_protos_advertised_cb_arg;//void *next_protos_advertised_cb_arg;
        /* For a client, this contains a callback function that selects the
         * next protocol from the list provided by the server. */

        [FieldOffset(396 + Native.SSL_MAX_SID_CTX_LENGTH)]
        public IntPtr next_proto_select_cb;
        //int (*next_proto_select_cb)(SSL *s, unsigned char **out,
        //			    unsigned char *outlen,
        //			    const unsigned char *in,
        //			    unsigned int inlen,
        //			    void *arg);

        [FieldOffset(400 + Native.SSL_MAX_SID_CTX_LENGTH)]
        public IntPtr next_proto_select_cb_arg; //void *next_proto_select_cb_arg;
# endif


        /*ALPN information
            * (we are in the process of transitioning from NPN to ALPN.) 

		     For a server, this contains a callback function that allows the
            * server to select the protocol for the connection.
            *   out: on successful return, this must point to the raw protocol
            *        name (without the length prefix).
            *   outlen: on successful return, this contains the length of |*out|.
            *   in: points to the client's list of supported protocols in
            *       wire-format.
            *   inlen: the length of |in|.*/

        [FieldOffset(404 + Native.SSL_MAX_SID_CTX_LENGTH)]
        public IntPtr alpn_select_cb;
        //int (*alpn_select_cb)(SSL *s,
        //        const unsigned char **out,
        //        unsigned char *outlen,
        //        const unsigned char* in,
        //        unsigned int inlen,
        //        void *arg);

        [FieldOffset(408 + Native.SSL_MAX_SID_CTX_LENGTH)]
        public IntPtr alpn_select_cb_arg;//void *alpn_select_cb_arg;

        // For a client, this contains the list of supported protocols in wire format.
        [FieldOffset(412 + Native.SSL_MAX_SID_CTX_LENGTH)]
        [MarshalAs(UnmanagedType.LPStr)]
        string alpn_client_proto_list;//unsigned char* alpn_client_proto_list;

        [FieldOffset(416 + Native.SSL_MAX_SID_CTX_LENGTH)]
        public UInt32 alpn_client_proto_list_len; //unsigned alpn_client_proto_list_len;

        [FieldOffset(420 + Native.SSL_MAX_SID_CTX_LENGTH)]
        public IntPtr srtp_profiles;
#endif
    }
}
