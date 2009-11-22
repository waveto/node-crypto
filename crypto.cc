#include <node.h>
#include <node_events.h>
#include <assert.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/err.h>



using namespace v8;
using namespace node;

void hex_encode(unsigned char *md_value, int md_len, char** md_hexdigest, int* md_hex_len) {
  *md_hex_len = (2*(md_len)) + 1;
  *md_hexdigest = (char *) malloc(*md_hex_len);
  for(int i = 0; i < md_len; i++) {
    sprintf((char *)(*md_hexdigest + (i*2)), "%02x",  md_value[i]);
  }
}

#define hex2i(c) ((c) <= '9' ? ((c) - '0') : (c) <= 'Z' ? ((c) - 'A' + 10) : ((c) - 'a' + 10))
void hex_decode(unsigned char *input, int length, char** buf64, int* buf64_len) {
  *buf64_len = (length/2);
  *buf64 = (char*) malloc(length/2 + 1);
  char *b = *buf64;
  for(int i = 0; i < length-1; i+=2) {
    b[i/2]  = (hex2i(input[i])<<4) | (hex2i(input[i+1]));
  }
}

void base64(unsigned char *input, int length, char** buf64, int* buf64_len)
{
  BIO *bmem, *b64;
  BUF_MEM *bptr;

  b64 = BIO_new(BIO_f_base64());
  bmem = BIO_new(BIO_s_mem());
  b64 = BIO_push(b64, bmem);
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  BIO_write(b64, input, length);
  BIO_flush(b64);
  BIO_get_mem_ptr(b64, &bptr);

  *buf64_len = bptr->length;
  *buf64 = (char *)malloc(*buf64_len+1);
  memcpy(*buf64, bptr->data, bptr->length);
  char* b = *buf64;
  b[bptr->length] = 0;

  BIO_free_all(b64);

}

void *unbase64(unsigned char *input, int length, char** buffer, int* buffer_len)
{
  BIO *b64, *bmem;
  *buffer = (char *)malloc(length);
  memset(*buffer, 0, length);

  b64 = BIO_new(BIO_f_base64());
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  bmem = BIO_new_mem_buf(input, length);
  bmem = BIO_push(b64, bmem);

  *buffer_len = BIO_read(bmem, *buffer, length);
  BIO_free_all(bmem);

}

class Hash : public EventEmitter {
 public:
  static void
  Initialize (v8::Handle<v8::Object> target)
  {
    HandleScope scope;

    Local<FunctionTemplate> t = FunctionTemplate::New(New);

    t->Inherit(EventEmitter::constructor_template);
    t->InstanceTemplate()->SetInternalFieldCount(1);

    NODE_SET_PROTOTYPE_METHOD(t, "init", HashInit);
    NODE_SET_PROTOTYPE_METHOD(t, "update", HashUpdate);
    NODE_SET_PROTOTYPE_METHOD(t, "digest", HashDigest);

    target->Set(String::NewSymbol("Hash"), t->GetFunction());
  }

  bool HashInit (const char* hashType)
  {
    md = EVP_get_digestbyname(hashType);
    if(!md) {
      fprintf(stderr, "node-crypto : Unknown message digest %s\n", hashType);
      return false;
    }
    EVP_MD_CTX_init(&mdctx);
    EVP_DigestInit_ex(&mdctx, md, NULL);
    initialised = true;
    return true;
    
  }

  int HashUpdate(char* data, int len) {
    if (!initialised)
      return 0;
    EVP_DigestUpdate(&mdctx, data, len);
    return 1;
  }

  int HashDigest(unsigned char** md_value, unsigned int *md_len) {
    if (!initialised)
      return 0;
    *md_value = (unsigned char*) malloc(EVP_MAX_MD_SIZE);
    EVP_DigestFinal_ex(&mdctx, *md_value, md_len);
    EVP_MD_CTX_cleanup(&mdctx);
    initialised = false;
    return 1;
  }


 protected:

  static Handle<Value>
  New (const Arguments& args)
  {
    HandleScope scope;

    Hash *hash = new Hash();
    hash->Wrap(args.This());
    return args.This();
  }

  static Handle<Value>
  HashInit(const Arguments& args) {
    Hash *hash = ObjectWrap::Unwrap<Hash>(args.This());

    HandleScope scope;

    if (args.Length() == 0 || !args[0]->IsString()) {
      return ThrowException(String::New("Must give hashtype string as argument"));
    }

    String::Utf8Value hashType(args[0]->ToString());

    bool r = hash->HashInit(*hashType);

    return args.This();
  }

  static Handle<Value>
  HashUpdate(const Arguments& args) {
    Hash *hash = ObjectWrap::Unwrap<Hash>(args.This());

    HandleScope scope;

    enum encoding enc = ParseEncoding(args[1]);
    ssize_t len = DecodeBytes(args[0], enc);

    if (len < 0) {
      Local<Value> exception = Exception::TypeError(String::New("Bad argument"));
      return ThrowException(exception);
    }

    char* buf = new char[len];
    ssize_t written = DecodeWrite(buf, len, args[0], enc);
    assert(written == len);

    int r = hash->HashUpdate(buf, len);

    return args.This();
  }

  static Handle<Value>
  HashDigest(const Arguments& args) {
    Hash *hash = ObjectWrap::Unwrap<Hash>(args.This());

    HandleScope scope;

    unsigned char* md_value;
    unsigned int md_len;
    char* md_hexdigest;
    int md_hex_len;
    Local<Value> outString ;

    int r = hash->HashDigest(&md_value, &md_len);

    if (md_len == 0 || r == 0) {
      return scope.Close(String::New(""));
    }

    if (args.Length() == 0 || !args[0]->IsString()) {
      // Binary
      outString = Encode(md_value, md_len, BINARY);
    } else {
      String::Utf8Value encoding(args[0]->ToString());
      if (strcasecmp(*encoding, "hex") == 0) {
        // Hex encoding
        hex_encode(md_value, md_len, &md_hexdigest, &md_hex_len);
        outString = Encode(md_hexdigest, md_hex_len, BINARY);
        free(md_hexdigest);
      } else if (strcasecmp(*encoding, "base64") == 0) {
        base64(md_value, md_len, &md_hexdigest, &md_hex_len);
        outString = Encode(md_hexdigest, md_hex_len, BINARY);
        free(md_hexdigest);
      } else if (strcasecmp(*encoding, "binary") == 0) {
        outString = Encode(md_value, md_len, BINARY);
      } else {
	fprintf(stderr, "node-crypto : Hash .digest encoding "
		"can be binary, hex or base64\n");
      }
    }
    free(md_value);
    return scope.Close(outString);

  }

  Hash () : EventEmitter () 
  {
    initialised = false;
  }

  ~Hash ()
  {
  }

 private:

  EVP_MD_CTX mdctx;
  const EVP_MD *md;
  bool initialised;

};

class Sign : public EventEmitter {
 public:
  static void
  Initialize (v8::Handle<v8::Object> target)
  {
    HandleScope scope;

    Local<FunctionTemplate> t = FunctionTemplate::New(New);

    t->Inherit(EventEmitter::constructor_template);
    t->InstanceTemplate()->SetInternalFieldCount(1);

    NODE_SET_PROTOTYPE_METHOD(t, "init", SignInit);
    NODE_SET_PROTOTYPE_METHOD(t, "update", SignUpdate);
    NODE_SET_PROTOTYPE_METHOD(t, "sign", SignFinal);

    target->Set(String::NewSymbol("Sign"), t->GetFunction());
  }

  bool SignInit (const char* signType)
  {
    md = EVP_get_digestbyname(signType);
    if(!md) {
      printf("Unknown message digest %s\n", signType);
      return false;
    }
    EVP_MD_CTX_init(&mdctx);
    EVP_SignInit_ex(&mdctx, md, NULL);
    initialised = true;
    return true;
    
  }

  int SignUpdate(char* data, int len) {
    if (!initialised)
      return 0;
    EVP_SignUpdate(&mdctx, data, len);
    return 1;
  }

  int SignFinal(unsigned char** md_value, unsigned int *md_len, char* keyPem, int keyPemLen) {
    if (!initialised)
      return 0;

    BIO *bp = NULL;
    EVP_PKEY* pkey;
    bp = BIO_new(BIO_s_mem()); 
    if(!BIO_write(bp, keyPem, keyPemLen))
      return 0;

    pkey = PEM_read_bio_PrivateKey( bp, NULL, NULL, NULL );
    if (pkey == NULL)
      return 0;

    EVP_SignFinal(&mdctx, *md_value, md_len, pkey);
    EVP_MD_CTX_cleanup(&mdctx);
    initialised = false;
    EVP_PKEY_free(pkey);
    BIO_free(bp);
    return 1;
  }


 protected:

  static Handle<Value>
  New (const Arguments& args)
  {
    HandleScope scope;

    Sign *sign = new Sign();
    sign->Wrap(args.This());

    return args.This();
  }

  static Handle<Value>
  SignInit(const Arguments& args) {
    Sign *sign = ObjectWrap::Unwrap<Sign>(args.This());

    HandleScope scope;

    if (args.Length() == 0 || !args[0]->IsString()) {
      return ThrowException(String::New("Must give signtype string as argument"));
    }

    String::Utf8Value signType(args[0]->ToString());

    bool r = sign->SignInit(*signType);

    return args.This();
  }

  static Handle<Value>
  SignUpdate(const Arguments& args) {
    Sign *sign = ObjectWrap::Unwrap<Sign>(args.This());

    HandleScope scope;

    enum encoding enc = ParseEncoding(args[1]);
    ssize_t len = DecodeBytes(args[0], enc);

    if (len < 0) {
      Local<Value> exception = Exception::TypeError(String::New("Bad argument"));
      return ThrowException(exception);
    }

    char* buf = new char[len];
    ssize_t written = DecodeWrite(buf, len, args[0], enc);
    assert(written == len);

    int r = sign->SignUpdate(buf, len);

    return args.This();
  }

  static Handle<Value>
  SignFinal(const Arguments& args) {
    Sign *sign = ObjectWrap::Unwrap<Sign>(args.This());

    HandleScope scope;

    unsigned char* md_value;
    unsigned int md_len;
    char* md_hexdigest;
    int md_hex_len;
    Local<Value> outString;

    md_len = 8192; // Maximum key size is 8192 bits
    md_value = new unsigned char[md_len];

    ssize_t len = DecodeBytes(args[0], BINARY);

    if (len < 0) {
      Local<Value> exception = Exception::TypeError(String::New("Bad argument"));
      return ThrowException(exception);
    }

    char* buf = new char[len];
    ssize_t written = DecodeWrite(buf, len, args[0], BINARY);
    assert(written == len);


    int r = sign->SignFinal(&md_value, &md_len, buf, len);

    if (md_len == 0 || r == 0) {
      return scope.Close(String::New(""));
    }

    if (args.Length() == 1 || !args[1]->IsString()) {
      // Binary
      outString = Encode(md_value, md_len, BINARY);
    } else {
      String::Utf8Value encoding(args[1]->ToString());
      if (strcasecmp(*encoding, "hex") == 0) {
        // Hex encoding
        hex_encode(md_value, md_len, &md_hexdigest, &md_hex_len);
        outString = Encode(md_hexdigest, md_hex_len, BINARY);
        free(md_hexdigest);
      } else if (strcasecmp(*encoding, "base64") == 0) {
        base64(md_value, md_len, &md_hexdigest, &md_hex_len);
        outString = Encode(md_hexdigest, md_hex_len, BINARY);
        free(md_hexdigest);
      } else if (strcasecmp(*encoding, "binary") == 0) {
        outString = Encode(md_value, md_len, BINARY);
      } else {
	outString = String::New("");
	fprintf(stderr, "node-crypto : Sign .sign encoding "
		"can be binary, hex or base64\n");
      }
    }
    return scope.Close(outString);

  }

  Sign () : EventEmitter () 
  {
    initialised = false;
  }

  ~Sign ()
  {
  }

 private:

  EVP_MD_CTX mdctx;
  const EVP_MD *md;
  bool initialised;

};

class Verify : public EventEmitter {
 public:
  static void
  Initialize (v8::Handle<v8::Object> target)
  {
    HandleScope scope;

    Local<FunctionTemplate> t = FunctionTemplate::New(New);

    t->Inherit(EventEmitter::constructor_template);
    t->InstanceTemplate()->SetInternalFieldCount(1);

    NODE_SET_PROTOTYPE_METHOD(t, "init", VerifyInit);
    NODE_SET_PROTOTYPE_METHOD(t, "update", VerifyUpdate);
    NODE_SET_PROTOTYPE_METHOD(t, "verify", VerifyFinal);

    target->Set(String::NewSymbol("Verify"), t->GetFunction());
  }

  bool VerifyInit (const char* verifyType)
  {
    md = EVP_get_digestbyname(verifyType);
    if(!md) {
      fprintf(stderr, "node-crypto : Unknown message digest %s\n", verifyType);
      return false;
    }
    EVP_MD_CTX_init(&mdctx);
    EVP_VerifyInit_ex(&mdctx, md, NULL);
    initialised = true;
    return true;
    
  }

  int VerifyUpdate(char* data, int len) {
    if (!initialised)
      return 0;
    EVP_VerifyUpdate(&mdctx, data, len);
    return 1;
  }

  int VerifyFinal(char* keyPem, int keyPemLen, unsigned char* sig, int siglen) {
    if (!initialised)
      return 0;

    BIO *bp = NULL;
    EVP_PKEY* pkey;
    X509 *        x509;

    bp = BIO_new(BIO_s_mem()); 
    if(!BIO_write(bp, keyPem, keyPemLen))
      return 0;

    x509 = PEM_read_bio_X509(bp, NULL, NULL, NULL );
    if (x509==NULL)
      return 0;

    pkey=X509_get_pubkey(x509);
    if (pkey==NULL)
      return 0;

    int r = EVP_VerifyFinal(&mdctx, sig, siglen, pkey);
    EVP_PKEY_free (pkey);

    if (r != 1) {
      ERR_print_errors_fp (stderr);
    }
    X509_free(x509);
    BIO_free(bp);
    EVP_MD_CTX_cleanup(&mdctx);
    initialised = false;
    return r;
  }


 protected:

  static Handle<Value>
  New (const Arguments& args)
  {
    HandleScope scope;

    Verify *verify = new Verify();
    verify->Wrap(args.This());

    return args.This();
  }

  static Handle<Value>
  VerifyInit(const Arguments& args) {
    Verify *verify = ObjectWrap::Unwrap<Verify>(args.This());

    HandleScope scope;

    if (args.Length() == 0 || !args[0]->IsString()) {
      return ThrowException(String::New("Must give verifytype string as argument"));
    }

    String::Utf8Value verifyType(args[0]->ToString());

    bool r = verify->VerifyInit(*verifyType);

    return args.This();
  }

  static Handle<Value>
  VerifyUpdate(const Arguments& args) {
    Verify *verify = ObjectWrap::Unwrap<Verify>(args.This());

    HandleScope scope;

    enum encoding enc = ParseEncoding(args[1]);
    ssize_t len = DecodeBytes(args[0], enc);

    if (len < 0) {
      Local<Value> exception = Exception::TypeError(String::New("Bad argument"));
      return ThrowException(exception);
    }

    char* buf = new char[len];
    ssize_t written = DecodeWrite(buf, len, args[0], enc);
    assert(written == len);

    int r = verify->VerifyUpdate(buf, len);

    return args.This();
  }

  static Handle<Value>
  VerifyFinal(const Arguments& args) {
    Verify *verify = ObjectWrap::Unwrap<Verify>(args.This());

    HandleScope scope;

    ssize_t klen = DecodeBytes(args[0], BINARY);

    if (klen < 0) {
      Local<Value> exception = Exception::TypeError(String::New("Bad argument"));
      return ThrowException(exception);
    }

    char* kbuf = new char[klen];
    ssize_t kwritten = DecodeWrite(kbuf, klen, args[0], BINARY);
    assert(kwritten == klen);


    ssize_t hlen = DecodeBytes(args[1], BINARY);

    if (hlen < 0) {
      Local<Value> exception = Exception::TypeError(String::New("Bad argument"));
      return ThrowException(exception);
    }
    
    unsigned char* hbuf = new unsigned char[hlen];
    ssize_t hwritten = DecodeWrite((char *)hbuf, hlen, args[1], BINARY);
    assert(hwritten == hlen);
    unsigned char* dbuf;
    int dlen;

    int r=-1;

    if (args.Length() == 2 || !args[2]->IsString()) {
      // Binary
      r = verify->VerifyFinal(kbuf, klen, hbuf, hlen);
    } else {
      String::Utf8Value encoding(args[2]->ToString());
      if (strcasecmp(*encoding, "hex") == 0) {
        // Hex encoding
        hex_decode(hbuf, hlen, (char **)&dbuf, &dlen);
        r = verify->VerifyFinal(kbuf, klen, dbuf, dlen);
	free(dbuf);
      } else if (strcasecmp(*encoding, "base64") == 0) {
        // Base64 encoding
        unbase64(hbuf, hlen, (char **)&dbuf, &dlen);
        r = verify->VerifyFinal(kbuf, klen, dbuf, dlen);
	free(dbuf);
      } else if (strcasecmp(*encoding, "binary") == 0) {
        r = verify->VerifyFinal(kbuf, klen, hbuf, hlen);
      } else {
	fprintf(stderr, "node-crypto : Verify .verify encoding "
		"can be binary, hex or base64\n");
      }
    }

    return scope.Close(Integer::New(r));
  }

  Verify () : EventEmitter () 
  {
    initialised = false;
  }

  ~Verify ()
  {
  }

 private:

  EVP_MD_CTX mdctx;
  const EVP_MD *md;
  bool initialised;

};



extern "C" void
init (Handle<Object> target) 
{
  HandleScope scope;

  ERR_load_crypto_strings();
  OpenSSL_add_all_digests();

  Hash::Initialize(target);
  Sign::Initialize(target);
  Verify::Initialize(target);
}
