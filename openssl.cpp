//
// Created by ahorvat on 31.08.22..
//
#include "catch.hpp"
#include "openssl/rsa.h"
#include "openssl/pem.h"
#include "openssl/asn1.h"

#include "memory"
#include <exception>
#include <utility>
#include <limits>
#include <iostream>
#include <strstream>
#include <array>
#include <cstring>

struct STR_DESTRUCTOR {
    void operator()(char *c) {
        OPENSSL_free(c);
    }
};

using STRPTR = std::unique_ptr<char, STR_DESTRUCTOR>;

struct SSLException : public std::exception {
    std::string msg;
    int err;
public:
    SSLException(std::string msg, int err) : std::exception(), msg{std::move(msg)}, err(err) {}

    [[nodiscard]] const std::string &getMsg() const &{
        return msg;
    }

    int getErr() const {
        return err;
    }

};


struct RSA_DESTRUCTOR {
public:
    void operator()(RSA *rsa) {
        RSA_free(rsa);
    }
};

class BioMem {
    struct BIO_METHOD_DESTRUCTOR {
        void operator()(BIO_METHOD *p) {
            BIO_meth_free(p);
        }
    };

    using BioMethod = std::unique_ptr<BIO_METHOD, BIO_METHOD_DESTRUCTOR>;

    BIO *m_bio;
public:
    BioMem(BIO *mBio) : m_bio(mBio) {}

    ~BioMem() {
        BIO_free(m_bio);
    }

    using PTR = std::unique_ptr<BioMem>;

    BIO *bio() {
        return m_bio;
    }

    static PTR make() {
        auto bio = BIO_new(BIO_s_mem());
        if (bio == nullptr) {
            throw SSLException("BIO_NEW NULL pointer exception", 0);
        }
        return std::make_unique<BioMem>(bio);
    }
};


class Sha256Utils {
public:
    using PTR = std::unique_ptr<SHA256_CTX>;
    using HASH = std::array<uint8_t, SHA256_DIGEST_LENGTH>;

    static HASH make(const unsigned char *ptr, size_t len) {
        auto ctx = PTR{new SHA256_CTX};
        SHA256_Init(ctx.get());
        SHA256_Update(ctx.get(), ptr, len);
        auto md = std::array<uint8_t, SHA256_DIGEST_LENGTH>{};
        SHA256_Final(md.data(), ctx.get());
        return md;
    }
};

class RsaUtils {
public:
    using PTR = std::unique_ptr<RSA, RSA_DESTRUCTOR>;

    static PTR make() {
        return PTR{RSA_new()};
    }

    static std::string dumpKey(const PTR &key) {
        auto d = RSA_get0_d(key.get());
        auto p = RSA_get0_p(key.get());
        auto q = RSA_get0_q(key.get());
        auto hex_d = STRPTR{BN_bn2hex(d)};
        auto hex_p = STRPTR{BN_bn2hex(p)};
        auto hex_q = STRPTR{BN_bn2hex(q)};
        std::ostrstream oss;
        oss << "d: " << hex_d.get() << "\n"
            << "p: " << hex_p.get() << "\n"
            << "q: " << hex_q.get() << "\n";

        return oss.str();
    }

    static std::string pemPrivateKey(PTR &key) {
        auto bio = BioMem::make();
        auto ret = PEM_write_bio_RSAPrivateKey(bio.get()->bio(), key.get(), nullptr, nullptr, 0, nullptr, nullptr);
        std::cout << ret << std::endl;

        char *mem = nullptr;
        auto len = BIO_get_mem_data(bio->bio(), &mem);
        if (len < 0) {
            throw SSLException("BIO_get_mem_data length negative", -1);
        }
        return std::string{mem, static_cast<unsigned long>(len)};
    }

    static std::vector<uint8_t> signSha1(PTR &key, const std::vector<uint8_t> &data) {

        auto hash = Sha256Utils::make(data.data(), data.size());

        if (data.size() > std::numeric_limits<unsigned int>::max()) {
            throw SSLException("data.size() exceeds unsigned int max value", -1);
        }
        auto sigret = std::vector<uint8_t>(RSA_size(key.get()));
        auto siglen = 0U;

        auto alloc = static_cast<uint8_t *>(alloca(RSA_size(key.get())));

        auto ret = RSA_sign(NID_RSA_SHA3_256, hash.data(), hash.size(), alloc, &siglen, key.get());
        if (ret == 0) {
            throw SSLException("RSA_sign returned 0", ret);
        }
        return std::vector<uint8_t>{alloc, alloc + siglen};
    }

    static std::vector<uint8_t> signSha1(PTR &key, const std::string &str) {
        return signSha1(key, std::vector<uint8_t>{str.data(), str.data() + str.length()});
    }
};

class BnUtils {
public:
    struct BN_CTX_DESTRUCTOR {
    public:
        void operator()(BIGNUM *bn) {
            BN_free(bn);
        }
    };

    using PTR = std::unique_ptr<BIGNUM, BN_CTX_DESTRUCTOR>;

    static PTR make() {
        return PTR{BN_new()};
    }
};

class Facade {
public:
    static RsaUtils::PTR rsa(int keySize = 4096) {
        auto rsa = RsaUtils::make();
        auto bn = BnUtils::make();
        BN_set_word(bn.get(), RSA_F4);

        auto ret = RSA_generate_key_ex(rsa.get(), keySize, bn.get(), NULL);
        if (!ret) {
            throw SSLException("RSA_generate_key_ex", ret);
        }
        return rsa;
    }
};

TEST_CASE("RSA_SIGN-SSA-PKCS1-V1-5") {
    RSA *rsa = RSA_new();
    BIGNUM *bn = BN_new();
    BN_set_word(bn, RSA_F4);

    int ret = RSA_generate_key_ex(rsa, 2048, bn, NULL);
    assert(0 != ret);

    SHA256_CTX *sha_ctx = (SHA256_CTX *) alloca(sizeof(SHA256_CTX));
    memset(sha_ctx, 0, sizeof(SHA256_CTX));
    assert(NULL != sha_ctx);
    SHA256_Init(sha_ctx);

    const char *msg_to_sign = "Hello, World";
    const size_t len = strlen(msg_to_sign);

    SHA256_Update(sha_ctx, msg_to_sign, len);
    unsigned char *digest = (unsigned char *) alloca(SHA256_DIGEST_LENGTH);
    memset(digest, 0, SHA256_DIGEST_LENGTH);
    SHA256_Final(digest, sha_ctx);

    int rsa_size = RSA_size(rsa);
    unsigned char *sigret = (unsigned char *) alloca(rsa_size);
    unsigned int siglen = 0;
    memset(sigret, 0, rsa_size);

    assert(1 == RSA_sign(NID_RSA_SHA3_256, digest, SHA256_DIGEST_LENGTH, sigret, &siglen, rsa));

    FILE *f = fopen("/tmp/signature.raw", "wc");
    assert(NULL != f);
    assert(siglen == fwrite(sigret, 1, siglen, f));
    fclose(f);

    RSA_free(rsa);
}


TEST_CASE("RSASSA-PSS") {
    RSA *rsa = RSA_new();
    BIGNUM *bn = BN_new();
    BN_set_word(bn, RSA_F4);

    int ret = RSA_generate_key_ex(rsa, 2048, bn, NULL);
    assert(0 != ret);

    SHA256_CTX *sha_ctx = (SHA256_CTX *) alloca(sizeof(SHA256_CTX));
    memset(sha_ctx, 0, sizeof(SHA256_CTX));
    assert(NULL != sha_ctx);
    SHA256_Init(sha_ctx);

    const char *msg_to_sign = "Hello, World";
    const size_t len = strlen(msg_to_sign);

    SHA256_Update(sha_ctx, msg_to_sign, len);
    unsigned char *digest = (unsigned char *) alloca(SHA256_DIGEST_LENGTH);
    memset(digest, 0, SHA256_DIGEST_LENGTH);
    SHA256_Final(digest, sha_ctx);

    int rsa_size = RSA_size(rsa);
    unsigned char *sigret = (unsigned char *) alloca(rsa_size);
    unsigned int siglen = 0;
    memset(sigret, 0, rsa_size);

    assert(1 == RSA_sign(NID_rsassaPss, digest, SHA256_DIGEST_LENGTH, sigret, &siglen, rsa));
    assert(siglen == rsa_size);

    FILE *f = fopen("/tmp/signature.raw", "wc");
    assert(NULL != f);
    assert(siglen == fwrite(sigret, 1, siglen, f));
    fclose(f);

    assert(1 == RSA_verify(NID_rsassaPss, digest, SHA256_DIGEST_LENGTH, sigret, siglen, rsa));

    RSA_free(rsa);
}


TEST_CASE("RSA_SIGN-c") {
    RSA *rsa = RSA_new();
    BIGNUM *bn = BN_new();
    BN_set_word(bn, RSA_F4);

    int ret = RSA_generate_key_ex(rsa, 2048, bn, NULL);
    assert(0 != ret);

    SHA256_CTX *sha_ctx = (SHA256_CTX *) alloca(sizeof(SHA256_CTX));
    memset(sha_ctx, 0, sizeof(SHA256_CTX));
    assert(NULL != sha_ctx);
    SHA256_Init(sha_ctx);

    const char *msg_to_sign = "Hello, World";
    const size_t len = strlen(msg_to_sign);

    SHA256_Update(sha_ctx, msg_to_sign, len);
    unsigned char *digest = (unsigned char *) alloca(SHA256_DIGEST_LENGTH);
    memset(digest, 0, SHA256_DIGEST_LENGTH);
    SHA256_Final(digest, sha_ctx);

    int rsa_size = RSA_size(rsa);
    unsigned char *sigret = (unsigned char *) alloca(rsa_size);
    unsigned int siglen = 0;
    memset(sigret, 0, rsa_size);

    assert(1 == RSA_sign(NID_RSA_SHA3_256, digest, SHA256_DIGEST_LENGTH, sigret, &siglen, rsa));

    FILE *f = fopen("/tmp/signature.raw", "wc");
    assert(NULL != f);
    assert(siglen == fwrite(sigret, 1, siglen, f));
    fclose(f);

    RSA_free(rsa);
}

TEST_CASE("RSA_KEYGEN") {
    for (auto size: std::array<int, 3>{2048, 4096, 4096 * 2}) {
        std::cout << "Key size: " << size << "\n";
        auto rsaKey = Facade::rsa(size);
        std::cout << RsaUtils::dumpKey(rsaKey);
    }
}

TEST_CASE("RSA_PEM_STR") {
    auto rsaKey = Facade::rsa(2048);
    auto str = RsaUtils::pemPrivateKey(rsaKey);
    std::cout << str;
}

TEST_CASE("RSA_SIGN") {
    auto rsaKey = Facade::rsa(1024);
    auto signature = RsaUtils::signSha1(rsaKey, "Hello, World!");
    std::cout << std::string{reinterpret_cast<const char *>(signature.data()), signature.size()};
}