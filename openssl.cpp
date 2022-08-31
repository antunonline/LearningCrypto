//
// Created by ahorvat on 31.08.22..
//
#include "catch.hpp"
#include "openssl/rsa.h"
#include "memory"
#include <exception>
#include <utility>
#include <iostream>

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


class RsaUtils {
public:
    using PTR = std::unique_ptr<RSA, RSA_DESTRUCTOR>;

    static PTR make() {
        return PTR{RSA_new()};
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
    static RsaUtils::PTR rsa() {
        auto rsa = RsaUtils::make();
        auto bn = BnUtils::make();
        BN_set_word(bn.get(), RSA_F4);

        auto ret = RSA_generate_key_ex(rsa.get(), 2048, bn.get(), NULL);
        if (!ret) {
            throw SSLException("RSA_generate_key_ex", ret);
        }

        return rsa;
    }
};

struct STR_DESTRUCTOR {
    void operator()(char *c) {
        OPENSSL_free(c);
    }
};

using STRPTR = std::unique_ptr<char, STR_DESTRUCTOR>;

TEST_CASE("RSA_KEYGEN") {

    auto rsaKey = Facade::rsa();
    auto d = RSA_get0_d(rsaKey.get());
    auto p = RSA_get0_p(rsaKey.get());
    auto q = RSA_get0_q(rsaKey.get());
    auto hex_d = STRPTR{BN_bn2hex(d)};
    auto hex_p = STRPTR{BN_bn2hex(p)};
    auto hex_q = STRPTR{BN_bn2hex(q)};


    std::cout << "d: " << hex_d.get() << "\n"
              << "p: " << hex_p.get() << "\n"
              << "q: " << hex_q.get() << "\n";

}