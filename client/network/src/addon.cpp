#include <napi.h>
#include "MessageClient.hpp"

static std::string strArg(const Napi::CallbackInfo& info, size_t idx, const char* name) {
    if (idx >= info.Length() || !info[idx].IsString()) {
        Napi::TypeError::New(info.Env(), std::string("Expected string for ") + name)
            .ThrowAsJavaScriptException();
        return "";
    }
    return info[idx].As<Napi::String>().Utf8Value();
}

static int intArg(const Napi::CallbackInfo& info, size_t idx, const char* name) {
    if (idx >= info.Length() || !info[idx].IsNumber()) {
        Napi::TypeError::New(info.Env(), std::string("Expected number for ") + name)
            .ThrowAsJavaScriptException();
        return 0;
    }
    return info[idx].As<Napi::Number>().Int32Value();
}

// registerUser(host, port, username, password, publicKeyJson) → undefined
Napi::Value RegisterUser(const Napi::CallbackInfo& info) {
    auto env       = info.Env();
    auto host      = strArg(info, 0, "host");
    auto port      = intArg(info, 1, "port");
    auto username  = strArg(info, 2, "username");
    auto password  = strArg(info, 3, "password");
    auto publicKey = strArg(info, 4, "publicKeyJson");
    if (env.IsExceptionPending()) return env.Undefined();
    try {
        MessageClient client(host, port);
        client.registerUser(username, password, publicKey);
    } catch (const std::exception& e) {
        Napi::Error::New(env, e.what()).ThrowAsJavaScriptException();
    }
    return env.Undefined();
}

// login(host, port, username, password) → token string
Napi::Value Login(const Napi::CallbackInfo& info) {
    auto env      = info.Env();
    auto host     = strArg(info, 0, "host");
    auto port     = intArg(info, 1, "port");
    auto username = strArg(info, 2, "username");
    auto password = strArg(info, 3, "password");
    if (env.IsExceptionPending()) return env.Undefined();
    try {
        MessageClient client(host, port);
        client.login(username, password);
        return Napi::String::New(env, client.getAuthToken());
    } catch (const std::exception& e) {
        Napi::Error::New(env, e.what()).ThrowAsJavaScriptException();
        return env.Undefined();
    }
}

// sendMessage(host, port, token, recipient, ciphertext, nonce, header, signature, digest) → JSON string
Napi::Value SendMessage(const Napi::CallbackInfo& info) {
    auto env        = info.Env();
    auto host       = strArg(info, 0, "host");
    auto port       = intArg(info, 1, "port");
    auto token      = strArg(info, 2, "token");
    auto recipient  = strArg(info, 3, "recipient");
    auto ciphertext = strArg(info, 4, "ciphertext");
    auto nonce      = strArg(info, 5, "nonce");
    auto header     = strArg(info, 6, "header");
    auto signature  = strArg(info, 7, "signature");
    auto digest     = strArg(info, 8, "digest");
    if (env.IsExceptionPending()) return env.Undefined();
    try {
        MessageClient client(host, port);
        client.setAuthToken(token);
        std::string response = client.sendMessage(recipient, ciphertext, nonce, header, signature, digest);
        return Napi::String::New(env, response);
    } catch (const std::exception& e) {
        Napi::Error::New(env, e.what()).ThrowAsJavaScriptException();
        return env.Undefined();
    }
}

// fetchMessages(host, port, token) → raw JSON string
Napi::Value FetchMessages(const Napi::CallbackInfo& info) {
    auto env   = info.Env();
    auto host  = strArg(info, 0, "host");
    auto port  = intArg(info, 1, "port");
    auto token = strArg(info, 2, "token");
    if (env.IsExceptionPending()) return env.Undefined();
    try {
        MessageClient client(host, port);
        client.setAuthToken(token);
        return Napi::String::New(env, client.fetchMessages());
    } catch (const std::exception& e) {
        Napi::Error::New(env, e.what()).ThrowAsJavaScriptException();
        return env.Undefined();
    }
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
    exports.Set("registerUser",  Napi::Function::New(env, RegisterUser));
    exports.Set("login",         Napi::Function::New(env, Login));
    exports.Set("sendMessage",   Napi::Function::New(env, SendMessage));
    exports.Set("fetchMessages", Napi::Function::New(env, FetchMessages));
    return exports;
}

NODE_API_MODULE(messaging_client, Init)
