#include "crypto.h"

v8::Local<v8::Value> createHMAC(v8::Local<v8::Promise::Resolver> resolver, v8::Isolate* isolate, v8::Local<v8::Object> data) {

     v8::Local<v8::Value> keyObject = data->Get(isolate->GetCurrentContext(), v8::String::NewFromUtf8(isolate, "key", v8::NewStringType::kNormal).ToLocalChecked()).ToLocalChecked();
     v8::Local<v8::Value> messageObject = data->Get(isolate->GetCurrentContext(), v8::String::NewFromUtf8(isolate, "message", v8::NewStringType::kNormal).ToLocalChecked()).ToLocalChecked();
     v8::Local<v8::Value> alg = data->Get(isolate->GetCurrentContext(), v8::String::NewFromUtf8(isolate, "alg", v8::NewStringType::kNormal).ToLocalChecked()).ToLocalChecked();
    
     const unsigned char* key = reinterpret_cast<const unsigned char*>(node::Buffer::Data(keyObject));
     size_t keyLength = node::Buffer::Length(keyObject);
    
     unsigned char* message = reinterpret_cast<unsigned char*>(node::Buffer::Data(messageObject));
     size_t messageLength = node::Buffer::Length(messageObject);

     
     EVP_PKEY* hmackey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key, keyLength);
     
     unsigned char* signedValue;
     size_t signedValueLen = 0;

     const char* hmacalg = *v8::String::Utf8Value(isolate, alg);
     int result = crypto::hmac_it(message, messageLength, &signedValue, &signedValueLen, hmackey, hmacalg);

     EVP_PKEY_free(hmackey);

      if (result != 1) {
          resolver->Reject(isolate->GetCurrentContext(), 
            v8::String::NewFromUtf8(isolate, "Unable to calculate HMAC", v8::NewStringType::kNormal).ToLocalChecked()).FromJust();
      } else {
          resolver->Resolve(isolate->GetCurrentContext(), 
            node::Buffer::New(isolate, reinterpret_cast<char*>(signedValue), signedValueLen).ToLocalChecked()).FromJust();
      }

     v8::Local<v8::Promise> promise = resolver->GetPromise();

     return promise->Result();
}

v8::Local<v8::Value> createRSAKeyPair(v8::Local<v8::Promise::Resolver> resolver, v8::Isolate* isolate, v8::Local<v8::Object> data) {
      v8::Local<v8::Value> modulusBitValue = data->Get(
                                     isolate->GetCurrentContext(),
                                     v8::String::NewFromUtf8(isolate, "modulusBits",
                                                             v8::NewStringType::kNormal)
                                         .ToLocalChecked())
                                 .FromMaybe(v8::Local<v8::Value>());

      double modulusBits = modulusBitValue->ToNumber(isolate->GetCurrentContext()).ToLocalChecked()->Value();

      RSA *keyPair = crypto::createRSAKeyPair(modulusBits);
      const BIGNUM* bigNumModulus = RSA_get0_n(keyPair);
      char *modulus = BN_bn2hex(bigNumModulus);
      int modLength = BN_num_bytes(bigNumModulus);
      v8::Local<v8::String> modulusLocal = v8::String::NewFromUtf8(isolate, modulus, v8::NewStringType::kNormal, modLength*2).ToLocalChecked();

      const BIGNUM *bigNumExponent = RSA_get0_e(keyPair);
      char* exponent = BN_bn2hex(bigNumExponent);
      int exponentLength = BN_num_bytes(bigNumExponent);
      v8::Local<v8::String> expLocal = v8::String::NewFromUtf8(isolate, exponent, v8::NewStringType::kNormal, exponentLength*2).ToLocalChecked();

      const BIGNUM *bigNumPrivate = RSA_get0_d(keyPair);
      char* privateKey = BN_bn2hex(bigNumPrivate);
      int privateKeyLength = BN_num_bytes(bigNumPrivate);
      v8::Local<v8::String> privateKeyLocal = v8::String::NewFromUtf8(isolate, privateKey, v8::NewStringType::kNormal, privateKeyLength*2).ToLocalChecked();


      RSA_free(keyPair);

      v8::Local<v8::Object> keyPairObject = v8::Object::New(isolate);
      
      keyPairObject->CreateDataProperty(isolate->GetCurrentContext(),
                        v8::String::NewFromUtf8(isolate, "modulus", v8::NewStringType::kNormal).ToLocalChecked(),
                        node::Buffer::New(isolate, modulusLocal, node::encoding::HEX).ToLocalChecked()).FromJust();

      keyPairObject->CreateDataProperty(isolate->GetCurrentContext(),
                        v8::String::NewFromUtf8(isolate, "exponent", v8::NewStringType::kNormal).ToLocalChecked(),
                        node::Buffer::New(isolate, expLocal, node::encoding::HEX).ToLocalChecked()).FromJust();
      
      keyPairObject->CreateDataProperty(isolate->GetCurrentContext(),
                        v8::String::NewFromUtf8(isolate, "privateKey", v8::NewStringType::kNormal).ToLocalChecked(),
                        node::Buffer::New(isolate, privateKeyLocal, node::encoding::HEX).ToLocalChecked()).FromJust();

      resolver->Resolve(isolate->GetCurrentContext(), keyPairObject).FromJust();

      v8::Local<v8::Promise> promise = resolver->GetPromise();

      return promise->Result();
}


void HMAC(const v8::FunctionCallbackInfo<v8::Value>& info) {
     v8::Isolate* isolate = info.GetIsolate();
     v8::Local<v8::Object> data = info[0].As<v8::Object>()->ToObject(isolate->GetCurrentContext()).ToLocalChecked();
     
     v8::Local<v8::Promise::Resolver> resolver = v8::Promise::Resolver::New(isolate->GetCurrentContext()).ToLocalChecked();
     
     resolver->Resolve(isolate->GetCurrentContext(), 
        createHMAC(resolver, isolate, data)).FromJust();
     info.GetReturnValue().Set(resolver->GetPromise());
}


void GenerateRSAKeyPair(const v8::FunctionCallbackInfo<v8::Value>& info) {
      v8::Isolate* isolate = info.GetIsolate();
      v8::Local<v8::Object> data = info[0].As<v8::Object>()->ToObject(isolate->GetCurrentContext()).ToLocalChecked();
     
      v8::Local<v8::Promise::Resolver> resolver = v8::Promise::Resolver::New(isolate->GetCurrentContext()).ToLocalChecked();

      resolver->Resolve(isolate->GetCurrentContext(), 
        createRSAKeyPair(resolver, isolate, data)).FromJust();
      info.GetReturnValue().Set(resolver->GetPromise());
}


NODE_MODULE_INIT() {
      v8::Isolate* isolate = context->GetIsolate();
      CRYPTO_METHOD("calculateHMAC", HMAC)

      CRYPTO_METHOD("generateRSAKeyPair", GenerateRSAKeyPair)
}