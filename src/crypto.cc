#include<node.h>
#include <node_buffer.h>

#include "integrity.cc"

v8::Local<v8::Value> CalculateHAMCPromise(v8::Local<v8::Promise::Resolver> resolver, v8::Isolate* isolate, v8::Local<v8::Object> data) {

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
          resolver->Reject(isolate->GetCurrentContext(), v8::String::NewFromUtf8(isolate, "Unable to calculate HMAC", v8::NewStringType::kNormal).ToLocalChecked());
      } else {
          resolver->Resolve(isolate->GetCurrentContext(), node::Buffer::New(isolate, reinterpret_cast<char*>(signedValue), signedValueLen).ToLocalChecked());
      }

     v8::Local<v8::Promise> promise = resolver->GetPromise();

     return promise->Result();
}


void CalculateHMAC(const v8::FunctionCallbackInfo<v8::Value>& info) {
     v8::Isolate* isolate = info.GetIsolate();
     v8::Local<v8::Object> data = info[0].As<v8::Object>()->ToObject(isolate->GetCurrentContext()).ToLocalChecked();
     
     v8::Local<v8::Promise::Resolver> resolver = v8::Promise::Resolver::New(isolate->GetCurrentContext()).ToLocalChecked();
     
     resolver->Resolve(isolate->GetCurrentContext(), CalculateHAMCPromise(resolver, isolate, data));
     info.GetReturnValue().Set(resolver->GetPromise());
}


NODE_MODULE_INIT() {
      v8::Isolate* isolate = context->GetIsolate();

      exports->Set(context, v8::String::NewFromUtf8(isolate, "calculateHMAC", v8::NewStringType::kNormal).ToLocalChecked(), v8::Function::New(context, CalculateHMAC).ToLocalChecked()).FromJust();
}