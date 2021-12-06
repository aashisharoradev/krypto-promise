#pragma once

#include<node.h>
#include <node_buffer.h>
#include <iostream>
#include "integrity.cc"
#include "keygen.cc"

#define CRYPTO_METHOD(jsName, name) \
                            exports->Set(context, v8::String::NewFromUtf8(isolate, jsName ,\
                            v8::NewStringType::kNormal).ToLocalChecked(), \
                            v8::Function::New(context, name).ToLocalChecked()).FromJust();
