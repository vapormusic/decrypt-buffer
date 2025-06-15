#include <map>
#include <napi.h>
#include "Ap4CommonEncryption.h"

void CleanUp(Napi::Env /*env*/, char* /*data*/, AP4_MemoryByteStream* stream) {
  if (stream) stream->Release();
}

class DecryptWorker : public Napi::AsyncWorker {
  private:
    AP4_MemoryByteStream* input;
    Napi::Reference<Napi::Buffer<char>> input_ref;
    AP4_MemoryByteStream* output;
    AP4_ProtectionKeyMap key_map;

  public:
    DecryptWorker(Napi::Function& callback, Napi::Buffer<char> buffer, std::map<std::string, std::string>& keys)
        : Napi::AsyncWorker(callback) {
          input_ref = Napi::Persistent(buffer);
          input_ref.SuppressDestruct();
          AP4_UI08* inputData = reinterpret_cast<AP4_UI08*>(buffer.Data());
          input = new AP4_MemoryByteStream(inputData, buffer.ByteLength());
          std::map<std::string, std::string>::iterator it;

          for (it = keys.begin(); it != keys.end(); it++) {
            unsigned char kid[16];
            unsigned char key[16];
            AP4_ParseHex(it->first.c_str(), kid, 16);
            AP4_ParseHex(it->second.c_str(), key, 16);
            key_map.SetKeyForKid(kid, key, 16);
          }
         }
    ~DecryptWorker() {}

    // Executed inside the worker-thread.
    // It is not safe to access JS engine data structure
    // here, so everything we need for input and output
    // should go on `this`.
    void Execute() {
      input->Seek(0);
      output = new AP4_MemoryByteStream();

      AP4_Processor* processor = new AP4_CencDecryptingProcessor(&key_map);
      AP4_Result result = processor->Process(*input, *output, NULL);
      delete processor;
      input->Release();

      if (AP4_FAILED(result)) {
        SetError("Decryption failed");
      }
    }

    // Executed when the async work is complete
    // this function will be run inside the main event loop
    // so it is safe to use JS engine data again
    void OnOK() {
      char* resultData = const_cast<char*>(reinterpret_cast<const char*>(output->GetData()));
      Napi::Buffer<char> outBuffer = Napi::Buffer<char>::New(
        Env(),
        resultData,
        output->GetDataSize(),
        CleanUp,
        output
      );

      Callback().Call({Env().Null(), outBuffer});
      input_ref.Unref();
    }

    void OnError(const Napi::Error& e) {
      Callback().Call({e.Value(), Env().Undefined()});
      input_ref.Unref();
    }
};

Napi::Value Decrypt(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (info.Length() < 3) {
    Napi::TypeError::New(env, "Wrong number of arguments")
        .ThrowAsJavaScriptException();
    return env.Null();
  }

  if (!info[0].IsBuffer() || !info[1].IsObject() || !info[2].IsFunction()) {
    Napi::TypeError::New(env, "Wrong arguments")
        .ThrowAsJavaScriptException();
    return env.Null();
  }

  Napi::Buffer<char> buffer = info[0].As<Napi::Buffer<char>>();
  Napi::Object keysObject = info[1].As<Napi::Object>();
  Napi::Function callback = info[2].As<Napi::Function>();

  std::map<std::string, std::string> keys;

  Napi::Array kids = keysObject.GetPropertyNames();
  for (uint32_t i = 0; i < kids.Length(); i++) {
    Napi::String hex_kid = kids.Get(i).ToString();
    Napi::String hex_key = keysObject.Get(hex_kid).ToString();
    keys[hex_kid.Utf8Value()] = hex_key.Utf8Value();
  }

  DecryptWorker* worker = new DecryptWorker(callback, buffer, keys);
  worker->Queue();

  return env.Undefined();
}

Napi::Object Init (Napi::Env env, Napi::Object exports) {
  exports.Set(Napi::String::New(env, "decrypt"),
              Napi::Function::New(env, Decrypt));
  return exports;
}

NODE_API_MODULE(NODE_GYP_MODULE_NAME, Init)
