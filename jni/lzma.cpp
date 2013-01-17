#include <jni.h>
#include <string.h>

typedef unsigned short char16_t;

class String8 {
public:
    String8() {
        mString = 0;
    }

    ~String8() {
        if (mString) {
            free(mString);
        }
    }

    void set(const char16_t* o, size_t numChars) {
        if (mString) {
            free(mString);
        }
        mString = (char*) malloc(numChars + 1);
        if (!mString) {
            return;
        }
        for (size_t i = 0; i < numChars; i++) {
            mString[i] = (char) o[i];
        }
        mString[numChars] = '\0';
    }

    const char* string() {
        return mString;
    }
private:
    char* mString;
};

extern "C" {

int lzma_main(int args, char* argc[]);

jint Java_org_gaeproxy_LZMA_extract(JNIEnv *env, jobject thiz, jobjectArray argc) {

    int args = argc ? env->GetArrayLength(argc) : 0;
    char **lzma_argc = NULL;
    String8 tmp_8;

    if (args > 0) {
        lzma_argc = (char **)malloc((args+1)*sizeof(char *));
        for (int i = 0; i < args; ++i) {
            jstring arg = reinterpret_cast<jstring>(env->GetObjectArrayElement(argc, i));
            const jchar *str = env->GetStringCritical(arg, 0);
            tmp_8.set(str, env->GetStringLength(arg));
            env->ReleaseStringCritical(arg, str);
            lzma_argc[i] = strdup(tmp_8.string());
        }
        lzma_argc[args] = NULL;
    }

    int ret = lzma_main(args, lzma_argc);

    free(lzma_argc);
    return ret;
}

}
