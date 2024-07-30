#include <android/log.h>
#include <sys/system_properties.h>
#include <string>
#include <vector>
#include <sstream>
#include <unistd.h>
#include "zygisk.hpp"

#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, "KeystoreInjection", __VA_ARGS__)

#define CLASSES_DEX "/data/adb/modules/keystoreinjection/classes.dex"
#define APPLIST_FILE_PATH "/data/adb/keystoreinjection/targetlist"
#define KEYBOX_FILE_PATH "/data/adb/keystoreinjection/keybox.xml"
#define PIF_JSON "/data/adb/keystoreinjection/pif.json"

ssize_t xread(int fd, void *buffer, size_t count) {
    ssize_t total = 0;
    char *buf = (char *)buffer;
    while (count > 0) {
        ssize_t ret = read(fd, buf, count);
        if (ret < 0) return -1;
        buf += ret;
        total += ret;
        count -= ret;
    }
    return total;
}

ssize_t xwrite(int fd, void *buffer, size_t count) {
    ssize_t total = 0;
    char *buf = (char *)buffer;
    while (count > 0) {
        ssize_t ret = write(fd, buf, count);
        if (ret < 0) return -1;
        buf += ret;
        total += ret;
        count -= ret;
    }
    return total;
}

std::vector<std::string> split(const std::string &strTotal) {
    std::vector<std::string> vecResult;
    std::istringstream iss(strTotal);
    std::string token;

    while (std::getline(iss, token, '\n')) {
        vecResult.push_back("/" + token);
    }

    return std::move(vecResult);
}

class KeystoreInjection : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);

        if (!args) return;

        const char *rawDir = env->GetStringUTFChars(args->app_data_dir, nullptr);
        if (!rawDir) return;

        std::string dir(rawDir);
        env->ReleaseStringUTFChars(args->app_data_dir, rawDir);

        int fd = api->connectCompanion();

        long applistSize = 0;
        xread(fd, &applistSize, sizeof(long));

        if (applistSize < 1) {
            close(fd);
            return;
        }

        std::vector<uint8_t> applistVector;
        applistVector.resize(applistSize);
        xread(fd, applistVector.data(), applistSize);

        std::string applist(applistVector.begin(), applistVector.end());
        std::vector<std::string> splitlist = split(applist);

        bool found = false;
        for (const std::string &app : splitlist) {
            if (dir.ends_with(app)) {
                found = true;
                break;
            }
        }

        if (!found) {
            close(fd);
            return;
        }

        long dexSize = 0, xmlSize = 0, jsonSize = 0;

        xread(fd, &dexSize, sizeof(long));
        xread(fd, &xmlSize, sizeof(long));
        xread(fd, &jsonSize, sizeof(long));

        LOGD("Dex file size: %ld", dexSize);
        LOGD("Xml file size: %ld", xmlSize);
        LOGD("Json file size: %ld", jsonSize);

        if (dexSize < 1 || xmlSize < 1) {
            close(fd);
            return;
        }

        dexVector.resize(dexSize);
        xread(fd, dexVector.data(), dexSize);

        std::vector<uint8_t> xmlVector;
        xmlVector.resize(xmlSize);
        xread(fd, xmlVector.data(), xmlSize);

        if (jsonSize > 0) {
            jsonVector.resize(jsonSize);
            xread(fd, jsonVector.data(), jsonSize);
        }

        close(fd);

        std::string xmlString(xmlVector.begin(), xmlVector.end());
        xml = xmlString;

        if (!jsonVector.empty()) {
            json = std::string(jsonVector.begin(), jsonVector.end());
        }
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        if (dexVector.empty() || xml.empty()) return;
        injectDex();
    }

    void preServerSpecialize(zygisk::ServerSpecializeArgs *args) override {
        api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
    }

private:
    zygisk::Api *api = nullptr;
    JNIEnv *env = nullptr;
    std::vector<uint8_t> dexVector;
    std::vector<uint8_t> jsonVector;
    std::string xml;
    std::string json;

    void injectDex() {
        LOGD("get system classloader");
        auto clClass = env->FindClass("java/lang/ClassLoader");
        auto getSystemClassLoader = env->GetStaticMethodID(clClass, "getSystemClassLoader",
                                                           "()Ljava/lang/ClassLoader;");
        auto systemClassLoader = env->CallStaticObjectMethod(clClass, getSystemClassLoader);

        LOGD("create class loader");
        auto dexClClass = env->FindClass("dalvik/system/InMemoryDexClassLoader");
        auto dexClInit = env->GetMethodID(dexClClass, "<init>",
                                          "(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V");
        auto buffer = env->NewDirectByteBuffer(dexVector.data(), dexVector.size());
        auto dexCl = env->NewObject(dexClClass, dexClInit, buffer, systemClassLoader);

        LOGD("load class");
        auto loadClass = env->GetMethodID(clClass, "loadClass",
                                          "(Ljava/lang/String;)Ljava/lang/Class;");
        auto entryClassName = env->NewStringUTF("io.github.aviraxp.keystoreinjection.EntryPoint");
        auto entryClassObj = env->CallObjectMethod(dexCl, loadClass, entryClassName);

        auto entryPointClass = (jclass) entryClassObj;

        LOGD("receive xml");
        auto receiveXml = env->GetStaticMethodID(entryPointClass, "receiveXml", "(Ljava/lang/String;)V");
        auto xmlString = env->NewStringUTF(xml.c_str());
        env->CallStaticVoidMethod(entryPointClass, receiveXml, xmlString);

        if (!json.empty()) {
            LOGD("receive json");
            auto receiveJson = env->GetStaticMethodID(entryPointClass, "receiveJson", "(Ljava/lang/String;)V");
            auto jsonString = env->NewStringUTF(json.c_str());
            env->CallStaticVoidMethod(entryPointClass, receiveJson, jsonString);
        }
    }
};

static std::vector<uint8_t> readFile(const char *path) {
    std::vector<uint8_t> vector;

    FILE *file = fopen(path, "rb");

    if (file) {
        fseek(file, 0, SEEK_END);
        long size = ftell(file);
        fseek(file, 0, SEEK_SET);

        vector.resize(size);
        fread(vector.data(), 1, size, file);
        fclose(file);
    } else {
        LOGD("Couldn't read %s file!", path);
    }

    return vector;
}

static void companion(int fd) {
    std::vector<uint8_t> applistVector, dexVector, xmlVector, jsonVector;

    applistVector = readFile(APPLIST_FILE_PATH);
    dexVector = readFile(CLASSES_DEX);
    xmlVector = readFile(KEYBOX_FILE_PATH);
    jsonVector = readFile(PIF_JSON);

    long applistSize = applistVector.size();
    long dexSize = dexVector.size();
    long xmlSize = xmlVector.size();
    long jsonSize = jsonVector.size();

    xwrite(fd, &applistSize, sizeof(long));
    // Write applist earlier, so we can avoid reading dex for unrelated apps
    xwrite(fd, applistVector.data(), applistSize);

    xwrite(fd, &dexSize, sizeof(long));
    xwrite(fd, &xmlSize, sizeof(long));
    xwrite(fd, &jsonSize, sizeof(long));

    xwrite(fd, dexVector.data(), dexSize);
    xwrite(fd, xmlVector.data(), xmlSize);
    xwrite(fd, jsonVector.data(), jsonSize);
}

REGISTER_ZYGISK_MODULE(KeystoreInjection)

REGISTER_ZYGISK_COMPANION(companion)
