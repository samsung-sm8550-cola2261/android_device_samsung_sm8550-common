// SPDX-License-Identifier: Apache-2.0
//
// Wrap Samsung libsec-ril.so:
// 1) Force NULL SMSC only for legacy CS SMS requests (IMS untouched).
// 2) Trigger tsds2 eSIM slot switch via OEM SEC_SIM_LOW_LEVEL_CONTROL when
//    vendor.calls.esim_switch is set to 0/1.
//
// OEM 0x10 on RIL_SOCKET_1 flips ril.simslottype2=1 and RIL publishes EID via
// GET_SLOT_STATUS. Do NOT thrash RADIO_POWER / SET_SIM_CARD_POWER on the
// primary socket — that knocks the pSIM offline and races SlotStatus.
// Ready == simslottype2==1 (EID appears with the type flip).

#define LOG_TAG "sec-ril-shim"

#include <dlfcn.h>
#include <pthread.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <mutex>

#include <log/log.h>
#include <sys/system_properties.h>
#include <telephony/ril.h>

#ifndef REAL_LIB_NAME
#error "REAL_LIB_NAME must be defined by Android.bp"
#endif

#ifndef RIL_REQUEST_SEND_SMS
#define RIL_REQUEST_SEND_SMS 25
#endif

#ifndef RIL_REQUEST_SEND_SMS_EXPECT_MORE
#define RIL_REQUEST_SEND_SMS_EXPECT_MORE 26
#endif

#ifndef RIL_REQUEST_OEM_HOOK_RAW
#define RIL_REQUEST_OEM_HOOK_RAW 59
#endif

#ifndef RIL_REQUEST_SET_SIM_CARD_POWER
#define RIL_REQUEST_SET_SIM_CARD_POWER 140
#endif

#ifndef RIL_REQUEST_RADIO_POWER
#define RIL_REQUEST_RADIO_POWER 23
#endif

#ifndef RIL_REQUEST_SIM_TRANSMIT_APDU_BASIC
#define RIL_REQUEST_SIM_TRANSMIT_APDU_BASIC 114
#endif

#ifndef RIL_REQUEST_SIM_OPEN_CHANNEL
#define RIL_REQUEST_SIM_OPEN_CHANNEL 115
#endif

#ifndef RIL_REQUEST_SIM_CLOSE_CHANNEL
#define RIL_REQUEST_SIM_CLOSE_CHANNEL 116
#endif

#ifndef RIL_REQUEST_SIM_TRANSMIT_APDU_CHANNEL
#define RIL_REQUEST_SIM_TRANSMIT_APDU_CHANNEL 117
#endif

#ifndef RIL_REQUEST_GET_SIM_STATUS
#define RIL_REQUEST_GET_SIM_STATUS 1
#endif

static constexpr char kRealPath[] = "/vendor/lib64/" REAL_LIB_NAME;
static constexpr char kEsimSwitchProp[] = "vendor.calls.esim_switch";
static constexpr char kEsimReadyProp[] = "vendor.calls.esim_ready";
static constexpr char kSimSlotType2[] = "ril.simslottype2";
static constexpr char kEsimDbgProp[] = "vendor.calls.esim_dbg";
static constexpr char kEfsEidPath[] = "/efs/FactoryApp/eID";
static constexpr char kIsdrAid[] = "A0000005591010FFFFFFFF8900000100";

// Cached EID hex from EFS (32 chars). Used to synthesize GetEID APDU
// responses so EuiccCard.mCardId is populated without framework changes.
static char gEidHex[64] = {};
static bool gEidLoaded = false;

// Track OPEN/TRANSMIT/CLOSE so response SW / channel id land in logcat + dbg.
struct TrackedApdu {
    RIL_Token token = nullptr;
    int request = 0;
    int socketId = -1;
    char tag[8] = {};
};

static constexpr int kTrackedApduSlots = 24;
static TrackedApdu gTrackedApdu[kTrackedApduSlots];
static std::mutex gTrackMu;

// SEC_SIM_LOW_LEVEL_CONTROL: opcode 0x06001415, payload 01 <type>
// 0x10 = switch hybrid slot to eSIM; 0x11 = back to physical.
// 0x20 = Samsung post-switch follow-up (ExecuteSlotSwitch soft path).
static constexpr uint8_t kOemTypeEsim = 0x10;
static constexpr uint8_t kOemTypePsim = 0x11;
static constexpr uint8_t kOemTypeFollowUp = 0x20;

using SamsungRequestFunc = void (*)(
        int, void*, size_t, RIL_Token, RIL_SOCKET_ID);

struct SamsungRilFunctionsPrefix {
    int version;
    SamsungRequestFunc onRequest;
};

static_assert(
        offsetof(SamsungRilFunctionsPrefix, onRequest) == sizeof(void*),
        "unexpected Samsung RIL function-table prefix");

using RilInit = const RIL_RadioFunctions* (*)(
        const RIL_Env*, int, char**);

static void* gRealHandle = nullptr;
static SamsungRequestFunc gRealOnRequest = nullptr;
static RIL_Env gRealEnv{};
static RIL_Env gShimEnv{};
static int gShimTokenStorage = 0;
static RIL_Token gShimToken = &gShimTokenStorage;
static std::atomic<bool> gWatcherStarted{false};

static std::mutex gReqMu;
static std::condition_variable gReqCv;
static bool gAwaitingComplete = false;
static int gCompleteErrno = 0;

#if defined(ANDROID_MULTI_SIM)
static constexpr RIL_SOCKET_ID kOemSocket = RIL_SOCKET_1;
static constexpr RIL_SOCKET_ID kEuiccSocket = RIL_SOCKET_2;
#else
static constexpr RIL_SOCKET_ID kOemSocket = static_cast<RIL_SOCKET_ID>(0);
static constexpr RIL_SOCKET_ID kEuiccSocket = static_cast<RIL_SOCKET_ID>(0);
#endif

static void dbg(const char* msg) {
    __system_property_set(kEsimDbgProp, msg);
    ALOGI("%s", msg);
}

static void dbgResult(const char* step, bool ok, int err) {
    char buf[PROP_VALUE_MAX];
    // Keep under PROP_VALUE_MAX; include errno for live diagnosis without logcat.
    std::snprintf(buf, sizeof(buf), "%s:%s:e%d", step, ok ? "ok" : "fail", err);
    dbg(buf);
}

static bool isApduDiagRequest(int request) {
    return request == RIL_REQUEST_SIM_OPEN_CHANNEL
            || request == RIL_REQUEST_SIM_CLOSE_CHANNEL
            || request == RIL_REQUEST_SIM_TRANSMIT_APDU_CHANNEL
            || request == RIL_REQUEST_SIM_TRANSMIT_APDU_BASIC;
}

static const char* classifyApduData(const char* dataHex) {
    if (dataHex == nullptr) {
        return "none";
    }
    // Prefer ES10 tags we care about for profile download.
    if (std::strstr(dataHex, "BF22") != nullptr) return "BF22";  // EuiccInfo2
    if (std::strstr(dataHex, "BF2D") != nullptr) return "BF2D";  // GetProfiles
    if (std::strstr(dataHex, "BF3E") != nullptr) return "BF3E";  // GetEID / GetEuiccData
    if (std::strstr(dataHex, "BF20") != nullptr) return "BF20";  // EuiccInfo1
    if (std::strstr(dataHex, "BF38") != nullptr) return "BF38";  // AuthenticateServer
    if (std::strstr(dataHex, "BF36") != nullptr) return "BF36";  // PrepareDownload
    if (std::strstr(dataHex, "BF31") != nullptr) return "BF31";  // EnableProfile
    if (std::strstr(dataHex, "BF32") != nullptr) return "BF32";  // DisableProfile
    return "other";
}

static void trackApduRequest(
        RIL_Token token, int request, int socketId, const char* tag) {
    std::lock_guard<std::mutex> lock(gTrackMu);
    for (int i = 0; i < kTrackedApduSlots; ++i) {
        if (gTrackedApdu[i].token == nullptr) {
            gTrackedApdu[i].token = token;
            gTrackedApdu[i].request = request;
            gTrackedApdu[i].socketId = socketId;
            std::snprintf(gTrackedApdu[i].tag, sizeof(gTrackedApdu[i].tag),
                    "%s", tag != nullptr ? tag : "?");
            return;
        }
    }
    // Overwrite slot 0 if full — diagnostics still beat silence.
    gTrackedApdu[0].token = token;
    gTrackedApdu[0].request = request;
    gTrackedApdu[0].socketId = socketId;
    std::snprintf(gTrackedApdu[0].tag, sizeof(gTrackedApdu[0].tag),
            "%s", tag != nullptr ? tag : "?");
}

static bool takeTrackedApdu(RIL_Token token, TrackedApdu* out) {
    std::lock_guard<std::mutex> lock(gTrackMu);
    for (int i = 0; i < kTrackedApduSlots; ++i) {
        if (gTrackedApdu[i].token == token) {
            *out = gTrackedApdu[i];
            gTrackedApdu[i] = TrackedApdu{};
            return true;
        }
    }
    return false;
}

// AOSP TransmitApduLogicalChannelInvocation does: cla | channel.
// Samsung OPEN_CHANNEL returns session ids like 101 (not ISO channel 1..19).
// That yields CLA 0xE5 for STORE DATA (0x80|101) and the card returns 6986.
// Modem +CGLA already keys off sessionid — strip the bogus OR from CLA.
static bool fixupSamsungApduCla(int request, void* data, size_t datalen) {
    if (request != RIL_REQUEST_SIM_TRANSMIT_APDU_CHANNEL
            && request != RIL_REQUEST_SIM_TRANSMIT_APDU_BASIC) {
        return false;
    }
    if (data == nullptr || datalen < sizeof(RIL_SIM_APDU)) {
        return false;
    }
    auto* apdu = static_cast<RIL_SIM_APDU*>(data);
    if (apdu->sessionid <= 3) {
        return false;  // Normal ISO channel — AOSP CLA encoding is fine.
    }
    const int before = apdu->cla;
    // Invert the AOSP `cla | sessionid` when bits of sessionid were OR'd in.
    apdu->cla = before & ~apdu->sessionid;
    if (apdu->cla == before) {
        return false;
    }
    ALOGI("APDU-CLA fix session=%d cla %02X -> %02X",
            apdu->sessionid, before & 0xff, apdu->cla & 0xff);
    dbg("apdu-cla-fix");
    return true;
}

static void logApduRequest(
        int request, void* data, size_t datalen, RIL_SOCKET_ID socketId,
        RIL_Token token) {
    const int sock = static_cast<int>(socketId);
    char tag[8] = "apdu";
    char detail[96] = {};

    if (request == RIL_REQUEST_SIM_OPEN_CHANNEL) {
        const char* aid = nullptr;
        if (data != nullptr && datalen >= sizeof(RIL_OpenChannelParams)) {
            const auto* params = static_cast<const RIL_OpenChannelParams*>(data);
            aid = params->aidPtr;
        } else if (data != nullptr && datalen >= sizeof(char*)) {
            // Older RIL: data is char** pointing at AID string.
            aid = *static_cast<char* const*>(data);
        }
        std::snprintf(tag, sizeof(tag), "open");
        const bool isdr = aid != nullptr
                && (std::strcmp(aid, kIsdrAid) == 0
                        || std::strstr(aid, "A000000559") != nullptr);
        std::snprintf(detail, sizeof(detail), "aid=%s%s",
                aid != nullptr ? aid : "(null)",
                isdr ? " (ISD-R)" : "");
        dbg(isdr ? "apdu-open-isdr" : "apdu-open");
    } else if (request == RIL_REQUEST_SIM_CLOSE_CHANNEL) {
        int channel = -1;
        if (data != nullptr && datalen >= sizeof(int)) {
            channel = *static_cast<const int*>(data);
        }
        std::snprintf(tag, sizeof(tag), "close");
        std::snprintf(detail, sizeof(detail), "ch=%d", channel);
        dbg("apdu-close");
    } else if (request == RIL_REQUEST_SIM_TRANSMIT_APDU_CHANNEL
            || request == RIL_REQUEST_SIM_TRANSMIT_APDU_BASIC) {
        int session = -1;
        int cla = -1;
        int ins = -1;
        int p1 = -1;
        int p2 = -1;
        const char* payload = nullptr;
        if (data != nullptr && datalen >= sizeof(RIL_SIM_APDU)) {
            const auto* apdu = static_cast<const RIL_SIM_APDU*>(data);
            session = apdu->sessionid;
            cla = apdu->cla;
            ins = apdu->instruction;
            p1 = apdu->p1;
            p2 = apdu->p2;
            payload = apdu->data;
        }
        const char* cls = classifyApduData(payload);
        std::snprintf(tag, sizeof(tag), "%s", cls);
        std::snprintf(detail, sizeof(detail),
                "ch=%d cla=%02X ins=%02X p1=%02X p2=%02X data=%.40s",
                session, cla & 0xff, ins & 0xff, p1 & 0xff, p2 & 0xff,
                payload != nullptr ? payload : "");
        char breadcrumb[PROP_VALUE_MAX];
        std::snprintf(breadcrumb, sizeof(breadcrumb), "apdu-s%d-%s", sock, cls);
        dbg(breadcrumb);
    } else {
        return;
    }

    ALOGI("APDU-REQ sock=%d req=%d tag=%s %s", sock, request, tag, detail);
    trackApduRequest(token, request, sock, tag);
}

static void logApduResponse(
        const TrackedApdu& tracked, RIL_Errno e, void* response,
        size_t responselen) {
    char breadcrumb[PROP_VALUE_MAX];
    if (tracked.request == RIL_REQUEST_SIM_OPEN_CHANNEL) {
        int channel = -1;
        if (e == RIL_E_SUCCESS && response != nullptr
                && responselen >= sizeof(int)) {
            channel = static_cast<const int*>(response)[0];
        }
        ALOGI("APDU-RSP sock=%d open tag=%s errno=%d ch=%d len=%zu",
                tracked.socketId, tracked.tag, static_cast<int>(e), channel,
                responselen);
        std::snprintf(breadcrumb, sizeof(breadcrumb), "apdu-s%d-open:%s:ch%d:e%d",
                tracked.socketId, e == RIL_E_SUCCESS ? "ok" : "fail",
                channel, static_cast<int>(e));
        dbg(breadcrumb);
        return;
    }

    if (tracked.request == RIL_REQUEST_SIM_TRANSMIT_APDU_CHANNEL
            || tracked.request == RIL_REQUEST_SIM_TRANSMIT_APDU_BASIC) {
        int sw1 = -1;
        int sw2 = -1;
        const char* simResponse = nullptr;
        if (e == RIL_E_SUCCESS && response != nullptr
                && responselen >= sizeof(RIL_SIM_IO_Response)) {
            const auto* io = static_cast<const RIL_SIM_IO_Response*>(response);
            sw1 = io->sw1;
            sw2 = io->sw2;
            simResponse = io->simResponse;
        }
        ALOGI("APDU-RSP sock=%d tx tag=%s errno=%d sw=%02X%02X resp=%.48s",
                tracked.socketId, tracked.tag, static_cast<int>(e),
                sw1 & 0xff, sw2 & 0xff,
                simResponse != nullptr ? simResponse : "");
        std::snprintf(breadcrumb, sizeof(breadcrumb),
                "apdu-s%d-%s:%02X%02X:e%d",
                tracked.socketId, tracked.tag, sw1 & 0xff, sw2 & 0xff,
                static_cast<int>(e));
        dbg(breadcrumb);
        return;
    }

    ALOGI("APDU-RSP sock=%d req=%d tag=%s errno=%d len=%zu",
            tracked.socketId, tracked.request, tracked.tag,
            static_cast<int>(e), responselen);
    std::snprintf(breadcrumb, sizeof(breadcrumb), "apdu-s%d-%s:e%d",
            tracked.socketId, tracked.tag, static_cast<int>(e));
    dbg(breadcrumb);
}

static bool loadEidFromEfs() {
    if (gEidLoaded && gEidHex[0] != '\0') {
        return true;
    }
    FILE* f = fopen(kEfsEidPath, "r");
    if (f == nullptr) {
        ALOGW("cannot open %s", kEfsEidPath);
        return false;
    }
    char buf[64] = {};
    const size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    // Keep only hex digits; EFS file is 32 ASCII hex chars.
    size_t out = 0;
    for (size_t i = 0; i < n && out + 1 < sizeof(gEidHex); ++i) {
        const char c = buf[i];
        if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')) {
            gEidHex[out++] = c;
        }
    }
    gEidHex[out] = '\0';
    gEidLoaded = out == 32;
    ALOGI("EFS EID loaded=%d len=%zu", gEidLoaded ? 1 : 0, out);
    if (gEidLoaded) {
        dbg("eid-loaded");
    }
    return gEidLoaded;
}

// GSMA GetEID (BF3E / tag 5A) StoreData APDU payload used by EuiccPort.
static bool isGetEidApdu(int request, void* data, size_t datalen) {
    if (request != RIL_REQUEST_SIM_TRANSMIT_APDU_CHANNEL || data == nullptr) {
        return false;
    }
    // RIL_SIM_APDU: sessionid,cla,instruction,p1,p2,p3,data*
    // Be liberal — Samsung may pad the struct; only require data pointer in-range.
    if (datalen < sizeof(RIL_SIM_APDU)) {
        return false;
    }
    const auto* apdu = static_cast<const RIL_SIM_APDU*>(data);
    if (apdu->data == nullptr) {
        return false;
    }
    // Expected: BF3E035C015A (GetEuiccData requesting EID tag 5A)
    return std::strstr(apdu->data, "BF3E") != nullptr
            && std::strstr(apdu->data, "5A") != nullptr;
}

// Synthesize a successful GetEID ES10 response: BF3E12 5A10 <16-byte EID>
static bool completeGetEidSynthetic(RIL_Token token) {
    if (!loadEidFromEfs()) {
        return false;
    }
    static char simResponse[128];
    static RIL_SIM_IO_Response ioResp;
    // BF3E + len(0x12) + 5A + len(0x10) + 32 hex chars
    std::snprintf(simResponse, sizeof(simResponse), "BF3E125A10%s", gEidHex);
    ioResp.sw1 = 0x90;
    ioResp.sw2 = 0x00;
    ioResp.simResponse = simResponse;
    dbg("geteid-synth");
    ALOGI("synthesizing GetEID APDU response");
    gRealEnv.OnRequestComplete(
            token, RIL_E_SUCCESS, &ioResp, sizeof(ioResp));
    return true;
}

static void* getRealHandle() {
    if (gRealHandle != nullptr) {
        return gRealHandle;
    }

    ALOGI("loading %s", kRealPath);
    gRealHandle = dlopen(kRealPath, RTLD_NOW);
    if (gRealHandle == nullptr) {
        ALOGE("dlopen failed: %s", dlerror());
    }

    return gRealHandle;
}

static RilInit getRealInit(const char* name) {
    void* realHandle = getRealHandle();
    if (realHandle == nullptr) {
        return nullptr;
    }

    dlerror();
    auto realInit = reinterpret_cast<RilInit>(dlsym(realHandle, name));
    const char* error = dlerror();
    if (error != nullptr) {
        ALOGE("dlsym %s failed: %s", name, error);
        return nullptr;
    }

    return realInit;
}

static bool isCsSmsRequest(int request) {
    return request == RIL_REQUEST_SEND_SMS
            || request == RIL_REQUEST_SEND_SMS_EXPECT_MORE;
}

static void buildSlotSwitchPayload(uint8_t type, uint8_t out[6]) {
    out[0] = 0x15;
    out[1] = 0x14;
    out[2] = 0x00;
    out[3] = 0x06;
    out[4] = 0x01;
    out[5] = type;
}

static bool propEquals(const char* key, const char* expect) {
    char value[PROP_VALUE_MAX] = {};
    __system_property_get(key, value);
    return std::strcmp(value, expect) == 0;
}

static bool fireAndWait(
        int request, void* data, size_t datalen, int timeoutMs,
        RIL_SOCKET_ID socketId) {
    if (gRealOnRequest == nullptr) {
        ALOGE("onRequest not ready");
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(gReqMu);
        gAwaitingComplete = true;
        gCompleteErrno = -1;
    }

    gRealOnRequest(request, data, datalen, gShimToken, socketId);

    std::unique_lock<std::mutex> lock(gReqMu);
    const bool ok = gReqCv.wait_for(
            lock, std::chrono::milliseconds(timeoutMs),
            [] { return !gAwaitingComplete; });
    if (!ok) {
        ALOGW("request %d socket=%d timed out after %dms",
                request, static_cast<int>(socketId), timeoutMs);
        gAwaitingComplete = false;
        return false;
    }

    ALOGI("request %d socket=%d complete errno=%d",
            request, static_cast<int>(socketId), gCompleteErrno);
    return gCompleteErrno == RIL_E_SUCCESS;
}

static bool fireOemType(uint8_t type, int timeoutMs) {
    static uint8_t payload[6];
    buildSlotSwitchPayload(type, payload);
    ALOGI("OEM SEC_SIM_LOW_LEVEL_CONTROL type=0x%02x on socket %d",
            type, static_cast<int>(kOemSocket));
    const bool ok = fireAndWait(
            RIL_REQUEST_OEM_HOOK_RAW, payload, sizeof(payload), timeoutMs,
            kOemSocket);
    char step[32];
    std::snprintf(step, sizeof(step), "oem-%02x", type);
    dbgResult(step, ok, gCompleteErrno);
    return ok;
}

static bool fireSimCardPower(int power, int timeoutMs, RIL_SOCKET_ID socketId) {
    static int powerState;
    powerState = power;
    ALOGI("SET_SIM_CARD_POWER %d on socket %d",
            power, static_cast<int>(socketId));
    const bool ok = fireAndWait(
            RIL_REQUEST_SET_SIM_CARD_POWER, &powerState, sizeof(powerState),
            timeoutMs, socketId);
    char step[32];
    std::snprintf(step, sizeof(step), "sim%d-p%d",
            static_cast<int>(socketId), power);
    dbgResult(step, ok, gCompleteErrno);
    return ok;
}

static bool fireRadioPower(int power, int timeoutMs, RIL_SOCKET_ID socketId) {
    static int radioPower;
    radioPower = power;
    ALOGI("RADIO_POWER %d on socket %d",
            power, static_cast<int>(socketId));
    const bool ok = fireAndWait(
            RIL_REQUEST_RADIO_POWER, &radioPower, sizeof(radioPower),
            timeoutMs, socketId);
    char step[32];
    std::snprintf(step, sizeof(step), "radio%d-p%d",
            static_cast<int>(socketId), power);
    dbgResult(step, ok, gCompleteErrno);
    return ok;
}

static bool switchPropIs(char want) {
    char value[PROP_VALUE_MAX] = {};
    __system_property_get(kEsimSwitchProp, value);
    return value[0] == want && value[1] == '\0';
}

// Hybrid eUICC port is on phone1 / RIL_SOCKET_2. Do not touch primary socket.
static void nudgeEuiccRadio() {
    dbg("nudge-radio2");
    fireRadioPower(1, 5000, kEuiccSocket);
    usleep(300 * 1000);
    if (switchPropIs('1')) {
        fireSimCardPower(1, 5000, kEuiccSocket);
    }
}

static bool slotTypeIsEsim() {
    return propEquals(kSimSlotType2, "1");
}

static void setEsimReady(bool ready) {
    __system_property_set(kEsimReadyProp, ready ? "1" : "0");
    ALOGI("%s=%s (type2=%s)",
            kEsimReadyProp, ready ? "1" : "0",
            slotTypeIsEsim() ? "1" : "0");
}

static bool waitFor(bool (*pred)(), int timeoutMs) {
    const int stepMs = 200;
    for (int elapsed = 0; elapsed < timeoutMs; elapsed += stepMs) {
        if (pred()) {
            return true;
        }
        usleep(stepMs * 1000);
    }
    return pred();
}

static void runEsimEnable() {
    if (slotTypeIsEsim()) {
        dbg("already-esim");
        // Still nudge phone1 — EID can be present from SlotStatus while APDU
        // (EuiccInfo2 / download) fails with RADIO_UNAVAILABLE on phone1.
        nudgeEuiccRadio();
        setEsimReady(true);
        return;
    }

    setEsimReady(false);
    dbg("enable-start");

    if (!fireOemType(kOemTypeEsim, 10000)) {
        ALOGW("initial eSIM OEM failed/timed out; still waiting for type");
    }
    if (!switchPropIs('1')) {
        dbg("enable-aborted");
        return;
    }

    waitFor(slotTypeIsEsim, 10000);

    if (!switchPropIs('1')) {
        dbg("enable-aborted");
        return;
    }

    // Soft follow-up used by stock ExecuteSlotSwitch path.
    usleep(500 * 1000);
    fireOemType(kOemTypeFollowUp, 5000);

    if (!switchPropIs('1')) {
        dbg("enable-aborted");
        return;
    }

    if (slotTypeIsEsim()) {
        dbg("type-ok");
        nudgeEuiccRadio();
        setEsimReady(true);
        dbg("enable-ok");
        return;
    }

    dbg("sim2-pulse");
    fireRadioPower(1, 5000, kEuiccSocket);
    fireSimCardPower(0, 3000, kEuiccSocket);
    usleep(500 * 1000);
    if (!switchPropIs('1')) return;
    fireSimCardPower(1, 8000, kEuiccSocket);
    waitFor(slotTypeIsEsim, 8000);

    const bool ready = slotTypeIsEsim();
    setEsimReady(ready);
    dbg(ready ? "enable-ok" : "enable-fail");
}

static void runEsimDisable() {
    setEsimReady(false);
    dbg("disable-start");
    if (slotTypeIsEsim()) {
        fireOemType(kOemTypePsim, 10000);
        waitFor([] {
            return !slotTypeIsEsim();
        }, 10000);
    }
    dbg(slotTypeIsEsim() ? "disable-fail" : "disable-ok");
}

static void shimOnRequestComplete(
        RIL_Token t, RIL_Errno e, void* response, size_t responselen) {
    if (t == gShimToken) {
        std::lock_guard<std::mutex> lock(gReqMu);
        gCompleteErrno = static_cast<int>(e);
        gAwaitingComplete = false;
        gReqCv.notify_all();
        return;
    }

    TrackedApdu tracked;
    if (takeTrackedApdu(t, &tracked)) {
        logApduResponse(tracked, e, response, responselen);
    }

    gRealEnv.OnRequestComplete(t, e, response, responselen);
}

static void shimOnRequest(
        int request, void* data, size_t datalen, RIL_Token token,
        RIL_SOCKET_ID socketId) {
    // Must run before logging so breadcrumbs show the CLA/payload actually sent.
    fixupSamsungApduCla(request, data, datalen);

    if (isApduDiagRequest(request)) {
        logApduRequest(request, data, datalen, socketId, token);
    }

    // Populate EuiccCard.mCardId without framework patches: when telephony
    // asks for GetEID over ES10 and the modem returns empty, answer from EFS.
    if (isGetEidApdu(request, data, datalen)) {
        if (completeGetEidSynthetic(token)) {
            // Clear tracking — we completed locally, no modem response.
            TrackedApdu discarded;
            takeTrackedApdu(token, &discarded);
            ALOGI("APDU-RSP sock=%d tx tag=BF3E SYNTH sw=9000",
                    static_cast<int>(socketId));
            dbg("apdu-synth-BF3E");
            return;
        }
        ALOGW("GetEID synth unavailable; passing through");
    }

    if (isCsSmsRequest(request) && data != nullptr
            && datalen >= 2 * sizeof(char*)) {
        const char** smsData = static_cast<const char**>(data);
        const char* smsc = smsData[0];
        const char* pdu = smsData[1];

        if (pdu != nullptr) {
            const char* fixedSmsData[] = {
                nullptr,
                pdu,
            };

            ALOGI("request %d: forcing CS SMSC NULL, original smsc=%s",
                    request, smsc != nullptr ? smsc : "null");
            gRealOnRequest(
                    request, const_cast<char**>(fixedSmsData),
                    sizeof(fixedSmsData), token, socketId);
            return;
        }

        ALOGW("request %d: null PDU", request);
    }

    gRealOnRequest(request, data, datalen, token, socketId);
}

static void applyEsimSwitchValue(const char* value) {
    char desired[PROP_VALUE_MAX] = {};
    std::strncpy(desired, value, sizeof(desired) - 1);

    for (int pass = 0; pass < 4; ++pass) {
        if (desired[0] == '1' && desired[1] == '\0') {
            runEsimEnable();
        } else if (desired[0] == '0' && desired[1] == '\0') {
            runEsimDisable();
        } else {
            return;
        }

        char cur[PROP_VALUE_MAX] = {};
        __system_property_get(kEsimSwitchProp, cur);
        if (std::strcmp(cur, desired) == 0) {
            return;
        }
        ALOGI("prop changed during apply '%s' -> '%s', re-applying",
                desired, cur);
        std::strncpy(desired, cur, sizeof(desired) - 1);
        desired[sizeof(desired) - 1] = '\0';
    }
}

static void* esimSwitchWatcher(void*) {
    char prev[PROP_VALUE_MAX] = {};

    dbg("watcher-start");
    ALOGI("esim switch watcher started (prop %s)", kEsimSwitchProp);
    loadEidFromEfs();

    usleep(3 * 1000 * 1000);

    __system_property_get(kEsimSwitchProp, prev);
    if (prev[0] != '\0') {
        dbg(prev[0] == '1' ? "boot-enable" : "boot-disable");
        applyEsimSwitchValue(prev);
        dbg(slotTypeIsEsim() ? "boot-ready" : "boot-not-ready");
    }

    while (true) {
        char cur[PROP_VALUE_MAX] = {};
        __system_property_get(kEsimSwitchProp, cur);

        if (strcmp(cur, prev) != 0) {
            ALOGI("%s changed '%s' -> '%s'", kEsimSwitchProp, prev, cur);
            std::strncpy(prev, cur, sizeof(prev) - 1);
            prev[sizeof(prev) - 1] = '\0';
            dbg(cur[0] == '1' ? "apply-enable" : "apply-disable");
            applyEsimSwitchValue(cur);
            dbg(slotTypeIsEsim() ? "apply-ready" : "apply-not-ready");
        } else if (cur[0] == '1' && cur[1] == '\0' && !slotTypeIsEsim()) {
            // Persist wants eSIM but type flipped back — one recovery attempt
            // every 30s, not a tight thrash loop.
            dbg("recover-enable");
            runEsimEnable();
            dbg(slotTypeIsEsim() ? "recover-ok" : "recover-fail");
            usleep(30 * 1000 * 1000);
            continue;
        } else if (cur[0] == '1' && cur[1] == '\0' && slotTypeIsEsim()
                && !propEquals(kEsimReadyProp, "1")) {
            setEsimReady(true);
            dbg("ready-latched");
        }

        usleep(500 * 1000);
    }
    return nullptr;
}

static void startEsimWatcher() {
    bool expected = false;
    if (!gWatcherStarted.compare_exchange_strong(expected, true)) {
        return;
    }

    pthread_t thread;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&thread, &attr, esimSwitchWatcher, nullptr) != 0) {
        ALOGE("failed to start esim watcher");
        gWatcherStarted = false;
    } else {
        pthread_setname_np(thread, "esimSwitchWatch");
    }
    pthread_attr_destroy(&attr);
}

extern "C" const RIL_RadioFunctions* RIL_Init(
        const RIL_Env* env, int argc, char** argv) {
    RilInit realRilInit = getRealInit("RIL_Init");
    if (realRilInit == nullptr) {
        return nullptr;
    }

    if (env != nullptr) {
        gRealEnv = *env;
        gShimEnv = *env;
        gShimEnv.OnRequestComplete = shimOnRequestComplete;
    }

    const RIL_RadioFunctions* real =
            realRilInit(env != nullptr ? &gShimEnv : env, argc, argv);
    if (real == nullptr) {
        ALOGE("invalid real RIL function table");
        return real;
    }

    auto* realPrefix = reinterpret_cast<SamsungRilFunctionsPrefix*>(
            const_cast<RIL_RadioFunctions*>(real));
    if (realPrefix->onRequest == nullptr) {
        ALOGE("real onRequest is null");
        return real;
    }

    if (realPrefix->onRequest != shimOnRequest) {
        gRealOnRequest = realPrefix->onRequest;
        realPrefix->onRequest = shimOnRequest;
    } else if (gRealOnRequest == nullptr) {
        ALOGE("missing saved real onRequest");
        return nullptr;
    }

    startEsimWatcher();
    ALOGI("installed CS SMSC + esim OEM-switch shim");
    return real;
}

extern "C" const RIL_RadioFunctions* RIL_SAP_Init(
        const RIL_Env* env, int argc, char** argv) {
    RilInit realSapInit = getRealInit("RIL_SAP_Init");
    if (realSapInit == nullptr) {
        return nullptr;
    }

    return realSapInit(env, argc, argv);
}
