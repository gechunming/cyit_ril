/* //device/libs/telephony/ril.cpp
**
** Copyright 2006, The Android Open Source Project
** Copyright (c) 2010-2011, Code Aurora Forum. All rights reserved.
** Copyright (C) 2012-2013 CYIT CO., LTD. All rights reserved.
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

#define LOG_TAG "RILC"

#include <hardware_legacy/power.h>

#include <telephony/ril.h>
#include <telephony/ril_cdma_sms.h>
#include <cutils/sockets.h>
#include <cutils/jstring.h>
#include <cutils/record_stream.h>
#include <utils/Log.h>
#include <utils/SystemClock.h>
#include <pthread.h>
#include <binder/Parcel.h>
#include <cutils/jstring.h>

#include <sys/types.h>
#include <pwd.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <assert.h>
#include <ctype.h>
#include <alloca.h>
#include <sys/un.h>
#include <assert.h>
#include <netinet/in.h>
#include <cutils/properties.h>

#include <ril_event.h>

namespace android {

#define PHONE_PROCESS "radio"

#define ANDROID_WAKE_LOCK_NAME "radio-interface"


#define PROPERTY_RIL_IMPL "gsm.version.ril-impl"

// match with constant in RIL.java
#define MAX_COMMAND_BYTES (8 * 1024)

// Basically: memset buffers that the client library
// shouldn't be using anymore in an attempt to find
// memory usage issues sooner.
#define MEMSET_FREED 1

#define NUM_ELEMS(a)     (sizeof (a) / sizeof (a)[0])

#define MIN(a,b) ((a)<(b) ? (a) : (b))

/* Constants for response types */
#define RESPONSE_SOLICITED 0
#define RESPONSE_UNSOLICITED 1

/* Negative values for private RIL errno's */
#define RIL_ERRNO_INVALID_RESPONSE -1

// request, response, and unsolicited msg print macro
#define PRINTBUF_SIZE 8096

// Enable RILC log
#define RILC_LOG 0

#if RILC_LOG
    #define startRequest           sprintf(printBuf, "(")
    #define closeRequest           sprintf(printBuf, "%s)", printBuf)
    #define printRequest(token, req)           \
            LOGD("[%04d]> %s %s", token, requestToString(req), printBuf)

    #define startResponse           sprintf(printBuf, "%s {", printBuf)
    #define closeResponse           sprintf(printBuf, "%s}", printBuf)
    #define printResponse           LOGD("%s", printBuf)

    #define clearPrintBuf           printBuf[0] = 0
    #define removeLastChar          printBuf[strlen(printBuf)-1] = 0
    #define appendPrintBuf(x...)    sprintf(printBuf, x)
#else
    #define startRequest
    #define closeRequest
    #define printRequest(token, req)
    #define startResponse
    #define closeResponse
    #define printResponse
    #define clearPrintBuf
    #define removeLastChar
    #define appendPrintBuf(x...)
#endif

enum WakeType {DONT_WAKE, WAKE_PARTIAL};

typedef struct {
    int requestNumber;
    int cid;
    void (*dispatchFunction) (Parcel &p, struct RequestInfo *pRI);
    int(*responseFunction) (Parcel &p, void *response, size_t responselen);
} CommandInfo;

typedef struct {
    int requestNumber;
    int (*responseFunction) (Parcel &p, void *response, size_t responselen);
    WakeType wakeType;
} UnsolResponseInfo;

typedef struct RequestInfo {
    int32_t token;      //this is not RIL_Token
    CommandInfo *pCI;
    struct RequestInfo *p_next;
    char cancelled;     // socket error, request don't report response in pending queue
    char local;         // responses to local commands do not go back to command process
    int client_id;      // 0 or 1 corresponding to each of RIL.java clients
    Parcel parcel;      // save the parcel from RILJ
    void * userParam;   // save the userParam in timeReq, may be NULL
} RequestInfo;

typedef struct UserCallbackInfo {
    //RIL_TimedCallback p_callback;
    void *userParam;
    int timeReq;
    struct ril_event event;
    struct UserCallbackInfo *p_next;
} UserCallbackInfo;

/*******************************************************************/
#define MAX_NUM_CLIENTS 2
RIL_RadioFunctions s_callbacks[MAX_NUM_CLIENTS] = {{0, NULL, NULL, NULL, NULL, NULL}};
// same as s_callbacks[0].onRequest //
RIL_RequestFunc s_onRequest;

static int s_registerCalled = 0;

static pthread_t s_tid_dispatch;
static pthread_t s_tid_reader;

// start other threads after dispatch thread //
static int s_started = 0;
// start request thread before dispatch thread //
//static int s_reqStarted[RIL_CHANNELS] = {0};
// there are new requests in request thread //
static int s_newReq[RIL_CHANNELS] = {0};

static int s_fdListen = -1;
enum FDStatus {
    FD_STATUS_INACTIVE = 0,
    FD_STATUS_ACTIVE
};

typedef struct {
    int fd;
    FDStatus fd_status;
}Client_fds;

static int s_fdCommand[MAX_NUM_CLIENTS] ={-1,-1};	//socket fd
RecordStream *p_rs[MAX_NUM_CLIENTS]={NULL};
static Client_fds client_fds[MAX_NUM_CLIENTS] ={{-1, FD_STATUS_INACTIVE}, {-1, FD_STATUS_INACTIVE}};
static int s_fdDebug = -1;

static int s_fdWakeupRead;
static int s_fdWakeupWrite;

static struct ril_event s_commands_event[MAX_NUM_CLIENTS];
static struct ril_event s_wakeupfd_event;
static struct ril_event s_listen_event;
static struct ril_event s_wake_timeout_event;
static struct ril_event s_debug_event;


static const struct timeval TIMEVAL_WAKE_TIMEOUT = {1,0};

// mutex lock and condition of get and set requsts //
static pthread_mutex_t s_pendingRequestsMutex[RIL_CHANNELS] = {PTHREAD_MUTEX_INITIALIZER};
static pthread_cond_t s_pendingRequestsCond[RIL_CHANNELS] = {PTHREAD_COND_INITIALIZER};

// mutex lock of write AT data to VPIPE //
static pthread_mutex_t s_writeMutex = PTHREAD_MUTEX_INITIALIZER;

// mutex lock and condition of start dispatch thread //
static pthread_mutex_t s_startupMutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t s_startupCond = PTHREAD_COND_INITIALIZER;

// mutex lock and condition of start request thread //
//static pthread_mutex_t s_startupReqMutex[RIL_CHANNELS] = {PTHREAD_MUTEX_INITIALIZER};
//static pthread_cond_t s_startupReqCond[RIL_CHANNELS] = {PTHREAD_COND_INITIALIZER};

// no use ? //
static pthread_mutex_t s_dispatchMutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t s_dispatchCond = PTHREAD_COND_INITIALIZER;

// requests list and new request add to the tail //
static RequestInfo *s_pendingRequests[RIL_CHANNELS] = {0};
static RequestInfo *s_pending_tail[RIL_CHANNELS] = {0};

static RequestInfo *s_toDispatchHead = NULL;
static RequestInfo *s_toDispatchTail = NULL;

static UserCallbackInfo *s_last_wake_timeout_info = NULL;

static void *s_lastNITZTimeData = NULL;
static size_t s_lastNITZTimeDataSize;

static char rild[6] = {0};

#if RILC_LOG
    static char printBuf[PRINTBUF_SIZE];
#endif

extern "C" pthread_key_t CID;

/*******************************************************************/

static void dispatchVoid (Parcel& p, RequestInfo *pRI);
static void dispatchTimeReq(Parcel& p, RequestInfo *pRI);
static void dispatchString (Parcel& p, RequestInfo *pRI);
static void dispatchStrings (Parcel& p, RequestInfo *pRI);
static void dispatchInts (Parcel& p, RequestInfo *pRI);
static void dispatchDial (Parcel& p, RequestInfo *pRI);
static void dispatchSIM_IO (Parcel& p, RequestInfo *pRI);
static void dispatchCallForward(Parcel& p, RequestInfo *pRI);
static void dispatchRaw(Parcel& p, RequestInfo *pRI);
static void dispatchSmsWrite (Parcel &p, RequestInfo *pRI);
static void dispatchDepersonalization(Parcel &p, RequestInfo *pRI);
static void dispatchCdmaSms(Parcel &p, RequestInfo *pRI);
static void dispatchImsSms(Parcel &p, RequestInfo *pRI);
static void dispatchImsCdmaSms(Parcel &p, RequestInfo *pRI);
static void dispatchImsGsmSms(Parcel &p, RequestInfo *pRI);
static void dispatchCdmaSmsAck(Parcel &p, RequestInfo *pRI);
static void dispatchGsmBrSmsCnf(Parcel &p, RequestInfo *pRI);
static void dispatchCdmaBrSmsCnf(Parcel &p, RequestInfo *pRI);
static void dispatchRilCdmaSmsWriteArgs(Parcel &p, RequestInfo *pRI);

/**************************************************************************
  Modified by CYIT 20120825 ----- start -----
  declaration
**************************************************************************/
static void dispatchApnInfo( Parcel &p , RequestInfo * pRI );
static void dispatchPrenetlist( Parcel &p , RequestInfo * pRI );
static void dispatchUSSD( Parcel &p , RequestInfo * pRI );
/**************************************************************************
  Modified by CYIT 20120825 ----- end -----
**************************************************************************/

static void dispatchUiccSubscripton(Parcel &p, RequestInfo *pRI);


static int responseInts(Parcel &p, void *response, size_t responselen);
static int responseStrings(Parcel &p, void *response, size_t responselen);
static int responseString(Parcel &p, void *response, size_t responselen);
static int responseVoid(Parcel &p, void *response, size_t responselen);
static int responseCallList(Parcel &p, void *response, size_t responselen);
static int responseSMS(Parcel &p, void *response, size_t responselen);
static int responseSIM_IO(Parcel &p, void *response, size_t responselen);
static int responseCallForwards(Parcel &p, void *response, size_t responselen);
static int responseDataCallList(Parcel &p, void *response, size_t responselen);
static int responseRaw(Parcel &p, void *response, size_t responselen);
static int responseSsn(Parcel &p, void *response, size_t responselen);
static int responseSimStatus(Parcel &p, void *response, size_t responselen);
static int responseGsmBrSmsCnf(Parcel &p, void *response, size_t responselen);
static int responseCdmaBrSmsCnf(Parcel &p, void *response, size_t responselen);
static int responseCdmaSms(Parcel &p, void *response, size_t responselen);
static int responseCellList(Parcel &p, void *response, size_t responselen);
static int responseCdmaInformationRecords(Parcel &p,void *response, size_t responselen);
static int responseRilSignalStrength(Parcel &p,void *response, size_t responselen);
static int responseCallRing(Parcel &p, void *response, size_t responselen);
static int responseCdmaSignalInfoRecord(Parcel &p,void *response, size_t responselen);
static int responseCdmaCallWaiting(Parcel &p,void *response, size_t responselen);
static int responseGetDataCallProfile(Parcel &p, void *response, size_t responselen);

static int responseUiccSubscription(Parcel &p, void *response, size_t responselen);
static int responseSimRefresh(Parcel &p, void *response, size_t responselen);
static int responseSSData(Parcel &p, void *response, size_t responselen);
static bool isServiceTypeCFQuery(RIL_SsServiceType serType, RIL_SsRequestType reqType);

/**************************************************************************
  Modified by CYIT 20120825 ----- start -----
  declaration
**************************************************************************/
static int responseApnInfo( Parcel &p, void * response, size_t responselen );
static int responsePdpInfo( Parcel &p, void * response, size_t responselen );
static int responseQosInfo( Parcel &p, void * response, size_t responselen );
static int responseCellInfo( Parcel &p, void * response, size_t responselen );
static int responsePrenet( Parcel &p, void * response, size_t responselen );
static int responseReadPbRec(Parcel &p, void *response, size_t responselen);
/**************************************************************************
  Modified by CYIT 20120825 ----- end -----
**************************************************************************/


extern "C" const char * requestToString(int request);
extern "C" const char * failCauseToString(RIL_Errno);
extern "C" const char * callStateToString(RIL_CallState);
extern "C" const char * radioStateToString(RIL_RadioState);

#ifdef RIL_SHLIB
extern "C" void RIL_onUnsolicitedResponse_Inst0(int unsolResponse, void *data,
                                size_t datalen);
extern "C" void RIL_onUnsolicitedResponse_Inst1(int unsolResponse, void *data,
                               size_t datalen);
#endif

static void wakeTimeoutCallback(void * param); 
static void RIL_onUnsolicitedResponse(int unsolResponse, void *data,
                               size_t datalen, int client_id);

/*
static UserCallbackInfo * internalRequestTimedCallback
    (RIL_TimedCallback callback, void *param,
        const struct timeval *relativeTime);
*/

static UserCallbackInfo * internalRequestTimedCallback(
        int timeReq, void *param, const struct timeval *relativeTime);

/** Index == requestNumber */
static CommandInfo s_commands[] = {
#include "ril_commands.h"
};

static UnsolResponseInfo s_unsolResponses[] = {
#include "ril_unsol_commands.h"
};

static char * RIL_getRilSocketName() {
    return rild;
}

extern "C"
void RIL_setRilSocketName(char * s) {
    strcpy(rild, s);
}

void printfds() {
    for(int i = 0; i < MAX_NUM_CLIENTS; i++) {
        LOGD("fd=%d,.....status=%d",client_fds[i].fd,client_fds[i].fd_status);
    }
}

static int addClientFd(int fd) {
    int ret = -1;
    for(int i = 0; i < MAX_NUM_CLIENTS; i++) {
        if (client_fds[i].fd_status == FD_STATUS_INACTIVE) {
            client_fds[i].fd = fd;
            client_fds[i].fd_status = FD_STATUS_ACTIVE;
            ret = i;
            break;
        }
    }
    printfds();
    return ret;
}

static int mapClientFD(int fd) {
    int ret = -1;
    for(int i = 0; i < MAX_NUM_CLIENTS; i++) {
        if ( client_fds[i].fd_status == FD_STATUS_ACTIVE && client_fds[i].fd == fd ) {
            ret = i;
            break;
        }
    }
    return ret;
}

static char *
strdupReadString(Parcel &p) {
    size_t stringlen;
    const char16_t *s16;

    s16 = p.readString16Inplace(&stringlen);

    return strndup16to8(s16, stringlen);
}

static void writeStringToParcel(Parcel &p, const char *s) {
    char16_t *s16;
    size_t s16_len;
    s16 = strdup8to16(s, &s16_len);
    p.writeString16(s16, s16_len);
    free(s16);
}


static void
memsetString (char *s) {
    if (s != NULL) {
        memset (s, 0, strlen(s));
    }
}

void   nullParcelReleaseFunction (const uint8_t* data, size_t dataSize,
                                    const size_t* objects, size_t objectsSize,
                                        void* cookie) {
    // do nothing -- the data reference lives longer than the Parcel object
}

/**
 * To be called from dispatch thread
 * Issue a single local request, ensuring that the response
 * is not sent back up to the command process
 */
static void
issueLocalRequest(int request, void *data, int len, int client_id) {
    RequestInfo *pRI;
    int ret;
    int cid = RIL_CHANNEL_DEBUG - 1;
    int parcel[2] = {0};

    pRI = (RequestInfo *)calloc(1, sizeof(RequestInfo));
    memset(pRI, 0 , sizeof(RequestInfo));
    pRI->local = 1;
    pRI->token = 0xffffffff; // token is not used in this context
    pRI->pCI = &(s_commands[request]);
    pRI->client_id = client_id;
    pRI->parcel.setData((uint8_t*)data, len);

    ret = pthread_mutex_lock(&s_pendingRequestsMutex[cid]);
    assert (ret == 0);

    //pRI->p_next = s_pendingRequests;
    //s_pendingRequests = pRI;
    pRI->p_next = NULL;
    if (!s_pendingRequests[cid]) {
        s_pendingRequests[cid] = pRI;
    } else {
        s_pending_tail[cid]->p_next = pRI;
    }
    s_pending_tail[cid] = pRI;
    s_newReq[cid] = 1;
    LOGD("C[locl]> %s", requestToString(request));

    pthread_cond_broadcast(&s_pendingRequestsCond[cid]);
    ret = pthread_mutex_unlock(&s_pendingRequestsMutex[cid]);
    assert (ret == 0);
}

static int
processCommandBuffer(void *buffer, size_t buflen, int client_id) {
    status_t status;
    int32_t request;
    int32_t token;
    RequestInfo *pRI;
    int ret;
    int cid;

    pRI = (RequestInfo *)calloc(1, sizeof(RequestInfo));
    memset(pRI, 0, sizeof(RequestInfo));
    pRI->client_id = client_id;
    pRI->userParam = NULL;
    pRI->local = 0;
    pRI->parcel.setData((uint8_t *) buffer, buflen);

    status = pRI->parcel.readInt32(&request);
    status = pRI->parcel.readInt32(&token);
    if (status != NO_ERROR) {
        LOGE("invalid request block");
        free(pRI);
        return 0;
    }
    pRI->token = token;

    if (request < 1 || request >= (int32_t)NUM_ELEMS(s_commands)) {
        LOGE("unsupported request code %d token %d", request, token);
        free(pRI);
        return 0;
    }
    pRI->pCI = &(s_commands[request]);
    
    if (RIL_CHANNELID_MIN > pRI->pCI->cid
            || RIL_CHANNELID_MAX < pRI->pCI->cid)
    {
        LOGE("%s's cid is out of range", requestToString(pRI->pCI->requestNumber));
        free(pRI);
        return 0;
    }
    
    pRI->p_next = NULL;
    cid = pRI->pCI->cid - 1;

    // append request to tail of pending list //
    ret = pthread_mutex_lock(&s_pendingRequestsMutex[cid]);
    assert (ret == 0);
    LOGD("[DISPATCH]: append request %s token(%04d) to pending list(%d)", 
            requestToString(pRI->pCI->requestNumber), pRI->token, cid);
    if (!s_pendingRequests[cid]) {
        s_pendingRequests[cid] = pRI;
    } else {
        s_pending_tail[cid]->p_next = pRI;
    }
    s_pending_tail[cid] = pRI;
    s_newReq[cid] = 1;
    LOGD("[DISPATCH]: append request over");
    pthread_cond_broadcast(&s_pendingRequestsCond[cid]);
    ret = pthread_mutex_unlock(&s_pendingRequestsMutex[cid]);
    assert (ret == 0);

    return 0;
}

static void
invalidCommandBlock (RequestInfo *pRI) {
    LOGE("invalid command block for token %d request %s and client_id %d ",
                pRI->token, requestToString(pRI->pCI->requestNumber), pRI->client_id);
}

/** Callee expects NULL */
static void
dispatchVoid (Parcel& p, RequestInfo *pRI) {
    clearPrintBuf;
    printRequest(pRI->token, pRI->pCI->requestNumber);
    s_callbacks[pRI->client_id].onRequest(pRI->pCI->requestNumber, NULL, 0, pRI);
}

static void dispatchDebugReq(Parcel& p, RequestInfo *pRI)
{
    clearPrintBuf;
    printRequest(pRI->token, pRI->pCI->requestNumber);
    if (s_onRequest) {
        s_onRequest(pRI->pCI->requestNumber, 
                (void *)(p.data()), p.dataSize(), pRI);
    } else {
        LOGE("onrequest pointer is NULL !!!");
    }
}

static void dispatchTimeReq(Parcel& p, RequestInfo *pRI)
{
    clearPrintBuf;
    printRequest(pRI->token, pRI->pCI->requestNumber);
    if (s_onRequest) {
        s_onRequest(pRI->pCI->requestNumber, pRI->userParam, 0, pRI);
    } else {
        LOGE("onrequest pointer is NULL !!!");
    }
}

/** Callee expects const char * */
static void
dispatchString (Parcel& p, RequestInfo *pRI) {
    status_t status;
    size_t datalen;
    size_t stringlen;
    char *string8 = NULL;

    string8 = strdupReadString(p);

    startRequest;
    appendPrintBuf("%s%s", printBuf, string8);
    closeRequest;
    printRequest(pRI->token, pRI->pCI->requestNumber);

    s_callbacks[pRI->client_id].onRequest(pRI->pCI->requestNumber, string8,
                       sizeof(char *), pRI);

#ifdef MEMSET_FREED
    memsetString(string8);
#endif

    free(string8);
    return;
invalid:
    invalidCommandBlock(pRI);
    return;
}

/** Callee expects const char ** */
static void
dispatchStrings (Parcel &p, RequestInfo *pRI) {
    int32_t countStrings;
    status_t status;
    size_t datalen;
    char **pStrings;

    status = p.readInt32 (&countStrings);

    if (status != NO_ERROR) {
        goto invalid;
    }

    startRequest;
    if (countStrings == 0) {
        // just some non-null pointer
        pStrings = (char **)alloca(sizeof(char *));
        datalen = 0;
    } else if (((int)countStrings) == -1) {
        pStrings = NULL;
        datalen = 0;
    } else {
        datalen = sizeof(char *) * countStrings;

        pStrings = (char **)alloca(datalen);

        for (int i = 0 ; i < countStrings ; i++) {
            pStrings[i] = strdupReadString(p);
            appendPrintBuf("%s%s,", printBuf, pStrings[i]);
        }
    }
    removeLastChar;
    closeRequest;
    printRequest(pRI->token, pRI->pCI->requestNumber);

    s_callbacks[pRI->client_id].onRequest(pRI->pCI->requestNumber, pStrings, datalen, pRI);

    if (pStrings != NULL) {
        for (int i = 0 ; i < countStrings ; i++) {
#ifdef MEMSET_FREED
            memsetString (pStrings[i]);
#endif
            free(pStrings[i]);
        }

#ifdef MEMSET_FREED
        memset(pStrings, 0, datalen);
#endif
    }

    return;
invalid:
    invalidCommandBlock(pRI);
    return;
}

/** Callee expects const int * */
static void
dispatchInts (Parcel &p, RequestInfo *pRI) {
    int32_t count;
    status_t status;
    size_t datalen;
    int *pInts;

    status = p.readInt32 (&count);

    if (status != NO_ERROR || count == 0) {
        goto invalid;
    }

    datalen = sizeof(int) * count;
    pInts = (int *)alloca(datalen);

    startRequest;
    for (int i = 0 ; i < count ; i++) {
        int32_t t;

        status = p.readInt32(&t);
        pInts[i] = (int)t;
        appendPrintBuf("%s%d,", printBuf, t);

        if (status != NO_ERROR) {
            goto invalid;
        }
   }
   removeLastChar;
   closeRequest;
   printRequest(pRI->token, pRI->pCI->requestNumber);

   s_callbacks[0].onRequest(pRI->pCI->requestNumber, const_cast<int *>(pInts),
                       datalen, pRI);

#ifdef MEMSET_FREED
    memset(pInts, 0, datalen);
#endif

    return;
invalid:
    invalidCommandBlock(pRI);
    return;
}


/**
 * Callee expects const RIL_SMS_WriteArgs *
 * Payload is:
 *   int32_t status
 *   String pdu
 */
static void
dispatchSmsWrite (Parcel &p, RequestInfo *pRI) {
    RIL_SMS_WriteArgs args;
    int32_t t;
    status_t status;

    memset (&args, 0, sizeof(args));

    status = p.readInt32(&t);
    args.status = (int)t;

    args.pdu = strdupReadString(p);

    if (status != NO_ERROR || args.pdu == NULL) {
        goto invalid;
    }

    args.smsc = strdupReadString(p);

    startRequest;
    appendPrintBuf("%s%d,%s,smsc=%s", printBuf, args.status,
        (char*)args.pdu,  (char*)args.smsc);
    closeRequest;
    printRequest(pRI->token, pRI->pCI->requestNumber);

    s_callbacks[pRI->client_id].onRequest(pRI->pCI->requestNumber, &args, sizeof(args), pRI);

#ifdef MEMSET_FREED
    memsetString (args.pdu);
#endif

    free (args.pdu);

#ifdef MEMSET_FREED
    memset(&args, 0, sizeof(args));
#endif

    return;
invalid:
    invalidCommandBlock(pRI);
    return;
}

/**
 * Callee expects const RIL_Dial *
 * Payload is:
 *   String address
 *   int32_t clir
 */
static void
dispatchDial (Parcel &p, RequestInfo *pRI) {
    RIL_Dial dial;
    RIL_UUS_Info uusInfo;
    int32_t sizeOfDial;
    int32_t t;
    int32_t uusPresent;
    status_t status;

    memset (&dial, 0, sizeof(dial));

    dial.address = strdupReadString(p);

    status = p.readInt32(&t);
    dial.clir = (int)t;

    if (status != NO_ERROR || dial.address == NULL) {
        goto invalid;
    }

    if (s_callbacks[pRI->client_id].version < 3) { // Remove when partners upgrade to version 3
        uusPresent = 0;
        sizeOfDial = sizeof(dial) - sizeof(RIL_UUS_Info *);
    } else {
        status = p.readInt32(&uusPresent);

        if (status != NO_ERROR) {
            goto invalid;
        }

        if (uusPresent == 0) {
            dial.uusInfo = NULL;
        } else {
            int32_t len;

            memset(&uusInfo, 0, sizeof(RIL_UUS_Info));

            status = p.readInt32(&t);
            uusInfo.uusType = (RIL_UUS_Type) t;

            status = p.readInt32(&t);
            uusInfo.uusDcs = (RIL_UUS_DCS) t;

            status = p.readInt32(&len);
            if (status != NO_ERROR) {
                goto invalid;
            }

            // The java code writes -1 for null arrays
            if (((int) len) == -1) {
                uusInfo.uusData = NULL;
                len = 0;
            } else {
                uusInfo.uusData = (char*) p.readInplace(len);
            }

            uusInfo.uusLength = len;
            dial.uusInfo = &uusInfo;
        }
        sizeOfDial = sizeof(dial);
    }

    startRequest;
    appendPrintBuf("%snum=%s,clir=%d", printBuf, dial.address, dial.clir);
    if (uusPresent) {
        appendPrintBuf("%s,uusType=%d,uusDcs=%d,uusLen=%d", printBuf,
                dial.uusInfo->uusType, dial.uusInfo->uusDcs,
                dial.uusInfo->uusLength);
    }
    closeRequest;
    printRequest(pRI->token, pRI->pCI->requestNumber);

    s_callbacks[pRI->client_id].onRequest(pRI->pCI->requestNumber, &dial, sizeOfDial, pRI);

#ifdef MEMSET_FREED
    memsetString (dial.address);
#endif

    free (dial.address);

#ifdef MEMSET_FREED
    memset(&uusInfo, 0, sizeof(RIL_UUS_Info));
    memset(&dial, 0, sizeof(dial));
#endif

    return;
invalid:
    invalidCommandBlock(pRI);
    return;
}

/**
 * Callee expects const RIL_SIM_IO *
 * Payload is:
 *   int32_t command
 *   int32_t fileid
 *   String path
 *   int32_t p1, p2, p3
 *   String data
 *   String pin2
 *   String aidPtr
 */
static void
dispatchSIM_IO (Parcel &p, RequestInfo *pRI) {
    union RIL_SIM_IO {
        RIL_SIM_IO_v6 v6;
        RIL_SIM_IO_v5 v5;
    } simIO;

    int32_t t;
    int size;
    status_t status;

    memset (&simIO, 0, sizeof(simIO));

    // note we only check status at the end

    status = p.readInt32(&t);
    simIO.v6.command = (int)t;

    status = p.readInt32(&t);
    simIO.v6.fileid = (int)t;

    simIO.v6.path = strdupReadString(p);

    status = p.readInt32(&t);
    simIO.v6.p1 = (int)t;

    status = p.readInt32(&t);
    simIO.v6.p2 = (int)t;

    status = p.readInt32(&t);
    simIO.v6.p3 = (int)t;

    simIO.v6.data = strdupReadString(p);
    simIO.v6.pin2 = strdupReadString(p);
    simIO.v6.aidPtr = strdupReadString(p);

    startRequest;
    appendPrintBuf("%scmd=0x%X,efid=0x%X,path=%s,%d,%d,%d,%s,pin2=%s,aid=%s", printBuf,
        simIO.v6.command, simIO.v6.fileid, (char*)simIO.v6.path,
        simIO.v6.p1, simIO.v6.p2, simIO.v6.p3,
        (char*)simIO.v6.data,  (char*)simIO.v6.pin2, simIO.v6.aidPtr);
    closeRequest;
    printRequest(pRI->token, pRI->pCI->requestNumber);

    if (status != NO_ERROR) {
        goto invalid;
    }

    size = (s_callbacks[pRI->client_id].version < 6) ? sizeof(simIO.v5) : sizeof(simIO.v6);
    s_callbacks[pRI->client_id].onRequest(pRI->pCI->requestNumber, &simIO, size, pRI);

#ifdef MEMSET_FREED
    memsetString (simIO.v6.path);
    memsetString (simIO.v6.data);
    memsetString (simIO.v6.pin2);
    memsetString (simIO.v6.aidPtr);
#endif

    free (simIO.v6.path);
    free (simIO.v6.data);
    free (simIO.v6.pin2);
    free (simIO.v6.aidPtr);

#ifdef MEMSET_FREED
    memset(&simIO, 0, sizeof(simIO));
#endif

    return;
invalid:
    invalidCommandBlock(pRI);
    return;
}

/**
 * Callee expects const RIL_CallForwardInfo *
 * Payload is:
 *  int32_t status/action
 *  int32_t reason
 *  int32_t serviceCode
 *  int32_t toa
 *  String number  (0 length -> null)
 *  int32_t timeSeconds
 */
static void
dispatchCallForward(Parcel &p, RequestInfo *pRI) {
    RIL_CallForwardInfo cff;
    int32_t t;
    status_t status;

    memset (&cff, 0, sizeof(cff));

    // note we only check status at the end

    status = p.readInt32(&t);
    cff.status = (int)t;

    status = p.readInt32(&t);
    cff.reason = (int)t;

    status = p.readInt32(&t);
    cff.serviceClass = (int)t;

    status = p.readInt32(&t);
    cff.toa = (int)t;

    cff.number = strdupReadString(p);

    status = p.readInt32(&t);
    cff.timeSeconds = (int)t;

    if (status != NO_ERROR) {
        goto invalid;
    }

    // special case: number 0-length fields is null

    if (cff.number != NULL && strlen (cff.number) == 0) {
        cff.number = NULL;
    }

    startRequest;
    appendPrintBuf("%sstat=%d,reason=%d,serv=%d,toa=%d,%s,tout=%d", printBuf,
        cff.status, cff.reason, cff.serviceClass, cff.toa,
        (char*)cff.number, cff.timeSeconds);
    closeRequest;
    printRequest(pRI->token, pRI->pCI->requestNumber);

    s_callbacks[pRI->client_id].onRequest(pRI->pCI->requestNumber, &cff, sizeof(cff), pRI);

#ifdef MEMSET_FREED
    memsetString(cff.number);
#endif

    free (cff.number);

#ifdef MEMSET_FREED
    memset(&cff, 0, sizeof(cff));
#endif

    return;
invalid:
    invalidCommandBlock(pRI);
    return;
}


static void
dispatchRaw(Parcel &p, RequestInfo *pRI) {
    int32_t len;
    status_t status;
    const void *data;

    status = p.readInt32(&len);

    if (status != NO_ERROR) {
        goto invalid;
    }

    // The java code writes -1 for null arrays
    if (((int)len) == -1) {
        data = NULL;
        len = 0;
    }

    data = p.readInplace(len);

    startRequest;
    appendPrintBuf("%sraw_size=%d", printBuf, len);
    closeRequest;
    printRequest(pRI->token, pRI->pCI->requestNumber);

    s_callbacks[pRI->client_id].onRequest(pRI->pCI->requestNumber, const_cast<void *>(data), len, pRI);

    return;
invalid:
    invalidCommandBlock(pRI);
    return;
}

static status_t
constructCdmaSms(Parcel &p, RequestInfo *pRI, RIL_CDMA_SMS_Message& rcsm) {
    int32_t  t;
    uint8_t ut;
    status_t status;
    int32_t digitCount;
    int digitLimit;

    memset(&rcsm, 0, sizeof(rcsm));

    status = p.readInt32(&t);
    rcsm.uTeleserviceID = (int) t;

    status = p.read(&ut,sizeof(ut));
    rcsm.bIsServicePresent = (uint8_t) ut;

    status = p.readInt32(&t);
    rcsm.uServicecategory = (int) t;

    status = p.readInt32(&t);
    rcsm.sAddress.digit_mode = (RIL_CDMA_SMS_DigitMode) t;

    status = p.readInt32(&t);
    rcsm.sAddress.number_mode = (RIL_CDMA_SMS_NumberMode) t;

    status = p.readInt32(&t);
    rcsm.sAddress.number_type = (RIL_CDMA_SMS_NumberType) t;

    status = p.readInt32(&t);
    rcsm.sAddress.number_plan = (RIL_CDMA_SMS_NumberPlan) t;

    status = p.read(&ut,sizeof(ut));
    rcsm.sAddress.number_of_digits= (uint8_t) ut;

    digitLimit= MIN((rcsm.sAddress.number_of_digits), RIL_CDMA_SMS_ADDRESS_MAX);
    for(digitCount =0 ; digitCount < digitLimit; digitCount ++) {
        status = p.read(&ut,sizeof(ut));
        rcsm.sAddress.digits[digitCount] = (uint8_t) ut;
    }

    status = p.readInt32(&t);
    rcsm.sSubAddress.subaddressType = (RIL_CDMA_SMS_SubaddressType) t;

    status = p.read(&ut,sizeof(ut));
    rcsm.sSubAddress.odd = (uint8_t) ut;

    status = p.read(&ut,sizeof(ut));
    rcsm.sSubAddress.number_of_digits = (uint8_t) ut;

    digitLimit= MIN((rcsm.sSubAddress.number_of_digits), RIL_CDMA_SMS_SUBADDRESS_MAX);
    for(digitCount =0 ; digitCount < digitLimit; digitCount ++) {
        status = p.read(&ut,sizeof(ut));
        rcsm.sSubAddress.digits[digitCount] = (uint8_t) ut;
    }

    status = p.readInt32(&t);
    rcsm.uBearerDataLen = (int) t;

    digitLimit= MIN((rcsm.uBearerDataLen), RIL_CDMA_SMS_BEARER_DATA_MAX);
    for(digitCount =0 ; digitCount < digitLimit; digitCount ++) {
        status = p.read(&ut, sizeof(ut));
        rcsm.aBearerData[digitCount] = (uint8_t) ut;
    }

    if (status != NO_ERROR) {
        return status;
    }

    startRequest;
    appendPrintBuf("%suTeleserviceID=%d, bIsServicePresent=%d, uServicecategory=%d, \
            sAddress.digit_mode=%d, sAddress.Number_mode=%d, sAddress.number_type=%d, ",
            printBuf, rcsm.uTeleserviceID,rcsm.bIsServicePresent,rcsm.uServicecategory,
            rcsm.sAddress.digit_mode, rcsm.sAddress.number_mode,rcsm.sAddress.number_type);
    closeRequest;

    printRequest(pRI->token, pRI->pCI->requestNumber);

    return status;
}

/**************************************************************************
  Modified by CYIT 20120825 ----- start -----
**************************************************************************/
static void dispatchApnInfo( Parcel &p, RequestInfo * pRI )
{
    int32_t                         t = 0;
    char                            *s = NULL;
    status_t                       status;
    RIL_APN_Info                data;

    memset( &data, 0, sizeof( RIL_APN_Info ) );

    status = p.readInt32( &t );
    if ( status != NO_ERROR )
    {
        goto invalid;
    }
    data.cid = ( int )t;

    data.apn = strdupReadString( p );

    startRequest;
    appendPrintBuf( "dispatchApnInfo %s[cid = %d, apn = %s]", printBuf, data.cid, data.apn );
    closeRequest;

    printRequest( pRI->token, pRI->pCI->requestNumber );
    s_callbacks[pRI->client_id].onRequest( pRI->pCI->requestNumber, &data, sizeof( RIL_APN_Info ), pRI );

#ifdef MEMSET_FREED
    memsetString( data.apn );
#endif

    free( data.apn );

#ifdef MEMSET_FREED
    memset( &data, 0, sizeof( RIL_APN_Info ) );
#endif

    return;

invalid:
    invalidCommandBlock( pRI );
    return;
}



static int responseApnInfo( Parcel &p, void * response, size_t responselen )
{
    int num;

    if (response == NULL && responselen != 0) {
        LOGE("invalid response: NULL");
        return RIL_ERRNO_INVALID_RESPONSE;
    }

    if (responselen % sizeof ( RIL_APN_Info * ) != 0) {
        LOGE("invalid response length %d expected multiple of %d\n", (int)responselen, (int)sizeof (RIL_APN_Info *));
        return RIL_ERRNO_INVALID_RESPONSE;
    }

    startResponse;
    /* number of apn info's */
    num = responselen / sizeof( RIL_APN_Info * );
    p.writeInt32(num);

    for ( int i = 0 ; i < num ; i++ ) {
        RIL_APN_Info *p_cur = (( RIL_APN_Info ** ) response )[i];
        /* each apn info */
        p.writeInt32( p_cur->cid );
        writeStringToParcel( p, p_cur->apn );

        appendPrintBuf("responseApnInfo %s[cid = %d, apn = %s]",  printBuf,  p_cur->cid, p_cur->apn );
    }
    removeLastChar;
    closeResponse;

    return 0;
}

static int responsePdpInfo( Parcel &p, void * response, size_t responselen )
{
    int num;

    if (response == NULL && responselen != 0) {
        LOGE("invalid response: NULL");
        return RIL_ERRNO_INVALID_RESPONSE;
    }

    if (responselen % sizeof ( RIL_Pdp_Info * ) != 0) {
        LOGE("invalid response length %d expected multiple of %d\n", (int)responselen, (int)sizeof (RIL_Pdp_Info *));
        return RIL_ERRNO_INVALID_RESPONSE;
    }

    startResponse;
    num = responselen / sizeof( RIL_Pdp_Info * );
    p.writeInt32(num);

    for ( int i = 0 ; i < num ; i++ ) {
        RIL_Pdp_Info *p_cur = (( RIL_Pdp_Info ** ) response )[i];
        p.writeInt32( p_cur->cid );
        p.writeInt32( p_cur->state);

        appendPrintBuf("responsePdpInfo %s[cid = %d, state = %d]",  printBuf,  p_cur->cid, p_cur->state );
    }
    removeLastChar;
    closeResponse;

    return 0;
}

static int responseQosInfo( Parcel &p, void * response, size_t responselen )
{
    int num;

    if (response == NULL && responselen != 0) {
        LOGE("invalid response: NULL");
        return RIL_ERRNO_INVALID_RESPONSE;
    }

    if (responselen % sizeof ( RIL_QOS_Info * ) != 0) {
        LOGE("invalid response length %d expected multiple of %d\n", (int)responselen, (int)sizeof (RIL_QOS_Info *));
        return RIL_ERRNO_INVALID_RESPONSE;
    }

    startResponse;
    num = responselen / sizeof( RIL_QOS_Info * );
    p.writeInt32(num);

    for ( int i = 0 ; i < num ; i++ ) {
        RIL_QOS_Info *p_cur = (( RIL_QOS_Info ** ) response )[i];
        /* each apn info */
        p.writeInt32( p_cur->cid );
        p.writeInt32( p_cur->trafficclass );
        p.writeInt32( p_cur->maxbitrateul );
        p.writeInt32( p_cur->maxbitratedl );

        appendPrintBuf("responseQosInfo %s[cid = %d, trafficclass = %d maxbitrateul = %d maxbitratedl = %d]",  
            printBuf,  p_cur->cid, p_cur->trafficclass, p_cur->maxbitrateul, p_cur->maxbitratedl );
    }
    removeLastChar;
    closeResponse;

    return 0;
}

static int responseCellInfo( Parcel &p, void * response, size_t responselen )
{
    if (response == NULL && responselen != 0) {
        LOGE("invalid response: NULL");
        return RIL_ERRNO_INVALID_RESPONSE;
    }

    if (responselen % sizeof ( RIL_CELL_Info ) != 0) {
        LOGE("invalid response length %d expected multiple of %d\n", (int)responselen, (int)sizeof (RIL_CELL_Info *));
        return RIL_ERRNO_INVALID_RESPONSE;
    }

    startResponse;

    /*cell info */
    RIL_CELL_Info *p_cur = ( RIL_CELL_Info * ) response;
    p.writeInt32( p_cur->cellfreq );
    p.writeInt32( p_cur->cellid );
    p.writeInt32( p_cur->cellrscp );
    p.writeInt32( p_cur->tdcellnum );
    p.writeInt32( p_cur->tdcell1freq );
    p.writeInt32( p_cur->tdcell1id );
    p.writeInt32( p_cur->tdcell1rscp );
    p.writeInt32( p_cur->tdcell2freq );
    p.writeInt32( p_cur->tdcell2id );
    p.writeInt32( p_cur->tdcell2rscp );
    p.writeInt32( p_cur->gsmcellnum );
    p.writeInt32( p_cur->gsmcell1freq );
    p.writeInt32( p_cur->gsmcell1id );
    p.writeInt32( p_cur->gsmcell1rscp );
    p.writeInt32( p_cur->gsmcell2freq );
    p.writeInt32( p_cur->gsmcell2id );
    p.writeInt32( p_cur->gsmcell2rscp );

    appendPrintBuf("responseCellInfo %s[cellfreq = %d, cellid = %d, cellrscp = %d, tdcellnum = %d,
                      tdcell1freq = %d, tdcell1id = %d, tdcell1rscp = %d, 
                      tdcell2freq = %d, tdcell2id = %d, tdcell2rscp = %d, gsmcellnum = %d,
                      gsmcell1freq = %d, gsmcell1id = %d, gsmcell1rscp = %d, 
                      gsmcell2freq = %d, gsmcell2id = %d, gsmcell2rscp = %d]",  
            printBuf, p_cur->cellfreq, p_cur->cellid, p_cur->cellrscp, p_cur->tdcellnum 
                      p_cur->tdcell1freq, p_cur->tdcell1id, p_cur->tdcell1rscp, 
                      p_cur->tdcell2freq, p_cur->tdcell2id, p_cur->tdcell2rscp, p_cur->gsmcellnum, 
                      p_cur->gsmcell1freq, p_cur->gsmcell1id, p_cur->gsmcell1rscp, 
                      p_cur->gsmcell2freq, p_cur->gsmcell2id, p_cur->gsmcell2rscp);
    removeLastChar;
    closeResponse;

    return 0;
}

static int responsePrenet( Parcel &p, void * response, size_t responselen )
{
    int num;

    if (response == NULL && responselen != 0) {
        LOGE("invalid response: NULL");
        return RIL_ERRNO_INVALID_RESPONSE;
    }

    if (responselen % sizeof ( RIL_PREFER_NETLIST * ) != 0) {
        LOGE("invalid response length %d expected multiple of %d\n", (int)responselen, (int)sizeof (RIL_PREFER_NETLIST *));
        return RIL_ERRNO_INVALID_RESPONSE;
    }

    startResponse;
    num = responselen / sizeof( RIL_PREFER_NETLIST * );
    p.writeInt32(num);

    for ( int i = 0 ; i < num ; i++ ) {
        RIL_PREFER_NETLIST *p_cur = (( RIL_PREFER_NETLIST ** ) response )[i];
        
        /* each prefer network list info */
        p.writeInt32( p_cur->index );
        p.writeInt32( p_cur->format );
        writeStringToParcel(p, p_cur->oper );
        p.writeInt32( p_cur->gsm );
        p.writeInt32( p_cur->gsm_compact );
        p.writeInt32( p_cur->utra );

        appendPrintBuf("responsePrenet %s[index = %d, format = %d  oper = %s gsm = %d gsm_compact = %d utra = %d]",  
            printBuf,  p_cur->index, p_cur->format, p_cur->oper, p_cur->gsm, p_cur->gsm_compact, p_cur->utra );
    }
    removeLastChar;
    closeResponse;

    return 0;
}
/**************************************************************************
  Modified by CYIT 20120825 ----- end -----
**************************************************************************/

static void
dispatchCdmaSms(Parcel &p, RequestInfo *pRI) {
    RIL_CDMA_SMS_Message rcsm;

    LOGD("dispatchCdmaSms");
    if (NO_ERROR != constructCdmaSms(p, pRI, rcsm)) {
        goto invalid;
    }

    s_callbacks[pRI->client_id].onRequest(pRI->pCI->requestNumber, &rcsm, sizeof(rcsm),pRI);

#ifdef MEMSET_FREED
    memset(&rcsm, 0, sizeof(rcsm));
#endif

    return;

invalid:
    invalidCommandBlock(pRI);
    return;
}

static void
dispatchImsCdmaSms(Parcel &p, RequestInfo *pRI) {
    RIL_IMS_SMS_Message rism;
    RIL_CDMA_SMS_Message rcsm;

    LOGD("dispatchImsCdmaSms");
    if (NO_ERROR != constructCdmaSms(p, pRI, rcsm)) {
        goto invalid;
    }
    memset(&rism, 0, sizeof(rism));
    rism.tech = RADIO_TECH_3GPP2;
    rism.message.cdmaMessage = &rcsm;

    s_callbacks[pRI->client_id].onRequest(pRI->pCI->requestNumber, &rism,
            sizeof(RIL_RadioTechnologyFamily)+sizeof(rcsm),pRI);

#ifdef MEMSET_FREED
    memset(&rcsm, 0, sizeof(rcsm));
    memset(&rism, 0, sizeof(rism));
#endif

    return;

invalid:
    invalidCommandBlock(pRI);
    return;
}

static void
dispatchImsGsmSms(Parcel &p, RequestInfo *pRI) {
    RIL_IMS_SMS_Message rism;
    int32_t countStrings;
    status_t status;
    size_t datalen;
    char **pStrings;

    status = p.readInt32 (&countStrings);

    if (status != NO_ERROR) {
        goto invalid;
    }

    memset(&rism, 0, sizeof(rism));
    rism.tech = RADIO_TECH_3GPP;

    startRequest;
    appendPrintBuf("%stech=%d,", printBuf, rism.tech);
    if (countStrings == 0) {
        // just some non-null pointer
        pStrings = (char **)alloca(sizeof(char *));
        datalen = 0;
    } else if (((int)countStrings) == -1) {
        pStrings = NULL;
        datalen = 0;
    } else {
        datalen = sizeof(char *) * countStrings;

        pStrings = (char **)alloca(datalen);

        for (int i = 0 ; i < countStrings ; i++) {
            pStrings[i] = strdupReadString(p);
            appendPrintBuf("%s%s,", printBuf, pStrings[i]);
        }
    }
    removeLastChar;
    closeRequest;
    printRequest(pRI->token, pRI->pCI->requestNumber);

    rism.message.gsmMessage = pStrings;
    s_callbacks[pRI->client_id].onRequest(pRI->pCI->requestNumber, &rism,
            sizeof(RIL_RadioTechnologyFamily)+datalen, pRI);

    if (pStrings != NULL) {
        for (int i = 0 ; i < countStrings ; i++) {
#ifdef MEMSET_FREED
            memsetString (pStrings[i]);
#endif
            free(pStrings[i]);
        }

#ifdef MEMSET_FREED
        memset(pStrings, 0, datalen);
#endif
    }

#ifdef MEMSET_FREED
    memset(&rism, 0, sizeof(rism));
#endif
    return;
invalid:
    LOGE("dispatchImsGsmSms invalid block");
    invalidCommandBlock(pRI);
    return;
}

static void
dispatchImsSms(Parcel &p, RequestInfo *pRI) {
    int32_t  t;
    status_t status = p.readInt32(&t);
    RIL_RadioTechnologyFamily tech;

    LOGD("dispatchImsSms");
    if (status != NO_ERROR) {
        goto invalid;
    }
    tech = (RIL_RadioTechnologyFamily) t;

    if (RADIO_TECH_3GPP == tech) {
        dispatchImsGsmSms(p, pRI);
    } else if (RADIO_TECH_3GPP2 == tech) {
        dispatchImsCdmaSms(p, pRI);
    } else {
        LOGE("requestImsSendSMS invalid tech value =%d", tech);
    }

    return;

invalid:
    invalidCommandBlock(pRI);
    return;
}

static void
dispatchCdmaSmsAck(Parcel &p, RequestInfo *pRI) {
    RIL_CDMA_SMS_Ack rcsa;
    int32_t  t;
    status_t status;
    int32_t digitCount;

    memset(&rcsa, 0, sizeof(rcsa));

    status = p.readInt32(&t);
    rcsa.uErrorClass = (RIL_CDMA_SMS_ErrorClass) t;

    status = p.readInt32(&t);
    rcsa.uSMSCauseCode = (int) t;

    if (status != NO_ERROR) {
        goto invalid;
    }

    startRequest;
    appendPrintBuf("%suErrorClass=%d, uTLStatus=%d, ",
            printBuf, rcsa.uErrorClass, rcsa.uSMSCauseCode);
    closeRequest;

    printRequest(pRI->token, pRI->pCI->requestNumber);

    s_callbacks[pRI->client_id].onRequest(pRI->pCI->requestNumber, &rcsa, sizeof(rcsa),pRI);

#ifdef MEMSET_FREED
    memset(&rcsa, 0, sizeof(rcsa));
#endif

    return;

invalid:
    invalidCommandBlock(pRI);
    return;
}

static void
dispatchGsmBrSmsCnf(Parcel &p, RequestInfo *pRI) {
    int32_t t;
    status_t status;
    int32_t num;

    status = p.readInt32(&num);
    if (status != NO_ERROR) {
        goto invalid;
    }

    RIL_GSM_BroadcastSmsConfigInfo gsmBci[num];
    RIL_GSM_BroadcastSmsConfigInfo *gsmBciPtrs[num];

    startRequest;
    for (int i = 0 ; i < num ; i++ ) {
        gsmBciPtrs[i] = &gsmBci[i];

        status = p.readInt32(&t);
        gsmBci[i].fromServiceId = (int) t;

        status = p.readInt32(&t);
        gsmBci[i].toServiceId = (int) t;

        status = p.readInt32(&t);
        gsmBci[i].fromCodeScheme = (int) t;

        status = p.readInt32(&t);
        gsmBci[i].toCodeScheme = (int) t;

        status = p.readInt32(&t);
        gsmBci[i].selected = (uint8_t) t;

        appendPrintBuf("%s [%d: fromServiceId=%d, toServiceId =%d, \
              fromCodeScheme=%d, toCodeScheme=%d, selected =%d]", printBuf, i,
              gsmBci[i].fromServiceId, gsmBci[i].toServiceId,
              gsmBci[i].fromCodeScheme, gsmBci[i].toCodeScheme,
              gsmBci[i].selected);
    }
    closeRequest;

    if (status != NO_ERROR) {
        goto invalid;
    }

    s_callbacks[pRI->client_id].onRequest(pRI->pCI->requestNumber,
                          gsmBciPtrs,
                          num * sizeof(RIL_GSM_BroadcastSmsConfigInfo *),
                          pRI);

#ifdef MEMSET_FREED
    memset(gsmBci, 0, num * sizeof(RIL_GSM_BroadcastSmsConfigInfo));
    memset(gsmBciPtrs, 0, num * sizeof(RIL_GSM_BroadcastSmsConfigInfo *));
#endif

    return;

invalid:
    invalidCommandBlock(pRI);
    return;
}

static void
dispatchCdmaBrSmsCnf(Parcel &p, RequestInfo *pRI) {
    int32_t t;
    status_t status;
    int32_t num;

    status = p.readInt32(&num);
    if (status != NO_ERROR) {
        goto invalid;
    }

    RIL_CDMA_BroadcastSmsConfigInfo cdmaBci[num];
    RIL_CDMA_BroadcastSmsConfigInfo *cdmaBciPtrs[num];

    startRequest;
    for (int i = 0 ; i < num ; i++ ) {
        cdmaBciPtrs[i] = &cdmaBci[i];

        status = p.readInt32(&t);
        cdmaBci[i].service_category = (int) t;

        status = p.readInt32(&t);
        cdmaBci[i].language = (int) t;

        status = p.readInt32(&t);
        cdmaBci[i].selected = (uint8_t) t;

        appendPrintBuf("%s [%d: service_category=%d, language =%d, \
              entries.bSelected =%d]", printBuf, i, cdmaBci[i].service_category,
              cdmaBci[i].language, cdmaBci[i].selected);
    }
    closeRequest;

    if (status != NO_ERROR) {
        goto invalid;
    }

    s_callbacks[pRI->client_id].onRequest(pRI->pCI->requestNumber,
                          cdmaBciPtrs,
                          num * sizeof(RIL_CDMA_BroadcastSmsConfigInfo *),
                          pRI);

#ifdef MEMSET_FREED
    memset(cdmaBci, 0, num * sizeof(RIL_CDMA_BroadcastSmsConfigInfo));
    memset(cdmaBciPtrs, 0, num * sizeof(RIL_CDMA_BroadcastSmsConfigInfo *));
#endif

    return;

invalid:
    invalidCommandBlock(pRI);
    return;
}

static void dispatchRilCdmaSmsWriteArgs(Parcel &p, RequestInfo *pRI) {
    RIL_CDMA_SMS_WriteArgs rcsw;
    int32_t  t;
    uint32_t ut;
    uint8_t  uct;
    status_t status;
    int32_t  digitCount;

    memset(&rcsw, 0, sizeof(rcsw));

    status = p.readInt32(&t);
    rcsw.status = t;

    status = p.readInt32(&t);
    rcsw.message.uTeleserviceID = (int) t;

    status = p.read(&uct,sizeof(uct));
    rcsw.message.bIsServicePresent = (uint8_t) uct;

    status = p.readInt32(&t);
    rcsw.message.uServicecategory = (int) t;

    status = p.readInt32(&t);
    rcsw.message.sAddress.digit_mode = (RIL_CDMA_SMS_DigitMode) t;

    status = p.readInt32(&t);
    rcsw.message.sAddress.number_mode = (RIL_CDMA_SMS_NumberMode) t;

    status = p.readInt32(&t);
    rcsw.message.sAddress.number_type = (RIL_CDMA_SMS_NumberType) t;

    status = p.readInt32(&t);
    rcsw.message.sAddress.number_plan = (RIL_CDMA_SMS_NumberPlan) t;

    status = p.read(&uct,sizeof(uct));
    rcsw.message.sAddress.number_of_digits = (uint8_t) uct;

    for(digitCount = 0 ; digitCount < RIL_CDMA_SMS_ADDRESS_MAX; digitCount ++) {
        status = p.read(&uct,sizeof(uct));
        rcsw.message.sAddress.digits[digitCount] = (uint8_t) uct;
    }

    status = p.readInt32(&t);
    rcsw.message.sSubAddress.subaddressType = (RIL_CDMA_SMS_SubaddressType) t;

    status = p.read(&uct,sizeof(uct));
    rcsw.message.sSubAddress.odd = (uint8_t) uct;

    status = p.read(&uct,sizeof(uct));
    rcsw.message.sSubAddress.number_of_digits = (uint8_t) uct;

    for(digitCount = 0 ; digitCount < RIL_CDMA_SMS_SUBADDRESS_MAX; digitCount ++) {
        status = p.read(&uct,sizeof(uct));
        rcsw.message.sSubAddress.digits[digitCount] = (uint8_t) uct;
    }

    status = p.readInt32(&t);
    rcsw.message.uBearerDataLen = (int) t;

    for(digitCount = 0 ; digitCount < RIL_CDMA_SMS_BEARER_DATA_MAX; digitCount ++) {
        status = p.read(&uct, sizeof(uct));
        rcsw.message.aBearerData[digitCount] = (uint8_t) uct;
    }

    if (status != NO_ERROR) {
        goto invalid;
    }

    startRequest;
    appendPrintBuf("%sstatus=%d, message.uTeleserviceID=%d, message.bIsServicePresent=%d, \
            message.uServicecategory=%d, message.sAddress.digit_mode=%d, \
            message.sAddress.number_mode=%d, \
            message.sAddress.number_type=%d, ",
            printBuf, rcsw.status, rcsw.message.uTeleserviceID, rcsw.message.bIsServicePresent,
            rcsw.message.uServicecategory, rcsw.message.sAddress.digit_mode,
            rcsw.message.sAddress.number_mode,
            rcsw.message.sAddress.number_type);
    closeRequest;

    printRequest(pRI->token, pRI->pCI->requestNumber);

    s_callbacks[pRI->client_id].onRequest(pRI->pCI->requestNumber, &rcsw, sizeof(rcsw),pRI);

#ifdef MEMSET_FREED
    memset(&rcsw, 0, sizeof(rcsw));
#endif

    return;

invalid:
    invalidCommandBlock(pRI);
    return;

}

/**
* Callee expects const RIL_Depersonalization *
* Payload is:
*   int32_t type
*   String pin
*/
static void
dispatchDepersonalization(Parcel &p, RequestInfo *pRI) {
    RIL_Depersonalization d;
    int32_t t;
    status_t status;

    memset (&d, 0, sizeof(d));

    // note we only check status at the end

    status = p.readInt32(&t);
    d.depersonalizationType = (RIL_PersoSubstate)t;

    d.depersonalizationCode = strdupReadString(p);

    startRequest;
    appendPrintBuf("%stype=%d,pin=****",
        printBuf, d.depersonalizationType);
    closeRequest;
    printRequest(pRI->token, pRI->pCI->requestNumber);

    if (status != NO_ERROR) {
        goto invalid;
    }

    s_callbacks[pRI->client_id].onRequest(pRI->pCI->requestNumber, &d, sizeof(d), pRI);


#ifdef MEMSET_FREED
    memsetString(d.depersonalizationCode);
#endif

    free(d.depersonalizationCode);

#ifdef MEMSET_FREED
    memset(&d, 0, sizeof(d));
#endif

    return;
invalid:
    free(d.depersonalizationCode);
    invalidCommandBlock(pRI);
    return;
}

static void dispatchUiccSubscripton(Parcel &p, RequestInfo *pRI) {
    RIL_SelectUiccSub uicc_sub;
    status_t status;
    int32_t  t;
    memset(&uicc_sub, 0, sizeof(uicc_sub));

    status = p.readInt32(&t);
    uicc_sub.slot = (int) t;

    status = p.readInt32(&t);
    uicc_sub.app_index = (int) t;

    status = p.readInt32(&t);
    uicc_sub.sub_num = (RIL_Subscription) t;

    status = p.readInt32(&t);
    uicc_sub.act_status = (RIL_UiccSubActStatus) t;

    if (status != NO_ERROR) {
        goto invalid;
    }

    startRequest;

    appendPrintBuf("slot=%d, app_index=%d, act_status = %d", uicc_sub.slot, uicc_sub.app_index, uicc_sub.act_status);
    LOGD("dispatchUiccSubscription, slot=%d, app_index=%d, act_status = %d", uicc_sub.slot, uicc_sub.app_index, uicc_sub.act_status);
    closeRequest;
    printRequest(pRI->token, pRI->pCI->requestNumber);
    s_callbacks[pRI->client_id].onRequest(pRI->pCI->requestNumber, &uicc_sub, sizeof(uicc_sub), pRI);
#ifdef MEMSET_FREED
    memset(&uicc_sub, 0, sizeof(uicc_sub));
#endif
    return;

invalid:
    invalidCommandBlock(pRI);
    return;
}

// -------------------------------------------------------------
//   modify by CYIT 20110819            ----- start -----
// -------------------------------------------------------------
static void dispatchUSSD( Parcel &p, RequestInfo * pRI )
{
    int32_t t = 0;
    status_t status;
    T_USSD_INFO data;

    memset( &data, 0, sizeof( T_USSD_INFO ) );

    data.m_ussdstring = strdupReadString( p );
    status = p.readInt32( &t );
    if ( status != NO_ERROR )
    {
        goto invalid;
    }
    data.m_dcs = ( int )t;

    startRequest;
    appendPrintBuf( "%s m_ussdstring = %s, m_dcs = %d",
        printBuf,
        data.m_ussdstring, data.m_dcs );
    closeRequest;

    printRequest( pRI->token, pRI->pCI->requestNumber );
    s_callbacks[pRI->client_id].onRequest( pRI->pCI->requestNumber, &data, sizeof( T_USSD_INFO ), pRI );

#ifdef MEMSET_FREED
    memsetString( data.m_ussdstring );
#endif

    free( data.m_ussdstring );

#ifdef MEMSET_FREED
    memset( &data, 0, sizeof( T_USSD_INFO ) );
#endif

    return;

invalid:
    invalidCommandBlock( pRI );
    return;
}
// -------------------------------------------------------------
//   modify by CYIT 20110819 for            -----  end  -----
// -------------------------------------------------------------



static int
blockingWrite(int fd, const void *buffer, size_t len) {
    size_t writeOffset = 0;
    const uint8_t *toWrite;

    toWrite = (const uint8_t *)buffer;

    while (writeOffset < len) {
        ssize_t written;
        do {
            written = write (fd, toWrite + writeOffset,
                                len - writeOffset);
        } while (written < 0 && errno == EINTR);

        if (written >= 0) {
            writeOffset += written;
        } else {   // written < 0
            LOGE ("RIL Response: unexpected error on write errno:%d", errno);
            close(fd);
            return -1;
        }
    }

    return 0;
}

static int
sendResponseRaw (const void *data, size_t dataSize, int client_id) {
    int fd = s_fdCommand[client_id]; //fd is chosen from global s_fdCommand vaiable
    int ret;
    uint32_t header;

    if (s_fdCommand[client_id] < 0) {
        return -1;
    }

    if (dataSize > MAX_COMMAND_BYTES) {
        LOGE("RIL: packet larger than %u (%u)",
                MAX_COMMAND_BYTES, (unsigned int )dataSize);

        return -1;
    }

    pthread_mutex_lock(&s_writeMutex);

    header = htonl(dataSize);

    ret = blockingWrite(fd, (void *)&header, sizeof(header));

    if (ret < 0) {
        pthread_mutex_unlock(&s_writeMutex);
        return ret;
    }

    ret = blockingWrite(fd, data, dataSize);

    if (ret < 0) {
        pthread_mutex_unlock(&s_writeMutex);
        return ret;
    }

    pthread_mutex_unlock(&s_writeMutex);

    return 0;
}

static int
sendResponse (Parcel &p, int client_id) {
    printResponse;
    return sendResponseRaw(p.data(), p.dataSize(), client_id);
}

/** response is an int* pointing to an array of ints*/

static int
responseInts(Parcel &p, void *response, size_t responselen) {
    int numInts;

    if (response == NULL && responselen != 0) {
        LOGE("invalid response: NULL");
        return RIL_ERRNO_INVALID_RESPONSE;
    }
    if (responselen % sizeof(int) != 0) {
        LOGE("invalid response length %d expected multiple of %d\n",
            (int)responselen, (int)sizeof(int));
        return RIL_ERRNO_INVALID_RESPONSE;
    }

    int *p_int = (int *) response;

    numInts = responselen / sizeof(int *);
    LOGD("responselen is %d, numInts is %d", responselen, numInts);
    p.writeInt32 (numInts);

    /* each int*/
    startResponse;
    for (int i = 0 ; i < numInts ; i++) {
        appendPrintBuf("%s%d,", printBuf, p_int[i]);
        p.writeInt32(p_int[i]);
        LOGD("write int %d", p_int[i]);
    }
    removeLastChar;
    closeResponse;

    return 0;
}

/** response is a char **, pointing to an array of char *'s */
static int responseStrings(Parcel &p, void *response, size_t responselen) {
    int numStrings;

    if (response == NULL && responselen != 0) {
        LOGE("invalid response: NULL");
        return RIL_ERRNO_INVALID_RESPONSE;
    }
    if (responselen % sizeof(char *) != 0) {
        LOGE("invalid response length %d expected multiple of %d\n",
            (int)responselen, (int)sizeof(char *));
        return RIL_ERRNO_INVALID_RESPONSE;
    }

    if (response == NULL) {
        p.writeInt32 (0);
    } else {
        char **p_cur = (char **) response;

        numStrings = responselen / sizeof(char *);
        p.writeInt32 (numStrings);

        /* each string*/
        startResponse;
        for (int i = 0 ; i < numStrings ; i++) {
            appendPrintBuf("%s%s,", printBuf, (char*)p_cur[i]);
            writeStringToParcel (p, p_cur[i]);
        }
        removeLastChar;
        closeResponse;
    }
    return 0;
}


/**
 * NULL strings are accepted
 * FIXME currently ignores responselen
 */
static int responseString(Parcel &p, void *response, size_t responselen) {
    /* one string only */
    startResponse;
    appendPrintBuf("%s%s", printBuf, (char*)response);
    closeResponse;

    writeStringToParcel(p, (const char *)response);

    return 0;
}

static int responseVoid(Parcel &p, void *response, size_t responselen) {
    startResponse;
    removeLastChar;
    return 0;
}

static int responseCallList(Parcel &p, void *response, size_t responselen) {
    int num;

    if (response == NULL && responselen != 0) {
        LOGE("invalid response: NULL");
        return RIL_ERRNO_INVALID_RESPONSE;
    }

    if (responselen % sizeof (RIL_Call *) != 0) {
        LOGE("invalid response length %d expected multiple of %d\n",
            (int)responselen, (int)sizeof (RIL_Call *));
        return RIL_ERRNO_INVALID_RESPONSE;
    }

    startResponse;
    /* number of call info's */
    num = responselen / sizeof(RIL_Call *);
    p.writeInt32(num);

    for (int i = 0 ; i < num ; i++) {
        RIL_Call *p_cur = ((RIL_Call **) response)[i];
        /* each call info */
        p.writeInt32(p_cur->state);
        p.writeInt32(p_cur->index);
        p.writeInt32(p_cur->toa);
        p.writeInt32(p_cur->isMpty);
        p.writeInt32(p_cur->isMT);
        p.writeInt32(p_cur->als);
        p.writeInt32(p_cur->isVoice);
        p.writeInt32(p_cur->isVoicePrivacy);
        writeStringToParcel(p, p_cur->number);
        p.writeInt32(p_cur->numberPresentation);
        writeStringToParcel(p, p_cur->name);
        p.writeInt32(p_cur->namePresentation);
        // Remove when partners upgrade to version 3
        if ((s_callbacks[0].version < 3) || (s_callbacks[1].version < 3) || (p_cur->uusInfo == NULL || p_cur->uusInfo->uusData == NULL)) {
            p.writeInt32(0); /* UUS Information is absent */
        } else {
            RIL_UUS_Info *uusInfo = p_cur->uusInfo;
            p.writeInt32(1); /* UUS Information is present */
            p.writeInt32(uusInfo->uusType);
            p.writeInt32(uusInfo->uusDcs);
            p.writeInt32(uusInfo->uusLength);
            p.write(uusInfo->uusData, uusInfo->uusLength);
        }
        appendPrintBuf("%s[id=%d,%s,toa=%d,",
            printBuf,
            p_cur->index,
            callStateToString(p_cur->state),
            p_cur->toa);
        appendPrintBuf("%s%s,%s,als=%d,%s,%s,",
            printBuf,
            (p_cur->isMpty)?"conf":"norm",
            (p_cur->isMT)?"mt":"mo",
            p_cur->als,
            (p_cur->isVoice)?"voc":"nonvoc",
            (p_cur->isVoicePrivacy)?"evp":"noevp");
        appendPrintBuf("%s%s,cli=%d,name='%s',%d]",
            printBuf,
            p_cur->number,
            p_cur->numberPresentation,
            p_cur->name,
            p_cur->namePresentation);
    }
    removeLastChar;
    closeResponse;

    return 0;
}

static int responseSMS(Parcel &p, void *response, size_t responselen) {
    if (response == NULL) {
        LOGE("invalid response: NULL");
        return RIL_ERRNO_INVALID_RESPONSE;
    }

    if (responselen != sizeof (RIL_SMS_Response) ) {
        LOGE("invalid response length %d expected %d",
                (int)responselen, (int)sizeof (RIL_SMS_Response));
        return RIL_ERRNO_INVALID_RESPONSE;
    }

    RIL_SMS_Response *p_cur = (RIL_SMS_Response *) response;

    p.writeInt32(p_cur->messageRef);
    writeStringToParcel(p, p_cur->ackPDU);
    p.writeInt32(p_cur->errorCode);

    startResponse;
    appendPrintBuf("%s%d,%s,%d", printBuf, p_cur->messageRef,
        (char*)p_cur->ackPDU, p_cur->errorCode);
    closeResponse;

    return 0;
}

/*
static int responseDataCallList(Parcel &p, void *response, size_t responselen)
{
    if (response == NULL && responselen != 0) {
        LOGE("invalid response: NULL");
        return RIL_ERRNO_INVALID_RESPONSE;
    }

    if (responselen % sizeof(RIL_Data_Call_Response) != 0) {
        LOGE("invalid response length %d expected multiple of %d",
                (int)responselen, (int)sizeof(RIL_Data_Call_Response));
        return RIL_ERRNO_INVALID_RESPONSE;
    }

    int num = responselen / sizeof(RIL_Data_Call_Response);
    p.writeInt32(num);

    RIL_Data_Call_Response *p_cur = (RIL_Data_Call_Response *) response;
    startResponse;
    int i;
    for (i = 0; i < num; i++) {
        p.writeInt32(p_cur[i].cid);
        p.writeInt32(p_cur[i].active);
        writeStringToParcel(p, p_cur[i].type);
        writeStringToParcel(p, p_cur[i].apn);
        writeStringToParcel(p, p_cur[i].address);
        p.writeInt32(p_cur[i].radioTech);
        p.writeInt32(p_cur[i].inactiveReason);
        appendPrintBuf("%s[cid=%d,%s,%s,%s,%s,%d,%d],", printBuf,
            p_cur[i].cid,
            (p_cur[i].active==0)?"down":"up",
            (char*)p_cur[i].type,
            (char*)p_cur[i].apn,
            (char*)p_cur[i].address,
            p_cur[i].radioTech,
            p_cur[i].inactiveReason);
    }
    removeLastChar;
    closeResponse;

    return 0;
}
*/

static int responseDataCallList(Parcel &p, void *response, size_t responselen)
{
    // Write version
    p.writeInt32(s_callbacks[0].version);

    if (response == NULL && responselen != 0) {
        LOGE("invalid response: NULL");
        return RIL_ERRNO_INVALID_RESPONSE;
    }

    if (responselen % sizeof(RIL_Data_Call_Response_v6) != 0) {
        LOGE("invalid response length %d expected multiple of %d",
                (int)responselen, (int)sizeof(RIL_Data_Call_Response_v6));
        return RIL_ERRNO_INVALID_RESPONSE;
    }

    int num = responselen / sizeof(RIL_Data_Call_Response_v6);
    p.writeInt32(num);

    RIL_Data_Call_Response_v6 *p_cur = (RIL_Data_Call_Response_v6 *) response;
    startResponse;
    int i;
    for (i = 0; i < num; i++) {
        p.writeInt32((int)p_cur[i].status);
        p.writeInt32(p_cur[i].suggestedRetryTime);
        p.writeInt32(p_cur[i].cid);
        p.writeInt32(p_cur[i].active);
        writeStringToParcel(p, p_cur[i].type);
        writeStringToParcel(p, p_cur[i].ifname);
        writeStringToParcel(p, p_cur[i].addresses);
        writeStringToParcel(p, p_cur[i].dnses);
        writeStringToParcel(p, p_cur[i].gateways);
        appendPrintBuf("%s[status=%d,cid=%d,%s,%s,%s,%s,%s],", printBuf,
                p_cur[i].status,
                p_cur[i].cid,
                (p_cur[i].active==0)?"down":"up",
                (char*)p_cur[i].ifname,
                (char*)p_cur[i].addresses,
                (char*)p_cur[i].dnses,
                (char*)p_cur[i].gateways);
    }
    removeLastChar;
    closeResponse;

    return 0;
}

static int responseRaw(Parcel &p, void *response, size_t responselen) {
    if (response == NULL && responselen != 0) {
        LOGE("invalid response: NULL with responselen != 0");
        return RIL_ERRNO_INVALID_RESPONSE;
    }

    // The java code reads -1 size as null byte array
    if (response == NULL) {
        p.writeInt32(-1);
    } else {
        p.writeInt32(responselen);
        p.write(response, responselen);
    }

    return 0;
}


static int responseSIM_IO(Parcel &p, void *response, size_t responselen) {
    if (response == NULL) {
        LOGE("invalid response: NULL");
        return RIL_ERRNO_INVALID_RESPONSE;
    }

    if (responselen != sizeof (RIL_SIM_IO_Response) ) {
        LOGE("invalid response length was %d expected %d",
                (int)responselen, (int)sizeof (RIL_SIM_IO_Response));
        return RIL_ERRNO_INVALID_RESPONSE;
    }

    RIL_SIM_IO_Response *p_cur = (RIL_SIM_IO_Response *) response;
    p.writeInt32(p_cur->sw1);
    p.writeInt32(p_cur->sw2);
    writeStringToParcel(p, p_cur->simResponse);

    startResponse;
    appendPrintBuf("%ssw1=0x%X,sw2=0x%X,%s", printBuf, p_cur->sw1, p_cur->sw2,
        (char*)p_cur->simResponse);
    closeResponse;


    return 0;
}


// modify by CYIT 20111202 ----- start ----- 
static int responseReadPbRec(Parcel &p, void *response, size_t responselen) {
    if (response == NULL) {
        LOGE("invalid response: NULL");
        return RIL_ERRNO_INVALID_RESPONSE;
    }

    if (responselen != sizeof (RIL_Read_PB_Record) ) {
        LOGE("invalid response length was %d expected %d",
                (int)responselen, (int)sizeof (RIL_Read_PB_Record));
        return RIL_ERRNO_INVALID_RESPONSE;
    }

    RIL_Read_PB_Record *p_cur = (RIL_Read_PB_Record *) response;
    p.writeInt32(p_cur->index);
    writeStringToParcel(p, p_cur->number);
    p.writeInt32(p_cur->numType);
    writeStringToParcel(p, p_cur->anr1);
    p.writeInt32(p_cur->anr1Type);
    writeStringToParcel(p, p_cur->anr2);
    p.writeInt32(p_cur->anr2Type);
    writeStringToParcel(p, p_cur->anr3);
    p.writeInt32(p_cur->anr3Type);
    writeStringToParcel(p, p_cur->alpha);
    p.writeInt32(p_cur->coding);
    writeStringToParcel(p, p_cur->email);

    startResponse;
    appendPrintBuf(
        "%sindex=%d, number=%s, numType=%d, anr1=%s, anr1Type=%d, anr2=%s, anr2Type=%d, anr3=%s, anr3Type=%d, alpha = %s, coding=%d, email = %s",
        printBuf, p_cur->index, p_cur->number, p_cur->numType, p_cur->anr1, p_cur->anr1Type,
        p_cur->anr2, p_cur->anr2Type, p_cur->anr3, p_cur->anr3Type, p_cur->alpha, p_cur->coding, p_cur->email,
        (char*)p_cur->simResponse);
    closeResponse;

    return 0;
}
// modify by CYIT 20111202 for -----  end  ----- 


static int responseCallForwards(Parcel &p, void *response, size_t responselen) {
    int num;

    if (response == NULL && responselen != 0) {
        LOGE("invalid response: NULL");
        return RIL_ERRNO_INVALID_RESPONSE;
    }

    if (responselen % sizeof(RIL_CallForwardInfo *) != 0) {
        LOGE("invalid response length %d expected multiple of %d",
                (int)responselen, (int)sizeof(RIL_CallForwardInfo *));
        return RIL_ERRNO_INVALID_RESPONSE;
    }

    /* number of call info's */
    num = responselen / sizeof(RIL_CallForwardInfo *);
    p.writeInt32(num);

    startResponse;
    for (int i = 0 ; i < num ; i++) {
        RIL_CallForwardInfo *p_cur = ((RIL_CallForwardInfo **) response)[i];

        p.writeInt32(p_cur->status);
        p.writeInt32(p_cur->reason);
        p.writeInt32(p_cur->serviceClass);
        p.writeInt32(p_cur->toa);
        writeStringToParcel(p, p_cur->number);
        p.writeInt32(p_cur->timeSeconds);
        appendPrintBuf("%s[%s,reason=%d,cls=%d,toa=%d,%s,tout=%d],", printBuf,
            (p_cur->status==1)?"enable":"disable",
            p_cur->reason, p_cur->serviceClass, p_cur->toa,
            (char*)p_cur->number,
            p_cur->timeSeconds);
    }
    removeLastChar;
    closeResponse;

    return 0;
}

static int responseSsn(Parcel &p, void *response, size_t responselen) {
    if (response == NULL) {
        LOGE("invalid response: NULL");
        return RIL_ERRNO_INVALID_RESPONSE;
    }

    if (responselen != sizeof(RIL_SuppSvcNotification)) {
        LOGE("invalid response length was %d expected %d",
                (int)responselen, (int)sizeof (RIL_SuppSvcNotification));
        return RIL_ERRNO_INVALID_RESPONSE;
    }

    RIL_SuppSvcNotification *p_cur = (RIL_SuppSvcNotification *) response;
    p.writeInt32(p_cur->notificationType);
    p.writeInt32(p_cur->code);
    p.writeInt32(p_cur->index);
    p.writeInt32(p_cur->type);
    writeStringToParcel(p, p_cur->number);

    startResponse;
    appendPrintBuf("%s%s,code=%d,id=%d,type=%d,%s", printBuf,
        (p_cur->notificationType==0)?"mo":"mt",
         p_cur->code, p_cur->index, p_cur->type,
        (char*)p_cur->number);
    closeResponse;

    return 0;
}

static int responseCellList(Parcel &p, void *response, size_t responselen) {
    int num;

    if (response == NULL && responselen != 0) {
        LOGE("invalid response: NULL");
        return RIL_ERRNO_INVALID_RESPONSE;
    }

    if (responselen % sizeof (RIL_NeighboringCell *) != 0) {
        LOGE("invalid response length %d expected multiple of %d\n",
            (int)responselen, (int)sizeof (RIL_NeighboringCell *));
        return RIL_ERRNO_INVALID_RESPONSE;
    }

    startResponse;
    /* number of records */
    num = responselen / sizeof(RIL_NeighboringCell *);
    p.writeInt32(num);

    for (int i = 0 ; i < num ; i++) {
        RIL_NeighboringCell *p_cur = ((RIL_NeighboringCell **) response)[i];

        p.writeInt32(p_cur->rssi);
        writeStringToParcel (p, p_cur->cid);

        appendPrintBuf("%s[cid=%s,rssi=%d],", printBuf,
            p_cur->cid, p_cur->rssi);
    }
    removeLastChar;
    closeResponse;

    return 0;
}

/**
 * Marshall the signalInfoRecord into the parcel if it exists.
 */
static void marshallSignalInfoRecord(Parcel &p,
            RIL_CDMA_SignalInfoRecord &p_signalInfoRecord) {
    p.writeInt32(p_signalInfoRecord.isPresent);
    p.writeInt32(p_signalInfoRecord.signalType);
    p.writeInt32(p_signalInfoRecord.alertPitch);
    p.writeInt32(p_signalInfoRecord.signal);
}

static int responseCdmaInformationRecords(Parcel &p,
            void *response, size_t responselen) {
    int num;
    char* string8 = NULL;
    int buffer_lenght;
    RIL_CDMA_InformationRecord *infoRec;

    if (response == NULL && responselen != 0) {
        LOGE("invalid response: NULL");
        return RIL_ERRNO_INVALID_RESPONSE;
    }

    if (responselen != sizeof (RIL_CDMA_InformationRecords)) {
        LOGE("invalid response length %d expected multiple of %d\n",
            (int)responselen, (int)sizeof (RIL_CDMA_InformationRecords *));
        return RIL_ERRNO_INVALID_RESPONSE;
    }

    RIL_CDMA_InformationRecords *p_cur =
                             (RIL_CDMA_InformationRecords *) response;
    num = MIN(p_cur->numberOfInfoRecs, RIL_CDMA_MAX_NUMBER_OF_INFO_RECS);

    startResponse;
    p.writeInt32(num);

    for (int i = 0 ; i < num ; i++) {
        infoRec = &p_cur->infoRec[i];
        p.writeInt32(infoRec->name);
        switch (infoRec->name) {
            case RIL_CDMA_EXTENDED_DISPLAY_INFO_REC:
                if (infoRec->rec.display.alpha_len >
                                         CDMA_ALPHA_INFO_BUFFER_LENGTH) {
                    LOGE("invalid display info response length %d \
                          expected not more than %d\n",
                         (int)infoRec->rec.display.alpha_len,
                         CDMA_ALPHA_INFO_BUFFER_LENGTH);
                    return RIL_ERRNO_INVALID_RESPONSE;
                }
                // Write as a byteArray
                p.writeInt32(infoRec->rec.display.alpha_len);
                p.write(infoRec->rec.display.alpha_buf,
                        infoRec->rec.display.alpha_len);
                break;
            case RIL_CDMA_DISPLAY_INFO_REC:
                if (infoRec->rec.display.alpha_len >
                                         CDMA_ALPHA_INFO_BUFFER_LENGTH) {
                    LOGE("invalid display info response length %d \
                          expected not more than %d\n",
                         (int)infoRec->rec.display.alpha_len,
                         CDMA_ALPHA_INFO_BUFFER_LENGTH);
                    return RIL_ERRNO_INVALID_RESPONSE;
                }
                string8 = (char*) malloc((infoRec->rec.display.alpha_len + 1)
                                                             * sizeof(char) );
                for (int i = 0 ; i < infoRec->rec.display.alpha_len ; i++) {
                    string8[i] = infoRec->rec.display.alpha_buf[i];
                }
                string8[(int)infoRec->rec.display.alpha_len] = '\0';
                writeStringToParcel(p, (const char*)string8);
                free(string8);
                string8 = NULL;
                break;
            case RIL_CDMA_CALLED_PARTY_NUMBER_INFO_REC:
            case RIL_CDMA_CALLING_PARTY_NUMBER_INFO_REC:
            case RIL_CDMA_CONNECTED_NUMBER_INFO_REC:
                if (infoRec->rec.number.len > CDMA_NUMBER_INFO_BUFFER_LENGTH) {
                    LOGE("invalid display info response length %d \
                          expected not more than %d\n",
                         (int)infoRec->rec.number.len,
                         CDMA_NUMBER_INFO_BUFFER_LENGTH);
                    return RIL_ERRNO_INVALID_RESPONSE;
                }
                string8 = (char*) malloc((infoRec->rec.number.len + 1)
                                                             * sizeof(char) );
                for (int i = 0 ; i < infoRec->rec.number.len; i++) {
                    string8[i] = infoRec->rec.number.buf[i];
                }
                string8[(int)infoRec->rec.number.len] = '\0';
                writeStringToParcel(p, (const char*)string8);
                free(string8);
                string8 = NULL;
                p.writeInt32(infoRec->rec.number.number_type);
                p.writeInt32(infoRec->rec.number.number_plan);
                p.writeInt32(infoRec->rec.number.pi);
                p.writeInt32(infoRec->rec.number.si);
                break;
            case RIL_CDMA_SIGNAL_INFO_REC:
                p.writeInt32(infoRec->rec.signal.isPresent);
                p.writeInt32(infoRec->rec.signal.signalType);
                p.writeInt32(infoRec->rec.signal.alertPitch);
                p.writeInt32(infoRec->rec.signal.signal);

                appendPrintBuf("%sisPresent=%X, signalType=%X, \
                                alertPitch=%X, signal=%X, ",
                   printBuf, (int)infoRec->rec.signal.isPresent,
                   (int)infoRec->rec.signal.signalType,
                   (int)infoRec->rec.signal.alertPitch,
                   (int)infoRec->rec.signal.signal);
                removeLastChar;
                break;
            case RIL_CDMA_REDIRECTING_NUMBER_INFO_REC:
                if (infoRec->rec.redir.redirectingNumber.len >
                                              CDMA_NUMBER_INFO_BUFFER_LENGTH) {
                    LOGE("invalid display info response length %d \
                          expected not more than %d\n",
                         (int)infoRec->rec.redir.redirectingNumber.len,
                         CDMA_NUMBER_INFO_BUFFER_LENGTH);
                    return RIL_ERRNO_INVALID_RESPONSE;
                }
                string8 = (char*) malloc((infoRec->rec.redir.redirectingNumber
                                          .len + 1) * sizeof(char) );
                for (int i = 0;
                         i < infoRec->rec.redir.redirectingNumber.len;
                         i++) {
                    string8[i] = infoRec->rec.redir.redirectingNumber.buf[i];
                }
                string8[(int)infoRec->rec.redir.redirectingNumber.len] = '\0';
                writeStringToParcel(p, (const char*)string8);
                free(string8);
                string8 = NULL;
                p.writeInt32(infoRec->rec.redir.redirectingNumber.number_type);
                p.writeInt32(infoRec->rec.redir.redirectingNumber.number_plan);
                p.writeInt32(infoRec->rec.redir.redirectingNumber.pi);
                p.writeInt32(infoRec->rec.redir.redirectingNumber.si);
                p.writeInt32(infoRec->rec.redir.redirectingReason);
                break;
            case RIL_CDMA_LINE_CONTROL_INFO_REC:
                p.writeInt32(infoRec->rec.lineCtrl.lineCtrlPolarityIncluded);
                p.writeInt32(infoRec->rec.lineCtrl.lineCtrlToggle);
                p.writeInt32(infoRec->rec.lineCtrl.lineCtrlReverse);
                p.writeInt32(infoRec->rec.lineCtrl.lineCtrlPowerDenial);

                appendPrintBuf("%slineCtrlPolarityIncluded=%d, \
                                lineCtrlToggle=%d, lineCtrlReverse=%d, \
                                lineCtrlPowerDenial=%d, ", printBuf,
                       (int)infoRec->rec.lineCtrl.lineCtrlPolarityIncluded,
                       (int)infoRec->rec.lineCtrl.lineCtrlToggle,
                       (int)infoRec->rec.lineCtrl.lineCtrlReverse,
                       (int)infoRec->rec.lineCtrl.lineCtrlPowerDenial);
                removeLastChar;
                break;
            case RIL_CDMA_T53_CLIR_INFO_REC:
                p.writeInt32((int)(infoRec->rec.clir.cause));

                appendPrintBuf("%scause%d", printBuf, infoRec->rec.clir.cause);
                removeLastChar;
                break;
            case RIL_CDMA_T53_AUDIO_CONTROL_INFO_REC:
                p.writeInt32(infoRec->rec.audioCtrl.upLink);
                p.writeInt32(infoRec->rec.audioCtrl.downLink);

                appendPrintBuf("%supLink=%d, downLink=%d, ", printBuf,
                        infoRec->rec.audioCtrl.upLink,
                        infoRec->rec.audioCtrl.downLink);
                removeLastChar;
                break;
            case RIL_CDMA_T53_RELEASE_INFO_REC:
                // TODO(Moto): See David Krause, he has the answer:)
                LOGE("RIL_CDMA_T53_RELEASE_INFO_REC: return INVALID_RESPONSE");
                return RIL_ERRNO_INVALID_RESPONSE;
            default:
                LOGE("Incorrect name value");
                return RIL_ERRNO_INVALID_RESPONSE;
        }
    }
    closeResponse;

    return 0;
}

static int responseRilSignalStrength(Parcel &p,
                    void *response, size_t responselen) {
    if ((response == NULL && responselen != 0) ||
        (responselen % sizeof (RIL_SignalStrength_v6) != 0 ))
    {
        LOGE(" invalid RilSignalStrength response length  %d" ,responselen );
        return RIL_ERRNO_INVALID_RESPONSE;
    }

    if (responselen == sizeof (RIL_SignalStrength_v6)) {
        // New RIL
        RIL_SignalStrength_v6 *p_cur = ((RIL_SignalStrength_v6 *) response);

        p.writeInt32(p_cur->GW_SignalStrength.signalStrength);
        p.writeInt32(p_cur->GW_SignalStrength.bitErrorRate);
        p.writeInt32(p_cur->CDMA_SignalStrength.dbm);
        p.writeInt32(p_cur->CDMA_SignalStrength.ecio);
        p.writeInt32(p_cur->EVDO_SignalStrength.dbm);
        p.writeInt32(p_cur->EVDO_SignalStrength.ecio);
        p.writeInt32(p_cur->EVDO_SignalStrength.signalNoiseRatio);
        p.writeInt32(p_cur->LTE_SignalStrength.signalStrength);
        p.writeInt32(p_cur->LTE_SignalStrength.rsrp);
        p.writeInt32(p_cur->LTE_SignalStrength.rsrq);
        p.writeInt32(p_cur->LTE_SignalStrength.rssnr);
        p.writeInt32(p_cur->LTE_SignalStrength.cqi);

        startResponse;
        appendPrintBuf("%s[GW_SignalStrength =%d,GW_SignalStrength.bitErrorRate=%d,\
                CDMA_SignalStrength.dbm=%d,CDMA_SignalStrength.ecio=%d,\
                EVDO_SignalStrength.dbm =%d,EVDO_SignalStrength.ecio=%d,\
                EVDO_SignalStrength.signalNoiseRatio=%d,\
                LTE_SignalStrength.signalStrength =%d,LTE_SignalStrength.rsrp=%d,\
                LTE_SignalStrength.rsrq=%d,LTE_SignalStrength.rssnr=%d,\
                LTE_SignalStrength.cqi=%d]",
                printBuf,
                p_cur->GW_SignalStrength.signalStrength,
                p_cur->GW_SignalStrength.bitErrorRate,
                p_cur->CDMA_SignalStrength.dbm,
                p_cur->CDMA_SignalStrength.ecio,
                p_cur->EVDO_SignalStrength.dbm,
                p_cur->EVDO_SignalStrength.ecio,
                p_cur->EVDO_SignalStrength.signalNoiseRatio,
                p_cur->LTE_SignalStrength.signalStrength,
                p_cur->LTE_SignalStrength.rsrp,
                p_cur->LTE_SignalStrength.rsrq,
                p_cur->LTE_SignalStrength.rssnr,
                p_cur->LTE_SignalStrength.cqi);
        closeResponse;

    } else {
        LOGE("invalid response length");
        return RIL_ERRNO_INVALID_RESPONSE;
    }

    return 0;
}

static int responseCallRing(Parcel &p, void *response, size_t responselen) {
    if ((response == NULL) || (responselen == 0)) {
        return responseVoid(p, response, responselen);
    } else {
        return responseCdmaSignalInfoRecord(p, response, responselen);
    }
}

static int responseCdmaSignalInfoRecord(Parcel &p, void *response, size_t responselen) {
    if (response == NULL || responselen == 0) {
        LOGE("invalid response: NULL");
        return RIL_ERRNO_INVALID_RESPONSE;
    }

    if (responselen != sizeof (RIL_CDMA_SignalInfoRecord)) {
        LOGE("invalid response length %d expected sizeof (RIL_CDMA_SignalInfoRecord) of %d\n",
            (int)responselen, (int)sizeof (RIL_CDMA_SignalInfoRecord));
        return RIL_ERRNO_INVALID_RESPONSE;
    }

    startResponse;

    RIL_CDMA_SignalInfoRecord *p_cur = ((RIL_CDMA_SignalInfoRecord *) response);
    marshallSignalInfoRecord(p, *p_cur);

    appendPrintBuf("%s[isPresent=%d,signalType=%d,alertPitch=%d\
              signal=%d]",
              printBuf,
              p_cur->isPresent,
              p_cur->signalType,
              p_cur->alertPitch,
              p_cur->signal);

    closeResponse;
    return 0;
}

static int responseCdmaCallWaiting(Parcel &p, void *response,
            size_t responselen) {
    if (response == NULL && responselen != 0) {
        LOGE("invalid response: NULL");
        return RIL_ERRNO_INVALID_RESPONSE;
    }

    if (responselen != sizeof(RIL_CDMA_CallWaiting_v5)) {
        LOGE("invalid response length %d expected %d\n",
            (int)responselen, (int)sizeof(RIL_CDMA_CallWaiting_v5));
        return RIL_ERRNO_INVALID_RESPONSE;
    }

    startResponse;
    RIL_CDMA_CallWaiting_v5 *p_cur = ((RIL_CDMA_CallWaiting_v5 *) response);

    writeStringToParcel (p, p_cur->number);
    p.writeInt32(p_cur->numberPresentation);
    writeStringToParcel (p, p_cur->name);
    marshallSignalInfoRecord(p, p_cur->signalInfoRecord);

    appendPrintBuf("%snumber=%s,numberPresentation=%d, name=%s,\
            signalInfoRecord[isPresent=%d,signalType=%d,alertPitch=%d\
            signal=%d]",
            printBuf,
            p_cur->number,
            p_cur->numberPresentation,
            p_cur->name,
            p_cur->signalInfoRecord.isPresent,
            p_cur->signalInfoRecord.signalType,
            p_cur->signalInfoRecord.alertPitch,
            p_cur->signalInfoRecord.signal);
    closeResponse;

    return 0;
}

static int responseUiccSubscription(Parcel &p,
        void *response,size_t responselen) {

    LOGD("In responseUiccSubscription");
    startResponse;

    RIL_SelectUiccSub *p_cur = (RIL_SelectUiccSub *)response;
    p.writeInt32(p_cur->slot);
    p.writeInt32(p_cur->app_index);
    p.writeInt32(p_cur->sub_num);
    p.writeInt32(p_cur->act_status);

    closeResponse;
    return 0;
}

static int responseSimRefresh(Parcel &p, void *response, size_t responselen) {
    if (response == NULL && responselen != 0) {
        LOGE("responseSimRefresh: invalid response: NULL");
        return RIL_ERRNO_INVALID_RESPONSE;
    }

    startResponse;
    if (s_callbacks[0].version < 6) {
        int *p_cur = ((int *) response);
        p.writeInt32(p_cur[0]);
        p.writeInt32(p_cur[1]);
        writeStringToParcel(p, "");

        appendPrintBuf("%sresult=%d, ef_id=%d",
                printBuf,
                p_cur[0],
                p_cur[1]);
    }
    // -------------------------------------------------------------
    //   modify by CYIT 20110806        ----- start -----
    // -------------------------------------------------------------
    else if (responselen == sizeof (RIL_SimRefreshResponse))
    {
        RIL_SimRefreshResponse *p_cur = ((RIL_SimRefreshResponse *) response);
        p.writeInt32(p_cur->result);
        p.writeInt32(p_cur->efIdNum);
        int i = 0x00;
        for(i = 0x00; i < p_cur->efIdNum; i++)
        {
            p.writeInt32((p_cur->ef_id)[i]);
            LOGD("responseSimRefresh: p_cur->ef_id)[%d] = %x", i, (p_cur->ef_id)[i]);
        }
        writeStringToParcel(p, p_cur->aid);
    }
    // -------------------------------------------------------------
    //   modify by CYIT 20110806         -----  end  -----
    // -------------------------------------------------------------
    else {
        LOGE("responseSimRefresh: Received invalid response length (%d)\n", responselen);
        return RIL_ERRNO_INVALID_RESPONSE;
    }
    closeResponse;

    return 0;
}

static int responseSSData(Parcel &p, void *response, size_t responselen) {
    LOGD("In responseSSData");
    int num;

    if (response == NULL && responselen != 0) {
        LOGE("invalid response: NULL");
        return RIL_ERRNO_INVALID_RESPONSE;
    }

    if (responselen != sizeof(RIL_StkCcUnsolSsResponse)) {
        LOGE("invalid response length %d, expected %d",
               (int)responselen, (int)sizeof(RIL_StkCcUnsolSsResponse));
        return RIL_ERRNO_INVALID_RESPONSE;
    }

    startResponse;
    RIL_StkCcUnsolSsResponse *p_cur = (RIL_StkCcUnsolSsResponse *) response;
    p.writeInt32(p_cur->serviceType);
    p.writeInt32(p_cur->requestType);
    p.writeInt32(p_cur->teleserviceType);
    p.writeInt32(p_cur->serviceClass);
    p.writeInt32(p_cur->result);

    if (isServiceTypeCFQuery(p_cur->serviceType, p_cur->requestType)) {
        LOGD("responseSSData CF type, num of Cf elements %d", p_cur->cfData.numValidIndexes);
        if (p_cur->cfData.numValidIndexes > NUM_SERVICE_CLASSES) {
            LOGE("numValidIndexes is greater than max value %d, "
                  "truncating it to max value", NUM_SERVICE_CLASSES);
            p_cur->cfData.numValidIndexes = NUM_SERVICE_CLASSES;
        }
        /* number of call info's */
        p.writeInt32(p_cur->cfData.numValidIndexes);

        for (int i = 0; i < p_cur->cfData.numValidIndexes; i++) {
             RIL_CallForwardInfo cf = p_cur->cfData.cfInfo[i];

             p.writeInt32(cf.status);
             p.writeInt32(cf.reason);
             p.writeInt32(cf.serviceClass);
             p.writeInt32(cf.toa);
             writeStringToParcel(p, cf.number);
             p.writeInt32(cf.timeSeconds);
             appendPrintBuf("%s[%s,reason=%d,cls=%d,toa=%d,%s,tout=%d],", printBuf,
                 (cf.status==1)?"enable":"disable", cf.reason, cf.serviceClass, cf.toa,
                  (char*)cf.number, cf.timeSeconds);
             LOGD("Data: %d,reason=%d,cls=%d,toa=%d,num=%s,tout=%d],", cf.status,
                  cf.reason, cf.serviceClass, cf.toa, (char*)cf.number, cf.timeSeconds);
        }
    } else {
        p.writeInt32 (SS_INFO_MAX);

        /* each int*/
        for (int i = 0; i < SS_INFO_MAX; i++) {
             appendPrintBuf("%s%d,", printBuf, p_cur->ssInfo[i]);
             LOGD("Data: %d",p_cur->ssInfo[i]);
             p.writeInt32(p_cur->ssInfo[i]);
        }
    }
    removeLastChar;
    closeResponse;

    return 0;
}

static bool isServiceTypeCFQuery(RIL_SsServiceType serType, RIL_SsRequestType reqType) {
    if ((reqType == SS_INTERROGATION) &&
        (serType == SS_CFU ||
         serType == SS_CF_BUSY ||
         serType == SS_CF_NO_REPLY ||
         serType == SS_CF_NOT_REACHABLE ||
         serType == SS_CF_ALL ||
         serType == SS_CF_ALL_CONDITIONAL)) {
        return true;
    }
    return false;
}

static void triggerEvLoop() {
    int ret;
    if (!pthread_equal(pthread_self(), s_tid_dispatch)) {
        /* trigger event loop to wakeup. No reason to do this,
         * if we're in the event loop thread */
         do {
            ret = write (s_fdWakeupWrite, " ", 1);
         } while (ret < 0 && errno == EINTR);
    }
}

static void rilEventAddWakeup(struct ril_event *ev) {
    ril_event_add(ev);
    triggerEvLoop();
}

static void sendSimStatusAppInfo(Parcel &p, int num_apps, RIL_AppStatus appStatus[]) {
        p.writeInt32(num_apps);
        startResponse;
        for (int i = 0; i < num_apps; i++) {
            p.writeInt32(appStatus[i].app_type);
            p.writeInt32(appStatus[i].app_state);
            p.writeInt32(appStatus[i].perso_substate);
            writeStringToParcel(p, (const char*)(appStatus[i].aid_ptr));
            writeStringToParcel(p, (const char*)
                                          (appStatus[i].app_label_ptr));
            p.writeInt32(appStatus[i].pin1_replaced);
            p.writeInt32(appStatus[i].pin1);
            p.writeInt32(appStatus[i].pin2);
            appendPrintBuf("%s[app_type=%d,app_state=%d,perso_substate=%d,\
                    aid_ptr=%s,app_label_ptr=%s,pin1_replaced=%d,pin1=%d,pin2=%d],",
                    printBuf,
                    appStatus[i].app_type,
                    appStatus[i].app_state,
                    appStatus[i].perso_substate,
                    appStatus[i].aid_ptr,
                    appStatus[i].app_label_ptr,
                    appStatus[i].pin1_replaced,
                    appStatus[i].pin1,
                    appStatus[i].pin2);
        }
        closeResponse;
}

static int responseSimStatus(Parcel &p, void *response, size_t responselen) {
    int i;

    if (response == NULL && responselen != 0) {
        LOGE("invalid response: NULL");
        return RIL_ERRNO_INVALID_RESPONSE;
    }

    if (responselen != sizeof (RIL_CardStatus_v6) && responselen != sizeof (RIL_CardStatus_v5)) {
        LOGE("responseSimStatus: Expecting RIL_CardStatus_v6 or RIL_CardStatus_v5 \
            instead received %d bytes\n", responselen);
        return RIL_ERRNO_INVALID_RESPONSE;
    }

    if (s_callbacks[0].version == 6) {
        RIL_CardStatus_v6 *p_cur = ((RIL_CardStatus_v6 *) response);

        p.writeInt32(p_cur->card_state);
        p.writeInt32(p_cur->universal_pin_state);
        p.writeInt32(p_cur->gsm_umts_subscription_app_index);
        p.writeInt32(p_cur->cdma_subscription_app_index);
        p.writeInt32(p_cur->ims_subscription_app_index);

        sendSimStatusAppInfo(p, p_cur->num_applications, p_cur->applications);
    } else {
        RIL_CardStatus_v5 *p_cur = ((RIL_CardStatus_v5 *) response);

        p.writeInt32(p_cur->card_state);
        p.writeInt32(p_cur->universal_pin_state);
        p.writeInt32(p_cur->gsm_umts_subscription_app_index);
        p.writeInt32(p_cur->cdma_subscription_app_index);
        p.writeInt32(-1);

        sendSimStatusAppInfo(p, p_cur->num_applications, p_cur->applications);
    }

    return 0;
}

static int responseGsmBrSmsCnf(Parcel &p, void *response, size_t responselen) {
    int num = responselen / sizeof(RIL_GSM_BroadcastSmsConfigInfo *);
    p.writeInt32(num);

    startResponse;
    RIL_GSM_BroadcastSmsConfigInfo **p_cur =
                (RIL_GSM_BroadcastSmsConfigInfo **) response;
    for (int i = 0; i < num; i++) {
        p.writeInt32(p_cur[i]->fromServiceId);
        p.writeInt32(p_cur[i]->toServiceId);
        p.writeInt32(p_cur[i]->fromCodeScheme);
        p.writeInt32(p_cur[i]->toCodeScheme);
        p.writeInt32(p_cur[i]->selected);

        appendPrintBuf("%s [%d: fromServiceId=%d, toServiceId=%d, \
                fromCodeScheme=%d, toCodeScheme=%d, selected =%d]",
                printBuf, i, p_cur[i]->fromServiceId, p_cur[i]->toServiceId,
                p_cur[i]->fromCodeScheme, p_cur[i]->toCodeScheme,
                p_cur[i]->selected);
    }
    closeResponse;

    return 0;
}

static int responseCdmaBrSmsCnf(Parcel &p, void *response, size_t responselen) {
    RIL_CDMA_BroadcastSmsConfigInfo **p_cur =
               (RIL_CDMA_BroadcastSmsConfigInfo **) response;

    int num = responselen / sizeof (RIL_CDMA_BroadcastSmsConfigInfo *);
    p.writeInt32(num);

    startResponse;
    for (int i = 0 ; i < num ; i++ ) {
        p.writeInt32(p_cur[i]->service_category);
        p.writeInt32(p_cur[i]->language);
        p.writeInt32(p_cur[i]->selected);

        appendPrintBuf("%s [%d: srvice_category=%d, language =%d, \
              selected =%d], ",
              printBuf, i, p_cur[i]->service_category, p_cur[i]->language,
              p_cur[i]->selected);
    }
    closeResponse;

    return 0;
}

static int responseCdmaSms(Parcel &p, void *response, size_t responselen) {
    int num;
    int digitCount;
    int digitLimit;
    uint8_t uct;
    void* dest;

    LOGD("Inside responseCdmaSms");

    if (response == NULL && responselen != 0) {
        LOGE("invalid response: NULL");
        return RIL_ERRNO_INVALID_RESPONSE;
    }

    if (responselen != sizeof(RIL_CDMA_SMS_Message)) {
        LOGE("invalid response length was %d expected %d",
                (int)responselen, (int)sizeof(RIL_CDMA_SMS_Message));
        return RIL_ERRNO_INVALID_RESPONSE;
    }

    RIL_CDMA_SMS_Message *p_cur = (RIL_CDMA_SMS_Message *) response;
    p.writeInt32(p_cur->uTeleserviceID);
    p.write(&(p_cur->bIsServicePresent),sizeof(uct));
    p.writeInt32(p_cur->uServicecategory);
    p.writeInt32(p_cur->sAddress.digit_mode);
    p.writeInt32(p_cur->sAddress.number_mode);
    p.writeInt32(p_cur->sAddress.number_type);
    p.writeInt32(p_cur->sAddress.number_plan);
    p.write(&(p_cur->sAddress.number_of_digits), sizeof(uct));
    digitLimit= MIN((p_cur->sAddress.number_of_digits), RIL_CDMA_SMS_ADDRESS_MAX);
    for(digitCount =0 ; digitCount < digitLimit; digitCount ++) {
        p.write(&(p_cur->sAddress.digits[digitCount]),sizeof(uct));
    }

    p.writeInt32(p_cur->sSubAddress.subaddressType);
    p.write(&(p_cur->sSubAddress.odd),sizeof(uct));
    p.write(&(p_cur->sSubAddress.number_of_digits),sizeof(uct));
    digitLimit= MIN((p_cur->sSubAddress.number_of_digits), RIL_CDMA_SMS_SUBADDRESS_MAX);
    for(digitCount =0 ; digitCount < digitLimit; digitCount ++) {
        p.write(&(p_cur->sSubAddress.digits[digitCount]),sizeof(uct));
    }

    digitLimit= MIN((p_cur->uBearerDataLen), RIL_CDMA_SMS_BEARER_DATA_MAX);
    p.writeInt32(p_cur->uBearerDataLen);
    for(digitCount =0 ; digitCount < digitLimit; digitCount ++) {
       p.write(&(p_cur->aBearerData[digitCount]), sizeof(uct));
    }

    startResponse;
    appendPrintBuf("%suTeleserviceID=%d, bIsServicePresent=%d, uServicecategory=%d, \
            sAddress.digit_mode=%d, sAddress.number_mode=%d, sAddress.number_type=%d, ",
            printBuf, p_cur->uTeleserviceID,p_cur->bIsServicePresent,p_cur->uServicecategory,
            p_cur->sAddress.digit_mode, p_cur->sAddress.number_mode,p_cur->sAddress.number_type);
    closeResponse;

    return 0;
}

/* response is the count and the list of RIL_DataCallProfileInfo */
static int responseGetDataCallProfile(Parcel &p, void *response, size_t responselen) {
    int num = 0;

    LOGD("[OMH>]> %d", responselen);

    if (response == NULL && responselen != 0) {
        LOGE("invalid response: NULL");
        return RIL_ERRNO_INVALID_RESPONSE;
    }

    LOGD("[OMH>]> processing response");

    /* number of profile info's */
    num = responselen / sizeof(RIL_DataCallProfileInfo);
    p.writeInt32(num);

    RIL_DataCallProfileInfo *p_cur = ((RIL_DataCallProfileInfo *) (response + sizeof(int)));

    startResponse;
    for (int i = 0 ; i < num ; i++) {
        p.writeInt32(p_cur->profileId);
        p.writeInt32(p_cur->priority);
        appendPrintBuf("[profileId=%d,priority=%d],", printBuf,
            p_cur->profileId, p_cur->priority);
        p_cur++;
    }
    removeLastChar;
    closeResponse;

    return 0;
}


/**
 * A write on the wakeup fd is done just to pop us out of select()
 * We empty the buffer here and then ril_event will reset the timers on the
 * way back down
 */
static void processWakeupCallback(int fd, short flags, void *param) {
    char buff[16];
    int ret;

    LOGV("processWakeupCallback");

    /* empty our wakeup socket out */
    do {
        ret = read(s_fdWakeupRead, &buff, sizeof(buff));
    } while (ret > 0 || (ret < 0 && errno == EINTR));
}

static void onCommandsSocketClosed() {
    int ret;
    int i = 0;
    RequestInfo *p_cur;

    // mark pending requests as "cancelled" so we dont report responses //
    for (; i < RIL_CHANNELS; i++) {
        ret = pthread_mutex_lock(&s_pendingRequestsMutex[i]);
        assert (ret == 0);

        for (p_cur = s_pendingRequests[i]
                ; p_cur != NULL
                ; p_cur  = p_cur->p_next
            ) {
            p_cur->cancelled = 1;
        }
        ret = pthread_mutex_unlock(&s_pendingRequestsMutex[i]);
        assert (ret == 0);
    }
}

static void processCommandsCallback(int fd, short flags, void *param) {
    void *p_record;  //RecordStream *p_rs is moved to global varibale
    size_t recordlen;
    int ret;

    int client_id = mapClientFD(fd);
    assert(fd == s_fdCommand[client_id]);
    p_rs[client_id] = (RecordStream *)param;

    for (;;) {
        // loop until EAGAIN/EINTR, end of stream, or other error //
        ret = record_stream_get_next(p_rs[client_id], &p_record, &recordlen);
        // end-of-stream //
        if (ret == 0 && p_record == NULL) {
            break;

        // something wrong //
        } else if (ret < 0) {
            break;

        // && p_record != NULL //
        } else if (ret == 0) {
            processCommandBuffer(p_record, recordlen, client_id);
        }
    }

    LOGD( "ret = %d, errno = %d", ret, errno );
    if (ret == 0 || !(errno == EAGAIN || errno == EINTR)) {
        if (ret != 0) {
            LOGE("error on reading command socket errno:%d\n", errno);
        } else {
            LOGW("EOS.  Closing command socket.");
        }

        close(s_fdCommand[client_id]);
        s_fdCommand[client_id] = -1;
        client_fds[client_id].fd_status = FD_STATUS_INACTIVE;
        ril_event_del(&s_commands_event[client_id]);
        record_stream_free(p_rs[client_id]);

        // s_listen_event is persistent. So, delete the listen event from
        // the watch list so that it doesn't get piled up.
        ril_event_del(&s_listen_event);
        // start listening for new connections again //
        rilEventAddWakeup(&s_listen_event);

        onCommandsSocketClosed();
    }
}

static void onNewCommandConnect(int fd) {
    // implicit radio state changed
    int client_id = mapClientFD(fd);
    // Inform we are connected and the ril version
    int rilVer = s_callbacks[client_id].version;

    LOGD("client_id is %d, rilVer is %d", client_id, rilVer);
    RIL_onUnsolicitedResponse(RIL_UNSOL_RIL_CONNECTED,
                                    &rilVer, sizeof(rilVer), client_id);
    RIL_onUnsolicitedResponse(RIL_UNSOL_RESPONSE_RADIO_STATE_CHANGED,
            NULL, 0, client_id);

    // Send last NITZ time data, in case it was missed
    if (s_lastNITZTimeData != NULL) {
        sendResponseRaw(s_lastNITZTimeData, s_lastNITZTimeDataSize, client_id);

        free(s_lastNITZTimeData);
        s_lastNITZTimeData = NULL;
    }

    // Get version string
    if (s_callbacks[client_id].getVersion != NULL) {
        const char *version;
        version = s_callbacks[client_id].getVersion();
        LOGI("RIL Daemon version: %s\n", version);

        property_set(PROPERTY_RIL_IMPL, version);
    } else {
        LOGI("RIL Daemon version: unavailable\n");
        property_set(PROPERTY_RIL_IMPL, "unavailable");
    }

}

static void listenCallback (int fd, short flags, void *param) {
    int ret;
    int err;
    int is_phone_socket;
    //RecordStram *p_rs is made as global variable.
    struct sockaddr_un peeraddr;
    socklen_t socklen = sizeof (peeraddr);

    struct ucred creds;
    socklen_t szCreds = sizeof(creds);

    struct passwd *pwd = NULL;

    LOGD("**RILD ListenCallback**");
    assert (fd == s_fdListen);

    fd = accept(s_fdListen, (sockaddr *) &peeraddr, &socklen);
    int client_id = addClientFd(fd);	//得到client号，有可能是双卡双待，则需要两个ril
    LOGD("client id:%d", client_id);
    if(client_id == -1) {
        LOGD("Max no of clients reached");
        close(fd);
        return ;
    } else {
        s_fdCommand[client_id] = fd;
    }

    if (s_fdCommand[client_id] < 0 ) {
        LOGE("Error on accept() errno:%d", errno);
        // s_listen_event is persistent. So, delete the listen event from
        // the watch list so that it doesn't get piled up.
        ril_event_del(&s_listen_event);
        /* start listening for new connections again */
        rilEventAddWakeup(&s_listen_event);
        return;
    }

    /* check the credential of the other side and only accept socket from
     * phone process
     */
    errno = 0;
    is_phone_socket = 0;

    err = getsockopt(s_fdCommand[client_id], SOL_SOCKET, SO_PEERCRED, &creds, &szCreds);

    if (err == 0 && szCreds > 0) {
        errno = 0;
        pwd = getpwuid(creds.uid);
        if (pwd != NULL) {
            if (strcmp(pwd->pw_name, PHONE_PROCESS) == 0 || strcmp(pwd->pw_name, "root") == 0 || strcmp(pwd->pw_name, "media") == 0) {
                is_phone_socket = 1;
            } else {
                LOGE("RILD can't accept socket from process %s", pwd->pw_name);
            }
        } else {
            LOGE("Error on getpwuid() errno: %d", errno);
        }
    } else {
        LOGD("Error on getsockopt() errno: %d", errno);
    }

    if ( !is_phone_socket ) {
        LOGE("RILD must accept socket from %s", PHONE_PROCESS);

        close(s_fdCommand[client_id]);
        s_fdCommand[client_id] = -1;
        client_fds[client_id].fd_status = FD_STATUS_INACTIVE;

        onCommandsSocketClosed();

        // s_listen_event is persistent. So, delete the listen event from
        // the watch list so that it doesn't get piled up.
        ril_event_del(&s_listen_event);
        /* start listening for new connections again */
        rilEventAddWakeup(&s_listen_event);

        return;
    }

    ret = fcntl(s_fdCommand[client_id], F_SETFL, O_NONBLOCK);
    if (ret < 0) {
        LOGE ("Error setting O_NONBLOCK errno:%d", errno);
    }
    LOGD("new connection");

    p_rs[client_id] = record_stream_new(s_fdCommand[client_id], MAX_COMMAND_BYTES);
    ril_event_set (&s_commands_event[client_id], s_fdCommand[client_id], 1,
        processCommandsCallback, p_rs[client_id]);		//上层得到的command 
    rilEventAddWakeup (&s_commands_event[client_id]);
    LOGD("dispatch list started");
    if ( client_id == 0 )
    onNewCommandConnect(s_fdCommand[client_id]);
}

static void freeDebugCallbackArgs(int number, char **args) {
    for (int i = 0; i < number; i++) {
        if (args[i] != NULL) {
            free(args[i]);
        }
    }
    free(args);
}

static void debugCallback (int fd, short flags, void *param) {
    int acceptFD, option;
    struct sockaddr_un peeraddr;
    socklen_t socklen = sizeof (peeraddr);
    int data;
    unsigned int qxdm_data[6];
    const char *deactData[1] = {"1"};
    char *actData[1];
    RIL_Dial dialData;
    int hangupData[1] = {1};
    int number;
    char **args;

    acceptFD = accept (fd,  (sockaddr *) &peeraddr, &socklen);

    int client_id = addClientFd(acceptFD);
    if(client_id == -1)
    {
        LOGE("Max no of clients reached");
        close(acceptFD);
        return ;
    }
    else
    {
        s_fdCommand[client_id] = acceptFD;
    }
    if (acceptFD < 0) {
        LOGE ("error accepting on debug port: %d\n", errno);
        return;
    }

    if (recv(acceptFD, &number, sizeof(int), 0) != sizeof(int)) {
        LOGE ("error reading on socket: number of Args: \n");
        return;
    }
    args = (char **) malloc(sizeof(char*) * number);

    for (int i = 0; i < number; i++) {
        int len;
        if (recv(acceptFD, &len, sizeof(int), 0) != sizeof(int)) {
            LOGE ("error reading on socket: Len of Args: \n");
            freeDebugCallbackArgs(i, args);
            return;
        }
        // +1 for null-term
        args[i] = (char *) malloc((sizeof(char) * len) + 1);
        if (recv(acceptFD, args[i], sizeof(char) * len, 0)
            != (int)sizeof(char) * len) {
            LOGE ("error reading on socket: Args[%d] \n", i);
            freeDebugCallbackArgs(i, args);
            return;
        }
        char * buf = args[i];
        buf[len] = 0;
    }

    switch (atoi(args[0])) {
        case 0:
            LOGI ("Connection on debug port: issuing reset.");
            issueLocalRequest(RIL_REQUEST_RESET_RADIO, NULL, 0, client_id);
            break;
        case 1:
            LOGI ("Connection on debug port: issuing radio power off.");
            data = 0;
            issueLocalRequest(RIL_REQUEST_RADIO_POWER, &data, sizeof(int), client_id);
            // Close the socket
            //TODO DSDS debug close socket
            close(s_fdCommand[0]);
            s_fdCommand[0] = -1;
            break;
        case 2:
            LOGI ("Debug port: issuing unsolicited network change.");
            RIL_onUnsolicitedResponse(RIL_UNSOL_RESPONSE_VOICE_NETWORK_STATE_CHANGED,
                                     NULL, 0, client_id);
            break;
        case 3:
            LOGI ("Debug port: QXDM log enable.");
            qxdm_data[0] = 65536;     // head.func_tag
            qxdm_data[1] = 16;        // head.len
            qxdm_data[2] = 1;         // mode: 1 for 'start logging'
            qxdm_data[3] = 32;        // log_file_size: 32megabytes
            qxdm_data[4] = 0;         // log_mask
            qxdm_data[5] = 8;         // log_max_fileindex
            issueLocalRequest(RIL_REQUEST_OEM_HOOK_RAW, qxdm_data,
                              6 * sizeof(int), client_id);
            break;
        case 4:
            LOGI ("Debug port: QXDM log disable.");
            qxdm_data[0] = 65536;
            qxdm_data[1] = 16;
            qxdm_data[2] = 0;          // mode: 0 for 'stop logging'
            qxdm_data[3] = 32;
            qxdm_data[4] = 0;
            qxdm_data[5] = 8;
            issueLocalRequest(RIL_REQUEST_OEM_HOOK_RAW, qxdm_data,
                              6 * sizeof(int), client_id);
            break;
        case 5:
            LOGI("Debug port: Radio On");
            data = 1;
            issueLocalRequest(RIL_REQUEST_RADIO_POWER, &data, sizeof(int), client_id);
            sleep(2);
            // Set network selection automatic.
            issueLocalRequest(RIL_REQUEST_SET_NETWORK_SELECTION_AUTOMATIC, NULL, 0, client_id);
            break;
        case 6:
            LOGI("Debug port: Setup Data Call, Apn :%s\n", args[1]);
            actData[0] = args[1];
            issueLocalRequest(RIL_REQUEST_SETUP_DATA_CALL, &actData,
                              sizeof(actData), client_id);
            break;
        case 7:
            LOGI("Debug port: Deactivate Data Call");
            issueLocalRequest(RIL_REQUEST_DEACTIVATE_DATA_CALL, &deactData,
                              sizeof(deactData), client_id);
            break;
        case 8:
            LOGI("Debug port: Dial Call");
            dialData.clir = 0;
            dialData.address = args[1];
            issueLocalRequest(RIL_REQUEST_DIAL, &dialData, sizeof(dialData), client_id);
            break;
        case 9:
            LOGI("Debug port: Answer Call");
            issueLocalRequest(RIL_REQUEST_ANSWER, NULL, 0, client_id);
            break;
        case 10:
            LOGI("Debug port: End Call");
            issueLocalRequest(RIL_REQUEST_HANGUP, &hangupData,
                              sizeof(hangupData), client_id);
            break;
        default:
            LOGE ("Invalid request");
            break;
    }
    freeDebugCallbackArgs(number, args);
    close(acceptFD);
}

/*
static void userTimerCallback (int fd, short flags, void *param) {
    UserCallbackInfo *p_info;

    p_info = (UserCallbackInfo *)param;

    p_info->p_callback(p_info->userParam);

    // FIXME generalize this...there should be a cancel mechanism
    if (s_last_wake_timeout_info != NULL && s_last_wake_timeout_info == p_info) {
        s_last_wake_timeout_info = NULL;
    }

    free(p_info);
}
*/

// add timeReq to pending list //
static void userTimerCallback(int fd, short flags, void *param) 
{
    int cid;
    int request;
    int parcel[2] = {0};
    UserCallbackInfo * p_info;
    RequestInfo *pRI;

    p_info = (UserCallbackInfo *)param;
    request = p_info->timeReq;

    pRI = (RequestInfo *)calloc(1, sizeof(RequestInfo));
    memset(pRI, 0, sizeof(RequestInfo));
    pRI->token = 0; // timeReq don't care about token //
    pRI->client_id = 0;
    pRI->userParam = p_info->userParam;
    pRI->local = 1;

    if (request < 1 || request >= (int32_t)NUM_ELEMS(s_commands)) {
        LOGE("unsupported request code %d token %d", request, pRI->token);
        goto error;
    }

    pRI->pCI = &(s_commands[request]);
    parcel[0] = request;
    parcel[1] = pRI->token;
    pRI->parcel.setData((uint8_t *)parcel, sizeof(parcel));

    if (RIL_CHANNELID_MIN > pRI->pCI->cid
            || RIL_CHANNELID_MAX < pRI->pCI->cid)
    {
        LOGE("%s's cid is out of range", 
                requestToString(pRI->pCI->requestNumber));
        goto error;
    }

    pRI->p_next = NULL;
    cid = pRI->pCI->cid - 1;
    
    // append timeReq to pending list //
    pthread_mutex_lock(&s_pendingRequestsMutex[cid]);
    LOGD("[DISPATCH]: append timeReq %s to pending list(%d)", 
            requestToString(pRI->pCI->requestNumber), cid);
    if (!s_pendingRequests[cid]) {
        // none node in the list, add to head //
        s_pendingRequests[cid] = pRI;
        s_pending_tail[cid] = pRI;
    } else {
        pRI->p_next = s_pendingRequests[cid]->p_next;
        s_pendingRequests[cid]->p_next = pRI;
        if (s_pendingRequests[cid] == s_pending_tail[cid]) {
            s_pending_tail[cid] = pRI;
        }
    }
    s_newReq[cid] = 1;
    LOGD("[DISPATCH]: append timeReq over");
    pthread_cond_broadcast(&s_pendingRequestsCond[cid]);
    pthread_mutex_unlock(&s_pendingRequestsMutex[cid]);

    // FIXME generalize this...there should be a cancel mechanism
    if (s_last_wake_timeout_info != NULL 
            && s_last_wake_timeout_info == p_info) {
        s_last_wake_timeout_info = NULL;
    }

    free(p_info);
    return;

error:
    if (p_info->userParam != NULL) {
        free(p_info->userParam);
    }
    free(p_info);
    free(pRI);
}

static void destroyTSD(void * buf)
{
    int * pid = (int *)pthread_getspecific(CID);
    LOGD("Thread[%d]: free TSD", *pid);
    free(pid);
    pthread_key_delete(CID);
}

// array of thread request //
static void * requestLoop(void * param) 
{
    int cid = *(int *)param;
    pthread_setspecific(CID, param);	//设置自己的cid

    LOGD("[REQ%d]: init request%d loop", cid, cid);
    //pthread_mutex_lock(&s_startupReqMutex[cid]);
    //s_reqStarted[cid] = 1;
    //pthread_cond_broadcast(&s_startupReqCond[cid]);
    //pthread_mutex_unlock(&s_startupReqMutex[cid]);

    while (1) {
        LOGD("[REQ%d]: waiting for pending list be refreshed", cid);
        pthread_mutex_lock(&s_pendingRequestsMutex[cid]);
        while (s_newReq[cid] == 0) {
            pthread_cond_wait(&s_pendingRequestsCond[cid], 
                    &s_pendingRequestsMutex[cid]);
        }
        s_newReq[cid] = 0;
        pthread_mutex_unlock(&s_pendingRequestsMutex[cid]);
        LOGD("[REQ%d]: refresh pending list over", cid);

        // checkAndDequeueRequestInfo() will reset list //
        // so s_pendingRequests[cid] wouldn't move to next //
        while (s_pendingRequests[cid]) {
            int reqnum = s_pendingRequests[cid]->pCI->requestNumber;
            int32_t token = s_pendingRequests[cid]->token;

            LOGD("[REQ%d]: dispatch requests %s token(%04d)", 
                    cid, requestToString(reqnum), token);
            // local request like debugReq and timeReq //
            if (s_pendingRequests[cid]->local == 1) {
                if (token == 0xFFFFFFFF) {
                    dispatchDebugReq(
                            s_pendingRequests[cid]->parcel, s_pendingRequests[cid]);
                } else {
                    dispatchTimeReq(
                            s_pendingRequests[cid]->parcel, s_pendingRequests[cid]);
                }
            } else {
                s_pendingRequests[cid]->pCI->dispatchFunction(
                        s_pendingRequests[cid]->parcel, s_pendingRequests[cid]);
            }
            LOGD("[REQ%d]: dispatch requests %s token(%04d) over", 
                    cid, requestToString(reqnum), token);
        }
        LOGD("[REQ%d]: dispatch over", cid);
    }

    return NULL;
}


static void *
eventLoop(void *param) {
    int ret;
    int filedes[2];
    
    // initialize timer list and pending list, clear fd set //
    ril_event_init();

    pthread_mutex_lock(&s_startupMutex);
    s_started = 1;
    pthread_cond_broadcast(&s_startupCond);
    pthread_mutex_unlock(&s_startupMutex);

    // wake up pipe use to update rfds in select() //
    ret = pipe(filedes);
    if (ret < 0) {
        LOGE("Error in wakeuppipe errno:%d", errno);
        return NULL;
    }

    s_fdWakeupRead = filedes[0];
    s_fdWakeupWrite = filedes[1];
    fcntl(s_fdWakeupRead, F_SETFL, O_NONBLOCK);
    ril_event_set(&s_wakeupfd_event, s_fdWakeupRead, true,
            processWakeupCallback, NULL);
    rilEventAddWakeup(&s_wakeupfd_event);
    LOGD("wake up list started");

    ril_event_loop();
    LOGE ("error in event_loop_base errno:%d", errno);

    return NULL;
}

extern "C" void
RIL_startEventLoop(void) {
	int ret;
	int i = 0;
	pthread_attr_t attr;
	pthread_t tid;
	void * pcid = NULL;

	// create TSD //
	pthread_key_create(&CID, destroyTSD);

	// create request loop and wait for it to get started ??? //
	for (; i < RIL_CHANNELS; i++) {
		//s_reqStarted[i] = 0;
		//pthread_mutex_lock(&s_startupReqMutex[i]);
		pthread_attr_init(&attr);
		pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
		pcid = malloc(sizeof(int));
		memcpy(pcid, &i, sizeof(int));
		ret = pthread_create(&tid, &attr, requestLoop, pcid);	/* 每一个ril channel 都有一个线程 request loop 来一直等待处理自己的队列  */
		if (ret < 0) {
			LOGE("Failed to create request thread %d errno:%d", i, errno);
			return;
		}
		//while (s_reqStarted[i] == 0) {
		//    pthread_cond_wait(&s_startupReqCond[i], &s_startupReqMutex[i]);
		//}
		//pthread_mutex_unlock(&s_startupReqMutex[i]);
	}

	// spin up eventLoop thread and wait for it to get started //
	s_started = 0;
	pthread_mutex_lock(&s_startupMutex);

	pthread_attr_init (&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	ret = pthread_create(&s_tid_dispatch, &attr, eventLoop, NULL);

	while (s_started == 0) {
		pthread_cond_wait(&s_startupCond, &s_startupMutex);
	}

	pthread_mutex_unlock(&s_startupMutex);

	if (ret < 0) {
		LOGE("Failed to create dispatch thread errno:%d", errno);
		return;
	}
}

// Used for testing purpose only.
extern "C" void RIL_setcallbacks (const RIL_RadioFunctions *callbacks, int client_id) {
    memcpy(&s_callbacks[client_id], callbacks, sizeof (RIL_RadioFunctions));
}

extern "C" void
RIL_register (const RIL_RadioFunctions *callbacks, int client_id) {
    int ret;
    int flags;

    if (callbacks == NULL) {
        LOGE("RIL_register: RIL_RadioFunctions * null");
        return;
    }
    if (callbacks->version < RIL_VERSION_MIN) {
        LOGE("RIL_register: version %d is to old, min version is %d",
             callbacks->version, RIL_VERSION_MIN);
        return;
    }
    if (callbacks->version > RIL_VERSION) {
        LOGE("RIL_register: version %d is too new, max version is %d",
             callbacks->version, RIL_VERSION);
        return;
    }
    LOGD("RIL_register: RIL version %d", callbacks->version);

    if (s_registerCalled >= MAX_NUM_CLIENTS) {
        LOGE("RIL_register has been called more than once. "
                "Subsequent call ignored");
        return;
    }

    memcpy(&s_callbacks[client_id], callbacks, sizeof (RIL_RadioFunctions));
    s_onRequest = callbacks->onRequest;
    s_registerCalled++;

    // Little self-check

    for (int i = 0; i < (int)NUM_ELEMS(s_commands); i++) {
        assert(i == s_commands[i].requestNumber);
    }

    for (int i = 0; i < (int)NUM_ELEMS(s_unsolResponses); i++) {
        assert(i + RIL_UNSOL_RESPONSE_BASE
                == s_unsolResponses[i].requestNumber);
    }

    // New rild impl calls RIL_startEventLoop() first
    // old standalone impl wants it here.

    if (s_started == 0) {
        RIL_startEventLoop();
    }

    // start listen socket

#if 0
    ret = socket_local_server (SOCKET_NAME_RIL,
            ANDROID_SOCKET_NAMESPACE_ABSTRACT, SOCK_STREAM);

    if (ret < 0) {
        LOGE("Unable to bind socket errno:%d", errno);
        exit (-1);
    }
    s_fdListen = ret;

#else
   LOGD("s_registerCalled=%d, s_started=%d ",s_registerCalled, s_started);
   if(s_registerCalled >  1) //already done for client 0
      return ;
    s_fdListen = android_get_control_socket(RIL_getRilSocketName());
    if (s_fdListen < 0) {
        LOGE("Failed to get socket %s", RIL_getRilSocketName());
        exit(-1);
    }

    ret = listen(s_fdListen, 4);
    LOGD(" Ril register s_fdListen=%d",s_fdListen);

    if (ret < 0) {
        LOGE("Failed to listen on control socket '%d': %s",
             s_fdListen, strerror(errno));
        exit(-1);
    }
#endif


    /*Make it persistent FD so that rild can listen for second client also */
    ril_event_set (&s_listen_event, s_fdListen, true,
                listenCallback, NULL);

    rilEventAddWakeup (&s_listen_event);
    LOGD("listen callback list started");

#if 1
    // start debug interface socket

    char rildebug[12] = {0};
    if (strcmp(RIL_getRilSocketName(), "rild") == 0) {
        strcpy(rildebug, "rild-debug");
    } else {
        strcpy(rildebug, "rild-debug1");
    }

    s_fdDebug = android_get_control_socket(rildebug);
    if (s_fdDebug < 0) {
        LOGE("Failed to get socket %s errno:%d", rildebug, errno);
        exit(-1);
    }

    ret = listen(s_fdDebug, 4);

    if (ret < 0) {
        LOGE("Failed to listen on ril debug socket '%d': %s",
             s_fdDebug, strerror(errno));
        exit(-1);
    }

    ril_event_set (&s_debug_event, s_fdDebug, true,
                debugCallback, NULL);

    rilEventAddWakeup (&s_debug_event);
    LOGD("debug list started");
#endif

}

static int
checkAndDequeueRequestInfo(struct RequestInfo *pRI) {
    int ret = 0;
    int cid = *(int *)pthread_getspecific(CID);

    if (pRI == NULL) {
        return 0;
    }

    pthread_mutex_lock(&s_pendingRequestsMutex[cid]);
    for(RequestInfo **ppCur = &s_pendingRequests[cid]
        ; *ppCur != NULL
        ; ppCur = &((*ppCur)->p_next)
    ) {
        if (pRI == *ppCur) {
            ret = 1;

            *ppCur = (*ppCur)->p_next;
            break;
        }
    }
    pthread_mutex_unlock(&s_pendingRequestsMutex[cid]);

    return ret;
}


extern "C" void
RIL_onRequestComplete(RIL_Token t, RIL_Errno e, void *response, size_t responselen) {
    RequestInfo *pRI;
    int ret;
    int cid;
    size_t errorOffset;

    pRI = (RequestInfo *)t;
    cid = pRI->pCI->cid - 1;

    if (!checkAndDequeueRequestInfo(pRI)) {
        LOGE("[REQ%d]: can't find request < %s in pending queue", 
                cid, requestToString(pRI->pCI->requestNumber));
        return;
    }

    // if URC all be sended in unsolicited queue, release wake lock //
    if (pRI->pCI->requestNumber == 
            RIL_TIME_REQUEST_RELEASE_POWERLOCK
    ) {
        wakeTimeoutCallback(pRI->userParam);
    }

    // userParam of timeReq should be free here //
    if (pRI->userParam) {
        LOGD("[REQ%d]: free timeReq %s's userParam", 
            cid, requestToString(pRI->pCI->requestNumber));
        free(pRI->userParam);
    }

    // local request no need to answer AP, as timeReq //
    if (pRI->local > 0) {
        // Locally issued command...void only!
        // response does not go back up the command socket
        LOGD("[REQ%d]: local request < %s finished", 
                cid, requestToString(pRI->pCI->requestNumber));
        goto done;
    }

    LOGD("[REQ%d]: token(%04d) < %s %s",
        cid, pRI->token, failCauseToString(e), 
        requestToString(pRI->pCI->requestNumber));
    appendPrintBuf("[%04d]< %s",
        pRI->token, requestToString(pRI->pCI->requestNumber));

    // answer AP //
    if (pRI->cancelled == 0) {
        Parcel p;

        p.writeInt32 (RESPONSE_SOLICITED);
        p.writeInt32 (pRI->token);
        errorOffset = p.dataPosition();

        p.writeInt32 (e);

        if (response != NULL) {
            // there is a response payload, no matter success or not.
            ret = pRI->pCI->responseFunction(p, response, responselen);

            /* if an error occurred, rewind and mark it */
            if (ret != 0) {
                p.setDataPosition(errorOffset);
                p.writeInt32 (ret);
            }
        }

        if (e != RIL_E_SUCCESS) {
            appendPrintBuf("%s fails by %s", printBuf, failCauseToString(e));
        }

        /*
        if (s_fdCommand[0] < 0 || s_fdCommand[1] < 0) {
            LOGD ("RIL onRequestComplete: Command channel closed");
        }
        */
        if (s_fdCommand[pRI->client_id] < 0) {
            LOGD("[REQ%d]: RIL onRequestComplete: Command channel[%d] closed", 
                    cid, pRI->client_id);
        }

        sendResponse(p,pRI->client_id);
    }

done:
    LOGD("[REQ%d]: free Req or timeReq %s", 
            cid, requestToString(pRI->pCI->requestNumber));
    free(pRI);
}

static void
grabPartialWakeLock() {
    acquire_wake_lock(PARTIAL_WAKE_LOCK, ANDROID_WAKE_LOCK_NAME);
}

static void
releaseWakeLock() {
    release_wake_lock(ANDROID_WAKE_LOCK_NAME);
}

/**
 * Timer callback to put us back to sleep before the default timeout
 */
static void
wakeTimeoutCallback (void *param) {
    // We're using "param != NULL" as a cancellation mechanism
    if (param == NULL) {
        LOGD("wakeTimeout: releasing wake lock");
        releaseWakeLock();
    } else {
        LOGD("wakeTimeout: releasing wake lock CANCELLED");
    }
}

extern "C" void
RIL_onUnsolicitedResponse_Inst0(int unsolResponse, void *data,
                                size_t datalen)
{
    RIL_onUnsolicitedResponse(unsolResponse, data, datalen, 0);
}

extern "C" void
RIL_onUnsolicitedResponse_Inst1(int unsolResponse, void *data,
                                size_t datalen)
{
    RIL_onUnsolicitedResponse(unsolResponse, data, datalen, 1);
}

void
RIL_onUnsolicitedResponse(int unsolResponse, void *data,
                                size_t datalen, int client_id)
{
    int unsolResponseIndex;
    int ret;
    int64_t timeReceived = 0;
    bool shouldScheduleTimeout = false;

    if (s_registerCalled == 0) {
        // Ignore RIL_onUnsolicitedResponse before RIL_register
        LOGW("RIL_onUnsolicitedResponse called before RIL_register");
        return;
    }

    unsolResponseIndex = unsolResponse - RIL_UNSOL_RESPONSE_BASE;

    if ((unsolResponseIndex < 0)
        || (unsolResponseIndex >= (int32_t)NUM_ELEMS(s_unsolResponses))) {
        LOGE("unsupported unsolicited response code %d", unsolResponse);
        return;
    }

    // Grab a wake lock if needed for this reponse,
    // as we exit we'll either release it immediately
    // or set a timer to release it later.
    switch (s_unsolResponses[unsolResponseIndex].wakeType) {
        case WAKE_PARTIAL:
            grabPartialWakeLock();
            shouldScheduleTimeout = true;
        break;

        case DONT_WAKE:
        default:
            // No wake lock is grabed so don't set timeout
            shouldScheduleTimeout = false;
            break;
    }

    // Mark the time this was received, doing this
    // after grabing the wakelock incase getting
    // the elapsedRealTime might cause us to goto
    // sleep.
    if (unsolResponse == RIL_UNSOL_NITZ_TIME_RECEIVED) {
        timeReceived = elapsedRealtime();
    }

    LOGD("[UNSL]< %s", requestToString(unsolResponse));
    appendPrintBuf("[UNSL]< %s", requestToString(unsolResponse));

    Parcel p;

    p.writeInt32 (RESPONSE_UNSOLICITED);
    p.writeInt32 (unsolResponse);

    ret = s_unsolResponses[unsolResponseIndex]
                .responseFunction(p, data, datalen);
    if (ret != 0) {
        // Problem with the response. Don't continue;
        goto error_exit;
    }

    // some things get more payload
    switch(unsolResponse) {
        case RIL_UNSOL_RESPONSE_RADIO_STATE_CHANGED:
            p.writeInt32(s_callbacks[client_id].onStateRequest()); //the call coresponds to client 0
            appendPrintBuf("%s {%s}", printBuf,
                radioStateToString(s_callbacks[client_id].onStateRequest()));
        break;


        case RIL_UNSOL_NITZ_TIME_RECEIVED:
            // Store the time that this was received so the
            // handler of this message can account for
            // the time it takes to arrive and process. In
            // particular the system has been known to sleep
            // before this message can be processed.
            p.writeInt64(timeReceived);
        break;
    }

    ret = sendResponse(p, client_id);
    if (ret != 0 && unsolResponse == RIL_UNSOL_NITZ_TIME_RECEIVED) {

        // Unfortunately, NITZ time is not poll/update like everything
        // else in the system. So, if the upstream client isn't connected,
        // keep a copy of the last NITZ response (with receive time noted
        // above) around so we can deliver it when it is connected

        if (s_lastNITZTimeData != NULL) {
            free (s_lastNITZTimeData);
            s_lastNITZTimeData = NULL;
        }

        s_lastNITZTimeData = malloc(p.dataSize());
        s_lastNITZTimeDataSize = p.dataSize();
        memcpy(s_lastNITZTimeData, p.data(), p.dataSize());
    }

    // For now, we automatically go back to sleep after TIMEVAL_WAKE_TIMEOUT
    // FIXME The java code should handshake here to release wake lock

    if (shouldScheduleTimeout) {
        // Cancel the previous request
        if (s_last_wake_timeout_info != NULL) {
            s_last_wake_timeout_info->userParam = malloc(1);
        }

        //s_last_wake_timeout_info
        //    = internalRequestTimedCallback(wakeTimeoutCallback, NULL,
        //                                    &TIMEVAL_WAKE_TIMEOUT);
        s_last_wake_timeout_info = internalRequestTimedCallback(
                RIL_TIME_REQUEST_RELEASE_POWERLOCK, NULL, &TIMEVAL_WAKE_TIMEOUT);
    }

    // Normal exit
    return;

error_exit:
    if (shouldScheduleTimeout) {
        releaseWakeLock();
    }
}

/** FIXME generalize this if you track UserCAllbackInfo, clear it
    when the callback occurs
*/
/*
static UserCallbackInfo *
internalRequestTimedCallback (RIL_TimedCallback callback, void *param,
                                const struct timeval *relativeTime)
{
    struct timeval myRelativeTime;
    UserCallbackInfo *p_info;

    p_info = (UserCallbackInfo *) malloc (sizeof(UserCallbackInfo));

    p_info->p_callback = callback;
    p_info->userParam = param;

    if (relativeTime == NULL) {
        // treat null parameter as a 0 relative time //
        memset (&myRelativeTime, 0, sizeof(myRelativeTime));
    } else {
        // FIXME I think event_add's tv param is really const anyway //
        memcpy (&myRelativeTime, relativeTime, sizeof(myRelativeTime));
    }

    ril_event_set(&(p_info->event), -1, false, userTimerCallback, p_info);

    ril_timer_add(&(p_info->event), &myRelativeTime);

    triggerEvLoop();
    return p_info;
}

extern "C" void
RIL_requestTimedCallback (RIL_TimedCallback callback, void *param,
                                const struct timeval *relativeTime) {
    internalRequestTimedCallback (callback, param, relativeTime);
}
*/

static UserCallbackInfo *
internalRequestTimedCallback(int timeReq, void *param,
        const struct timeval *relativeTime)
{
    struct timeval myRelativeTime;
    UserCallbackInfo *p_info;

    p_info = (UserCallbackInfo *)malloc(sizeof(UserCallbackInfo));
    p_info->timeReq = timeReq;
    // userParam will be freed in RIL_onRequestComplete() //
    p_info->userParam = param;

    if (relativeTime == NULL) {
        // treat null parameter as a 0 relative time //
        memset(&myRelativeTime, 0, sizeof(myRelativeTime));
    } else {
        // FIXME I think event_add's tv param is really const anyway //
        memcpy(&myRelativeTime, relativeTime, sizeof(myRelativeTime));
    }

    ril_event_set(&(p_info->event), -1, false, userTimerCallback, p_info);
    ril_timer_add(&(p_info->event), &myRelativeTime);
    LOGD("append timeReq %d to timerlist", timeReq);
    triggerEvLoop();

    return p_info;
}

extern "C" void
RIL_requestTimedCallback(int timeReq, void *param, 
        const struct timeval *relativeTime) {
    internalRequestTimedCallback(timeReq, param, relativeTime);
}

const char *
failCauseToString(RIL_Errno e) {
    switch(e) {
        case RIL_E_SUCCESS: return "E_SUCCESS";
        case RIL_E_RADIO_NOT_AVAILABLE: return "E_RAIDO_NOT_AVAILABLE";
        case RIL_E_GENERIC_FAILURE: return "E_GENERIC_FAILURE";
        case RIL_E_PASSWORD_INCORRECT: return "E_PASSWORD_INCORRECT";
        case RIL_E_SIM_PIN2: return "E_SIM_PIN2";
        case RIL_E_SIM_PUK2: return "E_SIM_PUK2";
        case RIL_E_REQUEST_NOT_SUPPORTED: return "E_REQUEST_NOT_SUPPORTED";
        case RIL_E_CANCELLED: return "E_CANCELLED";
        case RIL_E_OP_NOT_ALLOWED_DURING_VOICE_CALL: return "E_OP_NOT_ALLOWED_DURING_VOICE_CALL";
        case RIL_E_OP_NOT_ALLOWED_BEFORE_REG_TO_NW: return "E_OP_NOT_ALLOWED_BEFORE_REG_TO_NW";
        case RIL_E_SMS_SEND_FAIL_RETRY: return "E_SMS_SEND_FAIL_RETRY";
        case RIL_E_SIM_ABSENT:return "E_SIM_ABSENT";
        case RIL_E_ILLEGAL_SIM_OR_ME:return "E_ILLEGAL_SIM_OR_ME";
#ifdef FEATURE_MULTIMODE_ANDROID
        case RIL_E_SUBSCRIPTION_NOT_AVAILABLE:return "E_SUBSCRIPTION_NOT_AVAILABLE";
        case RIL_E_MODE_NOT_SUPPORTED:return "E_MODE_NOT_SUPPORTED";
#endif
        default: return "<unknown error>";
    }
}

const char *
radioStateToString(RIL_RadioState s) {
    switch(s) {
        case RADIO_STATE_OFF: return "RADIO_OFF";
        case RADIO_STATE_UNAVAILABLE: return "RADIO_UNAVAILABLE";
    /*modified by CYIT 20130219 for deal the sim state  ----- start -----*/
        case RADIO_STATE_SIM_NOT_READY: return "RADIO_SIM_NOT_READY";
        case RADIO_STATE_SIM_READY: return "RADIO_SIM_READY";
    /*modified by CYIT 20130219 for deal the sim state  -----  end  -----*/
        default: return "<unknown state>";
    }
}

const char *
callStateToString(RIL_CallState s) {
    switch(s) {
        case RIL_CALL_ACTIVE : return "ACTIVE";
        case RIL_CALL_HOLDING: return "HOLDING";
        case RIL_CALL_DIALING: return "DIALING";
        case RIL_CALL_ALERTING: return "ALERTING";
        case RIL_CALL_INCOMING: return "INCOMING";
        case RIL_CALL_WAITING: return "WAITING";
        default: return "<unknown state>";
    }
}

const char *
requestToString(int request) {
/*
  cat libs/telephony/ril_commands.h \
  | egrep "^ *{RIL_" \
  | sed -re 's/\{RIL_([^,]+),[^,]+,([^}]+).+/case RIL_\1: return "\1";/'

  cat libs/telephony/ril_unsol_commands.h \
  | egrep "^ *{RIL_" \
  | sed -re 's/\{RIL_([^,]+),([^}]+).+/case RIL_\1: return "\1";/'

*/
    switch(request) {
        case RIL_REQUEST_GET_SIM_STATUS: return "GET_SIM_STATUS";
        case RIL_REQUEST_ENTER_SIM_PIN: return "ENTER_SIM_PIN";
        case RIL_REQUEST_ENTER_SIM_PUK: return "ENTER_SIM_PUK";
        case RIL_REQUEST_ENTER_SIM_PIN2: return "ENTER_SIM_PIN2";
        case RIL_REQUEST_ENTER_SIM_PUK2: return "ENTER_SIM_PUK2";
        case RIL_REQUEST_CHANGE_SIM_PIN: return "CHANGE_SIM_PIN";
        case RIL_REQUEST_CHANGE_SIM_PIN2: return "CHANGE_SIM_PIN2";
        case RIL_REQUEST_ENTER_NETWORK_DEPERSONALIZATION: return "ENTER_NETWORK_DEPERSONALIZATION";
        case RIL_REQUEST_GET_CURRENT_CALLS: return "GET_CURRENT_CALLS";
        case RIL_REQUEST_DIAL: return "DIAL";
        case RIL_REQUEST_GET_IMSI: return "GET_IMSI";
        case RIL_REQUEST_HANGUP: return "HANGUP";
        case RIL_REQUEST_HANGUP_WAITING_OR_BACKGROUND: return "HANGUP_WAITING_OR_BACKGROUND";
        case RIL_REQUEST_HANGUP_FOREGROUND_RESUME_BACKGROUND: return "HANGUP_FOREGROUND_RESUME_BACKGROUND";
        case RIL_REQUEST_SWITCH_WAITING_OR_HOLDING_AND_ACTIVE: return "SWITCH_WAITING_OR_HOLDING_AND_ACTIVE";
        case RIL_REQUEST_CONFERENCE: return "CONFERENCE";
        case RIL_REQUEST_UDUB: return "UDUB";
        case RIL_REQUEST_LAST_CALL_FAIL_CAUSE: return "LAST_CALL_FAIL_CAUSE";
        case RIL_REQUEST_SIGNAL_STRENGTH: return "SIGNAL_STRENGTH";
        case RIL_REQUEST_VOICE_REGISTRATION_STATE: return "VOICE_REGISTRATION_STATE";
        case RIL_REQUEST_DATA_REGISTRATION_STATE: return "DATA_REGISTRATION_STATE";
        case RIL_REQUEST_OPERATOR: return "OPERATOR";
        case RIL_REQUEST_RADIO_POWER: return "RADIO_POWER";
        case RIL_REQUEST_DTMF: return "DTMF";
        case RIL_REQUEST_SEND_SMS: return "SEND_SMS";
        case RIL_REQUEST_SEND_SMS_EXPECT_MORE: return "SEND_SMS_EXPECT_MORE";
        case RIL_REQUEST_SETUP_DATA_CALL: return "SETUP_DATA_CALL";
        case RIL_REQUEST_SIM_IO: return "SIM_IO";
        case RIL_REQUEST_SEND_USSD: return "SEND_USSD";
        case RIL_REQUEST_CANCEL_USSD: return "CANCEL_USSD";
        case RIL_REQUEST_GET_CLIR: return "GET_CLIR";
        case RIL_REQUEST_SET_CLIR: return "SET_CLIR";
        case RIL_REQUEST_QUERY_CALL_FORWARD_STATUS: return "QUERY_CALL_FORWARD_STATUS";
        case RIL_REQUEST_SET_CALL_FORWARD: return "SET_CALL_FORWARD";
        case RIL_REQUEST_QUERY_CALL_WAITING: return "QUERY_CALL_WAITING";
        case RIL_REQUEST_SET_CALL_WAITING: return "SET_CALL_WAITING";
        case RIL_REQUEST_SMS_ACKNOWLEDGE: return "SMS_ACKNOWLEDGE";
        case RIL_REQUEST_GET_IMEI: return "GET_IMEI";
        case RIL_REQUEST_GET_IMEISV: return "GET_IMEISV";
        case RIL_REQUEST_ANSWER: return "ANSWER";
        case RIL_REQUEST_DEACTIVATE_DATA_CALL: return "DEACTIVATE_DATA_CALL";
        case RIL_REQUEST_QUERY_FACILITY_LOCK: return "QUERY_FACILITY_LOCK";
        case RIL_REQUEST_SET_FACILITY_LOCK: return "SET_FACILITY_LOCK";
        case RIL_REQUEST_CHANGE_BARRING_PASSWORD: return "CHANGE_BARRING_PASSWORD";
        case RIL_REQUEST_QUERY_NETWORK_SELECTION_MODE: return "QUERY_NETWORK_SELECTION_MODE";
        case RIL_REQUEST_SET_NETWORK_SELECTION_AUTOMATIC: return "SET_NETWORK_SELECTION_AUTOMATIC";
        case RIL_REQUEST_SET_NETWORK_SELECTION_MANUAL: return "SET_NETWORK_SELECTION_MANUAL";
        case RIL_REQUEST_QUERY_AVAILABLE_NETWORKS: return "QUERY_AVAILABLE_NETWORKS";
        case RIL_REQUEST_DTMF_START: return "DTMF_START";
        case RIL_REQUEST_DTMF_STOP: return "DTMF_STOP";
        case RIL_REQUEST_BASEBAND_VERSION: return "BASEBAND_VERSION";
        case RIL_REQUEST_SEPARATE_CONNECTION: return "SEPARATE_CONNECTION";
        case RIL_REQUEST_SET_PREFERRED_NETWORK_TYPE: return "SET_PREFERRED_NETWORK_TYPE";
        case RIL_REQUEST_GET_PREFERRED_NETWORK_TYPE: return "GET_PREFERRED_NETWORK_TYPE";
        case RIL_REQUEST_GET_NEIGHBORING_CELL_IDS: return "GET_NEIGHBORING_CELL_IDS";
        case RIL_REQUEST_SET_MUTE: return "SET_MUTE";
        case RIL_REQUEST_GET_MUTE: return "GET_MUTE";
        case RIL_REQUEST_QUERY_CLIP: return "QUERY_CLIP";
        case RIL_REQUEST_LAST_DATA_CALL_FAIL_CAUSE: return "LAST_DATA_CALL_FAIL_CAUSE";
        case RIL_REQUEST_DATA_CALL_LIST: return "DATA_CALL_LIST";
        case RIL_REQUEST_RESET_RADIO: return "RESET_RADIO";
        case RIL_REQUEST_OEM_HOOK_RAW: return "OEM_HOOK_RAW";
        case RIL_REQUEST_OEM_HOOK_STRINGS: return "OEM_HOOK_STRINGS";
        case RIL_REQUEST_SET_BAND_MODE: return "SET_BAND_MODE";
        case RIL_REQUEST_QUERY_AVAILABLE_BAND_MODE: return "QUERY_AVAILABLE_BAND_MODE";
        case RIL_REQUEST_STK_GET_PROFILE: return "STK_GET_PROFILE";
        case RIL_REQUEST_STK_SET_PROFILE: return "STK_SET_PROFILE";
        case RIL_REQUEST_STK_SEND_ENVELOPE_COMMAND: return "STK_SEND_ENVELOPE_COMMAND";
        case RIL_REQUEST_STK_SEND_TERMINAL_RESPONSE: return "STK_SEND_TERMINAL_RESPONSE";
        case RIL_REQUEST_STK_HANDLE_CALL_SETUP_REQUESTED_FROM_SIM: return "STK_HANDLE_CALL_SETUP_REQUESTED_FROM_SIM";
        case RIL_REQUEST_SCREEN_STATE: return "SCREEN_STATE";
        case RIL_REQUEST_EXPLICIT_CALL_TRANSFER: return "EXPLICIT_CALL_TRANSFER";
        case RIL_REQUEST_SET_LOCATION_UPDATES: return "SET_LOCATION_UPDATES";
        case RIL_REQUEST_CDMA_SET_SUBSCRIPTION_SOURCE: return "CDMA_SET_SUBSCRIPTION_SOURCE";
        case RIL_REQUEST_CDMA_SET_ROAMING_PREFERENCE:return"CDMA_SET_ROAMING_PREFERENCE";
        case RIL_REQUEST_CDMA_QUERY_ROAMING_PREFERENCE:return"CDMA_QUERY_ROAMING_PREFERENCE";
        case RIL_REQUEST_SET_TTY_MODE:return"SET_TTY_MODE";
        case RIL_REQUEST_QUERY_TTY_MODE:return"QUERY_TTY_MODE";
        case RIL_REQUEST_CDMA_SET_PREFERRED_VOICE_PRIVACY_MODE:return"CDMA_SET_PREFERRED_VOICE_PRIVACY_MODE";
        case RIL_REQUEST_CDMA_QUERY_PREFERRED_VOICE_PRIVACY_MODE:return"CDMA_QUERY_PREFERRED_VOICE_PRIVACY_MODE";
        case RIL_REQUEST_CDMA_FLASH:return"CDMA_FLASH";
        case RIL_REQUEST_CDMA_BURST_DTMF:return"CDMA_BURST_DTMF";
        case RIL_REQUEST_CDMA_SEND_SMS:return"CDMA_SEND_SMS";
        case RIL_REQUEST_CDMA_SMS_ACKNOWLEDGE:return"CDMA_SMS_ACKNOWLEDGE";
        case RIL_REQUEST_GSM_GET_BROADCAST_SMS_CONFIG:return"GSM_GET_BROADCAST_SMS_CONFIG";
        case RIL_REQUEST_GSM_SET_BROADCAST_SMS_CONFIG:return"GSM_SET_BROADCAST_SMS_CONFIG";
        case RIL_REQUEST_CDMA_GET_BROADCAST_SMS_CONFIG:return "CDMA_GET_BROADCAST_SMS_CONFIG";
        case RIL_REQUEST_CDMA_SET_BROADCAST_SMS_CONFIG:return "CDMA_SET_BROADCAST_SMS_CONFIG";
        case RIL_REQUEST_CDMA_SMS_BROADCAST_ACTIVATION:return "CDMA_SMS_BROADCAST_ACTIVATION";
        case RIL_REQUEST_CDMA_VALIDATE_AND_WRITE_AKEY: return"CDMA_VALIDATE_AND_WRITE_AKEY";
        case RIL_REQUEST_CDMA_SUBSCRIPTION: return"CDMA_SUBSCRIPTION";
        case RIL_REQUEST_CDMA_WRITE_SMS_TO_RUIM: return "CDMA_WRITE_SMS_TO_RUIM";
        case RIL_REQUEST_CDMA_DELETE_SMS_ON_RUIM: return "CDMA_DELETE_SMS_ON_RUIM";
        case RIL_REQUEST_DEVICE_IDENTITY: return "DEVICE_IDENTITY";
        case RIL_REQUEST_EXIT_EMERGENCY_CALLBACK_MODE: return "EXIT_EMERGENCY_CALLBACK_MODE";
        case RIL_REQUEST_GET_SMSC_ADDRESS: return "GET_SMSC_ADDRESS";
        case RIL_REQUEST_SET_SMSC_ADDRESS: return "SET_SMSC_ADDRESS";
        case RIL_REQUEST_REPORT_SMS_MEMORY_STATUS: return "REPORT_SMS_MEMORY_STATUS";
        case RIL_REQUEST_CDMA_GET_SUBSCRIPTION_SOURCE: return "CDMA_GET_SUBSCRIPTION_SOURCE";
        case RIL_REQUEST_DELETE_SMS_ON_SIM: return "DELETE_SMS_ON_SIM";
        case RIL_REQUEST_GSM_SMS_BROADCAST_ACTIVATION: return "GSM_SMS_BROADCAST_ACTIVATION";
        case RIL_REQUEST_REPORT_STK_SERVICE_IS_RUNNING: return "REPORT_STK_SERVICE_IS_RUNNING";
        case RIL_REQUEST_SET_SUPP_SVC_NOTIFICATION: return "SET_SUPP_SVC_NOTIFICATION";
        case RIL_REQUEST_VOICE_RADIO_TECH: return "VOICE_RADIO_TECH";
        case RIL_REQUEST_WRITE_SMS_TO_SIM: return "WRITE_SMS_TO_SIM";
        case RIL_REQUEST_IMS_REGISTRATION_STATE: return "IMS_REGISTRATION_STATE";
        case RIL_REQUEST_IMS_SEND_SMS: return "IMS_SEND_SMS";
        case RIL_REQUEST_GET_DATA_CALL_PROFILE: return "GET_DATA_CALL_PROFILE";
        case RIL_REQUEST_SET_UICC_SUBSCRIPTION_SOURCE: return "SET_UICC_SUBSCRIPTION_SOURCE";
        case RIL_REQUEST_SET_DATA_SUBSCRIPTION_SOURCE: return "SET_DATA_SUBSCRIPTION_SOURCE";
        case RIL_REQUEST_GET_UICC_SUBSCRIPTION_SOURCE: return "GET_UICC_SUBSCRIPTION_SOURCE";
        case RIL_REQUEST_GET_DATA_SUBSCRIPTION_SOURCE: return "GET_DATA_SUBSCRIPTION_SOURCE";
        case RIL_REQUEST_SET_SUBSCRIPTION_MODE: return "SET_SUBSCRIPTION_MODE";
        case RIL_REQUEST_ISIM_AUTHENTICATION: return "ISIM_AUTHENTICATION";
        case RIL_REQUEST_ACKNOWLEDGE_INCOMING_GSM_SMS_WITH_PDU: return "RIL_REQUEST_ACKNOWLEDGE_INCOMING_GSM_SMS_WITH_PDU";
        case RIL_REQUEST_STK_SEND_ENVELOPE_WITH_STATUS: return "RIL_REQUEST_STK_SEND_ENVELOPE_WITH_STATUS";
        case RIL_UNSOL_RESPONSE_RADIO_STATE_CHANGED: return "UNSOL_RESPONSE_RADIO_STATE_CHANGED";
        case RIL_UNSOL_RESPONSE_CALL_STATE_CHANGED: return "UNSOL_RESPONSE_CALL_STATE_CHANGED";
        case RIL_UNSOL_RESPONSE_VOICE_NETWORK_STATE_CHANGED: return "UNSOL_RESPONSE_VOICE_NETWORK_STATE_CHANGED";
        case RIL_UNSOL_RESPONSE_DATA_NETWORK_STATE_CHANGED: return "UNSOL_DATA_NETWORK_STATE_CHANGED";
        case RIL_UNSOL_RESPONSE_NEW_SMS: return "UNSOL_RESPONSE_NEW_SMS";
        case RIL_UNSOL_RESPONSE_NEW_SMS_STATUS_REPORT: return "UNSOL_RESPONSE_NEW_SMS_STATUS_REPORT";
        case RIL_UNSOL_RESPONSE_NEW_SMS_ON_SIM: return "UNSOL_RESPONSE_NEW_SMS_ON_SIM";
        case RIL_UNSOL_ON_USSD: return "UNSOL_ON_USSD";
        case RIL_UNSOL_ON_USSD_REQUEST: return "UNSOL_ON_USSD_REQUEST(obsolete)";
        case RIL_UNSOL_NITZ_TIME_RECEIVED: return "UNSOL_NITZ_TIME_RECEIVED";
        case RIL_UNSOL_SIGNAL_STRENGTH: return "UNSOL_SIGNAL_STRENGTH";
        case RIL_UNSOL_STK_SESSION_END: return "UNSOL_STK_SESSION_END";
        case RIL_UNSOL_STK_PROACTIVE_COMMAND: return "UNSOL_STK_PROACTIVE_COMMAND";
        case RIL_UNSOL_STK_EVENT_NOTIFY: return "UNSOL_STK_EVENT_NOTIFY";
        case RIL_UNSOL_STK_CALL_SETUP: return "UNSOL_STK_CALL_SETUP";
        case RIL_UNSOL_SIM_SMS_STORAGE_FULL: return "UNSOL_SIM_SMS_STORAGE_FUL";
        case RIL_UNSOL_SIM_REFRESH: return "UNSOL_SIM_REFRESH";
        case RIL_UNSOL_DATA_CALL_LIST_CHANGED: return "UNSOL_DATA_CALL_LIST_CHANGED";
        case RIL_UNSOL_CALL_RING: return "UNSOL_CALL_RING";
        case RIL_UNSOL_RESPONSE_SIM_STATUS_CHANGED: return "UNSOL_RESPONSE_SIM_STATUS_CHANGED";
        case RIL_UNSOL_RESPONSE_CDMA_NEW_SMS: return "UNSOL_NEW_CDMA_SMS";
        case RIL_UNSOL_RESPONSE_NEW_BROADCAST_SMS: return "UNSOL_NEW_BROADCAST_SMS";
        case RIL_UNSOL_CDMA_RUIM_SMS_STORAGE_FULL: return "UNSOL_CDMA_RUIM_SMS_STORAGE_FULL";
        case RIL_UNSOL_RESTRICTED_STATE_CHANGED: return "UNSOL_RESTRICTED_STATE_CHANGED";
        case RIL_UNSOL_ENTER_EMERGENCY_CALLBACK_MODE: return "UNSOL_ENTER_EMERGENCY_CALLBACK_MODE";
        case RIL_UNSOL_CDMA_CALL_WAITING: return "UNSOL_CDMA_CALL_WAITING";
        case RIL_UNSOL_CDMA_OTA_PROVISION_STATUS: return "UNSOL_CDMA_OTA_PROVISION_STATUS";
        case RIL_UNSOL_CDMA_INFO_REC: return "UNSOL_CDMA_INFO_REC";
        case RIL_UNSOL_OEM_HOOK_RAW: return "UNSOL_OEM_HOOK_RAW";
        case RIL_UNSOL_RINGBACK_TONE: return "UNSOL_RINGBACK_TONE";
        case RIL_UNSOL_RESEND_INCALL_MUTE: return "UNSOL_RESEND_INCALL_MUTE";
        case RIL_UNSOL_VOICE_RADIO_TECH_CHANGED: return "RIL_UNSOL_VOICE_RADIO_TECH_CHANGED";
        case RIL_UNSOL_CDMA_PRL_CHANGED: return "UNSOL_CDMA_PRL_CHANGED";
        case RIL_UNSOL_CDMA_SUBSCRIPTION_SOURCE_CHANGED: return "UNSOL_CDMA_SUBSCRIPTION_SOURCE_CHANGED";
        case RIL_UNSOL_SUPP_SVC_NOTIFICATION: return "UNSOL_SUPP_SVC_NOTIFICATION";
        case RIL_UNSOL_RESPONSE_IMS_NETWORK_STATE_CHANGED: return "RESPONSE_IMS_NETWORK_STATE_CHANGED";
        case RIL_UNSOL_RESPONSE_TETHERED_MODE_STATE_CHANGED: return "UNSOL_RESPONSE_TETHERED_MODE_STATE_CHANGED";
        case RIL_UNSOL_SUBSCRIPTION_READY: return "UNSOL_SUBSCRIPTION_READY";
        case RIL_UNSOL_EXIT_EMERGENCY_CALLBACK_MODE: return "UNSOL_EXIT_EMERGENCY_CALLBACK_MODE";
        case RIL_UNSOL_RIL_CONNECTED: return "UNSOL_RIL_CONNECTED";
   /**************************************************************************
      Modified by CYIT 20120825 ----- start -----
      RIL message
    **************************************************************************/
        case RIL_UNSOL_NETWORK_LIST: return "RIL_UNSOL_NETWORK_LIST";

        case RIL_REQUEST_SET_TE_TYPE:return "RIL_REQUEST_SET_TE_TYPE";
        case RIL_REQUEST_GET_TE_TYPE:return "RIL_REQUEST_GET_TE_TYPE";
        case RIL_REQUEST_SET_UE_CATEGORY:return "RIL_REQUEST_SET_UE_CATEGORY";
        case RIL_REQUEST_GET_UE_CATEGORY:return "RIL_REQUEST_GET_UE_CATEGORY";
        case RIL_REQUEST_GET_PS_ATTACHED:return "RIL_REQUEST_GET_PS_ATTACHED";
        case RIL_REQUEST_SET_PS_ATTACHED:return "RIL_REQUEST_SET_PS_ATTACHED";
        case RIL_REQUEST_GET_TD_FRQ_LOCK:return "RIL_REQUEST_GET_TD_FRQ_LOCK";
        case RIL_REQUEST_SET_TD_FRQ_LOCK:return "RIL_REQUEST_SET_TD_FRQ_LOCK";
        case RIL_REQUEST_GET_TD_CELL_ID_LOCK:return "RIL_REQUEST_GET_TD_CELL_ID_LOCK";
        case RIL_REQUEST_SET_TD_CELL_ID_LOCK:return "RIL_REQUEST_SET_TD_CELL_ID_LOCK";
        case RIL_REQUEST_GET_GSM_FRQ_LOCK:return "RIL_REQUEST_GET_GSM_FRQ_LOCK";
        case RIL_REQUEST_SET_GSM_FRQ_LOCK:return "RIL_REQUEST_SET_GSM_FRQ_LOCK";
        case RIL_REQUEST_GET_PRO_VERSION:return "RIL_REQUEST_GET_PRO_VERSION";
        case RIL_REQUEST_SET_PRO_VERSION:return "RIL_REQUEST_SET_PRO_VERSION";
        case RIL_REQUEST_GET_APN_INFO:return "RIL_REQUEST_GET_APN_INFO";
        case RIL_REQUEST_SET_APN_INFO:return "RIL_REQUEST_SET_APN_INFO";
        case RIL_REQUEST_GET_PDP_ACTIVE:return "RIL_REQUEST_GET_PDP_ACTIVE";
        case RIL_REQUEST_SET_PDP_ACTIVE:return "RIL_REQUEST_SET_PDP_ACTIVE";
        case RIL_REQUEST_GET_PDP_QOS:return "RIL_REQUEST_GET_PDP_QOS";
        case RIL_REQUEST_SET_PDP_QOS:return "RIL_REQUEST_SET_PDP_QOS";
        case RIL_REQUEST_SET_2NDPDP_CONTEXT:return "RIL_REQUEST_SET_2NDPDP_CONTEXT";
        case RIL_REQUEST_SET_TD_FRQ_UNLOCK:return "RIL_REQUEST_SET_TD_FRQ_UNLOCK";
        case RIL_REQUEST_SET_TD_CELL_UNLOCK:return "RIL_REQUEST_SET_TD_CELL_UNLOCK";
        case RIL_REQUEST_ENTER_BIOS:return "RIL_REQUEST_ENTER_BIOS";

        case RIL_REQUEST_WRITE_PB_RECORD: return "RIL_REQUEST_WRITE_PB_RECORD";
        case RIL_REQUEST_SELECT_PB_EF: return "RIL_REQUEST_SELECT_PB_EF";
        case RIL_REQUEST_PLAY_TONE: return "RIL_REQUEST_PLAY_TONE";

        case RIL_REQUEST_SET_MO_TYPE:return "RIL_REQUEST_SET_MO_TYPE";

        case RIL_REQUEST_ATCTST_AUD:return "RIL_REQUEST_ATCTST_AUD";//add by jiangjl CYIT 20110716 for audiotest

        case RIL_REQUEST_QUERY_CALL_RESTRICT_STATUS: return "RIL_REQUEST_QUERY_CALL_RESTRICT_STATUS";
        case RIL_REQUEST_SET_CALL_RESTRICT_STATUS: return "RIL_REQUEST_SET_CALL_RESTRICT_STATUS";

        case RIL_REQUEST_SET_SMS_STORAGE_LOC: return "RIL_REQUEST_SET_SMS_STORAGE_LOC";
        case RIL_REQUEST_GET_SMS_STORAGE_STATE: return "RIL_REQUEST_GET_SMS_STORAGE_STATE";

        case RIL_REQUEST_GET_SSWINFO: return "RIL_REQUEST_GET_SSWINFO";

        case RIL_REQUEST_WRITE_PB_RECORD_USER_DEFINED: return "RIL_REQUEST_WRITE_PB_RECORD_USER_DEFINED";
        case RIL_REQUEST_READ_PB_RECORD_USER_DEFINED: return "RIL_REQUEST_READ_PB_RECORD_USER_DEFINED";
        case RIL_REQUEST_GET_PB_RECORD_SIZE: return "RIL_REQUEST_GET_PB_RECORD_SIZE";

        case RIL_REQUEST_GET_PB_CONTENT_LENGTH: return "RIL_REQUEST_GET_PB_CONTENT_LENGTH";

        case RIL_REQUEST_GET_POWER_SAVING_CTRL:return "RIL_REQUEST_GET_POWER_SAVING_CTRL";
        case RIL_REQUEST_SET_POWER_SAVING_CTRL:return "RIL_REQUEST_SET_POWER_SAVING_CTRL";
        case RIL_REQUEST_GET_LOG_CTRL:return "RIL_REQUEST_GET_LOG_CTRL";
        case RIL_REQUEST_SET_LOG_CTRL:return "RIL_REQUEST_SET_LOG_CTRL";
        case RIL_REQUEST_GET_USB_ENUM_CTRL:return "RIL_REQUEST_GET_USB_ENUM_CTRL";
        case RIL_REQUEST_SET_USB_ENUM_CTRL:return "RIL_REQUEST_SET_USB_ENUM_CTRL";
        case RIL_REQUEST_GET_RESET_FLAG_CTRL:return "RIL_REQUEST_GET_RESET_FLAG_CTRL";
        case RIL_REQUEST_SET_RESET_FLAG_CTRL:return "RIL_REQUEST_SET_RESET_FLAG_CTRL";
        case RIL_REQUEST_GET_VERSION_CTRL:return "RIL_REQUEST_GET_VERSION_CTRL";
        case RIL_REQUEST_SET_VERSION_CTRL:return "RIL_REQUEST_SET_VERSION_CTRL";
        case RIL_REQUEST_GET_CELL_INFO:return "RIL_REQUEST_GET_CELL_INFO";
        case RIL_REQUEST_GET_PREFER_NETLIST:return "RIL_REQUEST_GET_PREFER_NETLIST";
        case RIL_REQUEST_SET_PREFER_NETLIST:return "RIL_REQUEST_SET_PREFER_NETLIST";
        case RIL_REQUEST_GET_POWERON_ATTACH_MODE:return "RIL_REQUEST_GET_POWERON_ATTACH_MODE";
        case RIL_REQUEST_SET_POWERON_ATTACH_MODE:return "RIL_REQUEST_SET_POWERON_ATTACH_MODE";
        case RIL_REQUEST_GET_POWERON_NETWORKSEL_CTRL:return "RIL_REQUEST_GET_POWERON_NETWORKSEL_CTRL";
        case RIL_REQUEST_SET_POWERON_NETWORKSEL_CTRL:return "RIL_REQUEST_SET_POWERON_NETWORKSEL_CTRL";
        case RIL_REQUEST_GET_STOP_PDPDATA_CTRL:return "RIL_REQUEST_GET_STOP_PDPDATA_CTRL";
        case RIL_REQUEST_SET_STOP_PDPDATA_CTRL:return "RIL_REQUEST_SET_STOP_PDPDATA_CTRL";
        case RIL_REQUEST_GET_IP_CHECK_CTRL:return "RIL_REQUEST_GET_IP_CHECK_CTRL";
        case RIL_REQUEST_SET_IP_CHECK_CTRL:return "RIL_REQUEST_SET_IP_CHECK_CTRL";
        case RIL_REQUEST_GET_SMS_BEAR_CTRL:return "RIL_REQUEST_GET_SMS_BEAR_CTRL";
        case RIL_REQUEST_SET_SMS_BEAR_CTRL:return "RIL_REQUEST_SET_SMS_BEAR_CTRL";       

        // Modified by CYIT 20130304 for append interface for querying available networks
        // together with access technology
        case RIL_REQUEST_QUERY_NETWORKS_WITH_TYPE: return "RIL_REQUEST_QUERY_NETWORKS_WITH_TYPE";

        // Modified by CYIT 20130319 for append interface for querying the reamin count
        // of sim PIN or PUK to continue input
        case RIL_REQUEST_GET_SIM_PIN_PUK_REMAIN_COUNT: return "RIL_REQUEST_GET_SIM_PIN_PUK_REMAIN_COUNT";
    /**************************************************************************
      Modified by CYIT 20120825 ----- end -----
    **************************************************************************/
        case RIL_UNSOL_PB_INIT_OVER: return "RIL_UNSOL_PB_INIT_OVER";
        case RIL_TIME_REQUEST_INITAT: return "RIL_TIME_REQUEST_INITAT";
        case RIL_TIME_REQUEST_CALL_STATE_CHANGED: return "RIL_TIME_REQUEST_CALL_STATE_CHANGED";
        case RIL_TIME_REQUEST_POLL_SIM_STATE: return "RIL_TIME_REQUEST_POLL_SIM_STATE";
        case RIL_TIME_REQUEST_DATA_CALL_LIST: return "RIL_TIME_REQUEST_DATA_CALL_LIST";
        case RIL_TIME_REQUEST_RELEASE_POWERLOCK: return "RIL_TIME_REQUEST_RELEASE_POWERLOCK";
        default: return "<unknown request>";
    }
}

} /* namespace android */
