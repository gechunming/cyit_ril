/* //device/system/reference-ril/reference-ril.c
**
** Copyright 2006, The Android Open Source Project
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

#include <telephony/ril.h>
#include <telephony/ril_cdma_sms.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include <alloca.h>
#include "atchannel.h"
#include "at_tok.h"
#include "misc.h"
#include <getopt.h>
#include <sys/socket.h>
#include <cutils/sockets.h>
#include <termios.h>

#define LOG_TAG "RIL"
#include <utils/Log.h>

#include <cutils/properties.h>
#include <arpa/inet.h>

#include <signal.h>

#ifdef USE_RAWIP
#include <sys/ioctl.h>
#endif

#define MAX_AT_RESPONSE 0x1000

/* pathname returned from RIL_REQUEST_SETUP_DATA_CALL / RIL_REQUEST_SETUP_DEFAULT_PDP */
#define PPP_TTY_PATH "/dev/omap_csmi_tty1"

#ifdef USE_TI_COMMANDS

// Enable a workaround
// 1) Make incoming call, do not answer
// 2) Hangup remote end
// Expected: call should disappear from CLCC line
// Actual: Call shows as "ACTIVE" before disappearing
#define WORKAROUND_ERRONEOUS_ANSWER 1

// Some varients of the TI stack do not support the +CGEV unsolicited
// response. However, they seem to send an unsolicited +CME ERROR: 150
#define WORKAROUND_FAKE_CGEV 1
#endif

/* Modem Technology bits */
#define MDM_GSM         0x01
//#define MDM_WCDMA       0x02
#define MDM_TD          0X02
#define MDM_CDMA        0x04
#define MDM_EVDO        0x08
#define MDM_LTE         0x10

typedef struct {
    int supportedTechs; // Bitmask of supported Modem Technology bits
    int currentTech;    // Technology the modem is currently using (in the format used by modem)
    int isMultimode;

    // Preferred mode bitmask. This is actually 4 byte-sized bitmasks with different priority values,
    // in which the byte number from LSB to MSB give the priority.
    //
    //          |MSB|   |   |LSB
    // value:   |00 |00 |00 |00
    // byte #:  |3  |2  |1  |0
    //
    // Higher byte order give higher priority. Thus, a value of 0x0000000f represents
    // a preferred mode of GSM, WCDMA, CDMA, and EvDo in which all are equally preferrable, whereas
    // 0x00000201 represents a mode with GSM and WCDMA, in which WCDMA is preferred over GSM
    int32_t preferredNetworkMode;
    int subscription_source;

} ModemInfo;

static ModemInfo *sMdmInfo;
// TECH returns the current technology in the format used by the modem.
// It can be used as an l-value
#define TECH(mdminfo)                 ((mdminfo)->currentTech)
// TECH_BIT returns the bitmask equivalent of the current tech
#define TECH_BIT(mdminfo)            (1 << ((mdminfo)->currentTech))
#define IS_MULTIMODE(mdminfo)         ((mdminfo)->isMultimode)
#define TECH_SUPPORTED(mdminfo, tech) ((mdminfo)->supportedTechs & (tech))
#define PREFERRED_NETWORK(mdminfo)    ((mdminfo)->preferredNetworkMode)
// CDMA Subscription Source
#define SSOURCE(mdminfo)              ((mdminfo)->subscription_source)

/*
static int net2modem[] = {
    MDM_GSM | MDM_WCDMA,                                 // 0  - GSM / WCDMA Pref
    MDM_GSM,                                             // 1  - GSM only
    MDM_WCDMA,                                           // 2  - WCDMA only
    MDM_GSM | MDM_WCDMA,                                 // 3  - GSM / WCDMA Auto
    MDM_CDMA | MDM_EVDO,                                 // 4  - CDMA / EvDo Auto
    MDM_CDMA,                                            // 5  - CDMA only
    MDM_EVDO,                                            // 6  - EvDo only
    MDM_GSM | MDM_WCDMA | MDM_CDMA | MDM_EVDO,           // 7  - GSM/WCDMA, CDMA, EvDo
    MDM_LTE | MDM_CDMA | MDM_EVDO,                       // 8  - LTE, CDMA and EvDo
    MDM_LTE | MDM_GSM | MDM_WCDMA,                       // 9  - LTE, GSM/WCDMA
    MDM_LTE | MDM_CDMA | MDM_EVDO | MDM_GSM | MDM_WCDMA, // 10 - LTE, CDMA, EvDo, GSM/WCDMA
    MDM_LTE,                                             // 11 - LTE only
};

static int32_t net2pmask[] = {
    MDM_GSM | (MDM_WCDMA << 8),                          // 0  - GSM / WCDMA Pref
    MDM_GSM,                                             // 1  - GSM only
    MDM_WCDMA,                                           // 2  - WCDMA only
    MDM_GSM | MDM_WCDMA,                                 // 3  - GSM / WCDMA Auto
    MDM_CDMA | MDM_EVDO,                                 // 4  - CDMA / EvDo Auto
    MDM_CDMA,                                            // 5  - CDMA only
    MDM_EVDO,                                            // 6  - EvDo only
    MDM_GSM | MDM_WCDMA | MDM_CDMA | MDM_EVDO,           // 7  - GSM/WCDMA, CDMA, EvDo
    MDM_LTE | MDM_CDMA | MDM_EVDO,                       // 8  - LTE, CDMA and EvDo
    MDM_LTE | MDM_GSM | MDM_WCDMA,                       // 9  - LTE, GSM/WCDMA
    MDM_LTE | MDM_CDMA | MDM_EVDO | MDM_GSM | MDM_WCDMA, // 10 - LTE, CDMA, EvDo, GSM/WCDMA
    MDM_LTE,                                             // 11 - LTE only
};
*/

static int net2modem[] = {
    MDM_GSM | MDM_TD,                                    // 0  - GSM / TD Pref
    MDM_GSM,                                             // 1  - GSM only
    MDM_TD,                                              // 2  - TD only
    MDM_GSM | MDM_TD,                                    // 3  - GSM Pref / TD
};

static int32_t net2pmask[] = {
    MDM_GSM | (MDM_TD << 8),                             // 0  - GSM / TD Pref
    MDM_GSM,                                             // 1  - GSM only
    MDM_TD,                                              // 2  - TD only
    (MDM_GSM << 8) | MDM_TD,                             // 3  - GSM Pref / TD   
};

static RIL_PinState s_Pin1State = RIL_PINSTATE_UNKNOWN;

typedef enum {
    SIM_ABSENT = 0,
    SIM_NOT_READY = 1,
    SIM_READY = 2, /* SIM_READY means the radio state is RADIO_STATE_SIM_READY */
    SIM_PIN = 3,
    SIM_PUK = 4,
    SIM_NETWORK_PERSONALIZATION = 5,
    RUIM_ABSENT = 6,
    RUIM_NOT_READY = 7,
    RUIM_READY = 8,
    RUIM_PIN = 9,
    RUIM_PUK = 10,
    RUIM_NETWORK_PERSONALIZATION = 11,
    SIM_IO_ERROR = 12,
} SIM_Status;

// modify by CYIT 20110831 //
#define AT_FILTER__LIST_LENGTH         23

static const char ATCMD[][11]=
{
   "AT^SHWINFO",
   "AT^HVER",
   "AT^SSWINFO",
   "AT^STMC?",
   "AT^SDATT?",
   "AT^SDATT=?",
   "AT+CGSMS?",
   "AT+CGSMS=?",
   "AT+CGATT?",
   "AT+CGATT=?",
   "AT+CGMR",
   "AT^SSPVT?",
   "AT^SSTRC?",
   "AT^SSPMT?",
   "AT^SSDHR?",
   "AT^SSPST?",
   "AT^SSATC?",
   "AT^SSATR?",
   "AT^SSDHC?",
   "AT^SSTL?",
   "AT^SSTL=?",
   "AT^SSMT?",
   "AT^SSMT=?"
};

static const char ATPREFIX[][10]=
{
   "^SHWINFO:",
   "^HVER:",
   "^SSWINFO:",
   "^STMC:",
   "^SDATT:",
   "^SDATT:",
   "+CGSMS:",
   "+CGSMS:",
   "+CGATT:",
   "+CGATT:",
   "V",
   "^SSPVT:",
   "^SSTRC:",
   "^SSPMT:",
   "^SSDHR:",
   "^SSPST:",
   "^SSATC:",
   "^SSATR:",
   "^SSDHC:",
   "^SSTL:",
   "^SSTL:",
   "^SSMT:",
   "^SSMT:"
};
// End add //

#ifdef USE_CYIT_FRAMEWORK
// modify by CYIT 20120525 -----start-----//
// to save call id in ring state not alert //
static int s_RingID = 0;
// modify by CYIT 20120525 ----- end-----//
#endif

#define M_MAXNUM_PDP 2

typedef struct {
    int m_PID; // PDP id //
    char m_Port[10]; // PDP port //
    int m_Used; // 0: unused; 1: used //
} RIL_PS_Ctl;

static RIL_PS_Ctl s_PSCtl[M_MAXNUM_PDP] = {

#ifdef USE_VM
    {1, "veth0", 0}, 
    {2, "veth1", 0},
#elif defined USE_PPP
    {1, "ppp0", 0},
    {2, "ppp1", 0},
#elif defined USE_RAWIP
    {1, "rmnet0", 0},
    {2, "rmnet1", 0},
#endif

};

#ifdef USE_RAWIP
typedef struct {
    char ttyPath[25];
    int ttyFd;
} RIL_PS_Tty;

int s_RawIP_Disc = 25; // N_RMNET defined in kernel //

#ifdef GSM_MUX_CHANNEL
RIL_PS_Tty s_Ttys[M_MAXNUM_PDP] = {
    {"gsm0710mux.channel11", -1},
    {"gsm0710mux.channel12", -1},
};
#else
RIL_PS_Tty s_Ttys[M_MAXNUM_PDP] = {
    {"/dev/ttyUSB0", -1},
    {"/dev/ttyUSB2", -1},
};
#endif
#endif

#define PDPID_MIN 1
#define PDPID_MAX 11
#define MAINPDPID_MIN 1
#define MAINPDPID_MAX 2



static void onRequest (int request, void *data, size_t datalen, RIL_Token t);
static RIL_RadioState currentState();
static int onSupports (int requestCode);
static void onCancel (RIL_Token t);
static const char *getVersion();
static int isRadioOn();
static SIM_Status getSIMStatus();
static int getCardStatus(RIL_CardStatus_v6 **pp_card_status);
static void freeCardStatus(RIL_CardStatus_v6 *p_card_status);
static void onDataCallListChanged(void *param, RIL_Token t);

/**************************************************************************
  Modified by CYIT 20120825 ----- start -----
**************************************************************************/
static void resetPdpList();
static char * getPdpPort(char * PdpID);
static int getUnUsedPdp();

static void requestSetTEType( void * data , size_t datalen , RIL_Token t );
static void requestGetTEType( void * data , size_t datalen , RIL_Token t );
static void requestGetCurNetMode( void * data , size_t datalen , RIL_Token t );
static void requestSetCurNetMode( void * data , size_t datalen , RIL_Token t );
static void requestGetTDFreq( void * data, size_t datalen, RIL_Token t );
static void requestSetTDFreq( void * data, size_t datalen, RIL_Token t );
static void requestGetTDCellIdLock( void * data, size_t datalen, RIL_Token t );
static void requestSetTDCellIdLock( void * data, size_t datalen, RIL_Token t );
static void requestGetGsmFreqLock( void * data, size_t datalen, RIL_Token t );
static void requestSetGsmFreqLock( void * data, size_t datalen, RIL_Token t );
static void requestGetProtocolVersion( void * data, size_t datalen, RIL_Token t );
static void requestSetProtocolVersion( void * data, size_t datalen, RIL_Token t );
static void requestGetUeCategroy( void * data, size_t datalen, RIL_Token t );
static void requestSetUeCategroy( void * data, size_t datalen, RIL_Token t );
static void requestGetApnInfo( void * data , size_t datalen , RIL_Token t );
static void requestSetApnInfo( void * data , size_t datalen , RIL_Token t );
static void requestGetPdpActive( void * data , size_t datalen , RIL_Token t );
static void requestSetPdpActive(void * data, size_t datalen, RIL_Token t);
static void requestGetPdpQos( void * data , size_t datalen , RIL_Token t );
static void requestSetPdpQos( void * data , size_t datalen , RIL_Token t );
static void requestSetTDFreqUnLock( void * data, size_t datalen, RIL_Token t );
static void requestSetTDCellUnLock( void * data, size_t datalen, RIL_Token t );
static void requestAtctstAud( void * data, size_t datalen, RIL_Token t );
static void requestSetPSRate( void * data , size_t datalen , RIL_Token t );
static void requestGetPSAttached( void * data , size_t datalen , RIL_Token t );
static void requestSetPSAttached( void * data , size_t datalen , RIL_Token t );
static void requestSet2ndPdpContext(void * data , size_t datalen , RIL_Token t);
static void requestSetMoType(void * data, size_t datalen, RIL_Token t);
static void requestGetPowerSavingCtrl( void * data, size_t datalen, RIL_Token t );
static void requestSetPowerSavingCtrl( void * data, size_t datalen, RIL_Token t );
static void requestGetSSWInfo( void * data , size_t datalen , RIL_Token t );
static void requestEnterBios( void * data, size_t datalen, RIL_Token t );
static void requestGetLogCtrl( void * data, size_t datalen, RIL_Token t );
static void requestSetLogCtrl( void * data, size_t datalen, RIL_Token t );
static void requestGetUsbEnumCtrl( void * data, size_t datalen, RIL_Token t );
static void requestSetUsbEnumCtrl( void * data, size_t datalen, RIL_Token t );
static void requestGetResetFlagCtrl( void * data, size_t datalen, RIL_Token t );
static void requestSetResetFlagCtrl( void * data, size_t datalen, RIL_Token t );
static void requestGetVersionCtrl( void * data, size_t datalen, RIL_Token t );
static void requestSetVersionCtrl( void * data, size_t datalen, RIL_Token t );
static void requestgetCellInfoList( void * data , size_t datalen , RIL_Token t );
static void requestgetPrenetList( void * data , size_t datalen , RIL_Token t );
static void requestsetPrenetList( void * data , size_t datalen , RIL_Token t );
static void requestGetPowerOnAttachMode( void * data, size_t datalen, RIL_Token t );
static void requestSetPowerOnAttachMode( void * data, size_t datalen, RIL_Token t );
static void requestGetPowerOnNetSelCtrl( void * data, size_t datalen, RIL_Token t );
static void requestSetPowerOnNetSelCtrl( void * data, size_t datalen, RIL_Token t );
static void requestGetStopPdpDataCtrl( void * data, size_t datalen, RIL_Token t );
static void requestSetStopPdpDataCtrl( void * data, size_t datalen, RIL_Token t );
static void requestGetIPCheckCtrl( void * data, size_t datalen, RIL_Token t );
static void requestSetIPCheckCtrl( void * data, size_t datalen, RIL_Token t );
static void requestGetSMSBear( void * data, size_t datalen, RIL_Token t );
static void requestSetSMSBear( void * data, size_t datalen, RIL_Token t );

static int isMainPdp(int pdpid);

static void requestGetIMEISV( void * data , size_t datalen , RIL_Token t );

typedef struct S_CRPos
{
    unsigned char m_pos;
    struct S_CRPos *m_pnext;
} T_CRPos;

static unsigned char HandleBinaryStr( 
    char *prefixstr, 
    unsigned char *srcbinary, unsigned int srclen, 
    unsigned char **dstbinary, unsigned int *dstlen );
/*
static void GetCROfBinaryStr( 
    unsigned char *srcbinary, int srclen, 
    int *crnum, T_CRPos **crpos );
    */

static void GetCROfBinaryStr( 
    unsigned char *srcbinary, int srclen, 
    int *crnum, T_CRPos *crpos );

static int HexStrToByteArray( char *Sour, unsigned int SourLen, 
    unsigned char *Dst, unsigned int DstLen );
/**************************************************************************
  Modified by CYIT 20120825 ----- end -----
**************************************************************************/

extern const char * requestToString(int request);
extern int ifc_set_addr(const char *name, in_addr_t addr);
extern int ifc_init(void);
extern void ifc_close(void);
extern int ifc_up(const char *name);
extern int ifc_disable(const char *ifname);
extern int ifc_get_info(const char *name, in_addr_t *addr, int *prefixLength, unsigned *flags);

extern pthread_key_t CID;

// for check the baseband status
extern int s_basebandReadyFlag;

#ifdef GSM_MUX_CHANNEL
extern fd_set readMuxs;
extern int nMuxfds;
extern int v_fds[RIL_CHANNELS]; /* fd of the AT channel */
#endif

/*** Static Variables ***/
static const RIL_RadioFunctions s_callbacks = {
    RIL_VERSION,
    onRequest,
    currentState,
    onSupports,
    onCancel,
    getVersion
};

#ifdef RIL_SHLIB
static const struct RIL_Env *s_rilenv;

#define RIL_onRequestComplete(t, e, response, responselen) s_rilenv->OnRequestComplete(t,e, response, responselen)
#define RIL_onUnsolicitedResponse(a,b,c) s_rilenv->OnUnsolicitedResponse(a,b,c)
#define RIL_requestTimedCallback(a,b,c) s_rilenv->RequestTimedCallback(a,b,c)
#endif

static RIL_RadioState sState = RADIO_STATE_UNAVAILABLE;

static pthread_mutex_t s_state_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t s_state_cond = PTHREAD_COND_INITIALIZER;

static int s_port = -1;
static const char * s_device_path = NULL;
static int          s_device_socket = 0;

/* trigger change to this with s_state_cond */
static int s_closed = 0;

static int sFD;     /* file desc of AT channel */
static char sATBuffer[MAX_AT_RESPONSE+1];
static char *sATBufferCur = NULL;

static const struct timeval TIMEVAL_SIMPOLL = {1,0};
static const struct timeval TIMEVAL_CALLSTATEPOLL = {0,500000};
static const struct timeval TIMEVAL_0 = {1,0};

#ifdef WORKAROUND_ERRONEOUS_ANSWER
// Max number of times we'll try to repoll when we think
// we have a AT+CLCC race condition
#define REPOLL_CALLS_COUNT_MAX 4

// Line index that was incoming or waiting at last poll, or -1 for none
static int s_incomingOrWaitingLine = -1;
// Number of times we've asked for a repoll of AT+CLCC
static int s_repollCallsCount = 0;
// Should we expect a call to be answered in the next CLCC?
static int s_expectAnswer = 0;
#endif /* WORKAROUND_ERRONEOUS_ANSWER */

// PIPE fd of virtual channel //
int fd_ReqRead[RIL_CHANNELS];
int fd_ReqWrite[RIL_CHANNELS];

int v_cardState = 0; // 0: sim not ready, 1: sim ready
int v_airmodeOper = RADIO_ACTION_NONE;//modified by CYIT 20130219 for airplane mode

static void pollSIMState (void *param, RIL_Token t);
static void setRadioState(RIL_RadioState newState);
static void setRadioTechnology(ModemInfo *mdm, int newtech);
static int query_ctec(ModemInfo *mdm, int *current, int32_t *preferred);
static int parse_technology_response(const char *response, int *current, int32_t *preferred);
static int techFamilyFromModemType(int mdmtype);
static void initializeCallback(void *param, RIL_Token t);
static int clccStateToRILState(int state, RIL_CallState *p_state)

{
    switch(state) {
        case 0: *p_state = RIL_CALL_ACTIVE;   return 0;
        case 1: *p_state = RIL_CALL_HOLDING;  return 0;
        case 2: *p_state = RIL_CALL_DIALING;  return 0;
        case 3: *p_state = RIL_CALL_ALERTING; return 0;
        case 4: *p_state = RIL_CALL_INCOMING; return 0;
        case 5: *p_state = RIL_CALL_WAITING;  return 0;
        case 7: *p_state = 7; return 0;
        default: return -1;
    }
}

/**
 * Note: directly modified line and has *p_call point directly into
 * modified line
 */
static int callFromCLCCLine(char *line, RIL_Call *p_call)
{
        //+CLCC: 1,0,2,0,0,\"+18005551212\",145
        //     index,isMT,state,mode,isMpty(,number,TOA)?

    int err;
    int state;
    int mode;

    err = at_tok_start(&line);
    if (err < 0) goto error;

    err = at_tok_nextint(&line, &(p_call->index));
    if (err < 0) goto error;

    err = at_tok_nextbool(&line, &(p_call->isMT));
    if (err < 0) goto error;

    err = at_tok_nextint(&line, &state);
    if (err < 0) goto error;

    err = clccStateToRILState(state, &(p_call->state));
    if (err < 0) goto error;

    err = at_tok_nextint(&line, &mode);
    if (err < 0) goto error;

    p_call->isVoice = (mode == 0);

    err = at_tok_nextbool(&line, &(p_call->isMpty));
    if (err < 0) goto error;

    if (at_tok_hasmore(&line)) {
        err = at_tok_nextstr(&line, &(p_call->number));

        /* tolerate null here */
        if (err < 0) return 0;

        // Some lame implementations return strings
        // like "NOT AVAILABLE" in the CLCC line
        if (p_call->number != NULL
            && 0 == strspn(p_call->number, "+0123456789")
        ) {
            p_call->number = NULL;
        }

        err = at_tok_nextint(&line, &p_call->toa);
        if (err < 0) goto error;
    }

    p_call->uusInfo = NULL;

#ifdef USE_CYIT_FRAMEWORK
    // modify by CYIT 20120525 ----start----//
    // skip call in ring state //
    //if (s_RingID == p_call->index) {
    if (RIL_CALL_INCOMING == p_call->state) {
	RIL_requestTimedCallback(RIL_TIME_REQUEST_CALL_STATE_CHANGED, NULL, &TIMEVAL_CALLSTATEPOLL);
        goto error;
    }

    if (7 == p_call->state) p_call->state = RIL_CALL_INCOMING;
    // modify by CYIT 20120525 ---- end ----//
#endif

    return 0;

error:
    LOGE("invalid CLCC line or call in ring state\n");
    return -1;
}

/**
 * Note: get version information
 */
int getVersionInfo()
{
    int Result = 0, err = 0;
    int dstlen = 0;
    unsigned char * srcbinary = NULL;
    unsigned char * dstbinary = NULL;
    unsigned short fc = ( unsigned short )E_ATCMD_VERS_READ;
    ATResponse * p_response = NULL;
    int response = 0x02; // 0x00 RF test; 0x01 operator test; 0x02 product
    char * versionInfo = NULL;

    srcbinary = ( unsigned char * )( &fc );

    err = HandleBinaryStr( "AT*", srcbinary, M_EGFC_LEN, &dstbinary, &dstlen );
    LOGD( "dstlen = %d", dstlen );
    if ( err == 0 || dstbinary == NULL || dstlen == 0 ) goto error;

    err = at_send_egcmd_singleline(dstbinary, dstlen, M_EGPREFIX, &p_response);
    free( dstbinary );

    if ( err < 0 || p_response->success == 0 )
    {
        goto error;
    }
    else
    {
        int prefixlen = 0;
        char * line = p_response->p_intermediates->line;

        prefixlen = M_EGPREFIX_LEN + M_EGFC_LEN + M_EGDATA_LEN;
        fc = *(( unsigned short * )( line + M_EGPREFIX_LEN ));
        
        if ( fc != E_ATCMD_VERS_READ )
        {
            LOGE( "Unmatching function code: %d." , fc);
            goto error;
        }

        // version ctrl info //
        response = *( line + prefixlen );
    }

error:
    at_response_free( p_response );
    LOGD("getVersionInfo response = %d", response);
    if(response == 0x00)
    {
        versionInfo = "0";
    }
    else if(response == 0x01)
    {
        versionInfo = "1";
    }
    else if(response == 0x02)
    {
        versionInfo = "2";
    }
    LOGD("getVersionInfo versionInfo = %s", versionInfo);
    property_set("ril.version.control", versionInfo);
    return response;
}

/** do post-AT+CFUN=1 initialization */
static void onRadioPowerOn()
{
    // ----------------------------------------------------------------
    // modify by CYIT 20111017 ----- start -----
    // ----------------------------------------------------------------
    int         err;
    ATResponse *p_response = NULL;
    int         setflag = 0x00;
    char       *line;
    int         mode = 0xFF;
    int         mt = 0xFF;
    int         bm = 0xFF;
    int         ds = 0xFF;
    int         bfr = 0xFF;
    // ----------------------------------------------------------------
    // modify by CYIT 20111017 -----  end  -----
    // ----------------------------------------------------------------

    LOGD("onRadioPowerOn");
#ifdef USE_TI_COMMANDS
    /*  Must be after CFUN=1 */
    /*  TI specific -- notifications for CPHS things such */
    /*  as CPHS message waiting indicator */

    at_send_command_min_timeout("AT%CPHS=1", NULL);

    /*  TI specific -- enable NITZ unsol notifs */
    at_send_command_min_timeout("AT%CTZV=1", NULL);
#endif

    at_send_command_singleline_min_timeout("AT+CSMS=1", "+CSMS:", NULL);

    // ----------------------------------------------------------------
    // modify by CYIT 20111017 ----- start -----
    // ----------------------------------------------------------------
    err = at_send_command_singleline_min_timeout("AT+CNMI?", "+CNMI:", &p_response);
    if (err < 0 || p_response->success == 0) {
        setflag = 0x01;
        goto cnmi_initial;
    }

    line = p_response->p_intermediates->line;

    err = at_tok_start(&line);
    if (err < 0) {
        setflag = 0x01;
        goto cnmi_initial;
    }

    err = at_tok_nextint(&line, &mode);
    if (err < 0) {
        setflag = 0x01;
        goto cnmi_initial;
    }

    err = at_tok_nextint(&line, &mt);
    if (err < 0) {
        setflag = 0x01;
        goto cnmi_initial;
    }

    err = at_tok_nextint(&line, &bm);
    if (err < 0) {
        setflag = 0x01;
        goto cnmi_initial;
    }

    err = at_tok_nextint(&line, &ds);
    if (err < 0) {
        setflag = 0x01;
        goto cnmi_initial;
    }

    err = at_tok_nextint(&line, &bfr);
    if (err < 0) {
        setflag = 0x01;
        goto cnmi_initial;
    }

    if(mode == 0x00 && mt == 0x00 && bm == 0x00 && ds == 0x00 && bfr == 0x00)
    {
        setflag = 0x01;
    }

cnmi_initial:
    at_response_free(p_response);
    if(setflag)
    {
        at_send_command_min_timeout("AT+CPMS=\"SM\",\"SM\",\"ME\"", NULL);
        // this command just notify baseband that the ME can receive more SMS
        at_send_command_min_timeout("AT^SSMME=0,100", NULL);// 0:used, 100:total
        at_send_command_min_timeout("AT+CNMI=2,2,2,1,1", NULL); // modify by CYIT 20120208
    }
    else if(mode == 0x02 && mt == 0x02 && bm == 0x02 && ds == 0x01 && bfr == 0x01)
    {
        at_send_command_min_timeout("AT^SSMME=0,100", NULL);// 0:used, 100:total
    }
    // ----------------------------------------------------------------
    // modify by CYIT 20111017 -----  end  -----
    // ----------------------------------------------------------------

    pollSIMState(NULL, NULL);
}

/** do post- SIM ready initialization */
static void onSIMReady()
{
    at_send_command_singleline_min_timeout("AT+CSMS=1", "+CSMS:", NULL);
    /*
     * Always send SMS messages directly to the TE
     *
     * mode = 1 // discard when link is reserved (link should never be
     *             reserved)
     * mt = 2   // most messages routed to TE
     * bm = 2   // new cell BM's routed to TE
     * ds = 1   // Status reports routed to TE
     * bfr = 1  // flush buffer
     */
    at_send_command_min_timeout("AT+CNMI=1,2,2,1,1", NULL);
}

// modify by CYIT 20120405 ----- start -----
static void sendAbortCmd(int type)
{
    LOGD("###ABORT###");
    char *cmd = NULL;
    asprintf(&cmd, "AT^SAOC=%d", type);
    at_send_command_min_timeout(cmd, NULL);
    free(cmd);
}
// modify by CYIT 20120405 -----  end  -----

static void requestRadioPower(void *data, size_t datalen, RIL_Token t)
{
    int onOff;

    int err;
    ATResponse *p_response = NULL;

    assert (datalen >= sizeof(int *));
    onOff = ((int *)data)[0];

    // ---------------------------------------------------------------
    //  modified by CYIT 20130219 for airplane mode  ----- start -----
    // ---------------------------------------------------------------
    LOGD("onOff: %d, sState: %d\n", onOff, sState);
    if (onOff == RADIO_ACTION_OFF && sState != RADIO_STATE_OFF) {
        // Save NV parameters before power off //
        err = at_send_command_timeout("AT&W", NO_RESULT, NULL, &p_response, CYIT_AT_TIMEOUT_10_SEC);
        if (err < 0 || p_response->success == 0) goto error;

        err = at_send_command_timeout("AT+CFUN=0", NO_RESULT, NULL, &p_response, CYIT_AT_TIMEOUT_10_SEC);
        if (err < 0 || p_response->success == 0) goto error;

        setRadioState(RADIO_STATE_OFF);
        v_airmodeOper = RADIO_ACTION_OFF;
        v_cardState = 0;
    } else if (onOff == RADIO_ACTION_ON && sState == RADIO_STATE_OFF) {
        // don't init PIN1 state in initializeCallback but here //
        // cause process 'PHONE' maybe reset ! //
        s_Pin1State = RIL_PINSTATE_UNKNOWN;

        // modify by CYIT 20120626 ----- start -----//
        // process 'PHONE' start or restart then set all PDP unused //
        resetPdpList();
        // modify by CYIT 20120626 -----  end -----//

        err = at_send_command_min_timeout("AT+CFUN=1", &p_response);
        if (err < 0|| p_response->success == 0) {
            // Some stacks return an error when there is no SIM,
            // but they really turn the RF portion on
            // So, if we get an error, let's check to see if it
            // turned on anyway

            if (isRadioOn() != 1) {
                goto error;
            }
        }

        char airType[1];
        property_get("airplane.type", airType, "1");
        if(!strcmp(&airType[0], "1")){
            at_send_command_min_timeout( "AT+CSCS=\"UCS2\"", NULL );
        }

        setRadioState(RADIO_STATE_SIM_NOT_READY);
        v_airmodeOper = RADIO_ACTION_ON;
        v_cardState = 0;
    } else if (onOff == RADIO_ACTION_AIRMODE_ON) {
        if(v_airmodeOper != RADIO_ACTION_AIRMODE_ON){
            err = at_send_command_timeout("AT+CFUN=27", NO_RESULT, NULL, &p_response, CYIT_AT_TIMEOUT_10_SEC);
            if (err < 0 || p_response->success == 0) {
                if (isRadioOn() != 27) {
                    goto error;
                }
            }
            if(v_airmodeOper == RADIO_ACTION_NONE){
                setRadioState(RADIO_STATE_SIM_NOT_READY);
            }
            v_airmodeOper = RADIO_ACTION_AIRMODE_ON;
            RIL_onUnsolicitedResponse(RIL_UNSOL_RESPONSE_VOICE_NETWORK_STATE_CHANGED, NULL, 0);
        }// else, return OK
    } else if (onOff == RADIO_ACTION_AIRMODE_OFF) {
        if(v_airmodeOper == RADIO_ACTION_AIRMODE_ON){
            err = at_send_command_timeout("AT+CFUN=28", NO_RESULT, NULL, &p_response, CYIT_AT_TIMEOUT_10_SEC);
            if (err < 0 || p_response->success == 0) {
                if (isRadioOn() != 1) {
                    goto error;
                }
            }
            v_airmodeOper = RADIO_ACTION_AIRMODE_OFF;
        }// else, return OK
    }  else goto error;
    // ---------------------------------------------------------------
    //  modified by CYIT 20130219 for airplane mode  -----  end  -----
    // ---------------------------------------------------------------

    at_response_free(p_response);
    RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
    return;
error:
    at_response_free(p_response);
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
}

static void requestOrSendDataCallList(RIL_Token *t);

static void onDataCallListChanged(void *param, RIL_Token t)
{
    requestOrSendDataCallList(NULL);
    RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
}

static void requestDataCallList(void *data, size_t datalen, RIL_Token t)
{
    requestOrSendDataCallList(&t);
}

static void requestOrSendDataCallList(RIL_Token *t)
{
    ATResponse *p_response = NULL;
    ATLine *p_cur;
    int err;
    int n = 0;
    char *out;

    // modify by CYIT 20120626 -----start-----//
    resetPdpList();
    // modify by CYIT 20120626 ----- end -----//

    err = at_send_command_multiline ("AT+CGACT?", "+CGACT:", &p_response);
    if (err != 0 || p_response->success == 0) {
        goto error;
    }

    for (p_cur = p_response->p_intermediates; p_cur != NULL;
         p_cur = p_cur->p_next)
        n++;

    RIL_Data_Call_Response_v6 *responses =
        alloca(n * sizeof(RIL_Data_Call_Response_v6));
    memset(responses, 0, n * sizeof(RIL_Data_Call_Response_v6));

    int i;
    for (i = 0; i < n; i++) {
        responses[i].cid = -1;
        responses[i].active = -1;
        responses[i].type = "";
        responses[i].addresses = "";
        responses[i].ifname = "";
    }

    RIL_Data_Call_Response_v6 *response = responses;
    for (p_cur = p_response->p_intermediates; p_cur != NULL;
         p_cur = p_cur->p_next) {
        char *line = p_cur->line;

        err = at_tok_start(&line);
        if (err < 0)
            goto error;

        err = at_tok_nextint(&line, &response->cid);
        if (err < 0)
            goto error;

        err = at_tok_nextint(&line, &response->active);
        if (err < 0)
            goto error;

        // modify by CYIT 20120626 //
        if (response->cid - 1 < M_MAXNUM_PDP) {
            s_PSCtl[response->cid - 1].m_Used = response->active;
            // in JAVA this field 'active' has 3 values downstairs //
            // DATA_CONNECTION_ACTIVE_PH_LINK_UP: 2 //
            // DATA_CONNECTION_ACTIVE_PH_LINK_DOWN: 1 //
            // DATA_CONNECTION_ACTIVE_PH_LINK_INACTIVE: 0 //
            response->active = response->active ? 2 : 0;
            if (response->active != 0) {
                response->ifname = alloca(strlen(s_PSCtl[response->cid - 1].m_Port) + 1);
                strcpy(response->ifname, s_PSCtl[response->cid - 1].m_Port);
            }
        }
        // end add //

        response++;
    }

    at_response_free(p_response);
    p_response = NULL;

    err = at_send_command_multiline ("AT+CGDCONT?", "+CGDCONT:", &p_response);
    if (err != 0 || p_response->success == 0) {
        goto error;
    }

    for (p_cur = p_response->p_intermediates; p_cur != NULL;
         p_cur = p_cur->p_next) {
        char *line = p_cur->line;
        int cid;
        char *type;
        char *apn;
        char *address;


        err = at_tok_start(&line);
        if (err < 0)
            goto error;

        err = at_tok_nextint(&line, &cid);
        if (err < 0)
            goto error;

        for (i = 0; i < n; i++) {
            if (responses[i].cid == cid)
                break;
        }

        if (i >= n) {
            /* details for a context we didn't hear about in the last request */
            continue;
        }

        err = at_tok_nextstr(&line, &out);
        if (err < 0)
            goto error;

        responses[i].type = alloca(strlen(out) + 1);
        strcpy(responses[i].type, out);

        err = at_tok_nextstr(&line, &out);
        if (err < 0)
            goto error;

#if 0
        responses[i].apn = alloca(strlen(out) + 1);
        strcpy(responses[i].apn, out);
#endif

        err = at_tok_nextstr(&line, &out);
        if (err < 0)
            goto error;

        responses[i].addresses = alloca(strlen(out) + 1);
        strcpy(responses[i].addresses, out);
    }

    at_response_free(p_response);

    if (t != NULL)
        RIL_onRequestComplete(*t, RIL_E_SUCCESS, responses,
                              n * sizeof(RIL_Data_Call_Response_v6));
    else
        RIL_onUnsolicitedResponse(RIL_UNSOL_DATA_CALL_LIST_CHANGED,
                                  responses,
                                  n * sizeof(RIL_Data_Call_Response_v6));

    return;

error:
    if (t != NULL)
        RIL_onRequestComplete(*t, RIL_E_GENERIC_FAILURE, NULL, 0);
    else
        RIL_onUnsolicitedResponse(RIL_UNSOL_DATA_CALL_LIST_CHANGED,
                                  NULL, 0);

    at_response_free(p_response);

    // modify by CYIT 20120626 ---- start -----//
    resetPdpList();
    // modify by CYIT 20120626 ----  end  -----//
}

static void requestQueryNetworkSelectionMode(
                void *data, size_t datalen, RIL_Token t)
{
    int err;
    ATResponse *p_response = NULL;
    int response = 0;
    char *line;

    err = at_send_command_singleline_min_timeout("AT+COPS?", "+COPS:", &p_response);

    if (err < 0 || p_response->success == 0) {
        goto error;
    }

    line = p_response->p_intermediates->line;

    err = at_tok_start(&line);

    if (err < 0) {
        goto error;
    }

    err = at_tok_nextint(&line, &response);

    if (err < 0) {
        goto error;
    }

    RIL_onRequestComplete(t, RIL_E_SUCCESS, &response, sizeof(int));
    at_response_free(p_response);
    return;
error:
    at_response_free(p_response);
    LOGE("requestQueryNetworkSelectionMode must never return error when radio is on");
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
}

/*
static void sendCallStateChanged(void *param)
{
    RIL_onUnsolicitedResponse (
        RIL_UNSOL_RESPONSE_CALL_STATE_CHANGED,
        NULL, 0);
}
*/

static void sendCallStateChanged(void *param, RIL_Token t)
{
    RIL_onUnsolicitedResponse (
        RIL_UNSOL_RESPONSE_CALL_STATE_CHANGED,
        NULL, 0);
    RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
}

static void requestGetCurrentCalls(void *data, size_t datalen, RIL_Token t)
{
    int err;
    ATResponse *p_response = NULL;
    ATLine *p_cur;
    int countCalls;
    int countValidCalls;
    RIL_Call *p_calls;
    RIL_Call **pp_calls;
    int i;
    int needRepoll = 0;

#ifdef WORKAROUND_ERRONEOUS_ANSWER
    int prevIncomingOrWaitingLine;

    prevIncomingOrWaitingLine = s_incomingOrWaitingLine;
    s_incomingOrWaitingLine = -1;
#endif /*WORKAROUND_ERRONEOUS_ANSWER*/

    err =at_send_command_timeout_poll(
            "AT+CLCC", MULTILINE, "+CLCC:",
            &p_response, CYIT_MIN_AT_TIMEOUT_MSEC, CYIT_AT_TIMEOUT_DEFAULT_POLL_NUM);

    if (err != 0 || p_response->success == 0) {
        /*pp_calls = (RIL_Call **)alloca(countCalls * sizeof(RIL_Call *));
        p_calls = (RIL_Call *)alloca(countCalls * sizeof(RIL_Call));
        memset (p_calls, 0, countCalls * sizeof(RIL_Call));

        RIL_onRequestComplete(t, RIL_E_SUCCESS, pp_calls, countCalls * sizeof (RIL_Call *));*/
        RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);

        at_response_free(p_response);

        return;
    }

    /* count the calls */
    for (countCalls = 0, p_cur = p_response->p_intermediates
            ; p_cur != NULL
            ; p_cur = p_cur->p_next
    ) {
        countCalls++;
    }

    /* yes, there's an array of pointers and then an array of structures */

    pp_calls = (RIL_Call **)alloca(countCalls * sizeof(RIL_Call *));
    p_calls = (RIL_Call *)alloca(countCalls * sizeof(RIL_Call));
    memset (p_calls, 0, countCalls * sizeof(RIL_Call));

    /* init the pointer array */
    for(i = 0; i < countCalls ; i++) {
        pp_calls[i] = &(p_calls[i]);
    }

    for (countValidCalls = 0, p_cur = p_response->p_intermediates
            ; p_cur != NULL
            ; p_cur = p_cur->p_next
    ) {
        err = callFromCLCCLine(p_cur->line, p_calls + countValidCalls);

        if (err != 0) {
            memset(p_calls + countValidCalls, 0, sizeof(RIL_Call));
            continue;
        }

#ifdef WORKAROUND_ERRONEOUS_ANSWER
        if (p_calls[countValidCalls].state == RIL_CALL_INCOMING
            || p_calls[countValidCalls].state == RIL_CALL_WAITING
        ) {
            s_incomingOrWaitingLine = p_calls[countValidCalls].index;
        }
#endif /*WORKAROUND_ERRONEOUS_ANSWER*/

        if (p_calls[countValidCalls].state != RIL_CALL_ACTIVE
            && p_calls[countValidCalls].state != RIL_CALL_HOLDING
        ) {
            needRepoll = 1;
        }

        countValidCalls++;
    }

#ifdef WORKAROUND_ERRONEOUS_ANSWER
    // Basically:
    // A call was incoming or waiting
    // Now it's marked as active
    // But we never answered it
    //
    // This is probably a bug, and the call will probably
    // disappear from the call list in the next poll
    if (prevIncomingOrWaitingLine >= 0
            && s_incomingOrWaitingLine < 0
            && s_expectAnswer == 0
    ) {
        for (i = 0; i < countValidCalls ; i++) {

            if (p_calls[i].index == prevIncomingOrWaitingLine
                    && p_calls[i].state == RIL_CALL_ACTIVE
                    && s_repollCallsCount < REPOLL_CALLS_COUNT_MAX
            ) {
                LOGI(
                    "Hit WORKAROUND_ERRONOUS_ANSWER case."
                    " Repoll count: %d\n", s_repollCallsCount);
                s_repollCallsCount++;
                goto error;
            }
        }
    }

    s_expectAnswer = 0;
    s_repollCallsCount = 0;
#endif /*WORKAROUND_ERRONEOUS_ANSWER*/

    RIL_onRequestComplete(t, RIL_E_SUCCESS, pp_calls,
            countValidCalls * sizeof (RIL_Call *));

    at_response_free(p_response);

#ifdef POLL_CALL_STATE
    if (countValidCalls) {  // We don't seem to get a "NO CARRIER" message from
                            // smd, so we're forced to poll until the call ends.
#else
    if (needRepoll) {
#endif
        //RIL_requestTimedCallback (sendCallStateChanged, NULL, &TIMEVAL_CALLSTATEPOLL);
        RIL_requestTimedCallback(RIL_TIME_REQUEST_CALL_STATE_CHANGED, NULL, &TIMEVAL_CALLSTATEPOLL);
    }

    return;
error:
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
    at_response_free(p_response);
}

static void requestDial(void *data, size_t datalen, RIL_Token t)
{
    RIL_Dial *p_dial;
    char *cmd;
    const char *clir;
    int ret;

    p_dial = (RIL_Dial *)data;

    switch (p_dial->clir) {
        case 1: clir = "I"; break;  /*invocation*/
        case 2: clir = "i"; break;  /*suppression*/
        default:
        case 0: clir = ""; break;   /*subscription default*/
    }

    asprintf(&cmd, "ATD%s%s;", p_dial->address, clir);
    ret = at_send_command_timeout(cmd, NO_RESULT, NULL, NULL, CYIT_AT_TIMEOUT_10_SEC);
    free(cmd);

    /* success or failure is ignored by the upper layer here.
       it will call GET_CURRENT_CALLS and determine success that way */
    RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
}

static void requestWriteSmsToSim(void *data, size_t datalen, RIL_Token t)
{
    /**************************************************************************
      Modified by CYIT 20121022 ----- start -----
      Append SMSC and send it to BB while copying SMS to SIM
    **************************************************************************/
    RIL_SMS_WriteArgs *p_args;
    char *cmd1, *cmd2;
    int length;
    int err;
    ATResponse *p_response = NULL;

    p_args = (RIL_SMS_WriteArgs *)data;

    // "NULL for default SMSC"
    if (p_args->smsc == NULL) {
        p_args->smsc= "00";
    }
    LOGD("smsc=%s, pdu=%s", p_args->smsc, p_args->pdu);

    length = strlen(p_args->pdu)/2;
    asprintf(&cmd1, "AT+CMGW=%d,%d", length, p_args->status);
    asprintf(&cmd2, "%s%s", p_args->smsc, p_args->pdu);
    // modify by CYIT 20120405
    err = at_send_command_sms(cmd1, cmd2, "+CMGW:", &p_response, CYIT_AT_TIMEOUT_70_SEC);
    free(cmd1);
    free(cmd2);
    /**************************************************************************
      Modified by CYIT 20121022 ----- start -----
    **************************************************************************/

    if ( err != 0 || p_response->success == 0 )
    {
        goto error;
    }

    RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
    at_response_free(p_response);

    return;
error:
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
    at_response_free(p_response);
}

static void requestHangup(void *data, size_t datalen, RIL_Token t)
{
    int *p_line;
    int ret;
    char *cmd;
    ATLine *p_cur;
    int countCalls = 0;
    RIL_Call *p_calls;
    int i = 0;
    int err;
    ATResponse *p_response = NULL;

    // Get the state of current calls //
    p_line = (int *)data;
    err =at_send_command_timeout_poll(
            "AT+CLCC", MULTILINE, "+CLCC:",
            &p_response, CYIT_MIN_AT_TIMEOUT_MSEC, CYIT_AT_TIMEOUT_DEFAULT_POLL_NUM);
    if (err != 0 || p_response->success == 0) {
        RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
        goto error;
    }

    // count the calls //
    for (p_cur = p_response->p_intermediates; 
            p_cur != NULL; 
            p_cur = p_cur->p_next ) {
        countCalls++;
    }

    p_calls = (RIL_Call *)alloca(countCalls * sizeof(RIL_Call));
    memset(p_calls, 0, countCalls * sizeof(RIL_Call));

    for (p_cur = p_response->p_intermediates; 
            p_cur != NULL; 
            p_cur = p_cur->p_next, i++ ) {
        err = callFromCLCCLine(p_cur->line, p_calls + i);
    }
    LOGD("%d,%d", p_line[0], p_calls[p_line[0]-1].state);

    switch (p_calls[p_line[0] - 1].state) {
        case RIL_CALL_ACTIVE:
            asprintf(&cmd, "AT+CHLD=1%d", p_line[0]);
            ret = at_send_command(cmd, NULL);
            free(cmd);
            break;
        case RIL_CALL_HOLDING:
        case RIL_CALL_INCOMING:
        case RIL_CALL_WAITING:
            ret = at_send_command("AT+CHLD=0", NULL);
            break;
        case RIL_CALL_DIALING:
        case RIL_CALL_ALERTING:
            ret = at_send_command("AT^SAOC", NULL);
            break;
    }

    // success or failure is ignored by the upper layer here. //
    // it will call GET_CURRENT_CALLS and determine success that way //
    RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
    at_response_free(p_response);
    return;

error: 
    LOGD("get current calls error in hangup process");
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
    at_response_free(p_response);
}

static void requestSignalStrength(void *data, size_t datalen, RIL_Token t)
{
    ATResponse *p_response = NULL;
    int err;
    char *line;
    int count =0;
    int numofElements=sizeof(RIL_SignalStrength_v6)/sizeof(int);
    int response[numofElements];

    err = at_send_command_singleline("AT+CSQ", "+CSQ:", &p_response);

    if (err < 0 || p_response->success == 0) {
        RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
        goto error;
    }

    line = p_response->p_intermediates->line;

    err = at_tok_start(&line);
    if (err < 0) goto error;

    /**************************************************************************
      Modified by CYIT 20121228 ----- start -----
      Make sure each element of response is -1, 
      except response[0] and response[1]
    **************************************************************************/
    memset(response, 0x00, numofElements);
    for (count =0; count < numofElements; count ++) {
    //for (count = 0; count < 2; count++) {
        if (count < 2) {
            err = at_tok_nextint(&line, &(response[count]));
            if (err < 0) goto error;
        } else {
            response[count] = -1;
        }
    }
    /**************************************************************************
      Modified by CYIT 20121228 ----- end -----
    **************************************************************************/

    RIL_onRequestComplete(t, RIL_E_SUCCESS, response, sizeof(response));

    at_response_free(p_response);
    return;

error:
    LOGE("requestSignalStrength must never return an error when radio is on");
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
    at_response_free(p_response);
}

/**
 * networkModePossible. Decides whether the network mode is appropriate for the
 * specified modem
 */
static int networkModePossible(ModemInfo *mdm, int nm)
{
    if ((net2modem[nm] & mdm->supportedTechs) == net2modem[nm]) {
       return 1;
    }
    return 0;
}
static void requestSetPreferredNetworkType( int request, void *data,
                                            size_t datalen, RIL_Token t )
{
    ATResponse *p_response = NULL;
    char *cmd = NULL;
    int value = *(int *)data;
    int current, old;
    int err;
    int32_t preferred = net2pmask[value];

    LOGD("requestSetPreferredNetworkType: current:%x. old prefer: %x. new prefer: %x", 
        TECH(sMdmInfo), PREFERRED_NETWORK(sMdmInfo), preferred);
    if (!networkModePossible(sMdmInfo, value)) {
        RIL_onRequestComplete(t, RIL_E_MODE_NOT_SUPPORTED, NULL, 0);
        return;
    }

    /*
    if (query_ctec(sMdmInfo, &current, NULL) < 0) {
        RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
        return;
    }
    */
    
    old = PREFERRED_NETWORK(sMdmInfo);
    LOGD("old != preferred: %d", old != preferred);
    if (old != preferred) {
        //asprintf(&cmd, "AT+CTEC=%d,\"%x\"", current, preferred);
        if (preferred == MDM_GSM) {
            asprintf( &cmd, "AT^STMC=13,1,1,4" );
        } else if (preferred == MDM_TD) {
            asprintf( &cmd, "AT^STMC=15,2,1,4" );
        } else if (preferred == ((MDM_GSM << 8) | MDM_TD)) {
            asprintf(&cmd, "AT^STMC=2,1,1,4");
        } else if (preferred == ((MDM_TD << 8) | MDM_GSM)) {
            asprintf(&cmd, "AT^STMC=2,2,1,4");
        }
        
        LOGD("Sending command: <%s>", cmd);
        err = at_send_command(cmd, &p_response);
        free(cmd);
        if (err < 0 || !p_response->success) {
            RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);

            at_response_free(p_response);

            return;
        }

        /*
        PREFERRED_NETWORK(sMdmInfo) = value;
        if (!strstr( p_response->p_intermediates->line, "DONE") ) {
            int current;
            int res = parse_technology_response(p_response->p_intermediates->line, &current, NULL);
            switch (res) {
                case -1: // Error or unable to parse
                    break;
                case 1: // Only able to parse current
                case 0: // Both current and preferred were parsed
                    setRadioTechnology(sMdmInfo, current);
                    break;
            }
        }
        */

        PREFERRED_NETWORK(sMdmInfo) = preferred;
    }
    RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);

    at_response_free(p_response);

}

static void requestGetPreferredNetworkType(int request, void *data,
                                   size_t datalen, RIL_Token t)
{
    int preferred;
    unsigned i;

    switch ( query_ctec(sMdmInfo, NULL, &preferred) ) {
        case -1: // Error or unable to parse
        case 1: // Only able to parse current
            RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
            break;
        case 0: // Both current and preferred were parsed
            for ( i = 0 ; i < sizeof(net2pmask) / sizeof(int32_t) ; i++ ) {
                if (preferred == net2pmask[i]) {
                    RIL_onRequestComplete(t, RIL_E_SUCCESS, &i, sizeof(int));
                    return;
                }
            }
            LOGE("Unknown preferred mode received from modem: %d", preferred);
            RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
            break;
    }

}

static void requestCdmaPrlVersion(int request, void *data,
                                   size_t datalen, RIL_Token t)
{
    int err;
    char * responseStr;
    ATResponse *p_response = NULL;
    const char *cmd;
    char *line;

    err = at_send_command_singleline("AT+WPRL?", "+WPRL:", &p_response);
    if (err < 0 || !p_response->success) goto error;
    line = p_response->p_intermediates->line;
    err = at_tok_start(&line);
    if (err < 0) goto error;
    err = at_tok_nextstr(&line, &responseStr);
    if (err < 0 || !responseStr) goto error;
    RIL_onRequestComplete(t, RIL_E_SUCCESS, responseStr, strlen(responseStr));
    at_response_free(p_response);
    return;
error:
    at_response_free(p_response);
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
}

static void requestCdmaBaseBandVersion(int request, void *data,
                                   size_t datalen, RIL_Token t)
{
    int err;
    char * responseStr;
    ATResponse *p_response = NULL;
    const char *cmd;
    const char *prefix;
    char *line, *p;
    int commas;
    int skip;
    int count = 4;

    // Fixed values. TODO: query modem
    responseStr = strdup("1.0.0.0");
    RIL_onRequestComplete(t, RIL_E_SUCCESS, responseStr, sizeof(responseStr));
    free(responseStr);
}

static void requestCdmaDeviceIdentity(int request, void *data,
                                        size_t datalen, RIL_Token t)
{
    int err;
    int response[4];
    char * responseStr[4];
    ATResponse *p_response = NULL;
    const char *cmd;
    const char *prefix;
    char *line, *p;
    int commas;
    int skip;
    int count = 4;

    // Fixed values. TODO: Query modem
    responseStr[0] = "----";
    responseStr[1] = "----";
    responseStr[2] = "77777777";

    err = at_send_command_numeric("AT+CGSN", &p_response);
    if (err < 0 || p_response->success == 0) {
        RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
        return;
    } else {
        responseStr[3] = p_response->p_intermediates->line;
    }

    RIL_onRequestComplete(t, RIL_E_SUCCESS, responseStr, count*sizeof(char*));
    at_response_free(p_response);

    return;
error:
    LOGE("requestCdmaDeviceIdentity must never return an error when radio is on");
    at_response_free(p_response);
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
}

static void requestCdmaGetSubscriptionSource(int request, void *data,
                                        size_t datalen, RIL_Token t)
{
    int err;
    int *ss = (int *)data;
    ATResponse *p_response = NULL;
    char *cmd = NULL;
    char *line = NULL;
    int response;

    asprintf(&cmd, "AT+CCSS?");
    if (!cmd) goto error;

    err = at_send_command_singleline(cmd, "+CCSS:", &p_response);
    if (err < 0 || !p_response->success)
        goto error;

    line = p_response->p_intermediates->line;
    err = at_tok_start(&line);
    if (err < 0) goto error;

    err = at_tok_nextint(&line, &response);
    free(cmd);
    cmd = NULL;

    RIL_onRequestComplete(t, RIL_E_SUCCESS, &response, sizeof(response));

    return;
error:
    free(cmd);
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
}

static void requestCdmaSetSubscriptionSource(int request, void *data,
                                        size_t datalen, RIL_Token t)
{
    int err;
    int *ss = (int *)data;
    ATResponse *p_response = NULL;
    char *cmd = NULL;

    if (!ss || !datalen) {
        LOGE("RIL_REQUEST_CDMA_SET_SUBSCRIPTION without data!");
        RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
        return;
    }
    asprintf(&cmd, "AT+CCSS=%d", ss[0]);
    if (!cmd) goto error;

    err = at_send_command(cmd, &p_response);
    if (err < 0 || !p_response->success)
        goto error;
    free(cmd);
    cmd = NULL;

    RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);

    RIL_onUnsolicitedResponse(RIL_UNSOL_CDMA_SUBSCRIPTION_SOURCE_CHANGED, &ss, sizeof(int *));

    return;
error:
    free(cmd);
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
}

static void requestCdmaSubscription(int request, void *data,
                                        size_t datalen, RIL_Token t)
{
    int err;
    int response[5];
    char * responseStr[5];
    ATResponse *p_response = NULL;
    const char *cmd;
    const char *prefix;
    char *line, *p;
    int commas;
    int skip;
    int count = 5;

    // Fixed values. TODO: Query modem
    responseStr[0] = "8587777777"; // MDN
    responseStr[1] = "1"; // SID
    responseStr[2] = "1"; // NID
    responseStr[3] = "8587777777"; // MIN
    responseStr[4] = "1"; // PRL Version
    RIL_onRequestComplete(t, RIL_E_SUCCESS, responseStr, count*sizeof(char*));

    return;
error:
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
}

static void requestCdmaGetRoamingPreference(int request, void *data,
                                                 size_t datalen, RIL_Token t)
{
    int roaming_pref = -1;
    ATResponse *p_response = NULL;
    char *line;
    int res;

    res = at_send_command_singleline("AT+WRMP?", "+WRMP:", &p_response);
    if (res < 0 || !p_response->success) {
        goto error;
    }
    line = p_response->p_intermediates->line;

    res = at_tok_start(&line);
    if (res < 0) goto error;

    res = at_tok_nextint(&line, &roaming_pref);
    if (res < 0) goto error;

     RIL_onRequestComplete(t, RIL_E_SUCCESS, &roaming_pref, sizeof(roaming_pref));
    return;
error:
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
}

static void requestCdmaSetRoamingPreference(int request, void *data,
                                                 size_t datalen, RIL_Token t)
{
    int *pref = (int *)data;
    ATResponse *p_response = NULL;
    char *line;
    int res;
    char *cmd = NULL;

    asprintf(&cmd, "AT+WRMP=%d", *pref);
    if (cmd == NULL) goto error;

    res = at_send_command(cmd, &p_response);
    if (res < 0 || !p_response->success)
        goto error;

    RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
    free(cmd);
    return;
error:
    free(cmd);
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
}

static int parseRegistrationState(char *str, int *type, int *items, int **response)
{
    int err;
    char *line = str, *p;
    int *resp = NULL;
    int skip;
    int count = 3;
    int commas;

    LOGD("parseRegistrationState. Parsing: %s",str);
    err = at_tok_start(&line);
    if (err < 0) goto error;

    /* Ok you have to be careful here
     * The solicited version of the CREG response is
     * +CREG: n, stat, [lac, cid]
     * and the unsolicited version is
     * +CREG: stat, [lac, cid]
     * The <n> parameter is basically "is unsolicited creg on?"
     * which it should always be
     *
     * Now we should normally get the solicited version here,
     * but the unsolicited version could have snuck in
     * so we have to handle both
     *
     * Also since the LAC and CID are only reported when registered,
     * we can have 1, 2, 3, or 4 arguments here
     *
     * finally, a +CGREG: answer may have a fifth value that corresponds
     * to the network type, as in;
     *
     *   +CGREG: n, stat [,lac, cid [,networkType]]
     */

    /* count number of commas */
    commas = 0;
    for (p = line ; *p != '\0' ;p++) {
        if (*p == ',') commas++;
    }

    resp = (int *)calloc(commas + 1, sizeof(int));
    if (!resp) goto error;
    switch (commas) {
        case 0: /* +CREG: <stat> */
            err = at_tok_nextint(&line, &resp[0]);
            if (err < 0) goto error;
            resp[1] = -1;
            resp[2] = -1;
        break;

        case 1: /* +CREG: <n>, <stat> */
            err = at_tok_nextint(&line, &skip);
            if (err < 0) goto error;
            err = at_tok_nextint(&line, &resp[0]);
            if (err < 0) goto error;
            resp[1] = -1;
            resp[2] = -1;
            if (err < 0) goto error;
        break;

        case 2: /* +CREG: <stat>, <lac>, <cid> */
            err = at_tok_nextint(&line, &resp[0]);
            if (err < 0) goto error;
            err = at_tok_nexthexint(&line, &resp[1]);
            if (err < 0) goto error;
            err = at_tok_nexthexint(&line, &resp[2]);
            if (err < 0) goto error;
        break;
        case 3: /* +CREG: <n>, <stat>, <lac>, <cid> */
            err = at_tok_nextint(&line, &skip);
            if (err < 0) goto error;
            err = at_tok_nextint(&line, &resp[0]);
            if (err < 0) goto error;
            err = at_tok_nexthexint(&line, &resp[1]);
            if (err < 0) goto error;
            err = at_tok_nexthexint(&line, &resp[2]);
            if (err < 0) goto error;
        break;
        /* special case for CGREG, there is a fourth parameter
         * that is the network type (unknown/gprs/edge/umts)
         */
        case 4: /* +CGREG: <n>, <stat>, <lac>, <cid>, <networkType> */
            err = at_tok_nextint(&line, &skip);
            if (err < 0) goto error;
            err = at_tok_nextint(&line, &resp[0]);
            if (err < 0) goto error;
            err = at_tok_nexthexint(&line, &resp[1]);
            if (err < 0) goto error;
            err = at_tok_nexthexint(&line, &resp[2]);
            if (err < 0) goto error;
            err = at_tok_nextint(&line, &resp[3]);
           if (err < 0) goto error;
            count = 4;
        break;
        default:
            goto error;
    }

    if (count > 3) {
        int curtech;
        switch(resp[3]) {
            case RADIO_TECHNOLOGY_BB_GSM:
                resp[3] = RADIO_TECHNOLOGY_APP_GPRS;
                break;

            case RADIO_TECHNOLOGY_BB_EDGE:
                resp[3] = RADIO_TECHNOLOGY_APP_EDGE;
                break;

            case RADIO_TECHNOLOGY_BB_UTRAN:
                resp[3] = RADIO_TECHNOLOGY_APP_UMTS;
                break;

            case RADIO_TECHNOLOGY_BB_HSDPA:
                resp[3] = RADIO_TECHNOLOGY_APP_HSDPA;
                break;

            case RADIO_TECHNOLOGY_BB_HSUPA:
                resp[3] = RADIO_TECHNOLOGY_APP_HSUPA;
                break;

            case RADIO_TECHNOLOGY_BB_HSPA:
                resp[3] = RADIO_TECHNOLOGY_APP_HSPA;
                break;

            case RADIO_TECHNOLOGY_BB_UNKNOWN:
            default:
                resp[3] = RADIO_TECHNOLOGY_APP_UNKNOWN;
                break;
        }

        if (resp[3] == RADIO_TECHNOLOGY_APP_GPRS || resp[3] == RADIO_TECHNOLOGY_APP_EDGE) {
            curtech = 0;
        } else if (resp[3] == RADIO_TECHNOLOGY_APP_UMTS
                || resp[3] == RADIO_TECHNOLOGY_APP_HSDPA
                || resp[3] == RADIO_TECHNOLOGY_APP_HSUPA
                || resp[3] == RADIO_TECHNOLOGY_APP_HSPA) {
            curtech = 1;
        } else {
            curtech = -1;
        }

        setRadioTechnology(sMdmInfo, curtech);
    }

    if (response)
        *response = resp;
    if (items)
        *items = commas + 1;
    if (type)
        *type = techFamilyFromModemType(TECH(sMdmInfo));
    return 0;
error:
    free(resp);
    return -1;
}

#define REG_STATE_LEN 15
#define REG_DATA_STATE_LEN 6
static void requestRegistrationState(int request, void *data,
                                        size_t datalen, RIL_Token t)
{
    int err;
    int *registration;
    char **responseStr = NULL;
    ATResponse *p_response = NULL;
    const char *cmd;
    const char *prefix;
    char *line;
    int i = 0, j = 0, numElements = 0;
    int count = 3;
    int type, startfrom;

    LOGD("requestRegistrationState");
    if (request == RIL_REQUEST_VOICE_REGISTRATION_STATE) {
        cmd = "AT+CREG?";
        prefix = "+CREG:";
        numElements = REG_STATE_LEN;
    } else if (request == RIL_REQUEST_DATA_REGISTRATION_STATE) {
        cmd = "AT+CGREG?";
        prefix = "+CGREG:";
        numElements = REG_DATA_STATE_LEN;
    } else {
        assert(0);
        goto error;
    }

    err = at_send_command_singleline_timeout(cmd, prefix, &p_response, CYIT_AT_TIMEOUT_10_SEC);

    if (err != 0 || p_response->success == 0) goto error;

    line = p_response->p_intermediates->line;

    if (parseRegistrationState(line, &type, &count, &registration)) goto error;

    responseStr = malloc(numElements * sizeof(char *));
    if (!responseStr) goto error;
    memset(responseStr, 0, numElements * sizeof(char *));
    /**
     * The first '4' bytes for both registration states remain the same.
     * But if the request is 'DATA_REGISTRATION_STATE',
     * the 5th and 6th byte(s) are optional.
     */
    if (type == RADIO_TECH_3GPP2) {
        LOGD("registration state type: 3GPP2");
        // TODO: Query modem
        startfrom = 3;
        if(request == RIL_REQUEST_VOICE_REGISTRATION_STATE) {
            asprintf(&responseStr[3], "8");     // EvDo revA
            asprintf(&responseStr[4], "1");     // BSID
            asprintf(&responseStr[5], "123");   // Latitude
            asprintf(&responseStr[6], "222");   // Longitude
            asprintf(&responseStr[7], "0");     // CSS Indicator
            asprintf(&responseStr[8], "4");     // SID
            asprintf(&responseStr[9], "65535"); // NID
            asprintf(&responseStr[10], "0");    // Roaming indicator
            asprintf(&responseStr[11], "1");    // System is in PRL
            asprintf(&responseStr[12], "0");    // Default Roaming indicator
            asprintf(&responseStr[13], "0");    // Reason for denial
            asprintf(&responseStr[14], "0");    // Primary Scrambling Code of Current cell
      } else if (request == RIL_REQUEST_DATA_REGISTRATION_STATE) {
            asprintf(&responseStr[3], "8");   // Available data radio technology
      }
    } else { // type == RADIO_TECH_3GPP or RADIO_TECH_NONE
        //LOGD("registration state type: 3GPP");
        startfrom = 0;
        asprintf(&responseStr[1], "%x", registration[1]);
        asprintf(&responseStr[2], "%x", registration[2]);
        if (count > 3)
            asprintf(&responseStr[3], "%d", registration[3]);
    }
    asprintf(&responseStr[0], "%d", registration[0]);

    /**
     * Optional bytes for DATA_REGISTRATION_STATE request
     * 4th byte : Registration denial code
     * 5th byte : The max. number of simultaneous Data Calls
     */
    if(request == RIL_REQUEST_DATA_REGISTRATION_STATE) {
        // asprintf(&responseStr[4], "3");
        // asprintf(&responseStr[5], "1");
    }

    /*
    for (j = startfrom; j < numElements; j++) {
        if (!responseStr[i]) goto error;
    }
    */
    if (!responseStr[0]) goto error;
    free(registration);
    registration = NULL;

    RIL_onRequestComplete(t, RIL_E_SUCCESS, responseStr, numElements*sizeof(responseStr));
    for (j = 0; j < numElements; j++ ) {
        free(responseStr[j]);
        responseStr[j] = NULL;
    }
    free(responseStr);
    responseStr = NULL;
    at_response_free(p_response);

    return;
error:
    if (responseStr) {
        for (j = 0; j < numElements; j++) {
            free(responseStr[j]);
            responseStr[j] = NULL;
        }
        free(responseStr);
        responseStr = NULL;
    }
    LOGE("requestRegistrationState must never return an error when radio is on");
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
    at_response_free(p_response);
}

static void requestOperator(void *data, size_t datalen, RIL_Token t)
{
    int err;
    int i;
    int skip;
    ATLine *p_cur;
    char *response[3];
    char *line, *cmd = NULL;

    memset(response, 0, sizeof(response));

    ATResponse *p_response = NULL;

    // modify by CYIT 20120330 ----- start -----
    /* we expect 3 lines here:
     * +COPS: 0,0,"T - Mobile"
     * +COPS: 0,1,"TMO"
     * +COPS: 0,2,"310170"
     */

    for(i = 0x00; i < 3; i++)
    {
        asprintf(&cmd, "AT+COPS=3,%d", i);
        err = at_send_command_min_timeout(cmd, NULL);
        free(cmd);
        if (err < 0) goto error;

        err = at_send_command_singleline_min_timeout("AT+COPS?", "+COPS:", &p_response);
        if (err != 0 || p_response->success == 0) goto error;

        line = p_response->p_intermediates->line;

        err = at_tok_start(&line);
        if (err < 0) goto error;

        err = at_tok_nextint(&line, &skip);
        if (err < 0) goto error;

        // If we're unregistered, we may just get
        // a "+COPS: 0" response
        if (!at_tok_hasmore(&line)) {
            response[i] = NULL;
            continue;
        }

        err = at_tok_nextint(&line, &skip);
        if (err < 0) goto error;

        // a "+COPS: 0, n" response is also possible
        if (!at_tok_hasmore(&line)) {
            response[i] = NULL;
            continue;
        }

        err = at_tok_nextstr(&line, &(response[i]));
        if (err < 0) goto error;
    }
    // modify by CYIT 20120330 -----  end  -----

    RIL_onRequestComplete(t, RIL_E_SUCCESS, response, sizeof(response));
    at_response_free(p_response);
    return;

error:
    LOGE("requestOperator must not return error when radio is on");
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
    at_response_free(p_response);
}

static void requestCdmaSendSMS(void *data, size_t datalen, RIL_Token t)
{
    int err = 1; // Set to go to error:
    RIL_SMS_Response response;
    RIL_CDMA_SMS_Message* rcsm;

    LOGD("requestCdmaSendSMS datalen=%d, sizeof(RIL_CDMA_SMS_Message)=%d",
            datalen, sizeof(RIL_CDMA_SMS_Message));

    // verify data content to test marshalling/unmarshalling:
    rcsm = (RIL_CDMA_SMS_Message*)data;
    LOGD("TeleserviceID=%d, bIsServicePresent=%d, \
            uServicecategory=%d, sAddress.digit_mode=%d, \
            sAddress.Number_mode=%d, sAddress.number_type=%d, ",
            rcsm->uTeleserviceID,  rcsm->bIsServicePresent,
            rcsm->uServicecategory,rcsm->sAddress.digit_mode,
            rcsm->sAddress.number_mode,rcsm->sAddress.number_type);

    if (err != 0) goto error;

    // Cdma Send SMS implementation will go here:
    // But it is not implemented yet.

    memset(&response, 0, sizeof(response));
    RIL_onRequestComplete(t, RIL_E_SUCCESS, &response, sizeof(response));
    return;

error:
    // Cdma Send SMS will always cause send retry error.
    RIL_onRequestComplete(t, RIL_E_SMS_SEND_FAIL_RETRY, NULL, 0);
}

static void requestSendSMS(void *data, size_t datalen, RIL_Token t)
{
    int err;
    const char *smsc;
    const char *pdu;
    int tpLayerLength = 0x00;
    char *cmd1, *cmd2;
    RIL_SMS_Response response;
    ATResponse *p_response = NULL;
    char * line;

    LOGD("requestSendSMS datalen =%d", datalen);
    smsc = ((const char **)data)[0];
    pdu = ((const char **)data)[1];

    if(pdu != NULL)
    {
        if(smsc != NULL)
        {
            tpLayerLength = strlen(smsc)/2;
        }

        tpLayerLength += strlen(pdu)/2;
    }
    else
    {
        goto error;
    }

    // "NULL for default SMSC"
    if (smsc == NULL) {
        smsc= "00";
    }
    LOGD("smsc=%s, pdu=%s", smsc, pdu);

    asprintf(&cmd1, "AT+CMGS=%d", tpLayerLength);
    asprintf(&cmd2, "%s%s", smsc, pdu);
    // modify by CYIT 20120405 ----- start -----
    err = at_send_command_sms(cmd1, cmd2, "+CMGS:", &p_response, CYIT_AT_TIMEOUT_70_SEC);
    free(cmd1);
    free(cmd2);

    if (err != 0 || p_response->success == 0)
    {
        if(err == AT_ERROR_TIMEOUT)
        {
            sendAbortCmd(CYIT_SAOC_TYPE_SMS);
        }
        goto error;
    }
    // modify by CYIT 20120405 -----  end  -----

    memset(&response, 0, sizeof(response));

    /* FIXME fill in messageRef and ackPDU */
    line = p_response->p_intermediates->line;
    err = at_tok_start(&line);
    if (err < 0) goto error;
    err = at_tok_nextint(&line, &(response.messageRef));
    if (err < 0) goto error;
    
    RIL_onRequestComplete(t, RIL_E_SUCCESS, &response, sizeof(response));
    at_response_free(p_response);

    return;
error:
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
    at_response_free(p_response);
}




// ----------------------------------------------------------------
// modify by CYIT 20111017 ----- start -----
// ----------------------------------------------------------------
static void requestSetSmsStorageLocation(void *data, size_t datalen, RIL_Token t)
{
    int     err;
    int     location = 0xFF;
    ATResponse *p_response = NULL;
    char * line;

    LOGD("requestSetSmsStorageLocation datalen =%d", datalen);
    location = ((int *)data)[0];

    if(location != 0xFF && location >= 0x00 && location <= 0x01)
    {
        if(location == 0x00)
        {
            err = at_send_command_timeout(
                "AT+CPMS=\"SM\",\"SM\",\"SM\"", NO_RESULT, NULL, &p_response, CYIT_AT_TIMEOUT_70_SEC);
            if (err < 0 || p_response->success == 0) goto error;
            // mt = 1   // save in SIM/USIM, and most messages routed to TE
            err = at_send_command_timeout(
                "AT+CNMI=2,1,2,1,1", NO_RESULT, NULL, &p_response, CYIT_AT_TIMEOUT_70_SEC);
        }
        else if(location == 0x01)
        {
            err = at_send_command_timeout(
                "AT+CPMS=\"SM\",\"SM\",\"SM\"", NO_RESULT, NULL, &p_response, CYIT_AT_TIMEOUT_70_SEC);
            if (err < 0 || p_response->success == 0) goto error;
            // this command just notify baseband that the ME can receive more SMS
            err = at_send_command_timeout(
                "AT^SSMME=0,100", NO_RESULT, NULL, &p_response, CYIT_AT_TIMEOUT_70_SEC);// 0:used, 100:total
            err = at_send_command_timeout(
                "AT+CNMI=2,2,2,1,1", NO_RESULT, NULL, &p_response, CYIT_AT_TIMEOUT_70_SEC);
        }
    }
    else
    {
        goto error;
    }

    RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
    at_response_free(p_response);
    return;

error:
    LOGE("requestSetSmsStorageLocation something may be wrong");
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
    at_response_free(p_response);
}


static void requestGetSmsStorageState(void *data, size_t datalen, RIL_Token t)
{
    int            err;
    int           response[9];
    ATResponse    *p_response = NULL;
    char          *skipstr = NULL;
    char          *line = NULL;
    char          *mem3 = NULL;

    LOGD("requestGetSmsStorageState");

    memset(response, 0x00, 9);

    err = at_send_command_singleline_timeout(
            "AT+CPMS?", "+CPMS", &p_response, CYIT_AT_TIMEOUT_70_SEC);
    if (err < 0 || p_response->success == 0) {
        if(p_response && (strStartsWith(p_response->finalResponse, "+CMS ERROR: 314")
            || strStartsWith(p_response->finalResponse, "+CME ERROR: 11")
            || strStartsWith(p_response->finalResponse, "+CME ERROR: 12")
            || strStartsWith(p_response->finalResponse, "+CME ERROR: 14")))
        {
            response[0] = 0xff; // usim busy
        }
        else
        {
            goto error;
        }
    }
    else
    {
        line = p_response->p_intermediates->line;
        err = at_tok_start(&line);
        if (err < 0) goto error;
        err = at_tok_nextstr(&line, &skipstr);//mem1
        if (err < 0) goto error;
        if(strcmp(skipstr, "SM") == 0){
            response[0] = 0;
        }else{
            response[0] = 1;
        }
        err = at_tok_nextint(&line, &(response[1]));//used1
        if (err < 0) goto error;
        err = at_tok_nextint(&line, &(response[2]));//total1
        if (err < 0) goto error;

        err = at_tok_nextstr(&line, &skipstr);//mem2
        if (err < 0) goto error;
        if(strcmp(skipstr, "SM") == 0){
            response[3] = 0;
        }else{
            response[3] = 1;
        }
        err = at_tok_nextint(&line, &(response[4]));//used2
        if (err < 0) goto error;
        err = at_tok_nextint(&line, &(response[5]));//total2
        if (err < 0) goto error;

        err = at_tok_nextstr(&line, &skipstr);//mem3
        if (err < 0) goto error;
        if(strcmp(skipstr, "SM") == 0){
            response[6] = 0;
        }else{
            response[6] = 1;
        }
        err = at_tok_nextint(&line, &(response[7]));//used3
        if (err < 0) goto error;
        err = at_tok_nextint(&line, &(response[8]));//total3
        if (err < 0) goto error;
    }
    RIL_onRequestComplete(t, RIL_E_SUCCESS, response, sizeof(response));
    at_response_free(p_response);
    return;

error:
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
    at_response_free(p_response);
}
// ----------------------------------------------------------------
// modify by CYIT 20111017 -----  end  -----
// ----------------------------------------------------------------




/*
static void requestSetupDataCall( void *data , size_t datalen , RIL_Token t )
{
    int err = 0;
    int linenum = 0;
    int pdpid = 1, pdpid2 = 0;
    int pcolen = 0;
    char *cmd = NULL;
    char *line = NULL;
    char *apn = (( char ** )data )[2];
    char *ipstr = NULL;
    char *pcostr = NULL;
    unsigned char *pcoarray = NULL;
    unsigned char dns1[16] = { 0 }, dns2[16] = { 0 };
    char pdpidstr[2] = "";
    char *response[3] = { "0", "veth0", "0.0.0.0" }; // Pdp id/device/ip //
    ATLine *p_cur = NULL;
    ATResponse *p_response = NULL;

    if ( !apn )
    {
        goto error;
    }

    // Set pdp context //
    asprintf( &cmd, "AT+CGDCONT=%d,\"IP\",\"%s\"", pdpid, apn );
    err = at_send_command_timeout( cmd, NO_RESULT, NULL, &p_response, 
        CYIT_MAX_AT_TIMEOUT_MSEC);
    free( cmd );
    if ( err != 0 || p_response->success == 0 ) 
    {
        goto error;
    }

    // Set PCO type //
    asprintf( &cmd, "AT^SGPCO=0,%d,\"8080211001E50010810600000000830600000000\"", pdpid );
    err = at_send_command_timeout( cmd, NO_RESULT, NULL, &p_response, 
        CYIT_MAX_AT_TIMEOUT_MSEC);
    free( cmd );
    if ( err !=0 || p_response->success == 0 )
    {
        goto error;
    }

    // Activate pdp //
    asprintf( &cmd, "AT+CGACT=1,%d", pdpid );
    err = at_send_command_timeout( cmd, NO_RESULT, NULL, &p_response, 
        CYIT_MAX_AT_TIMEOUT_MSEC);
    free( cmd );
    if ( err != 0 || p_response->success == 0 ) 
    {
        goto error;
    }

    // Get IP address //
    asprintf( &cmd, "AT+CGPADDR=%d", pdpid );
    err = at_send_command_singleline( cmd, "+CGPADDR:", &p_response );
    free( cmd );
    if ( err < 0 || p_response->success == 0 )
    {
        goto error2;
    }

    line = p_response->p_intermediates->line;
    err = at_tok_start( &line );
    if ( err < 0 )
    {
        goto error2;
    }

    err = at_tok_nextint( &line, &pdpid2 );
    if ( err < 0 || pdpid2 != pdpid )
    {
        goto error2;
    }

    err = at_tok_nextstr( &line, &ipstr );
    if ( err < 0 )
    {
        goto error2;
    }

    // Empty IP address //
    if ( !ipstr )
    {
        LOGE( "Empty IP address." );
        goto error2;
    }

    // Get PCO string //
    asprintf( &cmd, "AT^SGPCO=2,%d", pdpid );
    err = at_send_command_singleline( cmd, "^SGPCO:", &p_response );
    free( cmd );
    if ( err < 0 || p_response->success == 0 )
    {
        goto error2;
    }

    line = p_response->p_intermediates->line;
    err = at_tok_start( &line );
    if ( err < 0 )
    {
        goto error2;
    }

    err = at_tok_nextint( &line, &pdpid2 );
    if ( err < 0 || pdpid2 != pdpid )
    {
        goto error2;
    }

    err = at_tok_nextstr( &line, &pcostr );
    if ( err < 0 )
    {
        goto error2;
    }

    // Empty pco string //
    if ( !pcostr )
    {
        LOGE( "Empty PCO string." );
        goto error2;
    }

    // Analyze PCO string //
    pcolen = strlen( pcostr ) / 2;
    if ( pcolen > 251 )
    {
        LOGE( "The length of PCO is more than 251 bytes." );
        goto error2;
    }

    pcoarray = ( unsigned char * )malloc( pcolen );
    if ( HexStrToByteArray( pcostr, strlen( pcostr ), pcoarray, pcolen ) )
    {
        if ( pcoarray[0] != 0x80 || pcoarray[1] != 0x80 
                || pcoarray[2] != 0x21 || pcoarray[3] == 0x04 )
        {
            LOGE( "PCO header is wrong." );
            free( pcoarray );
            goto error2;
        }

        int i = 0;
        for ( ; i < pcolen; i++ )
        {
            // Get DNS1 //
            if     ( pcoarray[i] == 0x81 && pcoarray[i+1] == 0x06 )
            {
                sprintf( dns1, "%d.%d.%d.%d", 
                        pcoarray[i+2], pcoarray[i+3], pcoarray[i+4], pcoarray[i+5] );
                LOGD( "dns1 : %s\n", dns1 );
                i += 5;
            }

            // Get DNS2 //
            else if ( pcoarray[i] == 0x83 && pcoarray[i+1] == 0x06 )
            {
                sprintf( dns2, "%d.%d.%d.%d", 
                        pcoarray[i+2], pcoarray[i+3], pcoarray[i+4], pcoarray[i+5] );
                LOGD( "dns2 : %s\n", dns2 );
                i += 5;
            }
        }
    }
    else
    {
        LOGE( "HexStrToByteArray return 0." );
        free( pcoarray );
        goto error2;
    }
    
    free( pcoarray );

    if ( !strcmp( dns1, "" ) && !strcmp( dns2, "" ) )
    {
        LOGE( "Empty DNS1 and DNS2." );
        goto error2;
    }

    // Set IP and turn it on //
    ifc_init();
    if ( ifc_up( "veth0" ) 
            || ifc_set_addr( "veth0", inet_addr( ipstr )))
    {
        LOGE( "Set IP failed." );
        ifc_close();
        goto error2;
    }
    ifc_close();

    // Update global system properties //
    if ( property_set( "net.veth0.dns1", dns1 ) == -1 
        || property_set( "net.veth0.dns2", dns2 ) == -1 
        || property_set( "net.veth0.remote-ip", ipstr ) == -1 
        || property_set( "net.veth0.gw", ipstr ) == -1)
    {
        LOGE( "Set system properties failed !" );
        property_set( "net.veth0.dns1", "0.0.0.0" );
        property_set( "net.veth0.dns2", "0.0.0.0" );
        property_set( "net.veth0.remote-ip", "0.0.0.0" );
        property_set( "net.veth0.gw", "0.0.0.0" );
        goto error2;
    }

    {
        char tpstr[100] = "";
        LOGD("ipstr is: %s", ipstr);
        property_get("net.veth0.gw", tpstr, "fuck gw");
        LOGD("gateway is: %s", tpstr);
        property_get("net.veth0.remote-ip", tpstr, "fuck remote-ip");
        LOGD("remote-ip is: %s", tpstr);
        property_get("net.veth0.dns1", tpstr, "fuck dns1");
        LOGD("dns1 is: %s", tpstr);
        property_get("net.veth0.dns2", tpstr, "fuck dns2");
        LOGD("dns2 is: %s", tpstr);
    }

    // Return pdp id/device/IP address to MMI //
    sprintf( pdpidstr, "%d", pdpid );
    response[0] = pdpidstr;
    response[2] = ipstr;
    LOGD( "response[0] = %s\n response[1] = %s\n response[2] = %s\n", 
        response[0], response[1], response[2] );
    RIL_onRequestComplete( t, RIL_E_SUCCESS, response, sizeof( response ) );
    at_response_free( p_response );

    return;

error2:

    // Deactive pdp //
    asprintf( &cmd, "AT+CGACT=0,%d", pdpid );
    at_send_command_timeout( cmd, NO_RESULT, NULL, &p_response, 
        CYIT_MAX_AT_TIMEOUT_MSEC);
    free( cmd );

error:
    RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
    at_response_free( p_response );
}
*/

#ifdef USE_PPP
static void requestSetupDataCall( void *data , size_t datalen , RIL_Token t )
{
    int err = 0;
    int pdpid = 0, ppp_num = 0;
    int retry_cnt = 10;
    unsigned int ppp_flags = 0;
    char *cmd = NULL;
    char *apn = NULL;
    char dns1[PROPERTY_VALUE_MAX] = "", dns2[PROPERTY_VALUE_MAX] = "";
    char ppp_exit_code[PROPERTY_VALUE_MAX] = "";
    char ipaddr[100] = "";
    char *pdpport = NULL;
    char *pppd_start_args = NULL;
    char *pppd_stop_args = NULL;
    char *pppd_exit = NULL;
    char *pppd_pid = NULL;
    char *ppp_path = NULL;
    char *ppp_ip = NULL;
    char *ppp_dns1 = NULL, *ppp_dns2 = NULL;
    ATLine *p_cur = NULL;
    ATResponse *p_response = NULL;
    RIL_Data_Call_Response_v6 response;

    if (datalen != 7 * sizeof(char *)) goto error;

    // find unused PDP //
    pdpid = getUnUsedPdp();

    // all PDP be used, weird ??? //
    if (pdpid == 0) {
        LOGE("all PDP be used, cancel this request");
        goto error;
    }
    pdpport = s_PSCtl[pdpid - 1].m_Port;

    // Initialize response //
    response.status = PDP_FAIL_NONE;
    response.cid = pdpid;
    response.active = 2;
    response.type = ((char **)data)[6];
    response.ifname = pdpport;
    response.addresses = "";
    response.dnses = "";
    response.gateways = "";

    // initialize ppp args //
    ppp_num = response.cid - 1;
    asprintf(&pppd_start_args, "start_pppd%d:%d", ppp_num, ppp_num);
    asprintf(&pppd_stop_args, "stop_pppd%d:%d", ppp_num, ppp_num);
    asprintf(&pppd_exit, "net.gprs.ppp%d-exit", ppp_num);
    asprintf(&pppd_pid, "net.ppp%d.pid", ppp_num);
    asprintf(&ppp_path, "/sys/class/net/ppp%d", ppp_num);
    asprintf(&ppp_ip, "net.ppp%d.local-ip", ppp_num);
    asprintf(&ppp_dns1, "net.ppp%d.dns1", ppp_num);
    asprintf(&ppp_dns2, "net.ppp%d.dns2", ppp_num);

    // Data profile cann't be null //
    apn = ((char **)data)[2];
    if (!apn) goto error;

    // Check current PS //
    err = at_send_command_multiline("AT+CGACT?", "+CGACT:", &p_response);
    if (err == 0 && p_response->success == 1) {
        for (p_cur = p_response->p_intermediates
                ; p_cur != NULL
                ; p_cur = p_cur->p_next
        ) {
            int cid = 0, state = 0;
            char *line = p_cur->line;

            err = at_tok_start(&line);
            if (err < 0) goto error;

            err = at_tok_nextint(&line, &cid);
            if (err < 0) goto error;

            // same cid pdp and active, need to deactive 1st //
            if (cid == pdpid) {
                err = at_tok_nextint(&line, &state);
                if (err < 0) goto error;

                if (state == 1) {
                    char pid[10] = "";

                    LOGD("stop pppd%d...", ppp_num);
                    property_get(pppd_pid, pid, "");
                    if (!strcmp(pid, "")) {
                        LOGE("pppd%d is inactive", ppp_num);
                        goto error;
                    }
                    LOGD("pppd%d's pid is %s", ppp_num, pid);

                    //property_set("ctl.start", pppd_stop_args);
                    property_set("ril.gprs.start", "0");
                    while (retry_cnt--) {
                        LOGD("deactive retry_cnt:%d", retry_cnt);
                        sleep(3);
                        err = property_get(pppd_exit, ppp_exit_code, "");
                        if (strcmp(ppp_exit_code, "")) {
                            LOGD("deactive exit code:%s", ppp_exit_code);
                            break;
                        }
                    }

                    if (!strcmp(ppp_exit_code, "")) {
                        LOGD("kill pppd%d failed", ppp_num);
                        goto error;
                    }
                }

                break;
            }
        }
    }

    at_response_free(p_response);
    p_response = NULL;

    asprintf(&cmd, "AT+CGDCONT=%d,\"%s\",\"%s\"", 
            response.cid, response.type, apn);
    err = at_send_command_min_timeout(cmd, &p_response);
    free(cmd);
    if (err != 0 || p_response->success == 0) {
        goto error;
    }
    at_response_free(p_response);
    p_response = NULL;

    // Start pppd to acquire dns/ip adresses //
    LOGD("start pppd%d...", ppp_num);
    //err = property_set("ctl.start", pppd_start_args);
    err = property_set("ril.gprs.start", "1");
    if (err < 0) {
        LOGD("### error in starting service start_pppd%d: err %d", ppp_num, err);
        goto error;
    }

    ifc_init();
    retry_cnt = 10;
    while (retry_cnt--) {
        sleep(5);
        err = property_get(pppd_exit, ppp_exit_code, "");
        if (strcmp(ppp_exit_code, "")) break;

        if (!(err = access(ppp_path, F_OK)) &&
                !ifc_get_info(pdpport, NULL, NULL, &ppp_flags))
        {
            LOGD("ppp%d_flags: %x", ppp_num, ppp_flags);
            if (ppp_flags & 1) break;
        }

        LOGD("Check ppp%d status cnt:%d; access return:%d; error:%s", ppp_num, retry_cnt, err, strerror(errno));
    }
    ifc_close();

    if (ppp_flags & 1) {
        err = property_get(ppp_ip, ipaddr, "");
        if (err < 0) {
            LOGD("### error getting %s value: err %d", ppp_ip, err);
            goto error2;
        }

        err = property_get(ppp_dns1, dns1, "");
        err = property_get(ppp_dns2, dns2, "");

        LOGD("PPP connect successfully");
        LOGD("local-ip: %s", ipaddr);
        LOGD("dns1: %s, dns2: %s", dns1, dns2);
    } else {
        if (!strcmp(ppp_exit_code, "")) {
            LOGD("### time out and stop pppd!");
            goto error2;
        }

        LOGD("### PPP exit with error: %s", ppp_exit_code);
        goto error;
    }

    free(pppd_start_args);
    free(pppd_stop_args);
    free(pppd_exit);
    free(pppd_pid);
    free(ppp_path);
    free(ppp_ip);
    free(ppp_dns1);
    free(ppp_dns2);

    response.addresses = ipaddr;
    response.gateways = ipaddr;
    asprintf(&response.dnses, "%s %s", dns1, dns2);
    RIL_onRequestComplete(t, RIL_E_SUCCESS, &response, sizeof(response));
    free(response.dnses);

    s_PSCtl[pdpid - 1].m_Used = 1;
    return;

error2:
    //property_set("ctl.start", pppd_stop_args);
    property_set("ril.gprs.start", "0");
    retry_cnt = 10;
    while (retry_cnt--) {
        LOGD("deactive retry_cnt:%d", retry_cnt);
        sleep(3);
        err = property_get(pppd_exit, ppp_exit_code, "");
        if (strcmp(ppp_exit_code, "")) {
            LOGD("deactive exit code:%s", ppp_exit_code);
            break;
        }
    }

error:
    free(pppd_start_args);
    free(pppd_stop_args);
    free(pppd_exit);
    free(pppd_pid);
    free(ppp_path);
    free(ppp_ip);
    free(ppp_dns1);
    free(ppp_dns2);
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
    at_response_free(p_response);
}

#else

static void requestSetupDataCall( void *data , size_t datalen , RIL_Token t )
{
    int err = 0;
    int pdpid = 0;
    int pcolen = 0;
    char *cmd = NULL;
    char *line = NULL;
    char *apn = NULL;
    char *pcostr = NULL;
    char *prop1 = NULL, *prop2 = NULL;
    char *pdpport = NULL;
    char *devpath = NULL;
    unsigned char *pcoarray = NULL;
    unsigned char dns1[16] = { 0 }, dns2[16] = { 0 };
    ATLine *p_cur = NULL;
    ATResponse *p_response = NULL;
    RIL_Data_Call_Response_v6 response;

#ifdef USE_RAWIP
    int ttyfd = -1;
#endif

    if (datalen != 7 * sizeof(char *)) goto error;

    // find unused PDP //
    pdpid = getUnUsedPdp();

    // all PDP be used, weird ??? //
    if (pdpid == 0) {
        LOGE("all PDP be used, cancel this request");
        goto error;
    }

    pdpport = s_PSCtl[pdpid - 1].m_Port;

    // Initialize response //
    response.status = PDP_FAIL_NONE;
    response.cid = pdpid;
    pdpid = 0;
    response.active = 2;
    response.type = ((char **)data)[6];
    response.ifname = pdpport;
    response.addresses = "";
    response.dnses = "";
    response.gateways = "";

    // Data profile cann't be null //
    apn = ((char **)data)[2];
    if (!apn) goto error;

    // Check current PS //
    err = at_send_command_multiline("AT+CGACT?", "+CGACT:", &p_response);
    if (err == 0 && p_response->success == 1) {
        for (p_cur = p_response->p_intermediates
                ; p_cur != NULL
                ; p_cur = p_cur->p_next
        ) {
            int cid = 0, state = 0;
            char *line = p_cur->line;

            err = at_tok_start(&line);
            if (err < 0) goto error;

            err = at_tok_nextint(&line, &cid);
            if (err < 0) goto error;

            // same cid PS and active, need to deactivate it //
            if (cid == response.cid) {
                err = at_tok_nextint(&line, &state);
                if (err < 0) goto error;

                if (state == 1) {
                    at_response_free(p_response);
                    p_response = NULL;

                    // modify by CYIT 20120405 ----- start -----
                    asprintf(&cmd, "AT+CGACT=0,%d", cid);
                    err = at_send_command_timeout(
                        cmd, NO_RESULT, NULL, &p_response, CYIT_DEFAULT_AT_TIMEOUT_MSEC);
                    free(cmd);

                    if (err != 0 || p_response->success == 0) {
                        if (AT_ERROR_TIMEOUT == err) {
                            sendAbortCmd(CYIT_SAOC_TYPE_PDP_DEACTIVE);
                        }
                        goto error;
                    }
                    // modify by CYIT 20120405 ----- end  -----
                }

                break;
            }
        }
    }

    at_response_free(p_response);
    p_response = NULL;

    // Set pdp context //
    asprintf(&cmd, "AT+CGDCONT=%d,\"%s\",\"%s\"", 
            response.cid, response.type, apn);
    err = at_send_command_min_timeout(cmd, &p_response);
    free(cmd);
    if (err != 0 || p_response->success == 0) {
        goto error;
    }
    at_response_free(p_response);
    p_response = NULL;

    // Set PCO type //
    asprintf( &cmd, 
            "AT^SGPCO=0,%d,\"8080211001E50010810600000000830600000000\"", 
            response.cid );
    err = at_send_command_min_timeout( cmd, &p_response);
    free( cmd );
    if ( err !=0 || p_response->success == 0 )
    {
        goto error;
    }
    at_response_free(p_response);
    p_response = NULL;

    // Activate pdp //
    asprintf( &cmd, "AT+CGACT=1,%d", response.cid );
    // modify by CYIT 20120405 ----- start -----
    err = at_send_command_timeout( cmd, NO_RESULT, NULL, &p_response, CYIT_AT_TIMEOUT_70_SEC);
    free( cmd );

    if ( err != 0 || p_response->success == 0 ) 
    {
        if (AT_ERROR_TIMEOUT == err) {
            sendAbortCmd(CYIT_SAOC_TYPE_PDP_ACTIVE);
        }
        goto error;
    }
    // modify by CYIT 20120405 ----- end  -----
    at_response_free(p_response);
    p_response = NULL;

    // Get PCO string //
    asprintf( &cmd, "AT^SGPCO=2,%d", response.cid );
    err = at_send_command_singleline_min_timeout( cmd, "^SGPCO:", &p_response );
    free( cmd );
    if ( err < 0 || p_response->success == 0 )
    {
        goto error2;
    }

    line = p_response->p_intermediates->line;
    err = at_tok_start( &line );
    if ( err < 0 )
    {
        goto error2;
    }

    err = at_tok_nextint( &line, &pdpid );
    if ( err < 0 || pdpid != response.cid )
    {
        goto error2;
    }

    err = at_tok_nextstr( &line, &pcostr );
    if ( err < 0 )
    {
        goto error2;
    }

    // Empty pco string //
    if ( !pcostr || strcmp(pcostr, "") == 0 )
    {
        LOGE( "Empty PCO string." );
        goto error2;
    }

    // Analyze PCO string //
    pcolen = strlen( pcostr ) / 2;
    if ( pcolen > 251 )
    {
        LOGE( "The length of PCO is more than 251 bytes." );
        goto error2;
    }

    pcoarray = ( unsigned char * )malloc( pcolen );
    if ( HexStrToByteArray( pcostr, strlen( pcostr ), pcoarray, pcolen ) )
    {
        if ( pcoarray[0] != 0x80 || pcoarray[1] != 0x80 
                || pcoarray[2] != 0x21 || pcoarray[3] == 0x04 )
        {
            LOGE( "PCO header is wrong." );
            free( pcoarray );
            goto error2;
        }

        int i = 0;
        for ( ; i < pcolen; i++ )
        {
            // Get DNS1 //
            if     ( pcoarray[i] == 0x81 && pcoarray[i+1] == 0x06 )
            {
                sprintf( dns1, "%d.%d.%d.%d", 
                        pcoarray[i+2], pcoarray[i+3], pcoarray[i+4], pcoarray[i+5] );
                LOGD( "dns1 : %s\n", dns1 );
                i += 5;
            }

            // Get DNS2 //
            else if ( pcoarray[i] == 0x83 && pcoarray[i+1] == 0x06 )
            {
                sprintf( dns2, "%d.%d.%d.%d", 
                        pcoarray[i+2], pcoarray[i+3], pcoarray[i+4], pcoarray[i+5] );
                LOGD( "dns2 : %s\n", dns2 );
                i += 5;
            }
        }
    }
    else
    {
        LOGE( "HexStrToByteArray return 0." );
        free( pcoarray );
        goto error2;
    }
    
    free( pcoarray );

    if ( !strcmp( dns1, "" ) && !strcmp( dns2, "" ) )
    {
        LOGE( "Empty DNS1 and DNS2." );
        goto error2;
    }

    // Update global system properties //
    // modify by CYIT 20120625 //
    /*
       if ( property_set( "net.veth0.dns1", dns1 ) == -1 
       || property_set( "net.veth0.dns2", dns2 ) == -1)
       {
       LOGE( "Set system properties failed !" );
       property_set( "net.veth0.dns1", "0.0.0.0" );
       property_set( "net.veth0.dns2", "0.0.0.0" );
       goto error2;
       }
     */

    asprintf(&prop1, "net.%s.dns1", pdpport);
    asprintf(&prop2, "net.%s.dns2", pdpport);
    if (property_set(prop1, dns1) == -1 
            || property_set(prop2, dns2) == -1)
    {
        LOGE("Set system properties failed !");
        property_set(prop1, "0.0.0.0");
        property_set(prop2, "0.0.0.0");

        free(prop1);
        free(prop2);
        goto error2;
    }

    free(prop1);
    free(prop2);
    // end modify //

    at_response_free(p_response);
    p_response = NULL;

    // Get IP address //
    asprintf( &cmd, "AT+CGPADDR=%d", response.cid );
    err = at_send_command_singleline_min_timeout( cmd, "+CGPADDR:", &p_response );
    free( cmd );
    if ( err < 0 || p_response->success == 0 )
    {
        goto error2;
    }

    line = p_response->p_intermediates->line;
    err = at_tok_start( &line );
    if ( err < 0 )
    {
        goto error2;
    }

    err = at_tok_nextint( &line, &pdpid );
    if ( err < 0 || pdpid != response.cid )
    {
        goto error2;
    }

    err = at_tok_nextstr( &line, &response.addresses );
    if ( err < 0 )
    {
        goto error2;
    }

    // Empty IP address //
    if (response.addresses == NULL 
           || strcmp(response.addresses, "") == 0)
    {
        LOGE( "Empty IP address." );
        goto error2;
    }

    // Set IP and turn it on //

#ifdef USE_RAWIP
#ifdef GSM_MUX_CHANNEL
    devpath = malloc(PROPERTY_VALUE_MAX);
    memset(devpath, 0, PROPERTY_VALUE_MAX);
    property_get(s_Ttys[pdpid - 1].ttyPath, devpath, "");
    if (!strcmp(devpath, "")) {
        LOGE("get %s's device path failed", s_Ttys[pdpid - 1].ttyPath);
        free(devpath);
        goto error2;
    }
    LOGD("device path is %s", devpath);
#else
    devpath = s_Ttys[pdpid - 1].ttyPath;
#endif

    ttyfd = open(devpath, O_RDWR | O_NOCTTY | O_NONBLOCK);
#ifdef GSM_MUX_CHANNEL
    free(devpath);
#endif
    if (ttyfd < 0) {
        LOGE("open failed, errno is %s", strerror(errno));
        goto error2;
    }
    s_Ttys[pdpid - 1].ttyFd = ttyfd;

    if (ioctl(ttyfd, TIOCSETD, &s_RawIP_Disc) < 0) {
        LOGE("create %s failed.", pdpport);
        goto error2;
    }
#endif

    ifc_init();

    // modify by CYIT 20120625 ------- start -----//
    //if ( ifc_up( "veth0" ) 
    //        || ifc_set_addr( "veth0", inet_addr( response.addresses )))

    if (ifc_up(pdpport)
            || ifc_set_addr(pdpport, inet_addr(response.addresses))
    )
    // modify by CYIT 20120625 -------  end  -----//

    {
        LOGE( "Set IP failed." );
        ifc_close();
        goto error2;
    }
    ifc_close();

    response.gateways = response.addresses;
    asprintf(&response.dnses, "%s %s", dns1, dns2);
    RIL_onRequestComplete( t, RIL_E_SUCCESS, &response, sizeof( response ) );
    free(response.dnses);
    at_response_free( p_response );
    p_response = NULL;

    // add by dengxiangyu 2012-6-25 //
    // pdp is actived then set m_Used be true //
    s_PSCtl[pdpid - 1].m_Used = 1;
    // end add //

    return;

error2:

    // Deactive pdp //
    at_response_free( p_response );
    p_response = NULL;
    asprintf( &cmd, "AT+CGACT=0,%d", response.cid );
    // modify by CYIT 20120405 ----- start -----
    at_send_command_timeout(
        cmd, NO_RESULT, NULL, &p_response, CYIT_DEFAULT_AT_TIMEOUT_MSEC);
    free( cmd );

    if (err != 0 || p_response->success == 0) {
        if (AT_ERROR_TIMEOUT == err) {
            sendAbortCmd(CYIT_SAOC_TYPE_PDP_DEACTIVE);
        }
    }
    // modify by CYIT 20120405 -----  end  -----

error:
    RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
    at_response_free( p_response );
}

#endif

static void requestDeactivateDataCall( void * data, size_t datalen, RIL_Token t )
{
    int err = 0;
    char *cmd = NULL;
    char *pdpidstr = (( char ** )data )[0];
    char *pdpport = NULL;
    char *prop1 = NULL, *prop2 = NULL;
    char pid[10] = "";
    ATLine *p_cur = NULL;
    ATResponse *p_response = NULL;

#ifdef USE_PPP
    int ppp_num = 0;
    int retry_cnt = 10;
    char ppp_exit_code[PROPERTY_VALUE_MAX];
    char *pppd_pid = NULL;
    char *pppd_stop_args = NULL;
    char *pppd_exit = NULL;
#endif

    if (!pdpidstr) {
        LOGE("Pdp id is null.");
        goto error;
    }

    pdpport = getPdpPort(pdpidstr);

    // don't hava this PDP weird ??? //
    if (pdpport == NULL) {
        LOGE("no this PDP cann't deactivate");
        goto error;
    }

    // JAVA don't care about deactivate or not, set it unused //
    s_PSCtl[atoi(pdpidstr) - 1].m_Used = 0;

#ifdef USE_PPP

    // initialize ppp args //
    ppp_num = atoi(pdpidstr) - 1;
    asprintf(&pppd_pid, "net.ppp%d.pid", ppp_num);
    asprintf(&pppd_stop_args, "stop_pppd%d:%d", ppp_num, ppp_num);
    asprintf(&pppd_exit, "net.gprs.ppp%d-exit", ppp_num);

    property_get(pppd_pid, pid, "");
    if (!strcmp(pid, "")) {
        LOGE("pppd%d is inactive", ppp_num);
        goto error;
    }
    LOGD("pppd%d's pid is %s", ppp_num, pid);

    LOGD("stop pppd%d...", ppp_num);
    //property_set("ctl.start", pppd_stop_args);
    property_set("ril.gprs.start", "0");
    while (retry_cnt--) {
        LOGD("deactive retry_cnt:%d", retry_cnt);
        sleep(3);
        err = property_get(pppd_exit, ppp_exit_code, "");
        if (strcmp(ppp_exit_code, "")) {
            LOGD("deactive exit code:%s", ppp_exit_code);
            break;
        }
    }

    if (!strcmp(ppp_exit_code, "")) {
        LOGD("stop pppd failed");
        goto error;
    }

    free(pppd_pid);
    free(pppd_stop_args);
    free(pppd_exit);

#else

    err = ifc_disable(pdpport);
    if (err != 0) {
        LOGE("Set %s deactivate failed.", pdpport);
        goto error;
    }

#ifdef USE_RAWIP
    if (close(s_Ttys[atoi(pdpidstr) - 1].ttyFd) < 0) {
        LOGE("close %s failed, errno is %s", s_Ttys[atoi(pdpidstr) - 1].ttyPath, strerror(errno));
        goto error;
    }
#endif

    asprintf(&prop1, "net.%s.dns1", pdpport);
    asprintf(&prop2, "net.%s.dns2", pdpport);
    property_set(prop1, "0.0.0.0");
    property_set(prop2, "0.0.0.0");
    free(prop1);
    free(prop2);

    // modify by CYIT 20120405 ----- start -----
    asprintf( &cmd, "AT+CGACT=0,%s", pdpidstr );
    err = at_send_command_timeout( cmd, NO_RESULT, NULL, &p_response, 
        CYIT_DEFAULT_AT_TIMEOUT_MSEC);
    free( cmd );

    if ( err != 0 || p_response->success == 0 ) 
    {
        if (AT_ERROR_TIMEOUT == err) {
            sendAbortCmd(CYIT_SAOC_TYPE_PDP_DEACTIVE);
        }
        goto error;
    }
    // modify by CYIT 20120405 -----  end  -----

#endif

    RIL_onRequestComplete( t, RIL_E_SUCCESS, NULL, 0 );
    at_response_free( p_response );
    return;

error: 

#ifdef USE_PPP
    free(pppd_pid);
    free(pppd_stop_args);
    free(pppd_exit);
#endif

    RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
    at_response_free( p_response );
}

static void requestGetDataCallProfile(void *data, size_t datalen, RIL_Token t)
{
    //ATResponse *p_response = NULL;
    char *response = NULL;
    char *respPtr = NULL;
    int  responseLen = 0;
    int  numProfiles = 1; // hard coded to return only one profile
    int  i = 0;

    // TBD: AT command support

    int mallocSize = 0;
    mallocSize += (sizeof(RIL_DataCallProfileInfo));

    response = (char*)alloca(mallocSize + sizeof(int));
    respPtr = response;
    memcpy(respPtr, (char*)&numProfiles, sizeof(numProfiles));
    respPtr += sizeof(numProfiles);
    responseLen += sizeof(numProfiles);

    // Fill up 'numProfiles' dummy 'RIL_DataCallProfileInfo;
    for (i = 0; i < numProfiles; i++)
    {
        RIL_DataCallProfileInfo dummyProfile;

        // Adding arbitrary values for the dummy response
        dummyProfile.profileId = i+1;
        dummyProfile.priority = i+10;
        LOGI("profileId %d priority %d", dummyProfile.profileId, dummyProfile.priority);

        responseLen += sizeof(RIL_DataCallProfileInfo);
        memcpy(respPtr, (char*)&dummyProfile, sizeof(RIL_DataCallProfileInfo));
        respPtr += sizeof(RIL_DataCallProfileInfo);
    }

    LOGI("requestGetDataCallProfile():reponseLen:%d, %d profiles", responseLen, i);
    RIL_onRequestComplete(t, RIL_E_SUCCESS, response, responseLen);

    // at_response_free(p_response);
    return;
}

static void requestSMSAcknowledge(void *data, size_t datalen, RIL_Token t)
{
    int ackSuccess;
    int err;

    ackSuccess = ((int *)data)[0];

    if (ackSuccess == 1) {
        err = at_send_command_min_timeout("AT+CNMA=1", NULL);
    } else if (ackSuccess == 0)  {
        err = at_send_command_min_timeout("AT+CNMA=2", NULL);
    } else {
        LOGE("unsupported arg to RIL_REQUEST_SMS_ACKNOWLEDGE\n");
        goto error;
    }

    RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
    return;

error:
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);

}

// -----------------------------------------------------------------
// modify by CYIT 20110512 ----- start -----
// -----------------------------------------------------------------
static void requestGetCLIR( void *data , size_t datalen , RIL_Token t )
{
    ATResponse *p_response = NULL;
    int err;
    int response[2];
    char *line;

    err = at_send_command_timeout( "AT+CLIR?", SINGLELINE, "+CLIR:",
            &p_response, CYIT_AT_TIMEOUT_40_SEC );
    if ( err < 0 || p_response->success == 0 )
    {
        goto error;
    }

    line = p_response->p_intermediates->line;

    err = at_tok_start( &line );
    if ( err < 0 )
        goto error;

    err = at_tok_nextint( &line, &( response[0] ) );
    if ( err < 0 )
        goto error;

    err = at_tok_nextint( &line, &( response[1] ) );
    if ( err < 0 )
        goto error;

    RIL_onRequestComplete( t, RIL_E_SUCCESS, response, sizeof( response ) );

    at_response_free( p_response );
    return;

    error: LOGE("get CLIR error");
    RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
    at_response_free( p_response );
}

static void requestQueryCallWaiting( void *data , size_t datalen , RIL_Token t )
{
    ATResponse *p_response = NULL;
    int err;
    char *line = NULL;
    int countCallWaitingLine = 0x00;
    int *response = NULL;
    ATLine *p_cur;
    int i = 0x00;

    // modify by CYIT 20120405 ----- start -----
    err = at_send_command_timeout(
        "AT+CCWA=1,2", MULTILINE, "+CCWA:", &p_response, CYIT_AT_TIMEOUT_40_SEC);

    if ( err < 0 || p_response->success == 0 )
    {
        if(err == AT_ERROR_TIMEOUT)
        {
            sendAbortCmd(CYIT_SAOC_TYPE_SS);
        }
        goto error;
    }
    // modify by CYIT 20120405 -----  end  -----
    else
    {
        for ( p_cur = p_response->p_intermediates; p_cur != NULL; p_cur = p_cur->p_next )
        {
            countCallWaitingLine++;
        }
        response = ( int * )alloca(countCallWaitingLine * 2);
        memset( response, 0, countCallWaitingLine * 2 );

        for ( i = 0, p_cur = p_response->p_intermediates; p_cur != NULL; p_cur= p_cur->p_next, i+=2 )
        {
            line = p_cur->line;

            err = at_tok_start(&line);
            if (err < 0) goto error;

            err = at_tok_nextint( &line, &( response[i] ) );
            if ( err < 0 )
                goto error;

            if ( at_tok_hasmore( &line ) )
            {
              err = at_tok_nextint( &line, &( response[i + 1] ) );
              if ( err < 0 )
                  goto error;

              LOGD("query CW succses %d-status=%d, classx= %d", i, response[i], response[i + 1]);
            }
            else
            {
              response[i + 1] = 0x00;
              LOGD("query CW warning %d-status=%d, classx= %d", i, response[i], response[i + 1]);
            }
        }
        RIL_onRequestComplete( t, RIL_E_SUCCESS, response, countCallWaitingLine * sizeof(int) * 2 );

        at_response_free( p_response );
        return;

    }

    error: LOGE("query call waiting error");
    RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
    at_response_free( p_response );
}

static int CallForwardFromCCFC( char *line , RIL_CallForwardInfo *pcallforward )
{
    int err;
    err = at_tok_start( &line );
    if ( err < 0 )
        goto error;
    err = at_tok_nextint( &line, &pcallforward->status );
    if ( err < 0 )
        goto error;
    err = at_tok_nextint( &line, &pcallforward->serviceClass );
    if ( err < 0 )
        goto error;
    if ( at_tok_hasmore( &line ) )
    {
        err = at_tok_nextstr( &line, &pcallforward->number );
        if ( err < 0 )
            goto error;
        err = at_tok_nextint( &line, &pcallforward->toa );
        if ( err < 0 )
            goto error;
        LOGD("query call forward succses%d,%d,%d",pcallforward->status,pcallforward->serviceClass,pcallforward->toa);
    }
    if ( at_tok_hasmore( &line ) )
    {
        while ( *line == ',' )
        {
            line++;
        }
        err = at_tok_nextint( &line, &pcallforward->timeSeconds );
        if ( err < 0 )
            goto error;
        LOGD("query call forward succses%d,%d,%d,%d",pcallforward->status,pcallforward->serviceClass,pcallforward->toa,pcallforward->timeSeconds);
    }

    return 0;
    error: LOGE("invalid call forward");
    return -1;
}

static void requestQueryCallForwardStatus( void *data , size_t datalen ,
        RIL_Token t )
{

    ATResponse *p_response = NULL;
    int err;
    char *cmd = NULL;
    RIL_CallForwardInfo *p_args;
    RIL_CallForwardInfo *pcallforward;
    RIL_CallForwardInfo **p_pcallforward;
    ATLine *p_cur;
    int countcallforward = 0;

    p_args = ( RIL_CallForwardInfo * )data;

    asprintf( &cmd, "AT+CCFC=%d,%d", p_args->reason, p_args->status );

    err = at_send_command_timeout( cmd, MULTILINE, "+CCFC:", &p_response,
        CYIT_AT_TIMEOUT_40_SEC );
    free( cmd );
    if ( err < 0 || p_response->success == 0 )
    {
        goto error;
    }

    for ( p_cur = p_response->p_intermediates; p_cur != NULL; p_cur
            = p_cur->p_next )
    {
        countcallforward++;
    }
    p_pcallforward
            = ( RIL_CallForwardInfo ** )alloca(countcallforward * sizeof(RIL_CallForwardInfo *));
    pcallforward
            = ( RIL_CallForwardInfo * )alloca(countcallforward * sizeof(RIL_CallForwardInfo));
    memset( pcallforward, 0, countcallforward * sizeof(RIL_CallForwardInfo) );
    int i;
    /* init the pointer array */
    for ( i = 0; i < countcallforward; i++ )
    {
        p_pcallforward[i] = &( pcallforward[i] );
    }
    for ( i = 0, p_cur = p_response->p_intermediates; p_cur != NULL; p_cur
            = p_cur->p_next )
    {
        err = CallForwardFromCCFC( p_cur->line, pcallforward + i );
        if ( err != 0 )
        {
            continue;
        }
        pcallforward[i].reason = p_args->reason;
        i++;
    }
    RIL_onRequestComplete( t, RIL_E_SUCCESS, p_pcallforward, countcallforward
            * sizeof(RIL_CallForwardInfo *) );
    at_response_free( p_response );
    return;
    error: LOGE("Query call forward failed ");
    RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
    at_response_free( p_response );
}

static void requestSetCallForward( void *data , size_t datalen , RIL_Token t )
{
    ATResponse *p_response = NULL;
    int err;
    char *cmd = NULL;
    RIL_CallForwardInfo *p_args;
    int response[2];
    char *line;

    p_args = ( RIL_CallForwardInfo * )data;

    /* FIXME handle pin2 */

    if ( p_args->timeSeconds != 0 )
        asprintf( &cmd, "AT+CCFC=%d,%d,\"%s\",,%d,,,%d", p_args->reason,
                p_args->status, ( char* )p_args->number, p_args->serviceClass,
                p_args->timeSeconds );
    else
        asprintf( &cmd, "AT+CCFC=%d,%d,\"%s\",,%d", p_args->reason,
                p_args->status, ( char* )p_args->number, p_args->serviceClass );

    err = at_send_command_timeout( cmd, NO_RESULT, NULL, &p_response,
            CYIT_AT_TIMEOUT_40_SEC );
    free( cmd );
    if ( err < 0 || p_response->success == 0 )
    {
        at_response_free( p_response );
        RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
    }
    else
    {
        at_response_free( p_response );
        p_response = NULL;

        if( p_args->status == RIL_SSMODE_REGIS )
            asprintf( &cmd, "AT+CCFC=%d,1,,,%d", p_args->reason, p_args->serviceClass );  
        else if( p_args->status == RIL_SSMODE_DISABLE )
            asprintf( &cmd, "AT+CCFC=%d,4,,,%d", p_args->reason, p_args->serviceClass );  

        err = at_send_command_timeout( cmd, NO_RESULT, NULL, &p_response,
                CYIT_AT_TIMEOUT_40_SEC );
        free( cmd );

        if( err < 0 || p_response->success == 0 )
        {
            RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
        }
        else
        {
            RIL_onRequestComplete( t, RIL_E_SUCCESS, NULL, 0 );
        }
        at_response_free( p_response );
    }
}

static void requestQueryCallRestrictStatus( void *data , size_t datalen , RIL_Token t )
{

    ATResponse *p_response = NULL;
    int err;
    char* cmd = NULL;
    const char** strings = ( const char** )data;
    int countCallBarrLine = 0x00;
    int *response = NULL;
    char *line;
    ATLine *p_cur;

    // modify by CYIT 20120405 ----- start -----
    asprintf( &cmd, "AT+CLCK=\"%s\",2", strings[0] );
    err = at_send_command_timeout( cmd
        , MULTILINE, "+CLCK:", &p_response, CYIT_AT_TIMEOUT_40_SEC );
    free( cmd );

    if ( err < 0 || p_response->success == 0 )
    {
        if(err == AT_ERROR_TIMEOUT)
        {
            sendAbortCmd(CYIT_SAOC_TYPE_SS);
        }
        goto error;
    }
    // modify by CYIT 20120405 -----  end  -----
    else
    {
        for ( p_cur = p_response->p_intermediates; p_cur != NULL; p_cur = p_cur->p_next )
        {
            countCallBarrLine++;
        }

        response = ( int * )alloca(countCallBarrLine * 2);
        memset( response, 0, countCallBarrLine * 2 );

        int i = 0x00;
        for ( p_cur = p_response->p_intermediates; p_cur != NULL; p_cur = p_cur->p_next, i+=2 )
        {
            line = p_cur->line;

            LOGD("requestQueryCallRestrictStatus start");
            err = at_tok_start( &line );
            if ( err < 0 )
                goto error;

            err = at_tok_nextint( &line, &( response[i] ) );
            if ( err < 0 )
                goto error;
            LOGD("requestQueryCallRestrictStatus: status=%d", response[i]);

            if ( at_tok_hasmore( &line ) )
            {
              err = at_tok_nextint( &line, &( response[i + 1] ) );
              if ( err < 0 )
                  goto error;
              LOGD("requestQueryCallRestrictStatus: classx=%d", response[i + 1]);
            }
            else
            {
              response[i + 1] = 0x00;
              LOGD("query CB warning %d-status=%d, classx= %d", i, response[i], response[i + 1]);
            }
        }
        RIL_onRequestComplete( t, RIL_E_SUCCESS, response, countCallBarrLine * sizeof(int) * 2 );

        at_response_free( p_response );
        return;
    }

    error: LOGE("query call restrict status error");
    RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
    at_response_free( p_response );
}

static void requestSetCallRestrictStatus( void *data , size_t datalen ,
        RIL_Token t )
{
    ATResponse *p_response = NULL;
    int err;
    char *cmd = NULL;
    const char** strings = ( const char** )data;

    // modify by CYIT 20120405 ----- start -----
    asprintf( &cmd, "AT+CLCK=\"%s\",%s,\"%s\",%s", strings[0], strings[1],
            strings[2], strings[3] );
    err = at_send_command_timeout(cmd, NO_RESULT, NULL, &p_response, CYIT_AT_TIMEOUT_40_SEC);
    free( cmd );

    if ( err < 0 || p_response->success == 0 )
    {
        LOGE("set call restrict status error");
        if(err == AT_ERROR_TIMEOUT)
        {
            sendAbortCmd(CYIT_SAOC_TYPE_SS);
        }
        RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
    }
    // modify by CYIT 20120405 -----  end  -----
    else
    {
        LOGD("set call restrict status success");
        RIL_onRequestComplete( t, RIL_E_SUCCESS, NULL, 0 );
    }
    at_response_free( p_response );
}

static void requestChangeBarringPassward( void* data , size_t datalen ,
        RIL_Token t )
{
    ATResponse *p_response = NULL;
    int err;
    char* cmd = NULL;
    const char** strings = ( const char** )data;

    asprintf( &cmd, "AT+CPWD=\"%s\",\"%s\",\"%s\"", strings[0], strings[1], strings[2] );
    err = at_send_command_timeout(cmd, NO_RESULT, NULL, &p_response, CYIT_AT_TIMEOUT_10_SEC);
    free( cmd );

    if ( err < 0 || p_response->success == 0 )
    {
        RIL_onRequestComplete( t, RIL_E_PASSWORD_INCORRECT, NULL, 0 );
    }
    else
    {
        RIL_onRequestComplete( t, RIL_E_SUCCESS, NULL, 0 );
    }
    at_response_free( p_response );
}
// -----------------------------------------------------------------
// modify by CYIT 20110512 -----  end  -----
// -----------------------------------------------------------------

#ifndef USE_CYIT_FRAMEWORK

static void  requestSIM_IO(void *data, size_t datalen, RIL_Token t)
{
    ATResponse *p_response = NULL;
    RIL_SIM_IO_Response sr;
    int err;
    char *cmd = NULL;
    RIL_SIM_IO_v6 *p_args;
    char *line;

    memset(&sr, 0, sizeof(sr));

    p_args = (RIL_SIM_IO_v6 *)data;

    // FIXME handle pin2 //
    // FIXME handle aidPtr //

    if (p_args->data == NULL) {
        asprintf(&cmd, "AT+CRSM=%d,%d,%d,%d,%d",
                    p_args->command, p_args->fileid,
                    p_args->p1, p_args->p2, p_args->p3);
    } else {
        asprintf(&cmd, "AT+CRSM=%d,%d,%d,%d,%d,%s",
                    p_args->command, p_args->fileid,
                    p_args->p1, p_args->p2, p_args->p3, p_args->data);
    }

    err = at_send_command_singleline_timeout(cmd, "+CRSM:", &p_response, CYIT_AT_TIMEOUT_10_SEC);

    if (err < 0 || p_response->success == 0) {
        goto error;
    }

    line = p_response->p_intermediates->line;

    err = at_tok_start(&line);
    if (err < 0) goto error;

    err = at_tok_nextint(&line, &(sr.sw1));
    if (err < 0) goto error;

    err = at_tok_nextint(&line, &(sr.sw2));
    if (err < 0) goto error;

    if (at_tok_hasmore(&line)) {
        err = at_tok_nextstr(&line, &(sr.simResponse));
        if (err < 0) goto error;
    }

    RIL_onRequestComplete(t, RIL_E_SUCCESS, &sr, sizeof(sr));
    at_response_free(p_response);
    free(cmd);

    return;
error:
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
    at_response_free(p_response);
    free(cmd);

}

#else // USE_CYIT_FRAMEWORK //

static void requestSIM_IO( void *data , size_t datalen , RIL_Token t )
{
    ATResponse *p_response = NULL;
    RIL_SIM_IO_Response sr;
    int err;
    char *cmd = NULL;
    RIL_SIM_IO_v6 *p_args;
    char *line;
    int cmdtype = 0;

    memset(&sr, 0, sizeof(sr));
    p_args = (RIL_SIM_IO_v6 *)data;

    // FIXME handle pin2 //

    switch (p_args->command) {
    
        // Query sim file size //
        case 0xc0:
            cmdtype = 0;
            break;

        // Read sim binary file //
        case 0xb0:
            cmdtype = 1;
            break;

        // Read sim record file //
        case 0xb2:
            cmdtype = 2;
            break;
        default:
            LOGD("ICC IO command not supported");
            goto error2;
    }

    if (cmdtype == 0 || cmdtype == 1) {
        asprintf(&cmd, "AT^SSFA=%d,%d,\"%s\"", cmdtype, p_args->fileid, p_args->path);
    } else {
        asprintf(&cmd, "AT^SSFA=%d,%d,\"%s\",%d", cmdtype, p_args->fileid, p_args->path, p_args->p1);
    }

    err = at_send_command_singleline_timeout(cmd, "^SSFA:", &p_response, CYIT_AT_TIMEOUT_10_SEC);
    free( cmd );
    if (err < 0 || p_response->success == 0) goto error;
    line = p_response->p_intermediates->line;

    if (cmdtype == 0) {
        int skip = 0;

        err = at_tok_start( &line );
        if ( err < 0 ) goto error;

        err = at_tok_nextint( &line, &skip);
        if ( err < 0 ) goto error;

        err = at_tok_nextint( &line, &(sr.sw1));
        if ( err < 0 ) goto error;

        // Valid only in query sim record file //
        if (at_tok_hasmore(&line)) {
            err = at_tok_nextint( &line, &(sr.sw2));
            if ( err < 0 ) goto error; 
        }
        
    } else {
        err = at_tok_start(&line);
        if (err < 0) goto error;

        err = at_tok_nextstr(&line, &(sr.simResponse));
        if (err < 0) goto error;
    }

    LOGD("sw1=%d, sw2=%d, simresponse=%s", sr.sw1, sr.sw2, sr.simResponse);
    RIL_onRequestComplete( t, RIL_E_SUCCESS, &sr, sizeof( sr ) );
    at_response_free( p_response );

    return;

error: 
    RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
    at_response_free( p_response );
    return;

error2:
    RIL_onRequestComplete(t, RIL_E_REQUEST_NOT_SUPPORTED, NULL, 0);
    at_response_free(p_response);
}

#endif

static int parseCmeErrToRilErr(int BBErr)
{
    switch (BBErr) {
        case CME_OPERATION_NOT_ALLOWED: return RIL_E_REQUEST_NOT_SUPPORTED;
        case CME_INCORRECT_PWD: return RIL_E_PASSWORD_INCORRECT;
        case CME_SIM_PIN2_REQUIRED: return RIL_E_SIM_PIN2;
        case CME_SIM_PUK2_REQUIRED: return RIL_E_SIM_PUK2;
        case CME_NOTFOUND: return RIL_E_FDN_CHECK_FAILURE;
        default: return RIL_E_GENERIC_FAILURE;
    }
}

/**************************************************************************
  Modified by CYIT 20130319 ----- start -----
  Append interface for querying the remain count of sim PIN or PUK 
  to continue input
**************************************************************************/
static void requestGetSimPinPukRemainCount(void* data, size_t datalen, RIL_Token t) {
    ATResponse * p_response = NULL;
    int err;
    char* cmd, *line;
    int skip;
    char * skipstr;
    int residualcount = -1;
    int *queryType;

    if ( data )
    {
        queryType = ( int * )data;
    }
    else
    {
        goto error;
    }

    switch (queryType[0]) 
    {
    case 1:
        asprintf(&cmd, "AT^SPIC=\"SC\",0");
        break;

    case 2:
        asprintf(&cmd, "AT^SPIC=\"P2\",0");
        break;

    case 3:
        asprintf(&cmd, "AT^SPIC=\"SC\",1");
        break;

    default:
        LOGD("ZYS::::requestGetSimPinPukRemainCount, get invalid query type = %d", queryType[0]);
        goto error;
    }

    err = at_send_command_singleline_timeout(cmd, "^SPIC", &p_response, CYIT_AT_TIMEOUT_10_SEC);
    free(cmd);
    if (err < 0 || p_response->success == 0) {
        goto error;
    } else {
        line = p_response->p_intermediates->line;
        err = at_tok_start(&line);
        if (err < 0) goto error;
        err = at_tok_nextstr(&line, &skipstr);
        if (err < 0) goto error;
        err = at_tok_nextint(&line, &skip);
        if (err < 0) goto error;
        err = at_tok_nextint(&line, &residualcount);
        if (err < 0) {
            residualcount = -1;
            goto error;
        }
    }

    RIL_onRequestComplete( t, RIL_E_SUCCESS, &residualcount, sizeof( residualcount ) );
    at_response_free( p_response );
    return;

error:
    RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
    at_response_free( p_response );
}
/**************************************************************************
  Modified by CYIT 20130304 ----- end -----
**************************************************************************/

// PinType 0: pin; 1: puk //
static int requestPinResidualCount(char * Fac, int PinType)
{
    ATResponse * p_response = NULL;
    int err, ret = RIL_E_GENERIC_FAILURE;
    char* cmd, *line;
    int skip;
    char * skipstr;
    int residualcount = -1;

    if (strncmp(Fac, "FD", 2) == 0) {
        asprintf(&cmd, "AT^SPIC=\"P2\",%d", PinType);
    } else {
        asprintf(&cmd, "AT^SPIC=\"%s\",%d", Fac, PinType);
    }

    err = at_send_command_singleline_timeout(cmd, "^SPIC", &p_response, CYIT_AT_TIMEOUT_10_SEC);
    free(cmd);
    if (err < 0 || p_response->success == 0) {
        goto error;
    } else {
        line = p_response->p_intermediates->line;
        err = at_tok_start(&line);
        if (err < 0) goto error;
        err = at_tok_nextstr(&line, &skipstr);
        if (err < 0) goto error;
        err = at_tok_nextint(&line, &skip);
        if (err < 0) goto error;
        err = at_tok_nextint(&line, &residualcount);
        if (err < 0) {
            residualcount = -1;
            goto error;
        }
    }

    // notify SIM status only when PIN1 locked or PUK1 locked //
    if (strncmp(Fac, "SC", 2) == 0 && residualcount == 0) {
        //RIL_onUnsolicitedResponse(RIL_UNSOL_RESPONSE_SIM_STATUS_CHANGED, NULL, 0);
        // Modified by CYIT 20130130 for change SIM state by interface setRadioState while PIN setting
        setRadioState(RADIO_STATE_SIM_LOCKED_OR_ABSENT);
        v_cardState = 0;
    }

error:

    at_response_free(p_response);
    return residualcount;
}

static void  requestEnterSimPin(void*  data, size_t  datalen, RIL_Token  t, char * Fac)
{
    ATResponse   *p_response = NULL;
    int           err, ret = RIL_E_GENERIC_FAILURE;
    char*         cmd = NULL;
    const char**  strings = (const char**)data;
    int residualcount, pintype;

    if ( datalen == 2 * sizeof(char*) ) {
        pintype = 0; // pin //
        asprintf(&cmd, "AT+CPIN=\"%s\"", strings[0]);
    } else if (datalen == 3 * sizeof(char*)) {
        pintype = 1; // puk //
        //asprintf(&cmd, "AT+CPIN=\"%s\",\"%s\"", strings[0], strings[1]);
        asprintf(&cmd, "AT^SEPIN=\"%s\",\"%s\",\"%s\"", Fac, strings[0], strings[1]);
    } else { // wrong datalen //
        RIL_onRequestComplete(t, ret, NULL, 0);
        at_response_free(p_response);
        return;
    }

    err = at_send_command_timeout(cmd, NO_RESULT, NULL, &p_response, CYIT_AT_TIMEOUT_10_SEC);
    free(cmd);
    if (err < 0 || p_response->success == 0) {
        /*
        ret = at_get_cme_error(p_response);
        LOGD("BB error is %d", ret);
        ret = parseCmeErrToRilErr(ret);
        */
        ret = RIL_E_PASSWORD_INCORRECT;
        at_response_free(p_response);
        residualcount = requestPinResidualCount(Fac, pintype);
        if (residualcount >= 0) {
            RIL_onRequestComplete(t, ret, &residualcount, sizeof(residualcount));
        } else { // something wrong. not return wrong times of pin validation //
            RIL_onRequestComplete(t, ret, NULL, 0);
        }
    } else {
        ret = RIL_E_SUCCESS;
        RIL_onRequestComplete(t, ret, NULL, 0);
        at_response_free(p_response);
        RIL_onUnsolicitedResponse(RIL_UNSOL_RESPONSE_SIM_STATUS_CHANGED, NULL, 0);
    }
}

static void  requestChangeSimPin(void*  data, size_t  datalen, RIL_Token  t, char* Fac)
{
    ATResponse * p_response = NULL;
    int err, ret = RIL_E_GENERIC_FAILURE;
    char* cmd = NULL;
    const char ** strings = (const char**)data;
    int residualcount;

    // Modified by CYIT 20130227 for modified PIN
    if ( datalen == 3 * sizeof(char*)) {
        asprintf(&cmd, "AT+CPWD=\"%s\",\"%s\",\"%s\"", Fac, strings[0], strings[1]);
    } else goto error;

    err = at_send_command_timeout(cmd, NO_RESULT, NULL, &p_response, CYIT_AT_TIMEOUT_10_SEC);
    free(cmd);
    if (err < 0 || p_response->success == 0) {
        /*
        ret = at_get_cme_error(p_response);
        LOGD("BB error is %d", ret);
        ret = parseCmeErrToRilErr(ret);
        */
        ret = RIL_E_PASSWORD_INCORRECT;
    } else {
        ret = RIL_E_SUCCESS;
    }

    if (ret == RIL_E_PASSWORD_INCORRECT) {
        at_response_free(p_response);
        residualcount = requestPinResidualCount(Fac, 0);
        if (residualcount >= 0) {
            RIL_onRequestComplete(t, ret, &residualcount, sizeof(residualcount));
        } else {
            RIL_onRequestComplete(t, ret, NULL, 0);
        }

        return;
    }
    
error:

    LOGD("RIL error is %d", ret);
    RIL_onRequestComplete(t, ret, NULL, 0);
    at_response_free(p_response);
}

// -------------------------------------------------------------
//   modify by CYIT 20110819             ----- start -----
// -------------------------------------------------------------
static void  requestSendUSSD(void *data, size_t datalen, RIL_Token t)
{
    int err;
    char *cmd = NULL;
    char *ussdstring = NULL;
    signed char dcs = 0;
    T_USSD_INFO *p_ussdinfo = NULL;
    ATResponse *p_response = NULL;

    if ( data && datalen == sizeof(T_USSD_INFO) )
    {
        p_ussdinfo = (T_USSD_INFO *)data;
    }
    else
    {
        LOGE("requestSendUSSD invalid data length %d or data is NULL", (int)datalen);
        goto error_CUSD;
    }

    asprintf(&ussdstring, "%s", p_ussdinfo->m_ussdstring);
    dcs = p_ussdinfo->m_dcs;

    if ( dcs == -1 )
    {
        // Normal USSD string //
        asprintf(&cmd, "AT+CUSD=1,\"%s\"", ussdstring);
    }
    else
    {
        // USSD string from USAT //
        asprintf( &cmd, "AT+CUSD=1,\"%s\",%d", ussdstring, dcs );
    }

    // modify by CYIT 20120405 ----- start -----
    err = at_send_command_timeout(cmd, NO_RESULT, NULL, &p_response, CYIT_AT_TIMEOUT_70_SEC);
    free(cmd);
    free(ussdstring);

    if ( err < 0 || p_response->success == 0 ) 
    {
        LOGE( "send USSD ERROR" );
        if(err == AT_ERROR_TIMEOUT)
        {
            at_send_command("AT+CUSD=2", NULL);
        }
    // modify by CYIT 20120405 -----  end  -----
        goto error_CUSD;
    }
    else
    {
        LOGD( "send USSD SUCCESS " );
        // Normal USSD string //
        RIL_onRequestComplete( t, RIL_E_SUCCESS, NULL, 0 );
        at_response_free( p_response );
        return;
    }

error_CUSD:
    RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
    if(p_response != NULL) at_response_free(p_response);
}
// -------------------------------------------------------------
//   modify by CYIT 20110819            -----  end  -----
// -------------------------------------------------------------

static void requestExitEmergencyMode(void *data, size_t datalen, RIL_Token t)
{
    int err;
    ATResponse *p_response = NULL;

    err = at_send_command("AT+WSOS=0", &p_response);

    if (err < 0 || p_response->success == 0) {
        RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
        at_response_free(p_response);
        return;
    }

    RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
    at_response_free(p_response);
}

static void requestSetScreenState(void * data, size_t datalen, RIL_Token t)
{
    int err = 0;
    int state = 0;
    ATResponse * p_response = NULL;
    ATLine *p_cur;

    state = ( ( int * )data )[0];

    // Screen on //
    if ( state )
    {
        err = at_send_command_min_timeout( "AT+CREG=2", &p_response );
        if ( err < 0 || p_response->success == 0 )
        {
            LOGE( "At command \"AT+CREG=2\" return error.\n" );
            //goto error;
        }

        err = at_send_command_min_timeout( "AT+CGREG=2", &p_response );
        if ( err < 0 || p_response->success == 0 )
        {
            LOGE( "At command \"AT+CGREG=2\" return error.\n" );
            //goto error;
        }

        if(v_airmodeOper != RADIO_ACTION_AIRMODE_ON){
            // modify by CYIT ----- start -----
            RIL_onUnsolicitedResponse(RIL_UNSOL_RESPONSE_VOICE_NETWORK_STATE_CHANGED, NULL, 0);
            RIL_onUnsolicitedResponse(RIL_UNSOL_RESPONSE_CALL_STATE_CHANGED, NULL, 0);
            //RIL_onUnsolicitedResponse(RIL_UNSOL_RESPONSE_DATA_NETWORK_STATE_CHANGED, NULL, 0);
            // modify by CYIT -----  end  -----
        }
    }

    // Screen off //
    else
    {
        err = at_send_command_min_timeout( "AT+CREG=0", &p_response );
        if ( err < 0 || p_response->success == 0 )
        {
            LOGE( "At command \"AT+CREG=0\" return error.\n" );
            //goto error;
        }

        err = at_send_command_min_timeout( "AT+CGREG=0", &p_response );
        if ( err < 0 || p_response->success == 0 )
        {
            LOGE( "At command \"AT+CGREG=0\" return error.\n" );
            //goto error;
        }
    }

    RIL_onRequestComplete( t, RIL_E_SUCCESS, NULL, 0 );
    at_response_free( p_response );

    return;

error:

    RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
    at_response_free( p_response );
}

static void requestQueryNetworks(void *data, size_t datalen, RIL_Token t)
{
    int err;
    ATResponse * p_response = NULL;

    err = at_send_command_timeout("AT+COPS=?", SINGLELINE, "+COPS:",
            &p_response, CYIT_OPER_AT_TIMEOUT_MSEC);
    if (err < 0 || p_response->success == 0) {
        if (AT_ERROR_TIMEOUT == err) {
            sendAbortCmd(CYIT_SAOC_TYPE_NET); // modify by CYIT 20120405
        }
        goto error;
    } else {
        char *line, *p;
        int i = 0, n = 0;

        line = p_response->p_intermediates->line;
        err = at_tok_start(&line);
        if (err < 0) goto error;

        for (p = line; *p != '\0'; p++) {
            if (*p == '(') n++;
        }

        if (n <= 2) goto error;
        else {
            int state = 0, act = 0;
            char *response[4 * (n - 2)];

            for (i = 0; i < (n - 2); i++) {
                // Skip "(" in the begin //
                line += 2;

                // State //
                err = at_tok_nextint(&line, &state);
                if (err < 0) goto error;

                // Long Name //
                err = at_tok_nextstr(&line, &response[4 * i + 0]);
                if (err < 0) goto error;

                // Short Name //
                err = at_tok_nextstr(&line, &response[4 * i + 1]);
                if (err < 0) goto error;

                // Number Name //
                err = at_tok_nextstr(&line, &response[4 * i + 2]);
                if (err < 0) goto error;

                if (0 == state) asprintf(&response[4 * i + 3], "%s", "unknown");
                else if (1 == state) asprintf(&response[4 * i + 3], "%s", "available");
                else if (2 == state) asprintf(&response[4 * i + 3], "%s", "current");
                else if (3 == state) asprintf(&response[4 * i + 3], "%s", "forbidden");
                else
                {
                    for ( ; i >= 0; i--) {
                        free(response[4 * i + 3]);
                    }
                    goto error;
                }

                // Skip technology in the end //
                line = strstr(line, ")");
                line++;
            }

            RIL_onRequestComplete(t, RIL_E_SUCCESS, response, sizeof(char *) * 4 * (n - 2));
            for (i = 0; i < (n - 2); i++) {
                free(response[4 * i + 3]);
            }
            at_response_free(p_response);
        }
    }

    return;

error:

    at_response_free( p_response );
    RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
}

/**************************************************************************
  Modified by CYIT 20130304 ----- start -----
  Append interface for querying available networks
  together with access technology
**************************************************************************/
static void requestQueryNetworksWithType(void *data, size_t datalen, RIL_Token t)
{
    int          err;
    ATResponse * p_response = NULL;
    int          v_time = 0x00;
    int          v_pollTime = 12;

    while(1){
        err = at_send_command_timeout("AT+COPS=?", SINGLELINE, "+COPS:",
                &p_response, CYIT_AT_TIMEOUT_70_SEC);
        if (err < 0 || p_response->success == 0){
            if (AT_ERROR_TIMEOUT == err) 
            {
                sendAbortCmd(CYIT_SAOC_TYPE_NET);
            }else if(p_response
                    && (strStartsWith(p_response->finalResponse, "+CME ERROR: 201"))){
                if(v_time++ != v_pollTime){
                    sleep(5);
                    continue;
                }
            }
            goto error;
        }else{
            break;
        }
    }

    {
        char *line, *p;
        int i = 0, n = 0;

        line = p_response->p_intermediates->line;
        err = at_tok_start(&line);
        if (err < 0) goto error;

        for (p = line; *p != '\0'; p++) 
        {
            if (*p == '(') n++;
        }

        if (n <= 2) goto error;
        else 
        {
            int state = 0, act = 0;
            char *response[5 * (n - 2)];

            for (i = 0; i < (n - 2); i++) 
            {
                // Skip "(" in the begin //
                if (i == 0) 
                {
                    line ++;
                }
                line++;

                // State //
                err = at_tok_nextint(&line, &state);
                if (err < 0) goto error;

                // Long Name //
                err = at_tok_nextstr(&line, &response[5 * i + 0]);
                if (err < 0) goto error;

                // Short Name //
                err = at_tok_nextstr(&line, &response[5 * i + 1]);
                if (err < 0) goto error;

                // Number Name //
                err = at_tok_nextstr(&line, &response[5 * i + 2]);
                if (err < 0) goto error;

                if (0 == state) asprintf(&response[5 * i + 3], "%s", "unknown");
                else if (1 == state) asprintf(&response[5 * i + 3], "%s", "available");
                else if (2 == state) asprintf(&response[5 * i + 3], "%s", "current");
                else if (3 == state) asprintf(&response[5 * i + 3], "%s", "forbidden");
                else
                {
                    for ( ; i >= 0; i--) 
                    {
                        free(response[5 * i + 3]);
                    }
                    goto error;
                }

                if ( at_tok_hasmore( &line ) )
                {
                    err = at_tok_nextint( &line, &act ); // access technology
                    if(err < 0) goto error;

                    if (0 == act) asprintf(&response[5 * i + 4], "%s", "0");
                    else if (1 == act) asprintf(&response[5 * i + 4], "%s", "1");
                    else if (2 == act) asprintf(&response[5 * i + 4], "%s", "2");
                    else if (3 == act) asprintf(&response[5 * i + 4], "%s", "3");
                    else if (4 == act) asprintf(&response[5 * i + 4], "%s", "4");
                    else if (5 == act) asprintf(&response[5 * i + 4], "%s", "5");
                    else if (6 == act) asprintf(&response[5 * i + 4], "%s", "6");
                    else if (7 == act) asprintf(&response[5 * i + 4], "%s", "7");
                    else
                    {
                        for ( ; i >= 0; i--) 
                        {
                            free(response[5 * i + 4]);
                        }
                        goto error;
                    }
                }
                else
                {
                    asprintf(&response[5 * i + 4], "%s", "FF");
                }

            }

            // printf response
            int j = 0;
            for (j = 0; j < (n - 2); j++) 
            {
                for (i = 0; i < 5; i++) 
                {
                    LOGD("[requestQueryNetworksWithType] response[%d] = %s", (5 * j + i), response[5 * j + i]);
                }
            }

            RIL_onRequestComplete(t, RIL_E_SUCCESS, response, sizeof(char *) * 5 * (n - 2));
            for (i = 0; i < (n - 2); i++) {
                free(response[5 * i + 3]);
            }
            at_response_free(p_response);
        }
    }

    return;

error:

    at_response_free( p_response );
    RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
}
    /**************************************************************************
      Modified by CYIT 20130304 ----- end -----
    **************************************************************************/

static int techFamilyFromModemType(int mdmtype)
{
    int ret = -1;

    if (mdmtype < 0) return RADIO_TECH_NONE;
    switch (1 << mdmtype) {
        case MDM_CDMA:
        case MDM_EVDO:
            ret = RADIO_TECH_3GPP2;
            break;
        case MDM_GSM:
        //case MDM_WCDMA:
        case MDM_TD:
        case MDM_LTE:
            ret = RADIO_TECH_3GPP;
            break;
    }
    return ret;
}

// TODO: Use all radio types
static int techFromModemType(int mdmtype)
{
    int ret = -1;
    switch (1 << mdmtype) {
        case MDM_CDMA:
            ret = RADIO_TECH_1xRTT;
            break;
        case MDM_EVDO:
            ret = RADIO_TECH_EVDO_A;
            break;
        case MDM_GSM:
            ret = RADIO_TECH_GPRS;
            break;
        //case MDM_WCDMA:
        case MDM_TD:
            ret = RADIO_TECH_HSPA;
            break;
        case MDM_LTE:
            ret = RADIO_TECH_LTE;
            break;
    }
    return ret;
}

static void requestSelectPBEF(void * data, size_t datalen, RIL_Token t)
{
    ATResponse *p_response = NULL;
    int err;
    char * cmd = NULL;
    char * fileid = NULL;
    char * pin2 = NULL;

    if (datalen == 2 * sizeof(char *)) {
        fileid = ((char **)data)[0];
        pin2 = ((char **)data)[1];
    } else {
        RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
        return;
    }

    if (strcmp(fileid, "SM") == 0) {
        asprintf(&cmd, "AT+CPBS=\"SM\"");
    } else if (strcmp(fileid, "FD") == 0 
            || strcmp(fileid, "SD") == 0) {
        asprintf(&cmd, "AT+CPBS=\"%s\",\"%s\"", fileid, pin2);
    } else {
        RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
        return;
    }

    err = at_send_command_min_timeout(cmd, &p_response);
    free(cmd);

    if (err != 0 || p_response->success == 0) {
        RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
    } else {
        RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
    }
    at_response_free(p_response);
}

static void requestWritePBRecord(void * data, size_t datalen, RIL_Token t)
{
    ATResponse *p_response = NULL;
    int err;
    char * cmd = NULL;
    char * tempstr = NULL;
    int index = 0;
    char * phonenum = NULL;
    char * phonetext = NULL;
    int encoding = 0;

    if (datalen == 4 * sizeof(char *)) {
        tempstr = ((char **)data)[0];
        phonenum = ((char **)data)[1];
        phonetext = ((char **)data)[2];
        encoding = atoi((((char **)data)[3]));
    } else {
        RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
        return;
    }

    index = atoi(tempstr);
    //if (encoding == 0) { // UTF8 //
    //    at_send_command("AT+CSCS=\"IRA\"", NULL);
    //} else { // UTF16 //
    //    at_send_command("AT+CSCS=\"UCS2\"", NULL);
    //}
    asprintf(&cmd, "AT+CPBW=%d,\"%s\",%d,\"%s\"", 
            index, phonenum, 0x81, phonetext);
    err = at_send_command_timeout(cmd, NO_RESULT, NULL, &p_response, CYIT_AT_TIMEOUT_10_SEC);
    free(cmd);

    if (err != 0 || p_response->success == 0) {
        RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
    } else {
        RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
    }
    at_response_free(p_response);

    //if (encoding == 0) {
    //    at_send_command("AT+CSCS=\"UCS2\"", NULL);
    //}
}


// modify by CYIT 20111026 ----- start -----
static void requestWritePbRecordUserDefined(void * data, size_t datalen, RIL_Token t)
{
    ATResponse *p_response = NULL;
    int         err;
    char       *cmd = NULL;

    int         bitmap = 0x0000;
    int         index = 0x0000;
    int         i = 0x01;
    char       *tempStr = NULL;
    int         tempType = 0xFF;
    int         offset = 0x00;
    char       *parameterTemp = NULL;

    // bitmap point to the parameter whether exsit
    bitmap = atoi(((char **)data)[offset++]);
    // EFadn record id
    index = atoi(((char **)data)[offset++]);
    // delete the phonebook record
    if(bitmap == 0x00)
    {
        asprintf(&cmd, "AT^SCPBW=%d", index);
    }
    else
    {
        cmd = malloc(1024 * sizeof(char));
        memset(cmd, 0x00, 1024);

        while(bitmap && i <= 0x20)
        {
            // bit8   bit7   bit6   bit5   bit4   bit3   bit2   bit1
            // rfu    rfu    email  alpha  anr3   anr2   anr1   number
            if(bitmap & i)
            {
                tempStr = ((char **)data)[offset++];
                if(tempStr == NULL)
                {
                    tempStr = "\"\"";
                }
                else
                {
                    // Para-email not have encode type
                    if(i != 0x20) // not email
                    {
                        tempType = atoi(((char **)data)[offset]);
                    }
                    offset++;
                }
            }
            else
            {
                offset += 2;
            }
            // remove the already checked parameter
            bitmap &= ~i;

            switch(i)
            {
                case 0x01: // phone number
                    asprintf(&parameterTemp, "AT^SCPBW=%d", index);
                    memcpy(cmd, parameterTemp, strlen(parameterTemp));
                    free(parameterTemp);
                    parameterTemp = NULL;
                case 0x02: // anr1
                case 0x04: // anr2
                case 0x08: // anr3
                case 0x10: // alpha
                case 0x20: // email
                    if(tempStr != NULL)
                    {
                        if(tempType != 0xFF)
                        {
                            if(i == 0x10 && tempType == 0x01)
                            {
                                asprintf(&parameterTemp, ",\"80%s\",%d", tempStr, tempType);
                            }
                            else
                            {
                                asprintf(&parameterTemp, ",\"%s\",%d", tempStr, tempType);
                            }
                        }
                        else
                        {
                            if(bitmap)
                            {
                                asprintf(&parameterTemp, ",\"%s\",", tempStr);
                            }
                            else
                            {
                                asprintf(&parameterTemp, ",\"%s\"", tempStr);
                            }
                        }
                    }
                    else
                    {
                        if(bitmap)
                        {
                            asprintf(&parameterTemp, ",,");
                        }
                    }
                    break;

                default:
                    LOGD("requestWritePbRecordUserDefined bitmap error = %d", i);
                    break;
            }

            if(parameterTemp != NULL)
            {
                memcpy(cmd + strlen(cmd), parameterTemp, strlen(parameterTemp));
                free(parameterTemp);
                parameterTemp = NULL;
            }
            // point to the next parameter
            i *= 2;
            tempStr = NULL;
            tempType = 0xFF;

            LOGD("requestWritePbRecordUserDefined cmd1 = %s", cmd);
        }

        LOGD("requestWritePbRecordUserDefined cmd = %s", cmd);
    }

    err = at_send_command_min_timeout("AT+CPBS=\"SM\"", &p_response);
    if (err != 0 || p_response->success == 0)
    {
        goto write_error;
    }
    else
    {
        at_response_free(p_response);
        p_response = NULL;

        err = at_send_command_timeout(cmd, NO_RESULT, NULL, &p_response, CYIT_AT_TIMEOUT_10_SEC);
        free(cmd);
        if (err != 0 || p_response->success == 0)
        {
            RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
        }
        else
        {
            RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
        }
        at_response_free(p_response);

        return;
    }

write_error:
    LOGD("requestWritePbRecordUserDefined write_error");
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
    at_response_free(p_response);
    free(cmd);
}

static void requestPbRecordSize(void * data, size_t datalen, RIL_Token t)
{
    int         err;
    ATResponse *p_response = NULL;
    char       *skip = NULL;
    char       *line;
    int        *response = NULL;

    // modify by CYIT 20111230 ----- start -----
    response = (int *)alloca(sizeof(int) * 2);
    memset(response, 0, sizeof(int) * 2);

    err = at_send_command_min_timeout("AT+CPBS=\"SM\"", &p_response);
    if (err < 0 || p_response->success == 0)
    {
        LOGE("requestPbRecordSize, baseband not ready");
        goto request_error;
    }
    else
    {
        at_response_free(p_response);
        p_response = NULL;

        err = at_send_command_singleline_min_timeout("AT+CPBS?", "+CPBS:", &p_response);
        if (err < 0 || p_response->success == 0) {
            goto request_error;
        }

        line = p_response->p_intermediates->line;
        err = at_tok_start(&line);
        if (err < 0) goto request_error;

        err = at_tok_nextstr(&line, &skip);
        if (err < 0) goto request_error;

        if (at_tok_hasmore(&line)) {
            err = at_tok_nextint(&line, &(response[0]));// useNum
            if (err < 0) goto request_error;
            err = at_tok_nextint(&line, &(response[1]));// totalNum
            if (err < 0) goto request_error;

            RIL_onRequestComplete(t, RIL_E_SUCCESS, response, sizeof(int) * 2);
            at_response_free(p_response);
            return;
        }
    }

request_error:
    RIL_onRequestComplete(t, RIL_E_SUCCESS, response, sizeof(int) * 2);
    at_response_free( p_response );
    // modify by CYIT 20111230 -----  end  -----
}

static void requestReadPbRecordUserDefined(void * data, size_t datalen, RIL_Token t)
{
    int                        err;
    ATResponse                *p_response = NULL;
    int                        recNum = 0x00;
    RIL_Read_PB_Record         response;
    char                      *cmd = NULL;
    char                      *line;
    // bitmap point to the parameter whether exsit
    recNum = ((int *)data)[0];

    asprintf(&cmd, "AT^SCPBR=%d", recNum);
    err = at_send_command_singleline_timeout(cmd, "^SCPBR:", &p_response, CYIT_AT_TIMEOUT_10_SEC);
    if (err < 0 || p_response->success == 0) {
        goto request_error;
    }

    line = p_response->p_intermediates->line;
    err = at_tok_start(&line);
    if (err < 0) goto request_error;

    memset(&response, 0, sizeof(response));

    err = at_tok_nextint(&line, &(response.index));// index
    if (err < 0) goto request_error;

    err = at_tok_nextstr(&line, &(response.number)); // number
    if (err < 0) goto request_error;

    err = at_tok_nextint(&line, &(response.numType));
    if (err < 0) goto request_error;

    err = at_tok_nextstr(&line, &(response.anr1));// anr1
    if (err < 0) goto request_error;

    err = at_tok_nextint(&line, &(response.anr1Type));
    if (err < 0) goto request_error;

    err = at_tok_nextstr(&line, &(response.anr2));// anr2
    if (err < 0) goto request_error;

    err = at_tok_nextint(&line, &(response.anr2Type));
    if (err < 0) goto request_error;

    err = at_tok_nextstr(&line, &(response.anr3));// anr3
    if (err < 0) goto request_error;

    err = at_tok_nextint(&line, &(response.anr3Type));
    if (err < 0) goto request_error;

    err = at_tok_nextstr(&line, &(response.alpha));// alpha
    if (err < 0) goto request_error;

    err = at_tok_nextint(&line, &(response.coding));
    if (err < 0) goto request_error;

    if (at_tok_hasmore(&line))
    {
        err = at_tok_nextstr(&line, &(response.email));// email
        if (err < 0) goto request_error;

        if(!strlen(response.email))
        {
            response.email = NULL;
        }
    }
    else
    {
        response.email = NULL;
    }

    RIL_onRequestComplete(t, RIL_E_SUCCESS, &response, sizeof(response));
    at_response_free(p_response);
    free( cmd );
    return;

request_error:
    RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
    at_response_free( p_response );
    free( cmd );
}
// modify by CYIT 20111026 -----  end  -----


// modify by CYIT 20120229 for ----- start -----
static void requestPbContentLength(void * data, size_t datalen, RIL_Token t)
{
    int         err;
    ATResponse *p_response = NULL;
    char       *skip = NULL;
    char       *line, *p;
    int        *response = NULL;

    response = (int *)alloca(sizeof(int) * 3);
    memset(response, 0, sizeof(int) * 3);

    err = at_send_command_min_timeout("AT+CPBS=\"SM\"", &p_response);
    if (err < 0 || p_response->success == 0)
    {
        LOGE("requestPbContentLength, baseband not ready");
        goto req_len_error;
    }
    else
    {
        at_response_free(p_response);
        p_response = NULL;

        err = at_send_command_singleline_timeout(
                "AT^SCPBW=?", "^SCPBW:", &p_response, CYIT_AT_TIMEOUT_10_SEC);
        if (err < 0 || p_response->success == 0) {
            goto req_len_error;
        }

        line = p_response->p_intermediates->line;
        err = at_tok_start(&line);
        if (err < 0) goto req_len_error;

        // Skip Indexs
        line = strstr(line, ")");
        line+=2;

        // get number length
        err = at_tok_nextint(&line, &(response[0]));
        if (err < 0) goto req_len_error;

        // Skip Types
        line = strstr(line, ")");
        line+=2;

        // get alpha length
        err = at_tok_nextint(&line, &(response[1]));
        if (err < 0) goto req_len_error;

        // get email length
        err = at_tok_nextint(&line, &(response[2]));
        if (err < 0) goto req_len_error;

        RIL_onRequestComplete(t, RIL_E_SUCCESS, response, sizeof(int) * 3);
        at_response_free(p_response);
        return;
    }

req_len_error:
    RIL_onRequestComplete(t, RIL_E_SUCCESS, response, sizeof(int) * 3);
    at_response_free( p_response );
}
// modify by CYIT 20120229 -----  end  -----

static void  requestQueryFacilityLock(void*  data, size_t  datalen, RIL_Token  t)
{
    ATResponse * p_response = NULL;
    char* cmd, *line;
    const char ** strings = (const char**)data;
    int serviceclass, lockstate;
    int err, ret = RIL_E_GENERIC_FAILURE;
    int residualcount;

    if (datalen == 4 * sizeof(char*)) {
        serviceclass = atoi(strings[2]);
    } else goto error;

    if (strncmp("FD", strings[0], 2) == 0) {
        err = at_send_command_singleline_min_timeout("AT+CPBS=?", "+CPBS:", &p_response);
        if (err < 0 || p_response->success == 0) {
            goto error;
        } else {
            line = p_response->p_intermediates->line;
            err = at_tok_start(&line);
            if (err < 0) goto error;
            if (strstr(line, "FD") == NULL) {
                lockstate = 2; // 0: not active; 1: active; 2: disable no FDN //
                RIL_onRequestComplete(t, RIL_E_SUCCESS, &lockstate, sizeof(lockstate));
                at_response_free(p_response);

                return;
            }
        }

        at_response_free(p_response);
        p_response = NULL;
    }

    // modify by CYIT 20120405 ----- start -----
    asprintf(&cmd, "AT+CLCK=\"%s\",2,\"%s\",%d", 
                strings[0], strings[1], serviceclass);
    err = at_send_command_timeout(cmd, SINGLELINE, "+CLCK:", &p_response, CYIT_AT_TIMEOUT_40_SEC);
    free(cmd);

    if (err < 0 || p_response->success == 0) {
        if(err == AT_ERROR_TIMEOUT
            && (!strncmp("AO", strings[0], 2) || !strncmp("OI", strings[0], 2)
            || !strncmp("OX", strings[0], 2) || !strncmp("AI", strings[0], 2)
            || !strncmp("IR", strings[0], 2) || !strncmp("AB", strings[0], 2)
            || !strncmp("AG", strings[0], 2) || !strncmp("AC", strings[0], 2)))
        {
            sendAbortCmd(CYIT_SAOC_TYPE_SS);
        }
    // modify by CYIT 20120405 -----  end  -----
        /*
        ret = at_get_cme_error(p_response);
        LOGD("BB error is %d", ret);
        ret = parseCmeErrToRilErr(ret);
        */
        ret = RIL_E_PASSWORD_INCORRECT;
    } else {
        line = p_response->p_intermediates->line;
        err = at_tok_start(&line);
        if (err < 0) goto error;
        err = at_tok_nextint(&line, &lockstate);
        if (err < 0) goto error;

        RIL_onRequestComplete(t, RIL_E_SUCCESS, &lockstate, sizeof(lockstate));
        at_response_free(p_response);

        return;
    }

    if (ret == RIL_E_PASSWORD_INCORRECT) {
        at_response_free(p_response);
        residualcount = requestPinResidualCount(strings[0], 0);
        if (residualcount >= 0) {
            RIL_onRequestComplete(t, ret, &residualcount, sizeof(residualcount));
        } else {
            RIL_onRequestComplete(t, ret, NULL, 0);
        }
        
        return;
    }
    
error:

    RIL_onRequestComplete(t, ret, NULL, 0);
    at_response_free(p_response);
}

static void  requestSetFacilityLock(void*  data, size_t  datalen, RIL_Token  t)
{
    ATResponse * p_response = NULL;
    int err, ret = RIL_E_GENERIC_FAILURE;
    char* cmd, *line;
    const char ** strings = (const char**)data;
    int serviceclass, lockstate;
    int skip;
    char * skipstr;
    int residualcount;

    if (datalen == 5 * sizeof(char*)) {
        lockstate = atoi(strings[1]);
        serviceclass = atoi(strings[3]);
        asprintf(&cmd, "AT+CLCK=\"%s\",%d,\"%s\",%d", 
                strings[0], lockstate, strings[2], serviceclass);
    } else goto error;

    // modify by CYIT 20120405 ----- start -----
    err = at_send_command_timeout(cmd, NO_RESULT, NULL, &p_response, CYIT_AT_TIMEOUT_40_SEC);
    free(cmd);

    if (err < 0 || p_response->success == 0) {
        if(err == AT_ERROR_TIMEOUT
            && (!strncmp("AO", strings[0], 2) || !strncmp("OI", strings[0], 2)
            || !strncmp("OX", strings[0], 2) || !strncmp("AI", strings[0], 2)
            || !strncmp("IR", strings[0], 2) || !strncmp("AB", strings[0], 2)
            || !strncmp("AG", strings[0], 2) || !strncmp("AC", strings[0], 2)))
        {
            sendAbortCmd(CYIT_SAOC_TYPE_SS);
        }
    // modify by CYIT 20120405 -----  end  -----
        /*
        ret = at_get_cme_error(p_response);
        LOGD("BB error is %d", ret);
        ret = parseCmeErrToRilErr(ret);
        */
        ret = RIL_E_PASSWORD_INCORRECT;
    } else {
        ret = RIL_E_SUCCESS;
    }

    if (ret == RIL_E_PASSWORD_INCORRECT) {
        at_response_free(p_response);
        residualcount = requestPinResidualCount(strings[0], 0);
        if (residualcount >= 0) {
            RIL_onRequestComplete(t, ret, &residualcount, sizeof(residualcount));
        } else {
            RIL_onRequestComplete(t, ret, NULL, 0);
        }
        
        return;
    }

error:

    RIL_onRequestComplete(t, ret, NULL, 0);
    at_response_free(p_response);
}

static void  requestGetSCA(void*  data, size_t  datalen, RIL_Token  t)
{
    int err = 0;
    char * line, * sca;
    ATResponse * p_response = NULL;

    //at_send_command("AT+CSCS=\"IRA\"", NULL);
    err = at_send_command_singleline_timeout(
            "AT+CSCA?", "+CSCA:", &p_response, CYIT_AT_TIMEOUT_70_SEC);
    if (err < 0 || p_response->success == 0) {
        goto error;
    } 
    
    line = p_response->p_intermediates->line;
    err = at_tok_start(&line);
    if (err < 0) goto error;
    err = at_tok_nextstr(&line, &sca);
    if (err < 0) goto error;
    RIL_onRequestComplete(t, RIL_E_SUCCESS, sca, sizeof(sca));
    at_response_free(p_response);
    //at_send_command("AT+CSCS=\"UCS2\"", NULL);
    
    return;

error:
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
    at_response_free(p_response);
}

static void  requestSetSCA(void*  data, size_t  datalen, RIL_Token  t)
{
    int err = 0;
    char * cmd, * sca;
    ATResponse * p_response = NULL;

    if (data) sca = (char *)data;
    else goto error;

    //at_send_command("AT+CSCS=\"IRA\"", NULL);
    asprintf(&cmd, "AT+CSCA=\"%s\"", sca);
    err = at_send_command_timeout(
            cmd, NO_RESULT, NULL, &p_response, CYIT_AT_TIMEOUT_70_SEC);
    free(cmd);
    if (err != 0 || p_response->success == 0) {
        goto error;
    }

    RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
    at_response_free(p_response);
    //at_send_command("AT+CSCS=\"UCS2\"", NULL);

    return;
    
error:

    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
    at_response_free(p_response);
}


// -------------------------------------------------------------
//   modify by CYIT 20110922 ----- start -----
// -------------------------------------------------------------
static void requestCallFailCause( void *data , size_t datalen , RIL_Token t )
{
    int causeSelect = 0x00;
    int response[1];
    char *line;
    int err;
    ATResponse *p_response = NULL;
    err = at_send_command_singleline_min_timeout("AT+CEER", "+CEER:", &p_response);
    if (err < 0 || p_response->success == 0) goto error;

    line = p_response->p_intermediates->line;
    err = at_tok_start(&line);
    if (err < 0) goto error;
    err = at_tok_nextint(&line, &causeSelect);
    if (err < 0) goto error;
    err = at_tok_nextint(&line, &(response[0]));
    if (err < 0) goto error;

    // cause refer to 24.008 CC-Net-Cause
    if(causeSelect != 0x43)
    {
        response[0] = 0x10;// No.16 normal release
    }

    RIL_onRequestComplete(t, RIL_E_SUCCESS, response, sizeof(response));
    at_response_free(p_response);
    return;

error: LOGE("query last call fail cause error");
    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
    at_response_free(p_response);
}
// -------------------------------------------------------------
//   modify by CYIT 20110922 -----  end  -----
// -------------------------------------------------------------



/*** Callback methods from the RIL library to us ***/

/**
 * Call from RIL to us to make a RIL_REQUEST
 *
 * Must be completed with a call to RIL_onRequestComplete()
 *
 * RIL_onRequestComplete() may be called from any thread, before or after
 * this function returns.
 *
 * Will always be called from the same thread, so returning here implies
 * that the radio is ready to process another command (whether or not
 * the previous command has completed).
 */
static void
onRequest (int request, void *data, size_t datalen, RIL_Token t)
{
    ATResponse *p_response = NULL;
    int err;
    int cid;
    int token = -1;

    cid = *(int *)pthread_getspecific(CID);
    if (t) token = *(int *)t;
    LOGD("[REQ%d]: onRequest: %s token(%04d)", 
            cid, requestToString(request), token);

    /* Ignore all requests except RIL_REQUEST_GET_SIM_STATUS
     * when RADIO_STATE_UNAVAILABLE.
     */
    if (sState == RADIO_STATE_UNAVAILABLE
        && !(request == RIL_REQUEST_GET_SIM_STATUS 
            || request == RIL_REQUEST_GET_DATA_CALL_PROFILE
            || request == RIL_TIME_REQUEST_INITAT)
    ) {
        RIL_onRequestComplete(t, RIL_E_RADIO_NOT_AVAILABLE, NULL, 0);
        return;
    }

    /* Ignore all non-power requests when RADIO_STATE_OFF
     * (except RIL_REQUEST_GET_SIM_STATUS)
     */
    if (sState == RADIO_STATE_OFF
        && !(request == RIL_REQUEST_RADIO_POWER
            || request == RIL_REQUEST_GET_SIM_STATUS
            || request == RIL_REQUEST_GET_DATA_CALL_PROFILE
            || request == RIL_REQUEST_SCREEN_STATE
            || request == RIL_REQUEST_SET_PREFERRED_NETWORK_TYPE
            || request == RIL_REQUEST_GET_IMEI 
            || request == RIL_REQUEST_GET_IMEISV
            || request == RIL_REQUEST_BASEBAND_VERSION
            || request == RIL_REQUEST_ATCTST_AUD)
    ) {
        RIL_onRequestComplete(t, RIL_E_RADIO_NOT_AVAILABLE, NULL, 0);
        return;
    }

    // ----------------------------------------------------------------
    //   modified by CYIT 20130219 for airplane mode  ----- start -----
    // ----------------------------------------------------------------
    if (v_airmodeOper == RADIO_ACTION_AIRMODE_ON
        && (request == RIL_REQUEST_DIAL
            || (request >= RIL_REQUEST_HANGUP && request <= RIL_REQUEST_UDUB)
            || (request >= RIL_REQUEST_DTMF && request <= RIL_REQUEST_SETUP_DATA_CALL)
            || (request >= RIL_REQUEST_SEND_USSD && request <= RIL_REQUEST_SMS_ACKNOWLEDGE)
            || request == RIL_REQUEST_ANSWER
            || request == RIL_REQUEST_DEACTIVATE_DATA_CALL
            || request == RIL_REQUEST_CHANGE_BARRING_PASSWORD
            || (request >= RIL_REQUEST_SET_NETWORK_SELECTION_AUTOMATIC && request <= RIL_REQUEST_DTMF_STOP)
            || request == RIL_REQUEST_SEPARATE_CONNECTION
            || request == RIL_REQUEST_QUERY_CLIP
            || request == RIL_REQUEST_STK_HANDLE_CALL_SETUP_REQUESTED_FROM_SIM
            || request == RIL_REQUEST_SET_PDP_ACTIVE
            || request == RIL_REQUEST_QUERY_CALL_RESTRICT_STATUS
            || request == RIL_REQUEST_SET_CALL_RESTRICT_STATUS)
    ) {
        RIL_onRequestComplete(t, RIL_E_RADIO_NOT_AVAILABLE, NULL, 0);
        return;
    }
    // ----------------------------------------------------------------
    //   modified by CYIT 20130219 for airplane mode  -----  end  -----
    // ----------------------------------------------------------------

    switch (request) {
        case RIL_REQUEST_GET_SIM_STATUS: {
            RIL_CardStatus_v6 *p_card_status;
            char *p_buffer;
            int buffer_size;

            int result = getCardStatus(&p_card_status);
            if (result == RIL_E_SUCCESS) {
                p_buffer = (char *)p_card_status;
                buffer_size = sizeof(*p_card_status);
            } else {
                p_buffer = NULL;
                buffer_size = 0;
            }
            RIL_onRequestComplete(t, result, p_buffer, buffer_size);
            if(p_card_status->applications[0].app_state == RIL_APPSTATE_READY
                    && v_cardState != 1){
                v_cardState = 1;
                setRadioState(RADIO_STATE_SIM_READY);
            }else{
                v_cardState = 0;
            }
            freeCardStatus(p_card_status);
            break;
        }
        case RIL_REQUEST_GET_CURRENT_CALLS:
            requestGetCurrentCalls(data, datalen, t);
            break;
        case RIL_REQUEST_DIAL:
            requestDial(data, datalen, t);
            break;
        case RIL_REQUEST_HANGUP:
            requestHangup(data, datalen, t);
            break;
        case RIL_REQUEST_HANGUP_WAITING_OR_BACKGROUND:
            // 3GPP 22.030 6.5.5
            // "Releases all held calls or sets User Determined User Busy
            //  (UDUB) for a waiting call."
            at_send_command("AT+CHLD=0", NULL);

            /* success or failure is ignored by the upper layer here.
               it will call GET_CURRENT_CALLS and determine success that way */
            RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
            break;
        case RIL_REQUEST_HANGUP_FOREGROUND_RESUME_BACKGROUND:
            // 3GPP 22.030 6.5.5
            // "Releases all active calls (if any exist) and accepts
            //  the other (held or waiting) call."
            at_send_command("AT+CHLD=1", NULL);

            /* success or failure is ignored by the upper layer here.
               it will call GET_CURRENT_CALLS and determine success that way */
            RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
            break;
        case RIL_REQUEST_SWITCH_WAITING_OR_HOLDING_AND_ACTIVE:
            // 3GPP 22.030 6.5.5
            // "Places all active calls (if any exist) on hold and accepts
            //  the other (held or waiting) call."
            // modify by CYIT 20111216 ----- start -----
            p_response = NULL;
            err = at_send_command("AT+CHLD=2", &p_response);

            if (err < 0 || p_response->success == 0) {
                RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
            } else {
                #ifdef WORKAROUND_ERRONEOUS_ANSWER
                    s_expectAnswer = 1;
                #endif /* WORKAROUND_ERRONEOUS_ANSWER */
                RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
            }
            at_response_free(p_response);
            break;
            // modify by CYIT 20111216 -----  end  -----
        case RIL_REQUEST_ANSWER:
            // modify by CYIT 20120405 ----- start -----
            err = at_send_command("ATA", NULL);

            if(err == AT_ERROR_TIMEOUT)
            {
                sendAbortCmd(CYIT_SAOC_TYPE_CALL);
            }
            // modify by CYIT 20120405 -----  end  -----

#ifdef WORKAROUND_ERRONEOUS_ANSWER
            s_expectAnswer = 1;
#endif /* WORKAROUND_ERRONEOUS_ANSWER */

            /* success or failure is ignored by the upper layer here.
               it will call GET_CURRENT_CALLS and determine success that way */
            RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
            break;
        case RIL_REQUEST_CONFERENCE:
            // 3GPP 22.030 6.5.5
            // "Adds a held call to the conversation"
            // modify by CYIT 20111216 ----- start -----
            p_response = NULL;
            err = at_send_command("AT+CHLD=3", &p_response);

            if (err < 0 || p_response->success == 0) {
                RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
            } else {
                RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
            }
            at_response_free(p_response);
            break;
            // modify by CYIT 20111216 -----  end  -----
        case RIL_REQUEST_UDUB:
            /* user determined user busy */
            /* sometimes used: ATH */
            at_send_command("ATH", NULL);

            /* success or failure is ignored by the upper layer here.
               it will call GET_CURRENT_CALLS and determine success that way */
            RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
            break;

        case RIL_REQUEST_SEPARATE_CONNECTION:
            {
                char  cmd[12];
                int   party = ((int*)data)[0];

                // Make sure that party is in a valid range.
                // (Note: The Telephony middle layer imposes a range of 1 to 7.
                // It's sufficient for us to just make sure it's single digit.)
                if (party > 0 && party < 10) {
                    sprintf(cmd, "AT+CHLD=2%d", party);
                    at_send_command(cmd, NULL);
                    RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
                } else {
                    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
                }
            }
            break;

        case RIL_REQUEST_SIGNAL_STRENGTH:
            requestSignalStrength(data, datalen, t);
            break;
        case RIL_REQUEST_VOICE_REGISTRATION_STATE:
        case RIL_REQUEST_DATA_REGISTRATION_STATE:
            requestRegistrationState(request, data, datalen, t);
            break;
        case RIL_REQUEST_OPERATOR:
            requestOperator(data, datalen, t);
            break;
        case RIL_REQUEST_RADIO_POWER:
            requestRadioPower(data, datalen, t);
            break;
        case RIL_REQUEST_DTMF:
        case RIL_REQUEST_DTMF_START: {
            char c = ((char *)data)[0];
            char *cmd;
            asprintf(&cmd, "AT+VTS=%c", (int)c);
            at_send_command(cmd, NULL);
            free(cmd);
            RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
            break;
        }
        case RIL_REQUEST_DTMF_STOP: {
            RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
            break;
        }
        case RIL_REQUEST_SEND_SMS:
            requestSendSMS(data, datalen, t);
            break;
        // modify by CYIT 20111017 ----- start -----
        case RIL_REQUEST_SET_SMS_STORAGE_LOC:
            requestSetSmsStorageLocation(data, datalen, t);
            break;
        case RIL_REQUEST_GET_SMS_STORAGE_STATE:
            requestGetSmsStorageState(data, datalen, t);
            break;
        // modify by CYIT 20111017 -----  end  -----
        case RIL_REQUEST_CDMA_SEND_SMS:
            requestCdmaSendSMS(data, datalen, t);
            break;
        case RIL_REQUEST_SETUP_DATA_CALL:
            requestSetupDataCall(data, datalen, t);
            break;
        case RIL_REQUEST_DEACTIVATE_DATA_CALL:
            requestDeactivateDataCall( data, datalen, t );
            break;
        case RIL_REQUEST_GET_DATA_CALL_PROFILE:
            requestGetDataCallProfile(data, datalen, t);
            break;
        case RIL_REQUEST_SMS_ACKNOWLEDGE:
            requestSMSAcknowledge(data, datalen, t);
            break;

        case RIL_REQUEST_GET_IMSI:
            p_response = NULL;
            err = at_send_command_numeric("AT+CIMI", &p_response);

            if (err < 0 || p_response->success == 0) {
                RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
            } else {
                RIL_onRequestComplete(t, RIL_E_SUCCESS,
                    p_response->p_intermediates->line, sizeof(char *));
            }
            at_response_free(p_response);
            break;

        case RIL_REQUEST_GET_IMEI:
            LOGD("RIL_REQUEST_GET_IMEI");
            p_response = NULL;
            err = at_send_command_numeric("AT+CGSN", &p_response);

            if (err < 0 || p_response->success == 0) {
                RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
            } else {
                LOGD("get IMEI is %s", p_response->p_intermediates->line);
                RIL_onRequestComplete(t, RIL_E_SUCCESS,
                    p_response->p_intermediates->line, sizeof(char *));
            }
            at_response_free(p_response);
            break;

        case RIL_REQUEST_GET_IMEISV:
            LOGD("RIL_REQUEST_GET_IMEISV");
            requestGetIMEISV(data,datalen,t);
            break;

        case RIL_REQUEST_SIM_IO:
            requestSIM_IO(data,datalen,t);
            break;

        case RIL_REQUEST_SEND_USSD:
            requestSendUSSD(data, datalen, t);
            break;

        case RIL_REQUEST_CANCEL_USSD:
            p_response = NULL;
            // modify by CYIT 20120217 ----- start -----
            err = at_send_command_timeout("AT+CUSD=2"
                , NO_RESULT, NULL, &p_response, CYIT_AT_TIMEOUT_70_SEC);

            if (err < 0 || p_response->success == 0) {
                RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
            } else {
                RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
            }
            // modify by CYIT 20120217 -----  end  -----
            at_response_free(p_response);
            break;

// -----------------------------------------------------------------
// modify by CYIT 20110512    ----- start  -----
// -----------------------------------------------------------------
        case RIL_REQUEST_GET_CLIR:
            requestGetCLIR( data, datalen, t );
            break;

        case RIL_REQUEST_SET_CLIR:
        {
            char *cmd;
            asprintf( &cmd, "AT+CLIR=%d", ( ( int* )data )[0] );

            err = at_send_command_timeout( cmd, NO_RESULT, NULL, &p_response,
                    CYIT_AT_TIMEOUT_40_SEC );

            free( cmd );
            if ( err < 0 || p_response->success == 0 )
            {
                LOGD("set CLIR error");
                RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
            }
            else
            {
                LOGD("set CLIR success");
                RIL_onRequestComplete( t, RIL_E_SUCCESS, NULL, 0 );
            }
            at_response_free( p_response );
            break;
        }

        case RIL_REQUEST_QUERY_CALL_WAITING:
            requestQueryCallWaiting( data, datalen, t );
            break;

        case RIL_REQUEST_SET_CALL_WAITING:
        {
            char *cmd;
            p_response = NULL;
            asprintf( &cmd, "AT+CCWA=1,%d,1", ( ( int* )data )[0] );

            err = at_send_command_timeout(
                cmd, NO_RESULT, NULL, &p_response, CYIT_AT_TIMEOUT_40_SEC); // modify by CYIT 20120405
            free( cmd );
            if ( err < 0 || p_response->success == 0 )
            {
                LOGD("set CW error");
                RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
            }
            else
            {
                LOGD("set CW success");
                RIL_onRequestComplete( t, RIL_E_SUCCESS, NULL, 0 );
            }
            at_response_free( p_response );
            break;
        }

        case RIL_REQUEST_QUERY_CALL_FORWARD_STATUS:
            requestQueryCallForwardStatus( data, datalen, t );
            break;

        case RIL_REQUEST_SET_CALL_FORWARD:
            requestSetCallForward( data, datalen, t );
            break;

        case RIL_REQUEST_QUERY_CALL_RESTRICT_STATUS:
            requestQueryCallRestrictStatus( data, datalen, t );
            break;

        case RIL_REQUEST_SET_CALL_RESTRICT_STATUS:
            requestSetCallRestrictStatus( data, datalen, t );
            break;

        case RIL_REQUEST_CHANGE_BARRING_PASSWORD:
            requestChangeBarringPassward( data, datalen, t );
            break;

// -----------------------------------------------------------------
// modify by CYIT 20110512    -----  end  -----
// -----------------------------------------------------------------

        case RIL_REQUEST_SET_NETWORK_SELECTION_AUTOMATIC:
            p_response = NULL;
            err = at_send_command_timeout(
                    "AT+COPS=0", NO_RESULT, NULL, &p_response, CYIT_AT_TIMEOUT_40_SEC);
            if ( err < 0 || p_response->success == 0 ) {
                RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
            } else {
                RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
            }
            at_response_free( p_response );

            break;

        case RIL_REQUEST_SET_NETWORK_SELECTION_MANUAL:
            {
                char *cmd;

                p_response = NULL;
                asprintf(&cmd, "AT+COPS=1,2,\"%s\"", (char *)data);
                // modify by CYIT 20120405 ----- start -----
                err = at_send_command_timeout(
                    cmd, NO_RESULT, NULL, &p_response, CYIT_AT_TIMEOUT_40_SEC);
                free(cmd);

                if (err < 0 || p_response->success == 0) {
                    if (AT_ERROR_TIMEOUT == err) {
                        sendAbortCmd(CYIT_SAOC_TYPE_NET);
                    }
                // modify by CYIT 20120405 -----  end  -----
                    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
                } else {
                    RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
                }
                at_response_free(p_response);

                break;
            }

        case RIL_REQUEST_DATA_CALL_LIST:
            requestDataCallList(data, datalen, t);
            break;

        case RIL_REQUEST_QUERY_NETWORK_SELECTION_MODE:
            requestQueryNetworkSelectionMode(data, datalen, t);
            break;

        case RIL_REQUEST_OEM_HOOK_RAW:
            // echo back data
            RIL_onRequestComplete(t, RIL_E_SUCCESS, data, datalen);
            break;


        case RIL_REQUEST_OEM_HOOK_STRINGS: {
            int i;
            const char ** cur;

            LOGD("got OEM_HOOK_STRINGS: 0x%8p %lu", data, (long)datalen);


            for (i = (datalen / sizeof (char *)), cur = (const char **)data ;
                    i > 0 ; cur++, i --) {
                LOGD("> '%s'", *cur);
            }

            // echo back strings
            RIL_onRequestComplete(t, RIL_E_SUCCESS, data, datalen);
            break;
        }

        case RIL_REQUEST_WRITE_SMS_TO_SIM:
            requestWriteSmsToSim(data, datalen, t);
            break;

        case RIL_REQUEST_DELETE_SMS_ON_SIM: {
            char * cmd;
            p_response = NULL;
            asprintf(&cmd, "AT+CMGD=%d", ((int *)data)[0]);
            err = at_send_command_timeout(cmd, NO_RESULT, NULL, &p_response, CYIT_AT_TIMEOUT_70_SEC);
            free(cmd);
            if (err < 0 || p_response->success == 0) {
                RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
            } else {
                RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
            }
            at_response_free(p_response);
            break;
        }

        case RIL_REQUEST_ENTER_SIM_PIN:
        case RIL_REQUEST_ENTER_SIM_PUK:
            requestEnterSimPin(data, datalen, t, "SC");
            break;
        case RIL_REQUEST_ENTER_SIM_PIN2:
        case RIL_REQUEST_ENTER_SIM_PUK2:
            requestEnterSimPin(data, datalen, t, "P2");
            break;
            
        case RIL_REQUEST_CHANGE_SIM_PIN:
            requestChangeSimPin(data, datalen, t, "SC");
            break;
        case RIL_REQUEST_CHANGE_SIM_PIN2:
            requestChangeSimPin(data, datalen, t, "P2");
            break;

        case RIL_REQUEST_VOICE_RADIO_TECH:
            {
                int techfam = techFamilyFromModemType(TECH(sMdmInfo));
                if (techfam < 0 )
                    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
                else
                    RIL_onRequestComplete(t, RIL_E_SUCCESS, &techfam, sizeof(&techfam));
            }
            break;

        case RIL_REQUEST_SET_PREFERRED_NETWORK_TYPE:
            requestSetPreferredNetworkType(request, data, datalen, t);
            break;

        case RIL_REQUEST_STK_SEND_TERMINAL_RESPONSE:
        {
            char *cmd;
            int endType;
            int len = strlen( ( char* )data );
            p_response = NULL;
            asprintf( &cmd, "AT^SSTGR=0,%d,\"%s\"", len / 2, ( char* )data );
            err = at_send_command_timeout(cmd, NO_RESULT, NULL, &p_response, CYIT_AT_TIMEOUT_10_SEC);
            free( cmd );
            if ( err < 0 || p_response->success == 0 )
            {
                RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );

                if (AT_ERROR_TIMEOUT == err) {
                    endType = 1;
                    RIL_onUnsolicitedResponse( RIL_UNSOL_STK_SESSION_END, &endType, sizeof(int *) );
                }
            }
            else
            {
                RIL_onRequestComplete( t, RIL_E_SUCCESS, NULL, 0 );
            }
            at_response_free( p_response );
            break;
        }

        case RIL_REQUEST_STK_SEND_ENVELOPE_COMMAND:
        {
            char *cmd;
            int len = strlen( ( char* )data );
            p_response = NULL;
            asprintf( &cmd, "AT^SSTEV=0,%d,\"%s\"", len / 2, ( char* )data );
            err = at_send_command_timeout(cmd, NO_RESULT, NULL, &p_response, CYIT_AT_TIMEOUT_10_SEC);
            free( cmd );
            if ( err < 0 || p_response->success == 0 )
            {
                RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
            }
            else
            {
                RIL_onRequestComplete( t, RIL_E_SUCCESS, NULL, 0 );
            }
            at_response_free( p_response );
            break;
        }

        case RIL_REQUEST_GET_PREFERRED_NETWORK_TYPE:
            requestGetPreferredNetworkType(request, data, datalen, t);
            break;
        case RIL_REQUEST_CHANGE_VOLUME: 
         {
            char * cmd;
            p_response = NULL;
            asprintf(&cmd, "AT+CLVL=%d", ((int *)data)[0]);
            err = at_send_command_min_timeout(cmd, &p_response);
            free(cmd);
            if (err < 0 || p_response->success == 0) {
                 RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
              } else {
                 RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
              }
            at_response_free(p_response);
            break;
         
         }

        case RIL_REQUEST_CHOSE_VOICE_PATH:
         {
            char * cmd;
            p_response = NULL;
            asprintf(&cmd, "AT^SPATH=%d,%d", ((int *)data)[0],((int *)data)[1]);
            err = at_send_command_min_timeout(cmd, &p_response);
            free(cmd);
            if (err < 0 || p_response->success == 0) {
                 RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
              } else {
                 RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
              }
        
             at_response_free(p_response);
             break;
         }
        case RIL_REQUEST_SET_CALL_RECORDING:
         {
            char * cmd;
            p_response = NULL;
            asprintf(&cmd, "AT^SVMOP=%d", ((int *)data)[0]);
            err = at_send_command_min_timeout(cmd, &p_response);
            free(cmd);
            if (err < 0 || p_response->success == 0) {
                 RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
              } else {
                 RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
              }
        
             at_response_free(p_response);
             break;
         }   
    /**************************************************************************
      Modified by CYIT 20120825 ----- start -----
      Append RIL message dispose
    **************************************************************************/
        case RIL_REQUEST_GET_TD_FRQ_LOCK:
            requestGetTDFreq( data, datalen, t );
            break;
    
        case RIL_REQUEST_SET_TD_FRQ_LOCK:
            requestSetTDFreq( data, datalen, t );
            break;
    
        case RIL_REQUEST_GET_TD_CELL_ID_LOCK:
            requestGetTDCellIdLock( data, datalen, t );
            break;
    
        case RIL_REQUEST_SET_TD_CELL_ID_LOCK:
            requestSetTDCellIdLock( data, datalen, t );
            break;
    
        case RIL_REQUEST_GET_GSM_FRQ_LOCK:
            requestGetGsmFreqLock( data, datalen, t );
            break;
    
        case RIL_REQUEST_SET_GSM_FRQ_LOCK:
            requestSetGsmFreqLock( data, datalen, t );
            break;
    
        case RIL_REQUEST_GET_PRO_VERSION:
            requestGetProtocolVersion( data, datalen, t );
            break;
    
        case RIL_REQUEST_SET_PRO_VERSION:
            requestSetProtocolVersion( data, datalen, t );
            break;
    
        //case RIL_REQUEST_SET_PREFERRED_NETWORK_TYPE:  // see before
        //case RIL_REQUEST_GET_PREFERRED_NETWORK_TYPE:
    
        case RIL_REQUEST_GET_PS_ATTACHED:
            requestGetPSAttached( data, datalen, t );
            break;
    
        case RIL_REQUEST_SET_PS_ATTACHED:
            requestSetPSAttached( data, datalen, t );
            break;
    
        //case RIL_REQUEST_GET_IMEI:  // see before
        //case RIL_REQUEST_GET_IMSI:
    
        case RIL_REQUEST_GET_UE_CATEGORY:
            requestGetUeCategroy( data, datalen, t );
            break;
    
        case RIL_REQUEST_SET_UE_CATEGORY:
            requestSetUeCategroy( data, datalen, t );
            break;
    

        case RIL_REQUEST_SET_TE_TYPE:
            requestSetTEType( data, datalen, t );
            break;

        case RIL_REQUEST_GET_TE_TYPE:
            requestGetTEType( data, datalen, t );
            break;

    
        case RIL_REQUEST_GET_APN_INFO:
            requestGetApnInfo( data, datalen, t );
            break;
    
        case RIL_REQUEST_SET_APN_INFO:
            requestSetApnInfo( data, datalen, t );
            break;
    
        case RIL_REQUEST_GET_PDP_ACTIVE:
            requestGetPdpActive( data, datalen, t );
            break;
    
        case RIL_REQUEST_SET_PDP_ACTIVE:
            requestSetPdpActive( data, datalen, t );
            break;
    
        case RIL_REQUEST_GET_PDP_QOS:
            requestGetPdpQos( data, datalen, t );
            break;
    
        case RIL_REQUEST_SET_PDP_QOS:
            requestSetPdpQos( data, datalen, t );
            break;

        case RIL_REQUEST_SET_2NDPDP_CONTEXT:
            requestSet2ndPdpContext(data, datalen, t);
            break;
    
        case RIL_REQUEST_SET_TD_FRQ_UNLOCK:
            requestSetTDFreqUnLock( data, datalen, t );
            break;
    
        case RIL_REQUEST_SET_TD_CELL_UNLOCK:
            requestSetTDCellUnLock( data, datalen, t );
            break;

        case RIL_REQUEST_ENTER_BIOS:
            requestEnterBios( data, datalen, t );
            break;

        case RIL_REQUEST_GET_LOG_CTRL:
            requestGetLogCtrl( data, datalen, t );
            break;

        case RIL_REQUEST_SET_LOG_CTRL:
            requestSetLogCtrl( data, datalen, t );
            break;

        case RIL_REQUEST_GET_USB_ENUM_CTRL:
            requestGetUsbEnumCtrl( data, datalen, t );
            break;

        case RIL_REQUEST_SET_USB_ENUM_CTRL:
            requestSetUsbEnumCtrl( data, datalen, t );
            break;

        case RIL_REQUEST_GET_RESET_FLAG_CTRL:
            requestGetResetFlagCtrl( data, datalen, t );
            break;

        case RIL_REQUEST_SET_RESET_FLAG_CTRL:
            requestSetResetFlagCtrl( data, datalen, t );
            break;

        case RIL_REQUEST_GET_VERSION_CTRL:
            requestGetVersionCtrl( data, datalen, t );
            break;

        case RIL_REQUEST_SET_VERSION_CTRL:
            requestSetVersionCtrl( data, datalen, t );
            break;

        case RIL_REQUEST_GET_CELL_INFO:
            requestgetCellInfoList( data, datalen, t );
            break;

        case RIL_REQUEST_GET_PREFER_NETLIST:
            requestgetPrenetList( data, datalen, t );
            break;
            
        case RIL_REQUEST_SET_PREFER_NETLIST:
            requestsetPrenetList( data, datalen, t );
            break;

        case RIL_REQUEST_GET_POWERON_ATTACH_MODE:
            requestGetPowerOnAttachMode( data, datalen, t );
            break;

        case RIL_REQUEST_SET_POWERON_ATTACH_MODE:
            requestSetPowerOnAttachMode( data, datalen, t );
            break;

        case RIL_REQUEST_GET_POWERON_NETWORKSEL_CTRL:
            requestGetPowerOnNetSelCtrl( data, datalen, t );
            break;

        case RIL_REQUEST_SET_POWERON_NETWORKSEL_CTRL:
            requestSetPowerOnNetSelCtrl( data, datalen, t );
            break;

        case RIL_REQUEST_GET_STOP_PDPDATA_CTRL:
            requestGetStopPdpDataCtrl( data, datalen, t );
            break;

        case RIL_REQUEST_SET_STOP_PDPDATA_CTRL:
            requestSetStopPdpDataCtrl( data, datalen, t );
            break;

        case RIL_REQUEST_GET_IP_CHECK_CTRL:
            requestGetIPCheckCtrl( data, datalen, t );
            break;

        case RIL_REQUEST_SET_IP_CHECK_CTRL:
            requestSetIPCheckCtrl( data, datalen, t );
            break;

        case RIL_REQUEST_GET_SMS_BEAR_CTRL:
            requestGetSMSBear( data, datalen, t );
            break;

        case RIL_REQUEST_SET_SMS_BEAR_CTRL:
            requestSetSMSBear( data, datalen, t );
            break;

        case RIL_REQUEST_ATCTST_AUD:
            requestAtctstAud( data, datalen, t );
            break;

        case RIL_REQUEST_GET_SSWINFO:
            requestGetSSWInfo(data, datalen, t);
            break;

    /**************************************************************************
      Modified by CYIT 20120825 ----- end -----
    **************************************************************************/

        case RIL_REQUEST_BASEBAND_VERSION:
            if (TECH_BIT(sMdmInfo) == MDM_CDMA) {
                requestCdmaBaseBandVersion(request, data, datalen, t);
            } else {
                RIL_onRequestComplete(t, RIL_E_REQUEST_NOT_SUPPORTED, NULL, 0);
            }
            break;

        case RIL_REQUEST_DEVICE_IDENTITY:
            if (TECH_BIT(sMdmInfo) == MDM_CDMA) {
                requestCdmaDeviceIdentity(request, data, datalen, t);
            } else {
                RIL_onRequestComplete(t, RIL_E_REQUEST_NOT_SUPPORTED, NULL, 0);
            }
            break;

        case RIL_REQUEST_CDMA_SUBSCRIPTION:
            if (TECH_BIT(sMdmInfo) == MDM_CDMA) {
                requestCdmaSubscription(request, data, datalen, t);
            } else {
                RIL_onRequestComplete(t, RIL_E_REQUEST_NOT_SUPPORTED, NULL, 0);
            }
            break;

        case RIL_REQUEST_CDMA_SET_SUBSCRIPTION_SOURCE:
            if (TECH_BIT(sMdmInfo) == MDM_CDMA) {
                requestCdmaSetSubscriptionSource(request, data, datalen, t);
            } else {
                RIL_onRequestComplete(t, RIL_E_REQUEST_NOT_SUPPORTED, NULL, 0);
            }
            break;

        case RIL_REQUEST_CDMA_GET_SUBSCRIPTION_SOURCE:
            if (TECH_BIT(sMdmInfo) == MDM_CDMA) {
                requestCdmaGetSubscriptionSource(request, data, datalen, t);
            } else {
                RIL_onRequestComplete(t, RIL_E_REQUEST_NOT_SUPPORTED, NULL, 0);
            }
            break;

        case RIL_REQUEST_CDMA_QUERY_ROAMING_PREFERENCE:
            if (TECH_BIT(sMdmInfo) == MDM_CDMA) {
                requestCdmaGetRoamingPreference(request, data, datalen, t);
            } else {
                RIL_onRequestComplete(t, RIL_E_REQUEST_NOT_SUPPORTED, NULL, 0);
            }
            break;

        case RIL_REQUEST_CDMA_SET_ROAMING_PREFERENCE:
            if (TECH_BIT(sMdmInfo) == MDM_CDMA) {
                requestCdmaSetRoamingPreference(request, data, datalen, t);
            } else {
                RIL_onRequestComplete(t, RIL_E_REQUEST_NOT_SUPPORTED, NULL, 0);
            }
            break;

        case RIL_REQUEST_EXIT_EMERGENCY_CALLBACK_MODE:
            if (TECH_BIT(sMdmInfo) == MDM_CDMA) {
                requestExitEmergencyMode(data, datalen, t);
            } else {
                RIL_onRequestComplete(t, RIL_E_REQUEST_NOT_SUPPORTED, NULL, 0);
            }
            break;

        case RIL_REQUEST_SCREEN_STATE:
            requestSetScreenState(data, datalen, t);
            break;

        case RIL_REQUEST_QUERY_AVAILABLE_NETWORKS:
            requestQueryNetworks( data, datalen, t );
            break;

        case RIL_REQUEST_SET_MUTE:
            {
                char *cmd;
                
                asprintf(&cmd, "AT+CMUT=%d", ((int *)data)[0]);
                at_send_command_min_timeout(cmd, NULL);
                free(cmd);
                RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
                break;
            }

        case RIL_REQUEST_GET_MUTE:
            {
                int Result;

                p_response = NULL;
                err = at_send_command_singleline_min_timeout("AT+CMUT?", "+CMUT:", &p_response);

                RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
                if (err < 0 || p_response->success == 0) {
                    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
                } else {
                    char *line = p_response->p_intermediates->line;
                    at_tok_start(&line);
                    err = at_tok_nextint(&line, &Result);
                    if (err < 0) {
                        RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
                    } else {
                        RIL_onRequestComplete(t, RIL_E_SUCCESS, &Result, sizeof(int *));
                    }
                }

                at_response_free(p_response);
                break;
            }

        case RIL_REQUEST_SELECT_PB_EF:
            requestSelectPBEF(data, datalen, t);
            break;

        case RIL_REQUEST_WRITE_PB_RECORD:
            requestWritePBRecord(data, datalen, t);
            break;

        // modify by CYIT 20111026 ----- start -----
        case RIL_REQUEST_WRITE_PB_RECORD_USER_DEFINED:
            requestWritePbRecordUserDefined(data, datalen, t);
            break;

        case RIL_REQUEST_READ_PB_RECORD_USER_DEFINED:
            requestReadPbRecordUserDefined(data, datalen, t);
            break;

        case RIL_REQUEST_GET_PB_RECORD_SIZE:
            requestPbRecordSize(data, datalen, t);
            break;

        case RIL_REQUEST_GET_PB_CONTENT_LENGTH:
            requestPbContentLength(data, datalen, t);
            break;
        // modify by CYIT 20120229 -----  end  -----

        case RIL_REQUEST_PLAY_TONE:
            {
                char *cmd;

                asprintf(&cmd, "AT^SPLYT=%d", ((int *)data)[0]);
                err = at_send_command_min_timeout(cmd, NULL);
                free(cmd);
                RIL_onRequestComplete( t, RIL_E_SUCCESS, NULL, 0 );
            }
            break;

        // -------------------------------------------------------------
        //   modify by CYIT 20110715         ----- start -----
        // -------------------------------------------------------------
        case RIL_REQUEST_SET_MO_TYPE:
            requestSetMoType(data, datalen, t);
            break;
        // -------------------------------------------------------------
        //   modify by CYIT 20110715         -----  end  -----
        // -------------------------------------------------------------

        case RIL_REQUEST_QUERY_FACILITY_LOCK:
            requestQueryFacilityLock(data, datalen, t);
            break;
        case RIL_REQUEST_SET_FACILITY_LOCK:
            requestSetFacilityLock(data, datalen, t);
            break;

        case RIL_REQUEST_GET_SMSC_ADDRESS:
            requestGetSCA(data, datalen, t);
            break;

        case RIL_REQUEST_SET_SMSC_ADDRESS:
            requestSetSCA(data, datalen, t);
            break;

        // -------------------------------------------------------------
        //   modify by CYIT 20110922 ----- start -----
        // -------------------------------------------------------------
        case RIL_REQUEST_LAST_CALL_FAIL_CAUSE:
            requestCallFailCause( data, datalen, t );
            break;
        // -------------------------------------------------------------
        //   modify by CYIT 20110715 -----  end  -----
        // -------------------------------------------------------------

        case RIL_REQUEST_GET_POWER_SAVING_CTRL:
            requestGetPowerSavingCtrl( data, datalen, t );
            break;

        case RIL_REQUEST_SET_POWER_SAVING_CTRL:
            requestSetPowerSavingCtrl( data, datalen, t );
            break;

        case RIL_TIME_REQUEST_INITAT:
            initializeCallback(data, t);
            break;

        case RIL_TIME_REQUEST_CALL_STATE_CHANGED:
            sendCallStateChanged(data, t);
            break;

        case RIL_TIME_REQUEST_POLL_SIM_STATE:
            pollSIMState(data, t);
            break;

        case RIL_TIME_REQUEST_DATA_CALL_LIST:
            onDataCallListChanged(data, t);
            break;

        case RIL_TIME_REQUEST_RELEASE_POWERLOCK:
            RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
            break;

        /**************************************************************************
          Modified by CYIT 20130304 ----- start -----
          Append interface for querying available networks
          together with access technology
        **************************************************************************/
        case RIL_REQUEST_QUERY_NETWORKS_WITH_TYPE:
            requestQueryNetworksWithType( data, datalen, t );
            break;
        /**************************************************************************
          Modified by CYIT 20130304 ----- end -----
        **************************************************************************/

        /**************************************************************************
          Modified by CYIT 20130319 ----- start -----
          Append interface for querying the remain count of sim PIN or PUK 
          to continue input
        **************************************************************************/
        case RIL_REQUEST_GET_SIM_PIN_PUK_REMAIN_COUNT:
            requestGetSimPinPukRemainCount(data, datalen, t);
            break;
        /**************************************************************************
          Modified by CYIT 20130319 ----- end -----
        **************************************************************************/

        default:
            LOGD("Request not supported. Tech: %d",TECH(sMdmInfo));
            RIL_onRequestComplete(t, RIL_E_REQUEST_NOT_SUPPORTED, NULL, 0);
            break;
    }
}

/**
 * Synchronous call from the RIL to us to return current radio state.
 * RADIO_STATE_UNAVAILABLE should be the initial state.
 */
static RIL_RadioState
currentState()
{
    return sState;
}
/**
 * Call from RIL to us to find out whether a specific request code
 * is supported by this implementation.
 *
 * Return 1 for "supported" and 0 for "unsupported"
 */

static int
onSupports (int requestCode)
{
    //@@@ todo

    return 1;
}

static void onCancel (RIL_Token t)
{
    //@@@todo

}

static const char * getVersion(void)
{
    return "cyit-ril 1.0";
}

static void
setRadioTechnology(ModemInfo *mdm, int newtech)
{
    LOGD("setRadioTechnology(%d)", newtech);

    int oldtech = TECH(mdm);

    if (newtech != oldtech) {
        LOGD("Tech change (%d => %d)", oldtech, newtech);
        TECH(mdm) = newtech;
        if (techFamilyFromModemType(newtech) != techFamilyFromModemType(oldtech)) {
            RIL_onUnsolicitedResponse(RIL_UNSOL_VOICE_RADIO_TECH_CHANGED, NULL, 0);
        }
    }
}

static void
setRadioState(RIL_RadioState newState)
{
    LOGD("setRadioState(%d)", newState);
    RIL_RadioState oldState;

    pthread_mutex_lock(&s_state_mutex);

    oldState = sState;

    if (s_closed > 0) {
        // If we're closed, the only reasonable state is
        // RADIO_STATE_UNAVAILABLE
        // This is here because things on the main thread
        // may attempt to change the radio state after the closed
        // event happened in another thread
        newState = RADIO_STATE_UNAVAILABLE;
    }

    if (sState != newState || s_closed > 0) {
        sState = newState;

        pthread_cond_broadcast (&s_state_cond);
    }

    pthread_mutex_unlock(&s_state_mutex);


    /* do these outside of the mutex */
    if (sState != oldState) {
        RIL_onUnsolicitedResponse (RIL_UNSOL_RESPONSE_RADIO_STATE_CHANGED, NULL, 0);

        if (sState == RADIO_STATE_SIM_READY) {
            onSIMReady();
        } else if (sState == RADIO_STATE_SIM_NOT_READY) {
            onRadioPowerOn();
        }
    }
}

/** Returns RUIM_NOT_READY on error */
static SIM_Status
getRUIMStatus()
{
    ATResponse *p_response = NULL;
    int err;
    int ret;
    char *cpinLine;
    char *cpinResult;

    if (sState == RADIO_STATE_OFF || sState == RADIO_STATE_UNAVAILABLE) {
        ret = SIM_NOT_READY;
        goto done;
    }

    err = at_send_command_singleline_timeout(
            "AT+CPIN?", "+CPIN:", &p_response, CYIT_AT_TIMEOUT_10_SEC);

    if (err != 0) {
        ret = SIM_NOT_READY;
        goto done;
    }

    switch (at_get_cme_error(p_response)) {
        case CME_SUCCESS:
            break;

        case CME_SIM_NOT_INSERTED:
            ret = SIM_ABSENT;
            goto done;

        default:
            ret = SIM_NOT_READY;
            goto done;
    }

    /* CPIN? has succeeded, now look at the result */

    cpinLine = p_response->p_intermediates->line;
    err = at_tok_start (&cpinLine);

    if (err < 0) {
        ret = SIM_NOT_READY;
        goto done;
    }

    err = at_tok_nextstr(&cpinLine, &cpinResult);

    if (err < 0) {
        ret = SIM_NOT_READY;
        goto done;
    }

    if (0 == strcmp (cpinResult, "SIM PIN")) {
        ret = SIM_PIN;
        goto done;
    } else if (0 == strcmp (cpinResult, "SIM PUK")) {
        ret = SIM_PUK;
        goto done;
    } else if (0 == strcmp (cpinResult, "PH-NET PIN")) {
        return SIM_NETWORK_PERSONALIZATION;
    } else if (0 != strcmp (cpinResult, "READY"))  {
        /* we're treating unsupported lock types as "sim absent" */
        ret = SIM_ABSENT;
        goto done;
    }

    at_response_free(p_response);
    p_response = NULL;
    cpinResult = NULL;

    ret = SIM_READY;

done:
    at_response_free(p_response);
    return ret;
}

/** Returns SIM_NOT_READY on error */
static SIM_Status 
getSIMStatus()
{
    ATResponse *p_response = NULL;
    int err;
    int ret;
    char *cpinLine;
    char *cpinResult;

    LOGD("getSIMStatus(). sState: %d",sState);
    if (sState == RADIO_STATE_OFF || sState == RADIO_STATE_UNAVAILABLE) {
        ret = SIM_NOT_READY;
        s_Pin1State = RIL_PINSTATE_UNKNOWN;
        goto done;
    }

    err =at_send_command_timeout_poll(
            "AT+CPIN?", SINGLELINE, "+CPIN:",
            &p_response, CYIT_DEFAULT_AT_TIMEOUT_MSEC, CYIT_AT_TIMEOUT_DEFAULT_POLL_NUM);

    if (err != 0) {
        ret = SIM_NOT_READY;
        s_Pin1State = RIL_PINSTATE_UNKNOWN;
        goto done;
    }

    switch (at_get_cme_error(p_response)) {
        case CME_SUCCESS:
            break;

        case CME_SIM_NOT_INSERTED:
            ret = SIM_ABSENT;
            s_Pin1State = RIL_PINSTATE_UNKNOWN;
            goto done;

        case CME_SIM_FAILURE:
        case CME_SIM_BUSY:
        case CME_SIM_WRONG:
            ret = SIM_IO_ERROR;
            s_Pin1State = RIL_PINSTATE_UNKNOWN;
            goto done;

        default:
            ret = SIM_NOT_READY;
            s_Pin1State = RIL_PINSTATE_UNKNOWN;
            goto done;
    }

    /* CPIN? has succeeded, now look at the result */

    cpinLine = p_response->p_intermediates->line;
    err = at_tok_start (&cpinLine);

    if (err < 0) {
        ret = SIM_NOT_READY;
        s_Pin1State = RIL_PINSTATE_UNKNOWN;
        goto done;
    }

    err = at_tok_nextstr(&cpinLine, &cpinResult);

    if (err < 0) {
        ret = SIM_NOT_READY;
        s_Pin1State = RIL_PINSTATE_UNKNOWN;
        goto done;
    }

    if (0 == strcmp (cpinResult, "SIM PIN")) {
        ret = SIM_PIN;
        s_Pin1State = RIL_PINSTATE_ENABLED_NOT_VERIFIED;
        goto done;
    } else if (0 == strcmp (cpinResult, "SIM PUK")) {
        ret = SIM_PUK;
        s_Pin1State = RIL_PINSTATE_ENABLED_BLOCKED;
        goto done;
    } else if (0 == strcmp (cpinResult, "SIM PUK1 BLOCKED")) {
        ret = SIM_ABSENT;
        s_Pin1State = RIL_PINSTATE_ENABLED_PERM_BLOCKED;
        goto done;
    } else if (0 == strcmp (cpinResult, "PH-NET PIN")) {
        ret = SIM_NETWORK_PERSONALIZATION;
        s_Pin1State = RIL_PINSTATE_ENABLED_NOT_VERIFIED;
        goto done;
    } else if (0 != strcmp (cpinResult, "READY"))  {
        /* we're treating unsupported lock types as "sim absent" */
        ret = SIM_ABSENT;
        s_Pin1State = RIL_PINSTATE_UNKNOWN;
        goto done;
    }

    at_response_free(p_response);
    p_response = NULL;
    cpinResult = NULL;

    ret = SIM_READY;
    switch (s_Pin1State) {
        case RIL_PINSTATE_UNKNOWN: s_Pin1State = RIL_PINSTATE_DISABLED; break;
        case RIL_PINSTATE_ENABLED_NOT_VERIFIED:
        case RIL_PINSTATE_ENABLED_BLOCKED:
        // weird case !!!//
        case RIL_PINSTATE_ENABLED_PERM_BLOCKED: s_Pin1State = RIL_PINSTATE_ENABLED_VERIFIED; break;
        default: break;
    }

done:
    at_response_free(p_response);
    return ret;
}

static RIL_AppType getSIMType()
{
    ATResponse *p_response = NULL;
    int err;
    int ret = RIL_APPTYPE_UNKNOWN;
    char *cpinLine;
    char *cpinResult;
    char *line;

    LOGD("getSIMType(). sState: %d",sState);
    if (sState == RADIO_STATE_OFF 
        || sState == RADIO_STATE_UNAVAILABLE) {
        goto error;
    }

    err = at_send_command_singleline_min_timeout("AT^CARDMODE", "^CARDMODE:", &p_response);
    if (err < 0 || p_response->success == 0) {
        goto error;
    }

    line = p_response->p_intermediates->line;
    err = at_tok_start(&line);
    if (err < 0) goto error;

    err = at_tok_nextint(&line, &ret);
    if (err < 0) goto error;

error:

    at_response_free(p_response);
    return (RIL_AppType)ret;
}

/**
 * Get the current card status.
 *
 * This must be freed using freeCardStatus.
 * @return: On success returns RIL_E_SUCCESS
 */
static int getCardStatus(RIL_CardStatus_v6 **pp_card_status) {
    static RIL_AppStatus app_status_array[] = {
        // SIM_ABSENT = 0
        { RIL_APPTYPE_UNKNOWN, RIL_APPSTATE_UNKNOWN, RIL_PERSOSUBSTATE_UNKNOWN,
          NULL, NULL, 0, RIL_PINSTATE_UNKNOWN, RIL_PINSTATE_UNKNOWN },
        // SIM_NOT_READY = 1
        { RIL_APPTYPE_SIM, RIL_APPSTATE_DETECTED, RIL_PERSOSUBSTATE_UNKNOWN,
          NULL, NULL, 0, RIL_PINSTATE_UNKNOWN, RIL_PINSTATE_UNKNOWN },
        // SIM_READY = 2
        { RIL_APPTYPE_SIM, RIL_APPSTATE_READY, RIL_PERSOSUBSTATE_READY,
          NULL, NULL, 0, RIL_PINSTATE_UNKNOWN, RIL_PINSTATE_UNKNOWN },
        // SIM_PIN = 3
        { RIL_APPTYPE_SIM, RIL_APPSTATE_PIN, RIL_PERSOSUBSTATE_UNKNOWN,
          NULL, NULL, 0, RIL_PINSTATE_ENABLED_NOT_VERIFIED, RIL_PINSTATE_UNKNOWN },
        // SIM_PUK = 4
        { RIL_APPTYPE_SIM, RIL_APPSTATE_PUK, RIL_PERSOSUBSTATE_UNKNOWN,
          NULL, NULL, 0, RIL_PINSTATE_ENABLED_BLOCKED, RIL_PINSTATE_UNKNOWN },
        // SIM_NETWORK_PERSONALIZATION = 5
        { RIL_APPTYPE_SIM, RIL_APPSTATE_SUBSCRIPTION_PERSO, RIL_PERSOSUBSTATE_SIM_NETWORK,
          NULL, NULL, 0, RIL_PINSTATE_ENABLED_NOT_VERIFIED, RIL_PINSTATE_UNKNOWN },
        // RUIM_ABSENT = 6
        { RIL_APPTYPE_UNKNOWN, RIL_APPSTATE_UNKNOWN, RIL_PERSOSUBSTATE_UNKNOWN,
          NULL, NULL, 0, RIL_PINSTATE_UNKNOWN, RIL_PINSTATE_UNKNOWN },
        // RUIM_NOT_READY = 7
        { RIL_APPTYPE_RUIM, RIL_APPSTATE_DETECTED, RIL_PERSOSUBSTATE_UNKNOWN,
          NULL, NULL, 0, RIL_PINSTATE_UNKNOWN, RIL_PINSTATE_UNKNOWN },
        // RUIM_READY = 8
        { RIL_APPTYPE_RUIM, RIL_APPSTATE_READY, RIL_PERSOSUBSTATE_READY,
          NULL, NULL, 0, RIL_PINSTATE_UNKNOWN, RIL_PINSTATE_UNKNOWN },
        // RUIM_PIN = 9
        { RIL_APPTYPE_RUIM, RIL_APPSTATE_PIN, RIL_PERSOSUBSTATE_UNKNOWN,
          NULL, NULL, 0, RIL_PINSTATE_ENABLED_NOT_VERIFIED, RIL_PINSTATE_UNKNOWN },
        // RUIM_PUK = 10
        { RIL_APPTYPE_RUIM, RIL_APPSTATE_PUK, RIL_PERSOSUBSTATE_UNKNOWN,
          NULL, NULL, 0, RIL_PINSTATE_ENABLED_BLOCKED, RIL_PINSTATE_UNKNOWN },
        // RUIM_NETWORK_PERSONALIZATION = 11
        { RIL_APPTYPE_RUIM, RIL_APPSTATE_SUBSCRIPTION_PERSO, RIL_PERSOSUBSTATE_SIM_NETWORK,
           NULL, NULL, 0, RIL_PINSTATE_ENABLED_NOT_VERIFIED, RIL_PINSTATE_UNKNOWN }
    };
    RIL_CardState card_state;
    int num_apps;
    int sim_status = getSIMStatus();
    RIL_AppType sim_type = getSIMType();

    if (sim_status == SIM_ABSENT) {
        card_state = RIL_CARDSTATE_ABSENT;
        num_apps = 0;
    } else if (sim_status == SIM_IO_ERROR) {
        card_state = RIL_CARDSTATE_ERROR;
        num_apps = 0;
    } else if (sim_status == SIM_NOT_READY) {
        card_state = RIL_CARDSTATE_ERROR;
        num_apps = 0;
    } else {
        card_state = RIL_CARDSTATE_PRESENT;
        //num_apps = 2;
        num_apps = 1;
    }

    // Allocate and initialize base card status.
    RIL_CardStatus_v6 *p_card_status = malloc(sizeof(RIL_CardStatus_v6));
    p_card_status->card_state = card_state;
    p_card_status->universal_pin_state = RIL_PINSTATE_UNKNOWN;
    p_card_status->gsm_umts_subscription_app_index = RIL_CARD_MAX_APPS;
    //p_card_status->cdma_subscription_app_index = RIL_CARD_MAX_APPS;
    p_card_status->cdma_subscription_app_index = -1;
    p_card_status->ims_subscription_app_index = RIL_CARD_MAX_APPS;
    p_card_status->num_applications = num_apps;

    // Initialize application status
    int i;
    for (i = 0; i < RIL_CARD_MAX_APPS; i++) {
        p_card_status->applications[i] = app_status_array[SIM_ABSENT];
    }

    // Pickup the appropriate application status
    // that reflects sim_status for gsm.
    if (num_apps != 0) {
        //p_card_status->num_applications = 2;
        p_card_status->num_applications = num_apps;
        p_card_status->gsm_umts_subscription_app_index = 0;
        //p_card_status->cdma_subscription_app_index = 1;
        p_card_status->cdma_subscription_app_index = -1;

        // Get the correct app status
        p_card_status->applications[0] = app_status_array[sim_status];
        //p_card_status->applications[1] = app_status_array[sim_status + RUIM_ABSENT];
        p_card_status->applications[0].app_type = sim_type;
        p_card_status->applications[0].pin1 = s_Pin1State;

        // get PIN2 state only when PIN1 is ready //
        if (s_Pin1State == RIL_PINSTATE_ENABLED_VERIFIED 
                || s_Pin1State == RIL_PINSTATE_DISABLED) {
            int residualcount = 0;
            RIL_PinState pin2state = RIL_PINSTATE_UNKNOWN;

            // PIN2 locked ? //
            residualcount = requestPinResidualCount("P2", 0);
            if (residualcount == 0) pin2state = RIL_PINSTATE_ENABLED_BLOCKED;
            // PUK2 locked ? //
            residualcount = requestPinResidualCount("P2", 1);
            if (residualcount == 0) pin2state = RIL_PINSTATE_ENABLED_PERM_BLOCKED;
            p_card_status->applications[0].pin2 = pin2state;
        }
    }

    *pp_card_status = p_card_status;
    return RIL_E_SUCCESS;
}

/**
 * Free the card status returned by getCardStatus
 */
static void freeCardStatus(RIL_CardStatus_v6 *p_card_status) {
    free(p_card_status);
}

/**
 * SIM ready means any commands that access the SIM will work, including:
 *  AT+CPIN, AT+CSMS, AT+CNMI, AT+CRSM
 *  (all SMS-related commands)
 */

static void pollSIMState(void *param, RIL_Token t)
{
    switch(getSIMStatus()) {
        case SIM_ABSENT:
        case SIM_PIN:
        case SIM_PUK:
        case SIM_NETWORK_PERSONALIZATION:
        default:
            LOGI("SIM ABSENT or LOCKED");
            //RIL_onUnsolicitedResponse(RIL_UNSOL_RESPONSE_SIM_STATUS_CHANGED, NULL, 0);
            // Modified by CYIT 20130130 for change SIM state by interface setRadioState while PIN setting
            setRadioState(RADIO_STATE_SIM_LOCKED_OR_ABSENT);
            v_cardState = 0;
            break;

        case SIM_NOT_READY:
            ////RIL_requestTimedCallback (pollSIMState, NULL, &TIMEVAL_SIMPOLL);
            RIL_requestTimedCallback(RIL_TIME_REQUEST_POLL_SIM_STATE, NULL, &TIMEVAL_SIMPOLL);
            break;

        case SIM_READY:
            LOGI("SIM_READY");
            // if sim status is not ready in 1st time, may not return here //
            // so move onSIMReady before pollSIMState //
            //onSIMReady();
            RIL_onUnsolicitedResponse(RIL_UNSOL_RESPONSE_SIM_STATUS_CHANGED, NULL, 0);
            break;
    }

    if (t) RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
}

/** returns 1 if on, 0 if off, and -1 on error */
static int isRadioOn()
{
    ATResponse *p_response = NULL;
    int err;
    char *line;
    char ret;

    err = at_send_command_singleline_min_timeout("AT+CFUN?", "+CFUN:", &p_response);

    if (err < 0 || p_response->success == 0) {
        // assume radio is off
        goto error;
    }

    line = p_response->p_intermediates->line;

    err = at_tok_start(&line);
    if (err < 0) goto error;

    err = at_tok_nextbool(&line, &ret);
    if (err < 0) goto error;

    at_response_free(p_response);

    return (int)ret;

error:

    at_response_free(p_response);
    return -1;
}

/**
 * Parse the response generated by a +CTEC AT command
 * The values read from the response are stored in current and preferred.
 * Both current and preferred may be null. The corresponding value is ignored in that case.
 *
 * @return: -1 if some error occurs (or if the modem doesn't understand the +CTEC command)
 *          1 if the response includes the current technology only
 *          0 if the response includes both current technology and preferred mode
 */
int parse_technology_response( const char *response, int *current, int32_t *preferred )
{
    int err;
    char *line, *p;
    //int ct;
    int32_t pt = 0;
    //char *str_pt;
    int num1, num2;

    line = p = strdup(response);
    LOGD("Response: %s", line);
    err = at_tok_start(&p);
    if (err || !at_tok_hasmore(&p)) {
        LOGD("err: %d. p: %s", err, p);
        free(line);
        return -1;
    }

    //err = at_tok_nextint(&p, &ct);
    err = at_tok_nextint(&p, &num1);
    if (err) {
        free(line);
        return -1;
    }
    //if (current) *current = ct;

    LOGD("line remaining after int: %s", p);

    //err = at_tok_nexthexint(&p, &pt);
    err = at_tok_nextint(&p, &num2);
    if (err) {
        free(line);
        //return 1;
        // Only get preferred currently //
        return -1;
    }
    
    if (preferred) {
        //*preferred = pt;
        if (num1 == 13 && num2 == 1) *preferred = MDM_GSM;
        if (num1 == 15 && num2 == 2 ) *preferred = MDM_TD;
        if (num1 == 2 && num2 == 1) *preferred = (MDM_GSM << 8) | MDM_TD;
        if (num1 == 2 && num2 == 2) *preferred = (MDM_TD << 8) | MDM_GSM;
    }
    free(line);

    return 0;
}

int query_supported_techs( ModemInfo *mdm, int *supported )
{
    ATResponse *p_response = NULL;
    int err, val, techs = 0;
    char *tok;
    char *line;

    LOGD("query_supported_techs");
    err = at_send_command_singleline("AT+CTEC=?", "+CTEC:", &p_response);
    if (err || !p_response->success)
        goto error;
    line = p_response->p_intermediates->line;
    err = at_tok_start(&line);
    if (err || !at_tok_hasmore(&line))
        goto error;
    while (!at_tok_nextint(&line, &val)) {
        techs |= ( 1 << val );
    }
    if (supported) *supported = techs;
    at_response_free(p_response);
    return 0;
error:
    at_response_free(p_response);
    return -1;
}

/**
 * query_ctec. Send the +CTEC AT command to the modem to query the current
 * and preferred modes. It leaves values in the addresses pointed to by
 * current and preferred. If any of those pointers are NULL, the corresponding value
 * is ignored, but the return value will still reflect if retreiving and parsing of the
 * values suceeded.
 *
 * @mdm Currently unused
 * @current A pointer to store the current mode returned by the modem. May be null.
 * @preferred A pointer to store the preferred mode returned by the modem. May be null.
 * @return -1 on error (or failure to parse)
 *         1 if only the current mode was returned by modem (or failed to parse preferred)
 *         0 if both current and preferred were returned correctly
 */
int query_ctec(ModemInfo *mdm, int *current, int32_t *preferred)
{
    ATResponse *response = NULL;
    int err;
    int res;

    LOGD("query_ctec. current: %d, preferred: %d", (int)current, (int) preferred);
    //err = at_send_command_singleline("AT+CTEC?", "+CTEC:", &response);
    err = at_send_command_singleline("AT^STMC?", "^STMC:", &response);
    if (!err && response->success) {
        res = parse_technology_response(response->p_intermediates->line, current, preferred);
        at_response_free(response);
        return res;
    }
    LOGE("Error executing command: %d. response: %x. status: %d", err, (int)response, response? response->success : -1);
    at_response_free(response);
    return -1;
}

int is_multimode_modem(ModemInfo *mdm)
{
    ATResponse *response;
    int err;
    char *line;
    int tech;
    int32_t preferred;

    if (query_ctec(mdm, &tech, &preferred) == 0) {
        mdm->currentTech = tech;
        mdm->preferredNetworkMode = preferred;
        if (query_supported_techs(mdm, &mdm->supportedTechs)) {
            return 0;
        }
        return 1;
    }
    return 0;
}

/**
 * Find out if our modem is GSM, CDMA or both (Multimode)
 */
static void probeForModemMode(ModemInfo *info)
{
    ATResponse *response = NULL;
    int err;
    assert (info);
    // Currently, our only known multimode modem is qemu's android modem,
    // which implements the AT+CTEC command to query and set mode.
    // Try that first

    /*
    if (is_multimode_modem(info)) {
        LOGI("Found Multimode Modem. Supported techs mask: %8.8x. Current tech: %d",
            info->supportedTechs, info->currentTech);
        return;
    }
    */

    /* Being here means that our modem is not multimode */
    info->isMultimode = 0;

    /* CDMA Modems implement the AT+WNAM command */
    err = at_send_command_singleline("AT+WNAM","+WNAM:", &response);
    if (!err && response->success) {
        at_response_free(response);
        // TODO: find out if we really support EvDo
        info->supportedTechs = MDM_CDMA | MDM_EVDO;
        info->currentTech = MDM_CDMA;
        LOGI("Found CDMA Modem");
        return;
    }
    if (!err) at_response_free(response);
    // TODO: find out if modem really supports WCDMA/LTE
    //info->supportedTechs = MDM_GSM | MDM_WCDMA | MDM_LTE;
    info->supportedTechs = MDM_GSM | MDM_TD | MDM_LTE;
    info->currentTech = -1;
    LOGI("Found GSM Modem");
}

/**
 * Initialize everything that can be configured while we're still in
 * AT+CFUN=0
 */
static void initializeCallback(void *param, RIL_Token t)
{
    ATResponse *p_response = NULL;
    int err;

    setRadioState (RADIO_STATE_OFF);

    at_handshake();

    probeForModemMode(sMdmInfo);
    /* note: we don't check errors here. Everything important will
       be handled in onATTimeout and onATReaderClosed */

    /*  atchannel is tolerant of echo but it must */
    /*  have verbose result codes */
    // Format the AT string //

    s_basebandReadyFlag = 1;
//    s_timeoutFlag = 1;

     at_send_command_min_timeout( "ATE0", NULL );
     at_send_command_min_timeout( "ATV1", NULL );
     at_send_command_min_timeout( "AT+CSCS=\"UCS2\"", NULL );
     at_send_command_min_timeout( "AT+COPS=3,2", NULL );
     at_send_command_min_timeout( "AT+CMEE=1", NULL );
     at_send_command_min_timeout( "AT^SUSS=1", NULL );
     at_send_command_min_timeout( "AT+CGCLASS=\"A\"", NULL );

     at_send_command_min_timeout( "AT^SPSL=1", NULL );// modify by CYIT 20121009

     // STK/USAT function initial
     at_send_command_min_timeout( "AT^SSTSP=1,\"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\"", NULL );
     at_send_command_min_timeout( "AT^SSTPC=1", NULL );
     at_send_command_min_timeout( "AT^SSTES=1", NULL );
     // modify by CYIT 20110806         ----- start -----
     at_send_command_min_timeout( "AT^SSTRF=1", NULL );
     // modify by CYIT 20110806         -----  end  -----
 
     // Set URC mode //
 
     at_send_command_min_timeout( "AT+CGEREP=2,0", NULL );
     //at_send_command( "AT+CMER=1,0,0,2", NULL );
     //at_send_command( "AT+CLIP=1", NULL );
     //at_send_command( "AT+CRC=1", NULL );
     //at_send_command( "AT+CR=0", NULL );
     at_send_command_min_timeout( "AT+CUSD=1", NULL );
     at_send_command_min_timeout( "AT+CCWA=1", NULL );
     //at_send_command( "AT^SPIN=0", NULL );
     //at_send_command( "AT^SOPS=0", NULL );
     at_send_command_min_timeout( "AT^SINIT=1", NULL );
     at_send_command_min_timeout( "AT^SCKS=1", NULL );
     //at_send_command( "AT^SRABI=1", NULL );
     at_send_command_min_timeout( "AT^SSTMY=1", NULL );
     at_send_command_min_timeout( "AT^DSCI=1", NULL );
      // modify by CYIT 20121025         ----- start -----
     at_send_command_min_timeout( "AT+CPLS=0", NULL );
      // modify by CYIT 20121025         -----  end  -----

#ifdef USE_TI_COMMANDS

    at_send_command("AT%CPI=3", NULL);

    /*  TI specific -- notifications when SMS is ready (currently ignored) */
    at_send_command("AT%CSTAT=1", NULL);

#endif /* USE_TI_COMMANDS */


    /* assume radio is off on error */
    if (isRadioOn() > 0) {
        //setRadioState (RADIO_STATE_ON);
        setRadioState (RADIO_STATE_SIM_NOT_READY);
        v_cardState = 0;
    }

    RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
}

static void waitForClose()
{
    pthread_mutex_lock(&s_state_mutex);

    while (s_closed == 0) {
        pthread_cond_wait(&s_state_cond, &s_state_mutex);
    }

    pthread_mutex_unlock(&s_state_mutex);
}

/**
 * Called by atchannel when an unsolicited line appears
 * This is called on atchannel's reader thread. AT commands may
 * not be issued here
 */
static void onUnsolicited (const char *s, const char *sms_pdu)
{
    char *line = NULL, *p;
    int err;

    LOGD("URC: %s", s);

    /* Ignore unsolicited responses until we're initialized.
     * This is OK because the RIL library will poll for initial state
     */
    if ( sState == RADIO_STATE_UNAVAILABLE )
    {
        LOGD("radio unavailable ignored URC");
        return;
    }

    if ( strStartsWith( s, "%CTZV:" ) )
    {
        /* TI specific -- NITZ time */
        char *response;

        line = p = strdup(s);
        at_tok_start(&p);
        err = at_tok_nextstr(&p, &response);
        if ( err != 0 )
        {
            LOGE("invalid NITZ line %s\n", s);
        }
        else
        {
            RIL_onUnsolicitedResponse( RIL_UNSOL_NITZ_TIME_RECEIVED, response,
                    strlen( response ) );
        }
        
        free(line);
    }
//    else if (strStartsWith(s,"+CRING:")
//                || strStartsWith(s,"RING")
//                || strStartsWith(s,"NO CARRIER")
//                || strStartsWith(s,"+CCWA")
//    ) {
//        RIL_onUnsolicitedResponse (
//            RIL_UNSOL_RESPONSE_CALL_STATE_CHANGED,
//            NULL, 0);
//#ifdef WORKAROUND_FAKE_CGEV
//        RIL_requestTimedCallback (onDataCallListChanged, NULL, NULL); //TODO use new function
//#endif /* WORKAROUND_FAKE_CGEV */
//    }
    else if (strStartsWith(s, "^DSCI:")) {
        int calltype;
        int state;
        int skip;
        int callid;

        line = p = strdup(s);
        at_tok_start(&p);
        err = at_tok_nextint(&p, &callid);
        if (err != 0) goto error;
        err = at_tok_nextint(&p, &skip);
        if (err != 0) goto error;
        err = at_tok_nextint(&p, &state);
        if (err != 0) goto error;
        err = at_tok_nextint(&p, &calltype);
        if (err != 0) goto error;

#ifdef USE_CYIT_FRAMEWORK

        if (calltype == 0 && state == 4) {
            s_RingID = callid;
        }

        if (calltype == 0 && state != 4) {
            if (s_RingID == callid) s_RingID = 0;
            RIL_onUnsolicitedResponse (
                RIL_UNSOL_RESPONSE_CALL_STATE_CHANGED,
                NULL, 0);
        }

#else

        if (calltype == 0) {
            RIL_onUnsolicitedResponse (
                    RIL_UNSOL_RESPONSE_CALL_STATE_CHANGED,
                    NULL, 0);
        }

#endif

error:
        free(line);
    }// else if (strStartsWith(s,"+CREG:")
               // || strStartsWith(s,"+CGREG:") 
    else if (strStartsWith(s,"+CREG:")) {
        int        state = -1;

        line = p = strdup(s);
        if (!line) {
            LOGE("+CREG: Unable to allocate memory");
            return;
        }

        if (at_tok_start(&p) < 0) goto creg_error;
        if (at_tok_nextint(&p, &state) < 0) goto creg_error;
        if(state != 7){
            RIL_onUnsolicitedResponse (
                RIL_UNSOL_RESPONSE_VOICE_NETWORK_STATE_CHANGED,
                NULL, 0);
    #ifdef WORKAROUND_FAKE_CGEV
            //RIL_requestTimedCallback (onDataCallListChanged, NULL, NULL);
            RIL_requestTimedCallback(RIL_TIME_REQUEST_DATA_CALL_LIST, NULL, NULL);
    #endif /* WORKAROUND_FAKE_CGEV */
        //} else if (strStartsWith(s,"+CGREG:")) {
        //    RIL_onUnsolicitedResponse (
        //        RIL_UNSOL_RESPONSE_DATA_NETWORK_STATE_CHANGED,
        //        NULL, 0);
        }
        return;

creg_error:
        LOGE("invalid +CREG/CGREG response: %s", line);
        free(line);
    } else if (strStartsWith(s, "+CMT:"))
    {
        RIL_onUnsolicitedResponse (
            RIL_UNSOL_RESPONSE_NEW_SMS,
            sms_pdu, strlen(sms_pdu));
    }
    // ----------------------------------------------------------------
    // modify by CYIT 20111017 ----- start -----
    // ----------------------------------------------------------------
    else if (strStartsWith(s, "+CMTI:"))
    {
        char      *skip = 0;
        int        index = -1;

        line = p = strdup(s);
        if (!line) {
            LOGE("+CMTI: Unable to allocate memory");
            return;
        }

        if (at_tok_start(&p) < 0) goto cmti_error;
        if (at_tok_nextstr(&p, &skip) < 0) goto cmti_error;
        if (at_tok_nextint(&p, &index) < 0) goto cmti_error;

        RIL_onUnsolicitedResponse(RIL_UNSOL_RESPONSE_NEW_SMS_ON_SIM, &index, sizeof(int *));
        free(line);
        return;

cmti_error:
        LOGE("invalid +CMTI response: %s", line);
        free(line);
    } 
    // ----------------------------------------------------------------
    // modify by CYIT 20111017 -----  end  -----
    // ----------------------------------------------------------------
    else if ( strStartsWith( s, "+CDS:" ) )
    {
        RIL_onUnsolicitedResponse (
            RIL_UNSOL_RESPONSE_NEW_SMS_STATUS_REPORT,
            sms_pdu, strlen(sms_pdu));
    }
    else if ( strStartsWith( s, "+CGEV:" ) )
    {
        /* Really, we can ignore NW CLASS and ME CLASS events here,
         * but right now we don't since extranous
         * RIL_UNSOL_DATA_CALL_LIST_CHANGED calls are tolerated
         */
        /* can't issue AT commands here -- call on main thread */
        //RIL_requestTimedCallback (onDataCallListChanged, NULL, NULL);
        RIL_requestTimedCallback(RIL_TIME_REQUEST_DATA_CALL_LIST, NULL, NULL);
#ifdef WORKAROUND_FAKE_CGEV
    }
    else if (strStartsWith(s, "+CME ERROR: 150"))
    {
        //RIL_requestTimedCallback (onDataCallListChanged, NULL, NULL);
        RIL_requestTimedCallback(RIL_TIME_REQUEST_DATA_CALL_LIST, NULL, NULL);
#endif /* WORKAROUND_FAKE_CGEV */

    }
	 /*else if (strStartsWith(s, "+CTEC: ")) {
        int tech, mask;
        switch (parse_technology_response(s, &tech, NULL))
        {
            case -1: // no argument could be parsed.
                LOGE("invalid CTEC line %s\n", s);
                break;
            case 1: // current mode correctly parsed
            case 0: // preferred mode correctly parsed
                mask = 1 << tech;
                if (mask != MDM_GSM && mask != MDM_CDMA &&
                     mask != MDM_WCDMA && mask != MDM_LTE) {
                    LOGE("Unknown technology %d\n", tech);
                } else {
                    setRadioTechnology(sMdmInfo, tech);
                }
                break;
        }
    }*/ else if (strStartsWith(s, "+CCSS: ")) {
        int source = 0;
        line = p = strdup(s);
        if (!line) {
            LOGE("+CCSS: Unable to allocate memory");
            return;
        }
        if (at_tok_start(&p) < 0) {
            free(line);
            return;
        }
        if (at_tok_nextint(&p, &source) < 0) {
            LOGE("invalid +CCSS response: %s", line);
            free(line);
            return;
        }
        SSOURCE(sMdmInfo) = source;
        RIL_onUnsolicitedResponse(RIL_UNSOL_CDMA_SUBSCRIPTION_SOURCE_CHANGED, &source, sizeof(int *));
    } else if (strStartsWith(s, "+WSOS: ")) {
        char state = 0;
        int unsol;
        line = p = strdup(s);
        if (!line) {
            LOGE("+WSOS: Unable to allocate memory");
            return;
        }
        if (at_tok_start(&p) < 0) {
            free(line);
            return;
        }
        if (at_tok_nextbool(&p, &state) < 0) {
            LOGE("invalid +WSOS response: %s", line);
            free(line);
            return;
        }

        unsol = state ?
                RIL_UNSOL_ENTER_EMERGENCY_CALLBACK_MODE : RIL_UNSOL_EXIT_EMERGENCY_CALLBACK_MODE;

        RIL_onUnsolicitedResponse(unsol, NULL, 0);
        free(line);
    } else if (strStartsWith(s, "+WPRL: ")) {
        int version = -1;
        line = p = strdup(s);
        if (!line) {
            LOGE("+WPRL: Unable to allocate memory");
            return;
        }
        if (at_tok_start(&p) < 0) {
            LOGE("invalid +WPRL response: %s", s);
            free(line);
            return;
        }
        if (at_tok_nextint(&p, &version) < 0) {
            LOGE("invalid +WPRL response: %s", s);
            free(line);
            return;
        }
        
        RIL_onUnsolicitedResponse(RIL_UNSOL_CDMA_PRL_CHANGED, &version, sizeof(version));
        free(line);
    } else if (strStartsWith(s, "+CFUN: 0")) {
        setRadioState(RADIO_STATE_OFF);
        v_cardState = 0;
    }
    // -------------------------------------------------------------
    //   modify by CYIT 20110806        ----- start -----
    // -------------------------------------------------------------
    else if ( strStartsWith( s, "^SSTPC:" ) )
    {
        char *stkProcmd = NULL;
        char *cmdType = NULL;
        int   skip;

        line = p = strdup( s );
        err = at_tok_start( &p );
        if ( err < 0 )
            goto error_SSTPC;
        err = at_tok_nextstr( &p, &cmdType );
        if ( err < 0 )
            goto error_SSTPC;
        err = at_tok_nextint( &p, &skip );
        if ( err < 0 )
            goto error_SSTPC;
        err = at_tok_nextint( &p, &skip );
        if ( err < 0 )
            goto error_SSTPC;
        err = at_tok_nextint( &p, &skip );
        if ( err < 0 )
            goto error_SSTPC;
        err = at_tok_nextstr( &p, &stkProcmd );
        if ( err < 0 )
            goto error_SSTPC;
        LOGD("ATparser stk/usat Procmd: %s", stkProcmd);

        if(strlen(cmdType) == 0x02 && (!memcmp(cmdType, "RF", 2)))
        {
            LOGD("ATparser stk/usat Procmd RIL_UNSOL_STK_EVENT_NOTIFY");
            // refresh command not need to response TERMINAL_RESPONSE
            RIL_onUnsolicitedResponse(RIL_UNSOL_STK_EVENT_NOTIFY, stkProcmd,sizeof(stkProcmd));
        }
        else
        {
            LOGD("ATparser stk/usat Procmd RIL_UNSOL_STK_PROACTIVE_COMMAND");
            RIL_onUnsolicitedResponse(RIL_UNSOL_STK_PROACTIVE_COMMAND, stkProcmd, sizeof(stkProcmd));
        }
        free(line);

        return;

error_SSTPC: 
        
        LOGE("invalid SSTPC line: %s\n", s);
        free(line);
    }
    else if ( strStartsWith( s, "^SSTES:" ) )
    {
        // modify by CYIT 20111226 ----- start -----
        int endType;
        char *skip;

        line = p = strdup(s);
        if (!line) {
            LOGE("^SSTES: Unable to allocate memory");
            return;
        }
        if (at_tok_start(&p) < 0) goto sstes_error;
        if (at_tok_nextstr(&p, &skip) < 0) goto sstes_error;
        if (at_tok_nextstr(&p, &skip) < 0) goto sstes_error;
        if (at_tok_nextstr(&p, &skip) < 0) goto sstes_error;
        if (at_tok_nextint(&p, &endType) < 0) goto sstes_error;

        RIL_onUnsolicitedResponse( RIL_UNSOL_STK_SESSION_END, &endType, sizeof(int *) );
        free(line);
        return;
sstes_error:
        LOGE("invalid ^SSTES response: %s", line);
        free(line);
        // modify by CYIT 20111226 -----  end  -----
    }
    else if ( strStartsWith( s, "^SSTRF:" ) )
    {
        RIL_SimRefreshResponse   *simRefresh = NULL;
        int   mode;
        int   fileNum = 0x00;
        char *fileId = NULL;
        
        simRefresh = (RIL_SimRefreshResponse *)alloca(sizeof(RIL_SimRefreshResponse));
        memset(simRefresh, 0x00, sizeof(RIL_SimRefreshResponse));

        line = p = strdup( s );
        err = at_tok_start( &p );
        if(err < 0)
            goto error_SSTRF;

        err = at_tok_nextint( &p, &mode );
        if(err < 0)
            goto error_SSTRF;
        simRefresh->result = mode;

        err = at_tok_nextint( &p, &fileNum );
        if(err < 0) LOGD("refresh file number = 0x00");
        simRefresh->efIdNum = fileNum;

        if(fileNum)
        {
            simRefresh->ef_id = alloca(fileNum * sizeof(int));
            memset(simRefresh->ef_id, 0x00, fileNum * sizeof(int));

            err = at_tok_nextstr( &p, &fileId );
            if(err < 0 || ((fileNum * 4) != strlen(fileId)))
                goto error_SSTRF;

            char i = 0x00, pos = 0x00;
            for(i = 0x00; i < fileNum; i++)
            {
                char charNum = 0x01;
                unsigned short v_frsBits = 0x0000;
                unsigned short v_SecBits = 0x0000;
                unsigned short v_trdBits = 0x0000;
                short v_fthBits = 0x0000;
                while(charNum <= 0x04)
                {
                    unsigned short temp = fileId[pos];
                    if(temp >= 0x30 && temp <= 0x39)
                    {
                        if((pos % 0x04) == 0x00)
                        {
                            v_frsBits = (((short)temp - 0x30) & 0x000F) << 12;
                        }
                        else if((pos % 0x04) == 0x01)
                        {
                            v_SecBits = (((short)temp - 0x30) & 0x000F) << 8;
                        }
                        else if((pos % 0x04) == 0x02)
                        {
                            v_trdBits = (((short)temp - 0x30) & 0x000F) << 4;
                        }
                        else if((pos % 0x04) == 0x03)
                        {
                            v_fthBits = (((short)temp - 0x30) & 0x000F);
                        }
                    }
                    else if(temp >= 0x41 && temp <= 0x46)
                    {
                        if((pos % 0x04) == 0x00)
                        {
                            v_frsBits = (((short)temp - 0x37) & 0x000F) << 12;
                        }
                        else if((pos % 0x04) == 0x01)
                        {
                            v_SecBits = (((short)temp - 0x37) & 0x000F) << 8;
                        }
                        else if((pos % 0x04) == 0x02)
                        {
                            v_trdBits = (((short)temp - 0x37) & 0x000F) << 4;
                        }
                        else if((pos % 0x04) == 0x03)
                        {
                            v_fthBits = (((short)temp - 0x37) & 0x000F);
                        }
                    }
                    else
                    {
                        LOGE("invalid SSTRF fileId[%d] value = %c", pos, (char)temp);
                        goto error_SSTRF;
                    }

                    pos++;
                    charNum++;
                }

                (simRefresh->ef_id)[i] = (int)(v_frsBits | v_SecBits | v_trdBits | v_fthBits);
            }
        }
        
        RIL_onUnsolicitedResponse( RIL_UNSOL_SIM_REFRESH, simRefresh, sizeof(RIL_SimRefreshResponse) );
        free(line);
        return;
        
error_SSTRF:
        LOGE("invalid SSTRF line: %s\n", s);
        free(line);
    }
    // -------------------------------------------------------------
    //   modify by CYIT 20110806         -----  end  -----
    // -------------------------------------------------------------
    // -------------------------------------------------------------
    //   modify by CYIT 20110819             ----- start -----
    // -------------------------------------------------------------
    else if ( strStartsWith( s, "+CUSD:" ) )
    {
        int err;
        int m = 0, dcs = 0;
        char *response[3];
        static char mResponse[] = "0000";
        static char dcsResponse[] = "0000";

        line = strdup( s );
        at_tok_start( &line );
        err = at_tok_nextint( &line, &m );
        if(err < 0)
        {
            LOGE("invalid +cusd reason = %d\n", m);
            goto error_CUSD;
        }

        sprintf( mResponse, "%d", m );
        response[0] = mResponse;
        if ( at_tok_hasmore( &line ) )
        {
            err = at_tok_nextstr( &line, &( response[1] ) );
            if(err < 0)
            {
                LOGE("invalid cusd str = %s\n", response[1]);
                goto error_CUSD;
            }

            err = at_tok_nextint( &line, &dcs );
            if(err < 0)
            {
                LOGE("invalid cusd dcs = %d\n", dcs);
                goto error_CUSD;
            }
            sprintf( dcsResponse, "%d", dcs );
            response[2] = dcsResponse;
        }
        else
        {
            response[1] = NULL;

            dcs = 0xFF;
            sprintf( dcsResponse, "%d", dcs );
            response[2] = dcsResponse;
        }

        RIL_onUnsolicitedResponse(RIL_UNSOL_ON_USSD, response, sizeof(response));
        return;

error_CUSD:
        free(line);
    }
    // -------------------------------------------------------------
    //   modify by CYIT 20110819             -----  end  -----
    // -------------------------------------------------------------
    else if (strStartsWith(s, "^SINIT:")) {
        char *inittype = NULL;
        char type[] = "PHONEBOOK";
        int initstate = 0;

        line = p = strdup(s);
        err = at_tok_start(&p);
        if (err < 0) goto error_sinit;
        err = at_tok_nextstr(&p, &inittype);
        if (err < 0) goto error_sinit;
        err = at_tok_nextint(&p, &initstate);
        if (err < 0) goto error_sinit;

        if (strncmp(type, inittype, strlen(type)) == 0
                && initstate == 2) { // notify phonebook init state to update FDN facility lock //
            RIL_onUnsolicitedResponse(RIL_UNSOL_PB_INIT_OVER, NULL, 0);
        }

error_sinit:
        free(line);
    }

    else if (strStartsWith(s, "^SCKS:")) 
    {
        int   simState = 0x00;

        line = p = strdup( s );
        err = at_tok_start( &p );
        if(err < 0) goto error_SCKS;

        err = at_tok_nextint( &p, &simState );
        if(err < 0) goto error_SCKS;

        if(simState != 1)
        {
            RIL_onUnsolicitedResponse(RIL_UNSOL_RESPONSE_SIM_STATUS_CHANGED, NULL, 0);
        }

error_SCKS:
        free(line);
    }
    // modify by CYIT 20121009  ----- start -----
    else if (strStartsWith(s, "^SPSL:")) 
    {
        int   networkNum = 0x00;
        int   act;
        char *longOper = NULL;
        char *shortOper = NULL;
        char *numOper = NULL;
        int   i = 0x00;

        line = p = strdup( s );
        err = at_tok_start( &p );
        if(err < 0) goto error_SPSL;

        err = at_tok_nextint( &p, &networkNum );
        if(err < 0) goto error_SPSL;

        if(networkNum)
        {
            char *response[4 * networkNum];

            for(i = 0x00; i < networkNum; i++)
            {

                for (; *p != '\0'; p++) {
                    if (*p == '"') break;
                }

                err = at_tok_nextstr( &p, &response[4 * i + 0] ); // long alpha oper
                if(err < 0) goto error_SPSL;

                err = at_tok_nextstr( &p, &response[4 * i + 1] ); // short alpha oper
                if(err < 0) goto error_SPSL;

                err = at_tok_nextstr( &p, &response[4 * i + 2] ); // numeric alpha oper
                if(err < 0) goto error_SPSL;

                if ( at_tok_hasmore( &line ) )
                {
                    err = at_tok_nextint( &p, &act ); // access technology
                    if(err < 0) goto error_SPSL;

                    if (0 == act) asprintf(&response[4 * i + 3], "%s", "0");
                    else if (1 == act) asprintf(&response[4 * i + 3], "%s", "1");
                    else if (2 == act) asprintf(&response[4 * i + 3], "%s", "2");
                    else if (3 == act) asprintf(&response[4 * i + 3], "%s", "3");
                    else if (4 == act) asprintf(&response[4 * i + 3], "%s", "4");
                    else if (5 == act) asprintf(&response[4 * i + 3], "%s", "5");
                    else if (6 == act) asprintf(&response[4 * i + 3], "%s", "6");
                    else if (7 == act) asprintf(&response[4 * i + 3], "%s", "7");
                    else
                    {
                        for ( ; i >= 0; i--) {
                            free(response[4 * i + 3]);
                        }
                        goto error_SPSL;
                    }
                }
                else
                {
                
                    asprintf(&response[4 * i + 3], "%s", "FF");
                    
                }
            }

            RIL_onUnsolicitedResponse( RIL_UNSOL_NETWORK_LIST, response, sizeof(char *) * 4 * networkNum );
            for (i = 0; i < networkNum; i++) {
                free(response[4 * i + 3]);
            }
            free(line);
            return;
        }

error_SPSL:
        LOGE("invalid SPSL line: %s\n", s);
        free(line);
    }
    // modify by CYIT 20121009  -----  end  -----
}

/* Called on command or reader thread */
static void onATReaderClosed()
{
    LOGI("AT channel closed\n");
    at_close();
    s_closed = 1;

    setRadioState (RADIO_STATE_UNAVAILABLE);
    v_cardState = 0;
}

/* Called on command thread */
static void onATTimeout()
{
    LOGI("AT channel timeout; closing\n");
    at_close();

    s_closed = 1;

    /* FIXME cause a radio reset here */

    setRadioState (RADIO_STATE_UNAVAILABLE);
    v_cardState = 0;
}

static void usage(char *s)
{
#ifdef RIL_SHLIB
    fprintf(stderr, "reference-ril requires: -p <tcp port> or -d /dev/tty_device\n");
#else
    fprintf(stderr, "usage: %s [-p <tcp port>] [-d /dev/tty_device]\n", s);
    exit(-1);
#endif
}

static void *
mainLoop(void *param)
{
    int fd;
    int ret;
    int fds[2];
    int i = 0;

    LOGE("== entering mainLoop()");
    at_set_on_reader_closed(onATReaderClosed);
    at_set_on_timeout(onATTimeout);

    for (;;) {
        fd = -1;
        while  (fd < 0) {
            if (s_port > 0) {
                fd = socket_loopback_client(s_port, SOCK_STREAM);
            } else if (s_device_socket) {
                if (!strcmp(s_device_path, "/dev/socket/qemud")) {
                    // Qemu-specific control socket //
                    fd = socket_local_client( "qemud",
                                              ANDROID_SOCKET_NAMESPACE_RESERVED,
                                              SOCK_STREAM );
                    if (fd >= 0 ) {
                        char  answer[2];

                        if ( write(fd, "gsm", 3) != 3 ||
                             read(fd, answer, 2) != 2 ||
                             memcmp(answer, "OK", 2) != 0)
                        {
                            close(fd);
                            fd = -1;
                        }
                   }
                }
                else
                    fd = socket_local_client( s_device_path,
                                            ANDROID_SOCKET_NAMESPACE_FILESYSTEM,
                                            SOCK_STREAM );
            } else if (s_device_path != NULL) {
#ifdef GSM_MUX_CHANNEL	//这个打开的，所以设置fd= 0x00
                char s_muxEnable[1];
                property_get("gsm0710mux.muxing", s_muxEnable, "0");
                LOGE ("open MUX device : s_muxEnable = %s\n", s_muxEnable);
                if(!memcmp( s_muxEnable, "1", 1)){
                    fd = 0x00;		//fd == 0x00
                }else{
                    fd = -1;
                }
#else
                fd = open (s_device_path, O_RDWR);
                if ( fd >= 0 && (!memcmp( s_device_path, "/dev/ttyUSB", 11 ))) {
                    /* disable echo on serial ports */
                    struct termios  ios;
                    tcgetattr( fd, &ios );

                    ios.c_lflag = 0;  /* disable ECHO, ICANON, etc... */
                    ios.c_oflag &= ~OCRNL;
                    ios.c_iflag &= ~ICRNL;
                    ios.c_iflag &= ~(INLCR | ICRNL | IGNCR);
                    ios.c_oflag &= ~(ONLCR | OCRNL);
                    tcsetattr( fd, TCSANOW, &ios );
                } else if ( fd >= 0 && !memcmp( s_device_path, "/dev/ttySAC", 11 )){
                    /* disable echo on serial ports */
                    struct termios  ios;
                    tcgetattr( fd, &ios );

                    ios.c_lflag = 0;  /* disable ECHO, ICANON, etc... */
                    ios.c_oflag &= ~OCRNL;
                    ios.c_iflag &= ~ICRNL;
                    cfsetispeed(&ios, B115200);
                    cfsetospeed(&ios, B115200);
                    ios.c_cflag &= ~PARENB;
                    ios.c_cflag &= ~CSTOPB;
                    ios.c_cflag &= ~CSIZE;
                    ios.c_cflag |= CS8;
                    ios.c_iflag &= ~(INLCR | ICRNL | IGNCR);
                    ios.c_oflag &= ~(ONLCR | OCRNL);
                    //ios.c_lflag &= ~ (ICANON | ECHO | ECHOE | ISIG);
                    //ios.c_iflag &= ~ (IXON | IXOFF | IXANY); //off soft flow control
                    tcsetattr( fd, TCSANOW, &ios );
                    //tcflush( fd, TCIFLUSH );
                    //tcflush( fd, TCOFLUSH );
                }
#endif
            }

            if (fd < 0) {
                LOGE("opening AT interface. retrying...");
                sleep(10);
                /* never returns */
            }
        }

		/*
		 * 创建管道
		 */
        for (i = 0; i < RIL_CHANNELS; i++) {
            pipe(fds);
            fd_ReqRead[i] = fds[0];
            fd_ReqWrite[i] = fds[1];
        }

        s_closed = 0;
#ifdef GSM_MUX_CHANNEL
        // initialize fd set //
        memset(v_fds, 0x00, RIL_CHANNELS);
        FD_ZERO(&readMuxs);

        int j;
		/*
		 * 带开10个RIL——CHANNEL，也就是虚拟的串口，
		 * 打开失败时，会重试，知道打开位置
		 */
        for (j = 0 ; j < RIL_CHANNELS; j++)
        {
            char  s_muxChannelDevice[7] = {0};

            int size = sizeof("gsm0710mux.channelz");
            if((j + 1) >= 10) size++;
            char property[size];
            snprintf(property, size, "gsm0710mux.channel%d", (j + 1));
            LOGE ("openning MUX device: %s", property);
            property_get(property, s_muxChannelDevice, "");
            LOGE ("open MUX device %d: s_muxChannelDevice = %s", (j + 1), s_muxChannelDevice);

            fd = open (s_muxChannelDevice, O_RDWR);

            struct termios  ios;
            tcgetattr( fd, &ios );

            ios.c_lflag = 0;  /* disable ECHO, ICANON, etc... */
            ios.c_oflag &= ~OCRNL;
            ios.c_iflag &= ~ICRNL;
            ios.c_cflag &= ~PARENB;
            ios.c_cflag &= ~CSTOPB;
            ios.c_cflag &= ~CSIZE;
            ios.c_cflag |= CS8;
            ios.c_iflag &= ~(INLCR | ICRNL | IGNCR);
            ios.c_oflag &= ~(ONLCR | OCRNL);
            ios.c_lflag &= ~ (ICANON | ECHO | ECHOE | ISIG);
            ios.c_iflag &= ~ (IXON | IXOFF | IXANY); //open soft flow control
            tcsetattr( fd, TCSANOW, &ios );

            LOGE ("open MUX device : fd = %d", fd);
            if(fd < 0){
                LOGE ("open MUX device %s: %s ERROR: %d, retrying..."
                        , property, s_muxChannelDevice, errno);
                sleep(5);
                j--;
                continue;
            }

            v_fds[j] = fd;
            //if(j > 0) 
            FD_SET(fd, &readMuxs);
            if(fd >= nMuxfds){
                nMuxfds = fd + 1;
            }
        }
#endif
        ret = at_open(fd, onUnsolicited);

        if (ret < 0) {
            LOGE ("AT error %d on at_open\n", ret);
            return 0;
        }

        // append timeReq to s_pendingRequests, initializeCallback run so quickly // 
        // may cause null pointer exception in dispatchTimeReq !!! //
        // so run it 1 second later //
        // after ril_register() get onRequest pointer return from ril_init() //
        //RIL_requestTimedCallback(initializeCallback, NULL, &TIMEVAL_0);
        RIL_requestTimedCallback(RIL_TIME_REQUEST_INITAT, NULL, &TIMEVAL_0);

        // Give initializeCallback a chance to dispatched, since
        // we don't presently have a cancellation mechanism
        sleep(1);

        waitForClose();
        LOGI("Re-opening after close");
    }
}

#ifdef RIL_SHLIB

pthread_t s_tid_mainloop;

const RIL_RadioFunctions *RIL_Init(const struct RIL_Env *env, int argc, char **argv)
{
    int ret;
    int fd = -1;
    int opt;
    pthread_attr_t attr;

    s_rilenv = env;

    while ( -1 != (opt = getopt(argc, argv, "p:d:s:c:"))) {
        switch (opt) {
            case 'p':
                s_port = atoi(optarg);
                if (s_port == 0) {
                    usage(argv[0]);
                    return NULL;
                }
                LOGI("Opening loopback port %d\n", s_port);
            break;

            case 'd':
                s_device_path = optarg;
                LOGI("Opening tty device %s\n", s_device_path);
            break;

            case 's':
                s_device_path   = optarg;
                s_device_socket = 1;
                LOGI("Opening socket %s\n", s_device_path);
            break;

            case 'c':
                //TODO:This will be handled when DSDS two rild emualtor support is mainlined.
            break;

            default:
                usage(argv[0]);
                return NULL;
        }
    }

    if (s_port < 0 && s_device_path == NULL) {
        usage(argv[0]);
        return NULL;
    }

    sMdmInfo = calloc(1, sizeof(ModemInfo));
    if (!sMdmInfo) {
        LOGE("Unable to alloc memory for ModemInfo");
        return NULL;
    }
    pthread_attr_init (&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    ret = pthread_create(&s_tid_mainloop, &attr, mainLoop, NULL);

    return &s_callbacks;
}
#else /* RIL_SHLIB */
int main (int argc, char **argv)
{
    int ret;
    int fd = -1;
    int opt;

    while ( -1 != (opt = getopt(argc, argv, "p:d:"))) {
        switch (opt) {
            case 'p':
                s_port = atoi(optarg);
                if (s_port == 0) {
                    usage(argv[0]);
                }
                LOGI("Opening loopback port %d\n", s_port);
            break;

            case 'd':
                s_device_path = optarg;
                LOGI("Opening tty device %s\n", s_device_path);
            break;

            case 's':
                s_device_path   = optarg;
                s_device_socket = 1;
                LOGI("Opening socket %s\n", s_device_path);
            break;

            default:
                usage(argv[0]);
        }
    }

    if (s_port < 0 && s_device_path == NULL) {
        usage(argv[0]);
    }

    RIL_register(&s_callbacks);

    mainLoop(NULL);

    return 0;
}

#endif /* RIL_SHLIB */
/**************************************************************************
  Modified by CYIT 20120825 ----- start -----
**************************************************************************/
static void requestGetCurNetMode( void * data , size_t datalen , RIL_Token t )
{
    int err = 0;
    char * line;
    ATResponse * p_response = NULL;
    int response;

    err = at_send_command_singleline_min_timeout( "AT^STMC?", "^STMC:", &p_response);
    if ( err < 0 || p_response->success == 0 )
    {
        goto error;
    }

    line = p_response->p_intermediates->line;
    err = at_tok_start( &line );
    if ( err < 0 )
    {
        goto error;
    }

    err = at_tok_nextint( &line, &response );
    if ( err < 0 )
    {
        goto error;
    }

    if ( response == 13 )
    {
        response = GSMONLY;
    }
    else if ( response == 15 )
    {
        response = TDONLY;
    }
    else if ( response == 2 )
    {
        err = at_tok_nextint( &line, &response );
        if ( err < 0 )
        {
            goto error;
        }

        if ( response == 1 )
        {
            response = GSMPREFER;
        }
        else if ( response == 2 )
        {
            response = TDPREFER;
        }
        else
        {
            goto error;
        }
    }

    // Do not support //

    else
    {
        goto error;
    }

    RIL_onRequestComplete( t, RIL_E_SUCCESS, &response, sizeof( response ) );
    at_response_free( p_response );

    return;

    error:

    RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
    at_response_free( p_response );
}

static void requestSetCurNetMode( void * data , size_t datalen , RIL_Token t )
{
    char * cmd;
    int err = 0;
    int mode = 0;
    ATResponse * p_response = NULL;

    if ( data )
    {
        mode = ( ( int * )data )[0];
    }
    else
    {
        goto error;
    }

    if ( mode == GSMONLY )
    {
        asprintf( &cmd, "AT^STMC=13,1,1,4" );
    }
    else if ( mode == TDONLY )
    {
        asprintf( &cmd, "AT^STMC=15,2,1,4" );
    }
    else if ( mode == GSMPREFER )
    {
        asprintf( &cmd, "AT^STMC=2,1,1,4" );
    }
    else if ( mode == TDPREFER )
    {
        asprintf( &cmd, "AT^STMC=2,2,1,4" );
    }

    err = at_send_command_min_timeout( cmd, &p_response);
    free( cmd );
    if ( err != 0 || p_response->success == 0 )
    {
        goto error;
    }

    RIL_onRequestComplete( t, RIL_E_SUCCESS, NULL, 0 );
    at_response_free( p_response );

    return;

    error:

    RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
    at_response_free( p_response );
}

static void requestGetTDFreq( void * data, size_t datalen, RIL_Token t )
{
    int Result = 0, err = 0;
    int dstlen = 0;
    unsigned char * srcbinary = NULL;
    unsigned char * dstbinary = NULL;
    unsigned short fc = ( unsigned short )E_ATCMD_LOCKFREQ_READ;
    ATResponse * p_response = NULL;
    int response[9] = { 0 };

    srcbinary = ( unsigned char * )( &fc );
    err = HandleBinaryStr( 
        "AT*", 
        srcbinary, M_EGFC_LEN, 
        &dstbinary, &dstlen );
    LOGD( "dstlen = %d", dstlen );
    if ( err == 0 || dstbinary == NULL || dstlen == 0 ) goto error;
    
    err = at_send_egcmd_singleline(dstbinary, dstlen, M_EGPREFIX, &p_response);
    free( dstbinary );

    if ( err < 0 || p_response->success == 0 )
    {
        goto error;
    }
    else
    {
        int i = 0;
        int prefixlen = 0;
        char * line = p_response->p_intermediates->line;
        unsigned short num = 0;
        unsigned short frq = 0;

        prefixlen = M_EGPREFIX_LEN + M_EGFC_LEN + M_EGDATA_LEN;
        fc = *(( unsigned short * )( line + M_EGPREFIX_LEN ));
        
        if ( fc != E_ATCMD_LOCKFREQ_READ )
        {
            LOGE( "Unmatching function code: %d." , fc);
            goto error;
        }

        // Get FreqNum //
        num = *(( unsigned short * )( line + prefixlen));

        if( num > 9 )
        {
            LOGE( "num error: %d." , num);
            goto error;
        }

        // Get 9 * FreqInfo //
        for ( i = 0; i < num; i++ )
        {
            frq = *(( unsigned short * )( line + prefixlen + 2 + i * 2 ));
            response[i] = frq;
        }

        RIL_onRequestComplete( t, RIL_E_SUCCESS, 
            response, num * sizeof( int ));
    }
    
    at_response_free( p_response );

    return;

error: 
    RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
    at_response_free( p_response );
}

static void requestSetTDFreq( void * data, size_t datalen, RIL_Token t )
{
    int err = 0;
    int i = 0;
    int dstlen = 0;

    // FC + FreqNum + FreqInfo //
    unsigned short src[11];
    unsigned char * srcbinary = NULL;
    unsigned char * dstbinary = NULL;
    ATResponse * p_response = NULL;

    if ( data )
    {
        memset( src, 0xFFFF, sizeof( src ));

        // FC //
        src[0] = ( unsigned short )E_ATCMD_LOCKFREQ_SET;
    
        // FreqNum //
        LOGD( "datalen = %d", datalen );
        src[1] = datalen / sizeof( int );

        if ( src[1] > 9 ) goto error;

        // FreqInfo //
        for ( ; i < src[1]; i++ )
        {
            src[i + 2] = (( int * )data )[i];
        }
        srcbinary = ( unsigned char * )src;

        err = HandleBinaryStr( 
            "AT*", 
            srcbinary, sizeof( src ), 
            &dstbinary, &dstlen );
        LOGD( "dstlen = %d", dstlen );
        if ( err == 0 || dstbinary == NULL || dstlen== 0 ) goto error;
            
        err = at_send_egcmd( dstbinary, dstlen, &p_response );
        free( dstbinary );
        if ( err < 0 || p_response->success == 0 ) goto error;
    }
    else 
    {
        LOGE( "Invalid parameters of set TD freq." );
        RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );

        return;
    }

    RIL_onRequestComplete( t, RIL_E_SUCCESS, NULL, 0 );
    at_response_free( p_response );

    return;
    
error:
    RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
    at_response_free( p_response );
}

static void requestGetTDCellIdLock( void * data, size_t datalen, RIL_Token t )
{
    int Result = 0, err = 0;
    int dstlen = 0;
    unsigned char * srcbinary = NULL;
    unsigned char * dstbinary = NULL;
    unsigned short fc = ( unsigned short )E_ATCMD_LOCKCELL_READ;
    ATResponse * p_response = NULL;
    int response;

    srcbinary = ( unsigned char * )( &fc );
    err = HandleBinaryStr( "AT*", srcbinary, M_EGFC_LEN, &dstbinary, &dstlen );
    LOGD( "dstlen = %d", dstlen );
    if ( err == 0 || dstbinary == NULL || dstlen == 0 ) goto error;

    err = at_send_egcmd_singleline(dstbinary, dstlen, M_EGPREFIX, &p_response);
    free( dstbinary );

    if ( err < 0 || p_response->success == 0 )
    {
        goto error;
    }
    else
    {
        int prefixlen = 0;
        char * line = p_response->p_intermediates->line;

        prefixlen = M_EGPREFIX_LEN + M_EGFC_LEN + M_EGDATA_LEN;
        fc = *(( unsigned short * )( line + M_EGPREFIX_LEN ));
        
        if ( fc != E_ATCMD_LOCKCELL_READ )
        {
            LOGE( "Unmatching function code: %d." , fc);
            goto error;
        }

        // Cell id //
        response = *(( unsigned short * )( line + prefixlen));

        RIL_onRequestComplete( t, RIL_E_SUCCESS, &response, sizeof( response ));
    }
    
    at_response_free( p_response );

    return;

error: 
    RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
    at_response_free( p_response );
}

static void requestSetTDCellIdLock( void * data, size_t datalen, RIL_Token t )
{
    int err = 0;
    int dstlen = 0;
    // FC + Cell Id //
    unsigned short src[2];
    unsigned char * srcbinary = NULL;
    unsigned char * dstbinary = NULL;
    ATResponse * p_response = NULL;

    if ( data )
    {
        memset( src, 0xFF, sizeof( src ));

        // FC //
        src[0] = ( unsigned short )E_ATCMD_LOCKCELL_SET;
        // cell id //
        src[1] = *(( int * )data );
        srcbinary = ( unsigned char * )src;

        err = HandleBinaryStr( "AT*", srcbinary, sizeof( src ), &dstbinary, &dstlen );
        LOGD( "dstlen = %d", dstlen );
        if ( err == 0 || dstbinary == NULL || dstlen == 0 ) goto error;

        err = at_send_egcmd( dstbinary, dstlen, &p_response );
        free( dstbinary );

        if ( err < 0 || p_response->success == 0 ) goto error;
    }
    else 
    {
        LOGE( "Invalid parameters of set TD cell id." );
        RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
        return;
    }

    RIL_onRequestComplete( t, RIL_E_SUCCESS, NULL, 0 );
    at_response_free( p_response );

    return;
    
error:
    RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
    at_response_free( p_response );
}

static void requestGetGsmFreqLock( void * data, size_t datalen, RIL_Token t )
{
    int Result = 0, err = 0;
    int dstlen = 0;
    unsigned char * srcbinary = NULL;
    unsigned char * dstbinary = NULL;
    unsigned short fc = ( unsigned short )E_ATCMD_GSMLOCKFREQ_READ;
    ATResponse * p_response = NULL;
    int response;
    
    srcbinary = ( unsigned char * )( &fc );

    err = HandleBinaryStr( "AT*", srcbinary, M_EGFC_LEN, &dstbinary, &dstlen );
    LOGD( "dstlen = %d", dstlen );
    if ( err == 0 || dstbinary == NULL || dstlen == 0 ) goto error;

    err = at_send_egcmd_singleline(dstbinary, dstlen, M_EGPREFIX, &p_response );
    free( dstbinary );

    if ( err < 0 || p_response->success == 0 )
    {
        goto error;
    }
    else
    {
        int prefixlen = 0;
        char * line = p_response->p_intermediates->line;

        prefixlen = M_EGPREFIX_LEN + M_EGFC_LEN + M_EGDATA_LEN;
        fc = *(( unsigned short * )( line + M_EGPREFIX_LEN ));
        
        if ( fc != E_ATCMD_GSMLOCKFREQ_READ )
        {
            LOGE( "Unmatching function code: %d." , fc);
            goto error;
        }

        // Cell Info //
        response = *(( unsigned short * )( line + prefixlen ));

        RIL_onRequestComplete( t, RIL_E_SUCCESS, &response, sizeof( response ));
    }
    
    at_response_free( p_response );

    return;

error: 
    RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
    at_response_free( p_response );
}

static void requestSetGsmFreqLock( void * data, size_t datalen, RIL_Token t )
{
    int err = 0;
    int dstlen = 0;
    // FC + freq //
    unsigned short src[2];
    unsigned char * srcbinary = NULL;
    unsigned char * dstbinary = NULL;
    ATResponse * p_response = NULL;

    if ( data )
    {
        memset( src, 0xFF, sizeof( src ));

        // FC //
        src[0] = ( unsigned short )E_ATCMD_GSMLOCKFREQ_SET;
        // freq //
        src[1] = *(( int * )data );
        srcbinary = ( unsigned char * )src;

        err = HandleBinaryStr( "AT*", srcbinary, sizeof( src ), &dstbinary, &dstlen );
        LOGD( "dstlen = %d", dstlen );
        if ( err == 0 || dstbinary == NULL || dstlen == 0 ) goto error;

        err = at_send_egcmd( dstbinary, dstlen, &p_response );
        free( dstbinary );

        if ( err < 0 || p_response->success == 0 ) goto error;
    }
    else 
    {
        LOGE( "Invalid parameters of set Gsm freq." );
        RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
        return;
    }

    RIL_onRequestComplete( t, RIL_E_SUCCESS, NULL, 0 );
    at_response_free( p_response );

    return;
    
error:
    RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
    at_response_free( p_response );
}

static void requestGetProtocolVersion( void * data, size_t datalen, RIL_Token t )
{
    int Result = 0, err = 0;
    int dstlen = 0;
    unsigned char * srcbinary = NULL;
    unsigned char * dstbinary = NULL;
    unsigned short fc = ( unsigned short )E_ATCMD_NFREQVER_READ;
    ATResponse * p_response = NULL;
    int response;
    
    srcbinary = ( unsigned char * )( &fc );

    err = HandleBinaryStr( "AT*", srcbinary, M_EGFC_LEN, &dstbinary, &dstlen );
    LOGD( "dstlen = %d", dstlen );
    if ( err == 0 || dstbinary == NULL || dstlen == 0 ) goto error;
    
    err = at_send_egcmd_singleline(dstbinary, dstlen, M_EGPREFIX, &p_response );
    free( dstbinary );

    if ( err < 0 || p_response->success == 0 )
    {
        goto error;
    }
    else
    {
        int prefixlen = 0;
        char * line = p_response->p_intermediates->line;

        prefixlen = M_EGPREFIX_LEN + M_EGFC_LEN + M_EGDATA_LEN;
        fc = *(( unsigned short * )( line + M_EGPREFIX_LEN ));
        
        if ( fc != E_ATCMD_NFREQVER_READ )
        {
            LOGE( "Unmatching function code: %d." , fc);
            goto error;
        }

        // protocol version //
        response = *(( unsigned short * )( line + prefixlen ));

        RIL_onRequestComplete( t, RIL_E_SUCCESS, &response, sizeof( response ));
    }
    
    at_response_free( p_response );

    return;

error: 
    RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
    at_response_free( p_response );
}

static void requestSetProtocolVersion( void * data, size_t datalen, RIL_Token t )
{
    int err = 0;
    int dstlen = 0;
    // FC + protocol version //
    unsigned short src[2];
    unsigned char * srcbinary = NULL;
    unsigned char * dstbinary = NULL;
    ATResponse * p_response = NULL;

    if ( data )
    {
        memset( src, 0xFF, sizeof( src ));

        // FC //
        src[0] = ( unsigned short )E_ATCMD_NFREQVER_SET;
        // protocol version //
        src[1] = *(( int * )data );
        srcbinary = ( unsigned char * )src;

        err = HandleBinaryStr( "AT*", srcbinary, sizeof( src ), &dstbinary, &dstlen );
        LOGD( "dstlen = %d", dstlen );
        if ( err == 0 || dstbinary == NULL || dstlen == 0 ) goto error;

        err = at_send_egcmd( dstbinary, dstlen, &p_response );
        free( dstbinary );

        if ( err < 0 || p_response->success == 0 ) goto error;
    }
    else 
    {
        LOGE( "Invalid parameters of set Gsm freq." );
        RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
        return;
    }

    RIL_onRequestComplete( t, RIL_E_SUCCESS, NULL, 0 );
    at_response_free( p_response );

    return;
    
error:
    RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
    at_response_free( p_response );
}

static void requestGetPSAttached( void * data , size_t datalen , RIL_Token t )
{
    int err = 0;
    int state = 0;
    int response[1];
    char * line;
    ATResponse * p_response = NULL;

    err = at_send_command_singleline_min_timeout( "AT+CGATT?", "+CGATT:",&p_response);
    LOGW("err=%d,p_response->success = %d",err,p_response->success);
    if ( err != 0 || p_response->success == 0 )
    {
        goto error;
    }

    line = p_response->p_intermediates->line;
    err = at_tok_start( &line );
    if ( err < 0 )
    {
        goto error;
    }

    err = at_tok_nextint( &line, &state );
    if ( err < 0 )
    {
        goto error;
    }

    response[0] = state;

    RIL_onRequestComplete( t, RIL_E_SUCCESS, response, sizeof( response ) );
    at_response_free( p_response );

    return;

    error:

    RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
    at_response_free( p_response );
}

static void requestSetPSAttached( void * data , size_t datalen , RIL_Token t )
{
    int err = 0;
    char * cmd;
    int * arg = NULL;
    int state = 0;
    ATResponse * p_response = NULL;
    long long timeout = CYIT_AT_TIMEOUT_40_SEC;

    if ( data )
    {
        arg = ( int * )data;
    }
    else
    {
        goto error;
    }

    state = arg[0];
    asprintf( &cmd, "AT+CGATT=%d", state );
    if(state == 0){
        timeout = CYIT_AT_TIMEOUT_80_SEC;
    }
    err = at_send_command_timeout(cmd, NO_RESULT, NULL, &p_response, timeout);
    LOGW("err=%d,p_response->success = %d",err,p_response->success);
    free( cmd );
    if ( err != 0 || p_response->success == 0 )
    {
        goto error;
    }

    RIL_onRequestComplete( t, RIL_E_SUCCESS, NULL, 0 );
    at_response_free( p_response );

    return;

    error: LOGW("go to err");
    RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
    at_response_free( p_response );
}

static void requestGetUeCategroy( void * data, size_t datalen, RIL_Token t )
{
    int Result = 0, err = 0;
    int dstlen = 0;
    unsigned char * srcbinary = NULL;
    unsigned char * dstbinary = NULL;
    unsigned short fc = ( unsigned short )E_ATCMD_UECATE_READ;
    ATResponse * p_response = NULL;
    int response[2];
    
    srcbinary = ( unsigned char * )( &fc );

    err = HandleBinaryStr( "AT*", srcbinary, M_EGFC_LEN, &dstbinary, &dstlen );
    LOGD( "dstlen = %d", dstlen );
    if ( err == 0 || dstbinary == NULL || dstlen == 0 ) goto error;
    
    err = at_send_egcmd_singleline(dstbinary, dstlen, M_EGPREFIX, &p_response);
    free( dstbinary );

    if ( err < 0 || p_response->success == 0 )
    {
        goto error;
    }
    else
    {
        int prefixlen = 0;
        char * line = p_response->p_intermediates->line;

        prefixlen = M_EGPREFIX_LEN + M_EGFC_LEN + M_EGDATA_LEN;
        fc = *(( unsigned short * )( line + M_EGPREFIX_LEN ));
        
        if ( fc != E_ATCMD_UECATE_READ )
        {
            LOGE( "Unmatching function code: %d." , fc);
            goto error;
        }

        // dpa categroy //
        response[0] = *( line + prefixlen );
        // upa categroy //
        response[1] = *( line + prefixlen + 1 );

        RIL_onRequestComplete( t, RIL_E_SUCCESS, response, sizeof( response ));
    }
    
    at_response_free( p_response );

    return;

error: 
    RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
    at_response_free( p_response );
}

static void requestSetUeCategroy( void * data, size_t datalen, RIL_Token t )
{
    int err = 0;
    int dstlen = 0;
    // FC + ue categroy //
    unsigned short src[2];
    unsigned char * srcbinary = NULL;
    unsigned char * dstbinary = NULL;
    ATResponse * p_response = NULL;

    if ( data )
    {
        memset( src, 0xFF, sizeof( src ));

        // FC //
        src[0] = ( unsigned short )E_ATCMD_UECATE_SET;
        // ue categroy //
        src[1] = (( int * )data )[0] | ((( int * )data )[1] << 8 );
        srcbinary = ( unsigned char * )src;

        err = HandleBinaryStr( "AT*", srcbinary, sizeof( src ), &dstbinary, &dstlen );
        LOGD( "dstlen = %d", dstlen );
        if ( err == 0 || dstbinary == NULL || dstlen == 0 ) goto error;

        err = at_send_egcmd( dstbinary, dstlen, &p_response );
        free( dstbinary );

        if ( err < 0 || p_response->success == 0 ) goto error;
    }
    else 
    {
        LOGE( "Invalid parameters of set Gsm freq." );
        RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
        return;
    }

    RIL_onRequestComplete( t, RIL_E_SUCCESS, NULL, 0 );
    at_response_free( p_response );

    return;
    
error:
    RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
    at_response_free( p_response );
}

static void requestSetTEType( void * data , size_t datalen , RIL_Token t )
{
    int err = 0;
    char * cmd;
    char * tetype = NULL;
    ATResponse * p_response = NULL;

    if ( data )
    {
        tetype = ( char * )data;
    }
    else
    {
        goto error;
    }

    asprintf( &cmd, "AT+CGCLASS=\"%s\"", tetype );
    err = at_send_command_min_timeout( cmd, &p_response );
    free( cmd );
    if ( err != 0 || p_response->success == 0 )
    {
        goto error;
    }

    RIL_onRequestComplete( t, RIL_E_SUCCESS, NULL, 0 );
    at_response_free( p_response );

    return;

    error:

    RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
    at_response_free( p_response );
}

static void requestGetTEType( void * data , size_t datalen , RIL_Token t )
{
    int err = 0;
    char * line, *tetype;
    ATResponse * p_response = NULL;

    err = at_send_command_singleline_min_timeout( "AT+CGCLASS?", "+CGCLASS:", &p_response );
    if ( err != 0 || p_response->success == 0 )
    {
        goto error;
    }

    line = p_response->p_intermediates->line;
    err = at_tok_start( &line );
    if ( err < 0 )
    {
        goto error;
    }

    err = at_tok_nextstr( &line, &( tetype ) );
    if ( err < 0 )
    {
        goto error;
    }

    RIL_onRequestComplete( t, RIL_E_SUCCESS, tetype, sizeof(char *) );
    at_response_free( p_response );

    return;

    error:

    RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
    at_response_free( p_response );
}


// ----------------------
// ----------------------
//      static void requestGetPreferredNetworkType( void * data, size_t datalen, RIL_Token t )
//      static void requestSetPreferredNetworkType( void * data, size_t datalen, RIL_Token t )
// refer to
//      static void requestGetCurNetMode( void * data , size_t datalen , RIL_Token t )
//      static void requestSetCurNetMode( void * data , size_t datalen , RIL_Token t )
// ----------------------
// ----------------------


static void requestGetApnInfo( void * data , size_t datalen , RIL_Token t )
{
    char *cmd;
    int err;
    ATResponse *p_response = NULL;
    char *line, *temp;
    RIL_APN_Info **result;
    ATLine *p_cur;
    int n = 0, count = 0;

    err = at_send_command_multiline_min_timeout( "AT+CGDCONT?", "+CGDCONT:", &p_response);
    if ( err != 0 || p_response->success == 0 ) goto error;

    for ( p_cur = p_response->p_intermediates; p_cur != NULL; p_cur
            = p_cur->p_next, n++ )
        ;
    count = n;

    result = ( RIL_APN_Info ** )alloca(count*sizeof(RIL_APN_Info*));
    for ( p_cur = p_response->p_intermediates, n = 0; p_cur != NULL; p_cur
            = p_cur->p_next, n++ )
    {
        result[n] = ( RIL_APN_Info * )alloca(sizeof(RIL_APN_Info));

        line = p_cur->line;
        err = at_tok_start( &line );
        if ( err < 0 ) goto error;

        err = at_tok_nextint( &line, &( result[n]->cid ) );
        if ( err < 0 ) goto error;

        err = at_tok_nextstr( &line, &temp );
        if ( err < 0 ) goto error;

        err = at_tok_nextstr( &line, &temp );
        if ( err < 0 ) goto error;
        result[n]->apn = alloca(strlen(temp)+1);
        strcpy( result[n]->apn, temp );
    }

    RIL_onRequestComplete( t, RIL_E_SUCCESS, result, count
            * sizeof(RIL_APN_Info*) );
    at_response_free( p_response );
    return;

error: 
    RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
    at_response_free( p_response );
}


static void requestSetApnInfo( void * data , size_t datalen , RIL_Token t )
{
    ATResponse *p_response = NULL;
    int err;
    RIL_APN_Info *apnInfo = NULL;
    char *cmd = NULL;

    if ( data && datalen == sizeof( RIL_APN_Info ) )
    {
        apnInfo = ( RIL_APN_Info * )data;
    }
    else
    {
        goto error;
    }

    if ( (apnInfo->cid >= PDPID_MIN && apnInfo->cid <= PDPID_MAX) && apnInfo->apn != NULL)
    {
        asprintf( &cmd, "AT+CGDCONT=%d,,\"%s\"", apnInfo->cid, apnInfo->apn );
    }
    else
    {
        LOGE( "Set apn invalid parameter, cid = %d, apn = %s\n", apnInfo->cid, apnInfo->apn );
        goto error;
    }

    err = at_send_command_min_timeout( cmd, &p_response );
    free( cmd );
    if ( err < 0 || p_response->success == 0 )
    {
        LOGE( "Set apn error\n" );
        goto error;
    }

    RIL_onRequestComplete( t, RIL_E_SUCCESS, NULL, 0 );
    at_response_free( p_response );

    return;

    error:

    RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
    at_response_free( p_response );
}

static void requestGetPdpActive( void * data , size_t datalen , RIL_Token t )
{
    char *cmd;
    int err;
    ATResponse *p_response = NULL;
    char *line, *temp;
    RIL_Pdp_Info **result;
    ATLine *p_cur;
    int n = 0, count = 0;

    err = at_send_command_multiline_min_timeout( "AT+CGACT?", "+CGACT:", &p_response);
    if ( err != 0 || p_response->success == 0 ) goto error;

    for ( p_cur = p_response->p_intermediates; p_cur != NULL; p_cur
            = p_cur->p_next, n++ )
        ;
    count = n;

    result = ( RIL_Pdp_Info ** )alloca(count*sizeof(RIL_Pdp_Info*));
    for ( p_cur = p_response->p_intermediates, n = 0; p_cur != NULL; p_cur
            = p_cur->p_next, n++ )
    {
        result[n] = ( RIL_Pdp_Info * )alloca(sizeof(RIL_Pdp_Info));

        line = p_cur->line;
        err = at_tok_start( &line );
        if ( err < 0 ) goto error;

        err = at_tok_nextint( &line, &( result[n]->cid ) );
        if ( err < 0 ) goto error;

        err = at_tok_nextint( &line, &( result[n]->state ) );
        if ( err < 0 ) goto error;
    }

    RIL_onRequestComplete( t, RIL_E_SUCCESS, result, count
            * sizeof(RIL_Pdp_Info*) );
    at_response_free( p_response );
    return;

error: 
    RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
    at_response_free( p_response );
}

static void requestSetPdpActive( void * data , size_t datalen , RIL_Token t )
{
    int err = 0;
    char *cmd = NULL, *line = NULL;
    int * args = NULL;
    int pdpid = 0, state = 0;
    int tempint = 0;
    int ttyfd = -1;
    char *pdpport = NULL, *ipaddr = NULL;
    char *devpath = NULL;
    ATResponse * p_response = NULL;

    if (data && datalen == 2 * sizeof(int))
    {
        args = ( int * )data;
    }
    else
    {
        goto error;
    }

    pdpid = args[0];
    state = args[1];

    if( ( pdpid > PDPID_MAX ) || ( state > 0x01 ))
    {
        goto error;
    }

    if (isMainPdp(pdpid)) {
        pdpport = s_PSCtl[pdpid - 1].m_Port;

        // don't hava this PDP weird ??? //
        if (pdpport == NULL) {
            LOGE("Have no this PDP");
            goto error;
        }

        if (state == 1 && s_PSCtl[pdpid - 1].m_Used == 1) {
            LOGD("PDP id%d had been actived, cancel this request", pdpid);
            goto end;
        } else if (state == 0 && s_PSCtl[pdpid - 1].m_Used == 0) {
            LOGD("PDP id%d had been deactived, cancel this request", pdpid);
            goto end;
        }
    }

    asprintf( &cmd, "AT+CGACT=%d,%d", state, pdpid );

    if(state == 0)
    {
        err = at_send_command_timeout(
            cmd, NO_RESULT, NULL, &p_response, CYIT_DEFAULT_AT_TIMEOUT_MSEC);
    }
    else // (state == 1)
    {
        err = at_send_command_timeout(
            cmd, NO_RESULT, NULL, &p_response, CYIT_AT_TIMEOUT_70_SEC);
    }

    free( cmd );

    if ( err != 0 || p_response->success == 0 )
    {
        if (AT_ERROR_TIMEOUT == err) {
            if(state == 0)
            {
                sendAbortCmd(CYIT_SAOC_TYPE_PDP_DEACTIVE);
            }
            else // (state == 1)
            {
                sendAbortCmd(CYIT_SAOC_TYPE_PDP_ACTIVE);
            }
        }
        goto error;
    }

    if (isMainPdp(pdpid)) {

        // Active //
        if (state == 1) {
            // Get IP address //
            asprintf( &cmd, "AT+CGPADDR=%d", pdpid );
            err = at_send_command_singleline_min_timeout( cmd, "+CGPADDR:", &p_response );
            free( cmd );
            if ( err < 0 || p_response->success == 0 )
            {
                goto error2;
            }

            line = p_response->p_intermediates->line;
            err = at_tok_start( &line );
            if ( err < 0 )
            {
                goto error2;
            }

            err = at_tok_nextint( &line, &tempint );
            if ( err < 0 || pdpid != tempint )
            {
                goto error2;
            }

            err = at_tok_nextstr( &line, &ipaddr );
            if ( err < 0 )
            {
                goto error2;
            }

            // Empty IP address //
            if (ipaddr == NULL || strcmp(ipaddr, "") == 0)
            {
                LOGE( "Empty IP address." );
                goto error2;
            }

            // Set IP and turn it on //

#ifdef USE_RAWIP
#ifdef GSM_MUX_CHANNEL
            devpath = malloc(PROPERTY_VALUE_MAX);
            memset(devpath, 0, PROPERTY_VALUE_MAX);
            property_get(s_Ttys[pdpid - 1].ttyPath, devpath, "");
            if (!strcmp(devpath, "")) {
                LOGE("get %s's device path failed", s_Ttys[pdpid - 1].ttyPath);
                free(devpath);
                goto error2;
            }
            LOGD("device path is %s", devpath);
#else
            devpath = s_Ttys[pdpid - 1].ttyPath;
#endif

            ttyfd = open(devpath, O_RDWR | O_NOCTTY | O_NONBLOCK);
#ifdef GSM_MUX_CHANNEL
            free(devpath);
#endif
            if (ttyfd < 0) {
                LOGE("open failed, errno is %s", strerror(errno));
                goto error2;
            }
            s_Ttys[pdpid - 1].ttyFd = ttyfd;

            if (ioctl(ttyfd, TIOCSETD, &s_RawIP_Disc) < 0) {
                LOGE("create %s failed.", pdpport);
                goto error2;
            }
#endif

            ifc_init();
            if (ifc_up(pdpport)
                    || ifc_set_addr(pdpport, inet_addr(ipaddr)))
            {
                LOGE( "Set IP failed." );
                ifc_close();
                goto error2;
            }
            ifc_close();
            s_PSCtl[pdpid - 1].m_Used = 1; 
        } 
        
        // deactive //
        else {
            err = ifc_disable(pdpport);
            if (err != 0) {
                LOGE("Set %s deactivate failed.", pdpport);
                goto error2;
            }

#ifdef USE_RAWIP
            if (close(s_Ttys[pdpid - 1].ttyFd) < 0) {
                LOGE("close %s failed, errno is %s", s_Ttys[pdpid - 1].ttyPath, strerror(errno));
                goto error;
            }
#endif
            s_PSCtl[pdpid - 1].m_Used = 0;
        }
    }

end:

    RIL_onRequestComplete( t, RIL_E_SUCCESS, pdpport, sizeof(char *) );
    at_response_free( p_response );

    return;

error2:

#ifdef GSM_MUX_CHANNEL
    free(devpath);
#endif

    // Deactive pdp //
    at_response_free( p_response );
    p_response = NULL;
    asprintf( &cmd, "AT+CGACT=0,%d", pdpid );
    at_send_command_timeout(
            cmd, NO_RESULT, NULL, &p_response, CYIT_DEFAULT_AT_TIMEOUT_MSEC);
    free( cmd );

    if (err != 0 || p_response->success == 0) {
        if (AT_ERROR_TIMEOUT == err) {
            sendAbortCmd(CYIT_SAOC_TYPE_PDP_DEACTIVE);
        }
    }

error:

    RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
    at_response_free( p_response );
}


static void requestGetPdpQos( void * data , size_t datalen , RIL_Token t )
{
    char *cmd;
    int err;
    ATResponse *p_response = NULL;
    char *line, *temp;
    RIL_QOS_Info **result;
    ATLine *p_cur;
    int n = 0, count = 0;

    err = at_send_command_multiline_min_timeout( "AT+CGEQREQ?", "+CGEQREQ:", &p_response);
    if ( err != 0 || p_response->success == 0 ) goto error;

    for ( p_cur = p_response->p_intermediates; p_cur != NULL; p_cur
            = p_cur->p_next, n++ )
        ;
    count = n;

    result = ( RIL_QOS_Info ** )alloca(count*sizeof(RIL_QOS_Info*));
    for ( p_cur = p_response->p_intermediates, n = 0; p_cur != NULL; p_cur
            = p_cur->p_next, n++ )
    {
        result[n] = ( RIL_QOS_Info * )alloca(sizeof(RIL_QOS_Info));

        line = p_cur->line;
        err = at_tok_start( &line );
        if ( err < 0 ) goto error;

        err = at_tok_nextint( &line, &( result[n]->cid ) );
        if ( err < 0 ) goto error;

        err = at_tok_nextint( &line, &( result[n]->trafficclass ) );
        if ( err < 0 ) goto error;

        err = at_tok_nextint( &line, &( result[n]->maxbitrateul) );
        if ( err < 0 ) goto error;

        err = at_tok_nextint( &line, &( result[n]->maxbitratedl ) );
        if ( err < 0 ) goto error;
    }

    RIL_onRequestComplete( t, RIL_E_SUCCESS, result, count
            * sizeof(RIL_QOS_Info*) );
    at_response_free( p_response );
    return;

error: 
    RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
    at_response_free( p_response );
}

static void requestSetPdpQos( void * data , size_t datalen , RIL_Token t )
{
    ATResponse *p_response = NULL;
    int err;
    int cid;
    int trafficClass = 0x03;//back ground
    int maxBitrateUl = 512;
    int maxBitrateDl = 512;
    char *cmd = NULL;
    int * args = NULL;

    if ( data && datalen == 4 * sizeof(int) )
    {
        args = ( int* )data;

        cid = args[0] ;

        if( args[1] != -1 )
        {
            trafficClass = args[1];
        }

        if( args[2] != -1 )
        {
            maxBitrateUl = args[2] ;
        }

        if( args[3] != -1 )
        {
            maxBitrateDl = args[3] ;
        }
    }
    else
    {
        goto error;
    }

    if ( ( cid >= PDPID_MIN && cid <= PDPID_MAX ) && ( trafficClass >= 0x00 && trafficClass <= 0x04 ) )
    {
        asprintf( &cmd, "AT+CGEQREQ=%d,%d,%d,%d", cid, trafficClass, maxBitrateUl, maxBitrateDl );
    }
    else
    {
        LOGE( "set pdp Qos invalid parameter, cid = %d, trafficClass = %d\n", cid, trafficClass );
        goto error;
    }

    err = at_send_command_min_timeout( cmd, &p_response );
    free( cmd );
    if ( err < 0 || p_response->success == 0 )
    {
        LOGE( "set pdp Qos error\n" );
        goto error;
    }

    RIL_onRequestComplete( t, RIL_E_SUCCESS, NULL, 0 );
    at_response_free( p_response );

    return;

    error:

    RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
    at_response_free( p_response );    
}

static void requestSet2ndPdpContext(void * data , size_t datalen , RIL_Token t)
{
    int err;
    int cid, pid;
    int *args = NULL;
    char *cmd = NULL;
    ATResponse *p_response = NULL;

    if (data && datalen == 2 * sizeof(int)) {
        args = (int *)data;
        cid = args[0];
        pid = args[1];
    } else goto error;

    if ((cid >= PDPID_MIN && cid <= PDPID_MAX)
            && (pid >= PDPID_MIN && pid <= PDPID_MAX)) 
    {
        asprintf(&cmd, "AT+CGDSCONT=%d,%d", cid, pid);
    } else {
        LOGE("Set 2ndPDP context invalid parameter");
        goto error;
    }

    err = at_send_command_min_timeout(cmd, &p_response);
    free(cmd);
    if (err < 0 || p_response->success == 0) {
        LOGE( "Set 2ndPDP context failed");
        goto error;
    }

    RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
    at_response_free(p_response);

    return;

error:

    RIL_onRequestComplete(t, RIL_E_GENERIC_FAILURE, NULL, 0);
    at_response_free(p_response);
}

static void requestSetTDFreqUnLock( void * data, size_t datalen, RIL_Token t )
{
    int err = 0;
    int i = 0;
    int dstlen = 0;

    // FC + FreqNum + FreqInfo //
    unsigned short src[11];
    unsigned char * srcbinary = NULL;
    unsigned char * dstbinary = NULL;
    ATResponse * p_response = NULL;

    memset( src, 0xFFFF, sizeof( src ));

    // FC //
    src[0] = ( unsigned short )E_ATCMD_LOCKFREQ_SET;
    
    // FreqNum //
    src[1] = 0;

    srcbinary = ( unsigned char * )src;

    err = HandleBinaryStr( 
        "AT*", 
        srcbinary, sizeof( src ), 
        &dstbinary, &dstlen );
    LOGD( "dstlen = %d", dstlen );
    if ( err == 0 || dstbinary == NULL || dstlen== 0 ) goto error;
            
    err = at_send_egcmd( dstbinary, dstlen, &p_response );
    free( dstbinary );
    if ( err < 0 || p_response->success == 0 ) goto error;

    RIL_onRequestComplete( t, RIL_E_SUCCESS, NULL, 0 );
    at_response_free( p_response );

    return;
    
error:
    RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
    at_response_free( p_response );
}


static void requestSetTDCellUnLock( void * data, size_t datalen, RIL_Token t )
{
    int err = 0;
    int dstlen = 0;
    // FC + Cell Id //
    unsigned short src[2];
    unsigned char * srcbinary = NULL;
    unsigned char * dstbinary = NULL;
    ATResponse * p_response = NULL;

    memset( src, 0xFF, sizeof( src ));

    // FC //
    src[0] = ( unsigned short )E_ATCMD_LOCKCELL_SET;
    // cell id //
    src[1] = 255;
    srcbinary = ( unsigned char * )src;

    err = HandleBinaryStr( "AT*", srcbinary, sizeof( src ), &dstbinary, &dstlen );
    LOGD( "dstlen = %d", dstlen );
    if ( err == 0 || dstbinary == NULL || dstlen == 0 ) goto error;

    err = at_send_egcmd( dstbinary, dstlen, &p_response );
    free( dstbinary );

    if ( err < 0 || p_response->success == 0 ) goto error;

    RIL_onRequestComplete( t, RIL_E_SUCCESS, NULL, 0 );
    at_response_free( p_response );

    return;
    
error:
    RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
    at_response_free( p_response );
}


static void requestGetPowerSavingCtrl( void * data, size_t datalen, RIL_Token t )
{
    int Result = 0, err = 0;
    int dstlen = 0;
    unsigned char * srcbinary = NULL;
    unsigned char * dstbinary = NULL;
    unsigned short fc = ( unsigned short )E_ATCMD_POWER_SAVING_CTRL_GET;
    ATResponse * p_response = NULL;
    int response;
    
    srcbinary = ( unsigned char * )( &fc );

    err = HandleBinaryStr( "AT*", srcbinary, M_EGFC_LEN, &dstbinary, &dstlen );
    LOGD( "dstlen = %d", dstlen );
    if ( err == 0 || dstbinary == NULL || dstlen == 0 ) goto error;
    
    err = at_send_egcmd_singleline(dstbinary, dstlen, M_EGPREFIX, &p_response);
    free( dstbinary );

    if ( err < 0 || p_response->success == 0 )
    {
        goto error;
    }
    else
    {
        int prefixlen = 0;
        char * line = p_response->p_intermediates->line;

        prefixlen = M_EGPREFIX_LEN + M_EGFC_LEN + M_EGDATA_LEN;
        fc = *(( unsigned short * )( line + M_EGPREFIX_LEN ));
        
        if ( fc != E_ATCMD_POWER_SAVING_CTRL_GET )
        {
            LOGE( "Unmatching function code: %d." , fc);
            goto error;
        }

        // power saving state //
        response = *( line + prefixlen );

        RIL_onRequestComplete( t, RIL_E_SUCCESS, &response, sizeof( response ));
    }
    
    at_response_free( p_response );

    return;

error: 
    RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
    at_response_free( p_response );
}

static void requestSetPowerSavingCtrl( void * data, size_t datalen, RIL_Token t )
{
    int err = 0;
    int dstlen = 0;
    // FC + protocol version //
    unsigned char src[3];
    unsigned char * srcbinary = NULL;
    unsigned char * dstbinary = NULL;
    ATResponse * p_response = NULL;

    if ( data )
    {
        memset( src, 0xFF, sizeof( src ));

        // FC //
        src[0] = ( unsigned char )E_ATCMD_POWER_SAVING_CTRL_SET;
        src[1] = 0x00;
        // protocol version //
        src[2] = ( unsigned char )(*(( int * )data ));
        srcbinary = src;

        err = HandleBinaryStr( "AT*", srcbinary, sizeof( src ), &dstbinary, &dstlen );
        LOGD( "dstlen = %d", dstlen );
        if ( err == 0 || dstbinary == NULL || dstlen == 0 ) goto error;

        err = at_send_egcmd( dstbinary, dstlen, &p_response );
        free( dstbinary );

        if ( err < 0 || p_response->success == 0 ) goto error;
    }
    else 
    {
        LOGE( "Invalid parameters of set Gsm freq." );
        RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
        return;
    }

    RIL_onRequestComplete( t, RIL_E_SUCCESS, NULL, 0 );
    at_response_free( p_response );

    return;
    
error:
    RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
    at_response_free( p_response );
}

static void requestAtctstAud( void * data, size_t datalen, RIL_Token t )
{
    int err = 0;
    int prefixlen = 7;    // "^IFX:" + fc
    unsigned char * dstbinary = NULL;
    ATResponse * p_response = NULL;
    char * line = NULL;
    int len = 0;

    if ( data )
    {
        dstbinary = (unsigned char*)data;
        LOGD( "datalen = %d", datalen );
        dstbinary[datalen-1]= '\0';

        if ( dstbinary[3] == 0x00 ||dstbinary[3] ==0xfa)
        {
            if (dstbinary[2] == '#')
            {
                err = at_send_egcmd_singleline(dstbinary , datalen-1, M_IFXPREFIX, &p_response);
            }
            else
            {
                err = at_send_egcmd_singleline(dstbinary , datalen-1, M_EGPREFIX, &p_response);
            }

            //free( dstbinary );
            if ( err < 0 || p_response->success == 0 )
            {
                goto error;
            }
            else
            {
                line = p_response->p_intermediates->line;
                len = p_response->p_intermediates->len;

                RIL_onRequestComplete( t, RIL_E_SUCCESS, line,  len);
            }

            at_response_free( p_response );
            return;
        }
        else
        {
            int i = 0;
            for( i = 0 ; i < AT_FILTER__LIST_LENGTH ; i++)
            {
                if(!memcmp(dstbinary, ATCMD[i], strlen(ATCMD[i])))
                {
                    // Modified by CYIT 20130131 for adding time out mechanism
                    err= at_send_command_singleline_min_timeout(dstbinary,ATPREFIX[i],&p_response );

                    if ( err < 0 || p_response->success == 0 )
                    {
                        goto error;
                    }
                    else
                    {
                        line = p_response->p_intermediates->line;
                        LOGD( "line = %s", line );

                        RIL_onRequestComplete( t, RIL_E_SUCCESS, 
                                line,  strlen(line));
                    }

                    break;
                }
            }
            if(i >= AT_FILTER__LIST_LENGTH)
            {
                at_response_free( p_response );
                p_response = NULL;
                err= at_send_command(dstbinary,&p_response );

                if ( err < 0 || p_response->success == 0 )
                {
                    goto error;
                }
                else
                    RIL_onRequestComplete( t, RIL_E_SUCCESS, NULL,  0);
            }
            at_response_free( p_response );
            return;
        }

    }
    else 
    {
        LOGE( "Invalid parameters of Atcts Aud." );
        RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );

        return;
    }


error:

    RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
    at_response_free( p_response );
}

static void requestGetSSWInfo( void * data , size_t datalen , RIL_Token t )
{
    char *cmd;
    int err;
    char * line = NULL;
    ATResponse *p_response = NULL;
    char *response[10];

    memset(response, 0, sizeof(response));
    err = at_send_command_singleline_min_timeout("AT^SSWINFO", "^SSWINFO:", &p_response);
    if (err < 0 || p_response->success == 0) 
    {
        LOGE( "AT^SSWINFO err.");
    }
    else
    {
        line = p_response->p_intermediates->line;
        at_tok_start(&line);
        at_tok_nextstr(&line, &response[0]);
        at_tok_nextstr(&line, &response[1]);
        at_tok_nextstr(&line, &response[2]);
        at_tok_nextstr(&line, &response[3]);
        at_tok_nextstr(&line, &response[4]);
    }

    //modified by CYIT 20130109 for EngineerToolkit sofeware version
    err = at_send_command_singleline_min_timeout("AT^SHWINFO", "^SHWINFO:", &p_response);
    if (err < 0 || p_response->success == 0) 
    {
        LOGE( "AT^SHWINFO err.");
    }
    else
    {      
        line = p_response->p_intermediates->line;
        at_tok_start(&line);
        at_tok_nextstr(&line, &response[5]);
        at_tok_nextstr(&line, &response[6]);
        at_tok_nextstr(&line, &response[7]);
    }

    //modified by CYIT 20130109 for setting's sofeware version
    err = at_send_command_singleline_min_timeout("AT+CGMR", "", &p_response);
    if (err < 0 || p_response->success == 0) 
    {
        LOGE( "AT+CGMR err.");
    }
    else
    {
        line = p_response->p_intermediates->line;
        at_tok_nextstr(&line, &response[8]);
    }

    //modified by CYIT 20130109 for setting's hardware version
    err = at_send_command_singleline_min_timeout("AT^HVER", "^HVER:", &p_response);
    if (err < 0 || p_response->success == 0) 
    {
        LOGE( "AT^HVER err.");
    }
    else
    {
        line = p_response->p_intermediates->line;
        at_tok_start(&line);
        at_tok_nextstr(&line, &response[9]);
    }

    RIL_onRequestComplete(t, RIL_E_SUCCESS, response, sizeof(response));
    at_response_free(p_response);
    return;
}

static void requestEnterBios( void * data, size_t datalen, RIL_Token t )
{
    int ret;

    ret = at_send_command_min_timeout("AT^BIOS", NULL);

    // this command must success
    RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
}

static void requestGetLogCtrl( void * data, size_t datalen, RIL_Token t )
{
    int Result = 0, err = 0;
    int dstlen = 0;
    unsigned char * srcbinary = NULL;
    unsigned char * dstbinary = NULL;
    unsigned short fc = ( unsigned short )E_ATCMD_TRACEMODE_READ;
    ATResponse * p_response = NULL;
    int response;
    
    srcbinary = ( unsigned char * )( &fc );

    err = HandleBinaryStr( "AT*", srcbinary, M_EGFC_LEN, &dstbinary, &dstlen );
    LOGD( "dstlen = %d", dstlen );
    if ( err == 0 || dstbinary == NULL || dstlen == 0 ) goto error;
    
    err = at_send_egcmd_singleline(dstbinary, dstlen, M_EGPREFIX, &p_response);
    free( dstbinary );

    if ( err < 0 || p_response->success == 0 )
    {
        goto error;
    }
    else
    {
        int prefixlen = 0;
        char * line = p_response->p_intermediates->line;

        prefixlen = M_EGPREFIX_LEN + M_EGFC_LEN + M_EGDATA_LEN;
        fc = *(( unsigned short * )( line + M_EGPREFIX_LEN ));
        
        if ( fc != E_ATCMD_TRACEMODE_READ )
        {
            LOGE( "Unmatching function code: %d." , fc);
            goto error;
        }

        // baseband log ctrl state //
        response = *( line + prefixlen );

        RIL_onRequestComplete( t, RIL_E_SUCCESS, &response, sizeof( response ));
    }
    
    at_response_free( p_response );

    return;

error: 
    RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
    at_response_free( p_response );
}

static void requestSetLogCtrl( void * data, size_t datalen, RIL_Token t )
{
    int err = 0;
    int dstlen = 0;
    // FC + log control //
    unsigned char src[3];
    unsigned char * srcbinary = NULL;
    unsigned char * dstbinary = NULL;
    ATResponse * p_response = NULL;

    if ( data )
    {
        memset( src, 0xFF, sizeof( src ));

        // FC //
        src[0] = ( unsigned char )E_ATCMD_TRACEMODE_SET;
        src[1] = 0x00;
        // log control //
        src[2] = (unsigned char)(*(( int * )data ));

        srcbinary = src;

        err = HandleBinaryStr( "AT*", srcbinary, sizeof( src ), &dstbinary, &dstlen );
        LOGD( "dstlen = %d", dstlen );
        if ( err == 0 || dstbinary == NULL || dstlen == 0 ) goto error;

        err = at_send_egcmd( dstbinary, dstlen, &p_response );
        free( dstbinary );

        if ( err < 0 || p_response->success == 0 ) goto error;
    }
    else 
    {
        LOGE( "Invalid parameters of set Gsm freq." );
        RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
        return;
    }

    RIL_onRequestComplete( t, RIL_E_SUCCESS, NULL, 0 );
    at_response_free( p_response );

    return;

error:
    RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
    at_response_free( p_response );
}

static void requestGetUsbEnumCtrl( void * data, size_t datalen, RIL_Token t )
{
    int Result = 0, err = 0;
    int dstlen = 0;
    unsigned char * srcbinary = NULL;
    unsigned char * dstbinary = NULL;
    unsigned short fc = ( unsigned short )E_ATCMD_USB_ENUM_CTRL_GET;
    ATResponse * p_response = NULL;
    int response;

    srcbinary = ( unsigned char * )( &fc );

    err = HandleBinaryStr( "AT*", srcbinary, M_EGFC_LEN, &dstbinary, &dstlen );
    LOGD( "dstlen = %d", dstlen );
    if ( err == 0 || dstbinary == NULL || dstlen == 0 ) goto error;

    err = at_send_egcmd_singleline(dstbinary, dstlen, M_EGPREFIX, &p_response);
    free( dstbinary );

    if ( err < 0 || p_response->success == 0 )
    {
        goto error;
    }
    else
    {
        int prefixlen = 0;
        char * line = p_response->p_intermediates->line;

        prefixlen = M_EGPREFIX_LEN + M_EGFC_LEN + M_EGDATA_LEN;
        fc = *(( unsigned short * )( line + M_EGPREFIX_LEN ));
        
        if ( fc != E_ATCMD_USB_ENUM_CTRL_GET )
        {
            LOGE( "Unmatching function code: %d." , fc);
            goto error;
        }

        // usb enumerate control state //
        response = *( line + prefixlen );

        RIL_onRequestComplete( t, RIL_E_SUCCESS, &response, sizeof( response ));
    }

    at_response_free( p_response );

    return;

error: 
    RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
    at_response_free( p_response );
}

static void requestSetUsbEnumCtrl( void * data, size_t datalen, RIL_Token t )
{
    int err = 0;
    int dstlen = 0;
    // FC + usb enumerate control //
    unsigned char src[3];
    unsigned char * srcbinary = NULL;
    unsigned char * dstbinary = NULL;
    ATResponse * p_response = NULL;

    if ( data )
    {
        memset( src, 0xFF, sizeof( src ));

        // FC //
        src[0] = ( unsigned char )E_ATCMD_USB_ENUM_CTRL_SET;
        src[1] = 0x00;
        // usb enumerate control //
        src[2] = (unsigned char)(*(( int * )data ));

        srcbinary = src;

        err = HandleBinaryStr( "AT*", srcbinary, sizeof( src ), &dstbinary, &dstlen );
        LOGD( "dstlen = %d", dstlen );
        if ( err == 0 || dstbinary == NULL || dstlen == 0 ) goto error;

        err = at_send_egcmd( dstbinary, dstlen, &p_response );
        free( dstbinary );

        if ( err < 0 || p_response->success == 0 ) goto error;
    }
    else 
    {
        LOGE( "Invalid parameters of set usb enumerate control." );
        RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
        return;
    }

    RIL_onRequestComplete( t, RIL_E_SUCCESS, NULL, 0 );
    at_response_free( p_response );

    return;

error:
    RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
    at_response_free( p_response );
}

static void requestGetResetFlagCtrl( void * data, size_t datalen, RIL_Token t )
{
    int Result = 0, err = 0;
    int dstlen = 0;
    unsigned char * srcbinary = NULL;
    unsigned char * dstbinary = NULL;
    unsigned short fc = ( unsigned short )E_ATCMD_RESETFLAG_GET;
    ATResponse * p_response = NULL;
    int response;

    srcbinary = ( unsigned char * )( &fc );

    err = HandleBinaryStr( "AT*", srcbinary, M_EGFC_LEN, &dstbinary, &dstlen );
    LOGD( "dstlen = %d", dstlen );
    if ( err == 0 || dstbinary == NULL || dstlen == 0 ) goto error;

    err = at_send_egcmd_singleline(dstbinary, dstlen, M_EGPREFIX, &p_response);
    free( dstbinary );

    if ( err < 0 || p_response->success == 0 )
    {
        goto error;
    }
    else
    {
        int prefixlen = 0;
        char * line = p_response->p_intermediates->line;

        prefixlen = M_EGPREFIX_LEN + M_EGFC_LEN + M_EGDATA_LEN;
        fc = *(( unsigned short * )( line + M_EGPREFIX_LEN ));
        
        if ( fc != E_ATCMD_RESETFLAG_GET )
        {
            LOGE( "Unmatching function code: %d." , fc);
            goto error;
        }

        // reset flag Ctrl //
        response = *( line + prefixlen );

        RIL_onRequestComplete( t, RIL_E_SUCCESS, &response, sizeof( response ));
    }

    at_response_free( p_response );

    return;

error: 
    RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
    at_response_free( p_response );
}

static void requestSetResetFlagCtrl( void * data, size_t datalen, RIL_Token t )
{
    int err = 0;
    int dstlen = 0;
    // FC + reset flag //
    unsigned char src[3];
    unsigned char * srcbinary = NULL;
    unsigned char * dstbinary = NULL;
    ATResponse * p_response = NULL;

    if ( data )
    {
        memset( src, 0xFF, sizeof( src ));

        // FC //
        src[0] = ( unsigned char )E_ATCMD_RESETFLAG_SET;
        src[1] = 0x00;
        // reset flag Ctrl //
        src[2] = (unsigned char)(*(( int * )data ));

        srcbinary = src;

        err = HandleBinaryStr( "AT*", srcbinary, sizeof( src ), &dstbinary, &dstlen );
        LOGD( "dstlen = %d", dstlen );
        if ( err == 0 || dstbinary == NULL || dstlen == 0 ) goto error;

        err = at_send_egcmd( dstbinary, dstlen, &p_response );
        free( dstbinary );

        if ( err < 0 || p_response->success == 0 ) goto error;
    }
    else 
    {
        LOGE( "Invalid parameters of set reset flag." );
        RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
        return;
    }

    RIL_onRequestComplete( t, RIL_E_SUCCESS, NULL, 0 );
    at_response_free( p_response );

    return;

error:
    RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
    at_response_free( p_response );
}

static void requestGetVersionCtrl( void * data, size_t datalen, RIL_Token t )
{
    int response = getVersionInfo();

    RIL_onRequestComplete( t, RIL_E_SUCCESS, &response, sizeof( response ));

    return;
}

static void requestSetVersionCtrl( void * data, size_t datalen, RIL_Token t )
{
    int err = 0;
    int dstlen = 0;
    // FC + reset flag //
    unsigned char src[3];
    unsigned char * srcbinary = NULL;
    unsigned char * dstbinary = NULL;
    ATResponse * p_response = NULL;
    char * versionInfo = NULL;

    if ( data )
    {
        memset( src, 0xFF, sizeof( src ));

        // FC //
        src[0] = ( unsigned char )E_ATCMD_VERS_SET;
        src[1] = 0x00;
        // reset flag Ctrl //
        src[2] = (unsigned char)(*(( int * )data ));

        srcbinary = src;

        err = HandleBinaryStr( "AT*", srcbinary, sizeof( src ), &dstbinary, &dstlen );
        LOGD( "dstlen = %d", dstlen );
        if ( err == 0 || dstbinary == NULL || dstlen == 0 ) goto error;

        err = at_send_egcmd( dstbinary, dstlen, &p_response );
        free( dstbinary );

        if ( err < 0 || p_response->success == 0 ) goto error;
    }
    else 
    {
        LOGE( "Invalid parameters of set reset flag." );
        RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
        return;
    }

    if(src[2] == 0x00)
    {
        versionInfo = "0";
    }
    else if(src[2] == 0x01)
    {
        versionInfo = "1";
    }
    else if(src[2] == 0x02)
    {
        versionInfo = "2";
    }
    property_set("ril.version.control", versionInfo);

    RIL_onRequestComplete( t, RIL_E_SUCCESS, NULL, 0 );
    at_response_free( p_response );

    return;

error:
    RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
    at_response_free( p_response );
}

static void requestgetCellInfoList( void * data , size_t datalen , RIL_Token t )
{
    int err;
    int dstlen = 0;
    ATResponse *p_response = NULL;
    RIL_CELL_Info response;
    unsigned char * srcbinary = NULL;
    unsigned char * dstbinary = NULL;
    unsigned short fc = ( unsigned short )E_ATCMD_CELLINFO_READ;

    srcbinary = ( unsigned char * )( &fc );

    err = HandleBinaryStr( "AT*", srcbinary, M_EGFC_LEN, &dstbinary, &dstlen );
    LOGD( "dstlen = %d", dstlen );
    if ( err == 0 || dstbinary == NULL || dstlen == 0 ) goto error;
    
    err = at_send_egcmd_singleline(dstbinary, dstlen, M_EGPREFIX, &p_response);
    free( dstbinary );

    if ( err < 0 || p_response->success == 0 )
    {
        goto error;
    }
    else
    {
        int prefixlen = 0;
        char * line = p_response->p_intermediates->line;

        prefixlen = M_EGPREFIX_LEN + M_EGFC_LEN + M_EGDATA_LEN;
        fc = *(( unsigned short * )( line + M_EGPREFIX_LEN ));
        
        if ( fc != E_ATCMD_CELLINFO_READ )
        {
            LOGE( "Unmatching function code: %d." , fc);
            goto error;
        }

        response.cellfreq = *(( unsigned short * )( line + prefixlen ));
        response.cellid = *(( unsigned char * )( line + prefixlen + 2 ));
        response.cellrscp = *(( unsigned char * )( line + prefixlen + 3 ));
        response.tdcellnum = *(( unsigned short * )( line + prefixlen + 4 ));
        response.tdcell1freq = *(( unsigned short * )( line + prefixlen + 6 ));
        response.tdcell1id = *(( unsigned char * )( line + prefixlen + 8 ));
        response.tdcell1rscp = *(( unsigned char * )( line + prefixlen + 9 ));
        response.tdcell2freq = *(( unsigned short * )( line + prefixlen + 10 ));
        response.tdcell2id = *(( unsigned char * )( line + prefixlen + 12 ));
        response.tdcell2rscp = *(( unsigned char * )( line + prefixlen + 13 ));
        response.gsmcellnum = *(( unsigned short * )( line + prefixlen + 14 ));
        response.gsmcell1freq = *(( unsigned short * )( line + prefixlen + 16 ));
        response.gsmcell1id = *(( unsigned char * )( line + prefixlen + 18 ));
        response.gsmcell1rscp = *(( unsigned char * )( line + prefixlen + 19 ));
        response.gsmcell2freq = *(( unsigned short * )( line + prefixlen + 20 ));
        response.gsmcell2id = *(( unsigned char * )( line + prefixlen + 22 ));
        response.gsmcell2rscp = *(( unsigned char * )( line + prefixlen + 23 ));

        RIL_onRequestComplete( t, RIL_E_SUCCESS, &response, sizeof (RIL_CELL_Info));
    }
    
    at_response_free( p_response );

    return;

error: 
        RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
        at_response_free( p_response );
}

static void requestgetPrenetList( void * data , size_t datalen , RIL_Token t )
{
    char *cmd;
    int err;
    ATResponse *p_response = NULL;
    char *line;
    char *temp;
    RIL_PREFER_NETLIST **result;
    ATLine *p_cur;
    int n = 0;
    int count = 0;
        
    err = at_send_command_timeout( "AT+CPOL?", MULTILINE, "+CPOL:",
            &p_response, CYIT_DEFAULT_AT_TIMEOUT_MSEC );
    if ( err != 0 || p_response->success == 0 ) goto error;

    for ( p_cur = p_response->p_intermediates; p_cur != NULL; p_cur
                = p_cur->p_next, n++ )
        ;
    count = n;

    result = ( RIL_PREFER_NETLIST ** )alloca(count*sizeof(RIL_PREFER_NETLIST*));
    for ( p_cur = p_response->p_intermediates, n = 0; p_cur != NULL; p_cur
                = p_cur->p_next, n++ )
    {
        result[n] = ( RIL_PREFER_NETLIST * )alloca(sizeof(RIL_PREFER_NETLIST));

        line = p_cur->line;
        err = at_tok_start( &line );
        if ( err < 0 ) goto error;

        err = at_tok_nextint( &line, &( result[n]->index ) );
        if ( err < 0 ) goto error;
            
        err = at_tok_nextint( &line, &( result[n]->format ) );
        if ( err < 0 ) goto error;
            
        err = at_tok_nextstr( &line, &( result[n]->oper ) );
        if ( err < 0 ) goto error;

        if (at_tok_hasmore( &line ))
        {
            err = at_tok_nextint( &line, &( result[n]->gsm ) );
            if ( err < 0 ) goto error;
            
            err = at_tok_nextint( &line, &( result[n]->gsm_compact) );
            if ( err < 0 ) goto error;
            
            err = at_tok_nextint( &line, &( result[n]->utra ) );
            if ( err < 0 ) goto error;
        }
        else
        {
            result[n]->gsm = -1;
            result[n]->gsm_compact = -1;
            result[n]->utra = -1;
        }
    }

    RIL_onRequestComplete( t, RIL_E_SUCCESS, result, count
                * sizeof(RIL_PREFER_NETLIST*) );
    at_response_free( p_response );
    return;

error: 
    RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
    at_response_free( p_response );
}

static void requestsetPrenetList( void * data , size_t datalen , RIL_Token t )
{
    ATResponse *p_response = NULL;
    int err;
    int bitmap;
    int index;
    int format;
    char *operator;
    int gsm;
    int gsm_compact;
    int utra;
    char *cmd = NULL;
    int * args = NULL;

    if ( data )
    {
        bitmap = atoi(((char **)data)[0]);

        if ( bitmap == 0 )
        {
          format = atoi(((char **)data)[2]);
          operator  = ((char **)data)[3];
          gsm = atoi(((char **)data)[4]);
          gsm_compact = atoi(((char **)data)[5]);
          utra = atoi(((char **)data)[6]);
          asprintf( &cmd, "AT+CPOL=,%d,\"%s\",%d,%d,%d", format, operator, gsm, gsm_compact, utra );
          LOGD( "add prefer network list parameter: format = %d, operator = %s, gsm = %d, gsm_compact = %d, utra = %d\n", 
                format, operator, gsm, gsm_compact, utra );
        }
        else if ( bitmap == 1 )
        {
            index = atoi(((char **)data)[1]);
            asprintf( &cmd, "AT+CPOL=%d", index );
            LOGD( "delete prefer network list parameter: index = %d\n", index );
        }
        else if ( bitmap == 2 )
        {
            index = atoi(((char **)data)[1]);
            format = atoi(((char **)data)[2]);
            operator  = ((char **)data)[3];
            gsm = atoi(((char **)data)[4]);
            gsm_compact = atoi(((char **)data)[5]);
            utra = atoi(((char **)data)[6]);
            asprintf( &cmd, "AT+CPOL=%d,%d,\"%s\",%d,%d,%d", index, format, operator, gsm, gsm_compact, utra );
            LOGD( "update prefer network list parameter: index = %d, ormat = %d, operator = %s, gsm = %d, gsm_compact = %d, utra = %d\n", 
                index, format, operator, gsm, gsm_compact, utra );
        }
    }
    else
    {
        goto error;
    }

    err = at_send_command_timeout(cmd, NO_RESULT, NULL, &p_response, CYIT_AT_TIMEOUT_10_SEC);
    free( cmd );
    if ( err < 0 || p_response->success == 0 )
    {
        LOGE( "set prefer network list error\n" );
        goto error;
    }

    RIL_onRequestComplete( t, RIL_E_SUCCESS, NULL, 0 );
    at_response_free( p_response );

    return;

    error:

    RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
    at_response_free( p_response ); 
}

static void requestGetPowerOnAttachMode( void * data , size_t datalen , RIL_Token t )
{
    int err = 0;
    int state = 0;
    int response[1];
    char * line;
    ATResponse * p_response = NULL;

    err = at_send_command_singleline_min_timeout( "AT^SDATT?", "^SDATT:", &p_response );
    LOGW("err=%d,p_response->success = %d",err,p_response->success);
    if ( err != 0 || p_response->success == 0 )
    {
        goto error;
    }

    line = p_response->p_intermediates->line;
    err = at_tok_start( &line );
    if ( err < 0 )
    {
        goto error;
    }

    err = at_tok_nextint( &line, &state );
    if ( err < 0 )
    {
        goto error;
    }

    response[0] = state;

    RIL_onRequestComplete( t, RIL_E_SUCCESS, response, sizeof( response ) );
    at_response_free( p_response );

    return;

    error:

    RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
    at_response_free( p_response );
}

static void requestSetPowerOnAttachMode( void * data , size_t datalen , RIL_Token t )
{
    int err = 0;
    char * cmd;
    int * arg = NULL;
    int state = 0;
    ATResponse * p_response = NULL;

    if ( data )
    {
        arg = ( int * )data;
    }
    else
    {
        goto error;
    }

    state = arg[0];
    asprintf( &cmd, "AT^SDATT=%d", state );
    err = at_send_command_min_timeout( cmd, &p_response );
    LOGW("err=%d,p_response->success = %d",err,p_response->success);
    free( cmd );
    if ( err != 0 || p_response->success == 0 )
    {
        goto error;
    }

    RIL_onRequestComplete( t, RIL_E_SUCCESS, NULL, 0 );
    at_response_free( p_response );

    return;

    error: LOGW("go to err");
    RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
    at_response_free( p_response );
}

static void requestGetPowerOnNetSelCtrl( void * data, size_t datalen, RIL_Token t )
{
    int Result = 0, err = 0;
    int dstlen = 0;
    unsigned char * srcbinary = NULL;
    unsigned char * dstbinary = NULL;
    unsigned short fc = ( unsigned short )E_ATCMD_NETSELMODE_GET;
    ATResponse * p_response = NULL;
    int response;
    
    srcbinary = ( unsigned char * )( &fc );

    err = HandleBinaryStr( "AT*", srcbinary, M_EGFC_LEN, &dstbinary, &dstlen );
    LOGD( "dstlen = %d", dstlen );
    if ( err == 0 || dstbinary == NULL || dstlen == 0 ) goto error;
    
    err = at_send_egcmd_singleline(dstbinary, dstlen, M_EGPREFIX, &p_response);
    free( dstbinary );

    if ( err < 0 || p_response->success == 0 )
    {
        goto error;
    }
    else
    {
        int prefixlen = 0;
        char * line = p_response->p_intermediates->line;

        prefixlen = M_EGPREFIX_LEN + M_EGFC_LEN + M_EGDATA_LEN;
        fc = *(( unsigned short * )( line + M_EGPREFIX_LEN ));
        
        if ( fc != E_ATCMD_NETSELMODE_GET )
        {
            LOGE( "Unmatching function code: %d." , fc);
            goto error;
        }

        response = *( line + prefixlen );

        RIL_onRequestComplete( t, RIL_E_SUCCESS, &response, sizeof( response ));
    }
    
    at_response_free( p_response );

    return;

error: 
    RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
    at_response_free( p_response );
}

static void requestSetPowerOnNetSelCtrl( void * data, size_t datalen, RIL_Token t )
{
    int err = 0;
    int dstlen = 0;
    unsigned char src[3];
    unsigned char * srcbinary = NULL;
    unsigned char * dstbinary = NULL;
    ATResponse * p_response = NULL;

    if ( data )
    {
        memset( src, 0xFF, sizeof( src ));

        src[0] = ( unsigned char )E_ATCMD_NETSELMODE_SET;
        src[1] = 0x00;
        src[2] = (unsigned char)(*(( int * )data ));

        srcbinary = src;

        err = HandleBinaryStr( "AT*", srcbinary, sizeof( src ), &dstbinary, &dstlen );
        LOGD( "dstlen = %d", dstlen );
        if ( err == 0 || dstbinary == NULL || dstlen == 0 ) goto error;

        err = at_send_egcmd( dstbinary, dstlen, &p_response );
        free( dstbinary );

        if ( err < 0 || p_response->success == 0 ) goto error;
    }
    else 
    {
        LOGE( "Invalid parameters of power on network selected." );
        RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
        return;
    }

    RIL_onRequestComplete( t, RIL_E_SUCCESS, NULL, 0 );
    at_response_free( p_response );

    return;

error:
    RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
    at_response_free( p_response );
}

static void requestGetStopPdpDataCtrl( void * data, size_t datalen, RIL_Token t )
{
    int Result = 0, err = 0;
    int dstlen = 0;
    unsigned char * srcbinary = NULL;
    unsigned char * dstbinary = NULL;
    unsigned short fc = ( unsigned short )E_ATCMD_STOPDATAFLAG_GET;
    ATResponse * p_response = NULL;
    int response;
    
    srcbinary = ( unsigned char * )( &fc );

    err = HandleBinaryStr( "AT*", srcbinary, M_EGFC_LEN, &dstbinary, &dstlen );
    LOGD( "dstlen = %d", dstlen );
    if ( err == 0 || dstbinary == NULL || dstlen == 0 ) goto error;
    
    err = at_send_egcmd_singleline(dstbinary, dstlen, M_EGPREFIX, &p_response);
    free( dstbinary );

    if ( err < 0 || p_response->success == 0 )
    {
        goto error;
    }
    else
    {
        int prefixlen = 0;
        char * line = p_response->p_intermediates->line;

        prefixlen = M_EGPREFIX_LEN + M_EGFC_LEN + M_EGDATA_LEN;
        fc = *(( unsigned short * )( line + M_EGPREFIX_LEN ));
        
        if ( fc != E_ATCMD_STOPDATAFLAG_GET )
        {
            LOGE( "Unmatching function code: %d." , fc);
            goto error;
        }

        response = *( line + prefixlen );

        RIL_onRequestComplete( t, RIL_E_SUCCESS, &response, sizeof( response ));
    }
    
    at_response_free( p_response );

    return;

error: 
    RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
    at_response_free( p_response );
}

static void requestSetStopPdpDataCtrl( void * data, size_t datalen, RIL_Token t )
{
    int err = 0;
    int dstlen = 0;
    unsigned char src[3];
    unsigned char * srcbinary = NULL;
    unsigned char * dstbinary = NULL;
    ATResponse * p_response = NULL;

    if ( data )
    {
        memset( src, 0xFF, sizeof( src ));

        src[0] = ( unsigned char )E_ATCMD_STOPDATAFLAG_SET;
        src[1] = 0x00;
        src[2] = (unsigned char)(*(( int * )data ));

        srcbinary = src;

        err = HandleBinaryStr( "AT*", srcbinary, sizeof( src ), &dstbinary, &dstlen );
        LOGD( "dstlen = %d", dstlen );
        if ( err == 0 || dstbinary == NULL || dstlen == 0 ) goto error;

        err = at_send_egcmd( dstbinary, dstlen, &p_response );
        free( dstbinary );

        if ( err < 0 || p_response->success == 0 ) goto error;
    }
    else 
    {
        LOGE( "Invalid parameters of stop pdp data." );
        RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
        return;
    }

    RIL_onRequestComplete( t, RIL_E_SUCCESS, NULL, 0 );
    at_response_free( p_response );

    return;

error:
    RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
    at_response_free( p_response );
}

static void requestGetIPCheckCtrl( void * data, size_t datalen, RIL_Token t )
{
    int Result = 0, err = 0;
    int dstlen = 0;
    unsigned char * srcbinary = NULL;
    unsigned char * dstbinary = NULL;
    unsigned short fc = ( unsigned short )E_ATCMD_IPCHECKFLAG_GET;
    ATResponse * p_response = NULL;
    int response;
    
    srcbinary = ( unsigned char * )( &fc );

    err = HandleBinaryStr( "AT*", srcbinary, M_EGFC_LEN, &dstbinary, &dstlen );
    LOGD( "dstlen = %d", dstlen );
    if ( err == 0 || dstbinary == NULL || dstlen == 0 ) goto error;
    
    err = at_send_egcmd_singleline(dstbinary, dstlen, M_EGPREFIX, &p_response);
    free( dstbinary );

    if ( err < 0 || p_response->success == 0 )
    {
        goto error;
    }
    else
    {
        int prefixlen = 0;
        char * line = p_response->p_intermediates->line;

        prefixlen = M_EGPREFIX_LEN + M_EGFC_LEN + M_EGDATA_LEN;
        fc = *(( unsigned short * )( line + M_EGPREFIX_LEN ));
        
        if ( fc != E_ATCMD_IPCHECKFLAG_GET )
        {
            LOGE( "Unmatching function code: %d." , fc);
            goto error;
        }

        response = *( line + prefixlen );

        RIL_onRequestComplete( t, RIL_E_SUCCESS, &response, sizeof( response ));
    }
    
    at_response_free( p_response );

    return;

error: 
    RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
    at_response_free( p_response );
}

static void requestSetIPCheckCtrl( void * data, size_t datalen, RIL_Token t )
{
    int err = 0;
    int dstlen = 0;
    unsigned char src[3];
    unsigned char * srcbinary = NULL;
    unsigned char * dstbinary = NULL;
    ATResponse * p_response = NULL;

    if ( data )
    {
        memset( src, 0xFF, sizeof( src ));

        src[0] = ( unsigned char )E_ATCMD_IPCHECKFLAG_SET;
        src[1] = 0x00;
        src[2] = (unsigned char)(*(( int * )data ));

        srcbinary = src;

        err = HandleBinaryStr( "AT*", srcbinary, sizeof( src ), &dstbinary, &dstlen );
        LOGD( "dstlen = %d", dstlen );
        if ( err == 0 || dstbinary == NULL || dstlen == 0 ) goto error;

        err = at_send_egcmd( dstbinary, dstlen, &p_response );
        free( dstbinary );

        if ( err < 0 || p_response->success == 0 ) goto error;
    }
    else 
    {
        LOGE( "Invalid parameters of ip check." );
        RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
        return;
    }

    RIL_onRequestComplete( t, RIL_E_SUCCESS, NULL, 0 );
    at_response_free( p_response );

    return;

error:
    RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
    at_response_free( p_response );
}

static void requestGetSMSBear( void * data , size_t datalen , RIL_Token t )
{
    int err = 0;
    int state = 0;
    int response[1];
    char * line;
    ATResponse * p_response = NULL;

    err = at_send_command_singleline_timeout(
            "AT+CGSMS?", "+CGSMS:", &p_response, CYIT_AT_TIMEOUT_70_SEC);
    LOGW("err=%d,p_response->success = %d",err,p_response->success);
    if ( err != 0 || p_response->success == 0 )
    {
        goto error;
    }

    line = p_response->p_intermediates->line;
    err = at_tok_start( &line );
    if ( err < 0 )
    {
        goto error;
    }

    err = at_tok_nextint( &line, &state );
    if ( err < 0 )
    {
        goto error;
    }

    response[0] = state;

    RIL_onRequestComplete( t, RIL_E_SUCCESS, response, sizeof( response ) );
    at_response_free( p_response );

    return;

    error:

    RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
    at_response_free( p_response );
}

static void requestSetSMSBear( void * data , size_t datalen , RIL_Token t )
{
    int err = 0;
    char * cmd;
    int * arg = NULL;
    int state = 0;
    ATResponse * p_response = NULL;

    if ( data )
    {
        arg = ( int * )data;
    }
    else
    {
        goto error;
    }

    state = arg[0];
    asprintf( &cmd, "AT+CGSMS=%d", state );
    err = at_send_command_timeout(
            cmd, NO_RESULT, NULL, &p_response, CYIT_AT_TIMEOUT_70_SEC);
    LOGW("err=%d,p_response->success = %d",err,p_response->success);
    free( cmd );
    if ( err != 0 || p_response->success == 0 )
    {
        goto error;
    }

    RIL_onRequestComplete( t, RIL_E_SUCCESS, NULL, 0 );
    at_response_free( p_response );

    return;

    error: LOGW("go to err");
    RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
    at_response_free( p_response );
}

static void requestSetMoType( void * data, size_t datalen, RIL_Token t )
{
    int         err = 0;
    ATResponse *p_response = NULL;
    char       *cmd = NULL;
    char       *line;
    int        *paramter = (int *)data;
    int         moOperType = 0x00;
    int         mode = 0x00;

    int len = strlen(data);
    int i = 0;

    if(paramter != NULL)
    {
        for(i = 0; i < len ; i++) 
        moOperType = paramter[0];
        mode = paramter[1];
    }
    else
    {
        goto error;
    }

    if ( moOperType <= 0x04 && mode <= 0x03 )
    {
        asprintf( &cmd, "AT^SMOM=%d,%d", moOperType, mode );
    }
    else
    {
        goto error;
    }

    err = at_send_command_min_timeout( cmd, &p_response);
    free( cmd );

    if ( err < 0 || p_response->success == 0 )
    {
        goto error;
    }
    else
    {
        RIL_onRequestComplete( t, RIL_E_SUCCESS, NULL, 0 );
        at_response_free( p_response );
        return;
    }
    
error:
    RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
    at_response_free( p_response );
}

/*====================================================================

    FUNCTION: Turn source to binary array which be posted 
    to COM.
    RETURN VALUE: = 0 failed; > 0 successful.
    
    PARAMETER       IN/OUT      INFO
    -------------   ---------   -------------------------------------
    prefixstr       in          The prefix string of at command.
    srcbinary       in          The source binary array not include 
                                '\r' in the end, include function code 
                                in the begin and the order of bytes 
                                have been changed already.
    srclen          in          The size of <srcbinary>.
    dstbinary       out         The distination binary array, malloc 
                                from stack and need to be freed.
    dstlen          out         The size of <dstbinary>.
    
 ====================================================================*/
static unsigned char HandleBinaryStr( 
    char *prefixstr, 
    unsigned char *srcbinary, unsigned int srclen, 
    unsigned char **dstbinary, unsigned int *dstlen )
{
    int num = 0;
    int len = 0;
    int prefixlen = 0;
    unsigned char *p = NULL;
    T_CRPos *p_crpos = NULL, *p2 = NULL;
    
    if ( !prefixstr )
    {
        return 0;
    }
    else
    {
        prefixlen = strlen( prefixstr );
    }

    if ( !srcbinary || !srclen )
    {
        return 0;
    }

    if ( !dstbinary || !dstlen )
    {
        return 0;
    }

    p_crpos = ( T_CRPos * )malloc( sizeof( T_CRPos ) );
    p_crpos->m_pos = -1;
    p_crpos->m_pnext = NULL;

    LOGD( "begin to get <cr>, srclen = %d", srclen );
    GetCROfBinaryStr( srcbinary, srclen, &num, p_crpos );
    LOGD( "end get <cr> num = %d", num );

    // "AT*" + number of <crpos> + <crpos> + srclen //
    len = prefixlen + 1 + num + srclen;
    *dstlen = len;
    *dstbinary = ( unsigned char * )malloc( len );
    memset( *dstbinary, 0, len );

    p = *dstbinary;
    memcpy( p, prefixstr, prefixlen );
    p += prefixlen;
    *p++ = num;

    if ( num )
    {
        p2 = p_crpos;
        do
        {
            *p++ = p_crpos->m_pos;
            p_crpos = p_crpos->m_pnext;
            free( p2 );
            p2 = p_crpos;
        } while ( p2 );
    }
    else
    {
        free( p_crpos);
    }

    memcpy( p, srcbinary, srclen );

    return 1;
}

/*====================================================================

    FUNCTION: Find the postion of '\r' in the source binary array.
    RETURN VALUE: void.
    
    PARAMETER       IN/OUT      INFO
    -------------   ---------   -------------------------------------
    srcbinary       in          The source binary array not include 
                                '\r' in the end, include function code 
                                in the begin.
    srclen          in          The size of <srcbinary>.
    crnum           out         The number of '\r' in source binary array.
    crpos           out         The position of '\r'.
    
 ====================================================================*/
static void GetCROfBinaryStr( 
    unsigned char *srcbinary, int srclen, 
    int *crnum, T_CRPos *crpos )
{
    int i = 1;
    int num = 0;
    unsigned char *p_binary = srcbinary;
    T_CRPos *p_crpos = crpos;

    for ( ; i <= srclen; i++, p_binary++ )
    {
        if ( *p_binary == 0x0D )
        {
            *p_binary = 0x0C;

            if ( num > 0 )
            {
                p_crpos->m_pnext = ( T_CRPos * )malloc( sizeof( T_CRPos ) );
                p_crpos = p_crpos->m_pnext;
                p_crpos->m_pnext = NULL;
            }

            p_crpos->m_pos = i + 0x0D;
            num++;
        }
    }

    if ( num == 0x0D )
    {
        num = 0xFB;
    }
    *crnum = num;

    return;
}

/*======================================================

    Function: HexStrToByteArray
    Description: Turn hex string to bytes array.

    Args in:
        Sour: Hex string.
        SourLen: The length of hex string.
        DstLen: The length of bytes array.

    Args out:
        Dst: Bytes array.

    Return value:
        = 0: Error.
        = 1: Successful.

 =======================================================*/
static int HexStrToByteArray( char *Sour, unsigned int SourLen, 
    unsigned char *Dst, unsigned int DstLen )
{
    int i = 0;
    unsigned char tmp = 0;
    unsigned char *dst = Dst;

    if ( Sour == NULL || Dst == NULL )
    {
        return 0;
    }

    if ( SourLen == 0 || DstLen == 0 
        || SourLen % 2 > 0 || DstLen < SourLen / 2 )
    {
        return 0;
    }

    memset( Dst, 0, DstLen );

    for ( ; i < SourLen; )
    {
        tmp = 0;

        if      ( Sour[i] >= 65 && Sour[i] <= 70 )
        {
            tmp |= ( unsigned char )(( Sour[i] - 55 ) << 4 );
        }
        else if ( Sour[i] >= 97 && Sour[i] <= 102 )
        {
            tmp |= ( unsigned char )(( Sour[i] - 87 ) << 4 );
        }
        else if ( Sour[i] >= 48 && Sour[i] <= 57 )
        {
            tmp |= ( unsigned char )(( Sour[i] - 48 ) << 4 );
        }
        else
        {
            return 0;
        }

        i++;

        if      ( Sour[i] >= 65 && Sour[i] <= 70 )
        {
            tmp |= ( unsigned char )( Sour[i] - 55 );
        }
        else if ( Sour[i] >= 97 && Sour[i] <= 102 )
        {
            tmp |= ( unsigned char )( Sour[i] - 87 );
        }
        else if ( Sour[i] >= 48 && Sour[i] <= 57 )
        {
            tmp |= ( unsigned char )( Sour[i] - 48 );
        }
        else
        {
            return 0;
        }

        i++;
        *dst++ = tmp;
        LOGD( "*dst = %2X\n", tmp );
    }

    return 1;
}

static void resetPdpList()
{
    int pdpnum = 0;

    while (pdpnum < M_MAXNUM_PDP) {
        s_PSCtl[pdpnum].m_Used = 0;
        pdpnum++;
    }

    return;
}

static char * getPdpPort(char * PdpID)
{
    int pdpnum = 0;

    while (pdpnum < M_MAXNUM_PDP) {
        if (atoi(PdpID) == s_PSCtl[pdpnum].m_PID) {
            return s_PSCtl[pdpnum].m_Port;
        }

        pdpnum++;
    }

    return NULL;
}

static int getUnUsedPdp()
{
    int pdpnum = 0;

    while (pdpnum < M_MAXNUM_PDP) {
        if (0 == s_PSCtl[pdpnum].m_Used) {
            return s_PSCtl[pdpnum].m_PID;
        }

        pdpnum++;
    }

    return 0;
}

inline static int isMainPdp(int pdpid)
{
    return ((pdpid >= MAINPDPID_MIN 
     && pdpid <= MAINPDPID_MAX) ? 1 : 0);
}

static void requestGetIMEISV( void * data , size_t datalen , RIL_Token t )
{
    LOGD("requestGetIMEISV");
    int err = 0;
    char * line, *imeisv;
    ATResponse * p_response = NULL;

    err = at_send_command_singleline_min_timeout( "AT^SSSN=0,1", "^SSSN:", &p_response );

    if ( err != 0 || p_response->success == 0 )
    {
        goto error;
    }

    line = p_response->p_intermediates->line;
    LOGD("get IMEISV is %s", line);

    err = at_tok_start( &line );
    if ( err < 0 )
    {
        goto error;
    }

    err = at_tok_nextstr( &line, &( imeisv ) );
    if ( err < 0 )
    {
        goto error;
    }

    RIL_onRequestComplete( t, RIL_E_SUCCESS, imeisv, sizeof(char *) );
    at_response_free( p_response );

    return;

    error:

    RIL_onRequestComplete( t, RIL_E_GENERIC_FAILURE, NULL, 0 );
    at_response_free( p_response );
}
/**************************************************************************
  Modified by CYIT 20120825 ----- end -----
**************************************************************************/
