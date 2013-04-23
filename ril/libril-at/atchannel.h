/* //device/system/reference-ril/atchannel.h
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

#ifndef ATCHANNEL_H
#define ATCHANNEL_H 1

#ifdef USE_MULT_AT_CHAN
#define ATFLAGLEN 1
#else
#define ATFLAGLEN 0
#endif

#ifdef __cplusplus
extern "C"
{
#endif

/* define AT_DEBUG to send AT traffic to /tmp/radio-at.log" */
#define AT_DEBUG  0

#if AT_DEBUG
extern void  AT_DUMP(const char* prefix, const char*  buff, int  len);
#else
#define  AT_DUMP(prefix,buff,len)  do{}while(0)
#endif


// modify by CYIT 20120405 ----- start -----
#define CYIT_DEFAULT_AT_TIMEOUT_MSEC    30000
#define CYIT_MAX_AT_TIMEOUT_MSEC        60000
#define CYIT_MIN_AT_TIMEOUT_MSEC        4000
#define CYIT_OPER_AT_TIMEOUT_MSEC       120000
#define CYIT_PIN_AT_TIMEOUT_MSEC        90000

#define CYIT_MIN_AT_TIMEOUT_IMMEDIATE   2500

#define CYIT_AT_TIMEOUT_10_SEC          10000
#define CYIT_AT_TIMEOUT_40_SEC          40000
#define CYIT_AT_TIMEOUT_70_SEC          70000
#define CYIT_AT_TIMEOUT_80_SEC          80000

#define CYIT_AT_TIMEOUT_DEFAULT_POLL_NUM    3

#define CYIT_SAOC_TYPE_CALL             0x00
#define CYIT_SAOC_TYPE_SS               0x01
#define CYIT_SAOC_TYPE_SMS              0x02
#define CYIT_SAOC_TYPE_NET              0x03
#define CYIT_SAOC_TYPE_PDP_ACTIVE       0x04
#define CYIT_SAOC_TYPE_PDP_DEACTIVE     0x05
// modify by CYIT 20120405 -----  end  -----


#define AT_ERROR_GENERIC -1
#define AT_ERROR_COMMAND_PENDING -2
#define AT_ERROR_CHANNEL_CLOSED -3
#define AT_ERROR_TIMEOUT -4
#define AT_ERROR_INVALID_THREAD -5 /* AT commands may not be issued from
                                       reader thread (or unsolicited response
                                       callback */
#define AT_ERROR_INVALID_RESPONSE -6 /* eg an at_send_command_singleline that
                                        did not get back an intermediate
                                        response */

// modify by CYIT 20110407 //

#define AT_ERROR_INVALID_CMD -7 // Invalid AT cmd //

#define M_EGPREFIX "^ENG:"
#define M_EGPREFIX_LEN 5
#define M_EGFC_LEN 2
#define M_EGDATA_LEN 2
#define M_IFXPREFIX "^IFX:" //add for audiotest

// modify by CYIT 20110411 ----- start -----//

enum E_ATCMD_EG
{
    E_ATCMD_STATICNV_READ,
    E_ATCMD_STATICNV_WRITE,
    E_ATCMD_DYNAMICNV_READ,
    E_ATCMD_DYNAMICNV_WRITE,
    E_ATCMD_LOCKFREQ_READ,
    E_ATCMD_LOCKFREQ_SET,
    E_ATCMD_LOCKCELL_READ,
    E_ATCMD_LOCKCELL_SET,
    E_ATCMD_NFREQVER_READ,
    E_ATCMD_NFREQVER_SET,
    E_ATCMD_UECATE_READ,
    E_ATCMD_UECATE_SET,
    E_ATCMD_GSMLOCKFREQ_READ,   // 0x0C
    E_ATCMD_GSMLOCKFREQ_SET,    // 0x0D
    E_ATCMD_TRACEMODE_READ = 0x2D,
    E_ATCMD_TRACEMODE_SET = 0x2E,
    E_ATCMD_CELLINFO_READ = 0x30,
    E_ATCMD_FFREQ_READ = 0x31,
    E_ATCMD_FFREQ_SET = 0x32,
    E_ATCMD_VERS_READ = 0x33,
    E_ATCMD_VERS_SET = 0x34,
    E_ATCMD_STOPDATAFLAG_GET = 0x3C,
    E_ATCMD_STOPDATAFLAG_SET = 0x3D,
    E_ATCMD_RESETFLAG_GET = 0x3E,
    E_ATCMD_RESETFLAG_SET = 0x3F,
    E_ATCMD_RRMFLAG_GET = 0x40,
    E_ATCMD_RRMFLAG_SET = 0x41,
    E_ATCMD_IPCHECKFLAG_GET = 0x42,
    E_ATCMD_IPCHECKFLAG_SET = 0x43,
    E_ATCMD_NETSELMODE_GET = 0x44,
    E_ATCMD_NETSELMODE_SET = 0x45,
    E_ATCMD_USB_ENUM_CTRL_GET = 0x4B,
    E_ATCMD_USB_ENUM_CTRL_SET = 0x4C,
    E_ATCMD_POWER_SAVING_CTRL_GET = 0x4D,
    E_ATCMD_POWER_SAVING_CTRL_SET = 0x4E,
};
// modify by CYIT 20110411 -----  end  ----- //


// -------------------------------------------------------------------------
// modify by CYIT 20110524     ----- start -----
// -------------------------------------------------------------------------
typedef enum
{
    RADIO_TECHNOLOGY_APP_UNKNOWN = 0,
    RADIO_TECHNOLOGY_APP_GPRS,
    RADIO_TECHNOLOGY_APP_EDGE,
    RADIO_TECHNOLOGY_APP_UMTS,
    RADIO_TECHNOLOGY_APP_IS95A,
    RADIO_TECHNOLOGY_APP_IS95B,
    RADIO_TECHNOLOGY_APP_1xRTT,
    RADIO_TECHNOLOGY_APP_EVDO_0,
    RADIO_TECHNOLOGY_APP_EVDO_A,
    RADIO_TECHNOLOGY_APP_HSDPA,
    RADIO_TECHNOLOGY_APP_HSUPA,
    RADIO_TECHNOLOGY_APP_HSPA
} RIL_RAT_TYPE_APP;

typedef enum
{
    RADIO_TECHNOLOGY_BB_GSM = 0,
    RADIO_TECHNOLOGY_BB_GSMCOMPACT,
    RADIO_TECHNOLOGY_BB_UTRAN,
    RADIO_TECHNOLOGY_BB_EDGE,
    RADIO_TECHNOLOGY_BB_HSDPA,
    RADIO_TECHNOLOGY_BB_HSUPA,
    RADIO_TECHNOLOGY_BB_HSPA,
    RADIO_TECHNOLOGY_BB_EUTRAN,

    RADIO_TECHNOLOGY_BB_UNKNOWN = 0xFF
} RIL_RAT_TYPE_BB;
// -------------------------------------------------------------------------
// modify by CYIT 20110524     -----  end  -----
// -------------------------------------------------------------------------

// modify by CYIT 20110407 ----- start -----//

    typedef enum
    {
        NO_RESULT,      // no intermediate response expected //
        NUMERIC,        // a single intermediate response starting with a 0-9 //
        SINGLELINE,     // a single intermediate response starting with a prefix //
        MULTILINE,      // multiple line intermediate response starting with a prefix //
        MULTISMS,       // sms operate //
        EGATCMD,        // "^ENG:" AT cmd //
    } ATCommandType;

    /** a singly-lined list of intermediate responses */
    typedef struct ATLine
    {
        struct ATLine *p_next;
        char *line;
        int len;
    } ATLine;

// modify by CYIT 20110407 -----  end  -----//

    /** Free this with at_response_free() */
    typedef struct
    {
        int success; /* true if final response indicates success (eg "OK") */
        char *finalResponse; /* eg OK, ERROR */
        ATLine *p_intermediates; /* any intermediate responses */
    } ATResponse;

    typedef struct {
        ATCommandType type;
        const char * rspPrefix;
        const char * smsPDU;
        int egATLen;
    } ATRequest;

    /**
     * a user-provided unsolicited response handler function
     * this will be called from the reader thread, so do not block
     * "s" is the line, and "sms_pdu" is either NULL or the PDU response
     * for multi-line TS 27.005 SMS PDU responses (eg +CMT:)
     */
    typedef void (*ATUnsolHandler)(const char *s, const char *sms_pdu);

    int at_open(int fd, ATUnsolHandler h);
    void at_close();

    static int at_send_command_full_nolock( const char *command, const int cmdlen, 
        ATCommandType type, const char *responsePrefix, const char *smspdu,
        long long timeoutMsec, ATResponse **pp_outResponse );

    static int at_send_command_full( const char *command , ATCommandType type ,
        const char *responsePrefix , const char *smspdu ,
        long long timeoutMsec , ATResponse **pp_outResponse );

    /* This callback is invoked on the command thread.
     You should reset or handshake here to avoid getting out of sync */
    void at_set_on_timeout(void (*onTimeout)(void));
    /* This callback is invoked on the reader thread (like ATUnsolHandler)
     when the input stream closes before you call at_close
     (not when you call at_close())
     You should still call at_close()
     It may also be invoked immediately from the current thread if the read
     channel is already closed */
    void at_set_on_reader_closed(void (*onClose)(void));

    int at_send_command_singleline(const char *command ,
            const char *responsePrefix , ATResponse **pp_outResponse);

    int at_send_command_singleline_min_timeout( const char *command ,
        const char *responsePrefix , ATResponse **pp_outResponse );

    int at_send_command_singleline_timeout( const char *command ,
        const char *responsePrefix , ATResponse **pp_outResponse, long long timeout);

    int at_send_command_numeric(const char *command , ATResponse **pp_outResponse);

    int at_send_command_multiline(const char *command ,
            const char *responsePrefix , ATResponse **pp_outResponse);
    int at_send_command_multiline_timeout(const char *command ,
            const char *responsePrefix , long long timeoutMsec , ATResponse **pp_outResponse);
    int at_send_command_multiline_min_timeout( const char *command ,
            const char *responsePrefix , ATResponse **pp_outResponse );

    int at_handshake();

    int at_send_command(const char *command, ATResponse **pp_outResponse);
    int at_send_command_min_timeout(const char *command, ATResponse **pp_outResponse);
    int at_send_command_timeout_poll( const char * command , unsigned char commandtype ,
        const char * responsePrefix , ATResponse ** pp_outResponse , long long timeout, int pollNum );

    // modify by CYIT 20110407 ---- start -----//
    int at_send_egcmd( const char *command, const int cmdlen, 
        ATResponse **pp_outResponse );

    int at_send_egcmd_singleline( const char *command, const int cmdlen, 
        const char *responsePrefix, ATResponse **pp_outResponse );
    // modify by CYIT 20110407 ---- end ----- //

    int at_send_command_sms(const char * command,
            const char * pdu,
            const char * responsePrefix,
            ATResponse ** pp_outResponse,
            long long timeoutMsec);

    int at_send_command_timeout( const char * command ,
            unsigned char commandtype , const char * responsePrefix ,
            ATResponse ** pp_outResponse , long long timeout );

    int at_send_command_multiline_sms( const char *command ,
            const char *responsePrefix , ATResponse **pp_outResponse );

    void at_response_free(ATResponse *p_response);

    typedef enum
    {
        CME_ERROR_NON_CME = -1,
        CME_SUCCESS = 0,
        CME_OPERATION_NOT_ALLOWED = 3,
        CME_OPERATION_NOT_SUPPORTED = 4,
        CME_SIM_NOT_INSERTED = 10,
        CME_SIM_PIN_REQUIRED = 11,
        CME_SIM_PUK_REQUIRED = 12,
        CME_SIM_FAILURE = 13,
        CME_SIM_BUSY = 14,
        CME_SIM_WRONG = 15,
        CME_INCORRECT_PWD = 16,
        CME_SIM_PIN2_REQUIRED = 17,
        CME_SIM_PUK2_REQUIRED = 18,
        CME_NOTFOUND = 22,
    }AT_CME_Error;

    AT_CME_Error at_get_cme_error(const ATResponse *p_response);

#ifdef __cplusplus
}
#endif

#endif /*ATCHANNEL_H*/
