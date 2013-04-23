/* //device/system/reference-ril/atchannel.c
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

#include "atchannel.h"
#include "at_tok.h"

#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <ctype.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <telephony/ril.h>

#define LOG_NDEBUG 0
#define LOG_NIDEBUG 0
#define LOG_NDDEBUG 0
#define LOG_TAG "AT"
#include <utils/Log.h>

#ifdef HAVE_ANDROID_OS
/* for IOCTL's */
#include <linux/omap_csmi.h>
#endif /*HAVE_ANDROID_OS*/

#include "misc.h"

#ifdef HAVE_ANDROID_OS
#define USE_NP 1
#endif /* HAVE_ANDROID_OS */

#define NUM_ELEMS(x) (sizeof(x)/sizeof(x[0]))

#define MAX_AT_RESPONSE (8 * 1024)
#define HANDSHAKE_RETRY_COUNT 8
#define HANDSHAKE_TIMEOUT_MSEC 250

#define FINDCRLF(pos, len) \
    while (*pos != '\r' && *pos != '\n' && len > 0) { \
        pos++; len--; \
    }

#define SKIPCRLF(pos, len) \
    while ((*pos == '\r' || *pos == '\n') && len > 0) { \
        pos++; len--; \
    }


static pthread_t s_tid_reader;

#ifdef GSM_MUX_CHANNEL
fd_set readMuxs;
int nMuxfds;
int v_fds[RIL_CHANNELS]; /* fd of the AT channel */
#else
static int s_fd = -1; /* fd of the AT channel */
#endif
static ATUnsolHandler s_unsolHandler;

/* for input buffering */

static char s_ATBuffer[RIL_CHANNELS][MAX_AT_RESPONSE + 1];
static char * s_ATBufferCur[RIL_CHANNELS];

static int s_ackPowerIoctl; /* true if TTY has android byte-count
                                handshake for low power*/
static int s_readCount = 0;

// print AT data //
static unsigned char s_at_dump_buff_r[RIL_CHANNELS][3 * 1024];
static unsigned char s_at_dump_buff_w[RIL_CHANNELS][3 * 1024];

// Length of AT data unhandled //
//static int s_ATBufferLen;
static int s_ATBufferLen[RIL_CHANNELS] = {0};

// Length of "^ENG:" AT cmd //
//static int s_EGATLen;
// End modify //

// use for 2 step AT cmd //
static const char * s_2stepATReq[] = {"AT+CMGS=", "AT+CMGW="};
static int s_2stepFinished = 1;
static int s_stepFlag = 0;
static pthread_mutex_t s_2stepATMutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t s_2stepATCond = PTHREAD_COND_INITIALIZER;

extern int fd_ReqRead[];
extern int fd_ReqWrite[];
extern pthread_key_t CID;

// for check the baseband status
int s_basebandReadyFlag = 0;
int s_recoverFlag = 0;
int s_recoverChannel = 0xFF;

#if AT_DEBUG
void AT_DUMP(const char* prefix, const char* buff, int len)
{
    if (len < 0)
        len = strlen(buff);
    LOGD("%.*s", len, buff);
}
#endif

// for current pending write to VIPE //
static pthread_mutex_t s_commandmutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t s_commandcond = PTHREAD_COND_INITIALIZER;

//static ATCommandType s_type;
//static const char *s_responsePrefix = NULL;
//static const char *s_smsPDU = NULL;
//static ATResponse *sp_response = NULL;

static int s_Req[RIL_CHANNELS] = {0};

static void (*s_onTimeout)(void) = NULL;
static void (*s_onReaderClosed)(void) = NULL;
static int s_readerClosed;

static void onReaderClosed();
static int writeCtrlZ(const char *s, int cid);
static int writeline(const char *s, const int cmdlen, int cid);
static void at_processTimeout(int err, const char* smsPdu);

#ifndef USE_NP
static void setTimespecRelative(struct timespec *p_ts, long long msec)
{
    struct timeval tv;

    gettimeofday(&tv, (struct timezone *) NULL);

    /* what's really funny about this is that I know
       pthread_cond_timedwait just turns around and makes this
       a relative time again */
    p_ts->tv_sec = tv.tv_sec + (msec / 1000);
    p_ts->tv_nsec = (tv.tv_usec + (msec % 1000) * 1000L ) * 1000L;
}
#endif /*USE_NP*/

static void sleepMsec(long long msec)
{
    struct timespec ts;
    int err;

    ts.tv_sec = (msec / 1000);
    ts.tv_nsec = (msec % 1000) * 1000 * 1000;

    do {
        err = nanosleep (&ts, &ts);
    } while (err < 0 && errno == EINTR);
}



/** add an intermediate response to sp_response*/
/*
static void addIntermediate( const char *line )
{
    ATLine *p_new;

    p_new = ( ATLine * )malloc( sizeof( ATLine ));

    p_new->line = strdup( line );

    // note: this adds to the head of the list, so the list
    // will be in reverse order of lines received. the order is flipped
    // again before passing on to the command issuer
    p_new->p_next = sp_response->p_intermediates;
    sp_response->p_intermediates = p_new;
}
*/

// Add by dxy CYIT 2011-4-7 //
// Add "^ENG:" response to sp_response //
/*
static void addEGResponse( const char *line )
{
    ATLine *p_new;

    LOGD( "addEGResponse( ) s_EGATLen = %d", s_EGATLen );
    if ( s_EGATLen > 0 )
    {
        p_new = ( ATLine * )malloc( sizeof( ATLine ));
        p_new->line = ( char * )malloc( s_EGATLen );
        memset( p_new->line, 0, s_EGATLen );
        memcpy( p_new->line, line, s_EGATLen );
        p_new->len = s_EGATLen;
        s_EGATLen = 0;

        p_new->p_next = sp_response->p_intermediates;
        sp_response->p_intermediates = p_new;
    }
    else
    {
        LOGE( "Not ^ENG: response" );
    }
}
*/

static void addIntermediate(const char *line, ATResponse * response)
{
    ATLine *p_new;

    p_new = (ATLine *)malloc(sizeof(ATLine));
    p_new->line = strdup(line);

    // note: this adds to the head of the list, so the list
    // will be in reverse order of lines received. the order is flipped
    // again before passing on to the command issuer
    p_new->p_next = response->p_intermediates;
    response->p_intermediates = p_new;
}

static void addEGResponse(const char *line, ATRequest * request, ATResponse * response)
{
    ATLine *p_new;

    LOGD("addEGResponse( ) egATLen = %d", request->egATLen);
    if (request->egATLen > 0) {
        p_new = (ATLine *)malloc(sizeof(ATLine));
        p_new->line = (char *)malloc(request->egATLen);
        memset(p_new->line, 0, request->egATLen);
        memcpy(p_new->line, line, request->egATLen);
        p_new->len = request->egATLen;
        request->egATLen = 0;

        p_new->p_next = response->p_intermediates;
        response->p_intermediates = p_new;
    } else {
        LOGE("Not ^ENG: response");
    }
}
// End add //

/**
 * returns 1 if line is a final response indicating error
 * See 27.007 annex B
 * WARNING: NO CARRIER and others are sometimes unsolicited
 */
static const char * s_finalResponsesError[] = {
    "ERROR",
    "+CMS ERROR:",
    "+CME ERROR:",
    /*"NO CARRIER",*/ /* sometimes! */
    /*"NO ANSWER",
    "NO DIALTONE",*/
};
static int isFinalResponseError(const char *line)
{
    size_t i;

    for (i = 0 ; i < NUM_ELEMS(s_finalResponsesError) ; i++) {
        if (strStartsWith(line, s_finalResponsesError[i])) {
            return 1;
        }
    }

    return 0;
}

/**
 * returns 1 if line is a final response indicating success
 * See 27.007 annex B
 * WARNING: NO CARRIER and others are sometimes unsolicited
 */
static const char * s_finalResponsesSuccess[] = {
    "OK",
    "CONNECT"       /* some stacks start up data on another channel */
};
static int isFinalResponseSuccess(const char *line)
{
    size_t i;

    for (i = 0 ; i < NUM_ELEMS(s_finalResponsesSuccess) ; i++) {
        if (strStartsWith(line, s_finalResponsesSuccess[i])) {
            return 1;
        }
    }

    return 0;
}

/**
 * returns 1 if line is a final response, either  error or success
 * See 27.007 annex B
 * WARNING: NO CARRIER and others are sometimes unsolicited
 */
static int isFinalResponse(const char *line)
{
    return isFinalResponseSuccess(line) || isFinalResponseError(line);
}


/**
 * returns 1 if line is the first line in (what will be) a two-line
 * SMS unsolicited response
 */
static const char * s_smsUnsoliciteds[] = {
    "+CMT:",
    "+CDS:",
    "+CBM:"
};
static int isSMSUnsolicited(const char *line)
{
    size_t i;

    for (i = 0 ; i < NUM_ELEMS(s_smsUnsoliciteds) ; i++) {
        if (strStartsWith(line, s_smsUnsoliciteds[i])) {
            return 1;
        }
    }

    return 0;
}

/** assumes s_commandmutex is held */
/*
static void handleFinalResponse( const char *line )
{
    sp_response->finalResponse = strdup( line );
}
*/

static void handleFinalResponse(const char *line, ATResponse * response)
{
    response->finalResponse = strdup(line);
}

static void handleUnsolicited(const char *line)
{
    if (s_unsolHandler != NULL) {
        s_unsolHandler(line, NULL);
    }
}

/*
static void processLine( const char *line )
{
    if ( sp_response == NULL )
    {
        // no command pending //
        handleUnsolicited( line );
    }
    else if ( isFinalResponseSuccess( line ) )
    {
        sp_response->success = 1;
        handleFinalResponse( line );
    }
    else if ( isFinalResponseError( line ) )
    {
        sp_response->success = 0;
        handleFinalResponse( line );
    }
    else if ( s_smsPDU != NULL && 0 == strcmp( line, "> " ) )
    {
        // See eg. TS 27.005 4.3
        // Commands like AT+CMGS have a "> " prompt
        writeCtrlZ( s_smsPDU );
        s_smsPDU = NULL;
    }
    else
    {
        switch ( s_type )
        {
        case NO_RESULT:
            handleUnsolicited( line );
            break;
        case NUMERIC:
            if ( sp_response->p_intermediates == NULL && isdigit( line[0] ) )
            {
                addIntermediate( line );
            }
            else
            {
                // either we already have an intermediate response or
                 the line doesn't begin with a digit //
                handleUnsolicited( line );
            }
            break;
        case SINGLELINE:
            if ( sp_response->p_intermediates == NULL && strStartsWith( line,
                    s_responsePrefix ) )
            {
                addIntermediate( line );
            }
            else
            { 
                // we already have an intermediate response //
                handleUnsolicited( line );
            }
            break;
        case MULTILINE:
            if ( strStartsWith( line, s_responsePrefix ) )
            {
                addIntermediate( line );
            }
            else
            {
                handleUnsolicited( line );
            }
            break;

            // Add by dxy CYIT 2011-4-7 //

        case EGATCMD:
            if ( sp_response->p_intermediates == NULL 
                    && strStartsWith( line, s_responsePrefix ))
            {
                addEGResponse( line );
            }
            else
            {
                handleUnsolicited( line );
            }
            break;

            // End add //

        default: // this should never be reached //
            LOGE("Unsupported AT command type %d\n", s_type);
            handleUnsolicited( line );
            break;
        }
    }
}
*/

/**
 * Returns a pointer to the end of the next line
 * special-cases the "> " SMS prompt
 * special-cases the "^ENG:" AT cmd
 *
 * returns NULL if there is no complete line
 */
/*
static char * findNextEOL( char *cur )
{
    int egprefixlen = M_EGPREFIX_LEN + M_EGFC_LEN + M_EGDATA_LEN;
    int i = 0;

    // SMS prompt character...not '\r' terminated //
    if ( cur[0] == '>' && cur[1] == ' ' && cur[2] == '\0' )
    {
        return cur + 2;
    }

    // "^ENG:" AT cmd //
    if ( egprefixlen <= s_ATBufferLen 
            && (!memcmp( cur, M_EGPREFIX, M_EGPREFIX_LEN )||!memcmp( cur, M_IFXPREFIX, M_EGPREFIX_LEN )))
    {
        unsigned short egdatalen = 0;
        unsigned int egatlen = 0;

        LOGD( "Analyze ^ENG AT." );
        egdatalen = *(( unsigned short * )( cur + M_EGPREFIX_LEN + M_EGFC_LEN ));
        egatlen = egprefixlen + egdatalen;
        LOGD( "egdatalen = %d, egatlen = %d, s_ATBufferLen = %d", 
            egdatalen, egatlen, s_ATBufferLen );

        if ( egatlen <= s_ATBufferLen )
        {
            s_EGATLen = egatlen;
            LOGD( "findNextEOL( ) s_EGATLen = %d", s_EGATLen );
            
            return cur + egatlen - 1;
        }
        else
        {
            return NULL;
        }
    }

    // Normal AT, turn to string //
    while ( i < s_ATBufferLen && *cur != '\r' && *cur != '\n' )
    {
        cur++;
        i++;
    }

    if ( i >= s_ATBufferLen )
    {
        return NULL;
    }
    else
    {
        *cur = '\0';
        return cur;
    }
}
*/

/**
 * Reads a line from the AT channel, returns NULL on timeout.
 * Assumes it has exclusive read access to the FD
 *
 * This line is valid only until the next call to readline
 *
 * This function exists because as of writing, android libc does not
 * have buffered stdio.
 */
/*
static const char *readline( )
{
    ssize_t count;
    ssize_t i;

    // Pointer that begin to read from device //
    char *p_read = NULL;
    char *p_eol = NULL;
    char *ret;

    // All AT data be handled //
    if ( s_ATBufferLen == 0 )
    {
        LOGD( "No AT data in buffer." );
        s_ATBufferCur = s_ATBuffer;
        p_read = s_ATBuffer;
    }

    // There's data in the buffer from the last read //
    else
    {
        LOGD( "Last AT data in buffer." );
        LOGD( "1 s_ATBufferLen = %d", s_ATBufferLen );
        p_read = s_ATBufferCur + s_ATBufferLen;
    
        // Skip over leading newlines //
        while ( s_ATBufferLen > 0 
               &&  ( *s_ATBufferCur == '\r' 
                || *s_ATBufferCur == '\n' ))
        {
            s_ATBufferCur++;
            s_ATBufferLen--;
        }

        if ( s_ATBufferLen > 0 )
        {
            LOGD( "Find the eol 1." );
            p_eol = findNextEOL( s_ATBufferCur );
        }

        LOGD( "2 s_ATBufferLen = %d", s_ATBufferLen );
        if ( p_eol == NULL )
        {
            LOGD( "Last AT data is not full." );
        
            // A partial line. move it up and prepare to read more //
            memmove( s_ATBuffer, s_ATBufferCur, s_ATBufferLen );
            p_read = s_ATBuffer + s_ATBufferLen;
            s_ATBufferCur = s_ATBuffer;

#ifdef USE_CYIT_COMMANDS
            //memset( s_ATBufferCur, 0, sizeof( s_ATBufferCur ) );
#endif
        }
        // Otherwise, (p_eol != NULL) there is a complete line  //
        // that will be returned the while () loop below        //
    }

    while ( p_eol == NULL )
    {
        if ( 0 == MAX_AT_RESPONSE - ( p_read - s_ATBuffer ))
        {
            LOGE( "ERROR: Input line exceeded buffer\n" );

            // Ditch buffer and start over again //
            s_ATBufferCur = s_ATBuffer;
            s_ATBufferLen = 0;
            p_read = s_ATBuffer;
        }

        LOGD( "Begin to read device." );

        do
        {
            count = read( s_fd, p_read, 
                    MAX_AT_RESPONSE - ( p_read - s_ATBuffer ));
        }
        while ( count < 0 && errno == EINTR );

        if ( count > 0 )
        {
            AT_DUMP( "<< ", p_read, count );
            LOGD( "read count:%d",count );
            memset( s_at_dump_buff_r, 0, sizeof( s_at_dump_buff_r ));
            for ( i = 0; i < count && i < sizeof( s_at_dump_buff_r ) / 3; i++ ) 
            {
                sprintf( s_at_dump_buff_r + i * 3, "%02x ", p_read[i] );
            }
            LOGD( "%s",s_at_dump_buff_r );
            
            s_readCount += count;
            s_ATBufferLen += count;
            LOGD( "3 s_ATBufferLen = %d", s_ATBufferLen );
            
            // skip over leading newlines //
            while ( s_ATBufferLen > 0 
               &&  ( *s_ATBufferCur == '\r' 
                || *s_ATBufferCur == '\n' ))
            {
                s_ATBufferCur++;
                s_ATBufferLen--;
            }

            LOGD( "4 s_ATBufferLen = %d", s_ATBufferLen );
            LOGD( "Find the eol 2." );
            p_eol = findNextEOL( s_ATBufferCur );
            p_read += count;
        }
        else if ( count <= 0 )
        {
            // read error encountered or EOF reached //
            if ( count == 0 )
            {
                LOGD( "atchannel: EOF reached" );
            }
            else
            {
                LOGD( "atchannel: read error %s", strerror( errno ));
            }

            return NULL;
        }
    }

    LOGD( "Return full AT data." );

    ret = s_ATBufferCur;
    s_ATBufferCur = p_eol + 1;
    s_ATBufferLen = p_read -  s_ATBufferCur;

    LOGD("AT< %s\n", ret);
    return ret;
}
*/

static void processLine(const char *line, int cid, 
        ATRequest * request, ATResponse * response)
{
    if(s_recoverFlag && s_recoverChannel == cid){
        if(s_recoverFlag <= 3){
            char *cmd = NULL;
            char *pts = NULL;
            asprintf(&cmd, "^SUTEST: %d", s_recoverFlag);
            pts = strstr(line, cmd);
            free(cmd);
            if(pts == NULL){
                LOGE("[REQ%d]: WARNING!! not match the special respons yet", cid);
                return;
            }else{
                LOGE("[REQ%d]: match the special respons", cid);
                s_recoverFlag = 0;
            }
        }else{
            LOGE("[REQ%d]: s_recoverFlag must be ERROR!!", cid);
        }
    }

    if (response == NULL) {
        /* no command pending */
        handleUnsolicited(line);
    } else if (isFinalResponseSuccess(line)) {
        response->success = 1;
        handleFinalResponse(line, response);
    } else if (isFinalResponseError(line)) {
        response->success = 0;
        handleFinalResponse(line, response);
    } else if (request->smsPDU != NULL && 0 == strcmp(line, "> ")) {
        // See eg. TS 27.005 4.3
        // Commands like AT+CMGS have a "> " prompt
        pthread_mutex_lock(&s_commandmutex);
        if(s_stepFlag == 0){
            writeCtrlZ(request->smsPDU, cid + 1);
            s_stepFlag = 1;
        }else if(s_stepFlag == 1){
            s_stepFlag = 2;
            pthread_mutex_lock(&s_2stepATMutex);
            s_2stepFinished = 1;
            pthread_cond_broadcast(&s_2stepATCond);
            pthread_mutex_unlock(&s_2stepATMutex);
            LOGD("[REQ%d]: 2 step command finished, release mutex", cid);
        }else{
            LOGE("[REQ3]Send SMS procedure para:s_stepFlag MUST BE ERROR!!!\n");
        }
        pthread_mutex_unlock(&s_commandmutex);
    } else {
        switch (request->type) {
        case NO_RESULT:
            handleUnsolicited(line);
            break;
        case NUMERIC:
            if (response->p_intermediates == NULL && isdigit(line[0])) {
                addIntermediate(line, response);
            } else {
                // either we already have an intermediate response or //
                // the line doesn't begin with a digit //
                handleUnsolicited(line);
            }
            break;

        case SINGLELINE:
            if (response->p_intermediates == NULL 
                    && strStartsWith(line, request->rspPrefix)) {
                addIntermediate(line, response);
            } else {
                // we already have an intermediate response //
                handleUnsolicited(line);
            }
            break;

        case MULTILINE:
            if (strStartsWith(line, request->rspPrefix)) {
                addIntermediate(line, response);
            } else {
                handleUnsolicited(line);
            }
            break;

        case EGATCMD:
            if (response->p_intermediates == NULL 
                    && strStartsWith(line, request->rspPrefix)) {
                addEGResponse(line, request, response);
            }
            break;

        // this should never be reached //
        default: 
            LOGE("[REQ%d]Unsupported AT command type %d\n", cid, request->type);
            handleUnsolicited(line);
            response->success = 0;
            handleFinalResponse("ERROR", response);
            break;
        }
    }
}

static char * findNextEOL(char *cur, int cid, ATRequest * request)
{
    int egprefixlen = M_EGPREFIX_LEN + M_EGFC_LEN + M_EGDATA_LEN;
    int i = 0;

    // SMS prompt character...not '\r' terminated //
    // our BB return 0d 0a 0d 0a 3e 20 0d 0a like normal AT data ??? //
    /*
    if (cur[0] == '>' && cur[1] == ' ' && cur[2] == '\0') {
        return cur + 2;
    }
    */

    // "^ENG:" AT cmd //
    if (egprefixlen <= s_ATBufferLen[cid] 
        && (!memcmp(cur, M_EGPREFIX, M_EGPREFIX_LEN) 
            || !memcmp(cur, M_IFXPREFIX, M_EGPREFIX_LEN))
    ) {
        unsigned short egdatalen = 0;
        unsigned int egatlen = 0;

        //LOGD("[REQ%d]: Analyze ^ENG AT.", cid);
        egdatalen = *((unsigned short *)(cur + M_EGPREFIX_LEN + M_EGFC_LEN));
        egatlen = egprefixlen + egdatalen;
        //LOGD("[REQ%d]: egdatalen = %d, egatlen = %d, s_ATBufferLen = %d", 
            //cid, egdatalen, egatlen, s_ATBufferLen[cid]);

        if (egatlen <= s_ATBufferLen[cid]) {
            request->egATLen = egatlen;
            //LOGD("[REQ%d]: findNextEOL() egATLen = %d", cid, request->egATLen);
            
            return cur + egatlen - 1;
        } else {
            return NULL;
        }
    }

    // Normal AT, turn to string //
    while (i < s_ATBufferLen[cid] && *cur != '\r' && *cur != '\n' ) {
        cur++;
        i++;
    }

    if (i >= s_ATBufferLen[cid]) {
        return NULL;
    } else {
        *cur = '\0';
        return cur;
    }
}

static void readline(int cid, ATRequest * request, ATResponse * response)
{
    ssize_t count;
    ssize_t i;

    // Pointer that begin to read from device //
    char *p_read = NULL;
    char *p_eol = NULL;
    char *ret = NULL;

    // base on mechanism of time out we read AT line once a time //
    int readed = 0;
    
    do {
        p_eol = NULL;

        // All AT data be handled //
        if (s_ATBufferLen[cid] == 0) {
            //LOGD("[REQ%d]: No AT data in buffer.", cid);
            s_ATBufferCur[cid] = s_ATBuffer[cid];
            p_read = s_ATBuffer[cid];
        }

        // There's data in the buffer from the last read //
        else {
            //LOGD("[REQ%d]: Last AT data in buffer.", cid);
            //LOGD("[REQ%d]: 1 s_ATBufferLen = %d", cid, s_ATBufferLen[cid]);
            p_read = s_ATBufferCur[cid] + s_ATBufferLen[cid];

            // Skip over leading <CR><LF> //
            SKIPCRLF(s_ATBufferCur[cid], s_ATBufferLen[cid]);

            if (s_ATBufferLen[cid] > 0) {
                //LOGD("[REQ%d]: Find the eol 1.", cid);
                p_eol = findNextEOL(s_ATBufferCur[cid], cid, request);
            }

            //LOGD("[REQ%d]: 2 s_ATBufferLen = %d", cid, s_ATBufferLen[cid]);
            if (p_eol == NULL) {
                LOGD("[REQ%d]: Last AT data is not full.", cid);

                // A partial line. move it up and prepare to read more //
                memmove(s_ATBuffer[cid], s_ATBufferCur[cid], s_ATBufferLen[cid]);
                p_read = s_ATBuffer[cid] + s_ATBufferLen[cid];
                s_ATBufferCur[cid] = s_ATBuffer[cid];
            }

            // Otherwise, (p_eol != NULL) there is a complete line  //
            // that will be returned the while () loop below        //
        }

        if (p_eol == NULL && readed == 0) {
            if (0 == MAX_AT_RESPONSE - (p_read - s_ATBuffer[cid])) {
                LOGE("[REQ%d]: ERROR: Input line exceeded buffer\n", cid);

                // Ditch buffer and start over again //
                s_ATBufferCur[cid] = s_ATBuffer[cid];
                s_ATBufferLen[cid] = 0;
                p_read = s_ATBuffer[cid];
            }

            //LOGD( "[REQ%d]: Begin to read device.", cid );

            do {
                count = read(fd_ReqRead[cid], p_read, 
                        MAX_AT_RESPONSE - (p_read - s_ATBuffer[cid]));
                readed++;
            } while (count < 0 && errno == EINTR);

            if (count > 0) {
                AT_DUMP("<< ", p_read, count);
                memset(s_at_dump_buff_r[cid], 0, sizeof(s_at_dump_buff_r[cid]));
                for (i = 0; i < count 
                        && i < sizeof(s_at_dump_buff_r[cid]) / 3; i++) {
                    sprintf(s_at_dump_buff_r[cid] + i * 3, "%02x ", p_read[i]);
                }
                LOGD("[REQ%d]: read at data(%d):%s", cid, count, s_at_dump_buff_r[cid]);

                s_ATBufferLen[cid] += count;
                LOGD("[REQ%d]: 3 s_ATBufferLen = %d", cid, s_ATBufferLen[cid]);

                // skip over leading newlines //
                SKIPCRLF(s_ATBufferCur[cid], s_ATBufferLen[cid]);

                //LOGD("[REQ%d]: 4 s_ATBufferLen = %d", cid, s_ATBufferLen[cid]);
                //LOGD("[REQ%d]: Find the eol 2.", cid);
                p_eol = findNextEOL(s_ATBufferCur[cid], cid, request);
                p_read += count;
            } else {
                // read error encountered or EOF reached //
                // fd_ReqWrite & fd_ReqRead are closed after s_readerClosed set 1 //
                if (count == 0) {
                    LOGD("[REQ%d]: atchannel: EOF reached", cid);
                } else {
                    LOGD("[REQ%d]: atchannel: read error %s, should never happen", 
                            cid, strerror(errno));
                }

                //close(fd_ReqRead[cid]);
                //return;
            }
        } // if (p_eol == NULL && readed == 0) //

        if (p_eol != NULL) {
            //LOGD("[REQ%d]: Return full AT data.", cid);
            ret = s_ATBufferCur[cid];
            s_ATBufferCur[cid] = p_eol + 1;
            s_ATBufferLen[cid] = p_read -  s_ATBufferCur[cid];
            LOGD("[REQ%d]: AT< %s\n", cid, ret);

            processLine(ret, cid, request, response);
        }
    } while (p_eol != NULL);

    //LOGD("[REQ%d]: readline finished", cid);
}

// End modify //

/*
static void onReaderClosed( )
{
    if ( s_onReaderClosed != NULL && s_readerClosed == 0 )
    {

        pthread_mutex_lock( &s_commandmutex );

        s_readerClosed = 1;

        pthread_cond_broadcast( &s_commandcond );

        pthread_mutex_unlock( &s_commandmutex );

        s_onReaderClosed( );
    }
}
*/

static void onReaderClosed()
{
    int i = 0;

    if (s_onReaderClosed != NULL && s_readerClosed == 0) {
        s_readerClosed = 1;
        s_onReaderClosed();
        for (; i < RIL_CHANNELS; i++) {
            close(fd_ReqWrite[i]);
            close(fd_ReqRead[i]);
        }
    }
}

/*
 * return AT flag, 0 means not whole AT
 * Out Len means the length of whole AT without <CR><LF> and flag
 */
static int getATFlag(char ** pCur, int * Len, ssize_t * Count)
{
    static int flag = RIL_CHANNELID_MIN; // static variant use to store AT flag //
    char * p = *pCur;
    ssize_t count = *Count;
    int egprefixlen = M_EGPREFIX_LEN + ATFLAGLEN;

    // 1) SMS prompt character...not '\r' terminated //
    // our BB return 0d 0a 0d 0a 3e 20 0d 0a like normal AT data ??? //
    /*
    if (4 <= count && p[1] == '>' && p[2] == ' ' && p[3] == '\0') {
        flag = p[0];

        // return SMS prompt character, should skip first AT flag //
        *Len = 3;
        *Len = 2;
        (*pCur)++;
        (*Count)--;

        return flag;
    }
    */

    // 2) "^ENG:" AT cmd no <CR><LF> but begin with AT flag //
    // so need to skip 1st byte as p + 1 downstairs //
    if (egprefixlen <= count 
            && (!memcmp(p + ATFLAGLEN, M_EGPREFIX, M_EGPREFIX_LEN)
            || !memcmp(p + ATFLAGLEN, M_IFXPREFIX, M_EGPREFIX_LEN))) {
        unsigned short egdatalen = 0;
        unsigned int egatlen = 0;

#ifdef USE_MULT_AT_CHAN
        // get AT flag and skip //
        flag = *p++;
#endif

        // not include fc and length fields //
        if (count < egprefixlen + M_EGFC_LEN + M_EGDATA_LEN) {
            return 0;
        }

        egdatalen = *((unsigned short *)(p + M_EGPREFIX_LEN + M_EGFC_LEN));
        egatlen = egprefixlen + M_EGFC_LEN + M_EGDATA_LEN + egdatalen;
        if (egatlen <= count) {
            // skip AT flag //
            *Len = egatlen - ATFLAGLEN;
#ifdef USE_MULT_AT_CHAN
            (*pCur)++;
#endif
            (*Count)--;
            return flag;
        }

        // not whole "^ENG:" AT cmd // 
        else return 0;
    }

    // find position of <CR><LF> end of AT data //
    FINDCRLF(p, count);

    if (count > 0) {

        // 3) length 1 means AT flag //
        if (p - *pCur == ATFLAGLEN) {
            flag = (*pCur)[0];
            *Len = p - *pCur;
            return flag;
        }

        // 4) normal AT data //
        //if (flag == RIL_CHANNEL_URC) *p++ = '\0';
        *Len = p - *pCur;
        return flag;
    }

    // not whole normal AT //
    else return 0;
}

static void * readerLoop(void *arg)
{
	int rev = 0;
	int flag = 0;
	int i = 0;
	int len = 0; // whole AT data length //
	char tempbuf[1024 * 3]; // use to print AT command //
	char atbuf[1024 * 2], atdata[1024];
	char * pcur;
	ssize_t count = 0;
	char * smsprefix = NULL;
	int readcount = 0;
#ifdef GSM_MUX_CHANNEL
	fd_set muxs;
	int j = 0;
	int n = 0;
	char urcbuf[1024 * 2];
	int urcbufLen = 0;

	if(urcbufLen == 0x00){
		memset(urcbuf, 0x00, 1024 * 2);
	}
#endif

	while (1) {
#ifdef GSM_MUX_CHANNEL
		// update muxs in select() //
		memcpy(&muxs, &readMuxs, sizeof(fd_set));	//所有的fd都放入检查

		n = select(nMuxfds, &muxs, NULL, NULL, NULL);
		for (j = 0; ((j + 1) <= RIL_CHANNELS) && (n > 0); j++) {
			if (FD_ISSET(v_fds[j], &muxs))		//检查出来其中一个有数据
			{
#endif

				do {
					readcount = 0;
#ifdef GSM_MUX_CHANNEL
					readcount = read(v_fds[j], atbuf + count, sizeof(atbuf) - count);		//独到的数据暂存放入atbuf
#else
					readcount = read(s_fd, atbuf + count, sizeof(atbuf) - count);
#endif
					count += readcount;
				} while (readcount < 0 && errno == EINTR);

				if (readcount > 0) {		//有读取到的数据，进行处理 
					pcur = atbuf;

					memset(tempbuf, 0, sizeof(tempbuf));
					for (i = 0; i < count && i < sizeof(tempbuf) / 3; i++) {
						sprintf(tempbuf + i * 3, "%02x ", pcur[i]);
					}
					LOGD("[READER MUX]: channel%d handle %d bytes: %s", j, count, tempbuf);

#ifdef GSM_MUX_CHANNEL
					if((j + 1) == RIL_CHANNEL_URC)	//随时相应的，比如短信，电话打入
					{
#endif

						while (count > 0) {

#ifdef GSM_MUX_CHANNEL
							memcpy(&urcbuf[urcbufLen], pcur, count);
							pcur = urcbuf;
#endif

							memset(tempbuf, 0, sizeof(tempbuf));
							for (i = 0; i < count && i < sizeof(tempbuf) / 3; i++) {
								sprintf(tempbuf + i * 3, "%02x ", pcur[i]);
							}
							LOGD("[READER]: handle %d bytes: %s", count, tempbuf);

							// skip over leading newlines //
							SKIPCRLF(pcur, count);

							//LOGD("[READER]: skip header \\r \\n count is %d", count);
							if (count == 0) break;
							rev = getATFlag(&pcur, &len, &count);
							if ((rev >= RIL_CHANNELID_MIN && rev <= RIL_CHANNELID_MAX)
									|| rev == RIL_CHANNEL_URC)
							{
								LOGD("[READER]: get whole AT data, flag is %02X, length is %d, count is %d", 
										rev, len, count);
#ifdef GSM_MUX_CHANNEL
								flag = RIL_CHANNEL_URC;
#else
								flag = rev;
#endif
							} else if (rev == 0x00) {
								LOGD("[READER]: not whole AT data");
								memset(tempbuf, 0, sizeof(tempbuf));
								for (i = 0; i < count && i < sizeof(tempbuf) / 3; i++) {
									sprintf(tempbuf + i * 3, "%02x ", pcur[i]);
								}
								LOGD("[READER]: residual %d bytes: %s", count, tempbuf);
								memmove(atbuf, pcur, count);
								break;
							} else {
								LOGD("[READER]: flag is %02X out of range, should never happen !", rev);
								goto error;
							}

							// get AT flag //
							if (len == 1) {
								count -= len;
								pcur += len;
								continue;
							}

							*(pcur + len) = '\0';
							len++;

							// URC //
							if (isSMSUnsolicited(pcur)) {
								// The scope of string returned by 'getATFlag()' is valid only
								// till next call to 'getATFlag()' hence making a copy of line
								// before calling getATFlag() again.
								smsprefix = strdup(pcur);

#ifdef GSM_MUX_CHANNEL
								memset(urcbuf, 0x00, len);
								urcbufLen = 0x00;
#endif

							} else if (smsprefix) {
								if (s_unsolHandler != NULL) {
									s_unsolHandler(smsprefix, pcur);
								}
								free(smsprefix);
								smsprefix = NULL;

#ifdef GSM_MUX_CHANNEL
								memset(urcbuf, 0x00, len);
								urcbufLen = 0x00;
#endif
							}

#ifndef GSM_MUX_CHANNEL
#ifdef USE_MULT_AT_CHAN
							else if (flag == RIL_CHANNEL_URC)
#else
							else if (s_Req[flag - 1] == 0)
#endif
#else
							else if ((j + 1) == RIL_CHANNEL_URC && flag == RIL_CHANNEL_URC)
#endif
							{
								handleUnsolicited(pcur);

#ifdef GSM_MUX_CHANNEL
								memset(urcbuf, 0x00, len);
								urcbufLen = 0x00;
#endif
							}

							// normal AT cmd //
							else {
								int writecount = 0;
								char prefix[2] = {0x0D, 0x0A};
								int prelen = sizeof(prefix);
								int wholelen = prelen + len + prelen - 1;

								memcpy(atdata, prefix, prelen);
								memcpy(atdata + prelen, pcur, len - 1);
								memcpy(atdata + prelen + len - 1, prefix, prelen);

								LOGD("[READER]: write %d bytes to PIPE(%d)", 
										wholelen, flag - 1);
								while (writecount < wholelen) {
									do {
										rev = write(fd_ReqWrite[flag - 1], 
												atdata + writecount, wholelen - writecount);
									} while (rev < 0 && errno == EINTR);

									if (rev < 0) {
										LOGD("[READER]: write to PIPE%d return error(%d)", 
												flag - 1, errno);
										goto error;
									} else if (rev == 0) {
										LOGD("[READER]: PIPE_WRITE(%d) was closed", 
												flag - 1);
										goto error;
									}

									writecount += rev;
								}
								LOGD("[READER]: written %d bytes to PIPE(%d)", 
										writecount, flag - 1);
							} 

							count -= len;
							pcur += len;
						}

#ifdef GSM_MUX_CHANNEL
					}// end if((i + 1) == RIL_CHANNEL_URC)
					// normal AT cmd //
					else {
						int writecount = 0;

						LOGD("[READER]: write %d bytes to PIPE(%d)", count, j);
						while (writecount < count) {
							do {	//将数据写入管道 
								rev = write(fd_ReqWrite[j], pcur + writecount, count - writecount);
							} while (rev < 0 && errno == EINTR);

							if (rev < 0) {
								LOGD("[READER]: write to PIPE%d return error(%d)", j, errno);
								goto error;
							} else if (rev == 0) {
								LOGD("[READER]: PIPE_WRITE(%d) was closed", j);
								goto error;
							}

							writecount += rev;
						}
						count = 0x00;
						//LOGD("[READER]: written %d bytes to PIPE(%d)", writecount, j);
					}
#endif

				} else if (readcount <= 0) {
					if (readcount == 0) {
						LOGD("[READER]: get at data failed: EOF reached");
					} else {
						LOGD("[READER]: get at data failed: read error(%d)", errno);
					}

					goto error;
				}

#ifdef GSM_MUX_CHANNEL
				n--;
			}
		}
#endif

	}

error:

	onReaderClosed();
	return NULL;
}

/*
static void *readerLoop( void *arg )
{
    for ( ;; )
    {
        const char * line;

        line = readline( );

        if ( line == NULL )
        {
            break;
        }

        if ( isSMSUnsolicited( line ) )
        {
            char *line1;
            const char *line2;

            // The scope of string returned by 'readline()' is valid only
            // till next call to 'readline()' hence making a copy of line
            // before calling readline again.
            line1 = strdup( line );
            line2 = readline( );

            if ( line2 == NULL )
            {
                break;
            }

            if ( s_unsolHandler != NULL )
            {
                s_unsolHandler( line1, line2 );
            }
            free( line1 );
        }
        else
        {
            processLine( line );
        }

#ifdef HAVE_ANDROID_OS
        if (s_ackPowerIoctl > 0)
        {
            // acknowledge that bytes have been read and processed //
            ioctl(s_fd, OMAP_CSMI_TTY_ACK, &s_readCount);
            s_readCount = 0;
        }
#endif //HAVE_ANDROID_OS//
    }

    onReaderClosed( );

    return NULL;
}
*/

static int is2stepATReq(const char *line)
{
    size_t i = 0;

    for (; i < NUM_ELEMS(s_2stepATReq); i++) {
        if (strStartsWith(line, s_2stepATReq[i])) {
            return 1;
        }
    }

    return 0;
}

/**
 * Sends AT data to the radio with a \r appended.
 * Returns AT_ERROR_* on error, 0 on success
 *
 * This function exists because as of writing, android libc does not
 * have buffered stdio.
 */
static int writeline(const char *s, const int cmdlen, int cid)
{
    size_t cur = 0;
    size_t len = 0;
    ssize_t written;
    int i = 0;
    char * buf = NULL;

    if ( cmdlen <= 0 )
    {
        LOGE("[REQ%d]: Invalid command length %d", cid, cmdlen);
        return AT_ERROR_INVALID_CMD;
    }

#ifdef GSM_MUX_CHANNEL
    if ( v_fds[cid] < 0 || s_readerClosed > 0 )
#else
    if ( s_fd < 0 || s_readerClosed > 0 )
#endif
    {
        return AT_ERROR_CHANNEL_CLOSED;
    }

#ifdef USE_MULT_AT_CHAN

    // Append cid in the begin and '\r' in the end //
    len = 1 + cmdlen + 1;
    buf = (char *)malloc(len);
    memset(buf, 0, len);
    buf[0] = cid + 1; // channel id is 1-9 in BB side //
    memcpy(buf + 1, s, cmdlen);
    buf[len - 1] = '\r';

#else

    len = cmdlen + 1;
    buf = (char *)malloc(len);
    memset(buf, 0, len);
    memcpy(buf, s, cmdlen);
    buf[len - 1] = '\r';

#endif

#ifdef GSM_MUX_CHANNEL
    buf[len - 1] = 0x00;
    LOGD("[REQ%d]: write %d bytes AT> %s to v_fds[%d]:%d\n", cid, len, buf, cid, v_fds[cid]);
    buf[len - 1] = '\r';
#else
    LOGD("[REQ%d]: AT> %s\n", cid, buf);
    AT_DUMP(">> ", buf, len);
    memset(s_at_dump_buff_w[cid], 0, sizeof(s_at_dump_buff_w[cid]));
    for (i = 0; i < len && i < sizeof( s_at_dump_buff_w[cid]) / 3; i++) {
        sprintf( s_at_dump_buff_w[cid] + i * 3, "%02x ", buf[i] );
    }
    LOGD("[REQ%d]: send at data: %s", cid, s_at_dump_buff_w[cid]);
#endif

    while (cur < len) {
        do {
#ifdef GSM_MUX_CHANNEL
            written = write(v_fds[cid], buf + cur, len - cur);		//写入到对应的虚拟中断上
#else
            written = write(s_fd, buf + cur, len - cur);
#endif
        } while (written < 0 && errno == EINTR);

        if (written < 0) {
            free(buf);
            return AT_ERROR_GENERIC;
        }

        cur += written;
    }

    free(buf);
    return 0;
}
// End modify //

static int writeCtrlZ(const char *s, int cid)
{
    size_t cur = 0;
    size_t len = 0;
    ssize_t written;
    char * buf = NULL;

#ifdef GSM_MUX_CHANNEL
    if (v_fds[cid] < 0 || s_readerClosed > 0)
#else
    if (s_fd < 0 || s_readerClosed > 0)
#endif
    {
        return AT_ERROR_CHANNEL_CLOSED;
    }

#ifdef USE_MULT_AT_CHAN

    // cid + len + ^Z //
    len = 1 + strlen(s) + 1;
    buf = (char *)malloc(len);
    memset(buf, 0, len);
    buf[0] = cid;
    memcpy(buf + 1, s, strlen(s));
    buf[len - 1] = '\032';

#else

    len = strlen(s) + 1;
    buf = (char *)malloc(len);
    memset(buf, 0, len);
    memcpy(buf, s, strlen(s));
    buf[len - 1] = '\032';

#endif

    LOGD("[REQ%d]: AT> %s", cid - 1, buf);
    AT_DUMP(">* ", buf, len);

    /* the main string */
    while (cur < len) {
        do {
#ifdef GSM_MUX_CHANNEL
            written = write(v_fds[RIL_CHANNEL_SMS - 1], buf + cur, len - cur);
#else
            written = write(s_fd, buf + cur, len - cur);
#endif
        } while (written < 0 && errno == EINTR);

        if (written < 0) {
            free(buf);
            return AT_ERROR_GENERIC;
        }

        cur += written;
    }

    free(buf);
    return 0;
}

/*
static void clearPendingCommand( )
{
    if ( sp_response != NULL )
    {
        at_response_free( sp_response );
    }

    sp_response = NULL;
    s_responsePrefix = NULL;
    s_smsPDU = NULL;

}
*/

/**
 * Starts AT handler on stream "fd'
 * returns 0 on success, -1 on error
 */
int at_open( int fd , ATUnsolHandler h )
{
    int ret;
    int i = 0;
    pthread_t tid;
    pthread_attr_t attr;

#ifndef GSM_MUX_CHANNEL
    s_fd = fd;
#endif
    s_unsolHandler = h;
    s_readerClosed = 0;

    //s_responsePrefix = NULL;
    //s_smsPDU = NULL;
    //sp_response = NULL;

    while (i < sizeof(s_Req) / sizeof(int)) {
        s_Req[i++] = 0;
    }

#ifndef GSM_MUX_CHANNEL
    /* Android power control ioctl */
    #ifdef HAVE_ANDROID_OS
    #ifdef OMAP_CSMI_POWER_CONTROL
        ret = ioctl(fd, OMAP_CSMI_TTY_ENABLE_ACK);
        if(ret == 0) {
            int ack_count;
            int read_count;
            int old_flags;
            char sync_buf[256];
            old_flags = fcntl(fd, F_GETFL, 0);
            fcntl(fd, F_SETFL, old_flags | O_NONBLOCK);
            do {
                ioctl(fd, OMAP_CSMI_TTY_READ_UNACKED, &ack_count);
                read_count = 0;
                do {
                    ret = read(fd, sync_buf, sizeof(sync_buf));
                    if(ret > 0)
                    read_count += ret;
                } while (ret > 0 || (ret < 0 && errno == EINTR));
                ioctl(fd, OMAP_CSMI_TTY_ACK, &ack_count);
             } while (ack_count > 0 || read_count > 0);
            fcntl(fd, F_SETFL, old_flags);
            s_readCount = 0;
            s_ackPowerIoctl = 1;
        }
        else
            s_ackPowerIoctl = 0;
    
    #else // OMAP_CSMI_POWER_CONTROL
        s_ackPowerIoctl = 0;
    
    #endif // OMAP_CSMI_POWER_CONTROL
    #endif /*HAVE_ANDROID_OS*/
#endif /*GSM_MUX_CHANNEL*/

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    ret = pthread_create(&s_tid_reader, &attr, readerLoop, &attr);

    if (ret < 0) {
        perror("pthread_create");
        return -1;
    }

    return 0;
}

/* FIXME is it ok to call this from the reader and the command thread? */
/*
void at_close( )
{
    if ( s_fd >= 0 )
    {
        close( s_fd );
    }
    s_fd = -1;

    pthread_mutex_lock( &s_commandmutex );

    s_readerClosed = 1;

    pthread_cond_broadcast( &s_commandcond );

    pthread_mutex_unlock( &s_commandmutex );

    // the reader thread should eventually die //
}
*/

void at_close()
{
#ifdef GSM_MUX_CHANNEL
    int i;
    for (i = 0 ; i < RIL_CHANNELS; i++)
    {
        if (v_fds[i] >= 0) {
            close(v_fds[i]);
        }
        v_fds[i] = -1;
    }
#else
    if (s_fd >= 0) {
        close(s_fd);
    }
    s_fd = -1;
#endif
    s_readerClosed = 1;
}

static ATResponse * at_response_new()
{
    return (ATResponse *)calloc(1, sizeof(ATResponse));
}

static ATRequest * at_request_new()
{
    return (ATRequest *)calloc(1, sizeof(ATRequest));
}

void at_response_free(ATResponse *p_response)
{
    ATLine *p_line;

    if (p_response == NULL) return;

    p_line = p_response->p_intermediates;

    while (p_line != NULL) {
        ATLine *p_toFree;

        p_toFree = p_line;
        p_line = p_line->p_next;

        free(p_toFree->line);
        free(p_toFree);
    }

    free(p_response->finalResponse);
    free(p_response);
}

void at_request_free(ATRequest * p_request)
{
    if (p_request != NULL) {
        free(p_request);
    }
}

/**
 * The line reader places the intermediate responses in reverse order
 * here we flip them back
 */
static void reverseIntermediates(ATResponse *p_response)
{
    ATLine *pcur, *pnext;

    pcur = p_response->p_intermediates;
    p_response->p_intermediates = NULL;

    while (pcur != NULL) {
        pnext = pcur->p_next;
        pcur->p_next = p_response->p_intermediates;
        p_response->p_intermediates = pcur;
        pcur = pnext;
    }
}

// Modified by dxy CYIT 2011-4-7 //

/**
 * Internal send_command implementation
 * Doesn't lock or call the timeout callback
 *
 * timeoutMsec == 0 means infinite timeout
 */
/*
static int at_send_command_full_nolock( const char *command, const int cmdlen, 
        ATCommandType type, const char *responsePrefix, const char *smspdu,
        long long timeoutMsec, ATResponse **pp_outResponse )
{
    int err = 0;
#ifndef USE_NP
    struct timespec ts;
#endif //USE_NP/

    if ( sp_response != NULL )
    {
        err = AT_ERROR_COMMAND_PENDING;
        goto error;
    }

    //err = writeline( command );
    err = writeline( command, cmdlen );

    if ( err < 0 )
    {
        goto error;
    }
    
    s_EGATLen = 0;
    s_type = type;
    s_responsePrefix = responsePrefix;
    s_smsPDU = smspdu;
    sp_response = at_response_new( );

#ifdef USE_CYIT_COMMANDS
    if ( timeoutMsec == 0 )
    {
        timeoutMsec = CYIT_DEFAULT_AT_TIMEOUT_MSEC;
    }
#endif

#ifndef USE_NP
    if ( timeoutMsec != 0 )
    {
        setTimespecRelative( &ts, timeoutMsec );
    }
#endif //USE_NP//

    while ( sp_response->finalResponse == NULL && s_readerClosed == 0 )
    {
        if ( timeoutMsec != 0 )
        {
#ifdef USE_NP
            err = pthread_cond_timeout_np(&s_commandcond, &s_commandmutex, timeoutMsec);
#else
            err = pthread_cond_timedwait( &s_commandcond, &s_commandmutex, &ts );
#endif //USE_NP//
        }
        else
        {
            err = pthread_cond_wait( &s_commandcond, &s_commandmutex );
        }

        if ( err == ETIMEDOUT )
        {
#ifdef USE_CYIT_COMMANDS
            LOGD("####AT Time Out!###\n");
#endif
            err = AT_ERROR_TIMEOUT;

            goto error;
        }
    }

    if ( pp_outResponse == NULL )
    {
        at_response_free( sp_response );
    }
    else
    {
        // line reader stores intermediate responses in reverse order //
        reverseIntermediates( sp_response );
        *pp_outResponse = sp_response;
    }

    sp_response = NULL;

    if ( s_readerClosed > 0 )
    {
        err = AT_ERROR_CHANNEL_CLOSED;
        goto error;
    }

    err = 0;
    error: clearPendingCommand( );

     return err;
	
}
*/

// End modify //

static int at_send_command_full_nolock( const char *command, const int cmdlen, 
        ATCommandType type, const char *responsePrefix, const char *smspdu,
        long long timeoutMsec, ATResponse **pp_outResponse )
{
    int err = 0;
    int nfds = 0, n = 0;
    int cid = *(int *)pthread_getspecific(CID);
    fd_set rfds;
    struct timeval tv;
    ATRequest * request = NULL;
    ATResponse * response = NULL;

    // 2 step AT cmd like: +CMGS/+CMGW //
    pthread_mutex_lock(&s_2stepATMutex);
    if (!s_2stepFinished) {
        LOGD("[REQ%d]: wait for 2 step AT finished.", cid);
        while (!s_2stepFinished) {
            pthread_cond_wait(&s_2stepATCond, &s_2stepATMutex);
        }
        LOGD("[REQ%d]: signal coming 2 step AT finished.", cid);
    } else if (is2stepATReq(command)) {
        s_2stepFinished = 0;
        LOGD("[REQ%d]: begin to send 2 step AT command.", cid);
    }
    pthread_mutex_unlock(&s_2stepATMutex);

    s_Req[cid] = 1;
    
    // write AT data to VPIPE use mutex lock to keep line //
    pthread_mutex_lock(&s_commandmutex);
    err = writeline(command, cmdlen, cid);
    pthread_mutex_unlock(&s_commandmutex);
    if (err < 0) goto error;
    
    // to store AT data answer from BB or send from AP //
    request = at_request_new();
    response = at_response_new();
    request->egATLen = 0;
    request->type = type;
    request->smsPDU = smspdu;
    request->rspPrefix = responsePrefix;

    // time out handling //
    if (timeoutMsec == 0) {
        timeoutMsec = CYIT_DEFAULT_AT_TIMEOUT_MSEC;
    }
    tv.tv_sec = timeoutMsec / 1000;
    tv.tv_usec = timeoutMsec % 1000 * 1000;

	/*
	 * 等待在对应的管道上，知道有回应数据出现
	 */
    // initialize fd set //
    FD_ZERO(&rfds);
    FD_SET(fd_ReqRead[cid], &rfds);
    nfds = fd_ReqRead[cid] + 1;

    // wait until AT data answer from BB or time out or error occur //
    while (response->finalResponse == NULL && s_readerClosed == 0) {
        if(cid == 3){
            if(s_stepFlag != 2 && !s_2stepFinished){
                tv.tv_sec = CYIT_MIN_AT_TIMEOUT_IMMEDIATE / 1000;
                tv.tv_usec = CYIT_MIN_AT_TIMEOUT_IMMEDIATE % 1000 * 1000;
            }else if(s_stepFlag == 2 && s_2stepFinished){
                tv.tv_sec = CYIT_AT_TIMEOUT_70_SEC / 1000;
                tv.tv_usec = CYIT_AT_TIMEOUT_70_SEC % 1000 * 1000;
            }else{
                LOGE("[REQ3]Send SMS procedure MUST BE ERROR!!!\n");
                LOGE("[REQ3]s_stepFlag = %d, s_2stepFinished = %d\n" , s_stepFlag, s_2stepFinished);
            }
        }

        n = select(nfds, &rfds, NULL, NULL, &tv);

        if (n < 0) {
            LOGE("[REQ%d]: Select FDS return error(%d)", cid, errno);
            err = AT_ERROR_CHANNEL_CLOSED;
            goto error;
            continue;
        } else if (n == 0) {
            LOGD("[REQ%d]: ###AT Time Out!###", cid);
            err = AT_ERROR_TIMEOUT;
            goto error;
        } else {
            readline(cid, request, response);
        }
    }

    if (pp_outResponse != NULL) {
        // line reader stores intermediate responses in reverse order //
        reverseIntermediates(response);
        *pp_outResponse = response;
        // ensure not be freed by at_response_free() below //
        response = NULL;
    }

    s_Req[cid] = 0;

    if(s_readerClosed > 0) {
        err = AT_ERROR_CHANNEL_CLOSED;
        goto error;
    }
    err = 0;

error:

    if(cid == 3){
        s_stepFlag = 0;
    }

    s_Req[cid] = 0;
    at_request_free(request);
    at_response_free(response);
    if (is2stepATReq(command) && !s_2stepFinished) {
        if(err != AT_ERROR_TIMEOUT){
            LOGD("[REQ%d]: 2 step AT command failed, begin to release mutex", cid);
            pthread_mutex_lock(&s_2stepATMutex);
            s_2stepFinished = 1;
            pthread_cond_broadcast(&s_2stepATCond);
            pthread_mutex_unlock(&s_2stepATMutex);
            LOGD("[REQ%d]: 2 step AT command failed, release mutex", cid);
        }
    }

    return err;
}

/**
 * Internal send_command implementation
 *
 * timeoutMsec == 0 means infinite timeout
 */
static int at_send_command_full( const char *command , ATCommandType type ,
        const char *responsePrefix , const char *smspdu ,
        long long timeoutMsec , ATResponse **pp_outResponse )
{
    int err;
    int cid = *(int *)pthread_getspecific(CID);

    if (0 != pthread_equal(s_tid_reader, pthread_self())) {
        /* cannot be called from reader thread */
        return AT_ERROR_INVALID_THREAD;
    }

    // Modified by dxy 2011-4-7 //
    err = at_send_command_full_nolock( command, strlen( command ), 
            type, responsePrefix, smspdu,
            timeoutMsec, pp_outResponse );
    // End mofidy //

    at_processTimeout(err, smspdu);

#ifndef USE_CYIT_COMMANDS
    if (err == AT_ERROR_TIMEOUT && s_onTimeout != NULL)
    {
        s_onTimeout();
    }
#endif

    return err;
}


int at_send_command_timeout_poll( const char * command , unsigned char commandtype ,
        const char * responsePrefix , ATResponse ** pp_outResponse ,
        long long timeout, int pollNum )
{
    int err = 0;
    int i = 0;

    for(i = 0; i < pollNum; i++){
        err = at_send_command_timeout( command , commandtype ,
             responsePrefix , pp_outResponse , timeout );
        if(err == AT_ERROR_TIMEOUT && i != (pollNum - 1)){
            at_response_free(*pp_outResponse);
            *pp_outResponse = NULL;
        }else{
            break;
        }
    }

    return err;
}


int at_send_command_timeout( const char * command , unsigned char commandtype ,
        const char * responsePrefix , ATResponse ** pp_outResponse ,
        long long timeout )
{
    int err = 0;

    if ( commandtype == NO_RESULT || commandtype == MULTILINE )
    {
        err = at_send_command_full( command, commandtype, responsePrefix, NULL,
                timeout, pp_outResponse );
    }
    else if ( commandtype == SINGLELINE || commandtype == NUMERIC )
    {
        err = at_send_command_full( command, commandtype, responsePrefix, NULL,
                timeout, pp_outResponse );

        if ( err == 0 && pp_outResponse != NULL && ( *pp_outResponse )->success
                > 0 && ( *pp_outResponse )->p_intermediates == NULL )
        {
            /* successful command must have an intermediate response */
            at_response_free( *pp_outResponse );
            *pp_outResponse = NULL;
            return AT_ERROR_INVALID_RESPONSE;
        }
    }

    return err;
}


/**
 * Issue a single normal AT command with no intermediate response expected
 *
 * "command" should not include \r
 * pp_outResponse can be NULL
 *
 * if non-NULL, the resulting ATResponse * must be eventually freed with
 * at_response_free
 */
int at_send_command(const char *command, ATResponse **pp_outResponse)
{
    int err;

    err = at_send_command_full( command, NO_RESULT, NULL, NULL, 0,
            pp_outResponse );

    return err;
}


/**
 * Issue a single normal AT command with no intermediate response expected
 *
 * "command" should not include \r
 * pp_outResponse can be NULL
 *
 * if non-NULL, the resulting ATResponse * must be eventually freed with
 * at_response_free
 */
int at_send_command_min_timeout(const char *command, ATResponse **pp_outResponse)
{
    int err;

    err = at_send_command_full( command, NO_RESULT, NULL, NULL, CYIT_MIN_AT_TIMEOUT_IMMEDIATE,
            pp_outResponse );

    return err;
}


int at_send_command_singleline( const char *command ,
        const char *responsePrefix , ATResponse **pp_outResponse )
{
    int err;

    err = at_send_command_full( command, SINGLELINE, responsePrefix, NULL, 0,
            pp_outResponse );

    if (err == 0 && pp_outResponse != NULL
        && (*pp_outResponse)->success > 0
        && (*pp_outResponse)->p_intermediates == NULL
    ) {
        /* successful command must have an intermediate response */
        at_response_free(*pp_outResponse);
        *pp_outResponse = NULL;
        return AT_ERROR_INVALID_RESPONSE;
    }

    return err;
}


int at_send_command_singleline_timeout( const char *command ,
        const char *responsePrefix , ATResponse **pp_outResponse, long long timeout)
{
    int err;

    err = at_send_command_full(
            command, SINGLELINE, responsePrefix, NULL, timeout, pp_outResponse );

    if (err == 0 && pp_outResponse != NULL
        && (*pp_outResponse)->success > 0
        && (*pp_outResponse)->p_intermediates == NULL
    ) {
        /* successful command must have an intermediate response */
        at_response_free(*pp_outResponse);
        *pp_outResponse = NULL;
        return AT_ERROR_INVALID_RESPONSE;
    }

    return err;
}


int at_send_command_singleline_min_timeout( const char *command ,
        const char *responsePrefix , ATResponse **pp_outResponse )
{
    int err;

    err = at_send_command_full(
            command, SINGLELINE, responsePrefix, NULL, CYIT_MIN_AT_TIMEOUT_IMMEDIATE,
            pp_outResponse );

    if (err == 0 && pp_outResponse != NULL
        && (*pp_outResponse)->success > 0
        && (*pp_outResponse)->p_intermediates == NULL
    ) {
        /* successful command must have an intermediate response */
        at_response_free(*pp_outResponse);
        *pp_outResponse = NULL;
        return AT_ERROR_INVALID_RESPONSE;
    }

    return err;
}


// Add by dxy CYIT 2011-4-7 //
int at_send_egcmd( const char *command, const int cmdlen,
        ATResponse **pp_outResponse )
{
    int err;

    if ( 0 != pthread_equal( s_tid_reader, pthread_self( ) ) )
    {
        // cannot be called from reader thread //
        return AT_ERROR_INVALID_THREAD;
    }

    err = at_send_command_full_nolock( command, cmdlen, 
            NO_RESULT, NULL, NULL,  
            CYIT_MIN_AT_TIMEOUT_IMMEDIATE, pp_outResponse );

    at_processTimeout(err, NULL);

    return err;
}

int at_send_egcmd_singleline( const char *command, const int cmdlen, 
        const char *responsePrefix, ATResponse **pp_outResponse )
{
    int err;

    if ( 0 != pthread_equal( s_tid_reader, pthread_self( )))
    {
        // cannot be called from reader thread //
        return AT_ERROR_INVALID_THREAD;
    }

    err = at_send_command_full_nolock( command, cmdlen, 
            EGATCMD, responsePrefix, NULL, 
            CYIT_MIN_AT_TIMEOUT_IMMEDIATE, pp_outResponse );

    at_processTimeout(err, NULL);

    if ( err == 0 && pp_outResponse != NULL && ( *pp_outResponse )->success > 0
            && ( *pp_outResponse )->p_intermediates == NULL )
    {
        // successful command must have an intermediate response //
        at_response_free( *pp_outResponse );
        *pp_outResponse = NULL;
        return AT_ERROR_INVALID_RESPONSE;
    }

    return err;
}
// End add //

int at_send_command_numeric( const char *command , ATResponse **pp_outResponse )
{
    int err;

    err = at_send_command_full (command, NUMERIC, NULL,
            NULL, CYIT_MIN_AT_TIMEOUT_IMMEDIATE, pp_outResponse);

    if (err == 0 && pp_outResponse != NULL
        && (*pp_outResponse)->success > 0
        && (*pp_outResponse)->p_intermediates == NULL
    ) {
        /* successful command must have an intermediate response */
        at_response_free(*pp_outResponse);
        *pp_outResponse = NULL;
        return AT_ERROR_INVALID_RESPONSE;
    }

    return err;
}


int at_send_command_sms ( const char *command,
        const char *pdu,
        const char *responsePrefix,
        ATResponse **pp_outResponse,
        long long timeoutMsec )
{
    int err;

    err = at_send_command_full (command, SINGLELINE, responsePrefix,
            pdu, timeoutMsec, pp_outResponse);

    if (err == 0 && pp_outResponse != NULL
        && (*pp_outResponse)->success > 0
        && (*pp_outResponse)->p_intermediates == NULL
    ) {
        /* successful command must have an intermediate response */
        at_response_free(*pp_outResponse);
        *pp_outResponse = NULL;
        return AT_ERROR_INVALID_RESPONSE;
    }

    return err;
}


int at_send_command_multiline( const char *command ,
        const char *responsePrefix , ATResponse **pp_outResponse )
{
    int err;

    err = at_send_command_full(
            command, MULTILINE, responsePrefix, NULL, CYIT_AT_TIMEOUT_10_SEC,
            pp_outResponse );

    return err;
}


int at_send_command_multiline_timeout( const char *command ,
        const char *responsePrefix , long long timeoutMsec , ATResponse **pp_outResponse )
{
    int err;

    err = at_send_command_full(
            command, MULTILINE, responsePrefix, NULL, timeoutMsec, pp_outResponse );

    return err;
}


int at_send_command_multiline_min_timeout( const char *command ,
        const char *responsePrefix , ATResponse **pp_outResponse )
{
    int err;

    err = at_send_command_full(
            command, MULTILINE, responsePrefix, NULL, CYIT_MIN_AT_TIMEOUT_IMMEDIATE,
            pp_outResponse );

    return err;
}


/** This callback is invoked on the command thread */
void at_set_on_timeout(void (*onTimeout)(void))
{
    s_onTimeout = onTimeout;
}

/**
 *  This callback is invoked on the reader thread (like ATUnsolHandler)
 *  when the input stream closes before you call at_close
 *  (not when you call at_close())
 *  You should still call at_close()
 */

void at_set_on_reader_closed(void (*onClose)(void))
{
    s_onReaderClosed = onClose;
}


/**
 * Periodically issue an AT command and wait for a response.
 * Used to ensure channel has start up and is active
 */

int at_handshake()
{
    int i;
    int err = 0;

    if (0 != pthread_equal(s_tid_reader, pthread_self())) {
        /* cannot be called from reader thread */
        return AT_ERROR_INVALID_THREAD;
    }

    for (i = 0 ; i < HANDSHAKE_RETRY_COUNT ; i++) {
        // Modified by dxy CYIT 2011-4-7 //
        /* some stacks start with verbose off */
        err = at_send_command_full_nolock( "AT", strlen( "AT" ), NO_RESULT, NULL, NULL,
                HANDSHAKE_TIMEOUT_MSEC, NULL );
        // End modify //

        if (err == 0) {
            break;
        }
    }

    if (err == 0) {
        /* pause for a bit to let the input buffer drain any unmatched OK's
         (they will appear as extraneous unsolicited responses) */

        sleepMsec(HANDSHAKE_TIMEOUT_MSEC);
    }

    return err;
}

/**
 * Returns error code from response
 * Assumes AT+CMEE=1 (numeric) mode
 */
AT_CME_Error at_get_cme_error(const ATResponse *p_response)
{
    int ret;
    int err;
    char *p_cur;

    if (p_response->success > 0) {
        return CME_SUCCESS;
    }

    if (p_response->finalResponse == NULL
        || !strStartsWith(p_response->finalResponse, "+CME ERROR:")) {
        return CME_ERROR_NON_CME;
    }

    p_cur = p_response->finalResponse;
    err = at_tok_start(&p_cur);

    if (err < 0) {
        return CME_ERROR_NON_CME;
    }

    err = at_tok_nextint(&p_cur, &ret);

    if (err < 0) {
        return CME_ERROR_NON_CME;
    }

    return (AT_CME_Error) ret;
}


void at_processTimeout(int err, const char* smsPdu)
{
    int i = 0;
    int cid = *(int *)pthread_getspecific(CID);

    if(err == AT_ERROR_TIMEOUT && s_basebandReadyFlag){
        LOGD("at_processTimeout, cid = %d", cid);
        if(cid == 3 && smsPdu && !s_2stepFinished){
            char endChar[1] = {0x1B};

            LOGD("at_processTimeout, send SMS step1 failed, begin to end the procedure");
            s_2stepFinished = 1;

            err = at_send_command_full_nolock(
                    endChar, 1, NO_RESULT, NULL, NULL, CYIT_MIN_AT_TIMEOUT_IMMEDIATE, NULL);

            pthread_cond_broadcast(&s_2stepATCond);

            if(err != AT_ERROR_TIMEOUT){
                LOGE("at_processTimeout, SMS step1.end success: %d\n", err);
                return;
            }

            LOGE("at_processTimeout, end SMS step1 Timeout\n");
        }

        s_recoverChannel = cid;
        for(i = 0; i < 3; i++){
            char *cmd = NULL;
            s_recoverFlag++;
            LOGE("at_processTimeout, retrying %d.\n", s_recoverFlag);
            asprintf(&cmd, "AT^SUTEST=%d", s_recoverFlag);
            err = at_send_command_full_nolock(
                    cmd, 11, SINGLELINE, "^SUTEST:", NULL, CYIT_MIN_AT_TIMEOUT_IMMEDIATE, NULL);
            free(cmd);
            if(err == AT_ERROR_TIMEOUT){
                if(i == 2){
                    LOGE("at_processTimeout ERROR!!!!! we going to recover procedure.\n");
                    FILE * psys = 0;
                    if ((psys = fopen("/sys/devices/platform/c63xx_cp/command", "w")) != NULL){
                        fputs("3", psys);
                    }
                    fclose(psys);
                    break;
                }
            }else{
                LOGE("at_processTimeout err: %d \n", err);
                break;
            }
        }
        s_recoverChannel = 0xFF;
        s_recoverFlag = 0;
    }
}
