// Copyright (c) 2009-2010 Satoshi Nakamoto                     -*- c++ -*-
// Copyright (c) 2009-2013 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef __cplusplus
#error This header can only be compiled as C++.
#endif

#ifndef BITCOIN_PROTOCOL_H
#define BITCOIN_PROTOCOL_H

#include "netbase.h"
#include "serialize.h"
#include "uint256.h"
#include "version.h"

#include <stdint.h>
#include <string>

#define MESSAGE_START_SIZE 4



namespace NetMsgType {
extern const char *VERSION;
extern const char *VERACK;
extern const char *ADDR;
extern const char *ALERT;
extern const char *INV;
extern const char *GETDATA;
extern const char *MERKLEBLOCK;
extern const char *GETBLOCKS;
extern const char *GETHEADERS;
extern const char *TX;
extern const char *MNW;
extern const char *MPROP;
extern const char *IX;
extern const char *DSTX;
extern const char *FBS;
extern const char *MNB;
extern const char *MNP;
extern const char *MNGET;
extern const char *DSEEP;
extern const char *DSEE;
extern const char *DSEG;
extern const char *DSSU;
extern const char *DSS;
extern const char *DSA;
extern const char *DSQ;
extern const char *DSF;
extern const char *DSI;
extern const char *DSC;
extern const char *DSR;
extern const char *SPORK;
extern const char *GETSPORKS;
extern const char *GETSPORK;
extern const char *SSC;
extern const char *MNVS;
extern const char *HEADERS;
extern const char *BLOCK;
extern const char *GETADDR;
extern const char *MEMPOOL;
extern const char *PING;
extern const char *PONG;
extern const char *NOTFOUND;
extern const char *FILTERLOAD;
extern const char *FILTERADD;
extern const char *FILTERCLEAR;
extern const char *REJECT;
extern const char *SENDHEADERS;
extern const char *FEEFILTER;
extern const char *SENDCMPCT;
extern const char *CMPCTBLOCK;
extern const char *GETBLOCKTXN;
extern const char *BLOCKTXN;
};


/** Message header.
 * (4) message start.
 * (12) command.
 * (4) size.
 * (4) checksum.
 */
class CMessageHeader
{
public:
    CMessageHeader();
    CMessageHeader(const char* pszCommand, unsigned int nMessageSizeIn);

    std::string GetCommand() const;
    bool IsValid() const;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        READWRITE(FLATDATA(pchMessageStart));
        READWRITE(FLATDATA(pchCommand));
        READWRITE(nMessageSize);
        READWRITE(nChecksum);
    }

    // TODO: make private (improves encapsulation)
public:
    enum {
        COMMAND_SIZE = 12,
        MESSAGE_SIZE_SIZE = sizeof(int),
        CHECKSUM_SIZE = sizeof(int),

        MESSAGE_SIZE_OFFSET = MESSAGE_START_SIZE + COMMAND_SIZE,
        CHECKSUM_OFFSET = MESSAGE_SIZE_OFFSET + MESSAGE_SIZE_SIZE,
        HEADER_SIZE = MESSAGE_START_SIZE + COMMAND_SIZE + MESSAGE_SIZE_SIZE + CHECKSUM_SIZE
    };
    char pchMessageStart[MESSAGE_START_SIZE];
    char pchCommand[COMMAND_SIZE];
    unsigned int nMessageSize;
    unsigned int nChecksum;
};

/** nServices flags */
enum {
    LUX_NODE_NETWORK = (1 << 0),

    LUX_NODE_WITNESS = (1 << 3),

    // NODE_BLOOM means the node is capable and willing to handle bloom-filtered connections.
    // Bitcoin Core nodes used to support this by default, without advertising this bit,
    // but no longer do as of protocol version 70011 (= NO_BLOOM_VERSION)
    NODE_BLOOM = (1 << 2),

    // Bits 24-31 are reserved for temporary experiments. Just pick a bit that
    // isn't getting used, or one not being used much, and notify the
    // bitcoin-development mailing list. Remember that service bits are just
    // unauthenticated advertisements, so your code must be robust against
    // collisions and other cases where nodes may be advertising a service they
    // do not actually support. Other service bits should be allocated via the
    // BIP process.
};

/** A CService with information about it as peer */
class CAddress : public CService
{
public:
    CAddress();
    explicit CAddress(CService ipIn, uint64_t nServicesIn = LUX_NODE_NETWORK);

    void Init();

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        if (ser_action.ForRead())
            Init();
        if (nType & SER_DISK)
            READWRITE(nVersion);
        if ((nType & SER_DISK) ||
            (nVersion >= CADDR_TIME_VERSION && !(nType & SER_GETHASH)))
            READWRITE(nTime);
        READWRITE(nServices);
        READWRITE(*(CService*)this);
    }

    // TODO: make private (improves encapsulation)
public:
    uint64_t nServices;

    // disk and network only
    unsigned int nTime;

    // memory only
    int64_t nLastTry;
};

/** inv message data */
class CInv
{
public:
    CInv();
    CInv(int typeIn, const uint256& hashIn);
    CInv(const std::string& strType, const uint256& hashIn);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        READWRITE(type);
        READWRITE(hash);
    }

    friend bool operator<(const CInv& a, const CInv& b);

    bool IsKnownType() const;
    const char* GetCommand() const;
    std::string ToString() const;

    // TODO: make private (improves encapsulation)
public:
    int type;
    uint256 hash;
};

const uint32_t MSG_WITNESS_FLAG = 1 << 30;
const uint32_t MSG_TYPE_MASK    = 0xffffffff >> 2;
enum GetDataMsg {
    MSG_TX = 1,
    MSG_BLOCK,
    // Nodes may always request a MSG_FILTERED_BLOCK in a getdata, however,
    // MSG_FILTERED_BLOCK should not appear in any invs except as a part of getdata.
    MSG_FILTERED_BLOCK,
    MSG_TXLOCK_REQUEST,
    MSG_TXLOCK_VOTE,
    MSG_SPORK,
    MSG_MASTERNODE_WINNER,
    MSG_WITNESS_BLOCK = MSG_BLOCK | MSG_WITNESS_FLAG,
    MSG_WITNESS_TX = MSG_TX | MSG_WITNESS_FLAG,
    MSG_FILTERED_WITNESS_BLOCK = MSG_FILTERED_BLOCK | MSG_WITNESS_FLAG,
};

const int MSG_TYPE_MAX = MSG_FILTERED_BLOCK;

#endif // BITCOIN_PROTOCOL_H
