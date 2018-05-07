// Copyright (c) 2009-2010 Satoshi Nakamoto             -*- c++ -*-
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2017 The LUX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_MAIN_H
#define BITCOIN_MAIN_H

#if defined(HAVE_CONFIG_H)
#include "config/lux-config.h"
#endif

#include "amount.h"
#include "chain.h"
#include "chainparams.h"
#include "coins.h"
#include "consensus/validation.h"
#include "net.h"
#include "pow.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "script/sigcache.h"
#include "script/standard.h"
#include "sync.h"
#include "tinyformat.h"
#include "txmempool.h"
#include "uint256.h"
#include "undo.h"
#include "validationinterface.h"

#include <algorithm>
#include <exception>
#include <map>
#include <set>
#include <stdint.h>
#include <string>
#include <utility>
#include <vector>

#include <boost/unordered_map.hpp>

/**
 * Global LuxState
 */

/////////////////////////////////////////// lux
#include <lux/luxstate.h>
#include <lux/luxDGP.h>
#include <libethereum/ChainParams.h>
#include <libethashseal/Ethash.h>
#include <libethashseal/GenesisInfo.h>
#include <script/standard.h>
#include <lux/storageresults.h>
///////////////////////////////////////////

extern std::unique_ptr<LuxState> globalState;
extern std::shared_ptr<dev::eth::SealEngineFace> globalSealEngine;
extern bool fRecordLogOpcodes;
extern bool fIsVMlogFile;
extern bool fGettingValuesDGP;

struct EthTransactionParams;
using valtype = std::vector<unsigned char>;
using ExtractLuxTX = std::pair<std::vector<LuxTransaction>, std::vector<EthTransactionParams>>;
///////////////////////////////////////////

class CBlockIndex;
class CBlockTreeDB;
class CBloomFilter;
class CChainParams;
class CInv;
class CConnman;
class CScriptCheck;
class CValidationInterface;
class CValidationState;

struct CBlockTemplate;
struct CNodeStateStats;
/**SegWit**/
static const int SERIALIZE_TRANSACTION_NO_WITNESS = 0x40000000;

#define START_MASTERNODE_PAYMENTS_TESTNET 1432907775
#define START_MASTERNODE_PAYMENTS 1432907775

static const int64_t DARKSEND_COLLATERAL = (16120*COIN); //161.20 LUX
static const int64_t DARKSEND_FEE = (0.002*COIN); // reward masternode
static const int64_t DARKSEND_POOL_MAX = (1999999.99*COIN);

/** Default for -blockmaxsize and -blockminsize, which control the range of sizes the mining code will create **/
static const unsigned int DEFAULT_BLOCK_MAX_SIZE = 6000000;
static const unsigned int DEFAULT_BLOCK_MIN_SIZE = 0;
/** Default for -blockmaxcost, which control the range of block costs the mining code will create **/
static const unsigned int DEFAULT_BLOCK_MAX_COST = 3000000;
/** The maximum size for mined blocks */
static const unsigned int MAX_BLOCK_SIZE_GEN = MAX_BLOCK_SIZE/2;
/** Default for -blockprioritysize, maximum space for zero/low-fee transactions **/
static const unsigned int DEFAULT_BLOCK_PRIORITY_SIZE = 50000;
/** Default for accepting alerts from the P2P network. */
static const bool DEFAULT_ALERTS = true;
static const int64_t MAX_STANDARD_TX_COST = 400000;
/** The maximum allowed number of signature check operations in a block (network rule) */
static const int64_t MAX_BLOCK_SIGOPS_COST = 80000;
/** The maximum number of sigops we're willing to relay/mine in a single tx */
static const int64_t MAX_STANDARD_TX_SIGOPS_COST = MAX_BLOCK_SIGOPS_COST/5;
/** The maximum allowed number of signature check operations in a block (network rule) */
static const unsigned int MAX_BLOCK_SIGOPS = MAX_BLOCK_SIZE / 50;
/** Maximum number of signature check operations in an IsStandard() P2SH script */
static const unsigned int MAX_P2SH_SIGOPS = 15;
/** The maximum number of sigops we're willing to relay/mine in a single tx */
static const int64_t MAX_TX_SIGOPS_COST = MAX_BLOCK_SIGOPS_COST / 5;
/** The maximum allowed size for a serialized block, in bytes (only for buffer size limits) */
static const unsigned int MAX_BLOCK_SERIALIZED_SIZE = 4000000;
/** The maximum allowed cost for a block, see BIP 141 (network rule) */
static const int64_t MAX_BLOCK_COST = 4000000;
/** The maximum allowed size for a block excluding witness data, in bytes (network rule) */
static const unsigned int MAX_BLOCK_BASE_SIZE = 1000000;
/** Default for -maxorphantx, maximum number of orphan transactions kept in memory */
static const unsigned int DEFAULT_MAX_ORPHAN_TRANSACTIONS = MAX_BLOCK_SIZE/10;
/** The maximum size of a blk?????.dat file (since 0.8) */
static const unsigned int MAX_BLOCKFILE_SIZE = 0x8000000; // 128 MiB
/** The pre-allocation chunk size for blk?????.dat files (since 0.8) */
static const unsigned int BLOCKFILE_CHUNK_SIZE = 0x1000000; // 16 MiB
/** The pre-allocation chunk size for rev?????.dat files (since 0.8) */
static const unsigned int UNDOFILE_CHUNK_SIZE = 0x100000; // 1 MiB
/** Coinbase transaction outputs can only be spent after this number of new blocks (network rule) */
static const int COINBASE_MATURITY = 79;
/** Maximum number of script-checking threads allowed */
static const int MAX_SCRIPTCHECK_THREADS = 16;
/** -par default (number of script-checking threads, 0 = auto) */
static const int DEFAULT_SCRIPTCHECK_THREADS = 0;
/** Number of blocks that can be requested at any given time from a single peer. */
static const int MAX_BLOCKS_IN_TRANSIT_PER_PEER = 16;
/** Timeout in seconds during which a peer must stall block download progress before being disconnected. */
static const unsigned int BLOCK_STALLING_TIMEOUT = 2;
/** Number of headers sent in one getheaders result. We rely on the assumption that if a peer sends
 *  less than this number, we reached their tip. Changing this value is a protocol upgrade. */
static const unsigned int MAX_HEADERS_RESULTS = 2000;
/** Size of the "block download window": how far ahead of our current height do we fetch?
 *  Larger windows tolerate larger download speed differences between peer, but increase the potential
 *  degree of disordering of blocks on disk (which make reindexing and in the future perhaps pruning
 *  harder). We'll probably want to make this a per-peer adaptive value at some point. */
static const unsigned int BLOCK_DOWNLOAD_WINDOW = 1024;
/** Time to wait (in seconds) between writing blockchain state to disk. */
static const unsigned int DATABASE_WRITE_INTERVAL = 3600;
/** Maximum length of reject messages. */
static const unsigned int MAX_REJECT_MESSAGE_LENGTH = 111;
/** Default for -bytespersigop */
static const unsigned int DEFAULT_BYTES_PER_SIGOP = 20;
/** Bloomfilter setting. */
static const bool DEFAULT_PEERBLOOMFILTERS = true;
/** "reject" message codes */
//static const unsigned char REJECT_MALFORMED = 0x01;
//static const unsigned char REJECT_INVALID = 0x10;
//static const unsigned char REJECT_OBSOLETE = 0x11;
//static const unsigned char REJECT_DUPLICATE = 0x12;
//static const unsigned char REJECT_NONSTANDARD = 0x40;
//static const unsigned char REJECT_DUST = 0x41;
//static const unsigned char REJECT_INSUFFICIENTFEE = 0x42;
//static const unsigned char REJECT_CHECKPOINT = 0x43;

static const int64_t STATIC_POS_REWARD = 1 * COIN; //Constant reward 8%

static const bool DEFAULT_LOGEVENTS = false;

////////////////////////////////////////////////////// lux
static const uint64_t DEFAULT_GAS_LIMIT_OP_CREATE=2500000;
static const uint64_t DEFAULT_GAS_LIMIT_OP_SEND=250000;
static const CAmount DEFAULT_GAS_PRICE=0.00000040*COIN;
static const CAmount MAX_RPC_GAS_PRICE=0.00000100*COIN;

static const size_t MAX_CONTRACT_VOUTS = 1000;

/** Minimum gas limit that is allowed in a transaction within a block - prevent various types of tx and mempool spam **/
static const uint64_t MINIMUM_GAS_LIMIT = 10000;

static const uint64_t MEMPOOL_MIN_GAS_LIMIT = 22000;

//////////////////////////////////////////////////////

inline bool IsProtocolV2(int nHeight) { return IsTestNet() || nHeight > 0; }
inline int64_t GetMNCollateral(int nHeight) { return nHeight>=30000 ? 16120 : 1999999; }

struct BlockHasher {
    size_t operator()(const uint256& hash) const { return hash.GetLow64(); }
};

extern CScript COINBASE_FLAGS;
extern CCriticalSection cs_main;
extern CTxMemPool mempool;
typedef boost::unordered_map<uint256, CBlockIndex*, BlockHasher> BlockMap;
extern BlockMap mapBlockIndex;
extern uint64_t nLastBlockTx;
extern uint64_t nLastBlockCost;
extern const std::string strMessageMagic;
extern int64_t nTimeBestReceived;
extern CWaitableCriticalSection csBestBlock;
extern CConditionVariable cvBlockChange;
extern bool fImporting;
extern bool fReindex;
extern int nScriptCheckThreads;
extern bool fTxIndex;
extern bool fAddrIndex;
extern bool fLogEvents;
extern bool fIsBareMultisigStd;
extern bool fCheckBlockIndex;
extern unsigned int nCoinCacheSize;
extern CFeeRate minRelayTxFee;
extern bool fAlerts;
extern bool fVerifyingBlocks;

extern bool fLargeWorkForkFound;
extern bool fLargeWorkInvalidChainFound;

extern CBlockIndex* pindexBestHeader;

/** Minimum disk space required - used in CheckDiskSpace() */
static const uint64_t nMinDiskSpace = 52428800;

/** Register a wallet to receive updates from core */
void RegisterValidationInterface(CValidationInterface* pwalletIn);
/** Unregister a wallet from core */
void UnregisterValidationInterface(CValidationInterface* pwalletIn);
/** Unregister all wallets from core */
void UnregisterAllValidationInterfaces();
/** Push an updated transaction to all registered wallets */
void SyncWithWallets(const CTransaction& tx, const CBlock* pblock = NULL);

/** Register with a network node to receive its signals */
void RegisterNodeSignals(CNodeSignals& nodeSignals);
/** Unregister a network node */
void UnregisterNodeSignals(CNodeSignals& nodeSignals);

/**
 * Process an incoming block. This only returns after the best known valid
 * block is made active. Note that it does not, however, guarantee that the
 * specific block passed to it has been checked for validity!
 *
 * @param[out]  state   This may be set to an Error state if any error occurred processing it, including during validation/connection/etc of otherwise unrelated blocks during reorganisation; or it may be set to an Invalid state if pblock is itself invalid (but this is not guaranteed even when the block is checked). If you want to *possibly* get feedback on whether pblock is valid, you must also install a CValidationInterface - this will have its BlockChecked method called whenever *any* block completes validation.
 * @param[in]   pfrom   The node which we are receiving the block from; it is added to mapBlockSource and may be penalised if the block is invalid.
 * @param[in]   pblock  The block we want to process.
 * @param[out]  dbp     If pblock is stored to disk (or already there), this will be set to its location.
 * @return True if state.IsValid()
 */
bool ProcessNewBlock(CValidationState& state, CNode* pfrom, CBlock* pblock, CDiskBlockPos* dbp = NULL);
/** Check whether enough disk space is available for an incoming block */
bool CheckDiskSpace(uint64_t nAdditionalBytes = 0);
/** Open a block file (blk?????.dat) */
FILE* OpenBlockFile(const CDiskBlockPos& pos, bool fReadOnly = false);
/** Open an undo file (rev?????.dat) */
FILE* OpenUndoFile(const CDiskBlockPos& pos, bool fReadOnly = false);
/** Translation to a filesystem path */
boost::filesystem::path GetBlockPosFilename(const CDiskBlockPos& pos, const char* prefix);
/** Import blocks from an external file */
bool LoadExternalBlockFile(FILE* fileIn, CDiskBlockPos* dbp = NULL);
/** Initialize a new block tree database + block data on disk */
bool InitBlockIndex();
/** Load the block tree and coins database from disk */
bool LoadBlockIndex();
/** Unload database information */
void UnloadBlockIndex();
/** See whether the protocol update is enforced for connected nodes */
int ActiveProtocol();
/** Process protocol messages received from a given node */
bool ProcessMessages(CNode* pfrom);
/**
 * Send queued protocol messages to be sent to a give node.
 *
 * @param[in]   pto             The node which we are sending messages to.
 * @param[in]   fSendTrickle    When true send the trickled data, otherwise trickle the data until true.
 */
bool SendMessages(CNode* pto, bool fSendTrickle);
/** Run an instance of the script checking thread */
void ThreadScriptCheck();

// ***TODO*** probably not the right place for these 2
/** Check whether a block hash satisfies the proof-of-work requirement specified by nBits */
bool CheckProofOfWork(uint256 hash, unsigned int nBits);

/** Check whether we are doing an initial block download (synchronizing from disk or network) */
bool IsInitialBlockDownload();
/** Format a string that describes several potential problems detected by the core */
std::string GetWarnings(std::string strFor);
/** Retrieve a transaction (from memory pool, or from disk, if possible) */
bool GetTransaction(const uint256& hash, CTransaction& tx, uint256& hashBlock, bool fAllowSlow = false);
/** Find the best known block, and make it the tip of the block chain */

bool DisconnectBlocksAndReprocess(int blocks);

/** Check whether witness commitments are required for block. */
bool IsWitnessEnabled(const CBlockIndex* pindexPrev);
bool IsWitnessLocked(const CBlockIndex* pindexPrev);

// ***TODO***
double ConvertBitsToDouble(unsigned int nBits);
CAmount GetMasternodePayment(int nHeight, int64_t blockValue, int nMasternodeCount = 0);
unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader* pblock, bool fProofOfStake);
uint256 GetProofOfStakeLimit(int nHeight);
inline unsigned int GetTargetSpacing(int nHeight) { return IsProtocolV2(nHeight) ? 240 : 60; }

bool ActivateBestChain(CValidationState& state, CBlock* pblock = NULL, bool fAlreadyChecked = false);
CAmount GetProofOfWorkReward(int64_t nFees, int nHeight);
CAmount GetProofOfStakeReward(int64_t nCoinAge, int64_t nFees, int nHeight);

/** Create a new block index entry for a given block hash */
CBlockIndex* InsertBlockIndex(uint256 hash);
/** Abort with a message */
bool AbortNode(const std::string& msg, const std::string& userMessage = "");
/** Get statistics from node state */
bool GetNodeStateStats(NodeId nodeid, CNodeStateStats& stats);
/** Increase a node's misbehavior score. */
void Misbehaving(NodeId nodeid, int howmuch);
/** Flush all state, indexes and buffers to disk. */
void FlushStateToDisk();


/** (try to) add transaction to memory pool **/
bool AcceptToMemoryPool(CTxMemPool& pool, CValidationState& state, const CTransaction& tx, bool fLimitFree, bool* pfMissingInputs, bool fRejectInsaneFee = false, bool ignoreFees = false);

bool AcceptableInputs(CTxMemPool& pool, CValidationState& state, const CTransaction& tx, bool fLimitFree, bool* pfMissingInputs, bool fRejectInsaneFee = false, bool isDSTX = false);


//////////////////////////////////////////////////////////// // lux
struct CHeightTxIndexIteratorKey {
    unsigned int height;

    size_t GetSerializeSize(int nType, int nVersion) const {
        return 4;
    }
    template<typename Stream>
    void Serialize(Stream& s) const {
        ser_writedata32be(s, height);
    }
    template<typename Stream>
    void Unserialize(Stream& s) {
        height = ser_readdata32be(s);
    }

    CHeightTxIndexIteratorKey(unsigned int _height) {
        height = _height;
    }

    CHeightTxIndexIteratorKey() {
        SetNull();
    }

    void SetNull() {
        height = 0;
    }
};

struct CHeightTxIndexKey {
    unsigned int height;
    dev::h160 address;

    size_t GetSerializeSize(int nType, int nVersion) const {
        return 24;
    }
    template<typename Stream>
    void Serialize(Stream& s) const {
        ser_writedata32be(s, height);
        s << address.asBytes();
    }
    template<typename Stream>
    void Unserialize(Stream& s) {
        height = ser_readdata32be(s);
        valtype tmp;
        s >> tmp;
        address = dev::h160(tmp);
    }

    CHeightTxIndexKey(unsigned int _height, dev::h160 _address) {
        height = _height;
        address = _address;
    }

    CHeightTxIndexKey() {
        SetNull();
    }

    void SetNull() {
        height = 0;
        address.clear();
    }
};

////////////////////////////////////////////////////////////

int GetInputAge(CTxIn& vin);
int GetInputAgeIX(uint256 nTXHash, CTxIn& vin);
bool GetCoinAge(const CTransaction& tx, unsigned int nTxTime, uint64_t& nCoinAge);
int GetIXConfirmations(uint256 nTXHash);

struct CNodeStateStats {
    int nMisbehavior;
    int nSyncHeight;
    int nCommonHeight;
    std::vector<int> vHeightInFlight;
};

struct CDiskTxPos : public CDiskBlockPos {
    unsigned int nTxOffset; // after header

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        READWRITE(*(CDiskBlockPos*)this);
        READWRITE(VARINT(nTxOffset));
    }

    CDiskTxPos(const CDiskBlockPos& blockIn, unsigned int nTxOffsetIn) : CDiskBlockPos(blockIn.nFile, blockIn.nPos), nTxOffset(nTxOffsetIn)
    {
    }

    CDiskTxPos()
    {
        SetNull();
    }

    void SetNull()
    {
        CDiskBlockPos::SetNull();
        nTxOffset = 0;
    }

    friend bool operator<(const CDiskTxPos &a, const CDiskTxPos &b) {
        return (a.nFile < b.nFile || (
                (a.nFile == b.nFile) && (a.nPos < b.nPos || (
                (a.nPos == b.nPos) && (a.nTxOffset < b.nTxOffset)))));
    }
};

struct CExtDiskTxPos : public CDiskTxPos
{
    unsigned int nHeight;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
            READWRITE(*(CDiskTxPos*)this);
            READWRITE(VARINT(nHeight));
    }

    CExtDiskTxPos(const CDiskTxPos &pos, int nHeightIn) : CDiskTxPos(pos), nHeight(nHeightIn) {
    }

    CExtDiskTxPos() {
        SetNull();
    }

    void SetNull() {
        CDiskTxPos::SetNull();
        nHeight = 0;
    }

    friend bool operator==(const CExtDiskTxPos &a, const CExtDiskTxPos &b) {
        return (a.nHeight == b.nHeight && a.nFile == b.nFile && a.nPos == b.nPos && a.nTxOffset == b.nTxOffset);
    }

    friend bool operator!=(const CExtDiskTxPos &a, const CExtDiskTxPos &b) {
        return !(a == b);
    }

    friend bool operator<(const CExtDiskTxPos &a, const CExtDiskTxPos &b) {
        if (a.nHeight < b.nHeight) return true;
        if (a.nHeight > b.nHeight) return false;
        return ((const CDiskTxPos)a < (const CDiskTxPos)b);
    }
};

CAmount GetMinRelayFee(const CTransaction& tx, unsigned int nBytes, bool fAllowFree);

/**
 * Check transaction inputs, and make sure any
 * pay-to-script-hash transactions are evaluating IsStandard scripts
 *
 * Why bother? To avoid denial-of-service attacks; an attacker
 * can submit a standard HASH... OP_EQUAL transaction,
 * which will get accepted into blocks. The redemption
 * script can be anything; an attacker could use a very
 * expensive-to-check-upon-redemption script like:
 *   DUP CHECKSIG DROP ... repeated 100 times... OP_1
 */

/**
 * Check for standard transaction types
 * @param[in] mapInputs    Map of previous transactions that have outputs we're spending
 * @return True if all inputs (scriptSigs) use only standard transaction forms
 */

/**
  * Basic transaction serialization format:
  * - int32_t nVersion
  * - std::vector<CTxIn> vin
  * - std::vector<CTxOut> vout
  * - uint32_t nLockTime
  *
  * Extended transaction serialization format:
  * - int32_t nVersion
  * - unsigned char dummy = 0x00
  * - unsigned char flags (!= 0)
  * - std::vector<CTxIn> vin
  * - std::vector<CTxOut> vout
  * - if (flags & 1):
  *   - CTxWitness wit;
  * - uint32_t nLockTime
  */
 template<typename Stream, typename TxType>
 inline void UnserializeTransaction(TxType& tx, Stream& s) {
     const bool fAllowWitness = !(s.GetVersion() & SERIALIZE_TRANSACTION_NO_WITNESS);

     s >> tx.nVersion;
     unsigned char flags = 0;
     tx.vin.clear();
     tx.vout.clear();
     /* Try to read the vin. In case the dummy is there, this will be read as an empty vector. */
     s >> tx.vin;
     if (tx.vin.size() == 0 && fAllowWitness) {
         /* We read a dummy or an empty vin. */
         s >> flags;
     } else {
         /* We read a non-empty vin. Assume a normal vout follows. */
         s >> tx.vout;
     }
     s >> tx.nLockTime;
 }

 template<typename Stream, typename TxType>
 inline void SerializeTransaction(const TxType& tx, Stream& s) {
     const bool fAllowWitness = !(s.GetVersion() & SERIALIZE_TRANSACTION_NO_WITNESS);

     s << tx.nVersion;
     unsigned char flags = 0;
     // Consistency check
     if (fAllowWitness) {
         /* Check whether witnesses need to be serialized. */
         if (tx.HasWitness()) {
             flags |= 1;
         }
     }
     if (flags) {
         /* Use extended format in case witnesses are to be serialized. */
         std::vector<CTxIn> vinDummy;
         s << vinDummy;
         s << flags;
     }
     s << tx.vin;
     s << tx.vout;
     if (flags & 1) {
         for (size_t i = 0; i < tx.vin.size(); i++) {
             s << tx.vin[i].scriptWitness.stack;
         }
     }
     s << tx.nLockTime;
 }

bool AreInputsStandard(const CTransaction& tx, const CCoinsViewCache& mapInputs);

/**
 * Count ECDSA signature operations the old-fashioned (pre-0.6) way
 * @return number of sigops this transaction's outputs will produce when spent
 * @see CTransaction::FetchInputs
 */
unsigned int GetLegacySigOpCount(const CTransaction& tx);

/**
 * Count ECDSA signature operations in pay-to-script-hash inputs.
 *
 * @param[in] mapInputs Map of previous transactions that have outputs we're spending
 * @return maximum number of sigops required to validate this transaction's inputs
 * @see CTransaction::FetchInputs
 */
unsigned int GetP2SHSigOpCount(const CTransaction& tx, const CCoinsViewCache& mapInputs);

/**
 * Compute total signature operation cost of a transaction.
 * @param[in] tx     Transaction for which we are computing the cost
 * @param[in] inputs Map of previous transactions that have outputs we're spending
 * @param[out] flags Script verification flags
 * @return Total signature operation cost of tx
 */
int64_t GetTransactionSigOpCost(const CTransaction& tx, const CCoinsViewCache& inputs, int flags);

/**
 * Check whether all inputs of this transaction are valid (no double spends, scripts & sigs, amounts)
 * This does not modify the UTXO set. If pvChecks is not NULL, script checks are pushed onto it
 * instead of being performed inline.
 */
bool CheckInputs(const CTransaction& tx, CValidationState& state, const CCoinsViewCache& view, bool fScriptChecks, unsigned int flags, bool cacheStore, std::vector<CScriptCheck>* pvChecks = NULL);

/** Apply the effects of this transaction on the UTXO set represented by view */
void UpdateCoins(const CTransaction& tx, CValidationState& state, CCoinsViewCache& inputs, CTxUndo& txundo, int nHeight);

/** Context-independent validity checks */
bool CheckTransaction(const CTransaction& tx, CValidationState& state);

/**
 * Check if transaction will be final in the next block to be created.
 *
 * Calls IsFinalTx() with current block height and appropriate block time.
 *
 * See consensus/consensus.h for flag definitions.
 */
bool CheckFinalTx(const CTransaction& tx, int flags = -1);

/** Check for standard transaction types
 * @return True if all outputs (scriptPubKeys) use only standard transaction forms
 */
bool IsStandardTx(const CTransaction& tx, std::string& reason);

bool IsFinalTx(const CTransaction& tx, int nBlockHeight = 0, int64_t nBlockTime = 0);

/** Undo information for a CBlock */
class CBlockUndo
{
public:
    std::vector<CTxUndo> vtxundo; // for all but the coinbase

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        READWRITE(vtxundo);
    }

    bool WriteToDisk(CDiskBlockPos& pos, const uint256& hashBlock);
    bool ReadFromDisk(const CDiskBlockPos& pos, const uint256& hashBlock);
};


/**
 * Closure representing one script verification
 * Note that this stores references to the spending transaction
 */
class CScriptCheck
{
private:
    CScript scriptPubKey;
    const CTransaction* ptxTo;
    unsigned int nIn;
    unsigned int nFlags;
    bool cacheStore;
    ScriptError error;

public:
    CScriptCheck() : ptxTo(0), nIn(0), nFlags(0), cacheStore(false), error(SCRIPT_ERR_UNKNOWN_ERROR) {}
    CScriptCheck(const CCoins& txFromIn, const CTransaction& txToIn, unsigned int nInIn, unsigned int nFlagsIn, bool cacheIn) : scriptPubKey(txFromIn.vout[txToIn.vin[nInIn].prevout.n].scriptPubKey),
                                                                                                                                ptxTo(&txToIn), nIn(nInIn), nFlags(nFlagsIn), cacheStore(cacheIn), error(SCRIPT_ERR_UNKNOWN_ERROR) {}

    bool operator()();

    void swap(CScriptCheck& check)
    {
        scriptPubKey.swap(check.scriptPubKey);
        std::swap(ptxTo, check.ptxTo);
        std::swap(nIn, check.nIn);
        std::swap(nFlags, check.nFlags);
        std::swap(cacheStore, check.cacheStore);
        std::swap(error, check.error);
    }

    ScriptError GetScriptError() const { return error; }
};


/** Functions for disk access for blocks */
bool WriteBlockToDisk(CBlock& block, CDiskBlockPos& pos);
bool ReadBlockFromDisk(CBlock& block, const CDiskBlockPos& pos);
bool ReadBlockFromDisk(CBlock& block, const CBlockIndex* pindex);
bool ReadTransaction(CTransaction& tx, const CDiskTxPos &pos, uint256 &hashBlock);
bool FindTransactionsByDestination(const CTxDestination &dest, std::set<CExtDiskTxPos> &setpos);


/** Functions for validating blocks and updating the block tree */

/** Undo the effects of this block (with given index) on the UTXO set represented by coins.
 *  In case pfClean is provided, operation will try to be tolerant about errors, and *pfClean
 *  will be true if no problems were found. Otherwise, the return value will be false in case
 *  of problems. Note that in any case, coins may be modified. */
bool DisconnectBlock(CBlock& block, CValidationState& state, CBlockIndex* pindex, CCoinsViewCache& coins, bool* pfClean = NULL);

/** Reprocess a number of blocks to try and get on the correct chain again **/
bool DisconnectBlocksAndReprocess(int blocks);

/** Apply the effects of this block (with given index) on the UTXO set represented by coins */
bool ConnectBlock(const CBlock& block, CValidationState& state, CBlockIndex* pindex, CCoinsViewCache& coins, bool fJustCheck, bool fAlreadyChecked = false);

/** Context-independent validity checks */
bool CheckBlockHeader(const CBlockHeader& block, CValidationState& state, bool fCheckPOW = true);
bool CheckBlock(const CBlock& block, CValidationState& state, bool fCheckPOW = true, bool fCheckMerkleRoot = true, bool fCheckSig = true);
bool CheckWork(const CBlock &block, CBlockIndex* const pindexPrev);

/** Context-dependent validity checks */
bool ContextualCheckBlockHeader(const CBlockHeader& block, CValidationState& state, CBlockIndex* pindexPrev);
bool ContextualCheckBlock(const CBlock& block, CValidationState& state, CBlockIndex* pindexPrev);

/** Check a block is completely valid from start to finish (only works on top of our current best block, with cs_main held) */
bool TestBlockValidity(CValidationState& state, const CBlock& block, CBlockIndex* pindexPrev, bool fCheckPOW = true, bool fCheckMerkleRoot = true);

/** Store block on disk. If dbp is provided, the file is known to already reside on disk */
bool AcceptBlock(CBlock& block, CValidationState& state, CBlockIndex** pindex, CDiskBlockPos* dbp = NULL);
bool AcceptBlockHeader(const CBlockHeader& block, CValidationState& state, CBlockIndex** ppindex = NULL);

void UpdateUncommitedBlockStructures(CBlock& block, const CBlockIndex* pindexPrev);

/** Update uncommitted block structures (currently: only the witness nonce). This is safe for submitted blocks. */
void UpdateUncommitedBlockStructures(CBlock& block, const CBlockIndex* pindexPrev);

/** Produce the necessary coinbase commitment for a block (modifies the hash, don't call for mined blocks). */
std::vector<unsigned char> GenerateCoinbaseCommitment(CBlock& block, const CBlockIndex* pindexPrev);


class CBlockFileInfo
{
public:
    unsigned int nBlocks;      //! number of blocks stored in file
    unsigned int nSize;        //! number of used bytes of block file
    unsigned int nUndoSize;    //! number of used bytes in the undo file
    unsigned int nHeightFirst; //! lowest height of block in file
    unsigned int nHeightLast;  //! highest height of block in file
    uint64_t nTimeFirst;       //! earliest time of block in file
    uint64_t nTimeLast;        //! latest time of block in file

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        READWRITE(VARINT(nBlocks));
        READWRITE(VARINT(nSize));
        READWRITE(VARINT(nUndoSize));
        READWRITE(VARINT(nHeightFirst));
        READWRITE(VARINT(nHeightLast));
        READWRITE(VARINT(nTimeFirst));
        READWRITE(VARINT(nTimeLast));
    }

    void SetNull()
    {
        nBlocks = 0;
        nSize = 0;
        nUndoSize = 0;
        nHeightFirst = 0;
        nHeightLast = 0;
        nTimeFirst = 0;
        nTimeLast = 0;
    }

    CBlockFileInfo()
    {
        SetNull();
    }

    std::string ToString() const;

    /** update statistics (does not update nSize) */
    void AddBlock(unsigned int nHeightIn, uint64_t nTimeIn)
    {
        if (nBlocks == 0 || nHeightFirst > nHeightIn)
            nHeightFirst = nHeightIn;
        if (nBlocks == 0 || nTimeFirst > nTimeIn)
            nTimeFirst = nTimeIn;
        nBlocks++;
        if (nHeightIn > nHeightLast)
            nHeightLast = nHeightIn;
        if (nTimeIn > nTimeLast)
            nTimeLast = nTimeIn;
    }
};

/*
class CValidationState
{
private:
    enum mode_state {
        MODE_VALID,   //! everything ok
        MODE_INVALID, //! network rule violation (DoS value may be set)
        MODE_ERROR,   //! run-time error
    } mode;
    int nDoS;
    std::string strRejectReason;
    unsigned char chRejectCode;
    bool corruptionPossible;

public:
    CValidationState() : mode(MODE_VALID), nDoS(0), chRejectCode(0), corruptionPossible(false) {}
    bool DoS(int level, bool ret = false, unsigned char chRejectCodeIn = 0, std::string strRejectReasonIn = "", bool corruptionIn = false)
    {
        chRejectCode = chRejectCodeIn;
        strRejectReason = strRejectReasonIn;
        corruptionPossible = corruptionIn;
        if (mode == MODE_ERROR)
            return ret;
        nDoS += level;
        mode = MODE_INVALID;
        return ret;
    }
    bool Invalid(bool ret = false,
        unsigned char _chRejectCode = 0,
        std::string _strRejectReason = "")
    {
        return DoS(0, ret, _chRejectCode, _strRejectReason);
    }
    bool Error(std::string strRejectReasonIn = "")
    {
        if (mode == MODE_VALID)
            strRejectReason = strRejectReasonIn;
        mode = MODE_ERROR;
        return false;
    }
    bool Abort(const std::string& msg)
    {
        AbortNode(msg);
        return Error(msg);
    }
    bool IsValid() const
    {
        return mode == MODE_VALID;
    }
    bool IsInvalid() const
    {
        return mode == MODE_INVALID;
    }
    bool IsError() const
    {
        return mode == MODE_ERROR;
    }
    bool IsInvalid(int& nDoSOut) const
    {
        if (IsInvalid()) {
            nDoSOut = nDoS;
            return true;
        }
        return false;
    }
    bool CorruptionPossible() const
    {
        return corruptionPossible;
    }
    unsigned char GetRejectCode() const { return chRejectCode; }
    std::string GetRejectReason() const { return strRejectReason; }
};
*/
/** RAII wrapper for VerifyDB: Verify consistency of the block and coin databases */
class CVerifyDB
{
public:
    CVerifyDB();
    ~CVerifyDB();
    bool VerifyDB(CCoinsView* coinsview, int nCheckLevel, int nCheckDepth);
};

/** Find the last common block between the parameter chain and a locator. */
CBlockIndex* FindForkInGlobalIndex(const CChain& chain, const CBlockLocator& locator);

/** Mark a block as invalid. */
bool InvalidateBlock(CValidationState& state, CBlockIndex* pindex);

/** Remove invalidity status from a block and its descendants. */
bool ReconsiderBlock(CValidationState& state, CBlockIndex* pindex);

/** The currently-connected chain of blocks. */
extern CChain chainActive;

/** Global variable that points to the active CCoinsView (protected by cs_main) */
extern CCoinsViewCache* pcoinsTip;

/** Global variable that points to the active block tree (protected by cs_main) */
extern CBlockTreeDB* pblocktree;

extern StorageResults *pstorageresult;

struct CBlockTemplate {
    CBlock block;
    std::vector<CAmount> vTxFees;
    std::vector<int64_t> vTxSigOps;
    std::vector<int64_t> vTxSigOpsSize;
    std::vector<unsigned char> vchCoinbaseCommitment;
};


//////////////////////////////////////////////////////// lux
std::vector<ResultExecute> CallContract(const dev::Address& addrContract, std::vector<unsigned char> opcode, const dev::Address& sender = dev::Address(), uint64_t gasLimit=0);

bool CheckSenderScript(const CCoinsViewCache& view, const CTransaction& tx);

bool CheckMinGasPrice(std::vector<EthTransactionParams>& etps, const uint64_t& minGasPrice);

struct ByteCodeExecResult;

void EnforceContractVoutLimit(ByteCodeExecResult& bcer, ByteCodeExecResult& bcerOut, const dev::h256& oldHashLuxRoot,
                              const dev::h256& oldHashStateRoot, const std::vector<LuxTransaction>& transactions);

void writeVMlog(const std::vector<ResultExecute>& res, const CTransaction& tx = CTransaction(), const CBlock& block = CBlock());

struct EthTransactionParams{
    VersionVM version;
    dev::u256 gasLimit;
    dev::u256 gasPrice;
    valtype code;
    dev::Address receiveAddress;

    bool operator!=(EthTransactionParams etp){
        if(this->version.toRaw() != etp.version.toRaw() || this->gasLimit != etp.gasLimit ||
           this->gasPrice != etp.gasPrice || this->code != etp.code ||
           this->receiveAddress != etp.receiveAddress)
            return true;
        return false;
    }
};

struct ByteCodeExecResult{
    uint64_t usedGas = 0;
    CAmount refundSender = 0;
    std::vector<CTxOut> refundOutputs;
    std::vector<CTransaction> valueTransfers;
};

class LuxTxConverter{

public:

    LuxTxConverter(CTransaction tx, CCoinsViewCache* v = NULL, const std::vector<CTransaction>* blockTxs = NULL) : txBit(tx), view(v), blockTransactions(blockTxs){}

    bool extractionLuxTransactions(ExtractLuxTX& luxTx);

private:

    bool receiveStack(const CScript& scriptPubKey);

    bool parseEthTXParams(EthTransactionParams& params);

    LuxTransaction createEthTX(const EthTransactionParams& etp, const uint32_t nOut);

    const CTransaction txBit;
    const CCoinsViewCache* view;
    std::vector<valtype> stack;
    opcodetype opcode;
    const std::vector<CTransaction> *blockTransactions;

};

class ByteCodeExec {

public:

    ByteCodeExec(const CBlock& _block, std::vector<LuxTransaction> _txs, const uint64_t _blockGasLimit) : txs(_txs), block(_block), blockGasLimit(_blockGasLimit) {}

    bool performByteCode(dev::eth::Permanence type = dev::eth::Permanence::Committed);

    bool processingResults(ByteCodeExecResult& result);

    std::vector<ResultExecute>& getResult(){ return result; }

private:

    dev::eth::EnvInfo BuildEVMEnvironment();

    dev::Address EthAddrFromScript(const CScript& scriptIn);

    std::vector<LuxTransaction> txs;

    std::vector<ResultExecute> result;

    const CBlock& block;

    const uint64_t blockGasLimit;

};
////////////////////////////////////////////////////////


#endif // BITCOIN_MAIN_H
