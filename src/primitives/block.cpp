// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <cstring>
#include "primitives/block.h"

#include "hash.h"
#include "tinyformat.h"
#include "utilstrencodings.h"
#include "chainparams.h"
#include "consensus/params.h"
#include "crypto/common.h"
#include "crypto/scrypt.h"
#include "block.h"

uint256 CBlockHeader::GetHash(const Consensus::Params& params) const
{
    int version;
    if (nHeight >= (uint32_t)params.LTSHeight) {
        version = PROTOCOL_VERSION;
    } else {
        version = PROTOCOL_VERSION | SERIALIZE_BLOCK_LEGACY;
    }
    CHashWriter writer(SER_GETHASH, version);
    ::Serialize(writer, *this);
    return writer.GetHash();
}

uint256 CBlockHeader::GetHash() const
{
    const Consensus::Params& consensusParams = Params().GetConsensus();
    return GetHash(consensusParams);
}

uint256 CBlockHeader::GetPoWHash() const
{
    const Consensus::Params& consensusParams = Params().GetConsensus();
    return GetPoWHash(consensusParams);
}

uint256 CBlockHeader::GetPoWHash(const Consensus::Params& params) const
{
    if (nHeight >= (uint32_t)params.LTSHeight) {
        return GetHash(params);
    }

    uint32_t version;
    if (nHeight >= (uint32_t)params.LTSHeight) {
        version = PROTOCOL_VERSION;
    } else {
        version = PROTOCOL_VERSION | SERIALIZE_BLOCK_LEGACY;
    }

    // legacy serialize
    char buffer[80]={};
    int i = 0;
    buffer[0]=((char *)(&nVersion))[0];
    buffer[1]=((char *)(&nVersion))[1];
    buffer[2]=((char *)(&nVersion))[2];
    buffer[3]=((char *)(&nVersion))[3];
    i += sizeof(nVersion);
    memcpy(buffer+i, (char*)&hashPrevBlock, 32);
    i += 32;
    memcpy(buffer+i, (char*)&hashMerkleRoot, 32);
    i += 32;
    memcpy(buffer+i, (char*)&nTime, sizeof(nTime));
    i += sizeof(nTime);
    memcpy(buffer+i, (char*)&nBits, sizeof(nBits));
    i += sizeof(nBits);
    buffer[76]=((char *)(&nNonce))[0];
    buffer[77]=((char *)(&nNonce))[1];
    buffer[78]=((char *)(&nNonce))[2];
    buffer[79]=((char *)(&nNonce))[3];
    uint256 thash;
    scrypt_1024_1_1_256(buffer, BEGIN(thash));
    return thash;
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nHeight=%u, nTime=%u, nBits=%08x, nNonce=%s, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nHeight, nTime, nBits, nNonce.GetHex(),
        vtx.size());
    for (const auto& tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}


std::string CBlockHeader::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlockHeader(hash=%s, pow_hash=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nHeight=%u, nTime=%u, nBits=%08x, nNonce=%s)\n",
        GetHash().ToString(),
        GetPoWHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nHeight, nTime, nBits, nNonce.GetHex());
    return s.str();
}
