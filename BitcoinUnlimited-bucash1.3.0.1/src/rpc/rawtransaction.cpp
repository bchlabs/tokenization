// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2018 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "base58.h"
#include "chain.h"
#include "coins.h"
#include "consensus/validation.h"
#include "core_io.h"
#include "dstencode.h"
#include "init.h"
#include "keystore.h"
#include "main.h"
#include "merkleblock.h"
#include "net.h"
#include "policy/policy.h"
#include "primitives/transaction.h"
#include "rpc/server.h"
#include "script/script.h"
#include "script/script_error.h"
#include "script/sign.h"
#include "script/standard.h"
#include "txmempool.h"
#include "uahf_fork.h"
#include "uint256.h"
#include "utilstrencodings.h"
#ifdef ENABLE_WALLET
#include "wallet/wallet.h"
#endif

#include <stdint.h>

#include <boost/algorithm/string.hpp>
#include <boost/assign/list_of.hpp>

#include <univalue.h>

// Token
#include <amount.h>

using namespace std;

// Token
typedef vector<unsigned char> valtype;
std::map<std::string, CScript> scriptmap;

void ScriptPubKeyToJSON(const CScript &scriptPubKey, UniValue &out, bool fIncludeHex)
{
	txnouttype type;
	vector<CTxDestination> addresses;
	int nRequired;

	out.push_back(Pair("asm", ScriptToAsmStr(scriptPubKey)));
	if (fIncludeHex)
		out.push_back(Pair("hex", HexStr(scriptPubKey.begin(), scriptPubKey.end())));

	if (!ExtractDestinations(scriptPubKey, type, addresses, nRequired))
	{
		out.push_back(Pair("type", GetTxnOutputType(type)));
		return;
	}

	out.push_back(Pair("reqSigs", nRequired));
	out.push_back(Pair("type", GetTxnOutputType(type)));

	UniValue a(UniValue::VARR);
	for (const CTxDestination &addr : addresses)
	{
		a.push_back(EncodeDestination(addr));
	}

	out.push_back(Pair("addresses", a));
}

void TxToJSON(const CTransaction &tx, const uint256 hashBlock, UniValue &entry)
{
	entry.push_back(Pair("txid", tx.GetHash().GetHex()));
	entry.push_back(Pair("size", (int)::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION)));
	entry.push_back(Pair("version", tx.nVersion));
	entry.push_back(Pair("locktime", (int64_t)tx.nLockTime));
	UniValue vin(UniValue::VARR);
	BOOST_FOREACH (const CTxIn &txin, tx.vin)
	{
		UniValue in(UniValue::VOBJ);
		if (tx.IsCoinBase())
			in.push_back(Pair("coinbase", HexStr(txin.scriptSig.begin(), txin.scriptSig.end())));
		else
		{
			in.push_back(Pair("txid", txin.prevout.hash.GetHex()));
			in.push_back(Pair("vout", (int64_t)txin.prevout.n));
			UniValue o(UniValue::VOBJ);
			o.push_back(Pair("asm", ScriptToAsmStr(txin.scriptSig, true)));
			o.push_back(Pair("hex", HexStr(txin.scriptSig.begin(), txin.scriptSig.end())));
			in.push_back(Pair("scriptSig", o));
		}
		in.push_back(Pair("sequence", (int64_t)txin.nSequence));
		vin.push_back(in);
	}
	entry.push_back(Pair("vin", vin));
	UniValue vout(UniValue::VARR);
	for (unsigned int i = 0; i < tx.vout.size(); i++)
	{
		const CTxOut &txout = tx.vout[i];
		UniValue out(UniValue::VOBJ);
		out.push_back(Pair("value", ValueFromAmount(txout.nValue)));
		out.push_back(Pair("n", (int64_t)i));
		UniValue o(UniValue::VOBJ);
		ScriptPubKeyToJSON(txout.scriptPubKey, o, true);
		out.push_back(Pair("scriptPubKey", o));
		vout.push_back(out);
	}
	entry.push_back(Pair("vout", vout));

	if (!hashBlock.IsNull())
	{
		entry.push_back(Pair("blockhash", hashBlock.GetHex()));
		BlockMap::iterator mi = mapBlockIndex.find(hashBlock);
		if (mi != mapBlockIndex.end() && (*mi).second)
		{
			CBlockIndex *pindex = (*mi).second;
			if (chainActive.Contains(pindex))
			{
				entry.push_back(Pair("confirmations", 1 + chainActive.Height() - pindex->nHeight));
				entry.push_back(Pair("time", pindex->GetBlockTime()));
				entry.push_back(Pair("blocktime", pindex->GetBlockTime()));
			}
			else
				entry.push_back(Pair("confirmations", 0));
		}
	}
}

UniValue getrawtransaction(const UniValue &params, bool fHelp)
{
	if (fHelp || params.size() < 1 || params.size() > 2)
		throw runtime_error(
				"getrawtransaction \"txid\" ( verbose )\n"
				"\nNOTE: By default this function only works sometimes. This is when the tx is in the mempool\n"
				"or there is an unspent output in the utxo for this transaction. To make it always work,\n"
				"you need to maintain a transaction index, using the -txindex command line option.\n"
				"\nReturn the raw transaction data.\n"
				"\nIf verbose=0, returns a string that is serialized, hex-encoded data for 'txid'.\n"
				"If verbose is non-zero, returns an Object with information about 'txid'.\n"

				"\nArguments:\n"
				"1. \"txid\"      (string, required) The transaction id\n"
				"2. verbose       (numeric, optional, default=0) If 0, return a string, other return a json object\n"

				"\nResult (if verbose is not set or set to 0):\n"
				"\"data\"      (string) The serialized, hex-encoded data for 'txid'\n"

				"\nResult (if verbose > 0):\n"
				"{\n"
				"  \"hex\" : \"data\",       (string) The serialized, hex-encoded data for 'txid'\n"
				"  \"txid\" : \"id\",        (string) The transaction id (same as provided)\n"
				"  \"size\" : n,             (numeric) The transaction size\n"
				"  \"version\" : n,          (numeric) The version\n"
				"  \"locktime\" : ttt,       (numeric) The lock time\n"
				"  \"vin\" : [               (array of json objects)\n"
				"     {\n"
				"       \"txid\": \"id\",    (string) The transaction id\n"
				"       \"vout\": n,         (numeric) \n"
				"       \"scriptSig\": {     (json object) The script\n"
				"         \"asm\": \"asm\",  (string) asm\n"
				"         \"hex\": \"hex\"   (string) hex\n"
				"       },\n"
				"       \"sequence\": n      (numeric) The script sequence number\n"
				"     }\n"
				"     ,...\n"
				"  ],\n"
				"  \"vout\" : [              (array of json objects)\n"
				"     {\n"
				"       \"value\" : x.xxx,            (numeric) The value in " +
				CURRENCY_UNIT +
				"\n"
				"       \"n\" : n,                    (numeric) index\n"
				"       \"scriptPubKey\" : {          (json object)\n"
				"         \"asm\" : \"asm\",          (string) the asm\n"
				"         \"hex\" : \"hex\",          (string) the hex\n"
				"         \"reqSigs\" : n,            (numeric) The required sigs\n"
				"         \"type\" : \"pubkeyhash\",  (string) The type, eg 'pubkeyhash'\n"
				"         \"addresses\" : [           (json array of string)\n"
				"           \"bitcoinaddress\"        (string) bitcoin address\n"
				"           ,...\n"
				"         ]\n"
				"       }\n"
				"     }\n"
				"     ,...\n"
				"  ],\n"
				"  \"blockhash\" : \"hash\",   (string) the block hash\n"
				"  \"confirmations\" : n,      (numeric) The confirmations\n"
				"  \"time\" : ttt,             (numeric) The transaction time in seconds since epoch (Jan 1 1970 GMT)\n"
				"  \"blocktime\" : ttt         (numeric) The block time in seconds since epoch (Jan 1 1970 GMT)\n"
				"}\n"

				"\nExamples:\n" +
				HelpExampleCli("getrawtransaction", "\"mytxid\"") + HelpExampleCli("getrawtransaction", "\"mytxid\" 1") +
				HelpExampleRpc("getrawtransaction", "\"mytxid\", 1"));

	LOCK(cs_main);

	uint256 hash = ParseHashV(params[0], "parameter 1");

	bool fVerbose = false;
	if (params.size() > 1)
		fVerbose = (params[1].get_int() != 0);

	CTransactionRef tx;
	uint256 hashBlock;
	if (!GetTransaction(hash, tx, Params().GetConsensus(), hashBlock, true))
		throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available about transaction");

	string strHex = EncodeHexTx(*tx);

	if (!fVerbose)
		return strHex;

	UniValue result(UniValue::VOBJ);
	result.push_back(Pair("hex", strHex));
	TxToJSON(*tx, hashBlock, result);
	return result;
}

UniValue gettxoutproof(const UniValue &params, bool fHelp)
{
	if (fHelp || (params.size() != 1 && params.size() != 2))
		throw runtime_error(
				"gettxoutproof [\"txid\",...] ( blockhash )\n"
				"\nReturns a hex-encoded proof that \"txid\" was included in a block.\n"
				"\nNOTE: By default this function only works sometimes. This is when there is an\n"
				"unspent output in the utxo for this transaction. To make it always work,\n"
				"you need to maintain a transaction index, using the -txindex command line option or\n"
				"specify the block in which the transaction is included in manually (by blockhash).\n"
				"\nReturn the raw transaction data.\n"
				"\nArguments:\n"
				"1. \"txids\"       (string) A json array of txids to filter\n"
				"    [\n"
				"      \"txid\"     (string) A transaction hash\n"
				"      ,...\n"
				"    ]\n"
				"2. \"block hash\"  (string, optional) If specified, looks for txid in the block with this hash\n"
				"\nResult:\n"
				"\"data\"           (string) A string that is a serialized, hex-encoded data for the proof.\n");

	set<uint256> setTxids;
	uint256 oneTxid;
	UniValue txids = params[0].get_array();
	for (unsigned int idx = 0; idx < txids.size(); idx++)
	{
		const UniValue &txid = txids[idx];
		if (txid.get_str().length() != 64 || !IsHex(txid.get_str()))
			throw JSONRPCError(RPC_INVALID_PARAMETER, string("Invalid txid ") + txid.get_str());
		uint256 hash(uint256S(txid.get_str()));
		if (setTxids.count(hash))
			throw JSONRPCError(RPC_INVALID_PARAMETER, string("Invalid parameter, duplicated txid: ") + txid.get_str());
		setTxids.insert(hash);
		oneTxid = hash;
	}

	LOCK(cs_main);

	CBlockIndex *pblockindex = nullptr;

	uint256 hashBlock;
	if (params.size() > 1)
	{
		hashBlock = uint256S(params[1].get_str());
		if (!mapBlockIndex.count(hashBlock))
			throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
		pblockindex = mapBlockIndex[hashBlock];
	}
	else
	{
		const Coin &coin = AccessByTxid(*pcoinsTip, oneTxid);
		if (!coin.IsSpent() && coin.nHeight > 0 && coin.nHeight <= chainActive.Height())
		{
			pblockindex = chainActive[coin.nHeight];
		}
	}

	if (pblockindex == nullptr)
	{
		CTransactionRef tx;
		if (!GetTransaction(oneTxid, tx, Params().GetConsensus(), hashBlock, false) || hashBlock.IsNull())
			throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Transaction not yet in block");
		if (!mapBlockIndex.count(hashBlock))
			throw JSONRPCError(RPC_INTERNAL_ERROR, "Transaction index corrupt");
		pblockindex = mapBlockIndex[hashBlock];
	}

	CBlock block;
	if (!ReadBlockFromDisk(block, pblockindex, Params().GetConsensus()))
		throw JSONRPCError(RPC_INTERNAL_ERROR, "Can't read block from disk");

	unsigned int ntxFound = 0;
	for (const auto &tx : block.vtx)
		if (setTxids.count(tx->GetHash()))
			ntxFound++;
	if (ntxFound != setTxids.size())
		throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "(Not all) transactions not found in specified block");

	CDataStream ssMB(SER_NETWORK, PROTOCOL_VERSION);
	CMerkleBlock mb(block, setTxids);
	ssMB << mb;
	std::string strHex = HexStr(ssMB.begin(), ssMB.end());
	return strHex;
}

UniValue verifytxoutproof(const UniValue &params, bool fHelp)
{
	if (fHelp || params.size() != 1)
		throw runtime_error(
				"verifytxoutproof \"proof\"\n"
				"\nVerifies that a proof points to a transaction in a block, returning the transaction it commits to\n"
				"and throwing an RPC error if the block is not in our best chain\n"
				"\nArguments:\n"
				"1. \"proof\"    (string, required) The hex-encoded proof generated by gettxoutproof\n"
				"\nResult:\n"
				"[\"txid\"]      (array, strings) The txid(s) which the proof commits to, or empty array if the proof is "
				"invalid\n");

	CDataStream ssMB(ParseHexV(params[0], "proof"), SER_NETWORK, PROTOCOL_VERSION);
	CMerkleBlock merkleBlock;
	ssMB >> merkleBlock;

	UniValue res(UniValue::VARR);

	vector<uint256> vMatch;
	vector<unsigned int> vIndex;
	if (merkleBlock.txn.ExtractMatches(vMatch, vIndex) != merkleBlock.header.hashMerkleRoot)
		return res;

	LOCK(cs_main);

	if (!mapBlockIndex.count(merkleBlock.header.GetHash()) ||
			!chainActive.Contains(mapBlockIndex[merkleBlock.header.GetHash()]))
		throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found in chain");

	BOOST_FOREACH (const uint256 &hash, vMatch)
		res.push_back(hash.GetHex());
	return res;
}

UniValue createrawtransaction(const UniValue &params, bool fHelp)
{
	if (fHelp || params.size() < 2 || params.size() > 3)
		throw runtime_error(
				"createrawtransaction [{\"txid\":\"id\",\"vout\":n},...] {\"address\":amount,\"data\":\"hex\",...} ( "
				"locktime )\n"
				"\nCreate a transaction spending the given inputs and creating new outputs.\n"
				"Outputs can be addresses or data.\n"
				"Returns hex-encoded raw transaction.\n"
				"Note that the transaction's inputs are not signed, and\n"
				"it is not stored in the wallet or transmitted to the network.\n"

				"\nArguments:\n"
				"1. \"transactions\"        (string, required) A json array of json objects\n"
				"     [\n"
				"       {\n"
				"         \"txid\":\"id\",    (string, required) The transaction id\n"
				"         \"vout\":n        (numeric, required) The output number\n"
				"       }\n"
				"       ,...\n"
				"     ]\n"
				"2. \"outputs\"             (string, required) a json object with outputs\n"
				"    {\n"
				"      \"address\": x.xxx   (numeric or string, required) The key is the bitcoin address, the numeric "
				"value (can be string) is the " +
				CURRENCY_UNIT +
				" amount\n"
				"      \"data\": \"hex\",     (string, required) The key is \"data\", the value is hex encoded data\n"
				"      ...\n"
				"    }\n"
				"3. locktime                (numeric, optional, default=0) Raw locktime. Non-0 value also "
				"locktime-activates inputs\n"
				"\nResult:\n"
				"\"transaction\"            (string) hex string of the transaction\n"

				"\nExamples\n" +
				HelpExampleCli(
						"createrawtransaction", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\" \"{\\\"address\\\":0.01}\"") +
				HelpExampleCli("createrawtransaction",
						"\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\" \"{\\\"data\\\":\\\"00010203\\\"}\"") +
				HelpExampleRpc("createrawtransaction",
						"\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\", \"{\\\"address\\\":0.01}\"") +
				HelpExampleRpc("createrawtransaction",
						"\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\", \"{\\\"data\\\":\\\"00010203\\\"}\""));

	LOCK(cs_main);
	RPCTypeCheck(params, boost::assign::list_of(UniValue::VARR)(UniValue::VOBJ)(UniValue::VNUM), true);
	if (params[0].isNull() || params[1].isNull())
		throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, arguments 1 and 2 must be non-null");

	UniValue inputs = params[0].get_array();
	UniValue sendTo = params[1].get_obj();

	CMutableTransaction rawTx;

	if (params.size() > 2 && !params[2].isNull())
	{
		int64_t nLockTime = params[2].get_int64();
		if (nLockTime < 0 || nLockTime > std::numeric_limits<uint32_t>::max())
			throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, locktime out of range");
		rawTx.nLockTime = nLockTime;
	}

	for (unsigned int idx = 0; idx < inputs.size(); idx++)
	{
		const UniValue &input = inputs[idx];
		const UniValue &o = input.get_obj();

		uint256 txid = ParseHashO(o, "txid");

		const UniValue &vout_v = find_value(o, "vout");
		if (!vout_v.isNum())
			throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, missing vout key");
		int nOutput = vout_v.get_int();
		if (nOutput < 0)
			throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, vout must be positive");

		uint32_t nSequence =
			(rawTx.nLockTime ? std::numeric_limits<uint32_t>::max() - 1 : std::numeric_limits<uint32_t>::max());
		CTxIn in(COutPoint(txid, nOutput), CScript(), nSequence);

		rawTx.vin.push_back(in);
	}

	std::set<CTxDestination> destinations;
	std::vector<std::string> addrList = sendTo.getKeys();
	for (const std::string &name_ : addrList)
	{
		if (name_ == "data")
		{
			std::vector<unsigned char> data = ParseHexV(sendTo[name_].getValStr(), "Data");

			CTxOut out(0, CScript() << OP_RETURN << data);
			rawTx.vout.push_back(out);
		}
		else
		{
			CTxDestination destination = DecodeDestination(name_);
			if (!IsValidDestination(destination))
			{
				throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid Bitcoin address: ") + name_);
			}

			if (!destinations.insert(destination).second)
			{
				throw JSONRPCError(
						RPC_INVALID_PARAMETER, std::string("Invalid parameter, duplicated address: ") + name_);
			}

			CScript scriptPubKey = GetScriptForDestination(destination);
			CAmount nAmount = AmountFromValue(sendTo[name_]);

			CTxOut out(nAmount, scriptPubKey);
			rawTx.vout.push_back(out);
		}
	}

	return EncodeHexTx(rawTx);
}

UniValue decoderawtransaction(const UniValue &params, bool fHelp)
{
	if (fHelp || params.size() != 1)
		throw runtime_error("decoderawtransaction \"hexstring\"\n"
				"\nReturn a JSON object representing the serialized, hex-encoded transaction.\n"

				"\nArguments:\n"
				"1. \"hex\"      (string, required) The transaction hex string\n"

				"\nResult:\n"
				"{\n"
				"  \"txid\" : \"id\",        (string) The transaction id\n"
				"  \"size\" : n,             (numeric) The transaction size\n"
				"  \"version\" : n,          (numeric) The version\n"
				"  \"locktime\" : ttt,       (numeric) The lock time\n"
				"  \"vin\" : [               (array of json objects)\n"
				"     {\n"
				"       \"txid\": \"id\",    (string) The transaction id\n"
				"       \"vout\": n,         (numeric) The output number\n"
				"       \"scriptSig\": {     (json object) The script\n"
				"         \"asm\": \"asm\",  (string) asm\n"
				"         \"hex\": \"hex\"   (string) hex\n"
				"       },\n"
				"       \"sequence\": n     (numeric) The script sequence number\n"
				"     }\n"
				"     ,...\n"
				"  ],\n"
				"  \"vout\" : [             (array of json objects)\n"
				"     {\n"
				"       \"value\" : x.xxx,            (numeric) The value in " +
				CURRENCY_UNIT +
				"\n"
				"       \"n\" : n,                    (numeric) index\n"
				"       \"scriptPubKey\" : {          (json object)\n"
				"         \"asm\" : \"asm\",          (string) the asm\n"
				"         \"hex\" : \"hex\",          (string) the hex\n"
				"         \"reqSigs\" : n,            (numeric) The required sigs\n"
				"         \"type\" : \"pubkeyhash\",  (string) The type, eg 'pubkeyhash'\n"
				"         \"addresses\" : [           (json array of string)\n"
				"           \"12tvKAXCxZjSmdNbao16dKXC8tRWfcF5oc\"   (string) bitcoin address\n"
				"           ,...\n"
				"         ]\n"
				"       }\n"
				"     }\n"
				"     ,...\n"
				"  ],\n"
				"}\n"

				"\nExamples:\n" +
				HelpExampleCli("decoderawtransaction", "\"hexstring\"") +
				HelpExampleRpc("decoderawtransaction", "\"hexstring\""));

	LOCK(cs_main);
	RPCTypeCheck(params, boost::assign::list_of(UniValue::VSTR));

	CTransaction tx;

	if (!DecodeHexTx(tx, params[0].get_str()))
		throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");

	UniValue result(UniValue::VOBJ);
	TxToJSON(tx, uint256(), result);

	return result;
}

UniValue decodescript(const UniValue &params, bool fHelp)
{
	if (fHelp || params.size() != 1)
		throw runtime_error("decodescript \"hex\"\n"
				"\nDecode a hex-encoded script.\n"
				"\nArguments:\n"
				"1. \"hex\"     (string) the hex encoded script\n"
				"\nResult:\n"
				"{\n"
				"  \"asm\":\"asm\",   (string) Script public key\n"
				"  \"hex\":\"hex\",   (string) hex encoded public key\n"
				"  \"type\":\"type\", (string) The output type\n"
				"  \"reqSigs\": n,    (numeric) The required signatures\n"
				"  \"addresses\": [   (json array of string)\n"
				"     \"address\"     (string) bitcoin address\n"
				"     ,...\n"
				"  ],\n"
				"  \"p2sh\",\"address\" (string) script address\n"
				"}\n"
				"\nExamples:\n" +
				HelpExampleCli("decodescript", "\"hexstring\"") +
				HelpExampleRpc("decodescript", "\"hexstring\""));

	RPCTypeCheck(params, boost::assign::list_of(UniValue::VSTR));

	UniValue r(UniValue::VOBJ);
	CScript script;
	if (params[0].get_str().size() > 0)
	{
		vector<unsigned char> scriptData(ParseHexV(params[0], "argument"));
		script = CScript(scriptData.begin(), scriptData.end());
	}
	else
	{
		// Empty scripts are valid
	}
	ScriptPubKeyToJSON(script, r, false);

	UniValue type;
	type = find_value(r, "type");

	if (type.isStr() && type.get_str() != "scripthash")
	{
		// P2SH cannot be wrapped in a P2SH. If this script is already a P2SH,
		// don't return the address for a P2SH of the P2SH.
		r.push_back(Pair("p2sh", EncodeDestination(CScriptID(script))));
	}

	return r;
}

/** Pushes a JSON object for script verification or signing errors to vErrorsRet. */
static void TxInErrorToJSON(const CTxIn &txin, UniValue &vErrorsRet, const std::string &strMessage)
{
	UniValue entry(UniValue::VOBJ);
	entry.push_back(Pair("txid", txin.prevout.hash.ToString()));
	entry.push_back(Pair("vout", (uint64_t)txin.prevout.n));
	entry.push_back(Pair("scriptSig", HexStr(txin.scriptSig.begin(), txin.scriptSig.end())));
	entry.push_back(Pair("sequence", (uint64_t)txin.nSequence));
	entry.push_back(Pair("error", strMessage));
	vErrorsRet.push_back(entry);
}

UniValue signrawtransaction(const UniValue &params, bool fHelp)
{
	if (fHelp || params.size() < 1 || params.size() > 4)
		throw runtime_error(
				"signrawtransaction \"hexstring\" ( "
				"[{\"txid\":\"id\",\"vout\":n,\"scriptPubKey\":\"hex\",\"redeemScript\":\"hex\"},...] "
				"[\"privatekey1\",...] sighashtype )\n"
				"\nSign inputs for raw transaction (serialized, hex-encoded).\n"
				"The second optional argument (may be null) is an array of previous transaction outputs that\n"
				"this transaction depends on but may not yet be in the block chain.\n"
				"The third optional argument (may be null) is an array of base58-encoded private\n"
				"keys that, if given, will be the only keys used to sign the transaction.\n"
#ifdef ENABLE_WALLET
				+ HelpRequiringPassphrase() +
				"\n"
#endif

				"\nArguments:\n"
				"1. \"hexstring\"     (string, required) The transaction hex string\n"
				"2. \"prevtxs\"       (string, optional) An json array of previous dependent transaction outputs\n"
				"     [               (json array of json objects, or 'null' if none provided)\n"
				"       {\n"
				"         \"txid\":\"id\",             (string, required) The transaction id\n"
				"         \"vout\":n,                  (numeric, required) The output number\n"
				"         \"scriptPubKey\": \"hex\",   (string, required) script key\n"
				"         \"redeemScript\": \"hex\"    (string, required for P2SH) redeem script\n"
				"         \"amount\": value            (numeric, required) The amount spent\n"
				"       }\n"
				"       ,...\n"
				"    ]\n"
				"3. \"privatekeys\"     (string, optional) A json array of base58-encoded private keys for signing\n"
				"    [                  (json array of strings, or 'null' if none provided)\n"
				"      \"privatekey\"   (string) private key in base58-encoding\n"
				"      ,...\n"
				"    ]\n"
				"4. \"sighashtype\"     (string, optional, default=ALL) The signature hash type. Must be one of\n"
				"       \"ALL\"\n"
				"       \"NONE\"\n"
				"       \"SINGLE\"\n"
				"       followed by ANYONECANPAY and/or FORKID/NOFORKID flags separated with |, for example\n"
				"       \"ALL|ANYONECANPAY|FORKID\"\n"
				"       \"NONE|FORKID\"\n"
				"       \"SINGLE|ANYONECANPAY\"\n"

				"\nResult:\n"
				"{\n"
				"  \"hex\" : \"value\",           (string) The hex-encoded raw transaction with signature(s)\n"
				"  \"complete\" : true|false,   (boolean) If the transaction has a complete set of signatures\n"
				"  \"errors\" : [                 (json array of objects) Script verification errors (if there are any)\n"
				"    {\n"
				"      \"txid\" : \"hash\",           (string) The hash of the referenced, previous transaction\n"
				"      \"vout\" : n,                (numeric) The index of the output to spent and used as input\n"
				"      \"scriptSig\" : \"hex\",       (string) The hex-encoded signature script\n"
				"      \"sequence\" : n,            (numeric) Script sequence number\n"
				"      \"error\" : \"text\"           (string) Verification or signing error related to the input\n"
				"    }\n"
				"    ,...\n"
				"  ]\n"
				"}\n"

				"\nExamples:\n" +
				HelpExampleCli("signrawtransaction", "\"myhex\"") + HelpExampleRpc("signrawtransaction", "\"myhex\""));

#ifdef ENABLE_WALLET
	LOCK2(cs_main, pwalletMain ? &pwalletMain->cs_wallet : NULL);
#else
	LOCK(cs_main);
#endif
	RPCTypeCheck(params, boost::assign::list_of(UniValue::VSTR)(UniValue::VARR)(UniValue::VARR)(UniValue::VSTR), true);

	vector<unsigned char> txData(ParseHexV(params[0], "argument 1"));
	CDataStream ssData(txData, SER_NETWORK, PROTOCOL_VERSION);
	vector<CMutableTransaction> txVariants;
	while (!ssData.empty())
	{
		try
		{
			CMutableTransaction tx;
			ssData >> tx;
			txVariants.push_back(tx);
		}
		catch (const std::exception &)
		{
			throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
		}
	}

	if (txVariants.empty())
		throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Missing transaction");

	// mergedTx will end up with all the signatures; it
	// starts as a clone of the rawtx:
	CMutableTransaction mergedTx(txVariants[0]);

	// Fetch previous transactions (inputs):
	CCoinsView viewDummy;
	CCoinsViewCache view(&viewDummy);
	{
		READLOCK(mempool.cs);
		CCoinsViewCache &viewChain = *pcoinsTip;
		CCoinsViewMemPool viewMempool(&viewChain, mempool);
		view.SetBackend(viewMempool); // temporarily switch cache backend to db+mempool view

		BOOST_FOREACH (const CTxIn &txin, mergedTx.vin)
		{
			view.AccessCoin(txin.prevout); // Load entries from viewChain into view; can fail.
		}

		view.SetBackend(viewDummy); // switch back to avoid locking mempool for too long
	}

	bool fGivenKeys = false;
	CBasicKeyStore tempKeystore;
	if (params.size() > 2 && !params[2].isNull())
	{
		fGivenKeys = true;
		UniValue keys = params[2].get_array();
		for (unsigned int idx = 0; idx < keys.size(); idx++)
		{
			UniValue k = keys[idx];
			CBitcoinSecret vchSecret;
			bool fGood = vchSecret.SetString(k.get_str());
			if (!fGood)
				throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key");
			CKey key = vchSecret.GetKey();
			if (!key.IsValid())
				throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Private key outside allowed range");
			tempKeystore.AddKey(key);
		}
	}
#ifdef ENABLE_WALLET
	else if (pwalletMain)
		EnsureWalletIsUnlocked();
#endif

	// Add previous txouts given in the RPC call:
	if (params.size() > 1 && !params[1].isNull())
	{
		UniValue prevTxs = params[1].get_array();
		for (unsigned int idx = 0; idx < prevTxs.size(); idx++)
		{
			const UniValue &p = prevTxs[idx];
			if (!p.isObject())
				throw JSONRPCError(
						RPC_DESERIALIZATION_ERROR, "expected object with {\"txid'\",\"vout\",\"scriptPubKey\"}");

			UniValue prevOut = p.get_obj();

			RPCTypeCheckObj(prevOut, boost::assign::map_list_of("txid", UniValue::VSTR)("vout", UniValue::VNUM)(
						"scriptPubKey", UniValue::VSTR));

			uint256 txid = ParseHashO(prevOut, "txid");

			int nOut = find_value(prevOut, "vout").get_int();
			if (nOut < 0)
				throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "vout must be positive");

			COutPoint out(txid, nOut);
			std::vector<unsigned char> pkData(ParseHexO(prevOut, "scriptPubKey"));
			CScript scriptPubKey(pkData.begin(), pkData.end());

			{
				const Coin &coin = view.AccessCoin(out);
				if (!coin.IsSpent() && coin.out.scriptPubKey != scriptPubKey)
				{
					std::string err("Previous output scriptPubKey mismatch:\n");
					err = err + ScriptToAsmStr(coin.out.scriptPubKey) + "\nvs:\n" + ScriptToAsmStr(scriptPubKey);
					throw JSONRPCError(RPC_DESERIALIZATION_ERROR, err);
				}
				Coin newcoin;
				newcoin.out.scriptPubKey = scriptPubKey;
				newcoin.out.nValue = 0;
				if (prevOut.exists("amount"))
				{
					newcoin.out.nValue = AmountFromValue(find_value(prevOut, "amount"));
				}
				newcoin.nHeight = 1;
				view.AddCoin(out, std::move(newcoin), true);
			}

			// if redeemScript given and not using the local wallet (private keys
			// given), add redeemScript to the tempKeystore so it can be signed:
			if (fGivenKeys && scriptPubKey.IsPayToScriptHash())
			{
				RPCTypeCheckObj(prevOut, boost::assign::map_list_of("txid", UniValue::VSTR)("vout", UniValue::VNUM)(
							"scriptPubKey", UniValue::VSTR)("redeemScript", UniValue::VSTR));
				UniValue v = find_value(prevOut, "redeemScript");
				if (!v.isNull())
				{
					vector<unsigned char> rsData(ParseHexV(v, "redeemScript"));
					CScript redeemScript(rsData.begin(), rsData.end());
					tempKeystore.AddCScript(redeemScript);
				}
			}
		}
	}

#ifdef ENABLE_WALLET
	const CKeyStore &keystore = ((fGivenKeys || !pwalletMain) ? tempKeystore : *pwalletMain);
#else
	const CKeyStore &keystore = tempKeystore;
#endif

	int nHashType = SIGHASH_ALL;
	bool pickedForkId = false;
	if (params.size() > 3 && !params[3].isNull())
	{
		std::string strHashType = params[3].get_str();

		std::vector<string> strings;
		std::istringstream ss(strHashType);
		std::string s;
		while (getline(ss, s, '|'))
		{
			boost::trim(s);
			if (boost::iequals(s, "ALL"))
				nHashType = SIGHASH_ALL;
			else if (boost::iequals(s, "NONE"))
				nHashType = SIGHASH_NONE;
			else if (boost::iequals(s, "SINGLE"))
				nHashType = SIGHASH_SINGLE;
			else if (boost::iequals(s, "ANYONECANPAY"))
				nHashType |= SIGHASH_ANYONECANPAY;
			else if (boost::iequals(s, "FORKID"))
			{
				pickedForkId = true;
				nHashType |= SIGHASH_FORKID;
			}
			else if (boost::iequals(s, "NOFORKID"))
			{
				pickedForkId = true;
				nHashType &= ~SIGHASH_FORKID;
			}
			else
			{
				throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid sighash param");
			}
		}
	}
	if (!pickedForkId) // If the user didn't specify, use the configured default for the hash type
	{
		if (IsUAHFforkActiveOnNextBlock(chainActive.Tip()->nHeight))
		{
			nHashType |= SIGHASH_FORKID;
			pickedForkId = true;
		}
	}

	bool fHashSingle = ((nHashType & ~(SIGHASH_ANYONECANPAY | SIGHASH_FORKID)) == SIGHASH_SINGLE);

	// Script verification errors
	UniValue vErrors(UniValue::VARR);

	// Use CTransaction for the constant parts of the
	// transaction to avoid rehashing.
	const CTransaction txConst(mergedTx);
	// Sign what we can:
	for (unsigned int i = 0; i < mergedTx.vin.size(); i++)
	{
		CTxIn &txin = mergedTx.vin[i];
		const Coin &coin = view.AccessCoin(txin.prevout);
		if (coin.IsSpent())
		{
			TxInErrorToJSON(txin, vErrors, "Input not found or already spent");
			continue;
		}
		const CScript &prevPubKey = coin.out.scriptPubKey;
		const CAmount &amount = coin.out.nValue;

		// Only sign SIGHASH_SINGLE if there's a corresponding output:
		if (!fHashSingle || (i < mergedTx.vout.size()))
			SignSignature(keystore, prevPubKey, mergedTx, i, amount, nHashType);

		// ... and merge in other signatures:
		if (pickedForkId)
		{
			BOOST_FOREACH (const CMutableTransaction &txv, txVariants)
			{
				txin.scriptSig = CombineSignatures(prevPubKey,
						TransactionSignatureChecker(&txConst, i, amount, SCRIPT_ENABLE_SIGHASH_FORKID), txin.scriptSig,
						txv.vin[i].scriptSig);
			}
			ScriptError serror = SCRIPT_ERR_OK;

			if (!VerifyScript(txin.scriptSig, prevPubKey, STANDARD_SCRIPT_VERIFY_FLAGS | SCRIPT_ENABLE_SIGHASH_FORKID,
						MutableTransactionSignatureChecker(&mergedTx, i, amount, SCRIPT_ENABLE_SIGHASH_FORKID), &serror))
			{
				TxInErrorToJSON(txin, vErrors, ScriptErrorString(serror));
			}
		}
		else
		{
			BOOST_FOREACH (const CMutableTransaction &txv, txVariants)
			{
				txin.scriptSig = CombineSignatures(prevPubKey, TransactionSignatureChecker(&txConst, i, amount, 0),
						txin.scriptSig, txv.vin[i].scriptSig);
			}
			ScriptError serror = SCRIPT_ERR_OK;
			if (!VerifyScript(txin.scriptSig, prevPubKey, STANDARD_SCRIPT_VERIFY_FLAGS,
						MutableTransactionSignatureChecker(&mergedTx, i, amount, 0), &serror))
			{
				TxInErrorToJSON(txin, vErrors, ScriptErrorString(serror));
			}
		}
	}
	bool fComplete = vErrors.empty();

	UniValue result(UniValue::VOBJ);
	result.push_back(Pair("hex", EncodeHexTx(mergedTx)));
	result.push_back(Pair("complete", fComplete));
	if (!vErrors.empty())
	{
		result.push_back(Pair("errors", vErrors));
	}

	return result;
}

UniValue sendrawtransaction(const UniValue &params, bool fHelp)
{
	if (fHelp || params.size() < 1 || params.size() > 3)
		throw runtime_error(
				"sendrawtransaction \"hexstring\" ( allowhighfees, allownonstandard )\n"
				"\nSubmits raw transaction (serialized, hex-encoded) to local node and network.\n"
				"\nAlso see createrawtransaction and signrawtransaction calls.\n"
				"\nArguments:\n"
				"1. \"hexstring\"    (string, required) The hex string of the raw transaction)\n"
				"2. allowhighfees    (boolean, optional, default=false) Allow high fees\n"
				"3. allownonstandard (string 'standard', 'nonstandard', 'default', optional, default='default')\n"
				"                    Force standard or nonstandard transaction check\n"
				"\nResult:\n"
				"\"hex\"             (string) The transaction hash in hex\n"
				"\nExamples:\n"
				"\nCreate a transaction\n" +
				HelpExampleCli("createrawtransaction",
					"\"[{\\\"txid\\\" : \\\"mytxid\\\",\\\"vout\\\":0}]\" \"{\\\"myaddress\\\":0.01}\"") +
				"Sign the transaction, and get back the hex\n" + HelpExampleCli("signrawtransaction", "\"myhex\"") +
				"\nSend the transaction (signed hex)\n" + HelpExampleCli("sendrawtransaction", "\"signedhex\"") +
				"\nAs a json rpc call\n" + HelpExampleRpc("sendrawtransaction", "\"signedhex\""));

	LOCK(cs_main);
	RPCTypeCheck(params, boost::assign::list_of(UniValue::VSTR)(UniValue::VBOOL)(UniValue::VSTR));

	// parse hex string from parameter
	CTransaction tx;
	if (!DecodeHexTx(tx, params[0].get_str()))
		throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
	uint256 hashTx = tx.GetHash();

	bool fOverrideFees = false;
	TransactionClass txClass = TransactionClass::DEFAULT;

	// 2nd parameter allows high fees
	if (params.size() > 1)
	{
		fOverrideFees = params[1].get_bool();
	}
	// 3rd parameter must be the transaction class
	if (params.size() > 2)
	{
		txClass = ParseTransactionClass(params[2].get_str());
		if (txClass == TransactionClass::INVALID)
			throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid transaction class");
	}

	CCoinsViewCache &view = *pcoinsTip;
	bool fHaveChain = false;
	for (size_t o = 0; !fHaveChain && o < tx.vout.size(); o++)
	{
		const Coin &existingCoin = view.AccessCoin(COutPoint(hashTx, o));
		fHaveChain = !existingCoin.IsSpent();
	}
	bool fHaveMempool = mempool.exists(hashTx);
	if (!fHaveMempool && !fHaveChain)
	{
		// push to local node and sync with wallets
		CValidationState state;
		bool fMissingInputs;
		if (!AcceptToMemoryPool(mempool, state, tx, false, &fMissingInputs, false, !fOverrideFees, txClass))
		{
			if (state.IsInvalid())
			{
				throw JSONRPCError(
						RPC_TRANSACTION_REJECTED, strprintf("%i: %s", state.GetRejectCode(), state.GetRejectReason()));
			}
			else
			{
				if (fMissingInputs)
				{
					throw JSONRPCError(RPC_TRANSACTION_ERROR, "Missing inputs");
				}
				throw JSONRPCError(RPC_TRANSACTION_ERROR, state.GetRejectReason());
			}
		}
#ifdef ENABLE_WALLET
		else
			SyncWithWallets(tx, NULL, -1);
#endif
	}
	else if (fHaveChain)
	{
		throw JSONRPCError(RPC_TRANSACTION_ALREADY_IN_CHAIN, "transaction already in block chain");
	}
	RelayTransaction(tx);

	return hashTx.GetHex();
}


// Token
set<CTxDestination> GetAccountAddress(const std::string &account)
{
    set<CTxDestination> ret;
    for (const std::pair<CTxDestination, CAddressBookData> &item : pwalletMain->mapAddressBook)
    {
        const CTxDestination &dest = item.first;
        const std::string &strName = item.second.name;
        if (strName == account)
            ret.insert(dest);
    }
    return ret;
}

UniValue GetAccountInfo(const std::string &account)
{
	LOCK2(cs_main, pwalletMain->cs_wallet);
	assert(pwalletMain != NULL);

	UniValue result(UniValue::VOBJ);
    result.push_back(Pair("account", account));

    set<CTxDestination> destinations = GetAccountAddress(account);
    UniValue addresses(UniValue::VARR);
    for (const auto &dest: destinations)
    	addresses.push_back(EncodeDestination(dest));
    result.push_back(Pair("addresses", addresses));

    if (destinations.size() == 0)
    	return result;

	UniValue unspentBCH(UniValue::VARR);
	UniValue unspentToken(UniValue::VARR);
    CAmount nBCHAmount = 0;
    CAmount nTokenBCHAmount = 0;
    std::map<std::string, CAmount> mTokenAmount;

    vector<COutput> vecOutputs;
    pwalletMain->AvailableCoins(vecOutputs, false, NULL, true);
    BOOST_FOREACH (const COutput &out, vecOutputs)
    {
        CTxDestination address;
        if (!ExtractDestination(out.tx->vout[out.i].scriptPubKey, address))
            continue;

        if (!destinations.count(address))
            continue;

        CAmount nValue = out.tx->vout[out.i].nValue;
        const CScript &pk = out.tx->vout[out.i].scriptPubKey;

    	if (pk.IsPayToToken())
    	{
    	    UniValue entry(UniValue::VOBJ);
    	    entry.push_back(Pair("txid", out.tx->GetHash().GetHex()));
    	    entry.push_back(Pair("vout", out.i));

    	    CTxDestination address;
			if (ExtractDestination(out.tx->vout[out.i].scriptPubKey, address))
	        {
	            entry.push_back(Pair("address", EncodeDestination(address)));
	            if (pwalletMain->mapAddressBook.count(address))
	                entry.push_back(Pair("account", pwalletMain->mapAddressBook[address].name));
	        }

    		entry.push_back(Pair("scriptPubKey", HexStr(pk.begin(), pk.end())));
    		entry.push_back(Pair("amount", ValueFromAmount(nValue)));
    		entry.push_back(Pair("spendable", out.fSpendable));
    			
    		int namesize = pk[1];
    		int amountsize = pk[2 + namesize];
    		std::vector<unsigned char> vecName(pk.begin() + 2, pk.begin() + 2 + namesize);
    		std::string tokenName(vecName.begin(), vecName.end());
    		
            // check opcode or scriptnum
            CAmount tokenAmount = 0;
            std::vector<unsigned char> opcode(pk.begin() + 2 + namesize, pk.begin() + 3 + namesize);
            if (0x50 < opcode.at(0) && opcode.at(0) < 0x61)
            {
                tokenAmount = opcode.at(0) - 0x50;
            }
            else
            {
                std::vector<unsigned char> vec(pk.begin() + 3 + namesize, pk.begin() + 3 + namesize + amountsize);
                tokenAmount = CScriptNum(vec, true).getint64();
            }

    		entry.push_back(Pair("token", tokenName));
    		entry.push_back(Pair("tokenAmount", tokenAmount));
    		unspentToken.push_back(entry);
    		mTokenAmount[tokenName] += tokenAmount;
    		nTokenBCHAmount += nValue;
    		continue;
    	}

        UniValue entry(UniValue::VOBJ);
        entry.push_back(Pair("txid", out.tx->GetHash().GetHex()));
        entry.push_back(Pair("vout", out.i));
        if (ExtractDestination(out.tx->vout[out.i].scriptPubKey, address))
        {
            entry.push_back(Pair("address", EncodeDestination(address)));
            if (pwalletMain->mapAddressBook.count(address))
                entry.push_back(Pair("account", pwalletMain->mapAddressBook[address].name));
        }
        entry.push_back(Pair("scriptPubKey", HexStr(pk.begin(), pk.end())));
        if (pk.IsPayToScriptHash())
        {
            CTxDestination address;
            if (ExtractDestination(pk, address))
            {
                const CScriptID &hash = boost::get<CScriptID>(address);
                CScript redeemScript;
                if (pwalletMain->GetCScript(hash, redeemScript))
                    entry.push_back(Pair("redeemScript", HexStr(redeemScript.begin(), redeemScript.end())));
            }
        }
        entry.push_back(Pair("amount", ValueFromAmount(nValue)));
        entry.push_back(Pair("spendable", out.fSpendable));
        unspentBCH.push_back(entry);
        nBCHAmount += nValue;
    }

    result.push_back(Pair("BCH", ValueFromAmount(nBCHAmount)));
    result.push_back(Pair("BCHInToken", ValueFromAmount(nTokenBCHAmount)));

    UniValue tokenlist(UniValue::VARR);
    for (auto &it: mTokenAmount)
    {
    	UniValue u(UniValue::VOBJ);
        u.push_back(Pair("token", it.first));
        u.push_back(Pair("amount", it.second));
        tokenlist.push_back(u);
    }
    result.push_back(Pair("tokenList", tokenlist));
    result.push_back(Pair("unspentBCH", unspentBCH));
    result.push_back(Pair("unspentToken", unspentToken));
    return result;
}

UniValue getaccountinfo(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error("getaccountinfo \"account\" \n");

    RPCTypeCheck(params, boost::assign::list_of(UniValue::VSTR), true);
    if (params[0].isNull()) 
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, arguments must be non-null");

    std::string account = params[0].get_str();
    return GetAccountInfo(account);
}

bool SignTokenTx(CMutableTransaction &rawTx, UniValue &vErrors)
{
    // Fetch previous transactions (inputs):
    CCoinsView viewDummy;
    CCoinsViewCache view(&viewDummy);
    {
        READLOCK(mempool.cs);
        CCoinsViewCache &viewChain = *pcoinsTip;
        CCoinsViewMemPool viewMempool(&viewChain, mempool);
        view.SetBackend(viewMempool); // temporarily switch cache backend to db+mempool view

        BOOST_FOREACH (const CTxIn &txin, rawTx.vin)
        {
            view.AccessCoin(txin.prevout); // Load entries from viewChain into view; can fail.
        }

        view.SetBackend(viewDummy); // switch back to avoid locking mempool for too long
    }

    CBasicKeyStore tempKeystore;

#ifdef ENABLE_WALLET
    if (pwalletMain)
        EnsureWalletIsUnlocked();
#endif

#ifdef ENABLE_WALLET
    const CKeyStore &keystore = (!pwalletMain ? tempKeystore : *pwalletMain);
#else
    const CKeyStore &keystore = tempKeystore;
#endif

    int nHashType = SIGHASH_ALL;
    bool pickedForkId = false;
    if (!pickedForkId) // If the user didn't specify, use the configured default for the hash type
    {
        if (IsUAHFforkActiveOnNextBlock(chainActive.Tip()->nHeight))
        {
            nHashType |= SIGHASH_FORKID;
            pickedForkId = true;
        }
    }

    bool fHashSingle = ((nHashType & ~(SIGHASH_ANYONECANPAY | SIGHASH_FORKID)) == SIGHASH_SINGLE);

    // Use CTransaction for the constant parts of the
    // transaction to avoid rehashing.
    const CTransaction txConst(rawTx);

    // Sign what we can:
    for (unsigned int i = 0; i < rawTx.vin.size(); i++)
    {
        CTxIn &txin = rawTx.vin[i];
        const Coin &coin = view.AccessCoin(txin.prevout);
        if (coin.IsSpent())
        {
            TxInErrorToJSON(txin, vErrors, "Input not found or already spent");
            continue;
        }
        const CScript &prevPubKey = coin.out.scriptPubKey;
        const CAmount &amount = coin.out.nValue;

        // Only sign SIGHASH_SINGLE if there's a corresponding output:
        if (!fHashSingle || (i < rawTx.vout.size()))
            SignSignature(keystore, prevPubKey, rawTx, i, amount, nHashType);

        // ... and merge in other signatures:
        if (pickedForkId)
        {
            txin.scriptSig = CombineSignatures(prevPubKey,
                TransactionSignatureChecker(&txConst, i, amount, SCRIPT_ENABLE_SIGHASH_FORKID), txin.scriptSig, rawTx.vin[i].scriptSig);
            ScriptError serror = SCRIPT_ERR_OK;

            if (!VerifyScript(txin.scriptSig, prevPubKey, STANDARD_SCRIPT_VERIFY_FLAGS | SCRIPT_ENABLE_SIGHASH_FORKID,
                    MutableTransactionSignatureChecker(&rawTx, i, amount, SCRIPT_ENABLE_SIGHASH_FORKID), &serror))
            {
                TxInErrorToJSON(txin, vErrors, ScriptErrorString(serror));
            }
        }
        else
        {
            txin.scriptSig = CombineSignatures(prevPubKey, TransactionSignatureChecker(&txConst, i, amount, 0),
                        txin.scriptSig, rawTx.vin[i].scriptSig);
            ScriptError serror = SCRIPT_ERR_OK;

            if (!VerifyScript(txin.scriptSig, prevPubKey, STANDARD_SCRIPT_VERIFY_FLAGS,
                        MutableTransactionSignatureChecker(&rawTx, i, amount, 0), &serror))
            {
                TxInErrorToJSON(txin, vErrors, ScriptErrorString(serror));
            }
        }
    }

    return vErrors.empty();
}

void SendTokenTx(const CMutableTransaction &rawTx)
{
	uint256 hashTx = rawTx.GetHash();
    bool fOverrideFees = false;
    TransactionClass txClass = TransactionClass::DEFAULT;

    bool fHaveChain = false;
    bool fHaveMempool = mempool.exists(hashTx);
    if (!fHaveMempool && !fHaveChain)
    {
        // push to local node and sync with wallets
        CValidationState state;
        bool fMissingInputs;
        if (!AcceptToMemoryPool(mempool, state, rawTx, false, &fMissingInputs, false, !fOverrideFees, txClass))
        {
            if (state.IsInvalid())
            {
                throw JSONRPCError(
                        RPC_TRANSACTION_REJECTED, strprintf("%i: %s", state.GetRejectCode(), state.GetRejectReason()));
            }
            else
            {
                if (fMissingInputs)
                {
                    throw JSONRPCError(RPC_TRANSACTION_ERROR, "Missing inputs");
                }
                throw JSONRPCError(RPC_TRANSACTION_ERROR, state.GetRejectReason());
            }
        }
#ifdef ENABLE_WALLET
        else
            SyncWithWallets(rawTx, NULL, -1);
#endif
    }

    RelayTransaction(rawTx);
}

opcodetype GetOpcode(const CAmount n)
{
	opcodetype ret = OP_1;
	switch (n)
	{
		case 1:
			ret = OP_1;
			break;
		case 2:
			ret = OP_2;
			break;
		case 3:
			ret = OP_3;
			break;
		case 4:
			ret = OP_4;
			break;
		case 5:
			ret = OP_5;
			break;
		case 6:
			ret = OP_6;	
			break;
		case 7:
			ret = OP_7;
			break;
		case 8:
			ret = OP_8;
			break;
		case 9:
			ret = OP_9;
			break;
		case 10:
			ret = OP_10;
			break;
		case 11:
			ret = OP_11;
			break;
		case 12:
			ret = OP_12;
			break;
		case 13:
			ret = OP_13;
			break;
		case 14:
			ret = OP_14;
			break;	
		case 15:
			ret = OP_15;
			break;
		case 16:
			ret = OP_16;
			break;
	    default:
	    	break;
	}
	return ret;
} 

UniValue tokenmint(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() != 3)
        throw runtime_error(
            "tokenmint \"account\" \"token\" \"supply\"\n"
            "\nIssue a new token, token id is one of your UTXO's txid.\n"
            "The total amount of token must be less than 10**18.\n"
            "You need at least 0.1001BCH to issue token.\n"
            "Returns hex-encoded raw transaction.\n"

            "\nArguments:\n"
            "1. \"account\":   (string, required) token issuer\n"
            "2. \"token\":     (string, required) token name\n"
            "3. \"supply\":    (string, required) token supply\n"

            "\nResult:\n"
		    "\"txid\"          (string) The transaction hash in hex\n");

#ifdef ENABLE_WALLET
    LOCK2(cs_main, pwalletMain ? &pwalletMain->cs_wallet : NULL);
#else
    LOCK(cs_main);
#endif

    RPCTypeCheck(params, boost::assign::list_of(UniValue::VSTR)(UniValue::VSTR)(UniValue::VSTR), true);
    for (unsigned int i = 0; i < params.size(); ++i)
    	if (params[i].isNull()) 
        	throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, arguments must be non-null");

    std::string account = params[0].get_str();
    std::string tokenname = params[1].get_str();

    // check supply is valid
    std::string supply = params[2].get_str();
    CAmount nSupply = atoll(supply.c_str());
    if (nSupply <= 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, supply must be positive");
    if (nSupply > MAX_TOKEN_SUPPLY)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, supply is out of range, max supply is 10**18");

    // default fee
    CAmount defaultSupplyAmount = 0.01 * COIN;
    CAmount defaultSupplyFee = 0.0001 * COIN;
    UniValue result(UniValue::VOBJ);

    // get account info
    UniValue accountInfo = GetAccountInfo(account);
    UniValue addresses = accountInfo["addresses"].get_array();
    if (addresses.size() == 0)
    {
    	// account is not exist, return error
    	result.push_back(Pair("error", 1));
    	return result;
    }

    // create tx vin
    CMutableTransaction rawTx;
    uint32_t nSequence = std::numeric_limits<uint32_t>::max();

    UniValue utxoBCH = accountInfo["unspentBCH"].get_array();
    CAmount nVinAmount = 0;
    for (size_t i = 0; i < utxoBCH.size(); ++i)
    {
    	UniValue utxo = utxoBCH[i];
    	CAmount tmp = AmountFromValue(utxo["amount"]);
    	uint256 txid;
		txid.SetHex(utxo["txid"].get_str());
    	CTxIn in(COutPoint(txid, utxo["vout"].get_int()), CScript(), nSequence);
        rawTx.vin.push_back(in); 

        nVinAmount += tmp;
        if (nVinAmount >= (defaultSupplyAmount + defaultSupplyFee))
            break; 
    }

    // check BCH balance is enough
    if (nVinAmount < (defaultSupplyAmount + defaultSupplyFee))
    {
    	// BCH balance is not enough, return error
    	result.push_back(Pair("error", 1));
    	return result;
    }

    // build token script
    CTxDestination destination = DecodeDestination(addresses[0].get_str());
	CScript scriptPubKey = GetScriptForDestination(destination);

	CScript script;
    if (nSupply < 17) 
    	script = CScript() << OP_TOKEN << ToByteVector(tokenname) << GetOpcode(nSupply);
    else 
    	script = CScript() << OP_TOKEN << ToByteVector(tokenname) << CScriptNum(nSupply);

    script << OP_DROP << OP_DROP;
    script += scriptPubKey;

    CScriptID innerID(script);
    std::string address = EncodeDestination(innerID);
    result.push_back(Pair("account", account));
    result.push_back(Pair("token", tokenname));
    result.push_back(Pair("address", address));
    // result.push_back(Pair("script", HexStr(script.begin(), script.end())));

    pwalletMain->AddCScript(script);
    pwalletMain->SetAddressBook(innerID, "", account);

    // token vout
    CTxOut supplyOut(defaultSupplyAmount, script);
    rawTx.vout.push_back(supplyOut);

    // charge vout
    CAmount chargeAmount = nVinAmount - defaultSupplyAmount - defaultSupplyFee;
    if (chargeAmount) 
    {
	    CTxOut chargeOut(chargeAmount, scriptPubKey);
	    rawTx.vout.push_back(chargeOut);
	}

    UniValue vErrors(UniValue::VARR);
    // sign tx
    if (!SignTokenTx(rawTx, vErrors))
    {
        result.push_back(Pair("error", vErrors));
        return result;
    }

    // send tx
    SendTokenTx(rawTx);
   
    result.push_back(Pair("txid", rawTx.GetHash().ToString()));
    result.push_back(Pair("fee", "0.0001"));
    // result.push_back(Pair("hex", EncodeHexTx(rawTx)));
    return result;
}


UniValue tokentransfer(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() != 3)
        throw runtime_error(
            "tokentransfer \"token\" \"account\" [{\"address\":\"xxxx\", \"amount\":\"1111\"},...] \n"
            "\nCreate a transaction to transfer token.\n"
            "Returns hex-encoded raw transaction.\n"

            "\nArguments:\n"
            "1. \"token\":        (string, required) token name\n"
            "2. \"account\":      (string, required) sender account\n"
            "3. \"receivers\":    (string, required) A json array of receivers\n"
            "     [\n"
            "       {\n"
            "         \"address\":\"xxxx\",  (string, required) reveiver address\n"
            "         \"amount\":n           (numeric, required) token amount\n"
            "       }\n"
            "       ,...\n"
            "     ]\n"

            "\nResult:\n"
		    "\"txid\"             (string) The transaction hash in hex\n");

#ifdef ENABLE_WALLET
    LOCK2(cs_main, pwalletMain ? &pwalletMain->cs_wallet : NULL);
#else
    LOCK(cs_main);
#endif

    RPCTypeCheck(params, boost::assign::list_of(UniValue::VSTR)(UniValue::VSTR)(UniValue::VARR), true);
    for (unsigned int i = 0; i < params.size(); ++i)
    	if (params[i].isNull()) 
        	throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, arguments must be non-null");

    std::string token = params[0].get_str();
    std::string account = params[1].get_str();
    UniValue receivers = params[2].get_array();
    UniValue result(UniValue::VOBJ);

    // get account info 
    UniValue accountInfo = GetAccountInfo(account);
    UniValue addresses = accountInfo["addresses"].get_array();
    if (addresses.size() == 0)
    {
    	// account is not exist, return error
    	result.push_back(Pair("error", 2));
    	return result;
    }

    CAmount defaultTransferFee = 0.01 * COIN;
    CAmount defaultSupplyFee = 0.0001 * COIN;
    CAmount nVinToken = 0;
    CAmount nVoutToken = 0;
    CAmount nVinBCH = 0;
    CAmount nVoutBCH = defaultSupplyFee + defaultTransferFee * receivers.size();

    // calculate vout token amount  
    for (unsigned int idx = 0; idx < receivers.size(); ++idx)
    {
    	const UniValue &obj = receivers[idx].get_obj();
    	std::string address = obj["address"].get_str();
        CTxDestination destination = DecodeDestination(address);
        if (!IsValidDestination(destination))
        {
        	// address is invalid, return error
        	result.push_back(Pair("error", 3));
        	return result;
        }
    	CAmount n = atoll(obj["amount"].get_str().c_str());
    	if (n < 1)
        {
        	// amount < 1, return error
        	result.push_back(Pair("error", 3));
        	return result;
        }    		
    	nVoutToken += n;
	}

	// create tx
    CMutableTransaction rawTx;
    uint32_t nSequence = std::numeric_limits<uint32_t>::max();

   	// search enough token vin
    UniValue utxoToken = accountInfo["unspentToken"].get_array();
    for (size_t i = 0; i < utxoToken.size(); ++i)
    {
    	UniValue u = utxoToken[i];
    	if (u["token"].get_str() != token)
    		continue;

    	uint256 txid;
		txid.SetHex(u["txid"].get_str());
    	CTxIn in(COutPoint(txid, u["vout"].get_int()), CScript(), nSequence);
        rawTx.vin.push_back(in); 
        nVinToken += u["tokenAmount"].get_int64();
        if (nVinToken >= nVoutToken)
            break; 
    }

    if (nVinToken < nVoutToken)
	{
    	// token balance is not enough, return error
    	result.push_back(Pair("error", 2));
    	return result;
    }

    // if has token charge, raise BCH fee 
    if (nVinToken > nVoutToken)
    	nVoutBCH += defaultTransferFee;

    nVinBCH = rawTx.vin.size() * defaultTransferFee;

    // search BCH vin to pay fee
    UniValue utxoBCH = accountInfo["unspentBCH"].get_array();
    for (size_t i = 0; i < utxoBCH.size(); ++i)
    {
    	UniValue u = utxoBCH[i];
    	uint256 txid;
		txid.SetHex(u["txid"].get_str());
    	CTxIn in(COutPoint(txid, u["vout"].get_int()), CScript(), nSequence);
        rawTx.vin.push_back(in); 

        nVinBCH += AmountFromValue(u["amount"]);
        if (nVinBCH >= nVoutBCH)
            break; 
    }

    if (nVinBCH < nVoutBCH)
	{
    	// BCH balance is not enough, return error
    	result.push_back(Pair("error", 1));
    	return result;
    }

    // create token vout
    for (unsigned int idx = 0; idx < receivers.size(); idx++)
    {
        const UniValue &output = receivers[idx];
        std::string address = output["address"].get_str();
    	CAmount n = atoll(output["amount"].get_str().c_str());
        CTxDestination destination = DecodeDestination(address);

		CScript scriptPubKey;
        if (n < 17) 
        	scriptPubKey = CScript() << OP_TOKEN << ToByteVector(token) << GetOpcode(n) << OP_DROP << OP_DROP;
        else 
        	scriptPubKey = CScript() << OP_TOKEN << ToByteVector(token) << CScriptNum(n) << OP_DROP << OP_DROP;
        
        // CScript scriptPubKey = CScript() << OP_TOKEN << ToByteVector(token) << CScriptNum(n) << OP_DROP << OP_DROP;
        scriptPubKey += GetScriptForDestination(destination);
        CTxOut out(defaultTransferFee, scriptPubKey);
        rawTx.vout.push_back(out);	
    }

    CTxDestination chargeDest = DecodeDestination(addresses[0].get_str());

    // token charge
    if (nVinToken > nVoutToken)
    {
    	CAmount n = nVinToken - nVoutToken;
        CScript chargePubKey;
        if (n < 17) 
        	chargePubKey = CScript() << OP_TOKEN << ToByteVector(token) << GetOpcode(n) << OP_DROP << OP_DROP;
        else 
        	chargePubKey = CScript() << OP_TOKEN << ToByteVector(token) << CScriptNum(n) << OP_DROP << OP_DROP;

        // CScript chargePubKey = CScript() << OP_TOKEN << ToByteVector(token) << CScriptNum(nVinToken - nVoutToken) << OP_DROP << OP_DROP;
        chargePubKey += GetScriptForDestination(chargeDest);
        CTxOut out(defaultTransferFee, chargePubKey);
        rawTx.vout.push_back(out);	  	
    }

    // BCH charge
    if (nVinBCH > nVoutBCH)
	{
        CScript chargePubKey = GetScriptForDestination(chargeDest);
        CTxOut out(nVinBCH - nVoutBCH, chargePubKey);
        rawTx.vout.push_back(out);	
	}

    UniValue vErrors(UniValue::VARR);
    // sign tx
    if (!SignTokenTx(rawTx, vErrors))
    {
        result.push_back(Pair("error", vErrors));
        result.push_back(Pair("hex", EncodeHexTx(rawTx)));
        return result;
    }

    // send tx
    SendTokenTx(rawTx);
   
    result.push_back(Pair("txid", rawTx.GetHash().ToString()));
    result.push_back(Pair("fee", "0.0001"));
    // result.push_back(Pair("hex", EncodeHexTx(rawTx)));
    return result;
}

UniValue tokenlist(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "tokenlist \n"
            "\nList the information about all the issued token.\n"
            "Returns token list.\n");

	UniValue result(UniValue::VARR);
	std::set<std::string> sToken;
    int height = chainActive.Height();
    CBlockIndex *pblockindex = NULL;

    for (int i = 100; i <= height; ++i)
    {
        pblockindex = chainActive[i];
        CBlock block;
        if (ReadBlockFromDisk(block, pblockindex, Params().GetConsensus()))
        {
            for (const auto &tx: block.vtx)
            {
                if (tx->IsCoinBase())
                	continue;

                for (const auto &out: tx->vout)
                {
                	const CScript &pk = out.scriptPubKey;
			    	if (pk.IsPayToToken())
			    	{
			    		int namesize = pk[1];
			    		int amountsize = pk[2 + namesize];
			    		std::vector<unsigned char> vecName(pk.begin() + 2, pk.begin() + 2 + namesize);
			    		std::string tokenName(vecName.begin(), vecName.end());

			    		// check opcode or scriptnum
			            CAmount tokenAmount = 0;
			            std::vector<unsigned char> opcode(pk.begin() + 2 + namesize, pk.begin() + 3 + namesize);
			            if (0x50 < opcode.at(0) && opcode.at(0) < 0x61)
			            {
			                tokenAmount = opcode.at(0) - 0x50;
			            }
			            else
			            {
			                std::vector<unsigned char> vec(pk.begin() + 3 + namesize, pk.begin() + 3 + namesize + amountsize);
			                tokenAmount = CScriptNum(vec, true).getint64();
			            }

			    		if (sToken.count(tokenName))
			    			continue;
			    		else 
			    			sToken.insert(tokenName);
			    		
			    	    UniValue entry(UniValue::VOBJ);
			    	    entry.push_back(Pair("txid", tx->GetHash().GetHex()));
			    	    CTxDestination address;
						if (ExtractDestination(pk, address))
				        {
				            entry.push_back(Pair("address", EncodeDestination(address)));
				            if (pwalletMain->mapAddressBook.count(address))
				                entry.push_back(Pair("account", pwalletMain->mapAddressBook[address].name));
				        }
			    		entry.push_back(Pair("token", tokenName));
					    entry.push_back(Pair("supply", tokenAmount));
					    result.push_back(entry);
			    	}
                }

            }
        }
    }

    return result;
}

UniValue tokensearch(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() != 2)
        throw runtime_error(
            "tokensearch \"account\" \"token\" \n"
            "\nSearch token by account or token name.\n"
            "Returns token information.\n");

    RPCTypeCheck(params, boost::assign::list_of(UniValue::VSTR)(UniValue::VSTR)(UniValue::VSTR), true);
    std::string account = params[0].get_str();
    std::string token = params[1].get_str();
    if (account.empty() && token.empty()) 
    	throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, arguments only one can be null");

	UniValue result(UniValue::VARR);

    for (auto it: pwalletMain->mapWallet)
    {
    	const CWalletTx &wtx = it.second;
    	if (wtx.IsCoinBase())
    		continue;

    	for (const auto &out: wtx.vout)
    	{
        	const CScript &pk = out.scriptPubKey;
	    	if (pk.IsPayToToken())
	    	{
	    		int namesize = pk[1];
	    		int amountsize = pk[2 + namesize];
	    		std::vector<unsigned char> vecName(pk.begin() + 2, pk.begin() + 2 + namesize);
	    		std::string tokenName(vecName.begin(), vecName.end());

	    	    // check opcode or scriptnum
	            CAmount tokenAmount = 0;
	            std::vector<unsigned char> opcode(pk.begin() + 2 + namesize, pk.begin() + 3 + namesize);
	            if (0x50 < opcode.at(0) && opcode.at(0) < 0x61)
	            {
	                tokenAmount = opcode.at(0) - 0x50;
	            }
	            else
	            {
	                std::vector<unsigned char> vec(pk.begin() + 3 + namesize, pk.begin() + 3 + namesize + amountsize);
	                tokenAmount = CScriptNum(vec, true).getint64();
	            }

				CTxDestination address;
				std::string issuer = "";
				if (ExtractDestination(pk, address))
		        {     
		            if (pwalletMain->mapAddressBook.count(address))
		            	issuer = pwalletMain->mapAddressBook[address].name;
		        }	    		

	    		if (!token.empty())
	    		{
	    			if (token == tokenName && (account.empty() || account == issuer))
	    			{
			    	    UniValue entry(UniValue::VOBJ);
			    	    // entry.push_back(Pair("txid", it.first.ToString()));
			    	    entry.push_back(Pair("account", issuer));
			    		entry.push_back(Pair("token", tokenName));
					    entry.push_back(Pair("supply", tokenAmount));
					    // entry.push_back(Pair("address", EncodeDestination(address)));	
					    result.push_back(entry);
					    return result;
	    			}
	    		}
	    		else if (!account.empty() && account == issuer)
	    		{
    				UniValue entry(UniValue::VOBJ);
		    	    // entry.push_back(Pair("txid", it.first.ToString()));
		    	    entry.push_back(Pair("account", issuer));
		    		entry.push_back(Pair("token", tokenName));
				    entry.push_back(Pair("supply", tokenAmount));
				    // entry.push_back(Pair("address", EncodeDestination(address)));
				    result.push_back(entry);
				    return result;
	    		}
	    	}
    	}
    }
    return result;
}

UniValue GetTokenAddress(const std::string &account, const std::string &token)
{
	LOCK2(cs_main, pwalletMain->cs_wallet);
	assert(pwalletMain != NULL);

	UniValue result(UniValue::VARR);

    set<CTxDestination> destinations = GetAccountAddress(account);
    if (destinations.size() == 0)
    	return result;

    vector<COutput> vecOutputs;
    pwalletMain->AvailableCoins(vecOutputs, false, NULL, true);
    BOOST_FOREACH (const COutput &out, vecOutputs)
    {
        CTxDestination address;
        if (!ExtractDestination(out.tx->vout[out.i].scriptPubKey, address))
            continue;

        if (!destinations.count(address))
            continue;

        const CScript &pk = out.tx->vout[out.i].scriptPubKey;
    	if (pk.IsPayToToken())
    	{
    		int namesize = pk[1];
    		int amountsize = pk[2 + namesize];
    		std::vector<unsigned char> vecName(pk.begin() + 2, pk.begin() + 2 + namesize);
    		std::string tokenName(vecName.begin(), vecName.end());

    	    // check opcode or scriptnum
            CAmount tokenAmount = 0;
            std::vector<unsigned char> opcode(pk.begin() + 2 + namesize, pk.begin() + 3 + namesize);
            if (0x50 < opcode.at(0) && opcode.at(0) < 0x61)
            {
                tokenAmount = opcode.at(0) - 0x50;
            }
            else
            {
                std::vector<unsigned char> vec(pk.begin() + 3 + namesize, pk.begin() + 3 + namesize + amountsize);
                tokenAmount = CScriptNum(vec, true).getint64();
            }   		
    	
    		if (tokenName != token)
    			continue;

    	    UniValue entry(UniValue::VOBJ);
    	    CTxDestination address;
			if (ExtractDestination(out.tx->vout[out.i].scriptPubKey, address))
	        {
	            entry.push_back(Pair("address", EncodeDestination(address)));
	        }		
    		entry.push_back(Pair("token", tokenName));
    		entry.push_back(Pair("amount", tokenAmount));
    		result.push_back(entry);
    	}
    }
    return result;
}

UniValue tokenaddress(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() != 2)
        throw runtime_error(
            "tokenaddress \"account\" \"token\"\n"
            "\nList the addresses that contains token.\n"
            "Returns address list.\n");

    RPCTypeCheck(params, boost::assign::list_of(UniValue::VSTR)(UniValue::VSTR), true);
    if (params[0].isNull() || params[1].isNull()) 
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameters, arguments must be non-null");

    std::string account = params[0].get_str();
    std::string token = params[1].get_str();
    return GetTokenAddress(account, token);
}

void ListTokenTransactions(const CWalletTx &wtx,
    const string &strAccount,
    UniValue &ret,
    const isminefilter &filter)
{
    CAmount nFee;
    string strSentAccount;
    list<COutputEntry> listReceived;
    list<COutputEntry> listSent;

    wtx.GetAmounts(listReceived, listSent, nFee, strSentAccount, filter);

    bool fAllAccounts = (strAccount == string("*"));
    bool involvesWatchonly = wtx.IsFromMe(ISMINE_WATCH_ONLY);

    // Sent
    if ((!listSent.empty() || nFee != 0) && (fAllAccounts || strAccount == strSentAccount))
    {
        BOOST_FOREACH (const COutputEntry &s, listSent)
        {
            UniValue entry(UniValue::VOBJ);
            if (involvesWatchonly || (::IsMine(*pwalletMain, s.destination, chainActive.Tip()) & ISMINE_WATCH_ONLY))
                entry.push_back(Pair("involvesWatchonly", true));
            if (IsValidDestination(s.destination))
		        entry.push_back(Pair("address", EncodeDestination(s.destination)));

            entry.push_back(Pair("category", "send"));
            entry.push_back(Pair("amount", ValueFromAmount(-s.amount)));
            if (pwalletMain->mapAddressBook.count(s.destination))
                entry.push_back(Pair("account", pwalletMain->mapAddressBook[s.destination].name));
            entry.push_back(Pair("vout", s.vout));
            ret.push_back(entry);
        }
    }

    // Received
    if (listReceived.size() > 0 && wtx.GetDepthInMainChain() >= 0)
    {
        BOOST_FOREACH (const COutputEntry &r, listReceived)
        {
            string account;
            if (pwalletMain->mapAddressBook.count(r.destination))
                account = pwalletMain->mapAddressBook[r.destination].name;
            if (fAllAccounts || (account == strAccount))
            {
                UniValue entry(UniValue::VOBJ);
                if (involvesWatchonly || (::IsMine(*pwalletMain, r.destination, chainActive.Tip()) & ISMINE_WATCH_ONLY))
                    entry.push_back(Pair("involvesWatchonly", true));
            	if (IsValidDestination(r.destination))
		        	entry.push_back(Pair("address", EncodeDestination(r.destination)));

                entry.push_back(Pair("category", "receive"));
                entry.push_back(Pair("amount", ValueFromAmount(r.amount)));
                if (pwalletMain->mapAddressBook.count(r.destination))
                    entry.push_back(Pair("account", account));
                entry.push_back(Pair("vout", r.vout));
                ret.push_back(entry);
            }
        }
    }
}

UniValue tokenhistory(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() != 4)
        throw runtime_error(
            "tokenhistory \"account\" \"token\" \"index\" \"limit\" \n"
            "\nList the token transaction history.\n"
            "Returns token transaction list.\n");

    RPCTypeCheck(params, boost::assign::list_of(UniValue::VSTR)(UniValue::VSTR)(UniValue::VNUM)(UniValue::VNUM), true);
    for (size_t i = 0; i < params.size(); ++i)
    	if (params[i].isNull()) 
        	throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, arguments must be non-null");

    std::string account = params[0].get_str();
    std::string token = params[1].get_str();
    int index = params[2].get_int();
    int limit = params[3].get_int();

    UniValue result(UniValue::VARR);
    if (index < 0 || limit < 0)
    	return result;
    
    if (limit == 0)
    	return result;

    unsigned int end = index + limit - 1;

    for (auto it: pwalletMain->mapWallet)
    {
    	const CWalletTx &wtx = it.second;
    	if (wtx.IsCoinBase())
    		continue;

	    for (const auto &out: wtx.vout)
	    {
	    	const CScript &pk = out.scriptPubKey;
	    	if (pk.IsPayToToken())
	    	{
	    		int namesize = pk[1];
	    		int amountsize = pk[2 + namesize];
	    		std::vector<unsigned char> vecName(pk.begin() + 2, pk.begin() + 2 + namesize);
	    		std::string tokenName(vecName.begin(), vecName.end());

	    		// check opcode or scriptnum
	            CAmount tokenAmount = 0;
	            std::vector<unsigned char> opcode(pk.begin() + 2 + namesize, pk.begin() + 3 + namesize);
	            if (0x50 < opcode.at(0) && opcode.at(0) < 0x61)
	            {
	                tokenAmount = opcode.at(0) - 0x50;
	            }
	            else
	            {
	                std::vector<unsigned char> vec(pk.begin() + 3 + namesize, pk.begin() + 3 + namesize + amountsize);
	                tokenAmount = CScriptNum(vec, true).getint64();
	            }   		

	    		if (tokenName != token)
	    			continue;
				
				CTxDestination address;
				std::string receiver = "";
				if (ExtractDestination(pk, address))
		        {     
		            if (pwalletMain->mapAddressBook.count(address))
		            	receiver = pwalletMain->mapAddressBook[address].name;
		        }

		        if (account != receiver)
		        	continue;

				UniValue entry(UniValue::VOBJ);
				entry.push_back(Pair("txid", it.first.ToString()));
		        entry.push_back(Pair("address", EncodeDestination(address)));
		        entry.push_back(Pair("amount", tokenAmount));
		        entry.push_back(Pair("category", "receive"));
		        entry.push_back(Pair("timestamp", wtx.GetTxTime()));
		        result.push_back(entry);

		        if (result.size() > end)
		        {
		        	UniValue ret(UniValue::VARR);
		        	for (size_t i = index; i < end + 1; ++i)
		        		ret.push_back(result[i]);
		        	return ret;
		        }
	    	} 	
	    }

	    for (const auto &in: wtx.vin)
	    {
	    	const CWalletTx &wtx = pwalletMain->mapWallet[in.prevout.hash];
	    	CScript pk = wtx.vout[in.prevout.n].scriptPubKey;
	    	if (pk.IsPayToToken())
	    	{
	    		int namesize = pk[1];
	    		int amountsize = pk[2 + namesize];
	    		std::vector<unsigned char> vecName(pk.begin() + 2, pk.begin() + 2 + namesize);
	    		std::string tokenName(vecName.begin(), vecName.end());

	    		// check opcode or scriptnum
	            CAmount tokenAmount = 0;
	            std::vector<unsigned char> opcode(pk.begin() + 2 + namesize, pk.begin() + 3 + namesize);
	            if (0x50 < opcode.at(0) && opcode.at(0) < 0x61)
	            {
	                tokenAmount = opcode.at(0) - 0x50;
	            }
	            else
	            {
	                std::vector<unsigned char> vec(pk.begin() + 3 + namesize, pk.begin() + 3 + namesize + amountsize);
	                tokenAmount = CScriptNum(vec, true).getint64();
	            }  
				
	    		if (tokenName != token)
	    			continue;
				
				CTxDestination address;
				std::string receiver = "";
				if (ExtractDestination(pk, address))
		        {     
		            if (pwalletMain->mapAddressBook.count(address))
		            	receiver = pwalletMain->mapAddressBook[address].name;
		        }

		        if (account != receiver)
		        	continue;

				UniValue entry(UniValue::VOBJ);
		        entry.push_back(Pair("txid", it.first.ToString()));
		        entry.push_back(Pair("address", EncodeDestination(address)));
		        entry.push_back(Pair("amount", tokenAmount));
		        entry.push_back(Pair("category", "send"));
		        entry.push_back(Pair("timestamp", wtx.GetTxTime()));
		        result.push_back(entry);
		        if (result.size() > end)
		        {
		        	UniValue ret(UniValue::VARR);
		        	for (size_t i = index; i < end + 1; ++i)
		        		ret.push_back(result[i]);
		        	return ret;
		        }
	    	} 	
	    }
    }
    
    UniValue ret(UniValue::VARR);
    if (result.size() < (unsigned int)(index + 1))
    	return ret;

	for (size_t i = index; i < result.size(); ++i)
		ret.push_back(result[i]);
	return ret;
}

UniValue tokendetail(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "tokendetail \"txid\" \n"
            "\nReturns the transaction details\n");

    RPCTypeCheck(params, boost::assign::list_of(UniValue::VSTR), true);
	if (params[0].isNull()) 
    	throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, arguments must be non-null");

    LOCK2(cs_main, pwalletMain->cs_wallet);
    std::string txid = params[0].get_str();
    uint256 hash;
    hash.SetHex(txid);
	isminefilter filter = ISMINE_SPENDABLE;

    UniValue result(UniValue::VOBJ);
    if (!pwalletMain->mapWallet.count(hash))
        return result;

    const CWalletTx &wtx = pwalletMain->mapWallet[hash];
    result.push_back(Pair("txid", txid));

    int confirms = wtx.GetDepthInMainChain();
    int height = chainActive.Height() + 1 - confirms;
    result.push_back(Pair("height", height));

    CAmount nDebit = wtx.GetDebit(filter);
    CAmount nFee = wtx.GetValueOut() > nDebit ? wtx.GetValueOut() - nDebit : nDebit - wtx.GetValueOut();
    result.push_back(Pair("fee", ValueFromAmount(nFee)));
    result.push_back(Pair("time", wtx.GetTxTime()));

    UniValue details(UniValue::VARR);
    std::string token = "";
    CAmount nTokenAmount = 0;
    for (const auto &out: wtx.vout)
    {
    	const CScript &pk = out.scriptPubKey;
    	if (pk.IsPayToToken())
    	{
    		int namesize = pk[1];
    		int amountsize = pk[2 + namesize];
    		std::vector<unsigned char> vecName(pk.begin() + 2, pk.begin() + 2 + namesize);
    		std::string name(vecName.begin(), vecName.end());
			
    		// check opcode or scriptnum
            CAmount amount = 0;
            std::vector<unsigned char> opcode(pk.begin() + 2 + namesize, pk.begin() + 3 + namesize);
            if (0x50 < opcode.at(0) && opcode.at(0) < 0x61)
            {
                amount = opcode.at(0) - 0x50;
            }
            else
            {
                std::vector<unsigned char> vec(pk.begin() + 3 + namesize, pk.begin() + 3 + namesize + amountsize);
                amount = CScriptNum(vec, true).getint64();
            }  

			UniValue entry(UniValue::VOBJ);
			CTxDestination address;
			if (ExtractDestination(pk, address))
	        {     
	            if (pwalletMain->mapAddressBook.count(address))
	            	entry.push_back(Pair("account", pwalletMain->mapAddressBook[address].name));
	            
	            entry.push_back(Pair("address", EncodeDestination(address)));
	        }
	        entry.push_back(Pair("amount", amount));
	        entry.push_back(Pair("category", "receive"));
	        details.push_back(entry);

    		if (token.empty())
    			token = name;
    		nTokenAmount += amount;
    	} 	
    }

    for (const auto &in: wtx.vin)
    {
    	const CWalletTx &wtx = pwalletMain->mapWallet[in.prevout.hash];
    	CScript pk = wtx.vout[in.prevout.n].scriptPubKey;
    	if (pk.IsPayToToken())
    	{
    		int namesize = pk[1];
    		int amountsize = pk[2 + namesize];

    		// check opcode or scriptnum
            CAmount amount = 0;
            std::vector<unsigned char> opcode(pk.begin() + 2 + namesize, pk.begin() + 3 + namesize);
            if (0x50 < opcode.at(0) && opcode.at(0) < 0x61)
            {
                amount = opcode.at(0) - 0x50;
            }
            else
            {
                std::vector<unsigned char> vec(pk.begin() + 3 + namesize, pk.begin() + 3 + namesize + amountsize);
                amount = CScriptNum(vec, true).getint64();
            }  
			
			UniValue entry(UniValue::VOBJ);
			CTxDestination address;
			if (ExtractDestination(pk, address))
	        {     
	            if (pwalletMain->mapAddressBook.count(address))
	            	entry.push_back(Pair("account", pwalletMain->mapAddressBook[address].name));
	            
	            entry.push_back(Pair("address", EncodeDestination(address)));
	        }
	        entry.push_back(Pair("amount", amount));
	        entry.push_back(Pair("category", "send"));
	        details.push_back(entry);
    	} 	
    }

    result.push_back(Pair("token", token));
    result.push_back(Pair("amount", nTokenAmount));
    result.push_back(Pair("details", details));

    return result;
}


UniValue tokenissue(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "tokenissue \"supply\" \n"
            "\nIssue a new token, token id is one of your UTXO's txid.\n"
            "The total amount of token must be less than 10**18.\n"
            "You need at least 0.0101BCH to issue token.\n"
            "Returns hex-encoded raw transaction.\n"

            "\nArguments:\n"
            "1. \"supply\":    (string, required) token supply\n"
            "\nResult:\n"
            "\"transaction\"   (string) hex string of the transaction\n");

#ifdef ENABLE_WALLET
    LOCK2(cs_main, pwalletMain ? &pwalletMain->cs_wallet : NULL);
#else
    LOCK(cs_main);
#endif

    RPCTypeCheck(params, boost::assign::list_of(UniValue::VSTR), true);
    if (params[0].isNull())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, arguments must be non-null");

    // check supply is valid
    std::string supply = params[0].get_str();
    CAmount nSupply = atoll(supply.c_str());
    if (nSupply <= 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, supply must be positive");
    if (nSupply > MAX_TOKEN_SUPPLY)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, supply is out of range, max supply is 10**18");

    // calaulate enough utxo
    CAmount defaultSupplyAmount = 0.01 * COIN;
    CAmount defaultSupplyFee = 0.0001 * COIN;

    std::vector<COutput> utxo;
    CAmount utxoAmount = 0;

    UniValue results(UniValue::VARR);
    std::vector<COutput> vecOutputs;
    pwalletMain->AvailableCoins(vecOutputs, false, NULL, true);
    BOOST_FOREACH (const COutput &out, vecOutputs)
    {
        const CScript &pk = out.tx->vout[out.i].scriptPubKey;
        if (pk.IsPayToScriptHash())
        {
            std::vector<unsigned char> vec(pk.begin() + 2, pk.begin() + 22);
            CScriptID hash = CScriptID(uint160(vec));
            CScript redeemScript;
            if (pwalletMain->GetCScript(hash, redeemScript))
            {
                if (redeemScript.IsPayToToken())
                    continue;
            }
        }
        else if (pk.IsPayToToken()) 
        {
            continue;
        }

        CAmount nValue = out.tx->vout[out.i].nValue;
        utxoAmount += nValue;
        if (utxoAmount > (defaultSupplyAmount + defaultSupplyFee))
        {
            utxo.push_back(out);
            break;
        }  
    }

    // check balance is enough
    if (utxoAmount < (defaultSupplyAmount + defaultSupplyFee))
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "balance is not enough for token issue, at least 0.0101BCH");

    // create tx
    CMutableTransaction rawTx;
    uint32_t nSequence = std::numeric_limits<uint32_t>::max();
    for (COutput out: utxo)
    {
        CTxIn in(COutPoint(out.tx->GetHash(), out.i), CScript(), nSequence);
        rawTx.vin.push_back(in);      
    }

    CPubKey newKey;
    if (!pwalletMain->GetKeyFromPool(newKey))
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");
    CKeyID keyID = newKey.GetID();
    CScript scriptPubKey = GetScriptForDestination(keyID);

    // TODO utxo[0].tx->GetHash().GetHex() 
    // TODO put hex into script directly
    std::string tokenid = utxo[0].tx->GetHash().ToString();
    CScript script = CScript() << OP_TOKEN << ToByteVector(tokenid) << CScriptNum(nSupply);
    script << OP_DROP << OP_DROP;
    script += scriptPubKey;

    CScriptID innerID(script);
    std::string address = EncodeDestination(innerID);
    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("tokenid", tokenid));
    result.push_back(Pair("tokenAddress", address));
    result.push_back(Pair("tokenScript", HexStr(script.begin(), script.end())));

    pwalletMain->AddCScript(script);
    pwalletMain->SetAddressBook(innerID, "", "token");

    CTxOut supplyOut(defaultSupplyAmount, script);
    rawTx.vout.push_back(supplyOut);

    CAmount chargeAmount = utxoAmount - defaultSupplyAmount - defaultSupplyFee;
    CTxOut chargeOut(chargeAmount, scriptPubKey);
    rawTx.vout.push_back(chargeOut);
 
    // sign tx
    // Fetch previous transactions (inputs):
    CCoinsView viewDummy;
    CCoinsViewCache view(&viewDummy);
    {
        READLOCK(mempool.cs);
        CCoinsViewCache &viewChain = *pcoinsTip;
        CCoinsViewMemPool viewMempool(&viewChain, mempool);
        view.SetBackend(viewMempool); // temporarily switch cache backend to db+mempool view

        BOOST_FOREACH (const CTxIn &txin, rawTx.vin)
        {
            view.AccessCoin(txin.prevout); // Load entries from viewChain into view; can fail.
        }

        view.SetBackend(viewDummy); // switch back to avoid locking mempool for too long
    }

    CBasicKeyStore tempKeystore;

#ifdef ENABLE_WALLET
    if (pwalletMain)
        EnsureWalletIsUnlocked();
#endif

#ifdef ENABLE_WALLET
    const CKeyStore &keystore = (!pwalletMain ? tempKeystore : *pwalletMain);
#else
    const CKeyStore &keystore = tempKeystore;
#endif

    int nHashType = SIGHASH_ALL;
    bool pickedForkId = false;
    if (!pickedForkId) // If the user didn't specify, use the configured default for the hash type
    {
        if (IsUAHFforkActiveOnNextBlock(chainActive.Tip()->nHeight))
        {
            nHashType |= SIGHASH_FORKID;
            pickedForkId = true;
        }
    }

    bool fHashSingle = ((nHashType & ~(SIGHASH_ANYONECANPAY | SIGHASH_FORKID)) == SIGHASH_SINGLE);

    // Script verification errors
    UniValue vErrors(UniValue::VARR);

    // Use CTransaction for the constant parts of the
    // transaction to avoid rehashing.
    const CTransaction txConst(rawTx);

    // Sign what we can:
    for (unsigned int i = 0; i < rawTx.vin.size(); i++)
    {
        CTxIn &txin = rawTx.vin[i];
        const Coin &coin = view.AccessCoin(txin.prevout);
        if (coin.IsSpent())
        {
            TxInErrorToJSON(txin, vErrors, "Input not found or already spent");
            continue;
        }
        const CScript &prevPubKey = coin.out.scriptPubKey;
        const CAmount &amount = coin.out.nValue;

        // Only sign SIGHASH_SINGLE if there's a corresponding output:
        if (!fHashSingle || (i < rawTx.vout.size()))
            SignSignature(keystore, prevPubKey, rawTx, i, amount, nHashType);

        // ... and merge in other signatures:
        if (pickedForkId)
        {
            txin.scriptSig = CombineSignatures(prevPubKey,
                TransactionSignatureChecker(&txConst, i, amount, SCRIPT_ENABLE_SIGHASH_FORKID), txin.scriptSig, rawTx.vin[i].scriptSig);
            ScriptError serror = SCRIPT_ERR_OK;

            if (!VerifyScript(txin.scriptSig, prevPubKey, STANDARD_SCRIPT_VERIFY_FLAGS | SCRIPT_ENABLE_SIGHASH_FORKID,
                    MutableTransactionSignatureChecker(&rawTx, i, amount, SCRIPT_ENABLE_SIGHASH_FORKID), &serror))
            {
                TxInErrorToJSON(txin, vErrors, ScriptErrorString(serror));
            }
        }
        else
        {
            txin.scriptSig = CombineSignatures(prevPubKey, TransactionSignatureChecker(&txConst, i, amount, 0),
                        txin.scriptSig, rawTx.vin[i].scriptSig);
            ScriptError serror = SCRIPT_ERR_OK;

            if (!VerifyScript(txin.scriptSig, prevPubKey, STANDARD_SCRIPT_VERIFY_FLAGS,
                        MutableTransactionSignatureChecker(&rawTx, i, amount, 0), &serror))
            {
                TxInErrorToJSON(txin, vErrors, ScriptErrorString(serror));
            }
        }
    }

    if (!vErrors.empty())
    {
        result.push_back(Pair("signErrors", vErrors));
        return result;
    }

    // send tx
    uint256 hashTx = rawTx.GetHash();

    bool fOverrideFees = false;
    TransactionClass txClass = TransactionClass::DEFAULT;

    bool fHaveChain = false;
    bool fHaveMempool = mempool.exists(hashTx);
    if (!fHaveMempool && !fHaveChain)
    {
        // push to local node and sync with wallets
        CValidationState state;
        bool fMissingInputs;
        if (!AcceptToMemoryPool(mempool, state, rawTx, false, &fMissingInputs, false, !fOverrideFees, txClass))
        {
            if (state.IsInvalid())
            {
                throw JSONRPCError(
                        RPC_TRANSACTION_REJECTED, strprintf("%i: %s", state.GetRejectCode(), state.GetRejectReason()));
            }
            else
            {
                if (fMissingInputs)
                {
                    throw JSONRPCError(RPC_TRANSACTION_ERROR, "Missing inputs");
                }
                throw JSONRPCError(RPC_TRANSACTION_ERROR, state.GetRejectReason());
            }
        }
#ifdef ENABLE_WALLET
        else
            SyncWithWallets(rawTx, NULL, -1);
#endif
    }
    else if (fHaveChain)
    {
        throw JSONRPCError(RPC_TRANSACTION_ALREADY_IN_CHAIN, "transaction already in block chain");
    }
    RelayTransaction(rawTx);

    result.push_back(Pair("txid", hashTx.GetHex()));
    return result;
}


UniValue createtokenscript(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() != 2)
        throw runtime_error("createtokenscript \"tokename\" \"tokensupply\" \n");

    LOCK(cs_main);
    RPCTypeCheck(params, boost::assign::list_of(UniValue::VSTR)(UniValue::VSTR), true);
    if (params[0].isNull() || params[1].isNull())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, arguments 1 and 2 must be non-null");

    std::string name = params[0].get_str();

    CAmount supply = atoll(params[1].get_str().c_str());
    if (supply > MAX_TOKEN_SUPPLY)
        throw runtime_error("tokensupply is out of range, max supply is 10**18");

    CPubKey newKey;
    if (!pwalletMain->GetKeyFromPool(newKey))
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");
    CKeyID keyID = newKey.GetID();
    CScript scriptPubKey = GetScriptForDestination(keyID);

    CScript script = CScript() << OP_TOKEN << ToByteVector(name) << CScriptNum(supply);
    script << OP_DROP << OP_DROP;
    script += scriptPubKey;

    CScriptID innerID(script);
    std::string address = EncodeDestination(innerID);
    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("address", address));
    result.push_back(Pair("token", HexStr(script.begin(), script.end())));

    pwalletMain->AddCScript(script);
    pwalletMain->SetAddressBook(innerID, "", "token");

    return result;
}

UniValue sendtoken(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 4)
        throw runtime_error(
            "sendtoken [{\"txid\":\"id\",\"vout\":n},...] [{\"address\":\"xxx\", \"amount\":x.xxx, "
            "\"tokenname\":\"xxx\", \"tokenamount\":xxx, \"data\":\"hex\"},...] \"melt\" \n"
            "\nCreate a transaction spending the given inputs and creating new outputs.\n"
            "Outputs can be addresses or data.\n"
            "Returns hex-encoded raw transaction.\n"
            "Note that the transaction's is signed, and broadcast to the network.\n"

            "\nArguments:\n"
            "1. \"transactions\"        (string, required) A json array of json objects\n"
            "     [\n"
            "       {\n"
            "         \"txid\":\"id\",  (string, required) The transaction id\n"
            "         \"vout\":n        (numeric, required) The output number\n"
            "       }\n"
            "       ,...\n"
            "     ]\n"
            "2. \"outputs\"             (string, required) a json object with outputs\n"
            "     [\n"
            "       {\n"
            "         \"address\":\"xxx\",    (string) The bitcoin address\n"
            "         \"amount\":x.xxx,       (numeric or string) the numeric value (can be string) is the amount\n"
            "         \"tokenname\":\"xxx\",  (string) The token name\n"
            "         \"tokenamount\":xxx,    (string) The token amount\n"
            "         \"data\":\"hex\",       (string) the value is hex encoded data\n"
            "       }\n"
            "       ,...\n"
            "     ]\n"
            "3. melt                    (boolean, optional, default = false) allow melt token \n"

            "\nResult:\n"
            "\"transaction\"            (string) hex string of the transaction\n" );

#ifdef ENABLE_WALLET
    LOCK2(cs_main, pwalletMain ? &pwalletMain->cs_wallet : NULL);
#else
    LOCK(cs_main);
#endif

    RPCTypeCheck(params, boost::assign::list_of(UniValue::VARR)(UniValue::VARR), true);
    if (params[0].isNull() || params[1].isNull())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, arguments must be non-null");

    UniValue inputs = params[0].get_array();
    UniValue outputs = params[1].get_array();

    // create token tx
    CMutableTransaction rawTx;
    for (unsigned int idx = 0; idx < inputs.size(); idx++)
    {
        const UniValue &input = inputs[idx];
        const UniValue &o = input.get_obj();

        uint256 txid = ParseHashO(o, "txid");
        
        const UniValue &vout_v = find_value(o, "vout");
        if (!vout_v.isNum())
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, missing vout key");
        int nOutput = vout_v.get_int();
        if (nOutput < 0)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, vout must be positive");

        uint32_t nSequence =
            (rawTx.nLockTime ? std::numeric_limits<uint32_t>::max() - 1 : std::numeric_limits<uint32_t>::max());
        CTxIn in(COutPoint(txid, nOutput), CScript(), nSequence);

        rawTx.vin.push_back(in);
    }

    std::set<CTxDestination> destinations;
    for (unsigned int idx = 0; idx < outputs.size(); idx++)
    {
        const UniValue &output = outputs[idx];
        const UniValue &o = output.get_obj();	

        if (!find_value(o, "address").isNull() && !find_value(o, "amount").isNull() && find_value(o, "data").isNull() )
        {
            std::string address = find_value(o, "address").get_str();
            CTxDestination destination = DecodeDestination(address);
            if (!IsValidDestination(destination))
            {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid Bitcoin address: ") + address);
            }

            if (!destinations.insert(destination).second)
            {
                throw JSONRPCError(
                    RPC_INVALID_PARAMETER, std::string("Invalid parameter, duplicated address: ") + address);
            }

            CScript scriptPubKey;
            if (!find_value(o, "tokenamount").isNull() && !find_value(o, "tokenname").isNull() )
            {
                std::string name = find_value(o, "tokenname").get_str();
                std::string amount = find_value(o, "tokenamount").get_str();
                CAmount nAmount = atoll(amount.c_str());
                scriptPubKey << OP_TOKEN << ToByteVector(name) << CScriptNum(nAmount) << OP_DROP << OP_DROP;
            }
            scriptPubKey += GetScriptForDestination(destination);

            std::string amount = find_value(o, "amount").get_str();
            CAmount nAmount = AmountFromValue(amount);
            CTxOut out(nAmount, scriptPubKey);
            rawTx.vout.push_back(out);	
        }
        else if (!find_value(o, "data").isNull() && find_value(o, "address").isNull())
        {
            std::string hex = find_value(o, "data").get_str();
            if (!IsHex(hex))
                throw JSONRPCError(RPC_INVALID_PARAMETER, "hex must be hexadecimal string");

            CTxOut out(0, CScript() << OP_RETURN << ToByteVector(hex));
            rawTx.vout.push_back(out);
		}
		else
		{
		    throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, output error");	
		}
    }

    // sign token tx
    vector<CMutableTransaction> txVariants;
    txVariants.push_back(rawTx);

    // mergedTx will end up with all the signatures; it
    // starts as a clone of the rawtx:
    CMutableTransaction mergedTx(rawTx);

    // Fetch previous transactions (inputs):
    CCoinsView viewDummy;
    CCoinsViewCache view(&viewDummy);
    {
        READLOCK(mempool.cs);
        CCoinsViewCache &viewChain = *pcoinsTip;
        CCoinsViewMemPool viewMempool(&viewChain, mempool);
        view.SetBackend(viewMempool); // temporarily switch cache backend to db+mempool view

        BOOST_FOREACH (const CTxIn &txin, rawTx.vin)
        {
            view.AccessCoin(txin.prevout); // Load entries from viewChain into view; can fail.
        }

        view.SetBackend(viewDummy); // switch back to avoid locking mempool for too long
    }

    CBasicKeyStore tempKeystore;

#ifdef ENABLE_WALLET
    if (pwalletMain)
        EnsureWalletIsUnlocked();
#endif

#ifdef ENABLE_WALLET
    const CKeyStore &keystore = (!pwalletMain ? tempKeystore : *pwalletMain);
#else
    const CKeyStore &keystore = tempKeystore;
#endif

    int nHashType = SIGHASH_ALL;
    bool pickedForkId = false;
    if (!pickedForkId) // If the user didn't specify, use the configured default for the hash type
    {
        if (IsUAHFforkActiveOnNextBlock(chainActive.Tip()->nHeight))
        {
            nHashType |= SIGHASH_FORKID;
            pickedForkId = true;
        }
    }

    bool fHashSingle = ((nHashType & ~(SIGHASH_ANYONECANPAY | SIGHASH_FORKID)) == SIGHASH_SINGLE);

    // Script verification errors
    UniValue vErrors(UniValue::VARR);

    // Use CTransaction for the constant parts of the
    // transaction to avoid rehashing.
    const CTransaction txConst(mergedTx);

    std::map<std::string, CAmount> mVinAmount;
    std::map<std::string, CAmount> mVoutAmount;

    // Sign what we can:
    for (unsigned int i = 0; i < mergedTx.vin.size(); i++)
    {
        CTxIn &txin = mergedTx.vin[i];
        const Coin &coin = view.AccessCoin(txin.prevout);
        if (coin.IsSpent())
        {
            TxInErrorToJSON(txin, vErrors, "Input not found or already spent");
            continue;
        }
        const CScript &prevPubKey = coin.out.scriptPubKey;
        const CAmount &amount = coin.out.nValue;

        if (prevPubKey.IsPayToScriptHash())
        {
            vector<unsigned char> hashBytes(prevPubKey.begin() + 2, prevPubKey.begin() + 22);
            CTransaction txToConst(mergedTx);
            TransactionSignatureCreator creator(&keystore, &txToConst, i, amount, nHashType);
            CScript scriptSigRet;
            creator.KeyStore().GetCScript(uint160(hashBytes), scriptSigRet);

            if (scriptSigRet.IsPayToToken()) {
                int namesize = scriptSigRet[1];
                int amountsize = scriptSigRet[2 + namesize];

                valtype vecName(scriptSigRet.begin() + 2, scriptSigRet.begin() + 2 + namesize);
                std::string name(vecName.begin(), vecName.end());

                valtype vec(scriptSigRet.begin() + 3 + namesize, scriptSigRet.begin() + 3 + namesize + amountsize);
                CAmount amount = CScriptNum(vec, true).getint64();
                if (amount > MAX_TOKEN_SUPPLY) 
                    throw runtime_error("token amount out of range");

				CAmount temp = mVinAmount[name];
				temp += amount;
				if (temp > MAX_TOKEN_SUPPLY)
				    throw runtime_error("vin amount out of range");
				mVinAmount[name] = temp;
            }
        }
        else if (prevPubKey.IsPayToToken())
        {
            int namesize = prevPubKey[1];
            int amountsize = prevPubKey[2 + namesize];

            valtype vecName(prevPubKey.begin() + 2, prevPubKey.begin() + 2 + namesize);
            std::string name(vecName.begin(), vecName.end());

            valtype vec(prevPubKey.begin() + 3 + namesize, prevPubKey.begin() + 3 + namesize + amountsize);
            CAmount amount = CScriptNum(vec, true).getint64();
            if (amount > MAX_TOKEN_SUPPLY) 
                throw runtime_error("token amount out of range");

            CAmount temp = mVinAmount[name];
            temp += amount;
            if (temp > MAX_TOKEN_SUPPLY)
                throw runtime_error("vin amount out of range");
            mVinAmount[name] = temp;
        }		

        // Only sign SIGHASH_SINGLE if there's a corresponding output:
        if (!fHashSingle || (i < mergedTx.vout.size()))
            SignSignature(keystore, prevPubKey, mergedTx, i, amount, nHashType);

        // ... and merge in other signatures:
        if (pickedForkId)
        {
            BOOST_FOREACH (const CMutableTransaction &txv, txVariants)
            {
                txin.scriptSig = CombineSignatures(prevPubKey,
                    TransactionSignatureChecker(&txConst, i, amount, SCRIPT_ENABLE_SIGHASH_FORKID), txin.scriptSig,
                    txv.vin[i].scriptSig);
            }
            ScriptError serror = SCRIPT_ERR_OK;

            if (!VerifyScript(txin.scriptSig, prevPubKey, STANDARD_SCRIPT_VERIFY_FLAGS | SCRIPT_ENABLE_SIGHASH_FORKID,
                MutableTransactionSignatureChecker(&mergedTx, i, amount, SCRIPT_ENABLE_SIGHASH_FORKID), &serror))
            {
                TxInErrorToJSON(txin, vErrors, ScriptErrorString(serror));
            }
        }
        else
        {
            BOOST_FOREACH (const CMutableTransaction &txv, txVariants)
            {
                txin.scriptSig = CombineSignatures(prevPubKey, TransactionSignatureChecker(&txConst, i, amount, 0),
                    txin.scriptSig, txv.vin[i].scriptSig);
            }
            ScriptError serror = SCRIPT_ERR_OK;
            if (!VerifyScript(txin.scriptSig, prevPubKey, STANDARD_SCRIPT_VERIFY_FLAGS,
                    MutableTransactionSignatureChecker(&mergedTx, i, amount, 0), &serror))
            {
                TxInErrorToJSON(txin, vErrors, ScriptErrorString(serror));
            }
        }
    }

    UniValue result(UniValue::VOBJ);
    if (!vErrors.empty())
    {
        result.push_back(Pair("hex", EncodeHexTx(mergedTx)));
        result.push_back(Pair("signerrors", vErrors));
        return result;
    }

    for (unsigned int i = 0; i < mergedTx.vout.size(); i++)
    {
        CTxOut &txout = mergedTx.vout[i];
        CScript outScript = txout.scriptPubKey;
        if (outScript.IsPayToToken())
        {
            int namesize = outScript[1];
            int amountsize = outScript[2 + namesize];

            valtype vecName(outScript.begin() + 2, outScript.begin() + 2 + namesize);
            std::string name(vecName.begin(), vecName.end());

            valtype vec(outScript.begin() + 3 + namesize, outScript.begin() + 3 + namesize + amountsize);
            CAmount amount = CScriptNum(vec, true).getint64();
            if (amount > MAX_TOKEN_SUPPLY) 
                throw runtime_error("amount out of range");

            CAmount temp = mVoutAmount[name];
            temp += amount;
            if (temp > MAX_TOKEN_SUPPLY)
                throw runtime_error("vout amount out of range");
            mVoutAmount[name] = temp;
        }	
    }

    bool melt = false; 
    if (params.size() > 2)
         melt = params[2].get_bool();

    for (auto &it: mVinAmount)
    {
        if (it.second < mVoutAmount[it.first]) 
        {
            throw runtime_error("vin token amount < vout token amount");	
        }
        else if (!melt && it.second > mVoutAmount[it.first])
        {
            throw runtime_error("vin token amount > vout token amount, " + std::to_string(it.second - mVoutAmount[it.first]) + " token will be melted");
        }
    }

    // send tx
    uint256 hashTx = mergedTx.GetHash();

    bool fOverrideFees = false;
    TransactionClass txClass = TransactionClass::DEFAULT;

    bool fHaveChain = false;
    bool fHaveMempool = mempool.exists(hashTx);
    if (!fHaveMempool && !fHaveChain)
    {
        // push to local node and sync with wallets
        CValidationState state;
        bool fMissingInputs;
        if (!AcceptToMemoryPool(mempool, state, mergedTx, false, &fMissingInputs, false, !fOverrideFees, txClass))
        {
            if (state.IsInvalid())
            {
                throw JSONRPCError(
                        RPC_TRANSACTION_REJECTED, strprintf("%i: %s", state.GetRejectCode(), state.GetRejectReason()));
            }
            else
            {
                if (fMissingInputs)
                {
                    throw JSONRPCError(RPC_TRANSACTION_ERROR, "Missing inputs");
                }
                throw JSONRPCError(RPC_TRANSACTION_ERROR, state.GetRejectReason());
            }
        }
#ifdef ENABLE_WALLET
        else
            SyncWithWallets(mergedTx, NULL, -1);
#endif
    }
    else if (fHaveChain)
    {
        throw JSONRPCError(RPC_TRANSACTION_ALREADY_IN_CHAIN, "transaction already in block chain");
    }
    RelayTransaction(rawTx);

    return hashTx.GetHex();
}

static const CRPCCommand commands[] = {
    //  category              name                      actor (function)         okSafeMode
    //  --------------------- ------------------------  -----------------------  ----------
    {"rawtransactions", "getrawtransaction", &getrawtransaction, true},
    {"rawtransactions", "createrawtransaction", &createrawtransaction, true},
    {"rawtransactions", "decoderawtransaction", &decoderawtransaction, true},
    {"rawtransactions", "decodescript", &decodescript, true},
    {"rawtransactions", "sendrawtransaction", &sendrawtransaction, false},
    {"rawtransactions", "signrawtransaction", &signrawtransaction, false}, /* uses wallet if enabled */
    {"blockchain", "gettxoutproof", &gettxoutproof, true}, {"blockchain", "verifytxoutproof", &verifytxoutproof, true},
    // Token
    {"token", "createtokenscript", &createtokenscript, true},
    {"token", "tokenissue", &tokenissue, true},
    {"token", "sendtoken", &sendtoken, true},
    {"token", "getaccountinfo", &getaccountinfo, true},
    {"token", "tokenmint", &tokenmint, true},
    {"token", "tokentransfer", &tokentransfer, true},
    {"token", "tokenlist", &tokenlist, true},
    {"token", "tokensearch", &tokensearch, true},
    {"token", "tokenaddress", &tokenaddress, true},
    {"token", "tokenhistory", &tokenhistory, true},
    {"token", "tokendetail", &tokendetail, true},
};

void RegisterRawTransactionRPCCommands(CRPCTable &tableRPC)
{
	for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
		tableRPC.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
