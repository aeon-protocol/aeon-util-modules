// Only supports P2WPKH addresses
// implementation based on electrum wallet
module aeon_chains::bitcoin_P2WPKH {
    use std::hash;
    use sui::hex;
    use std::vector;
    use sui::bcs;
    use std::ascii::{Self, String as AsciiString};
    use std::string::{Self, String};
    use std::debug;

    const EByteOperationError: u64=0;
    const EInvalidInput: u64=1;

    //we only allow for sighash all as anything else is unsafe for our usecase
    const SIGHASH_ALL: u32=1;
    //we only allow for transaction version 2
    const VERSION: u32=2;
    //we only allow for locktime 0
    const LOCKTIME: u32=0;

    const RBF_NSEQUENCE: u32=0xfffffffd;

    const CHARSET:vector<u8> =b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

    // Required op codes
    const OP_0: u8 = 0; // 00 in hexadecimal is 0 in decimal
    const OP_1: u8 = 81; // 51 in hexadecimal is 81 in decimal
    const OP_1NEGATE: u8 = 79; // 4f in hexadecimal is 79 in decimal
    const OP_PUSHDATA1: u8 = 76; // 4c in hexadecimal is 76 in decimal
    const OP_PUSHDATA2: u8 = 77; // 4d in hexadecimal is 77 in decimal
    const OP_PUSHDATA4: u8 = 78; // 4e in hexadecimal is 78 in decimal

    struct TxOutput has drop, copy, store{
        scriptpubkey: vector<u8>,
        value: u64 
    }

    struct TxOutpoint has drop, copy, store {
        txid: vector<u8>,
        out_idx: u32
    }

    struct SimplifiedP2WPKHTxInput has drop, copy, store {
        witness_utxo: TxOutput,
        prevout: TxOutpoint,

        // The following are omitted for now for simplicity:
        // nsequence: u32,
        // bip32_path_xpub_fingerprint:vector<u8>,
        // bip32_path_path: vector<u64>, //normally these two are Table<vector<u8>,(vector<u8>,vector<u64>)> because of multi transactions; we dont support that so its just one path
    }

    public fun create_tx_output(scriptpubkey: vector<u8>, value: u64): TxOutput {
        return TxOutput{
            scriptpubkey: scriptpubkey,
            value: value
        }
    }

    public fun create_tx_outpoint(txid: vector<u8>, out_idx: u32): TxOutpoint {
        return TxOutpoint{
            txid: txid,
            out_idx: out_idx
        }
    }

    public fun create_simplified_p2wpkh_tx_input(witness_utxo: TxOutput, prevout: TxOutpoint): SimplifiedP2WPKHTxInput {
        return SimplifiedP2WPKHTxInput{
            witness_utxo: witness_utxo,
            prevout: prevout
        }
    }

    // preimage scripts have to be calculcated offchain to save gas costs; should be hex encoded!
    // As we use P2WPKH, using blackbox preimage scripts does not pose a security risk
    public fun to_signable_blobs(
        source: vector<u8>,
        outputs_without_change: vector<TxOutput>, //we need to calculate change output based on inputs, hence can't ask for it here
        inputs: vector<SimplifiedP2WPKHTxInput>,
        precalculated_preimage_scripts: vector<vector<u8>>,
        tx_bytes: u64, //has to be calculated offchain
        fee_rate: u64
    ): vector<vector<u8>> {

        //gas price denotes the fee rate for us so we have to calculate the actual fee to pay
        let fee=fee_rate*tx_bytes;

        let total_input_value=0;
        let i=0;
        while (i < vector::length(&inputs)) {
            let input=vector::borrow(&inputs,i);
            total_input_value=total_input_value+input.witness_utxo.value;
            i=i+1;
        };

        let signable_blobs={
            //1. Calculate change output
            let total_output_value=0;
            let i=0;
            while (i < vector::length(&outputs_without_change)) {
                let output=vector::borrow(&outputs_without_change,i);
                total_output_value=total_output_value+output.value;
                i=i+1;
            };

            let change_value=total_input_value-total_output_value-fee;
            let change_output=TxOutput{
                scriptpubkey: hex::decode(address_to_script_hex(source)), //this assumes we use source as the change address for simplicity when working with dwallets. we could also derive a new one on the fly
                value: change_value
            };
            vector::push_back(&mut outputs_without_change,change_output);
            get_signable_blobs_internal(inputs, outputs_without_change,precalculated_preimage_scripts)
        };
        return signable_blobs
    }

    /// Internal bitcoin encoding logic
    
    fun get_signable_blobs_internal(inputs: vector<SimplifiedP2WPKHTxInput>, outputs: vector<TxOutput>, precalculated_preimage_scripts:vector<vector<u8>>): vector<vector<u8>> {
        let i=0;
        let signable_blobs=vector::empty<vector<u8>>();
        while (i < vector::length(&inputs)) {
            let precalculated_preimage_script=vector::borrow(&precalculated_preimage_scripts,i);
            vector::push_back(&mut signable_blobs,sha256d(hex::decode(transaction_serialize_preimage(inputs,outputs,*precalculated_preimage_script, i))));
            i=i+1;
        };
        return signable_blobs
    }

    fun address_to_script_hex(address_:vector<u8>): vector<u8> {
        let (witver,witprog)=decode_segwit_address(ascii::string(address_));
        return construct_script(witver,witprog)
    }

    fun construct_script(witver: u8, witprog: vector<u8>): vector<u8> {
        let script_=vector::empty<u8>();
        vector::append(&mut script_, hex::encode(add_number_to_script(witver)));
        vector::append(&mut script_, push_script(hex::encode(witprog)));
        return script_
    }

    fun add_number_to_script(i: u8): vector<u8> {
        let witver_bytes=hex::encode(bcs::to_bytes<u8>(&i)); //normally this would call script_num_to_hex but due to small number, we can just hex encode (source: https://github.com/bitcoin/bitcoin/blob/8cbc5c4be4be22aca228074f087a374a7ec38be8/src/script/script.h#L326)
        return hex::decode(push_script(witver_bytes))
    }

    fun push_script(hex_data: vector<u8>): vector<u8> {
        let data=hex::decode(hex_data);
        let data_len = vector::length(&data);
        if (data_len==0 || data_len==1 && *vector::borrow(&data,0)==0) {
            return hex::encode(vector::singleton(OP_0));
        } else if (data_len==1 && *vector::borrow(&data,0)<=16) {
            return hex::encode(vector::singleton(OP_1+*vector::borrow(&data,0)-1));
        } else if (data_len==1&&*vector::borrow(&data,0)==129) {
            return hex::encode(vector::singleton(OP_1NEGATE));
        };
        let res=op_push((data_len as u32));
        vector::append(&mut res, hex_data);
        return res
    }

    fun op_push(i: u32): vector<u8> {
        if (i < (OP_PUSHDATA1 as u32)) {
            return hex::encode(bcs::to_bytes<u8>(&(i as u8)))
        } else if (i <= 255) {
            let res=hex::encode(vector::singleton(OP_PUSHDATA1));
            vector::append(&mut res, hex::encode(bcs::to_bytes<u8>(&(i as u8))));
            return res
        } else if (i <= 65535) {
            let res=hex::encode(vector::singleton(OP_PUSHDATA2));
            vector::append(&mut res, hex::encode(bcs::to_bytes<u16>(&(i as u16))));
            return res
        } else {
            let res = hex::encode(vector::singleton(OP_PUSHDATA4));
            vector::append(&mut res, hex::encode(bcs::to_bytes<u32>(&i)));
            return res
        }
    }

    fun transaction_calc_bip143_shared_txdigest_fields(inputs: vector<SimplifiedP2WPKHTxInput>, outputs: vector<TxOutput>): (vector<u8>,vector<u8>,vector<u8>) {
        let prevout_bytes=vector::empty<u8>();
        let sequence_hex_bytes=vector::empty<u8>();
        let outputs_hex_bytes=vector::empty<u8>();
        let i=0;
        while (i < vector::length(&inputs)) {
            let input=vector::borrow(&inputs,i);
            vector::append(&mut prevout_bytes,tx_outpoint_serialize_to_network(input.prevout));
            vector::append(&mut sequence_hex_bytes,hex::encode(bcs::to_bytes<u32>(&RBF_NSEQUENCE)));
            i=i+1;
        };
        let i=0;
        while (i < vector::length(&outputs)) {
            let output=vector::borrow(&outputs,i);
            vector::append(&mut outputs_hex_bytes,hex::encode(tx_output_serialize_to_network(output)));
            i=i+1;
        };

        let hash_prevouts=hex::encode(sha256d(prevout_bytes));
        let hash_sequence=hex::encode(sha256d(hex::decode(sequence_hex_bytes)));
        let hash_outputs=hex::encode(sha256d(hex::decode(outputs_hex_bytes)));
        return (hash_prevouts,hash_sequence,hash_outputs)
    }

    fun transaction_serialize_preimage(inputs: vector<SimplifiedP2WPKHTxInput>, outputs: vector<TxOutput>, precalculated_preimage_script: vector<u8>,txin_index: u64): vector<u8> {
        let (hash_prevouts,hash_sequence,hash_outputs)=transaction_calc_bip143_shared_txdigest_fields(inputs,outputs);

        let n_version=hex::encode(bcs::to_bytes<u32>(&VERSION));
        let n_locktime=hex::encode(bcs::to_bytes<u32>(&LOCKTIME));
        let txin=vector::borrow(&inputs,txin_index);
        let n_hash_type=hex::encode(bcs::to_bytes<u32>(&SIGHASH_ALL));

        let outpoint=hex::encode(tx_outpoint_serialize_to_network(txin.prevout));
        let script_code=var_int(vector::length(&precalculated_preimage_script)/2);
        vector::append(&mut script_code,precalculated_preimage_script);
        let amount=hex::encode(bcs::to_bytes<u64>(&txin.witness_utxo.value));
        let n_sequence=hex::encode(bcs::to_bytes<u32>(&RBF_NSEQUENCE));

        let hex_preimage=vector::empty<u8>();
        vector::append(&mut hex_preimage,n_version);
        vector::append(&mut hex_preimage,hash_prevouts);
        vector::append(&mut hex_preimage,hash_sequence);
        vector::append(&mut hex_preimage,outpoint);
        vector::append(&mut hex_preimage,script_code);

        vector::append(&mut hex_preimage,amount);
        vector::append(&mut hex_preimage,n_sequence);
        vector::append(&mut hex_preimage,hash_outputs);
        vector::append(&mut hex_preimage,n_locktime);
        vector::append(&mut hex_preimage,n_hash_type);

        return hex_preimage
    }

    fun tx_outpoint_serialize_to_network(outpoint: TxOutpoint): vector<u8> {
        let res=outpoint.txid;
        vector::reverse(&mut res);
        vector::append(&mut res, bcs::to_bytes<u32>(&outpoint.out_idx));
        return res
    }

    fun tx_output_serialize_to_network(output: &TxOutput): vector<u8> {
        let bytes=bcs::to_bytes<u64>(&output.value);
        vector::append(&mut bytes,hex::decode(var_int(vector::length(&hex::encode(output.scriptpubkey))/2)));
        vector::append(&mut bytes,output.scriptpubkey);
        return bytes
    }

    //u64 should be sufficient as compactsize cant handle more anyhow
    fun var_int(i: u64): vector<u8> {
        // https://en.bitcoin.it/wiki/Protocol_specification#Variable_length_integer
        // https://github.com/bitcoin/bitcoin/blob/efe1ee0d8d7f82150789f1f6840f139289628a2b/src/serialize.h#L247
        // "CompactSize"
        let bytes=if (i < 253) {
            bcs::to_bytes<u8>(&(i as u8))
        } else if (i <= 65535) {
            let res=bcs::to_bytes<u8>(&253);
            vector::append(&mut res,bcs::to_bytes<u16>(&(i as u16)));
            res
        } else if (i <= 4294967295) {
            let res=bcs::to_bytes<u8>(&254);
            vector::append(&mut res,bcs::to_bytes<u32>(&(i as u32)));
            res
        } else {
            let res=bcs::to_bytes<u8>(&255);
            vector::append(&mut res,bcs::to_bytes<u64>(&i));
            res
        };
        return hex::encode(bytes)
    }

    fun sha256d(bytes: vector<u8>): vector<u8> {
        return hash::sha2_256(hash::sha2_256(bytes))
    }

    // based on https://github.com/sipa/bech32/blob/7a7d7ab158db7078a333384e0e918c90dbc42917/ref/python/segwit_addr.py#L73-L89
    fun bech32_decode(bech: AsciiString):vector<u8> {
        let data_string=ascii::string(vector::empty<u8>());
        let i=ascii::length(&bech)-1;
        while (i > 0) {
            let c=ascii::pop_char(&mut bech);
            if (c==ascii::char(49)) { //equivalent to 1
                break;
            };
            ascii::push_char(&mut data_string,c);
            i=i-1;
        };

        let bytes=ascii::into_bytes(data_string);
        let decoded=vector::empty<u8>();
        let i=ascii::length(&data_string)-1;
        while (i > 5) {
            let (found,index)=vector::index_of(&CHARSET,vector::borrow(&bytes,i));
            assert!(found,EInvalidInput);
            let char=(index as u8);
            vector::push_back(&mut decoded,char);
            i=i-1;
        };
        return decoded
    }

    // General power-of-2 base conversion
    fun convert_bits(data: vector<u8>, from_bits: u8, to_bits: u8, pad: bool): vector<u8> {
        let acc: u64 = 0;
        let bits: u8 = 0;
        let ret: vector<u8> = vector::empty<u8>();
        let maxv: u64 = (1 << to_bits) - 1; //255
        let max_acc: u64 = (1 << (from_bits+ to_bits - 1)) - 1;  //4095

        let i = 0;
        while (i < vector::length(&data)) {
            let value = vector::borrow(&data, i);
            
            if ((*value >> from_bits ) != 0) {
                return vector::empty<u8>(); // Error handling
            };

            acc = ((acc << from_bits as u64) | (*value as u64)) & max_acc;
            bits = bits + from_bits;

            while (bits >= to_bits) {
                bits = bits - to_bits;
                vector::push_back(&mut ret, (((acc >> bits) & maxv) as u8));
            };

            i = i + 1;
        };

        if (pad) {
            if (bits > 0) {
                vector::push_back(&mut ret, (((acc << (to_bits - bits) as u64) & maxv) as u8));
            }
        } else if (bits >= from_bits || ((acc << (to_bits - bits) as u64) & maxv) != 0) {
            return vector::empty<u8>(); // Error handling
        };

        return ret
    }

    //we dont do any validation here as we already confirmed that address == account address
    fun decode_segwit_address(addr: AsciiString): (u8,vector<u8>) {
        let dec=bech32_decode(addr);
        let witver=vector::remove(&mut dec,0);
        let witprog=convert_bits(dec,5,8,false);

        return (witver,witprog)
    }

    #[test]
    fun test_address_to_script_hex(){
        let address_=b"bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
        let script_hex=address_to_script_hex(address_);
        assert!(script_hex==b"0014e8df018c7e326cc253faac7e46cdc51e68542c42",EByteOperationError);    
    }

    #[test]
    fun test_transaction_serialize_preimage(){
        let precalculated_preimage_script=b"76a914751e76e8199196d454941c45d1b3a323f1433bd688ac";
        let i=0;
        let input=SimplifiedP2WPKHTxInput {
            witness_utxo: TxOutput{
                scriptpubkey: hex::decode(b"0014e8df018c7e326cc253faac7e46cdc51e68542c42"),
                value: 100000
            },
            prevout: TxOutpoint{
                txid: hex::decode(b"4e9b5d11fa4d1e8a39b4a6b4c7c48d311d44b8cfa8f2db4162e42e91f51756f9"),
                out_idx: 1
            }
        };
        let inputs=vector::singleton(input);

        //change output first
        let outputs=vector::singleton(TxOutput{
            scriptpubkey: hex::decode(b"0014e8df018c7e326cc253faac7e46cdc51e68542c42"),
            value: 10000
        });
        vector::push_back(
            &mut outputs,
            TxOutput{
                scriptpubkey: hex::decode(b"0014311564348890e005880a9bc834aaa5884f1b5932"),
                value: 85000
            }
        );
        let preimage=transaction_serialize_preimage(inputs,outputs,precalculated_preimage_script,i);
        assert!(preimage==b"02000000c91b15fbe2c4724057b42a423772dd2e7a462b6ef68641eee9458942592002c5caf35e5224de16efa3ccaf41070f6e7b9432b6f79551e629fca9d1c03b43bc52f95617f5912ee46241dbf2a8cfb8441d318dc4c7b4a6b4398a1e4dfa115d9b4e010000001976a914751e76e8199196d454941c45d1b3a323f1433bd688aca086010000000000fdffffff17955f16d20bca06a7ca8f1afc452ba72390432d576e62f6fd500957a9b41f3c0000000001000000",EByteOperationError);    
    }
}
