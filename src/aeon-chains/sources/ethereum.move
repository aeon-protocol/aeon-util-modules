module aeon_chains::ethereum {
    use sui::hash;
    use sui::hex;
    use std::vector;
    use sui::bcs;
    use sui::object::{Self,UID,ID};
    use sui::transfer;
    use sui::tx_context::{TxContext};

    //these hex values are non padded. They also have to be valid hex values (i.e. even number of characters)
    struct EthereumTransactionEIP1559 has drop, copy, store {
        data: vector<u8>,
        gas_limit: vector<u8>,
        nonce: vector<u8>,
        to: vector<u8>,
        value: vector<u8>,
        chain_id: vector<u8>,
        max_priority_fee_per_gas: vector<u8>,
        max_fee_per_gas: vector<u8>,
        access_list: vector<vector<u8>>,
    }

    struct EthereumTransactionLegacy has store, copy, drop {
        data: vector<u8>,
        gas_limit: vector<u8>,
        nonce: vector<u8>,
        to: vector<u8>,
        value: vector<u8>,
        chain_id: vector<u8>,
        gas_price: vector<u8>
    }


    public fun create_ethereum_transaction_eip1559(
        data: vector<u8>,
        gas_limit: vector<u8>,
        nonce: vector<u8>,
        to: vector<u8>,
        value: vector<u8>,
        chain_id: vector<u8>,
        max_priority_fee_per_gas: vector<u8>,
        max_fee_per_gas: vector<u8>,
        access_list: vector<vector<u8>>,
    ): EthereumTransactionEIP1559 {
        return EthereumTransactionEIP1559 {
            data: data,
            gas_limit: gas_limit,
            nonce: nonce,
            to: to,
            value: value,
            chain_id: chain_id,
            max_priority_fee_per_gas: max_priority_fee_per_gas,
            max_fee_per_gas: max_fee_per_gas,
            access_list: access_list,
        }
    }

    public fun create_ethereum_transaction_legacy(
        data: vector<u8>,
        gas_limit: vector<u8>,
        nonce: vector<u8>,
        to: vector<u8>,
        value: vector<u8>,
        chain_id: vector<u8>,
        gas_price: vector<u8>,
    ): EthereumTransactionLegacy {
        return EthereumTransactionLegacy{
            data: data,
            gas_limit: gas_limit,
            nonce: nonce,
            to: to,
            value: value,
            chain_id: chain_id,
            gas_price: gas_price,
        }
    }

    public fun to_signable_blob_legacy(ethereum_transaction: &EthereumTransactionLegacy): vector<u8> {
        let blob = vector::empty<u8>();
        //go through struct and push back vec
        vector::append(&mut blob,encode_bytes(ethereum_transaction.nonce));
        vector::append(&mut blob,encode_bytes(ethereum_transaction.gas_price));
        vector::append(&mut blob,encode_bytes(ethereum_transaction.gas_limit));
        vector::append(&mut blob,encode_bytes(ethereum_transaction.to));
        vector::append(&mut blob,encode_bytes(ethereum_transaction.value));
        vector::append(&mut blob,encode_bytes(ethereum_transaction.data));
        vector::append(&mut blob,encode_bytes(ethereum_transaction.chain_id));
        vector::append(&mut blob,encode_bytes(vector::empty<u8>()));
        vector::append(&mut blob,encode_bytes(vector::empty<u8>()));

        let encoded_base=add_length_bytes(blob);  

        let hashed=hash::keccak256(&encoded_base);
        return hashed
    }

    public fun to_signable_blob_eip1559(ethereum_transaction: &EthereumTransactionEIP1559): vector<u8> {
        let blob = vector::empty<u8>();
        //go through struct and push back vec
        vector::append(&mut blob,encode_bytes(ethereum_transaction.chain_id));
        vector::append(&mut blob,encode_bytes(ethereum_transaction.nonce));
        vector::append(&mut blob,encode_bytes(ethereum_transaction.max_priority_fee_per_gas));
        vector::append(&mut blob,encode_bytes(ethereum_transaction.max_fee_per_gas));
        vector::append(&mut blob,encode_bytes(ethereum_transaction.gas_limit));
        vector::append(&mut blob,encode_bytes(ethereum_transaction.to));
        vector::append(&mut blob,encode_bytes(ethereum_transaction.value));
        vector::append(&mut blob,encode_bytes(ethereum_transaction.data));
        vector::append(&mut blob,encode_array_of_bytes(ethereum_transaction.access_list));

        let encoded_base=add_length_bytes(blob);  

        let eip1559_blob=vector::singleton(2u8);
        vector::append(&mut eip1559_blob, encoded_base);
        let hashed=hash::keccak256(&eip1559_blob);
        return hashed
    }

    ///Public encoding helper

    public fun u256_to_32_byte_vector(value: u256): vector<u8> {
        let bytes = vector::empty<u8>();
        let temp_value = value;

        let i = 0;
        while (i < 32) {
            // For each iteration, extract the corresponding byte.
            // This step assumes a way to shift u256 and mask it to get the byte,
            // similar to how you might with u64.
            let byte = (temp_value >> (8 * (31 - i))) & 0xFF_u256;
            vector::push_back(&mut bytes, (byte as u8));
            i = i + 1;
        };

        bytes
    }

    public fun left_pad_address_to_32_bytes(addr: vector<u8>): vector<u8> {
        let target_length: u64 = 32;
        let current_length: u64 = vector::length(&addr);

        let padding_needed: u64 = if (current_length < target_length) target_length - current_length else 0;

        // Create a new mutable vector for the address and immediately reverse it
        let padded_address: vector<u8> = addr;
        vector::reverse(&mut padded_address);

        // Append zeros to the now reversed address vector (which is effectively prepending them to the original vector)
        let i = 0;
        while (i < padding_needed) {
            vector::push_back(&mut padded_address, 0u8);
            i = i + 1;
        };

        // Reverse the vector again to restore the original order with zeros prepended
        vector::reverse(&mut padded_address);

        padded_address
    }

    public fun bytes4 (data: vector<u8>): vector<u8> {
        let result = vector::empty();
        let i = 0;
        while (i < 4) {
            vector::push_back(&mut result, *vector::borrow(&data, i));
            i = i + 1;
        };
        result
    }

    public fun to_eth_bytes<T>(input: &T): vector<u8> {
        let bcs_bytes=bcs::to_bytes<T>(input);
        //remove trailing 0
        while (*vector::borrow(&bcs_bytes,vector::length(&bcs_bytes)-1)==0u8){
            vector::pop_back(&mut bcs_bytes);
        };
        vector::reverse(&mut bcs_bytes);
        return bcs_bytes
    }


    /// Internal ethereum encoding logic

    fun add_length_bytes(input:vector<u8>):vector<u8>{
        let length=vector::length(&input);
        let result=encode_length(length, 192);
        vector::append(&mut result, input);
        return result
    }

    fun encode_array_of_bytes(input: vector<vector<u8>>): vector<u8> {
        let result = vector::empty<u8>();
        let output_length = 0u64;
        let i=0u64;
        while (i < vector::length(&input)){
            let sub_vec = vector::borrow(&input,i);
            let encoded_sub_vec=encode_bytes(*sub_vec);
            vector::append(&mut result, encoded_sub_vec);
            output_length=output_length+vector::length(&encoded_sub_vec);
            i=i+1;
        };
        let encoded_vec=add_length_bytes(result);
        return encoded_vec
    }



    fun encode_bytes(input: vector<u8>): vector<u8> {
        if (vector::length(&input) == 1 && *vector::borrow(&input,0) < 128u8) {
            return input
        };
        let encoded_vec=encode_length(vector::length(&input), 128);
        vector::append(&mut encoded_vec, input);
        return encoded_vec
    }

    fun encode_length(len: u64, offset: u8): vector<u8> {
        if (len < 56) {
            let sum=(len as u8) + offset;
            return vector::singleton(sum);
        };
        let hex_length = hex::encode(to_eth_bytes<u64>(&len));
        let l_length = vector::length(&hex_length)/2;

        let sum=(offset as u64) + 55 + l_length;
        let combined = hex::encode(to_eth_bytes<u64>(&sum));
        vector::append(&mut combined,hex_length);
        return hex::decode(combined)
    }
    
    //using a swap tx on uniswap as an example
    #[test]
    fun test_to_signable_blob(){
        let ethereum_transaction = EthereumTransactionEIP1559{
            data: x"3593564c000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000659c2b4200000000000000000000000000000000000000000000000000000000000000020b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000b1a2bc2ec500000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000b1a2bc2ec50000000000000000000000000000000000000000000000000000000000000000959d00000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002b0d500b1d8e8ef31e21c99d1db9a6444d3adf12700001f43c499c542cef5e3811e1192ce70d8cc03d5c3359000000000000000000000000000000000000000000",
            gas_limit: x"02ea7e",
            nonce: x"",
            to: x"643770e279d5d0733f21d6dc03a8efbabf3255b4",
            value: x"b1a2bc2ec50000",
            chain_id: x"89",
            max_priority_fee_per_gas: x"0e068f1b0f",
            max_fee_per_gas: x"1a0addc3d0",
            access_list: vector::empty<vector<u8>>(),
        };
        let signable_blob=to_signable_blob_eip1559(&ethereum_transaction);
        assert!(hex::encode(signable_blob)==b"3532f3cdaee787f6cb178613de6e182ee58815969682f637b5e3c98ba643eae4",0);
    }

    //using a swap tx on pancakeswap as an example
    #[test]
    fun test_to_signable_blob_legacy(){
        let ethereum_transaction = EthereumTransactionLegacy{
            data: x"5ae401dc00000000000000000000000000000000000000000000000000000000659c812800000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000e404e45aaf000000000000000000000000bb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c0000000000000000000000000e09fabb73bd3ade0a17ecc321fd13a19e81ce82000000000000000000000000000000000000000000000000000000000000271000000000000000000000000033c0a7be92fe7b86362cc4bd003f74de23ed3f990000000000000000000000000000000000000000000000000001c6bf5263400000000000000000000000000000000000000000000000000000b481635efb53a2000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            gas_limit: x"02EA0D",
            nonce: x"",
            to: x"13f4ea83d0bd40e75c8222255bc855a974568dd4",
            value: x"01C6BF52634000",
            chain_id: x"38",
            gas_price: x"DF847580",
        };
        let signable_blob=to_signable_blob_legacy(&ethereum_transaction);
        assert!(hex::encode(signable_blob)==b"537a454adb2c1ac229b7783acbfd395a35fa36bc0659a37578aa808088264e85",0);
    }
    
}