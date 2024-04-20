

module aeon_actions::evm_transfer {

    use std::vector;
    use sui::object::{Self, ID, UID};
    use sui::tx_context::{Self,TxContext};
    use std::option::{Self, Option};
    use std::string::{Self,String};
    use sui::transfer::{Self};
    use sui::hash;
    use sui::bcs;
    use std::debug;
    use sui::hex;
    use aeon_chains::ethereum;



    //Convenience function to get data vector for an erc20 transfer
    fun assemble_ethereum_erc20_data(recipient_address_bytes: vector<u8>, amount: u256): vector<u8> {
        
        let data = vector::empty<u8>();

        // assembling the data field
        let function_sig = sui::hash::keccak256(&b"transfer(address,uint256)");
        let function_sig4 = ethereum::bytes4(function_sig);

        let amount_bytes = ethereum::u256_to_32_byte_vector(amount);
        vector::append(&mut data, function_sig4);
        vector::append(&mut data, ethereum::left_pad_address_to_32_bytes(recipient_address_bytes));
        vector::append(&mut data, amount_bytes);

        data
    }

    //Convenience function to get value vector for an native transfer
    fun assemble_ethereum_native_transfer_value(amount: u256): vector<u8> {
        ethereum::u256_to_32_byte_vector(amount)
    }

    #[test]
    fun test_erc20_transfer_assembling(){
        use sui::test_scenario;
        use std::string;
        use sui::object::{Self, ID, UID};
        use sui::hex;
        use sui::bcs;
        use std::debug;
        
        let token_address_bytes = x"2ed7afa17473e17ac59908f088b4371d28585476";
        let recipient_address_bytes = x"1234567890123456789012345678901234567890"; // === hex::decode(b"1234567890123456789012345678901234567890")

        let amount = 1;

        let data = assemble_ethereum_erc20_data(recipient_address_bytes, amount);

        let chain_id = x"01";

        let value_bytes=x"";

        let nonce = ethereum::to_eth_bytes<u64>(&2);  // ===x"02"
        let gas_limit = ethereum::to_eth_bytes<u8>(&2);
        let max_priority_fee_per_gas = ethereum::to_eth_bytes<u8>(&2);
        let max_fee_per_gas = ethereum::to_eth_bytes<u8>(&2);
        let access_list_bytes = vector::empty<vector<u8>>();

        let eip1559_tx = ethereum::create_ethereum_transaction_eip1559(data,  gas_limit, nonce,token_address_bytes,value_bytes,chain_id, max_priority_fee_per_gas, max_fee_per_gas, access_list_bytes);

        let tx_signable = ethereum::to_signable_blob_eip1559(&eip1559_tx);

        let hex_assert = hex::decode(b"02f8620102020202942ed7afa17473e17ac59908f088b4371d2858547680b844a9059cbb00000000000000000000000012345678901234567890123456789012345678900000000000000000000000000000000000000000000000000000000000000001c0");

        assert!(tx_signable == hash::keccak256(&hex_assert), 0);
    }

}
    


