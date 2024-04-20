# Aeon util modules

Helper functions for assembling byte blobs to sign with dWallets.

## Ethereum

For transfers, you can use aeon_actions::evm_transfer to get the data and value byte vectors as required.

Assembling an arbitrary Legacy or EIP1559 tx using the ethereum module:

1. `ethereum::create_ethereum_transaction_eip1559` or `ethereum::create_ethereum_transaction_legacy`
2. `ethereum::to_signable_blob_eip1559` or `ethereum::to_signable_blob_legacy`
3. `sui_state_proof::approve_message` with the byte blob and your dwallet cap

## Bitcoin

Only simple P2WPKH supported!

Preimage scripts calculation is expected to be performed offchain (see [here](https://github.com/spesmilo/electrum/blob/20d7543b53cda78977f18d565d9a56361436682d/electrum/transaction.py#L887) for help)

1. Use previous transaction output offchain data to create `TxOutput`, `TxOutpoint` and `SimplifiedP2WPKHTxInput` as required.
2. Calculate preimage scripts.
3. Calculate number of bytes of tx and fee_rate for cost estimation.
4. Call `to_signable_blobs`
5. `sui_state_proof::approve_message` for each signable byte blob for the respective dwallet
