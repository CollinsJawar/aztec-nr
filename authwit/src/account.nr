use dep::aztec::context::PrivateContext;

use crate::entrypoint::{app::AppPayload, fee::FeePayload};
use crate::auth::{IS_VALID_SELECTOR, compute_authwit_message_hash};

struct AccountActions<Context> {
  context: Context,
  is_valid_impl: fn(&mut PrivateContext, Field) -> bool,
}

impl<Context> AccountActions<Context> {
    pub fn init(context: Context, is_valid_impl: fn(&mut PrivateContext, Field) -> bool) -> Self {
        AccountActions { context, is_valid_impl }
    }
}

/**
 * An implementation of the Account Action struct for the private context.
 * 
 * Implements logic to verify authorization and execute payloads.
 */
impl AccountActions<&mut PrivateContext> {

    /** 
     * Verifies that the `app_hash` and `fee_hash` are authorized and then executes them.
     * 
     * Executes the `fee_payload` and `app_payload` in sequence.
     * Will execute the `fee_payload` as part of the setup, and then enter the app phase.
     * 
     * @param app_payload The payload that contains the calls to be executed in the app phase.
     * @param fee_payload The payload that contains the calls to be executed in the setup phase.
     */
    // docs:start:entrypoint
    pub fn entrypoint(self, app_payload: AppPayload, fee_payload: FeePayload) {
        let valid_fn = self.is_valid_impl;

        let fee_hash = fee_payload.hash();
        assert(valid_fn(self.context, fee_hash));
        fee_payload.execute_calls(self.context);
        self.context.end_setup();

        let app_hash = app_payload.hash();
        assert(valid_fn(self.context, app_hash));
        app_payload.execute_calls(self.context);
    }
    // docs:end:entrypoint

    /**
     * Verifies that the `msg_sender` is authorized to consume `inner_hash` by the account.
     * 
     * Computes the `message_hash` using the `msg_sender`, `chain_id`, `version` and `inner_hash`.
     * Then executes the `is_valid_impl` function to verify that the message is authorized.
     * 
     * Will revert if the message is not authorized. 
     * 
     * @param inner_hash The hash of the message that the `msg_sender` is trying to consume.
     */
    // docs:start:verify_private_authwit
    pub fn verify_private_authwit(self, inner_hash: Field) -> Field {
        // The `inner_hash` is "siloed" with the `msg_sender` to ensure that only it can 
        // consume the message.
        // This ensures that contracts cannot consume messages that are not intended for them.
        let message_hash = compute_authwit_message_hash(
            self.context.msg_sender(),
            self.context.chain_id(),
            self.context.version(),
            inner_hash
        );
        let valid_fn = self.is_valid_impl;
        assert(valid_fn(self.context, message_hash) == true, "Message not authorized by account");
        IS_VALID_SELECTOR
    }
    // docs:end:verify_private_authwit
}
