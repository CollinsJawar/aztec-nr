use dep::aztec::{
    protocol_types::{
        address::AztecAddress, 
        traits::Empty, 
        constants::GENERATOR_INDEX__NOTE_NULLIFIER,
        hash::poseidon2_hash_with_separator,
    },
    note::{
        note_header::NoteHeader, 
        note_interface::NoteInterface, 
        utils::compute_note_hash_for_nullify,
    },
    oracle::unsafe_rand::unsafe_rand, 
    keys::getters::get_nsk_app, 
    context::PrivateContext,
};

// Define constants for address note length and byte length
const ADDRESS_NOTE_LEN: usize = 3; // Use usize for lengths
const ADDRESS_NOTE_BYTES_LEN: usize = ADDRESS_NOTE_LEN * 32 + 64;

// AddressNote structure storing an address, npk_m_hash, and randomness
#[aztec(note)]
struct AddressNote {
    address: AztecAddress,
    npk_m_hash: Field, // The nullifying public key hash for private spending
    randomness: Field,
    header: NoteHeader, // Added header field for consistency with the `new` function
}

impl NoteInterface<ADDRESS_NOTE_LEN, ADDRESS_NOTE_BYTES_LEN> for AddressNote {
    // Compute the nullifier with context
    fn compute_nullifier(self, context: &mut PrivateContext, note_hash_for_nullify: Field) -> Field {
        let secret = context.request_nsk_app(self.npk_m_hash);
        poseidon2_hash_with_separator(
            [note_hash_for_nullify, secret],
            GENERATOR_INDEX__NOTE_NULLIFIER as Field,
        )
    }

    // Compute the nullifier without context
    fn compute_nullifier_without_context(self) -> Field {
        let note_hash_for_nullify = compute_note_hash_for_nullify(self);
        let secret = get_nsk_app(self.npk_m_hash);
        poseidon2_hash_with_separator(
            [note_hash_for_nullify, secret],
            GENERATOR_INDEX__NOTE_NULLIFIER as Field,
        )
    }
}

impl AddressNote {
    // Create a new AddressNote instance with randomness and an empty header
    pub fn new(address: AztecAddress, npk_m_hash: Field) -> Self {
        let randomness = unsafe_rand();
        AddressNote { 
            address, 
            npk_m_hash, 
            randomness, 
            header: NoteHeader::empty() 
        }
    }
}
