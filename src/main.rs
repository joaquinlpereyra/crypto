mod first_set;
mod third_set;

fn main() {
    // first_set::xor_cypher();
    // first_set::xor_file();
    // first_set::xor_encrypt();
    // first_set::decrypt_yellow_submarine();
    // first_set::find_ecb();
    // first_set::implement_pkcs7();
    // first_set::decrypt_with_cbc();
    // first_set::cbc_ecb_oracle();
    // first_set::byte_at_a_time_ecb_decryption();
    // first_set::ecb_cut_and_paste();
    // first_set::byte_at_a_time_ecb_decryption_hard();
    // first_set::detect_and_strip_pkcs7();
    // first_set::cbc_bitflipping_attacks();
    for _ in 0..100 {
        third_set::cbc_padding_oracle::attack();
    }
}
