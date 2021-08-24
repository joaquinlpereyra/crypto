use crypto::bytes;
use crypto::encoding::base64;
use crypto::frequency;
use crypto::random;
use crypto::symm::{self, padding::Padding, Ciphertext, Mode};
use std::collections::HashMap;
use std::{fs, str};

/// No. 17
pub fn cbc_padding_oracle() {
    for _ in 0..100 {
        cbc_padding_oracle::attack()
    }
}

/// No. 18
pub fn implement_ctr() {
    let raw_ciphertext =
        base64::decode("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
            .unwrap();
    let ciphertext =
        Ciphertext::from_existing(raw_ciphertext, Mode::CTR { nonce: 0 }, Padding::None);
    let plaintext = ciphertext.decrypt("YELLOW_SUBMARINE".as_bytes());
    println!("{}", str::from_utf8(&plaintext).unwrap());
}

/// No. 19 / No. 20
pub fn break_fixed_nonce_ctr() {
    let key = random::get_random(16);

    // Encrypt all plaintexts badly, with a fixed zero nonce and
    // join them into a big vector of bytes
    let ciphertexts: Vec<Ciphertext> = fs::read_to_string("./19.txt")
        .expect("file 19.txt not found")
        .lines()
        .map(|l| base64::decode(l).expect("could not decode b64"))
        .map(|decoded| Ciphertext::new(&key, &decoded, Mode::CTR { nonce: 0 }, Padding::None))
        .collect();

    // It is effectively easy to see that his sucks. I'm encrypting doing
    // plaintext[0..16]  XOR AES(00000000_00000000, key) |
    // plaintext[16..32] XOR AES(00000000_10000000, key) |
    // etc et
    //
    // So if P is plaintext, C ciphertext and KS the keystream and i is each byte
    // P[i] XOR KS[i] = C[i]
    // C[i] XOR P[i] = KS[i]
    // C[i] XOR KS[i] = P[i]
    //
    // We know C[i]. And we can guess KS[i] by using the ciphertexts. All KS[i] are equal!
    // I can use my statical analysis to find ocurrences of common bytes
    //
    // We will try to see which bytes contain valid ASCII
    for b in 0..32 {
        println!("Guess for byte number: {}", b);
        let ciphertexts_bytes_nth = ciphertexts
            .clone()
            .into_iter()
            .map(|ct| ct.bytes[b])
            .collect::<Vec<u8>>();
        for i in 0..=255 {
            let guess_keystream = vec![i; 16];
            let plaintext_try = bytes::xor(&ciphertexts_bytes_nth, &guess_keystream);
            // println!("{:?}", String::from_utf8_lossy(&plaintext_try.clone()));
            let utf8 = match String::from_utf8(plaintext_try) {
                Ok(txt) => txt,
                Err(_) => continue,
            };
            if frequency::analysis(&utf8) > 0.01
                && utf8.chars().all(|c| {
                    c.is_alphanumeric()
                        || c.is_whitespace()
                        || c == ','
                        || c == '.'
                        || c == ':'
                        || c == ';'
                        || c == '\''
                        || c == '?'
                        || c == '!'
                        || c == '\n'
                })
            {
                println!("{:2X?} -> {:?}", guess_keystream, utf8);
            }
        }
    }
    // After a lot of effort joining strings you can read the poem.
    // https://www.poetryfoundation.org/poems/43289/easter-1916
    // I have met?them? at closed?
    // Coming wit?viv?d
    // From count?r or
}

/// No 21
pub fn implement_mt19937_mersenne_twister() {}

#[allow(dead_code)]
mod cbc_padding_oracle {
    use crypto::encoding::base64;
    use crypto::random;
    use crypto::symm::padding::{unpad, Padding};
    use crypto::symm::{Ciphertext, Mode};
    use std::{fs, str};

    struct Server {
        texts: Vec<String>,
        key: Vec<u8>,
    }

    impl Server {
        pub fn new() -> Server {
            let texts: Vec<String> = fs::read_to_string("./17.txt")
                .expect("file 17.txt not found")
                .lines()
                .map(|l| l.to_owned())
                .collect::<Vec<String>>();
            Server {
                key: random::get_random(16),
                texts,
            }
        }

        fn select_at_random(&self) -> String {
            return self.texts[random::in_range(0, 10)].to_string();
        }

        pub fn give_ciphertext(&self) -> Ciphertext {
            let text = self.select_at_random();
            let iv = random::get_random(16);

            Ciphertext::new(
                &self.key,
                &text.as_bytes(),
                Mode::CBC { iv },
                Padding::PKCS7,
            )
        }

        pub fn valid_padding(&self, ciphertext: &Ciphertext) -> bool {
            let decrypted = ciphertext.decrypt_without_unpadding(&self.key);
            unpad(&Padding::PKCS7, &decrypted).is_some()
        }
    }

    fn get_intermediate_state(
        oracle: &Server,
        prev_block: &[u8],
        cur_block: &[u8],
        target_byte: u8,
        prev_intermediate_states: &[u8],
    ) -> u8 {
        let known = prev_intermediate_states.len();

        if target_byte > 15 || known > 15 {
            panic!("can't target a byte outside a block")
        }
        if usize::from(target_byte) + known != 15 {
            panic!("can only know one byte a a time")
        }

        // Poison previous block with bytes that when XORED
        // against the intermediate state will produce the valid pad
        let poison_len = known + 1;
        let valid_pad = 16 - target_byte;
        let mut poison = Vec::with_capacity(poison_len);
        poison.push(0x00); // we will poison this value in the for loop
        poison.extend(prev_intermediate_states.iter().map(|b| b ^ valid_pad).rev());

        for r in 0..=255 {
            // Create a new valid ciphertext (C') with the poison
            poison[0] = r;
            let mut poisoned_bytes = prev_block.to_vec();
            poisoned_bytes.splice(16 - poison_len.., poison.iter().copied());
            poisoned_bytes.extend_from_slice(cur_block);

            assert_eq!(poison[0], poisoned_bytes[target_byte as usize]);

            let poisoned =
                Ciphertext::cbc_from_prepended_iv(poisoned_bytes.clone(), Padding::PKCS7);

            // Check that poisoned block has valid padding.
            // The idea here being that if:
            // poisoned[target_byte] XOR IS(cur_block) has valid padding,
            // then that valid padding is "valid_pad" and we can do:
            // poisoned[target_byte] XOR IS(cur_block) = valid_pad
            // poisoned[target_byte] XOR valid_pad = IS(cur_block)
            if !oracle.valid_padding(&poisoned) {
                continue;
            }

            // That may lead to false positives, though,
            // as nothing forces the valid pading to actually
            // be my "valid pad"
            //
            // Consider the case of a full ciphertext block filled with padding 0x10
            // So:
            // * Plaintext: [0x10, 0x10, 0x10, 0x10,
            //               0x10, 0x10, 0x10, 0x10,
            //               0x10, 0x10, 0x10, 0x10,
            //               0x10, 0x10, 0x10, 0x10]
            // * IS:        [0x49, 0x36, 0x9A, 0xF7,
            //               0x17, 0x2C, 0x87, 0xB2,
            //               0x4B, 0x82, 0xF3, 0xBC,
            //               0xCE, 0x8B, 0x99, 0x19]
            //
            // When we we are just getting the first byte, ie:
            // * target_byte == 0x0F
            // * valid_pad == 0x01
            //
            // When we poison the previous block with 0x09, we get:
            // valid_padding(poison[0x0F] XOR 0x19)
            // valid_padding(0x09 XOR 0x19)
            // valid_padding(0x10) --> TRUE!
            // We hit the 0x10 padding just by luck... but waaay before
            // we actually should have. Now we have r = 0x09
            // and we will return 0x09 ^ 0x01 as the itermediate state...
            // which is actually 0x19!

            // To disambiguate, we poison one extra byte.
            // If this results in valid padding again, I can be sure
            // I did not hit jackpot by chance.
            // If this results in invalid padding, I did hit jackpot by
            // chance, and my padding was not by "valid_pad". I can keep trying.
            if poison_len < 15 {
                poisoned_bytes[16 - poison_len - 1] = 0x00;
                let poisoned = Ciphertext::cbc_from_prepended_iv(poisoned_bytes, Padding::PKCS7);
                if !oracle.valid_padding(&poisoned) {
                    continue;
                }
            }

            // remember:
            // r XOR IS(cur_block) <=>
            // r XOR valid_pad = IS(cur_block)
            return r ^ valid_pad;
        }

        // There **must** be a valid padding produced by bruteforce,
        // because there **is** at least one number that when
        // xored against r will produce a the valid padding byte
        unreachable!("No poison produced valid padding? Impossible.")
    }

    fn intermediate_state_to_plaintext(is: u8, prev_block: &[u8], target_byte: u8) -> u8 {
        // Once I have IS(cipherblock), I know that
        // IS(cipherblock) XOR prev_block = plain_text, so...
        is ^ prev_block[target_byte as usize]
    }

    pub fn attack() {
        let server = Server::new();
        let Ciphertext { bytes, mode, .. } = server.give_ciphertext();
        let iv = match mode {
            Mode::CBC { iv } => iv,
            _ => unreachable!("wrong mode"),
        };

        // All right. So now we have a random ciphertext from the server.
        // Rationale of the attack:
        // CBC will do C[i-1] XOR I[i] to produce P[i],
        // where C is ciphertext, I is intermediate state and P is plaintext.
        // So to produce block 2, CBC will do:
        // C[1] XOR I[2] = P[2]
        // Of course for block zero CBC will use IV as C[-1].
        //
        // Now note that I as an attacker control C[i] and that:
        // C[i-1] XOR I[i] = P[i] <=> C[i-1] XOR P[i] = I[i],
        // as XOR is its own inverse.
        //
        // Not note that a plaintext ending with 0x01 will have valid
        // PKCS7 padding. A plaintext ending with 0x02:0x02 will have valid
        // padding. And so on.
        //
        // So, joining these two ideas. Let's attack block number two.
        // C'[1] XOR I[2] will have valid padding only if
        // C'[1][15] XOR I[2][15] = 0x01
        // I can set C'1[15] to random numbers R until
        // C'[1][15] XOR I[2][15] = 0x01 <=> R XOR I[2][15] = 0x01
        // Now:
        // R XOR 0x01 = I[2][15]
        // Now I have the intermediate state ;)
        //
        // Once I have the intermediate state, all I have to do is
        // I[2][15] XOR C[2][15] which will leak the last byte of the ciphertext
        //
        // Once I have the last byte of plaintext and the last byte of intermediate
        // state, I can repeat the attack.
        //
        // Valid padding only if:
        // C'[1][14] XOR I[2][14] = 0x02 && C'[1][15] XOR I[2][15] == 0x02
        // To set my C'[15][15] XOR I[2][15] to 0x02, I can just use the previously
        // found intermediate state. I already know I[2][15].

        let mut iv_plus_blocks = Vec::with_capacity(16 + bytes.len() / 16);
        iv_plus_blocks.extend(&iv);
        iv_plus_blocks.extend(&bytes);
        let chunks = iv_plus_blocks.chunks_exact(16);
        let zipped = chunks.clone().zip(chunks.skip(1));
        let mut plaintext = Vec::new();

        for (prev, curr) in zipped {
            let mut intermediate_states = Vec::new();
            let mut inverted_plaintext = Vec::new();
            for i in (0..16).rev() {
                let intermediate_byte =
                    get_intermediate_state(&server, prev, curr, i, &intermediate_states);
                intermediate_states.push(intermediate_byte);
                let plain_byte = intermediate_state_to_plaintext(intermediate_byte, prev, i);
                println!(
                    "ASCII(0x{:2X}) -> {}",
                    plain_byte,
                    str::from_utf8(&[plain_byte]).unwrap_or_default(),
                );
                inverted_plaintext.push(plain_byte);
            }
            plaintext.extend(inverted_plaintext.iter().rev());
            let unpad_maybe = unpad(&Padding::PKCS7, &plaintext).unwrap_or(plaintext.clone());
            println!(
                "Partial plaintext: {}",
                str::from_utf8(&unpad_maybe).unwrap_or("can't interpret partial plaintext")
            );
        }

        let plain_as_b64 = unpad(&Padding::PKCS7, &plaintext).unwrap();
        let plain = base64::decode(str::from_utf8(&plain_as_b64).unwrap()).unwrap();

        println!("{}", str::from_utf8(&plain).unwrap());
    }
}
