use crypto::encoding::base64;
use crypto::frequency;
use crypto::random::{self, MersenneTwister, Random};
use crypto::symm::MersenneTwisterCipherText;
use crypto::symm::{padding::Padding, AESCiphertext, Mode};
use crypto::{bytes};
use std::{convert::TryInto, fs, str};
use std::{thread, time};

/// No. 17
#[allow(dead_code)]
pub fn cbc_padding_oracle() {
    for _ in 0..100 {
        cbc_padding_oracle::attack()
    }
}

/// No. 18
#[allow(dead_code)]
pub fn implement_ctr() {
    let raw_ciphertext =
        base64::decode("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
            .unwrap();
    let ciphertext =
        AESCiphertext::from_existing(raw_ciphertext, Mode::CTR { nonce: 0 }, Padding::None);
    let plaintext = ciphertext.decrypt("YELLOW_SUBMARINE".as_bytes());
    println!("{}", str::from_utf8(&plaintext).unwrap());
}

/// No. 19 / No. 20
#[allow(dead_code)]
pub fn break_fixed_nonce_ctr() {
    let key = random::get_random(16);

    // Encrypt all plaintexts badly, with a fixed zero nonce and
    // join them into a big vector of bytes
    let ciphertexts: Vec<AESCiphertext> = fs::read_to_string("./19.txt")
        .expect("file 19.txt not found")
        .lines()
        .map(|l| base64::decode(l).expect("could not decode b64"))
        .map(|decoded| AESCiphertext::new(&key, &decoded, Mode::CTR { nonce: 0 }, Padding::None))
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
    // I can use my statical analysis to find occurrences of common bytes
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
#[allow(dead_code)]
pub fn implement_mt19937_mersenne_twister() {
    println!("{}", random::MersenneTwister::new(5489).next().unwrap());
}

// No 22
// Write a routine that performs the following operation:
// Wait a random number of seconds between, I don't know, 40 and 1000.
// Seeds the RNG with the current Unix timestamp
// Waits a random number of seconds again.
// Returns the first 32 bit output of the RNG.
// XXX: apparently this is just bruteforcing taking advantage of the fact 
// that the timestamp is predictable... boring, see 23 for a better exercise.
use std::time::{SystemTime, UNIX_EPOCH};
#[allow(dead_code)]
pub fn crack_mt19937_seed() {
    let start = SystemTime::now();
    let seed = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");

    let timestamp: u32 = (seed.as_secs() % u32::MAX as u64) as u32;
    let mut mt = random::MersenneTwister::new(timestamp);
    let random_n = mt.get(1).unwrap()[0];

    let start = SystemTime::now();

    let first_seed_attempt = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    let mut seed_attempt: u32 = (first_seed_attempt.as_secs() % u32::MAX as u64) as u32;

    let mut my_mt = random::MersenneTwister::new(seed_attempt);

    while my_mt.get(1).unwrap()[0] != random_n {
        seed_attempt -= 1;
        my_mt = random::MersenneTwister::new(seed_attempt);
    }
    println!("[Hacked]: Seed was: {}", seed_attempt);
    assert_eq!(seed_attempt, timestamp);
}

// given a number generated by a standard mersenne twister, this will
// give the original state, used for 22/23/24
fn recover_state(output: usize) -> usize {
    let l = 18;
    // println!("[INVERTING] output: {}", output);

    // First reversal:
    // output = y3 ^ (y3 >> l).
    // keep in mind, the first (len - l) bits of output are exactly y3!
    // so we have this equation as well:
    // output >> l = y3 >> l
    // with that, and knowing a ^ b = c <=> a ^ c = b
    // output = y3 ^ (y3 >> l)
    // output = y3 ^ (output >> l)
    // y3 = output ^ (output >> l)
    let y3 = output ^ (output >> l);
    // println!("[INVERTING] y3 = output ^ (output >> l) = {}", y3);

    // Second reversal:
    // y3 = y2 ^ ((y2 << t) & c)
    // Note that the last t bits of y2 are equal to the
    // last t bits of y3, because (y2 << t)  leaves the last
    // t bits at zero, and then & with zero is zero and ^ with
    // zero is the input, y2.
    // so: y2 >> (size - t) = y3 >> (size - t)
    // T is 15, as seen below, so we have the last 15 bits of y2
    // for free. OK.
    // So:
    // Last 15 bits: y3[len-15..len] = y2[len-15..len]
    // Now, (y2 << t) is exactly y3[len-15..len]!
    // So, we have:
    // y3 = y2 ^ ((y3 << t) & c) =>
    // y2 = y3 ^ ((y3 << t) & c)
    // Note that this only works because the first bits of
    // c are 11! , this preserve the value in the first bits
    // of ((y3 << t) & c). If they were zero and ((y3 << t)) first
    // bits where 1, I would loose that 1 to the ether.
    let (t, c) = (15, 0xEFC60000);
    let y2 = y3 ^ ((y3 << t) & c);
    // println!("[INVERTING] y2 = y ^ ((y << t) & c) = {}", y2);

    // Third reversal:
    // y2 = y1 ^ ((y1 << s) & b)
    // All right now, first of all see that the last
    // s bits of y1 are the same as the last s bits of y2.
    // y1[len-s..len] = y2[len-s..len] =>
    // y2 << s = y1 << s
    // then we have:
    // y2 = y1 ^ ((y2 << s) & b)[-7:]
    // y1 = y2 ^ ((y2 << s) & b)[-7:]
    // Ok, but I missing the rest of y1 D:
    //
    // To recover every bit whilst just having access to 7,
    // we will mask b so as to only have data on the seven bits
    // we actually care about. This will cause the & operation
    // to only leave data on those seven bits. Then we will
    // move the mask and perform the operation again...
    let (s, b) = (7, 0x9D2C5680);
    let mask = 0x7f; // (0b01111111)

    // the last s bits are completely equal.
    // for the next 7 bits, xor (y2 << s) with the mask
    // (to leave everything else equal) to get the original seven
    // bits of y1
    // this gives us the last 14 bits...
    let masked_b = b & (mask << 7);
    let y1_last14 = y2 ^ ((y2 << s) & masked_b);

    let masked_b = b & (mask << 14);
    let y1_last_21 = y1_last14 ^ ((y1_last14 << s) & masked_b);

    let masked_b = b & (mask << 21);
    let y1_last_28 = y1_last_21 ^ ((y1_last_21 << s) & masked_b);

    let masked_b = b & (mask << 28);
    let y1 = y1_last_28 ^ ((y1_last_28 << s) & masked_b);

    // println!("[INVERTING] y1 = y ^ ((y << s) & b) = {}", y1);

    // Fourth reversal:
    // y1 = y ^ ((y >> u) & d) =>
    //
    // Easily we see that the first `u` bits will be the same
    // in y1 and y. For the next bits we will have to XOR again
    // against y >> u a couple of times.
    //
    // Similar to what we did in the third reversal.
    let (u, d) = (11, 0xFFFFFFFF);

    let y_first_eleven = y1 ^ ((y1 >> u) & d);
    let y_first_twenty_two = y_first_eleven ^ ((y_first_eleven >> u) & d);
    let y = y_first_twenty_two ^ ((y_first_twenty_two >> u) & d);
    y
}

// No 23. Skipped number 22 because it is basically a subset of 23: our
// untwist function recovers state.
#[allow(dead_code)]
pub fn clone_mt19937_from_output() {
    let seed: u32 = u32::from_be_bytes(random::get_random(4).try_into().unwrap());
    let mut original = random::MersenneTwister::new(seed);

    let random_bytes = original.get(1).unwrap();
    let mut untwisted = vec![];
    for random_byte in &random_bytes {
        untwisted.push(recover_state(*random_byte));
    }

    let mut predictor = random::MersenneTwister::new_from_twisted_state(untwisted);

    assert_eq!(predictor.next().unwrap(), random_bytes[0]);
    println!("[RESULT] success! correctly predicted the next output from MT");
}

// No 24
#[allow(dead_code)]
pub fn create_mt1993_stream_cipher_break_it() {
    let seed: u16 = u16::from_be_bytes(random::get_random(2).try_into().unwrap());
    let mut plaintext = random::get_random(random::in_range(0, 64));
    plaintext.extend("AAAAAAAAAAAAAA".as_bytes());
    let mt_cipher = MersenneTwisterCipherText::new(seed.into(), &plaintext);
    let ciphertext = mt_cipher.bytes;

    // OK, so we are _xoring_ with a fairly small key.
    // ciphertext = plain_text ^ mersenne_twister(seed)
    // because stream cipher i also know length of ciphertext
    // so i will just create all mersenne twister possible
    // with these two byte-keys and just try until I get a hit of AAA
    // at the end???

    let mut my_seed = 0;
    for i in 0..u16::MAX {
        let mut try_mt = MersenneTwister::new(i.into());
        for _ in 0..ciphertext.len() - 14 {
            try_mt.next();
        }
        let mut oks = 0;
        for i in ciphertext.len() - 14..ciphertext.len() {
            if (ciphertext[i] ^ try_mt.next().unwrap() as u8) != *"A".as_bytes().get(0).unwrap() {
                break;
            }
            oks += 1;
        }
        if oks == 14 {
            my_seed = i;
            break;
        }
    }
    println!("seed: {}", seed);
    println!("reverted: {}", my_seed);
}

#[allow(dead_code)]
mod cbc_padding_oracle {
    use crypto::encoding::base64;
    use crypto::random;
    use crypto::symm::padding::{unpad, Padding};
    use crypto::symm::{AESCiphertext, Mode};
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

        pub fn give_ciphertext(&self) -> AESCiphertext {
            let text = self.select_at_random();
            let iv = random::get_random(16);

            AESCiphertext::new(
                &self.key,
                &text.as_bytes(),
                Mode::CBC { iv },
                Padding::PKCS7,
            )
        }

        pub fn valid_padding(&self, ciphertext: &AESCiphertext) -> bool {
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
                AESCiphertext::cbc_from_prepended_iv(poisoned_bytes.clone(), Padding::PKCS7);

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
                let poisoned = AESCiphertext::cbc_from_prepended_iv(poisoned_bytes, Padding::PKCS7);
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
        let AESCiphertext { bytes, mode, .. } = server.give_ciphertext();
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
