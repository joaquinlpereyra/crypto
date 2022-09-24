use crypto::encoding::{base64, hex};
use crypto::symm::padding::Padding;
use crypto::symm::AESCiphertext;
use crypto::{random, symm};
use std::collections::HashMap;
use std::fs::read_to_string;
use std::str;
#[allow(dead_code)]
pub fn cbc_ecb_oracle() {
    /*
    This was one of the most interesting excercises so far and great example
    of a "chosen plain text attack".

    So let's recap what has been done. First, I must say that this is one
    of the most confusingly-worded challenges so far, and my search online
    confirmed that it was not only me.

    What the problem asks of you is to prepend and append a chosen plain text
    with random bytes from 5 to 10. Then you encrypt under an unknown key.
    The key part is that the input is DIFFERENT for each run, if not, the
    excercise becomes quite trivial and indeed IMPOSSIBLE if you happen
    to choose a small input.

    So the challenge is both in the coding and in figuring out an input
    which will leak information about the mode in which AES is operating in.

    The gist is that you have from five to ten bytes at the begginning, so
    you should write at least 11 "garbage" bytes at the begginning. Now you are
    at the second block, even if there were only five random bytes.

    Write 16 more of the SAME byte to fill a second block.

    So now we are either at the beginning of a third block (if there were
    only five bytes at the beginning) or somewhere in the middle of a third block.
    Make sure you fill this third block too! So 16 bytes more at least of the SAME byte.

    Now we are either at the beginning of the fourth or in the middle of the fourth
    AES block. Now we can just let go. We know we have one block with random data,
    two blocks with exclusively the same byte everywhere, and the fourth which will
    get the appendix and then padded.

    Now we have it easy: are the two blocks of the middle equal? Then, we are using ECB
    If not, we are using CBC.
     */

    fn encrypt_ecb_or_cbc(plain_text: &str) -> (Vec<u8>, String) {
        let random_key = random::get_random(16);
        let iv = random::get_random(16);
        let mut pretext = random::get_random(random::in_range(5, 10));
        let posttext = random::get_random(random::in_range(5, 10));

        pretext.extend(plain_text.as_bytes());
        pretext.extend(posttext);
        let mode = match random::flip_coin() {
            true => symm::Mode::CBC { iv },
            false => symm::Mode::ECB,
        };
        let mode_str = format!("{}", &mode);
        (
            AESCiphertext::new(&random_key, &pretext, mode, Padding::PKCS7).bytes,
            mode_str,
        )
    }

    fn is_ecb(cipher_text: &[u8]) -> bool {
        let mut blocks: HashMap<String, usize> = HashMap::new();

        // aes encrypts 16 bytes per block
        for block in cipher_text.chunks(16) {
            let hex = hex::to_string(&block);
            let counter = blocks.entry(hex).or_insert(0);
            *counter += 1
        }

        for (_, count) in blocks.iter() {
            if *count > 1 {
                return true;
            }
        }
        return false;
    }

    let plain_text = vec!["A"; 43];
    let plain_text = plain_text.join("");
    // io::stdin()
    //     .read_line(&mut plain_text)
    //     .expect("Failed to read line");
    let (encrypted, mode) = encrypt_ecb_or_cbc(&plain_text);
    if is_ecb(&encrypted) {
        println!("oracle says ECB!");
    } else {
        println!("oracle says CBC!");
    }
    println!("encryptor says {}", mode)
}

#[allow(dead_code)]
pub fn byte_at_a_time_ecb_decryption() {
    let random_key = random::get_random(16);

    let oracle = |user_input: &str| -> Vec<u8> {
        let secret_message = read_to_string("./12.txt").expect("could not read file");
        let secret_message = secret_message.replace('\n', "");
        let secret_message = base64::decode(&secret_message).unwrap();
        let secret_message = str::from_utf8(&secret_message).unwrap();

        let text_to_encrypt = user_input.to_owned() + secret_message;

        let cipher_text = AESCiphertext::new(
            &random_key,
            text_to_encrypt.as_bytes(),
            symm::Mode::ECB,
            Padding::PKCS7,
        );
        return cipher_text.bytes;
    };

    // This a nice solution which I coded after reading
    // https://medium.com/@__cpg/cryptopals-2-14-byte-at-a-time-ecb-decryption-e73c629f6801
    // My previous solution, which worked but was way less elegant, can be found in commit
    // 3552ffd911d781b46b04ab793facdfdb01ff4ccf
    // The main innovation this solution provides is that the "padding" length needs not
    // to be always less than the block size. I can pad for as many blocks I'm trying
    // to guess and work from there.

    let mut padding = "X".repeat(16);
    let mut plain_text = String::new();
    let start = (padding.len() / 16 - 1) * 16;
    let end = start + 16;

    loop {
        println!("{}", &plain_text);
        if padding.len() > 0 {
            padding = padding[1..].to_string()
        };

        // encrypt the payload with ajusted to leave space
        // the the amount of unknown bytes in the block
        let cipher_text = oracle(&padding);

        // grab the block we are actually interested in
        let cipher_block = &cipher_text[start..end];

        // bruteforce  the heck out of it
        let mut found = false;
        for n in 0..128 {
            let ascii = str::from_utf8(&[n]).unwrap().to_owned();
            let payload = padding.clone() + &plain_text + &ascii;
            let attempt = oracle(&payload);
            let attempt_block = &attempt[start..end];
            if attempt_block == cipher_block {
                plain_text += &ascii;
                found = true;
                break;
            }
        }
        if !found {
            // this should be the padding, but lets check
            // if this is the padding, it must be the U+0001 char
            match &plain_text.chars().last() {
                None => panic!("could not bruteforce even first char"),
                Some(c) if *c != '\u{0001}' => panic!("could not bruteforce!"),
                Some(_) => plain_text = plain_text[0..plain_text.len() - 2].to_string(),
            };
            break;
        }
    }
    println!("{}", &plain_text);
}

#[allow(dead_code)]
pub fn ecb_cut_and_paste() {
    #[derive(Debug)]
    struct User {
        email: String,
        uid: String,
        role: String,
    }

    impl User {
        pub fn new(data: &str) -> User {
            let (mut email, mut uid, mut role): (String, String, String) =
                ("".to_owned(), "".to_owned(), "".to_owned());
            let attrs = data.split('&').map(|a| a.split('='));
            for mut attr in attrs {
                let key = match attr.next() {
                    Some("") => continue,
                    Some(s) => s.to_owned(),
                    // It is surprisingly impossible as far as I can tell
                    // to get a zero-length iterator from a split.
                    None => unreachable!(),
                };
                let value = attr.next().map(|s| s.into()).unwrap_or(String::from(""));

                if let Some(_) = attr.next() {
                    panic!()
                }

                match key.as_ref() {
                    "email" => email = value,
                    "uid" => uid = value,
                    "role" => role = value,
                    _ => panic!(),
                }
            }

            User { email, uid, role }
        }

        pub fn as_cookie(&self) -> String {
            format!("email={}&uid={}&role={}", self.email, self.uid, self.role)
        }
    }

    let profile_for = |email: &str| -> String {
        // Sanitize, what could go wrong?
        let mut ok_email = email.replace("&", "");
        ok_email = ok_email.replace("=", "");

        let user = User {
            email: ok_email,
            uid: "10".into(),
            role: "user".into(),
        };
        user.as_cookie()
    };
    let random_key = random::get_random(16);

    // "email=EMAIL&uid=UID&role=ROLE"
    // we have to leave the string ADMIN in there somewhere
    // use an email so that the `email=EMAIL` part is exactly
    // 16 bytes, then set the rest to the string admin + padding
    let email = "1".repeat(10);
    let admin = "admin";
    let pad =
        &symm::padding::get_pad(&symm::padding::Padding::PKCS7, admin.as_bytes(), 16).unwrap();

    let email = (email.to_owned() + admin) + str::from_utf8(&pad).unwrap();
    let profile = profile_for(&email);
    let first_cipher_text = AESCiphertext::new(
        &random_key,
        profile.as_bytes(),
        symm::Mode::ECB,
        Padding::PKCS7,
    );

    // now we have to leave the USER be by itself, so we can replace it
    // with the second block of the first ciphertext
    // without an email we have 23 bytes
    // "email=&uid=10&role=user"
    // we need to push it to exactly 36 bytes (so only the user word is in the third block)
    let profile = profile_for(&"1".repeat(13));
    let second_cipher_text = AESCiphertext::new(
        &random_key,
        profile.as_bytes(),
        symm::Mode::ECB,
        Padding::PKCS7,
    );

    // the second block of the first cipher text
    let admin = &first_cipher_text.bytes[16..32];
    let mut copy_pasted_buf = Vec::new();
    copy_pasted_buf.extend_from_slice(&second_cipher_text.bytes[0..32]);
    copy_pasted_buf.extend_from_slice(admin);
    let copy_pasted =
        AESCiphertext::from_existing(copy_pasted_buf, symm::Mode::ECB, Padding::PKCS7);
    let decrypted = copy_pasted.decrypt(&random_key);
    let decoded = User::new(str::from_utf8(&decrypted).unwrap());
    println!("{:?}", decoded)
}

#[allow(dead_code)]
pub fn byte_at_a_time_ecb_decryption_hard() {
    let random_key = random::get_random(16);
    let random_number = random::in_range(0, 32);
    let random_prefix = random::get_random(random_number);

    let oracle = |user_input: &str| -> Vec<u8> {
        let secret_message = read_to_string("./12.txt").expect("could not read file");
        let secret_message = secret_message.replace('\n', "");
        let secret_message = base64::decode(&secret_message).unwrap();
        let secret_message = str::from_utf8(&secret_message).unwrap();

        let text_to_encrypt = user_input.to_owned() + secret_message;
        let mut plaintext = random_prefix.clone();
        plaintext.extend_from_slice(text_to_encrypt.as_bytes());

        let cipher_text =
            AESCiphertext::new(&random_key, &plaintext, symm::Mode::ECB, Padding::PKCS7);
        return cipher_text.bytes;
    };

    // The only real challenge here is separating the target bytes from
    // the prefix. Remeber:
    // Oracle(INPUT) -> E(RANDOM | INPUT | TARGET, K).
    // If my INPUT is 32 bytes long, now matter how big or small the RANDOM
    // is, I can assure that my input will occupy by itself AT LEAST a block.
    //
    // Now this is ECB. If I continue sending the same ciphertext all blocks will
    // have that same ciphertext.
    //
    // If I send 48 (!!!) bytes, I can assure that at least two blocks will be the same.
    // The padding ocuppies at least as many blocks as where those two are.
    //
    // RANDOM BLOCK * N |
    // (RANDOM+INPUT) BLOCK |
    // INPUT BLOCK |
    // INPUT BLOCK |
    // (INPUT + TARGET) BLOCK |
    // TARGET BLOCK * M
    //
    // Once I know N, then I need to know how many random bytes are extra. I can send 47
    // bytes. If my two pure input blocks are still there, it means there is at least
    // one padding byte. Repeat until I know exactly how many padding bytes are ther.
    let get_repeated_in_ecb = |ciphertext: &[u8]| -> Option<(Vec<u8>, usize)> {
        let mut blocks: HashMap<&[u8], usize> = HashMap::new();
        for block in ciphertext.chunks(16) {
            let counter = blocks.entry(&block).or_insert(0);
            *counter += 1
        }
        let repeated: HashMap<&[u8], usize> = blocks
            .iter()
            .filter(|&(_, &v)| v != 1)
            .map(|(&k, &v)| (k, v))
            .collect();
        let three = repeated.iter().find(|&(_, &v)| v == 3 as usize);
        let two = repeated.iter().find(|&(_, &v)| v == 2 as usize);
        if let Some((k, &n)) = three {
            return Some((k.to_vec(), n));
        };
        if let Some((k, &n)) = two {
            return Some((k.to_vec(), n));
        };
        None
    };

    let padding = "X".repeat(48);
    let mut oracled = oracle(&padding);
    let (repeated_block, mut times) = get_repeated_in_ecb(&oracled).unwrap();
    let position_of_repeated = crypto::position_of_block_in(&oracled, &repeated_block);

    // Now the fun starts. I need to make my input block appear only one time.
    // Then I know I have figured out how many random bytes are there mixing
    // with my input. I will add the possible random byte blocks of the beginning
    // later
    let mut random_size = 0;
    while times != 1 {
        random_size += 1;
        let padding = "X".repeat(48 - random_size);
        oracled = oracle(&padding);
        times = crypto::count_block_in_ciphertext(&oracled, &repeated_block);
    }

    // Make note that I had to try one padding LESS than random
    // to see if the blocks changed, so random_size is actually one byte smaller
    // than calculated
    random_size -= 1;

    // Add the random bytes which ocuppied whole blocks at the beginning of the
    // ciphertext
    random_size += (position_of_repeated - 1) * 16;

    // There, we know the padding size now. The rest is like challenge 12.
    let pad_random = 16 - random_size % 16;
    // Set the padding to enough as to separate the random bytes in their own
    // blocks. 16 extra to start the bruteforce ;)
    let mut padding = "X".repeat(pad_random + 16);
    let mut plain_text = String::new();
    let start = ((padding.len() + random_size) / 16 - 1) * 16;
    let end = start + 16;

    loop {
        println!("{}", &plain_text);
        if padding.len() > 0 {
            padding = padding[1..].to_string()
        };

        // encrypt the payload with ajusted to leave space
        // the the amount of unknown bytes in the block
        let cipher_text = oracle(&padding);

        // grab the block we are actually interested in
        let cipher_block = &cipher_text[start..end];

        // bruteforce  the heck out of it
        let mut found = false;
        for n in 0..128 {
            let ascii = str::from_utf8(&[n]).unwrap().to_owned();
            let payload = padding.clone() + &plain_text + &ascii;
            let attempt = oracle(&payload);
            let attempt_block = &attempt[start..end];
            if attempt_block == cipher_block {
                plain_text += &ascii;
                found = true;
                break;
            }
        }
        if !found {
            // this should be the padding, but lets check
            // if this is the padding, it must be the U+0001 char
            match &plain_text.chars().last() {
                None => panic!("could not bruteforce even first char"),
                Some(c) if *c != '\u{0001}' => panic!("could not bruteforce!"),
                Some(_) => plain_text = plain_text[0..plain_text.len() - 2].to_string(),
            };
            break;
        }
    }
    println!("{}", &plain_text);
}

#[allow(dead_code)]
pub fn detect_and_strip_pkcs7() {
    // This one is easy because I basically already have it implemented
    let strip_pkcs7 = |input: &[u8]| -> Vec<u8> {
        symm::padding::unpad(&symm::padding::Padding::PKCS7, input).unwrap()
    };

    let stripped = strip_pkcs7("ICE ICE BABY\x04\x04\x04\x04".as_bytes());
    println!("{}", str::from_utf8(&stripped).unwrap());
}

#[allow(dead_code)]
pub fn cbc_bitflipping_attacks() {
    // Final string if input is "vinito" will look like this:
    // comment1=cooking%20MCs;userdata=vinito;comment2=%20like%20a%20pound%20of%20bacon;
    let random_key = random::get_random(16);
    let iv = random::get_random(16);

    let encrypt_cbc = |s: &str| -> Vec<u8> {
        let mut ok_input = s.replace(";", "");
        ok_input = ok_input.replace("=", "");

        let first_chunk = "comment1=cooking%20MCs;userdata=".to_owned();
        let last_chunk = ";comment2=%20like%20a%20pound%20of%20bacon";

        let plain_text = first_chunk + &ok_input + last_chunk;
        let cipher_text = AESCiphertext::new(
            &random_key,
            plain_text.as_bytes(),
            symm::Mode::CBC { iv: iv.clone() },
            Padding::PKCS7,
        );
        return cipher_text.bytes;
    };

    let decrypt_and_check_admin = |cipher_text: &[u8]| -> bool {
        let plain = symm::aes_decrypt(
            &random_key,
            &cipher_text,
            symm::Mode::CBC { iv: iv.clone() },
            Padding::PKCS7,
        );
        return str::from_utf8(&plain)
            .and_then(|s: &str| Ok(s.contains(";admin=true")))
            .unwrap_or_default();
    };

    // Now, the objective is to get to put an `;admin=true` inside
    // the ciphertext. This should not be possible, because
    // the encrypt_cbc function will eat up both ; and =, so the
    // best I can do is endup with something like admintrue
    //
    // I will somehow have to craft a ciphertext that decrypts to that
    // though.
    // Let's do this programatically, although it would probably first
    // it would be easier to do it interatively.

    // This is my best attempt, I know this should fail though
    let cipher_attempt = encrypt_cbc(";admin=true");
    println!("{:?}", cipher_attempt);
    println!("{}", hex::to_string(&cipher_attempt));
    assert!(!decrypt_and_check_admin(&cipher_attempt));

    // OK, so here's the strategy. When ECB decrypts, it does:
    // XOR(decripted_block, last_ciphertext_block)
    // So it XORs with the ciphertext! I can abuse this to change
    // the actual plaintext.
    //
    // So I will set my input to be a bunch of filling
    // + (close to ;)admin(close to =)true
    //
    // Then I can modify the ciphertext of my filling.
    // That part of the ciphertext will decrypt to garbage, but then
    // it will get xored with the part the encrypted the
    // (close to;)admin(close to =)true.
    //
    // Of course when I say (close to ;) I mean a character
    // that is close to it in the ASCII table.
    //
    // ASCII(;) == 0x3b == 0b1110 1100
    // ASCII(=) == 0x3d == 0b1111 0100
    //
    // I will start by introducing a ;, I will be happy with that
    // So if instead of ; I will something close to it
    // ASCII(:) == 0b1110 1000
    let mut cipher_break = encrypt_cbc("aa:admin\x3ctrue");

    // One kinda needs to know where the things is putting the input
    // at least roughly... In this case we can decrypt the output so that's easy
    //
    // So, why XOR the first block with 1 works?
    // Because this will get xored with the almost-plaintext before producing the final text
    // when decrypting in ECB
    //
    // In practice, this means that I will keep all of the XOR except for the last bit,
    // which will get flipped (hence, CBC bit flipping)
    //
    // When flipping before xoring, we will cause the XOR to produce a byte exactly
    // one bit bigger. Why?
    //
    // Because we know what's the input. We know that CIPHER_BLOCK_1[18] XOR PLAIN_TEXT_2[18]
    // (where CIPHER_BLOCK_1 referes to CIPHER_BLOCK number 1 of course and [18] an example position)
    // equals ":", which is 0b1110 1100. This means that both have the same bit at the last position
    // By flipping one, we cause it return 1 when xoring, thus increasing it one bit.
    //
    // If our input ended with one, 0b1110 1101, for example, we would know that CIPHER_BLOCK_1[X]
    // XOR PLAIN_TEXT_2[X] are different. When flipping one, we would cause them to be the same.
    // Thus, we would DECREASE one bit!
    cipher_break[18] ^= 0b0000_0001;
    cipher_break[24] ^= 0b0000_0001;
    println!("{:?}", &cipher_break);
    let plain = symm::aes_decrypt(
        &random_key,
        &cipher_break,
        symm::Mode::CBC { iv: iv.clone() },
        Padding::PKCS7,
    );
    println!("{:?}", &plain);
    println!("{}", hex::to_string(&plain));
    unsafe {
        println!("{}", str::from_utf8_unchecked(&plain[16..]));
    }
    println!("{}", str::from_utf8(&plain[16..]).unwrap());
}
