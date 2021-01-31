use crypto::encoding::{base64, cookies, hex};
use crypto::frequency;
use crypto::symm::padding::{self, Padding};
use crypto::{bytes, random, symm};
use std::collections::{BTreeMap, HashMap};
use std::fs::{read_to_string, File};
use std::io::{self, BufRead, BufReader, Read};
use std::str;

fn main() {
    // xor_cypher();
    // xor_file();
    // xor_encrypt();
    // decrypt_yellow_submarine();
    // find_ecb();
    // implement_pkcs7();
    // decrypt_with_cbc();
    // cbc_ecb_oracle();
    // byte_at_a_time_ecb_decryption();
    // ecb_cut_and_paste();
    // byte_at_a_time_ecb_decryption_hard();
    detect_and_strip_pkcs7();
}

#[allow(dead_code)]
fn xor_cypher() {
    // You have access to an encrypted message.
    // You know it has been xored against a single character
    // Find it.
    let cypher_text = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let encrypted_as_hex = hex::from_string(&cypher_text).unwrap();

    // All ASCII characters can fill 7 bits: from zero to 127.
    for i in 0..127 {
        let xored = bytes::repeating_xor(&encrypted_as_hex, &[i as u8]);
        let text = match bytes::to_string(&xored) {
            Some(text) => text,
            None => continue,
        };
        let score = frequency::analysis(&text);
        if score > 0.6 {
            println!("{}, key: {}", text, i);
        }
    }
}

#[allow(dead_code)]
fn xor_file() {
    // There's one line in the file which has been encrypted against a single character.
    // Find the line and the character.

    let file = match File::open("./6.txt") {
        Ok(file) => file,
        Err(_) => panic!("file not found!"),
    };
    let buffer = BufReader::new(file);
    // a lesson here:
    // at first, I spawned a thread every line.
    // target/release/crypto  0,24s user 0,02s system 385% cpu 0,066 total
    // then, i removed the threads...
    // target/release/crypto  0,03s user 0,00s system 99% cpu 0,032 total
    // remember kids. threads are not free!
    for encrypted_line in buffer.lines().map(|l| l.unwrap()) {
        let encrypted_bytes = hex::from_string(&encrypted_line).unwrap();
        for i in 0..127 {
            let xored = bytes::repeating_xor(&encrypted_bytes, &[i as u8]);
            let text = match bytes::to_string(&xored) {
                Some(text) => text,
                None => continue, // most probably our secret is utf8, at least?
            };
            let score = frequency::analysis(&text);
            if score > 0.7 {
                println!("score: {}, text: {}, key: {}", score, text, i);
            }
        }
    }
}

#[allow(dead_code)]
fn xor_encrypt() {
    // Encrypt the plain text using repeating-key XOR
    // with the key 'ICE'
    let plain_text = "Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal";
    let cypher_text = hex::to_string(&bytes::repeating_xor(
        &plain_text.as_bytes(),
        &['I' as u8, 'C' as u8, 'E' as u8],
    ));
    println!("0x{}", cypher_text);
}

#[allow(dead_code)]
fn decrypt_yellow_submarine() {
    // https://cryptopals.com/sets/1/challenges/7

    let cipher_text = read_to_string("./7.txt").expect("could not read file");
    let cipher_text = cipher_text.replace('\n', "");
    let cipher_text = base64::decode(&cipher_text).unwrap();
    let cipher_key = "YELLOW SUBMARINE".as_bytes();

    let plain = symm::decrypt(&cipher_key, &cipher_text, symm::Mode::ECB, Padding::None);
    let plain_ascii = str::from_utf8(&plain).unwrap();
    print!("{}", plain_ascii);
}

#[allow(dead_code)]
fn find_ecb() {
    // https://cryptopals.com/sets/1/challenges/8
    // In this file are a bunch of hex-encoded ciphertexts.
    // One of them has been encrypted with ECB.
    // Detect it.
    let mut blocks: HashMap<String, usize> = HashMap::new();

    let cipher_texts = read_to_string("./8.txt").expect("could not read file");
    let cipher_texts = cipher_texts.replace('\n', "");

    let bytes = hex::from_string(&cipher_texts).unwrap();

    // aes encrypts 16 bytes per block
    for block in bytes.chunks(16) {
        let hex = hex::to_string(&block);
        let counter = blocks.entry(hex).or_insert(0);
        *counter += 1
    }
    blocks
        .iter()
        .filter(|&(_, v)| *v != 1)
        .map(|(k, v)| println!("{}: {}", k, v))
        .collect()
}

#[allow(dead_code)]
fn implement_pkcs7() {
    let input = "YELLOW SUBMARINE";
    let padded = match padding::get_pad(padding::Padding::PKCS7, input.as_bytes(), 20) {
        Some(bytes) => bytes,
        None => panic!("could not pad? why?"),
    };
    println!("{:?}", str::from_utf8(&padded));
}

#[allow(dead_code)]
fn decrypt_with_cbc() {
    let key = "YELLOW SUBMARINE".as_bytes();
    let iv = vec![0; 16];
    let cipher_text = read_to_string("./10.txt").expect("could not read file");
    let cipher_text = cipher_text.replace("\n", "");
    let cipher_text = base64::decode(&cipher_text).unwrap();
    let cbc = symm::Mode::CBC { iv };
    let plain = symm::decrypt(&key, &cipher_text, cbc, Padding::None);
    let plain_str = str::from_utf8(&plain).unwrap();
    println!("{}", plain_str);
}

#[allow(dead_code)]
fn cbc_ecb_oracle() {
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
            symm::encrypt(&random_key, &pretext, mode, Padding::PKCS7),
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
fn byte_at_a_time_ecb_decryption() {
    let random_key = random::get_random(16);

    let oracle = |user_input: &str| -> Vec<u8> {
        let secret_message = read_to_string("./12.txt").expect("could not read file");
        let secret_message = secret_message.replace('\n', "");
        let secret_message = base64::decode(&secret_message).unwrap();
        let secret_message = str::from_utf8(&secret_message).unwrap();

        let text_to_encrypt = user_input.to_owned() + secret_message;

        let cipher_text = symm::encrypt(
            &random_key.clone(),
            text_to_encrypt.as_bytes(),
            symm::Mode::ECB,
            Padding::PKCS7,
        );
        return cipher_text;
    };

    // This a nice solution which I coded after reading
    // https://medium.com/@__cpg/cryptopals-2-14-byte-at-a-time-ecb-decryption-e73c629f6801
    // My previous solution, which worked but was way less elegant, can be found in commit
    // 3552ffd911d781b46b04ab793facdfdb01ff4ccf
    // The main innovation this solution provides is that the "padding" length needs not
    // to be always less than the block size. I can pad for as many blocks I'm trying
    // to guess and work from there.

    let secret = oracle("");
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
fn ecb_cut_and_paste() {
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
    let pad = &symm::padding::get_pad(symm::padding::Padding::PKCS7, admin.as_bytes(), 16).unwrap();

    let email = (email.to_owned() + admin) + str::from_utf8(&pad).unwrap();
    let profile = profile_for(&email);
    let first_cipher_text = symm::encrypt(
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
    let second_cipher_text = symm::encrypt(
        &random_key,
        profile.as_bytes(),
        symm::Mode::ECB,
        Padding::PKCS7,
    );

    // the second block of the first cipher text
    let admin = &first_cipher_text[16..32];
    let mut copy_pasted = Vec::new();
    copy_pasted.extend_from_slice(&second_cipher_text[0..32]);
    copy_pasted.extend_from_slice(admin);
    let decrypted = symm::decrypt(&random_key, &copy_pasted, symm::Mode::ECB, Padding::PKCS7);
    let decoded = User::new(str::from_utf8(&decrypted).unwrap());
    println!("{:?}", decoded)
}

#[allow(dead_code)]
fn byte_at_a_time_ecb_decryption_hard() {
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

        let cipher_text = symm::encrypt(
            &random_key.clone(),
            &plaintext,
            symm::Mode::ECB,
            Padding::PKCS7,
        );
        return cipher_text;
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
fn detect_and_strip_pkcs7() {
    // This one is easy because I basically already have it implemented
    //
    let strip_pkcs7 = |input: &[u8]| -> Vec<u8> {
        symm::padding::unpad(symm::padding::Padding::PKCS7, input).unwrap()
    };

    let stripped = strip_pkcs7("ICE ICE BABY\x04\x04\x04\x04".as_bytes());
    println!("{}", str::from_utf8(&stripped).unwrap());
}
