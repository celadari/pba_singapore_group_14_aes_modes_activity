//! In Module 1, we discussed Block ciphers like AES. Block ciphers have a fixed length input.
//! Real wold data that we wish to encrypt _may_ be exactly the right length, but is probably not.
//! When your data is too short, you can simply pad it up to the correct length.
//! When your data is too long, you have some options.
//!
//! In this exercise, we will explore a few of the common ways that large pieces of data can be
//! broken up and combined in order to encrypt it with a fixed-length block cipher.
//!
//! WARNING: ECB MODE IS NOT SECURE.
//! Seriously, ECB is NOT secure. Don't use it irl. We are implementing it here to understand _why_
//! it is not secure and make the point that the most straight-forward approach isn't always the
//! best, and can sometimes be trivially broken.

use aes::{
    cipher,
    cipher::{generic_array::GenericArray, BlockCipher, BlockDecrypt, BlockEncrypt, KeyInit},
    Aes128,
};
use rand::Rng;

///We're using AES 128 which has 16-byte (128 bit) blocks.
const BLOCK_SIZE: usize = 16;

fn main() {
    todo!("Maybe this should be a library crate. TBD");
}

/// Simple AES encryption
/// Helper function to make the core AES block cipher easier to understand.
fn aes_encrypt(data: [u8; BLOCK_SIZE], key: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    // Convert the inputs to the necessary data type
    let mut block = GenericArray::from(data);
    let key = GenericArray::from(*key);

    let cipher = Aes128::new(&key);

    cipher.encrypt_block(&mut block);

    block.into()
}

/// Simple AES encryption
/// Helper function to make the core AES block cipher easier to understand.
fn aes_decrypt(data: [u8; BLOCK_SIZE], key: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    // Convert the inputs to the necessary data type
    let mut block = GenericArray::from(data);
    let key = GenericArray::from(*key);

    let cipher = Aes128::new(&key);

    cipher.decrypt_block(&mut block);

    block.into()
}

/// Before we can begin encrypting our raw data, we need it to be a multiple of the
/// block length which is 16 bytes (128 bits) in AES128.
///
/// The padding algorithm here is actually not trivial. The trouble is that if we just
/// naively throw a bunch of zeros on the end, there is no way to know, later, whether
/// those zeros are padding, or part of the message, or some of each.
///
/// The scheme works like this. If the data is not a multiple of the block length,  we
/// compute how many pad bytes we need, and then write that number into the last several bytes.
/// Later we look at the last byte, and remove that number of bytes.
///
/// But if the data _is_ a multiple of the block length, then we have a problem. We don't want
/// to later look at the last byte and remove part of the data. Instead, in this case, we add
/// another entire block containing the block length in each byte. In our case,
/// [16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16]
fn pad(mut data: Vec<u8>) -> Vec<u8> {
    // When twe have a multiple the second term is 0
    let number_pad_bytes = BLOCK_SIZE - data.len() % BLOCK_SIZE;

    for _ in 0..number_pad_bytes {
        data.push(number_pad_bytes as u8);
    }

    data
}

/// Groups the data into BLOCK_SIZE blocks. Assumes the data is already
/// a multiple of the block size. If this is not the case, call `pad` first.
fn group(data: Vec<u8>) -> Vec<[u8; BLOCK_SIZE]> {
    let mut blocks = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let mut block: [u8; BLOCK_SIZE] = Default::default();
        block.copy_from_slice(&data[i..i + BLOCK_SIZE]);
        blocks.push(block);

        i += BLOCK_SIZE;
    }

    blocks
}

/// Does the opposite of the group function
fn un_group(blocks: Vec<[u8; BLOCK_SIZE]>) -> Vec<u8> {
    let mut data = Vec::new();

    for block in blocks {
        data.extend_from_slice(&block);
    }

    data
}

/// Does the opposite of the pad function.
fn un_pad(data: Vec<u8>) -> Vec<u8> {
    let pad_data_len = data.len();
    if (pad_data_len == 0) {
        return data;
    }
    let pad_amount = *data.get(pad_data_len - 1).unwrap();
    data[..pad_data_len - usize::from(pad_amount)].to_vec()
}

/// The first mode we will implement is the Electronic Code Book, or ECB mode.
/// Warning: THIS MODE IS NOT SECURE!!!!
///
/// This is probably the first thing you think of when considering how to encrypt
/// large data. In this mode we simply encrypt each block of data under the same key.
/// One good thing about this mode is that it is parallelizable. But to see why it is
/// insecure look at: https://www.ubiqsecurity.com/wp-content/uploads/2022/02/ECB2.png
fn ecb_encrypt(plain_text: Vec<u8>, key: [u8; 16]) -> Vec<u8> {
    // 1. Get and encrypt blocks
    let blocks = group(pad(plain_text));
    let mut data = vec![];

    for block in blocks {
        let encrypted = aes_encrypt(block, &key);
        data.extend_from_slice(&encrypted)
    }
    return data;
}

/// Opposite of ecb_encrypt.
fn ecb_decrypt(cipher_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    // 1. Get and block encrypted
    let blocks = group(cipher_text);
    let mut message = vec![];
    for block in blocks {
        let data = aes_decrypt(block, &key);
        message.extend_from_slice(&data);
    }
    return un_pad(message);
}

fn xor(x: [u8; BLOCK_SIZE], y: [u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    let mut xored: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];

    for (i, (&x, &y)) in x.iter().zip(y.iter()).enumerate() {
        xored[i] = x ^ y;
    }
    xored
}

/// The next mode, which you can implement on your own is cipherblock chaining.
/// This mode actually is secure, and it often used in real world applications.
///
/// In this mode, the ciphertext from the first block is XORed with the
/// plaintext of the next block before it is encrypted.
///
/// For more information, and a very clear diagram,
/// see https://de.wikipedia.org/wiki/Cipher_Block_Chaining_Mode
///
/// You will need to generate a random initialization vector (IV) to encrypt the
/// very first block because it doesn't have a previous block. Typically this IV
/// is inserted as the first block of ciphertext.
fn cbc_encrypt(plain_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    // Remember to generate a random initialization vector for the first block.

    use rand::thread_rng;
    use rand::{rngs::ThreadRng, Rng};

    fn generate_random_iv(rng: &mut ThreadRng) -> [u8; BLOCK_SIZE] {
        let mut iv = [0u8; BLOCK_SIZE];
        rng.fill(&mut iv);
        iv
    }

    let mut rng = thread_rng();

    // Generate a random IV
    let iv = generate_random_iv(&mut rng);

    // Pad the data
    let plain_text_padded = pad(plain_text);

    // Group the data into blocks
    let groups = group(plain_text_padded);

    let mut current_iv = iv;
    let mut result: Vec<u8> = current_iv.to_vec();

    for group in groups {
        // xor group with IV
        let mut xored: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];
        for (i, (&x, &y)) in current_iv.iter().zip(group.iter()).enumerate() {
            xored[i] = x ^ y;
        }

        // encrypt the xor'd group
        let current_cipher_text = aes_encrypt(xored, &key);
        println!("encrypted data: {:?}", current_cipher_text);

        // use the cipher text as the new IV
        current_iv = current_cipher_text;

        result.extend(current_cipher_text.iter());
    }

    result
}

fn cbc_decrypt(cipher_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    // 1. get iv
    let mut groups = group(cipher_text);

    let mut IV = groups.first().unwrap().clone();
    groups.remove(0);
    let mut message: Vec<u8> = vec![];
    // 2. get groups
    for group in groups {
        let new_group = group.clone();
        // 3. decrypt
        let data = aes_decrypt(group, &key);

        println!("encrypted data: {:?}", data);

        // 4. XOR with IV
        let decrypt_data = xor(data, IV);
        message.extend(decrypt_data.iter());
        IV = new_group;
    }

    message
}

/// Another mode which you can implement on your own is counter mode.
/// This mode is secure as well, and is used in real world applications.
/// It allows parallelized encryption and decryption, as well as random read access when decrypting.
///
/// In this mode, there is an index for each block being encrypted (the "counter"), as well as a random nonce.
/// For a 128-bit cipher, the nonce is 64 bits long.
///
/// For the ith block, the 128-bit value V of `nonce | counter` is constructed, where | denotes
/// concatenation. Then, V is encrypted with the key using ECB mode. Finally, the encrypted V is
/// XOR'd with the plaintext to produce the ciphertext.
///
/// A very clear diagram is present here:
/// https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)
///
/// Once again, you will need to generate a random nonce which is 64 bits long. This should be
/// inserted as the first block of the ciphertext.
fn ctr_encrypt(plain_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    // Remember to generate a random nonce
    let mut rng = rand::thread_rng();
    let mut nonce: [u8; 8] = Default::default();
    for i in 0..8 {
        nonce[i] = rng.gen();
    }

    let plain_text_blocks = group(pad(plain_text));
    let nb_blocks = plain_text_blocks.len();

    let counters = (0..nb_blocks - 1).into_iter();

    let ciphered_blocks = counters
        .zip(plain_text_blocks)
        .map(|(counter_number, plain_text_block)| {
            let counter_bytes: [u8; 8] = counter_number.to_le_bytes();
            let mut v: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];
            v[0..8].copy_from_slice(&nonce);
            v[8..16].copy_from_slice(&counter_bytes);
            xor_arrays(aes_encrypt(v, &key), plain_text_block)
        })
        .collect::<Vec<[u8; BLOCK_SIZE]>>();

    // // Insert the nonce as the first block of the ciphered text
    let mut result = Vec::with_capacity(ciphered_blocks.len() * BLOCK_SIZE + 8);
    result.extend_from_slice(&nonce);
    for block in ciphered_blocks {
        result.extend_from_slice(&block);
    }
    result
}

fn xor_arrays(array1: [u8; BLOCK_SIZE], array2: [u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    let mut xor_result: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        xor_result[i] = array1[i] ^ array2[i];
    }
    xor_result
}

fn ctr_decrypt(cipher_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    // Extract the nonce from the first 8 bytes of the ciphertext
    let nonce: [u8; 8] = {
        let mut nonce = [0u8; 8];
        nonce.copy_from_slice(&cipher_text[0..8]);
        nonce
    };

    // Extract the remaining ciphertext blocks
    let ciphered_text = cipher_text[8..].to_vec();
    let ciphered_blocks = group(ciphered_text);
    let nb_blocks = ciphered_blocks.len();

    let counters = (0..nb_blocks - 1).into_iter();

    let plain_text_blocks = counters
        .zip(ciphered_blocks)
        .map(|(counter_number, ciphered_block)| {
            let counter_bytes: [u8; 8] = counter_number.to_le_bytes();
            let mut v: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];
            v[0..8].copy_from_slice(&nonce);
            v[8..16].copy_from_slice(&counter_bytes);
            xor_arrays(aes_encrypt(v, &key), ciphered_block)
        })
        .collect::<Vec<[u8; BLOCK_SIZE]>>();

    un_pad(un_group(plain_text_blocks))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ungroup_test1() {
        let blocks1 = vec![
            [
                1u8, 3u8, 4u8, 76u8, 45u8, 90u8, 124u8, 200u8, 11u8, 22u8, 33u8, 44u8, 55u8, 66u8,
                77u8, 88u8,
            ],
            [
                2u8, 4u8, 5u8, 77u8, 46u8, 91u8, 125u8, 201u8, 12u8, 23u8, 34u8, 45u8, 56u8, 67u8,
                78u8, 89u8,
            ],
            [
                3u8, 5u8, 6u8, 78u8, 47u8, 92u8, 126u8, 202u8, 13u8, 24u8, 35u8, 46u8, 57u8, 68u8,
                79u8, 90u8,
            ],
            [
                4u8, 6u8, 7u8, 79u8, 48u8, 93u8, 127u8, 203u8, 14u8, 25u8, 36u8, 47u8, 58u8, 69u8,
                80u8, 91u8,
            ],
            [
                5u8, 7u8, 8u8, 80u8, 49u8, 94u8, 128u8, 204u8, 15u8, 26u8, 37u8, 48u8, 59u8, 70u8,
                81u8, 92u8,
            ],
            [
                6u8, 8u8, 9u8, 81u8, 50u8, 95u8, 129u8, 205u8, 16u8, 27u8, 38u8, 49u8, 60u8, 71u8,
                82u8, 93u8,
            ],
            [
                7u8, 9u8, 10u8, 82u8, 12u8, 12u8, 12u8, 12u8, 12u8, 12u8, 12u8, 12u8, 12u8, 12u8,
                12u8, 12u8,
            ],
        ];
        let expected_data1 = vec![
            1u8, 3u8, 4u8, 76u8, 45u8, 90u8, 124u8, 200u8, 11u8, 22u8, 33u8, 44u8, 55u8, 66u8,
            77u8, 88u8, 2u8, 4u8, 5u8, 77u8, 46u8, 91u8, 125u8, 201u8, 12u8, 23u8, 34u8, 45u8,
            56u8, 67u8, 78u8, 89u8, 3u8, 5u8, 6u8, 78u8, 47u8, 92u8, 126u8, 202u8, 13u8, 24u8,
            35u8, 46u8, 57u8, 68u8, 79u8, 90u8, 4u8, 6u8, 7u8, 79u8, 48u8, 93u8, 127u8, 203u8,
            14u8, 25u8, 36u8, 47u8, 58u8, 69u8, 80u8, 91u8, 5u8, 7u8, 8u8, 80u8, 49u8, 94u8, 128u8,
            204u8, 15u8, 26u8, 37u8, 48u8, 59u8, 70u8, 81u8, 92u8, 6u8, 8u8, 9u8, 81u8, 50u8, 95u8,
            129u8, 205u8, 16u8, 27u8, 38u8, 49u8, 60u8, 71u8, 82u8, 93u8, 7u8, 9u8, 10u8, 82u8,
            12u8, 12u8, 12u8, 12u8, 12u8, 12u8, 12u8, 12u8, 12u8, 12u8, 12u8, 12u8,
        ];
        let data1 = un_group(blocks1);

        assert_eq!(data1, expected_data1)
    }

    #[test]
    fn ungroup_test2() {
        let blocks2 = vec![
            [
                1u8, 3u8, 4u8, 76u8, 45u8, 90u8, 124u8, 200u8, 11u8, 22u8, 33u8, 44u8, 55u8, 66u8,
                77u8, 88u8,
            ],
            [
                2u8, 4u8, 5u8, 77u8, 46u8, 91u8, 125u8, 201u8, 12u8, 23u8, 34u8, 45u8, 56u8, 67u8,
                78u8, 89u8,
            ],
            [
                3u8, 5u8, 6u8, 78u8, 47u8, 92u8, 126u8, 202u8, 13u8, 24u8, 35u8, 46u8, 57u8, 68u8,
                79u8, 90u8,
            ],
            [
                4u8, 6u8, 7u8, 79u8, 48u8, 93u8, 127u8, 203u8, 14u8, 25u8, 36u8, 47u8, 58u8, 69u8,
                80u8, 91u8,
            ],
            [
                5u8, 7u8, 8u8, 80u8, 49u8, 94u8, 128u8, 204u8, 15u8, 26u8, 37u8, 48u8, 59u8, 70u8,
                81u8, 92u8,
            ],
            [
                6u8, 8u8, 9u8, 81u8, 50u8, 95u8, 129u8, 205u8, 16u8, 27u8, 38u8, 49u8, 60u8, 71u8,
                82u8, 93u8,
            ],
            [
                7u8, 9u8, 10u8, 82u8, 51u8, 96u8, 130u8, 206u8, 17u8, 28u8, 39u8, 50u8, 61u8, 72u8,
                83u8, 94u8,
            ],
        ];
        let expected_data2 = vec![
            1u8, 3u8, 4u8, 76u8, 45u8, 90u8, 124u8, 200u8, 11u8, 22u8, 33u8, 44u8, 55u8, 66u8,
            77u8, 88u8, 2u8, 4u8, 5u8, 77u8, 46u8, 91u8, 125u8, 201u8, 12u8, 23u8, 34u8, 45u8,
            56u8, 67u8, 78u8, 89u8, 3u8, 5u8, 6u8, 78u8, 47u8, 92u8, 126u8, 202u8, 13u8, 24u8,
            35u8, 46u8, 57u8, 68u8, 79u8, 90u8, 4u8, 6u8, 7u8, 79u8, 48u8, 93u8, 127u8, 203u8,
            14u8, 25u8, 36u8, 47u8, 58u8, 69u8, 80u8, 91u8, 5u8, 7u8, 8u8, 80u8, 49u8, 94u8, 128u8,
            204u8, 15u8, 26u8, 37u8, 48u8, 59u8, 70u8, 81u8, 92u8, 6u8, 8u8, 9u8, 81u8, 50u8, 95u8,
            129u8, 205u8, 16u8, 27u8, 38u8, 49u8, 60u8, 71u8, 82u8, 93u8, 7u8, 9u8, 10u8, 82u8,
            51u8, 96u8, 130u8, 206u8, 17u8, 28u8, 39u8, 50u8, 61u8, 72u8, 83u8, 94u8,
        ];
        let data2 = un_group(blocks2);

        assert_eq!(data2, expected_data2)
    }

    #[test]
    fn unpad_test() {
        assert_eq!(
            vec![2u8, 1u8, 7u8, 5u8],
            un_pad(vec![
                2u8, 1u8, 7u8, 5u8, 12u8, 12u8, 12u8, 12u8, 12u8, 12u8, 12u8, 12u8, 12u8, 12u8,
                12u8, 12u8
            ])
        );

        assert_eq!(
            vec![
                2u8, 1u8, 7u8, 5u8, 12u8, 12u8, 12u8, 12u8, 12u8, 12u8, 12u8, 12u8, 12u8, 12u8,
                12u8
            ],
            un_pad(vec![
                2u8, 1u8, 7u8, 5u8, 12u8, 12u8, 12u8, 12u8, 12u8, 12u8, 12u8, 12u8, 12u8, 12u8,
                12u8, 1u8
            ])
        );
        assert_eq!(
            vec![
                2u8, 1u8, 7u8, 5u8, 12u8, 12u8, 12u8, 12u8, 12u8, 12u8, 12u8, 12u8, 12u8, 12u8,
                12u8, 7u8
            ],
            un_pad(vec![
                2u8, 1u8, 7u8, 5u8, 12u8, 12u8, 12u8, 12u8, 12u8, 12u8, 12u8, 12u8, 12u8, 12u8,
                12u8, 7u8, 16u8, 16u8, 16u8, 16u8, 16u8, 16u8, 16u8, 16u8, 16u8, 16u8, 16u8, 16u8,
                16u8, 16u8, 16u8, 16u8
            ])
        )
    }

    #[test]
    fn ctr_encrypt_test() {
        let plain_text = "i am a cow";
        let byte_vector: Vec<u8> = plain_text.as_bytes().to_vec();
        let key =
            [1u8, 6u8, 5u8, 6u8, 2u8, 5u8, 44u8, 3u8, 7u8, 8u8, 9u8, 1u8, 14u8, 13u8, 15u8, 76u8];
        let groups = group(pad(byte_vector.clone()));
        let num_groups = groups.len();
        let encrypted = ctr_encrypt(byte_vector, key);
        assert_eq!(encrypted.len(), num_groups);
    }

    #[test]
    fn cbc_should_works() {
        let plain_text = "Bitcoin is the first decentralized cryptocurrency. Nodes in the peer-to-peer bitcoin network verify transactions through cryptography and record them in a public distributed ledger, called a blockchain, without central oversight.".as_bytes().to_vec();

        // Happy case
        // let plain_text = vec![
        //     2u8, 1u8, 7u8, 5u8, 12u8, 12u8, 12u8, 12u8, 12u8, 12u8, 12u8, 12u8, 12u8, 12u8, 12u8,
        //     7u8,
        // ];

        let key: [u8; BLOCK_SIZE] = [0; 16];

        let cipher_text = cbc_encrypt(plain_text.clone(), key);

        let decrypted_message = cbc_decrypt(cipher_text, key);

        assert_eq!(plain_text, decrypted_message);
    }

    #[test]
    fn ecb_should_works() {
        let plain_text = "Bitcoin is the first decentralized cryptocurrency. Nodes in the peer-to-peer bitcoin network verify transactions through cryptography and record them in a public distributed ledger, called a blockchain, without central oversight.".as_bytes().to_vec();

        let key: [u8; BLOCK_SIZE] = [0; 16];

        let cipher_text = ecb_encrypt(plain_text.clone(), key);

        let message = ecb_decrypt(cipher_text, key);

        assert_eq!(plain_text, message);
    }
}
