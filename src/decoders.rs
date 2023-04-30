use std::mem::transmute;
use std::time::Instant;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::io::Read;

use blake3;
use aes::Aes128;
use aes::cipher::{
    BlockDecryptMut, KeyIvInit,
    generic_array::GenericArray,
};

use crate::blockgen::{GROUP_BYTE_SIZE,INIT_SIZE, block_gen, FRAGMENT_BYTES, InitGroup};

type Aes128Cbc = cbc::Decryptor<Aes128>;

const ID_PUBLIC_KEY: &[u8] = b"727 is a funny number";

pub fn decode(mut input_file: File, mut output_file: File) -> io::Result<()> {
    let startup = Instant::now();

    let pub_hash = blake3::hash(ID_PUBLIC_KEY);

    // Read input file size from the start of input file
    let mut size_bytes = [0u8; 8];
    input_file.read_exact(&mut size_bytes)?;
    let input_lenght = u64::from_le(unsafe { transmute(size_bytes) });
    let block_count = ((input_lenght - 1) / GROUP_BYTE_SIZE as u64) + 1;

    // Decode blocks
    for i in 0..block_count {
        let mut input = vec![0u8; GROUP_BYTE_SIZE + 32];
        input_file.read(&mut input)?;

        let mut inits: InitGroup = [[0; FRAGMENT_BYTES]; INIT_SIZE];
        for g in 0..FRAGMENT_BYTES {
            let pos_bytes: [u8; 8] = unsafe {
                transmute(((i * FRAGMENT_BYTES as u64) + g as u64).to_le())
            };
            let mut hasher = blake3::Hasher::new();
            hasher.update(&pos_bytes);
            hasher.update(pub_hash.as_bytes());
            let block_hash = hasher.finalize();
            let block_hash = block_hash.as_bytes();
            for i in 0..INIT_SIZE {
                let mut hash_bytes = [0u8; 1]; // ????
                hash_bytes[0] = block_hash[i];
                inits[i][g] = u8::from_le_bytes(hash_bytes);
            }
        }

        // Compute block_gen
        let group = block_gen(inits,"");


        // Extract group output from input
        //let mut group_output = vec![0u8; N*GROUP_SIZE];
        let mut group_output: Vec<u8> = Vec::with_capacity(GROUP_BYTE_SIZE);
        //for i in 0..(N*GROUP_SIZE) {
        for i in 0..(GROUP_BYTE_SIZE) {
            let mut data_bytes = [input[32+i]];
            //let data = u8::from_le_bytes(data_bytes);
            //group_output[i] = (data ^ group[i / GROUP_SIZE][i % GROUP_SIZE]) as u8;

            let mut data = u8::from_le_bytes(data_bytes);
            data = data ^ group[i / FRAGMENT_BYTES][i % FRAGMENT_BYTES];
            data_bytes = unsafe { transmute(data.to_le()) };
            group_output.push(data_bytes[0]);
        }

        // Extract AES key and IV from input
        let key_bytes = GenericArray::from_slice(&input[0..16]);
        let iv_bytes = GenericArray::from_slice(&input[16..32]);

        // TODO: Decrypt input with AES using the key and IV.
        let mut cipher = Aes128Cbc::new(&key_bytes, &iv_bytes);
        for i in 0..(GROUP_BYTE_SIZE / 16) {
            let from = i*16;
            let to = from + 16;
            cipher.decrypt_block_mut(GenericArray::from_mut_slice(&mut group_output[from..to]));
        }


        // Write decoded block to output file
        output_file.write_all(&group_output)?;
    }

    let ttotal = startup.elapsed();
    let ms = ttotal.as_micros() as f32 / 1_000.0;
    println!("Decoded the file in {}ms", ms);
    Ok(())
}
