use std::fs::File;
use std::mem::transmute;
use std::fs::metadata;
use std::io::{Read,Write};
use blake3;
use aes::Aes128;

use aes::cipher::{
    BlockEncryptMut, KeyIvInit,
    generic_array::GenericArray,
};


const NAME_SIZE: usize = 128;
const MAX_NB_FILES: usize = 100;
const MAX_NB_BLOCKS: usize = 100;

type Hash = [u8;16];

use crate::blockgen::{INIT_SIZE, InitGroup, GROUP_BYTE_SIZE, block_gen, FRAGMENT_BYTES};

//const PADDING_HEADER: usize = GROUP_BYTE_SIZE - NAME_SIZE - 8 - MAX_NB_BLOCKS * 2 * 16;
const PADDING_HEADER: usize = GROUP_BYTE_SIZE - NAME_SIZE - 8;

struct FileHeader {
    name: [u8;NAME_SIZE],
    size: u64,
    //key: [Hash;MAX_NB_BLOCKS],
    //iv: [Hash;MAX_NB_BLOCKS],
    padding: [u8;PADDING_HEADER],
}

fn get_header_from_file(filename:&str) -> Option<FileHeader> {
    let mut header: FileHeader  = unsafe { std::mem::zeroed() };
    let metadata = match metadata(filename){
        Ok(m) => m,
        Err(_) => return None,
    };
    if metadata.is_dir() {
        todo!("directory support")
    }
    let file_size = metadata.len();
    header.name = filename.as_bytes().try_into().unwrap();
    header.size = file_size;
    let block_count = ((header.size - 1) / GROUP_BYTE_SIZE as u64) + 1;
    let mut ffile = match File::open(filename) {
        Ok(f) => f,
        Err(_) => return None,
    };


    //for i in 0..block_count {
    //    let mut input = vec![0u8; GROUP_BYTE_SIZE];
    //    match ffile.read(&mut input) {
    //        Ok(_) => {},
    //        Err(_) => return None,
    //    }

    //    let mut keys: Vec<u8> = Vec::with_capacity(16);
    //    let mut ivs: Vec<u8> = Vec::with_capacity(16);
    //    let input_hash = blake3::hash(&input);
    //    let input_hash = input_hash.as_bytes();
    //    let key_bytes = GenericArray::from_slice(&input_hash[0..16]);
    //    let iv_bytes = GenericArray::from_slice(&input_hash[16..32]);

    //    for j in 0..16 {
    //        header.key[i as usize][j] = (key_bytes[j]);
    //        header.iv[i as usize][j] = (iv_bytes[j])
    //    }
    //}

    Some(header)
}

const ID_PUBLIC_KEY: &[u8] = b"727 is a funny number";
type Aes128Cbc = cbc::Encryptor<Aes128>;



fn encode(header:&FileHeader,input_file:File, output: File  ){
    let pub_hash = blake3::hash(ID_PUBLIC_KEY);

    let block_count = ((header.size - 1) / GROUP_BYTE_SIZE as u64) + 1;
    for i in 0..block_count {
        let mut input = vec![0u8; GROUP_BYTE_SIZE];
        input_file.read(&mut input);

        // Compute init vectors
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

        // Compute input hash
        let mut output: Vec<u8> = Vec::with_capacity(32 + GROUP_BYTE_SIZE);
        let input_hash = blake3::hash(&input);
        let input_hash = input_hash.as_bytes();
        let key_bytes = GenericArray::from_slice(&input_hash[0..16]);
        let iv_bytes = GenericArray::from_slice(&input_hash[16..32]);

        for i in 0..16 {
            output.push(key_bytes[i]);
        }
        for i in 0..16 {
            output.push(iv_bytes[i]);
        }

        // TODO : Encrypt input with AES using the hash.
        let mut cipher = Aes128Cbc::new(&key_bytes, &iv_bytes);
        for i in 0..(GROUP_BYTE_SIZE / 16) {
            let from = i*16;
            let to = from + 16;
            cipher.encrypt_block_mut(GenericArray::from_mut_slice(&mut input[from..to]));
        }

        // Compute the output : XOR the input with the output of f
        for i in 0..(GROUP_BYTE_SIZE) {
            let mut data_bytes = [0u8; 1]; // ???
            data_bytes[0] = input[i];
            let mut data = u8::from_le_bytes(data_bytes); // ????
            data = data ^ group[i / FRAGMENT_BYTES][i % FRAGMENT_BYTES];
            data_bytes = unsafe { transmute(data.to_le()) };
            output.push(data_bytes[0]);
        }


        println!("output length = {}", output.len());
        assert!(output.len() == GROUP_BYTE_SIZE + 32);
        output.write_all(&output);
    }
    todo!()
}



const PADDING_FIRST_HEADER: usize = GROUP_BYTE_SIZE - 8 - 100 * NAME_SIZE ;

#[repr(packed)]
struct FirstHeader {
    number_of_files: u64,
    name: [[u8;NAME_SIZE];100],
    padding: [u8;PADDING_FIRST_HEADER],
}


pub fn tar(output_files: &str, input_files:&[String]) -> Result<(), std::io::Error> {
    // number of files to tar
    let file_count = input_files.len();
    let headers = input_files.iter().map(|x| get_header_from_file(x)).collect::<Vec<_>>();
    
    let mut first_header: FirstHeader = unsafe { std::mem::zeroed() };
    first_header.number_of_files = file_count as u64;
    for i in 0..file_count {
        first_header.name[i] = headers[i].as_ref().unwrap().name;
    }

    let mut ffile = match File::create(output_files) {
        Ok(f) => f,
        Err(e) => return Err(e),
    };

    let first_header = unsafe { std::mem::transmute::<FirstHeader, [u8;GROUP_BYTE_SIZE]>(first_header) };

    match ffile.write(&first_header) {
        Ok(_) => {},
        Err(e) => return Err(e),
    }

    // write the headers
    for i in 0..file_count {
        let header = headers[i].as_ref().unwrap();
        let header = unsafe { std::mem::transmute::<FileHeader, [u8;GROUP_BYTE_SIZE]>(*header) };
        match ffile.write(&header) {
            Ok(_) => {},
            Err(e) => return Err(e),
        }
    }
    
    for i in 0..file_count {
        let header = headers[i].as_ref().unwrap();
        let block_count = ((header.size - 1) / GROUP_BYTE_SIZE as u64) + 1;
        let mut single_file = match File::open(input_files[i].as_str()) {
            Ok(f) => f,
            Err(e) => return Err(e),
        };
        encode(header,single_file,ffile);
    }

    Ok(())
}

pub fn untar(){

} 
