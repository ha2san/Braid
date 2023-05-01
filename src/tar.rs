use std::fs::File;
use std::str;
use std::mem::transmute;
use std::fs::metadata;
use std::io::{Read,Write};
use blake3;
use aes::Aes128;

use aes::cipher::{
    BlockDecryptMut,BlockEncryptMut, KeyIvInit,
    generic_array::GenericArray,
};


const NAME_SIZE: usize = 128;
//const MAX_NB_FILES: usize = 100;
const MAX_NB_BLOCKS: usize = 100;

type Hash = [u8;32];
type Aes128CbcD = cbc::Decryptor<Aes128>;
type Aes128CbcE = cbc::Encryptor<Aes128>;

use crate::blockgen::{INIT_SIZE, InitGroup, GROUP_BYTE_SIZE, block_gen, FRAGMENT_BYTES};

const PADDING_HEADER: usize = GROUP_BYTE_SIZE - NAME_SIZE - 8 - MAX_NB_BLOCKS * 32;
//const PADDING_HEADER: usize = GROUP_BYTE_SIZE - NAME_SIZE - 8;

#[derive(Copy,Clone)]
struct FileHeader {
    name: [u8;NAME_SIZE],
    size: u64,
    hash: [Hash;MAX_NB_BLOCKS],
    padding: [u8;PADDING_HEADER],
}

const PADDING_FIRST_HEADER: usize = GROUP_BYTE_SIZE - 8 - 100 * NAME_SIZE ;

#[repr(packed)]
struct FirstHeader {
    number_of_files: u64,
    name: [[u8;NAME_SIZE];100],
    padding: [u8;PADDING_FIRST_HEADER],
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
    println!("filename is {}",filename);
    //header.name = filename.as_bytes().try_into().unwrap();
    for i in 0..filename.len() {
        header.name[i] = filename.as_bytes()[i];
    }

    header.size = file_size;
    let block_count = ((header.size - 1) / GROUP_BYTE_SIZE as u64) + 1;
    let mut ffile = match File::open(filename) {
        Ok(f) => f,
        Err(_) => return None,
    };


    for i in 0..block_count {
        let mut input = vec![0u8; GROUP_BYTE_SIZE];
        match ffile.read(&mut input) {
            Ok(_) => {},
            Err(_) => return None,
        }

        let input_hash = blake3::hash(&input);
        let input_hash = input_hash.as_bytes();
        //let key_bytes = GenericArray::from_slice(&input_hash[0..16]);
        //let iv_bytes = GenericArray::from_slice(&input_hash[16..32]);

        for j in 0..32 {
            header.hash[i as usize][j] = input_hash[j];
        }
    }

    Some(header)
}

const ID_PUBLIC_KEY: &[u8] = b"727 is a funny number";



fn encode(header:&FileHeader,mut input_file:&File, mut output_file:&File){
    let pub_hash = blake3::hash(ID_PUBLIC_KEY);

    let block_count = ((header.size - 1) / GROUP_BYTE_SIZE as u64) + 1;
    for i in 0..block_count {
        let mut input = vec![0u8; GROUP_BYTE_SIZE];
        match input_file.read(&mut input) {
            Ok(_) => {},
            Err(_) => return,
        }

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
        //let mut output: Vec<u8> = Vec::with_capacity(32 + GROUP_BYTE_SIZE);
        let mut output: Vec<u8> = Vec::with_capacity(GROUP_BYTE_SIZE);
        //let input_hash = blake3::hash(&input);
        //let input_hash = input_hash.as_bytes();
        let key_bytes = GenericArray::from_slice(&header.hash[i as usize][0..16]);
        let iv_bytes = GenericArray::from_slice(&header.hash[i as usize][16..32]);

        //for i in 0..16 {
        //    output.push(key_bytes[i]);
        //}
        //for i in 0..16 {
        //    output.push(iv_bytes[i]);
        //}

        // TODO : Encrypt input with AES using the hash.
        let mut cipher = Aes128CbcE::new(key_bytes, iv_bytes);
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
        assert!(output.len() == GROUP_BYTE_SIZE);
        match output_file.write_all(&output){
            Ok(_) => {},
            Err(_) => return,
        }
    }
}

fn decode(header:&FileHeader,mut input_file: &File, mut output_file: &File ) {
    let pub_hash = blake3::hash(ID_PUBLIC_KEY);
    let input_length = header.size;
    let block_count = ((input_length - 1) / GROUP_BYTE_SIZE as u64) + 1;

    // Decode blocks
    for i in 0..block_count {
        //let mut input = vec![0u8; GROUP_BYTE_SIZE + 32];
        let mut input = vec![0u8; GROUP_BYTE_SIZE];
        match input_file.read(&mut input) {
            Ok(_) => {},
            Err(_) => return,
        }

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
            //let mut data_bytes = [input[32+i]];
            let mut data_bytes = [input[i]];
            //let data = u8::from_le_bytes(data_bytes);
            //group_output[i] = (data ^ group[i / GROUP_SIZE][i % GROUP_SIZE]) as u8;

            let mut data = u8::from_le_bytes(data_bytes);
            data = data ^ group[i / FRAGMENT_BYTES][i % FRAGMENT_BYTES];
            data_bytes = unsafe { transmute(data.to_le()) };
            group_output.push(data_bytes[0]);
        }

        // Extract AES key and IV from input
        let key_bytes = GenericArray::from_slice(&header.hash[i as usize][0..16]);
        let iv_bytes = GenericArray::from_slice(&header.hash[i as usize][16..32]);

        // TODO: Decrypt input with AES using the key and IV.
        let mut cipher = Aes128CbcD::new(&key_bytes, &iv_bytes);
        for i in 0..(GROUP_BYTE_SIZE / 16) {
            let from = i*16;
            let to = from + 16;
            cipher.decrypt_block_mut(GenericArray::from_mut_slice(&mut group_output[from..to]));
        }


        // Write decoded block to output file
        match output_file.write_all(&group_output) {
            Ok(_) => {},
            Err(_) => return,
        }
    }
    //truncate output file to the right size
    match output_file.set_len(input_length) {
        Ok(_) => {},
        Err(_) => return,

    }
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
            let single_file = match File::open(input_files[i].as_str()) {
                Ok(f) => f,
                Err(e) => return Err(e),
            };
            encode(header,&single_file,&ffile);
        }

        Ok(())
    }

    pub fn untar(input_file: &str){
        let mut ffile = match File::open(input_file) {
            Ok(f) => f,
            Err(e) => panic!("Error opening file : {}", e),
        };

        let first_header: FirstHeader;
        let mut first_header_bytes = [0u8; GROUP_BYTE_SIZE];
        match ffile.read(&mut first_header_bytes) {
            Ok(_) => {},
            Err(e) => panic!("Error reading file : {}", e),
        }
        first_header = unsafe { std::mem::transmute::<[u8;GROUP_BYTE_SIZE], FirstHeader>(first_header_bytes) };

        let file_count = first_header.number_of_files as usize;
        let mut headers = Vec::with_capacity(file_count);
        for _ in 0..file_count {
            let mut header_bytes = [0u8; GROUP_BYTE_SIZE];
            match ffile.read(&mut header_bytes) {
                Ok(_) => {},
                Err(e) => panic!("Error reading file : {}", e),
            }
            let header = unsafe { std::mem::transmute::<[u8;GROUP_BYTE_SIZE], FileHeader>(header_bytes) };
            headers.push(header);
        }

        for i in 0..file_count {
            let header = &headers[i];
            let name_str = get_string_from_slice(&header.name);
            println!("name_str = {}", name_str);
            //let name = String::from(name_str);
            println!("name = {}", name_str);
            let single_file = match File::create(name_str) {
                Ok(f) => f,
                Err(e) => panic!("Error creating file : {}", e),
            };
            decode(&header,&ffile,&single_file);
        }
    } 

    fn get_string_from_slice(slice: &[u8]) -> String {
        let mut string = String::new();
        for i in 0..slice.len() {
            if slice[i] == 0 {
                break;
            }
            string.push(slice[i] as char);
        }
        string
    }

    pub fn list(input_file: &str) {
        let mut ffile = match File::open(input_file) {
            Ok(f) => f,
            Err(e) => panic!("Error opening file : {}", e),
        };

        let first_header: FirstHeader;
        let mut first_header_bytes = [0u8; GROUP_BYTE_SIZE];
        match ffile.read(&mut first_header_bytes) {
            Ok(_) => {},
            Err(e) => panic!("Error reading file : {}", e),
        }
        first_header = unsafe { std::mem::transmute::<[u8;GROUP_BYTE_SIZE], FirstHeader>(first_header_bytes) };

        let file_count = first_header.number_of_files as usize;
        for i in 0..file_count {
            //print file name
            println!("{}",get_string_from_slice(&first_header.name[i]));
        }
        
    }

    // pas du tout optimal, à modifier si possible
    pub fn untar_file(input_file: &str, output_file: &str) {
        let mut ffile = match File::open(input_file) {
            Ok(f) => f,
            Err(e) => panic!("Error opening file : {}", e),
        };

        let first_header: FirstHeader;
        let mut first_header_bytes = [0u8; GROUP_BYTE_SIZE];
        match ffile.read(&mut first_header_bytes) {
            Ok(_) => {},
            Err(e) => panic!("Error reading file : {}", e),
        }
        first_header = unsafe { std::mem::transmute::<[u8;GROUP_BYTE_SIZE], FirstHeader>(first_header_bytes) };

        let file_count = first_header.number_of_files as usize;
        let mut headers = Vec::with_capacity(file_count);
        for _ in 0..file_count {
            let mut header_bytes = [0u8; GROUP_BYTE_SIZE];
            match ffile.read(&mut header_bytes) {
                Ok(_) => {},
                Err(e) => panic!("Error reading file : {}", e),
            }
            let header = unsafe { std::mem::transmute::<[u8;GROUP_BYTE_SIZE], FileHeader>(header_bytes) };
            headers.push(header);
        }

        for i in 0..file_count {
            let header = &headers[i];
            let name_str = get_string_from_slice(&header.name);
            if name_str == output_file {
                let single_file = match File::create(name_str) {
                    Ok(f) => f,
                    Err(e) => panic!("Error creating file : {}", e),
                };
                decode(&header,&ffile,&single_file);
            }
        }
    } 
