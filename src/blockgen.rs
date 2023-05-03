use std::vec::Vec;

//siphash
//use digest::DynDigest;
use std::collections::hash_map::DefaultHasher;
use std::hash::Hasher;

pub const E: usize = 13;
pub const D: usize = E + 1; // Amount of dependencies of each fragment
pub const N: usize = 1 << E as usize; // Amount of fragment per block
const INDEX_MASK: usize = N - 1;

pub const ABSOLUTE_SPEEDUP_UPPERBOUND: usize = E * (1 << (E - 1)) * E + (N / 2) - 1;
const MIN_ADVERSARY_OPERATIONS: usize = 8000000; // 20GHz (adversary max speed) * 0.2ms (disk latency) * 2 (security margin)
const OPERATIONS_PER_STEP: usize = 124; // siphash is at least  sequential primitive operations per 32 bytes of input.
const MIN_ADVERSARY_STEPS: usize =
    (MIN_ADVERSARY_OPERATIONS + (OPERATIONS_PER_STEP - 1)) / OPERATIONS_PER_STEP;
const STEPS_LOWERBOUND: usize = MIN_ADVERSARY_STEPS + ABSOLUTE_SPEEDUP_UPPERBOUND;
pub const SIZE: usize = (STEPS_LOWERBOUND + (E - 1)) / E;
pub const STEPS: usize = SIZE * E;

pub const FRAGMENT_BYTES: usize = 8;
pub type Fragment = [u8; FRAGMENT_BYTES];
pub const BLOCK_BYTE_SIZE: usize = N * FRAGMENT_BYTES;

pub const GROUP_SIZE: usize = 1;
pub const GROUP_BYTE_SIZE: usize = BLOCK_BYTE_SIZE * GROUP_SIZE;
pub type FragmentGroup = Fragment;
pub type BlockGroup = Vec<FragmentGroup>;

pub const INIT_SIZE_EXP: usize = 2;
pub const INIT_SIZE: usize = 1 << INIT_SIZE_EXP; // 4x64bit = 256bit
pub const INIT_MASK: usize = INIT_SIZE - 1;
pub type InitGroup = [FragmentGroup; INIT_SIZE];

pub fn block_gen(inits: InitGroup, hash: &str) -> BlockGroup {
    if is_x86_feature_detected!("avx2") {
        unsafe { block_gen_avx2(inits, hash) }
    } else {
        block_gen_inner(inits, hash)
    }
}

#[target_feature(enable = "avx2")]
unsafe fn block_gen_avx2(inits: InitGroup, hash: &str) -> BlockGroup {
    block_gen_inner(inits, hash)
}

#[inline(always)]
fn block_gen_inner(inits: InitGroup, _hash: &str) -> BlockGroup {
    // let mut block: Block = [[0; FRAGMENTSIZE]; N as usize];
    let mut block: BlockGroup = vec![[0u8; FRAGMENT_BYTES]; N as usize];
    for i in 0..N {
        block[i] = inits[i & INIT_MASK];
    }

    let start = N - (SIZE % N);
    let mut hasher = DefaultHasher::new();

    for i in 0..SIZE {
        let index = (i + start) % N;

        for j in 0..D {
            let jump = 1 << j;
            let target = (index + N - jump) & INDEX_MASK;
            let x = block[target];
            hasher.write(&x); //siphasher
        }

        //store the hash in the first 4 bytes of the fragment
        // hash => 4 bytes
        let hash = hasher.finish();
        //store u64 in 8 bytes
        block[index][0] = (hash >> 56) as u8;
        block[index][1] = (hash >> 48) as u8;
        block[index][2] = (hash >> 40) as u8;
        block[index][3] = (hash >> 32) as u8;
        block[index][4] = (hash >> 24) as u8;
        block[index][5] = (hash >> 16) as u8;
        block[index][6] = (hash >> 8) as u8;
        block[index][7] = hash as u8;
    }
    return block;
}

/*
#[allow(dead_code)]
fn select_hasher(s: &str) -> Box<dyn DynDigest> {
    match s {
        //"blake3" => Box::new(blake3::default()),
        "blake2" => Box::new(blake2::Blake2b512::default()),
        "FSB" => Box::new(fsb::Fsb256::default()),
        "Groestl"=>  Box::new(groestl::Groestl512::default()),
        "ripemd"=> Box::new(ripemd::Ripemd320::default()),
        "sha2"=> Box::new(sha2::Sha512::default()),
        "sha3"=>  Box::new(sha3::Sha3_512::default()),
        "shabal"=> Box::new(shabal::Shabal512::default()),
        "sm3"=> Box::new(sm3::Sm3::default()),
        "Tiger"=> Box::new(tiger::Tiger::default()),
        "Whirlpool"=> Box::new(whirlpool::Whirlpool::default()),
        _ => unimplemented!("unsupported digest: {}", s),
    }
}
*/
