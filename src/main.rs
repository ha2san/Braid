#![recursion_limit="50000"]
use std::io;
use std::time::Instant;
use std::path::Path;
use std::fs::File;
use std::env;
use std::process::exit;

use crate::blockgen::{INIT_SIZE, N};

mod blockgen;
mod encoders;
mod decoders;
mod tar;

const RUNS: usize = 10;
const ITER: usize = 32;

enum Command {
//    Speedtest,
    Encode,
    Decode,
    Tar,
    Untar,
    ALL,
}

fn print_usage(command: Command) {
    
    println!("Usage :");
    match command {
 //       Command::Speedtest => {
 //           println!("speedtest");
 //           println!("\tbenchmark it's raw performances at computing storage advices");
 //       },
        Command::Encode => {
            println!("encode [input file] [output_file]");
            println!("\tencode the input file using the braid");
        },
        Command::Decode => {
            println!("decode [input_file] [output_file]");
            println!("\tdecode the input file using the braid");
        },
        Command::Tar => {
            println!("tar [output_file] [input_file]");
            println!("\tencode the input file using the braid and tar it");
        },
        Command::Untar => {
            println!("untar [input_file]");
            println!("\tdecode the input file using the braid and untar it");
            println!("untar [input_file] [output_file]...");
            println!("\tdecode specific files in the input file using the braid and untar it");
            println!("untar ls [input_file]");
            println!("\tlist the content of the tar file");
        },
        Command::ALL => {
            println!("speedtest");
            println!("\tbenchmark it's raw performances at computing storage advices");
            println!("encode [input_file] [output_file]");
            println!("\tencode the input file using the braid");
            println!("decode [input_file] [output_file]");
            println!("\tdecode the input file using the braid");
            println!("tar [input_file] [output_file]");
            println!("\tencode the input file using the braid and tar it");
            println!("untar [input_file]");
            println!("\tdecode the input file using the braid and untar it");
            println!("untar [input_file] [output_file]...");
            println!("\tdecode specific files in the input file using the braid and untar it");
            println!("untar ls [input_file]");
            println!("\tlist the content of the tar file");
        },
    }
}


fn main() -> io::Result<()>{
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_usage(Command::ALL);
        exit(1)
    }

    match args[1].as_str() {
        "speedtest" => {
            hash_run("siphash");
            exit(0)
        },
        "encode" => {
            if args.len() != 4 {
                eprintln!("Not enough arguments");
                print_usage(Command::Encode);
                exit(1);
            }
            let input = &args[2];
            let output = &args[3];
            let input_file = File::open(Path::new(input))?;
            let output_file = File::create(Path::new(output))?;
            encoders::encode(input_file,output_file)
        },
        "decode" => {
            if args.len() != 4 {
                print_usage(Command::Decode);
                exit(1)
            }
            let input = &args[2];
            let output = &args[3];
            let input_file = File::open(Path::new(input))?;
            let output_file = File::create(Path::new(output))?;
            decoders::decode(input_file,output_file)
        },
        "tar" => {
            if args.len() < 4 {
                eprintln!("Not enough arguments");
                print_usage(Command::Tar);
                exit(1)
            }
             
            let output_file = &args[2];
            let input_files = &args[3..];
            tar::tar(output_file, input_files)
        },
        "untar" => {
            match args[2].as_str() {
                "ls" => {
                    if args.len() != 4 {
                        eprintln!("Not enough arguments");
                        print_usage(Command::Untar);
                        exit(1)
                    }
                    let input_file = &args[3];
                    tar::list(input_file);
                    exit(0)
                },
                _ => {
                    match args.len() {
                        3 => {
                            let input_file = &args[2];
                            tar::untar(input_file);
                            exit(0)
                        },
                        _ => {
                            let input_file = &args[2];
                            let output_file = &args[3..];
                            for file in output_file {
                                tar::untar_file(input_file, file);
                            } 
                            exit(0);
                        }
                    }
                } 
            }
        },

        _ => {
            eprintln!("Not enough arguments");
            print_usage(Command::ALL);
            exit(1)
        }
    }
}

fn hash_run(hash: &str) {
    println!("Hash : {}", hash);
    println!("Total amount of steps : {}", blockgen::STEPS);
    println!("Group size : {}MiB", (blockgen::GROUP_BYTE_SIZE/1024) as f32 / 1024.0);
    let mut x: blockgen::InitGroup = [[0u8; blockgen::FRAGMENT_BYTES]; blockgen::INIT_SIZE];
    for j in 0..blockgen::INIT_SIZE {
        for k in 0..blockgen::FRAGMENT_BYTES {
            x[j][k] = ((j) * blockgen::FRAGMENT_BYTES + k + 727) as u8;
        }
    }
    for _ in 0..ITER {
        let res = blockgen::block_gen(x, hash);
        // Chain computations to avoid optimizations :
        for j in 0..INIT_SIZE {
            x[j] = res[N - 1 - j];
        }
    }
    println!("Warmup done.");
    // array of time measurements and read speed to compute average
    let mut times = [0.0; RUNS];
    let mut speeds = [0.0; RUNS];
    for i in 0..RUNS {
        let start = Instant::now();
        for _ in 0..ITER {
            let res = blockgen::block_gen(x, hash);
            // Chain computations to avoid optimizations :
            for j in 0..INIT_SIZE {
                x[j] = res[N - 1 - j];
            }
        }
        let t = start.elapsed();
        let ms = (t.as_micros() / ITER as u128) as f32 / 1_000.0;
        times[i] = ms;
        speeds[i] = (blockgen::GROUP_BYTE_SIZE * 1_000) as f32 / (ms * (1 << 20) as f32);
        //println!("# Runtime per block = {:.2}ms", ms);
        //println!("# Read speed = {:.2}MB/s", (blockgen::GROUP_BYTE_SIZE * 1_000) as f32 / (ms * (1 << 20) as f32));
    }

    let mut sum = 0.0;
    for i in 0..RUNS {
        sum += times[i];
    }

    let mut sum_speed = 0.0;
    for i in 0..RUNS {
        sum_speed += speeds[i];
    }

    println!("# Average runtime per block = {:.2}ms", sum / RUNS as f32);
    println!("# Average read speed = {:.2}MB/s", sum_speed / RUNS as f32);
    println!("");
}
