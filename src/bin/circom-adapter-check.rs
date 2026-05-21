use std::{env, process};

fn main() {
    let args = env::args().collect::<Vec<_>>();
    if args.len() != 3 {
        eprintln!("usage: circom-adapter-check <circuit.r1cs> <witness.wtns>");
        process::exit(2);
    }

    match spartan_whir::circom::import_paths(&args[1], &args[2]) {
        Ok((shape, witness, public_inputs)) => {
            println!(
                "ok constraints={} vars={} public_inputs={} witness={}",
                shape.num_cons,
                shape.num_vars,
                public_inputs.len(),
                witness.w.len()
            );
        }
        Err(err) => {
            eprintln!("error: {err}");
            process::exit(1);
        }
    }
}
