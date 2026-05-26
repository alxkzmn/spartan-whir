use std::{env, fs, path::PathBuf, process, time::Instant};

use p3_challenger::CanObserve;
use serde::Serialize;
use serde_json::Value;
use spartan_whir::{
    circom::import_paths,
    engine::{ExtField, F},
    setup_poseidon, MatrixClosingMode, MlePcs, Plonky3WhirPcs, PoseidonChallenger, PoseidonEngine,
    PoseidonSetupConfig, QuarticBinExtension, R1csShape, R1csWitness, SpartanWhirError,
};

type OcticBinExtension = spartan_whir::OcticBinExtension;
type QuinticExtension = spartan_whir::QuinticExtension;

const DEFAULT_REPEATS: usize = 3;
const DEFAULT_WARMUPS: usize = 1;
const DEFAULT_MAX_ROWS: usize = 5;

#[derive(Debug)]
struct Args {
    r1cs: PathBuf,
    wtns: PathBuf,
    report: PathBuf,
    out: PathBuf,
    labels: Option<Vec<String>>,
    case_label: Option<String>,
    extension: Option<String>,
    repeats: usize,
    warmups: usize,
    max_rows: usize,
    include_strata: bool,
}

#[derive(Debug, Serialize)]
struct HeldoutDump {
    schema_version: u32,
    measurement_kind: &'static str,
    units: &'static str,
    source_report: String,
    r1cs: String,
    wtns: String,
    repeats: usize,
    warmups: usize,
    rows: Vec<Value>,
}

fn main() {
    if let Err(error) = run_main() {
        eprintln!("{error}");
        process::exit(1);
    }
}

fn run_main() -> Result<(), String> {
    let args = parse_args().unwrap_or_else(|error| {
        eprintln!("{error}");
        usage();
        process::exit(2);
    });

    let report = read_json(&args.report)?;
    let rows = select_rows(&report, &args)?;
    if rows.is_empty() {
        return Err("no heldout rows selected".to_owned());
    }

    let (shape, witness, public_inputs) = import_paths(&args.r1cs, &args.wtns)
        .map_err(|err| format!("failed to import circom artifacts: {err}"))?;

    let mut measured = Vec::new();
    for row in rows {
        let mut measured_row = row.clone();
        let label = row
            .get("label")
            .and_then(Value::as_str)
            .unwrap_or("<missing-label>");
        let extension = row
            .get("extension")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("{label}: missing extension"))?;
        let setup_config = row
            .get("setup_config")
            .cloned()
            .ok_or_else(|| format!("{label}: missing setup_config"))?;
        let setup_config: PoseidonSetupConfig = serde_json::from_value(setup_config)
            .map_err(|err| format!("{label}: invalid setup_config: {err}"))?;
        if setup_config.matrix_closing != MatrixClosingMode::DirectSparse {
            return Err(format!(
                "{label}: heldout measurement only supports DirectSparse"
            ));
        }

        let measurement = match extension {
            "quartic" => measure_prove::<QuarticBinExtension>(
                &shape,
                &witness,
                &public_inputs,
                setup_config,
                args.repeats,
                args.warmups,
            ),
            "quintic" => measure_prove::<QuinticExtension>(
                &shape,
                &witness,
                &public_inputs,
                setup_config,
                args.repeats,
                args.warmups,
            ),
            "octic" => measure_prove::<OcticBinExtension>(
                &shape,
                &witness,
                &public_inputs,
                setup_config,
                args.repeats,
                args.warmups,
            ),
            other => Err(format!("{label}: unsupported extension {other}")),
        }?;

        let object = measured_row
            .as_object_mut()
            .ok_or_else(|| format!("{label}: row is not an object"))?;
        object.insert(
            "measured_seconds".to_owned(),
            Value::from(measurement.median_seconds),
        );
        object.insert(
            "heldout_prove_seconds".to_owned(),
            Value::from(measurement.median_seconds),
        );
        object.insert(
            "constraint_work".to_owned(),
            Value::from(shape.num_cons as u64),
        );
        object.insert(
            "witness_work".to_owned(),
            Value::from(shape.num_vars as u64),
        );
        if let Some(case_label) = &args.case_label {
            object.insert(
                "heldout_case_label".to_owned(),
                Value::from(case_label.clone()),
            );
        }
        object.insert(
            "heldout_repeats".to_owned(),
            Value::from(args.repeats as u64),
        );
        object.insert(
            "heldout_warmups".to_owned(),
            Value::from(args.warmups as u64),
        );
        object.insert(
            "heldout_samples_seconds".to_owned(),
            Value::Array(
                measurement
                    .samples_seconds
                    .iter()
                    .copied()
                    .map(Value::from)
                    .collect(),
            ),
        );
        measured.push(measured_row);
    }

    let dump = HeldoutDump {
        schema_version: 1,
        measurement_kind: "poseidon_schedule_full_proof_heldout",
        units: "seconds",
        source_report: args.report.display().to_string(),
        r1cs: args.r1cs.display().to_string(),
        wtns: args.wtns.display().to_string(),
        repeats: args.repeats,
        warmups: args.warmups,
        rows: measured,
    };
    let file = fs::File::create(&args.out)
        .map_err(|err| format!("failed to create {}: {err}", args.out.display()))?;
    serde_json::to_writer_pretty(file, &dump)
        .map_err(|err| format!("failed to write {}: {err}", args.out.display()))?;
    Ok(())
}

struct Measurement {
    median_seconds: f64,
    samples_seconds: Vec<f64>,
}

fn measure_prove<Ext>(
    shape: &R1csShape<F>,
    witness: &R1csWitness<F>,
    public_inputs: &[F],
    setup_config: PoseidonSetupConfig,
    repeats: usize,
    warmups: usize,
) -> Result<Measurement, String>
where
    Ext: ExtField,
    PoseidonChallenger: CanObserve<<Plonky3WhirPcs as MlePcs<PoseidonEngine<Ext>>>::Commitment>,
{
    let (pk, vk) = setup_poseidon::<Ext>(shape.clone(), setup_config)
        .map_err(|err| format!("setup failed: {err:?}"))?;
    for _ in 0..warmups {
        let proof = pk
            .prove(witness.clone(), public_inputs.to_vec())
            .map_err(format_protocol_error("warmup prove"))?;
        vk.verify(&proof)
            .map_err(format_protocol_error("warmup verify"))?;
    }

    let mut durations = Vec::with_capacity(repeats);
    for _ in 0..repeats {
        let start = Instant::now();
        let proof = pk
            .prove(witness.clone(), public_inputs.to_vec())
            .map_err(format_protocol_error("prove"))?;
        let elapsed = start.elapsed();
        vk.verify(&proof).map_err(format_protocol_error("verify"))?;
        durations.push(elapsed);
    }
    let mut sorted = durations.clone();
    sorted.sort();
    Ok(Measurement {
        median_seconds: sorted[sorted.len() / 2].as_secs_f64(),
        samples_seconds: durations
            .into_iter()
            .map(|duration| duration.as_secs_f64())
            .collect(),
    })
}

fn format_protocol_error(phase: &'static str) -> impl FnOnce(SpartanWhirError) -> String {
    move |err| format!("{phase} failed: {err:?}")
}

fn select_rows(report: &Value, args: &Args) -> Result<Vec<Value>, String> {
    let source = report
        .get("scores")
        .or_else(|| report.get("candidates"))
        .and_then(Value::as_array)
        .ok_or_else(|| "report must contain scores or candidates array".to_owned())?;

    let mut rows = Vec::new();
    for row in source {
        let label = row.get("label").and_then(Value::as_str).unwrap_or_default();
        if let Some(labels) = &args.labels {
            if !labels.iter().any(|wanted| wanted == label) {
                continue;
            }
        }
        if let Some(extension) = &args.extension {
            if row.get("extension").and_then(Value::as_str) != Some(extension.as_str()) {
                continue;
            }
        }
        if row.get("accepted_for_ranking").and_then(Value::as_bool) == Some(false) {
            continue;
        }
        if row.get("valid").and_then(Value::as_bool) == Some(false) {
            continue;
        }
        if row.get("setup_config").is_none() {
            continue;
        }
        rows.push(row.clone());
    }
    if args.labels.is_none() && rows.len() > args.max_rows {
        rows = if args.include_strata {
            stratified_rows(&rows, args.max_rows)
        } else {
            rows.into_iter().take(args.max_rows).collect()
        };
    }
    Ok(rows)
}

fn stratified_rows(rows: &[Value], max_rows: usize) -> Vec<Value> {
    if rows.len() <= max_rows {
        return rows.to_vec();
    }
    if max_rows == 1 {
        return vec![rows[0].clone()];
    }
    let last = rows.len() - 1;
    let mut selected = Vec::with_capacity(max_rows);
    let mut last_index = None;
    for slot in 0..max_rows {
        let index = (slot * last + (max_rows - 1) / 2) / (max_rows - 1);
        if Some(index) != last_index {
            selected.push(rows[index].clone());
            last_index = Some(index);
        }
    }
    selected
}

fn read_json(path: &PathBuf) -> Result<Value, String> {
    let file =
        fs::File::open(path).map_err(|err| format!("failed to open {}: {err}", path.display()))?;
    serde_json::from_reader(file)
        .map_err(|err| format!("failed to parse {}: {err}", path.display()))
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        r1cs: PathBuf::new(),
        wtns: PathBuf::new(),
        report: PathBuf::new(),
        out: PathBuf::new(),
        labels: None,
        case_label: None,
        extension: None,
        repeats: DEFAULT_REPEATS,
        warmups: DEFAULT_WARMUPS,
        max_rows: DEFAULT_MAX_ROWS,
        include_strata: false,
    };
    let mut iter = env::args().skip(1);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--r1cs" => args.r1cs = PathBuf::from(parse_next_string(&mut iter, &arg)?),
            "--wtns" => args.wtns = PathBuf::from(parse_next_string(&mut iter, &arg)?),
            "--report" => args.report = PathBuf::from(parse_next_string(&mut iter, &arg)?),
            "--out" => args.out = PathBuf::from(parse_next_string(&mut iter, &arg)?),
            "--labels" => {
                args.labels = Some(
                    parse_next_string(&mut iter, &arg)?
                        .split(',')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(ToOwned::to_owned)
                        .collect(),
                )
            }
            "--case-label" => args.case_label = Some(parse_next_string(&mut iter, &arg)?),
            "--extension" => args.extension = Some(parse_next_string(&mut iter, &arg)?),
            "--repeats" => args.repeats = parse_next(&mut iter, &arg)?,
            "--warmups" => args.warmups = parse_next(&mut iter, &arg)?,
            "--max-rows" => args.max_rows = parse_next(&mut iter, &arg)?,
            "--include-strata" => args.include_strata = true,
            "--help" | "-h" => {
                usage();
                process::exit(0);
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    if args.r1cs.as_os_str().is_empty()
        || args.wtns.as_os_str().is_empty()
        || args.report.as_os_str().is_empty()
        || args.out.as_os_str().is_empty()
    {
        return Err("--r1cs, --wtns, --report, and --out are required".to_owned());
    }
    if args.repeats == 0 {
        return Err("--repeats must be positive".to_owned());
    }
    if args.labels.as_ref().is_some_and(Vec::is_empty) {
        return Err("--labels must not be empty".to_owned());
    }
    if args.max_rows == 0 {
        return Err("--max-rows must be positive".to_owned());
    }
    Ok(args)
}

fn parse_next(iter: &mut impl Iterator<Item = String>, name: &str) -> Result<usize, String> {
    parse_next_string(iter, name)?
        .parse()
        .map_err(|_| format!("{name} must be a non-negative integer"))
}

fn parse_next_string(
    iter: &mut impl Iterator<Item = String>,
    name: &str,
) -> Result<String, String> {
    iter.next()
        .ok_or_else(|| format!("{name} requires a value"))
}

fn usage() {
    eprintln!(
        "usage: poseidon-schedule-heldout --r1cs circuit.r1cs --wtns witness.wtns --report report.json --out heldout.json [--case-label sha256_512b] [--extension octic] [--max-rows 5] [--include-strata] [--repeats 3] [--warmups 1]"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn args(include_strata: bool, max_rows: usize) -> Args {
        Args {
            r1cs: PathBuf::new(),
            wtns: PathBuf::new(),
            report: PathBuf::new(),
            out: PathBuf::new(),
            labels: None,
            case_label: None,
            extension: None,
            repeats: 1,
            warmups: 0,
            max_rows,
            include_strata,
        }
    }

    fn report() -> Value {
        json!({
            "scores": (0..7)
                .map(|i| json!({
                    "label": format!("row{i}"),
                    "valid": true,
                    "accepted_for_ranking": true,
                    "setup_config": {"matrix_closing": "DirectSparse"}
                }))
                .collect::<Vec<_>>()
        })
    }

    #[test]
    fn select_rows_defaults_to_top_rows() {
        let selected = select_rows(&report(), &args(false, 3)).unwrap();
        let labels = selected
            .iter()
            .map(|row| row["label"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(labels, vec!["row0", "row1", "row2"]);
    }

    #[test]
    fn select_rows_can_sample_strata() {
        let selected = select_rows(&report(), &args(true, 3)).unwrap();
        let labels = selected
            .iter()
            .map(|row| row["label"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(labels, vec!["row0", "row3", "row6"]);
    }
}
