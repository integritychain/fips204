use crate::stats;

use std::{
    fs::{File, OpenOptions},
    io::{self, Write},
    iter::repeat,
    path::PathBuf,
    process,
    sync::{
        atomic::{self, AtomicBool},
        Arc,
    },
    time::Instant,
};

use ctrlc;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaChaRng;

/// Just a static str representing the name of a function
#[derive(Copy, Clone)]
pub struct BenchName(pub &'static str);

impl BenchName {
    fn padded(&self, column_count: usize) -> String {
        let mut name = self.0.to_string();
        let fill = column_count.saturating_sub(name.len());
        let pad = repeat(" ").take(fill).collect::<String>();
        name.push_str(&pad);

        name
    }
}

/// A random number generator implementing [`rand::SeedableRng`]. This is given to every
/// benchmarking function to use as a source of randomness.
pub type BenchRng = ChaChaRng;

/// A function that is to be benchmarked. This crate only supports statically-defined functions.
pub type BenchFn = fn(&mut CtRunner, &mut BenchRng);

// TODO: Consider giving this a lifetime so we don't have to copy names and vecs into it
#[derive(Clone)]
enum BenchEvent {
    BContStart,
    BBegin(Vec<BenchName>),
    BWait(BenchName),
    BResult(MonitorMsg),
    BSeed(u64, BenchName),
}

type MonitorMsg = (BenchName, stats::CtSummary);

/// CtBencher is the primary interface for benchmarking. All setup for function inputs should be
/// doen within the closure supplied to the `iter` method.
struct CtBencher {
    samples: (Vec<u64>, Vec<u64>),
    ctx: Option<stats::CtCtx>,
    file_out: Option<File>,
    rng: BenchRng,
}

impl CtBencher {
    /// Creates and returns a new empty `CtBencher` whose `BenchRng` is zero-seeded
    pub fn new() -> CtBencher {
        CtBencher {
            samples: (Vec::new(), Vec::new()),
            ctx: None,
            file_out: None,
            rng: BenchRng::seed_from_u64(0u64),
        }
    }

    /// Runs the bench function and returns the CtSummary
    fn go(&mut self, f: BenchFn) -> stats::CtSummary {
        // This populates self.samples
        let mut runner = CtRunner::default();
        f(&mut runner, &mut self.rng);
        self.samples = runner.runtimes;

        // Replace the old CtCtx with an updated one
        let old_self = ::std::mem::replace(self, CtBencher::new());
        let (summ, new_ctx) = stats::update_ct_stats(old_self.ctx, &old_self.samples);

        // Copy the old stuff back in
        self.samples = old_self.samples;
        self.file_out = old_self.file_out;
        self.ctx = Some(new_ctx);
        self.rng = old_self.rng;

        summ
    }

    /// Returns a random seed
    fn rand_seed() -> u64 {
        rand::rng().random()
    }

    /// Reseeds the internal RNG with the given seed
    pub fn seed_with(&mut self, seed: u64) {
        self.rng = BenchRng::seed_from_u64(seed);
    }

    /// Clears out all sample and contextual data
    fn clear_data(&mut self) {
        self.samples = (Vec::new(), Vec::new());
        self.ctx = None;
    }
}

/// Represents a single benchmark to conduct
pub struct BenchMetadata {
    pub name: BenchName,
    pub seed: Option<u64>,
    pub benchfn: BenchFn,
}

/// Benchmarking options.
///
/// When `continuous` is set, it will continuously set the first (alphabetically) of the benchmarks
/// after they have been optionally filtered.
///
/// When `filter` is set and `continuous` is not set, only benchmarks whose names contain the
/// filter string as a substring will be executed.
///
/// `file_out` is optionally the filename where CSV output of raw runtime data should be written
#[derive(Default)]
pub struct BenchOpts {
    pub continuous: bool,
    pub filter: Option<String>,
    pub file_out: Option<PathBuf>,
}

#[derive(Default)]
struct ConsoleBenchState {
    // Number of columns to fill when aligning names
    max_name_len: usize,
}

impl ConsoleBenchState {
    fn write_plain(&mut self, s: &str) -> io::Result<()> {
        let mut stdout = io::stdout();
        stdout.write_all(s.as_bytes())?;
        stdout.flush()
    }

    fn write_bench_start(&mut self, name: &BenchName) -> io::Result<()> {
        let name = name.padded(self.max_name_len);
        self.write_plain(&format!("bench {} ... ", name))
    }

    fn write_seed(&mut self, seed: u64, name: &BenchName) -> io::Result<()> {
        let name = name.padded(self.max_name_len);
        self.write_plain(&format!("bench {} seeded with 0x{:016x}\n", name, seed))
    }

    fn write_run_start(&mut self, len: usize) -> io::Result<()> {
        let noun = if len != 1 { "benches" } else { "bench" };
        self.write_plain(&format!("\nrunning {} {}\n", len, noun))
    }

    fn write_continuous_start(&mut self) -> io::Result<()> {
        self.write_plain("running 1 benchmark continuously\n")
    }

    fn write_result(&mut self, summ: &stats::CtSummary) -> io::Result<()> {
        self.write_plain(&format!(": {}\n", summ.fmt()))
    }

    fn write_run_finish(&mut self) -> io::Result<()> {
        self.write_plain("\ndudect benches complete\n\n")
    }
}

/// Runs the given benches under the given options and prints the output to the console
pub fn run_benches_console(opts: BenchOpts, benches: Vec<BenchMetadata>) -> io::Result<()> {
    // TODO: Consider making this do screen updates in continuous mode
    // TODO: Consider making this run in its own thread
    fn callback(event: &BenchEvent, st: &mut ConsoleBenchState) -> io::Result<()> {
        match (*event).clone() {
            BenchEvent::BContStart => st.write_continuous_start(),
            BenchEvent::BBegin(ref filtered_benches) => st.write_run_start(filtered_benches.len()),
            BenchEvent::BWait(ref b) => st.write_bench_start(b),
            BenchEvent::BResult(msg) => {
                let (_, summ) = msg;
                st.write_result(&summ)
            }
            BenchEvent::BSeed(seed, ref name) => st.write_seed(seed, name),
        }
    }

    let mut st = ConsoleBenchState::default();
    st.max_name_len = benches.iter().map(|t| t.name.0.len()).max().unwrap_or(0);

    run_benches(&opts, benches, |x| callback(&x, &mut st))?;
    st.write_run_finish()
}

/// Returns an atomic bool that indicates whether Ctrl-C was pressed
fn setup_kill_bit() -> Arc<AtomicBool> {
    let x = Arc::new(AtomicBool::new(false));
    let y = x.clone();

    ctrlc::set_handler(move || y.store(true, atomic::Ordering::SeqCst))
        .expect("Error setting Ctrl-C handler");

    x
}

fn run_benches<F>(opts: &BenchOpts, benches: Vec<BenchMetadata>, mut callback: F) -> io::Result<()>
where
    F: FnMut(BenchEvent) -> io::Result<()>,
{
    use self::BenchEvent::*;

    let filter = &opts.filter;
    let filtered_benches = filter_benches(filter, benches);
    let filtered_names = filtered_benches.iter().map(|b| b.name).collect();

    // Write the CSV header line to the file if the file is defined
    let mut file_out = opts.file_out.as_ref().map(|filename| {
        OpenOptions::new()
            .write(true)
            .truncate(true)
            .create(true)
            .open(filename)
            .expect(&*format!(
                "Could not open file '{:?}' for writing",
                filename
            ))
    });
    file_out.as_mut().map(|f| {
        f.write(b"benchname,class,runtime")
            .expect("Error writing CSV header to file")
    });

    // Make a bencher with the optional file output specified
    let mut cb: CtBencher = {
        let mut d = CtBencher::new();
        d.file_out = file_out;
        d
    };

    if opts.continuous {
        callback(BContStart)?;

        if filtered_benches.is_empty() {
            match *filter {
                Some(ref f) => panic!("No benchmark matching '{}' was found", f),
                None => return Ok(()),
            }
        }

        // Get a bit that tells us when we've been killed
        let kill_bit = setup_kill_bit();

        // Continuously run the first matched bench we see
        let mut filtered_benches = filtered_benches;
        let bench = filtered_benches.remove(0);

        // If a seed was specified for this bench, use it. Otherwise, use a random seed
        let seed = bench.seed.unwrap_or_else(CtBencher::rand_seed);
        cb.seed_with(seed);
        callback(BSeed(seed, bench.name))?;

        loop {
            callback(BWait(bench.name))?;
            let msg = run_bench_with_bencher(&bench.name, bench.benchfn, &mut cb);
            callback(BResult(msg))?;

            // Check if the program has been killed. If so, exit
            if kill_bit.load(atomic::Ordering::SeqCst) {
                process::exit(0);
            }
        }
    } else {
        callback(BBegin(filtered_names))?;

        // Run different benches
        for bench in filtered_benches {
            // Clear the data out from the previous bench, but keep the CSV file open
            cb.clear_data();

            // If a seed was specified for this bench, use it. Otherwise, use a random seed
            let seed = bench.seed.unwrap_or_else(CtBencher::rand_seed);
            cb.seed_with(seed);
            callback(BSeed(seed, bench.name))?;

            callback(BWait(bench.name))?;
            let msg = run_bench_with_bencher(&bench.name, bench.benchfn, &mut cb);
            callback(BResult(msg))?;
        }
        Ok(())
    }
}

fn run_bench_with_bencher(name: &BenchName, benchfn: BenchFn, cb: &mut CtBencher) -> MonitorMsg {
    let summ = cb.go(benchfn);

    // Write the runtime samples out
    let samples_iter = cb.samples.0.iter().zip(cb.samples.1.iter());
    if let Some(f) = cb.file_out.as_mut() {
        for (x, y) in samples_iter {
            write!(f, "\n{},0,{}", name.0, x).expect("Error writing data to file");
            write!(f, "\n{},0,{}", name.0, y).expect("Error writing data to file");
        }
    };

    (*name, summ)
}

fn filter_benches(filter: &Option<String>, bs: Vec<BenchMetadata>) -> Vec<BenchMetadata> {
    let mut filtered = bs;

    // Remove benches that don't match the filter
    filtered = match *filter {
        None => filtered,
        Some(ref filter) => filtered
            .into_iter()
            .filter(|b| b.name.0.contains(&filter[..]))
            .collect(),
    };

    // Sort them alphabetically
    filtered.sort_by(|b1, b2| b1.name.0.cmp(&b2.name.0));

    filtered
}

// NOTE: We don't have a proper black box in stable Rust. This is a workaround implementation,
// that may have a too big performance overhead, depending on operation, or it may fail to
// properly avoid having code optimized out. It is good enough that it is used by default.
//
// A function that is opaque to the optimizer, to allow benchmarks to pretend to use outputs to
// assist in avoiding dead-code elimination.
#[cfg(not(feature = "core-hint-black-box"))]
fn black_box<T>(dummy: T) -> T {
    unsafe {
        let ret = ::std::ptr::read_volatile(&dummy);
        ::std::mem::forget(dummy);
        ret
    }
}

#[cfg(feature = "core-hint-black-box")]
#[inline]
fn black_box<T>(dummy: T) -> T {
    ::core::hint::black_box(dummy)
}

/// Specifies the distribution that a particular run belongs to
#[derive(Copy, Clone)]
pub enum Class {
    Left,
    Right,
}

/// Used for timing single operations at a time
#[derive(Default)]
pub struct CtRunner {
    // Runtimes of left and right distributions in nanoseconds
    runtimes: (Vec<u64>, Vec<u64>),
}

impl CtRunner {
    /// Runs and times a single operation whose constant-timeness is in question
    pub fn run_one<T, F>(&mut self, class: Class, f: F)
    where
        F: Fn() -> T,
    {
        let start = Instant::now();
        black_box(f());
        let end = Instant::now();

        let runtime = {
            let dur = end.duration_since(start);
            dur.as_secs() * 1_000_000_000 + u64::from(dur.subsec_nanos())
        };

        match class {
            Class::Left => self.runtimes.0.push(runtime),
            Class::Right => self.runtimes.1.push(runtime),
        }
    }
}
