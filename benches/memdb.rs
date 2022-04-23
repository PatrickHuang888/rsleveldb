use byteorder::{ByteOrder, LittleEndian};
use criterion::{criterion_group, criterion_main, Criterion};
use rand::{prelude::ThreadRng, thread_rng, Rng};

use rsleveldb::memdb::{BytesComparer, MemDb};

pub fn put_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("put iteration 10 times");
    group.sample_size(10);

    let mut keys: Vec<Vec<u8>> = Vec::new();
    for i in 0..1_000_000 {
        let mut k = vec![0; 4];
        LittleEndian::write_u32(&mut k, i as u32);
        keys.push(k);
    }
    group.bench_function("put", |b| b.iter(|| put(&keys)));
    group.finish();
}

pub fn put_random_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("put random iteration 10 times");
    group.sample_size(10);

    let mut rng = thread_rng();
    let mut keys: Vec<Vec<u8>> = Vec::new();
    for _ in 0..1_000_000 {
        let mut k = vec![0; 4];
        let r: u32 = rng.gen();
        LittleEndian::write_u32(&mut k, r);
        keys.push(k);
    }
    group.bench_function("put", |b| b.iter(|| put(&keys)));
    group.finish();
}

fn put(keys: &Vec<Vec<u8>>) {
    let default_cmp: BytesComparer = Default::default();
    let mut memdb = MemDb::new(&default_cmp);
    let v = vec![];
    for k in keys {
        let _ = memdb.put(&k, &v);
    }
}

pub fn get_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("get iterate 10 times");
    group.sample_size(10);

    let default_cmp: BytesComparer = Default::default();
    let mut memdb = MemDb::new(&default_cmp);
    let mut keys: Vec<Vec<u8>> = Vec::new();
    for i in 0..1_000_000 {
        let mut k = vec![0; 4];
        LittleEndian::write_u32(&mut k, i as u32);
        keys.push(k);
    }
    let v = vec![];
    for k in &keys {
        let _ = memdb.put(k, &v);
    }

    group.bench_function("get", |b| b.iter(|| get(&memdb, &keys)));
    group.finish();
}

pub fn get_random_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("random get iterate 10 times");
    group.sample_size(10);

    let default_cmp: BytesComparer = Default::default();
    let mut memdb = MemDb::new(&default_cmp);
    let mut keys: Vec<Vec<u8>> = Vec::new();
    for i in 0..1_000_000 {
        let mut k = vec![0; 4];
        LittleEndian::write_u32(&mut k, i as u32);
        keys.push(k);
    }
    let v = vec![];
    for k in &keys {
        let _ = memdb.put(k, &v);
    }

    let mut rng = thread_rng();
    group.bench_function("get", |b| b.iter(|| get_random(&memdb, &mut rng, &keys)));
    group.finish();
}

fn get(db: &MemDb, keys: &Vec<Vec<u8>>) {
    for k in keys {
        db.get(&k);
    }
}

fn get_random(db: &MemDb, rng: &mut ThreadRng, keys: &Vec<Vec<u8>>) {
    // goleveldb random get testcase has random generation code in it, 
    for _ in 0..1_000_000 {
        let r = rng.gen_range(0..1_000_000); // fix: random gen should not be here
        db.get(&keys[r]);
    }
}

//criterion_group!(benches, put_benchmark, put_random_benchmark);
criterion_group!(benches, get_benchmark, get_random_benchmark);
criterion_main!(benches);
