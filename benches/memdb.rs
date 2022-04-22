use byteorder::{ByteOrder, LittleEndian};
use criterion::{criterion_group, criterion_main, Criterion};

use rsleveldb::memdb::{BytesComparer, MemDb};

pub fn put_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("put iteration 10 times");
    group.sample_size(10);

    let mut keys: Vec<Vec<u8>> = Vec::new();
    for i in 0..1_000_000 {
        let mut k = vec![0;4];
        LittleEndian::write_u32(&mut k, i as u32);
        keys.push(k);
    }
    //c.bench_function("put", |b| b.iter(|| put(&keys)));
    group.bench_function("put", |b| b.iter(|| put(&keys)));

    group.finish();
}

fn put(buf: &Vec<Vec<u8>>) {
    let default_cmp: BytesComparer = Default::default();
    let mut memdb = MemDb::new(&default_cmp);
    let v = vec![];
    for k in buf {
        let _ = memdb.put(&k, &v);
    }
}

criterion_group!(benches, put_benchmark);
criterion_main!(benches);
