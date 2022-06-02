# rsleveldb

rust version of  [leveldb](https://github.com/google/leveldb)  
some idea from [goleveldb](https://github.com/syndtr/goleveldb)

## benchmark
### memdb
have done some benchmark job on my first version memdb as goleveldb, here is the result

* put 1_000_000 key into memdb
1. goleveldb
```console
go test -run=none -benchtime=1000000x -bench Put
goos: linux
goarch: amd64
pkg: github.com/syndtr/goleveldb/leveldb/memdb
cpu: AMD Ryzen 5 3600X 6-Core Processor             
BenchmarkPut-12          	 1000000	       582.8 ns/op
BenchmarkPutRandom-12    	 1000000	       974.4 ns/op
PASS
ok  	github.com/syndtr/goleveldb/leveldb/memdb	1.586s
```
sequence put 583ns/op, random put 974ns/op

2. rsleveldb
```console
put iteration 10 times/put                                                                          
                        time:   [479.42 ms 481.18 ms 483.00 ms]
                        change: [-1.1574% -0.6530% -0.1162%] (p = 0.03 < 0.05)

put random iteration 10 times/put                                                                          
                        time:   [870.47 ms 885.05 ms 898.45 ms]
                        change: [-4.4164% -2.7461% -1.3909%] (p = 0.00 < 0.05)

```
Because benchmark in test lib is unstable, I use third party lib Criterion.rs as bench lib, and their least runtimes is 10s, so rsult above is 10 million insert.
actually result: sequence put 481ns/op, random put 885ns/op.