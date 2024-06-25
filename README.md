# Microsoft CAPI utilities

## Build

```
$ make
```

## HTTPS client

```
$ make https
```

```
$ export WINEDEBUG=fixme-all,err-winediag,-winsock,+secur32
```

```
$ wine https -sSERVER -pPORT -f/api-v1-server/get-time -H"Authorization: Basic `echo -n 'USER:PASS' | base64`"
```

```
$ winedbg --gdb https.exe -sSERVER -pPORT -f/api-v1-server/get-time -H"Authorization: Basic `echo -n 'USER:PASS' | base64`"
(gdb) break main
(gdb) continue
```

```
> https -sSERVER -pPORT -I"cpsspap.dll" -f/api-v1-server/get-time -H"Authorization: Basic `echo -n 'USER:PASS' | base64`" -W
```

```
> https -sSERVER -pPORT -I"C:\\Program Files\\Common Files\\Avest\\Avest CSP\\AvSSPc.dll" -f/api-v1-server/get-time -H"Authorization: Basic `echo -n 'USER:PASS' | base64`"
```

## providers

```
$ make providers
```

```
$ wine providers.exe
```

```
> providers
```

## provider-algs

```
$ make provider-algs
```

```
> provider-algs -t 1
> provider-algs -t 80
> provider-algs -t 422 -x
```

## keycont

```
$ make keycont
```

```
> certutil -csplist
> providers
```

List key containers

```
> keycont -n "Avest CSP Bel Pro" -t 423 -L
karp
tuna
```

```
> keycont -t 423 -L
karp
tuna
```

Create key container

```
> keycont -n "Avest CSP Bel Pro" -t 423 -C shark
```

Create key container with AT_SIGNATURE key

```
> keycont -n "Crypto-Pro GOST R 34.10-2012 Cryptographic Service Provider" -t 80 -C admin -s
```

Delete key container

```
> keycont -n "Avest CSP Bel Pro" -t 423 -D tuna
```

## create-rand

```
$ make create-rand
```

```
> create-rand -t 422
ac92a4c564957309
```

```
$ wine create-rand -t 1 -s 16
47294e38c0e9be3906c53b23d571ce61
```

## create-hash

```
$ make create-hash
```

Determine HASH Alg Ids

```
$ wine provider-algs.exe -t 1
```

MD5

```
$ echo -n HELLO | wine create-hash -t 1 -a 0x8003
eb61eead90e3b899c6bcbe27ac581660

$ echo -n HELLO | md5sum
eb61eead90e3b899c6bcbe27ac581660  -

$ echo -n HELLO | openssl dgst -md5
MD5(stdin)= eb61eead90e3b899c6bcbe27ac581660
```

SHA1

```
$ echo -n HELLO | wine create-hash -t 1 -a 32772
c65f99f8c5376adadddc46d5cbcf5762f9e55eb7

$ echo -n HELLO | sha1sum
c65f99f8c5376adadddc46d5cbcf5762f9e55eb7  -

$ echo -n HELLO | openssl dgst -sha1
SHA1(stdin)= c65f99f8c5376adadddc46d5cbcf5762f9e55eb7
```

Avest CSP vs OpenSSL Bee2 СТБ 34.101.31

```
> type file.txt | create-hash -t 422 -a 0x8039
497bc3d653353a4b45885bc922dc3f7b483416447ade3931e86c22a116897815

> type file.txt | create-hash -t 422 -a 0x8033
497bc3d653353a4b45885bc922dc3f7b483416447ade3931e86c22a116897815
```

```
$ echo -n HELLO | openssl dgst -belt-hash
(stdin)= 497bc3d653353a4b45885bc922dc3f7b483416447ade3931e86c22a116897815
```

CryptoPro CSP vs OpenSSL

```
$ echo -n HELLO | wine create-hash -t 80 -a 0x8021
628d78193859861a63c8bf2eba3a37d0d8cb3b4617c371e33f07879c2de71f31
```

```
$ echo -n HELLO | openssl dgst -md_gost12_256
md_gost12_256(stdin)= 628d78193859861a63c8bf2eba3a37d0d8cb3b4617c371e33f07879c2de71f31
```

## create-req

```
$ make create-req
```

"1.2.643.7.1.1.3.2" Алгоритм цифровой подписи ГОСТ Р 34.10-2012 для ключей длины 256 бит

```
> create-req -n "Crypto-Pro GOST R 34.10-2012 Cryptographic Service Provider" -t 80 -a "1.2.643.7.1.1.3.2" -r test
```

"1.2.112.0.2.0.34.101.45.12" Алгоритм ЭЦП с функцией хэширования СТБ 34.101.45/31 (bign-with-hbelt)

```
> create-req -n "Avest CSP Bel" -t 422 -a "1.2.112.0.2.0.34.101.45.12" -c BY
```
