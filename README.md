# druntime-fat

Fat contract version SaaS3 decentralized oracle runtime.
`config`  should be called after the deployment of the contract.
With phala TEE environment, the oracle data like API token can be safely stored in the contract.


## Build
```
cd src/js && yarn run build
cd -
cargo +nightly contract build --release
```

## Test
```
cargo +nightly test
```