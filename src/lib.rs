#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use ink_lang as ink;

/// Fat contract version SaaS3 decentralized oracle runtime
/// `config`  should be called after the deployment of the contract
/// With phala TEE environment, the oracle data like API token can be safely stored in the contract
#[ink::contract(env = pink_extension::PinkEnvironment)]
mod druntime {
    use core::str::Bytes;

    use alloc::{borrow::ToOwned, string::String, string::ToString, vec::Vec};
    use ink_storage::traits::{PackedLayout, SpreadLayout};
    use phat_offchain_rollup::{
        clients::evm::read::{Action, QueuedRollupSession},
        lock::GLOBAL as GLOBAL_LOCK,
        RollupHandler, RollupResult,
    };
    use pink_extension as pink;
    use pink_web3::ethabi;
    use primitive_types::H160;
    use scale::{Decode, Encode};

    use abi::{encode::str_chunk32_bytes, ABI};
    use alloc::vec;
    use hex;
    use pink::http_get;
    use primitive_types::U256;

    /// The the storage of druntime
    #[ink(storage)]
    pub struct Oracle {
        owner: AccountId,
        /// oracle config, is none before config
        config: Option<Config>,
    }

    #[derive(Encode, Decode, Debug, PackedLayout, SpreadLayout)]
    #[cfg_attr(
        feature = "std",
        derive(scale_info::TypeInfo, ink_storage::traits::StorageLayout)
    )]
    struct Config {
        rpc: String,
        anchor: [u8; 20],
        qjs: String,
        url: String,
        apikey: Option<String>,
    }

    #[derive(Encode, Decode, Debug, PartialEq)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum Error {
        BadOrigin,
        NotConfigurated,
        BadAbi,
        FailedToGetStorage,
        FailedToDecodeStorage,
        FailedToDecodeOracleRequest,
        FailedToDecodeParams,
        FailedToDecodeResBody,
        FailedToDecodeByPath,
        FailedToGetInternalPath,
        Web2StatusError,
        TimesTooSmall,
        FailedToCreateRollupSession,
        FailedToFetchLock,
        FailedToReadQueueHead,
        FailedToDecodeNumberFromJson,
        TypeNotSet,
        InvalidType,
        InvalidRootValue,
        NumberSignNotMatch,
        EncodeNonDecimalNumberTo256Failed,
        EncodeStringTo32BytesFailed,
        TimesParseFailed,
        NotANumberOrString,
        FailedToDecodeQjsCodeHash,
        FailedTurnQjsCodeHashToHashType,
        InvalidUtf8,
        EvalJsError,
        JsScriptReturnError,
    }

    type Result<T> = core::result::Result<T, Error>;

    impl Oracle {
        #[ink(constructor)]
        pub fn default() -> Self {
            Self {
                owner: Self::env().caller(),
                config: None,
            }
        }

        /// Configures the oracle
        #[ink(message)]
        pub fn config(
            &mut self,
            // saas3 protocol target chain rpc
            target_chain_rpc: Option<String>,
            // phala anchor contract address
            anchor_contract_addr: Option<H160>,
            // js engine code hash string
            js_engine_code_hash: Option<String>,
            // web2 api url prefix
            web2_api_url_prefix: Option<String>,
            // web2 api key
            api_key: Option<String>,
        ) -> Result<()> {
            self.ensure_owner()?;
            if self.config.is_none() {
                if target_chain_rpc.is_none()
                    || anchor_contract_addr.is_none()
                    || js_engine_code_hash.is_none()
                {
                    return Err(Error::NotConfigurated);
                }
                self.config = Some(Config {
                    rpc: target_chain_rpc.unwrap(),
                    anchor: anchor_contract_addr.unwrap().into(),
                    qjs: js_engine_code_hash.unwrap().into(),
                    url: web2_api_url_prefix.unwrap_or_default(),
                    apikey: api_key,
                });
            } else {
                if let Some(rpc) = target_chain_rpc {
                    self.config.as_mut().unwrap().rpc = rpc;
                }
                if let Some(anchor) = anchor_contract_addr {
                    self.config.as_mut().unwrap().anchor = anchor.into();
                }
                if let Some(qjs) = js_engine_code_hash {
                    self.config.as_mut().unwrap().qjs = qjs.into();
                }
                if let Some(url) = web2_api_url_prefix {
                    self.config.as_mut().unwrap().url = url;
                }
                if let Some(apikey) = api_key {
                    self.config.as_mut().unwrap().apikey = Some(apikey);
                }
            }
            Ok(())
        }

        fn encode_from_string_to_256(
            &self,
            s: String,
            signed: bool,
            _times: u32,
        ) -> Result<ethabi::Token> {
            let is_signed = s.starts_with("-");
            if is_signed && !signed {
                // eg. try encode "-3" to u256
                return Err(Error::NumberSignNotMatch);
            }
            let pos = s.find(".");
            if pos != None {
                // offset count
                let y = s.len() - pos.unwrap() - 1;

                if 10_u32.pow(y as u32) > _times {
                    return Err(Error::TimesTooSmall);
                }

                // remove decimal point
                let mut s = s.to_owned();
                s.retain(|c| c != '.' && c != '-');

                // alreay multiply by 10^y
                let mut v = s.parse::<u64>().unwrap();

                // times must >= 10^y
                v = v * (_times / 10_u32.pow(y as u32)) as u64;

                // encode to u256
                if is_signed {
                    return Ok(ethabi::Token::Int(U256::from(v)));
                } else {
                    return Ok(ethabi::Token::Uint(U256::from(v)));
                }
            } else {
                // not a decimal number
                let mut s = s.to_owned();
                s.retain(|c| c != '-');

                #[cfg(feature = "std")]
                println!("s: {}", s);

                if signed {
                    s.parse::<i64>()
                        .map(|x| ethabi::Token::Int(U256::from(x)))
                        .map_err(|_| Error::EncodeNonDecimalNumberTo256Failed)
                } else {
                    s.parse::<u64>()
                        .map(|x| ethabi::Token::Uint(U256::from(x)))
                        .map_err(|_| Error::EncodeNonDecimalNumberTo256Failed)
                }
            }
        }

        fn encode_answer(&self, s: String, _type: &str, _times: u32) -> Result<ethabi::Token> {
            #[cfg(feature = "std")]
            println!("String: {}", s);

            return match _type {
                "string" => Ok(ethabi::Token::String(s)),
                "string32" => {
                    let chunk = str_chunk32_bytes(&s.to_string())
                        .map_err(|_| Error::EncodeStringTo32BytesFailed)?;
                    Ok(ethabi::Token::FixedBytes(chunk))
                }
                "uint256" => Ok(self.encode_from_string_to_256(s, false, _times)?),
                "int256" => Ok(self.encode_from_string_to_256(s, true, _times)?),
                _ => Err(Error::InvalidType),
            };
        }

        #[ink(message)]
        pub fn run_js(&self, json_text: String, path: String) -> Result<String> {
            let script = include_str!("js/dist/index.js");
            let r = crate::js::eval(script, &[json_text, path]);
            if r.is_err() {
                pink::error!("eval js error: {:?}", r.err().unwrap());
                return Err(Error::EvalJsError);
            }
            match r.unwrap() {
                crate::js::Output::String(s) => {
                    #[cfg(feature = "std")]
                    println!("s: {}", s);

                    Err(Error::JsScriptReturnError)
                }
                crate::js::Output::Bytes(b) => Ok(String::from_utf8(b).unwrap()),
            }
        }

        fn handle_req(&self) -> Result<Option<RollupResult>> {
            #[cfg(feature = "std")]
            println!("handling req");

            let Config {
                rpc,
                anchor,
                qjs,
                url,
                apikey: _,
            } = self.config.as_ref().ok_or(Error::NotConfigurated)?;

            let mut rollup =
                QueuedRollupSession::new(rpc, anchor.into(), |_locks| {}).map_err(|e| {
                    pink::warn!("Failed to create rollup session: {e:?}");
                    Error::FailedToCreateRollupSession
                })?;

            // Declare write to global lock since it pops an element from the queue
            rollup.lock_read(GLOBAL_LOCK).map_err(|e| {
                pink::warn!("Failed to fetch lock: {e:?}");
                Error::FailedToFetchLock
            })?;

            #[cfg(feature = "std")]
            println!("reading raw data from qeueue ...");

            // Read the first item in the queue (return if the queue is empty)
            let (raw_item, idx) = rollup.queue_head().map_err(|e| {
                pink::warn!("Failed to read queue head: {e:?}");
                Error::FailedToReadQueueHead
            })?;

            let raw_item = match raw_item {
                Some(v) => v,
                _ => {
                    pink::debug!("No items in the queue. Returning.");
                    return Ok(None);
                }
            };

            #[cfg(feature = "std")]
            println!("raw_item {:?}", raw_item);

            // Decode the queue data by ethabi (u256, bytes)
            let decoded = ethabi::decode(
                &[ethabi::ParamType::Uint(32), ethabi::ParamType::Bytes],
                &raw_item,
            )
            .or(Err(Error::FailedToDecodeStorage))?;

            let (rid, parameter_abi_bytes) = match decoded.as_slice() {
                [ethabi::Token::Uint(reqid), ethabi::Token::Bytes(content)] => (reqid, content),
                _ => return Err(Error::FailedToDecodeOracleRequest),
            };

            #[cfg(feature = "std")]
            println!("ask_id {:?}", rid);

            let decoded_abi = ABI::decode_from_slice(parameter_abi_bytes, true)
                .or(Err(Error::FailedToDecodeParams))?;

            #[cfg(feature = "std")]
            println!("Got decoded params abi {:?}", decoded_abi);

            // build url suffix
            let url_suffix = decoded_abi
                .params
                .iter()
                .filter(|param| !param.get_name().starts_with("_")) // skip the internal params
                .map(|param| param.get_name().to_string() + "=" + &param.get_value().to_string())
                .collect::<Vec<String>>()
                .join("&");

            // path is optional, if not set, we will use the root path
            let _path = decoded_abi
                .params
                .iter()
                .find(|param| param.get_name() == "_path")
                .get_or_insert(&abi::Param::String {
                    name: "_path".to_string(),
                    value: "".to_string(),
                })
                .get_value();

            // _type is necessary
            let _type = decoded_abi
                .params
                .iter()
                .find(|param| param.get_name() == "_type")
                .ok_or(Error::TypeNotSet)?
                .get_value();

            // _times is only necessary for float number data
            let _times = decoded_abi
                .params
                .iter()
                .find(|param| param.get_name() == "_times")
                .get_or_insert(&abi::Param::String {
                    name: "_times".to_string(),
                    value: "100".to_string(),
                })
                .get_value()
                .parse::<u32>()
                .map_err(|_| Error::TimesParseFailed)?;

            #[cfg(feature = "std")]
            println!("Got url suffix {:?}", url_suffix);

            let uri = url.to_owned() + "?" + &url_suffix;

            #[cfg(feature = "std")]
            println!("Got uri {:?}", uri);

            let resp = http_get!(uri);
            if resp.status_code != 200 {
                return Err(Error::Web2StatusError);
            }

            #[cfg(feature = "std")]
            println!("Got response {:?}", resp.body);

            let jt = core::str::from_utf8(resp.body.as_slice()).map_err(|_| Error::InvalidUtf8)?;
            let v = self.run_js(jt.to_string(), _path)?;

            #[cfg(feature = "std")]
            println!("Got value {:#?}", v);

            let answer = self.encode_answer(v, &_type, _times)?;

            #[cfg(feature = "std")]
            println!("answer {:#?}", answer);

            //let answer = ethabi::encode(&[answer]);
            let answer = ethabi::encode(&[ethabi::Token::Uint(U256::from(1))]);

            // Apply the response to request
            let payload =
                ethabi::encode(&[ethabi::Token::Uint(*rid), ethabi::Token::Bytes(answer)]);

            rollup
                .tx_mut()
                .action(Action::Reply(payload))
                .action(Action::ProcessedTo(idx + 1));

            Ok(Some(rollup.build()))
        }

        /// Returns BadOrigin error if the caller is not the owner
        fn ensure_owner(&self) -> Result<()> {
            if self.env().caller() == self.owner {
                Ok(())
            } else {
                Err(Error::BadOrigin)
            }
        }
    }

    impl RollupHandler for Oracle {
        /// The anchor contract message handler
        /// It should be called by a scheduled task
        #[ink(message)]
        fn handle_rollup(&self) -> core::result::Result<Option<RollupResult>, Vec<u8>> {
            self.handle_req().map_err(|e| Encode::encode(&e))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use ink_lang as ink;

        #[ink::test]
        fn encode_from_string_to_256_should_ok() {
            let _ = env_logger::try_init();
            pink_extension_runtime::mock_ext::mock_all_ext();

            let oracle = Oracle::default();
            let v = oracle
                .encode_from_string_to_256("1.23".to_string(), false, 100)
                .unwrap();
            assert_eq!(v, ethabi::Token::Uint(123.into()));
        }

        #[ink::test]
        fn encode_from_string_to_256_should_ok_with_signed_decimal() {
            let _ = env_logger::try_init();
            pink_extension_runtime::mock_ext::mock_all_ext();

            let oracle = Oracle::default();
            let v = oracle
                .encode_from_string_to_256("-1.23".to_string(), true, 100)
                .unwrap();
            assert_eq!(v, ethabi::Token::Int(123.into()));
        }

        #[ink::test]
        fn encode_from_string_to_256_should_ok_with_signed_non_decimal() {
            let _ = env_logger::try_init();
            pink_extension_runtime::mock_ext::mock_all_ext();

            let oracle = Oracle::default();
            let v = oracle
                .encode_from_string_to_256("-123".to_string(), true, 100)
                .unwrap();
            assert_eq!(v, ethabi::Token::Int(123.into()));
        }

        #[ink::test]
        fn encode_from_string_to_256_should_fail() {
            let _ = env_logger::try_init();
            pink_extension_runtime::mock_ext::mock_all_ext();

            let oracle = Oracle::default();
            let v = oracle.encode_from_string_to_256("1.23".to_string(), false, 10);
            assert_eq!(v.err().unwrap(), Error::TimesTooSmall);
        }

        #[ink::test]
        fn encode_from_string_to_256_should_ok_with_non_decimal_str() {
            let _ = env_logger::try_init();
            pink_extension_runtime::mock_ext::mock_all_ext();

            let oracle = Oracle::default();
            let v = oracle.encode_from_string_to_256("123".to_string(), false, 10);
            assert_eq!(v.unwrap(), ethabi::Token::Uint(123.into()));
        }

        #[ink::test]
        fn eval_js_should_ok() {
            let _ = env_logger::try_init();
            pink_extension_runtime::mock_ext::mock_all_ext();

            let oracle = Oracle::default();
            let r = hex::decode("ab2fde00a6df6a0443ae4fafc0d27c19907b105475e119556b4ad35acda0a90b");
            if r.is_err() {
                println!("err {:#?}", r.err().unwrap());
            }
            let r = oracle.run_js(
                r#"{ a: "b"}"#.to_string(), "$.a".to_string()
                
            );
            if r.is_err() {
                println!("err {:#?}", r.err().unwrap());
            }
        }

        fn consts() -> (String, H160, String) {
            dotenvy::dotenv().ok();
            // let rpc = env::var("RPC").unwrap();
            //let rpc = "https://goerli.infura.io/v3/e5cbadfb7319409f981ee0231c256639".to_string();
            // let rpc = "https://moonbase-alpha.public.blastapi.io".to_string();
            // let rpc = "https://rpc.api.moonbase.moonbeam.network".to_string();
            //let rpc = "https://moonbeam-alpha.api.onfinality.io/public".to_string();
            let rpc = "https://polygon-mainnet.public.blastapi.io".to_string();
            let qjs = "ab2fde00a6df6a0443ae4fafc0d27c19907b105475e119556b4ad35acda0a90b";

            let anchor_addr: [u8; 20] = hex::decode("63De844992279204a7132C936EF07c27A770D809")
                .expect("hex decode failed")
                .try_into()
                .expect("invald length");
            let anchor_addr: H160 = anchor_addr.into();
            (rpc, anchor_addr, qjs.to_string())
        }

        #[ink::test]
        fn default_works() {
            let _ = env_logger::try_init();
            pink_extension_runtime::mock_ext::mock_all_ext();

            let (rpc, anchor_addr, qjs) = consts();

            let mut oracle = Oracle::default();
            oracle
                .config(
                    Some(rpc),
                    Some(anchor_addr),
                    Some(qjs),
                    Some("https://rpc.saas3.io:3301/saas3/web2/qatar2022/played".to_string()),
                    None,
                )
                .unwrap();
            let res = oracle.handle_req().unwrap();
            println!("res: {:#?}", res);
        }
    }
}

mod js {
    use super::*;

    use alloc::string::String;
    use alloc::vec::Vec;
    use pink_extension as pink;
    use scale::{Decode, Encode};

    #[derive(Debug, Encode, Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum Output {
        String(String),
        Bytes(Vec<u8>),
    }

    pub fn eval(script: &str, args: &[String]) -> Result<Output, String> {
        use ink_env::call;
        //let system = pink::system::SystemRef::instance();
        //let delegate = system
        //    .get_driver("JsDelegate".into())
        //    .ok_or("No JS driver found")?;
        let hash: ink_env::Hash = hex::decode("ab2fde00a6df6a0443ae4fafc0d27c19907b105475e119556b4ad35acda0a90b").unwrap().as_slice().try_into().unwrap();

        pink::debug!("args {:#?}", args);

        let result = call::build_call::<pink::PinkEnvironment>()
            .call_type(call::DelegateCall::new().code_hash(hash))
            .exec_input(
                call::ExecutionInput::new(call::Selector::new(0x49bfcd24_u32.to_be_bytes()))
                    .push_arg(script)
                    .push_arg(args),
            )
            .returns::<Result<Output, String>>()
            .fire();
        if result.is_err() {
            pink::error!("result is error {:#?}", result.err().unwrap());
            return Err(String::from("result is error"));
        }
        pink::debug!("eval result: {result:?}");
        result.unwrap()
    }

    pub trait ConvertTo<To> {
        fn convert_to(&self) -> To;
    }

    impl<F, T> ConvertTo<T> for F
    where
        F: AsRef<[u8; 32]>,
        T: From<[u8; 32]>,
    {
        fn convert_to(&self) -> T {
            (*self.as_ref()).into()
        }
    }
}
