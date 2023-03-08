#![cfg_attr(not(feature = "std"), no_std)]
#![feature(let_else)]

#[macro_use]
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

    // To enable `(result).log_err("Reason")?`
    use phat_offchain_rollup::{clients::evm::EvmRollupClient, Action};
    use pink::ResultExt;

    use pink_extension as pink;
    use pink_web3::ethabi;
    use primitive_types::H160;
    use scale::{Decode, Encode};

    use abi::{encode::str_chunk32_bytes, ABI};
    use alloc::vec;
    use hex;
    use pink::chain_extension::HttpResponse;
    use pink::http_get;
    use pink::http_post;
    use primitive_types::U256;

    // Defined in SaaS3 Protocol
    const TYPE_RESPONSE: u32 = 0;
    const TYPE_ERROR: u32 = 1;

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
        /// Key for submiting rollup transaction
        submit_key: [u8; 32],
        qjs: String,
        url: String,
        apikey: Option<String>,
        method: String,
        auth_type: AuthType,
    }

    #[derive(Encode, Decode, Debug, PackedLayout, SpreadLayout, PartialEq)]
    #[cfg_attr(
        feature = "std",
        derive(scale_info::TypeInfo, ink_storage::traits::StorageLayout)
    )]
    pub enum AuthType {
        NoAuth,
        ApiKey,
        Bearer,
    }

    #[derive(Encode, Decode, Debug, PartialEq)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum Error {
        // basic error
        BadOrigin,
        NotConfigured,
        // config
        InvalidKeyLength,
        InvaldJsCodeHashPrefix,
        NoApiKey,
        // fetching request error
        FailedToCreateClient,
        NoRequestInQueue,
        FailedToDecode,
        // handling request error
        InvalidMethod,
        // js handling error
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
        // transaction error
        FailedToCommitTx,
        FailedToSendTransaction,
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
            submit_key: Option<U256>,
            // js engine code hash string
            js_engine_code_hash: Option<String>,
            // web2 api url prefix
            web2_api_url_prefix: Option<String>,
            // web2 api key
            api_key: Option<String>,
            // web2 api method
            method: Option<String>,
            // auth type
            auth_type: Option<String>,
        ) -> Result<()> {
            self.ensure_owner()?;
            if self.config.is_none() {
                if target_chain_rpc.is_none()
                    || anchor_contract_addr.is_none()
                    || js_engine_code_hash.is_none()
                    || submit_key.is_none()
                {
                    return Err(Error::NotConfigured);
                }
                if js_engine_code_hash.clone().unwrap().starts_with("0x") {
                    return Err(Error::InvaldJsCodeHashPrefix);
                }
                self.config = Some(Config {
                    rpc: target_chain_rpc.unwrap(),
                    anchor: anchor_contract_addr.unwrap().into(),
                    submit_key: submit_key.unwrap().into(),
                    qjs: js_engine_code_hash.unwrap(),
                    url: web2_api_url_prefix.unwrap_or_default(),
                    apikey: api_key.clone(),
                    method: method.unwrap_or("GET".to_string()),
                    auth_type: AuthType::NoAuth,
                });
                let auth_type = auth_type.unwrap_or("NoAuth".into());
                match auth_type.to_ascii_uppercase().as_str() {
                    "NOAUTH" => self.config.as_mut().unwrap().auth_type = AuthType::NoAuth,
                    "APIKEY" => self.config.as_mut().unwrap().auth_type = AuthType::ApiKey,
                    "BEARER" => self.config.as_mut().unwrap().auth_type = AuthType::Bearer,
                    _ => return Err(Error::InvalidType),
                }
                if let Some(ak) = api_key {
                    if self.config.as_mut().unwrap().auth_type == AuthType::Bearer
                        && !ak.starts_with("Bearer ")
                    {
                        self.config.as_mut().unwrap().apikey = Some(format!("Bearer {}", ak));
                    }
                }
            } else {
                if let Some(rpc) = target_chain_rpc {
                    self.config.as_mut().unwrap().rpc = rpc;
                }
                if let Some(anchor) = anchor_contract_addr {
                    self.config.as_mut().unwrap().anchor = anchor.into();
                }
                if let Some(sk) = submit_key {
                    self.config.as_mut().unwrap().submit_key =
                        sk.try_into().or(Err(Error::InvalidKeyLength))?;
                }
                if let Some(qjs) = js_engine_code_hash {
                    if qjs.starts_with("0x") {
                        return Err(Error::InvaldJsCodeHashPrefix);
                    }
                    self.config.as_mut().unwrap().qjs = qjs;
                }
                if let Some(url) = web2_api_url_prefix {
                    self.config.as_mut().unwrap().url = url;
                }
                if let Some(apikey) = api_key {
                    self.config.as_mut().unwrap().apikey = Some(apikey);
                }
                if let Some(method) = method {
                    self.config.as_mut().unwrap().method = method;
                }
                if let Some(auth_type) = auth_type {
                    match auth_type.to_ascii_uppercase().as_str() {
                        "NOAUTH" => self.config.as_mut().unwrap().auth_type = AuthType::NoAuth,
                        "APIKEY" => self.config.as_mut().unwrap().auth_type = AuthType::ApiKey,
                        "BEARER" => self.config.as_mut().unwrap().auth_type = AuthType::Bearer,
                        _ => return Err(Error::InvalidType),
                    };
                }
            }
            Ok(())
        }

        /// Transfers the ownership of the contract (admin only)
        #[ink(message)]
        pub fn transfer_ownership(&mut self, new_owner: AccountId) -> Result<()> {
            self.ensure_owner()?;
            self.owner = new_owner;
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
        pub fn test_run_js(&self, url: String, path: String) -> Result<String> {
            let config = self.ensure_configured()?;

            #[cfg(feature = "std")]
            println!("config {:#?}", config);

            pink::debug!("config {:#?}", config);

            let mut url = url.clone();
            let mut headers = vec![];
            match config.auth_type {
                AuthType::ApiKey => {
                    url = format!("{}&apikey={}", url, config.apikey.clone().unwrap());
                }
                AuthType::Bearer => {
                    headers.push(("Authorization".to_string(), config.apikey.clone().unwrap()));
                    headers.push(("Content-Type".to_string(), "application/json".to_string()));
                }
                _ => {
                    // do nothing
                }
            }

            #[cfg(feature = "std")]
            println!("url {:#?}, headers {:#?}", url, headers);

            let resp: HttpResponse = match config.method.as_str() {
                "GET" => {
                    http_get!(url)
                }
                "POST" => {
                    #[cfg(feature = "std")]
                    println!("doing http_post!");

                    http_post!(
                        url,
                        r#"{
                        "model": "text-davinci-edit-001",
                        "input": "我吃过了午饭",
                        "instruction": "Fix the spelling mistakes"
                      }"#,
                        headers
                    )
                }
                _ => {
                    return Err(Error::InvalidMethod);
                }
            };
            #[cfg(feature = "std")]
            println!("response code {}, {:#?}", resp.status_code, resp.body);

            #[cfg(feature = "std")]
            println!("Got response {:#?}", resp.body);

            let jt = core::str::from_utf8(resp.body.as_slice()).map_err(|_| Error::InvalidUtf8)?;
            pink::debug!("Json string: {:#?}", jt);

            #[cfg(feature = "std")]
            println!("Json string: {:#?}", jt);

            if resp.status_code != 200 {
                return Err(Error::Web2StatusError);
            }

            let v = self.run_js(config.qjs.clone(), jt.to_string(), path)?;
            Ok(v)
        }

        #[ink(message)]
        pub fn run_js(&self, delegate: String, json_text: String, path: String) -> Result<String> {
            let script = include_str!("js/dist/index.js");
            let r = crate::js::eval(&delegate, script, &[json_text.clone(), path.clone()]);
            if r.is_err() {
                pink::error!(
                    "eval js error: {:?}, json_text: {:?}, path: {:?}",
                    r.err().unwrap(),
                    json_text,
                    path
                );
                return Err(Error::EvalJsError);
            }
            match r.unwrap() {
                crate::js::Output::String(s) => {
                    pink::debug!("Output String {:?}", s);
                    Ok(s)
                }
                crate::js::Output::Bytes(b) => Ok(String::from_utf8(b).unwrap()),
            }
        }

        /// Processes a oracle request by a rollup transaction
        #[ink(message)]
        pub fn answer(&self) -> Result<Option<Vec<u8>>> {
            use ethabi::Token;
            let config = self.ensure_configured()?;
            // Initialize a rollup client. The client tracks a "rollup transaction" that allows you
            // to read, write, and execute actions on the target chain with atomicity.
            let mut client = connect(&config)?;
            let action = match self.handle_req(&mut client)? {
                OracleResponse::Response(rid, answer) => ethabi::encode(&[
                    Token::Uint(TYPE_RESPONSE.into()),
                    Token::Uint(rid),
                    Token::Bytes(answer.into()),
                ]),
                OracleResponse::Error(rid, error) => ethabi::encode(&[
                    Token::Uint(TYPE_ERROR.into()),
                    Token::Uint(rid.unwrap_or_default()),
                    Token::Bytes(ethabi::encode(&[ethabi::Token::Uint((error as u8).into())])),
                ]),
            };
            client.action(Action::Reply(action));
            maybe_submit_tx(client, &config)
        }

        fn handle_req(&self, client: &mut EvmRollupClient) -> Result<OracleResponse> {
            #[cfg(feature = "std")]
            println!("handling req");

            use ethabi::ParamType;
            use pink_kv_session::traits::QueueSession;

            let config = self.ensure_configured()?;

            // Get a request if presents
            let raw_req = client
                .session()
                .pop()
                .log_err("answer_request: failed to read queue")
                .or(Err(Error::FailedToGetStorage))?
                .ok_or(Error::NoRequestInQueue)?;

            // Decode the queue data by ethabi (u256, bytes)
            let Ok(decoded) = ethabi::decode(&[ParamType::Uint(32), ParamType::Bytes], &raw_req) else {
                return Ok(OracleResponse::Error(None, Error::FailedToDecode))
            };

            let (rid, abi_bytes) = match decoded.as_slice() {
                [ethabi::Token::Uint(reqid), ethabi::Token::Bytes(content)] => (reqid, content),
                _ => return Err(Error::FailedToDecodeOracleRequest),
            };

            let decoded_abi =
                ABI::decode_from_slice(abi_bytes, true).or(Err(Error::FailedToDecodeParams))?;

            #[cfg(feature = "std")]
            println!("Got decoded params abi {:?}", decoded_abi);

            pink::debug!("decoded_abi {:#?}", decoded_abi);

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
                .find(|param| param.get_name() == "_times" && !param.get_value().is_empty())
                .get_or_insert(&abi::Param::String {
                    name: "_times".to_string(),
                    value: "100".to_string(),
                })
                .get_value()
                .parse::<u32>()
                .map_err(|_| Error::TimesParseFailed)?;

            #[cfg(feature = "std")]
            println!("Got url suffix {:?}", url_suffix);

            pink::debug!("url suffix {:?}", url_suffix);

            let uri = config.url.to_owned() + "?" + &url_suffix;

            #[cfg(feature = "std")]
            println!("Got uri {:?}", uri);

            pink::debug!("Got uri {:?}", uri);

            let resp = http_get!(uri);
            if resp.status_code != 200 {
                return Err(Error::Web2StatusError);
            }

            #[cfg(feature = "std")]
            println!("Got response {:?}", resp.body);

            pink::debug!("Got response {:?}", resp.body);

            let jt = core::str::from_utf8(resp.body.as_slice()).map_err(|_| Error::InvalidUtf8)?;

            pink::debug!("json string: {:?}", jt);

            let v = self.run_js(config.qjs.clone(), jt.to_string(), _path)?;

            #[cfg(feature = "std")]
            println!("Got value {:#?}", v);

            pink::debug!("Got value {:#?}", v);

            let answer = self.encode_answer(v, &_type, _times)?;

            #[cfg(feature = "std")]
            println!("answer {:#?}", answer);

            pink::debug!("answer {:#?}", answer);

            let answer = ethabi::encode(&[answer]);

            Ok(OracleResponse::Response(*rid, answer))
        }

        /// Returns BadOrigin error if the caller is not the owner
        fn ensure_owner(&self) -> Result<()> {
            if self.env().caller() == self.owner {
                Ok(())
            } else {
                Err(Error::BadOrigin)
            }
        }

        /// Returns the config reference or raise the error `NotConfigured`
        fn ensure_configured(&self) -> Result<&Config> {
            self.config.as_ref().ok_or(Error::NotConfigured)
        }
    }

    enum OracleResponse {
        Response(U256, Vec<u8>),
        Error(Option<U256>, Error),
    }

    fn connect(config: &Config) -> Result<EvmRollupClient> {
        let anchor_addr: H160 = config.anchor.into();
        EvmRollupClient::new(&config.rpc, anchor_addr, b"q/")
            .log_err("failed to create rollup client")
            .or(Err(Error::FailedToCreateClient))
    }

    fn maybe_submit_tx(client: EvmRollupClient, config: &Config) -> Result<Option<Vec<u8>>> {
        let maybe_submittable = client
            .commit()
            .log_err("failed to commit")
            .or(Err(Error::FailedToCommitTx))?;
        if let Some(submittable) = maybe_submittable {
            let pair = pink_web3::keys::pink::KeyPair::from(config.submit_key);
            let tx_id = submittable
                .submit(pair)
                .log_err("failed to submit rollup tx")
                .or(Err(Error::FailedToSendTransaction))?;
            return Ok(Some(tx_id));
        }
        Ok(None)
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
        fn encode_answer_should_ok() {
            let _ = env_logger::try_init();
            pink_extension_runtime::mock_ext::mock_all_ext();

            let oracle = Oracle::default();
            let v = oracle.encode_answer("1.234".to_string(), "uint256", 1000);
            println!("{:#?}", v);
        }

        fn consts() -> (String, H160, String, U256) {
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

            let submit_key: [u8; 32] = hex::decode("")
                .expect("hex decode failed")
                .try_into()
                .expect("invalid length");
            let submit_key: U256 = submit_key.into();
            (rpc, anchor_addr, qjs.to_string(), submit_key)
        }

        #[ink::test]
        fn test_run_js() {
            let _ = env_logger::try_init();
            pink_extension_runtime::mock_ext::mock_all_ext();

            let mut oracle = Oracle::default();
            let (rpc, anchor, qjs, submit_key) = consts();
            let r = oracle.config(
                Some(rpc),
                Some(anchor),
                Some(submit_key),
                Some(qjs),
                //Some("https://api.openai.com/v1/completions".to_string()),
                Some("https://httpbin.org/post".to_string()),
                Some("sk-2I4".to_string()),
                Some("POST".to_string()),
                Some("Bearer".to_string()),
            );
            assert!(r.is_ok(), "config failed");
            let r = oracle.test_run_js(
                "https://api.openai.com/v1/edits".to_string(),
                //"https://httpbin.org/post".to_string(),
                "choices.0.text".to_string(),
            );
            println!("{:#?}", r);
            assert!(r.is_ok(), "test run js failed");
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

    pub fn eval(delegate_hash: &str, script: &str, args: &[String]) -> Result<Output, String> {
        use ink_env::call;
        //let system = pink::system::SystemRef::instance();
        //let delegate = system
        //    .get_driver("JsDelegate".into())
        //    .ok_or("No JS driver found")?;

        pink::debug!("decoding hash string {:#?}", delegate_hash);

        let hash: ink_env::Hash = hex::decode(delegate_hash)
            .unwrap()
            .as_slice()
            .try_into()
            .unwrap();

        pink::debug!("hash {:#?}, args {:#?}", hash, args);

        let result = call::build_call::<pink::PinkEnvironment>()
            //.call_type(call::DelegateCall::new().code_hash(delegate.convert_to()))
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
