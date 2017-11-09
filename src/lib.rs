extern crate futures;
extern crate hyper;
extern crate hyper_tls;
extern crate tokio_core;
extern crate ring;
extern crate url;
extern crate openssl;
extern crate base64;

use futures::{Future, Stream};
use hyper::{Method, Request, Client};
use hyper::header::ContentType;
use hyper_tls::HttpsConnector;
use tokio_core::reactor::Core;
use ring::digest;
use url::form_urlencoded;
use openssl::rsa::Rsa;
use openssl::bn::BigNum;

const THREADS: usize = 4;
const SIGNING_KEY: &'static str = "AAAAgMom/1a/v0lblO2Ubrt60J2gcuXSljGFQXgcyZWveWLEwo6prwgi3iJIZdodyhKZQrNWp5nKJ3srRXcUW+F1BD3baEVGcmEgqaLZUNBjm057pKRI16kB0YppeGx5qIQ5QjKzsR8ETQbKLNWgRY0QRNVz34kMJR3P/LgHax/6rmf5AAAAAwEAAQ==";

const BASE_URL: &'static str = "https://www.googleapis.com/sj/v1.11/";
const WEB_URL: &'static str = "https://play.google.com/music/";
const MOBILE_URL: &'static str = "https://android.clients.google.com/music/";
const ACCOUNT_URL: &'static str = "https://www.google.com/accounts/";
const AUTH_URL: &'static str = "https://android.clients.google.com/auth";

pub struct Instance {
	core: Core,
	client: Client<HttpsConnector<hyper::client::HttpConnector>>,
}

pub struct LoginDetails<'a> {
	email: Option<&'a str>,
	password: Option<&'a str>,
	master_token: Option<&'a str>
}

impl Instance {
	pub fn new() -> Instance {
		let core = Core::new().unwrap();
		let handle = core.handle();
		let client = Client::configure().connector(HttpsConnector::new(THREADS, &handle).unwrap()).build(&handle);

		Instance {
			core,
			client,
		}
	}
	
	pub fn init(&mut self, details: LoginDetails) -> Result<(), hyper::Error> {
		let mut request = Request::new(Method::Post, AUTH_URL.parse().unwrap());
		request.headers_mut().set(ContentType::form_url_encoded());

		let mut body = form_urlencoded::Serializer::new(String::new());
		body.append_pair("accountType", "HOSTED_OR_GOOGLE")
			.append_pair("has_permission", "1")
			.append_pair("service", "sj")
			.append_pair("source", "android")
			.append_pair("androidId", "")
			.append_pair("app", "com.google.android.music")
			.append_pair("device_country", "us")
			.append_pair("operatorCountry", "us")
			// .append_pair("client_sig", "61ed377e85d386a8dfee6b864bd85b0bfaa5af81")
			.append_pair("lang", "en")
			.append_pair("sdk_version", "17");
		match details.master_token {
			Some(token) => body.append_pair("Token", token),
			None => {
				let email = details.email.expect("Email required if no master token");
				let password = details.password.expect("Password required if no master token");
				body.append_pair("EncryptedPasswd", &encrypt_login(email, password))
				    .append_pair("Email", email)
			}
		};

		request.set_body(body.finish());
		let post = self.client.request(request).and_then(|response| {
			println!("Status code: {}", response.status());
			response.body().concat2()
		});
		let result = self.core.run(post).unwrap();
		println!("Response: {}", std::str::from_utf8(&result)?);
		
		Ok(())
	}
}

fn encrypt_login(email: &str, password: &str) -> String {
	// Ported from https://github.com/jamon/playmusic/blob/master/lib/encryptLogin.js and
	// https://github.com/yeriomin/play-store-api/blob/master/src/main/java/com/github/yeriomin/playstoreapi/PasswordEncrypter.java
	fn bytes_to_u32(bytes: &[u8]) -> u32 {
		((bytes[0] as u32) << 24) +
		((bytes[1] as u32) << 16) +
		((bytes[2] as u32) <<  8) +
		((bytes[3] as u32) <<  0)
	}

	let mut data: Vec<u8> = vec![];
	data.extend_from_slice(email.as_bytes());
	data.push(0);
	data.extend_from_slice(password.as_bytes());

	// The components of Google's public key

	let key = base64::decode(SIGNING_KEY).unwrap();
	let digest = digest::digest(&digest::SHA1, &key);

	let modulus_length = bytes_to_u32(&key[0..4]) as usize;
	let modulus = BigNum::from_slice(&key[4..modulus_length + 4]).unwrap();
	let exponent_length = bytes_to_u32(&key[modulus_length + 4..modulus_length + 8]) as usize;
	let exponent = BigNum::from_slice(&key[modulus_length + 8..modulus_length + 8 + exponent_length]).unwrap();

	let rsa = Rsa::from_public_components(modulus, exponent).unwrap();

	let mut result = vec![0; rsa.size()];
	rsa.public_encrypt(&data, &mut result, openssl::rsa::PKCS1_OAEP_PADDING).unwrap();
	
	let mut res: Vec<u8> = vec![];
	res.push(0);
	res.extend_from_slice(&digest.as_ref()[0..4]);
	res.extend_from_slice(&result);
	
	base64::encode_config(&res, base64::URL_SAFE)
}


#[cfg(test)]
mod tests {
	#[test]
    fn create_instance() {
        super::Instance::new();
    }
	#[test]
	#[should_panic]
	fn empty_init() {
		super::Instance::new().init(super::LoginDetails {
			email: None,
			password: None,
			master_token: None
		});
	}
	#[test]
	fn init() {
		super::Instance::new().init(super::LoginDetails {
			email: Some("petschekr@gmail.com"),
			password: Some(include_str!("password.txt")),
			master_token: None
		});
	}
}
