#[macro_use]
extern crate serde_derive;

extern crate reqwest;
extern crate ring;
extern crate openssl;
extern crate base64;

use std::collections::HashMap;
use reqwest::header;
use ring::digest;
use openssl::rsa::Rsa;
use openssl::bn::BigNum;

mod json;

const SIGNING_KEY: &'static str = "AAAAgMom/1a/v0lblO2Ubrt60J2gcuXSljGFQXgcyZWveWLEwo6prwgi3iJIZdodyhKZQrNWp5nKJ3srRXcUW+F1BD3baEVGcmEgqaLZUNBjm057pKRI16kB0YppeGx5qIQ5QjKzsR8ETQbKLNWgRY0QRNVz34kMJR3P/LgHax/6rmf5AAAAAwEAAQ==";

const BASE_URL: &'static str = "https://www.googleapis.com/sj/v1.11";
const WEB_URL: &'static str = "https://play.google.com/music";
const MOBILE_URL: &'static str = "https://android.clients.google.com/music";
const ACCOUNT_URL: &'static str = "https://www.google.com/accounts";
const AUTH_URL: &'static str = "https://android.clients.google.com/auth";

pub struct Instance {
	client: reqwest::Client,
	token: Option<String>,
	device_id: Option<String>,
}

pub struct LoginDetails<'a> {
	email: Option<&'a str>,
	password: Option<&'a str>,
	master_token: Option<&'a str>
}

impl Instance {
	pub fn new() -> Instance {
		Instance {
			client: reqwest::Client::new(),
			token: None,
			device_id: None,
		}
	}
	
	pub fn init(&mut self, details: LoginDetails) -> Result<(), reqwest::Error> {
		let password;
		let mut body = HashMap::new();

		body.insert("accountType", "HOSTED_OR_GOOGLE");
		body.insert("has_permission", "1");
		body.insert("service", "sj");
		body.insert("source", "android");
		body.insert("androidId", "");
		body.insert("app", "com.google.android.music");
		body.insert("device_country", "us");
		body.insert("operatorCountry", "us");
		// headers.insert("client_sig", "61ed377e85d386a8dfee6b864bd85b0bfaa5af81");
		body.insert("lang", "en");
		body.insert("sdk_version", "17");

		match details.master_token {
			Some(token) => {
				body.insert("Token", token);
			},
			None => {
				let email = details.email.expect("Email required if no master token");
				let raw_password = details.password.expect("Password required if no master token");
				password = encrypt_login(email, raw_password);
				body.insert("EncryptedPasswd", &password);
				body.insert("Email", email);
			}
		};

		let response = self.client.post(AUTH_URL).form(&body).send()?.text()?;
		let parsed = parse_key_values(&response);

		self.token = Some(parsed.get("Auth").unwrap().to_string());

		let settings = self.get_settings()?;
		self.device_id = None;
		for device in settings.uploadDevice.iter() {
			let id: &str = match device.deviceType {
				// Strip the "0x" from the device ID
				2 => &device.id[2..],
				3 => &device.id,
				_ => continue
			};
			println!("Using device ID: {}", id);
			self.device_id = Some(id.to_string());
			break;
		}

		Ok(())
	}

	fn get_auth_header(&self) -> reqwest::header::Authorization<std::string::String> {
		let token = self.token.as_ref().expect("You must call init() before accessing the API");
		header::Authorization(format!("GoogleLogin auth={}", token))
	}

	pub fn get_settings(&mut self) -> Result<json::Settings, reqwest::Error> {
		let mut body = HashMap::new();
		body.insert("sessionId", "");

		let url = format!("{}/services/fetchsettings?u=0", WEB_URL);
		let response: json::SettingsResponse = self.client
			.post(&url)
			.header(self.get_auth_header())
			.json(&body)
			.send()?
			.json()?;
		Ok(response.settings)
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

fn parse_key_values(body: &str) -> HashMap<&str, &str> {
	let mut parsed = HashMap::new();
	for line in body.lines() {
		let mut key_value = line.split("=");
		parsed.insert(key_value.next().unwrap(), key_value.next().unwrap());
	}
	parsed
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
		let mut instance = super::Instance::new();
		instance.init(super::LoginDetails {
			email: Some("petschekr@gmail.com"),
			password: Some(include_str!("password.txt")),
			master_token: None
		});
		instance.get_settings();
	}
}
