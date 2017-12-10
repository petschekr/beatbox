#[macro_use]
extern crate serde_derive;
extern crate hyper;

extern crate reqwest;
extern crate ring;
extern crate openssl;
extern crate base64;

use std::collections::HashMap;
use std::fmt;
use reqwest::{header, StatusCode};
use ring::digest;
use ring::rand::SecureRandom;
use openssl::rsa::Rsa;
use openssl::bn::BigNum;

mod json;
use json::{settings, library};

const LOGIN_SIGNING_KEY: &'static str = "AAAAgMom/1a/v0lblO2Ubrt60J2gcuXSljGFQXgcyZWveWLEwo6prwgi3iJIZdodyhKZQrNWp5nKJ3srRXcUW+F1BD3baEVGcmEgqaLZUNBjm057pKRI16kB0YppeGx5qIQ5QjKzsR8ETQbKLNWgRY0QRNVz34kMJR3P/LgHax/6rmf5AAAAAwEAAQ==";
const STREAM_SIGNING_KEY: &'static str = "MzRlZTc5ODMtNWVlNi00MTQ3LWFhODYtNDQzZWEwNjJhYmY3NzQ0OTNkNmEtMmExNS00M2ZlLWFhY2UtZTc4NTY2OTI3NTg1Cg==";

const BASE_URL: &'static str = "https://www.googleapis.com/sj/v1.11";
const WEB_URL: &'static str = "https://play.google.com/music";
const MOBILE_URL: &'static str = "https://android.clients.google.com/music";
const AUTH_URL: &'static str = "https://android.clients.google.com/auth";

pub struct Instance {
	client: reqwest::Client,
	rng: ring::rand::SystemRandom,
	token: Option<String>,
	device_id: Option<String>,
}

pub struct LoginDetails<'a> {
	email: &'a str,
	password: &'a str,
}

pub struct TokenDetails {
	android_id: String,
	token: String,
}

pub enum LibraryOptions {
	Default,
	Limit(u32),
	NextPageToken(String),
	LimitAndNextPageToken(u32, String)
}

#[derive(Debug)]
pub enum Error {
	Network(reqwest::Error),
	User(&'static str),
}
impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Error {
        Error::Network(err)
    }
}
impl From<&'static str> for Error {
	fn from(err: &'static str) -> Error {
		Error::User(err)
	}
}

#[derive(Clone, Debug, PartialEq)]
struct XDeviceID(String);
impl ::std::ops::Deref for XDeviceID {
	type Target = String;
	fn deref(&self) -> &String {
		&self.0
	}
}
impl ::std::ops::DerefMut for XDeviceID {
	fn deref_mut(&mut self) -> &mut String {
		&mut self.0
	}
}
impl fmt::Display for XDeviceID {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		fmt::Display::fmt(&self.0, f)
	}
}
impl hyper::header::Header for XDeviceID {
	fn header_name() -> &'static str {
		"X-Device-ID"
	}
	fn parse_header(raw: &hyper::header::Raw) -> hyper::Result<Self> {
		hyper::header::parsing::from_one_raw_str(raw).map(XDeviceID)
	}
	fn fmt_header(&self, f: &mut hyper::header::Formatter) -> fmt::Result {
		f.fmt_line(self)
	}
}

impl Instance {
	fn new() -> Instance {
		Instance {
			client: reqwest::Client::builder()
				.redirect(reqwest::RedirectPolicy::none())
				.build().unwrap(),
			rng: ring::rand::SystemRandom::new(),
			token: None,
			device_id: None,
		}
	}

	/// Creates a new instance using a username and password
	pub fn from_login(details: LoginDetails) -> Result<Instance, reqwest::Error> {
		let mut instance = Instance::new();
		
		let password = encrypt_login(details.email, details.password);
		let mut body: HashMap<&str, &str> = HashMap::new();
		body.insert("EncryptedPasswd", &password);
		body.insert("Email", &details.email);

		instance.init(&mut body)?;
		Ok(instance)
	}

	/// Creates a new instance using a master token
	pub fn from_token(details: TokenDetails) -> Result<Instance, reqwest::Error> {
		let mut instance = Instance::new();

		let mut body: HashMap<&str, &str> = HashMap::new();
		body.insert("Token", &details.token);

		instance.init(&mut body)?;
		instance.device_id = Some(details.android_id.to_string());
		Ok(instance)
	}
	
	fn init(&mut self, body: &mut HashMap<&str, &str>) -> Result<(), reqwest::Error> {
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
			self.device_id = Some(id.to_string());
			break;
		}

		Ok(())
	}

	/// Generates a token from a username and password that can be used later to initialize a new instance
	pub fn generate_token(details: LoginDetails, android_id: Option<&str>) -> Result<TokenDetails, reqwest::Error> {
		let password = encrypt_login(details.email, details.password);
		let android_id: String = match android_id {
			Some(id) => id.to_string(),
			None => {
				let generator = ring::rand::SystemRandom::new();
				let mut id: [u8; 8] = [0; 8];
				generator.fill(&mut id).unwrap();
				id.to_hex()
			}
		};

		let token: String;
		{
			let mut body = HashMap::new();
			body.insert("accountType", "HOSTED_OR_GOOGLE");
			body.insert("has_permission", "1");
			body.insert("add_account", "1");
			body.insert("service", "ac2dm");
			body.insert("source", "android");
			body.insert("device_country", "us");
			body.insert("operatorCountry", "us");
			body.insert("lang", "en");
			body.insert("sdk_version", "17");
			body.insert("Email", details.email);
			body.insert("EncryptedPasswd", &password);
			body.insert("androidId", &android_id);

			let client = reqwest::Client::new();
			let response = client.post(AUTH_URL).form(&body).send()?.text()?;
			let parsed = parse_key_values(&response);
			token = parsed.get("Token").unwrap().to_string();
		}
		Ok(TokenDetails { token, android_id })
	}

	fn get_auth_header(&self) -> reqwest::header::Authorization<String> {
		let token = self.token.as_ref().expect("You must call init() before accessing the API");
		header::Authorization(format!("GoogleLogin auth={}", token))
	}

	/// Returns settings and device ids authorized for account
	pub fn get_settings(&mut self) -> Result<settings::Settings, reqwest::Error> {
		let mut body = HashMap::new();
		body.insert("sessionId", "");

		let url = format!("{}/services/fetchsettings?u=0", WEB_URL);
		let response: settings::Response = self.client
			.post(&url)
			.header(self.get_auth_header())
			.json(&body)
			.send()?
			.json()?;
		Ok(response.settings)
	}

	/// Returns a list of all tracks in the user's library
	/// 
	/// Defaults to a limit of 1000 tracks
	pub fn get_library(&self, options: LibraryOptions) -> Result<library::Response, Error> {
		let mut request = library::Request {
			limit: 1000,
			next_page_token: String::new(),
		};
		match options {
			LibraryOptions::Default => {},
			LibraryOptions::Limit(limit) => request.limit = limit,
			LibraryOptions::NextPageToken(token) => request.next_page_token = token,
			LibraryOptions::LimitAndNextPageToken(limit, token) => {
				request.limit = limit;
				request.next_page_token = token;
			}
		}

		let url = format!("{}/trackfeed", BASE_URL);
		let response: library::Response = self.client
			.post(&url)
			.header(self.get_auth_header())
			.json(&request)
			.send()?
			.json().unwrap();

		Ok(response)
	}

	/// Returns a track's stream URL
	pub fn get_stream_url(&self, track: &library::Track) -> Result<String, Error> {
		if self.device_id.is_none() {
			Err("Unable to find a usable device on your account, access from a mobile device and try again")?;
		}
		let key = base64::decode(STREAM_SIGNING_KEY).unwrap();
		let key = ring::hmac::SigningKey::new(&digest::SHA1, &key);

		let mut salt = [0u8; 13];
		self.rng.fill(&mut salt).unwrap();
		let salt: String = salt.to_hex();

		let message = track.id.clone() + &salt;
		let signature = base64::encode_config(
			ring::hmac::sign(&key, message.as_bytes()).as_ref(),
			base64::URL_SAFE_NO_PAD
		);

		let mut query = HashMap::new();
		query.insert("u", "0");
		query.insert("net", "wifi");
		query.insert("pt", "e");
		query.insert("targetkbps", "8310");
		query.insert("slt", &salt);
		query.insert("sig", &signature);
		if track.id.chars().next().unwrap() == 'T' {
			query.insert("mjck", &track.id);
		}
		else {
			query.insert("songid", &track.id);
		}

		let url = reqwest::Url::parse_with_params(&format!("{}/mplay", MOBILE_URL), query).unwrap().into_string();
		let response = self.client
			.get(&url)
			.header(self.get_auth_header())
			.header(XDeviceID(self.device_id.as_ref().cloned().unwrap()))
			.send()?;

		match response.status() {
			StatusCode::Found => {
				let url = response.headers().get::<header::Location>().unwrap();
				Ok(url.to_string())
			},
			_ => {
				if let Err(err) = response.error_for_status() {
					Err(err)?
				}
				else {
					Err("Couldn't get stream URL")?
				}
			}
		}
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

	let key = base64::decode(LOGIN_SIGNING_KEY).unwrap();
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

const HEX_CHARS: &'static [u8] = b"0123456789abcdef";
trait ToHex {
    fn to_hex(&self) -> String;
}
impl ToHex for [u8] {
    fn to_hex(&self) -> String {
        let mut v = Vec::with_capacity(self.len() * 2);
        for &byte in self {
            v.push(HEX_CHARS[(byte >> 4) as usize]);
            v.push(HEX_CHARS[(byte & 0xf) as usize]);
        }

        unsafe {
            String::from_utf8_unchecked(v)
        }
    }
}

#[cfg(test)]
mod tests {
	fn get_login_details<'a>() -> super::LoginDetails<'a> {
		super::LoginDetails {
			email: "petschekr@gmail.com",
			password: include_str!("password.txt"),
		}
	}
	#[test]
	fn init() {
		let instance = super::Instance::from_login(get_login_details()).unwrap();
		let tracks = instance.get_library(super::LibraryOptions::Default).unwrap().tracks;
		let url = instance.get_stream_url(&tracks[0]).unwrap();
		println!("Got stream URL for {} by {}: {}", tracks[0].title, tracks[0].artist, url);
	}
	#[test]
	fn generate_token() {
		let token_details = super::Instance::generate_token(get_login_details(), None).unwrap();
		println!("Got random ID {} and token {}", token_details.android_id, token_details.token);
	}
}
