extern crate serde;
extern crate serde_json;

pub mod settings {
	#[allow(non_snake_case)]
	#[derive(Deserialize)]
	pub struct Response {
		pub settings: Settings,
	}

	#[allow(non_snake_case)]
	#[derive(Deserialize, Debug)]
	pub struct Settings {
		pub uploadDevice: Vec<Device>,
		pub entitlementInfo: EntitlementInfo,
		pub subscriptionNewsletter: bool,
	}

	#[allow(non_snake_case)]
	#[derive(Deserialize, Debug)]
	pub struct Device {
		pub id: String,
		pub lastEventTimeMillis: u64,
		pub lastAccessedTimeMillis: u64,
		pub carrier: Option<String>,
		pub manufacturer: Option<String>,
		pub model: Option<String>,
		pub deviceType: u8,
		pub lastAccessedFormatted: String,
	}

	#[allow(non_snake_case)]
	#[derive(Deserialize, Debug)]
	pub struct EntitlementInfo {
		pub isTrial: bool,
		pub isCanceled: bool,
		pub expirationMillis: u64,
	}
}
pub mod library {
	use super::serde::{Deserialize, Deserializer};
	use super::serde_json::{self, Value, Map};

	#[derive(Serialize)]
	pub struct Request {
		#[serde(rename = "max-results")]
		pub limit: u32,
		#[serde(rename = "start-token")]
		pub next_page_token: String
	}

	#[derive(Deserialize, Debug)]
	pub struct Response {
		pub kind: String,
		#[serde(rename = "nextPageToken")]
		pub next_page_token: Option<String>,
		#[serde(rename = "data")]
		#[serde(deserialize_with = "extract_data")]
		pub tracks: Vec<Track>,
	}
	fn extract_data<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Track>, D::Error> {
		let n: Map<String, Value> = Deserialize::deserialize(d)?;
		let items = n.get("items").unwrap().clone();
		Ok(serde_json::from_value(items).unwrap())
	}
	impl Response {
		pub fn next_page_request(&self) -> Option<Request> {
			match self.next_page_token {
				None => None,
				Some(ref token) => Some(Request {
					limit: self.tracks.len() as u32,
					next_page_token: token.clone(),
				})
			}
		}
	}
	
	#[derive(Deserialize, Debug)]
	#[serde(rename_all = "camelCase")]
	pub struct Track {
		pub kind: String,
		pub deleted: bool,

		pub id: String,
		pub album_id: Option<String>,
		pub artist_id: Option<Vec<String>>,
		pub client_id: Option<String>,
		pub store_id: Option<String>,
		
		#[serde(deserialize_with = "string_to_u64")]
		pub creation_timestamp: u64,
		#[serde(deserialize_with = "string_to_u64")]
		pub last_modified_timestamp: u64,
		#[serde(deserialize_with = "string_to_u64")]
		pub recent_timestamp: u64,
		
		pub title: String,
		pub artist: String,
		pub album: String,
		pub album_artist: String,
		pub composer: Option<String>,
		pub year: Option<u16>,
		pub genre: Option<String>,
		pub track_number: u16,
		pub disc_number: u16,

		#[serde(default)]
		#[serde(rename = "artistArtRef")]
		#[serde(deserialize_with = "extract_art")]
		pub artist_art_url: Option<String>,
		#[serde(default)]
		#[serde(rename = "albumArtRef")]
		#[serde(deserialize_with = "extract_art")]
		pub album_art_url: Option<String>,
		
		#[serde(deserialize_with = "string_to_u64")]
		pub duration_millis: u64,
		#[serde(deserialize_with = "string_to_u64")]
		pub estimated_size: u64,
	}
	fn string_to_u64<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
		let n: String = Deserialize::deserialize(d)?;
		Ok(n.parse().unwrap())
	}
	fn extract_art<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
		let n: Value = Deserialize::deserialize(d)?;
		let url = n[0]["url"].clone();
		Ok(serde_json::from_value(url).unwrap())
	}
}
