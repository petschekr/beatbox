#[allow(non_snake_case)]
#[derive(Deserialize)]
pub struct SettingsResponse {
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
