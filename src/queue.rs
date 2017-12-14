use std::collections::VecDeque;
use json::library::Track;

struct Queue {
	tracks: VecDeque<Track>,
	station_id: Option<String>,
	instance: &Instance,
}

impl Queue {
	/// Creates a new, empty queue
	pub fn new(instance: &Instance) -> Queue {
		Queue {
			tracks: VecDeque::new(),
			station_id: None,
			instance,
		}
	}

	/// Plays the next track in the queue
	/// Returns the track's stream URL and increments its playcount
	pub fn play_next(&mut self) -> Option<String> {
		Some("")
	}
	
	pub fn skip(&mut self) -> Option<Track> {
		self.tracks.pop_front()
	}
}
