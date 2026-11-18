//! Observe DECSTBM and DECSET 5522 without exposing the dependency's private grid state.
use alacritty_terminal::vte::ansi::{Handler, PrivateMode, Processor};

pub(crate) struct ScrollRegionTracker {
    parser: Processor,
    region: Region,
}

struct Region {
    rows: usize,
    top: usize,
    bottom: usize,
    kitty_paste_events: bool,
}

impl Handler for Region {
    fn set_scrolling_region(&mut self, top: usize, bottom: Option<usize>) {
        let bottom = bottom.unwrap_or(self.rows);
        if top >= bottom {
            return;
        }
        self.top = top.saturating_sub(1).min(self.rows);
        self.bottom = bottom.min(self.rows).saturating_sub(1);
    }
    fn set_private_mode(&mut self, mode: PrivateMode) {
        if mode == PrivateMode::Unknown(5522) {
            self.kitty_paste_events = true;
        }
    }
    fn unset_private_mode(&mut self, mode: PrivateMode) {
        if mode == PrivateMode::Unknown(5522) {
            self.kitty_paste_events = false;
        }
    }
    fn reset_state(&mut self) {
        self.top = 0;
        self.bottom = self.rows.saturating_sub(1);
        self.kitty_paste_events = false;
    }
}

impl ScrollRegionTracker {
    pub(crate) fn new(rows: usize) -> Self {
        Self {
            parser: Processor::new(),
            region: Region {
                rows,
                top: 0,
                bottom: rows.saturating_sub(1),
                kitty_paste_events: false,
            },
        }
    }
    pub(crate) fn advance(&mut self, bytes: &[u8]) {
        self.parser.advance(&mut self.region, bytes);
    }
    pub(crate) fn resize(&mut self, rows: usize) {
        let kitty_paste_events = self.region.kitty_paste_events;
        self.region.rows = rows;
        self.region.reset_state();
        self.region.kitty_paste_events = kitty_paste_events;
    }
    pub(crate) fn reset_stream(&mut self) {
        self.parser = Processor::new();
    }
    pub(crate) fn reset_kitty_paste_events(&mut self) {
        self.region.kitty_paste_events = false;
    }
    pub(crate) fn kitty_paste_events(&self) -> bool {
        self.region.kitty_paste_events
    }
    pub(crate) fn bounds(&self) -> (usize, usize) {
        (self.region.top, self.region.bottom)
    }
}
