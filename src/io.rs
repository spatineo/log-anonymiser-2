use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;

use anyhow::Result;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;

pub struct InputOutput {
    pub compress_input: Option<bool>,
    pub compress_output: Option<bool>,
    /// Remembers whether the last opened input was compressed
    last_input_compressed: bool,
}

impl InputOutput {
    pub fn new(compress_input: Option<bool>, compress_output: Option<bool>) -> Self {
        InputOutput { compress_input, compress_output, last_input_compressed: false }
    }

    fn should_compress_by_name(path: &Path) -> bool {
        path.extension()
            .and_then(|e| e.to_str())
            .map(|e| e == "gz" || e == "Z")
            .unwrap_or(false)
    }

    pub fn open_input(&mut self, path: &Path) -> Result<Box<dyn Read>> {
        let compressed = self.compress_input.unwrap_or_else(|| Self::should_compress_by_name(path));
        self.last_input_compressed = compressed;
        let file = File::open(path)?;
        if compressed {
            Ok(Box::new(BufReader::new(GzDecoder::new(file))))
        } else {
            Ok(Box::new(BufReader::new(file)))
        }
    }

    pub fn open_output(&self, path: &Path) -> Result<Box<dyn Write>> {
        let compressed = self.compress_output.unwrap_or(self.last_input_compressed);
        let file = File::create(path)?;
        if compressed {
            Ok(Box::new(BufWriter::new(GzEncoder::new(file, Compression::default()))))
        } else {
            Ok(Box::new(BufWriter::new(file)))
        }
    }
}
