use serde::{Deserialize, Serialize};

#[derive(Debug, Clone,Serialize,Deserialize)]
pub struct Config {   
    pub host: String,
    pub domains: Vec<String>,
    pub port: u16,
    pub nodes: Vec<String>,
    pub pk:Option<Vec<u8>>,
    pub authority:Option<Vec<u8>>
}

impl Default for Config {
    fn default() -> Self {
        Config {
            host: "127.0.0.1".to_string(),
            domains: vec!["http://localhost:3000".to_string()],
            port: 3000,
            nodes: vec![],
            pk: None,
            authority: None
        }
    }
}