// TODO: Remove these before publishing finished product.
#![allow(dead_code)]
#![allow(unused)]

pub mod spa_config;
pub mod spa_protocol;
pub mod spa_runner;

use std::sync::Arc;

use spa_config::*;
use spa_protocol::*;
use spa_runner::*;


fn main()
{
    /* Prep and init. */
    /* Register signal handlers. */
    /* Handle params/options. */
    /* Parse configuration. */
    /* Daemonize and spawn socket(s). */
    /* Enter main polling loop for the socket. */
    /* Spin requests off into their own threads as they arrive. */

    let config: Arc<CspauthConfig> =
        // TODO: Replace static string with config path from args/CLI-opts.
        match CspauthConfig::load(String::from("cspauthd.sample.json")) {
            Err(e) => {
                println!("ERROR: Failed to load the CSPAuthD configuration: {e:#?}");
                std::process::exit(1);
            },
            Ok(result) => {
                println!("Configuration loaded and validated!");
                result
            }
        };

    println!("{} - {:#?}", std::mem::size_of::<CspauthUdpRequest>(), config);
}
