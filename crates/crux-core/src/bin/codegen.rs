use std::path::PathBuf;
use anyhow::Result;
use clap::{Parser, ValueEnum};
use crux_core::type_generation::facet::{Config, TypeRegistry};
use pick_crux_core::PickApp;

fn main() -> Result<()> {
    pretty_env_logger::init();
    let args = Args::parse();
    let typegen = TypeRegistry::new().register_app::<PickApp>()?.build()?;
    match args.language {
        Language::Swift => {
            let cfg = Config::builder("PickShared", &args.output_dir).build();
            typegen.swift(&cfg)?;
        }
        Language::Kotlin => {
            let cfg = Config::builder("com.strike48.pick.shared", &args.output_dir).build();
            typegen.kotlin(&cfg)?;
        }
    }
    Ok(())
}

#[derive(Parser)]
struct Args {
    #[arg(value_enum)]
    language: Language,
    output_dir: PathBuf,
}

#[derive(ValueEnum, Clone)]
enum Language { Swift, Kotlin }
