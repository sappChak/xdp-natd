use config::builder::DefaultState;
use serde::Deserialize;
use serde_aux::field_attributes::deserialize_number_from_string;

use crate::configuration::environment::Environment;

#[derive(Deserialize)]
pub struct Configuration {
    pub control_plane: ApplicationConfiguration,
    pub data_plane: DataPlaneConfiguration,
}

#[derive(Deserialize)]
pub struct ApplicationConfiguration {
    pub host: String,
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub port: u16,
    pub prefix: String,
    pub logger_name: String,
    pub default_env_filter: String,
}

#[derive(serde::Deserialize)]
pub struct DataPlaneConfiguration {
    pub network: String,
    pub mode: String,
    pub pnic: Option<String>,
}

pub fn get_configuration() -> Result<Configuration, config::ConfigError> {
    let base_path = std::env::current_dir().expect("Failed to get current directory.");
    let config_directory = base_path.join("configuration");

    let builder = config::ConfigBuilder::<DefaultState>::default()
        .add_source(config::File::from(config_directory.join("base")).required(true));

    let environment: Environment = std::env::var("APP_ENV")
        .unwrap_or_else(|_| "local".into())
        .try_into()
        .expect("Failed to read APP_ENV");

    let config = builder
        .add_source(config::File::from(config_directory.join(environment.as_str())).required(true))
        .add_source(config::Environment::with_prefix("app").separator("__"))
        .build()?;

    config.try_deserialize::<Configuration>()
}
