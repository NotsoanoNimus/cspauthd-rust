use std::{sync::Arc};

use serde::{Serialize, Deserialize};


#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all="snake_case")]
pub enum SpaMode {
    Dead,
    Stealthy,
    Helpful,
    Noisy
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all="snake_case")]
pub enum SpaLogLevel {
    Quiet,
    Normal,
    Vebose,
    Debug
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all="snake_case")]
pub struct SpaInstance {
    id: String,
    address: String,
    port: u16,
    log_level: Option<SpaLogLevel>,
    mode: Option<SpaMode>,
    validity_window: Option<u32>,
    replay_protection: Option<bool>,
    generic_action: Option<String>
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all="snake_case")]
pub struct GlobalOptions {
    i_accept_the_risks: bool,
    map_ipv4_addresses: bool,
    skip_invalid_users: bool,
    default_mode: SpaMode,
    default_log_level: SpaLogLevel,
    default_validity_window: Option<u32>,
    default_replay_protection: bool,
    default_generic_action: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all="snake_case")]
pub struct SystemUser {
    uid: Option<u16>,
    username: Option<String>
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all="snake_case")]
pub struct Authorization {
    action_id: u16,
    options: Vec<String>
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all="snake_case")]
#[serde(tag = "source")]
pub enum ZkpSaltType {
    Epoch {
        interval: u64
    },
    Timestamp {},
    PacketHash {
        chars: u8,
        offset: u8
    },
    ActionOption {}
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all="snake_case")]
#[serde(tag = "auth_type")]
pub enum AuthType {
    ZeroKnowledgeProof {
        salt: ZkpSaltType,
        root: String,
        hash_type: String,
        iterations: u32
    },
    PublicKey {
        path: Option<String>,
        raw: Option<String>
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all="snake_case")]
pub struct User {
    name: String,
    runas: Option<SystemUser>,
    authentication: AuthType,
    authorizations: Vec<Authorization>
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all="snake_case")]
pub struct ActionFilter {
    token: String,
    users: Vec<String>,
    user_enforcement: Option<String>,
    r#match: String,
    replace: Option<String>,
    required: bool
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all="snake_case")]
pub enum ActionLockType {
    None,
    User,
    Global
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all="snake_case")]
pub struct Action {
    id: u16,
    cmd: String,
    lock_type: ActionLockType,
    fork: bool,
    filters: Vec<ActionFilter>,
    instance_ids: Vec<String>
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all="snake_case")]
pub struct CspauthConfig {
    global: GlobalOptions,
    instances: Vec<SpaInstance>,
    users: Vec<User>,
    actions: Vec<Action>
}


impl CspauthConfig {
    pub fn load(path: String) -> Result<Arc<CspauthConfig>, &'static str>
    {
        /* First, ensure the configuration file exists at all. Bit redundant but helps. */
        match std::fs::exists(&path) {
            Ok(b) => match b {
                true => (),
                false => return Err("Configuration file found, but appears to be a broken symlink.")
            },
            Err(_) => return Err("Configuration file was not found."),
        };

        /* Get the JSON input from the specified config file. */
        let in_json: String =
            std::fs::read_to_string(path)
                .expect("Failed to read the application configuration file.");
            
        /* Deserialize the JSON into the config structure. */
        let mut config: CspauthConfig = 
            match serde_json::from_str::<CspauthConfig>(&in_json) {
                Ok(result) => result,
                Err(problemo) => {
                    println!("ERROR: {:#?}", problemo);
                    return Err("Failed to parse configuration JSON");
                }
            };

        /* Validate the config. Pass through errors on failure. */
        config.validate()?;

        /* Done! Return the config as a heap value (unique_ptr). */
        Ok(Arc::from(config))
    }


    pub fn validate(&mut self) -> Result<(), &'static str>
    {
        /* Outer checks for acceptance and populated vectors. */
        if !self.global.i_accept_the_risks {
            return Err("The risks of using cspauthd must be accepted by setting 'i_accept_the_risks' to true.");
        }
        else if self.users.is_empty() { return Err("No users are defined.") }
        else if self.instances.is_empty() { return Err("No instances are defined.") }
        else if self.actions.is_empty() { return Err("No actions are defined.") }

        /* For each instance, override NULL values with the default options. */
        for inst in &mut self.instances {
            if inst.generic_action.is_none() { inst.generic_action = self.global.default_generic_action.clone() }
            if inst.replay_protection.is_none() { inst.replay_protection = Some(self.global.default_replay_protection.clone()) }
            if inst.validity_window.is_none() { inst.validity_window = self.global.default_validity_window.clone() }
            if inst.log_level.is_none() { inst.log_level = Some(self.global.default_log_level.clone()) }
            if inst.mode.is_none() { inst.mode = Some(self.global.default_mode.clone()) }

            /* Check the instance's IP, port, and ID for validity. */
            if inst.address.is_empty() { return Err("Instance address cannot be empty.") }
            if inst.port == 0 { return Err("Instance port cannot be 0.") }
            if inst.id.is_empty() { return Err("Instance ID cannot be empty.") }
        }

        /* Check instance names for uniqueness. */
        for instance in self.instances.iter() {
            if self.instances.iter().filter(|i| i.id == instance.id).count() > 1 {
                return Err("Duplicate Instance IDs are not permitted.");
            }
        }

        /* Check user names for uniqueness. */
        for user in self.users.iter() {
            if self.users.iter().filter(|u| u.name == user.name).count() > 1 {
                return Err("Duplicate user names are not permitted.");
            }
        }

        /* Check action IDs for uniqueness. */
        for action in &self.actions {
            if self.actions.iter().filter(|a| a.id == action.id).count() > 1 {
                return Err("Duplicate action IDs are not permitted.");
            }
        }

        /* All done! */
        Ok(())
    }
}
