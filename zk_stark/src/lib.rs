use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::{rngs::OsRng, RngCore};
use rpassword::read_password;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    io::Write,
    sync::{Arc, Mutex},
};

pub type Username = String;
pub type Commitment = String;

pub struct Client {
    prover: Prover,
    server: Arc<Mutex<Server>>,
}

impl Client {
    pub fn new(server: Arc<Mutex<Server>>) -> Self {
        Self {
            prover: Prover::new(),
            server,
        }
    }

    pub fn run(&mut self) {
        loop {
            print!("\nChoose an option:\n1. Sign up\n2. Sign in\n3. Quit\n\n> ");
            std::io::stdout().flush().unwrap();
            match self.get_input() {
                Ok(option) => match option.as_str() {
                    "1" => match self.sign_up() {
                        Ok(_) => {
                            println!("\nSign up succeeded!");
                        }
                        Err(e) => {
                            println!("\nSign up failed: {}", e);
                        }
                    },
                    "2" => match self.sign_in() {
                        Ok(_) => {
                            println!("\nSign in succeeded!");
                        }
                        Err(e) => {
                            println!("\nSign in failed: {}", e);
                        }
                    },
                    "3" => {
                        break;
                    }
                    _ => {
                        println!("\nInvalid option.");
                        continue;
                    }
                },
                Err(e) => {
                    println!("\nFailed to get input: {}", e);
                }
            }
        }
    }

    fn get_input(&self) -> Result<String, String> {
        let mut option = String::new();
        std::io::stdin().read_line(&mut option).unwrap();
        option.truncate(option.len() - 1);
        Ok(option)
    }

    fn sign_up(&mut self) -> Result<(), String> {
        println!("\nEnter username:");
        let username = self.get_input()?;
        self.validate_username(username.as_str())?;

        println!("\nEnter password:");
        let password = read_password().unwrap();
        self.validate_password(password.as_bytes())?;
        println!("\nConfirm password:");
        if read_password().unwrap() != password {
            return Err("passwords do not match".to_string());
        }

        let challenge = self
            .server
            .lock()
            .unwrap()
            .commit(&username, self.prover.generate_commitment())?;
        let hash = Scalar::from_bytes_mod_order(Sha256::digest(password.as_bytes()).into());
        let response = self.prover.prove(&challenge, &hash)?;
        let proof = self.prover.generate_proof(&hash);
        self.server
            .lock()
            .unwrap()
            .sign_up(&username, &response, proof)?;

        Ok(())
    }

    fn sign_in(&mut self) -> Result<(), String> {
        println!("\nEnter username:");
        let username = self.get_input()?;

        println!("\nEnter password:");
        let password = read_password().unwrap();

        let challenge = self
            .server
            .lock()
            .unwrap()
            .commit(&username, self.prover.generate_commitment())?;
        let hash = Scalar::from_bytes_mod_order(Sha256::digest(password.as_bytes()).into());
        let response = self.prover.prove(&challenge, &hash)?;
        self.server.lock().unwrap().sign_in(&username, &response)?;
        Ok(())
    }

    fn validate_username(&self, username: &str) -> Result<(), String> {
        if username.len() < 1 {
            return Err("username must be at least 1 character".to_string());
        }
        if username.len() > 32 {
            return Err("username must be at most 32 characters".to_string());
        }
        if !username.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Err("username must only contain letters and numbers".to_string());
        }
        Ok(())
    }

    fn validate_password(&self, password: &[u8]) -> Result<(), String> {
        if password.len() < 8 {
            return Err("password must be at least 8 characters".to_string());
        }
        if password.len() > 64 {
            return Err("password must be at most 64 characters".to_string());
        }
        if !password.iter().all(|&c| (32..=126).contains(&(c as u8))) {
            return Err(
                "password must only use ASCII characters from ordinal 32 to 126".to_string(),
            );
        }
        Ok(())
    }
}

struct Prover {
    nonce: Scalar,
    ready: bool,
}

impl Prover {
    pub fn new() -> Self {
        Self {
            nonce: Scalar::default(),
            ready: false,
        }
    }

    fn generate_nonce(&mut self) {
        let mut random_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut random_bytes);
        self.nonce = Scalar::from_bytes_mod_order(random_bytes);
        self.ready = true;
    }

    pub fn generate_commitment(&mut self) -> RistrettoPoint {
        self.generate_nonce();
        self.nonce * RISTRETTO_BASEPOINT_POINT
    }

    pub fn generate_proof(&self, hash: &Scalar) -> RistrettoPoint {
        hash * RISTRETTO_BASEPOINT_POINT
    }

    pub fn prove(&mut self, challenge: &Scalar, hash: &Scalar) -> Result<Scalar, String> {
        if !self.ready {
            return Err("must generate commitment before proof".to_string());
        }
        self.ready = false;
        Ok(self.nonce + challenge * hash)
    }
}

pub struct Server {
    verifier: Verifier,
    users: Arc<Mutex<HashMap<Username, RistrettoPoint>>>,
    commitment: RistrettoPoint,
}

impl Server {
    pub fn new() -> Self {
        Self {
            verifier: Verifier::new(),
            users: Arc::new(Mutex::new(HashMap::new())),
            commitment: RistrettoPoint::default(),
        }
    }

    pub fn commit(
        &mut self,
        username: &Username,
        commitment: RistrettoPoint,
    ) -> Result<Scalar, String> {
        self.commitment = commitment;
        Ok(self.verifier.generate_challenge())
    }

    pub fn sign_up(
        &mut self,
        username: &Username,
        response: &Scalar,
        proof: RistrettoPoint,
    ) -> Result<(), String> {
        let mut users = self.users.lock().unwrap();
        if users.contains_key(username) {
            return Err("username already taken".to_string());
        }

        self.verifier.verify(self.commitment, response, &proof)?;
        users.insert(username.to_string(), proof);
        Ok(())
    }

    pub fn sign_in(&mut self, username: &Username, response: &Scalar) -> Result<(), String> {
        let users = self.users.lock().unwrap();
        if users.get(username).map_or(true, |stored_proof| {
            self.verifier
                .verify(self.commitment, response, stored_proof)
                .is_err()
        }) {
            return Err("invalid credentials".to_string());
        }

        Ok(())
    }
}

struct Verifier {
    challenge: Scalar,
    ready: bool,
}

impl Verifier {
    pub fn new() -> Self {
        Self {
            challenge: Scalar::default(),
            ready: false,
        }
    }

    pub fn generate_challenge(&mut self) -> Scalar {
        let mut random_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut random_bytes);
        self.challenge = Scalar::from_bytes_mod_order(random_bytes);
        self.ready = true;
        self.challenge
    }

    pub fn verify(
        &mut self,
        commitment: RistrettoPoint,
        response: &Scalar,
        proof: &RistrettoPoint,
    ) -> Result<(), String> {
        if !self.ready {
            return Err("must generate challenge before verification".to_string());
        }
        self.ready = false;
        if commitment != response * RISTRETTO_BASEPOINT_POINT - self.challenge * proof {
            return Err("invalid credentials".to_string());
        }

        Ok(())
    }
}
