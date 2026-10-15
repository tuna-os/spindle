//! Reuse Argon2's working memory and serialize password computations (#571).

use std::sync::Mutex;

use argon2::password_hash::phc::{Output, ParamsString, PasswordHash, Salt};
use argon2::password_hash::{self, CustomizedPasswordHasher, PasswordHasher};
use argon2::{Algorithm, Argon2, Block, Params, Version};

static WORKSPACE: Mutex<Vec<Block>> = Mutex::new(Vec::new());

/// The PHC format and verification remain the password-hash crate's own.
pub(crate) struct ReusableArgon2;

impl CustomizedPasswordHasher<PasswordHash> for ReusableArgon2 {
    type Params = Params;

    fn hash_password_customized(
        &self,
        password: &[u8],
        salt: &[u8],
        alg_id: Option<&str>,
        version: Option<u32>,
        params: Params,
    ) -> password_hash::Result<PasswordHash> {
        let algorithm = alg_id
            .map(Algorithm::try_from)
            .transpose()?
            .unwrap_or_default();
        let version = version
            .map(Version::try_from)
            .transpose()?
            .unwrap_or_default();
        let salt = Salt::new(salt)?;
        let output_len = params.output_len().unwrap_or(Params::DEFAULT_OUTPUT_LEN);
        let mut buffer = [0_u8; Output::MAX_LENGTH];
        let out = buffer
            .get_mut(..output_len)
            .ok_or(password_hash::Error::OutputSize)?;
        let encoded_params = ParamsString::try_from(&params)?;
        let block_count = params.block_count();
        let argon = Argon2::new(algorithm, version, params);
        {
            let mut memory = WORKSPACE
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            // Keep the largest trusted stored hash's workspace. A login burst
            // cannot allocate one workspace per request or per allocator arena.
            if memory.len() < block_count {
                let additional = block_count - memory.len();
                memory
                    .try_reserve_exact(additional)
                    .map_err(|_| password_hash::Error::OutOfMemory)?;
                memory.resize(block_count, Block::new());
            }
            let result = argon.hash_password_into_with_memory(
                password,
                &salt,
                out,
                &mut memory[..block_count],
            );
            memory[..block_count].fill(Block::new());
            result?;
        }
        Ok(PasswordHash {
            algorithm: algorithm.ident(),
            version: Some(version.into()),
            params: encoded_params,
            salt: Some(salt),
            hash: Some(Output::new(out)?),
        })
    }
}

impl PasswordHasher<PasswordHash> for ReusableArgon2 {
    fn hash_password_with_salt(
        &self,
        password: &[u8],
        salt: &[u8],
    ) -> password_hash::Result<PasswordHash> {
        self.hash_password_customized(password, salt, None, None, Params::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use argon2::password_hash::PasswordVerifier;

    #[test]
    fn repeated_hashes_reuse_the_allocation() {
        ReusableArgon2
            .hash_password_with_salt(b"warmup", b"fixed test salt")
            .unwrap();
        let (address, capacity) = {
            let memory = WORKSPACE.lock().unwrap();
            (memory.as_ptr() as usize, memory.capacity())
        };
        for i in 0_u8..32 {
            ReusableArgon2
                .hash_password_customized(
                    &[i; 16],
                    b"fixed test salt",
                    None,
                    None,
                    Params::new(64, 2, 1, None).unwrap(),
                )
                .unwrap();
            let memory = WORKSPACE.lock().unwrap();
            assert_eq!(memory.as_ptr() as usize, address);
            assert_eq!(memory.capacity(), capacity);
        }
    }

    #[test]
    fn output_matches_argon2_for_stored_algorithms_and_parameters() {
        for algorithm in [Algorithm::Argon2d, Algorithm::Argon2i, Algorithm::Argon2id] {
            for version in [Version::V0x10, Version::V0x13] {
                let params = Params::new(64, 2, 2, Some(24)).unwrap();
                let expected = Argon2::new(algorithm, version, params.clone())
                    .hash_password_with_salt(b"password", b"fixed test salt")
                    .unwrap();
                let actual = ReusableArgon2
                    .hash_password_customized(
                        b"password",
                        b"fixed test salt",
                        Some(algorithm.ident().as_str()),
                        Some(version.into()),
                        params,
                    )
                    .unwrap();
                assert_eq!(actual.to_string(), expected.to_string());
                ReusableArgon2
                    .verify_password(b"password", &expected)
                    .unwrap();
                assert!(ReusableArgon2.verify_password(b"wrong", &expected).is_err());
            }
        }
    }

    #[test]
    fn concurrent_hashes_keep_independent_salts_and_passwords() {
        let handles: Vec<_> = (0_u8..4)
            .map(|i| {
                std::thread::spawn(move || {
                    let password = [i; 16];
                    let salt = [i + 1; 16];
                    let hash = ReusableArgon2
                        .hash_password_customized(
                            &password,
                            &salt,
                            None,
                            None,
                            Params::new(64, 2, 1, None).unwrap(),
                        )
                        .unwrap();
                    Argon2::default().verify_password(&password, &hash).unwrap();
                    assert!(
                        Argon2::default()
                            .verify_password(&[i + 1; 16], &hash)
                            .is_err()
                    );
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }
    }
}
