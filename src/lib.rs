extern crate g16worker_sys;

// pub fn verify_groth16_proof(
//     proof_with_public_inputs: &str,
//     vk: &str,
// ) -> anyhow::Result<bool>{

//     let result = g16worker_sys::verify_groth16_proof(&proof_with_public_inputs, &vk);
//     Ok(result == "true")
// }

// pub fn initialize(key_path: &str) -> anyhow::Result<()>{
//     g16worker_sys::initialize(key_path);
//     Ok(())
// }

#[cfg(test)]
mod tests {
    #[test]
    fn test_setup_once() {
        g16worker_sys::initialize("./keystore/");
        let path = "./testdata/f1/";
        let (proof_str, vk_str) = g16worker_sys::generate_groth16_proof(
            &std::fs::read_to_string(format!("{}{}", path, "common_circuit_data.json")).unwrap(),
            &std::fs::read_to_string(format!("{}{}", path, "proof_with_public_inputs.json"))
                .unwrap(),
            &std::fs::read_to_string(format!("{}{}", path, "verifier_only_circuit_data.json"))
                .unwrap(),
            "../keystore/",
        );
        assert_eq!(true, g16worker_sys::verify_groth16_proof(&proof_str, &vk_str));

        let path2 = "./testdata/f2/";
        let (proof_str, vk_str) = g16worker_sys::generate_groth16_proof(
            &std::fs::read_to_string(format!("{}{}", path2, "common_circuit_data.json")).unwrap(),
            &std::fs::read_to_string(format!("{}{}", path2, "proof_with_public_inputs.json"))
                .unwrap(),
            &std::fs::read_to_string(format!("{}{}", path2, "verifier_only_circuit_data.json"))
                .unwrap(),
            "../keystore/",
        );

        assert_eq!(true, g16worker_sys::verify_groth16_proof(&proof_str, &vk_str));
    }
}
