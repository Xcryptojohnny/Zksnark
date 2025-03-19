use ark_bn254::Bn254;
// use ark_ff::UniformRand;
use ark_groth16::Groth16; // , Proof, ProvingKey, VerifyingKey};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_relations::r1cs::ConstraintSystem; //ConstraintLayer
use ark_relations::r1cs::ConstraintSystemRef;
use ark_relations::r1cs::SynthesisError;
use ark_serialize::CanonicalSerialize;
use ark_snark::CircuitSpecificSetupSNARK;
use ark_snark::SNARK;
use ark_std::rand::thread_rng;
// use std::hash::Hash;
// use tracing_subscriber::layer::SubscriberExt;
use std::io::{self, Write};
// use ark_ff::Field;
use ark_ff::Fp; // Make sure to import the necessary traits // Adjust the import based on your actual usage
use std::hash;

// use arkworks::arkworks_setup;

// For hex encoding, we use the hex crate.
use hex;

#[derive(Clone)]
struct SumCircuit {
    pub a: Option<u32>,
    pub b: Option<u32>,
    pub c: u32,
}
impl ConstraintSynthesizer<ark_bn254::Fr> for SumCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ark_bn254::Fr>,
    ) -> Result<(), SynthesisError> {
        // println!("\n[+] Generating constraints for the circuit...");

        // Allocate private variables

        // Assuming self.a and self.b are of type Option<u8>
        let a_var = FpVar::new_witness(cs.clone(), || {
            self.a
                .map(|a| Fp::from(a))
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let b_var = FpVar::new_witness(cs.clone(), || {
            self.b
                .map(|b| Fp::from(b))
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let c_var = FpVar::new_input(cs.clone(), || Ok(ark_bn254::Fr::from(self.c)))?;
        // println!(
        //     "[+] Allocated variables: a = {:?}, b = {:?}, c = {:?}",
        //     self.a, self.b, self.c
        // );

        let sum = &a_var + &b_var;
        sum.enforce_equal(&c_var)?;
        // println!("[+] Constraint added: a + b = c");

        Ok(())
    }
}
/// Main function for demonstrating the usage of the
/// `SumCircuit` struct.
///
/// This function will:
///
/// 1. Initialize the circuit with a = 3, b = 5, and c = 8.
/// 2. Generate constraints for the circuit.
/// 3. Generate a Groth16 proof for the circuit.
/// 4. Verify the proof.
///

/// Helper function to serialize field elements into hex format
fn serialize_to_hex<T: CanonicalSerialize>(value: &T) -> String {
    let mut bytes = Vec::new();
    value.serialize_compressed(&mut bytes).unwrap();
    hex::encode(bytes)
}
/// Function to print the verifying key and proof in a user-friendly format.

fn main() {
    println!("Welcome to the Arkworks Interactive Application!");
    println!("Choose mode:\n1. Owner (Generate proof)\n2. User (Verify proof manually)");

    let choice = read_line("Enter your choice (1 or 2): ");

    match choice.as_str() {
        "1" => owner_mode(),
        "2" => user_mode(),
        _ => println!("Invalid choice. Please run the program again and choose either 1 or 2."),
    }
    // 1owner_mode();
    // let rng = &mut thread_rng();
    // println!("Arkworks setup initialized!");
    // println!("[+] Setting up the circuit...");

    // let circuit = SumCircuit {
    //     a: Some(3),
    //     b: Some(5),
    //     c: 8,
    // };
    // let cs = ConstraintSystem::<ark_bn254::Fr>::new_ref();
    // circuit.clone().generate_constraints(cs.clone()).unwrap();
    // println!("[+] Number of constraints: {}", cs.num_constraints());

    // // Generate proving and verifying keys
    // println!("[+] Generating proving and verifying keys...");
    // let (pk, vk) = Groth16::<Bn254>::setup(circuit.clone(), rng).expect("Setup failed");
    // // println!("[+] Proof generated!");

    // // Generate proof
    // println!("[+] Creating proof...");
    // let proof = Groth16::<Bn254>::prove(&pk, circuit, rng).expect("Proof generation failed");

    // println!("[+] Proof generated!");

    // // Verify proof
    // let pvk = Groth16::<Bn254>::process_vk(&vk).expect("Failed to process verifying key");

    // let is_vaild = Groth16::<Bn254>::verify(&pvk.vk, &[ark_bn254::Fr::from(8)], &proof)
    //     .expect("Verification failed");

    // if is_vaild {
    //     println!("[✅] Proof is valid!");
    // } else {
    //     println!("[❌] Proof is invalid!");
    // }
}

/// Helper function to read a trimmed line from standard input.
fn read_line(prompt: &str) -> String {
    print!("{}", prompt);
    io::stdout().flush().unwrap(); // Ensure prompt is printed immediately.
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input.trim().to_string()
}

//////////////////////////////////////////
// We'll use the BLS12-381 pairing-friendly group for this example.
// use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_bn254::{G1Affine, G1Projective as G1, G2Affine, G2Projective as G2};
// use ark_ec::models::short_weierstrass::affine::Affine;
use ark_std::UniformRand;

// use ark_serialize::CanonicalSerialize;
/// Owner mode: The owner enters secret values, the system generates the proof and verifying key,
/// and then displays values (as hex strings) that can be shared with a user.

fn owner_mode() {
    println!("\n[Owner Mode]");
    // Prompt the owner for secret inputs.
    let a_str = read_line("Enter secret value for a (integer): ");
    let b_str = read_line("Enter secret value for b (integer): ");
    let a: u32 = a_str.parse().expect("Invalid number for a");
    let b: u32 = b_str.parse().expect("Invalid number for b");
    let c = a + b;
    println!(
        "[+] Computed public value c = a + b = {} + {} = {}",
        a, b, c
    );

    let rng = &mut thread_rng();

    // Create the circuit using the provided values.
    let circuit = SumCircuit {
        a: Some(a),
        b: Some(b),
        c,
    };

    let rng = &mut thread_rng();

    // Generate proving and verifying keys.
    println!("[+] Generating proving and verifying keys...");
    let (_pk, vk) = Groth16::<Bn254>::setup(circuit.clone(), rng).expect("Setup failed");

    // Generate the proof using the owner's secret inputs.
    println!("[+] Generating proof...");
    let proof = Groth16::<Bn254>::prove(&_pk, circuit, rng).expect("Proof generation failed");
    println!("[+] Proof generated successfully!");

    let proof_hex = proof.c.clone();

    // let mut vk_bytes = Vec::new();
    // vk.gamma_abc_g1;
    // let vk_hex = hex::encode(vk;);

    // Display the values that the owner should share with the user.
    println!("\n[Share these values with the user for verification]");
    println!("Public Input (c): {}", c);
    println!("Verifying Key (hex): {:?}", vk);
    println!("Proof (hex): {:?}", proof_hex);
    println!("\n[Share these values with the user for verification]\n");

    println!("Public Input (c): <INSERT C VALUE>");

    println!("\nVerifying Key (hex):");
    println!("vk.alpha_g1: \"{}\"", serialize_to_hex(&vk.alpha_g1));
    println!("vk.beta_g2: \"{}\"", serialize_to_hex(&vk.beta_g2));
    println!("vk.gamma_g2: \"{}\"", serialize_to_hex(&vk.gamma_g2));
    println!("vk.delta_g2: \"{}\"", serialize_to_hex(&vk.delta_g2));

    println!("vk.gamma_abc_g1:");
    for (i, el) in vk.gamma_abc_g1.iter().enumerate() {
        println!("  [{}]: \"{}\"", i, serialize_to_hex(el));
    }

    println!("\nProof (hex):");
    println!("Proof.a: \"{}\"", serialize_to_hex(&proof.a));
    println!("Proof.b: \"{}\"", serialize_to_hex(&proof.b));
    println!("Proof.c: \"{}\"", serialize_to_hex(&proof.c));

    println!("\n[End of values]");
    // print_verifying_key_and_proof(&vk, &proof);
}

/// User mode:
///   - User is prompted to input the public input value c,
///     along with the values for the verifying key and proof as provided by the owner.
///   - In this example, for simplicity, we ask the user to re-enter the same values
///     (as printed by owner mode) and then verify the proof.
fn user_mode() {
    println!("\n[User Mode]");
    println!("For this example, please copy the values provided by the owner exactly.");
    let c_str = read_line("Enter the public input value c: ");
    let c: u32 = c_str.parse().expect("Invalid number for c");

    println!("\nEnter the verifying key fields exactly as provided:");
    let alpha_g1_str = read_line("vk.alpha_g1: ");
    let beta_g2_str = read_line("vk.beta_g2: ");
    let gamma_g2_str = read_line("vk.gamma_g2: ");
    let delta_g2_str = read_line("vk.delta_g2: ");
    // For gamma_abc_g1, we assume there is at least one element (typically the first element is for the constant term).
    let gamma_0_str = read_line("vk.gamma_abc_g1[0]: ");

    println!("\nEnter the proof fields exactly as provided:");
    let proof_a_str = read_line("Proof.a: ");
    let proof_b_str = read_line("Proof.b: ");
    let proof_c_str = read_line("Proof.c: ");

    // NOTE:
    // In a real-world application, you would need a proper deserialization mechanism.
    // Here, for simplicity, we cannot reconstruct group elements from their printed Debug format.
    // Therefore, this example shows how you might structure the interactive flow.
    //
    // In practice, you would serialize to a well-defined string format (e.g., hex or base64)
    // and then deserialize back into the group element types before verification.
    //
    // For demonstration purposes, we assume the user verifies that the values match those generated by the owner.
    println!("\n[User Mode] Manual verification is not fully implemented in this example.");
    println!("Please ensure that the entered values exactly match the owner's output.");
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Bn254;
    use ark_groth16::Groth16;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::rand::thread_rng;

    #[test]
    fn test_circuit_setup() {
        let circuit = SumCircuit {
            a: Some(3),
            b: Some(5),
            c: 8,
        };
        let cs = ConstraintSystem::<ark_bn254::Fr>::new_ref();
        circuit.clone().generate_constraints(cs.clone()).unwrap();
        assert!(cs.num_constraints() > 0);
    }

    // #[test]
    // fn test_proving_and_verifying_key_generation() {
    //     let circuit = SumCircuit {
    //         a: Some(3),
    //         b: Some(5),
    //         c: 8,
    //     };
    //     let rng = &mut thread_rng();
    //     let (pk, vk) = Groth16::<Bn254>::setup(circuit.clone(), rng).expect("Setup failed");
    //     assert!(pk.is_some());
    //     assert!(vk.is_some());
    // }

    #[test]
    fn test_proof_generation_and_verification() {
        let circuit = SumCircuit {
            a: Some(3),
            b: Some(5),
            c: 8,
        };
        let rng = &mut thread_rng();
        let (pk, vk) = Groth16::<Bn254>::setup(circuit.clone(), rng).expect("Setup failed");
        let proof = Groth16::<Bn254>::prove(&pk, circuit, rng).expect("Proof generation failed");
        let pvk = Groth16::<Bn254>::process_vk(&vk).expect("Failed to process verifying key");
        let is_valid = Groth16::<Bn254>::verify(&pvk.vk, &[ark_bn254::Fr::from(8)], &proof)
            .expect("Verification failed");
        assert!(is_valid);
    }

    /*************  ✨ Codeium Command 🌟  *************/
    #[test]
    fn test_invalid_proof_verification() {
        println!("Starting test_invalid_proof_verification...");

        let circuit = SumCircuit {
            a: Some(3),
            b: Some(5),
            c: 8,
        };
        println!("Circuit initialized with a=3, b=5, c=8");

        let rng = &mut thread_rng();
        println!("Random number generator initialized");

        let (pk, vk) = Groth16::<Bn254>::setup(circuit.clone(), rng).expect("Setup failed");
        println!("Proving and verifying keys generated");

        let proof = Groth16::<Bn254>::prove(&pk, circuit, rng).expect("Proof generation failed");
        println!("Proof generated");

        let pvk = Groth16::<Bn254>::process_vk(&vk).expect("Failed to process verifying key");
        println!("Verifying key processed");

        let is_valid = Groth16::<Bn254>::verify(&pvk.vk, &[ark_bn254::Fr::from(7)], &proof)
            .expect("Verification failed");
        println!("Verification result: {}", is_valid);

        assert!(!is_valid);
        println!("Test completed - proof should be invalid");
    }
    /******  e9ee93af-0b88-48bd-bf45-29f2bf0f6fb0  *******/

    #[test]
    fn test_edge_cases() {
        let circuit = SumCircuit {
            a: Some(0),
            b: Some(0),
            c: 0,
        };
        let rng = &mut thread_rng();
        let (pk, vk) = Groth16::<Bn254>::setup(circuit.clone(), rng).expect("Setup failed");
        let proof = Groth16::<Bn254>::prove(&pk, circuit, rng).expect("Proof generation failed");
        let pvk = Groth16::<Bn254>::process_vk(&vk).expect("Failed to process verifying key");
        let is_valid = Groth16::<Bn254>::verify(&pvk.vk, &[ark_bn254::Fr::from(0)], &proof)
            .expect("Verification failed");
        assert!(is_valid);
    }
}
