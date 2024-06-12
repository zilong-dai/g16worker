package main

/*
#include <stdlib.h> // Include C standard library, if necessary
#include <string.h>
typedef struct {
    char* proof;
    char* vk;
} Groth16ProofWithVK;
*/
import "C"
import (
	"encoding/json"
	"fmt"

	"github.com/zilong-dai/g16worker/serialize"
	"github.com/zilong-dai/g16worker/worker"
)

var g16Worker *worker.G16Worker

type Groth16ProofWithVK struct {
	Proof string
	Vk    string
}

func init() {
	var err error
	g16Worker, err = worker.NewG16Worker()
	if err != nil {
		panic(err)
	}
}

//export GenerateGroth16Proof
func GenerateGroth16Proof(common_circuit_data *C.char, proof_with_public_inputs *C.char, verifier_only_circuit_data *C.char, keystore_path *C.char) *C.Groth16ProofWithVK {
	if common_circuit_data == nil || proof_with_public_inputs == nil || verifier_only_circuit_data == nil || keystore_path == nil {	
		panic("common_circuit_data, proof_with_public_inputs or verifier_only_circuit_data is null")
	}
	if err := g16Worker.GenerateProof(C.GoString(common_circuit_data), C.GoString(proof_with_public_inputs), C.GoString(verifier_only_circuit_data)); err != nil {
		panic(err)
	}

	g16ProofWithPublicInputs := worker.G16ProofWithPublicInputs{
		Proof:        g16Worker.Proof,
		PublicInputs: g16Worker.PublicInputs,
	}
	proofBytes, err := json.Marshal(g16ProofWithPublicInputs)
	if err != nil {
		panic(err)
	}
	proof_str := string(proofBytes)

	g16VerifyingKey := worker.G16VerifyingKey{
		VK: g16Worker.VK,
	}
	vkBytes, err := json.Marshal(g16VerifyingKey)
	if err != nil {
		panic(err)
	}
	vk_str := string(vkBytes)

	cProofWithVk := (*C.Groth16ProofWithVK)(C.malloc(C.sizeof_Groth16ProofWithVK))
	cProofWithVk.proof = C.CString(proof_str)
	cProofWithVk.vk = C.CString(vk_str)
	return cProofWithVk
}

//export VerifyGroth16Proof
func VerifyGroth16Proof(proofString *C.char, vkString *C.char) *C.char {
	if err := g16Worker.VerifyProof(C.GoString(proofString), serialize.GNARK); err != err {
		return C.CString("false")
	}
	return C.CString("true")
}

//export Initialize
func Initialize(keyPath *C.char) {
	g16Worker.Initialize(C.GoString(keyPath))
}

func main() {

	path := "./testdata/f1/"
	plonky2Strings, _ := serialize.ReadPlonky2Data(path)

	if err := g16Worker.SetUp(path); err != nil {
		panic(err)
	}
	g16Worker.Initialize(worker.KEY_STORE_PATH)
	if err := g16Worker.GenerateProof(plonky2Strings[0], plonky2Strings[1], plonky2Strings[2]); err != nil {
		panic(err)
	} else {
		fmt.Println("Generate proof success")
	}

	p := worker.G16ProofWithPublicInputs{
		Proof:        g16Worker.Proof,
		PublicInputs: g16Worker.PublicInputs,
	}
	proofBytes, err := json.Marshal(p)
	if err != nil {
		panic(err)
	}
	if err := g16Worker.VerifyProof(string(proofBytes), serialize.GNARK); err != nil {
		panic(err)
	} else {
		fmt.Println("Verify success")
	}
}
