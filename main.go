package main

import (
	"encoding/json"

	"github.com/zilong-dai/g16worker/serialize"
	"github.com/zilong-dai/g16worker/worker"
)

func main() {

	path := "./testdata/f1/"
	plonky2Strings, _ := serialize.ReadPlonky2Data(path)

	g16Worker, err := worker.NewG16Worker()
	if err != nil {
		panic(err)
	}
	// if err := g16Worker.SetUp(path); err!= nil {
	// 	panic(err)
	// }
	g16Worker.Initialize(worker.KEY_STORE_PATH)
	if err := g16Worker.GenerateProof(plonky2Strings[0], plonky2Strings[1], plonky2Strings[2]); err != nil {
		panic(err)
	}

	p := worker.G16ProofWithPublicInputs{
		Proof: g16Worker.Proof,
		PublicInputs: g16Worker.PublicInputs,
	}
	 proofBytes, err:= json.Marshal(p); 
	 if err!= nil {
		panic(err)
	}
	if err := g16Worker.VerifyProof(string(proofBytes), serialize.GNARK); err != nil {
		panic(err)
	}	
}
