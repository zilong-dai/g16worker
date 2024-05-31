package serialize

type ArkProofE2 struct {
	A0 string `json:"a0"`
	A1 string `json:"a1"`
}
type ArkProofG1 struct {
	X string `json:"x"`
	Y string `json:"y"`
}
type ArkProofG2 struct {
	X ArkProofE2 `json:"x"`
	Y ArkProofE2 `json:"y"`
}
type ArkVK struct {
	AlphaG1 ArkProofG1 `json:"alpha_g1"`
	BetaG2  ArkProofG2 `json:"beta_g2"`
	GammaG2 ArkProofG2 `json:"gamma_g2"`
	DeltaG2 ArkProofG2 `json:"delta_g2"`
	// length dependent on circuit public inputs
	G1K []ArkProofG1 `json:"k"`
}
type ArkProof struct {
	Ar      ArkProofG1 `json:"pi_a"`
	Bs      ArkProofG2 `json:"pi_b"`
	Krs     ArkProofG1 `json:"pi_c"`
	Witness []string   `json:"public_inputs"`
}

type ArkHex2Proof struct {
	Ar      ArkProofG1 `json:"pi_a"`
	Bs      ArkProofG2 `json:"pi_b"`
	Krs     ArkProofG1 `json:"pi_c"`
	Witness []string   `json:"public_inputs"`
}

type ArkHexProof struct {
	Ar      string   `json:"pi_a"`
	Bs      string   `json:"pi_b"`
	Krs     string   `json:"pi_c"`
	Witness []string `json:"public_inputs"`
}

type ArkHex2VK struct {
	AlphaG1 ArkProofG1 `json:"alpha_g1"`
	BetaG2  ArkProofG2 `json:"beta_g2"`
	GammaG2 ArkProofG2 `json:"gamma_g2"`
	DeltaG2 ArkProofG2 `json:"delta_g2"`
	// length dependent on circuit public inputs
	G1K []ArkProofG1 `json:"k"`
}

type GnarkHex2Proof struct {
	Ar            ArkProofG1   `json:"pi_a"`
	Bs            ArkProofG2   `json:"pi_b"`
	Krs           ArkProofG1   `json:"pi_c"`
	Commitments   []ArkProofG1 `json:"Commitments"`
	CommitmentPok ArkProofG1   `json:"CommitmentPok"`
	Witness       []string     `json:"public_inputs"`
}

type GnarkHex2VK struct {
	AlphaG1 ArkProofG1 `json:"alpha_g1"`
	BetaG2  ArkProofG2 `json:"beta_g2"`
	GammaG2 ArkProofG2 `json:"gamma_g2"`
	DeltaG2 ArkProofG2 `json:"delta_g2"`
	// length dependent on circuit public inputs
	G1K                          []ArkProofG1 `json:"gamma_abc"`
	CommitmentKey                string       `json:"CommitmentKey"`
	PublicAndCommitmentCommitted [][]int      `json:"PublicAndCommitmentCommitted"`
}

type CityG16Proof struct {
	PiA          string `json:"pi_a"`
	PiBA0        string `json:"pi_b_a0"`
	PiBA1        string `json:"pi_b_a1"`
	PiC          string `json:"pi_c"`
	PublicInput0 string `json:"public_input_0"`
	PublicInput1 string `json:"public_input_1"`
}

type CityG16VK struct {
	AlphaG1 string   `json:"alpha_g1"`
	BetaG2  string   `json:"beta_g2"`
	GammaG2 string   `json:"gamma_g2"`
	DeltaG2 string   `json:"delta_g2"`
	G1K     []string `json:"k"`
}

type G16CompressProof struct {
	PiA          string   `json:"pi_a"`
	PiB          string   `json:"pi_b"`
	PiC          string   `json:"pi_c"`
	PublicInputs []string `json:"public_input"`
}

type G16CompressVK struct {
	AlphaG1 string   `json:"alpha_g1"`
	BetaG2  string   `json:"beta_g2"`
	GammaG2 string   `json:"gamma_g2"`
	DeltaG2 string   `json:"delta_g2"`
	G1K     []string `json:"k"`
}
