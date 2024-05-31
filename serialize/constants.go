package serialize

import "github.com/zilong-dai/g16worker/utils"

const CURVE_ID = utils.CURVE_ID
const KEY_STORE_PATH = utils.KEY_STORE_PATH

const CIRCUIT_PATH = utils.CIRCUIT_PATH
const VK_PATH string = utils.VK_PATH
const PK_PATH string = utils.PK_PATH

const COMMON_CIRCUIT_DATA_FILE = utils.COMMON_CIRCUIT_DATA_FILE
const PROOF_WITH_PUBLIC_INPUTS_FILE = utils.PROOF_WITH_PUBLIC_INPUTS_FILE
const VERIFIER_ONLY_CIRCUIT_DATA_FILE = utils.VERIFIER_ONLY_CIRCUIT_DATA_FILE


type MODE uint16
const (
	UNKNOWN MODE = iota
	GNARK
	ARK
	MCL
)