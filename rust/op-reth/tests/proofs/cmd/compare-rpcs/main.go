// compare-rpcs compares eth_getProof responses from two RPCs over a block range.
//
// Usage:
//
//	go run ./rust/op-reth/tests/proofs/cmd/compare-rpcs \
//	    --rpc1 http://localhost:8545 \
//	    --rpc2 http://localhost:9545 \
//	    --from 44017767 --to 44017800
//
// Proofs are fetched from both RPCs, normalised via utils.NormalizeProofResponse,
// compared for equality, and (when --verify is set) verified against the state
// root reported by rpc1 at that block. A per-address cross-block stability note
// indicates whether the proof changed since the previous sampled block.
package main

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"reflect"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rpc"

	"github.com/ethereum-optimism/optimism/op-service/eth"
	"github.com/ethereum-optimism/optimism/rust/op-reth/tests/proofs/utils"
)

// Default WETH-on-OP contract and balanceOf holders (mapping slot 3).
var (
	defaultContract = common.HexToAddress("0x4200000000000000000000000000000000000006")
	defaultAddrs    = []common.Address{
		common.HexToAddress("0xe50fA9b3c56FfB159cB0FCA61F5c9D750e8128c8"),
		common.HexToAddress("0xc1738D90E2E26C35784A0d3E3d8A9f795074bcA4"),
		common.HexToAddress("0xdD4c717a69763176d8B7A687728e228597eAB86d"),
		common.HexToAddress("0x0bEB0e87661a15cEEa56D8B7ED99e583459F48bA"),
		common.HexToAddress("0x86Bb63148d17d445Ed5398ef26Aa05Bf76dD5b59"),
		common.HexToAddress("0x478946BcD4a5a22b316470F5486fAfb928C0bA25"),
		common.HexToAddress("0xa1055762336F92b4B8d2eDC032A0Ce45ead6280a"),
		common.HexToAddress("0x274d9E726844AB52E351e8F1272e7fc3f58B7E5F"),
		common.HexToAddress("0xb4104C02BBf4E9be85AAa41a62974E4e28D59A33"),
		common.HexToAddress("0x319C0DD36284ac24A6b2beE73929f699b9f48c38"),
		common.HexToAddress("0x73B14a78a0D396C521f954532d43fd5fFe385216"),
		common.HexToAddress("0xdD06d01966688B4efBe18d789e8E1DDBa7Bc31F8"),
		common.HexToAddress("0xc4d4500326981eacD020e20A81b1c479c161c7EF"),
		common.HexToAddress("0x995E394b8B2437aC8Ce61Ee0bC610D617962B214"),
		common.HexToAddress("0x917AA69D539D6518440dd0BEA2eaAc142a8d5610"),
	}
	balanceOfMappingSlot uint64 = 3
)

// mappingSlot computes keccak256(pad(addr,32) || pad(slot,32)) for a `mapping(address => *)` at storage slot `slot`.
func mappingSlot(addr common.Address, slot uint64) common.Hash {
	var buf [64]byte
	copy(buf[12:32], addr[:])
	binary.BigEndian.PutUint64(buf[56:64], slot)
	return crypto.Keccak256Hash(buf[:])
}

func getProof(ctx context.Context, c *rpc.Client, contract common.Address, slot common.Hash, blockHex string) (*eth.AccountResult, error) {
	var res eth.AccountResult
	if err := c.CallContext(ctx, &res, "eth_getProof", contract, []common.Hash{slot}, blockHex); err != nil {
		return nil, err
	}
	return &res, nil
}

func getStateRoot(ctx context.Context, c *rpc.Client, blockHex string) (common.Hash, error) {
	var hdr struct {
		StateRoot common.Hash `json:"stateRoot"`
	}
	if err := c.CallContext(ctx, &hdr, "eth_getBlockByNumber", blockHex, false); err != nil {
		return common.Hash{}, err
	}
	return hdr.StateRoot, nil
}

func main() {
	rpc1URL := flag.String("rpc1", "", "first RPC URL")
	rpc2URL := flag.String("rpc2", "", "second RPC URL")
	from := flag.Uint64("from", 0, "start block (inclusive)")
	to := flag.Uint64("to", 0, "end block (inclusive)")
	step := flag.Uint64("step", 1, "block step")
	verify := flag.Bool("verify", true, "verify rpc1's proof against its state root at each block")
	flag.Parse()

	if *rpc1URL == "" || *rpc2URL == "" || *step == 0 || *from > *to {
		fmt.Fprintln(os.Stderr, "Usage: compare-rpcs --rpc1 <url> --rpc2 <url> --from <block> --to <block> [--step <n>] [--verify=false]")
		os.Exit(2)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c1, err := rpc.DialContext(ctx, *rpc1URL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "rpc1 dial: %v\n", err)
		os.Exit(1)
	}
	defer c1.Close()
	c2, err := rpc.DialContext(ctx, *rpc2URL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "rpc2 dial: %v\n", err)
		os.Exit(1)
	}
	defer c2.Close()

	slots := make(map[common.Address]common.Hash, len(defaultAddrs))
	for _, addr := range defaultAddrs {
		slots[addr] = mappingSlot(addr, balanceOfMappingSlot)
	}

	bar := strings.Repeat("━", 60)
	fmt.Println(bar)
	fmt.Printf(" RPC comparison  |  blocks %d → %d  (step %d)\n", *from, *to, *step)
	fmt.Printf(" RPC1: %s\n", *rpc1URL)
	fmt.Printf(" RPC2: %s\n", *rpc2URL)
	fmt.Println(bar)

	var total, mismatches, errors int
	prevResult := map[common.Address]*eth.AccountResult{}
	prevBlock := map[common.Address]uint64{}

	for blk := *from; blk <= *to; blk += *step {
		blkHex := hexutil.EncodeUint64(blk)

		var stateRoot common.Hash
		if *verify {
			stateRoot, err = getStateRoot(ctx, c1, blkHex)
			if err != nil {
				errors++
				fmt.Printf("  [ERROR]  block=%d  failed to get state root from rpc1: %v\n", blk, err)
				continue
			}
		}

		for _, addr := range defaultAddrs {
			total++
			slot := slots[addr]

			r1, err1 := getProof(ctx, c1, defaultContract, slot, blkHex)
			r2, err2 := getProof(ctx, c2, defaultContract, slot, blkHex)
			if err1 != nil || err2 != nil {
				errors++
				fmt.Printf("  [ERROR]  block=%d  addr=%s\n", blk, addr.Hex())
				if err1 != nil {
					fmt.Printf("    rpc1: %v\n", err1)
				}
				if err2 != nil {
					fmt.Printf("    rpc2: %v\n", err2)
				}
				continue
			}

			utils.NormalizeProofResponse(r1)
			utils.NormalizeProofResponse(r2)

			if !reflect.DeepEqual(r1, r2) {
				mismatches++
				fmt.Printf("  [MISMATCH]  block=%d  addr=%s\n", blk, addr.Hex())
				fmt.Printf("    rpc1 storageHash: %s\n", r1.StorageHash.Hex())
				fmt.Printf("    rpc2 storageHash: %s\n", r2.StorageHash.Hex())
				continue
			}

			if *verify {
				if vErr := utils.VerifyProof(r1, stateRoot); vErr != nil {
					errors++
					fmt.Printf("  [VERIFY-FAIL]  block=%d  addr=%s: %v\n", blk, addr.Hex(), vErr)
					continue
				}
			}

			short := addr.Hex()[:12]
			storageHash := r1.StorageHash.Hex()
			if prev, ok := prevResult[addr]; ok {
				note := "proof unchanged"
				if !reflect.DeepEqual(prev, r1) {
					note = "proof CHANGED"
				}
				fmt.Printf("  [OK]  block=%d  addr=%s…  storageHash=%s  (%s from block %d)\n",
					blk, short, storageHash, note, prevBlock[addr])
			} else {
				fmt.Printf("  [OK]  block=%d  addr=%s…  storageHash=%s\n", blk, short, storageHash)
			}
			prevResult[addr] = r1
			prevBlock[addr] = blk
		}
	}

	fmt.Println(bar)
	fmt.Printf(" Total checks : %d\n", total)
	fmt.Printf(" Matches      : %d\n", total-mismatches-errors)
	fmt.Printf(" Mismatches   : %d\n", mismatches)
	fmt.Printf(" Errors       : %d\n", errors)
	fmt.Println(bar)

	if mismatches > 0 || errors > 0 {
		os.Exit(1)
	}
}
