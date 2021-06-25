//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//---------------------------------------------------------------------------//

#include <iostream>

#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>

#include "detail/r1cs_examples.hpp"
#include "detail/sha256_component.hpp"

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/fields/bls12/base_field.hpp>
#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/algebra/curves/params/multiexp/bls12.hpp>
#include <nil/crypto3/algebra/curves/params/wnaf/bls12.hpp>

#include <nil/crypto3/zk/snark/blueprint.hpp>
#include <nil/crypto3/zk/snark/blueprint_variable.hpp>

#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark/marshalling.hpp>

#include <nil/crypto3/zk/snark/algorithms/generate.hpp>
#include <nil/crypto3/zk/snark/algorithms/verify.hpp>
#include <nil/crypto3/zk/snark/algorithms/prove.hpp>

#include "toto.cpp"

using namespace nil::crypto3;

typedef algebra::curves::bls12<381> curve_type;
typedef typename curve_type::scalar_field_type field_type;

typedef zk::snark::r1cs_gg_ppzksnark<curve_type> scheme_type;



int main(int argc, char *argv[]) {
    boost::filesystem::path pout, pkout, vkout;
    boost::program_options::options_description options(
        "R1CS Generic Group PreProcessing Zero-Knowledge Succinct Non-interactive ARgument of Knowledge "
        "(https://eprint.iacr.org/2016/260.pdf) CLI Proof Generator");
    // clang-format off
    options.add_options()("help,h", "Display help message")
    ("version,v", "Display version")
    ("generate", "Generate proofs and/or keys")
    ("verify", "verify proofs and/or keys")
    ("proof-output,po", boost::program_options::value<boost::filesystem::path>(&pout)->default_value("proof"))
    ("proving-key-output,pko", boost::program_options::value<boost::filesystem::path>(&pkout)->default_value("pkey"))
    ("verifying-key-output,vko", boost::program_options::value<boost::filesystem::path>(&vkout)->default_value("vkey"));
    // clang-format on

    boost::program_options::variables_map vm;
    boost::program_options::store(boost::program_options::command_line_parser(argc, argv).options(options).run(), vm);
    boost::program_options::notify(vm);

    if (vm.count("help") || argc < 2) {
        std::cout << options << std::endl;
        return 0;
    }

    test ();
    return 0;

    std::cout << "SHA2-256 blueprint generation started." << std::endl;

    blueprint<field_type> bp = sha2_two_to_one_bp<field_type>();

    std::cout << "SHA2-256 blueprint generation finished." << std::endl;

    std::cout << "R1CS generation started." << std::endl;

    r1cs_example<field_type> example =
        r1cs_example<field_type>(bp.get_constraint_system(), bp.primary_input(), bp.auxiliary_input());

    std::cout << "R1CS generation finished." << std::endl;

    //const bool bit = run_r1cs_gg_ppzksnark<curve_type>(example);

    // zk::snark::detail::r1cs_example<field_type> example =
    //     zk::snark::detail::r1cs_example<field_type>(bp.get_constraint_system(), bp.primary_input(), bp.auxiliary_input());

    //zk::snark::r1cs_constraint_system<field_type> constraint_system = bp.get_constraint_system();

    std::cout << "Starting generator" << std::endl;

    typename scheme_type::keypair_type keypair = zk::snark::generate<scheme_type>(example.constraint_system);

    std::cout << "Starting prover" << std::endl;

    const typename scheme_type::proof_type proof = prove<scheme_type>(keypair.first, example.primary_input, example.auxiliary_input);

    // std::cout << "Starting verifier" << std::endl;

    // const bool ans = verify<basic_proof_system>(keypair.second, example.primary_input, proof);

    // std::cout << "Verifier finished, result: " << ans << std::endl;

    if (vm.count("proving-key-output")) {
    }

    if (vm.count("verifying-key-output")) {
    }

    if (vm.count("proof-output")) {
        
    }

    std::vector<std::uint8_t> byteblob;

    std::vector<std::uint8_t> verification_key_byteblob = nil::marshalling::verifier_input_serializer_tvm<scheme_type>::process(
        keypair.second);
    std::vector<std::uint8_t> primary_input_byteblob = nil::marshalling::verifier_input_serializer_tvm<scheme_type>::process(
        example.primary_input);
    std::vector<std::uint8_t> proof_byteblob = nil::marshalling::verifier_input_serializer_tvm<scheme_type>::process(
        proof);

    byteblob.insert (byteblob.end(), proof_byteblob.begin(), proof_byteblob.end());
    byteblob.insert (byteblob.end(), primary_input_byteblob.begin(), primary_input_byteblob.end());
    byteblob.insert (byteblob.end(), verification_key_byteblob.begin(), verification_key_byteblob.end());

    boost::filesystem::ofstream poutf(pout);
    for (const auto &v : byteblob) {
        poutf << v;
    }
    poutf.close();

    return 0;
}
