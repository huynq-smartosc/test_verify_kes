use hex::decode;
use base64::{engine::general_purpose, Engine as _};
use kes_summed_ed25519::{PublicKey, kes::Sum6KesSig, traits::KesSig};


pub fn base64_to_hex(base64: String) -> String {
    let mut buffer = Vec::<u8>::new();
    general_purpose::STANDARD
        .decode_vec(base64, &mut buffer)
        .unwrap();
    // Convert to hex thanks to https://stackoverflow.com/a/73358987
    return buffer
        .iter()
        .map(|b| format!("{:02x}", b).to_string())
        .collect::<Vec<String>>()
        .join("");
}

/* 
    I'm trying to verify the signature of block 9317023 on mainnet (https://cardanoscan.io/block/9317023)
    The data is fetched using Ogmios v5, and be located in ./block.json file.
    I'm assummed that I'll load signature byte (header.signature) to sig_kes using Sum6KesSig::from_bytes
    and then verify it with period, pk (header.issuerVk), m (headerHash)
    
    But what I got at the end is Err(InvalidHashComparison).
    Could you help to guide me how to walk thought this issue?

    Thanks a lot for your time and effort.
 */

fn main() {
    println!("=============VERIFY SIGNATURE===========================");
    let slots_per_kes_period = 129600;
    let current_slot = 103710047;
    let current_period: u32 = current_slot/slots_per_kes_period;
    let start_kes_period = 759; // header.opCert.kesPeriod
    let period = current_period - start_kes_period;
    println!("period {:?}", period);

    let block_header_hash = "c5dc9fe994ffc46b1d1a81dfa2af07b9b530a059bb03506ab41f439be3e0482d";
    let block_body_hash = "3a6d165f14f4d13b2a06c022cbd868a31d26bb02cb404ec098be915427394904";
    let header_bytes = &decode(block_header_hash.clone()).unwrap()[..];

    let signature_b64 = "izxxaquV9qOqxL+23e6OjSqMUlwAdznRRhKqIVmeLnlNJFbLD/kSSfty/uj1dPFsDkyx+6N0lvkHsQr3G02VCXGnVmbe8jFazQFUmy+KXY3jgeghAwhlCrMOT4x6W+kNlvdC4ioa13Q4ZqJsOL+HkT07UgLGlMQPRKkZNyU4E17S55U5yrPozmSpX4Cu6rYXb34/rDT/IrTjXWcTn+MCvOQEFskzAych6yElnGDsbcOK4fXrSXNe5gz+NdIQB6NMQE3i8nkXmJkh4j6NLXrjR6FX51ma37Gr0awF3nT4fi36aYkrxcjPPmMPoQNSNBCKldAC1H7uEx2stKzrgCVtPIS4h2pgIhOz9bwUeyXyaux2MRwHCUo7HpCI401WQRlpkslpbskwpxoGdumzp3d0IL92rx8BZr4u8JHer2a15ymy5crgsWbl1pKG/cTbTIlCdsKw6GhocuFwMlazey6MmxNKGQKoIku82cgtbvtydM47LGGxJUUE0wwWVlSToQdE/SxDDmEi281Gt49ZWWi0x0f26jz7kPdoUWzjuN0bcSCsPY4DfryXCM7y+5jGom7xGU04n2MW5f20mMoP9LcqYQ==";
    let signature = base64_to_hex(signature_b64.to_string());
    let signature_bytes = &decode(signature.clone()).unwrap()[..];

    let issuer_vk = "fbbb8ec5487e40ee9e32686675b1672fcf5498533f19a778b1aae460434bfeae";

    // hotVk: header.opCert.hotVk
    let hot_vkey_b64 = "XxQD2sdfIBJTQ0xyzmxakd8QWi2gsBvNU4ICPVq7jvI=";
    let hot_vkey = base64_to_hex(hot_vkey_b64.to_string());
    // HotVKey 5f1403dac75f201253434c72ce6c5a91df105a2da0b01bcd5382023d5abb8ef2
    // println!("hot_vkey {:?}", hot_vkey);

    let pk: PublicKey = PublicKey::from_bytes(&decode(issuer_vk.clone()).unwrap()[..]).unwrap();


    // A bit intereting that if I use hot_vkey, the verify give me another error 
    // Err(Ed25519Signature("signature error: Verification equation was not satisfied"))
    // let pk: PublicKey = PublicKey::from_bytes(&decode(hot_vkey.clone()).unwrap()[..]).unwrap();

    let sig_kes = Sum6KesSig::from_bytes(signature_bytes).unwrap();
    let is_valid = sig_kes.verify(period, &pk, header_bytes);
    println!("is_valid {:?}", is_valid);
    println!("=============END VERIFY SIGNATURE===========================");

}
