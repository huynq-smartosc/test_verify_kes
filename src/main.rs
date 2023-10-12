use hex::{FromHex, decode};
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
    and then verify it with period, pk (header.opCert.hotVk), m (header.blockHash)
    
    But what I got at the end is Err(Ed25519Signature("signature error: Verification equation was not satisfied")).
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

    // let header_hash = "c5dc9fe994ffc46b1d1a81dfa2af07b9b530a059bb03506ab41f439be3e0482d";
    let block_body_hash = "3a6d165f14f4d13b2a06c022cbd868a31d26bb02cb404ec098be915427394904";
    let block_body_hash_bytes =  <[u8; 32]>::from_hex(block_body_hash).expect("Decoding failed");
    println!("header_bytes {:?}", &block_body_hash_bytes);
    
    let hot_vkey_bytes = &[95,20,3,218,199,95,32,18,83,67,76,114,206,108,90,145,223,16,90,45,160,176,27,205,83,130,2,61,90,187,142,242];
    let pk: PublicKey = PublicKey::from_bytes(hot_vkey_bytes).unwrap();

    let sig_bytes = [139,60,113,106,171,149,246,163,170,196,191,182,221,238,142,141,42,140,82,92,0,119,57,209,70,18,170,33,89,158,46,121,77,36,86,203,15,249,18,73,251,114,254,232,245,116,241,108,14,76,177,251,163,116,150,249,7,177,10,247,27,77,149,9,113,167,86,102,222,242,49,90,205,1,84,155,47,138,93,141,227,129,232,33,3,8,101,10,179,14,79,140,122,91,233,13,150,247,66,226,42,26,215,116,56,102,162,108,56,191,135,145,61,59,82,2,198,148,196,15,68,169,25,55,37,56,19,94,210,231,149,57,202,179,232,206,100,169,95,128,174,234,182,23,111,126,63,172,52,255,34,180,227,93,103,19,159,227,2,188,228,4,22,201,51,3,39,33,235,33,37,156,96,236,109,195,138,225,245,235,73,115,94,230,12,254,53,210,16,7,163,76,64,77,226,242,121,23,152,153,33,226,62,141,45,122,227,71,161,87,231,89,154,223,177,171,209,172,5,222,116,248,126,45,250,105,137,43,197,200,207,62,99,15,161,3,82,52,16,138,149,208,2,212,126,238,19,29,172,180,172,235,128,37,109,60,132,184,135,106,96,34,19,179,245,188,20,123,37,242,106,236,118,49,28,7,9,74,59,30,144,136,227,77,86,65,25,105,146,201,105,110,201,48,167,26,6,118,233,179,167,119,116,32,191,118,175,31,1,102,190,46,240,145,222,175,102,181,231,41,178,229,202,224,177,102,229,214,146,134,253,196,219,76,137,66,118,194,176,232,104,104,114,225,112,50,86,179,123,46,140,155,19,74,25,2,168,34,75,188,217,200,45,110,251,114,116,206,59,44,97,177,37,69,4,211,12,22,86,84,147,161,7,68,253,44,67,14,97,34,219,205,70,183,143,89,89,104,180,199,71,246,234,60,251,144,247,104,81,108,227,184,221,27,113,32,172,61,142,3,126,188,151,8,206,242,251,152,198,162,110,241,25,77,56,159,99,22,229,253,180,152,202,15,244,183,42,97];
    let sig_kes = Sum6KesSig::from_bytes(&sig_bytes).unwrap();

    let is_valid = sig_kes.verify(period, &pk, &block_body_hash_bytes);
    println!("Check valid with perid {:?} : {:?}", period, is_valid);

    // Event try to bruceforce the period, didn't success
    for i in 0..65535 {
        // println!("i {:?}", i);
        let is_v = sig_kes.verify(i, &pk, &block_body_hash_bytes);
        match is_v {
            Err(..) => {},
            Ok(..) => {println!("valid");}
        }
    }
    println!("=============END VERIFY SIGNATURE===========================");

}
