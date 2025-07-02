use super::{ Message };

const MAX_INPUT_SIZE: usize = 1024 * 1024;

extern "C" {
    fn get_input_data(ptr: i32, len: i32);
    fn set_output(ptr: i32, len: i32);
    fn console_log(ptr: i32, len: i32);
    fn call_ai(model: i32, ptr: i32, len: i32, output_ptr: i32, output_len: i32);
    fn get_cid_file(ptr: i32, len: i32, output_ptr: i32, output_len: i32);
    fn get_input_file(ptr: i32, len: i32);
    fn read_chain_state(pallet_ptr: i32, pallet_len: i32, storage_ptr: i32, storage_len: i32, key_ptr: i32, key_len: i32, output_ptr: i32, output_len: i32);
}

pub fn parse_messages(input: &[u8]) -> Vec<Message> {
    let input_str = String::from_utf8_lossy(input);
    let messages: Vec<Message> = serde_json::from_str(&input_str).unwrap();
    messages
}

pub fn system_message(content: String) -> Message {
    Message {
        role: "system".to_string(),
        content,
    }
}

pub fn process_messages(system_message: Message, mut messages: Vec<Message>) -> Vec<Message> {
    messages.insert(0, system_message);
    messages
}

// ===========================================================
// =============== Offchain API, DO NOT MODIFY ===============
// ===========================================================
#[allow(dead_code)]
pub fn log(message: &str) {
    unsafe {
        console_log(message.as_ptr() as i32, message.len() as i32);
    }
}
#[allow(dead_code)]
pub fn get_input_file_service() -> Vec<u8> {
    let mut response = vec![0u8; MAX_INPUT_SIZE + 4];

    unsafe {
        get_input_file(response.as_mut_ptr() as i32, response.len() as i32);
    }

    extract_wasm_data(response)
}
#[allow(dead_code)]
pub fn read_input() -> Vec<u8> {
    let mut input_bytes = vec![0u8; MAX_INPUT_SIZE + 4];
    unsafe {
        get_input_data(input_bytes.as_mut_ptr() as i32, input_bytes.len() as i32);
    }
    let input = extract_wasm_data(input_bytes);
    input
}
#[allow(dead_code)]
pub fn prepare_request(body: &str) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(body.as_bytes());
    data
}
#[allow(dead_code)]
pub fn call_ai_service(model: i32, content: Vec<u8>) -> Vec<u8> {
    let mut response = vec![0u8; MAX_INPUT_SIZE + 4];

    unsafe {
        call_ai(
            model,
            content.as_ptr() as i32,
            content.len() as i32,
            response.as_mut_ptr() as i32,
            response.len() as i32
        );
    }

    extract_wasm_data(response)
}
#[allow(dead_code)]
pub fn get_cid_file_service(cid: Vec<u8>) -> Vec<u8> {
    let mut response = vec![0u8; MAX_INPUT_SIZE + 4];

    unsafe {
        get_cid_file(
            cid.as_ptr() as i32,
            cid.len() as i32,
            response.as_mut_ptr() as i32,
            response.len() as i32
        );
    }

    extract_wasm_data(response)
}
#[allow(dead_code)]
pub fn read_chain_state_service(pallet: &str, storage: &str, key: Option<&str>) -> Vec<u8> {
    let mut response = vec![0u8; MAX_INPUT_SIZE + 4];
    let key_bytes = key.unwrap_or("").as_bytes();
    unsafe {
        read_chain_state(
            pallet.as_ptr() as i32, pallet.len() as i32,
            storage.as_ptr() as i32, storage.len() as i32,
            key_bytes.as_ptr() as i32, key_bytes.len() as i32,
            response.as_mut_ptr() as i32, response.len() as i32
        );
    }
    extract_wasm_data(response)
}

#[allow(dead_code)]
pub fn save_output(data: &[u8]) {
    unsafe {
        set_output(data.as_ptr() as i32, data.len() as i32);
    }
}

#[allow(dead_code)]
fn extract_wasm_data(data: Vec<u8>) -> Vec<u8> {
    let data_len = u32::from_le_bytes(data[..4].try_into().unwrap()) as usize;
    data[4..data_len + 4].to_vec()
}
