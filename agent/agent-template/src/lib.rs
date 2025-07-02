use serde::{Deserialize, Serialize};
use utils::log;

mod utils;

#[derive(Serialize, Deserialize, Debug)]
struct Message {
    role: String,
    content: String,
}

#[no_mangle]
pub extern "C" fn run() {
        log("This is a log inside the WASM module!");
        //get the user input
        let input = utils::read_input();
        //you can parse the input if you expect to receive a json
        let messages = utils::parse_messages(&input);
        //create a system message
        let system_message = utils::system_message("Your name is UOMI Agent".to_string());
        //process the messages
        let modified_messages = utils::process_messages(system_message, messages);

        let cid = "bafkreicevizwv5glcsuhsqzokpowk4oh7kn4zl5xl5eiewjgfvxkhjgzdm".as_bytes().to_vec();

        let message_file = utils::get_cid_file_service(cid);
    
        log(&format!("Message from a file on IPFS: {:?}", String::from_utf8(message_file).unwrap()));

        let message_file_bytes = utils::get_input_file_service();
        log(&format!("Message from input file: {:?}", String::from_utf8(message_file_bytes).unwrap()));
     
        //transform the messages into a json string and add "messages" key, this is for the LLM model
        let modified_messages_str = format!("{{\"messages\": {}}}", serde_json::to_string(&modified_messages).unwrap());

        let pallet = "UomiEngine";
        let storage = "AIModels";
        let key = "1";

        let chain_state_data = utils::read_chain_state_service(pallet, storage, Some(key));

        log(&format!("Chain state data: {:?}", chain_state_data));

        let request = utils::prepare_request(&modified_messages_str);
        //call the service offchain
        let response = utils::call_ai_service(1, request);
        //save the output
        utils::save_output(&response);
}

