


//use chrono::*;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use data_encoding::BASE64;
use urlparse::quote;

// Create alias for HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

pub struct NotificationHub {
    pub connection_string: String,
    pub hub_name: String,
    endpoint: String,
    shared_access_key: String,
    shared_access_keyname: String,
    expiry_time : i64
}

use crate::errors::*;
//use reqwest::Error;

fn find_starting_string(
    splitted_connection: &Vec<&str>,
    starting_string: &str,
) -> Result<String, ParsingError> {
    let brut = splitted_connection
        .into_iter()
        .filter(|s| s.starts_with(starting_string))
        .collect::<Vec<&&str>>()
        .first().map(|s| **s);
    match brut {
        Some(value) => Ok(String::from(value)),
        None => Err(ParsingError::from_string(format!(
            "impossible de trouver la valeur de {}",
            starting_string
        ))),
    }
}
pub trait ResultErrorExt<T> {
    fn to_sending_error(self) -> Result<T,SendingError>;
}  
impl<T>  ResultErrorExt<T> for Result<T,reqwest::Error> {
    fn to_sending_error(self) -> Result<T,SendingError>{
        match self {
            Ok(value) => Ok(value),
            Err(reqwest_err) => Err(SendingError::from_string(format!("{}",reqwest_err)))
        }
    }
}

impl NotificationHub {
    pub fn new(hub_name: &str, connection_string: &str) -> NotificationHub {
        NotificationHub {
            hub_name: String::from(hub_name),
            connection_string: String::from(connection_string),
            endpoint: String::from(""),
            shared_access_key: String::from(""),
            shared_access_keyname: String::from(""),
            expiry_time: 300, //set by default
        }
    }

    pub fn parse(&self) -> Result<NotificationHub, ParsingError> {
        let splitted_connection: Vec<&str> = self.connection_string.split(';').collect();
        if splitted_connection.len() == 3 {
            let local_endpoint = String::from("https")
                + &(find_starting_string(&splitted_connection, "Endpoint=")?)[11..];
            let local_shared_access_keyname =
                &(find_starting_string(&splitted_connection, "SharedAccessKeyName=")?)[20..];
            let local_shared_access_key =
                &(find_starting_string(&splitted_connection, "SharedAccessKey=")?)[16..];

            Ok(NotificationHub {
                hub_name: self.hub_name.clone(),
                connection_string: self.connection_string.clone(),
                endpoint: String::from(local_endpoint),
                shared_access_key: String::from(local_shared_access_key),
                shared_access_keyname: String::from(local_shared_access_keyname),
                expiry_time: self.expiry_time
            })
        } else {
            Err(ParsingError::new("malformed connection string"))
        }
    }

    pub fn set_expiry(self,time : i64) -> NotificationHub { NotificationHub{expiry_time: time , .. self }}

    pub fn send_gcm(&self,body : String) -> Result<String,SendingError> {
        let get_expiry = || { (chrono::Utc::now() + chrono::Duration::seconds(self.expiry_time)).timestamp()};
        let target_uri = &*( self.endpoint.clone() + &*self.hub_name);
        let expiry = &*(get_expiry().to_string());
        let to_sign = target_uri.to_string() + "\n" + expiry;

        //hash de to_sign
        let mut signed_hmac_sha256 = HmacSha256::new_varkey(self.shared_access_key.as_bytes()).expect("HMAC can take key of any size");
        signed_hmac_sha256.input(&to_sign.as_bytes());
        let signature = signed_hmac_sha256.result().code();
        let signature_str = quote(BASE64.encode(signature.as_ref()),b"").expect("fail parsing");
        //println!("signature_str = {}",signature_str);
        let sas_token = format!("SharedAccessSignature sig={}&se={}&skn={}&sr={}",signature_str,expiry,self.shared_access_keyname,target_uri);//target_uri
        //println!("sas_token = {}",sas_token);
        let url = &*(String::from(target_uri) + "/messages?api-version=2013-10");//&test
        let response =  reqwest::blocking::Client::new()
        .post(url)
        .header("Authorization",sas_token)
        .header("Content-Type", "application/json;charset=utf-8")
        .header("ServiceBusNotification-Format", "gcm")
        .body(body)
        .send().to_sending_error()?;
    
    let result_code = response.status();
    let text_result = response.text();
    let text = match text_result {
        Ok(text) => text,
        Err(reqwest_err) => format!("{}",reqwest_err)
    };
    if result_code.is_success() {
        Ok(text)
    }
    else {
        Err(SendingError::from_string(format!("text = {} - {}",result_code,text)))
    }
    }
}
















/*TEST SECTION */
#[test]
fn test_new_ok() {
    let nothub = NotificationHub::new("ayasha", "Endpoint=sb://ayasha.servicebus.windows.net/;SharedAccessKeyName=DefaultFullSharedAccessSignature;SharedAccessKey=rY5kVCbkxE1sNS8qys0usJAPOZk8ASbpG1ZQY14R27w=");

    assert_eq!(nothub.hub_name, "ayasha");
    assert_eq!(nothub.connection_string, "Endpoint=sb://ayasha.servicebus.windows.net/;SharedAccessKeyName=DefaultFullSharedAccessSignature;SharedAccessKey=rY5kVCbkxE1sNS8qys0usJAPOZk8ASbpG1ZQY14R27w=");
    assert_eq!(nothub.shared_access_key, "");
    assert_eq!(nothub.endpoint, "");
    assert_eq!(nothub.shared_access_keyname, "");
}
#[test]
fn test_parse_ok() {
    let nothub = NotificationHub::new("ayasha", "Endpoint=sb://ayasha.servicebus.windows.net/;SharedAccessKeyName=DefaultFullSharedAccessSignature;SharedAccessKey=rY5kVCbkxE1sNS8qys0usJAPOZk8ASbpG1ZQY14R27w=").parse().unwrap();

    assert_eq!(nothub.hub_name, "ayasha");
    assert_eq!(nothub.endpoint, "https://ayasha.servicebus.windows.net/");
    assert_eq!(
        nothub.shared_access_key,
        "rY5kVCbkxE1sNS8qys0usJAPOZk8ASbpG1ZQY14R27w="
    );
    assert_eq!(
        nothub.shared_access_keyname,
        "DefaultFullSharedAccessSignature"
    );
}

#[test]
fn test_parse_too_short() {
    let nothub = NotificationHub::new("ayasha", "Endpoi;SharedAccessKeyName=DefaultFullSharedAccessSignature;SharedAccessKey=rY5kVCbkxE1sNS8qys0usJAPOZk8ASbpG1ZQY14R27w=").parse();

    match nothub {
        Err(pe) => assert_eq!(&*format!("{}",pe),"impossible de trouver la valeur de Endpoint=" ),
        _ => panic!("Le test test_parse_too_short aurait du avoir un resultat Err(ParsingError)")
    }
}

#[test]
fn test_parse_not_enought_split() {
    let nothub = NotificationHub::new("ayasha", "Endpoint=sb://ayasha.servicebus.windows.net/;SharedAccessKeyName=DefaultFullSharedAccessSignature").parse();
    match nothub {
        Err(pe) => assert_eq!(&*format!("{}",pe),"malformed connection string" ),
        _ => panic!("Le test test_parse_not_enought_split aurait du avoir un resultat Err(ParsingError)")
    }
}

#[test]
fn test_set_expiry() {
    let nothub = NotificationHub::new("ayasha", "Endpoint=sb://ayasha.servicebus.windows.net/;SharedAccessKeyName=DefaultFullSharedAccessSignature").set_expiry(600);

    assert_eq!(nothub.expiry_time,600 );
}
