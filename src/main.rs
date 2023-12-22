#![allow(dead_code)]
use chrono::{DateTime, Utc};
use clap::Parser;
use core::time;
use reqwest::blocking::Client;
use std::env;
use std::fmt::Write;
use std::{borrow::Cow, ops::Deref};
use urlencoding::encode;
use uuid::Uuid;

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

// const REGION: &str = "eu-west-1";
// const INVOKE_URL: &str = "https://lambda.{}.amazonaws.com/2015-03-31/functions/{}/invocations";

// https://docs.aws.amazon.com/lambda/latest/dg/API_Invoke.html
// POST /2015-03-31/functions/FunctionName/invocations?Qualifier=Qualifier HTTP/1.1
// X-Amz-Invocation-Type: InvocationType
// X-Amz-Log-Type: LogType
// X-Amz-Client-Context: ClientContext
//
// Payload

// https://docs.aws.amazon.com/lambda/latest/dg/CommonParameters.html
// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_aws-signing.html

// https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html
// Canonical request format
// <HTTPMethod>\n
// <CanonicalURI>\n
// <CanonicalQueryString>\n
// <CanonicalHeaders>\n
// <SignedHeaders>\n
// <HashedPayload>

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long)]
    function_name: String,

    #[arg(short, long, default_value_t = 10)]
    wait: u64,

    #[arg(short, long, default_value = "eu-west-1")]
    region: Box<str>,

    payload: Box<str>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!();

    let args = Args::parse();

    println!("Starting...");

    let client = Client::new();
    let base_url = format!("https://lambda.{}.amazonaws.com", args.region);

    // Warm up the client before beginning.
    client.get(&base_url).send()?;

    for i in 0.. {
        let start = std::time::Instant::now();
        invoke(
            &client,
            &base_url,
            &args.region,
            &args.function_name,
            process_templates(&args.payload).as_bytes(),
        )?;
        println!(
            "({i}) - Total Execution time: {}",
            start.elapsed().as_millis()
        );

        std::thread::sleep(time::Duration::from_secs(args.wait));
    }

    Ok(())
}

fn invoke(
    client: &Client,
    base_url: &str,
    region: &str,
    function_name: &str,
    payload: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let now = Utc::now();

    let aws_date = get_aws_date(&now);
    let aws_datetime = get_aws_datetime(&now);

    let payload_hash = hexify(create_sha256_hash(payload));

    let signed_headers = concat!(
        "content-type;",
        "host;",
        // "x-amz-client-context;",
        "x-amz-content-sha256;",
        "x-amz-date;",
        "x-amz-invocation-type;",
        "x-amz-log-type;",
        "x-amz-security-token",
    );

    // Use aws-vault to set these in the environment.
    let access_key_id =
        env::var("AWS_ACCESS_KEY_ID").expect("AWS_ACCESS_KEY_ID is not set!");
    let secret_access_key = env::var("AWS_SECRET_ACCESS_KEY")
        .expect("AWS_ACCESS_KEY_ID is not set!");
    let session_token =
        env::var("AWS_SESSION_TOKEN").expect("AWS_ACCESS_KEY_ID is not set!");

    let mut canonical_request = String::new();
    writeln!(canonical_request, "POST")?;
    writeln!(
        canonical_request,
        "/2015-03-31/functions/{function_name}/invocations"
    )?;

    // Leave a blank line, if no query params
    writeln!(canonical_request)?; //, "Qualifier=latest")?;

    writeln!(canonical_request, "content-type:application/json")?;
    writeln!(canonical_request, "host:lambda.{region}.amazonaws.com")?;
    // writeln!(canonical_request, "x-amz-client-context:a")?;
    writeln!(canonical_request, "x-amz-content-sha256:{payload_hash}")?;
    writeln!(canonical_request, "x-amz-date:{aws_datetime}")?;
    writeln!(canonical_request, "x-amz-invocation-type:RequestResponse")?;
    writeln!(canonical_request, "x-amz-log-type:Tail")?;
    writeln!(canonical_request, "x-amz-security-token:{session_token}")?;
    writeln!(canonical_request)?;
    writeln!(canonical_request, "{signed_headers}")?;
    write!(canonical_request, "{payload_hash}")?;

    // println!("Canonical Request:\n{canonical_request}");
    // println!();

    let credential_scope = format!("{}/{region}/lambda/aws4_request", aws_date);
    let signature = hexify(create_sha256_hash(canonical_request));

    let mut string_to_sign = String::new();
    writeln!(string_to_sign, "AWS4-HMAC-SHA256")?;
    writeln!(string_to_sign, "{aws_datetime}")?;
    writeln!(string_to_sign, "{credential_scope}")?;
    write!(string_to_sign, "{signature}")?;

    // println!("String to Sign:\n{string_to_sign}");
    // println!();

    let date_key =
        create_hmac_sha256_hash(format!("AWS4{secret_access_key}"), aws_date);
    let date_region_key = create_hmac_sha256_hash(date_key, region);
    let date_region_service_key =
        create_hmac_sha256_hash(date_region_key, "lambda");
    let signing_key =
        create_hmac_sha256_hash(date_region_service_key, "aws4_request");
    let signature =
        hexify(&create_hmac_sha256_hash(signing_key, string_to_sign));

    let mut authorization = String::new();
    write!(authorization, "AWS4-HMAC-SHA256 ")?;
    write!(
        authorization,
        "Credential={access_key_id}/{credential_scope},"
    )?;
    write!(authorization, "SignedHeaders={signed_headers},")?;
    write!(authorization, "Signature={signature}")?;

    // println!("Authorization:\n{authorization}");
    // println!();

    let resp = client
        .post(format!(
            "{base_url}/2015-03-31/functions/{function_name}/invocations" //?Qualifier=latest"
        ))
        .header("Content-type", "application/json")
        .header("Authorization", authorization)
        //
        // Invoke parameters
        .header("X-Amz-Invocation-Type", "RequestResponse")
        .header("X-Amz-Log-Type", "Tail")
        // .header("X-Amz-Client-Context", "a")
        //
        // Other Required Parameters
        .header("X-Amz-Content-Sha256", payload_hash.deref())
        .header("X-Amz-Date", aws_datetime)
        .header("X-Amz-Security-Token", session_token)
        .body(Vec::from(payload))
        .send()?;

    if !resp.status().is_success() {
        return Err(String::from_utf8_lossy(&resp.bytes()?).into());
    } else {
        let body = resp.text()?;

        if body.contains("statusCode") && !body.contains("statusCode\": 20") {
            return Err(body.into());
        }
    }

    Ok(())
}

fn aws_uri_encode(uri: &str) -> String {
    uri.split('/')
        .map(|part| encode(part))
        .collect::<Vec<Cow<str>>>()
        .join("/")
}

fn create_hmac_sha256_hash<T, D>(key: T, data: D) -> Box<[u8]>
where
    T: AsRef<[u8]>,
    D: AsRef<[u8]>,
{
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_ref())
        .expect("error creating hmac key");
    mac.update(data.as_ref());

    let result = mac.finalize();

    Vec::from(&result.into_bytes()[..]).into()
}

fn create_sha256_hash<D>(data: D) -> Box<[u8]>
where
    D: AsRef<[u8]>,
{
    let mut hasher = Sha256::new();
    hasher.update(data.as_ref());

    hasher.finalize().to_vec().into()
}

fn get_aws_datetime(dt: &DateTime<Utc>) -> String {
    dt.format("%Y%m%dT%H%M%SZ").to_string()
}

fn get_aws_date(dt: &DateTime<Utc>) -> String {
    dt.format("%Y%m%d").to_string()
}

fn hexify<D>(data: D) -> Box<str>
where
    D: AsRef<[u8]>,
{
    data.as_ref()
        .iter()
        .fold(String::new(), |mut output, c| {
            write!(output, "{c:02x}").expect("error creating string");
            output
        })
        .into()
}

fn process_templates(payload: &str) -> Box<str> {
    let uuid = Uuid::new_v4();

    payload
        .replace("{IDEMPOTENCY_KEY}", &uuid.to_string())
        .into()
}
