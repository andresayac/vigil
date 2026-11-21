//! VirusTotal and the two AI API standards (OpenAI Chat Completions, Anthropic Messages) against local
//! fake servers: nothing goes to the Internet.

mod support;

use serde_json::{Value, json};
use support::{Reply, Server};
use vigil_scan::ai::{self, AiError, ApiAuth, Provider};
use vigil_scan::model::{Flag, Item};
use vigil_scan::vt;

fn vt_server() -> Server {
    Server::start(|request| {
        let digest = request.path.rsplit('/').next().unwrap_or("").to_string();
        if request.header("x-apikey") != Some("key") {
            Reply::new(401, "text/plain", "")
        } else if digest.starts_with('0') {
            Reply::new(404, "text/plain", "")
        } else if digest.starts_with('9') {
            Reply::new(429, "text/plain", "")
        } else {
            let body = json!({"data": {"attributes": {
                "last_analysis_stats": {"malicious": 41, "suspicious": 2, "harmless": 0, "undetected": 27},
                "popular_threat_classification": {"suggested_threat_label": "trojan.miner/xmrig"}}}});
            Reply::new(200, "application/json", body.to_string())
        }
    })
}

#[test]
fn virustotal_lookup() {
    let server = vt_server();
    let base = format!("{}/api/v3/files/", server.base);
    let timeout = std::time::Duration::from_secs(10);
    let known = vt::lookup(&"a".repeat(64), "key", &base, timeout).expect("lookup");
    assert_eq!(
        (known["malicious"].clone(), known["engines"].clone()),
        (json!(41), json!(70))
    );
    assert!(known["summary"].as_str().unwrap_or("").contains("xmrig"));
    assert_eq!(
        known["summary"],
        "41 of 70 engines flag it as malicious and 2 as suspicious (classification: trojan.miner/xmrig)"
    );
    let unknown = vt::lookup(&"0".repeat(64), "key", &base, timeout).expect("lookup");
    assert_eq!(unknown["known"], false);
    assert_eq!(
        vt::lookup(&"a".repeat(64), "bad", &base, timeout),
        Err(vt::VtError::Failed("the VirusTotal API key is not valid".into()))
    );
    assert_eq!(
        vt::lookup("not-a-hash", "key", &base, timeout),
        Err(vt::VtError::Failed("invalid SHA-256 hash".into()))
    );
    assert!(matches!(
        vt::lookup(&"9".repeat(64), "key", &base, timeout),
        Err(vt::VtError::Quota(_))
    ));
    let requests = server.requests.lock().expect("requests");
    assert!(
        requests
            .iter()
            .all(|r| r.method == "GET" && r.header("accept") == Some("application/json"))
    );
    assert!(
        !requests.iter().any(|r| r.path.contains("not-a-hash")),
        "invalid hashes are never sent"
    );
}

#[test]
fn virustotal_enrich_adds_flags() {
    let server = vt_server();
    let base = format!("{}/api/v3/files/", server.base);
    let mut bad = Item::new("executable", "bad.exe", "");
    bad.sha256 = Some("a".repeat(64));
    bad.flags = vec![Flag::new("unsigned", 20, "x")];
    let mut rare = Item::new("executable", "rare.exe", "");
    rare.sha256 = Some("0".repeat(64));
    let mut items = vec![bad, rare];
    let (done, note) = vt::enrich(&mut items, "key", 25, 0.0, &base, &|_| {});
    assert_eq!((done, note), (2, None));
    assert!(items[0].flags.iter().any(|f| f.code == "virustotal_malicious"));
    assert!(items[0].score >= 70);
    assert!(items[1].flags.iter().any(|f| f.code == "virustotal_unknown"));
}

#[test]
fn virustotal_quota_stops_the_lookups() {
    let server = vt_server();
    let base = format!("{}/api/v3/files/", server.base);
    let mut item = Item::new("executable", "x.exe", "");
    item.sha256 = Some("9".repeat(64));
    let mut items = vec![item];
    let (done, note) = vt::enrich(&mut items, "key", 25, 0.0, &base, &|_| {});
    assert_eq!(
        (done, note.as_deref()),
        (0, Some("the VirusTotal lookup quota is exhausted"))
    );
}

/// A streamed Messages API answer (server-sent events).
fn sse(events: &[Value]) -> String {
    events
        .iter()
        .map(|e| format!("event: {}\ndata: {}\n\n", e["type"].as_str().unwrap_or(""), e))
        .collect()
}

fn message(text_blocks: &[(&str, &str)], stop_reason: &str, stop_details: Value) -> String {
    let mut events = vec![
        json!({"type": "message_start", "message": {"model": "claude-opus-5-5", "usage": {
        "input_tokens": 100, "cache_read_input_tokens": 20, "cache_creation_input_tokens": 5, "output_tokens": 1}}}),
    ];
    for (index, (kind, text)) in text_blocks.iter().enumerate() {
        if *kind == "text" {
            events.push(
                json!({"type": "content_block_start", "index": index, "content_block": {"type": "text", "text": ""}}),
            );
            let (a, b) = text.split_at(text.len() / 2);
            for part in [a, b] {
                events.push(json!({"type": "content_block_delta", "index": index, "delta": {"type": "text_delta", "text": part}}));
            }
        } else {
            events.push(json!({"type": "content_block_start", "index": index, "content_block": {"type": kind}}));
        }
        events.push(json!({"type": "content_block_stop", "index": index}));
        events.push(json!({"type": "ping"}));
    }
    events.push(
        json!({"type": "message_delta", "delta": {"stop_reason": stop_reason, "stop_details": stop_details},
                       "usage": {"output_tokens": 42}}),
    );
    events.push(json!({"type": "message_stop"}));
    sse(&events)
}

fn api_server() -> Server {
    Server::start(|request| {
        let body: Value = serde_json::from_str(&request.body).unwrap_or(Value::Null);
        if request.path.starts_with("/v1/models") {
            let models = json!({"data": [{"id": "claude-sonnet-5-5"}, {"id": "claude-opus-5-5"}]});
            return Reply::new(200, "application/json", models.to_string());
        }
        if request.header("x-api-key") != Some("test-key") {
            return Reply::new(
                401,
                "application/json",
                r#"{"type":"error","error":{"type":"authentication_error","message":"bad key"}}"#,
            );
        }
        let user = body["messages"][0]["content"].as_str().unwrap_or("");
        let answer = if user.contains("REFUSE") {
            message(&[], "refusal", json!({"type": "refusal", "category": "cyber"}))
        } else if user.contains("LONG") {
            message(&[("text", "{\"findings\": [")], "max_tokens", Value::Null)
        } else if user.contains("BAD") {
            return Reply::new(
                400,
                "application/json",
                r#"{"type":"error","error":{"type":"invalid_request_error","message":"max_tokens: too large"}}"#,
            );
        } else if user.contains("FALLBACK") {
            message(
                &[
                    ("text", "{\"partial\": "),
                    ("fallback", ""),
                    ("text", "{\"ok\": \"after fallback\"}"),
                ],
                "end_turn",
                Value::Null,
            )
        } else {
            message(
                &[(
                    "text",
                    "{\"findings\": [], \"safe_ids\": [{\"id\": \"B1\", \"what\": \"x\"}]}",
                )],
                "end_turn",
                Value::Null,
            )
        };
        Reply::new(200, "text/event-stream", answer)
    })
}

fn provider(server: &Server, key: &str) -> Provider {
    Provider::anthropic(
        ai::DEFAULT_MODEL,
        ai::DEFAULT_EFFORT,
        ApiAuth::Key(key.into()),
        &server.base,
    )
    .with_retries(0)
}

#[test]
fn api_request_shape_and_streamed_answer() {
    let server = api_server();
    let provider = provider(&server, "test-key");
    let answer = provider
        .complete("system text", "classify these", &ai::verdict_schema())
        .expect("answer");
    assert_eq!(answer["safe_ids"][0]["id"], "B1");
    assert_eq!(
        provider.usage()["input_tokens"],
        125,
        "input + cache read + cache creation"
    );
    assert_eq!(provider.usage()["output_tokens"], 42);
    assert_eq!(provider.usage()["calls"], 1);

    let requests = server.requests.lock().expect("requests");
    let request = &requests[0];
    assert_eq!(request.method, "POST");
    assert_eq!(request.path, "/v1/messages");
    assert_eq!(request.header("anthropic-version"), Some("2026-10-21"));
    assert_eq!(
        request.header("anthropic-beta"),
        Some("server-side-fallback-2026-07-01")
    );
    let body: Value = serde_json::from_str(&request.body).expect("json body");
    assert_eq!(body["model"], ai::DEFAULT_MODEL);
    assert_eq!(body["max_tokens"], 64000);
    assert_eq!(body["stream"], true);
    assert_eq!(body["fallbacks"], "default");
    assert_eq!(body["system"][0]["cache_control"]["type"], "ephemeral");
    assert_eq!(body["output_config"]["effort"], "high");
    assert_eq!(body["output_config"]["format"]["type"], "json_schema");
    assert_eq!(body["output_config"]["format"]["schema"], ai::verdict_schema());
    assert!(
        body.get("temperature").is_none() && body.get("tools").is_none(),
        "no sampling parameters and no tools"
    );
}

#[test]
fn api_refusal_truncation_and_errors() {
    let server = api_server();
    let provider = provider(&server, "test-key");
    let schema = ai::verdict_schema();
    assert_eq!(
        provider.complete("s", "REFUSE", &schema),
        Err(AiError::Refusal(
            "the model refused the analysis (category: cyber)".into()
        ))
    );
    assert!(matches!(
        provider.complete("s", "LONG", &schema),
        Err(AiError::Truncated(_))
    ));
    assert_eq!(
        provider.complete("s", "BAD", &schema),
        Err(AiError::Failed(
            "request rejected by the API: max_tokens: too large".into()
        ))
    );
    let wrong = self::provider(&server, "wrong");
    assert_eq!(
        wrong.complete("s", "x", &schema),
        Err(AiError::Failed(
            "the API rejected the key (check it in Settings or ANTHROPIC_API_KEY)".into()
        ))
    );
    let nowhere = Provider::anthropic(
        ai::DEFAULT_MODEL,
        "high",
        ApiAuth::Key("k".into()),
        "http://127.0.0.1:9",
    )
    .with_retries(0);
    assert_eq!(
        nowhere.complete("s", "x", &schema),
        Err(AiError::Failed("could not connect to http://127.0.0.1:9".into()))
    );
}

/// A server that speaks the Anthropic standard but not its structured output: the schema goes in
/// the prompt instead, and the JSON is read from the text.
#[test]
fn anthropic_compatible_servers_without_output_config_still_answer() {
    let server = Server::start(|request| {
        let body: Value = serde_json::from_str(&request.body).unwrap_or(Value::Null);
        if body.get("output_config").is_some() {
            return Reply::new(
                400,
                "application/json",
                r#"{"type":"error","error":{"type":"invalid_request_error","message":"output_config: Extra inputs are not permitted"}}"#,
            );
        }
        let fenced = format!("Sure:\n```json\n{ANSWER}\n```");
        Reply::new(
            200,
            "text/event-stream",
            message(&[("text", fenced.as_str())], "end_turn", Value::Null),
        )
    });
    let provider = Provider::anthropic("some-model", "high", ApiAuth::Key("k".into()), &server.base).with_retries(0);
    let answer = provider
        .complete("s", "classify", &ai::verdict_schema())
        .expect("answer");
    assert_eq!(answer["safe_ids"][0]["id"], "B1");
    let requests = server.requests.lock().expect("requests");
    assert_eq!(
        requests.len(),
        2,
        "output_config refused, then the schema in the prompt"
    );
    let second: Value = serde_json::from_str(&requests[1].body).expect("json");
    assert!(second.get("output_config").is_none());
    assert!(
        second["messages"][0]["content"]
            .as_str()
            .unwrap_or("")
            .contains("conforms to this schema")
    );
}

#[test]
fn anthropic_compatible_models_are_listed() {
    let server = api_server();
    let keys = |id: &str| (id == "anthropic-compatible").then(|| "test-key".to_string());
    let models = ai::list_models("anthropic-compatible", &server.base, &keys).expect("models");
    assert_eq!(
        models,
        vec!["claude-opus-5-5".to_string(), "claude-sonnet-5-5".to_string()]
    );
    let requests = server.requests.lock().expect("requests");
    let listing = requests
        .iter()
        .find(|r| r.path.starts_with("/v1/models"))
        .expect("listing request");
    assert_eq!(listing.header("anthropic-version"), Some("2026-10-21"));
}

#[test]
fn api_answer_after_a_server_side_fallback() {
    let server = api_server();
    let provider = provider(&server, "test-key");
    let answer = provider
        .complete("s", "FALLBACK", &ai::verdict_schema())
        .expect("answer");
    assert_eq!(answer, json!({"ok": "after fallback"}));
}

#[test]
fn models_without_fallbacks_do_not_send_the_beta() {
    let server = api_server();
    let provider =
        Provider::anthropic("claude-haiku-5-5", "low", ApiAuth::Key("test-key".into()), &server.base).with_retries(0);
    provider.complete("s", "x", &ai::verdict_schema()).expect("answer");
    let requests = server.requests.lock().expect("requests");
    assert_eq!(requests[0].header("anthropic-beta"), None);
    let body: Value = serde_json::from_str(&requests[0].body).expect("json");
    assert!(body.get("fallbacks").is_none());
}

// --------------------------------------------------------------------------- OpenAI protocol

const ANSWER: &str = r#"{"findings": [], "safe_ids": [{"id": "B1", "what": "x"}]}"#;

fn chat_reply(content: &str, finish: &str) -> String {
    json!({"choices": [{"message": {"role": "assistant", "content": content}, "finish_reason": finish}],
           "usage": {"prompt_tokens": 70, "completion_tokens": 9}})
    .to_string()
}

/// An OpenAI-style server. `schema_support`: answers 400 to `json_schema` requests (like some
/// local servers) when false.
fn openai_server(schema_support: bool) -> Server {
    Server::start(move |request| {
        let body: Value = serde_json::from_str(&request.body).unwrap_or(Value::Null);
        if request.path.ends_with("/models") {
            return Reply::new(
                200,
                "application/json",
                json!({"data": [{"id": "model-b"}, {"id": "model-a"}, {"id": "bad id"}]}).to_string(),
            );
        }
        if request.header("authorization").is_some_and(|a| a != "Bearer test-key") {
            return Reply::new(
                401,
                "application/json",
                r#"{"error": {"message": "Incorrect API key"}}"#,
            );
        }
        let user = body["messages"][1]["content"].as_str().unwrap_or("");
        if !schema_support && body["response_format"]["type"] == "json_schema" {
            return Reply::new(
                400,
                "application/json",
                r#"{"error": {"message": "response_format json_schema is not supported"}}"#,
            );
        }
        if user.contains("REFUSE") {
            let refusal = json!({"choices": [{"message": {"role": "assistant", "content": null, "refusal": "I can't help"}, "finish_reason": "stop"}]});
            return Reply::new(200, "application/json", refusal.to_string());
        }
        if user.contains("LONG") {
            return Reply::new(200, "application/json", chat_reply("{\"findings\": [", "length"));
        }
        if user.contains("FENCED") {
            return Reply::new(
                200,
                "application/json",
                chat_reply(&format!("Here you go:\n```json\n{ANSWER}\n```"), "stop"),
            );
        }
        if user.contains("GARBAGE") {
            return Reply::new(
                200,
                "application/json",
                chat_reply("I think everything is fine.", "stop"),
            );
        }
        if user.contains("HUGE") {
            return Reply::new(200, "application/json", "x".repeat(17 * 1024 * 1024));
        }
        if user.contains("MOVED") {
            return Reply::new(302, "text/plain", "");
        }
        Reply::new(200, "application/json", chat_reply(ANSWER, "stop"))
    })
}

#[test]
fn openai_request_shape_and_answer() {
    let server = openai_server(true);
    let provider =
        Provider::openai_compatible("gpt-5", Some("test-key"), &format!("{}/v1", server.base)).with_retries(0);
    let answer = provider
        .complete("system text", "classify these", &ai::verdict_schema())
        .expect("answer");
    assert_eq!(answer["safe_ids"][0]["id"], "B1");
    assert_eq!(provider.usage()["input_tokens"], 70);
    let requests = server.requests.lock().expect("requests");
    let request = &requests[0];
    assert_eq!(
        (request.method.as_str(), request.path.as_str()),
        ("POST", "/v1/chat/completions")
    );
    assert_eq!(request.header("authorization"), Some("Bearer test-key"));
    let body: Value = serde_json::from_str(&request.body).expect("json body");
    assert_eq!(body["model"], "gpt-5");
    assert_eq!(body["messages"][0], json!({"role": "system", "content": "system text"}));
    assert_eq!(body["response_format"]["type"], "json_schema");
    assert_eq!(body["response_format"]["json_schema"]["strict"], true);
    assert_eq!(body["response_format"]["json_schema"]["schema"], ai::verdict_schema());
    assert!(body.get("tools").is_none(), "no tools");
}

#[test]
fn openai_refusal_truncation_garbage_and_errors() {
    let server = openai_server(true);
    let base = format!("{}/v1", server.base);
    let provider = Provider::openai_compatible("gpt-5", Some("test-key"), &base).with_retries(0);
    let schema = ai::verdict_schema();
    assert!(matches!(
        provider.complete("s", "REFUSE", &schema),
        Err(AiError::Refusal(_))
    ));
    assert!(matches!(
        provider.complete("s", "LONG", &schema),
        Err(AiError::Truncated(_))
    ));
    assert_eq!(
        provider.complete("s", "FENCED", &schema).expect("fenced")["safe_ids"][0]["id"],
        "B1"
    );
    assert_eq!(
        provider.complete("s", "GARBAGE", &schema),
        Err(AiError::Failed("the AI did not return a JSON object".into()))
    );
    let huge = provider.complete("s", "HUGE", &schema).expect_err("capped");
    assert!(huge.to_string().contains("could not read the answer"), "{huge}");
    let moved = provider.complete("s", "MOVED", &schema).expect_err("redirect");
    assert!(moved.to_string().contains("redirect, which is not followed"), "{moved}");
    let wrong = Provider::openai_compatible("gpt-5", Some("wrong"), &base).with_retries(0);
    let error = wrong.complete("s", "x", &schema).expect_err("bad key").to_string();
    assert!(error.contains("rejected the API key"), "{error}");
    assert!(!error.contains("wrong"), "the key never appears in messages");
}

#[test]
fn compatible_servers_without_schema_support_still_answer() {
    let server = openai_server(false);
    let provider = Provider::openai_compatible("local-model", None, &format!("{}/v1", server.base)).with_retries(0);
    assert!(provider.local, "127.0.0.1 is this computer");
    let answer = provider
        .complete("s", "classify", &ai::verdict_schema())
        .expect("answer");
    assert_eq!(answer["safe_ids"][0]["id"], "B1");
    let requests = server.requests.lock().expect("requests");
    assert_eq!(requests.len(), 2, "json_schema refused, then json_object");
    let second: Value = serde_json::from_str(&requests[1].body).expect("json");
    assert_eq!(second["response_format"]["type"], "json_object");
    assert!(
        second["messages"][1]["content"]
            .as_str()
            .unwrap_or("")
            .contains("conforms to this schema")
    );
    assert_eq!(requests[0].header("authorization"), None, "no key, no header");
}

#[test]
fn compatible_server_models_are_listed() {
    let server = openai_server(true);
    let models = ai::list_models("openai-compatible", &format!("{}/v1", server.base), &|_| None).expect("models");
    assert_eq!(
        models,
        vec!["model-a".to_string(), "model-b".to_string()],
        "sorted, invalid ids dropped"
    );
}

// --------------------------------------------------------------------------- Ollama on this computer

/// An Ollama server: its own API (`/api/version`, `/api/tags`) and the OpenAI standard it serves
/// (`/v1/models`, `/v1/chat/completions`). It lists cloud models too, as the real one does.
fn ollama_server() -> Server {
    Server::start(|request| match request.path.as_str() {
        "/api/version" => Reply::new(200, "application/json", r#"{"version": "0.40.16"}"#.to_string()),
        "/api/tags" => Reply::new(
            200,
            "application/json",
            json!({"models": [
                {"name": "qwen3:14b", "size": 9_276_198_565_u64},
                {"name": "llama3.1:8b", "size": 4_920_753_328_u64},
                // Cloud models: the local server only relays them to ollama.com.
                {"name": "aaa-first:cloud", "size": 0},
                {"name": "deepseek-v4-flash:latest", "size": 384,
                 "remote_model": "deepseek-v4-flash", "remote_host": "https://ollama.com:443"},
                {"name": "gemma4:31b-cloud"},
                {"name": "kimi-k3:cloud", "remote_host": "https://ollama.com:443"},
                // A cloud model republished under a user's name, without "cloud" in it.
                {"name": "someone/security-helper:latest", "size": 719}]})
            .to_string(),
        ),
        "/v1/models" => Reply::new(
            200,
            "application/json",
            json!({"data": [{"id": "qwen3:14b"}, {"id": "llama3.1:8b"}, {"id": "kimi-k3:cloud"},
                            {"id": "someone/security-helper:latest"}]})
            .to_string(),
        ),
        _ => Reply::new(200, "application/json", chat_reply(ANSWER, "stop")),
    })
}

/// The real computer probe, without any stored key (the fake server is on 127.0.0.1).
fn local_probe() -> ai::SystemProbe<'static> {
    ai::SystemProbe { keys: &|_| None }
}

#[test]
fn ollama_through_the_openai_standard() {
    let server = ollama_server();
    let endpoint = format!("{}/v1", server.base);
    let config = ai::AiConfig {
        provider: "openai-compatible".into(),
        model: "qwen3:14b".into(),
        endpoint: endpoint.clone(),
        ..ai::AiConfig::default()
    };
    let provider = ai::pick_provider(&config, &local_probe()).expect("local model");
    assert!(provider.local && provider.destination.contains("this computer"));
    assert_eq!(provider.batching(), (12, 1), "one request at a time on a local model");
    let answer = provider
        .complete("s", "classify", &ai::verdict_schema())
        .expect("answer");
    assert_eq!(answer["safe_ids"][0]["id"], "B1");
    // Without a model, the first one installed on this computer.
    let first = ai::AiConfig {
        model: String::new(),
        ..config
    };
    assert_eq!(
        ai::pick_provider(&first, &local_probe()).expect("first").model,
        "llama3.1:8b"
    );
    let models = ai::list_models("openai-compatible", &endpoint, &|_| None).expect("models");
    assert_eq!(models, vec!["llama3.1:8b".to_string(), "qwen3:14b".to_string()]);
}

/// Ollama cloud models would send the inventory to ollama.com: they are never listed, refused when
/// configured (through either standard), and refused again right before sending.
#[test]
fn ollama_cloud_models_are_never_used() {
    let server = ollama_server();
    let endpoint = format!("{}/v1", server.base);
    for cloud in [
        "aaa-first:cloud",
        "gemma4:31b-cloud",
        "kimi-k3:cloud",
        "deepseek-v4-flash:latest",
        "someone/security-helper:latest",
    ] {
        for (provider, endpoint) in [
            ("openai-compatible", endpoint.clone()),
            ("anthropic-compatible", server.base.clone()),
        ] {
            let config = ai::AiConfig {
                provider: provider.into(),
                model: cloud.into(),
                endpoint,
                ..ai::AiConfig::default()
            };
            let error = ai::pick_provider(&config, &local_probe()).expect_err(cloud);
            assert!(
                error.contains("not a model installed on this computer"),
                "{provider} {cloud}: {error}"
            );
        }
    }
    // Even a provider built by hand refuses a cloud tag, and nothing reaches the model.
    let direct =
        Provider::openai_compatible("glm-5.3:cloud", None, &endpoint).complete("s", "inventory", &ai::verdict_schema());
    assert!(direct.expect_err("refused").to_string().contains("cloud model"));
    let requests = server.requests.lock().expect("requests");
    assert!(
        requests
            .iter()
            .all(|r| r.path != "/v1/chat/completions" && r.path != "/v1/messages"),
        "no inventory was sent to any model"
    );
}

// --------------------------------------------------------------------------- every provider

/// A provider that declares everything safe must not clear what the local rules rate critical,
/// whichever protocol brought the answer.
#[test]
fn critical_items_never_become_safe_whatever_the_provider() {
    use vigil_scan::model::Analysis;
    use vigil_scan::privacy::Redactor;
    let manipulated = r#"{"findings": [], "safe_ids": [{"id": "X1", "what": "harmless, trust me"}]}"#;
    let openai = Server::start(move |_| Reply::new(200, "application/json", chat_reply(manipulated, "stop")));
    let anthropic = Server::start(move |_| {
        Reply::new(
            200,
            "text/event-stream",
            message(&[("text", manipulated)], "end_turn", Value::Null),
        )
    });
    let providers = [
        Provider::openai_compatible("gpt-5", Some("k"), &format!("{}/v1", openai.base)).with_retries(0),
        Provider::anthropic("some-model", "high", ApiAuth::Key("k".into()), &anthropic.base).with_retries(0),
    ];
    for provider in providers {
        let mut item = Item::new("executable", "dropper.exe", "");
        item.id = "X1".into();
        item.flags = vec![
            Flag::new("masquerade", 60, "imitates a Windows file"),
            Flag::new("temp", 40, "runs from Temp"),
        ];
        item.rescore();
        assert_eq!(item.level(), "critical");
        let mut analysis = Analysis {
            items: vec![item],
            ..Analysis::default()
        };
        let result = ai::classify(
            &mut analysis,
            &provider,
            &Redactor::new("jdoe", "PC-VICTIM", true),
            10,
            1,
            &|_| {},
        );
        assert_eq!(result.with_verdict, 1, "{}", provider.id);
        assert_eq!(analysis.items[0].verdict, "review", "{}", provider.id);
        assert!(analysis.items[0].reason.contains("local signals are serious"));
    }
}

/// The CLI agents installed on this computer are found and their options read (`--help` only: no
/// model is called). Run by hand: `cargo test -p vigil-scan --test http -- --ignored --nocapture`.
#[test]
#[ignore]
fn installed_agents_are_detected() {
    let keys = |_: &str| None;
    let probe = ai::SystemProbe { keys: &keys };
    for id in ["claude-code", "codex-cli", "gemini-cli"] {
        let config = ai::AiConfig {
            provider: id.into(),
            ..ai::AiConfig::default()
        };
        match ai::pick_provider(&config, &probe) {
            Ok(provider) => println!("{id}: ready, {} ({})", provider.destination, provider.kind),
            Err(problem) => println!("{id}: {problem}"),
        }
    }
    for status in ai::statuses(&ai::AiConfig::default(), &probe) {
        println!("{:18} {:5} {}", status.info.id, status.available, status.note);
    }
}
