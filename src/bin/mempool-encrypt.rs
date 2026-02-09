use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use mempool_encryption::dkg::{
    BlsDkgScheme, DkgMessage, DkgPartySecret, DkgPublicParams, DkgSnapshot, DkgState,
    compute_pk_from_shares,
};
use mempool_encryption::kem::{BlsCiphertext, BlsFullSig, BlsPartialSig, BlsPlaintext, BlsTag};
use mempool_encryption::scheme::{SetupProtocol, ThresholdRelease};
use mempool_encryption::types::{Error, Params, PartyInfo, Wire};
use rand_core::SeedableRng;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct WireMessage {
    from: u32,
    to: u32,
    bytes_b64: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct PublicParamsJson {
    pk_b64: Option<String>,
    pk_shares: Vec<(u32, String)>,
    transcript_hash_b64: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct PartySecretJson {
    id: u32,
    share_b64: String,
}

fn main() {
    mempool_encryption::logging::init_tracing(None);

    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() {
        usage();
        return;
    }
    let cmd = &args[0];
    let rest = &args[1..];

    match cmd.as_str() {
        "dkg-init" => cmd_dkg_init(rest),
        "dkg-handle" => cmd_dkg_handle(rest),
        "dkg-verify" => cmd_dkg_verify(rest),
        "dkg-finalize" => cmd_dkg_finalize(rest),
        "broadcast" => cmd_broadcast(rest),
        "deliver-outbox" => cmd_deliver_outbox(rest),
        "encrypt" => cmd_encrypt(rest),
        "partial-release" => cmd_partial_release(rest),
        "combine" => cmd_combine(rest),
        "decrypt" => cmd_decrypt(rest),
        "public-merge" => cmd_public_merge(rest),
        _ => usage(),
    }
}

fn usage() {
    eprintln!("mempool-encrypt <cmd> [args]\n");
    eprintln!("Commands:");
    eprintln!("  dkg-init --id <id> --n <n> --t <t> --root <dir>");
    eprintln!("  dkg-handle --id <id> --root <dir>");
    eprintln!("  dkg-verify --id <id> --root <dir>");
    eprintln!("  dkg-finalize --id <id> --root <dir>");
    eprintln!("  broadcast --from <id> --to <id,id,..> --root <dir>");
    eprintln!("  deliver-outbox --from <id> --root <dir>");
    eprintln!("  encrypt --pub <file> --tag <b64> --in <file> --out <file>");
    eprintln!("  partial-release --secret <file> --pub <file> --tag <b64> --out <file>");
    eprintln!("  combine --tag <b64> --partials <dir> --pub <file> --out <file>");
    eprintln!("  decrypt --pub <file> --tag <b64> --ct <file> --witness <file> --out <file>");
    eprintln!("  public-merge --root <dir> --n <n> --out <file>");
}

fn cmd_dkg_init(args: &[String]) {
    let id = get_u32(args, "--id").unwrap_or(1);
    let n = get_u32(args, "--n").unwrap_or(7);
    let t = get_u32(args, "--t").unwrap_or(4);
    let root = get_path(args, "--root").unwrap_or_else(|| PathBuf::from("target"));

    let params = Params { n, t };
    let me = PartyInfo { id };
    let mut state = BlsDkgScheme::init(params, me);
    save_state(&root, id, &state).expect("save state");

    let out = state.initial_messages().expect("initial_messages");
    write_outbox(&root, id, out).expect("write outbox");
}

fn cmd_dkg_handle(args: &[String]) {
    let id = get_u32(args, "--id").unwrap_or(1);
    let root = get_path(args, "--root").unwrap_or_else(|| PathBuf::from("target"));

    let mut state = load_state(&root, id).expect("load state");
    let inbox = drain_inbox(&root, id).expect("drain inbox");
    let mut out_all = Vec::new();
    for (from, msg) in inbox {
        let out = BlsDkgScheme::handle_message(&mut state, from, msg).expect("handle_message");
        out_all.extend(out);
    }
    save_state(&root, id, &state).expect("save state");
    write_outbox(&root, id, out_all).expect("write outbox");
}

fn cmd_dkg_verify(args: &[String]) {
    let id = get_u32(args, "--id").unwrap_or(1);
    let root = get_path(args, "--root").unwrap_or_else(|| PathBuf::from("target"));

    let mut state = load_state(&root, id).expect("load state");
    let complaints = state.verify_shares().expect("verify_shares");
    save_state(&root, id, &state).expect("save state");
    write_outbox(&root, id, complaints).expect("write outbox");
}

fn cmd_dkg_finalize(args: &[String]) {
    let id = get_u32(args, "--id").unwrap_or(1);
    let root = get_path(args, "--root").unwrap_or_else(|| PathBuf::from("target"));

    let state = load_state(&root, id).expect("load state");
    let (pp, sk) = BlsDkgScheme::finalize(state).expect("finalize");

    save_public(&root, id, &pp).expect("save public");
    save_secret(&root, id, &sk).expect("save secret");
}

fn cmd_broadcast(args: &[String]) {
    let from = get_u32(args, "--from").unwrap_or(1);
    let to_list = get_str(args, "--to").unwrap_or_default();
    let root = get_path(args, "--root").unwrap_or_else(|| PathBuf::from("target"));
    let dests = parse_id_list(&to_list);

    let outbox = party_dir(&root, from).join("outbox");
    let entries = match fs::read_dir(&outbox) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let mut buf = String::new();
        if let Ok(mut f) = File::open(entry.path()) {
            let _ = f.read_to_string(&mut buf);
            if let Ok(wire) = serde_json::from_str::<WireMessage>(&buf) {
                for to in dests.iter().copied() {
                    // Preserve the original sender.
                    let msg = WireMessage {
                        from: wire.from,
                        to,
                        bytes_b64: wire.bytes_b64.clone(),
                    };
                    write_inbox(&root, to, &msg).expect("write inbox");
                }
            }
        }
        let _ = fs::remove_file(entry.path());
    }
}

fn cmd_deliver_outbox(args: &[String]) {
    let from = get_u32(args, "--from").unwrap_or(1);
    let root = get_path(args, "--root").unwrap_or_else(|| PathBuf::from("target"));

    let outbox = party_dir(&root, from).join("outbox");
    let entries = match fs::read_dir(&outbox) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let mut buf = String::new();
        if let Ok(mut f) = File::open(entry.path()) {
            let _ = f.read_to_string(&mut buf);
            if let Ok(wire) = serde_json::from_str::<WireMessage>(&buf) {
                write_inbox(&root, wire.to, &wire).expect("write inbox");
            }
        }
        let _ = fs::remove_file(entry.path());
    }
}

fn cmd_encrypt(args: &[String]) {
    let pub_path = get_path(args, "--pub").expect("--pub");
    let tag_b64 = get_str(args, "--tag").expect("--tag");
    let in_path = get_path(args, "--in").expect("--in");
    let out_path = get_path(args, "--out").expect("--out");

    let pp = load_public(&pub_path).expect("load public");
    let tag = BlsTag(decode_b64(&tag_b64).expect("tag"));
    let mut pt = Vec::new();
    File::open(in_path)
        .expect("open in")
        .read_to_end(&mut pt)
        .unwrap();

    let mut rng = rand_chacha::ChaCha20Rng::from_entropy();
    let ct = <BlsDkgScheme as ThresholdRelease>::encrypt(&pp, &tag, &BlsPlaintext(pt), &mut rng)
        .expect("encrypt");

    let ct_b64 = STANDARD.encode(ct.encode());
    let mut f = File::create(out_path).expect("out");
    let _ = f.write_all(ct_b64.as_bytes());
}

fn cmd_partial_release(args: &[String]) {
    let secret_path = get_path(args, "--secret").expect("--secret");
    let tag_b64 = get_str(args, "--tag").expect("--tag");
    let pub_path = get_path(args, "--pub").expect("--pub");
    let out_path = get_path(args, "--out").expect("--out");

    let sk = load_secret(&secret_path).expect("load secret");
    let pp = load_public(&pub_path).expect("load public");

    let tag = BlsTag(decode_b64(&tag_b64).expect("tag"));
    let sig = <BlsDkgScheme as ThresholdRelease>::partial_release(&pp, &sk, &tag)
        .expect("partial_release");

    let sig_b64 = STANDARD.encode(sig.encode());
    let mut f = File::create(out_path).expect("out");
    let _ = f.write_all(sig_b64.as_bytes());
}

fn cmd_combine(args: &[String]) {
    let tag_b64 = get_str(args, "--tag").expect("--tag");
    let partials_dir = get_path(args, "--partials").expect("--partials");
    let pub_path = get_path(args, "--pub").expect("--pub");
    let out_path = get_path(args, "--out").expect("--out");

    let tag = BlsTag(decode_b64(&tag_b64).expect("tag"));

    let mut partials = Vec::new();
    for entry in fs::read_dir(partials_dir).expect("partials").flatten() {
        let mut buf = String::new();
        if let Ok(mut f) = File::open(entry.path()) {
            let _ = f.read_to_string(&mut buf);
            if let Ok(bytes) = STANDARD.decode(buf.as_bytes())
                && let Ok(sig) = BlsPartialSig::decode(&bytes)
                && let Some(id) =
                    parse_id_from_filename(entry.file_name().to_string_lossy().as_ref())
            {
                partials.push((id, sig));
            }
        }
    }

    let pp = load_public(&pub_path).expect("public");
    let full = <BlsDkgScheme as ThresholdRelease>::combine(&pp, &tag, &partials).expect("combine");
    let out_b64 = STANDARD.encode(full.encode());
    let mut f = File::create(out_path).expect("out");
    let _ = f.write_all(out_b64.as_bytes());
}

fn cmd_public_merge(args: &[String]) {
    let root = get_path(args, "--root").unwrap_or_else(|| PathBuf::from("target"));
    let n = get_u32(args, "--n").unwrap_or(7);
    let out_path = get_path(args, "--out").unwrap_or_else(|| root.join("public.json"));

    let mut pk_shares = Vec::new();
    let mut transcript_hash = [0u8; 32];
    for id in 1..=n {
        let dir = party_dir(&root, id);
        let pp = load_public(&dir.join("public.json")).expect("public");
        if transcript_hash == [0u8; 32] {
            transcript_hash = pp.transcript_hash;
        }
        for (pid, pk_i) in pp.pk_shares {
            if !pk_shares.iter().any(|(x, _)| *x == pid) {
                pk_shares.push((pid, pk_i));
            }
        }
    }
    let pk = compute_pk_from_shares(&pk_shares).expect("compute pk");
    let merged = DkgPublicParams {
        pk: Some(pk),
        pk_shares,
        transcript_hash,
    };
    let json = serde_json::to_string_pretty(&PublicParamsJson {
        pk_b64: Some(STANDARD.encode(merged.pk.as_ref().expect("pk").encode())),
        pk_shares: merged
            .pk_shares
            .iter()
            .map(|(id, pk)| (*id, STANDARD.encode(pk.encode())))
            .collect(),
        transcript_hash_b64: STANDARD.encode(merged.transcript_hash),
    })
    .expect("json");
    let mut f = File::create(out_path).expect("out");
    let _ = f.write_all(json.as_bytes());
}

fn cmd_decrypt(args: &[String]) {
    let pub_path = get_path(args, "--pub").expect("--pub");
    let tag_b64 = get_str(args, "--tag").expect("--tag");
    let ct_path = get_path(args, "--ct").expect("--ct");
    let wit_path = get_path(args, "--witness").expect("--witness");
    let out_path = get_path(args, "--out").expect("--out");

    let pp = load_public(&pub_path).expect("public");
    let tag = BlsTag(decode_b64(&tag_b64).expect("tag"));

    let ct_b64 = read_string(&ct_path);
    let ct_bytes = STANDARD.decode(ct_b64.as_bytes()).expect("ct b64");
    let ct = BlsCiphertext::decode(&ct_bytes).expect("ct decode");

    let wit_b64 = read_string(&wit_path);
    let wit_bytes = STANDARD.decode(wit_b64.as_bytes()).expect("wit b64");
    let wit = BlsFullSig::decode(&wit_bytes).expect("wit decode");

    let pt = <BlsDkgScheme as ThresholdRelease>::decrypt(&pp, &tag, &ct, &wit).expect("decrypt");

    let mut f = File::create(out_path).expect("out");
    let _ = f.write_all(&pt.0);
}

fn read_string(path: &Path) -> String {
    let mut s = String::new();
    File::open(path)
        .expect("open")
        .read_to_string(&mut s)
        .unwrap();
    s
}

fn save_state(root: &Path, id: u32, state: &DkgState) -> Result<(), Error> {
    let dir = party_dir(root, id);
    fs::create_dir_all(&dir).map_err(|_| Error::InvalidEncoding)?;
    let snap = state.to_snapshot();
    let json = serde_json::to_string_pretty(&snap).map_err(|_| Error::InvalidEncoding)?;
    let mut f = File::create(dir.join("state.json")).map_err(|_| Error::InvalidEncoding)?;
    f.write_all(json.as_bytes())
        .map_err(|_| Error::InvalidEncoding)?;
    Ok(())
}

fn load_state(root: &Path, id: u32) -> Result<DkgState, Error> {
    let dir = party_dir(root, id);
    let json = read_string(&dir.join("state.json"));
    let snap: DkgSnapshot = serde_json::from_str(&json).map_err(|_| Error::InvalidEncoding)?;
    DkgState::from_snapshot(snap)
}

fn save_public(root: &Path, id: u32, pp: &DkgPublicParams) -> Result<(), Error> {
    let dir = party_dir(root, id);
    let pk_b64 = pp.pk.as_ref().map(|pk| STANDARD.encode(pk.encode()));
    let pk_shares = pp
        .pk_shares
        .iter()
        .map(|(id, pk)| (*id, STANDARD.encode(pk.encode())))
        .collect();
    let transcript_hash_b64 = STANDARD.encode(pp.transcript_hash);
    let json = serde_json::to_string_pretty(&PublicParamsJson {
        pk_b64,
        pk_shares,
        transcript_hash_b64,
    })
    .map_err(|_| Error::InvalidEncoding)?;
    let mut f = File::create(dir.join("public.json")).map_err(|_| Error::InvalidEncoding)?;
    f.write_all(json.as_bytes())
        .map_err(|_| Error::InvalidEncoding)?;
    Ok(())
}

fn save_secret(root: &Path, id: u32, sk: &DkgPartySecret) -> Result<(), Error> {
    let dir = party_dir(root, id);
    let json = serde_json::to_string_pretty(&PartySecretJson {
        id: sk.id,
        share_b64: STANDARD.encode(sk.share.to_bytes_be()),
    })
    .map_err(|_| Error::InvalidEncoding)?;
    let mut f = File::create(dir.join("secret.json")).map_err(|_| Error::InvalidEncoding)?;
    f.write_all(json.as_bytes())
        .map_err(|_| Error::InvalidEncoding)?;
    Ok(())
}

fn load_public(path: &Path) -> Result<DkgPublicParams, Error> {
    let json = read_string(path);
    let pp: PublicParamsJson = serde_json::from_str(&json).map_err(|_| Error::InvalidEncoding)?;
    let pk = if let Some(pk_b64) = pp.pk_b64.as_ref() {
        let pk_bytes = STANDARD
            .decode(pk_b64.as_bytes())
            .map_err(|_| Error::InvalidEncoding)?;
        Some(mempool_encryption::bls::g2_from_bytes(&pk_bytes)?)
    } else {
        None
    };
    let pk_shares = pp
        .pk_shares
        .iter()
        .map(|(id, pk_b64)| {
            let bytes = STANDARD
                .decode(pk_b64.as_bytes())
                .map_err(|_| Error::InvalidEncoding)?;
            let pk_i = mempool_encryption::bls::g2_from_bytes(&bytes)?;
            Ok((*id, pk_i))
        })
        .collect::<Result<_, Error>>()?;
    let th_bytes = STANDARD
        .decode(pp.transcript_hash_b64.as_bytes())
        .map_err(|_| Error::InvalidEncoding)?;
    if th_bytes.len() != 32 {
        return Err(Error::InvalidEncoding);
    }
    let mut th = [0u8; 32];
    th.copy_from_slice(&th_bytes);
    Ok(DkgPublicParams {
        pk,
        pk_shares,
        transcript_hash: th,
    })
}

fn load_secret(path: &Path) -> Result<DkgPartySecret, Error> {
    let json = read_string(path);
    let sk: PartySecretJson = serde_json::from_str(&json).map_err(|_| Error::InvalidEncoding)?;
    let bytes = STANDARD
        .decode(sk.share_b64.as_bytes())
        .map_err(|_| Error::InvalidEncoding)?;
    if bytes.len() != 32 {
        return Err(Error::InvalidEncoding);
    }
    let mut raw = [0u8; 32];
    raw.copy_from_slice(&bytes);
    let share = Option::<blstrs::Scalar>::from(blstrs::Scalar::from_bytes_be(&raw))
        .ok_or(Error::InvalidEncoding)?;
    Ok(DkgPartySecret { id: sk.id, share })
}

fn party_dir(root: &Path, id: u32) -> PathBuf {
    root.join(format!("party_{:02}", id))
}

fn write_outbox(root: &Path, from: u32, msgs: Vec<(u32, DkgMessage)>) -> Result<(), Error> {
    let outbox = party_dir(root, from).join("outbox");
    fs::create_dir_all(&outbox).map_err(|_| Error::InvalidEncoding)?;
    for (to, msg) in msgs {
        let wire = WireMessage {
            from,
            to,
            bytes_b64: STANDARD.encode(msg.encode()),
        };
        let json = serde_json::to_string(&wire).map_err(|_| Error::InvalidEncoding)?;
        let fname = outbox.join(format!("msg_{}_{}_{}.json", from, to, unique_id()));
        let mut f = File::create(fname).map_err(|_| Error::InvalidEncoding)?;
        f.write_all(json.as_bytes())
            .map_err(|_| Error::InvalidEncoding)?;
    }
    Ok(())
}

fn write_inbox(root: &Path, to: u32, msg: &WireMessage) -> Result<(), Error> {
    let inbox = party_dir(root, to).join("inbox");
    fs::create_dir_all(&inbox).map_err(|_| Error::InvalidEncoding)?;
    let fname = inbox.join(format!("msg_{}_{}_{}.json", msg.from, to, unique_id()));
    let json = serde_json::to_string(msg).map_err(|_| Error::InvalidEncoding)?;
    let mut f = File::create(fname).map_err(|_| Error::InvalidEncoding)?;
    f.write_all(json.as_bytes())
        .map_err(|_| Error::InvalidEncoding)?;
    append_server_log(root, &json)?;
    Ok(())
}

fn drain_inbox(root: &Path, me: u32) -> Result<Vec<(u32, DkgMessage)>, Error> {
    let inbox = party_dir(root, me).join("inbox");
    let mut out = Vec::new();
    let entries = match fs::read_dir(&inbox) {
        Ok(e) => e,
        Err(_) => return Ok(out),
    };
    for entry in entries.flatten() {
        let mut buf = String::new();
        if let Ok(mut f) = File::open(entry.path()) {
            let _ = f.read_to_string(&mut buf);
            if let Ok(wire) = serde_json::from_str::<WireMessage>(&buf)
                && let Ok(bytes) = STANDARD.decode(wire.bytes_b64.as_bytes())
                && let Ok(msg) = DkgMessage::decode(&bytes)
            {
                out.push((wire.from, msg));
            }
        }
        let _ = fs::remove_file(entry.path());
    }
    Ok(out)
}

fn parse_id_list(s: &str) -> Vec<u32> {
    s.split(',')
        .filter_map(|x| x.trim().parse::<u32>().ok())
        .collect()
}

fn parse_id_from_filename(name: &str) -> Option<u32> {
    let parts: Vec<&str> = name.split('_').collect();
    let raw = parts.get(1)?;
    let raw = raw.split('.').next().unwrap_or(raw);
    raw.parse::<u32>().ok()
}

fn get_u32(args: &[String], key: &str) -> Option<u32> {
    args.iter()
        .position(|a| a == key)
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse().ok())
}

fn get_str(args: &[String], key: &str) -> Option<String> {
    args.iter()
        .position(|a| a == key)
        .and_then(|i| args.get(i + 1))
        .map(|v| v.to_string())
}

fn get_path(args: &[String], key: &str) -> Option<PathBuf> {
    get_str(args, key).map(PathBuf::from)
}

fn decode_b64(s: &str) -> Result<Vec<u8>, Error> {
    STANDARD
        .decode(s.as_bytes())
        .map_err(|_| Error::InvalidEncoding)
}

fn unique_id() -> u128 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}

fn append_server_log(root: &Path, line: &str) -> Result<(), Error> {
    let server_dir = root.join("server");
    fs::create_dir_all(&server_dir).map_err(|_| Error::InvalidEncoding)?;
    let path = server_dir.join("server.log");
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|_| Error::InvalidEncoding)?;
    f.write_all(line.as_bytes())
        .map_err(|_| Error::InvalidEncoding)?;
    f.write_all(b"\n").map_err(|_| Error::InvalidEncoding)?;
    Ok(())
}
