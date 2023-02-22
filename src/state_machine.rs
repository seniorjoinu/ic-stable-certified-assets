//! This module contains a pure implementation of the certified assets state machine.

// NB. This module should not depend on ic_cdk, it contains only pure state transition functions.
// All the environment (time, certificates, etc.) is passed to the state transition functions
// as formal arguments.  This approach makes it very easy to test the state machine.

use crate::{
    http::{
        HeaderField, HttpRequest, HttpResponse, StreamingCallbackHttpResponse,
        StreamingCallbackToken,
    },
    rc_bytes::RcBytes,
    types::*,
    url_decode::url_decode,
};
use candid::{CandidType, Deserialize, Func, Int, Nat, Principal};
use ic_stable_memory::collections::SCertifiedBTreeMap;
use ic_stable_memory::collections::SHashMap;
use ic_stable_memory::collections::SHashSet;
use ic_stable_memory::derive::{AsFixedSizeBytes, CandidAsDynSizeBytes, StableType};
use ic_stable_memory::primitive::s_ref::SRef;
use ic_stable_memory::utils::certification::{
    labeled, labeled_hash, leaf, AsHashTree, Hash, HashTree,
};
use ic_stable_memory::utils::certification::{leaf_hash, merge_hash_trees, AsHashableBytes};
use ic_stable_memory::utils::DebuglessUnwrap;
use ic_stable_memory::StableType;
use ic_stable_memory::{retrieve_custom_data, store_custom_data, SBox};
use num_traits::ToPrimitive;
use serde::Serialize;
use serde_bytes::ByteBuf;
use sha2::Digest;
use std::collections::HashMap;
use std::convert::TryInto;

/// The amount of time a batch is kept alive. Modifying the batch
/// delays the expiry further.
pub const BATCH_EXPIRY_NANOS: u64 = 300_000_000_000;

/// The order in which we pick encodings for certification.
const ENCODING_CERTIFICATION_ORDER: &[&str] = &["identity", "gzip", "compress", "deflate", "br"];

/// The file to serve if the requested file wasn't found.
const INDEX_FILE: &str = "/index.html";

/// Default aliasing behavior.
const DEFAULT_ALIAS_ENABLED: bool = true;

#[derive(
    Copy, Clone, Debug, Default, Ord, PartialOrd, Eq, PartialEq, AsFixedSizeBytes, StableType,
)]
struct WrappedHash(pub Hash);

impl AsHashTree for WrappedHash {
    fn root_hash(&self) -> Hash {
        leaf_hash(&self.0)
    }
    fn hash_tree(&self) -> HashTree {
        leaf(self.0.to_vec())
    }
}

type AssetHashes = SCertifiedBTreeMap<SBox<Key>, WrappedHash>;
type Timestamp = Int;

#[derive(Default, Clone, Debug, CandidType, Deserialize, CandidAsDynSizeBytes)]
pub struct AssetEncoding {
    pub modified: Timestamp,
    pub content_chunks: Vec<RcBytes>,
    pub total_length: usize,
    pub certified: bool,
    pub sha256: [u8; 32],
}

impl StableType for AssetEncoding {}

#[derive(Default, Clone, Debug, CandidType, Deserialize, CandidAsDynSizeBytes)]
pub struct Asset {
    pub content_type: String,
    pub encodings: HashMap<String, AssetEncoding>,
    pub max_age: Option<u64>,
    pub headers: Option<HashMap<String, String>>,
    pub is_aliased: Option<bool>,
    pub allow_raw_access: Option<bool>,
}

impl StableType for Asset {}

#[derive(Clone, Debug, CandidType, Deserialize, CandidAsDynSizeBytes, StableType)]
pub struct EncodedAsset {
    pub content: RcBytes,
    pub content_type: String,
    pub content_encoding: String,
    pub total_length: Nat,
    pub sha256: Option<ByteBuf>,
}

#[derive(Clone, Debug, CandidType, Deserialize, CandidAsDynSizeBytes)]
pub struct AssetDetails {
    pub key: String,
    pub content_type: String,
    pub encodings: Vec<AssetEncodingDetails>,
}

impl StableType for AssetDetails {}

#[derive(Clone, Debug, CandidType, Deserialize, CandidAsDynSizeBytes, StableType)]
pub struct AssetEncodingDetails {
    pub content_encoding: String,
    pub sha256: Option<ByteBuf>,
    pub length: Nat,
    pub modified: Timestamp,
}

#[derive(Clone, Debug, CandidType, Deserialize, CandidAsDynSizeBytes, StableType)]
pub struct CertifiedTree {
    pub certificate: Vec<u8>,
    pub tree: Vec<u8>,
}

#[derive(CandidType, Deserialize, CandidAsDynSizeBytes, StableType)]
pub struct Chunk {
    pub batch_id: BatchId,
    pub content: RcBytes,
}

#[derive(StableType, AsFixedSizeBytes)]
pub struct Batch {
    pub expires_at: Timestamp,
}

#[derive(Default, StableType, AsFixedSizeBytes)]
pub struct State {
    assets: SHashMap<SBox<Key>, SBox<Asset>>,

    chunks: SHashMap<ChunkId, SBox<Chunk>>,
    next_chunk_id: ChunkId,

    batches: SHashMap<BatchId, Batch>,
    next_batch_id: BatchId,

    authorized: SHashSet<Principal>,

    asset_hashes: AssetHashes,
}

impl Asset {
    fn allow_raw_access(&self) -> bool {
        self.allow_raw_access.unwrap_or(false)
    }
}

impl State {
    fn get_asset<'a>(&'a self, key: &Key) -> Result<SRef<'a, SBox<Asset>>, String> {
        let asset = self.assets.get(key);

        if let Some(a) = asset {
            return Ok(a);
        }

        let aliased = aliases_of(key)
            .into_iter()
            .find_map(|alias_key| self.assets.get(&alias_key));

        if let Some(a) = aliased {
            if a.is_aliased.unwrap_or(DEFAULT_ALIAS_ENABLED) {
                return Ok(a);
            }
        }

        Err("asset not found".to_string())
    }

    pub fn authorize_unconditionally(&mut self, principal: Principal) {
        self.authorized.insert(principal).debugless_unwrap();
    }

    pub fn deauthorize_unconditionally(&mut self, principal: Principal) {
        self.authorized.remove(&principal);
    }

    pub fn list_authorized(&self) -> Vec<Principal> {
        self.authorized.iter().map(|it| *it).collect()
    }

    pub fn take_ownership(&mut self, controller: Principal) {
        self.authorized.clear();
        self.authorized.insert(controller).debugless_unwrap();
    }

    pub fn root_hash(&self) -> Hash {
        labeled_hash(b"http_assets", &self.asset_hashes.root_hash())
    }

    pub fn create_asset(&mut self, arg: CreateAssetArguments) -> Result<(), String> {
        if let Some(asset) = self.assets.get(&arg.key) {
            if asset.content_type != arg.content_type {
                return Err("create_asset: content type mismatch".to_string());
            }
        } else {
            self.assets
                .insert(
                    SBox::new(arg.key).debugless_unwrap(),
                    SBox::new(Asset {
                        content_type: arg.content_type,
                        encodings: HashMap::new(),
                        max_age: arg.max_age,
                        headers: arg.headers,
                        is_aliased: arg.enable_aliasing,
                        allow_raw_access: arg.allow_raw_access,
                    })
                    .debugless_unwrap(),
                )
                .debugless_unwrap();
        }
        Ok(())
    }

    pub fn set_asset_content(
        &mut self,
        arg: SetAssetContentArguments,
        now: u64,
    ) -> Result<(), String> {
        if arg.chunk_ids.is_empty() {
            return Err("encoding must have at least one chunk".to_string());
        }

        let dependent_keys = self.dependent_keys(&arg.key);
        let mut asset_ref = self
            .assets
            .get_mut(&arg.key)
            .ok_or_else(|| "asset not found".to_string())?;

        let now = Int::from(now);

        let mut content_chunks = vec![];
        for chunk_id in arg.chunk_ids.iter() {
            let chunk = self.chunks.remove(chunk_id).expect("chunk not found");
            content_chunks.push(chunk.into_inner().content);
        }

        let sha256: [u8; 32] = match arg.sha256 {
            Some(bytes) => bytes
                .into_vec()
                .try_into()
                .map_err(|_| "invalid SHA-256".to_string())?,
            None => {
                let mut hasher = sha2::Sha256::new();
                for chunk in content_chunks.iter() {
                    hasher.update(chunk);
                }
                hasher.finalize().into()
            }
        };

        let total_length: usize = content_chunks.iter().map(|c| c.len()).sum();
        let enc = AssetEncoding {
            modified: now,
            content_chunks,
            certified: false,
            total_length,
            sha256,
        };

        asset_ref
            .with(|asset| {
                asset.encodings.insert(arg.content_encoding, enc);
                on_asset_change(&mut self.asset_hashes, &arg.key, asset, dependent_keys);
            })
            .unwrap();

        Ok(())
    }

    pub fn unset_asset_content(&mut self, arg: UnsetAssetContentArguments) -> Result<(), String> {
        let dependent_keys = self.dependent_keys(&arg.key);
        let mut asset_box_ref = self
            .assets
            .get_mut(&arg.key)
            .ok_or_else(|| "asset not found".to_string())?;

        asset_box_ref
            .with(|asset: &mut Asset| {
                if asset.encodings.remove(&arg.content_encoding).is_some() {
                    on_asset_change(&mut self.asset_hashes, &arg.key, asset, dependent_keys);
                }
            })
            .unwrap();

        Ok(())
    }

    pub fn delete_asset(&mut self, arg: DeleteAssetArguments) {
        for dependent in &self.dependent_keys(&arg.key) {
            self.asset_hashes.remove(dependent);
        }
        self.assets.remove(&arg.key);
        self.asset_hashes.remove(&arg.key);

        self.asset_hashes.commit();
    }

    pub fn clear(&mut self) {
        self.assets.clear();
        self.batches.clear();
        self.chunks.clear();
        self.next_batch_id = Nat::from(1);
        self.next_chunk_id = Nat::from(1);
    }

    pub fn is_authorized(&self, principal: &Principal) -> bool {
        self.authorized.contains(principal)
    }

    pub fn retrieve(&self, key: &Key) -> Result<RcBytes, String> {
        let asset = self.get_asset(key)?;

        let id_enc = asset
            .encodings
            .get("identity")
            .ok_or_else(|| "no identity encoding".to_string())?;

        if id_enc.content_chunks.len() > 1 {
            return Err("Asset too large. Use get() and get_chunk() instead.".to_string());
        }

        Ok(id_enc.content_chunks[0].clone())
    }

    pub fn store(&mut self, arg: StoreArg, time: u64) -> Result<(), String> {
        let dependent_keys = self.dependent_keys(&arg.key);

        if !self.assets.contains_key(&arg.key) {
            self.assets
                .insert(
                    SBox::new(arg.key.clone()).unwrap(),
                    SBox::new(Asset::default()).unwrap(),
                )
                .debugless_unwrap();
        }

        let mut asset_box = self.assets.get_mut(&arg.key).unwrap();

        asset_box
            .with(|asset: &mut Asset| {
                asset.content_type = arg.content_type;
                asset.is_aliased = arg.aliased;

                let hash = sha2::Sha256::digest(&arg.content).into();
                if let Some(provided_hash) = arg.sha256 {
                    if hash != provided_hash.as_ref() {
                        return Err("sha256 mismatch".to_string());
                    }
                }

                let encoding = asset.encodings.entry(arg.content_encoding).or_default();
                encoding.total_length = arg.content.len();
                encoding.content_chunks = vec![RcBytes::from(arg.content)];
                encoding.modified = Int::from(time);
                encoding.sha256 = hash;

                on_asset_change(&mut self.asset_hashes, &arg.key, asset, dependent_keys);

                Ok(())
            })
            .unwrap()?;

        Ok(())
    }

    pub fn create_batch(&mut self, now: u64) -> BatchId {
        let batch_id = self.next_batch_id.clone();
        self.next_batch_id += 1;

        self.batches
            .insert(
                batch_id.clone(),
                Batch {
                    expires_at: Int::from(now + BATCH_EXPIRY_NANOS),
                },
            )
            .debugless_unwrap();
        self.chunks.retain(|_, c| {
            self.batches
                .get(&c.batch_id)
                .map(|b| b.expires_at > now)
                .unwrap_or(false)
        });
        self.batches.retain(|_, b| b.expires_at > now);

        batch_id
    }

    pub fn create_chunk(&mut self, arg: CreateChunkArg, now: u64) -> Result<ChunkId, String> {
        let mut batch = self
            .batches
            .get_mut(&arg.batch_id)
            .ok_or_else(|| "batch not found".to_string())?;

        batch.expires_at = Int::from(now + BATCH_EXPIRY_NANOS);

        let chunk_id = self.next_chunk_id.clone();
        self.next_chunk_id += 1;

        self.chunks
            .insert(
                chunk_id.clone(),
                SBox::new(Chunk {
                    batch_id: arg.batch_id,
                    content: RcBytes::from(arg.content),
                })
                .debugless_unwrap(),
            )
            .debugless_unwrap();

        Ok(chunk_id)
    }

    pub fn commit_batch(&mut self, arg: CommitBatchArguments, now: u64) -> Result<(), String> {
        let batch_id = arg.batch_id;
        for op in arg.operations {
            match op {
                BatchOperation::CreateAsset(arg) => self.create_asset(arg)?,
                BatchOperation::SetAssetContent(arg) => self.set_asset_content(arg, now)?,
                BatchOperation::UnsetAssetContent(arg) => self.unset_asset_content(arg)?,
                BatchOperation::DeleteAsset(arg) => self.delete_asset(arg),
                BatchOperation::Clear(_) => self.clear(),
            }
        }
        self.batches.remove(&batch_id);
        Ok(())
    }

    pub fn list_assets(&self) -> Vec<AssetDetails> {
        self.assets
            .iter()
            .map(|(key_box_ref, asset_box_ref)| {
                let mut encodings: Vec<_> = asset_box_ref
                    .encodings
                    .iter()
                    .map(|(enc_name, enc)| AssetEncodingDetails {
                        content_encoding: enc_name.clone(),
                        sha256: Some(ByteBuf::from(enc.sha256)),
                        length: Nat::from(enc.total_length),
                        modified: enc.modified.clone(),
                    })
                    .collect();
                encodings.sort_by(|l, r| l.content_encoding.cmp(&r.content_encoding));

                AssetDetails {
                    key: key_box_ref.0.clone(),
                    content_type: asset_box_ref.content_type.clone(),
                    encodings,
                }
            })
            .collect::<Vec<_>>()
    }

    pub fn certified_tree(&self, certificate: &[u8]) -> CertifiedTree {
        // FIXME: This call may easily panic if the tree is big enough
        let hash_tree = labeled(b"http_assets".to_vec(), self.asset_hashes.hash_tree());

        let mut serializer = serde_cbor::ser::Serializer::new(vec![]);
        serializer.self_describe().unwrap();
        hash_tree.serialize(&mut serializer).unwrap();

        CertifiedTree {
            certificate: certificate.to_vec(),
            tree: serializer.into_inner(),
        }
    }

    pub fn get(&self, arg: GetArg) -> Result<EncodedAsset, String> {
        let asset = self.get_asset(&arg.key)?;

        for enc in arg.accept_encodings.iter() {
            if let Some(asset_enc) = asset.encodings.get(enc) {
                return Ok(EncodedAsset {
                    content: asset_enc.content_chunks[0].clone(),
                    content_type: asset.content_type.clone(),
                    content_encoding: enc.clone(),
                    total_length: Nat::from(asset_enc.total_length as u64),
                    sha256: Some(ByteBuf::from(asset_enc.sha256)),
                });
            }
        }
        Err("no such encoding".to_string())
    }

    pub fn get_chunk(&self, arg: GetChunkArg) -> Result<RcBytes, String> {
        let asset = self.get_asset(&arg.key)?;

        let enc = asset
            .encodings
            .get(&arg.content_encoding)
            .ok_or_else(|| "no such encoding".to_string())?;

        if let Some(expected_hash) = arg.sha256 {
            if expected_hash != enc.sha256 {
                return Err("sha256 mismatch".to_string());
            }
        }
        if arg.index >= enc.content_chunks.len() {
            return Err("chunk index out of bounds".to_string());
        }
        let index: usize = arg.index.0.to_usize().unwrap();

        Ok(enc.content_chunks[index].clone())
    }

    fn build_http_response(
        &self,
        certificate: &[u8],
        path: &str,
        encodings: Vec<String>,
        index: usize,
        callback: Func,
        etags: Vec<Hash>,
        req: HttpRequest,
    ) -> HttpResponse {
        let path_key = Key(path.into());
        let index_key = Key(INDEX_FILE.into());

        let index_redirect_certificate = if self.asset_hashes.get(&path_key).is_none()
            && self.asset_hashes.get(&index_key).is_some()
        {
            let absence_proof = self.asset_hashes.prove_absence(&path_key);
            let index_proof = self.asset_hashes.witness(&index_key);
            let combined_proof = merge_hash_trees(absence_proof, index_proof);
            Some(witness_to_header(combined_proof, certificate))
        } else {
            None
        };

        if let Some(certificate_header) = index_redirect_certificate {
            if let Some(asset) = self.assets.get(&index_key) {
                if !asset.allow_raw_access() && req.is_raw_domain() {
                    return req.redirect_from_raw_to_certified_domain();
                }
                for enc_name in encodings.iter() {
                    if let Some(enc) = asset.encodings.get(enc_name) {
                        if enc.certified {
                            return HttpResponse::build_ok(
                                &asset,
                                enc_name,
                                enc,
                                INDEX_FILE,
                                index,
                                Some(certificate_header),
                                callback,
                                etags,
                            );
                        }
                    }
                }
            }
        }

        let witness_or_absence_proof = if self.asset_hashes.contains_key(&path_key) {
            self.asset_hashes
                .witness_with(&path_key, |it| leaf(it.0.to_vec()))
        } else {
            self.asset_hashes.prove_absence(&path_key)
        };

        let certificate_header = witness_to_header(witness_or_absence_proof, certificate);

        if let Ok(asset) = self.get_asset(&path_key) {
            if !asset.allow_raw_access() && req.is_raw_domain() {
                return req.redirect_from_raw_to_certified_domain();
            }
            for enc_name in encodings.iter() {
                if let Some(enc) = asset.encodings.get(enc_name) {
                    if enc.certified {
                        return HttpResponse::build_ok(
                            &asset,
                            enc_name,
                            enc,
                            path,
                            index,
                            Some(certificate_header),
                            callback,
                            etags,
                        );
                    } else {
                        // Find if identity is certified, if it's not.
                        if let Some(id_enc) = asset.encodings.get("identity") {
                            if id_enc.certified {
                                return HttpResponse::build_ok(
                                    &asset,
                                    enc_name,
                                    enc,
                                    path,
                                    index,
                                    Some(certificate_header),
                                    callback,
                                    etags,
                                );
                            }
                        }
                    }
                }
            }
        }

        HttpResponse::build_404(certificate_header)
    }

    pub fn http_request(
        &self,
        req: HttpRequest,
        certificate: &[u8],
        callback: Func,
    ) -> HttpResponse {
        let mut encodings = vec![];
        // waiting for https://dfinity.atlassian.net/browse/BOUN-446
        let etags = Vec::new();
        for (name, value) in req.headers.iter() {
            if name.eq_ignore_ascii_case("Accept-Encoding") {
                for v in value.split(',') {
                    encodings.push(v.trim().to_string());
                }
            }
        }
        encodings.push("identity".to_string());

        let path = match req.url.find('?') {
            Some(i) => &req.url[..i],
            None => &req.url[..],
        };

        match url_decode(path) {
            Ok(path) => {
                self.build_http_response(certificate, &path, encodings, 0, callback, etags, req)
            }
            Err(err) => HttpResponse {
                status_code: 400,
                headers: vec![],
                body: RcBytes::from(ByteBuf::from(format!(
                    "failed to decode path '{path}': {err}"
                ))),
                streaming_strategy: None,
            },
        }
    }

    pub fn http_request_streaming_callback(
        &self,
        StreamingCallbackToken {
            key,
            content_encoding,
            index,
            sha256,
        }: StreamingCallbackToken,
    ) -> Result<StreamingCallbackHttpResponse, String> {
        let asset = self
            .get_asset(&Key(key.clone()))
            .map_err(|_| "Invalid token on streaming: key not found.".to_string())?;

        let enc = asset
            .encodings
            .get(&content_encoding)
            .ok_or_else(|| "Invalid token on streaming: encoding not found.".to_string())?;

        if let Some(expected_hash) = sha256 {
            if expected_hash != enc.sha256 {
                return Err("sha256 mismatch".to_string());
            }
        }

        // MAX is good enough. This means a chunk would be above 64-bits, which is impossible...
        let chunk_index = index.0.to_usize().unwrap_or(usize::MAX);

        Ok(StreamingCallbackHttpResponse {
            body: enc.content_chunks[chunk_index].clone(),
            token: StreamingCallbackToken::create_token(
                &content_encoding,
                enc.content_chunks.len(),
                enc.sha256,
                &key,
                chunk_index,
            ),
        })
    }

    pub fn get_asset_properties(&self, key: Key) -> Result<AssetProperties, String> {
        let asset = self
            .assets
            .get(&key)
            .ok_or_else(|| "asset not found".to_string())?;

        Ok(AssetProperties {
            max_age: asset.max_age,
            headers: asset.headers.clone(),
            allow_raw_access: asset.allow_raw_access,
        })
    }

    pub fn set_asset_properties(&mut self, arg: SetAssetPropertiesArguments) -> Result<(), String> {
        let mut asset_ref = self
            .assets
            .get_mut(&arg.key)
            .ok_or_else(|| "asset not found".to_string())?;

        asset_ref
            .with(|asset| {
                if let Some(headers) = arg.headers {
                    asset.headers = headers
                }
                if let Some(max_age) = arg.max_age {
                    asset.max_age = max_age
                }
                if let Some(allow_raw_access) = arg.allow_raw_access {
                    asset.allow_raw_access = allow_raw_access
                }
            })
            .debugless_unwrap();

        Ok(())
    }

    // Returns keys that needs to be updated if the supplied key is changed.
    fn dependent_keys(&self, key: &Key) -> Vec<Key> {
        if self
            .assets
            .get(key)
            .and_then(|asset| asset.is_aliased)
            .unwrap_or(DEFAULT_ALIAS_ENABLED)
        {
            aliased_by(key)
                .into_iter()
                .filter(|k| !self.assets.contains_key(k))
                .collect()
        } else {
            Vec::new()
        }
    }

    pub fn pre_upgrade(self) {
        store_custom_data(1, SBox::new(self).debugless_unwrap());
    }

    pub fn post_upgrade() -> Self {
        retrieve_custom_data::<State>(1).unwrap().into_inner()
    }
}

fn on_asset_change(
    asset_hashes: &mut AssetHashes,
    key: &Key,
    asset: &mut Asset,
    dependent_keys: Vec<Key>,
) {
    // If the most preferred encoding is present and certified,
    // there is nothing to do.
    for enc_name in ENCODING_CERTIFICATION_ORDER.iter() {
        if let Some(enc) = asset.encodings.get(*enc_name) {
            if enc.certified {
                return;
            } else {
                break;
            }
        }
    }

    if asset.encodings.is_empty() {
        asset_hashes.remove(key);

        for dependent in &dependent_keys {
            asset_hashes.remove(dependent);
        }
        asset_hashes.commit();

        return;
    }

    // An encoding with a higher priority was added, let's certify it
    // instead.

    for enc in asset.encodings.values_mut() {
        enc.certified = false;
    }

    for enc_name in ENCODING_CERTIFICATION_ORDER.iter() {
        if let Some(enc) = asset.encodings.get_mut(*enc_name) {
            asset_hashes
                .insert(SBox::new(key.clone()).unwrap(), WrappedHash(enc.sha256))
                .debugless_unwrap();

            for dependent in &dependent_keys {
                asset_hashes
                    .insert(
                        SBox::new(dependent.clone()).unwrap(),
                        WrappedHash(enc.sha256),
                    )
                    .debugless_unwrap();
            }
            enc.certified = true;
            asset_hashes.commit();

            return;
        }
    }

    // No known encodings found. Just pick the first one. The exact
    // order is hard to predict because we use a hash map. Should
    // almost never happen anyway.
    if let Some(enc) = asset.encodings.values_mut().next() {
        asset_hashes
            .insert(SBox::new(key.clone()).unwrap(), WrappedHash(enc.sha256))
            .debugless_unwrap();
        for dependent in &dependent_keys {
            asset_hashes
                .insert(
                    SBox::new(dependent.clone()).unwrap(),
                    WrappedHash(enc.sha256),
                )
                .debugless_unwrap();
        }
        enc.certified = true;

        asset_hashes.commit();
    }
}

fn witness_to_header(witness: HashTree, certificate: &[u8]) -> HeaderField {
    let hash_tree = labeled(b"http_assets".to_vec(), witness);
    let mut serializer = serde_cbor::ser::Serializer::new(vec![]);
    serializer.self_describe().unwrap();
    hash_tree.serialize(&mut serializer).unwrap();

    (
        "IC-Certificate".to_string(),
        String::from("certificate=:")
            + &base64::encode(certificate)
            + ":, tree=:"
            + &base64::encode(&serializer.into_inner())
            + ":",
    )
}

// path like /path/to/my/asset should also be valid for /path/to/my/asset.html or /path/to/my/asset/index.html
fn aliases_of(key: &Key) -> Vec<Key> {
    let str_key = &key.0;

    if str_key.ends_with('/') {
        vec![Key(format!("{str_key}index.html"))]
    } else if !str_key.ends_with(".html") {
        vec![
            Key(format!("{str_key}.html")),
            Key(format!("{str_key}/index.html")),
        ]
    } else {
        Vec::new()
    }
}

// Determines possible original keys in case the supplied key is being aliaseded to.
// Sort-of a reverse operation of `alias_of`
fn aliased_by(key: &Key) -> Vec<Key> {
    let str_key = &key.0;

    if str_key.ends_with("/index.html") {
        vec![
            Key(str_key[..(str_key.len() - 5)].into()),
            Key(str_key[..(str_key.len() - 10)].into()),
            Key(str_key[..(str_key.len() - 11)].into()),
        ]
    } else if str_key.ends_with(".html") {
        vec![Key(str_key[..(str_key.len() - 5)].into())]
    } else {
        Vec::new()
    }
}
