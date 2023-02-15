use ic_cdk::{init, post_upgrade, pre_upgrade, query};
use ic_stable_memory::utils::DebuglessUnwrap;
use ic_stable_memory::{stable_memory_init, stable_memory_post_upgrade, stable_memory_pre_upgrade};

#[init]
fn init() {
    stable_memory_init();

    ic_stable_certified_assets::init();
}

#[pre_upgrade]
fn pre_upgrade() {
    ic_stable_certified_assets::pre_upgrade();

    stable_memory_pre_upgrade().debugless_unwrap();
}

#[post_upgrade]
fn post_upgrade() {
    stable_memory_post_upgrade();

    ic_stable_certified_assets::post_upgrade();
}
