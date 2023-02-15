# Stable certified assets

This is a fork of [Dfinity's certified assets](https://github.com/dfinity/sdk/tree/master/src/canisters/frontend/ic-certified-assets) 
library, but with data structures replaced with their stable memory analogs 
from [ic-stable-memory](https://github.com/seniorjoinu/ic-stable-memory).

This library uses SCertifiedBTreeMap data collection, which is a Merkle tree stored completely in stable memory. This 
allows, easier than with the original implementation, to create canisters which simultaneously serve both: certified frontend 
and certified backend at the same time.

This is a reference implementation. Tests pass and it produces valid certificates on main-net, but don't use it for anything 
important, unless you know what you're doing.

## Deployment
Directory `example_project` contains certified assets canister, similar to [this one](https://github.com/dfinity/sdk/tree/master/src/canisters/frontend/ic-frontend-canister).
This canister appears to behave exactly like it's originator, but it stores all its data in stable memory, instead of heap.

In order to try this canister yourself:
1. `dfx start` in a separate terminal
2. `cd example_project`
3. `dfx deploy`
4. `icx-asset --pem ~/.config/dfx/identity/default/identity.pem sync <CANISTER ID> ./assets/`

This last step will upload every file from `example_project/assets` directory into the canister. If there is a file named
`index.html`, you can go to `http://127.0.0.1:4943/?canisterId=<CANISTER ID>` and see it is rendered in your browser.