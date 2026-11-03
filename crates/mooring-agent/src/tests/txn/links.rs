// SPDX-License-Identifier: GPL-3.0-or-later

//! The links a swap replaces (design §11.2 step 4): Debian's own
//! `/etc/nftables.conf` kept once as `.pre-mooring`, and a link with no
//! parent directory refused.

use std::fs;
use std::path::Path;

use super::world::{World, idle, same};
use crate::txn;

#[test]
fn the_ruleset_the_node_had_before_mooring_is_kept_once() {
    let world = World::new();
    world.commit(&world.node(1000), world.bundle(1, same));
    let nft = world.paths.nft_conf_link();
    fs::remove_file(&nft).unwrap();
    fs::write(&nft, "#!/usr/sbin/nft -f\n# written later\n").unwrap();
    world.commit(&world.node(2000), world.bundle(2, idle(301)));
    assert_eq!(
        fs::read_link(&nft).unwrap(),
        Path::new("mooring/current/nftables.conf")
    );
    assert_eq!(
        fs::read_to_string(world.paths.at("/etc/nftables.conf.pre-mooring")).unwrap(),
        "#!/usr/sbin/nft -f\nflush ruleset\n"
    );
}

#[test]
fn a_link_without_a_parent_directory_is_refused() {
    assert_eq!(
        txn::links::replace_link(Path::new("/"), Path::new("gen-1"))
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::InvalidInput
    );
}
