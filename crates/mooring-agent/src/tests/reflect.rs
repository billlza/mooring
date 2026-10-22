// SPDX-License-Identifier: GPL-3.0-or-later

//! The reflector on loopback: the peer's address and a newline, then close.

use std::io::Read;
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
use std::thread;

use crate::reflect::{MAX_CONNECTIONS, line, serve};

#[test]
fn the_line_is_the_address_and_a_newline() {
    assert_eq!(
        line(SocketAddrV4::new(Ipv4Addr::new(92, 40, 201, 97), 5)),
        "92.40.201.97\n"
    );
    assert_eq!(MAX_CONNECTIONS, 16);
}

#[test]
fn the_reflector_answers_each_connection_with_its_source() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    thread::spawn(move || serve(&listener));
    for _ in 0..3 {
        let mut stream = TcpStream::connect(address).unwrap();
        let mut answer = String::new();
        stream.read_to_string(&mut answer).unwrap();
        assert_eq!(answer, "127.0.0.1\n");
    }
}
