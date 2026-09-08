pub type IPv4Addr = [u8; 4];

pub type IPv6Addr = [u8; 16];

pub struct IPv4Key {
    pub prefix: u32,
    pub addr: IPv4Addr,
}

pub struct IPv6Key {
    pub prefix: u32,
    pub addr: IPv6Addr,
}
