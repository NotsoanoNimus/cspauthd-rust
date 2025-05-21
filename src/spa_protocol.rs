pub const PROTOCOL_VERSION: u32 = 0x_0000_1002;
pub const PACKET_BUFFER_SIZE: usize = 4096;


#[derive(Debug)]
#[repr(packed(1))]
pub struct CspauthUdpRequest {
    data:       [u8; 32],   /* can be random data or useful data, depending on action */
    username:   [u8; 16],
    timestamp:  u64,
    action:     u16,
    option:     u16,
    nonce:      u32,
    hash:       [u8; 32],   /* SHA256 hash over the prior fields above */
    auth_len:   u16,
    auth:       [u8; 3998]   /* can be a crypto sig or a hash */
}

#[derive(Debug)]
#[repr(packed(1))]
pub struct CspauthUdpResponse {
    server_version:     u32,
    response_code:      u16,
    reserved:           u16,
    timestamp:          u64,
    packet_id:          u64,
    data:               [u8; 232]
}

#[derive(Debug)]
#[repr(u16)]
pub enum CspauthResponseCode {
    Success                 = (1 << 0),
    InvalidUser             = (1 << 1),
    HashMismatch            = (1 << 2),
    InvalidReplay           = (1 << 3),
    InvalidAction           = (1 << 4),
    NotAuthorized           = (1 << 5),
    InvalidAuthentication   = (1 << 6),
    InvalidSignature        = (1 << 7),
    BadTimestamp            = (1 << 8),
}