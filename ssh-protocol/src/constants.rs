//! Constants defined in the SSH protocol

// https://www.rfc-editor.org/rfc/rfc4253#section-12
/// Message number for Disconnection Message
pub const SSH_MSG_DISCONNECT: u8 = 1;
/// Message number for Ignored Data Message
pub const SSH_MSG_IGNORE: u8 = 2;
/// Message number for Unrecognized Message
pub const SSH_MSG_UNIMPLEMENTED: u8 = 3;
/// Message number for Debug Message
pub const SSH_MSG_DEBUG: u8 = 4;
/// Message number for Service Request Message
pub const SSH_MSG_SERVICE_REQUEST: u8 = 5;
/// Message number for Service Accept Message
pub const SSH_MSG_SERVICE_ACCEPT: u8 = 6;
/// Message number for Algorithm Negociation Message
pub const SSH_MSG_KEXINIT: u8 = 20;
/// Message number for end of Key Exchange Message
pub const SSH_MSG_NEWKEYS: u8 = 21;

// https://datatracker.ietf.org/doc/html/rfc5656#section-7.1
/// Message number for ECDH Key Exchange initial message
pub const SSH_MSG_KEX_ECDH_INIT: u8 = 30;
/// Message number for ECDH Key Exchange reply message
pub const SSH_MSG_KEX_ECDH_REPLY: u8 = 31;

// https://datatracker.ietf.org/doc/html/rfc5656#section-7.2
/// Message number for ECMQV Key Exchange initial message
pub const SSH_MSG_KEX_ECMQV_INIT: u8 = 30;
/// Message number for ECMQV Key Exchange reply message
pub const SSH_MSG_KEX_ECMQV_REPLY: u8 = 31;

// https://www.rfc-editor.org/rfc/rfc4252#section-6
/// Message number for Authentication Request message
pub const SSH_MSG_USERAUTH_REQUEST: u8 = 50;
/// Message number for Authentication rejection message
pub const SSH_MSG_USERAUTH_FAILURE: u8 = 51;
/// Message number for Authentication success message
pub const SSH_MSG_USERAUTH_SUCCESS: u8 = 52;
/// Message number for Banner Message
pub const SSH_MSG_USERAUTH_BANNER: u8 = 53;
