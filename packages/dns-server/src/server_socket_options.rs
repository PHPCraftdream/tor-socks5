//! Read actual IPV6_V6ONLY without socket2's Windows short-write/uninit path.

use std::io;

pub(super) fn only_v6(socket: &socket2::SockRef<'_>) -> io::Result<bool> {
    #[cfg(windows)]
    {
        use std::os::windows::io::AsSocket;
        windows_only_v6(socket.as_socket())
    }
    #[cfg(not(windows))]
    {
        socket.only_v6()
    }
}

#[cfg(windows)]
fn windows_only_v6(socket: std::os::windows::io::BorrowedSocket<'_>) -> io::Result<bool> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{
        getsockopt, WSAGetLastError, IPPROTO_IPV6, IPV6_V6ONLY, SOCKET_ERROR,
    };

    let mut bytes = [0u8; 4];
    let mut len = 4i32;
    // SAFETY: BorrowedSocket keeps the live socket borrowed for this call. The
    // fixed IPPROTO_IPV6/IPV6_V6ONLY pair is valid; both output pointers refer to
    // exclusive live stack storage, with optlen giving its four-byte capacity.
    // The buffer is fully initialized, so short writes leave safe initialized
    // tails; decoding uses only the bytes covered by the returned length.
    // getsockopt borrows (does not retain/free) these buffers and reports bytes:
    // https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-getsockopt
    let result = unsafe {
        getsockopt(
            socket.as_raw_socket() as _,
            IPPROTO_IPV6,
            IPV6_V6ONLY,
            bytes.as_mut_ptr(),
            &mut len,
        )
    };
    if result == SOCKET_ERROR {
        // SAFETY: no pointer/initialization preconditions; capture this thread's
        // Winsock error immediately, before any other call can overwrite it:
        // https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-wsagetlasterror
        let error = unsafe { WSAGetLastError() };
        return Err(io::Error::from_raw_os_error(error));
    }
    decode_bool(bytes, len)
}

// Accept the observed one-byte provider result and the documented DWORD form.
// Reference: https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ipv6-socket-options
// Decode only returned bytes, never treat a malformed result as coverage.
#[cfg(any(windows, test))]
fn decode_bool(bytes: [u8; 4], len: i32) -> io::Result<bool> {
    match len {
        1 => Ok(bytes[0] != 0),
        4 => Ok(u32::from_ne_bytes(bytes) != 0),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid IPV6_V6ONLY result length (expected 1 or 4 bytes)",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::decode_bool;
    use std::io::ErrorKind;

    #[test]
    fn one_and_four_byte_zero_false_nonzero_true() {
        for value in [0u32, 1, 2, 255, 256, 0x8000_0000, u32::MAX] {
            assert_eq!(decode_bool(value.to_ne_bytes(), 4).unwrap(), value != 0);
        }
        for value in 0..=u8::MAX {
            // Non-returned tail bytes must not influence a one-byte result.
            for tail in [[0; 3], [255; 3]] {
                assert_eq!(
                    decode_bool([value, tail[0], tail[1], tail[2]], 1).unwrap(),
                    value != 0
                );
            }
        }
    }

    #[test]
    fn rejects_invalid_lengths() {
        for len in [i32::MIN, -1, 0, 2, 3, 5, i32::MAX] {
            assert_eq!(
                decode_bool([0; 4], len).unwrap_err().kind(),
                ErrorKind::InvalidData
            );
        }
    }
}
