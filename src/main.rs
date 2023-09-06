use std::{
    io,
    net::{Ipv4Addr, SocketAddrV4},
    string::FromUtf8Error,
};

use derive_more::{Display, From};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, BufWriter},
    net::{TcpListener, TcpStream},
};
use tracing::Instrument;

#[tokio::main]
async fn main() -> io::Result<()> {
    tracing_subscriber::fmt().init();

    let addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 25565);

    let listener = TcpListener::bind(addr).await?;

    tracing::info!("listening on {}", addr);

    loop {
        let (stream, peer) = listener.accept().await?;

        let span = tracing::info_span!("conn", %peer);

        tokio::spawn(
            async move {
                if let Err(e) = on_connection(stream).await {
                    tracing::error!("{}", e);
                }
            }
            .instrument(span),
        );
    }
}

#[derive(Debug, Display, From)]
enum ConnectionError {
    #[display(fmt = "failed to read packet header: {}", _0)]
    ReadPacketHeader(ReadPacketHeaderError),
    #[display(fmt = "invalid connection state: {}", _0)]
    UnexpectedPacket(ConnectionState),
    #[display(fmt = "failed to process handshake packet: {}", _0)]
    Handshake(HandshakeError),
    #[display(fmt = "failed to process status request packet: {}", _0)]
    StatusRequest(StatusRequestError),
    #[display(fmt = "failed to process ping request packet: {}", _0)]
    PingRequest(PingRequestError),
}

#[derive(Copy, Clone, Debug, Display)]
enum ConnectionState {
    Handshaking,
    Status,
}

async fn on_connection(stream: TcpStream) -> Result<(), ConnectionError> {
    let (r, w) = stream.into_split();

    let mut r = BufReader::new(r);
    let mut w = BufWriter::new(w);

    let mut state = ConnectionState::Handshaking;

    loop {
        let header = read_packet_header(state, &mut r)
            .await
            .map_err(ConnectionError::from)?;

        let Some((_length, kind)) = header else {
            return Ok(());
        };

        tracing::info!("received packet: state={}, kind={}", state, kind);

        match kind {
            PacketKind::Handshake => {
                state = on_handshake(&mut r).await?;
            }
            PacketKind::StatusRequest => {
                on_status_request(&mut r, &mut w).await?;
            }
            PacketKind::PingRequest => {
                on_ping_request(&mut r, &mut w).await?;
            }
        }
    }
}

#[derive(Debug, Display)]
enum HandshakeError {
    #[display(fmt = "failed to read protocol version: {}", _0)]
    ReadProtocolVersion(ReadVarIntError),
    #[display(fmt = "failed to read server address: {}", _0)]
    ReadServerAddress(ReadStringError),
    #[display(fmt = "failed to read server port: {}", _0)]
    ReadServerPort(io::Error),
    #[display(fmt = "failed to read next state: {}", _0)]
    ReadNextState(io::Error),
    #[display(fmt = "invalid next state: {}", _0)]
    InvalidNextState(u8),
}

async fn on_handshake<R>(reader: &mut R) -> Result<ConnectionState, HandshakeError>
where
    R: AsyncRead + Unpin,
{
    let protocol_version = read_var_i32(reader)
        .await
        .map_err(|e| HandshakeError::ReadProtocolVersion(e))?;

    let server_address = read_string(255, reader)
        .await
        .map_err(|e| HandshakeError::ReadServerAddress(e))?;

    let server_port = reader
        .read_u16()
        .await
        .map_err(|e| HandshakeError::ReadServerPort(e))?;

    tracing::info!(protocol_version, server_address, server_port);

    let next_state = reader
        .read_u8()
        .await
        .map_err(|e| HandshakeError::ReadNextState(e))?;

    let connection_state = match next_state {
        1 => ConnectionState::Status,
        _ => {
            return Err(HandshakeError::InvalidNextState(next_state));
        }
    };

    Ok(connection_state)
}

#[cfg(test)]
mod on_handshake_spec {
    use assert_matches::assert_matches;

    use super::*;

    #[tokio::test]
    async fn err_when_no_protocol_version() {
        let mut reader = io::Cursor::new([]);

        assert_matches!(
            on_handshake(&mut reader).await,
            Err(HandshakeError::ReadProtocolVersion(_))
        );
    }

    #[tokio::test]
    async fn err_when_protocol_version_is_too_big() {
        let mut reader = io::Cursor::new([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f]);

        assert_matches!(
            on_handshake(&mut reader).await,
            Err(HandshakeError::ReadProtocolVersion(_))
        );
    }

    #[tokio::test]
    async fn err_when_no_server_address_string_length() {
        let mut reader = io::Cursor::new([0x1]);

        assert_matches!(
            on_handshake(&mut reader).await,
            Err(HandshakeError::ReadServerAddress(_))
        );
    }

    #[tokio::test]
    async fn err_when_server_address_string_length_is_too_big() {
        let mut reader =
            io::Cursor::new([0x1, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f]);

        assert_matches!(
            on_handshake(&mut reader).await,
            Err(HandshakeError::ReadServerAddress(_))
        );
    }

    #[tokio::test]
    async fn err_when_server_address_string_length_value_is_too_small() {
        let mut reader = io::Cursor::new([0x1, 0x0]);

        assert_matches!(
            on_handshake(&mut reader).await,
            Err(HandshakeError::ReadServerAddress(_))
        );
    }

    #[tokio::test]
    async fn err_when_server_address_string_length_value_is_too_big() {
        let mut reader = io::Cursor::new([0x1, 0xfd, 0x7]);

        assert_matches!(
            on_handshake(&mut reader).await,
            Err(HandshakeError::ReadServerAddress(_))
        );
    }

    #[tokio::test]
    async fn err_when_non_utf8_server_address() {
        let mut reader = io::Cursor::new([0x1, 0x4, 0, 159, 146, 150]);

        assert_matches!(
            on_handshake(&mut reader).await,
            Err(HandshakeError::ReadServerAddress(_))
        );
    }

    #[tokio::test]
    async fn err_when_no_server_port() {
        let mut reader = io::Cursor::new([0x1, 0x1, 49]);

        assert_matches!(
            on_handshake(&mut reader).await,
            Err(HandshakeError::ReadServerPort(_))
        );
    }

    #[tokio::test]
    async fn err_when_no_next_state() {
        let mut reader = io::Cursor::new([0x1, 0x1, 49, 0x63, 0xdd]);

        assert_matches!(
            on_handshake(&mut reader).await,
            Err(HandshakeError::ReadNextState(_))
        );
    }

    #[tokio::test]
    async fn err_when_unknown_next_state() {
        let mut reader = io::Cursor::new([0x1, 0x1, 49, 0x63, 0xdd, 0xea, 0x1]);

        assert_matches!(
            on_handshake(&mut reader).await,
            Err(HandshakeError::InvalidNextState(234))
        );
    }

    #[tokio::test]
    async fn ok_when_valid() {
        let mut reader = io::Cursor::new([0x1, 0x1, 49, 0x63, 0xdd, 0x1]);

        assert_matches!(on_handshake(&mut reader).await, Ok(ConnectionState::Status));
    }
}

#[derive(Debug, Display)]
enum PingRequestError {
    #[display(fmt = "failed to read payload: {}", _0)]
    ReadPayload(io::Error),
    #[display(fmt = "failed to write packet length: {}", _0)]
    WritePacketLength(WriteVarIntError),
    #[display(fmt = "failed to write packet id: {}", _0)]
    WritePacketId(io::Error),
    #[display(fmt = "failed to write payload: {}", _0)]
    WritePayload(io::Error),
    #[display(fmt = "failed to flush the writer: {}", _0)]
    Flush(io::Error),
}

async fn on_ping_request<R, W>(reader: &mut R, writer: &mut W) -> Result<(), PingRequestError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut payload = [0; std::mem::size_of::<i64>()];

    reader
        .read_exact(&mut payload)
        .await
        .map_err(|e| PingRequestError::ReadPayload(e))?;

    let Ok(length) = (payload.len() + 1).try_into() else {
        unreachable!("must fit in i32");
    };

    write_var_i32(length, writer)
        .await
        .map_err(|e| PingRequestError::WritePacketLength(e))?;

    writer
        .write_u8(0x1)
        .await
        .map_err(|e| PingRequestError::WritePacketId(e))?;

    writer
        .write_all(&payload)
        .await
        .map_err(|e| PingRequestError::WritePayload(e))?;

    writer
        .flush()
        .await
        .map_err(|e| PingRequestError::Flush(e))?;

    Ok(())
}

#[cfg(test)]
mod on_ping_request_spec {
    use assert_matches::assert_matches;

    use super::*;

    #[tokio::test]
    async fn err_when_no_payload() {
        let (mut reader, mut writer) = (io::Cursor::new([]), io::Cursor::new(Vec::new()));

        assert_matches!(
            on_ping_request(&mut reader, &mut writer).await,
            Err(PingRequestError::ReadPayload(_))
        );
    }

    #[tokio::test]
    async fn ok_when_valid() {
        let (mut reader, mut writer) = (io::Cursor::new([0; 8]), io::Cursor::new(vec![]));

        assert_matches!(on_ping_request(&mut reader, &mut writer).await, Ok(()));

        assert_eq!(
            writer.get_ref(),
            &[0x9, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
        );
    }
}

#[derive(Debug, Display)]
enum StatusRequestError {
    #[display(fmt = "failed to write packet length: {}", _0)]
    WritePacketLength(WriteVarIntError),
    #[display(fmt = "failed to write packet id: {}", _0)]
    WritePacketId(io::Error),
    #[display(fmt = "failed to write response bytes: {}", _0)]
    WriteResponse(io::Error),
    #[display(fmt = "failed to flush the writer: {}", _0)]
    Flush(io::Error),
}

async fn on_status_request<R, W>(_reader: &mut R, writer: &mut W) -> Result<(), StatusRequestError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    const RESPONSE: &str = include_str!("../response.json");

    let mut buf = io::Cursor::new(Vec::with_capacity(RESPONSE.len()));

    if let Err(_) = write_string(RESPONSE, &mut buf).await {
        unreachable!("must not fail");
    }

    let Ok(length) = (buf.get_ref().len() + 1).try_into() else {
        unreachable!("must fit in i32");
    };

    write_var_i32(length, writer)
        .await
        .map_err(|e| StatusRequestError::WritePacketLength(e))?;

    writer
        .write_u8(0x0)
        .await
        .map_err(|e| StatusRequestError::WritePacketId(e))?;

    writer
        .write_all(buf.get_ref())
        .await
        .map_err(|e| StatusRequestError::WriteResponse(e))?;

    writer
        .flush()
        .await
        .map_err(|e| StatusRequestError::Flush(e))?;

    Ok(())
}

#[derive(Debug, Display)]
enum ReadPacketHeaderError {
    #[display(fmt = "failed to read length: {}", _0)]
    ReadLength(ReadVarIntError),
    #[display(fmt = "failed to read id: {}", _0)]
    ReadId(ReadVarIntError),
    #[display(fmt = "invalid length: {}", _0)]
    InvalidLength(i32),
    #[display(fmt = "invalid id: {}", _0)]
    InvalidId(i32),
}

#[derive(Debug, Display)]
enum PacketKind {
    Handshake,
    StatusRequest,
    PingRequest,
}

async fn read_packet_header<R>(
    connection_state: ConnectionState,
    reader: &mut R,
) -> Result<Option<(usize, PacketKind)>, ReadPacketHeaderError>
where
    R: AsyncRead + Unpin,
{
    let length = match read_var_i32(reader).await {
        Ok(length) => length,
        Err(e) => {
            if let ReadVarIntError::Io(e) = &e {
                if e.kind() == io::ErrorKind::UnexpectedEof {
                    return Ok(None);
                }
            }

            return Err(ReadPacketHeaderError::ReadLength(e));
        }
    };

    if length < 1 || length > 2_097_151 {
        return Err(ReadPacketHeaderError::InvalidLength(length));
    }

    let Ok(length) = length.try_into() else {
        unreachable!("must fit in usize");
    };

    let id = read_var_i32(reader)
        .await
        .map_err(|e| ReadPacketHeaderError::ReadId(e))?;

    let kind = match (connection_state, id) {
        (ConnectionState::Handshaking, 0) => PacketKind::Handshake,
        (ConnectionState::Status, 0) => PacketKind::StatusRequest,
        (ConnectionState::Status, 1) => PacketKind::PingRequest,
        _ => return Err(ReadPacketHeaderError::InvalidId(id)),
    };

    Ok(Some((length, kind)))
}

#[cfg(test)]
mod read_packet_header_spec {
    use assert_matches::assert_matches;

    use super::*;

    #[tokio::test]
    async fn err_when_length_is_too_big() {
        let mut reader = io::Cursor::new([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f]);

        assert_matches!(
            read_packet_header(ConnectionState::Handshaking, &mut reader).await,
            Err(ReadPacketHeaderError::ReadLength(_))
        );
    }

    #[tokio::test]
    async fn err_when_no_id() {
        let mut reader = io::Cursor::new([0x1]);

        assert_matches!(
            read_packet_header(ConnectionState::Handshaking, &mut reader).await,
            Err(ReadPacketHeaderError::ReadId(_))
        );
    }

    #[tokio::test]
    async fn err_when_id_is_too_big() {
        let mut reader =
            io::Cursor::new([0x1, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f]);

        assert_matches!(
            read_packet_header(ConnectionState::Handshaking, &mut reader).await,
            Err(ReadPacketHeaderError::ReadId(_))
        );
    }

    #[tokio::test]
    async fn err_when_length_value_is_too_small() {
        let mut reader = io::Cursor::new([0x0]);

        assert_matches!(
            read_packet_header(ConnectionState::Handshaking, &mut reader).await,
            Err(ReadPacketHeaderError::InvalidLength(0))
        );
    }

    #[tokio::test]
    async fn err_when_length_value_is_too_big() {
        let mut reader = io::Cursor::new([0xff, 0xff, 0xff, 0xff, 0x07]);

        assert_matches!(
            read_packet_header(ConnectionState::Handshaking, &mut reader).await,
            Err(ReadPacketHeaderError::InvalidLength(2_147_483_647))
        );
    }

    #[tokio::test]
    async fn err_when_id_is_unknown() {
        let mut reader = io::Cursor::new([0x01, 0x1]);

        assert_matches!(
            read_packet_header(ConnectionState::Handshaking, &mut reader).await,
            Err(ReadPacketHeaderError::InvalidId(0x1))
        );
    }

    #[tokio::test]
    async fn ok_when_valid() {
        let mut reader = io::Cursor::new([0x01, 0x0]);

        assert_matches!(
            read_packet_header(ConnectionState::Handshaking, &mut reader).await,
            Ok(Some((1, PacketKind::Handshake)))
        );
    }

    #[tokio::test]
    async fn ok_when_eof() {
        let mut reader = io::Cursor::new([]);

        assert_matches!(
            read_packet_header(ConnectionState::Handshaking, &mut reader).await,
            Ok(None)
        );
    }
}

#[derive(Debug, Display, From)]
enum ReadVarIntError {
    #[display(fmt = "var int is too big")]
    TooBig,
    Io(io::Error),
}

async fn read_var_i32<R>(reader: &mut R) -> Result<i32, ReadVarIntError>
where
    R: AsyncRead + Unpin,
{
    const SEGMENT_BITS: i32 = 0x7F;
    const CONTINUE_BIT: i32 = 0x80;

    let mut value = 0;
    let mut position = 0;

    loop {
        let current_byte: i32 = reader
            .read_u8()
            .await
            .map_err(ReadVarIntError::from)?
            .into();

        value |= (current_byte & SEGMENT_BITS) << position;

        if current_byte & CONTINUE_BIT == 0 {
            return Ok(value);
        }

        position += 7;

        if position >= 32 {
            return Err(ReadVarIntError::TooBig);
        }
    }
}

#[cfg(test)]
mod read_var_i32_spec {
    use assert_matches::assert_matches;

    use super::*;

    #[tokio::test]
    async fn ok_when_zero() {
        let mut reader = io::Cursor::new([0x0]);

        assert_matches!(read_var_i32(&mut reader).await, Ok(0));
    }

    #[tokio::test]
    async fn ok_when_positive() {
        let mut reader = io::Cursor::new([
            0x01, 0x02, 0x7f, 0x80, 0x01, 0xff, 0x01, 0xdd, 0xc7, 0x01, 0xff, 0xff, 0x7f, 0xff,
            0xff, 0xff, 0xff, 0x07,
        ]);

        for i in [1, 2, 127, 128, 255, 25565, 2097151, 2147483647] {
            assert_matches!(read_var_i32(&mut reader).await, Ok(i));
        }
    }

    #[tokio::test]
    async fn ok_when_negative() {
        let mut reader =
            io::Cursor::new([0xff, 0xff, 0xff, 0xff, 0x0f, 0x80, 0x80, 0x80, 0x80, 0x08]);

        for i in [-1, -2147483648] {
            assert_matches!(read_var_i32(&mut reader).await, Ok(i));
        }
    }

    #[tokio::test]
    async fn err_when_empty() {
        let mut reader = io::Cursor::new([]);

        assert_matches!(read_var_i32(&mut reader).await, Err(ReadVarIntError::Io(_)));
    }

    #[tokio::test]
    async fn err_when_too_big() {
        let mut reader =
            io::Cursor::new([0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01]);

        assert_matches!(
            read_var_i32(&mut reader).await,
            Err(ReadVarIntError::TooBig)
        )
    }
}

#[derive(Debug, Display)]
enum WriteVarIntError {
    Io(io::Error),
}

async fn write_var_i32<W>(value: i32, writer: &mut W) -> Result<(), WriteVarIntError>
where
    W: AsyncWrite + Unpin,
{
    let mut value = value as u32;

    const SEGMENT_BITS: u32 = 0x7F;
    const CONTINUE_BIT: u32 = 0x80;

    loop {
        if (value & !SEGMENT_BITS) == 0 {
            return writer
                .write_u8(value as _)
                .await
                .map_err(|e| WriteVarIntError::Io(e));
        }

        writer
            .write_u8(((value & SEGMENT_BITS) | CONTINUE_BIT) as _)
            .await
            .map_err(|e| WriteVarIntError::Io(e))?;

        value >>= 7;
    }
}

#[cfg(test)]
mod write_var_i32_spec {
    use super::*;

    #[tokio::test]
    async fn ok_when_zero() {
        let mut writer = io::Cursor::new(Vec::new());

        write_var_i32(0, &mut writer).await.unwrap();

        assert_eq!(writer.get_ref(), &[0x0]);
    }

    #[tokio::test]
    async fn ok_when_positive() {
        let mut writer = io::Cursor::new(Vec::new());

        for i in [1, 2, 127, 128, 255, 25565, 2097151, 2147483647] {
            write_var_i32(i, &mut writer).await.unwrap();
        }

        assert_eq!(
            writer.get_ref(),
            &[
                0x01, 0x02, 0x7f, 0x80, 0x01, 0xff, 0x01, 0xdd, 0xc7, 0x01, 0xff, 0xff, 0x7f, 0xff,
                0xff, 0xff, 0xff, 0x07,
            ]
        )
    }

    #[tokio::test]
    async fn ok_when_negative() {
        let mut writer = io::Cursor::new(Vec::new());

        for i in [-1, -2147483648] {
            write_var_i32(i, &mut writer).await.unwrap();
        }

        assert_eq!(
            writer.get_ref(),
            &[0xff, 0xff, 0xff, 0xff, 0x0f, 0x80, 0x80, 0x80, 0x80, 0x08]
        )
    }
}

#[derive(Debug, Display)]
enum ReadStringError {
    #[display(fmt = "failed to read length: {}", _0)]
    ReadLength(ReadVarIntError),
    #[display(fmt = "failed to read string: {}", _0)]
    ReadString(io::Error),
    #[display(fmt = "invalid length: {}", _0)]
    InvalidLength(i32),
    #[display(fmt = "invalid string: {}", _0)]
    InvalidString(FromUtf8Error),
}

async fn read_string<R>(max_len: i32, reader: &mut R) -> Result<String, ReadStringError>
where
    R: AsyncRead + Unpin,
{
    let length = read_var_i32(reader)
        .await
        .map_err(|e| ReadStringError::ReadLength(e))?;

    if length < 1 || length > max_len * 4 {
        return Err(ReadStringError::InvalidLength(length));
    }

    let mut string = vec![0; length as usize];

    reader
        .read_exact(&mut string)
        .await
        .map_err(|e| ReadStringError::ReadString(e))?;

    String::from_utf8(string).map_err(|e| ReadStringError::InvalidString(e))
}

#[cfg(test)]
mod read_string_spec {
    use assert_matches::assert_matches;

    use super::*;

    #[tokio::test]
    async fn err_when_no_length() {
        let mut reader = io::Cursor::new([]);

        assert_matches!(
            read_string(255, &mut reader).await,
            Err(ReadStringError::ReadLength(_))
        );
    }

    #[tokio::test]
    async fn err_when_length_is_too_big() {
        let mut reader = io::Cursor::new([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f]);

        assert_matches!(
            read_string(255, &mut reader).await,
            Err(ReadStringError::ReadLength(_))
        );
    }

    #[tokio::test]
    async fn err_when_no_string() {
        let mut reader = io::Cursor::new([0x1]);

        assert_matches!(
            read_string(255, &mut reader).await,
            Err(ReadStringError::ReadString(_))
        );
    }

    #[tokio::test]
    async fn err_when_length_value_is_too_small() {
        let mut reader = io::Cursor::new([0x0]);

        assert_matches!(
            read_string(255, &mut reader).await,
            Err(ReadStringError::InvalidLength(0))
        );
    }

    #[tokio::test]
    async fn err_when_length_value_is_too_big() {
        let mut reader = io::Cursor::new([0xff, 0xff, 0xff, 0xff, 0x07]);

        assert_matches!(
            read_string(255, &mut reader).await,
            Err(ReadStringError::InvalidLength(2_147_483_647))
        );
    }

    #[tokio::test]
    async fn err_when_non_utf8_string() {
        let mut reader = io::Cursor::new([0x4, 0, 159, 146, 150]);

        assert_matches!(
            read_string(1, &mut reader).await,
            Err(ReadStringError::InvalidString(_))
        );
    }

    #[tokio::test]
    async fn ok_when_valid() {
        let mut reader = io::Cursor::new([0x3, 49, 50, 51]);

        let expected = "123".to_string();

        assert_matches!(read_string(3, &mut reader).await, Ok(expected));
    }
}

#[derive(Debug, Display)]
enum WriteStringError {
    #[display(fmt = "failed to write length: {}", _0)]
    WriteLength(WriteVarIntError),
    #[display(fmt = "failed to write string bytes: {}", _0)]
    WriteBytes(io::Error),
}

async fn write_string<W>(string: &str, writer: &mut W) -> Result<(), WriteStringError>
where
    W: AsyncWrite + Unpin,
{
    let Ok(length) = string.len().try_into() else {
        unreachable!("must fit in i32");
    };

    write_var_i32(length, writer)
        .await
        .map_err(|e| WriteStringError::WriteLength(e))?;

    writer
        .write_all(string.as_bytes())
        .await
        .map_err(|e| WriteStringError::WriteBytes(e))?;

    Ok(())
}

#[cfg(test)]
mod write_string_spec {
    use super::*;

    #[tokio::test]
    async fn ok_when_empty() {
        let mut writer = io::Cursor::new(Vec::new());

        write_string("", &mut writer).await.unwrap();

        assert_eq!(writer.get_ref(), &[0x0]);
    }

    #[tokio::test]
    async fn ok_when_not_empty() {
        let mut writer = io::Cursor::new(Vec::new());

        write_string("123", &mut writer).await.unwrap();

        assert_eq!(writer.get_ref(), &[0x3, 49, 50, 51]);
    }
}
