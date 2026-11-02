use ptrs::ClientTransport;
use tokio::{io::DuplexStream, net::TcpStream};
use webtunnel::{PrefixStream, WebTunnelClient, WebTunnelStream};

#[test]
fn supplied_carrier_output_can_be_named_by_consumers() {
    type Output = <WebTunnelClient as ClientTransport<DuplexStream, std::io::Error>>::OutRW;
    let _: fn(Output) -> PrefixStream<WebTunnelStream<DuplexStream>> = |stream| stream;
}

#[test]
fn tcp_output_keeps_the_default_stream_type() {
    type Output = <WebTunnelClient as ClientTransport<TcpStream, std::io::Error>>::OutRW;
    let _: fn(Output) -> PrefixStream<WebTunnelStream> = |stream| stream;
}
