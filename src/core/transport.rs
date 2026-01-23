// Copyright (c) 2026 Fastcomcorp, LLC. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Transport Layer Implementation
//!
//! This module provides transport abstraction for SIP message delivery
//! over UDP, TCP, and TLS protocols. Each transport type is handled
//! asynchronously with proper connection management.

use anyhow::Result;
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    sync::{mpsc, RwLock},
};
use tokio_rustls::TlsAcceptor;
use log::{debug, error, info};

/// Supported transport protocols for SIP
#[derive(Debug, Clone, Copy)]
pub enum TransportProtocol {
    /// User Datagram Protocol (RFC 3261)
    Udp,
    /// Transmission Control Protocol (RFC 3261)
    Tcp,
    /// Transport Layer Security (RFC 3261)
    Tls,
}

/// Message received from a transport listener
///
/// Contains the raw SIP message data, peer address, and optionally
/// a response channel for connection-oriented transports (TCP/TLS).
#[derive(Clone)]
pub struct TransportMessage {
    /// Raw SIP message bytes
    pub data: Vec<u8>,
    /// Peer socket address
    pub peer: SocketAddr,
    /// Response channel for TCP/TLS connections (None for UDP)
    pub response_tx: Option<mpsc::Sender<Vec<u8>>>,
}

#[derive(Clone)]
pub struct TransportListener {
    pub protocol: TransportProtocol,
    inbound: Arc<mpsc::Receiver<TransportMessage>>,
    udp_socket: Option<Arc<UdpSocket>>,
    tcp_connections: Arc<RwLock<HashMap<SocketAddr, mpsc::Sender<Vec<u8>>>>>,
}

impl TransportListener {
    pub async fn bind_udp(address: &SocketAddr) -> Result<Self> {
        let socket = UdpSocket::bind(address).await?;
        let socket = Arc::new(socket);
        let (sender, inbound) = mpsc::channel(1024);

        let recv_socket = socket.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                match recv_socket.recv_from(&mut buf).await {
                    Ok((len, peer)) => {
                        let msg = TransportMessage {
                            data: buf[..len].to_vec(),
                            peer,
                            response_tx: None,
                        };
                        if sender.send(msg).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        error!("UDP receive error: {}", e);
                        break;
                    }
                }
            }
        });

        info!("UDP listener bound to {}", address);

        Ok(TransportListener {
            protocol: TransportProtocol::Udp,
            inbound: Arc::new(inbound),
            udp_socket: Some(socket),
            tcp_connections: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub async fn bind_tcp(address: &SocketAddr) -> Result<Self> {
        let listener = TcpListener::bind(address).await?;
        let (sender, inbound) = mpsc::channel(1024);
        let connections = Arc::new(RwLock::new(HashMap::new()));

        let sender_clone = sender.clone();
        let connections_clone = connections.clone();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, peer)) => {
                        let sender = sender_clone.clone();
                        let connections = connections_clone.clone();
                        let (response_tx, mut response_rx) = mpsc::channel(16);
                        
                        connections.write().await.insert(peer, response_tx.clone());
                        
                        tokio::spawn(async move {
                            let (mut reader, mut writer) = stream.split();
                            let mut buf = vec![0u8; 4096];
                            
                            let read_task = tokio::spawn(async move {
                                loop {
                                    match reader.read(&mut buf).await {
                                        Ok(0) => break,
                                        Ok(len) => {
                                            let msg = TransportMessage {
                                                data: buf[..len].to_vec(),
                                                peer,
                                                response_tx: Some(response_tx.clone()),
                                            };
                                            if sender.send(msg).await.is_err() {
                                                break;
                                            }
                                        }
                                        Err(e) => {
                                            debug!("TCP read error from {}: {}", peer, e);
                                            break;
                                        }
                                    }
                                }
                                connections.write().await.remove(&peer);
                            });

                            let write_task = tokio::spawn(async move {
                                while let Some(data) = response_rx.recv().await {
                                    if writer.write_all(&data).await.is_err() {
                                        break;
                                    }
                                }
                            });

                            let _ = tokio::try_join!(read_task, write_task);
                        });
                    }
                    Err(e) => {
                        error!("TCP accept error: {}", e);
                        break;
                    }
                }
            }
        });

        info!("TCP listener bound to {}", address);

        Ok(TransportListener {
            protocol: TransportProtocol::Tcp,
            inbound: Arc::new(inbound),
            udp_socket: None,
            tcp_connections: connections,
        })
    }

    pub async fn bind_tls(
        address: &SocketAddr,
        tls_acceptor: Arc<TlsAcceptor>,
    ) -> Result<Self> {
        let listener = TcpListener::bind(address).await?;
        let (sender, inbound) = mpsc::channel(1024);
        let connections = Arc::new(RwLock::new(HashMap::new()));

        let sender_clone = sender.clone();
        let connections_clone = connections.clone();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, peer)) => {
                        let sender = sender_clone.clone();
                        let connections = connections_clone.clone();
                        let tls_acceptor = tls_acceptor.clone();
                        let (response_tx, mut response_rx) = mpsc::channel(16);
                        
                        tokio::spawn(async move {
                            match tls_acceptor.accept(stream).await {
                                Ok(tls_stream) => {
                                    connections.write().await.insert(peer, response_tx.clone());
                                    
                                    let (mut reader, mut writer) = tokio::io::split(tls_stream);
                                    let mut buf = vec![0u8; 4096];
                                    
                                    let read_task = tokio::spawn(async move {
                                        loop {
                                            match reader.read(&mut buf).await {
                                                Ok(0) => break,
                                                Ok(len) => {
                                                    let msg = TransportMessage {
                                                        data: buf[..len].to_vec(),
                                                        peer,
                                                        response_tx: Some(response_tx.clone()),
                                                    };
                                                    if sender.send(msg).await.is_err() {
                                                        break;
                                                    }
                                                }
                                                Err(e) => {
                                                    debug!("TLS read error from {}: {}", peer, e);
                                                    break;
                                                }
                                            }
                                        }
                                        connections.write().await.remove(&peer);
                                    });

                                    let write_task = tokio::spawn(async move {
                                        while let Some(data) = response_rx.recv().await {
                                            if writer.write_all(&data).await.is_err() {
                                                break;
                                            }
                                        }
                                    });

                                    let _ = tokio::try_join!(read_task, write_task);
                                }
                                Err(e) => {
                                    error!("TLS handshake error from {}: {}", peer, e);
                                }
                            }
                        });
                    }
                    Err(e) => {
                        error!("TLS accept error: {}", e);
                        break;
                    }
                }
            }
        });

        info!("TLS listener bound to {}", address);

        Ok(TransportListener {
            protocol: TransportProtocol::Tls,
            inbound,
            udp_socket: None,
            tcp_connections: connections,
        })
    }

    pub async fn recv(&self) -> Option<TransportMessage> {
        self.inbound.as_ref().recv().await
    }

    pub async fn send(&self, data: &[u8], peer: SocketAddr) -> Result<()> {
        match self.protocol {
            TransportProtocol::Udp => {
                if let Some(socket) = &self.udp_socket {
                    socket.send_to(data, peer).await?;
                    Ok(())
                } else {
                    Err(anyhow::anyhow!("UDP socket not available"))
                }
            }
            TransportProtocol::Tcp | TransportProtocol::Tls => {
                let connections = self.tcp_connections.read().await;
                if let Some(tx) = connections.get(&peer) {
                    tx.send(data.to_vec()).await
                        .map_err(|e| anyhow::anyhow!("Failed to send TCP/TLS response: {}", e))?;
                    Ok(())
                } else {
                    Err(anyhow::anyhow!("No connection found for peer {}", peer))
                }
            }
        }
    }
}
