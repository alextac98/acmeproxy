//! DNS-01 propagation resolution, deliberately independent of HTTP-01/system DNS.
use hickory_resolver::{
    TokioResolver,
    config::{NameServerConfig, ResolverConfig},
    name_server::TokioConnectionProvider,
    proto::xfer::Protocol,
};
use std::net::{IpAddr, SocketAddr};

fn resolver_config(addresses: &[IpAddr]) -> ResolverConfig {
    let mut config = ResolverConfig::new();
    for &ip in addresses {
        for protocol in [Protocol::Udp, Protocol::Tcp] {
            config.add_name_server(NameServerConfig::new(SocketAddr::new(ip, 53), protocol));
        }
    }
    config
}

pub(crate) fn propagation_resolver(addresses: &[IpAddr]) -> anyhow::Result<TokioResolver> {
    let mut builder = if addresses.is_empty() {
        TokioResolver::builder_tokio()?
    } else {
        TokioResolver::builder_with_config(
            resolver_config(addresses),
            TokioConnectionProvider::default(),
        )
    };
    // Do not cache positive or negative answers while a challenge propagates.
    builder.options_mut().cache_size = 0;
    Ok(builder.build())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn servers(config: &ResolverConfig) -> Vec<(SocketAddr, Protocol)> {
        config
            .name_servers()
            .iter()
            .map(|server| (server.socket_addr, server.protocol))
            .collect()
    }

    #[test]
    fn settings_default_and_round_trip() {
        for source in ["[server]", "[server]\ndns01_resolvers = []"] {
            let config: Config = toml::from_str(source).unwrap();
            assert!(config.server.dns01_resolvers.is_empty());
        }
        let config: Config =
            toml::from_str("[server]\ndns01_resolvers = [\"1.1.1.1\", \"2606:4700:4700::1111\"]")
                .unwrap();
        let saved = toml::to_string(&config).unwrap();
        let restored: Config = toml::from_str(&saved).unwrap();
        assert_eq!(
            config.server.dns01_resolvers,
            restored.server.dns01_resolvers
        );
    }

    #[test]
    fn settings_reject_invalid_resolvers() {
        for value in [
            "",
            "dns.example.com",
            "1.1.1.999",
            "1.1.1.1:53",
            "[::1]",
            "https://1.1.1.1",
        ] {
            let source = format!("[server]\ndns01_resolvers = [{value:?}]");
            assert!(toml::from_str::<Config>(&source).is_err(), "{value}");
        }
        assert!(toml::from_str::<Config>("[server]\ndns01_resolvers = \"1.1.1.1\"").is_err());
    }

    #[tokio::test]
    async fn explicit_resolvers_replace_system_servers_without_changing_system_lookup() {
        let ips = ["192.0.2.1".parse().unwrap(), "2001:db8::1".parse().unwrap()];
        let config = resolver_config(&ips);
        assert!(config.search().is_empty());
        assert_eq!(config.name_servers().len(), 4);
        for (servers, ip) in config.name_servers().as_chunks::<2>().0.iter().zip(ips) {
            assert_eq!(servers[0].socket_addr, SocketAddr::new(ip, 53));
            assert_eq!(servers[1].socket_addr, SocketAddr::new(ip, 53));
            assert_eq!(servers[0].protocol, Protocol::Udp);
            assert_eq!(servers[1].protocol, Protocol::Tcp);
        }
        let before: Vec<_> = tokio::net::lookup_host(("localhost", 80))
            .await
            .unwrap()
            .collect();
        let resolver = propagation_resolver(&ips).unwrap();
        assert_eq!(servers(resolver.config()), servers(&config));
        assert_eq!(resolver.options().cache_size, 0);
        let after: Vec<_> = tokio::net::lookup_host(("localhost", 80))
            .await
            .unwrap()
            .collect();
        assert_eq!(before, after);
        assert!(after.iter().all(|address| address.ip().is_loopback()));
    }

    #[tokio::test]
    async fn default_resolver_preserves_system_configuration_without_caching() {
        let resolver = propagation_resolver(&[]).unwrap();
        let system = TokioResolver::builder_tokio().unwrap().build();
        assert_eq!(servers(resolver.config()), servers(system.config()));
        assert_eq!(resolver.config().search(), system.config().search());
        assert_eq!(resolver.config().domain(), system.config().domain());
        assert_eq!(resolver.options().cache_size, 0);
    }
}
