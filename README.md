# acme_digitalocean

## Name

acme_digitalocean - a CoreDNS plugin for automated tls certificates using digitalocean as dns provider

## Description

_acme_digitalocean_ is an alternative to the existing TLS plugin for CoreDNS, it can be used as a drop in replacement for the exisiting plugin and everything will continue to work.
What this plugin offers over the current builtin TLS plugin is the ability to generate and manage TLS certificates for you, so that you never have to worry about aquiring or renewing certificates,
all that will automatically be done for you.

This plugin uses Digitalocean as DNS provider to solve the acme DNS-01 challenge - meaning that you'll need to have a domain registered at digitalocean.

## Usage

First you need to compile CoreDNS with this plugin

```
# Clone CoreDNS
git clone https://github.com/coredns/coredns
cd coredns

# replace the original tls plugin with this tlsplus plugin
sed -i 's/tls:tls/tls:github.com\/mariuskimmina\/coredns-tlsplus/g' plugin.cfg

# Get the module
go get github.com/mariuskimmina/coredns-tlsplus


# Compile
make gen
make
```

Example Corefile

```
tls://.:5555 {
    debug
    tls acme {
        domain coredns-acme.xyz # replace with your domain
        email example@example.com # replace with your email
    }

    forward . tls://9.9.9.9 {
      tls_servername dns.quad9.net
    }
}
```

The env variable `DO_AUTH_TOKEN` is required.

```
DO_AUTH_TOKEN=xxxxxxxxx ./coredns
```
