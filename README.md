# spicy-noise

## Overview
This repository is a [Spicy](https://docs.zeek.org/projects/spicy/en/latest/index.html) protocol analyzer for [WireGuard](https://www.wireguard.com/protocol/).  The goal is to be able to identify and analyze WireGuard traffic at wire speed with [Zeek](https://zeek.org).  

The analyzer is based on WireGuard's [whitepaper](https://www.wireguard.com/papers/wireguard.pdf).


## Setup development environment
Spicy must be installed.  Reference the [Installation documents](https://docs.zeek.org/projects/spicy/en/latest/installation.html) for additional details on setup.

## Clone the repository

    git clone https://github.com/theparanoids/spicy-noise
    cd spicy-noise

## Zeek Integration
Zeek with the Spicy plugin install can load analyzers in two methods.  Just-In-Time (JIT) compilation will build the parser when Zeek is started.  Zeek can also load a precompiled parser, referred to as non-JIT.  Both methods require a .spicy file and a .evt file.

## JIT Usage
Zeek can perform just in time compilation of spicy parsers.  You can test this from the directory where the repository was downloaded.  Start Zeek and have it read in the wireguard-psk.pcap file and load the parser, event file,  and Spicy-Noise script.

    ./zeek -Cr traces/wireguard-psk.pcap spicy-noise.spicy spicy-noise.evt zeek/__load__.zeek

## non JIT Usage
Zeek can also load precompiled parsers.  Change to the directory containing Spicy and configure with this command.

### Build Compiled Parser

To build a compiled parser change into the repository's directory. Then use spicyz to create the compiled spicy-noise.hlto parser by specifying the .spicy and .evt files.

    spicyz -o spicy-noise.hlto spicy-noise.spicy spicy-noise.evt

### Build Zeek Plugin
Reference Spicy's Installation document and configure with the disable jit for zeek option.  Then make the zeek-plugin.
    
    ./configure --disable-jit-for-zeek
    make zeek-plugin
    make install

This will build the [Zeek plugin](https://docs.zeek.org/projects/spicy/en/latest/zeek.html?highlight=plugin#installation) found at <spicy_source_dir>/zeek/plugin/Zeek_Spicy.tgz.  Move the Zeek_Spicy.tgz archive to your monitoring platform.  Extract contents of the archive to <zeek_install_dir>/lib/zeek/plugins/Zeek_Spicy.  

Zeek must be built with Zeek support as defined in the documentation.

## Deploy Spicy Noise

Following the instructions above will install all of the requirements to deploy Spicy WireGuard parser.  Copy the contents of the zeek directory from the repository and the spicy-noise.hlto file just created to <zeek_install_dir>/share/zeek/site/spicy-noise.  Load the spicy-noise directory by adding the following line to your local.zeek file.

    @load spicy-noise

Add the following line to <zeek_install_dir>/share/zeek/site/spicy-noise/__load__.bro to instruct Zeek to use the spicy-noise.hlto parser.

    @load ./spicy-noise.hlto

Restart Zeek via zeekctl and deploy the new Spicy WireGuard parser. 

    zeekctl stop
    zeekctl install
    zeekctl check
    zeekctl deploy

Zeek will match packets on the monitored network to the dynamic protocol detection signature for WireGuard.  The streams will be forwarded and parsed by spicy-noise.hlto and raise events which are handled by wg.zeek.  Zeek will notate WireGuard traffic in conn.log with a service of wireguard.  A new spicy-noise.log will be created containing details of the protocol negotiation.

Sample of conn.log
    
    1533078876.827830	C7vNhD34zEBSPh6gh4	10.9.0.1	41255	10.9.0.2	51820	udp	wireguard	0.003753	148	92	SF	-	-	0	Dd	1	176	1	120	-
    1533079228.549600	CgCeXs3AQVNtWqtggj	10.9.0.2	51820	10.9.0.1	41255	udp	wireguard	0.005269	148	92	SF	-	-	0	Dd	1	176	1	120	-
    #close	2020-06-26-17-10-28

Sample of spicy-noise.log

    1533078876.827830	10.9.0.1	41255	10.9.0.2	51820	INITIATION	c1039c02	-	f30ceb67148dd27c78d52d0196b6b78b71542986f563ac898879353f022f1747	70c5b3d433cfb49fd3311688284ce67ec72111e655129fc5f6bed2e0a44b8d28c222c6e1479a0833c7a1f6417b733c1e	f049fab5e451aff561ea428c2116f7d1023ccdac2b2a00ecbe0273c9	-	-	-	f84b1c695032084b58e7d2ff9fcf19fd	00000000000000000000000000000000	-	-
    
    1533078876.831583	10.9.0.1	41255	10.9.0.2	51820	RESPONSE	dce3fa01	c1039c02	394ce1067faccdff74d71ddde6450ccedb94839008a7a2c0cdb0b4abe080565b	-	-	96d16752c32e60baabfb5413fba24276	-	-	beae31ece918c01700e5dfe66ca3c7b9	00000000000000000000000000000000	-	-
    
## Spicy-Noise Creator
  Jeff Atkinson.  

Please share your questions and suggestions by filing an issue on [Github](https://github.com/theparanoids/spicy-noise/issues). 
