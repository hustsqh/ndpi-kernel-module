/* 
 * xt_ndpi.h
 * Copyright (C) 2010-2012 G. Elian Gidoni
 *               2012 Ed Wildgoose
 *               2014 Humberto Jucá <betolj@gmail.com>
 * 
 * This file is part of nDPI, an open source deep packet inspection
 * library based on the PACE technology by ipoque GmbH
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2 of the License.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#ifndef _LINUX_NETFILTER_XT_NDPI_H
#define _LINUX_NETFILTER_XT_NDPI_H 1

#include <linux/netfilter.h>
#include "ndpi_main.h"

#ifndef NDPI_BITMASK_IS_ZERO
#define NDPI_BITMASK_IS_ZERO(a) NDPI_BITMASK_IS_EMPTY(a)
#endif

struct xt_ndpi_mtinfo {
        NDPI_PROTOCOL_BITMASK flags;
};

/* /usr/src/nDPI/src/include/ndpi_protocol_ids.h
 - protocols summ per line: 9, 23, 29, 37, 52, 63, 75, 90, 104, 114, 126, 135, 144, 156, 170, 185, 197, 208, 214
*/
#ifndef NDPI_PROTOCOL_LONG_STRING
#define NDPI_PROTOCOL_LONG_STRING "UNKNOWN","FTP_CONTROL","MAIL_POP","MAIL_SMTP","MAIL_IMAP","DNS","IPP","HTTP","MDNS","NTP","NETBIOS","NFS","SSDP","BGP",\
	"SNMP","XDMCP","SMBV1","SYSLOG","DHCP","POSTGRES","MYSQL","HOTMAIL","DIRECT_DOWNLOAD_LINK","MAIL_POPS","APPLEJUICE",\
	"DIRECTCONNECT","NTOP","COAP","VMWARE","MAIL_SMTPS","FBZERO","UBNTAC2","KONTIKI","OPENFT","FASTTRACK","GNUTELLA",\
	"EDONKEY","BITTORRENT","SKYPE_CALL","SIGNAL","MEMCACHED","SMBV23","MINING","NEST_LOG_SINK","MODBUS","WHATSAPP_VIDEO",\
	"DATASAVER","XBOX","QQ","TIKTOK","RTSP","MAIL_IMAPS","ICECAST","PPLIVE","PPSTREAM","ZATTOO","SHOUTCAST","SOPCAST",\
	"TVANTS","TVUPLAYER","HTTP_DOWNLOAD","QQLIVE","THUNDER","SOULSEEK","TLS_NO_CERT","IRC","AYIYA","UNENCRYPTED_JABBER",\
	"MSN","OSCAR","YAHOO","BATTLEFIELD","GOOGLE_PLUS","IP_VRRP","STEAM","HALFLIFE2","WORLDOFWARCRAFT","TELNET","STUN",\
	"IP_IPSEC","IP_GRE","IP_ICMP","IP_IGMP","IP_EGP","IP_SCTP","IP_OSPF","IP_IP_IN_IP","RTP","RDP","VNC","PCANYWHERE",\
	"TLS","SSH","USENET","MGCP","IAX","TFTP","AFP","STEALTHNET","AIMINI","SIP","TRUPHONE","IP_ICMPV6","DHCPV6",\
	"ARMAGETRON","CROSSFIRE","DOFUS","FIESTA","FLORENSIA","GUILDWARS","HTTP_ACTIVESYNC","KERBEROS","LDAP","MAPLESTORY",\
	"MSSQL_TDS","PPTP","WARCRAFT3","WORLD_OF_KUNG_FU","SLACK","FACEBOOK","TWITTER","DROPBOX","GMAIL","GOOGLE_MAPS",\
	"YOUTUBE","SKYPE","GOOGLE","DCERPC","NETFLOW","SFLOW","HTTP_CONNECT","HTTP_PROXY","CITRIX","NETFLIX","LASTFM",\
	"WAZE","YOUTUBE_UPLOAD","GENERIC","CHECKMK","AJP","APPLE","WEBEX","WHATSAPP","APPLE_ICLOUD","VIBER","APPLE_ITUNES",\
	"RADIUS","WINDOWS_UPDATE","TEAMVIEWER","TUENTI","LOTUS_NOTES","SAP","GTP","UPNP","LLMNR","REMOTE_SCAN","SPOTIFY",\
	"MESSENGER","H323","OPENVPN","NOE","CISCOVPN","TEAMSPEAK","TOR","SKINNY","RTCP","RSYNC","ORACLE","CORBA","UBUNTUONE",\
	"WHOIS_DAS","COLLECTD","SOCKS","NINTENDO","RTMP","FTP_DATA","WIKIPEDIA","ZMQ","AMAZON","EBAY","CNN","MEGACO","REDIS",\
	"PANDO","VHUA","TELEGRAM","VEVO","PANDORA","QUIC","WHATSAPP_VOICE","EAQ","OOKLA","AMQP","KAKAOTALK","KAKAOTALK_VOICE",\
	"TWITCH","DNS_OVER_HTTPS","WECHAT","MPEGTS","SNAPCHAT","SINA","HANGOUT_DUO","IFLIX","GITHUB","BJNP","LINE","FREE206",\
	"SMPP","DNSCRYPT","TINC","DEEZER","INSTAGRAM","MICROSOFT","STARCRAFT","TEREDO","HOTSPOT_SHIELD","HEP","GOOGLE_DRIVE",\
	"OCS","OFFICE_365","CLOUDFLARE","MS_ONE_DRIVE","MQTT","RX","APPLESTORE","OPENDNS","GIT","DRDA","PLAYSTORE","SOMEIP",\
	"FIX","PLAYSTATION","PASTEBIN","LINKEDIN","SOUNDCLOUD","CSGO","LISP","DIAMETER","APPLE_PUSH","GOOGLE_SERVICES",\
	"AMAZON_VIDEO","GOOGLE_DOCS","WHATSAPP_FILES"
#endif

#ifndef NDPI_PROTOCOL_SHORT_STRING
#define NDPI_PROTOCOL_SHORT_STRING "unknown","ftp_control","mail_pop","mail_smtp","mail_imap","dns","ipp","http","mdns","ntp","netbios","nfs","ssdp","bgp",\
	"snmp","xdmcp","smbv1","syslog","dhcp","postgres","mysql","hotmail","direct_download_link","mail_pops","applejuice",\
	"directconnect","ntop","coap","vmware","mail_smtps","fbzero","ubntac2","kontiki","openft","fasttrack","gnutella",\
	"edonkey","bittorrent","skype_call","signal","memcached","smbv23","mining","nest_log_sink","modbus","whatsapp_video",\
	"datasaver","xbox","qq","tiktok","rtsp","mail_imaps","icecast","pplive","ppstream","zattoo","shoutcast","sopcast",\
	"tvants","tvuplayer","http_download","qqlive","thunder","soulseek","tls_no_cert","irc","ayiya","unencrypted_jabber",\
	"msn","oscar","yahoo","battlefield","google_plus","ip_vrrp","steam","halflife2","worldofwarcraft","telnet","stun",\
	"ip_ipsec","ip_gre","ip_icmp","ip_igmp","ip_egp","ip_sctp","ip_ospf","ip_ip_in_ip","rtp","rdp","vnc","pcanywhere",\
	"tls","ssh","usenet","mgcp","iax","tftp","afp","stealthnet","aimini","sip","truphone","ip_icmpv6","dhcpv6",\
	"armagetron","crossfire","dofus","fiesta","florensia","guildwars","http_activesync","kerberos","ldap","maplestory",\
	"mssql_tds","pptp","warcraft3","world_of_kung_fu","slack","facebook","twitter","dropbox","gmail","google_maps",\
	"youtube","skype","google","dcerpc","netflow","sflow","http_connect","http_proxy","citrix","netflix","lastfm",\
	"waze","youtube_upload","generic","checkmk","ajp","apple","webex","whatsapp","apple_icloud","viber","apple_itunes",\
	"radius","windows_update","teamviewer","tuenti","lotus_notes","sap","gtp","upnp","llmnr","remote_scan","spotify",\
	"messenger","h323","openvpn","noe","ciscovpn","teamspeak","tor","skinny","rtcp","rsync","oracle","corba","ubuntuone",\
	"whois_das","collectd","socks","nintendo","rtmp","ftp_data","wikipedia","zmq","amazon","ebay","cnn","megaco","redis",\
	"pando","vhua","telegram","vevo","pandora","quic","whatsapp_voice","eaq","ookla","amqp","kakaotalk","kakaotalk_voice",\
	"twitch","dns_over_https","wechat","mpegts","snapchat","sina","hangout_duo","iflix","github","bjnp","line","free206",\
	"smpp","dnscrypt","tinc","deezer","instagram","microsoft","starcraft","teredo","hotspot_shield","hep","google_drive",\
	"ocs","office_365","cloudflare","ms_one_drive","mqtt","rx","applestore","opendns","git","drda","playstore","someip",\
	"fix","playstation","pastebin","linkedin","soundcloud","csgo","lisp","diameter","apple_push","google_services",\
	"amazon_video","google_docs","whatsapp_files"
#endif

#ifndef NDPI_LAST_NFPROTO
#define NDPI_LAST_NFPROTO NDPI_LAST_IMPLEMENTED_PROTOCOL + 1
#endif

#endif /* _LINUX_NETFILTER_XT_NDPI_H */
