#!/usr/bin/env zsh

function linebreak() {
	printf "\n"
}

#########################
# Define Some Variables #
#########################
SCRIPTROOT=$(pwd)
mkdir -p $SCRIPTROOT/scan
mkdir -p $SCRIPTROOT/scan/specific
SCANDIR=$SCRIPTROOT/scan

# Ask if this is a specific ip address scan
read -q "specific?Is This Scan For A Specific IP?:"
linebreak

if [[ $specific == 'y' ]]; then
	# Specific Scan
	read "IP?What is the IP Address?:"
	linebreak

	nmap --script=smb-vuln-ms17-010 -p 139,445,3389 -sV -Pn -vv -oN $SCANDIR/specific/$IP.log $IP
else
	# Range Scan
	read "IPRANGE1?First IP Range MAX (1-255):"
	read "IPRANGE2?Second IP Range MAX (1-255):"
	read "IPRANGE3?Third IP Range MAX (1-255):"
	read "IPRANGE4?Fourth IP Range MAX (1-255):"

	mkdir -p $SCANDIR/range
	mkdir -p $SCANDIR/range/${IPRANGE1}.${IPRANGE2}.${IPRANGE3}.${IPRANGE4}
	RANGEDIR=$SCANDIR/range/${IPRANGE1}.${IPRANGE2}.${IPRANGE3}.${IPRANGE4}
	cd $RANGEDIR
	IPLIST=({1..$IPRANGE1}.{1..$IPRANGE2}.{1..$IPRANGE3}.{1..$IPRANGE4})

	for ip in $IPLIST; do
		if [[ $ip == '1.1.1.1' ]]; then
			continue
		fi
		printf "WORKING ON: $ip\n\n"
		# Start the scan
		nmap --script=smb-vuln-ms17-010 -p 139,445,3389 -sV -Pn -vv -oN $ip.log $ip
	done
fi

# Host script results:
# smb-vuln-ms17-010:
# VULNERABLE:
# .....
# State: VULNERABLE
# IDs: CVE:CVE-2017-0143

# If any other port, just grep for the open ports
# grep -hnr "${PORT}/open/tcp" networkscan.log > open_ports.log