/*
 * Network.cpp
 *
 *  Created on: 12 ott 2015
 *      Author: Stefano Ceccherini
 */

#include "NetworkInterface.h"
#include "Support.h"

#include <errno.h>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <stdexcept>
#include <unistd.h>

#include <arpa/inet.h>

#ifdef __linux__
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#endif

#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>

#include <sys/ioctl.h>

#include <iomanip>
#include <iostream>
#include <sstream>


static std::string
SpeedToString(struct ethtool_cmd* edata)
{
#ifdef __linux__
	int speed = ethtool_cmd_speed(edata);
	if (speed == -1)
		return "";
	return int_to_string(speed);
#else
	return "";
#endif
}


static std::string
SpeedToStringWithUnit(struct ethtool_cmd* edata)
{
	std::string result = "";
#ifdef __linux__
	int speed = ethtool_cmd_speed(edata);
	if (speed == -1)
		return "";

	std::string unit = "";
	std::string count = "";
	if (speed / 1000 >= 1) {
		unit = "Gb/s";
		count = int_to_string(speed / 1000);
	} else if (speed / 1 >= 1) {
		unit = "Mb/s";
		count = int_to_string(speed / 1);
	}

	if (count == "" && unit == "")
		return "";


	result.append(count).append(" ").append(unit);

#if 0
	// Seems that GLPI doesn't like if we add duplex info here
	std::string duplex = "";
	if (edata->duplex == DUPLEX_FULL)
		duplex = "Full Duplex";
	else if (edata->duplex == DUPLEX_HALF)
		duplex = "Half Duplex";
	
	if (duplex != "")
		result.append(" ").append(duplex);
#endif
#endif
	return result;
}


NetworkInterface::NetworkInterface()
{
}


NetworkInterface::NetworkInterface(const char* name)
	:
	fName(name)
{
	if (fName.size() > IFNAMSIZ)
		throw std::runtime_error("NetworkInterface::NetworkInterface(): Name too long");
}


NetworkInterface::~NetworkInterface()
{
}


std::string
NetworkInterface::Name() const
{
	return fName;
}


std::string
NetworkInterface::HardwareAddress() const
{
#ifdef __linux__
	struct ifreq ifr;
	if (_DoRequest(SIOCGIFHWADDR, ifr) != 0)
		return "";

	struct sockaddr* addr = reinterpret_cast<struct sockaddr*>(&ifr.ifr_hwaddr);
	std::ostringstream stream;
	for (size_t i = 0; i < ETHER_ADDR_LEN; i++) {
		int byte = addr->sa_data[i] & 0xFF;
		if (i != 0)
			stream << ":";
		stream << std::hex << std::setw(2) << std::setfill('0') << byte;
	}

	return stream.str();
#else
	return "";
#endif
}


bool
NetworkInterface::HasIPAddress() const
{
	std::string ip = IPAddress();
	if (ip.empty() || ip == "" || ip == "0.0.0.0")
		return false;
	return true;
}


std::string
NetworkInterface::IPAddress() const
{
	struct ifreq ifr;
	if (_DoRequest(SIOCGIFADDR, ifr) != 0)
		return "";

	struct sockaddr_in* ipaddr = reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr);
	return inet_ntoa(ipaddr->sin_addr);
}


std::string
NetworkInterface::NetMask() const
{
#ifdef __linux__
	struct ifreq ifr;
	if (_DoRequest(SIOCGIFNETMASK, ifr) != 0)
		return "";

	struct sockaddr_in* ipaddr = reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_netmask);
	return inet_ntoa(ipaddr->sin_addr);
#else
	return "";
#endif
}


std::string
NetworkInterface::Network() const
{
#ifdef __linux__
	struct ifreq ifrNetMask;
	if (_DoRequest(SIOCGIFNETMASK, ifrNetMask) != 0)
		return "";

	struct ifreq ifrIpAddress;
	if (_DoRequest(SIOCGIFADDR, ifrIpAddress) != 0)
		return "";

	struct sockaddr_in* ipAddr = reinterpret_cast<struct sockaddr_in*>(&ifrIpAddress.ifr_addr);
	struct sockaddr_in* netMask = reinterpret_cast<struct sockaddr_in*>(&ifrNetMask.ifr_netmask);

	struct in_addr networkAddress;
	::memset(&networkAddress, 0, sizeof(networkAddress));
	networkAddress.s_addr = ipAddr->sin_addr.s_addr & netMask->sin_addr.s_addr;

	return inet_ntoa(networkAddress);
#else
	return "";
#endif
}


std::string
NetworkInterface::BroadcastAddress() const
{
	struct ifreq ifr;
	if (_DoRequest(SIOCGIFBRDADDR, ifr) != 0)
		return "";

	struct sockaddr_in* ipaddr = reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_broadaddr);
	return inet_ntoa(ipaddr->sin_addr);
}


bool
NetworkInterface::HasDefaultGateway() const
{
	std::string gateway = DefaultGateway();
	if (gateway.empty() || gateway == "" || gateway == "0.0.0.0")
		return false;
	return true;
}


std::string
NetworkInterface::DefaultGateway() const
{
	std::list<route_info> routeInfo;
	if (_GetRoutes(routeInfo) != 0)
		return "";

	std::list<route_info>::const_iterator i;
	for (i = routeInfo.begin(); i != routeInfo.end(); i++) {
		if (i->dstAddr.s_addr == 0)
			return reinterpret_cast<char*>(inet_ntoa(i->gateway));
	}

	return "";
}


std::string
NetworkInterface::Type() const
{
	// TODO:
	return "Ethernet";
}



std::string
NetworkInterface::Speed() const
{
#ifdef __linux__
	struct ifreq ifr;
	struct ethtool_cmd edata;

	ifr.ifr_data = reinterpret_cast<char*>(&edata);

	edata.cmd = ETHTOOL_GSET;

	if (_DoRequest(SIOCETHTOOL, ifr) != 0)
		return "0";

	return SpeedToString(&edata);
#else
	return "";
#endif
}


std::string
NetworkInterface::SpeedWithUnit() const
{
#ifdef __linux__
	struct ifreq ifr;
	struct ethtool_cmd edata;

	ifr.ifr_data = reinterpret_cast<char*>(&edata);

	edata.cmd = ETHTOOL_GSET;

	if (_DoRequest(SIOCETHTOOL, ifr) != 0)
		return "0";

	return SpeedToStringWithUnit(&edata);
#else
	return "";
#endif
}


std::string
NetworkInterface::Status() const
{
	struct ifreq ifr;
	if (_DoRequest(SIOCGIFFLAGS, ifr) != 0)
		return "";

	return (ifr.ifr_flags & IFF_UP) ? "Up" : "Down";
}


bool
NetworkInterface::IsLoopback() const
{
	struct ifreq ifr;
	if (_DoRequest(SIOCGIFFLAGS, ifr) != 0)
		return "";

	return ifr.ifr_flags & IFF_LOOPBACK;
}


int
NetworkInterface::_DoRequest(int request, struct ifreq& ifr)  const
{
	size_t ifNameLen = fName.size();
	::memcpy(ifr.ifr_name, fName.c_str(), ifNameLen);
	ifr.ifr_name[ifNameLen] = 0;

	int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
	if (fd == -1)
		return errno;

	int status = 0;
	if (::ioctl(fd, request, &ifr) < 0)
		status = errno;

	::close(fd);

	return status;
}


#ifdef __linux__
const static int kBufSize = 8192;

static bool
ParseRoutes(struct nlmsghdr* nlHdr, route_info* rtInfo,
	const char* interfaceName)
{
	rtmsg* rtMsg = reinterpret_cast<rtmsg*>(NLMSG_DATA(nlHdr));

	// If the route is not for AF_INET or does not belong to main routing table then return.
	if ((rtMsg->rtm_family != AF_INET) || (rtMsg->rtm_table != RT_TABLE_MAIN))
		return false;

	int rtLen = RTM_PAYLOAD(nlHdr);
	for (rtattr* rtAttr = (rtattr*)RTM_RTA(rtMsg);
			RTA_OK(rtAttr, rtLen);
			rtAttr = RTA_NEXT(rtAttr, rtLen)) {
		switch (rtAttr->rta_type) {
			case RTA_OIF:
				if_indextoname(*(int*)RTA_DATA(rtAttr), rtInfo->ifName);
				break;
			case RTA_GATEWAY:
				rtInfo->gateway = *reinterpret_cast<in_addr*>(RTA_DATA(rtAttr));
				break;
			case RTA_PREFSRC:
				rtInfo->srcAddr = *reinterpret_cast<in_addr*>(RTA_DATA(rtAttr));
				break;
			case RTA_DST:
				rtInfo->dstAddr = *reinterpret_cast<in_addr*>(RTA_DATA(rtAttr));
				break;
			default:
				break;
		}
	}

	// If the route is for a different interface, return false
	// TODO: Check if we can filter the list beforehand
	return ::strcmp(interfaceName, rtInfo->ifName) == 0;
}


static int
ReadRouteInfoFromSocket(int sockFd, char *bufPtr, int seqNum, int pId)
{
	nlmsghdr* nlHdr = NULL;
	int msgLen = 0;
	do {
		// Receive response from the kernel
		int readLen = 0;
		if ((readLen = ::recv(sockFd, bufPtr, kBufSize - msgLen, 0)) < 0)
			return -1;

		nlHdr = (nlmsghdr*)bufPtr;

		// Check if the header is valid
		if ((NLMSG_OK(nlHdr, readLen) == (int)0) ||
				(nlHdr->nlmsg_type == NLMSG_ERROR)) {
			return -1;
		}

		// Check if the its the last message
		if (nlHdr->nlmsg_type == NLMSG_DONE) {
			break;
		} else {
			// Else move the pointer to buffer appropriately
			bufPtr += readLen;
			msgLen += readLen;
		}

		// Check if its a multi part message
		if ((nlHdr->nlmsg_flags & NLM_F_MULTI) == 0)
			break;
	} while(((int)nlHdr->nlmsg_seq != seqNum) || ((int)nlHdr->nlmsg_pid != pId));

	return msgLen;
}
#endif


int
NetworkInterface::_GetRoutes(std::list<route_info>& routeList) const
{
#ifdef __linux__
	int sock = 0;
	if ((sock = ::socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE)) < 0)
		return -1;

	char msgBuf[kBufSize];
	::memset(msgBuf, 0, kBufSize);
	struct nlmsghdr* nlMsg = reinterpret_cast<struct nlmsghdr*>(msgBuf);

	int msgSeq = 0;
	// Fill in the nlmsg header
	nlMsg->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	nlMsg->nlmsg_type = RTM_GETROUTE;
	nlMsg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
	nlMsg->nlmsg_seq = msgSeq++;
	nlMsg->nlmsg_pid = getpid();

	if (::send(sock, nlMsg, nlMsg->nlmsg_len, 0) < 0) {
		::close(sock);
		return -1;
	}

	// Read the response
	int len = 0;
	if ((len = ReadRouteInfoFromSocket(sock, msgBuf, msgSeq, getpid())) < 0) {
		::close(sock);
		return len;
	}

	// Parse and add to list
	for (; NLMSG_OK(nlMsg, len) != (int)0; nlMsg = NLMSG_NEXT(nlMsg, len)) {
		route_info rtInfo;
		memset(&rtInfo, 0, sizeof(rtInfo));
		if (ParseRoutes(nlMsg, &rtInfo, Name().c_str()))
			routeList.push_back(rtInfo);
	}

	::close(sock);
#endif
	// Success
	return 0;
}
