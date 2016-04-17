/*
* The MIT License(MIT)
* Copyright(c) 2016 Lorenzo Delana, https://searchathing.com
*
* Permission is hereby granted, free of charge, to any person obtaining a
* copy of this software and associated documentation files (the "Software"),
* to deal in the Software without restriction, including without limitation
* the rights to use, copy, modify, merge, publish, distribute, sublicense,
* and/or sell copies of the Software, and to permit persons to whom the
* Software is furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in
* all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
* FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
* DEALINGS IN THE SOFTWARE.
*/

#include <limits.h>
#include <MemoryFree\MemoryFree.h>

#include <SearchAThing.Arduino.Utils\Util.h>
#include <SearchAThing.Arduino.Utils\BufferInfo.h>
#include <SearchAThing.Arduino.Utils\IdStorage.h>
#include <SearchAThing.Arduino.Utils\RamData.h>
#include <SearchAThing.Arduino.Utils\SList.h>
using namespace SearchAThing::Arduino;

#include <SearchAThing.Arduino.Net\Protocol.h>
#include <SearchAThing.Arduino.Net\Checksum.h>
#include <SearchAThing.Arduino.Net\IPEndPoint.h>
using namespace SearchAThing::Arduino::Net;

#define PASSED 0
#define FAILED 1

int testsDoneCount = 0;
int failedCount = 0;

void EvalTest(int(*fn)(), const char *testName)
{
	auto testResult = fn();
	failedCount += testResult;

	if (testResult == FAILED)
		DPrint(F("* Failed\t"));
	else
		DPrint(F("Ok\t"));
	DPrintln(testName);

	++testsDoneCount;
}


//===========================================================================
// module		: SearchAThing.Ardino.Utils
//===========================================================================

//---------------------------------------------------------------------------
// namespace	: SearchAThing::Arduino
// fn			: FreeMemoryMaxBlock

int TestFreeMemoryMaxBlock()
{
	auto f = FreeMemoryMaxBlock() -
		sizeof(void *); // the ptr below

	void *ptr = malloc(f);
	if (ptr == NULL) return FAILED;
	free(ptr);

	ptr = malloc(f + 16);
	if (ptr != NULL) { free(ptr); return FAILED; }

	return PASSED;
}

//---------------------------------------------------------------------------
// namespace	: SearchAThing::Arduino
// fn			: TimeDiff

int TestTimeDiff()
{
	if (TimeDiff(0, ULONG_MAX) != ULONG_MAX) return FAILED;
	if (TimeDiff(ULONG_MAX, 0) != 1) return FAILED;
	if (TimeDiff(ULONG_MAX - 100, 99) != 200) return FAILED;

	return PASSED;
}

//---------------------------------------------------------------------------
// namespace	: SearchAThing::Arduino
// fn			: BufWrite16

int TestBufWrite16()
{
	byte b[3];

	BufWrite16(b, 0x0020);
	if (b[0] != 0x00) return FAILED;
	if (b[1] != 0x20) return FAILED;

	BufWrite16(b, 0x1e20);
	if (b[0] != 0x1e) return FAILED;
	if (b[1] != 0x20) return FAILED;

	return PASSED;
}

//---------------------------------------------------------------------------
// namespace	: SearchAThing::Arduino
// fn			: BufWrite32

int TestBufWrite32()
{
	byte b[5];

	BufWrite32(b, 0x00000020);
	if (b[0] != 0x00) return FAILED;
	if (b[1] != 0x00) return FAILED;
	if (b[2] != 0x00) return FAILED;
	if (b[3] != 0x20) return FAILED;

	BufWrite32(b, 0x00001a20);
	if (b[0] != 0x00) return FAILED;
	if (b[1] != 0x00) return FAILED;
	if (b[2] != 0x1a) return FAILED;
	if (b[3] != 0x20) return FAILED;

	BufWrite32(b, 0x00e01a20);
	if (b[0] != 0x00) return FAILED;
	if (b[1] != 0xe0) return FAILED;
	if (b[2] != 0x1a) return FAILED;
	if (b[3] != 0x20) return FAILED;

	BufWrite32(b, 0xfae01a20);
	if (b[0] != 0xfa) return FAILED;
	if (b[1] != 0xe0) return FAILED;
	if (b[2] != 0x1a) return FAILED;
	if (b[3] != 0x20) return FAILED;

	return PASSED;
}

//---------------------------------------------------------------------------
// namespace	: SearchAThing::Arduino
// fn			: BufReadUInt16_t

int TestBufReadUInt16_t()
{
	byte b[] =
	{
		0x1a,
		0x24
	};

	if (BufReadUInt16_t(b) != 0x1a24) return FAILED;

	return PASSED;
}

//---------------------------------------------------------------------------
// namespace	: SearchAThing::Arduino
// fn			: BufReadUInt32_t

int TestBufReadUInt32_t()
{
	byte b[] =
	{
		0xfe,
		0x35,
		0x1a,
		0x24
	};

	if (BufReadUInt32_t(b) != 0xfe351a24) return FAILED;

	return PASSED;
}

//---------------------------------------------------------------------------
// namespace	: SearchAThing::Arduino
// class		: BufferInfo

int TestBufferInfo()
{
	// checks memory allocation behavior
	auto mem = freeMemory();
	{
		byte buf[] = { 10, 20, 30 };
		auto b = BufferInfo(buf, sizeof(buf));
	}
	{
		BufferInfo a;

		byte *buf = new byte[10];
		BufferInfo b(buf, 10);
		if (b.Length() != 10) return FAILED; // checks if initial length equals capacity
		b.SetLength(5);

		a = b; // default copy-value

		if (a.Buf() != buf) return FAILED;
		if (a.Length() != 5) return FAILED;
		if (a.Capacity() != 10) return FAILED;

		delete buf;
	}
	// memory after the function back the original size
	if (freeMemory() != mem) return FAILED;

	return PASSED;
}

//---------------------------------------------------------------------------
// namespace	: SearchAThing::Arduino
// class		: IdStorage

// tests alloc,release ids and comprehensive object memory consistency
int TestIdStorage()
{
	int mem = freeMemory();
	{
		IdStorage cc;
		{
			IdStorage ids(100);// = new IdStorage(100);
			for (int i = 0; i < 20; ++i)
			{
				auto x = ids.Allocate();
				if (x != 100 + i) return FAILED;
			}
			ids.Release(108); // bit-0 of byte-1
			ids.Release(115); // bit-7 of byte-1
			ids.Release(116); // bit-0 of byte-2	
			if (ids.Allocate() != 108) return FAILED;
			if (ids.Allocate() != 115) return FAILED;
			if (ids.Allocate() != 116) return FAILED;

			cc = ids;
		} // ids deallocated		

		if (cc.Allocate() != 120) return FAILED;

		{
			auto a = cc;
			IdStorage b;
			b = a;

			if (cc.Allocate() != 121) return FAILED;
			if (a.Allocate() != 121) return FAILED;
			if (b.Allocate() != 121) return FAILED;
		}

		{
			IdStorage k(1);
			bool failed;
			auto cnt = 8UL + freeMemory() * 8;
			for (uint32_t i = 0L; i < cnt; ++i)
			{
				k.Allocate(&failed);
				if (failed) break;
			}
			if (!failed) return FAILED;
		}
	} // cc deallocated
	if (mem != freeMemory()) return FAILED;

	return PASSED;
}

//---------------------------------------------------------------------------
// namespace	: SearchAThing::Arduino
// class		: RamData

// states that RamData release memory at destruct time and that consumed memory equals to Size() + sizeof(byte *)
int TestRamData()
{
	int mem = freeMemory();
	{
		RamData cc;
		{
			auto data = RamData(100);
			for (int i = 0; i < data.Size(); ++i) data.Buf()[i] = i;
			cc = data;
		} // data deallocated

		{
			for (int i = 0; i < cc.Size(); ++i)
			{
				if (cc.Buf()[i] != i) return FAILED;
			}
		}

		RamData ooo(8192);
		if (ooo.Size() != 0) return FAILED;

		{
			auto a = cc;
			RamData b;
			b = a;

			for (int i = 0; i < cc.Size(); ++i)
			{
				if (cc.Buf()[i] != i) return FAILED;
				if (a.Buf()[i] != i) return FAILED;
				if (b.Buf()[i] != i) return FAILED;
			}

			RamData s("test str");
		}
	} // cc deallocated	

	{
		RamData K;

		uint16_t size = (freeMemory() / 2) - 200;
		for (int y = 0; y < 1; ++y)
		{
			K = RamData(size);

			byte b = y;
			for (int i = 0; i < K.Size(); ++i) K.Buf()[i] = b++;

			b = y;
			for (int i = 0; i < K.Size(); ++i) { if (K.Buf()[i] != b++) return false; }
		}
	}

	{
		RamData s("test123");

		if (!s.Equals(F("test123"))) return FAILED;
	}

	{
		auto ip = RamData::FromArray(IPV4_IPSIZE, 8, 8, 8, 8);		
		auto netmask = RamData::FromArray(IPV4_IPSIZE, 255, 255, 255, 0);
		auto network = RamData::FromArray(IPV4_IPSIZE, 192, 168, 0, 0);

		if (ip.And(netmask).Equals(network)) return FAILED;
	}

	if (freeMemory() != mem) {
		DPrint("mem leak:"); DPrintln(mem - freeMemory());
		return FAILED;
	}

	return PASSED;
}

//---------------------------------------------------------------------------
// namespace	: SearchAThing::Arduino
// class		: SList

class ItemCls
{
public:
	ItemCls() { }
	ItemCls(int v) { value = v; }
	int value;
};

// test slink using ptr as data type
int _TestSList(int phase)
{
	int mem = freeMemory();
	{
		SList<ItemCls> cc;

		{
			SList<ItemCls> slist;

			if (slist.Size() != 0) return FAILED;
			slist.Add(ItemCls(10));
			slist.Add(ItemCls(20));
			slist.Add(ItemCls(30));
			if (slist.Size() != 3) return FAILED;

			if (slist.Get(0).value != 10) return FAILED;
			if (slist.Get(1).value != 20) return FAILED;
			if (slist.Get(2).value != 30) return FAILED;

			// remove first
			if (phase == 0)
			{
				slist.Remove(0);
				if (slist.Size() != 2) return FAILED;
				if (slist.Get(0).value != 20) return FAILED;
				if (slist.Get(1).value != 30) return FAILED;
			}
			else if (phase == 1)
			{
				// remove middle			
				slist.Remove(1);
				if (slist.Size() != 2) return FAILED;
				if (slist.Get(0).value != 10) return FAILED;
				if (slist.Get(1).value != 30) return FAILED;
			}
			else if (phase == 2)
			{
				// remove last			
				slist.Remove(2);
				if (slist.Size() != 2) return FAILED;
				if (slist.Get(0).value != 10) return FAILED;
				if (slist.Get(1).value != 20) return FAILED;
			}
			else if (phase == 3)
			{
				slist.Remove(1);
				if (slist.Size() != 2) return FAILED;
				slist.Add(40);
				if (slist.Size() != 3) return FAILED;
				if (slist.Get(0).value != 10) return FAILED;
				if (slist.Get(1).value != 30) return FAILED;
				if (slist.Get(2).value != 40) return FAILED;

				cc = slist;
			}
			else if (phase == 4)
			{
				slist.Get(0).value = 11; // ref value
				if (slist.Get(0).value != 11) return FAILED;

				slist.Add(ItemCls(21)).value = 22; // ref value
				if (slist.Get(slist.Size() - 1).value != 22) return FAILED;

				slist.Clear();
				if (slist.Size() != 0) return FAILED;
			}
		} // slist deallocated

		if (phase == 3)
		{
			if (cc.Size() != 3) return FAILED;
			if (cc.Get(0).value != 10) return FAILED;
			if (cc.Get(1).value != 30) return FAILED;
			if (cc.Get(2).value != 40) return FAILED;

			{
				auto a = cc;
				SList<ItemCls> b;
				b = a;

				if (cc.Size() != 3) return FAILED;
				if (cc.Get(0).value != 10) return FAILED;
				if (cc.Get(1).value != 30) return FAILED;
				if (cc.Get(2).value != 40) return FAILED;
				cc.Clear();

				if (a.Size() != 3) return FAILED;
				if (a.Get(0).value != 10) return FAILED;
				if (a.Get(1).value != 30) return FAILED;
				if (a.Get(2).value != 40) return FAILED;
				a.Clear();

				if (b.Size() != 3) return FAILED;
				if (b.Get(0).value != 10) return FAILED;
				if (b.Get(1).value != 30) return FAILED;
				if (b.Get(2).value != 40) return FAILED;
			}
		}
	} // cc deallocated

	  //if (mem != freeMemory()) return FAILED;

	return PASSED;
}

int TestSList()
{
	if (_TestSList(0) == FAILED) return FAILED;
	if (_TestSList(1) == FAILED) return FAILED;
	if (_TestSList(2) == FAILED) return FAILED;
	if (_TestSList(3) == FAILED) return FAILED;
	if (_TestSList(4) == FAILED) return FAILED;

	return PASSED;
}

//===========================================================================
// module		: SearchAThing.Ardino.Net
//===========================================================================

//---------------------------------------------------------------------------
// namespace	: SearchAThing::Arduino::Net
// class		: IPEndPoint

int TestIPEndPoint()
{
	if (!IPEndPoint(RamData::FromArray(IPV4_IPSIZE, 192, 168, 0, 80), 50000).Equals(
		IPEndPoint(RamData::FromArray(IPV4_IPSIZE, 192, 168, 0, 80), 50000)))
		return FAILED;

	if (IPEndPoint(RamData::FromArray(IPV4_IPSIZE, 192, 168, 0, 80), 50000).Equals(
		IPEndPoint(RamData::FromArray(IPV4_IPSIZE, 192, 168, 0, 80), 50001)))
		return FAILED;

	return PASSED;
}

//---------------------------------------------------------------------------
// namespace	: SearchAThing::Arduino::Net
// struct		: Eth2Header

int TestEth2Header()
{
	byte bytes[] =
	{
		0x00,0x15,0x5d,0x37,0x92,0x65,0x40,0x16,0x7e,0x47,0x35,0x85,0x08,0x00
	};

	byte dstMac[] = { 0x00,0x15,0x5d,0x37,0x92,0x65 };
	byte srcMac[] = { 0x40,0x16,0x7e,0x47,0x35,0x85 };

	auto eth2 = Eth2GetHeader(bytes);
	if ((byte *)eth2 != bytes) return FAILED;
	if (memcmp(eth2->dstMAC, dstMac, IPV4_MACSIZE) != 0) return FAILED;
	if (memcmp(eth2->srcMAC, srcMac, IPV4_MACSIZE) != 0) return FAILED;
	if (Eth2GetType(eth2) != Eth2Type::Eth2Type_IP) return FAILED;

	return PASSED;
}

//---------------------------------------------------------------------------
// namespace	: SearchAThing::Arduino::Net
// struct		: ARPHeader

int TestARPHeader()
{
	byte bytes[] =
	{
		0x00,0x01,0x08,0x00,0x06,0x04,0x00,0x01,0x40,0x16,0x7e,0x47,0x35,0x85,0xc0,0xa8,
		0x00,0x51,0x00,0x15,0x5d,0x37,0x92,0x65,0xc0,0xa8,0x00,0x01
	};

	byte srcMAC[] = { 0x40,0x16,0x7e,0x47,0x35,0x85 };
	byte srcIP[] = { 0xc0,0xa8,0x00,0x51 };
	byte dstMAC[] = { 0x00,0x15,0x5d,0x37,0x92,0x65 };
	byte dstIP[] = { 0xc0,0xa8,0x00,0x01 };

	auto arp = (ARPHeader *)bytes;
	if (BufReadUInt16_t(arp->hwType) != ARPType::ARPType_Ethernet) return FAILED;
	if (BufReadUInt16_t(arp->protoType) != ARPProtocolType::ARPProtocolType_IP) return FAILED;
	if (arp->hwAddrLength != IPV4_MACSIZE) return FAILED;
	if (arp->protoAddrLength != IPV4_IPSIZE) return FAILED;
	if (BufReadUInt16_t(arp->opCode) != ARPOpcodeType::ARPOpCodeType_Request) return FAILED;

	if (memcmp(ARPSourceHardwareAddress(arp), srcMAC, IPV4_MACSIZE) != 0) return FAILED;
	if (memcmp(ARPSourceProtocolAddress(arp), srcIP, IPV4_IPSIZE) != 0) return FAILED;
	if (memcmp(ARPDestinationHardwareAddress(arp), dstMAC, IPV4_MACSIZE) != 0) return FAILED;
	if (memcmp(ARPDestinationProtocolAddress(arp), dstIP, IPV4_IPSIZE) != 0) return FAILED;

	if (ARPSize(arp) != sizeof(ARPHeader) + 2 * arp->hwAddrLength + 2 * arp->protoAddrLength) return FAILED;

	return PASSED;
}

//---------------------------------------------------------------------------
// namespace	: SearchAThing::Arduino::Net
// fn			: Checksum

int TestChecksum()
{
	{
		byte buf[] =
		{
			0x45, 0x00, 0x00, 0x28, 0x2e, 0x27, 0x40, 0x00, 0x80, 0x06,
			0x00, 0x00, 0xc0, 0xa8, 0x00, 0x64, 0x6c, 0xa8, 0x97, 0x06
		};
		if (CheckSum(buf, sizeof(buf)) != 0x07ee) return FAILED;

		{
			uint32_t pchksum = 0;
			pchksum = CheckSumPartial(pchksum, buf, 10);
			pchksum = CheckSumPartial(pchksum, buf + 10, 10);
			if (CheckSumFinalize(pchksum) != 0x07ee) return FAILED;
		}
	}

	{
		byte buf[] = { 0x00 };
		if (CheckSum(buf, sizeof(buf)) != 0xffff) return FAILED;
	}

	{
		byte buf[] = { 0x00, 0xff };
		if (CheckSum(buf, sizeof(buf)) != 0xff00) return FAILED;
	}

	{
		byte buf[] = { 0xff };
		if (CheckSum(buf, sizeof(buf)) != 0xff) return FAILED;
	}

	{
		byte ipv4Bytes[] =
		{
			0x45,0x00,0x00,0x1f,0x45,0x00,0x00,0x00,0x80,0x11,0x74,0x05,0xc0,0xa8,0x00,0x28,
			0xc0,0xa8,0x00,0x50
		};

		byte udpBytes[] =
		{
			0xc0,0x00,0xc3,0x50,0x00,0x0b,0x78,0xbe,
			0x02,0x00,0x80,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
		};

		auto ipv4 = (IPv4Header *)ipv4Bytes;
		auto udp = (UDPHeader *)udpBytes;

		UDPWriteValidChecksum(ipv4, udp);
		if (BufReadUInt16_t(udp->chksum) != 0x78bd) return FAILED;
	}

	return PASSED;
}

//---------------------------------------------------------------------------
// namespace	: SearchAThing::Arduino::Net
// struct		: IPv4Header

int TestIPv4HeaderWChecksum()
{
	byte bytes[] =
	{
		0x45,0x00,0x00,0x3c,0x08,0xf4,0x00,0x00,0x80,0x01,0xb0,0x04,0xc0,0xa8,0x00,0x28,
		0xc0,0xa8,0x00,0x50
	};

	byte srcIP[] = { 192, 168, 0, 40 };
	byte dstIP[] = { 192, 168, 0, 80 };

	auto ipv4 = (IPv4Header *)bytes;
	if (ipv4->version != 4) return FAILED;
	if (ipv4->ihl != sizeof(IPv4Header) / 4) return FAILED;
	if (ipv4->services != 0) return FAILED;
	if (BufReadUInt16_t(ipv4->totalLength) != 60) return FAILED;
	if (BufReadUInt16_t(ipv4->identification) != 0x08f4) return FAILED;
	if (ipv4->flags != 0) return FAILED;
	if (ipv4->ttl != 128) return FAILED;
	if (ipv4->protocol != IPv4Type_ICMP) return FAILED;
	if (BufReadUInt16_t(ipv4->chksum) != 0xb004) return FAILED;
	if (memcmp(ipv4->srcip, srcIP, IPV4_IPSIZE) != 0) return FAILED;
	if (memcmp(ipv4->dstip, dstIP, IPV4_IPSIZE) != 0) return FAILED;

	IPv4WriteValidChecksum(ipv4);
	if (BufReadUInt16_t(ipv4->chksum) != 0xb004) return FAILED;

	return PASSED;
}

//---------------------------------------------------------------------------
// namespace	: SearchAThing::Arduino::Net
// struct		: ICMPHeader

int TestICMPHeaderWChecksum()
{
	byte bytes[] =
	{
		// ipv4
		0x45,0x00,0x00,0x3c,0x08,0xf4,0x00,0x00,0x80,0x01,0xb0,0x04,0xc0,0xa8,0x00,0x28,
		0xc0,0xa8,0x00,0x50,

		// icmp
		0x00,0x00,0x4c,0x46,0x00,0x01,0x09,0x15,0x61,0x62,0x63,0x64,0x65,0x66,0x67,0x68,
		0x69,0x6a,0x6b,0x6c,0x6d,0x6e,0x6f,0x70,0x71,0x72,0x73,0x74,0x75,0x76,0x77,0x61,
		0x62,0x63,0x64,0x65,0x66,0x67,0x68,0x69
	};

	auto ipv4 = (IPv4Header *)bytes;
	auto icmp = ICMPGetHeader(ipv4);

	if (icmp->type != ICMPType::ICMPType_EchoReply) return FAILED;
	if (icmp->code != 0) return FAILED;
	if (BufReadUInt16_t(icmp->chksum) != 0x4c46) return FAILED;

	auto icmpEcho = (ICMPEchoHeader *)icmp;
	if (BufReadUInt16_t(icmpEcho->identifier) != 1) return FAILED;
	if (BufReadUInt16_t(icmpEcho->seqnr) != 2325) return FAILED;

	auto echodata = "abcdefghijklmnopqrstuvwabcdefghi";
	if (memcmp(echodata, ((byte *)icmpEcho) + sizeof(ICMPEchoHeader), strlen(echodata)) != 0) return FAILED;

	ICMPWriteValidChecksum(ipv4, icmp);
	if (BufReadUInt16_t(icmp->chksum) != 0x4c46) return FAILED;

	return PASSED;
}

//---------------------------------------------------------------------------
// namespace	: SearchAThing::Arduino::Net
// struct		: UDPHeader, DHCPHeader

int TestUDPandDHCPHeaderWChecksum()
{
	byte bytes[] =
	{
		// ipv4
		0x45,0x10,0x01,0x64,0x00,0x00,0x00,0x00,0x80,0x11,0xb7,0xff,0xc0,0xa8,0x00,0x01,
		0xc0,0xa8,0x00,0x28,

		// udp
		0x00,0x43,0x00,0x44,0x01,0x50,0x3e,0xe9,

		// bootp (discover)
		0x02,0x01,0x06,0x00,0x00,0x00,
		0x01,0xfa,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0xa8,0x00,0x28,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x0e,0xa6,0xfb,0x38,0x1a,0x8f,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x63,0x82,0x53,0x63,0x35,0x01,0x05,0x36,0x04,0xc0,
		0xa8,0x00,0x01,0x33,0x04,0x00,0x00,0x02,0x58,0x01,0x04,0xff,0xff,0xff,0x00,0x03,
		0x04,0xc0,0xa8,0x00,0x01,0x06,0x04,0xc0,0xa8,0x00,0x01,0x0c,0x1c,0x61,0x72,0x64,
		0x75,0x69,0x6e,0x6f,0x74,0x65,0x73,0x74,0x2e,0x73,0x65,0x61,0x72,0x63,0x68,0x61,
		0x74,0x68,0x69,0x6e,0x67,0x2e,0x63,0x6f,0x6d,0x1c,0x04,0xc0,0xa8,0x00,0xff,0x0f,
		0x10,0x73,0x65,0x61,0x72,0x63,0x68,0x61,0x74,0x68,0x69,0x6e,0x67,0x2e,0x63,0x6f,
		0x6d,0xff
	};

	auto ipv4 = (IPv4Header *)bytes;
	auto udp = UDPGetHeader(ipv4);
	if (BufReadUInt16_t(udp->sourcePort) != 67) return FAILED;
	if (BufReadUInt16_t(udp->destPort) != 68) return FAILED;
	if (BufReadUInt16_t(udp->length) != 336) return FAILED;
	if (BufReadUInt16_t(udp->chksum) != 0x3ee9) return FAILED;

	byte zeroIp[] = { 0,0,0,0 };
	byte yourIp[] = { 192,168,0,40 };
	byte clientMac[] = { 0x0e, 0xa6, 0xfb, 0x38, 0x1a, 0x8f };

	auto dhcp = DHCPGetHeader(udp);
	if (dhcp->opCode != DHCPOpCode::DHCPOpCode_BootReply) return FAILED;
	if (dhcp->hwType != DHCPHwType::DHCPHwType_Ethernet) return FAILED;
	if (dhcp->hwLength != IPV4_MACSIZE) return FAILED;
	if (dhcp->hopCount != 0) return FAILED;
	if (BufReadUInt32_t(dhcp->transactionId) != 0x1fa) return FAILED;
	if (BufReadUInt16_t(dhcp->nrSeconds) != 0) return FAILED;
	if (BufReadUInt16_t(dhcp->flags) != 0) return FAILED;
	if (memcmp(dhcp->clientIpAddress, zeroIp, IPV4_IPSIZE) != 0) return FAILED;
	if (memcmp(dhcp->yourIp, yourIp, IPV4_IPSIZE) != 0) return FAILED;
	if (memcmp(dhcp->serverIp, zeroIp, IPV4_IPSIZE) != 0) return FAILED;
	if (memcmp(dhcp->gatewayIp, zeroIp, IPV4_IPSIZE) != 0) return FAILED;
	if (memcmp(dhcp->clientHwAddress, clientMac, IPV4_IPSIZE) != 0) return FAILED;
	if (dhcp->serverHostname[0] != 0) return FAILED;
	if (dhcp->bootFilename[0] != 0) return FAILED;
	if (memcmp(dhcp->magic, DHCPMagicCookie, DHCPMagicCookieSIZE) != 0) return FAILED;

	{
		byte opts[] = { DHCPOption::DHCPOptionMsgType, 1, DHCPMsgType::DHCPMsgTypeAck };
		auto optsBuf = BufferInfo(opts, sizeof(opts));
		if (!DHCPMatchesOption(ipv4, udp, dhcp, optsBuf)) return FAILED;
	}

	{
		byte opts[] = { DHCPOption::DHCPOptionServerIdentifier, IPV4_IPSIZE, 192, 168, 0, 1 };
		auto optsBuf = BufferInfo(opts, sizeof(opts));
		if (!DHCPMatchesOption(ipv4, udp, dhcp, optsBuf)) return FAILED;
	}

	{
		byte opts[] = { DHCPOption::DHCPOptionLeaseTime, sizeof(uint32_t), 0, 0, 0, 0 };
		BufWrite32(opts + 2, 600L); // 600 secs
		auto optsBuf = BufferInfo(opts, sizeof(opts));
		if (!DHCPMatchesOption(ipv4, udp, dhcp, optsBuf)) return FAILED;
	}

	{
		byte opts[] = { DHCPOption::DHCPOptionSubnetMask, IPV4_IPSIZE, 255, 255, 255, 0 };
		auto optsBuf = BufferInfo(opts, sizeof(opts));
		if (!DHCPMatchesOption(ipv4, udp, dhcp, optsBuf)) return FAILED;
	}

	{
		byte opts[] = { DHCPOption::DHCPOptionGateway, IPV4_IPSIZE, 192, 168, 0, 1 };
		auto optsBuf = BufferInfo(opts, sizeof(opts));
		if (!DHCPMatchesOption(ipv4, udp, dhcp, optsBuf)) return FAILED;
	}

	{
		byte opts[] = { DHCPOption::DHCPOptionDns, IPV4_IPSIZE, 192, 168, 0, 1 };
		auto optsBuf = BufferInfo(opts, sizeof(opts));
		if (!DHCPMatchesOption(ipv4, udp, dhcp, optsBuf)) return FAILED;
	}

	{
		auto str = "arduinotest.searchathing.com";
		auto opts = new byte[2 + strlen(str)];
		opts[0] = DHCPOption::DHCPOptionHostname;
		opts[1] = strlen(str);
		memcpy(opts + 2, str, strlen(str));
		auto optsBuf = BufferInfo(opts, sizeof(opts));
		auto res = DHCPMatchesOption(ipv4, udp, dhcp, optsBuf);
		delete opts;
		if (!res) return FAILED;
	}

	{
		byte opts[] = { DHCPOption::DHCPOptionBroadcast, IPV4_IPSIZE, 192, 168, 0, 255 };
		auto optsBuf = BufferInfo(opts, sizeof(opts));
		if (!DHCPMatchesOption(ipv4, udp, dhcp, optsBuf)) return FAILED;
	}

	{
		auto str = "searchathing.com";
		auto opts = new byte[2 + strlen(str)];
		opts[0] = DHCPOption::DHCPOptionDomainName;
		opts[1] = strlen(str);
		memcpy(opts + 2, str, strlen(str));
		auto optsBuf = BufferInfo(opts, sizeof(opts));
		auto res = DHCPMatchesOption(ipv4, udp, dhcp, optsBuf);
		delete opts;
		if (!res) return FAILED;
	}

	if (DHCPLocateOption(ipv4, udp, dhcp, DHCPOption::DHCPOptionEnd) == NULL) return FAILED;

	return PASSED;
}

//===========================================================================
// TEST RUNNER
//===========================================================================

void setup() {
	// Util global methos
	EvalTest(TestFreeMemoryMaxBlock, "FreeMemoryMaxBlock");
	EvalTest(TestTimeDiff, "TimeDiff");
	EvalTest(TestBufWrite16, "BufWrite16");
	EvalTest(TestBufWrite32, "BufWrite32");
	EvalTest(TestBufReadUInt16_t, "BufReadUInt16_t");
	EvalTest(TestBufReadUInt32_t, "BufReadUInt32_t");

	// Util classes	
	EvalTest(TestBufferInfo, "BufferInfo");
	EvalTest(TestIdStorage, "IdStorage");
	EvalTest(TestRamData, "RamData");
	EvalTest(TestSList, "SList");

	// Net classes	
	EvalTest(TestIPEndPoint, "IPEndPoint");
	EvalTest(TestEth2Header, "Eth2Header");
	EvalTest(TestARPHeader, "ARPHeader");
	EvalTest(TestChecksum, "Checksum");
	EvalTest(TestIPv4HeaderWChecksum, "IPv4HeaderWChecksum");
	EvalTest(TestICMPHeaderWChecksum, "ICMPHeaderWChecksum");
	EvalTest(TestUDPandDHCPHeaderWChecksum, "UDPandDHCPHeaderWChecksum");

	// [summary]
	DNewline();
	DPrintln(F("Summary:"));
	DPrint("\t");
	if (failedCount == 0)
		DPrintln(F("SUCCESS"));
	else
		DPrintln(F("*FAILED"));

	DPrint("\t"); DPrint(testsDoneCount - failedCount); DPrint("/"); DPrint(testsDoneCount); DPrintln(" passed.");
}

void loop()
{
}
