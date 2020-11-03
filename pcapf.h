#pragma once
#include <stdio.h>
#include <io.h>


#pragma  warning(push)
#pragma  warning(disable: 4996)
// -------------------------------------------------
// copy from 'pcap.h'
typedef  int                      int32;
typedef  unsigned char            uint8;
typedef  unsigned short           uint16;
typedef  unsigned int             uint32;
#define  TCPDUMP_MAGIC            0xa1b2c3d4
#define  DLT_EN10MB               1
#define  PCAP_VERSION_MAJOR       3
#define  PCAP_VERSION_MINOR       0
#define  NTOHS(_v)                SwapByte<USHORT>(_v)
#define  NTOHL(_v)                SwapByte<UINT>(_v)


struct pcap_file_header
{
	uint32 magic;
	uint16 version_major;
	uint16 version_minor;
	int32  thiszone;
	uint32 sigfigs;
	uint32 snaplen;
	uint32 linktype;
};

struct pcap_pkthdr
{
	struct timeval ts;
	uint32 caplen;
	uint32 len;
};
#pragma  warning(pop)


template <typename T>
T SwapByte(T v1)
{
	//NT_ASSERT(sizeof(T) > 1);
	BYTE v2[sizeof(T)], * ptr = (BYTE*)&v1;
	for(int i = 0, n = sizeof(v2); i < n; i++) v2[i] = ptr[n-i-1];
	return *(T*)v2;
}


class CPcapWriteFile
{
public:
	CPcapWriteFile(FILE * pf = 0)
		: m_pf(pf)
	{}

	~CPcapWriteFile()
	{
		Close();
	}

	FILE * File()           { return m_pf; }
	void   Attach(FILE * f) { m_pf = f; }
	void   Detach()         { m_pf = 0; }
	void   Close()          { if(m_pf) fclose(m_pf); m_pf = 0; }

	FILE * Open(const char * path)
	{
		struct pcap_file_header header = {0};
		FILE * pf = 0;

		Assert(m_pf == 0);
		pf = fopen(path, "r");
		if(pf)
		{
			int fd  = fileno(pf);
			int len = filelength(fd);

			fclose(pf); pf  = 0;
			if(len > 0) pf  = fopen(path, "ab");
		}

		if(!pf) pf = fopen(path, "wb");
		if(!pf) return 0;

		header.magic         = TCPDUMP_MAGIC;
		header.version_major = PCAP_VERSION_MAJOR;
		header.version_minor = PCAP_VERSION_MINOR;

		// snaplen is default 65535.
		// DLT_EN10MB: Wan, 802.3, (this is (presumably) a real Ethernet capture).
		header.snaplen       = 0x10000;
		header.linktype      = DLT_EN10MB;

		fwrite(&header, 1, sizeof(header), pf);
		m_pf = pf;
		return pf;
	}

	int    Write(const char * szData, int nLen, const char * szPreData, int nPreLen, const char * szPostData, int nPostLen, __int64 nTimestamp)
	{
		int    ret;
		struct pcap_pkthdr header = {0};
		FILE * pf = m_pf;

		Assert(pf);
		header.ts.tv_sec  = int(nTimestamp/10000);
		header.ts.tv_usec = int(nTimestamp%10000);
		header.caplen     = nLen+nPreLen+nPostLen;
		header.len        = nLen+nPreLen;

		Assert(nLen);
		ret = WriteImpl(&header, sizeof(header), pf); Assert(!ret);
		if(nPreLen)  { ret = WriteImpl(szPreData,  nPreLen,  pf);  Assert(!ret); }
		ret = WriteImpl(szData,  nLen, pf);           Assert(!ret);
		if(nPostLen) { ret = WriteImpl(szPostData, nPostLen, pf);  Assert(!ret); }

		return ret;
	}

	int    WriteImpl(const void * data, int len, FILE * pf)
	{
		int nRet = 0;

		nRet = fwrite(data, 1, len, pf); Assert(nRet == len);
		fflush(pf);
		return 0;
	}


private:
	FILE * m_pf;
};


class CProxyPcapFile
{
public:
	CProxyPcapFile()
		: m_seq1(0), m_ack1(0)
		, m_seq2(0), m_ack2(0)
		, m_ip1(0),  m_port1(0)
		, m_ip2(0),  m_port2(0)
	{}

	~CProxyPcapFile()
	{
		m_pfile.Detach();
	}

	int   Init(FILE * pf)
	{
		Assert(pf);
		m_pfile.Attach(pf);
		return 0;
	}

	void  WritePcapData(const char * szData, int nLen, int nSrcIp, int nSrcPort, int nDstIp, int nDstPort)
	{
		unsigned char g_net_header[] = 
		{
			// --------------------------------
			// ethernet header.
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 
			0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 
			0x08, 0x00, 
			// --------------------------------
			// ip header.
			0x45, 0x00, 0x00, 0x00, 0x00, 0x00,        // len=(2,2), id=(4,2)
			0x40, 0x00, 0x80, 0x06, 0x00, 0x00,        // 
			0x00, 0x00, 0x00, 0x00,                    // src ip
			0x00, 0x00, 0x00, 0x00,                    // dst ip.
			// tcp header
			0x00, 0x00, 0x00, 0x00,                    // src port, dst port.
			0x00, 0x00, 0x00, 0x00,                    // seq
			0x00, 0x00, 0x00, 0x00,                    // ack
			0x50, 0x18, 0xfa, 0xf0, 0x00, 0x00,        // header_len=20, flags=0x18(psh, ack).
			0x00, 0x00, 
			// payload.
		}; 

		// 包的长度要以 4字节对齐
		static USHORT g_id = 0;
		static char   g_add_datas[10] = {0};
		char * p  = (char*)&g_net_header[14];
		USHORT id = g_id++, len = sizeof(g_net_header)+nLen-14, add_len = 0;

		if(add_len = (len%4)) add_len = 4-add_len;
		if(len < (60-14))     add_len = 46-len;
		Assert(add_len < sizeof(g_add_datas));

		*(uint16*)(p+ 2) = NTOHS(len);
		*(uint16*)(p+ 4) = NTOHS(id);
		*(uint32*)(p+12) = nSrcIp;
		*(uint32*)(p+16) = nDstIp;
		*(uint16*)(p+20) = NTOHS(nSrcPort);
		*(uint16*)(p+22) = NTOHS(nDstPort);

		// 计算 seq/ack. 下一次使用. 
		// 判断应该用 1还是2
		Assert(nSrcIp && nDstIp && nSrcPort && nDstPort);
		if(m_ip1 == 0)
		{
			Assert(!m_ip2 && !m_port1 && !m_port2);
			m_ip1 = nSrcIp; m_port1 = nSrcPort;
			m_ip2 = nDstIp; m_port2 = nDstPort;
		}

		if(m_ip1 == nSrcIp && m_port1 == nSrcPort && m_ip2 == nDstIp && m_port2 == nDstPort)
		{
			*(uint32*)(p+24) = NTOHL(m_seq1);
			*(uint32*)(p+28) = NTOHL(m_ack1);
			m_seq1 += nLen; m_ack2 += nLen;
		}
		else
		{
			Assert(m_ip1 == nDstIp && m_port1 == nDstPort && m_ip2 == nSrcIp && m_port2 == nSrcPort);
			*(uint32*)(p+24) = NTOHL(m_seq2);
			*(uint32*)(p+28) = NTOHL(m_ack2);
			m_ack1 += nLen; m_seq2 += nLen;
		}

		__int64  timestamp = _time32(0); Assert(m_pfile.File());
		m_pfile.Write(szData, nLen, (const char*)g_net_header, sizeof(g_net_header), g_add_datas, add_len, timestamp * 10000);
	}


private:
	unsigned int   m_ip1, m_ip2, m_port1, m_port2;
	unsigned int   m_seq1, m_ack1;
	unsigned int   m_seq2, m_ack2;

	CPcapWriteFile m_pfile;
};
