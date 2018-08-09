#ifndef __PCAP_HPP__
#define __PCAP_HPP__

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<time.h>
#include<sys/types.h>
#include<pcap.h>

class pcap
{
public:
	pcap(void)
	{
		char* devname=pcap_lookupdev(m_err_buf);
		if(devname)
		{
			printf("success: device: %s\n", devname);
			memcpy(m_dev_name,devname,strlen(devname)+1);
		}
		else
		{
			printf("error: %s\n", m_err_buf);
			exit(-1);
		}
		if(-1 == pcap_lookupnet(m_dev_name,&m_net_num,&m_net_mask,m_err_buf))
		{
			printf("error: %s\n",m_err_buf);
			exit(-1);
		}
	}
	pcap(const char* devname)
	{
		memcpy(m_dev_name,devname,strlen(devname));
		if(-1 == pcap_lookupnet(m_dev_name,&m_net_num,&m_net_mask,m_err_buf))
		{
			printf("error: %s\n",m_err_buf);
			exit(-1);
		}
	}
	~pcap(void)
	{
		close();
	}
	bool open(uint32_t snaplen=65535,uint32_t promisc=1,uint32_t to_ms=0)
	{
		m_snaplen=snaplen;
		m_promisc=promisc;
		m_to_ms=to_ms;

		m_device=pcap_open_live(m_dev_name,m_snaplen,m_promisc,m_to_ms,m_err_buf);
		if(m_device == nullptr)
		{
			printf("error: pcap_open_live(): %s\n", m_err_buf);
			return false;
		}
		return true;
	}
	bool close(void)
	{
		if(m_device)
		{
			pcap_close(m_device);
			m_device=nullptr;
			return true;
		}
		return false;
	}
	const uint8_t* get_one_packet(struct pcap_pkthdr* pkt_info)
	{
		return pcap_next(m_device,pkt_info);
	}
	void print_net_info(void)
	{
		printf("device: %s num: %u.%u.%u.%u mask: %u.%u.%u.%u\n",m_dev_name,
				(m_net_num << (3*8)) >> (3*8),
				(m_net_num << (2*8)) >> (3*8),
				(m_net_num << (1*8)) >> (3*8),
				(m_net_num << (0*8)) >> (3*8),

				(m_net_mask << (3*8)) >> (3*8),
				(m_net_mask << (2*8)) >> (3*8),
				(m_net_mask << (1*8)) >> (3*8),
				(m_net_mask << (0*8)) >> (3*8)
			  );
	}
	static void print_packet_info(struct pcap_pkthdr* pkt_info)
	{
		//len 和 caplen的区别：
		//因为在某些情况下你不能保证捕获的包是完整的，例如一个包长 1480，但是你捕获到 1000 的时候，可能因为某些原因就中止捕获了，所以 caplen 是记录实际捕获的包长，也就是 1000，而 len 就是 1480。
		printf("sec:%10ld usec:%6ld caplen:%5u len:%5u\n",pkt_info->ts.tv_sec,pkt_info->ts.tv_usec,pkt_info->caplen,pkt_info->len);
	}
private:
	//存放错误信息的缓冲区
	char m_err_buf[PCAP_ERRBUF_SIZE]={0};
	//网卡名
	char m_dev_name[64]={0};
	//网络地址
	uint32_t m_net_num=0;
	//掩码
	uint32_t m_net_mask=0;
	//捕获数据包的长度，长度不能大于 65535 个字节
	uint32_t m_snaplen=65535;
	//1 代表混杂模式，其它非混杂模式
	uint32_t m_promisc=1;
	//指定需要等待的毫秒数，超过这个数值后，获取数据包的函数就会立即返回，0 表示一直等待直到有数据包到来
	uint32_t m_to_ms=0;
	//打开的设备资源指针
	pcap_t* m_device=nullptr;
};

#endif//__PCAP_HPP__
