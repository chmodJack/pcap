#include<iostream>
#include"pcap.hpp"
#include"coprintf.h"
using namespace std;

int main(int argc,char* argv[])
{
	pcap pp("wlp7s0");
	pp.print_net_info();
	pp.open();
	struct pcap_pkthdr hd;
	while(1)
	{
		const uint8_t* arr = pp.get_one_packet(&hd);
		pp.print_packet_info(&hd);
		for(int i=0;i<hd.caplen;i++)
		{
			if(i<6)
			{
				coprintf("^g%02x ",arr[i]);
			}
			else if(i<12)
			{
				coprintf("^r%02x ",arr[i]);
			}
			else if(i<14)
			{
				coprintf("^y%02x ",arr[i]);
			}
			else if(i<(14+(1*4)))
			{
				coprintf("^p%02x ",arr[i]);
			}
			else if(i<(14+(2*4)))
			{
				coprintf("^p%02x ",arr[i]);
			}
			else if(i<(14+(3*4)))
			{
				coprintf("^p%02x ",arr[i]);
			}
			else if(i<(14+(4*4)))
			{
				coprintf("^r%02u ",arr[i]);
			}
			else if(i<(14+(5*4)))
			{
				coprintf("^g%02u ",arr[i]);
			}
			else if(i<(14+(5*4)+2))
			{
				coprintf("^r%02u ",arr[i]);
			}
			else if(i<(14+(6*4)))
			{
				coprintf("^g%02u ",arr[i]);
			}
			else if(i<(14+(7*4)))
			{
				coprintf("^y%02u ",arr[i]);
			}
			else if(i<(14+(8*4)))
			{
				coprintf("^b%02u ",arr[i]);
			}
			else if(i<(14+(9*4)))
			{
				coprintf("^p%02u ",arr[i]);
			}
			else if(i<(14+(10*4)))
			{
				coprintf("^p%02u ",arr[i]);
			}
			else
				printf("%02x ",arr[i]);
		}
		printf("\n\n");
	}
    return 0;
}
