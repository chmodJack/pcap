#ifndef __NET_PACKET_HPP__
#define __NET_PACKET_HPP__

class net_packet
{
public:
	net_packet(const uint8_t* address,uint32_t length)
	{
		m_address=(uint8_t*)address;
		m_length=length;

		//mac layer
		m_mac_start=m_address;
		m_mac_destination=m_mac_start;
		m_mac_source=m_mac_start+6;
		m_mac_type=((m_mac_start[12]) << 8) | (m_mac_start[13]);

		//ip layer
		m_ip_start=m_mac_start+14;
		m_ip_version=((m_ip_start[0]) & 0xF0) >> 4;
		m_ip_header_length=(m_ip_start[0]) & 0x0F;
		m_ip_differentiated_services=m_ip_start[1];
		m_ip_total_length=((m_ip_start[2]) << 8) | (m_ip_start[3]);
		m_ip_identification=((m_ip_start[4]) << 8) | (m_ip_start[5]);
		m_ip_more_fragment=(m_ip_start[6]) & (1 << 7);
		m_ip_don_not_fragment=(m_ip_start[6]) & (1 << 6);
		m_ip_fragment_offset=(((m_ip_start[6]) & 0x1F) << 8) | (m_ip_start[7]);
		m_ip_time_to_live=m_ip_start[8];
		m_ip_protocol=m_ip_start[9];
		m_ip_header_check_sum=((m_ip_start[10]) << 8) | (m_ip_start[11]);
		m_ip_source_address=m_ip_start+12;
		m_ip_destination_address=m_ip_start+16;

		//transport layer
		m_tcp_start=m_ip_start+(m_ip_header_length*4);
		m_udp_start=m_ip_start+(m_ip_header_length*4);
		//tcp
		m_tcp_source_port=((m_tcp_start[0]) << 8) | (m_tcp_start[1]);
		m_tcp_destination_port=((m_tcp_start[2]) << 8) | (m_tcp_start[3]);
		m_tcp_sequence=
			((m_tcp_start[4]) << (3*8)) |
			((m_tcp_start[5]) << (2*8)) |
			((m_tcp_start[6]) << (1*8)) |
			((m_tcp_start[7]) << (0*8)) ;
		m_tcp_ack_sequence=
			((m_tcp_start[8]) << (3*8)) |
			((m_tcp_start[9]) << (2*8)) |
			((m_tcp_start[10]) << (1*8)) |
			((m_tcp_start[11]) << (0*8)) ;
		m_tcp_header_length=(m_tcp_start[12]) >> 4;
		m_tcp_urg=(m_tcp_start[13]) & (1 << 5);
		m_tcp_ack=(m_tcp_start[13]) & (1 << 4);
		m_tcp_psh=(m_tcp_start[13]) & (1 << 3);
		m_tcp_rst=(m_tcp_start[13]) & (1 << 2);
		m_tcp_syn=(m_tcp_start[13]) & (1 << 1);
		m_tcp_fin=(m_tcp_start[13]) & (1 << 0);
		m_tcp_window_size=((m_tcp_start[14]) << 8) | (m_tcp_start[15]);
		m_tcp_check_sum=((m_tcp_start[16]) << 8) | (m_tcp_start[17]);
		m_tcp_urgent_pointer=((m_tcp_start[18]) << 8) | (m_tcp_start[19]);

		m_data_start=m_tcp_start+(m_tcp_header_length*4);
		m_data_length=m_ip_total_length-(m_ip_header_length*4)-(m_tcp_header_length*4);
	}
	void print_mac_info(void)
	{
		printf("mac dest : [%02x %02x %02x %02x %02x %02x]\n",m_mac_destination[0],m_mac_destination[1],m_mac_destination[02],m_mac_destination[3],m_mac_destination[4],m_mac_destination[5]);

		printf("mac sour : [%02x %02x %02x %02x %02x %02x]\n",m_mac_source[0],m_mac_source[1],m_mac_source[02],m_mac_source[3],m_mac_source[4],m_mac_source[5]);

		const char* type;
		switch(m_mac_type)
		{
			case 0x0800:type="IP";break;
			case 0x0806:type="ARP";break;
			case 0x8035:type="RARP";break;
			default:type="UNKNOW";break;
		}

		printf("mac packet type: [%04x] -> %s\n",m_mac_type,type);
	}
	void print_ip_info(void)
	{
		printf("ip version: [%u]\n",m_ip_version);
		printf("ip header length: [%u] -> (%u*4==%2u)\n",m_ip_header_length,m_ip_header_length,m_ip_header_length*4);
		printf("ip differentiated services: [%u]\n",m_ip_differentiated_services);
		printf("ip total length: [%u]\n",m_ip_total_length);
		printf("ip identification: [%u]\n",m_ip_identification);
		printf("ip more fragment: [%u]\n",m_ip_more_fragment?1:0);
		printf("ip do not fragment: [%u]\n",m_ip_don_not_fragment?1:0);
		printf("ip fragment offset: [%u]\n",m_ip_fragment_offset);
		printf("ip time to live: [%u]\n",m_ip_time_to_live);

		const char* type;
		switch(m_ip_protocol)
		{
			case 1:type="ICMP";break;
			case 6:type="TCP";break;
			case 17:type="UDP";break;
			default:type="UNKNOW";break;
		}

		printf("ip protocol: [%u] -> %s\n",m_ip_protocol,type);
		printf("ip header check sum: [%u]\n",m_ip_header_check_sum);
		printf("ip source address: [%u.%u.%u.%u]\n",m_ip_source_address[0],m_ip_source_address[1],m_ip_source_address[2],m_ip_source_address[3]);
		printf("ip destination address: [%u.%u.%u.%u]\n",m_ip_destination_address[0],m_ip_destination_address[1],m_ip_destination_address[2],m_ip_destination_address[3]);
	}
	void print_tcp_info(void)
	{
		printf("tcp source port: [%u]\n",m_tcp_source_port);
		printf("tcp destination port: [%u]\n",m_tcp_destination_port);
		printf("tcp sequence: [%u]\n",m_tcp_sequence);
		printf("tcp ack sequence: [%u]\n",m_tcp_ack_sequence);
		printf("tcp header length: [%u] -> (%u*4==%u)\n",m_tcp_header_length,m_tcp_header_length,m_tcp_header_length*4);
		printf("tcp urg[%u]\n",m_tcp_urg?1:0);
		printf("tcp ack[%u]\n",m_tcp_ack?1:0);
		printf("tcp psh[%u]\n",m_tcp_psh?1:0);
		printf("tcp rst[%u]\n",m_tcp_rst?1:0);
		printf("tcp syn[%u]\n",m_tcp_syn?1:0);
		printf("tcp fin[%u]\n",m_tcp_fin?1:0);
		printf("tcp window size: [%u]\n",m_tcp_window_size);
		printf("tcp check sum: [%u]\n",m_tcp_check_sum);
		printf("tcp urgent pointer: [%u]\n",m_tcp_urgent_pointer);
	}
	void print_data(void)
	{
		coprintf("data length: ^g%u\n",m_data_length);
		coprintf("^rdata :\n");
		for(int i=0;i<m_data_length;i++)
		{
			coprintf("^p%02x ",m_data_start[i]);
		}
		printf("\n");
		for(int i=0;i<m_data_length;i++)
		{
			coprintf("^y%c",m_data_start[i]);
		}
		printf("\n");
	}
public:
	uint8_t* m_address;
	uint32_t m_length;

	uint8_t* m_mac_start;

	uint8_t* m_ip_start;

	uint8_t* m_tcp_start;
	uint8_t* m_udp_start;

	//mac layer
	//6 bytes
	uint8_t* m_mac_destination;
	//6 bytes
	uint8_t* m_mac_source;
	//2 bytes
	uint16_t m_mac_type;

	//ip layer
	//4 bits
	uint8_t m_ip_version;
	//4 bits, count by word(32bits)
	uint8_t m_ip_header_length;
	//8 bits
	uint8_t m_ip_differentiated_services;
	//16 bits, count by byte
	uint16_t m_ip_total_length;
	//16 bits
	uint16_t m_ip_identification;
	//1 bit
	bool m_ip_more_fragment;
	//1 bit
	bool m_ip_don_not_fragment;
	//13 bits
	uint16_t m_ip_fragment_offset;
	//8 bits
	uint8_t m_ip_time_to_live;
	//8 bits
	uint8_t m_ip_protocol;
	//16 bits
	uint16_t m_ip_header_check_sum;
	//32 bits
	uint8_t* m_ip_source_address;
	//32 bits
	uint8_t* m_ip_destination_address;

	//transport layer
	//tcp
	//16 bits
	uint16_t m_tcp_source_port;
	//16 bits
	uint16_t m_tcp_destination_port;
	//32 bits
	uint32_t m_tcp_sequence;
	//32 bits
	uint32_t m_tcp_ack_sequence;
	//4 bits
	uint8_t m_tcp_header_length;
	//1 bit
	bool m_tcp_urg;
	//1 bit
	bool m_tcp_ack;
	//1 bit
	bool m_tcp_psh;
	//1 bit
	bool m_tcp_rst;
	//1 bit
	bool m_tcp_syn;
	//1 bit
	bool m_tcp_fin;
	//16 bits
	uint16_t m_tcp_window_size;
	//16 bits
	uint16_t m_tcp_check_sum;
	//16 bits
	uint16_t m_tcp_urgent_pointer;

	//udp
	//...

	//data
	uint8_t* m_data_start;
	uint32_t m_data_length;
};

#endif//__NET_PACKET_HPP__
