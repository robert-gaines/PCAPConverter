from scapy.all import *
import xlsxwriter
import time
import csv
import os

class PcapToXLSX():

    def __init__(self,capture_file_name):
        #
        self.capture_file_name = capture_file_name

    def GenerateFilename(self):
        #
        subject_file = self.capture_file_name.split('.')[0]
        #
        timestamp = time.ctime()
        #
        timestamp = timestamp.replace(' ','_')
        #
        timestamp = timestamp.replace(':','_')
        #
        filename  = subject_file+'_'+timestamp+'.xlsx'
        #
        return filename

    def WriteEntry(self,row_index,current_packet,current_worksheet):
        #
        chars = ['A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z']
        #
        current_iter = 0
        #
        alpha_iter = 0
        #
        secondary_iter = 0
        #
        secondary_index = 0
        #
        limit = len(current_packet)
        #
        while(current_iter < limit-1):
            #
            char_index = 0
            #
            if(current_iter == limit):
                #
                break
                #
            while(alpha_iter <= 25):
                #
                if(current_iter == limit):
                    #
                    break
                    #
                if(current_iter > 25):
                    #
                    write_index = chars[secondary_index]+chars[alpha_iter]+str(row_index)
                    #
                    write_value = str(current_packet[current_iter])
                    #
                    current_worksheet.write(write_index,write_value)
                    #
                if(current_iter <= 25):
                    #
                    write_index = chars[alpha_iter]+str(row_index)
                    #
                    write_value = str(current_packet[current_iter])
                    #
                    current_worksheet.write(write_index,write_value)
                    #
                current_iter += 1 ; char_index += 1 ; alpha_iter += 1
                #
            if(current_iter > 50):
                #
                secondary_index += 1
                #
            char_index = 0
            alpha_iter = 0
            #
        current_iter  = 0

    def WriteHeaders(self,col_header_list,current_worksheet):
        #
        limit =len(col_header_list)
        #
        chars = ['A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z']
        #
        current_iter = 0
        #
        alpha_iter = 0
        #
        secondary_iter = 0
        #
        col_index = 1
        #
        secondary_index = 0
        #
        while(current_iter < limit-1):
            #
            char_index = 0
            #
            if(current_iter == limit):
                #
                break
                #
            while(alpha_iter <= 25):
                #
                if(current_iter == limit):
                    #
                    break
                    #
                if(current_iter > 25):
                    #
                    write_index = chars[secondary_index]+chars[alpha_iter]+str(col_index)
                    #
                    current_worksheet.write(write_index,col_header_list[current_iter])
                    #
                if(current_iter <= 25):
                    #
                    write_index = chars[char_index]+str(col_index)
                    #
                    current_worksheet.write(write_index,col_header_list[current_iter])
                    #
                current_iter += 1 ; char_index += 1 ; alpha_iter += 1
                #
            if(current_iter > 50):
                #
                secondary_index += 1
                #
            char_index = 0
            alpha_iter = 0

    def ConvertToXLSX(self):
        #
        try:
            output_filename = self.GenerateFilename()
            #
            capture_contents = rdpcap(self.capture_file_name)
            #
            workbook = xlsxwriter.Workbook(output_filename)
            #
            standard_worksheet = workbook.add_worksheet('TCP-UDP')
            icmp_worksheet     = workbook.add_worksheet('ICMP')
            arp_worksheet      = workbook.add_worksheet('ARP')
            dns_worksheet      = workbook.add_worksheet('DNS')
            #
            standard_header_list = ['Entry','Source MAC','Destination MAC','L2 Type','IP Version','IHL','TOS','Length','Identifier','Flags','Fragment','TTL','Protocol','Checksum','L3 Options','Source IP','Destination IP','Transport','Source Port','Destination Port','Sequence','Acknowledgement','Offset','Reserved','Flags','Window','Length','Transport Checksum','Urgent Pointer','L4 Options']
            arp_header_list      = ['Entry','Source MAC','Destination MAC','L2 Type','Hardware Type','Protocol Type','Hardware Address Length','Protocol Address Length','Operation Code','Sender Hardware Address','Sender Protocol Address','Target Hardware Address','Target Protocol Address']
            icmp_header_list     = ['Entry','Source MAC','Destination MAC','L2 Type','IP Version','IHL','TOS','Length','Identifier','Flags','Fragment','TTL','Protocol','Checksum','Source IP','Destination IP','ICMP Type','ICMP Code','ICMP CHecksum','ICMP ID','ICMP Sequence','ICMP - Unused']
            dns_header_list      = ['Entry','Source MAC','Destination MAC','L2 Type','IP Version','IHL','TOS','Length','Identifier','Flags','Fragment','TTL','Protocol','Checksum','L3 Options','Source IP','Destination IP','Transport','Source Port','Destination Port','Sequence','Acknowledgement','Offset','Reserved','Flags','Window','Length','Transport Checksum','Urgent Pointer','L4 Options','DNS Query']
            #
            self.WriteHeaders(standard_header_list,standard_worksheet)
            self.WriteHeaders(arp_header_list,arp_worksheet)
            self.WriteHeaders(icmp_header_list,icmp_worksheet)
            self.WriteHeaders(dns_header_list,dns_worksheet)
            #
            arp_row_index      = 2
            icmp_row_index     = 2 
            standard_row_index = 2
            dns_row_index      = 2
            #
            arp_entry      = 0
            icmp_entry     = 0
            standard_entry = 0
            dns_entry      = 0
            #
            for packet in capture_contents:
                #
                '''
                ARP - Variables
                '''
                hwtype = ''
                ptype  = ''
                hwlen  = ''
                plen   = ''
                op     = ''
                hwsrc  = ''
                psrc   = ''
                hwdst  = ''
                pdst   = ''
                #
                '''
                ICMP - Variables
                '''
                icmp_type   = ''
                icmp_code   = ''
                icmp_chksum = ''
                icmp_id     = ''
                icmp_seq    = ''
                icmp_unused = ''
                #
                '''
                TCP/UDP - General Category Variables
                '''
                source_mac      = ''
                destination_mac = ''
                l2_type         = ''
                ip_version      = ''
                ihl             = ''
                tos             = ''
                length          = ''
                idnt            = ''
                flags           = ''
                frag            = ''
                ttl             = ''
                proto           = ''
                chksum          = ''
                ip_options      = ''
                src_ip          = ''
                dst_ip          = ''
                transport       = ''
                src_port        = ''
                dst_port        = ''
                seq             = ''
                ack             = ''
                dataofs         = ''
                reserved        = ''
                flags           = ''
                window          = ''
                l4_chksum       = ''
                l4_len          = ''
                urgptr          = ''
                options         = ''
                #
                '''
                DNS Variable(s)
                '''
                dns_qry         = ''
                #
                current_packet = []
                #
                if(packet.haslayer('Ethernet')):
                    #
                    source_mac      = packet['Ethernet'].src
                    destination_mac = packet['Ethernet'].dst
                    l2_type         = packet['Ethernet'].type
                    #
                    if(packet.haslayer('ARP')):
                        #
                        hwtype = packet['ARP'].hwtype
                        ptype  = packet['ARP'].ptype
                        hwlen  = packet['ARP'].hwlen
                        plen   = packet['ARP'].plen
                        op     = packet['ARP'].op
                        hwsrc  = packet['ARP'].hwsrc
                        psrc   = packet['ARP'].psrc
                        hwdst  = packet['ARP'].hwdst
                        pdst   = packet['ARP'].pdst
                        #
                        arp_data = [arp_entry,source_mac,destination_mac,l2_type,hwtype,ptype,hwlen,plen,op,hwsrc,psrc,hwdst,pdst]
                        #
                        self.WriteEntry(arp_row_index,arp_data,arp_worksheet)
                        arp_row_index += 1
                        arp_entry += 1
                        #
                    if(packet.haslayer('IP')):
                        #
                        ip_version = packet['IP'].version
                        ihl        = packet['IP'].ihl
                        tos        = packet['IP'].tos
                        length     = packet['IP'].len
                        idnt       = packet['IP'].id
                        flags      = packet['IP'].flags
                        frag       = packet['IP'].frag
                        ttl        = packet['IP'].ttl
                        proto      = packet['IP'].proto
                        chksum     = packet['IP'].chksum
                        ip_options = packet['IP'].options
                        src_ip     = packet['IP'].src
                        dst_ip     = packet['IP'].dst
                        #
                        if(packet.haslayer('ICMP')):
                            #
                            icmp_type   = packet['ICMP'].type
                            icmp_code   = packet['ICMP'].code
                            icmp_chksum = packet['ICMP'].chksum
                            icmp_id     = packet['ICMP'].id
                            icmp_seq    = packet['ICMP'].seq
                            icmp_unused = packet['ICMP'].unused
                            #
                            icmp_data = [icmp_entry,source_mac,destination_mac,l2_type,ip_version,ihl,tos,length,idnt,flags,frag,ttl,proto,chksum,src_ip,dst_ip,icmp_type,icmp_code,icmp_chksum,icmp_id,icmp_seq,icmp_unused]
                            self.WriteEntry(icmp_row_index,icmp_data,icmp_worksheet)
                            icmp_entry     += 1
                            icmp_row_index += 1
                            #
                        if(packet.haslayer('TCP') or packet.haslayer('UDP')):
                            #
                            if(packet.haslayer('TCP')):
                                #
                                transport = 'TCP'
                                src_port  = packet['TCP'].sport
                                dst_port  = packet['TCP'].dport
                                seq       = packet['TCP'].seq
                                ack       = packet['TCP'].ack
                                dataofs   = packet['TCP'].dataofs
                                reserved  = packet['TCP'].reserved
                                flags     = packet['TCP'].flags
                                window    = packet['TCP'].window
                                l4_chksum = packet['TCP'].chksum
                                l4_len    = 'Not Applicable'
                                urgptr    = packet['TCP'].urgptr
                                options   = packet['TCP'].options
                                #
                            if(packet.haslayer('UDP')):
                                #
                                transport = 'UDP'
                                src_port  = packet['UDP'].sport
                                dst_port  = packet['UDP'].dport
                                seq       = 'Not Applicable'
                                ack       = 'Not Applicable'
                                dataofs   = 'Not Applicable'
                                reserved  = 'Not Applicable'
                                flags     = 'Not Applicable'
                                window    = 'Not Applicable'
                                l4_len    = packet['UDP'].len
                                l4_chksum = packet['UDP'].chksum
                                urgptr    = 'Not Applicable'
                                options   = 'Not Applicable'
                                #
                            current_packet = [standard_entry,source_mac,destination_mac,l2_type,ip_version,ihl,tos,length,idnt,flags,frag,ttl,proto,chksum,ip_options,src_ip,dst_ip,transport,src_port,dst_port,seq,ack,dataofs,reserved,flags,window,l4_chksum,l4_len,urgptr,options]
                            #
                            self.WriteEntry(standard_row_index,current_packet,standard_worksheet)
                            standard_row_index += 1
                            standard_entry += 1
                            #
                        if(packet.haslayer('DNS')):
                            #
                            dns_qry = packet['DNS'].mysummary()
                            dns_data = [dns_entry,source_mac,destination_mac,l2_type,ip_version,ihl,tos,length,idnt,flags,frag,ttl,proto,chksum,ip_options,src_ip,dst_ip,transport,src_port,dst_port,seq,ack,dataofs,reserved,flags,window,l4_chksum,l4_len,urgptr,options,dns_qry]
                            self.WriteEntry(dns_row_index,dns_data,dns_worksheet)
                            dns_row_index += 1
                            dns_entry     += 1
                            #
            workbook.close()
            #
            return output_filename
            #
        except Exception as e:
            #
            return e

# cap = PcapToXLSX('Sample.pcap')

# fileName = cap.ConvertToXLSX()

# print(fileName)