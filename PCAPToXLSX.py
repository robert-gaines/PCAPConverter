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
        timestamp = time.ctime()
        #
        timestamp = timestamp.replace(' ','_')
        #
        timestamp = timestamp.replace(':','_')
        #
        filename  = 'pcap_'+timestamp+'.xlsx'
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

    def ConvertToXLSX(self):
        #
        output_filename = self.GenerateFilename()
        #
        capture_contents = rdpcap(self.capture_file_name)
        #
        workbook = xlsxwriter.Workbook(output_filename)
        #
        current_worksheet = workbook.add_worksheet('Converted PCAP')
        #
        col_header_list = ['Entry','Source MAC','Destination MAC','L2 Type','IP Version','IHL','TOS','Length','Identifier','Flags','Fragment','TTL','Protocol','Checksum','L3 Options','Source IP','Destination IP','Transport','Source Port','Destination Port','Sequence','Acknowledgement','Offset','Reserved','Flags','Window','Length','Transport Checksum','Urgent Pointer','L4 Options']
        #
        limit = len(col_header_list)
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
            time.sleep(1)
            char_index = 0
            alpha_iter = 0
            #
        row_index = 2
        #
        entry = 0
        #
        for packet in capture_contents:
            #
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
            current_packet = []
            #
            if(packet.haslayer('Ethernet')):
                #
                source_mac      = packet['Ethernet'].src
                destination_mac = packet['Ethernet'].dst
                l2_type         = packet['Ethernet'].type
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
                        current_packet = [entry,source_mac,destination_mac,l2_type,ip_version,ihl,tos,length,idnt,flags,frag,ttl,proto,chksum,ip_options,src_ip,dst_ip,transport,src_port,dst_port,seq,ack,dataofs,reserved,flags,window,l4_chksum,l4_len,urgptr,options]
                        #
                        limit = len(current_packet)
                        #
                        # row_index,current_packet,worksheet
                        #
                        self.WriteEntry(row_index,current_packet,current_worksheet)
                        row_index += 1
                        entry += 1
                        #
        workbook.close()

cap = PcapToXLSX('Sample.pcap')

cap.ConvertToXLSX()
