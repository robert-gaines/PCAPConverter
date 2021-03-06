from scapy.all import *
import time

class PCAPToText():
    #
    def __init__(self,capture_file_name):
        #
        self.capture_file_name = capture_file_name
        #
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
        filename  = subject_file+'_'+timestamp+'.txt'
        #
        return filename

    def ConvertToText(self):
        #
        try:
            filename = self.GenerateFilename()
            #
            capture_contents = rdpcap(self.capture_file_name)
            #
            with open(filename,'w',newline='') as conv_file:
                #
                conv_file.write("'Entry','Source MAC','Destination MAC','L2 Type','IP Version','IHL','TOS','Length','Identifier','Flags','Fragment','TTL','Protocol','Checksum','L3 Options','Source IP','Destination IP','Transport','Source Port','Destination Port','Sequence','Acknowledgement','Offset','Reserved','Flags','Window','Length','Transport Checksum','Urgent Pointer','L4 Options'\n")
                #
                entry = 0 
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
                for packet in capture_contents:
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
                        conv_file.write("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n"%(entry,source_mac,destination_mac,l2_type,ip_version,ihl,tos,length,idnt,flags,frag,ttl,proto,chksum,ip_options,src_ip,dst_ip,transport,src_port,dst_port,seq,ack,dataofs,reserved,flags,window,l4_len,l4_chksum,urgptr,options))
                        #
                        entry += 1
                        #
            return filename
        except:
            return False